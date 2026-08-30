# Reconnaissance module:
#   1. Port scanning via nmap (stealth-profile aware)
#   2. HTTP/HTTPS service probing (multi-port, auto-protocol)
#   3. WAF detection (header + body + status-code fingerprinting)
#   4. Technology fingerprinting (Server header, X-Powered-By, cookies)
#   5. Banner grabbing
#
# All subprocess calls use argument lists — zero shell injection surface
# Results are fed directly into the ScanSession findings aggregator

import re
import ssl
import json
import socket
import shutil
import subprocess
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from config.settings import (
    STEALTH_PROFILES,
    DEFAULT_STEALTH_PROFILE,
    PORT_PROFILES,
    DEFAULT_PORT_PROFILE,
    RECON_DEPTH_PROFILES,
    DEFAULT_RECON_DEPTH,
    ALL_WEB_PORTS,
    HTTP_PORTS,
    HTTPS_PORTS,
    WAF_SIGNATURES,
    WAF_BLOCK_CODES,
    DEFAULT_HEADERS,
    REQUEST_TIMEOUT,
    HTTPX_ALT_BINARY,
)
from core.session import ScanSession, log
from core.tools_manager import get_binary


def _depth_config(recon_depth: str) -> dict:
    # Returning the recon-depth profile dict, defaulting safely.
    return RECON_DEPTH_PROFILES.get(recon_depth, RECON_DEPTH_PROFILES[DEFAULT_RECON_DEPTH])

# Nmap scanning
def run_nmap(
    session: ScanSession,
    tool_statuses: dict,
    port_profile: str = DEFAULT_PORT_PROFILE,
    recon_depth: str = DEFAULT_RECON_DEPTH,
    custom_ports: list = None,
) -> Path:
    """
    Running nmap against the session target using the session's stealth profile
    Output is written to session's nmap subdirectory
    Returning the Path to the raw nmap output file

    Stealth profile controls:
        - Timing template (-T1 through -T4)
        - Scan delay
        - Max retries
    All combined with service/version detection (-sV), default scripts (-sC),
    and OS fingerprinting (-O) which requires root — gracefully skipped if not.
    """
    nmap_bin   = get_binary(tool_statuses, "nmap")
    profile    = STEALTH_PROFILES.get(session.stealth_profile, STEALTH_PROFILES[DEFAULT_STEALTH_PROFILE])
    port_arg   = PORT_PROFILES.get(port_profile, PORT_PROFILES[DEFAULT_PORT_PROFILE])
    target     = session.target["value"]
    out_file   = session.artifact_path("nmap", "initial_scan.txt")

    log("info", f"Starting nmap scan | profile={session.stealth_profile} | ports={port_profile}")
    log("info", f"  Timing: -{profile['nmap_timing']}  Extra: {profile['nmap_extra'] or 'none'}")

    # Building argument list — NO shell=True, NO string formatting into a single shell command
    cmd = [nmap_bin, "-sV", "-sC", f"-{profile['nmap_timing']}"]

    # Appending port spec. A custom --port overrides the port profile.
    if custom_ports:
        cmd += ["-p", ",".join(str(p) for p in custom_ports)]
        log("info", f"  Custom ports: {','.join(str(p) for p in custom_ports)}")
    else:
        cmd += port_arg.split()

    # NSE scripts driven by recon depth (http-enum, http-title, ... and vuln at deep)
    depth   = _depth_config(recon_depth)
    scripts = depth.get("nmap_scripts", [])
    if scripts:
        cmd += ["--script", ",".join(scripts)]
        log("info", f"  NSE scripts: {','.join(scripts)}")

    # Appending extra timing/evasion flags if any
    if profile["nmap_extra"]:
        cmd += profile["nmap_extra"].split()

    # OS detection — requires root; adding flag and warning if not root
    import os as _os
    if _os.geteuid() == 0:
        cmd += ["-O"]
    else:
        log("warning", "Not running as root — OS detection (-O) skipped.")

    # Output: normal format to file + xml for parsing
    xml_out = session.artifact_path("nmap", "initial_scan.xml")
    cmd += ["-oN", str(out_file), "-oX", str(xml_out)]

    # Target last
    cmd.append(target)

    log("info", f"  Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute hard cap
        )
        if result.returncode not in (0, 1):  # nmap returns 1 on some warnings
            log("error", f"nmap exited with code {result.returncode}")
            if result.stderr:
                log("error", f"nmap stderr: {result.stderr[:300]}")
        else:
            log("success", f"nmap scan complete → {out_file}")
    except subprocess.TimeoutExpired:
        log("error", "nmap scan timed out after 10 minutes.")
    except FileNotFoundError:
        log("error", "nmap binary not found. Check tools_manager output.")
        return out_file

    # Parsing results and feed into session
    _parse_nmap_output(session, out_file)
    return out_file


def _parse_nmap_output(session: ScanSession, nmap_file: Path) -> None:
    """
    Parsing nmap normal format output and extracting:
        - Open ports with service and version
        - HTTP/HTTPS services for downstream modules
    Feeds directly into session.findings via session methods.
    """
    if not nmap_file.exists() or nmap_file.stat().st_size == 0:
        log("warning", "nmap output file is empty or missing — nothing to parse.")
        return

    # Regex patterns for nmap normal output lines
    # Example: "80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))"
    port_pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$",
        re.IGNORECASE
    )

    with open(nmap_file, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = port_pattern.match(line)
            if not m:
                continue
            port     = int(m.group(1))
            protocol = m.group(2)
            service  = m.group(3)
            version  = m.group(4).strip() if m.group(4) else ""

            session.add_open_port(port, protocol, service, version)

            # Flag HTTP/HTTPS services for the enum and WAF modules
            svc_lower = service.lower()
            if any(kw in svc_lower for kw in ("http", "ssl", "https", "web")):
                # Determining protocol from port number
                proto = "https" if port in HTTPS_PORTS or "ssl" in svc_lower else "http"
                base_url = f"{proto}://{session.target['value']}"
                if not (proto == "http" and port == 80) and not (proto == "https" and port == 443):
                    base_url += f":{port}"
                session.add_http_service(base_url, 0, version)  # status filled in by probe_http

# http / https Service Probing
def probe_http_services(session: ScanSession, custom_ports: list = None) -> list[dict]:
    """
    For each HTTP service found by nmap (or from ALL_WEB_PORTS as fallback),
    sending a HEAD + GET request to:
        - Confirm the service is actually responding
        - Capture real HTTP status, Server header, and tech stack
        - Feed WAF detection
        - Auto-detect HTTPS vs HTTP

    custom_ports (from --port) are always probed with https-then-http scheme
    auto-detection so a user-specified non-standard port is never missed.

    Returning list of live service dicts for downstream use.
    """
    target  = session.target["value"]
    live    = []

    # If nmap already found http services, probe those specifically
    # Otherwise fall back to probing standard web ports
    if session.findings["http_services"]:
        targets_to_probe = [
            {"url": svc["url"], "port": _extract_port(svc["url"])}
            for svc in session.findings["http_services"]
        ]
    else:
        log("info", "No HTTP services from nmap — probing standard web ports...")
        targets_to_probe = []
        for port in ALL_WEB_PORTS:
            proto = "https" if port in HTTPS_PORTS else "http"
            url   = f"{proto}://{target}" if port in (80, 443) else f"{proto}://{target}:{port}"
            targets_to_probe.append({"url": url, "port": port})

    # Custom ports: auto-detect scheme (https wins if it responds) and add any
    # not already covered by the candidates above.
    if custom_ports:
        known_ports = {t["port"] for t in targets_to_probe}
        for port in custom_ports:
            if port in known_ports:
                continue
            scheme = _detect_scheme(target, port)
            url = f"{scheme}://{target}:{port}"
            targets_to_probe.append({"url": url, "port": port})
            log("info", f"  Custom port {port} detected as {scheme}")

    for item in targets_to_probe:
        url  = item["url"]
        log("info", f"Probing: {url}")
        result = _http_probe(url)
        if result is None:
            log("debug", f"  No response from {url}")
            continue

        status  = result["status"]
        server  = result.get("server", "")
        headers = result.get("headers", {})
        body    = result.get("body_snippet", "")
        tech    = _fingerprint_tech(headers, body)

        # Updating the http_service entry with real status and tech
        session.add_http_service(url, status, server, tech)

        # WAF checking on every live service
        waf_result = detect_waf(url, headers, body, status)
        if waf_result:
            session.add_waf(waf_result["waf"], waf_result["evidence"])

        live.append({
            "url":     url,
            "status":  status,
            "server":  server,
            "tech":    tech,
            "headers": headers,
            "waf":     waf_result,
        })

    if not live:
        log("warning", "No live HTTP/HTTPS services found on this target.")
    else:
        log("success", f"Found {len(live)} live web service(s).")

    return live


def _http_probe(url: str) -> Optional[dict]:
    # Sending a GET request to a URL and return response metadata
    # Handling http and https (including self-signed certs on internal targets)
    # Returning None on connection failure
    # Build request with realistic browser headers
    req = urllib.request.Request(url, headers=DEFAULT_HEADERS, method="GET")

    # SSL context: verifying certificates in prod, but for pentest targets we accept self-signed
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
            headers     = dict(resp.getheaders())
            body_bytes  = resp.read(2048)  # Only first 2KB for fingerprinting
            body_snippet = body_bytes.decode("utf-8", errors="replace")
            return {
                "status":       resp.status,
                "server":       headers.get("Server", ""),
                "headers":      {k.lower(): v for k, v in headers.items()},
                "body_snippet": body_snippet,
            }
    except urllib.error.HTTPError as e:
        # HTTPError still gives us status + headers — useful for WAF detection
        headers = dict(e.headers)
        return {
            "status":       e.code,
            "server":       headers.get("Server", ""),
            "headers":      {k.lower(): v for k, v in headers.items()},
            "body_snippet": "",
        }
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionRefusedError, OSError):
        return None


def _extract_port(url: str) -> int:
    # Extracting port from a URL string
    # Returning 80 or 443 as defaults
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _detect_scheme(host: str, port: int) -> str:
    # Deciding http vs https for a custom port by trying HTTPS first.
    # An HTTPS listener (e.g. nginx) answers plain HTTP with a 400, which would
    # otherwise register a bogus http service -- so HTTPS wins when it responds.
    if _http_probe(f"https://{host}:{port}") is not None:
        return "https"
    if _http_probe(f"http://{host}:{port}") is not None:
        return "http"
    # Fall back to the well-known default for that port number
    return "https" if port in HTTPS_PORTS else "http"

# WAF Detection
def detect_waf(
    url: str,
    headers: dict,
    body: str,
    status: int,
) -> Optional[dict]:
    """
    Fingerprinting WAF presence using three detection layers:

    Layer 1 — Header signatures:
        Known WAF-specific headers and cookie names.

    Layer 2 — Body signatures:
        WAF block/challenge page keywords in response body.

    Layer 3 — Status code heuristics:
        Unusual blocking codes (403, 406, 429, 999) on non-sensitive paths
        combined with header evidence.

    Returning dict {"waf": name, "evidence": description} or None.
    """
    headers_str  = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    body_lower   = body.lower()

    # Layer 1 & 2 — signature matching
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            sig_lower = sig.lower()
            if sig_lower in headers_str:
                return {
                    "waf":      waf_name,
                    "evidence": f"Header match: '{sig}'"
                }
            if sig_lower in body_lower:
                return {
                    "waf":      waf_name,
                    "evidence": f"Body match: '{sig}'"
                }

    # Layer 3 — generic WAF behaviour (block code + no specific signature)
    if status in WAF_BLOCK_CODES:
        # Generic WAF — we can't name it but we know something's there
        return {
            "waf":      "Unknown WAF",
            "evidence": f"HTTP {status} returned on probe — possible WAF block"
        }

    return None


def probe_waf_evasion(url: str) -> dict:
    """
    Sending probes with payloads that most WAFs block
    Comparing responses to baseline to infer WAF behavior more precisely

    Useful for:
        - Confirming WAF presence before brute-force (avoid wasting time / lockout)
        - Identifying bypass-worthy WAF configs

    Returning dict with keys: "baseline_status", "probe_status", "likely_waf", "recommendation"
    """
    log("info", f"Running WAF evasion probe against {url}")

    # Baseline — normal GET
    baseline = _http_probe(url)
    baseline_status = baseline["status"] if baseline else 0

    # WAF probe — appending a classic SQLi payload that most WAFs catch
    probe_url = url + "/?id=1'%20OR%20'1'='1"
    probe     = _http_probe(probe_url)
    probe_status = probe["status"] if probe else 0

    # Comparing
    likely_waf = probe_status != baseline_status and probe_status in WAF_BLOCK_CODES

    if likely_waf:
        log("warning",
            f"WAF confirmed via evasion probe: baseline={baseline_status}, "
            f"probe={probe_status}"
        )
        recommendation = (
            "WAF is actively blocking payloads. Consider:\n"
            "  - URL encoding / double encoding bypass\n"
            "  - Case variation in SQL keywords\n"
            "  - HTTP header injection (X-Forwarded-For: 127.0.0.1)\n"
            "  - Chunked Transfer-Encoding to bypass body inspection\n"
            "  - Slowloris-style requests to exhaust WAF state table"
        )
    else:
        log("info", "WAF evasion probe: no differential response — WAF may not be present or is passive.")
        recommendation = "No active WAF blocking detected. Standard enumeration can proceed."

    return {
        "baseline_status": baseline_status,
        "probe_status":    probe_status,
        "likely_waf":      likely_waf,
        "recommendation":  recommendation,
    }

# Technology Fingerprinting
def _fingerprint_tech(headers: dict, body: str) -> list[str]:
    """
    Identifying server-side and client-side technologies from response headers
    and body content
    Returning a list of identified technology strings.

    Covers:
        - Server software (Apache, Nginx, IIS, LiteSpeed)
        - Backend language (PHP, ASP.NET, Python, Ruby, Java)
        - CMS (WordPress, Drupal, Joomla, Magento)
        - Frameworks (Laravel, Django, Rails, Spring)
        - CDN / proxy (Cloudflare, Fastly, Varnish)
    """
    tech = []
    body_lower = body.lower()

    # Headers
    server = headers.get("server", "").lower()
    x_powered = headers.get("x-powered-by", "").lower()
    set_cookie = headers.get("set-cookie", "").lower()

    # Server software
    for name in ("apache", "nginx", "microsoft-iis", "litespeed", "openresty", "caddy"):
        if name in server:
            tech.append(f"Server:{name.title()}")

    # Backend language
    if "php" in x_powered or "php" in server:
        tech.append("Lang:PHP")
    if "asp.net" in x_powered:
        tech.append("Lang:ASP.NET")
    if "python" in x_powered or "python" in server:
        tech.append("Lang:Python")
    if "ruby" in server or "passenger" in server:
        tech.append("Lang:Ruby")
    if "java" in x_powered or "tomcat" in server or "jetty" in server:
        tech.append("Lang:Java")

    # Session cookies as language indicators
    if "phpsessid" in set_cookie:
        tech.append("Lang:PHP")
    if "jsessionid" in set_cookie:
        tech.append("Lang:Java")
    if "asp.net_sessionid" in set_cookie:
        tech.append("Lang:ASP.NET")

    # Body fingerprinting
    cms_sigs = {
        "CMS:WordPress":  ["/wp-content/", "/wp-includes/", "wp-login"],
        "CMS:Drupal":     ["/sites/default/", "drupal.js", 'content="Drupal'],
        "CMS:Joomla":     ["/media/jui/", "joomla!", "/components/com_"],
        "CMS:Magento":    ["mage/", "magento", "/skin/frontend/"],
        "CMS:Ghost":      ["ghost-url", "content=\"Ghost\""],
    }
    for label, sigs in cms_sigs.items():
        if any(s.lower() in body_lower for s in sigs):
            tech.append(label)

    framework_sigs = {
        "Framework:Laravel":  ["laravel_session", "laravel"],
        "Framework:Django":   ["csrfmiddlewaretoken", "django"],
        "Framework:Rails":    ["authenticity_token", "rails-ujs"],
        "Framework:Spring":   ["spring", "jsessionid"],
        "Framework:Express":  ["x-powered-by: express"],
        "Framework:FastAPI":  ["/openapi.json", "fastapi"],
    }
    for label, sigs in framework_sigs.items():
        if any(s.lower() in body_lower or s.lower() in str(headers).lower() for s in sigs):
            tech.append(label)

    # CDN / Proxy
    cdn_headers = {
        "CDN:Cloudflare": ["cf-cache-status", "cf-ray"],
        "CDN:Fastly":     ["fastly-restarts", "x-fastly-request-id"],
        "CDN:Varnish":    ["x-varnish", "via"],
        "CDN:Akamai":     ["x-akamai-transformed", "x-check-cacheable"],
    }
    for label, h_keys in cdn_headers.items():
        if any(k in headers for k in h_keys):
            tech.append(label)

    # Deduplicating while preserving order
    seen = set()
    unique_tech = []
    for t in tech:
        if t not in seen:
            seen.add(t)
            unique_tech.append(t)

    if unique_tech:
        log("info", f"  Tech detected: {', '.join(unique_tech)}")

    return unique_tech

# Banner Grabbing
# Raw socket banner grabbing, useful for non-http services and for grabbing
# banners that http libraries might suppress
def grab_banner(host: str, port: int, timeout: int = 5) -> Optional[str]:
    # Raw TCP banner grabbing on any port.
    # Sending a minimal http GET if port looks like web, otherwise just listening
    # Returning the first 1024 bytes of response as a string, or None on failure
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # For web ports, send a minimal HTTP request to elicit a banner
            if port in ALL_WEB_PORTS:
                sock.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                    .encode()
                )
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            if banner:
                log("info", f"  Banner [{host}:{port}]: {banner[:120]}")
                return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None

def grab_all_banners(session: ScanSession) -> dict[str, str]:
    # Grabbing banners from all open ports discovered in session.findings.
    # Returning dict of {"host:port": banner_string}.
    banners = {}
    host    = session.target["value"]

    if not session.findings["open_ports"]:
        log("warning", "No open ports in session to grab banners from.")
        return banners

    log("info", f"Banner grabbing {len(session.findings['open_ports'])} open port(s)...")
    for port_entry in session.findings["open_ports"]:
        port   = port_entry["port"]
        banner = grab_banner(host, port)
        if banner:
            key = f"{host}:{port}"
            banners[key] = banner
            session.record("banner", {"target": key, "banner": banner[:512]})

    return banners

# Real-world tool integrations
# Each wrapper is optional: if the tool is missing (or, for httpx, the wrong
# binary is on PATH) it logs and returns without touching findings, so the
# built-in probes above remain the fallback.

def _run_tool(cmd: list, timeout: int = 300) -> Optional[subprocess.CompletedProcess]:
    # Running an external tool with an argument list (no shell) and a hard timeout.
    # Returning the CompletedProcess, or None on timeout / missing binary.
    log("info", f"  $ {' '.join(cmd)}")
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        log("warning", f"  Tool timed out after {timeout}s: {cmd[0]}")
        return None
    except FileNotFoundError:
        log("warning", f"  Binary not found: {cmd[0]}")
        return None


def _is_pd_httpx(binary: str) -> bool:
    """
    Verifying a binary is ProjectDiscovery httpx and NOT the Python 'httpx'
    HTTP client, which shares the name. PD httpx accepts '-version' and prints
    a version banner; the Python client rejects it (click parses '-version'
    as unknown options). This collision is common on systems where pip's httpx
    is installed -- Kali ships the scanner separately as 'httpx-toolkit'.
    """
    try:
        res = subprocess.run([binary, "-version"], capture_output=True,
                             text=True, timeout=8)
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError):
        return False
    blob = f"{res.stdout}\n{res.stderr}".lower()
    if "no such option" in blob or "usage: httpx <url>" in blob:
        return False   # Python httpx client
    # PD httpx prints e.g. "[INF] Current httpx version v1.6.0"
    return res.returncode == 0 and "version" in blob


def resolve_httpx_binary(tool_statuses: dict) -> Optional[str]:
    # Returning a usable ProjectDiscovery httpx binary path, or None.
    # Prefers the collision-free 'httpx-toolkit', then a verified 'httpx'.
    candidates = []
    alt = shutil.which(HTTPX_ALT_BINARY)
    if alt:
        candidates.append(alt)
    primary = get_binary(tool_statuses, "httpx")
    if primary:
        candidates.append(primary)

    for cand in candidates:
        if _is_pd_httpx(cand):
            return cand

    if primary and not alt:
        log("warning",
            "'httpx' on PATH is the Python HTTP client, not ProjectDiscovery httpx. "
            f"Install the scanner (e.g. 'apt install {HTTPX_ALT_BINARY}' or "
            "'go install github.com/projectdiscovery/httpx/cmd/httpx@latest'). "
            "Falling back to the built-in prober.")
    return None


def _parse_httpx_obj(obj: dict) -> Optional[dict]:
    # Normalizing one ProjectDiscovery httpx JSON object into a service dict.
    # Returning None when there is no usable URL.
    url = obj.get("url") or obj.get("input") or ""
    if not url:
        return None
    status = obj.get("status_code", 0) or 0
    server = obj.get("webserver", "") or ""
    title  = obj.get("title", "") or ""
    tech   = obj.get("tech", []) or obj.get("technologies", []) or []
    cdn    = obj.get("cdn_name", "") or obj.get("cdn", "")
    tls    = obj.get("tls", {}) or {}

    tech_display = list(tech)
    if cdn:
        tech_display.append(f"CDN:{cdn}")
    if title:
        tech_display.append(f"Title:{title[:60]}")
    return {
        "url": url, "status": status, "server": server, "title": title,
        "tech": list(tech), "tech_display": tech_display, "cdn": cdn, "tls": tls,
    }


def _parse_nuclei_obj(obj: dict) -> dict:
    # Normalizing one nuclei JSONL object into a vulnerability finding dict.
    info     = obj.get("info", {}) or {}
    name     = info.get("name", obj.get("template-id", "unknown"))
    severity = info.get("severity", "unknown")
    url      = obj.get("matched-at") or obj.get("host") or obj.get("matched") or ""
    template = obj.get("template-id", "")
    return {"name": name, "severity": severity, "url": url, "template": template}


def _write_url_list(session: ScanSession, urls: list) -> Path:
    # Writing a deduplicated URL list to the nmap subdir for tool -l input.
    path = session.artifact_path("recon", "targets.txt")
    seen, ordered = set(), []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            ordered.append(u)
    path.write_text("\n".join(ordered) + ("\n" if ordered else ""))
    return path


def run_httpx(session: ScanSession, tool_statuses: dict, urls: list) -> dict:
    """
    ProjectDiscovery httpx: fast, accurate probing of the candidate URLs.
    Captures status, page title, detected technologies, web server, CDN, and
    TLS metadata in one pass, enriching the http_services findings.

    Returning {url: parsed_dict}. Empty dict if httpx is unavailable.
    """
    binary = resolve_httpx_binary(tool_statuses)
    if not binary or not urls:
        return {}

    profile   = STEALTH_PROFILES.get(session.stealth_profile, STEALTH_PROFILES[DEFAULT_STEALTH_PROFILE])
    url_file  = _write_url_list(session, urls)
    out_file  = session.artifact_path("recon", "httpx.jsonl")

    cmd = [
        binary,
        "-l", str(url_file),
        "-json",
        "-silent", "-no-color",
        "-status-code", "-title", "-tech-detect",
        "-web-server", "-tls-grab", "-follow-redirects",
        "-timeout", str(REQUEST_TIMEOUT),
        "-threads", str(profile.get("httpx_threads", 10)),
        "-rate-limit", str(profile.get("httpx_rate_limit", 50)),
        "-o", str(out_file),
    ]
    log("info", f"httpx probing {len(urls)} URL(s)...")
    res = _run_tool(cmd, timeout=300)
    if res is None:
        return {}

    parsed = {}
    raw = ""
    if out_file.exists():
        raw = out_file.read_text(errors="replace")
    if not raw.strip():
        raw = res.stdout or ""   # some builds only emit to stdout

    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        rec = _parse_httpx_obj(obj)
        if rec is None:
            continue
        session.add_http_service(rec["url"], rec["status"], rec["server"], rec["tech_display"])
        parsed[rec["url"]] = {
            "status": rec["status"], "server": rec["server"], "title": rec["title"],
            "tech": rec["tech"], "cdn": rec["cdn"], "tls": rec["tls"],
        }

    if parsed:
        log("success", f"httpx confirmed {len(parsed)} live service(s).")
    return parsed


# whatweb plugin keys that are metadata rather than a technology signal
_WHATWEB_NOISE = {
    "ip", "country", "title", "uncommonheaders", "allow", "html5",
    "cookies", "email", "redirectlocation", "meta-refresh-redirect",
}


def run_whatweb(session: ScanSession, tool_statuses: dict, urls: list) -> dict:
    """
    whatweb deep technology fingerprinting. Aggression level scales with the
    stealth profile (1 = passive single request, 3 = follows leads).
    Returning {url: [tech, ...]}. Empty if whatweb is unavailable.
    """
    binary = get_binary(tool_statuses, "whatweb")
    if not binary or not urls:
        return {}

    profile    = STEALTH_PROFILES.get(session.stealth_profile, STEALTH_PROFILES[DEFAULT_STEALTH_PROFILE])
    aggression = profile.get("whatweb_aggression", 1)
    out_file   = session.artifact_path("recon", "whatweb.json")

    cmd = [binary, "--quiet", f"--aggression={aggression}",
           f"--log-json={out_file}"] + list(urls)
    log("info", f"whatweb fingerprinting {len(urls)} URL(s) (aggression={aggression})...")
    if _run_tool(cmd, timeout=240) is None:
        return {}
    if not out_file.exists():
        return {}

    try:
        entries = json.loads(out_file.read_text(errors="replace") or "[]")
    except json.JSONDecodeError:
        log("warning", "  Could not parse whatweb JSON output.")
        return {}

    results = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        target  = entry.get("target", "")
        plugins = entry.get("plugins", {}) or {}
        techs = []
        for name, meta in plugins.items():
            if name.lower() in _WHATWEB_NOISE:
                continue
            version = ""
            if isinstance(meta, dict):
                ver = meta.get("version") or meta.get("string")
                if isinstance(ver, list) and ver:
                    version = str(ver[0])
                elif isinstance(ver, str):
                    version = ver
            techs.append(f"{name}[{version}]" if version else name)
        if target and techs:
            results[target] = techs
            _merge_tech(session, target, techs)
            log("info", f"  {target}: {', '.join(techs[:8])}")
    return results


def _merge_tech(session: ScanSession, url: str, techs: list) -> None:
    # Merging newly-found tech into an existing http_service entry (dedup),
    # or recording it as an event if the service was not already tracked.
    for svc in session.findings["http_services"]:
        if svc["url"].rstrip("/") == url.rstrip("/"):
            existing = svc.setdefault("tech", [])
            for t in techs:
                if t not in existing:
                    existing.append(t)
            return
    session.record("tech_fingerprint", {"url": url, "tech": techs})


def run_wafw00f(session: ScanSession, tool_statuses: dict, urls: list) -> dict:
    """
    wafw00f authoritative WAF fingerprinting. Names the specific WAF product
    where the built-in signature list can only guess. Feeds the same
    waf_detected findings that the auth phase uses to back off hydra.
    Returning {url: firewall_name}. Empty if wafw00f is unavailable.
    """
    binary = get_binary(tool_statuses, "wafw00f")
    if not binary or not urls:
        return {}

    out_file = session.artifact_path("recon", "wafw00f.json")
    cmd = [binary, "-o", str(out_file), "-f", "json"] + list(urls)
    log("info", f"wafw00f checking {len(urls)} URL(s)...")
    if _run_tool(cmd, timeout=180) is None:
        return {}
    if not out_file.exists():
        return {}

    try:
        entries = json.loads(out_file.read_text(errors="replace") or "[]")
    except json.JSONDecodeError:
        return {}

    results = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("detected"):
            continue
        url      = entry.get("url", "")
        firewall = entry.get("firewall", "Unknown")
        vendor   = entry.get("manufacturer", "")
        evidence = f"wafw00f: {firewall}" + (f" ({vendor})" if vendor else "")
        session.add_waf(firewall, evidence)
        results[url] = firewall
    return results


def run_nuclei(
    session: ScanSession,
    tool_statuses: dict,
    urls: list,
    recon_depth: str = DEFAULT_RECON_DEPTH,
) -> list:
    """
    nuclei template-based scanning. Tags and severity floor are driven by the
    recon depth (light = tech only; standard = + exposure/misconfig/default-login;
    deep = + CVE). Rate/concurrency follow the stealth profile. Findings feed the
    vulnerabilities bucket that drives the report's severity charts.
    Returning a list of parsed finding dicts. Empty if nuclei is unavailable.
    """
    binary = get_binary(tool_statuses, "nuclei")
    depth  = _depth_config(recon_depth)
    if not binary or not urls or not depth.get("run_nuclei", True):
        return []

    profile   = STEALTH_PROFILES.get(session.stealth_profile, STEALTH_PROFILES[DEFAULT_STEALTH_PROFILE])
    url_file  = _write_url_list(session, urls)
    out_file  = session.artifact_path("recon", "nuclei.jsonl")

    cmd = [
        binary,
        "-l", str(url_file),
        "-jsonl", "-o", str(out_file),
        "-silent", "-no-color",
        "-disable-update-check",           # keep the template-update table off stdout
        "-rate-limit", str(profile.get("nuclei_rate_limit", 50)),
        "-c", str(profile.get("nuclei_concurrency", 10)),
        "-timeout", str(REQUEST_TIMEOUT),
    ]
    tags = depth.get("nuclei_tags", [])
    if tags:
        cmd += ["-tags", ",".join(tags)]
    severity = depth.get("nuclei_severity", "")
    if severity:
        cmd += ["-severity", severity]

    log("info", f"nuclei scanning {len(urls)} URL(s) | tags={','.join(tags) or 'all'} "
                f"| severity={severity or 'any'}")
    # nuclei can be slow; scale timeout with depth
    tmo = 900 if recon_depth == "deep" else 480
    if _run_tool(cmd, timeout=tmo) is None:
        return []

    findings = []
    if not out_file.exists():
        return findings
    for line in out_file.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        rec = _parse_nuclei_obj(obj)
        session.add_vulnerability(rec["name"], rec["severity"], rec["url"],
                                  source="nuclei", template=rec["template"], matched=rec["url"])
        findings.append(rec)
    log("success", f"nuclei found {len(findings)} finding(s).")
    return findings


def run_tls_scan(session: ScanSession, tool_statuses: dict, https_urls: list) -> dict:
    """
    sslscan TLS / cipher assessment on live HTTPS services. Flags legacy
    protocols (SSLv2/3, TLS 1.0/1.1), weak ciphers, and expired certificates --
    and surfaces certificate SANs, which frequently leak internal hostnames.
    Returning {host:port: tls_dict}. Empty if sslscan is unavailable.
    """
    binary = get_binary(tool_statuses, "sslscan")
    if not binary or not https_urls:
        return {}

    results = {}
    for url in https_urls:
        host = _host_from_url(url)
        port = _extract_port(url)
        target = f"{host}:{port}"
        cmd = [binary, "--no-colour", "--xml=-", target]
        log("info", f"sslscan assessing {target}...")
        res = _run_tool(cmd, timeout=120)
        if res is None or not res.stdout:
            continue
        info = _parse_sslscan_xml(res.stdout)
        if info:
            session.add_tls(url, info)
            results[target] = info
    return results


def _host_from_url(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


def _parse_sslscan_xml(xml_text: str) -> dict:
    # Parsing sslscan --xml output into a compact TLS summary with issue flags.
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    protocols, weak_ciphers, issues = [], [], []
    for proto in root.iter("protocol"):
        if proto.get("enabled") == "1":
            ptype = proto.get("type", "")
            pver  = proto.get("version", "")
            label = f"{ptype}{pver}".upper()
            protocols.append(label)
            if (ptype == "ssl") or (ptype == "tls" and pver in ("1.0", "1.1")):
                issues.append(f"legacy protocol {label}")

    for cipher in root.iter("cipher"):
        strength = (cipher.get("strength", "") or "").lower()
        name     = cipher.get("cipher", "")
        if strength in ("weak", "null", "anonymous"):
            weak_ciphers.append(name)

    cert = {}
    for c in root.iter("certificate"):
        subj = c.findtext("subject")
        if subj:
            cert["subject"] = subj
        not_after = c.findtext("not-valid-after")
        if not_after:
            cert["expires"] = not_after
        expired_flag = (c.findtext("expired") or "").strip().lower()
        if expired_flag in ("true", "1"):
            issues.append("certificate expired")
    if weak_ciphers:
        issues.append(f"{len(weak_ciphers)} weak cipher(s)")

    return {
        "protocols":    protocols,
        "weak_ciphers": weak_ciphers[:20],
        "cert":         cert,
        "issues":       issues,
    }


# Full Recon Pipeline
# Single call that runs the complete recon phase in correct order
def run_recon(
    session: ScanSession,
    tool_statuses: dict,
    port_profile: str = DEFAULT_PORT_PROFILE,
    skip_waf_probe: bool = False,
    recon_depth: str = DEFAULT_RECON_DEPTH,
    custom_ports: list = None,
) -> dict:
    """
    Orchestrating the full recon phase. Real-world tools drive each step when
    present; the built-in probes are the fallback so recon never hard-fails.

        1. nmap port scan (+ NSE http scripts / vuln by depth)
        2. built-in HTTP probe -- liveness gate + passive WAF + tech fallback
        3. httpx      -- fast accurate probe: status, title, tech, CDN, TLS
        4. whatweb    -- deep technology fingerprint
        5. wafw00f    -- authoritative WAF naming (feeds hydra backoff)
        6. nuclei     -- template vuln / exposure / misconfig / CVE scan
        7. TLS scan   -- sslscan cipher / protocol / cert assessment (HTTPS)
        8. WAF evasion probe (active, differential) -- skippable
        9. Banner grabbing on all open ports

    Returning a summary dict consumed by main.py and downstream modules.
    """
    depth = _depth_config(recon_depth)
    log("info", "="*55)
    log("info", f"  RECON PHASE -- target: {session.target['value']}")
    log("info", f"  depth={recon_depth} ({depth['description']})")
    log("info", "="*55)

    # 1. nmap (depth-aware NSE scripts; custom --port overrides the profile)
    nmap_out = run_nmap(session, tool_statuses, port_profile, recon_depth, custom_ports)

    # 2. Built-in probe: confirms liveness, passive WAF, tech fallback
    live_services = probe_http_services(session, custom_ports=custom_ports)
    live_urls = [svc["url"] for svc in live_services]

    # If the built-in probe found nothing but nmap saw web services, still try
    # the external tools against the recorded service URLs.
    if not live_urls and session.findings["http_services"]:
        live_urls = [s["url"] for s in session.findings["http_services"]]

    # 3. httpx -- fast accurate enrichment
    httpx_results = run_httpx(session, tool_statuses, live_urls)

    # 4. whatweb -- deep tech fingerprint
    whatweb_results = run_whatweb(session, tool_statuses, live_urls)

    # 5. wafw00f -- authoritative WAF naming
    wafw00f_results = run_wafw00f(session, tool_statuses, live_urls)

    # 6. nuclei -- template scanning
    nuclei_findings = run_nuclei(session, tool_statuses, live_urls, recon_depth)

    # 7. TLS assessment on HTTPS services (depth-gated)
    tls_results = {}
    if depth.get("run_tls"):
        https_urls = [u for u in live_urls if u.lower().startswith("https://")]
        tls_results = run_tls_scan(session, tool_statuses, https_urls)

    # 8. Active WAF evasion probing (per live service)
    waf_evasion_results = {}
    if not skip_waf_probe and live_services:
        log("info", "Running active WAF evasion probes...")
        for svc in live_services:
            evasion = probe_waf_evasion(svc["url"])
            waf_evasion_results[svc["url"]] = evasion

    # 9. Banner grabbing
    banners = grab_all_banners(session)

    summary = {
        "recon_depth":     recon_depth,
        "open_ports":      session.findings["open_ports"],
        "http_services":   session.findings["http_services"],
        "waf_detected":    session.findings["waf_detected"],
        "vulnerabilities": session.findings["vulnerabilities"],
        "tls":             session.findings["tls"],
        "httpx":           httpx_results,
        "whatweb":         whatweb_results,
        "wafw00f":         wafw00f_results,
        "nuclei":          nuclei_findings,
        "tls_scan":        tls_results,
        "waf_evasion":     waf_evasion_results,
        "banners":         banners,
        "nmap_file":       str(nmap_out),
    }

    log("success", "Recon phase complete.")
    return summary
