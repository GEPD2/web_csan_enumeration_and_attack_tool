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
import socket
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

from config.settings import (
    STEALTH_PROFILES,
    DEFAULT_STEALTH_PROFILE,
    PORT_PROFILES,
    DEFAULT_PORT_PROFILE,
    ALL_WEB_PORTS,
    HTTP_PORTS,
    HTTPS_PORTS,
    WAF_SIGNATURES,
    WAF_BLOCK_CODES,
    DEFAULT_HEADERS,
    REQUEST_TIMEOUT,
)
from core.session import ScanSession, log
from core.tools_manager import get_binary

# Nmap scanning
def run_nmap(
    session: ScanSession,
    tool_statuses: dict,
    port_profile: str = DEFAULT_PORT_PROFILE,
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

    # Appending port spec
    cmd += port_arg.split()

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
def probe_http_services(session: ScanSession) -> list[dict]:
    """
    For each HTTP service found by nmap (or from ALL_WEB_PORTS as fallback),
    sending a HEAD + GET request to:
        - Confirm the service is actually responding
        - Capture real HTTP status, Server header, and tech stack
        - Feed WAF detection
        - Auto-detect HTTPS vs HTTP

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

# Full Recon Pipeline
# Single call that runs the complete recon phase in correct order
def run_recon(
    session: ScanSession,
    tool_statuses: dict,
    port_profile: str = DEFAULT_PORT_PROFILE,
    skip_waf_probe: bool = False,
) -> dict:
    """
    Orchestrating the full recon phase:
        1. nmap port scan
        2. http/https service probing + tech fingerprinting
        3. WAF detection (passive, from probe responses)
        4. WAF evasion probe (active, on each live service) — skippable
        5. Banner grabbing on all open ports

    Returning a summary dict consumed by main.py and downstream modules.
    """
    log("info", "="*55)
    log("info", f"  RECON PHASE — target: {session.target['value']}")
    log("info", "="*55)

    # 1. nmap
    nmap_out = run_nmap(session, tool_statuses, port_profile)

    # 2. http probing + passive WAF detection
    live_services = probe_http_services(session)

    # 3. Active WAF evasion probing (per live service)
    waf_evasion_results = {}
    if not skip_waf_probe and live_services:
        log("info", "Running active WAF evasion probes...")
        for svc in live_services:
            evasion = probe_waf_evasion(svc["url"])
            waf_evasion_results[svc["url"]] = evasion

    # 4. Banner grabbing
    banners = grab_all_banners(session)

    summary = {
        "open_ports":    session.findings["open_ports"],
        "http_services": live_services,
        "waf_detected":  session.findings["waf_detected"],
        "waf_evasion":   waf_evasion_results,
        "banners":       banners,
        "nmap_file":     str(nmap_out),
    }

    log("success", "Recon phase complete.")
    return summary
