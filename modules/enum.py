# Enumeration module — three attack surfaces, one module:
#
#   1. Directory/file enumeration     (gobuster dir)
#   2. Virtual host enumeration       (gobuster vhost)
#   3. Subdomain enumeration          (gobuster dns)
#
# All runs are stealth-profile aware (threads, delay).
# Admin page detection is regex-driven, not fragile grep string matching.
# Output is parsed and fed into ScanSession — no raw files left behind.
#
# Fixes from original:
#   - grep overwrite bug (>> vs >) eliminated — parsing done in Python
#   - admin_pages.txt race condition eliminated
#   - subprocess arg lists — no injection
#   - HTTPS support — not hardcoded to http://
#   - Status code filtering (200, 301, 302, 403 all useful)

import re
import subprocess
from pathlib import Path
from typing import Optional

from config.settings import (
    STEALTH_PROFILES,
    DEFAULT_STEALTH_PROFILE,
    resolve_wordlist,
)
from core.session import ScanSession, log
from core.tools_manager import get_binary


# =============================================================================
# ADMIN PAGE PATTERNS
# Regex-based — catches more variants than the original's two hardcoded strings
# =============================================================================

ADMIN_PATTERNS = [
    re.compile(r"/(admin|administrator|admins|adm)(/|$)", re.IGNORECASE),
    re.compile(r"/(login|signin|sign-in|auth|authenticate)(/|$)", re.IGNORECASE),
    re.compile(r"/(dashboard|controlpanel|cpanel|panel|backend)(/|$)", re.IGNORECASE),
    re.compile(r"/(wp-admin|wp-login|drupal/user|joomla/administrator)", re.IGNORECASE),
    re.compile(r"/(manager|management|manage|admin-panel)", re.IGNORECASE),
    re.compile(r"\.(php|asp|aspx|jsp|cgi)$", re.IGNORECASE),  # any script extension is notable
]

INTERESTING_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".cgi",
    ".bak", ".old", ".backup", ".config", ".conf",
    ".xml", ".json", ".yaml", ".env", ".sql",
    ".log", ".txt", ".zip", ".tar", ".gz",
]

INTERESTING_PATTERNS = [
    re.compile(r"\.(bak|old|backup|orig|save|swp|tmp)$", re.IGNORECASE),
    re.compile(r"/(config|configuration|settings|setup|install|setup)(/|$)", re.IGNORECASE),
    re.compile(r"/(api|v1|v2|v3|graphql|swagger|openapi)(/|$)", re.IGNORECASE),
    re.compile(r"/(\.git|\.env|\.htaccess|\.htpasswd|robots\.txt|sitemap\.xml)", re.IGNORECASE),
]

# Gobusster Output Parser
# Handles both gobuster dir and dns output formats
def _parse_gobuster_dir(output: str) -> list[dict]:
    # Parsing gobuster dir mode output.
    # Example line: "/admin                (Status: 200) [Size: 1234]"
    # Returning list of dicts: {path, status, size, url}
    results = []
    # Modern gobuster format: "/path  (Status: NNN) [Size: NNN]"
    line_re = re.compile(
        r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?",
        re.IGNORECASE
    )
    for line in output.splitlines():
        line = line.strip()
        m = line_re.match(line)
        if m:
            results.append({
                "path":   m.group(1),
                "status": int(m.group(2)),
                "size":   int(m.group(3)) if m.group(3) else 0,
            })
    return results

# Gobuster dns Parser
def _parse_gobuster_dns(output: str) -> list[str]:
    # Parsing gobuster dns mode output
    # Example line: "Found: sub.target.com"
    # Returning list of subdomain strings.
    subdomains = []
    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("found:"):
            sub = line.split(":", 1)[1].strip()
            subdomains.append(sub)
    return subdomains

# Gobuster vhost Parser
def _parse_gobuster_vhost(output: str) -> list[dict]:
    # Parsing gobuster vhost mode output
    # Example line: "Found: dev.target.com (Status: 200) [Size: 2048]"
    # Returning list of dicts: {vhost, status, size}
    results = []
    line_re = re.compile(
        r"Found:\s*(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?",
        re.IGNORECASE
    )
    for line in output.splitlines():
        m = line_re.search(line)
        if m:
            results.append({
                "vhost":  m.group(1),
                "status": int(m.group(2)),
                "size":   int(m.group(3)) if m.group(3) else 0,
            })
    return results

# Directory enumeration
def run_dir_enum(
    session: ScanSession,
    tool_statuses: dict,
    base_url: str,
    wordlist_key: str = "dirs_medium",
    custom_wordlist: Optional[str] = None,
    extra_extensions: Optional[list] = None,
) -> list[dict]:
    """
    Running gobuster dir mode against base_url

    Wordlist resolution order:
        1. custom_wordlist if explicitly provided
        2. resolve_wordlist(wordlist_key) from settings
        3. Prompt user if neither found on disk

    Stealth profile controls threads and inter-request delay.
    Results parsed in Python (no grep, no temp grep files).

    Returning list of discovered path dicts, also fed into session.
    """
    gobuster_bin = get_binary(tool_statuses, "gobuster")
    profile      = STEALTH_PROFILES.get(
        session.stealth_profile, STEALTH_PROFILES[DEFAULT_STEALTH_PROFILE]
    )

    # Resolving wordlist
    wordlist = custom_wordlist or resolve_wordlist(wordlist_key)
    if not wordlist:
        log("warning", f"Wordlist '{wordlist_key}' not found at any configured path.")
        wordlist = input("  Enter full path to wordlist manually: ").strip()
        if not wordlist:
            log("error", "No wordlist provided — skipping directory enumeration.")
            return []

    # Extensions to probe — combine defaults with any extras
    default_ext = ",".join(e.lstrip(".") for e in INTERESTING_EXTENSIONS[:6])
    if extra_extensions:
        default_ext += "," + ",".join(e.lstrip(".") for e in extra_extensions)

    out_file = session.artifact_path("gobuster", "dir_enum.txt")

    log("info", f"Directory enumeration: {base_url}")
    log("info", f"  Wordlist : {wordlist}")
    log("info", f"  Threads  : {profile['gobuster_threads']}")
    log("info", f"  Delay    : {profile['gobuster_delay']}")
    log("info", f"  Exts     : {default_ext}")

    cmd = [
        gobuster_bin, "dir",
        "-u", base_url,
        "-w", wordlist,
        "-t", str(profile["gobuster_threads"]),
        "-x", default_ext,
        "-o", str(out_file),
        "--no-error",             # suppress individual connection errors
        "-q",                     # quiet — less noise
    ]

    # Apply delay only if non-zero
    if profile["gobuster_delay"] != "0ms":
        cmd += ["--delay", profile["gobuster_delay"]]

    # Status codes to report — include 403 (may indicate protected resources)
    cmd += ["-s", "200,201,204,301,302,307,401,403"]

    log("info", f"  Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,  # 30 min max for large wordlists
        )
        raw_output = result.stdout
    except subprocess.TimeoutExpired:
        log("error", "gobuster dir timed out.")
        return []
    except FileNotFoundError:
        log("error", "gobuster not found.")
        return []

    # Parsing results
    entries = _parse_gobuster_dir(raw_output)

    if not entries:
        # Also trying reading from output file if stdout was empty
        if out_file.exists():
            entries = _parse_gobuster_dir(out_file.read_text(errors="replace"))

    log("success", f"Directory enum complete: {len(entries)} paths found.")

    # Classifying results and feed into session
    for entry in entries:
        full_url = base_url.rstrip("/") + entry["path"]
        entry["url"] = full_url

        # Feed into session directories
        session.add_directory(full_url, entry["status"], entry["size"])

        # Checking for admin/sensitive pages
        if _is_admin_page(entry["path"]):
            session.add_admin_page(full_url, entry["status"])
            log("found", f"Admin/login page detected: {full_url} [{entry['status']}]")

        # Checking for interesting/sensitive files
        if _is_interesting(entry["path"]):
            log("found", f"Interesting file: {full_url} [{entry['status']}] size={entry['size']}")
            session.record("interesting_file", {
                "url": full_url, "status": entry["status"], "size": entry["size"]
            })

    return entries


def _is_admin_page(path: str) -> bool:
    # Returning True if the path matches any admin/auth pattern
    return any(p.search(path) for p in ADMIN_PATTERNS)


def _is_interesting(path: str) -> bool:
    # Returning True if the path matches any sensitive file pattern
    return any(p.search(path) for p in INTERESTING_PATTERNS)

# Virtual Host Enumeration
def run_vhost_enum(
    session: ScanSession,
    tool_statuses: dict,
    base_url: str,
    wordlist_key: str = "vhosts",
    custom_wordlist: Optional[str] = None,
) -> list[dict]:
    # Running gobuster vhost mode to discover virtual hosts on the target
    # Critical for finding dev/staging/admin subdomains on shared hosting.

    # Returning list of vhost dicts.
    gobuster_bin = get_binary(tool_statuses, "gobuster")
    profile      = STEALTH_PROFILES.get(
        session.stealth_profile, STEALTH_PROFILES[DEFAULT_STEALTH_PROFILE]
    )

    wordlist = custom_wordlist or resolve_wordlist(wordlist_key)
    if not wordlist:
        log("warning", "No vhost wordlist found — skipping vhost enumeration.")
        return []

    # Extracting domain from base_url for gobuster
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    domain = parsed.hostname

    out_file = session.artifact_path("gobuster", "vhost_enum.txt")

    log("info", f"Virtual host enumeration: {base_url}")
    log("info", f"  Domain   : {domain}")
    log("info", f"  Wordlist : {wordlist}")
    log("info", f"  Threads  : {profile['gobuster_threads']}")

    cmd = [
        gobuster_bin, "vhost",
        "-u", base_url,
        "-w", wordlist,
        "-t", str(profile["gobuster_threads"]),
        "--append-domain",    # appending domain to each word (gobuster >=3.2)
        "-o", str(out_file),
        "-q",
        "--no-error",
    ]

    if profile["gobuster_delay"] != "0ms":
        cmd += ["--delay", profile["gobuster_delay"]]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        entries = _parse_gobuster_vhost(result.stdout)
    except subprocess.TimeoutExpired:
        log("error", "gobuster vhost timed out.")
        return []

    log("success", f"Vhost enum complete: {len(entries)} virtual hosts found.")

    for entry in entries:
        session.record("vhost_found", entry)
        log("found", f"Vhost: {entry['vhost']} [{entry['status']}]")

    return entries

# Subdomain Enumeration
def run_subdomain_enum(
    session: ScanSession,
    tool_statuses: dict,
    domain: str,
    wordlist_key: str = "subdomains",
    custom_wordlist: Optional[str] = None,
) -> list[str]:
    # Running gobuster dns mode to discover subdomains
    # Only applicable when target is a domain (not a bare IP).

    # Returning list of discovered subdomain strings.
    if session.target["type"] != "domain":
        log("warning", "Subdomain enumeration only works against domain targets — skipping.")
        return []

    gobuster_bin = get_binary(tool_statuses, "gobuster")
    profile      = STEALTH_PROFILES.get(
        session.stealth_profile, STEALTH_PROFILES[DEFAULT_STEALTH_PROFILE]
    )

    wordlist = custom_wordlist or resolve_wordlist(wordlist_key)
    if not wordlist:
        log("warning", "No subdomain wordlist found — skipping subdomain enumeration.")
        return []

    out_file = session.artifact_path("gobuster", "subdomain_enum.txt")

    log("info", f"Subdomain enumeration: {domain}")
    log("info", f"  Wordlist : {wordlist}")
    log("info", f"  Threads  : {profile['gobuster_threads']}")

    cmd = [
        gobuster_bin, "dns",
        "-d", domain,
        "-w", wordlist,
        "-t", str(profile["gobuster_threads"]),
        "-o", str(out_file),
        "-q",
        "--no-error",
    ]

    if profile["gobuster_delay"] != "0ms":
        cmd += ["--delay", profile["gobuster_delay"]]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        subdomains = _parse_gobuster_dns(result.stdout)
        if not subdomains and out_file.exists():
            subdomains = _parse_gobuster_dns(out_file.read_text(errors="replace"))
    except subprocess.TimeoutExpired:
        log("error", "gobuster dns timed out.")
        return []

    log("success", f"Subdomain enum complete: {len(subdomains)} subdomains found.")

    for sub in subdomains:
        session.record("subdomain_found", {"subdomain": sub})
        log("found", f"Subdomain: {sub}")

    return subdomains

# Full Enumeration Pipeline
def run_enum(
    session: ScanSession,
    tool_statuses: dict,
    wordlist_size: str = "medium",     # "small" | "medium" | "large"
    run_vhost: bool = True,
    run_subdomains: bool = True,
) -> dict:
    """
    Orchestrating the full enumeration phase against all live HTTP services
    discovered during recon

    For each live service:
        - Directory/file enumeration
        - Virtual host enumeration (if run_vhost=True)

    If target is a domain:
        - Subdomain enumeration (if run_subdomains=True)

    Returning summary dict consumed by main.py and downstream modules
    """
    log("info", "="*55)
    log("info", f"  ENUM PHASE — target: {session.target['value']}")
    log("info", "="*55)

    wordlist_key = f"dirs_{wordlist_size}"
    all_dirs     = []
    all_vhosts   = []
    all_subs     = []

    services = session.findings["http_services"]
    if not services:
        log("warning", "No HTTP services found to enumerate. Run recon first.")
        return {"dirs": [], "vhosts": [], "subdomains": []}

    for svc in services:
        url = svc["url"]
        log("info", f"Enumerating: {url}")

        # Directory enumeration
        dirs = run_dir_enum(session, tool_statuses, url, wordlist_key)
        all_dirs.extend(dirs)

        # Vhost enumeration
        if run_vhost:
            vhosts = run_vhost_enum(session, tool_statuses, url)
            all_vhosts.extend(vhosts)

    # Subdomain enumeration (domain targets only)
    if run_subdomains and session.target["type"] == "domain":
        all_subs = run_subdomain_enum(
            session, tool_statuses, session.target["value"]
        )

    log("success", "Enum phase complete.")
    log("success",
        f"  Dirs: {len(all_dirs)}  |  "
        f"Admin pages: {len(session.findings['admin_pages'])}  |  "
        f"Vhosts: {len(all_vhosts)}  |  "
        f"Subdomains: {len(all_subs)}"
    )

    return {
        "dirs":       all_dirs,
        "vhosts":     all_vhosts,
        "subdomains": all_subs,
    }
