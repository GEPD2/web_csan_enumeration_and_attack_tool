import re
import socket
import ipaddress
from urllib.parse import urlparse
from config.settings import (
    VALID_IP_REGEX,
    VALID_DOMAIN_REGEX,
    VALID_URL_REGEX,
    VALID_PORT_RANGE,
    SHELL_INJECTION_CHARS,
)

class ValidationError(Exception):
    # Raised when input fails validation. Caller decides how to handle
    pass

# CORE SANITIZATION
def sanitize_input(raw: str) -> str:
    # Striping whitespace and rejecting any input containing shell metacharacters. 
    # This is the first line of defense against command injection called before every os.system-subprocess call. Raises ValidationError on detection.
    cleaned = raw.strip()
    for bad in SHELL_INJECTION_CHARS:
        if bad in cleaned:
            raise ValidationError(
                f"Rejected: input contains forbidden character sequence '{bad}'. "
                f"Possible shell injection attempt."
            )
    return cleaned

def sanitize_path(raw: str) -> str:
    # Validating a filesystem path supplied by the user (e.g. wordlist path).
    # Preventing path traversal attacks and shell injection in file args.
    cleaned = sanitize_input(raw)
    # Rejecting null bytes
    if "\x00" in cleaned:
        raise ValidationError("Rejected: null byte in path.")
    # Allowing absolute and relative paths but block traversal sequences
    if ".." in cleaned.split("/"):
        raise ValidationError("Rejected: path traversal sequence detected.")
    return cleaned

# target validation
def validate_ip(raw: str) -> str:
    # Validating an IPv4 address. Returns the cleaned IP string.
    # Raising ValidationError if invalid.
    cleaned = sanitize_input(raw)
    if not VALID_IP_REGEX.match(cleaned):
        raise ValidationError(f"'{cleaned}' is not a valid IPv4 address.")
    return cleaned

# Validating a domain name (e.g. target.com, sub.target.com).
def validate_domain(raw: str) -> str:
    # Returns the cleaned domain string.
    cleaned = sanitize_input(raw).lower()
    if not VALID_DOMAIN_REGEX.match(cleaned):
        raise ValidationError(f"'{cleaned}' is not a valid domain name.")
    return cleaned

# Accept either an IP or a domain. It returns a dict with: value, type and resolved or it raises ValidationError on failure
def validate_target(raw: str) -> dict:
    cleaned = sanitize_input(raw)

    # Trying IP first
    if VALID_IP_REGEX.match(cleaned):
        _check_private_scope(cleaned)
        return {"value": cleaned, "type": "ip", "resolved": cleaned}

    # Trying domain
    if VALID_DOMAIN_REGEX.match(cleaned.lower()):
        try:
            resolved = socket.gethostbyname(cleaned)
        except socket.gaierror:
            raise ValidationError(
                f"Cannot resolve domain '{cleaned}'. "
                f"Check spelling or DNS connectivity."
            )
        _check_private_scope(resolved)
        return {"value": cleaned.lower(), "type": "domain", "resolved": resolved}

    raise ValidationError(
        f"'{cleaned}' is neither a valid IP address nor a valid domain name."
    )

# Validating a full URL (http or https). It returns cleaned URL string
def validate_url(raw: str) -> str:
    # Raising ValidationError if the URL is malformed.
    cleaned = sanitize_input(raw)
    if not VALID_URL_REGEX.match(cleaned):
        raise ValidationError(
            f"'{cleaned}' is not a valid URL. Must start with http:// or https://"
        )
    parsed = urlparse(cleaned)
    if not parsed.scheme or not parsed.netloc:
        raise ValidationError(f"Malformed URL: missing scheme or host in '{cleaned}'.")
    return cleaned

# Validate a TCP port number. It accepts string or int
def validate_port(raw: str | int) -> int:
    # Returning the port as int or raise ValidationError if out of range
    try:
        port = int(str(raw).strip())
    except ValueError:
        raise ValidationError(f"'{raw}' is not a valid port number.")
    lo, hi = VALID_PORT_RANGE
    if not (lo <= port <= hi):
        raise ValidationError(
            f"Port {port} is out of range. Must be between {lo} and {hi}."
        )
    return port

# Validating the attacker's LHOST (must be a valid IP, not a domain, since reverse shell connections go to an IP, not a hostname in most cases)
def validate_lhost(raw: str) -> str:
    return validate_ip(raw)

# Multi target support using a file
def validate_target_file(path: str) -> list[dict]:
    # Parsing a file containing one target (IP or domain) per line
    # Returning a list of validated target dicts (same format as validate_target)
    # Lines starting with # or empty lines are skipped
    cleaned_path = sanitize_path(path)
    try:
        with open(cleaned_path, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        raise ValidationError(f"Target file not found: '{cleaned_path}'")
    except PermissionError:
        raise ValidationError(f"Permission denied reading: '{cleaned_path}'")

    targets = []
    errors  = []
    for i, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            targets.append(validate_target(line))
        except ValidationError as e:
            errors.append(f"  Line {i}: {e}")

    if errors:
        print("[!] Some targets in the file failed validation:")
        for err in errors:
            print(err)
    # Raising ValidationError if the file cannot be read or is empty
    if not targets:
        raise ValidationError(
            f"No valid targets found in '{cleaned_path}'. "
            f"Check the file format (one IP or domain per line)."
        )

    return targets

# Warning-blocking scans against loopback, RFC1918, or known critical infra
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

def _check_private_scope(ip: str) -> None:
    """
    Emit a warning (not a hard block) when targeting private/loopback ranges.
    Red teamers often target internal nets — this is informational only.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return  # Not a parseable IP — skip check
    for net in _PRIVATE_NETWORKS:
        if addr in net:
            print(
                f"[~] WARNING: Target {ip} is in a private/loopback range ({net}). "
                f"Ensure you have explicit authorization."
            )
            return

# Displaying target list and requires explicit user confirmation before any active scanning begins
def confirm_scope(targets: list[dict]) -> bool:
    # Returning True if confirmed, False if aborted
    print("\n" + "="*60)
    print("  SCOPE CONFIRMATION — READ CAREFULLY")
    print("="*60)
    print(f"  You are about to actively scan the following target(s):\n")
    for t in targets:
        resolved_note = (
            f"  → resolves to {t['resolved']}" if t["type"] == "domain" else ""
        )
        print(f"    [{t['type'].upper()}]  {t['value']}{resolved_note}")
    print(
        "\n  Unauthorized scanning is illegal. Confirm you have written\n"
        "  authorization for all listed targets.\n"
    )
    print("="*60)
    answer = input("  Type 'YES' to confirm scope and continue: ").strip()
    return answer == "YES"

# Determine http or https based on port. Falling back to probing with a basic socket connect if port is ambiguous
def resolve_protocol(target_value: str, port: int) -> str:
    from config.settings import HTTP_PORTS, HTTPS_PORTS
    if port in HTTPS_PORTS:
        return "https"
    if port in HTTP_PORTS:
        return "http"
    # Ambiguous port — trying HTTPS first, falling back to HTTP
    try:
        import ssl
        ctx = ssl.create_default_context()
        with socket.create_connection((target_value, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_value):
                return "https"
    except Exception:
        return "http"

# Constructing a base URL from a validated target dict and port
def build_base_url(target: dict, port: int) -> str:
    # Automatically selecting http/https
    proto = resolve_protocol(target["value"], port)
    host  = target["value"]
    # Omit default ports for cleaner URLs
    from config.settings import HTTP_PORTS, HTTPS_PORTS
    if (proto == "http" and port == 80) or (proto == "https" and port == 443):
        return f"{proto}://{host}"
    # Example output https://10.0.0.1:443
    return f"{proto}://{host}:{port}"