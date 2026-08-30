# web_csan — Web Enumeration and Attack Tool v2.0
# Entry point: argument parsing, phase orchestration, multi-target support
#
# Usage examples:
#   python3 main.py -t 10.0.0.1
#   python3 main.py -t target.com --profile ghost --ports web_only
#   python3 main.py -T targets.txt --profile stealth --wordlist medium
#   python3 main.py -t 10.0.0.1 --skip-exploit --report html
#   python3 main.py -t 10.0.0.1 --phase recon          (recon only)
#   python3 main.py -t 10.0.0.1 --phase recon,enum      (recon + enum)

import sys
import argparse
import platform

from config.settings import (
    STEALTH_PROFILES,
    PORT_PROFILES,
    DEFAULT_STEALTH_PROFILE,
    DEFAULT_PORT_PROFILE,
    RECON_DEPTH_PROFILES,
    DEFAULT_RECON_DEPTH,
    REPORT_FORMATS,
    REPORT_ALL_FORMATS,
)
from core.session     import log, ScanSession, MultiTargetSession
from core.validator   import (
    validate_target, validate_target_file, confirm_scope, ValidationError
)
from core.tools_manager import ensure_tools

from modules.recon   import run_recon
from modules.enum    import run_enum
from modules.auth    import run_auth
from modules.exploit import run_exploit
from modules.report  import generate_reports

# BANNER
BANNER = r"""
  ██╗    ██╗███████╗██████╗      ██████╗███████╗ █████╗ ███╗   ██╗
  ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║ █╗ ██║█████╗  ██████╔╝    ██║     ███████╗███████║██╔██╗ ██║
  ██║███╗██║██╔══╝  ██╔══██╗    ██║     ╚════██║██╔══██║██║╚██╗██║
  ╚███╔███╔╝███████╗██████╔╝    ╚██████╗███████║██║  ██║██║ ╚████║
   ╚══╝╚══╝ ╚══════╝╚═════╝      ╚═════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝

  Web Enumeration & Attack Tool v2.0
  For authorized penetration testing only.
"""

PHASES_ALL = ["recon", "enum", "auth", "exploit", "report"]

# Argument Parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web_csan",
        description="Web enumeration and attack tool for authorized engagements.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -t 10.10.10.10
  python3 main.py -t target.com --profile ghost --ports full
  python3 main.py -T targets.txt --profile stealth
  python3 main.py -t 10.10.10.10 --phase recon,enum
  python3 main.py -t 10.10.10.10 --skip-auth --skip-exploit --report json
        """
    )

    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--target",
        metavar="IP/DOMAIN",
        help="Single target IP address or domain name."
    )
    target_group.add_argument(
        "-T", "--target-file",
        metavar="FILE",
        help="File containing one target per line (IPs or domains)."
    )

    # Stealth profile
    parser.add_argument(
        "--profile",
        choices=list(STEALTH_PROFILES.keys()),
        default=DEFAULT_STEALTH_PROFILE,
        metavar="PROFILE",
        help=(
            "Stealth/timing profile. "
            f"Choices: {list(STEALTH_PROFILES.keys())}. "
            f"Default: {DEFAULT_STEALTH_PROFILE}"
        )
    )

    # Port profile
    parser.add_argument(
        "--ports",
        choices=list(PORT_PROFILES.keys()),
        default=DEFAULT_PORT_PROFILE,
        metavar="PORT_PROFILE",
        help=(
            f"Port scan scope. Choices: {list(PORT_PROFILES.keys())}. "
            f"Default: {DEFAULT_PORT_PROFILE}"
        )
    )

    # Custom target port(s)
    parser.add_argument(
        "--port", "--target-port",
        dest="port",
        metavar="PORTS",
        help=(
            "Scan specific port(s) instead of a --ports profile. "
            "Comma-separated, e.g. '8420' or '8080,8443'. "
            "Scheme (http/https) is auto-detected."
        )
    )

    # Recon depth
    parser.add_argument(
        "--recon-depth",
        choices=list(RECON_DEPTH_PROFILES.keys()),
        default=DEFAULT_RECON_DEPTH,
        metavar="DEPTH",
        help=(
            "How much active recon to run (nuclei tags, NSE scripts, TLS). "
            f"Choices: {list(RECON_DEPTH_PROFILES.keys())}. "
            f"Default: {DEFAULT_RECON_DEPTH}"
        )
    )

    # Phase control
    parser.add_argument(
        "--phase",
        metavar="PHASES",
        help=(
            "Comma-separated list of phases to run. "
            f"Available: {','.join(PHASES_ALL)}. "
            "Default: all phases."
        )
    )
    parser.add_argument("--skip-recon",   action="store_true", help="Skip recon phase.")
    parser.add_argument("--skip-enum",    action="store_true", help="Skip enumeration phase.")
    parser.add_argument("--skip-auth",    action="store_true", help="Skip auth brute-force phase.")
    parser.add_argument("--skip-exploit", action="store_true", help="Skip exploit phase.")

    # Wordlist size
    parser.add_argument(
        "--wordlist",
        choices=["small", "medium", "large"],
        default="medium",
        help="Wordlist size for dir enumeration. Default: medium."
    )

    # Report
    parser.add_argument(
        "--report",
        choices=REPORT_FORMATS + ["all"],
        default="all",
        help=f"Report format(s). Choices: {REPORT_FORMATS + ['all']}. "
             "Default: all (json + html + markdown + csv)."
    )

    # Extra options
    parser.add_argument(
        "--no-vhost",      action="store_true", help="Skip virtual host enumeration."
    )
    parser.add_argument(
        "--no-subdomain",  action="store_true", help="Skip subdomain enumeration."
    )
    parser.add_argument(
        "--skip-waf-probe",action="store_true", help="Skip active WAF evasion probe."
    )
    parser.add_argument(
        "--yes",           action="store_true",
        help="Auto-confirm scope (use with caution — skips the safety prompt)."
    )
    parser.add_argument(
        "--debug",         action="store_true", help="Enable debug output."
    )

    return parser

# Custom port parsing
def parse_custom_ports(raw: str) -> list:
    # Parsing a comma-separated --port value into a validated list of ints.
    # Exiting with an error on any out-of-range or non-numeric entry.
    if not raw:
        return None
    ports = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit():
            log("error", f"Invalid port '{chunk}' — ports must be numeric.")
            sys.exit(1)
        p = int(chunk)
        if not (1 <= p <= 65535):
            log("error", f"Port {p} out of range (1-65535).")
            sys.exit(1)
        ports.append(p)
    return ports or None


# Phase Rersolver
def resolve_phases(args: argparse.Namespace) -> list[str]:
    # Determining which phases to run based on --phase, --skip-* flags, and defaults
    # Returning ordered list of phase names
    if args.phase:
        requested = [p.strip().lower() for p in args.phase.split(",")]
        invalid = [p for p in requested if p not in PHASES_ALL]
        if invalid:
            log("error", f"Unknown phase(s): {invalid}. Valid: {PHASES_ALL}")
            sys.exit(1)
        return requested

    # Starting with all phases, removing skipped ones
    phases = list(PHASES_ALL)
    if args.skip_recon:   phases.remove("recon")
    if args.skip_enum:    phases.remove("enum")
    if args.skip_auth:    phases.remove("auth")
    if args.skip_exploit: phases.remove("exploit")

    return phases

# Single Target Scan
def scan_target(
    target: dict,
    phases: list[str],
    args: argparse.Namespace,
    tool_statuses: dict,
) -> None:
    # Running all requested phases against a single validated target
    session = ScanSession(target, stealth_profile=args.profile)

    # Determining report formats
    report_formats = (
        list(REPORT_ALL_FORMATS) if args.report == "all"
        else [args.report]
    )

    # Recon
    if "recon" in phases:
        run_recon(
            session, tool_statuses,
            port_profile=args.ports,
            skip_waf_probe=args.skip_waf_probe,
            recon_depth=args.recon_depth,
            custom_ports=getattr(args, "custom_ports", None),
        )

    # Enumeration
    if "enum" in phases:
        if not session.findings["http_services"] and "recon" not in phases:
            log("warning",
                "No HTTP services in session — enum phase may find nothing. "
                "Consider running recon first."
            )
        run_enum(
            session, tool_statuses,
            wordlist_size=args.wordlist,
            run_vhost=not args.no_vhost,
            run_subdomains=not args.no_subdomain,
        )

    # Authentication
    if "auth" in phases:
        if not session.findings["admin_pages"] and "enum" not in phases:
            log("warning",
                "No admin pages in session — auth phase may find nothing. "
                "Consider running enum first."
            )
        run_auth(
            session, tool_statuses,
            wordlist_size=args.wordlist,
        )

    # Exploit
    if "exploit" in phases:
        run_exploit(session, tool_statuses)

    # Report
    if "report" in phases:
        generate_reports(session, formats=report_formats)

    # Session finalized automatically via atexit in ScanSession.__init__

# Multy Target Orchestration
def scan_multiple(
    targets: list[dict],
    phases: list[str],
    args: argparse.Namespace,
    tool_statuses: dict,
) -> None:
    """
    Running scans sequentially against a list of targets
    Each gets its own session directory and report

    Note: parallel execution (ThreadPoolExecutor) intentionally omitted here —
    parallelism + stealth profiles is a contradiction. Adding if needed for lab use.
    """
    log("info", f"Multi-target scan: {len(targets)} target(s) queued.")

    for i, target in enumerate(targets, start=1):
        log("info", f"\n[{i}/{len(targets)}] Scanning: {target['value']}")
        try:
            scan_target(target, phases, args, tool_statuses)
        except KeyboardInterrupt:
            log("warning", f"Scan of {target['value']} interrupted. Moving to next.")
            continue
        except Exception as e:
            log("error", f"Unexpected error scanning {target['value']}: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
            continue

# Main
def main() -> None:
    # OS checking — Linux only (nmap, gobuster, hydra are Linux tools)
    if platform.system() != "Linux":
        print("[✗] This tool requires Linux. Detected: " + platform.system())
        sys.exit(1)

    print(BANNER)

    parser = build_parser()
    args   = parser.parse_args()

    # Tool verification
    # ensure_tools() now returns (statuses, SystemProfile) for OS-aware modules
    tool_statuses, sys_profile = ensure_tools()
    log("info", f"Package manager: {sys_profile.pkg_manager.cmd_base or sys_profile.pkg_manager.windows_mgr or 'n/a'}")

    # Target resolution
    try:
        if args.target:
            targets = [validate_target(args.target)]
        else:
            targets = validate_target_file(args.target_file)
    except ValidationError as e:
        log("error", str(e))
        sys.exit(1)

    # Phase resolution
    phases = resolve_phases(args)

    # Custom port resolution (validated early so bad input fails fast)
    args.custom_ports = parse_custom_ports(args.port)

    # Stealth profile info
    profile_info = STEALTH_PROFILES[args.profile]
    log("info", f"Stealth profile : {args.profile} — {profile_info['description']}")
    log("info", f"Recon depth     : {args.recon_depth} — {RECON_DEPTH_PROFILES[args.recon_depth]['description']}")
    if args.custom_ports:
        log("info", f"Custom ports    : {','.join(str(p) for p in args.custom_ports)} (overrides --ports)")
    log("info", f"Phases          : {' → '.join(phases)}")
    log("info", f"Targets         : {len(targets)}")

    # Scope confirmation
    if not args.yes:
        if not confirm_scope(targets):
            log("warning", "Scope not confirmed. Exiting.")
            sys.exit(0)
    else:
        log("warning", "--yes flag set: scope confirmation bypassed.")

    # Execute
    if len(targets) == 1:
        scan_target(targets[0], phases, args, tool_statuses)
    else:
        scan_multiple(targets, phases, args, tool_statuses)


if __name__ == "__main__":
    main()
