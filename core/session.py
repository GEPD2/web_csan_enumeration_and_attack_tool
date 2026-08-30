# Scan session lifecycle management:
#   - timestamped output directories per target
#   - structured event logging (JSON lines + console)
#   - artifact tracking so cleanup never misses a file
#   - graceful teardown even on SIGINT / crash

import os
import json
import signal
import shutil
import atexit
import logging
import datetime
from pathlib import Path
from typing import Optional

from config.settings import OUTPUT_BASE_DIR

# Console Format
# Color-coded severity levels for terminal output
class _Colors:
    RESET  = "\033[0m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    GREY   = "\033[90m"
    BOLD   = "\033[1m"

_PREFIX = {
    "info":    f"{_Colors.CYAN}[*]{_Colors.RESET}",
    "success": f"{_Colors.GREEN}[+]{_Colors.RESET}",
    "warning": f"{_Colors.YELLOW}[!]{_Colors.RESET}",
    "error":   f"{_Colors.RED}[✗]{_Colors.RESET}",
    "debug":   f"{_Colors.GREY}[~]{_Colors.RESET}",
    "attack":  f"{_Colors.RED}{_Colors.BOLD}[»]{_Colors.RESET}",
    "found":   f"{_Colors.GREEN}{_Colors.BOLD}[★]{_Colors.RESET}",
}

def log(level: str, message: str) -> None:
    """
    Print a color-coded message to the console.
    level: "info" | "success" | "warning" | "error" | "debug" | "attack" | "found"
    """
    prefix = _PREFIX.get(level, _PREFIX["info"])
    print(f"{prefix} {message}")

# One ScanSession per run or per target in multi-target mode
class ScanSession:
    """
    Manages all I/O for a single scan run against one target.

    Directory layout created under OUTPUT_BASE_DIR:
        <target>_<timestamp>/
            session.json        ← metadata + event log
            nmap/               ← nmap raw output files
            gobuster/           ← gobuster raw output files
            hydra/              ← hydra raw output files
            shells/             ← generated shell payloads
            report/             ← final HTML / JSON reports
    """

    SUBDIRS = ["nmap", "recon", "gobuster", "hydra", "shells", "report"]

    def __init__(self, target: dict, stealth_profile: str = "stealth"):
        self.target          = target
        self.stealth_profile = stealth_profile
        self.started_at      = datetime.datetime.utcnow()
        self.events: list    = []          # structured event log
        self.artifacts: list = []          # all files written this session
        self.findings: dict  = {           # aggregated discoveries
            "open_ports":     [],
            "http_services":  [],
            "waf_detected":   [],
            "directories":    [],
            "admin_pages":    [],
            "credentials":    [],
            "shells":         [],
            "vulnerabilities": [],         # nuclei / nmap-vuln / nikto findings
            "tls":             [],         # per-service TLS / cipher assessment
        }

        # Build session directory
        ts     = self.started_at.strftime("%Y%m%d_%H%M%S")
        safe   = target["value"].replace(".", "_").replace(":", "_")
        self.session_dir = Path(OUTPUT_BASE_DIR) / f"{safe}_{ts}"
        self._init_directories()

        # File-based structured log (JSON Lines format)
        self.session_log_path = self.session_dir / "session.json"
        self._write_session_header()

        # Register cleanup handlers
        atexit.register(self._finalize)
        signal.signal(signal.SIGINT, self._handle_sigint)

        log("info", f"Session started → {self.session_dir}")

    # Directory setup
    def _init_directories(self) -> None:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        for sub in self.SUBDIRS:
            (self.session_dir / sub).mkdir(exist_ok=True)

    def subdir(self, name: str) -> Path:
        # Returning the Path object for a named subdirectory
        return self.session_dir / name

    def artifact_path(self, subdir: str, filename: str) -> Path:
        """
        Building a full path for an output artifact, registering it for tracking and returning the Path object.

        Usage:
            path = session.artifact_path("nmap", "initial_scan.txt")
            os.system(f"nmap ... > {path}")
        """
        full_path = self.session_dir / subdir / filename
        self.artifacts.append(str(full_path))
        return full_path

    # Structured Event Logging
    def _write_session_header(self) -> None:
        header = {
            "type":     "session_start",
            "target":   self.target,
            "profile":  self.stealth_profile,
            "started":  self.started_at.isoformat(),
        }
        with open(self.session_log_path, "w") as f:
            f.write(json.dumps(header) + "\n")

    def record(self, event_type: str, data: dict) -> None:
        # Appending a structured event to the session log, event_type examples: "nmap_result", "waf_detected", "credential_found"
        event = {
            "type":      event_type,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "data":      data,
        }
        self.events.append(event)
        with open(self.session_log_path, "a") as f:
            f.write(json.dumps(event) + "\n")

    # Findings Aggregation
    # Calling these from modules to feed the final report
    def add_open_port(self, port: int, protocol: str, service: str, version: str = "") -> None:
        entry = {"port": port, "protocol": protocol, "service": service, "version": version}
        self.findings["open_ports"].append(entry)
        self.record("open_port", entry)
        log("found", f"Open port: {port}/{protocol} → {service} {version}".strip())

    def add_http_service(self, url: str, status: int, server: str = "", tech: list = None) -> None:
        tech = tech or []
        # Merge into an existing entry for the same URL (nmap seeds status 0,
        # the prober/httpx later fill in the real status, server, and tech) so
        # a single service is never counted twice.
        for entry in self.findings["http_services"]:
            if entry["url"].rstrip("/") == url.rstrip("/"):
                if status:
                    entry["status"] = status
                if server:
                    entry["server"] = server
                for t in tech:
                    if t not in entry["tech"]:
                        entry["tech"].append(t)
                self.record("http_service", entry)
                return
        entry = {"url": url, "status": status, "server": server, "tech": tech}
        self.findings["http_services"].append(entry)
        self.record("http_service", entry)
        log("found", f"HTTP service: {url} [{status}] server={server}")

    def add_waf(self, waf_name: str, evidence: str) -> None:
        entry = {"waf": waf_name, "evidence": evidence}
        self.findings["waf_detected"].append(entry)
        self.record("waf_detected", entry)
        log("warning", f"WAF detected: {waf_name} (evidence: {evidence})")

    def add_directory(self, url: str, status: int, size: int = 0) -> None:
        entry = {"url": url, "status": status, "size": size}
        self.findings["directories"].append(entry)
        self.record("directory_found", entry)
        log("found", f"Directory: {url} [{status}]")

    def add_admin_page(self, url: str, status: int) -> None:
        entry = {"url": url, "status": status}
        self.findings["admin_pages"].append(entry)
        self.record("admin_page_found", entry)
        log("found", f"Admin page: {url} [{status}]")

    def add_credential(self, username: str, password: str, url: str) -> None:
        entry = {"username": username, "password": password, "url": url}
        self.findings["credentials"].append(entry)
        self.record("credential_found", entry)
        log("found", f"Credential: {username}:{password} @ {url}")

    def add_shell(self, shell_type: str, path: str) -> None:
        entry = {"type": shell_type, "path": path}
        self.findings["shells"].append(entry)
        self.record("shell_generated", entry)
        log("success", f"Shell payload written: {path} [{shell_type}]")

    def add_vulnerability(
        self,
        name: str,
        severity: str,
        url: str,
        source: str = "nuclei",
        template: str = "",
        matched: str = "",
    ) -> None:
        # Recording a vulnerability / exposure / misconfiguration finding.
        # severity: "critical" | "high" | "medium" | "low" | "info" | "unknown"
        entry = {
            "name":     name,
            "severity": (severity or "unknown").lower(),
            "url":      url,
            "source":   source,
            "template": template,
            "matched":  matched,
        }
        self.findings["vulnerabilities"].append(entry)
        self.record("vulnerability", entry)
        level = "attack" if entry["severity"] in ("critical", "high") else "found"
        log(level, f"[{entry['severity'].upper()}] {name} @ {url} ({source})")

    def add_tls(self, url: str, data: dict) -> None:
        # Recording a TLS / cipher assessment for one HTTPS service.
        # data typically holds keys such as protocols, weak_ciphers, cert, issues.
        entry = {"url": url, **data}
        self.findings["tls"].append(entry)
        self.record("tls_info", entry)
        issues = data.get("issues", [])
        if issues:
            log("warning", f"TLS issues on {url}: {', '.join(issues[:3])}")
        else:
            log("info", f"TLS assessed: {url}")

    # Summary Print
    def print_summary(self) -> None:
        print(f"\n{_Colors.BOLD}{'='*60}{_Colors.RESET}")
        print(f"{_Colors.BOLD}  SCAN SUMMARY — {self.target['value']}{_Colors.RESET}")
        print(f"{'='*60}")
        print(f"  Open ports    : {len(self.findings['open_ports'])}")
        print(f"  HTTP services : {len(self.findings['http_services'])}")
        print(f"  WAF detected  : {len(self.findings['waf_detected'])}")
        print(f"  Vulnerabilities: {len(self.findings['vulnerabilities'])}")
        print(f"  TLS assessed  : {len(self.findings['tls'])}")
        print(f"  Directories   : {len(self.findings['directories'])}")
        print(f"  Admin pages   : {len(self.findings['admin_pages'])}")
        print(f"  Credentials   : {len(self.findings['credentials'])}")
        print(f"  Shells staged : {len(self.findings['shells'])}")
        elapsed = datetime.datetime.utcnow() - self.started_at
        print(f"\n  Duration      : {str(elapsed).split('.')[0]}")
        print(f"  Output dir    : {self.session_dir}")
        print(f"{'='*60}\n")

    # Cleanup & Finalization
    def _finalize(self) -> None:
        # Called on normal exit via atexit and Writes session close event.
        # Guarded so a removed/unwritable session dir (e.g. cleaned up in tests
        # or on a full disk) never raises from an atexit callback.
        if getattr(self, "_finalized", False):
            return
        self._finalized = True
        closed_at = datetime.datetime.utcnow()
        footer = {
            "type":     "session_end",
            "ended":    closed_at.isoformat(),
            "findings": self.findings,
        }
        try:
            with open(self.session_log_path, "a") as f:
                f.write(json.dumps(footer) + "\n")
        except OSError:
            return
        self.print_summary()

    def _handle_sigint(self, signum, frame) -> None:
        # Handling Ctrl+C gracefully by flushing session log and exit cleanly. No dangling temp files, no partial state
        print()
        log("warning", "Caught SIGINT — flushing session and exiting cleanly.")
        self._finalize()
        raise SystemExit(0)

    def cleanup_temp(self, paths: list[str] = None) -> None:
        # Explicitly deleting a list of temp file paths
        targets = paths or [
            p for p in self.artifacts
            if p.startswith("/tmp") or p.endswith((".tmp", ".temp"))
        ]
        for p in targets:
            try:
                os.remove(p)
                log("debug", f"Removed temp file: {p}")
            except FileNotFoundError:
                pass
            except PermissionError:
                log("warning", f"Could not remove: {p}")

# Multy Target Session Manager
# Wraping multiple ScanSession objects for multi target runs
class MultiTargetSession:
    # Orchestrating parallel or sequential scan sessions for a list of targets
    # Each target gets its own ScanSession and output directory
    def __init__(self, targets: list[dict], stealth_profile: str = "stealth"):
        self.targets         = targets
        self.stealth_profile = stealth_profile
        self.sessions: dict  = {}   # target_value → ScanSession
        self.started_at      = datetime.datetime.utcnow()

    def create_session(self, target: dict) -> ScanSession:
        # Creating and registering a ScanSession for a single target
        session = ScanSession(target, self.stealth_profile)
        self.sessions[target["value"]] = session
        return session

    def get_session(self, target_value: str) -> Optional[ScanSession]:
        return self.sessions.get(target_value)

    def all_findings(self) -> dict:
        # Aggregating findings across all sessions for a combined report
        combined = {}
        for target_val, session in self.sessions.items():
            combined[target_val] = session.findings
        return combined
