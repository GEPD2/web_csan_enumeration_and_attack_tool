# Tool detection, version checking, and cross-platform installation management
#
# Supported package managers (auto-detected):
#   Linux  → apt      (Debian / Ubuntu / Kali / Parrot / Mint / Pop!_OS)
#            dnf/yum  (Fedora / RHEL / CentOS / Rocky / AlmaLinux / Nobara)
#            pacman   (Arch / Manjaro / EndeavourOS / Garuda / BlackArch)
#            zypper   (openSUSE Leap & Tumbleweed / SLES)
#            xbps     (Void Linux)
#            apk      (Alpine Linux)
#            eopkg    (Solus)
#            emerge   (Gentoo) ← flagged as manual (too complex to automate safely)
#   macOS  → brew (Homebrew)
#   Windows → winget → chocolatey (choco) → scoop  (first available wins)
#
# Key design decisions:
#   - Per-tool, per-distro-family package name mapping
#     (hydra on suse = thc-hydra, gobuster rarely in default repos → go install)
#   - __go_install__ sentinel: install via `go install` when no repo package exists
#   - __manual__    sentinel: no automated path, print distro-specific instructions
#   - shutil.which() for all detection — no NUL files, no shell=True
#   - All install commands via subprocess arg lists
#   - Optional tools degrade gracefully (None returned, callers handle it)
#   - ensure_tools() returns (statuses, SystemProfile)

import os
import sys
import shutil
import platform
import subprocess
from dataclasses import dataclass
from typing import Optional

from config.settings import TOOL_BINARIES, MANDATORY_TOOLS, OPTIONAL_TOOLS
from core.session import log

# Data model
@dataclass
class ToolStatus:
    name:      str
    binary:    str
    available: bool          = False
    version:   str           = "unknown"
    path:      Optional[str] = None
    mandatory: bool          = True

# OS and distro detection
class SystemProfile:
    #Detecting the current OS, Linux distro family, and available package manager
    """
    Attributes:
        os_name       : "linux" | "windows" | "macos" | "unknown"
        distro_id     : raw /etc/os-release ID  (e.g. "kali", "arch", "void")
        distro_family : normalized family key   (e.g. "debian", "arch", "void")
        pkg_manager   : PackageManager instance for this system
        is_root       : True if running as root / Administrator
    """

    def __init__(self):
        raw_os = platform.system().lower()

        if raw_os == "linux":
            self.os_name = "linux"
            self.distro_id, self.distro_family = self._detect_linux_distro()
        elif raw_os == "darwin":
            self.os_name      = "macos"
            self.distro_id    = "macos"
            self.distro_family = "macos"
        elif raw_os == "windows":
            self.os_name      = "windows"
            self.distro_id    = "windows"
            self.distro_family = "windows"
        else:
            self.os_name      = "unknown"
            self.distro_id    = raw_os
            self.distro_family = "unknown"

        self.pkg_manager = PackageManager(self)
        self.is_root     = self._check_root()

    # Linux distro detection
    def _detect_linux_distro(self) -> tuple[str, str]:
        # Parsing /etc/os-release
        # Falling back to probing package manager binaries if os-release is absent
        os_release: dict[str, str] = {}
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line:
                        k, _, v = line.partition("=")
                        os_release[k.strip()] = v.strip().strip('"').lower()
        except FileNotFoundError:
            pass

        distro_id = os_release.get("id", "unknown")
        id_like   = os_release.get("id_like", "")
        family    = self._map_to_family(distro_id, id_like)
        return distro_id, family

    def _map_to_family(self, distro_id: str, id_like: str) -> str:
        # Mapping a distro ID (or id_like ancestry chain) to a package-manager family
        # id_like may contain multiple space-separated values e.g. "ubuntu debian"
        DIRECT: dict[str, str] = {
            # Debian / apt 
            "debian": "debian",    "ubuntu": "debian",   "kali": "debian",
            "parrot": "debian",    "mint": "debian",      "pop": "debian",
            "elementary": "debian","zorin": "debian",     "mx": "debian",
            "raspbian": "debian",  "linuxmint": "debian", "lmde": "debian",
            "tails": "debian",     "whonix": "debian",    "backbox": "debian",
            # Fedora / dnf / yum
            "fedora": "fedora",    "rhel": "fedora",      "centos": "fedora",
            "rocky": "fedora",     "almalinux": "fedora", "alma": "fedora",
            "ol": "fedora",        "nobara": "fedora",    "eln": "fedora",
            "scientific": "fedora","eurolinux": "fedora",
            # Arch / pacman
            "arch": "arch",        "manjaro": "arch",     "endeavouros": "arch",
            "artix": "arch",       "garuda": "arch",      "blackarch": "arch",
            "cachyos": "arch",     "archcraft": "arch",   "xerolinux": "arch",
            # openSUSE / zypper
            "opensuse": "suse",    "opensuse-leap": "suse",
            "opensuse-tumbleweed": "suse",  "sles": "suse",
            # Void / xbps
            "void": "void",
            # Alpine / apk
            "alpine": "alpine",
            # Solus / eopkg
            "solus": "solus",
            # Gentoo / emerge
            "gentoo": "gentoo",
            # Slackware
            "slackware": "slackware",
        }

        if distro_id in DIRECT:
            return DIRECT[distro_id]

        # Walking the id_like ancestry chain
        for ancestor in id_like.split():
            if ancestor in DIRECT:
                return DIRECT[ancestor]

        # Last resort: probing for binary presence
        for binary, family in [
            ("apt-get",       "debian"),
            ("dnf",           "fedora"),
            ("yum",           "fedora"),
            ("pacman",        "arch"),
            ("zypper",        "suse"),
            ("xbps-install",  "void"),
            ("apk",           "alpine"),
            ("eopkg",         "solus"),
            ("emerge",        "gentoo"),
        ]:
            if shutil.which(binary):
                return family

        return "unknown"

    # Root detection
    def _check_root(self) -> bool:
        if self.os_name == "windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

    def __str__(self) -> str:
        root_tag = "root" if self.is_root else "user"
        return (
            f"os={self.os_name}  distro={self.distro_id}  "
            f"family={self.distro_family}  priv={root_tag}"
        )

# Per-tool, per-family correct package names.
# Sentinels:
#   __go_install__  : installing via `go install <GO_INSTALL_PATHS[tool]>`
#   __manual__      : no automated install; print instructions

PACKAGE_NAMES: dict[str, dict[str, str]] = {
    "nmap": {
        "debian":    "nmap",
        "fedora":    "nmap",
        "arch":      "nmap",
        "suse":      "nmap",
        "void":      "nmap",
        "alpine":    "nmap",
        "solus":     "nmap",
        "gentoo":    "__manual__",     # emerge net-analyzer/nmap
        "slackware": "__manual__",
        "macos":     "nmap",
        "windows":   "Insecure.Nmap", # winget ID
    },
    "gobuster": {
        # Not reliably in most default repos — go install is the safe universal path
        "debian":    "__go_install__",
        "fedora":    "__go_install__",
        "arch":      "gobuster",       # available in BlackArch / AUR
        "suse":      "__go_install__",
        "void":      "__go_install__",
        "alpine":    "__go_install__",
        "solus":     "__go_install__",
        "gentoo":    "__manual__",
        "slackware": "__manual__",
        "macos":     "gobuster",       # homebrew
        "windows":   "__go_install__",
    },
    "hydra": {
        "debian":    "hydra",
        "fedora":    "hydra",
        "arch":      "hydra",
        "suse":      "thc-hydra",      # openSUSE uses thc-hydra
        "void":      "thc-hydra",
        "alpine":    "__manual__",     # not in Alpine repos
        "solus":     "__manual__",
        "gentoo":    "__manual__",
        "slackware": "__manual__",
        "macos":     "hydra",
        "windows":   "__manual__",     # no native Windows build; use WSL
    },
    "grep": {
        # Preinstalled everywhere on Linux/macOS; macOS ships BSD grep → brew gives GNU
        "debian":    "grep",
        "fedora":    "grep",
        "arch":      "grep",
        "suse":      "grep",
        "void":      "grep",
        "alpine":    "grep",
        "solus":     "grep",
        "gentoo":    "grep",
        "slackware": "grep",
        "macos":     "grep",           # brew install grep (GNU version)
        "windows":   "__manual__",     # use WSL2 or Git Bash
    },
    "curl": {
        "debian":    "curl",
        "fedora":    "curl",
        "arch":      "curl",
        "suse":      "curl",
        "void":      "curl",
        "alpine":    "curl",
        "solus":     "curl",
        "gentoo":    "__manual__",
        "slackware": "__manual__",
        "macos":     "curl",
        "windows":   "cURL.cURL",      # winget ID
    },
    "whatweb": {
        "debian":    "whatweb",
        "fedora":    "__manual__",     # gem install whatweb
        "arch":      "whatweb",        # AUR
        "suse":      "__manual__",
        "void":      "__manual__",
        "alpine":    "__manual__",
        "solus":     "__manual__",
        "gentoo":    "__manual__",
        "slackware": "__manual__",
        "macos":     "whatweb",
        "windows":   "__manual__",
    },
    "nc": {
        "debian":    "netcat-openbsd",
        "fedora":    "nmap-ncat",      # Fedora ships ncat as part of nmap
        "arch":      "openbsd-netcat",
        "suse":      "netcat-openbsd",
        "void":      "netcat",
        "alpine":    "netcat-openbsd",
        "solus":     "netcat",
        "gentoo":    "__manual__",
        "slackware": "__manual__",
        "macos":     "netcat",
        "windows":   "__manual__",     # install nmap for Windows → use ncat.exe
    },
}

# winget IDs (Windows only) — overrides PACKAGE_NAMES for winget path
WINGET_IDS: dict[str, str] = {
    "nmap":    "Insecure.Nmap",
    "curl":    "cURL.cURL",
    "grep":    "__manual__",
    "gobuster":"__go_install__",
    "hydra":   "__manual__",
    "whatweb": "__manual__",
    "nc":      "__manual__",
}

# Go module paths for __go_install__ tools
GO_INSTALL_PATHS: dict[str, str] = {
    "gobuster": "github.com/OJ/gobuster/v3@latest",
}

# Packge Manager Abstraction
class PackageManager:
    # Wraping package installation for any supported system
    #Detecting which manager is available and handles install command construction
    # Base install commands per family (first available binary wins)
    FAMILY_CMDS: dict[str, list[list[str]]] = {
        "debian":    [["apt-get", "install", "-y"], ["apt", "install", "-y"]],
        "fedora":    [["dnf",     "install", "-y"], ["yum", "install", "-y"]],
        "arch":      [["pacman",  "-S", "--noconfirm"]],
        "suse":      [["zypper",  "install", "-y"]],
        "void":      [["xbps-install", "-Sy"]],
        "alpine":    [["apk",     "add", "--no-cache"]],
        "solus":     [["eopkg",   "install", "-y"]],
        "gentoo":    [],   # emerge: not automated
        "slackware": [],   # slackpkg: not automated here
        "macos":     [["brew", "install"]],
        "windows":   [],   # handled via winget/choco/scoop
        "unknown":   [],
    }

    def __init__(self, sys_profile: "SystemProfile"):
        self.profile      = sys_profile
        self.family       = sys_profile.distro_family
        self.cmd_base     = self._resolve_base_cmd()
        self.windows_mgr  = self._detect_windows_mgr()

    def _resolve_base_cmd(self) -> Optional[list[str]]:
        # Returning first available package manager command list for this family
        for cmd in self.FAMILY_CMDS.get(self.family, []):
            if shutil.which(cmd[0]):
                return cmd
        return None

    def _detect_windows_mgr(self) -> Optional[str]:
        # On Windows, returning first available package manager name
        if self.profile.os_name != "windows":
            return None
        for mgr in ("winget", "choco", "scoop"):
            if shutil.which(mgr):
                return mgr
        return None

    def is_available(self) -> bool:
        if self.profile.os_name == "windows":
            return self.windows_mgr is not None
        return self.cmd_base is not None

    def needs_sudo(self) -> bool:
        return (
            self.profile.os_name == "linux"
            and not self.profile.is_root
        )

    def resolve_package_name(self, tool_name: str) -> str:
        # Returning correct package name for this tool on this family
        return PACKAGE_NAMES.get(tool_name, {}).get(self.family, tool_name)

    # Main dispatcher
    def install(self, tool_name: str) -> bool:
        pkg_name = self.resolve_package_name(tool_name)

        if pkg_name == "__manual__":
            return self._handle_manual(tool_name)
        if pkg_name == "__go_install__":
            return self._go_install(tool_name)
        if self.profile.os_name == "windows":
            return self._windows_install(tool_name, pkg_name)
        if self.profile.os_name == "macos":
            return self._brew_install(pkg_name)
        return self._linux_install(pkg_name)

    # Linux
    def _linux_install(self, pkg_name: str) -> bool:
        if not self.cmd_base:
            log("error",
                f"No package manager found for family '{self.family}'. "
                f"Install '{pkg_name}' manually."
            )
            return False

        cmd = (["sudo"] if self.needs_sudo() else []) + self.cmd_base + [pkg_name]
        log("info", f"  $ {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, timeout=180)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            log("error", f"Install timed out for '{pkg_name}'.")
            return False
        except FileNotFoundError:
            log("error", f"Package manager binary not found: {self.cmd_base[0]}")
            return False

    # macOS / Homebrew
    def _brew_install(self, pkg_name: str) -> bool:
        if not shutil.which("brew"):
            log("error",
                "Homebrew not found.\n"
                "  Install from: https://brew.sh\n"
                "  /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/"
                "Homebrew/install/HEAD/install.sh)\""
            )
            return False
        try:
            result = subprocess.run(["brew", "install", pkg_name], timeout=300)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            log("error", f"brew install timed out for '{pkg_name}'.")
            return False

    # Windows
    def _windows_install(self, tool_name: str, pkg_name: str) -> bool:
        mgr = self.windows_mgr
        if not mgr:
            log("error",
                "No package manager found on Windows.\n"
                "  Options:\n"
                "    winget  — built into Windows 11 / Windows 10 (updated)\n"
                "    choco   — https://chocolatey.org/install\n"
                "    scoop   — https://scoop.sh\n"
                "  Or run this tool in WSL2 for full Linux tool support."
            )
            return False

        if mgr == "winget":
            winget_id = WINGET_IDS.get(tool_name, pkg_name)
            if winget_id == "__manual__":
                return self._handle_manual(tool_name)
            if winget_id == "__go_install__":
                return self._go_install(tool_name)
            cmd = [
                "winget", "install",
                "--id", winget_id,
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ]
        elif mgr == "choco":
            cmd = ["choco", "install", pkg_name, "-y"]
        elif mgr == "scoop":
            cmd = ["scoop", "install", pkg_name]
        else:
            return False

        log("info", f"  $ {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, timeout=300)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            log("error", f"Windows install timed out for '{pkg_name}'.")
            return False

    # Go install
    def _go_install(self, tool_name: str) -> bool:
        go_path = GO_INSTALL_PATHS.get(tool_name)
        if not go_path:
            log("error", f"No go install path configured for '{tool_name}'.")
            return False

        if not shutil.which("go"):
            log("error",
                f"'go' runtime not found — required for installing {tool_name}.\n"
                f"  Install Go: https://go.dev/dl/\n"
                f"  Then: go install {go_path}"
            )
            return False

        # Ensuring $GOPATH/bin is on PATH so the binary is found after install
        gopath_bin = os.path.join(
            os.environ.get("GOPATH",
                           os.path.join(os.path.expanduser("~"), "go")),
            "bin"
        )
        if gopath_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = gopath_bin + os.pathsep + os.environ.get("PATH", "")
            log("info", f"  Added {gopath_bin} to PATH for this session.")

        cmd = ["go", "install", go_path]
        log("info", f"  $ {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, timeout=300)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            log("error", f"go install timed out for '{tool_name}'.")
            return False

    # Manual
    def _handle_manual(self, tool_name: str) -> bool:
        instructions = _manual_instructions(tool_name, self.family)
        log("warning",
            f"'{tool_name}' cannot be auto-installed on {self.family}.\n"
            f"  Manual install guide:\n{instructions}"
        )
        return False

# Manual installation instructions
def _manual_instructions(tool_name: str, family: str) -> str:
    INSTRUCTIONS: dict[str, dict[str, str]] = {
        "gobuster": {
            "gentoo":    "    emerge --ask net-analyzer/gobuster  (check overlays first)",
            "slackware": "    Download binary: https://github.com/OJ/gobuster/releases",
            "default":   "    go install github.com/OJ/gobuster/v3@latest\n"
                         "    Ensure $GOPATH/bin (~/.go/bin) is in your PATH.",
        },
        "hydra": {
            "windows":   "    Hydra has no native Windows build.\n"
                         "    Use WSL2 with Ubuntu or Kali:\n"
                         "      wsl --install -d kali-linux\n"
                         "      sudo apt install hydra",
            "alpine":    "    Compile from source:\n"
                         "      apk add git make gcc openssl-dev\n"
                         "      git clone https://github.com/vanhauser-thc/thc-hydra\n"
                         "      cd thc-hydra && ./configure && make && make install",
            "default":   "    Compile from source:\n"
                         "      git clone https://github.com/vanhauser-thc/thc-hydra\n"
                         "      cd thc-hydra && ./configure && make && sudo make install",
        },
        "nc": {
            "windows":   "    Install nmap for Windows (includes ncat.exe):\n"
                         "      winget install Insecure.Nmap\n"
                         "    Then alias: set NC=C:\\Program Files (x86)\\Nmap\\ncat.exe",
            "gentoo":    "    emerge --ask net-analyzer/netcat",
            "default":   "    Debian/Ubuntu : sudo apt install netcat-openbsd\n"
                         "    Fedora        : sudo dnf install nmap-ncat\n"
                         "    Arch          : sudo pacman -S openbsd-netcat",
        },
        "whatweb": {
            "default":   "    gem install whatweb   (requires Ruby)\n"
                         "    Or: git clone https://github.com/urbanadventurer/WhatWeb\n"
                         "        cd WhatWeb && gem install bundler && bundle install",
        },
        "grep": {
            "windows":   "    Install Git for Windows (includes GNU grep):\n"
                         "      winget install Git.Git\n"
                         "    Or install WSL2: wsl --install",
            "slackware": "    grep is bundled with Slackware — check your installation.",
            "default":   "    grep should be pre-installed. If missing, reinstall coreutils.",
        },
        "nmap": {
            "gentoo":    "    emerge --ask net-analyzer/nmap",
            "slackware": "    Download from: https://nmap.org/download.html",
            "default":   "    See: https://nmap.org/download.html",
        },
    }
    tool_entry = INSTRUCTIONS.get(tool_name, {})
    return tool_entry.get(family, tool_entry.get("default", "    No instructions available — check the project's GitHub."))

# Tool Detection
def _detect_tool(name: str, binary: str) -> ToolStatus:
    path      = shutil.which(binary)
    mandatory = name in MANDATORY_TOOLS

    if path is None:
        return ToolStatus(name=name, binary=binary, available=False, mandatory=mandatory)

    version = _get_version(binary)
    return ToolStatus(name=name, binary=binary, available=True,
                      version=version, path=path, mandatory=mandatory)


def _get_version(binary: str) -> str:
    for flag in ["--version", "-version", "version", "-V"]:
        try:
            result = subprocess.run(
                [binary, flag],
                capture_output=True, text=True, timeout=5,
            )
            output = (result.stdout or result.stderr or "").strip()
            if output:
                return output.splitlines()[0]
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            continue
    return "unknown"

# Tool check table
def check_all_tools(sys_profile: SystemProfile) -> dict[str, ToolStatus]:
    # Detecting all configured tools and printing a status table
    # Showing the package name that would be used for install on this system
    statuses: dict[str, ToolStatus] = {}
    all_tools = list(MANDATORY_TOOLS) + list(OPTIONAL_TOOLS)

    sys_str = str(sys_profile)
    print(f"\n  ┌{'─'*55}┐")
    print(f"  │{'TOOL AVAILABILITY CHECK':^55}│")
    print(f"  │  {sys_str:<53}│")
    print(f"  └{'─'*55}┘")

    for name in all_tools:
        binary  = TOOL_BINARIES.get(name, name)
        status  = _detect_tool(name, binary)
        statuses[name] = status

        icon     = "✓" if status.available else "✗"
        req_tag  = "[req]" if status.mandatory else "[opt]"
        color    = (
            "\033[92m" if status.available else
            "\033[91m" if status.mandatory else
            "\033[93m"
        )
        reset    = "\033[0m"

        if status.available:
            right_col = status.version[:36]
        else:
            pkg = sys_profile.pkg_manager.resolve_package_name(name)
            right_col = f"NOT FOUND  →  install: {pkg}"

        print(f"  {color}{icon}{reset}  {name:<12} {req_tag:<6}  {right_col}")

    print()
    return statuses

# Installation Orchestration
def install_missing(
    statuses: dict[str, ToolStatus],
    sys_profile: SystemProfile,
) -> dict[str, bool]:
    # Prompting and installing missing mandatory tools using the detected package manager
    missing_mandatory = [s for s in statuses.values() if not s.available and s.mandatory]
    missing_optional  = [s for s in statuses.values() if not s.available and not s.mandatory]
    results: dict[str, bool] = {}

    if missing_optional:
        log("warning", "Optional tools not found (reduced functionality):")
        for s in missing_optional:
            pkg = sys_profile.pkg_manager.resolve_package_name(s.name)
            log("warning", f"  - {s.name:<12}  package: {pkg}")

    if not missing_mandatory:
        log("success", "All mandatory tools present. Ready to operate.")
        return results

    log("warning", f"{len(missing_mandatory)} mandatory tool(s) missing:")
    for s in missing_mandatory:
        pkg = sys_profile.pkg_manager.resolve_package_name(s.name)
        log("warning", f"  - {s.name:<12}  package: {pkg}")

    # OS-specific advisories
    if sys_profile.os_name == "windows":
        log("warning",
            "Running on Windows. Pentest tool support is limited.\n"
            "  Recommendation: use WSL2 with Kali Linux for full functionality.\n"
            "  wsl --install -d kali-linux"
        )
    elif sys_profile.distro_family == "gentoo":
        log("warning",
            "Gentoo detected — automated emerge installation is not supported.\n"
            "  See per-tool manual instructions above."
        )
    elif sys_profile.distro_family in ("slackware", "unknown"):
        log("warning",
            f"Distribution family '{sys_profile.distro_family}' has limited automated install support."
        )

    if not sys_profile.pkg_manager.is_available():
        log("error",
            "No supported package manager detected. Install tools manually and rerun."
        )
        sys.exit(1)

    mgr_display = (
        sys_profile.pkg_manager.cmd_base[0]
        if sys_profile.pkg_manager.cmd_base
        else sys_profile.pkg_manager.windows_mgr or "?"
    )
    answer = input(f"\n  Install missing tools via {mgr_display}? [y/N]: ").strip().lower()
    if answer not in ("y", "yes"):
        log("error", "Installation declined. Cannot continue without mandatory tools.")
        sys.exit(1)

    if sys_profile.pkg_manager.needs_sudo():
        print("  You may be prompted for your sudo password.\n")

    for status in missing_mandatory:
        log("info", f"Installing {status.name}...")
        success = sys_profile.pkg_manager.install(status.name)

        if success:
            refreshed = _detect_tool(status.name, status.binary)
            if refreshed.available:
                log("success", f"  ✓ {status.name} installed and verified  ({refreshed.version[:40]})")
                results[status.name] = True
            else:
                log("error",
                    f"  {status.name} install completed but binary not found on PATH.\n"
                    f"  You may need to open a new shell or manually add the install "
                    f"  directory to your PATH."
                )
                results[status.name] = False
        else:
            log("error", f"  {status.name} installation failed.")
            results[status.name] = False

    failed = [n for n, ok in results.items() if not ok]
    if failed:
        log("error", f"Could not install: {', '.join(failed)}")
        log("error", "Resolve manually and rerun the tool.")
        sys.exit(1)

    return results

# primary entry point
def ensure_tools() -> tuple[dict[str, ToolStatus], SystemProfile]:
    """
    Full pre-flight gate. Calling this once from main.py.
    Steps:
        1. Detect OS, distro family, package manager
        2. Check all tool availability
        3. Prompt and install any missing mandatory tools
        4. Final re-verification pass
        5. Abort if any critical tool still unresolvable
    Returns:
        (final_statuses, sys_profile)
        sys_profile is passed to modules that need OS-aware behaviour
        (e.g. exploit.py skips PowerShell shells on Linux).
    """
    sys_profile = SystemProfile()
    log("info", f"System profile: {sys_profile}")

    statuses = check_all_tools(sys_profile)
    install_missing(statuses, sys_profile)

    # Final re-detection after any installs
    final: dict[str, ToolStatus] = {}
    for name in statuses:
        binary = TOOL_BINARIES.get(name, name)
        final[name] = _detect_tool(name, binary)

    missing_critical = [n for n, s in final.items() if s.mandatory and not s.available]
    if missing_critical:
        log("error", f"Critical tools still missing: {missing_critical}")
        log("error", "Cannot continue. Resolve manually and rerun.")
        sys.exit(1)

    return final, sys_profile

# Convenience Accessor
def get_binary(tool_statuses: dict[str, ToolStatus], name: str) -> Optional[str]:
    # Returning resolved binary path for a named tool
    # Mandatory tool missing : raises RuntimeError
    # Optional tool missing  : returns None (caller handles gracefully)
    status = tool_statuses.get(name)
    if status is None:
        raise RuntimeError(f"Unknown tool '{name}' — not in TOOL_BINARIES config.")
    if not status.available:
        if status.mandatory:
            raise RuntimeError(
                f"Mandatory tool '{name}' unavailable. Run ensure_tools() first."
            )
        return None
    return status.path or status.binary