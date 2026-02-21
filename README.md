# web_csan 🔐
### Web Enumeration & Attack Toolkit — v2.0

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square&logo=linux&logoColor=white)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](https://github.com/GEPD2/web_csan_enumeration_and_attack_tool/blob/main/LICENSE)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)
![Tools](https://img.shields.io/badge/Tools-nmap%20%7C%20gobuster%20%7C%20hydra-red?style=flat-square)

*A modular, stealth-aware web penetration testing framework for authorized security assessments*

</div>

---

> ⚠️ **Legal Notice** — This tool is for **authorized security testing only**.
> Use it exclusively on systems you own or have **explicit written permission** to test.
> Unauthorized use is illegal and may result in criminal prosecution.
> The authors assume no liability for misuse.

---

## What is web_csan?

web_csan is a structured penetration testing toolkit that automates the web application assessment workflow — from initial reconnaissance to credential brute-forcing and reverse shell staging. It was built to replace ad-hoc command chaining with a clean, modular, session-aware architecture that handles the operational details so you can focus on the assessment.

The tool evolved from a single-script proof-of-concept into a fully modularized framework with:

- **Cross-platform tool detection and installation** — auto-installs missing dependencies using the correct package manager for your OS and distro
- **4 stealth profiles** — from ghost mode (IDS evasion) to aggressive (lab speed)
- **Session management** — every scan gets a timestamped output directory, structured JSON event log, and automatic cleanup
- **Input sanitization** — all user input validated and injection-protected before touching subprocess
- **Multi-target support** — scan a list of targets from a file, each with its own session
- **Dual-format reporting** — machine-readable JSON + self-contained HTML report per scan

---

## Architecture

```
web_csan/
├── main.py                  ← CLI entry point, phase orchestration
├── config/
│   └── settings.py          ← All configurable parameters (stealth profiles,
│                               wordlists, WAF signatures, shell templates, etc.)
├── core/
│   ├── validator.py         ← Input sanitization, scope enforcement, injection prevention
│   ├── session.py           ← Session lifecycle, structured logging, artifact tracking
│   └── tools_manager.py     ← Cross-platform tool detection & installation
└── modules/
    ├── recon.py             ← nmap, HTTP probing, WAF detection, banner grabbing
    ├── enum.py              ← gobuster dir/vhost/dns enumeration
    ├── auth.py              ← Hydra brute-force, credential validation
    ├── exploit.py           ← Shell payload generation, LFI probe, nc listener
    └── report.py            ← JSON + HTML report generation
```

Each phase is independently runnable — you can execute only the modules you need for a given engagement.

---

## Capabilities

### 🔍 Recon Phase (`modules/recon.py`)
- **nmap** service/version/script scan with stealth profile timing (`-T1` through `-T4`)
- Automatic OS detection (root) with graceful fallback
- HTTP/HTTPS service probing on all discovered web ports
- **3-layer WAF detection**: header signatures, body fingerprinting, status-code heuristics
- Active WAF evasion probe (differential response analysis)
- Technology fingerprinting: server software, backend language, CMS, framework, CDN
- Raw TCP banner grabbing on all open ports

### 📂 Enum Phase (`modules/enum.py`)
- **gobuster dir** — directory and file enumeration with extension fuzzing
- **gobuster vhost** — virtual host discovery
- **gobuster dns** — subdomain enumeration (domain targets only)
- Admin/login page detection via regex (15+ path patterns)
- Sensitive file flagging: `.bak`, `.env`, `.sql`, `.config`, API endpoints, `.git`
- Stealth profile controls threads and inter-request delay

### 🔑 Auth Phase (`modules/auth.py`)
- Hydra `http-post-form` brute-force with auto-detected failure strings
- Hydra HTTP Basic Auth (401 targets)
- WAF-aware rate limiting — auto-reduces task count if WAF was detected
- Credential validation via live login replay after discovery
- Wordlist resolution: configured paths → built-in defaults (no hard crashes)

### 💣 Exploit Phase (`modules/exploit.py`)
- **7 shell payload types** generated simultaneously:

| Type | Use Case |
|---|---|
| `php_exec` | Web shell via GET parameter (`?cmd=id`) |
| `php_reverse` | PHP fsockopen reverse shell |
| `bash_reverse` | `/dev/tcp` bash reverse shell |
| `python_reverse` | Python3 socket reverse shell |
| `nc_reverse` | Netcat with `-e` flag |
| `nc_mkfifo` | Netcat via `mkfifo` (no `-e` needed) |
| `powershell_reverse` | Windows PowerShell reverse shell |

- Upload path suggestion from enum discoveries
- LFI probe (5 encoded payloads, regex-confirmed hits)
- Interactive `nc -nlvp` listener with subprocess (interactive shell output)

### 📊 Report Phase (`modules/report.py`)
- **JSON report** — structured findings dump with full event log, metadata, timestamps
- **HTML report** — self-contained (no CDN, works air-gapped), dark-themed, severity-color-coded, collapsible sections, overall risk badge

---

## Stealth Profiles

| Profile | nmap Timing | Threads | Delay | Use Case |
|---|---|---|---|---|
| `ghost` | T1 | 5 | 500ms | Maximum IDS evasion, slow |
| `stealth` | T2 | 10 | 200ms | Balanced — default |
| `normal` | T3 | 20 | none | Standard assessment |
| `aggressive` | T4 | 50 | none | Isolated lab environments |

---

## Installation

**Clone the repository:**
```bash
git clone https://github.com/GEPD2/web_csan_enumeration_and_attack_tool.git
cd web_csan_enumeration_and_attack_tool
```

**Requirements:**
- Python 3.10+
- External tools: `nmap`, `gobuster`, `hydra`, `curl`, `grep` — the tool will detect and offer to install any missing ones automatically on first run

**Tool installation is handled automatically** using your system's native package manager:

| OS / Distro | Package Manager Used |
|---|---|
| Kali / Parrot / Ubuntu / Debian | `apt` |
| Fedora / RHEL / CentOS / Rocky | `dnf` / `yum` |
| Arch / Manjaro / BlackArch | `pacman` |
| openSUSE | `zypper` |
| Void Linux | `xbps-install` |
| Alpine | `apk` |
| Solus | `eopkg` |
| macOS | `brew` (Homebrew) |
| Windows | `winget` → `choco` → `scoop` |
| Gobuster (any) | `go install` (fallback when not in repos) |

---

## Usage

```bash
# Single target — all phases — default stealth profile
python3 main.py -t 10.10.10.10

# Target by domain
python3 main.py -t target.com

# Specify stealth profile and port scope
python3 main.py -t 10.10.10.10 --profile ghost --ports full

# Run only recon and enumeration phases
python3 main.py -t 10.10.10.10 --phase recon,enum

# Multi-target from file
python3 main.py -T targets.txt --profile stealth

# Large wordlist, skip exploit phase, JSON report only
python3 main.py -t 10.10.10.10 --wordlist large --skip-exploit --report json

# Automation mode (skip scope confirmation prompt)
python3 main.py -t 10.10.10.10 --yes
```

### All Options

```
Targets:
  -t IP/DOMAIN        Single target (IPv4 address or domain name)
  -T FILE             File with one target per line

Stealth:
  --profile PROFILE   ghost | stealth | normal | aggressive  (default: stealth)
  --ports PROFILE     web_only | common | full               (default: web_only)

Phase Control:
  --phase PHASES      Comma-separated: recon,enum,auth,exploit,report
  --skip-recon        Skip recon phase
  --skip-enum         Skip enumeration phase
  --skip-auth         Skip auth brute-force phase
  --skip-exploit      Skip exploit staging phase

Enumeration:
  --wordlist SIZE     small | medium | large                  (default: medium)
  --no-vhost          Skip virtual host enumeration
  --no-subdomain      Skip subdomain enumeration
  --skip-waf-probe    Skip active WAF evasion probe

Output:
  --report FORMAT     json | html | all                       (default: all)

Misc:
  --yes               Auto-confirm scope (bypass safety prompt)
  --debug             Enable debug output
```

---

## Output Structure

Each scan creates a timestamped session directory:

```
~/web_csan_output/
└── 10_10_10_10_20250219_143022/
    ├── session.json         ← structured event log (JSON Lines)
    ├── nmap/
    │   ├── initial_scan.txt
    │   └── initial_scan.xml
    ├── gobuster/
    │   ├── dir_enum.txt
    │   ├── vhost_enum.txt
    │   └── subdomain_enum.txt
    ├── hydra/
    │   ├── form_results.txt
    │   └── usernames.txt
    ├── shells/
    │   ├── shell_php_exec.php
    │   ├── shell_php_reverse.php
    │   ├── shell_bash_reverse.sh
    │   ├── shell_python_reverse.py
    │   ├── shell_nc_mkfifo.sh
    │   └── shell_powershell_reverse.ps1
    └── report/
        ├── report.json
        └── report.html
```

---

## Security Design

- **Zero `os.system()` calls** — all subprocess invocations use argument lists (`subprocess.run([...])`) eliminating shell injection entirely
- **Input validation on every user-supplied value** — IP, domain, URL, port, path, all validated and sanitized before touching any subprocess or filesystem call
- **Scope confirmation gate** — requires typing `YES` explicitly before any active scanning begins
- **Graceful SIGINT handling** — Ctrl+C flushes session log and exits cleanly; no dangling temp files
- **WAF-aware brute-forcing** — automatically backs off hydra rate when WAF is detected to avoid lockout

---

## Development Status

| Module | Status |
|---|---|
| `config/settings.py` | ✅ Complete |
| `core/validator.py` | ✅ Complete |
| `core/session.py` | ✅ Complete |
| `core/tools_manager.py` | ✅ Complete — cross-platform |
| `modules/recon.py` | ✅ Complete |
| `modules/enum.py` | ✅ Complete |
| `modules/auth.py` | ✅ Complete |
| `modules/exploit.py` | ✅ Complete |
| `modules/report.py` | ✅ Complete |
| `main.py` | ✅ Complete |

**Planned:**
- [ ] Cookie/session-based auth support
- [ ] SQLi detection probe module
- [ ] Concurrent multi-target scanning (ThreadPoolExecutor)
- [ ] SOCKS proxy / Tor routing for ghost-mode operations
- [ ] Plugin system for custom modules

---

## Contributing

Pull requests are welcome. For significant changes, open an issue first to discuss the direction. Please follow the existing module structure and ensure all user input passes through `core/validator.py` before reaching any subprocess call.

---

## License

MIT License — see `LICENSE` for details.

---

<div align="center">
<sub>Built for security professionals. Use responsibly.</sub>
</div>
