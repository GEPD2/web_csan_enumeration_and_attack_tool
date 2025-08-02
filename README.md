# Automated Security Assessment Toolkit 🔐

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

A comprehensive penetration testing automation script that performs:
- Network scanning with Nmap
- Web directory brute-forcing with Gobuster
- Credential cracking with Hydra
- Reverse shell deployment

## Features 🚀

- **Automated Dependency Setup** - Installs required tools
- **Intelligent Reconnaissance** - Service detection and analysis
- **Targeted Attacks** - Focuses on Apache web servers
- **Credential Testing** - Built-in wordlists and custom generation
- **Post-Exploitation** - PHP reverse shell deployment

## Installation 📦

```bash
git clone https://github.com/yourusername/security-assessment-toolkit.git
cd security-assessment-toolkit
chmod +x security_scanner.py
```
Usage 🛠️
Basic Scan

```bash
python3 security_scanner.py
```
The tool will guide you through:

Automatic dependency installation

Target IP input

Scan configuration

Attack vector selection

Workflow Overview
Nmap service detection (-sV -sC -T4 -A)

Apache server identification

Gobuster directory brute-forcing

Admin page discovery

Hydra credential attacks

Reverse shell deployment (if admin access gained)

## 🔧 Integrated Tools

| Tool | Description | Auto-Installed | Default Wordlist | Common Usage |
|------|-------------|----------------|------------------|--------------|
| <img src="https://nmap.org/images/sitelogo-nmap.svg" width="20"> **Nmap** | Network scanning and service detection | ✅ Yes | N/A | `nmap -sV -sC -T4 -A {target}` |
| <img src="https://github.com/OJ/gobuster/raw/master/docs/logo.jpg" width="20"> **Gobuster** | Directory/file brute-forcing | ✅ Yes | `directory-list-2.3-medium.txt` | `gobuster dir -u {url} -w {wordlist}` |
| <img src="https://www.kali.org/tools/hydra/images/hydra-logo.svg" width="20"> **Hydra** | Credential brute-forcing | ✅ Yes | `rockyou.txt` | `hydra -L users.txt -P passwords.txt {target} http-post-form` |
| <img src="https://git.savannah.gnu.org/gitweb/?p=grep.git;a=blob_plain;f=gnulib/lib/grep.c;hb=HEAD" width="20"> **Grep** | Pattern matching in files | ✅ Yes | N/A | `grep 'pattern' file.txt` |

### Key Features:
- **Automatic Installation**: All tools install with one confirmation
- **Optimized Configurations**: Pre-configured with effective scanning parameters
- **Wordlist Management**: Uses Kali Linux default wordlists when available
- **Error Handling**: Verifies tool availability before execution

> **Note**: Tools will be installed to `/usr/bin/` by default. Requires `sudo` privileges for installation.

Example Scenarios 🎯
Web Application Testing

```bash
1. Detects Apache servers
2. Finds admin interfaces
3. Tests common credentials
4. Deploys reverse shell on success
```
Custom Wordlist Usage

```bash
[?] For default wordlist type d else give the path name:
> /path/to/custom_wordlist.txt
```
Security Notice ⚠️
Legal Use Only
This tool should only be used on:

Systems you own

Systems you have explicit permission to test

Educational environments

```bash
- Illegal use may result in criminal charges
```
