# Report generation module — two output formats:
#
#   1. JSON  — machine-readable, structured findings dump
#   2. HTML  — operator-readable, color-coded, self-contained single file
#
# The HTML report is fully self-contained (no external dependencies) so it
# renders correctly on air-gapped systems or when sharing with clients
# Severity classification assigns risk ratings to each finding category

import json
import datetime
from pathlib import Path

from core.session import ScanSession, log

# Severity Classification
def _severity_for_finding(finding_type: str, data: dict) -> str:
    # Assigning a severity level (Critical/High/Medium/Low/Info) based on finding type and content.
    if finding_type == "credentials":
        return "Critical"
    if finding_type == "shells":
        return "Critical"
    if finding_type == "lfi_hits":
        return "High"
    if finding_type == "admin_pages":
        return "High"
    if finding_type == "waf_detected":
        return "Info"
    if finding_type == "directories":
        status = data.get("status", 0)
        if status == 200:
            return "Medium"
        if status == 403:
            return "Low"
        return "Info"
    if finding_type == "open_ports":
        return "Low"
    if finding_type == "http_services":
        return "Info"
    return "Info"


SEVERITY_ORDER  = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#27ae60",
    "Info":     "#2980b9",
}

# JSON report
def generate_json_report(session: ScanSession) -> Path:
    # Dumping all session findings, metadata, and events to a structured JSON file written to session's report/ subdirectory.
    out_path = session.artifact_path("report", "report.json")

    report = {
        "meta": {
            "tool":       "web_csan",
            "version":    "2.0",
            "target":     session.target,
            "profile":    session.stealth_profile,
            "started_at": session.started_at.isoformat(),
            "generated":  datetime.datetime.utcnow().isoformat(),
        },
        "findings":  session.findings,
        "events":    session.events,
        "summary": {
            "open_ports":    len(session.findings["open_ports"]),
            "http_services": len(session.findings["http_services"]),
            "waf_detected":  len(session.findings["waf_detected"]),
            "directories":   len(session.findings["directories"]),
            "admin_pages":   len(session.findings["admin_pages"]),
            "credentials":   len(session.findings["credentials"]),
            "shells":        len(session.findings["shells"]),
        }
    }

    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    log("success", f"JSON report written: {out_path}")
    return out_path

# Html Report
# Self-contained — no CDN, no external JS, works offline
def generate_html_report(session: ScanSession) -> Path:
    # Generate a single self-contained HTML report file from session findings
    # Color-coded by severity, collapsible sections, timestamp header
    out_path = session.artifact_path("report", "report.html")

    html = _build_html(session)
    with open(out_path, "w") as f:
        f.write(html)

    log("success", f"HTML report written: {out_path}")
    return out_path


def _build_html(session: ScanSession) -> str:
    target  = session.target["value"]
    ts      = session.started_at.strftime("%Y-%m-%d %H:%M UTC")
    summary = {
        "Open Ports":    len(session.findings["open_ports"]),
        "HTTP Services": len(session.findings["http_services"]),
        "WAF Detected":  len(session.findings["waf_detected"]),
        "Directories":   len(session.findings["directories"]),
        "Admin Pages":   len(session.findings["admin_pages"]),
        "Credentials":   len(session.findings["credentials"]),
        "Shells Staged": len(session.findings["shells"]),
    }

    # Determining overall risk level
    if session.findings["credentials"] or session.findings["shells"]:
        overall_risk = "Critical"
    elif session.findings["admin_pages"]:
        overall_risk = "High"
    elif session.findings["directories"]:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    overall_color = SEVERITY_COLORS[overall_risk]

    # Building summary cards
    summary_cards = ""
    for label, count in summary.items():
        card_color = "#c0392b" if count > 0 and label in ("Credentials", "Shells Staged") else "#34495e"
        summary_cards += f"""
        <div class="card">
            <div class="card-count" style="color:{card_color}">{count}</div>
            <div class="card-label">{label}</div>
        </div>"""

    # Building finding sections
    sections = ""
    sections += _html_section("Open Ports",    _table_ports(session.findings["open_ports"]),    "Low")
    sections += _html_section("HTTP Services", _table_services(session.findings["http_services"]), "Info")
    sections += _html_section("WAF Detection", _table_waf(session.findings["waf_detected"]),     "Info")
    sections += _html_section("Directories",   _table_dirs(session.findings["directories"]),     "Medium")
    sections += _html_section("Admin Pages",   _table_admin(session.findings["admin_pages"]),    "High")
    sections += _html_section("Credentials",   _table_creds(session.findings["credentials"]),    "Critical")
    sections += _html_section("Shells Staged", _table_shells(session.findings["shells"]),         "Critical")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>web_csan Report — {target}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
  a {{ color: #58a6ff; }}
  .header {{ background: #161b22; border-bottom: 3px solid {overall_color}; padding: 24px 40px; }}
  .header h1 {{ font-size: 1.6rem; color: #f0f6fc; letter-spacing: 0.05em; }}
  .header .meta {{ font-size: 0.85rem; color: #8b949e; margin-top: 6px; }}
  .risk-badge {{
    display: inline-block; padding: 4px 14px; border-radius: 20px;
    background: {overall_color}22; border: 1px solid {overall_color};
    color: {overall_color}; font-weight: 700; font-size: 0.85rem;
    margin-left: 12px; vertical-align: middle;
  }}
  .summary-grid {{ display: flex; flex-wrap: wrap; gap: 16px; padding: 24px 40px; background: #0d1117; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px 24px; min-width: 140px; text-align: center; }}
  .card-count {{ font-size: 2rem; font-weight: 700; }}
  .card-label {{ font-size: 0.8rem; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }}
  .content {{ padding: 0 40px 40px; }}
  .section {{ margin-bottom: 24px; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
  .section-header {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 14px 20px; background: #161b22; cursor: pointer;
    border-bottom: 1px solid #30363d;
  }}
  .section-header:hover {{ background: #1f2937; }}
  .section-title {{ font-weight: 600; font-size: 1rem; color: #f0f6fc; }}
  .section-body {{ padding: 0; }}
  .sev-badge {{
    padding: 3px 10px; border-radius: 12px; font-size: 0.75rem;
    font-weight: 700; letter-spacing: 0.04em;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th {{ background: #21262d; color: #8b949e; font-weight: 600; text-transform: uppercase;
        font-size: 0.75rem; letter-spacing: 0.05em; padding: 10px 16px; text-align: left; }}
  td {{ padding: 10px 16px; border-top: 1px solid #21262d; color: #c9d1d9; word-break: break-all; }}
  tr:hover td {{ background: #161b22; }}
  .status-2xx {{ color: #3fb950; }}
  .status-3xx {{ color: #d29922; }}
  .status-4xx {{ color: #f85149; }}
  .empty-note {{ padding: 16px 20px; color: #8b949e; font-style: italic; font-size: 0.88rem; }}
  .toggle-icon {{ color: #8b949e; font-size: 1.1rem; transition: transform 0.2s; }}
  details[open] .toggle-icon {{ transform: rotate(90deg); }}
  details summary {{ list-style: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
  .footer {{ text-align: center; padding: 24px; color: #484f58; font-size: 0.8rem; border-top: 1px solid #21262d; margin-top: 40px; }}
</style>
</head>
<body>

<div class="header">
  <h1>
    🔍 web_csan Scan Report
    <span class="risk-badge">{overall_risk} Risk</span>
  </h1>
  <div class="meta">
    Target: <strong style="color:#f0f6fc">{target}</strong>
    &nbsp;·&nbsp; Stealth profile: <strong>{session.stealth_profile}</strong>
    &nbsp;·&nbsp; Scanned: {ts}
  </div>
</div>

<div class="summary-grid">{summary_cards}</div>

<div class="content">
{sections}
</div>

<div class="footer">
  Generated by web_csan v2.0 &nbsp;·&nbsp;
  For authorized security testing only &nbsp;·&nbsp;
  {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
</div>

</body>
</html>"""

# Selection Builders
def _html_section(title: str, body_html: str, severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#2980b9")
    sev_style = f"background:{color}22; border:1px solid {color}; color:{color};"
    return f"""
<div class="section">
  <details open>
    <summary class="section-header">
      <span class="section-title">{title}</span>
      <span style="display:flex;align-items:center;gap:10px">
        <span class="sev-badge" style="{sev_style}">{severity}</span>
        <span class="toggle-icon">▶</span>
      </span>
    </summary>
    <div class="section-body">
      {body_html}
    </div>
  </details>
</div>"""

def _status_class(status: int) -> str:
    if 200 <= status < 300:
        return "status-2xx"
    if 300 <= status < 400:
        return "status-3xx"
    return "status-4xx"

def _table_ports(ports: list) -> str:
    if not ports:
        return '<div class="empty-note">No open ports recorded.</div>'
    rows = "".join(
        f"<tr><td>{p['port']}/{p['protocol']}</td>"
        f"<td>{p['service']}</td>"
        f"<td>{p.get('version','')}</td></tr>"
        for p in ports
    )
    return f"<table><tr><th>Port</th><th>Service</th><th>Version</th></tr>{rows}</table>"

def _table_services(services: list) -> str:
    if not services:
        return '<div class="empty-note">No HTTP services recorded.</div>'
    rows = "".join(
        f"<tr><td><a href='{s['url']}' target='_blank'>{s['url']}</a></td>"
        f"<td class='{_status_class(s.get('status',0))}'>{s.get('status','-')}</td>"
        f"<td>{s.get('server','')}</td>"
        f"<td>{', '.join(s.get('tech',[]))}</td></tr>"
        for s in services
    )
    return (
        f"<table><tr><th>URL</th><th>Status</th>"
        f"<th>Server</th><th>Tech</th></tr>{rows}</table>"
    )

def _table_waf(wafs: list) -> str:
    if not wafs:
        return '<div class="empty-note">No WAF detected.</div>'
    rows = "".join(
        f"<tr><td>{w['waf']}</td><td>{w['evidence']}</td></tr>"
        for w in wafs
    )
    return f"<table><tr><th>WAF</th><th>Evidence</th></tr>{rows}</table>"

def _table_dirs(dirs: list) -> str:
    if not dirs:
        return '<div class="empty-note">No directories found.</div>'
    # Showing max 200 to keep report manageable
    shown = dirs[:200]
    note  = f"<div class='empty-note'>Showing {len(shown)} of {len(dirs)} entries.</div>" if len(dirs) > 200 else ""
    rows  = "".join(
        f"<tr><td><a href='{d['url']}' target='_blank'>{d['url']}</a></td>"
        f"<td class='{_status_class(d.get('status',0))}'>{d.get('status','-')}</td>"
        f"<td>{d.get('size','-')}</td></tr>"
        for d in shown
    )
    return (
        f"<table><tr><th>URL</th><th>Status</th><th>Size</th></tr>{rows}</table>{note}"
    )

def _table_admin(pages: list) -> str:
    if not pages:
        return '<div class="empty-note">No admin/login pages found.</div>'
    rows = "".join(
        f"<tr><td><a href='{p['url']}' target='_blank'>{p['url']}</a></td>"
        f"<td class='{_status_class(p.get('status',0))}'>{p.get('status','-')}</td></tr>"
        for p in pages
    )
    return f"<table><tr><th>URL</th><th>Status</th></tr>{rows}</table>"

def _table_creds(creds: list) -> str:
    if not creds:
        return '<div class="empty-note">No credentials found.</div>'
    rows = "".join(
        f"<tr>"
        f"<td style='color:#f85149;font-weight:700'>{c['username']}</td>"
        f"<td style='color:#f85149;font-weight:700'>{c['password']}</td>"
        f"<td>{c.get('url','')}</td></tr>"
        for c in creds
    )
    return f"<table><tr><th>Username</th><th>Password</th><th>Target URL</th></tr>{rows}</table>"

def _table_shells(shells: list) -> str:
    if not shells:
        return '<div class="empty-note">No shells generated.</div>'
    rows = "".join(
        f"<tr><td>{s['type']}</td><td><code>{s['path']}</code></td></tr>"
        for s in shells
    )
    return f"<table><tr><th>Type</th><th>File Path</th></tr>{rows}</table>"

# Full Report Pipeline
def generate_reports(
    session: ScanSession,
    formats: list[str] = None,
) -> dict[str, Path]:
    # Generating reports in requested formats
    # formats: list of "json" | "html" (defaults to both)
    # Returning dict of {format: Path}.
    if formats is None:
        formats = ["json", "html"]

    log("info", "="*55)
    log("info", "  REPORT GENERATION")
    log("info", "="*55)

    results = {}
    if "json" in formats:
        results["json"] = generate_json_report(session)
    if "html" in formats:
        results["html"] = generate_html_report(session)

    log("success", f"Reports written to: {session.subdir('report')}")
    return results
