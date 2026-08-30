# Report generation module — four output formats:
#
#   1. JSON     — machine-readable, structured findings dump
#   2. HTML     — operator dashboard, self-contained, inline-SVG charts
#   3. Markdown — engagement / CTF writeup, paste-ready into notes
#   4. CSV      — flat findings table for spreadsheets and pivoting
#
# The HTML report is fully self-contained (no CDN, no external JS) so it renders
# correctly on air-gapped systems or when sharing with clients. All charts are
# hand-rendered inline SVG for the same reason.

import csv
import json
import html
import datetime
from pathlib import Path

from core.session import ScanSession, log

# Severity Classification
SEVERITY_ORDER  = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#27ae60",
    "Info":     "#2980b9",
}
# nuclei / lowercase severities → report severity label
_SEV_NORMALIZE = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info", "informational": "Info",
    "unknown": "Info", "": "Info",
}


def _norm_sev(value: str) -> str:
    return _SEV_NORMALIZE.get((value or "").lower(), "Info")


def _vuln_severity_counts(session: ScanSession) -> dict:
    # Counting vulnerabilities by normalized severity label (report ordering).
    counts = {k: 0 for k in SEVERITY_ORDER}
    for v in session.findings.get("vulnerabilities", []):
        counts[_norm_sev(v.get("severity"))] += 1
    return counts


def _overall_risk(session: ScanSession) -> str:
    f = session.findings
    sev_counts = _vuln_severity_counts(session)
    if f["credentials"] or f["shells"] or sev_counts["Critical"]:
        return "Critical"
    if f["admin_pages"] or sev_counts["High"]:
        return "High"
    if f["directories"] or sev_counts["Medium"] or f["tls"]:
        return "Medium"
    return "Low"


# JSON report
def generate_json_report(session: ScanSession) -> Path:
    # Dumping all session findings, metadata, and events to a structured JSON file.
    out_path = session.artifact_path("report", "report.json")

    report = {
        "meta": {
            "tool":       "web_csan",
            "version":    "2.0",
            "target":     session.target,
            "profile":    session.stealth_profile,
            "started_at": session.started_at.isoformat(),
            "generated":  datetime.datetime.utcnow().isoformat(),
            "overall_risk": _overall_risk(session),
        },
        "findings":  session.findings,
        "events":    session.events,
        "summary": {
            "open_ports":      len(session.findings["open_ports"]),
            "http_services":   len(session.findings["http_services"]),
            "waf_detected":    len(session.findings["waf_detected"]),
            "vulnerabilities": len(session.findings["vulnerabilities"]),
            "tls":             len(session.findings["tls"]),
            "directories":     len(session.findings["directories"]),
            "admin_pages":     len(session.findings["admin_pages"]),
            "credentials":     len(session.findings["credentials"]),
            "shells":          len(session.findings["shells"]),
        },
        "severity_breakdown": _vuln_severity_counts(session),
    }

    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    log("success", f"JSON report written: {out_path}")
    return out_path


# Inline-SVG charts (no JS, no CDN)
def _svg_donut(counts: dict, size: int = 180, thickness: int = 26) -> str:
    # Rendering a severity donut chart from an ordered {label: count} dict.
    total = sum(counts.values())
    r = (size - thickness) / 2
    cx = cy = size / 2
    circ = 2 * 3.141592653589793 * r
    if total == 0:
        return (
            f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
            f'role="img" aria-label="No findings">'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#30363d" '
            f'stroke-width="{thickness}"/>'
            f'<text x="{cx}" y="{cy+5}" text-anchor="middle" fill="#8b949e" '
            f'font-size="14">none</text></svg>'
        )
    segments = ""
    offset = 0.0
    for label in sorted(counts, key=lambda k: SEVERITY_ORDER.get(k, 99)):
        val = counts[label]
        if val == 0:
            continue
        frac = val / total
        seg_len = frac * circ
        color = SEVERITY_COLORS.get(label, "#2980b9")
        segments += (
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="{thickness}" '
            f'stroke-dasharray="{seg_len:.2f} {circ - seg_len:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"><title>{label}: {val}</title></circle>'
        )
        offset += seg_len
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
        f'role="img" aria-label="Severity distribution">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#21262d" '
        f'stroke-width="{thickness}"/>{segments}'
        f'<text x="{cx}" y="{cy-2}" text-anchor="middle" fill="#f0f6fc" '
        f'font-size="30" font-weight="700">{total}</text>'
        f'<text x="{cx}" y="{cy+18}" text-anchor="middle" fill="#8b949e" '
        f'font-size="12">findings</text></svg>'
    )


def _svg_hbar(data: list, width: int = 420, bar_h: int = 22, gap: int = 10) -> str:
    # Rendering a horizontal bar chart from [(label, value, color), ...].
    if not data:
        return '<div class="empty-note">No data.</div>'
    max_val = max((v for _, v, _ in data), default=0) or 1
    label_w = 150
    track_w = width - label_w - 50
    height  = len(data) * (bar_h + gap) + gap
    rows = ""
    y = gap
    for label, val, color in data:
        bw = (val / max_val) * track_w
        rows += (
            f'<text x="0" y="{y + bar_h*0.7:.0f}" fill="#8b949e" font-size="12">'
            f'{html.escape(str(label))[:22]}</text>'
            f'<rect x="{label_w}" y="{y}" width="{track_w}" height="{bar_h}" '
            f'rx="4" fill="#21262d"/>'
            f'<rect x="{label_w}" y="{y}" width="{bw:.1f}" height="{bar_h}" '
            f'rx="4" fill="{color}"><title>{html.escape(str(label))}: {val}</title></rect>'
            f'<text x="{label_w + track_w + 8}" y="{y + bar_h*0.7:.0f}" '
            f'fill="#c9d1d9" font-size="12" font-weight="600">{val}</text>'
        )
        y += bar_h + gap
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'role="img" aria-label="Bar chart">{rows}</svg>'
    )


def _severity_legend(counts: dict) -> str:
    items = ""
    for label in sorted(counts, key=lambda k: SEVERITY_ORDER.get(k, 99)):
        color = SEVERITY_COLORS.get(label, "#2980b9")
        items += (
            f'<span class="legend-item"><span class="legend-dot" '
            f'style="background:{color}"></span>{label} '
            f'<strong>{counts[label]}</strong></span>'
        )
    return f'<div class="legend">{items}</div>'


# HTML report — self-contained dashboard
def generate_html_report(session: ScanSession) -> Path:
    out_path = session.artifact_path("report", "report.html")
    html_doc = _build_html(session)
    with open(out_path, "w") as f:
        f.write(html_doc)
    log("success", f"HTML report written: {out_path}")
    return out_path


def _build_html(session: ScanSession) -> str:
    target  = html.escape(session.target["value"])
    ts      = session.started_at.strftime("%Y-%m-%d %H:%M UTC")
    f       = session.findings
    summary = {
        "Open Ports":      len(f["open_ports"]),
        "HTTP Services":   len(f["http_services"]),
        "Vulnerabilities": len(f["vulnerabilities"]),
        "WAF Detected":    len(f["waf_detected"]),
        "TLS Issues":      sum(1 for t in f["tls"] if t.get("issues")),
        "Directories":     len(f["directories"]),
        "Admin Pages":     len(f["admin_pages"]),
        "Credentials":     len(f["credentials"]),
        "Shells Staged":   len(f["shells"]),
    }

    overall_risk  = _overall_risk(session)
    overall_color = SEVERITY_COLORS[overall_risk]
    sev_counts    = _vuln_severity_counts(session)

    # Summary cards
    summary_cards = ""
    highlight = ("Credentials", "Shells Staged", "Vulnerabilities")
    for label, count in summary.items():
        card_color = "#c0392b" if count > 0 and label in highlight else "#34495e"
        summary_cards += f"""
        <div class="card">
            <div class="card-count" style="color:{card_color}">{count}</div>
            <div class="card-label">{label}</div>
        </div>"""

    # Charts
    donut = _svg_donut(sev_counts)
    legend = _severity_legend(sev_counts)
    svc_bar = _svg_hbar([
        ("Open ports",     len(f["open_ports"]),      "#2980b9"),
        ("HTTP services",  len(f["http_services"]),   "#2980b9"),
        ("Directories",    len(f["directories"]),     "#f1c40f"),
        ("Admin pages",    len(f["admin_pages"]),     "#e67e22"),
        ("Vulnerabilities",len(f["vulnerabilities"]), "#c0392b"),
    ])

    charts = f"""
    <div class="charts">
      <div class="chart-box">
        <div class="chart-title">Findings by Severity</div>
        <div class="chart-flex">{donut}{legend}</div>
      </div>
      <div class="chart-box">
        <div class="chart-title">Attack Surface</div>
        {svc_bar}
      </div>
    </div>"""

    # Sections
    sections  = _html_section("Vulnerabilities", _table_vulns(f["vulnerabilities"]), "High")
    sections += _html_section("Open Ports",    _table_ports(f["open_ports"]),      "Low")
    sections += _html_section("HTTP Services", _table_services(f["http_services"]),"Info")
    sections += _html_section("TLS Assessment",_table_tls(f["tls"]),               "Medium")
    sections += _html_section("WAF Detection", _table_waf(f["waf_detected"]),      "Info")
    sections += _html_section("Directories",   _table_dirs(f["directories"]),      "Medium")
    sections += _html_section("Admin Pages",   _table_admin(f["admin_pages"]),     "High")
    sections += _html_section("Credentials",   _table_creds(f["credentials"]),     "Critical")
    sections += _html_section("Shells Staged", _table_shells(f["shells"]),         "Critical")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>web_csan Report -- {target}</title>
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
  .summary-grid {{ display: flex; flex-wrap: wrap; gap: 16px; padding: 24px 40px 8px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 18px 22px; min-width: 130px; text-align: center; flex: 1; }}
  .card-count {{ font-size: 2rem; font-weight: 700; }}
  .card-label {{ font-size: 0.75rem; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }}
  .charts {{ display: flex; flex-wrap: wrap; gap: 16px; padding: 16px 40px; }}
  .chart-box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px 24px; flex: 1; min-width: 320px; }}
  .chart-title {{ font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 14px; }}
  .chart-flex {{ display: flex; align-items: center; gap: 24px; flex-wrap: wrap; }}
  .legend {{ display: flex; flex-direction: column; gap: 6px; }}
  .legend-item {{ font-size: 0.85rem; color: #c9d1d9; }}
  .legend-dot {{ display: inline-block; width: 11px; height: 11px; border-radius: 3px; margin-right: 8px; vertical-align: middle; }}
  .content {{ padding: 8px 40px 40px; }}
  .section {{ margin-bottom: 20px; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
  .section-header {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 14px 20px; background: #161b22; cursor: pointer;
    border-bottom: 1px solid #30363d;
  }}
  .section-header:hover {{ background: #1f2937; }}
  .section-title {{ font-weight: 600; font-size: 1rem; color: #f0f6fc; }}
  .sev-badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.04em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th {{ background: #21262d; color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; padding: 10px 16px; text-align: left; }}
  td {{ padding: 10px 16px; border-top: 1px solid #21262d; color: #c9d1d9; word-break: break-all; }}
  tr:hover td {{ background: #161b22; }}
  .status-2xx {{ color: #3fb950; }}
  .status-3xx {{ color: #d29922; }}
  .status-4xx {{ color: #f85149; }}
  .sev-pill {{ padding: 2px 9px; border-radius: 10px; font-size: 0.72rem; font-weight: 700; }}
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
    web_csan Scan Report
    <span class="risk-badge">{overall_risk} Risk</span>
  </h1>
  <div class="meta">
    Target: <strong style="color:#f0f6fc">{target}</strong>
    &nbsp;&middot;&nbsp; Stealth profile: <strong>{html.escape(session.stealth_profile)}</strong>
    &nbsp;&middot;&nbsp; Scanned: {ts}
  </div>
</div>

<div class="summary-grid">{summary_cards}</div>
{charts}
<div class="content">
{sections}
</div>

<div class="footer">
  Generated by web_csan v2.0 &nbsp;&middot;&nbsp;
  For authorized security testing only &nbsp;&middot;&nbsp;
  {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
</div>

</body>
</html>"""


# HTML section / table builders
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
        <span class="toggle-icon">&#9654;</span>
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


def _sev_pill(sev: str) -> str:
    label = _norm_sev(sev)
    color = SEVERITY_COLORS[label]
    return f'<span class="sev-pill" style="background:{color}22;border:1px solid {color};color:{color}">{label}</span>'


def _table_vulns(vulns: list) -> str:
    if not vulns:
        return '<div class="empty-note">No vulnerabilities or exposures found.</div>'
    ordered = sorted(vulns, key=lambda v: SEVERITY_ORDER.get(_norm_sev(v.get("severity")), 4))
    rows = "".join(
        f"<tr><td>{_sev_pill(v.get('severity'))}</td>"
        f"<td>{html.escape(str(v.get('name','')))}</td>"
        f"<td><a href='{html.escape(str(v.get('url','')))}' target='_blank'>{html.escape(str(v.get('url','')))}</a></td>"
        f"<td>{html.escape(str(v.get('source','')))}</td></tr>"
        for v in ordered
    )
    return f"<table><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Source</th></tr>{rows}</table>"


def _table_tls(tls: list) -> str:
    if not tls:
        return '<div class="empty-note">No TLS services assessed.</div>'
    rows = ""
    for t in tls:
        issues = ", ".join(t.get("issues", [])) or "none"
        protos = ", ".join(t.get("protocols", [])) or "-"
        color  = "#f85149" if t.get("issues") else "#3fb950"
        rows += (
            f"<tr><td><a href='{html.escape(str(t.get('url','')))}' target='_blank'>{html.escape(str(t.get('url','')))}</a></td>"
            f"<td>{html.escape(protos)}</td>"
            f"<td style='color:{color}'>{html.escape(issues)}</td></tr>"
        )
    return f"<table><tr><th>Service</th><th>Protocols</th><th>Issues</th></tr>{rows}</table>"


def _table_ports(ports: list) -> str:
    if not ports:
        return '<div class="empty-note">No open ports recorded.</div>'
    rows = "".join(
        f"<tr><td>{p['port']}/{p['protocol']}</td>"
        f"<td>{html.escape(str(p['service']))}</td>"
        f"<td>{html.escape(str(p.get('version','')))}</td></tr>"
        for p in ports
    )
    return f"<table><tr><th>Port</th><th>Service</th><th>Version</th></tr>{rows}</table>"


def _table_services(services: list) -> str:
    if not services:
        return '<div class="empty-note">No HTTP services recorded.</div>'
    rows = "".join(
        f"<tr><td><a href='{html.escape(str(s['url']))}' target='_blank'>{html.escape(str(s['url']))}</a></td>"
        f"<td class='{_status_class(s.get('status',0))}'>{s.get('status','-')}</td>"
        f"<td>{html.escape(str(s.get('server','')))}</td>"
        f"<td>{html.escape(', '.join(s.get('tech',[])))}</td></tr>"
        for s in services
    )
    return f"<table><tr><th>URL</th><th>Status</th><th>Server</th><th>Tech</th></tr>{rows}</table>"


def _table_waf(wafs: list) -> str:
    if not wafs:
        return '<div class="empty-note">No WAF detected.</div>'
    rows = "".join(
        f"<tr><td>{html.escape(str(w['waf']))}</td><td>{html.escape(str(w['evidence']))}</td></tr>"
        for w in wafs
    )
    return f"<table><tr><th>WAF</th><th>Evidence</th></tr>{rows}</table>"


def _table_dirs(dirs: list) -> str:
    if not dirs:
        return '<div class="empty-note">No directories found.</div>'
    shown = dirs[:200]
    note  = f"<div class='empty-note'>Showing {len(shown)} of {len(dirs)} entries.</div>" if len(dirs) > 200 else ""
    rows  = "".join(
        f"<tr><td><a href='{html.escape(str(d['url']))}' target='_blank'>{html.escape(str(d['url']))}</a></td>"
        f"<td class='{_status_class(d.get('status',0))}'>{d.get('status','-')}</td>"
        f"<td>{d.get('size','-')}</td></tr>"
        for d in shown
    )
    return f"<table><tr><th>URL</th><th>Status</th><th>Size</th></tr>{rows}</table>{note}"


def _table_admin(pages: list) -> str:
    if not pages:
        return '<div class="empty-note">No admin/login pages found.</div>'
    rows = "".join(
        f"<tr><td><a href='{html.escape(str(p['url']))}' target='_blank'>{html.escape(str(p['url']))}</a></td>"
        f"<td class='{_status_class(p.get('status',0))}'>{p.get('status','-')}</td></tr>"
        for p in pages
    )
    return f"<table><tr><th>URL</th><th>Status</th></tr>{rows}</table>"


def _table_creds(creds: list) -> str:
    if not creds:
        return '<div class="empty-note">No credentials found.</div>'
    rows = "".join(
        f"<tr><td style='color:#f85149;font-weight:700'>{html.escape(str(c['username']))}</td>"
        f"<td style='color:#f85149;font-weight:700'>{html.escape(str(c['password']))}</td>"
        f"<td>{html.escape(str(c.get('url','')))}</td></tr>"
        for c in creds
    )
    return f"<table><tr><th>Username</th><th>Password</th><th>Target URL</th></tr>{rows}</table>"


def _table_shells(shells: list) -> str:
    if not shells:
        return '<div class="empty-note">No shells generated.</div>'
    rows = "".join(
        f"<tr><td>{html.escape(str(s['type']))}</td><td><code>{html.escape(str(s['path']))}</code></td></tr>"
        for s in shells
    )
    return f"<table><tr><th>Type</th><th>File Path</th></tr>{rows}</table>"


# Markdown report — engagement / CTF writeup
def generate_markdown_report(session: ScanSession) -> Path:
    out_path = session.artifact_path("report", "report.md")
    out_path.write_text(_build_markdown(session))
    log("success", f"Markdown report written: {out_path}")
    return out_path


def _md_table(headers: list, rows: list) -> str:
    if not rows:
        return "_None found._\n"
    head = "| " + " | ".join(headers) + " |\n"
    sep  = "| " + " | ".join("---" for _ in headers) + " |\n"
    body = "".join(
        "| " + " | ".join(str(c).replace("|", "\\|") for c in row) + " |\n"
        for row in rows
    )
    return head + sep + body


def _build_markdown(session: ScanSession) -> str:
    f       = session.findings
    target  = session.target["value"]
    ts      = session.started_at.strftime("%Y-%m-%d %H:%M UTC")
    risk    = _overall_risk(session)
    sev     = _vuln_severity_counts(session)

    md  = f"# web_csan Report -- {target}\n\n"
    md += f"- **Overall risk:** {risk}\n"
    md += f"- **Stealth profile:** {session.stealth_profile}\n"
    md += f"- **Scanned:** {ts}\n\n"

    md += "## Summary\n\n"
    md += _md_table(
        ["Category", "Count"],
        [
            ["Open ports",      len(f["open_ports"])],
            ["HTTP services",   len(f["http_services"])],
            ["Vulnerabilities", len(f["vulnerabilities"])],
            ["WAF detected",    len(f["waf_detected"])],
            ["TLS assessed",    len(f["tls"])],
            ["Directories",     len(f["directories"])],
            ["Admin pages",     len(f["admin_pages"])],
            ["Credentials",     len(f["credentials"])],
            ["Shells staged",   len(f["shells"])],
        ],
    )
    md += "\n### Severity breakdown\n\n"
    md += _md_table(["Severity", "Count"], [[k, sev[k]] for k in SEVERITY_ORDER])

    md += "\n## Vulnerabilities\n\n"
    ordered = sorted(f["vulnerabilities"],
                     key=lambda v: SEVERITY_ORDER.get(_norm_sev(v.get("severity")), 4))
    md += _md_table(
        ["Severity", "Finding", "Location", "Source"],
        [[_norm_sev(v.get("severity")), v.get("name", ""), v.get("url", ""), v.get("source", "")]
         for v in ordered],
    )

    md += "\n## Open Ports\n\n"
    md += _md_table(["Port", "Service", "Version"],
                    [[f"{p['port']}/{p['protocol']}", p["service"], p.get("version", "")]
                     for p in f["open_ports"]])

    md += "\n## HTTP Services\n\n"
    md += _md_table(["URL", "Status", "Server", "Tech"],
                    [[s["url"], s.get("status", "-"), s.get("server", ""), ", ".join(s.get("tech", []))]
                     for s in f["http_services"]])

    md += "\n## TLS Assessment\n\n"
    md += _md_table(["Service", "Protocols", "Issues"],
                    [[t.get("url", ""), ", ".join(t.get("protocols", [])),
                      ", ".join(t.get("issues", [])) or "none"] for t in f["tls"]])

    md += "\n## WAF Detection\n\n"
    md += _md_table(["WAF", "Evidence"],
                    [[w["waf"], w["evidence"]] for w in f["waf_detected"]])

    md += "\n## Admin Pages\n\n"
    md += _md_table(["URL", "Status"],
                    [[p["url"], p.get("status", "-")] for p in f["admin_pages"]])

    md += "\n## Credentials\n\n"
    md += _md_table(["Username", "Password", "Target URL"],
                    [[c["username"], c["password"], c.get("url", "")] for c in f["credentials"]])

    md += "\n---\n_Generated by web_csan v2.0 -- for authorized security testing only._\n"
    return md


# CSV report — flat findings table
def generate_csv_report(session: ScanSession) -> Path:
    out_path = session.artifact_path("report", "report.csv")
    f = session.findings
    with open(out_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["category", "severity", "name", "location", "detail", "source"])
        for v in f["vulnerabilities"]:
            w.writerow(["vulnerability", _norm_sev(v.get("severity")), v.get("name", ""),
                        v.get("url", ""), v.get("template", ""), v.get("source", "")])
        for p in f["open_ports"]:
            w.writerow(["open_port", "Low", f"{p['port']}/{p['protocol']}",
                        p["service"], p.get("version", ""), "nmap"])
        for s in f["http_services"]:
            w.writerow(["http_service", "Info", s.get("server", ""), s["url"],
                        ", ".join(s.get("tech", [])), "recon"])
        for t in f["tls"]:
            w.writerow(["tls", "Medium" if t.get("issues") else "Info", "",
                        t.get("url", ""), ", ".join(t.get("issues", [])), "sslscan"])
        for wafe in f["waf_detected"]:
            w.writerow(["waf", "Info", wafe["waf"], "", wafe["evidence"], "recon"])
        for d in f["directories"]:
            w.writerow(["directory", "Medium", "", d["url"], str(d.get("status", "")), "gobuster"])
        for a in f["admin_pages"]:
            w.writerow(["admin_page", "High", "", a["url"], str(a.get("status", "")), "enum"])
        for c in f["credentials"]:
            w.writerow(["credential", "Critical", c["username"], c.get("url", ""),
                        c["password"], "auth"])
        for sh in f["shells"]:
            w.writerow(["shell", "Critical", sh["type"], sh["path"], "", "exploit"])
    log("success", f"CSV report written: {out_path}")
    return out_path


# Full Report Pipeline
_GENERATORS = {
    "json":     generate_json_report,
    "html":     generate_html_report,
    "markdown": generate_markdown_report,
    "csv":      generate_csv_report,
}


def generate_reports(session: ScanSession, formats: list = None) -> dict:
    # Generating reports in requested formats. Returns {format: Path}.
    if formats is None:
        formats = ["json", "html", "markdown", "csv"]

    log("info", "="*55)
    log("info", "  REPORT GENERATION")
    log("info", "="*55)

    results = {}
    for fmt in formats:
        gen = _GENERATORS.get(fmt)
        if gen is None:
            log("warning", f"Unknown report format '{fmt}' — skipped.")
            continue
        results[fmt] = gen(session)

    log("success", f"Reports written to: {session.subdir('report')}")
    return results
