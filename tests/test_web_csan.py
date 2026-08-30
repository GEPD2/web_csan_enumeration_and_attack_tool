# Offline test suite for web_csan.
#
# Runs without any external scanning tool installed and without network access:
#   python3 -m unittest discover -s tests -v
#
# A small optional live-integration test hits the real tools and network only
# when WEB_CSAN_LIVE_TESTS=1 is set, so CI / offline runs stay hermetic.

import os
import csv
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import config.settings as settings
import core.session as session_mod
from core.session import ScanSession
from core.tools_manager import (
    PACKAGE_NAMES, GO_INSTALL_PATHS, PIP_INSTALL_PATHS, _detect_tool,
)
from modules import recon, report


def make_session(tmp: str, target_value: str = "10.10.10.10") -> ScanSession:
    # Building a ScanSession rooted in a temp dir so tests never touch $HOME.
    session_mod.OUTPUT_BASE_DIR = tmp
    return ScanSession({"type": "ip", "value": target_value}, stealth_profile="stealth")


def seed_findings(s: ScanSession) -> None:
    # Populating a session with a representative finding of every type.
    s.add_open_port(80, "tcp", "http", "Apache 2.4.41")
    s.add_open_port(443, "tcp", "https", "nginx")
    s.add_http_service("http://10.10.10.10", 200, "Apache", ["PHP", "WordPress"])
    s.add_waf("Cloudflare", "wafw00f: Cloudflare (Cloudflare Inc.)")
    s.add_directory("http://10.10.10.10/admin", 200, 1234)
    s.add_admin_page("http://10.10.10.10/wp-login.php", 200)
    s.add_vulnerability("Exposed .git", "high", "http://10.10.10.10/.git/", source="nuclei",
                        template="git-config")
    s.add_vulnerability("Wappalyzer tech", "info", "http://10.10.10.10", source="nuclei",
                        template="tech-detect")
    s.add_tls("https://10.10.10.10", {
        "protocols": ["TLS1.0", "TLS1.2"], "weak_ciphers": ["RC4"],
        "cert": {"subject": "CN=dev.internal"},
        "issues": ["legacy protocol TLS1.0", "1 weak cipher(s)"],
    })
    s.add_credential("admin", "password123", "http://10.10.10.10/wp-login.php")
    s.add_shell("php_reverse", "/tmp/shell.php")


class TestConfig(unittest.TestCase):
    def test_profiles_have_recon_tool_keys(self):
        for name, p in settings.STEALTH_PROFILES.items():
            for key in ("httpx_threads", "httpx_rate_limit",
                        "nuclei_concurrency", "nuclei_rate_limit", "whatweb_aggression"):
                self.assertIn(key, p, f"{name} missing {key}")

    def test_recon_depth_profiles(self):
        self.assertEqual(set(settings.RECON_DEPTH_PROFILES), {"light", "standard", "deep"})
        self.assertTrue(settings.RECON_DEPTH_PROFILES["deep"]["run_vuln_nse"])
        self.assertFalse(settings.RECON_DEPTH_PROFILES["light"]["run_tls"])
        self.assertIn("cve", settings.RECON_DEPTH_PROFILES["deep"]["nuclei_tags"])

    def test_report_formats(self):
        self.assertEqual(settings.REPORT_ALL_FORMATS, ["json", "html", "markdown", "csv"])

    def test_new_tools_registered(self):
        for t in ("httpx", "wafw00f", "nuclei", "sslscan"):
            self.assertIn(t, settings.TOOL_BINARIES)
            self.assertIn(t, settings.OPTIONAL_TOOLS)
            self.assertIn(t, PACKAGE_NAMES)

    def test_install_paths(self):
        self.assertIn("httpx", GO_INSTALL_PATHS)
        self.assertIn("nuclei", GO_INSTALL_PATHS)
        self.assertIn("wafw00f", PIP_INSTALL_PATHS)


class TestSession(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_new_finding_buckets(self):
        s = make_session(self.tmp)
        self.assertIn("vulnerabilities", s.findings)
        self.assertIn("tls", s.findings)

    def test_add_vulnerability_and_tls(self):
        s = make_session(self.tmp)
        s.add_vulnerability("Exposed .env", "critical", "http://t/.env", source="nuclei")
        s.add_tls("https://t", {"protocols": ["TLS1.2"], "issues": []})
        self.assertEqual(len(s.findings["vulnerabilities"]), 1)
        self.assertEqual(s.findings["vulnerabilities"][0]["severity"], "critical")
        self.assertEqual(len(s.findings["tls"]), 1)
        # events are logged too
        types = [e["type"] for e in s.events]
        self.assertIn("vulnerability", types)
        self.assertIn("tls_info", types)


class TestReconParsers(unittest.TestCase):
    def test_depth_config_defaults_to_standard(self):
        self.assertEqual(recon._depth_config("bogus"), settings.RECON_DEPTH_PROFILES["standard"])

    def test_parse_httpx_obj(self):
        obj = {
            "url": "https://x.tld", "status_code": 200, "title": "Home",
            "webserver": "nginx", "tech": ["Nginx", "PHP"],
            "cdn_name": "cloudflare", "tls": {"tls_version": "tls13"},
        }
        rec = recon._parse_httpx_obj(obj)
        self.assertEqual(rec["url"], "https://x.tld")
        self.assertEqual(rec["status"], 200)
        self.assertEqual(rec["server"], "nginx")
        self.assertIn("CDN:cloudflare", rec["tech_display"])
        self.assertTrue(any(t.startswith("Title:") for t in rec["tech_display"]))
        self.assertEqual(rec["tech"], ["Nginx", "PHP"])

    def test_parse_httpx_obj_no_url(self):
        self.assertIsNone(recon._parse_httpx_obj({"status_code": 200}))

    def test_parse_nuclei_obj(self):
        obj = {
            "template-id": "git-config",
            "info": {"name": "Exposed .git", "severity": "high"},
            "matched-at": "http://x.tld/.git/config",
        }
        rec = recon._parse_nuclei_obj(obj)
        self.assertEqual(rec["name"], "Exposed .git")
        self.assertEqual(rec["severity"], "high")
        self.assertEqual(rec["url"], "http://x.tld/.git/config")
        self.assertEqual(rec["template"], "git-config")

    def test_parse_sslscan_xml(self):
        xml = """<document>
          <ssltest host="ex.tld" port="443">
            <protocol type="ssl" version="3" enabled="0" />
            <protocol type="tls" version="1.0" enabled="1" />
            <protocol type="tls" version="1.2" enabled="1" />
            <cipher status="accepted" strength="weak" cipher="RC4-MD5" />
            <cipher status="accepted" strength="strong" cipher="AES256-GCM" />
            <certificate>
              <subject>CN=dev.internal</subject>
              <not-valid-after>2020-01-01</not-valid-after>
              <expired>true</expired>
            </certificate>
          </ssltest>
        </document>"""
        info = recon._parse_sslscan_xml(xml)
        self.assertIn("TLS1.0", info["protocols"])
        self.assertNotIn("SSL3", info["protocols"])   # disabled, excluded
        self.assertIn("RC4-MD5", info["weak_ciphers"])
        self.assertTrue(any("legacy protocol" in i for i in info["issues"]))
        self.assertTrue(any("weak cipher" in i for i in info["issues"]))
        self.assertTrue(any("expired" in i for i in info["issues"]))

    def test_parse_sslscan_xml_malformed(self):
        self.assertEqual(recon._parse_sslscan_xml("<not xml"), {})


class TestHttpxResolution(unittest.TestCase):
    @unittest.skipUnless(shutil.which("httpx"), "no httpx binary on PATH")
    def test_python_httpx_rejected(self):
        # On this environment the "httpx" on PATH is the Python HTTP client.
        # resolve_httpx_binary must not mistake it for the PD scanner.
        statuses = {"httpx": _detect_tool("httpx", "httpx")}
        resolved = recon.resolve_httpx_binary(statuses)
        # If it is the Python client, resolution returns None (falls back);
        # if a genuine PD httpx / httpx-toolkit is present it returns a path.
        if not shutil.which("httpx-toolkit"):
            probe = recon._is_pd_httpx("httpx")
            self.assertEqual(resolved is not None, probe)


class TestReports(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.s = make_session(self.tmp)
        seed_findings(self.s)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_all_formats_generated(self):
        results = report.generate_reports(self.s, formats=["json", "html", "markdown", "csv"])
        for fmt in ("json", "html", "markdown", "csv"):
            self.assertTrue(results[fmt].exists(), f"{fmt} not written")

    def test_json_structure(self):
        p = report.generate_json_report(self.s)
        data = json.loads(p.read_text())
        self.assertEqual(data["summary"]["vulnerabilities"], 2)
        self.assertEqual(data["summary"]["tls"], 1)
        self.assertIn("severity_breakdown", data)
        self.assertEqual(data["severity_breakdown"]["High"], 1)
        self.assertEqual(data["meta"]["overall_risk"], "Critical")  # creds + shell present

    def test_html_has_charts_and_no_emoji(self):
        p = report.generate_html_report(self.s)
        doc = p.read_text()
        self.assertIn("<svg", doc)                # inline chart present
        self.assertIn("web_csan Scan Report", doc)
        self.assertIn("Vulnerabilities", doc)
        # No emoji anywhere in the rendered report
        self.assertTrue(all(ord(ch) < 0x1F000 for ch in doc), "emoji found in HTML report")

    def test_markdown_content(self):
        p = report.generate_markdown_report(self.s)
        md = p.read_text()
        self.assertIn("## Vulnerabilities", md)
        self.assertIn("Exposed .git", md)
        self.assertIn("| Severity |", md)

    def test_csv_rows(self):
        p = report.generate_csv_report(self.s)
        rows = list(csv.reader(p.read_text().splitlines()))
        self.assertEqual(rows[0], ["category", "severity", "name", "location", "detail", "source"])
        cats = {r[0] for r in rows[1:]}
        for expected in ("vulnerability", "open_port", "credential", "shell", "tls"):
            self.assertIn(expected, cats)


class TestCharts(unittest.TestCase):
    def test_donut_empty(self):
        svg = report._svg_donut({k: 0 for k in report.SEVERITY_ORDER})
        self.assertIn("<svg", svg)
        self.assertIn("none", svg)

    def test_donut_with_data(self):
        svg = report._svg_donut({"Critical": 1, "High": 2, "Medium": 0, "Low": 0, "Info": 3})
        self.assertIn("stroke-dasharray", svg)
        self.assertIn(">6<", svg)   # total findings label

    def test_hbar(self):
        svg = report._svg_hbar([("A", 3, "#fff"), ("B", 7, "#000")])
        self.assertIn("<rect", svg)


class TestCustomPorts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_parse_custom_ports_valid(self):
        import main
        self.assertEqual(main.parse_custom_ports("8420"), [8420])
        self.assertEqual(main.parse_custom_ports("80,443, 8443"), [80, 443, 8443])
        self.assertIsNone(main.parse_custom_ports(""))
        self.assertIsNone(main.parse_custom_ports(None))

    def test_parse_custom_ports_invalid(self):
        import main
        with self.assertRaises(SystemExit):
            main.parse_custom_ports("nope")
        with self.assertRaises(SystemExit):
            main.parse_custom_ports("70000")

    def test_detect_scheme_prefers_https(self):
        # https responds -> https wins even though http also would.
        recon_http_probe = recon._http_probe
        try:
            recon._http_probe = lambda url: {"status": 200} if url.startswith("https") else {"status": 400}
            self.assertEqual(recon._detect_scheme("h", 8420), "https")
            recon._http_probe = lambda url: {"status": 200} if url.startswith("http://") else None
            self.assertEqual(recon._detect_scheme("h", 8080), "http")
            recon._http_probe = lambda url: None   # nothing responds -> default by port
            self.assertEqual(recon._detect_scheme("h", 8443), "https")  # 8443 is a HTTPS port
        finally:
            recon._http_probe = recon_http_probe

    def test_probe_adds_custom_port(self):
        s = make_session(self.tmp)
        orig_probe, orig_waf = recon._http_probe, recon.detect_waf
        try:
            recon._http_probe = lambda url: (
                {"status": 200, "server": "nginx", "headers": {}, "body_snippet": ""}
                if url == "https://10.10.10.10:8420" else None
            )
            recon.detect_waf = lambda *a, **k: None
            live = recon.probe_http_services(s, custom_ports=[8420])
            urls = [x["url"] for x in live]
            self.assertIn("https://10.10.10.10:8420", urls)
        finally:
            recon._http_probe, recon.detect_waf = orig_probe, orig_waf


class TestHttpServiceDedup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_same_url_merges(self):
        s = make_session(self.tmp)
        s.add_http_service("https://t:8420", 0, "", [])            # nmap seed
        s.add_http_service("https://t:8420/", 200, "nginx", ["PHP"])  # prober fill-in
        self.assertEqual(len(s.findings["http_services"]), 1)
        svc = s.findings["http_services"][0]
        self.assertEqual(svc["status"], 200)
        self.assertEqual(svc["server"], "nginx")
        self.assertIn("PHP", svc["tech"])


@unittest.skipUnless(os.environ.get("WEB_CSAN_LIVE_TESTS") == "1",
                     "live test (set WEB_CSAN_LIVE_TESTS=1 to run; needs tools + network)")
class TestLiveIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_wafw00f_live(self):
        if not shutil.which("wafw00f"):
            self.skipTest("wafw00f not installed")
        s = make_session(self.tmp, "example.com")
        statuses = {"wafw00f": _detect_tool("wafw00f", "wafw00f")}
        res = recon.run_wafw00f(s, statuses, ["http://example.com"])
        self.assertIsInstance(res, dict)


if __name__ == "__main__":
    unittest.main()
