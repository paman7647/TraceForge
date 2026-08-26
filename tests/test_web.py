import json
import os
import shutil
import tempfile
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

from traceforge.case import Case, create_case, get_active_case, list_all_cases, set_active_case
from traceforge.catalog import Catalog
from traceforge.config import get_project_root, get_workspace_dir, set_runtime_profile
from traceforge.exporters import CaseExporter
from traceforge.modules.documents import run_document_harvesting
from traceforge.modules.domain import run_domain_dns
from traceforge.modules.email import run_email_breach
from traceforge.modules.identity import run_identity_social
from traceforge.modules.image import run_image_forensics
from traceforge.modules.network import run_network_recon
from traceforge.modules.opsec import run_opsec_audit
from traceforge.platform_detect import is_tool_installed, which_tool
from traceforge.tools import (
    AssetGraph,
    correlate_observations,
    create_filesystem_baseline,
    defang_ioc,
    extract_iocs,
    index_evidence_directory,
    inspect_endpoint,
    normalize_timeline,
    package_case,
    summarize_pcap,
    triage_log_stream,
)

class TestTraceForgeCore(unittest.TestCase):
    """Verifies all first-party core utilities and analytical engines."""

    def test_ioc_extraction_and_defanging(self):
        text = "Observed malicious beacon from 198.51.100.23 connecting to https://evil-c2.net/payload.exe with md5 44d88612fea8a8f36de82e1278abb02f"
        iocs = extract_iocs(text)
        types = [i["type"] for i in iocs]
        self.assertIn("ipv4", types)
        self.assertIn("domain", types)
        self.assertIn("url", types)
        self.assertIn("md5", types)

        defanged_ip = defang_ioc("ipv4", "198.51.100.23")
        self.assertEqual(defanged_ip, "198[.]51[.]100[.]23")

        defanged_url = defang_ioc("url", "https://evil-c2.net/payload.exe")
        self.assertTrue(defanged_url.startswith("hxxps://"))

    def test_asset_graph(self):
        g = AssetGraph()
        lines = [
            "evil-corp.com, 198.51.100.99",
            "api.evil-corp.com: 198.51.100.99",
        ]
        g.parse_lines(lines)
        d = g.to_dict()
        self.assertGreaterEqual(len(d["nodes"]), 2)
        self.assertGreaterEqual(len(d["edges"]), 1)
        html = g.export_html()
        self.assertIn("<!DOCTYPE html>", html)

    def test_log_triage(self):
        logs = [
            '203.0.113.5 - - [26/Aug/2026:04:00:00 +0000] "POST /login HTTP/1.1" 401 120 - Failed password',
            '203.0.113.5 - - [26/Aug/2026:04:00:01 +0000] "POST /login HTTP/1.1" 401 120 - Failed password',
            '203.0.113.5 - - [26/Aug/2026:04:00:02 +0000] "POST /login HTTP/1.1" 401 120 - Failed password',
        ]
        res = triage_log_stream(logs)
        self.assertEqual(res["auth_failures"], 3)
        self.assertIn("203.0.113.5", res["top_ips"])

    def test_endpoint_inspect(self):
        snap = inspect_endpoint()
        self.assertIn("hostname", snap)
        self.assertIn("os", snap)
        self.assertIn("architecture", snap)

    def test_evidence_indexing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "file1.txt").write_text("hello world")
            (p / "file2.bin").write_bytes(b"\x00\x01\x02")
            indexed = index_evidence_directory(p)
            self.assertEqual(len(indexed), 2)
            self.assertTrue(all("sha256" in x for x in indexed))

class TestTraceForgeCaseAndExporters(unittest.TestCase):
    """Verifies case creation, evidence registration, findings, and deliverables export."""

    def setUp(self):
        self.test_case_id = f"TEST-{os.urandom(4).hex().upper()}"
        self.case = create_case(name="Automated Test Case", analyst="CI Runner", case_id=self.test_case_id)

    def tearDown(self):
        if self.case.case_dir.exists():
            shutil.rmtree(self.case.case_dir, ignore_errors=True)

    def test_case_lifecycle(self):
        self.assertTrue(self.case.exists())
        self.assertEqual(self.case.data["case_name"], "Automated Test Case")

        # Ingest Evidence
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp.write(b"Malicious specimen memory artifact with IP 198.51.100.1")
            tmp_path = Path(tmp.name)

        try:
            evid = self.case.add_evidence(tmp_path, description="Test Specimen", source_device="Unit-Test")
            self.assertEqual(evid["id"], "EVID-001")
            self.assertIn("sha256", evid)
            self.assertIn("md5", evid)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

        # Add Finding
        f = self.case.add_finding("Suspicious Ingress", severity="high", category="Network")
        self.assertEqual(f["id"], "FIND-001")

        # Add IOC
        ioc = self.case.add_ioc("198.51.100.1", "ipv4", source="Memory Artifact", confidence="high")
        self.assertEqual(ioc["id"], "IOC-001")

        # Add Timeline Event
        ev = self.case.add_event("2026-08-26T04:00:00Z", "Initial Discovery", severity="high")
        self.assertEqual(ev["severity"], "high")

        # Package Case
        pkg, digest = package_case(self.case.case_dir, format_type="zip")
        self.assertTrue(pkg.exists())
        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 64)

        # Exporter
        exporter = CaseExporter(self.case)
        all_exports = exporter.export_all()
        self.assertIn("markdown", all_exports)
        self.assertIn("html", all_exports)
        self.assertIn("stix", all_exports)
        self.assertIn("misp", all_exports)
        self.assertIn("csv_iocs", all_exports)
        self.assertTrue(all_exports["markdown"].exists())
        self.assertTrue(all_exports["html"].exists())

if __name__ == "__main__":
    unittest.main()
