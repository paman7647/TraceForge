"""
Automated Test Suite for TraceForge Batch Investigation & Custom Tool Sets Engine
Lead Architect: Aman Kumar Pandey
"""

import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

from traceforge.batch import (
    BatchEngine,
    BatchPlan,
    BatchResult,
    NormalizedToolResult,
    PREDEFINED_WORKFLOWS,
    classify_input_type,
    evaluate_tool_input_compatibility,
    is_active_network_tool,
)
from traceforge.catalog import Catalog, ToolRecord


class TestBatchEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="traceforge_batch_test_")
        self.engine = BatchEngine()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_classify_input_type(self):
        # Image file
        img = Path(self.temp_dir) / "sample.jpg"
        img.write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * 32)
        c_img = classify_input_type(str(img))
        self.assertEqual(c_img["type"], "file")
        self.assertEqual(c_img["specific"], "image")
        self.assertTrue(c_img["exists"])

        # PCAP file
        pcap = Path(self.temp_dir) / "capture.pcap"
        pcap.write_bytes(b"\xD4\xC3\xB2\xA1" + b"\x00" * 32)
        c_pcap = classify_input_type(str(pcap))
        self.assertEqual(c_pcap["type"], "file")
        self.assertEqual(c_pcap["specific"], "pcap")

        # Network Observables
        c_dom = classify_input_type("target-domain.com")
        self.assertEqual(c_dom["type"], "domain")

        c_ip = classify_input_type("192.168.1.100")
        self.assertEqual(c_ip["type"], "ipv4")

        c_url = classify_input_type("https://malicious.site/login.php")
        self.assertEqual(c_url["type"], "url")

        c_mail = classify_input_type("target@company.org")
        self.assertEqual(c_mail["type"], "email")

        c_user = classify_input_type("shadow_hunter99")
        self.assertEqual(c_user["type"], "username")

    def test_active_network_detection(self):
        self.assertTrue(is_active_network_tool("nmap"))
        self.assertTrue(is_active_network_tool("subfinder"))
        self.assertTrue(is_active_network_tool("masscan"))
        self.assertFalse(is_active_network_tool("exiftool"))
        self.assertFalse(is_active_network_tool("strings"))
        self.assertFalse(is_active_network_tool("binwalk"))

    def test_input_compatibility_rules(self):
        cat = Catalog()
        exiftool = cat.find_tool("exiftool")
        tshark = cat.find_tool("tshark")
        whois = cat.find_tool("whois")

        self.assertIsNotNone(exiftool)
        self.assertIsNotNone(tshark)
        self.assertIsNotNone(whois)

        # Image compatibility
        img_info = {"type": "file", "specific": "image", "extension": ".jpg"}
        self.assertTrue(evaluate_tool_input_compatibility(exiftool, img_info)["is_compatible"])
        self.assertFalse(evaluate_tool_input_compatibility(tshark, img_info)["is_compatible"])

        # PCAP compatibility
        pcap_info = {"type": "file", "specific": "pcap", "extension": ".pcap"}
        self.assertTrue(evaluate_tool_input_compatibility(tshark, pcap_info)["is_compatible"])

        # Domain compatibility
        dom_info = {"type": "domain", "specific": "domain", "value": "example.com"}
        self.assertTrue(evaluate_tool_input_compatibility(whois, dom_info)["is_compatible"])
        self.assertFalse(evaluate_tool_input_compatibility(exiftool, dom_info)["is_compatible"])

    def test_batch_plan_creation(self):
        # Create plan for domain
        plan = self.engine.create_plan(
            raw_input="example.com",
            tool_identifiers=["whois", "dig", "exiftool", "tshark"],
            execution_mode="sequential",
        )

        self.assertEqual(plan.input_info["type"], "domain")
        compatible_bins = [t["binary"] for t in (plan.executable_tools + plan.missing_tools)]
        self.assertIn("whois", compatible_bins)
        self.assertTrue(any(t["binary"] == "exiftool" for t in plan.incompatible_tools))
        self.assertTrue(any(t["binary"] == "tshark" for t in plan.incompatible_tools))


    def test_normalized_tool_result_and_deduplication(self):
        t1 = NormalizedToolResult(
            tool_id=1,
            tool_name="Tool 1",
            binary="tool1",
            command=["tool1", "arg"],
            exit_code=0,
            stdout="Found domain suspicious.org and IP 1.2.3.4 and sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            stderr="",
            duration_seconds=0.5,
            executed_at="2026-08-26T12:00:00Z",
            input_target="specimen.bin",
        )

        t2 = NormalizedToolResult(
            tool_id=2,
            tool_name="Tool 2",
            binary="tool2",
            command=["tool2", "arg"],
            exit_code=0,
            stdout="Referenced 1.2.3.4 and suspicious.org and evil.com",
            stderr="",
            duration_seconds=0.4,
            executed_at="2026-08-26T12:00:01Z",
            input_target="specimen.bin",
        )

        res = BatchResult(
            job_id="test-job-001",
            input_target="specimen.bin",
            input_type="file",
            workflow_name="Custom Test",
            started_at="2026-08-26T12:00:00Z",
            completed_at="2026-08-26T12:00:02Z",
            duration_seconds=0.9,
            tool_results=[t1, t2],
            skipped_tools=[],
        )

        # Check deduplication & multi-source attribution
        iocs = res.deduplicated_indicators
        ip_ioc = next((i for i in iocs if i["value"] == "1.2.3.4"), None)
        self.assertIsNotNone(ip_ioc)
        self.assertIn("tool1", ip_ioc["sources"])
        self.assertIn("tool2", ip_ioc["sources"])
        self.assertEqual(ip_ioc["defanged"], "1[.]2[.]3[.]4")

        # Check report generation
        md = res.generate_markdown_report()
        self.assertIn("# TraceForge Batch Investigation Report", md)
        self.assertIn("test-job-001", md)
        self.assertIn("1[.]2[.]3[.]4", md)

    def test_custom_profile_crud(self):
        # Save profile
        p = self.engine.save_custom_profile("Deep Media Triage", "Comprehensive media analysis", ["exiftool", "strings", "binwalk"])
        self.assertIsNotNone(p["id"])
        self.assertEqual(p["name"], "Deep Media Triage")

        # List profiles
        profs = self.engine.list_saved_profiles()
        self.assertTrue(any(x["id"] == p["id"] for x in profs))

        # Delete profile
        ok = self.engine.delete_custom_profile(p["id"])
        self.assertTrue(ok)

        # System profile protected
        sys_del = self.engine.delete_custom_profile("image")
        self.assertFalse(sys_del)


if __name__ == "__main__":
    unittest.main()
