import json
import unittest
from pathlib import Path

from traceforge.case import Case
from traceforge.config import get_workspace_dir
from traceforge.web.router import Request, Response, Router
from traceforge.web.routes import register_all_routes
from traceforge.web.services import (
    batch_service,
    case_service,
    investigation_service,
    report_service,
    runtime_service,
    tool_service,
)


class TestWebRestructure(unittest.TestCase):
    def setUp(self):
        self.router = Router()
        register_all_routes(self.router)
        self.test_case_name = "Web Restructure Test Case"
        self.case = case_service.create_case(self.test_case_name, "Analyst Smith")

    def tearDown(self):
        if self.case:
            case_service.delete_case(self.case.case_id)

    def test_router_dispatch_get_cases(self):
        req = Request(method="GET", path="/api/cases", query_params={}, body=b"", headers={})
        resp = self.router.dispatch(req)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.body.decode("utf-8"))
        self.assertIn("cases", data)
        self.assertTrue(any(c["case_id"] == self.case.case_id for c in data["cases"]))

    def test_router_dispatch_get_single_case(self):
        req = Request(method="GET", path=f"/api/cases/{self.case.case_id}", query_params={}, body=b"", headers={})
        resp = self.router.dispatch(req)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.body.decode("utf-8"))
        self.assertEqual(data.get("case_id"), self.case.case_id)

    def test_case_service_evidence_and_iocs(self):
        # Ingest evidence
        rec = case_service.add_evidence(self.case.case_id, "network_sample.pcap", b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00", description="PCAP sample")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["filename"], "network_sample.pcap")

        # Ingest IOC
        ioc = case_service.add_case_ioc(self.case.case_id, "ip", "198.51.100.14")
        self.assertIsNotNone(ioc)
        self.assertEqual(ioc["type"], "ip")
        self.assertEqual(ioc["defanged"], "198[.]51[.]100[.]14")

        # Ingest finding
        f = case_service.add_case_finding(self.case.case_id, "Suspicious DNS query", "Found malicious lookup", severity="High")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"].lower(), "high")

        # Query via router
        req_iocs = Request(method="GET", path=f"/api/cases/{self.case.case_id}/iocs", query_params={"type": "ip"}, body=b"", headers={})
        resp_iocs = self.router.dispatch(req_iocs)
        self.assertEqual(resp_iocs.status_code, 200)
        data_iocs = json.loads(resp_iocs.body.decode("utf-8"))
        self.assertEqual(len(data_iocs["iocs"]), 1)
        self.assertEqual(data_iocs["iocs"][0]["value"], "198.51.100.14")

    def test_tool_service_and_catalog(self):
        tools = tool_service.list_catalog_tools()
        self.assertGreaterEqual(len(tools), 150)
        
        # Test tool lookup
        exif_tool = tool_service.get_tool_details("exiftool")
        self.assertIsNotNone(exif_tool)
        self.assertEqual(exif_tool["binary"], "exiftool")

        # Test platform audit endpoint
        req = Request(method="GET", path="/api/catalog/platform-audit", query_params={}, body=b"", headers={})
        resp = self.router.dispatch(req)
        self.assertEqual(resp.status_code, 200)
        audit_data = json.loads(resp.body.decode("utf-8"))
        self.assertIn("audit", audit_data)
        self.assertEqual(audit_data["audit"]["total_tools"], 152)

    def test_investigation_service_modules(self):
        mods = investigation_service.list_investigation_modules()
        self.assertEqual(len(mods), 7)
        mod_ids = [m["id"] for m in mods]
        self.assertIn("image", mod_ids)
        self.assertIn("network", mod_ids)
        self.assertIn("domain", mod_ids)
        self.assertIn("email", mod_ids)
        self.assertIn("identity", mod_ids)
        self.assertIn("documents", mod_ids)
        self.assertIn("opsec", mod_ids)

    def test_batch_service_plan_creation(self):
        req = Request(
            method="POST",
            path="/api/batch/plan",
            query_params={},
            body=json.dumps({"input": "target.example.com", "workflow": "domain"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        resp = self.router.dispatch(req)
        self.assertEqual(resp.status_code, 200)
        plan_data = json.loads(resp.body.decode("utf-8"))
        self.assertIn("plan", plan_data)
        self.assertEqual(plan_data["plan"]["input_type"].lower(), "domain")

    def test_runtime_service_endpoints(self):
        req_status = Request(method="GET", path="/api/runtime/status", query_params={}, body=b"", headers={})
        resp_status = self.router.dispatch(req_status)
        self.assertEqual(resp_status.status_code, 200)
        status_data = json.loads(resp_status.body.decode("utf-8"))
        self.assertIn("host", status_data)
        self.assertIn("capabilities", status_data)

        req_paths = Request(method="GET", path="/api/runtime/paths", query_params={}, body=b"", headers={})
        resp_paths = self.router.dispatch(req_paths)
        self.assertEqual(resp_paths.status_code, 200)
        paths_data = json.loads(resp_paths.body.decode("utf-8"))
        self.assertIn("workspace_dir", paths_data["paths"])

    def test_report_generation(self):
        report_md = report_service.generate_case_report(self.case.case_id, fmt="markdown")
        self.assertIn(self.test_case_name, report_md)


if __name__ == "__main__":
    unittest.main()
