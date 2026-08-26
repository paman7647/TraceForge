import json
import unittest
from pathlib import Path
from traceforge.catalog import Catalog, ToolRecord, VALID_ECOSYSTEMS
from traceforge.platform_detect import detect_full_environment
from traceforge.runners import ToolRunner
from traceforge.cli import main as cli_main

class TestCatalogTools(unittest.TestCase):
    def setUp(self):
        self.catalog = Catalog()
        self.env = detect_full_environment()

    def test_catalog_integrity(self):
        """Audits all 152 catalog entries for uniqueness, non-empty fields, and valid ecosystems."""
        self.assertEqual(len(self.catalog), 152, f"Expected 152 catalog tools, found {len(self.catalog)}")
        audit_res = self.catalog.audit()
        self.assertTrue(audit_res["is_clean"], f"Catalog audit reported anomalies: {audit_res}")
        self.assertEqual(len(audit_res["duplicate_ids"]), 0)
        self.assertEqual(len(audit_res["duplicate_binaries"]), 0)
        self.assertEqual(len(audit_res["invalid_ecosystems"]), 0)

        for tool in self.catalog:
            self.assertGreater(tool.id, 0)
            self.assertTrue(tool.name, f"Tool #{tool.id} has empty name")
            self.assertTrue(tool.binary, f"Tool #{tool.id} has empty binary")
            self.assertTrue(tool.category, f"Tool #{tool.id} has empty category")
            self.assertIn(tool.ecosystem, VALID_ECOSYSTEMS, f"Tool #{tool.id} invalid ecosystem: {tool.ecosystem}")
            self.assertTrue(tool.description, f"Tool #{tool.id} has empty description")

    def test_tool_status_engine(self):
        """Verifies tool status serialization, platform support, and install commands."""
        tool = self.catalog.get_by_binary("exiftool")
        self.assertIsNotNone(tool, "ExifTool must exist in catalog")
        d = tool.to_dict()
        self.assertEqual(d["binary"], "exiftool")
        self.assertIn("is_installed", d)
        self.assertIn("is_supported", d)
        self.assertIn("install_command", d)
        self.assertIn("status_label", d)

    def test_catalog_search_and_filter(self):
        """Tests multi-field search and category/ecosystem filtering."""
        search_res = self.catalog.search("packet")
        self.assertGreater(len(search_res), 0)
        binaries = [t.binary for t in search_res]
        self.assertTrue(any(b in ("tshark", "tcpdump", "dumpcap") for b in binaries))

        # Filter by ecosystem
        native_tools = self.catalog.filter_tools(ecosystem="native")
        self.assertGreater(len(native_tools), 0)
        for t in native_tools:
            self.assertEqual(t.ecosystem, "native")

        # Filter by category
        forensics = self.catalog.filter_tools(category="Media & Image Forensics")
        self.assertGreater(len(forensics), 0)

    def test_profile_tool_mappings(self):
        """Validates that minimal, recommended, and full profiles resolve to registered catalog tools."""
        minimal = self.catalog.get_tools_for_profile("minimal")
        self.assertGreater(len(minimal), 10)
        recommended = self.catalog.get_tools_for_profile("recommended")
        self.assertGreater(len(recommended), len(minimal))
        full = self.catalog.get_tools_for_profile("full")
        self.assertEqual(len(full), 152)

    def test_coverage_calculation(self):
        """Tests dynamic calculation of coverage metrics."""
        cov = self.catalog.get_coverage_report()
        self.assertEqual(cov["total_catalog"], 152)
        self.assertEqual(cov["cli_accessible"], 152)
        self.assertEqual(cov["web_exposed"], 152)
        self.assertGreaterEqual(cov["installed_locally"], 0)
        self.assertEqual(cov["installed_locally"] + cov["missing_locally"] + cov["unavailable_on_platform"] + cov["manual_only"], 152)
        self.assertEqual(cov["installed_locally"] + cov["missing_locally"] + cov["manual_only"], cov["platform_supported"])

    def test_safe_runner_rejection_of_arbitrary_binary(self):
        """Asserts that ToolRunner.run_catalog_tool rejects non-cataloged binaries."""
        res = ToolRunner.run_catalog_tool("arbitrary_malicious_tool_xyz")
        self.assertEqual(res.exit_code, 127)
        self.assertIn("not a registered TraceForge catalog utility", res.stderr)

    def test_cli_tools_audit_and_coverage(self):
        """Tests that CLI commands for audit and coverage return exit code 0."""
        ret_audit = cli_main(["tools", "audit"])
        self.assertEqual(ret_audit, 0)

        ret_cov = cli_main(["tools", "coverage"])
        self.assertEqual(ret_cov, 0)

    def test_tool_dict_has_is_supported_key(self):
        """Regression: to_dict() must expose 'is_supported', not 'is_available_on_platform'."""
        for tool in self.catalog:
            d = tool.to_dict(self.env)
            self.assertIn("is_supported", d, f"Tool {tool.binary} missing 'is_supported' key")
            self.assertNotIn(
                "is_available_on_platform", d,
                f"Tool {tool.binary} has stale 'is_available_on_platform' key — update tool_service.py filter",
            )

    def test_platform_capability_has_no_is_manual_key(self):
        """Regression: get_platform_capability() must not expose 'is_manual'; availability string encodes this."""
        for tool in self.catalog:
            cap = tool.get_platform_capability(self.env)
            self.assertNotIn(
                "is_manual", cap,
                f"Tool {tool.binary} has stale 'is_manual' in capability dict",
            )
            self.assertIn("availability", cap)

    def test_integration_audit_shape_and_invariants(self):
        """Validates integration_audit() returns correct structure and tool counts sum to total."""
        result = self.catalog.integration_audit(self.env)

        required_keys = {
            "total_catalog", "fully_integrated", "runnable",
            "manual_only", "unsupported_on_platform",
            "fully_integrated_tools", "runnable_tools", "manual_tools",
            "unsupported_tools", "note",
        }
        self.assertEqual(required_keys, required_keys & result.keys())

        total = result["total_catalog"]
        self.assertEqual(total, 152)

        counted = (
            result["fully_integrated"]
            + result["runnable"]
            + result["manual_only"]
            + result["unsupported_on_platform"]
        )
        self.assertEqual(counted, total, "Integration depth counts must sum to total catalog size")

        # Known manual tools always classified as manual_only
        manual_binaries = {t["binary"] for t in result["manual_tools"]}
        for known_manual in ("snoop", "whatsmyname", "DiscordChatExporter-CLI"):
            self.assertIn(known_manual, manual_binaries, f"{known_manual} must be manual_only")

        # Spot-check: exiftool must be fully_integrated
        fi_binaries = {t["binary"] for t in result["fully_integrated_tools"]}
        self.assertIn("exiftool", fi_binaries)
        self.assertIn("tshark", fi_binaries)

    def test_list_catalog_tools_available_only_filter(self):
        """Regression: list_catalog_tools(available_only=True) must not raise KeyError."""
        from traceforge.web.services.tool_service import list_catalog_tools
        try:
            result = list_catalog_tools(available_only=True)
            self.assertIsInstance(result, list)
        except KeyError as e:
            self.fail(f"list_catalog_tools(available_only=True) raised KeyError: {e}")

    def test_install_catalog_tool_manual_returns_not_is_manual_keyerror(self):
        """Regression: install_catalog_tool on a manual tool must return error dict, not raise KeyError."""
        from traceforge.web.services.tool_service import install_catalog_tool
        try:
            result = install_catalog_tool("snoop")
            self.assertFalse(result.get("success", True), "Manual tool install must return success=False")
            self.assertIn("error", result)
        except KeyError as e:
            self.fail(f"install_catalog_tool raised KeyError on manual tool: {e}")

    def test_cli_tools_audit_integration_flag(self):
        """Tests that 'traceforge tools audit --integration' runs and returns exit code 0."""
        ret = cli_main(["tools", "audit", "--integration"])
        self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
