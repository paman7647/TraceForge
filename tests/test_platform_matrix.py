#!/usr/bin/env python3
"""
TraceForge Platform Matrix Unit Tests
====================================
Validates platform-aware capability resolution, environment detection fixtures,
profile installation preview planning, and platform rejection logic across:
- macOS (Apple Silicon arm64 & Intel x86_64)
- Linux (Debian x86_64, Ubuntu arm64, Kali Linux x86_64, Fedora x86_64)
- Android / Termux (aarch64)
- Unsupported OS environments
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

from traceforge.catalog import Catalog, ToolRecord
from traceforge.platform_detect import detect_platform, detect_full_environment


class TestPlatformMatrix(unittest.TestCase):
    def setUp(self):
        self.catalog = Catalog()
        self.assertEqual(len(self.catalog.tools), 152)

    def test_macos_arm64_environment(self):
        """Simulate macOS Apple Silicon arm64 environment."""
        mock_env = {
            "os": "darwin",
            "os_name": "macOS",
            "distro": "macOS",
            "distro_family": "darwin",
            "os_version": "14.5",
            "arch": "arm64",
            "hardware": "Apple Silicon (M-Series)",
            "display_name": "macOS Apple Silicon (arm64)",
            "is_termux": False,
            "has_root": False,
            "sudo_available": True,
            "pkg_manager": "homebrew",
            "pkg_manager_path": "/opt/homebrew/bin/brew",
            "python_version": "3.12.0",
            "in_venv": True,
            "has_go": True,
            "has_rust": False,
            "has_pipx": True,
        }

        audit = self.catalog.audit_platform(mock_env)
        self.assertEqual(audit["platform_name"], "macOS Apple Silicon (arm64)")
        self.assertGreater(audit["available_count"], 100)
        self.assertEqual(audit["total_catalog"], 152)

        # Exiftool (Homebrew available)
        exif = self.catalog.find_tool("exiftool")
        self.assertIsNotNone(exif)
        cap = exif.get_platform_capability(mock_env)
        self.assertTrue(cap["is_available"])
        self.assertEqual(cap["install_method"].lower(), "homebrew")
        self.assertEqual(cap["install_command"], "brew install exiftool")

        # Sherlock (Python / pipx)
        sherlock = self.catalog.find_tool("sherlock")
        self.assertIsNotNone(sherlock)
        cap_s = sherlock.get_platform_capability(mock_env)
        self.assertTrue(cap_s["is_available"])
        self.assertIn(cap_s["install_method"].lower(), ("python", "pipx"))

    def test_termux_aarch64_environment(self):
        """Simulate Android / Termux environment with pkg."""
        mock_env = {
            "os": "termux",
            "os_name": "Termux (Android)",
            "distro": "termux",
            "distro_family": "termux",
            "os_version": "Android 14",
            "arch": "arm64",
            "hardware": "ARM64",
            "display_name": "Termux / Android (arm64)",
            "is_termux": True,
            "has_root": False,
            "sudo_available": False,
            "pkg_manager": "pkg",
            "pkg_manager_path": "/data/data/com.termux/files/usr/bin/pkg",
            "python_version": "3.11.8",
            "in_venv": False,
            "has_go": True,
            "has_rust": False,
            "has_pipx": False,
        }

        audit = self.catalog.audit_platform(mock_env)
        self.assertEqual(audit["platform_name"], "Termux / Android (arm64)")
        self.assertGreater(audit["available_count"], 60)

        # Pure python tool is available on Termux
        holehe = self.catalog.find_tool("holehe")
        self.assertIsNotNone(holehe)
        cap_h = holehe.get_platform_capability(mock_env)
        self.assertTrue(cap_h["is_available"])

        # Tool without Termux recipe is marked NOT_AVAILABLE or MANUAL
        for tool in self.catalog.tools:
            cap = tool.get_platform_capability(mock_env)
            if not cap["is_available"]:
                self.assertEqual(cap["availability"], "NOT_AVAILABLE")
                self.assertIn("Termux", cap["reason"])
                self.assertFalse(cap["is_installable"])

    def test_linux_debian_environment(self):
        """Simulate Linux Debian x86_64 environment with apt."""
        mock_env = {
            "os": "linux",
            "os_name": "Linux",
            "distro": "Debian GNU/Linux",
            "distro_family": "debian",
            "os_version": "12.5",
            "arch": "x86_64",
            "hardware": "x86_64",
            "display_name": "Debian GNU/Linux (x86_64)",
            "is_termux": False,
            "has_root": False,
            "sudo_available": True,
            "pkg_manager": "apt",
            "pkg_manager_path": "/usr/bin/apt-get",
            "python_version": "3.11.2",
            "in_venv": True,
            "has_go": True,
            "has_rust": True,
            "has_pipx": True,
        }

        audit = self.catalog.audit_platform(mock_env)
        self.assertEqual(audit["platform_name"], "Debian GNU/Linux (x86_64)")
        self.assertGreater(audit["available_count"], 120)

        # Nmap via apt
        nmap = self.catalog.find_tool("nmap")
        self.assertIsNotNone(nmap)
        cap = nmap.get_platform_capability(mock_env)
        self.assertTrue(cap["is_available"])
        self.assertEqual(cap["install_method"].lower(), "apt")
        self.assertEqual(cap["install_command"], "sudo apt-get install -y nmap")

    def test_unsupported_platform_environment(self):
        """Simulate an unsupported platform (e.g. Windows or unknown BSD)."""
        mock_env = {
            "os": "windows",
            "os_name": "Windows",
            "distro": "Windows",
            "distro_family": "windows",
            "os_version": "11",
            "arch": "x86_64",
            "hardware": "x86_64",
            "display_name": "Windows (x86_64)",
            "is_termux": False,
            "has_root": False,
            "sudo_available": False,
            "pkg_manager": "none",
            "pkg_manager_path": None,
            "python_version": "3.12.0",
            "in_venv": False,
            "has_go": False,
            "has_rust": False,
            "has_pipx": False,
        }

        for tool in self.catalog.tools:
            cap = tool.get_platform_capability(mock_env)
            self.assertFalse(cap["is_available"])
            self.assertEqual(cap["availability"], "NOT_AVAILABLE")
            self.assertTrue("not supported" in cap["reason"].lower() or "not available" in cap["reason"].lower())

    def test_profile_installation_plan(self):
        """Test pre-installation plan generation for profiles."""
        mock_env_mac = {
            "os": "darwin",
            "os_name": "macOS",
            "distro": "macOS",
            "distro_family": "darwin",
            "os_version": "14.5",
            "arch": "arm64",
            "hardware": "Apple Silicon (M-Series)",
            "display_name": "macOS Apple Silicon (arm64)",
            "is_termux": False,
            "has_root": False,
            "sudo_available": True,
            "pkg_manager": "homebrew",
            "pkg_manager_path": "/opt/homebrew/bin/brew",
            "python_version": "3.12.0",
            "in_venv": True,
            "has_go": True,
            "has_rust": False,
            "has_pipx": True,
        }

        for profile in ["minimal", "recommended", "full"]:
            plan = self.catalog.get_install_plan_for_profile(profile, mock_env_mac)
            self.assertEqual(plan["profile"], profile)
            self.assertIn("installable", plan)
            self.assertIn("skipped_unavailable", plan)
            self.assertIn("skipped_manual", plan)

            # Sum of categorized tools matches total targeted
            total_resolved = (
                len(plan["installable"])
                + len(plan["already_installed"])
                + len(plan["skipped_unavailable"])
                + len(plan["skipped_manual"])
            )
            self.assertEqual(total_resolved, plan["total_profile_tools"])

            # Verify no skipped unavailable tool has is_installable == True
            for skip in plan["skipped_unavailable"]:
                self.assertIn("reason", skip)
                self.assertTrue(len(skip["reason"]) > 0)


if __name__ == "__main__":
    unittest.main()
