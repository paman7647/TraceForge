"""
TraceForge Automated Packaging, Installation, and Path Isolation Test Suite.
Validates pyproject.toml, package data integrity, path separation, Go build helper, and doctor repair.
"""

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from traceforge import __version__
from traceforge.catalog import Catalog, get_bundled_catalog_path
from traceforge.cli import run_doctor
from traceforge.config import (
    get_cache_dir,
    get_config_dir,
    get_config_path,
    get_logs_dir,
    get_project_root,
    get_user_data_dir,
    get_workspace_dir,
    load_config,
)


class TestInstallerPackaging(unittest.TestCase):
    def setUp(self):
        self.root_dir = Path(__file__).resolve().parent.parent

    def test_pyproject_structure(self):
        pyproj_path = self.root_dir / "pyproject.toml"
        self.assertTrue(pyproj_path.exists(), "pyproject.toml must exist")
        content = pyproj_path.read_text(encoding="utf-8")

        self.assertIn('name = "traceforge-osint"', content)
        self.assertIn(f'version = "{__version__}"', content)
        self.assertIn('requires-python = ">=3.9"', content)
        self.assertIn("traceforge = \"traceforge.cli:main\"", content)

        # Verify clean extras separation
        self.assertIn("[project.optional-dependencies]", content)
        self.assertIn("reporting =", content)
        self.assertIn("openpyxl", content)
        self.assertIn("python-docx", content)
        self.assertIn("docs =", content)
        self.assertIn("dev =", content)
        self.assertIn("all =", content)

    def test_manifest_and_requirements(self):
        manifest_path = self.root_dir / "MANIFEST.in"
        req_path = self.root_dir / "requirements.txt"
        req_dev_path = self.root_dir / "requirements-dev.txt"

        self.assertTrue(manifest_path.exists(), "MANIFEST.in must exist")
        self.assertTrue(req_path.exists(), "requirements.txt must exist")
        self.assertTrue(req_dev_path.exists(), "requirements-dev.txt must exist")

        m_content = manifest_path.read_text(encoding="utf-8")
        self.assertIn("traceforge/data", m_content)
        self.assertIn("traceforge/web/static", m_content)

    def test_bundled_package_data_assets(self):
        cat_path = get_bundled_catalog_path()
        self.assertTrue(cat_path.exists(), f"Bundled catalog path must exist: {cat_path}")

        cat = Catalog()
        self.assertGreaterEqual(len(cat.tools), 150, "Must load at least 150 tools from catalog")

        # Static assets
        static_dir = self.root_dir / "traceforge" / "web" / "static"
        self.assertTrue((static_dir / "app.js").exists(), "app.js must be present in static assets")
        self.assertTrue((static_dir / "style.css").exists(), "style.css must be present in static assets")
        self.assertTrue((static_dir / "index.html").exists(), "index.html must be present in static assets")

    def test_system_paths_isolation(self):
        cfg_dir = get_config_dir()
        cfg_path = get_config_path()
        user_data = get_user_data_dir()
        ws_dir = get_workspace_dir()
        cache_dir = get_cache_dir()
        logs_dir = get_logs_dir()

        self.assertTrue(isinstance(cfg_dir, Path))
        self.assertTrue(isinstance(cfg_path, Path))
        self.assertTrue(isinstance(user_data, Path))
        self.assertTrue(isinstance(ws_dir, Path))
        self.assertTrue(isinstance(cache_dir, Path))
        self.assertTrue(isinstance(logs_dir, Path))

        # Must not write to site-packages
        self.assertNotIn("site-packages", str(cfg_dir))
        self.assertNotIn("site-packages", str(cache_dir))
        self.assertNotIn("site-packages", str(logs_dir))

    def test_doctor_repair_execution(self):
        # Execute doctor in repair mode without error
        try:
            run_doctor(repair=True)
        except Exception as e:
            self.fail(f"run_doctor(repair=True) raised unexpected exception: {e}")

    def test_build_native_script_execution(self):
        script_path = self.root_dir / "scripts" / "build_native.sh"
        self.assertTrue(script_path.exists(), "scripts/build_native.sh must exist")
        self.assertTrue(os.access(script_path, os.X_OK), "scripts/build_native.sh must be executable")

        res = subprocess.run([str(script_path)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"scripts/build_native.sh failed: {res.stderr}")


if __name__ == "__main__":
    unittest.main()
