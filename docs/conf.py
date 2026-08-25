import os
import sys
from pathlib import Path

# Path setup
DOCS_DIR = Path(__file__).resolve().parent
REPO_ROOT = DOCS_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

# Project information
project = "TraceForge"
copyright = "2026, Aman Kumar Pandey"
author = "Aman Kumar Pandey"

# Canonical version from VERSION file
version_file = REPO_ROOT / "VERSION"
if version_file.is_file():
    release = version_file.read_text(encoding="utf-8").strip()
else:
    release = "1.0.0"
version = ".".join(release.split(".")[:2])

# General configuration
extensions = [
    "myst_parser",
    "sphinx_rtd_theme",
]

source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

master_doc = "index"
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "README.md"]

# MyST Parser configuration
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
    "tasklist",
]
myst_heading_anchors = 3

# HTML output configuration
html_theme = "sphinx_rtd_theme"
html_title = f"TraceForge {release} Documentation"
html_theme_options = {
    "navigation_depth": 4,
    "collapse_navigation": False,
    "sticky_navigation": True,
    "includehidden": True,
    "titles_only": False,
}
html_static_path = []
