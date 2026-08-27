# Changelogs

Refer to the primary [CHANGELOG.md](file:///Users/paman/TraceForge/CHANGELOG.md) for detailed version history.

---

## Quick Summary of Recent Releases

### [1.0.1] - 2026-08-26
- **Release Automation**: Introduced `up.py` maintainer tool for building, creating clean zip releases, PyPI token verification, and GitHub tag management.
- **Catalog Integration Depth Audit**: Added `traceforge tools audit --integration` and web API route `GET /api/tools/audit`.
- **Toolchain Module Extensions**: Expanded automated forensics execution across image (`mediainfo`, `ffprobe`, `pngcheck`, `jhead`, `steghide`, `tesseract`, `foremost`), document (`pdfinfo`, `pdftotext`, `pdfimages`, `mutool`, `olevba`, `docx2txt`), and network (`capinfos`, `zeek`) modules.
- **Bug Fixes**: Resolved web service capability lookups and error handling for manual tools.
- **Diagnostics & Verification**: Runtime diagnostics and catalog integration audit passing cleanly.


### [1.0.0] - 2026-08-25
- **Initial Public Release**: 152-tool catalog, hybrid Python/Go performance engine, case management, multi-format exports (STIX 2.1, MISP, HTML, CSV, PDF), 7 investigation modules, and Termux mobile support.
