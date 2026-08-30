# Changelogs

Refer to the primary [CHANGELOG.md](file:///Users/paman/TraceForge/CHANGELOG.md) for detailed version history.

---

## Quick Summary of Recent Releases

### [1.1.0] - 2026-08-31
- **API Keys & OSINT Credentials Vault**: Secure local storage at `~/.traceforge/credentials.env` (`chmod 600`), masking in output, and interactive/CLI key management for 20+ OSINT API providers (Shodan, VT, Censys, Hunter, HIBP, OTX, Chaos, IPinfo, WiGLE, Etherscan, etc.).
- **Deep OSINT Catalog Expansion**: Expanded catalog from 152 to **175 audited tools** across **13 investigation domains**, introducing Threat Intelligence, Cloud Exposure, Crypto/Blockchain, Geospatial/IoT, and Corporate/Darknet OSINT categories.
- **Quick vs. Full Deep Scan Execution**: Module execution prompts for quick vs. deep scans with real-time terminal progress timers, generating standardized 6-format structured reports (`report.txt`, `report.md`, `report.html`, `report.json`, `iocs.json`, `manifest.txt`).
- **macOS Bash 3.2 Compatibility & Environment Auto-Repair**: Full compatibility across older BSD/macOS Bash versions and automated shell PATH integration.

### [1.0.1] - 2026-08-26

- **Release Automation**: Introduced `up.py` maintainer tool for building, creating clean zip releases, PyPI token verification, and GitHub tag management.
- **Catalog Integration Depth Audit**: Added `traceforge tools audit --integration` and web API route `GET /api/tools/audit`.
- **Toolchain Module Extensions**: Expanded automated forensics execution across image (`mediainfo`, `ffprobe`, `pngcheck`, `jhead`, `steghide`, `tesseract`, `foremost`), document (`pdfinfo`, `pdftotext`, `pdfimages`, `mutool`, `olevba`, `docx2txt`), and network (`capinfos`, `zeek`) modules.
- **Bug Fixes**: Resolved web service capability lookups and error handling for manual tools.
- **Diagnostics & Verification**: Runtime diagnostics and catalog integration audit passing cleanly.


### [1.0.0] - 2026-08-25
- **Initial Public Release**: 152-tool catalog, hybrid Python/Go performance engine, case management, multi-format exports (STIX 2.1, MISP, HTML, CSV, PDF), 7 investigation modules, and Termux mobile support.
