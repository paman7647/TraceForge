# Changelog

All notable changes to **TraceForge** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] - 2026-08-26

### Fixed
- **Web API Tool Filtering**: Corrected parameter resolution in `traceforge/web/services/tool_service.py` where `is_available_on_platform` was checked instead of `is_supported`.
- **Manual Tool Installation**: Corrected error reporting logic in `install_catalog_tool()` to inspect `cap.get("availability") == "MANUAL_INSTALL"` rather than a missing dictionary key.
- **Workflow Binary Consistency**: Standardized case-sensitive binary identifiers across batch workflows (`theHarvester`, `gpg`).

### Added
- **Tool Integration Depth Audit**: New `Catalog.integration_audit()` system and CLI command (`traceforge tools audit --integration`) classifying tools into `FULLY_INTEGRATED`, `RUNNABLE`, `MANUAL_ONLY`, and `UNSUPPORTED_ON_PLATFORM`.
- **Web Integration Audit Endpoint**: Exposed `GET /api/tools/audit` route in the web console for real-time toolchain integration telemetry.
- **Extended Module Coverage**:
  - `traceforge/modules/image.py`: Native inspection support for `ffprobe`, `mediainfo`, `pngcheck`, `jhead`, `steghide`, `yara`, `tesseract`, and `foremost`.
  - `traceforge/modules/documents.py`: Native parsing support for `pdfinfo`, `pdftotext`, `pdfimages`, `mutool`, `olevba`, `oleid`, `antiword`, `docx2txt`, and `mat2`.
  - `traceforge/modules/network.py`: PCAP telemetry enhancements using `capinfos`, `tcpdump` fallback inspection, and `zeek` connection log extraction.
- **Extended Predefined Batch Workflows**: Expanded automated tool chains in `traceforge/batch.py` for image, network, domain, and document investigation routines.
- **Regression Validation**: Validated catalog tool dictionary invariants, capability lookups, integration audit counts, and CLI `--integration` flags.


### Security
- **Secure Secret Handling in Release Pipeline**: Release tokens are loaded dynamically from environment variables or masked interactive prompts (`getpass`), preventing credential leaks in terminal history and logs.
- **Ignored Release and Test Artifacts**: Hardened `.gitignore` to strictly exclude `up.py`, `.env`, build wheels, release ZIPs, and local test artifacts from public source control.

---

## [1.0.0] - 2026-08-25

### Added
- **Initial Stable Release**: TraceForge 1.0.0 open-source OSINT, DFIR, and digital investigation toolkit.
- **First-Party High-Performance Engine**: Pure Python analytical reference implementations in `traceforge/` with compiled Go acceleration helpers (`traceforge-native`) for asset graphing, snapshot diffing, streaming IOC extraction, evidence directory indexing, log stream triage, and PCAP analysis.
- **Adaptive Runtime Profiles**: Interactive setup and configuration supporting `python-go` (default), `python`, `go`, `minimal`, `full`, and `custom` profiles with feature-level fast-path overrides.
- **Termux & Android Support**: First-class support for Termux on Android (ARM64, ARMv7, x86_64) without root, supporting `$HOME/storage` integration, Termux `pkg` provisioning, and userland forensics.
- **152-Tool Catalog**: 22-column verified catalog (`catalog/tools.tsv`) with per-platform installation recipes across Homebrew, Debian/APT, Termux `pkg`, `pipx`, Go, Cargo, and RubyGems.
- **Case Management & Chain of Custody**: Workspaces in `workspace/` with unique case IDs, SHA-256 evidence hashing, findings, indicators, timeline events, and append-only audit logging.
- **Multi-Format Export Subsystem**: Generates case reports in Markdown, standalone dark-mode HTML, relational CSV (with formula injection defense), TSV, JSON, JSONL event streams, STIX 2.1 intelligence bundles, MISP event JSON, GeoJSON, Google Earth KML, and signed ZIP evidence packages.
- **PII & Data Redaction Engine**: Built-in `--redact` flag for masking sensitive IP addresses and email addresses in generated exports and threat intelligence feeds.
- **7 Investigation Modules**: Automated CLI workflows covering media forensics, network PCAPs, usernames, email breaches, domain DNS, document harvesting, and defensive OPSEC audits.
- **Interactive Console & CLI Dispatcher**: Interactive TTY menu (`main.sh` / `traceforge`) and direct CLI subcommands (`doctor`, `profile`, `config`, `case`, `tools`, `module`, `catalog`, `export`, `termux`, `legal`).
- **Pre-Flight Release Suite**: `scripts/release_check.sh` automating file existence, permissions, syntax, ShellCheck, catalog schema, secret scanning, and test verification.

### Security
- Comprehensive legal disclaimer, responsible use policy, and privacy policy documentation (`DISCLAIMER.md`, `RESPONSIBLE_USE.md`, `PRIVACY.md`).
- Structured array execution (`"${cmd[@]}"`) eliminating shell command injection risks.
- RFC 4180 CSV formula sanitization (`'`, `+`, `-`, `=`, `@`) preventing spreadsheet injection vulnerabilities.
- Read-only evidence ingestion preserving cryptographic file integrity.
- Zero hardcoded secrets, private keys, or machine-specific developer paths.

### Documentation
- Architectural guides for runtime profiles (`docs/RUNTIME_PROFILES.md`), first-party tools (`docs/FIRST_PARTY_TOOLS.md`), Termux deployment (`docs/platforms/termux.md`), branching model (`docs/BRANCHING.md`), bug reporting (`docs/BUG_REPORTING.md`), legal risk assessment (`docs/LEGAL_RISK_ASSESSMENT.md`), and third-party notices (`THIRD_PARTY_NOTICES.md`).

---

[1.0.1]: https://github.com/paman7647/TraceForge/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/paman7647/TraceForge/releases/tag/v1.0.0
