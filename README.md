# TraceForge

<div align="center">

**Open-source OSINT, digital forensics, and security investigation toolkit.**

[![Documentation](https://img.shields.io/badge/docs-ReadTheDocs-blue.svg)](https://traceforge.readthedocs.io/en/latest/)
[![CI](https://github.com/paman7647/TraceForge/actions/workflows/ci.yml/badge.svg)](https://github.com/paman7647/TraceForge/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/traceforge-osint.svg)](https://pypi.org/project/traceforge-osint/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Android-informational.svg)](https://traceforge.readthedocs.io/en/latest/installation.html)

[Documentation](https://traceforge.readthedocs.io/en/latest/) · [Releases](https://github.com/paman7647/TraceForge/releases) · [Issues](https://github.com/paman7647/TraceForge/issues) · [Contributing](CONTRIBUTING.md)

</div>

---

TraceForge is a local CLI toolkit designed for investigative workflows such as IOC extraction, evidence hashing, timeline processing, log triage, filesystem baselining, case management, reporting, and external-tool integration.

Built for authorized security research, DFIR, OSINT, and educational lab work.

---

## Features

- **IOC Extraction & Defanging** — Extract IPs, domains, hashes, and URLs with automatic defanging.
- **Evidence Hashing & Indexing** — Cryptographic SHA-256 evidence hashing and chain-of-custody tracking.
- **Timeline & Log Processing** — Parse, normalize, and triage timestamps and event logs.
- **Filesystem Baselines & Diffs** — Track filesystem integrity, file additions, deletions, and modifications.
- **Local Case Management** — Self-contained case workspaces under `workspace/`.
- **Asset Relationship Graphs** — Generate visual entity and infrastructure graphs.
- **Multi-Format Exports** — Export findings to Markdown, standalone HTML, CSV, JSON/JSONL, STIX 2.1, MISP, GeoJSON, and KML.
- **External Tool Catalog** — Curated index of security and forensic tools with automated profile-based setup.
- **Adaptive Architecture** — Python reference implementations with native Go fast paths.
- **Cross-Platform** — macOS (Apple Silicon & Intel), Linux (Debian, Ubuntu, Kali), and Android (Termux).

---

## Architecture

TraceForge intentionally uses three languages for different roles:

- **Python** — Main application, CLI, case workflows, analysis, configuration, and reporting.
- **Go** — High-throughput fast paths such as bulk hashing, streaming IOC extraction, and filesystem scanning.
- **Bash** — Installation, dependency setup, platform detection, and system-level operations.

```text
User
 ↓
Python CLI (traceforge / ./main.sh)
 ├── Cases / Analysis / Reports
 ├── External Tool Integrations
 └── Go Fast Paths (with Python fallbacks)
```

The project does not use Go as a duplicate copy of the application; Go provides focused, compiled binaries for compute- and I/O-heavy paths.

---

## Quick Start

### 1. One-Liner Quick Install (`curl`)

Install and bootstrap TraceForge automatically with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/paman7647/TraceForge/master/scripts/bootstrap.sh | bash
```

Or with a specific profile:

```bash
curl -fsSL https://raw.githubusercontent.com/paman7647/TraceForge/master/scripts/bootstrap.sh | bash -s -- --profile recommended
```

---

### 2. Global Installation via `pip`

```bash
pip install traceforge-osint
```

Once installed, TraceForge is immediately available globally from any directory:

```bash
# Verify installation and toolchain health
traceforge doctor

# Launch the interactive terminal console
traceforge

# Launch the local interactive web interface (http://127.0.0.1:8000)
traceforge web
```

---

### 3. Development Installation from Source

```bash
git clone https://github.com/paman7647/TraceForge.git
cd TraceForge
pip install -e .
./setup.sh
```

---

## Example CLI Commands

TraceForge operates seamlessly without requiring users to change into specific directories:

```bash
# View system & user data paths
traceforge config paths

# Case Management
traceforge case new "Operation Red Horizon" --analyst "Lead Analyst"
traceforge cases
traceforge case open CASE-20260826-XXXXXX

# Evidence Ingestion & Hashing
traceforge evidence add /path/to/specimen.pcap --desc "Network Capture"
traceforge evidence list

# Threat Observables (IOCs)
echo "Suspicious node: 198.51.100.25 on malware.domain.org" | traceforge ioc extract --defang
traceforge ioc add 203.0.113.50 --type ipv4

# API Keys & OSINT Credentials Vault
traceforge credentials list
traceforge credentials set SHODAN_API_KEY <YOUR_KEY>

# Run Investigation Modules (Quick or Full Deep Scan)
traceforge investigate image specimen.jpg --mode full
traceforge investigate network capture.pcap
traceforge investigate domain target.corp --mode quick
traceforge investigate identity analyst_handle
traceforge investigate email suspect@domain.com
traceforge investigate opsec

# Multi-Format Deliverable Reports
traceforge export CASE-20260826-XXXXXX --redact --out ./reports

# Launch Local Web Console
traceforge web --port 8000
```

---

## Installation Profiles

Install tool collections tailored to your environment using `./setup.sh` or `./install_all.sh`:

```bash
./setup.sh --profile minimal       # Core CLI and essential utilities
./setup.sh --profile recommended   # Standard investigation toolkit
./setup.sh --profile full          # Complete 175-tool suite
```

Use `--dry-run` to preview installation commands without making changes:

```bash
./setup.sh --dry-run
```

---

## Repository Structure

```text
TraceForge/
├── traceforge/     Python application package (CLI, case engine, analyzers, exporters, credentials vault)
├── go/             Native Go analytical utilities & fast-paths
├── modules/        Domain-specific shell investigation workflows (Quick & Full scans)
├── lib/            Shared shell libraries (platform detection, packaging, UI, credentials)
├── scripts/        Bootstrap, installer, and maintenance scripts
├── catalog/        175-tool categorized external tool catalog (13 investigation domains)
└── docs/           Full documentation site sources (Sphinx / ReadTheDocs)
```



---

## Supported Platforms

- **macOS** (Apple Silicon & Intel) — Homebrew
- **Debian / Ubuntu** — APT & pipx
- **Kali Linux** — APT & native security packages
- **Termux / Android** — `pkg` (offline forensics and non-root workflows)

*Note: Some external tools have specific platform or elevated privilege requirements.*

---

## Documentation

Full documentation, module references, and technical guides are available at **[traceforge.readthedocs.io](https://traceforge.readthedocs.io/en/latest/)**.

- [Installation Guide](https://traceforge.readthedocs.io/en/latest/installation.html)
- [CLI Commands](https://traceforge.readthedocs.io/en/latest/commands.html)
- [Architecture & Fast-Paths](https://traceforge.readthedocs.io/en/latest/architecture.html)
- [Investigation Modules](https://traceforge.readthedocs.io/en/latest/modules.html)
- [Case Management](https://traceforge.readthedocs.io/en/latest/cases.html)
- [Tool Catalog](https://traceforge.readthedocs.io/en/latest/tools.html)
- [Security Model](https://traceforge.readthedocs.io/en/latest/security.html)

---

## Responsible Use

TraceForge is a dual-use security and digital forensics toolkit. Use it only on systems, accounts, networks, and data you are authorized to investigate.

Please review our [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and [DISCLAIMER.md](DISCLAIMER.md) policies before conducting operations.

---

## Contributing

Contributions, bug reports, and suggestions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details on submitting pull requests and reporting issues.

---

## License

This project is licensed under the [MIT License](LICENSE).
Third-party utilities referenced in the catalog retain their respective licenses (see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).
