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

### Automatic Setup

```bash
git clone https://github.com/paman7647/TraceForge.git
cd TraceForge
chmod +x setup.sh run.sh main.sh install_all.sh
./setup.sh
```

### Run

```bash
./run.sh
```

or using the Python CLI:

```bash
traceforge --help
```

### System Diagnostics

```bash
traceforge doctor
# or
./main.sh doctor
```

---

## Example Commands

```bash
# Extract and defang IOCs from evidence
traceforge ioc extract evidence.txt

# Generate an interactive HTML entity graph
traceforge asset graph entities.jsonl --html graph.html

# Interactive case management and catalog search
./main.sh list-cases
./main.sh search "pcap"

# Export case findings across all supported formats
./main.sh export CASE-20260825-ABC123 --all
```

---

## Installation Profiles

Install tool collections tailored to your environment using `./setup.sh` or `./install_all.sh`:

```bash
./setup.sh --profile minimal       # Core CLI and essential utilities
./setup.sh --profile recommended   # Standard investigation toolkit
./setup.sh --profile full          # Complete 152-tool suite
```

Use `--dry-run` to preview installation commands without making changes:

```bash
./setup.sh --dry-run
```

---

## Repository Structure

```text
TraceForge/
├── traceforge/     Python application package (CLI, case engine, analyzers, exporters)
├── go/             Native Go analytical utilities & fast-paths
├── modules/        Domain-specific shell investigation workflows
├── lib/            Shared shell libraries (platform detection, packaging, UI)
├── scripts/        Bootstrap, release, and maintenance scripts
├── catalog/        152-tool categorized external tool catalog
├── docs/           Full documentation site sources (Sphinx / ReadTheDocs)
└── tests/          Test suites and validation checks
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
