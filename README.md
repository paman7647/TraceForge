# TraceForge

<div align="center">

**Open-source OSINT, DFIR and security investigation toolkit.**

[![Documentation](https://img.shields.io/badge/docs-ReadTheDocs-blue.svg)](https://traceforge.readthedocs.io/en/latest/)
[![CI](https://github.com/paman7647/TraceForge/actions/workflows/ci.yml/badge.svg)](https://github.com/paman7647/TraceForge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/paman7647/TraceForge?color=blue)](https://github.com/paman7647/TraceForge/releases/latest)
[![PyPI](https://img.shields.io/pypi/v/traceforge-osint.svg)](https://pypi.org/project/traceforge-osint/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Android-informational.svg)](https://traceforge.readthedocs.io/en/latest/installation.html)
[![Catalog](https://img.shields.io/badge/Catalog-152%20Tools-blueviolet.svg)](catalog/TOOLS.md)

[Documentation](https://traceforge.readthedocs.io/en/latest/) · [Releases](https://github.com/paman7647/TraceForge/releases) · [Issues](https://github.com/paman7647/TraceForge/issues) · [Pull Requests](https://github.com/paman7647/TraceForge/pulls) · [Contributing](CONTRIBUTING.md)

</div>

---

> ### ⚠️ Responsible Use & Educational Disclaimer
> TraceForge is built for lawful OSINT investigations, digital forensics, incident response, security research, and educational lab work.  
> **Always obtain authorization before scanning or collecting data from systems or networks you do not own.**  
> See [DISCLAIMER.md](DISCLAIMER.md) and [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for full policy details.

---

## What It Does

TraceForge is a command-line toolkit for open-source intelligence and digital forensics:

* **Built-in Tools (`traceforge` / `go/`)**: Fast Go and Python utilities for IOC extraction, defanging, timeline normalization, log triage, evidence indexing, filesystem baselining, and case packaging.
* **152-Tool Catalog**: Searchable index of 152 open-source tools with automated package installation for Homebrew (macOS), APT (Debian/Ubuntu/Kali), and pipx.
* **7 Investigation Modules**: Ready-to-run scripts for image metadata, network PCAPs, usernames, email breach records, domain DNS records, document metadata, and OPSEC checks.
* **Case Management**: Local workspaces under `workspace/` with case IDs, SHA-256 evidence hashing, and append-only audit logging.
* **Multi-Format Exports**: Exports findings to Markdown, standalone HTML (dark mode), CSV, TSV, JSON, JSONL, STIX 2.1, MISP, GeoJSON, and KML.
* **PII Redaction**: Built-in `--redact` flag to automatically mask IP and email addresses in exported reports.

---

## Architecture

TraceForge does not ship binary copies of third-party tools. It installs and launches external tools via your system's package managers:

```text
+-------------------------------------------------------------------+
|                            TraceForge                             |
|      (CLI Menu, Tool Catalog, Case Workspaces, Report Exporter)   |
|                         [ MIT License ]                           |
+---------------------------------+---------------------------------+
                                  |
                                  | Installs / Launches / Collects Output
                                  v
+-------------------------------------------------------------------+
|                 Third-Party Command-Line Tools                    |
|   (ExifTool, TShark, Binwalk, Nmap, Sherlock, Maigret, etc.)     |
|         [ Retain Respective Upstream Copyright & Licenses ]        |
+-------------------------------------------------------------------+
```

All third-party tools remain the property of their respective creators and are licensed under their own terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for details.

---

## Supported Systems

| Platform | Tier | Architecture | Package Manager | Guide & Notes |
|---|---|---|---|---|
| **macOS Apple Silicon** | Supported | `arm64` (M1/M2/M3/M4) | Homebrew | Full native support |
| **macOS Intel** | Supported | `x86_64` | Homebrew | Full native support |
| **Debian / Ubuntu** | Supported | `x86_64`, `arm64` | APT | Full native support |
| **Kali Linux** | Supported | `x86_64`, `arm64` | APT | Full native support |
| **Termux / Android** | Supported with limitations | `arm64`, `armv7`, `x86_64` | `pkg` | Non-root userland. Offline forensics & PCAP analysis. [Termux Guide](https://traceforge.readthedocs.io/en/latest/platforms/termux.html) |

---

## Installation & Quick Start

### Method A: One-Command Auto-Deploy (Recommended)

Run TraceForge's automated remote installer to detect your OS, set up a Python virtual environment, and configure tools in one step:

```bash
curl -fsSL https://raw.githubusercontent.com/paman7647/TraceForge/master/scripts/bootstrap.sh | bash
```

---

### Method B: Manual Git Clone & Setup

```bash
# 1. Clone the repository
git clone https://github.com/paman7647/TraceForge.git
cd TraceForge

# 2. Grant executable permissions
chmod +x setup.sh run.sh main.sh install_all.sh modules/*.sh scripts/*.sh

# 3. Run automated setup
./setup.sh

# Or install tool packages by profile
./install_all.sh --profile recommended
```

---

### Method C: PyPI Package Installation

```bash
pip install traceforge-osint
```

---

### Running TraceForge

```bash
# Unified Launcher (auto-detects virtualenv and binaries)
./run.sh

# Interactive TTY Console
./main.sh

# Standalone Python CLI
traceforge --help
traceforge doctor
```

```bash
# Run system diagnostics
./main.sh doctor

# List existing cases
./main.sh list-cases

# Search the tool catalog
./main.sh search "pcap"

# Run first-party tools
traceforge ioc extract /path/to/intel.txt
traceforge asset graph /path/to/entities.jsonl --html graph.html

# Run a module directly
./main.sh module 1 /path/to/evidence.png CASE-20260825-ABC123

# Export a case
./main.sh export CASE-20260825-ABC123 --all
```

---

## Investigation Modules

| Module | Script | Target & Tools Used |
|---|---|---|
| **01. Media & Image Forensics** | `modules/01_image_forensics.sh` | Images and videos: EXIF/IPTC metadata, GPS coordinates, strings, steganography (`exiftool`, `binwalk`, `zsteg`, `xxd`). |
| **02. Network & PCAP Forensics** | `modules/02_network_recon.sh` | Packet captures: DNS queries, HTTP URIs, TLS SNI headers, conversations (`tshark`, `capinfos`, `aircrack-ng`). |
| **03. Identity & Social Research** | `modules/03_identity_social.sh` | Usernames and aliases: account discovery across web platforms (`sherlock`, `maigret`, `blackbird`, `socialscan`). |
| **04. Email & Breach Intelligence** | `modules/04_email_breach.sh` | Email addresses: account registrations, breach dumps, SPF/DMARC posture (`holehe`, `h8mail`, `emailrep`, `theHarvester`, `checkdmarc`). |
| **05. Domain & DNS Intelligence** | `modules/05_domain_dns.sh` | Domains: DNS records, passive subdomains, HTTP probing, typosquats (`dig`, `whois`, `subfinder`, `amass`, `dnsx`, `httpx`, `dnstwist`). |
| **06. Document & Metadata Harvesting** | `modules/06_document_harvesting.sh` | Documents (PDF, DOCX, XLSX): properties, text, embedded objects, macros, secret keys (`poppler`, `oletools`, `exiftool`, `qpdf`, `ripgrep`). |
| **07. OPSEC & Environment Audit** | `modules/07_opsec_anonymization.sh` | Local audit: public IP detection, DNS leak test, Tor/proxy status, encryption tools (`mat2`, `tor`, `proxychains`, `gnupg`, `age`). |

---

## Directory Structure

```text
TraceForge/
├── setup.sh                       # Primary automated environment and dependency installer
├── run.sh                         # Unified application runner
├── main.sh                        # Interactive console and CLI dispatcher
├── install_all.sh                 # Multi-ecosystem package installer
├── pyproject.toml                 # Modern Python package configuration
├── go.mod                         # Go module declaration (zero external dependencies)
├── VERSION                        # Project version (1.0.0)
├── LICENSE                        # MIT License
├── NOTICE                         # Copyright and attribution
├── THIRD_PARTY_NOTICES.md         # Upstream tool licenses and repository links
├── README.md                      # Main project documentation
├── SECURITY.md                    # Vulnerability reporting guidelines
├── CONTRIBUTING.md                # Contribution guidelines
├── CODE_OF_CONDUCT.md             # Contributor Covenant 2.1
├── CHANGELOG.md                   # Version release history
├── RELEASE_NOTES.md               # 1.0.0 release notes
│
├── go/                            # Go-native high-performance engine
├── traceforge/                    # Pure Python implementation and package data
│
├── catalog/
│   ├── README.md                  # Catalog schema specification
│   ├── tools.tsv                  # 22-column registry of 152 tools
│   └── TOOLS.md                   # Formatted markdown tool index
│
├── lib/
│   ├── common.sh                  # Terminal UI, colors, logging, string helpers
│   ├── platform.sh                # OS and architecture detection
│   ├── packages.sh                # Package managers (Homebrew, APT, pipx, Go, Gem, Cargo)
│   ├── catalog.sh                 # Catalog search and filter functions
│   ├── case.sh                    # Case lifecycle, evidence, findings, IOCs, timeline
│   ├── export.sh                  # Export coordinator, packaging, and hashing
│   └── report.sh                  # Markdown, HTML, and CSV/JSON report generators
│
├── modules/                       # 7 investigation modules (01 to 07)
├── scripts/
│   ├── bootstrap.sh               # One-command remote installer
│   └── doctor.sh                  # System and dependency diagnostic checker
│
├── docs/                          # Read the Docs Sphinx documentation site
└── workspace/                     # Local investigation cases
    └── .gitkeep
```

---

## Documentation

Full documentation is available at **[traceforge.readthedocs.io](https://traceforge.readthedocs.io/en/latest/)**.

* [Official Documentation Site](https://traceforge.readthedocs.io/en/latest/)
* [Installation Guide](https://traceforge.readthedocs.io/en/latest/installation.html)
* [Quickstart Walkthrough](https://traceforge.readthedocs.io/en/latest/quickstart.html)
* [CLI Commands Reference](https://traceforge.readthedocs.io/en/latest/commands.html)
* [Investigation Modules](https://traceforge.readthedocs.io/en/latest/modules.html)
* [152-Tool Catalog](https://traceforge.readthedocs.io/en/latest/tools.html)
* [Case Management & Chain of Custody](https://traceforge.readthedocs.io/en/latest/cases.html)
* [Multi-Format Reporting](https://traceforge.readthedocs.io/en/latest/reporting.html)
* [Architecture & Fast-Paths](https://traceforge.readthedocs.io/en/latest/architecture.html)
* [Termux & Android Integration](https://traceforge.readthedocs.io/en/latest/platforms/termux.html)
* [Security & Threat Model](https://traceforge.readthedocs.io/en/latest/security.html)
* [Responsible Use Guidelines](https://traceforge.readthedocs.io/en/latest/responsible-use.html)
* [Privacy & Local Data Policy](https://traceforge.readthedocs.io/en/latest/privacy.html)
* [Branching Model](https://traceforge.readthedocs.io/en/latest/branching.html)
* [Contributing Guide](https://traceforge.readthedocs.io/en/latest/contributing.html)

---

## Authors & License

* **Lead Architect & Developer**: Aman Kumar Pandey (<paman7647@proton.me>)
* **Documentation**: [traceforge.readthedocs.io](https://traceforge.readthedocs.io/en/latest/)
* **License**: [MIT License](LICENSE)
* **Copyright**: Copyright (c) 2026 Aman Kumar Pandey
