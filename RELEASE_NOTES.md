# TraceForge 1.0.0 Release Notes

**Release Date**: August 25, 2026  
**Lead Architect & Core Developer**: Aman Kumar Pandey  
**License**: MIT License  

TraceForge 1.0.0 is the first stable release of the open-source OSINT, DFIR, and digital forensics investigation toolkit.

---

## What's Included

### 1. Unified Architecture & Fast-Path Engine
* **First-Party Capabilities**: High-performance Go native engine (`traceforge-native`) and pure Python package (`traceforge`) for Asset Graph generation, streaming IOC extraction/defanging, timeline normalization, log triage, evidence directory indexing, filesystem baselining, and case packaging.
* **Dual Interface**: Interactive CLI console (`main.sh` / `traceforge`) and non-interactive module runners.

### 2. Adaptive Runtime Profiles
* Six selectable profiles: `python-go` (default: Python orchestration + Go fast-paths), `python` (pure Python reference), `go` (compiled Go tools), `minimal` (essential built-ins), `full` (complete catalog), and `custom` (per-component control).
* Feature-level runtime overrides via `traceforge config set <feature>.runtime <python|go|auto>`.

### 3. Cross-Platform Package Management
* Automated installer (`./install_all.sh`) for macOS (Homebrew), Linux (Debian, Ubuntu, Kali via APT), and Termux / Android (`pkg`).
* Python tools isolated in virtual environments using `pipx` (PEP 668 compliant).
* Go and Rust tools compiled into user directories (`$HOME/go/bin`, `$HOME/.cargo/bin`).
* Non-destructive `--dry-run` flag to preview planned installation commands.

### 4. Searchable 152-Tool Catalog
* 152 tools indexed in `catalog/tools.tsv` across 7 investigation domains with 22 metadata columns including Termux support tiers and root/hardware requirements.
* Fast CLI search: `traceforge search <query>`.

### 5. Investigation Modules
* `01_image_forensics.sh`: MIME detection, EXIF metadata, GPS extraction, strings, and steganography.
* `02_network_recon.sh`: Offline PCAP analysis, DNS query extraction, HTTP requests, and TLS SNI headers.
* `03_identity_social.sh`: Username enumeration across public web platforms.
* `04_email_breach.sh`: Email account registrations, public breach databases, and SPF/DMARC posture.
* `05_domain_dns.sh`: DNS resolution, passive subdomain discovery, HTTP probing, and typosquats.
* `06_document_harvesting.sh`: PDF/DOCX metadata, text extraction, macros, and secret key scanning.
* `07_opsec_anonymization.sh`: Workstation OPSEC checks, DNS leaks, Tor status, and encryption tools.

### 6. Case Management & Reporting
* Self-contained investigation workspaces under `workspace/`.
* SHA-256 integrity hashing and append-only `evidence-chain.jsonl` audit logging.
* Exports to Markdown, standalone HTML (dark mode), relational CSV (with formula injection protection), TSV, JSON, JSONL event streams, STIX 2.1, MISP JSON, GeoJSON, and KML.
* Redaction mode (`--redact`) for sanitizing sensitive IP and email addresses.

---

## Supported Platforms

| Platform | Tier | Architecture | Notes |
|---|---|---|---|
| **macOS Apple Silicon** | Supported | `arm64` (M1/M2/M3/M4) | Full native support via Homebrew |
| **macOS Intel** | Supported | `x86_64` | Full native support via Homebrew |
| **Debian / Ubuntu / Kali** | Supported | `x86_64`, `arm64` | Full native support via APT |
| **Termux / Android** | Supported with limitations | `arm64`, `armv7`, `x86_64` | Non-root userland. Offline forensics & PCAP analysis. (See `docs/platforms/termux.md`) |

---

## Important Limitations & Boundaries

1. **Android Live Capture**: Promiscuous packet capture and wireless monitor mode require a rooted Android kernel or external OTG hardware; offline PCAP file analysis runs unrooted.
2. **Third-Party Availability**: Certain third-party tools (e.g. GUI tools like Maltego or Ghidra) are desktop-only and skipped automatically on headless or mobile targets.
3. **Authorized Use Only**: TraceForge is strictly intended for authorized security audits, incident response, and academic research. See `DISCLAIMER.md` and `RESPONSIBLE_USE.md`.

---

## Getting Started

```bash
git clone https://github.com/paman7647/TraceForge.git
cd TraceForge
chmod +x install_all.sh main.sh modules/*.sh scripts/*.sh tests/*.sh

# Run installer (default: python-go profile)
./install_all.sh --profile python-go

# Launch interactive menu or CLI
./main.sh
# or
python3 -m traceforge
```
