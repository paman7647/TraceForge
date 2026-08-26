# TraceForge Interactive Web Console

TraceForge includes a built-in, local-first web interface designed for operators who prefer an interactive visual console alongside the command line.

The web interface binds strictly to the local loopback interface (`127.0.0.1`) by default, ensuring zero network exposure and preserving local privacy.

---

## 1. Quick Start

To launch the web console from the project root:

```bash
# Via main.sh
./main.sh web

# Or with a custom port
./main.sh web --port 8080

# Or via the Python CLI
traceforge web --port 8000

# Or via run.sh
./run.sh web
```

Once running, navigate to:

```text
http://127.0.0.1:8000
```

To stop the web console, press `Ctrl+C` in the terminal.

---

## 2. Desktop-Grade Architecture & Capabilities

The web interface is a zero-dependency single-page application (SPA) backed by Python's standard library `http.server` API routes. It directly invokes the existing Python, Go, and Bash modules without running external database daemons or node servers.

### Navigation Hierarchy:

#### WORKSPACE
1. **Live Dashboard**: Real-time summary of the active case (Evidence count, Findings, IOCs, Timeline events) and core toolchain health (`tshark`, `exiftool`, `subfinder`, `sherlock`, `binwalk`, `mat2`).
2. **Case Management**: Create, list, open, rename, package into signed archives (`.zip` / `.tar.gz`), and view the immutable Chain of Custody audit trail.
3. **Evidence Vault**: Non-destructive upload and specimen ingestion with automatic SHA-256 and MD5 hashing, source attribution, and direct 1-click investigation triggers.

#### INVESTIGATION
4. **Investigation Modules (01–07)**: Execute all 7 core modules (`Image Forensics`, `Network Recon`, `Identity & Social`, `Email Breach`, `Domain & DNS`, `Document Harvesting`, `OPSEC Audit`) featuring:
   - **Pre-flight Dependency Checking**: Real-time evaluation of required vs. optional external tools before running.
   - **1-Click Missing Tool Installation**: Direct installation from the module workspace.
   - **Input Mode Selector**: Choose between active case evidence, local file upload, or raw target input.
   - **Live Terminal Execution**: Real-time log streaming and structured result cards.

#### ANALYSIS
5. **Analytical Tools**: First-party analytical utilities:
   - **IOC Stream Extractor & Defanger**: Automated indicator harvesting from unstructured text with defanging.
   - **PCAP Packet Capture Dissector**: Dissect protocols, top endpoints, DNS queries, and TLS SNIs.
   - **Cryptographic Hash Calculator**: Multi-algorithm hashing (SHA-256, MD5, SHA-1) for strings or files.
   - **Log Stream Triage Engine**: High-rate authentication failure, scanning burst, and format anomaly detection.
   - **Asset Relationship Graph**: Node/edge entity relationship graph parsing with standalone HTML export.
   - **Endpoint Posture Inspector**: Host network interfaces, listening sockets, active sessions, and OS posture.
   - **Recursive Evidence Directory Indexer**: Enumerate and hash entire directory hierarchies with SHA-256.
6. **Indicator Registry (IOCs)**: Dedicated observable repository with type filtering (`domain`, `ipv4`, `ipv6`, `url`, `email`, `sha256`, `cve`), confidence ratings, and defanged indicators.
7. **Threat Findings**: Record and categorize findings by severity (`Critical`, `High`, `Medium`, `Low`, `Info`) and status (`open`, `investigating`, `mitigated`, `closed`).
8. **Forensic Timeline**: Chronological event ordering with UTC ISO-8601 normalization.
9. **Asset Correlation**: Entity relationship topology and cross-source observable mapping.

#### OUTPUT
10. **Deliverables & Reports**: One-click generation and downloads for Markdown (`.md`), Standalone HTML (`.html`), CSV datasets, STIX 2.1 JSON, MISP Event JSON, Timesketch JSONL, GeoJSON, and Signed ZIP Archives.

#### SYSTEM
11. **Security Tool Catalog**: Search, filter, inspect specifications, and install from the 152 audited tools across Homebrew, APT, Pacman, DNF, Termux (`pkg`), Go, pipx, and Cargo.
12. **Runtime Configuration**: Switch profiles (`recommended`, `minimal`, `python`, `go`, `python-go`, `full`, `custom`) and inspect first-party fast-path routing.
13. **System Doctor**: Comprehensive host diagnostics (OS, Distro, Arch, Python, Go, Rust, Package Manager, Storage) and 1-click environment repair.

---

## 3. Security & Safety Standards

- **Strict Localhost Binding**: Binds strictly to `127.0.0.1` by default (Zero LAN exposure).
- **Path Traversal Protection**: Upload and download endpoints validate canonical paths strictly within the project root and workspace boundaries.
- **Defensive Subprocess Execution**: Subprocess calls use structured arrays with allowlisted parameters without shell string concatenation.
- **Immutable Read-Only Storage**: Ingested evidence files are given read-only permissions (`0o444`) with cryptographic hash verification.
