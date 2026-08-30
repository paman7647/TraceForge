# Tool Catalog & First-Party Engine

TraceForge bridges two categories of security software:
1. **First-Party Analytical Tools**: High-performance built-in tools implemented in Python and compiled Go.
2. **Third-Party Security Toolchain**: A curated catalog of 175 verified external tools across OSINT, digital forensics, threat intelligence, and network analysis.

---

## 1. First-Party Analytical Utilities

The first-party tools run with zero external dependencies and provide high-speed analytical functions:

| Tool Command | Preferred Runtime | Functionality |
|---|---|---|
| `traceforge tools asset-graph` | Python / Go | Builds node/edge relationship graphs from domains, IPs, and URLs with interactive HTML export. |
| `traceforge tools diff` | Python / Go | Compares snapshots of DNS records, HTTP responses, or asset lists to identify changes over time. |
| `traceforge tools ioc-extract` | Go (Fast-Path) / Python | High-throughput streaming IOC extractor and defanger (IPv4, IPv6, domains, emails, SHA-256). |
| `traceforge tools evidence-index` | Python / Go | Recursively indexes evidence folders with SHA-256 hashes, MIME types, and file sizes. |
| `traceforge tools log-triage` | Go (Fast-Path) / Python | Analyzes web server access logs and syslogs for brute-force attacks and rate anomalies. |
| `traceforge tools pcap-summary` | Python | Dissects offline PCAP captures, identifying top talkers, protocol hierarchy, DNS, and TLS SNI. |
| `traceforge tools file-baseline` | Python | Creates or diffs cryptographic directory baselines for filesystem integrity monitoring. |
| `traceforge tools endpoint-inspect`| Python | Collects defensive local posture (interfaces, ports, storage, Termux:API telemetry). |

---

## 2. The 175-Tool Catalog

The single source of truth for all supported external tools is:
- **`catalog/tools.tsv`**: 22-column tab-separated dataset.
- **`catalog/TOOLS.md`**: Human-readable catalog generated from `tools.tsv`.

### Catalog Breakdown by Category (13 Investigation Domains)

| Category | Tool Count | Key Examples |
|---|---|---|
| **Media & Image Forensics** | 39 tools | `exiftool`, `binwalk`, `steghide`, `jhead`, `pngcheck`, `ffmpeg`, `sox`, `stegsnow`, `jsteg`, `recoverjpeg` |
| **Domain, DNS & Infrastructure** | 30 tools | `subfinder`, `amass`, `assetfinder`, `dnsrecon`, `dnstwist`, `puredns`, `alterx`, `cero`, `wafw00f` |
| **Document Harvesting** | 20 tools | `poppler`, `oletools`, `mat2`, `qpdf`, `capa`, `floss`, `cabextract`, `pandoc` |
| **Network, PCAP & Wireless** | 18 tools | `tshark`, `tcpdump`, `nmap`, `masscan`, `tcpprep`, `dumpcap`, `zeek` |
| **OPSEC & Anonymization** | 17 tools | `tor`, `torsocks`, `proxychains-ng`, `srm`, `gnupg`, `age`, `privoxy`, `cloudflared` |
| **Email & Breach Intelligence** | 15 tools | `holehe`, `h8mail`, `pwnedornot`, `crosslinked`, `theharvester`, `checkdmarc` |
| **Identity & Social Recon** | 12 tools | `sherlock`, `maigret`, `blackbird`, `socialscan`, `ghunt`, `snscrape` |
| **Threat Intelligence & Passive DNS** | 6 tools | `vt-cli`, `otx-cli`, `urlscan`, `abuseipdb`, `asnlookup`, `ipinfo` |
| **Geospatial, Wireless & IoT** | 5 tools | `wigle-api`, `suncalc`, `overpass-cli`, `bettercap`, `rtl_433` |
| **Cloud & Attack Surface Exposure** | 4 tools | `cloudlist`, `bucket-stream`, `git-hound`, `festin` |
| **Financial & Crypto OSINT** | 4 tools | `txfetch`, `blockstream-cli`, `etherscan-cli`, `crypto-check` |
| **Public Records & Darknet OSINT** | 4 tools | `waybackpy`, `sec-edgar`, `opencorporates`, `onionscan` |
| **First-Party Suite Native Tools** | 1 tool | `traceforge-native` |


---

## 3. Tool Installation Ecosystems

Every catalog tool defines package installation recipes for its upstream ecosystem:

- **`native`**: Managed by system package managers (`brew` on macOS, `apt-get` on Linux, `pkg` on Termux).
- **`pipx`**: Python tools installed in isolated virtual environments (`pipx install <pkg>`) to comply with PEP 668.
- **`go`**: Compiled directly into `$HOME/go/bin` (`go install ...@latest`).
- **`cargo`**: Rust tools compiled into `$HOME/.cargo/bin` (`cargo install ...`).
- **`ruby_gem`**: Ruby tools installed in user space (`gem install --user-install ...`).

---

## 4. Platform-Aware Tool Management & CLI Commands

TraceForge actively evaluates host compatibility across macOS, Linux distros, and Android (Termux) before displaying or installing any utility.

```bash
# Platform capability audit
traceforge tools audit-platform
traceforge doctor

# Filter catalog by active platform availability
traceforge tools list --platform current --available
traceforge tools list --platform current --unavailable
traceforge tools list --platform current --manual
traceforge tools list --platform current --installed
traceforge tools list --platform current --missing

# Detailed platform specification and recipe
traceforge tools info exiftool
traceforge tools info macchanger

# Pre-flight checked platform installation
traceforge tools install sherlock
traceforge tools install-profile recommended
```

---

## 5. Web Console Platform Lifecycle Explorer

The TraceForge Web Interface (`http://127.0.0.1:8000/#catalog`) exposes real-time platform awareness:
- **Platform Banner**: Live display of active host OS, architecture, package manager, and privilege state.
- **Platform Toggle**: Switch between `Current Platform` (host-compatible utilities) and `All Platforms`.
- **Availability Filters**: Filter by `Available on Host`, `Unavailable on Host`, `Manual Install Only`, `Installed Only`, or `Missing Only`.
- **Platform-Aware Profiles**: Shows preview counts of installable, installed, and skipped utilities prior to triggering batch workers.
- **REST Endpoints**:
  - `GET /api/catalog?platform=current&availability=available`: Returns platform-filtered tools.
  - `GET /api/catalog/platform-audit`: Returns platform capability metrics and breakdown.
  - `POST /api/catalog/install`: Pre-flight validates compatibility before execution.
  - `POST /api/catalog/install-profile`: Executes batch installation plan skipping unavailable tools.

---

## 6. Termux & Android Tool Support

The catalog includes 7 dedicated metadata columns for Termux/Android compatibility:
- **`termux_status`**: `supported`, `limited`, `manual`, or `desktop_only`.
- **`termux_package`**: Native Termux package name (e.g. `exiftool`, `nmap`, `tshark`).
- **`termux_install`**: Specific Termux installation command if different from `pkg`.
- **`termux_root`**: Whether execution requires Android root (`su`).
- **`termux_hardware`**: Whether execution requires external hardware (e.g. Wi-Fi OTG adapter).
