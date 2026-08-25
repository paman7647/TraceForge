# Tool Catalog & First-Party Engine

TraceForge bridges two categories of security software:
1. **First-Party Analytical Tools**: High-performance built-in tools implemented in Python and compiled Go.
2. **Third-Party Security Toolchain**: A curated catalog of 152 verified external tools across OSINT, digital forensics, and network analysis.

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

## 2. The 152-Tool Catalog

The single source of truth for all supported external tools is:
- **`catalog/tools.tsv`**: 22-column tab-separated dataset.
- **`catalog/TOOLS.md`**: Human-readable catalog generated from `tools.tsv`.

### Catalog Breakdown by Category

| Category | Tool Count | Key Examples |
|---|---|---|
| **Media & Image Forensics** | 22 tools | `exiftool`, `binwalk`, `steghide`, `jhead`, `pngcheck`, `ffmpeg`, `foremost`, `scalpel`, `testdisk` |
| **Network, PCAP & Wireless** | 28 tools | `tshark`, `tcpdump`, `nmap`, `masscan`, `nikto`, `hydra`, `aircrack-ng`, `hcxtools`, `zeek` |
| **Identity & Social Recon** | 20 tools | `sherlock`, `maigret`, `blackbird`, `socialscan`, `ghunt`, `twarc2`, `snscrape` |
| **Email & Breach Intelligence** | 16 tools | `holehe`, `h8mail`, `emailrep`, `theharvester`, `checkdmarc`, `pwnedornot` |
| **Domain & DNS Intelligence** | 26 tools | `subfinder`, `amass`, `assetfinder`, `dnsrecon`, `dnstwist`, `wafw00f`, `shodan`, `censys` |
| **Document Harvesting** | 18 tools | `poppler` (`pdftotext`), `oletools` (`olevba`), `mat2`, `qpdf`, `pandoc`, `peepdf` |
| **OPSEC & Anonymization** | 22 tools | `tor`, `torsocks`, `proxychains-ng`, `gnupg`, `age`, `macchanger`, `privoxy`, `cloudflared` |

---

## 3. Tool Installation Ecosystems

Every catalog tool defines package installation recipes for its upstream ecosystem:

- **`native`**: Managed by system package managers (`brew` on macOS, `apt-get` on Linux, `pkg` on Termux).
- **`pipx`**: Python tools installed in isolated virtual environments (`pipx install <pkg>`) to comply with PEP 668.
- **`go`**: Compiled directly into `$HOME/go/bin` (`go install ...@latest`).
- **`cargo`**: Rust tools compiled into `$HOME/.cargo/bin` (`cargo install ...`).
- **`ruby_gem`**: Ruby tools installed in user space (`gem install --user-install ...`).

---

## 4. Searching & Inspecting the Catalog

Search the catalog from the CLI:

```bash
# Search by keyword
traceforge catalog "pcap"

# Search via main shell entrypoint
./main.sh search "exif"
```

Output displays installed vs available status:
```text
TraceForge Catalog: 4 tools found
    2. [INSTALLED] ExifTool               (exiftool) [Media & Image Forensics] - Read and write meta information in files
   12. [AVAILABLE] Exiv2                  (exiv2)    [Media & Image Forensics] - Image metadata library and tools
```

---

## 5. Termux & Android Tool Support

The catalog includes 7 dedicated metadata columns for Termux/Android compatibility:
- **`termux_status`**: `supported`, `hardware_dependent`, `root_required`, or `desktop_only`.
- **`termux_package`**: Native Termux package name (e.g. `exiftool`, `nmap`, `tshark`).
- **`termux_root`**: Whether execution requires Android root (`su`).
- **`termux_hardware`**: Whether execution requires external hardware (e.g. Wi-Fi OTG adapter).
