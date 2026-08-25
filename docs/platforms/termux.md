# TraceForge — Termux & Android Platform Architecture Guide

## 1. Overview & Android Execution Model

TraceForge provides first-class support for **Termux on Android (ARM64, ARMv7, x86_64, i686)**.

Unlike desktop Linux, Termux operates inside an unprivileged Android userland container without root permissions, standard `/usr` paths, or standard Linux system services (systemd, sysvinit). TraceForge embraces this model:

- **Filesystem Prefix**: Executables and libraries live under `$PREFIX` (typically `/data/data/com.termux/files/usr/`).
- **Zero-Root Design**: All first-party analytical tools, parsing engines, IOC extractors, timeline normalizers, and report generators run without root.
- **Root/Hardware Boundaries**: Features that strictly require kernel monitor-mode drivers or raw packet injection (e.g. Aircrack-NG live monitor mode) are clearly separated from offline file analysis.

```text
                      +-------------------------------+
                      |   Android Host (OS / Kernel)  |
                      +---------------+---------------+
                                      |
                                      v
                      +-------------------------------+
                      |  Termux Application Sandbox   |
                      |       (Non-Root Userland)     |
                      +---------------+---------------+
                                      |
                 +--------------------+--------------------+
                 |                                         |
                 v                                         v
   [ Termux Environment ($PREFIX) ]           [ Android Shared Storage ]
   • Python 3.11+ / isolated venv             • $HOME/storage/shared/
   • Golang (pkg install golang)              • /sdcard/Download/
   • Native Termux pkgs (exiftool, nmap)      • /sdcard/DCIM/
                 |                                         |
                 +--------------------+--------------------+
                                      |
                                      v
                      +-------------------------------+
                      |   TraceForge Analysis Engine  |
                      | (Offline Triage & Reporting)  |
                      +-------------------------------+
```

---

## 2. Prerequisites & Quickstart

### Step 1: Install Termux
Install the latest official Termux build from **F-Droid** or official releases (avoid outdated Play Store releases).

### Step 2: Update Packages & Grant Storage
Open Termux and execute:
```bash
pkg update -y && pkg upgrade -y
termux-setup-storage
```
> [!IMPORTANT]
> `termux-setup-storage` prompts an Android permission dialog to allow access to `/sdcard/Download/`, `/sdcard/DCIM/`, etc.

### Step 3: Clone & Install TraceForge
```bash
pkg install -y git python
git clone https://github.com/paman7647/TraceForge.git
cd TraceForge
./install_all.sh --profile python-go
```

---

## 3. Storage Architecture & Accessing Files

Termux uses an isolated private internal sandbox (`$HOME` / `/data/data/com.termux/files/home/`).

To analyze files located in normal Android phone storage:

| Storage Path | Access Point in Termux | Description |
|---|---|---|
| **Downloads** | `~/storage/downloads/` or `/sdcard/Download/` | Ingest exported PCAPs, documents, or downloaded forensic artifacts |
| **Camera / Images** | `~/storage/dcim/` or `/sdcard/DCIM/` | Media files for EXIF and steganography analysis |
| **Internal Storage** | `~/storage/shared/` or `/sdcard/` | General internal phone storage |
| **TraceForge Cases** | `~/TraceForge/workspace/` | Isolated local forensic cases and export artifacts |

Example Ingestion:
```bash
traceforge case add-evidence ~/storage/downloads/suspicious_evidence.pcap --desc "Network capture from field audit"
```

---

## 4. Capability Matrix: Supported vs Root-Required

| Investigation Domain | Feature / Tool | Termux Support Tier | Android Root Required? | Notes |
|---|---|---|---|---|
| **Media Forensics** | ExifTool, Binwalk, xxd, Steghide, Jhead, FFmpeg | **✓ Fully Supported** | **No** | Installed via `pkg install <tool>`. Runs with native speed. |
| **Document Analysis** | Poppler (`pdftotext`, `pdfinfo`), Oletools, MAT2 | **✓ Fully Supported** | **No** | Metadata sanitization and text harvesting unrooted. |
| **IOC Extraction** | Streaming IOC regex engine, defanger | **✓ Fully Supported** | **No** | Pure Python or compiled Go fast-path. |
| **PCAP Analysis** | Offline PCAP file triage (`summarize_pcap`, TShark offline) | **✓ Fully Supported** | **No** | Reads capture files from shared storage or downloads. |
| **Network Recon** | Nmap service/port scanning (`-sT`, `-sV`), DNS Recon, WHOIS | **✓ Fully Supported** | **No** | Standard TCP connect scan operates in userland. |
| **Network Live Capture** | Live packet capture via `tshark -i` or `tcpdump -i` | **! Limited** | **Yes** | Promiscuous packet capture requires Android root privileges (`su` / `tsu`). |
| **Wireless Injection** | Aircrack-NG, HCXtools live 802.11 monitor mode | **! Hardware-Dependent** | **Yes + Hardware** | Requires rooted Android kernel with wireless monitor-mode drivers or external USB OTG wireless adapter. |
| **Identity & Breaches** | Sherlock, Maigret, Holehe, GHunt, EmailRep | **✓ Fully Supported** | **No** | Operates over standard HTTPS REST APIs via Python. |
| **Case Reporting** | Markdown, HTML, Relational CSV, STIX 2.1, MISP JSON | **✓ Fully Supported** | **No** | Generates standalone reports directly into workspace. |

---

## 5. Optional Termux:API Integration

TraceForge optionally queries `termux-api` utilities to enhance host posture diagnostics during endpoint audits:

- `termux-battery-status`: Battery health, temperature, and charging state.
- `termux-wifi-connectioninfo`: Active SSID, BSSID, RSSI signal strength, and link speed.
- `termux-device-info`: Hardware manufacturer, model, and ABI.

To enable Termux:API:
```bash
pkg install -y termux-api
# Install Termux:API companion APK from F-Droid
```

---

## 6. Runtime Profiles on Android

| Profile | Command | Footprint | Best Use Case |
|---|---|---|---|
| **`python-go`** *(Recommended)* | `./install_all.sh --profile python-go` | ~1.2 GB | Workstations with Go toolchain for accelerated file indexing |
| **`python`** | `./install_all.sh --profile python` | ~600 MB | Fast setup; runs pure Python reference engine with zero build steps |
| **`minimal`** | `./install_all.sh --profile minimal` | ~250 MB | Low-storage Android devices (<2 GB free space) |
| **`full`** | `./install_all.sh --profile full` | ~3.5 GB | Comprehensive DFIR and OSINT toolset |

---

## 7. Troubleshooting & FAQs

### Q: Why does live packet capture or wireless monitor mode fail?
> Android limits raw socket binding (`SOCK_RAW`) and wireless interface configuration (`ioctl`) to the `root` user (`uid 0`). Live packet capture and Wi-Fi frame injection require a rooted phone with kernel driver support or a compatible USB OTG Wi-Fi card. Offline PCAP file analysis works completely unrooted.

### Q: Permission denied when accessing `/sdcard`?
> Run `termux-setup-storage` and grant storage permissions in the Android popup.

### Q: Can TraceForge compile Go helpers on ARM64?
> Yes. Termux provides the official Go compiler (`pkg install golang`). TraceForge automatically builds `traceforge-native` with `-trimpath -ldflags="-s -w"`.
