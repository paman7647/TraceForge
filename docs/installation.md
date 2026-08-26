# Installation & Setup

This guide explains how to install TraceForge, set up external package dependencies, configure optional extras, and verify your runtime environment.

---

## 1. System Requirements

| Platform | Tier | Architecture | Package Manager | Python | Notes |
|---|---|---|---|---|---|
| **macOS** | Supported | `arm64` (Apple Silicon), `x86_64` (Intel) | [Homebrew](https://brew.sh/) | 3.9+ | macOS 12 Monterey or later |
| **Linux** | Supported | `x86_64`, `arm64` | APT (Debian, Ubuntu, Kali) | 3.9+ | Ubuntu 22.04+, Debian 12+, Kali Linux |
| **Termux (Android)** | Supported | `arm64`, `armv7`, `x86_64` | `pkg` (Termux userland) | 3.11+ | Non-root userland. See [Termux Guide](platforms/termux.md) |

---

## 2. One-Liner Quick Install (`curl`)

Install TraceForge with a single terminal command:

```bash
curl -fsSL https://raw.githubusercontent.com/paman7647/TraceForge/master/scripts/bootstrap.sh | bash
```

Or pass installation profiles directly:

```bash
curl -fsSL https://raw.githubusercontent.com/paman7647/TraceForge/master/scripts/bootstrap.sh | bash -s -- --profile recommended
```

---

## 3. Global Installation via `pip`

TraceForge core has **zero required external Python dependencies** (100% standard library).

```bash
# Core CLI and localhost Web Console
pip install traceforge-osint

# Optional Document & Spreadsheet Reporting (Excel / Word)
pip install "traceforge-osint[reporting]"

# Optional Complete Package (Reporting + Documentation + Dev Tools)
pip install "traceforge-osint[all]"
```

Verify your installation from any directory:

```bash
traceforge --version
traceforge doctor
traceforge config paths
```

---

## 4. Source Repository Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/paman7647/TraceForge.git
cd TraceForge
```

### Step 2: Run the Setup Script
```bash
# Default Recommended Setup (Python logic + Go fast-paths + Core tools)
./setup.sh --profile recommended

# Preview planned installation actions without modifying the system
./setup.sh --dry-run

# Offline Setup (uses local dependencies without network updates)
./setup.sh --offline

# Automated Environment & System Repair
./setup.sh --repair
```

---

## 5. Runtime Installation Profiles

Select the profile that best matches your disk space and performance requirements:

| Profile | Command | Disk Space | Description |
|---|---|---|---|
| **`recommended`** *(Default)* | `./setup.sh --profile recommended` | ~1.2 GB | Python application logic + compiled Go fast-paths for hashing and stream triage. |
| **`minimal`** | `./setup.sh --profile minimal` | ~250 MB | Core built-in analysis engine and essential CLI tools only. |
| **`full`** | `./setup.sh --profile full` | ~3.5 GB | Complete suite including all automatically installable and supported catalog utilities. |
| **`custom`** | `./setup.sh --profile custom` | Variable | Interactive component selection. |

---

## 6. Native Go Fast-Path Compilation

TraceForge provides compiled Go acceleration binaries (`bin/traceforge-native`) for high-throughput IOC extraction, file diffing, timeline normalization, and packet indexing.

```bash
# Compile native helper (automatically skips if source is unchanged)
./scripts/build_native.sh

# Force re-compilation
./scripts/build_native.sh --force
```

---

## 7. Diagnostics & Environment Repair

TraceForge includes automated diagnostic and repair capabilities:

```bash
# Run complete system diagnostic check
traceforge doctor

# Auto-repair directories, configuration, and native helpers
traceforge doctor --repair

# Check platform-aware data, cache, config, and catalog paths
traceforge config paths
```

---

## 8. Platform Specific Details

### macOS
- **Apple Silicon (`arm64`)**: Homebrew installs binaries to `/opt/homebrew/bin`. Ensure `/opt/homebrew/bin` is in your `$PATH`.
- **Intel (`x86_64`)**: Homebrew installs binaries to `/usr/local/bin`.
- **Terminal Permissions (TCC)**: If analyzing files in `~/Desktop`, `~/Documents`, or `~/Downloads`, grant **Full Disk Access** to your terminal emulator under **System Settings → Privacy & Security → Full Disk Access**.

### Linux
- Supported distributions: Debian 12+, Ubuntu 22.04+, Kali Linux.
- Base packages: `git`, `python3`, `python3-venv`, `python3-pip`, `curl`, `ffmpeg`, `build-essential`.

### Termux / Android
- Run entirely in standard userland (`pkg install python golang tshark exiftool`).
- Android shared storage: Run `termux-setup-storage` to grant access to `/sdcard`, `Downloads`, and `DCIM`.
