# Installation & Setup

This guide explains how to install TraceForge, set up external package dependencies, and configure your runtime environment.

---

## 1. System Requirements

| Platform | Tier | Architecture | Package Manager | Python | Notes |
|---|---|---|---|---|---|
| **macOS** | Supported | `arm64` (Apple Silicon), `x86_64` (Intel) | [Homebrew](https://brew.sh/) | 3.9+ | macOS 12 Monterey or later |
| **Linux** | Supported | `x86_64`, `arm64` | APT (Debian, Ubuntu, Kali) | 3.9+ | Ubuntu 22.04+, Debian 12+, Kali Linux |
| **Termux (Android)** | Supported | `arm64`, `armv7`, `x86_64` | `pkg` (Termux userland) | 3.11+ | Non-root userland. See [Termux Guide](platforms/termux.md) |

---

## 2. Standard Installation (Recommended)

TraceForge provides an automated installer (`install_all.sh`) that provisions system packages, sets up isolated Python tool virtualenvs via `pipx`, and optionally compiles Go helpers.

### Step 1: Clone Repository
```bash
git clone https://github.com/paman7647/TraceForge.git
cd TraceForge
chmod +x install_all.sh main.sh modules/*.sh scripts/*.sh tests/*.sh
```

### Step 2: Run the Installer
```bash
# Default Recommended Setup (Python logic + Go acceleration)
./install_all.sh --profile python-go
```

To preview the planned installation commands without modifying your system:
```bash
./install_all.sh --profile python-go --dry-run
```

---

## 3. Runtime Installation Profiles

Select the profile that best matches your disk space and performance requirements:

| Profile | Command | Disk Space | Description |
|---|---|---|---|
| **`python-go`** *(Default)* | `./install_all.sh --profile python-go` | ~1.2 GB | Python application logic + compiled Go fast-paths for hashing and stream triage. |
| **`python`** | `./install_all.sh --profile python` | ~600 MB | Pure Python reference implementation; zero native compiler requirements. |
| **`go`** | `./install_all.sh --profile go` | ~400 MB | High-throughput Go utilities; minimal Python dependencies. |
| **`minimal`** | `./install_all.sh --profile minimal` | ~250 MB | Core built-in analysis engine and essential CLI tools only. |
| **`full`** | `./install_all.sh --profile full` | ~3.5 GB | Complete suite including all 152 catalog utilities. |
| **`custom`** | `./install_all.sh --profile custom` | Variable | Interactive component selection. |

---

## 4. Python Package Installation

To install the TraceForge CLI package directly in a Python virtual environment:

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install TraceForge in editable mode
pip install -e .

# 3. Verify CLI availability
traceforge --version
traceforge doctor
```

---

## 5. macOS Details

- **Apple Silicon (`arm64`)**: Homebrew installs binaries to `/opt/homebrew/bin`. Ensure `/opt/homebrew/bin` is in your `$PATH`.
- **Intel (`x86_64`)**: Homebrew installs binaries to `/usr/local/bin`.
- **Terminal Permissions (TCC)**: If analyzing files in `~/Desktop`, `~/Documents`, or `~/Downloads`, grant **Full Disk Access** to your terminal emulator (Terminal.app, iTerm2, Kitty, Alacritty) under **System Settings → Privacy & Security → Full Disk Access**.

---

## 6. Linux Details (Debian / Ubuntu / Kali)

- The installer uses `apt-get` for native tools (e.g. `tshark`, `exiftool`, `poppler-utils`).
- Ensure your user has `sudo` privileges to install system packages.
- On Kali Linux, many OSINT and forensics tools are already pre-installed; TraceForge detects existing binaries and avoids redundant downloads.

---

## 7. Verifying Installation

Run the environment doctor to verify your runtime and toolchain:

```bash
traceforge doctor
# or
./main.sh doctor
```
