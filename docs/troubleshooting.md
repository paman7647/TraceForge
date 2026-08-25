# Troubleshooting & Common Issues

Solutions to common installation, environment, and runtime problems.

---

## 1. Environment & Path Issues

### Issue: `command not found: traceforge`
- **Cause**: The Python virtual environment is not activated, or `$HOME/.local/bin` is not in your `$PATH`.
- **Solution**:
  ```bash
  source .venv/bin/activate
  # or invoke directly via python:
  python3 -m traceforge --version
  ```

### Issue: Homebrew commands not found on Apple Silicon macOS
- **Cause**: Apple Silicon Macs install Homebrew to `/opt/homebrew/bin`, which may not be in your default shell path.
- **Solution**: Add the following to your `~/.zshrc` or `~/.bashrc`:
  ```bash
  eval "$(/opt/homebrew/bin/brew shellenv)"
  ```

---

## 2. Termux / Android Issues

### Issue: Permission denied when accessing `/sdcard` or `~/storage`
- **Cause**: Android has not granted storage read permissions to the Termux app.
- **Solution**: Run:
  ```bash
  termux-setup-storage
  ```
  Accept the Android permission prompt, then access files via `~/storage/shared/` or `~/storage/downloads/`.

### Issue: `tshark` or `aircrack-ng` live capture fails on Termux
- **Cause**: Android restricts raw socket capture (`SOCK_RAW`) and wireless monitor mode to the `root` user (`uid 0`).
- **Solution**: TraceForge supports **offline PCAP file analysis** completely unrooted. Use `traceforge tools pcap-summary <file>` or `traceforge module 2 <file>` without root.

---

## 3. Toolchain & Compiler Issues

### Issue: `Go Toolchain: Not available` in `traceforge doctor`
- **Behavior**: TraceForge automatically and transparently falls back to its built-in pure Python reference implementations for hashing, IOC extraction, and log triage.
- **Solution** (Optional): Install Go to enable accelerated fast-paths:
  ```bash
  # macOS:
  brew install go
  # Linux:
  sudo apt-get install -y golang-go
  # Termux:
  pkg install -y golang
  ```

---

## 4. Reporting & Rendering Dependencies

### Issue: `[WARN] openpyxl not installed. Skipping XLSX generation.`
- **Cause**: Optional Python libraries for Microsoft Office document generation are not installed.
- **Solution**: Core HTML, Markdown, CSV, STIX, and MISP exports work with zero dependencies. If you need Excel, Word, or PDF outputs:
  ```bash
  pip install openpyxl python-docx
  ```

---

## 5. macOS Terminal Permissions (TCC)

### Issue: `Operation not permitted` when reading evidence in Downloads or Desktop
- **Cause**: macOS Transparency, Consent, and Control (TCC) subsystem blocks terminal access to user directories.
- **Solution**:
  1. Open **System Settings → Privacy & Security → Full Disk Access**.
  2. Enable your terminal app (Terminal, iTerm2, Kitty, Alacritty).
  3. Restart the terminal.
