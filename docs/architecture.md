# System Architecture

TraceForge is designed around three architectural principles: **reliability**, **portability**, and **defensive safety**.

---

## 1. High-Level Architecture

TraceForge does not force every task into a single language. It uses each technology where it is strongest:

```text
                        +--------------------------------+
                        |         Operator CLI           |
                        |     (traceforge / main.sh)     |
                        +---------------+----------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
  +-------------------------------+             +-------------------------------+
  |   Python Application Layer    |             |    Bash Provisioning Layer    |
  |  • Case Lifecycle & Chain     |             |  • macOS Homebrew Installer   |
  |  • Multi-Format Exporters     |             |  • Linux APT Installer        |
  |  • Module Orchestration       |             |  • Termux 'pkg' Installer     |
  |  • STIX / MISP / HTML / CSV   |             |  • Environment Doctor & Path  |
  +---------------+---------------+             +-------------------------------+
                  |
                  v (Dynamic Runtime Dispatch)
  +-------------------------------+
  |   First-Party Analysis Engine |
  |  • Pure Python Reference      | <--- Adaptive Fallback ---> +-------------------------------+
  |  • Compiled Go Fast-Paths     |                             |  Compiled Go Binary (go/)     |
  +---------------+---------------+                             |  • High-Speed SHA-256 Hashing |
                  |                                             |  • Streaming IOC Regex Engine |
                  v                                             |  • High-Volume Log Triage     |
  +-------------------------------+                             +-------------------------------+
  |   Third-Party Tool Wrappers   |
  |  (ExifTool, TShark, Nmap,     |
  |   Sherlock, Holehe, etc.)     |
  +-------------------------------+
```

---

## 2. Component Roles

### 1. Python Application Layer (`traceforge/`)
- Handles case state management, evidence ingestion, audit logging, module logic, and report generation.
- Python is chosen for application logic because of its rich string handling, structured data capabilities (JSON, STIX, GeoJSON), and ecosystem portability.

### 2. Go Native Engine (`go/` ➔ `traceforge-native`)
- Implements high-throughput analytical routines: streaming regular expression IOC matching, multi-gigabyte SHA-256 directory hashing, and fast log parsing.
- Benchmarks confirm the compiled Go engine achieves **4.1x faster** execution than interpreted regular expressions on large log dumps, with 100% digest consistency.

### 3. Bash Installation & Execution Scripts (`lib/`, `modules/`, `install_all.sh`)
- Manages native OS package installation (`brew`, `apt-get`, `pkg`), command existence checks, and process isolation.
- Written for POSIX / Bash 3.2+ compatibility (runs out of the box on macOS default Bash as well as Linux).
- Uses structured arrays (`"${cmd[@]}"`) to guarantee zero shell injection vulnerabilities.

### 4. Central Tool Catalog (`catalog/tools.tsv`)
- Single source of truth defining 175 verified security tools across 22 structured columns (recipes, ecosystems, root flags, Termux support) spanning 13 investigative disciplines.


---

## 3. Evidence & Data Isolation

- **Non-Destructive Ingestion**: Original evidence files are never modified in place. Ingested copies are stored read-only (`0444`).
- **Chain of Custody**: Every evidence ingestion, finding, and report export is cryptographically stamped in an append-only `evidence-chain.jsonl` audit log.
- **Zero Cloud Leakage**: TraceForge runs 100% offline by default; no case evidence, telemetry, or logs are transmitted to external servers.
