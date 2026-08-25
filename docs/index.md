# TraceForge

> **Open-source OSINT, DFIR and security investigation toolkit.**

TraceForge is a command-line toolkit for open-source intelligence (OSINT), digital forensics and incident response (DFIR), network packet capture triage, evidence management, and multi-format case reporting.

It provides first-party analytical tools in Python and Go, manages 152 third-party security utilities across macOS, Linux, and Android (Termux), and creates self-contained investigation workspaces with cryptographic chain-of-custody logging.

---

## Key Capabilities

- **Adaptive Runtime Engine**: Pure Python analytical reference tools with compiled Go helpers for high-throughput hashing and stream processing.
- **Unified CLI & Console**: Full interactive TTY console (`traceforge` / `./main.sh`) and direct CLI subcommands for automation.
- **152-Tool Catalog**: Curated installation and execution recipes across Homebrew, Debian/APT, Termux `pkg`, `pipx`, Go, and Cargo.
- **7 Investigation Modules**: Built-in workflows for media forensics, network PCAPs, identity and social accounts, email breach records, domain DNS reconnaissance, document metadata, and OPSEC audits.
- **Case Management & Evidence Integrity**: Self-contained cases under `workspace/` with SHA-256 evidence hashing, timeline normalization, and immutable audit logs.
- **Multi-Format Export Subsystem**: Generates case deliverables in Markdown, standalone dark-mode HTML, relational CSV, TSV, JSON, JSONL event streams, STIX 2.1, MISP JSON, GeoJSON, KML, and signed ZIP packages.
- **Defensive PII Redaction**: Built-in `--redact` flag to mask sensitive IP and email addresses before sharing reports.

---

## Quick Example

```bash
# 1. Create and activate a forensic case
traceforge case new "Operation Beacon" --analyst "Aman"

# 2. Extract IOCs from a suspicious text log
traceforge tools ioc-extract ./evidence.log --defang

# 3. Dissect a network capture file
traceforge tools pcap-summary ./traffic.pcap

# 4. Export full case reports with PII redaction
traceforge export --redact
```

---

```{toctree}
:maxdepth: 2
:caption: Getting Started

installation
quickstart
usage
```

```{toctree}
:maxdepth: 2
:caption: Investigation & Tools

commands
modules
tools
configuration
```

```{toctree}
:maxdepth: 2
:caption: Case Management & Reporting

cases
reporting
platforms/termux
```

```{toctree}
:maxdepth: 2
:caption: System Architecture

architecture
troubleshooting
```

```{toctree}
:maxdepth: 2
:caption: Policies & Legal Boundaries

responsible-use
privacy
security
third-party
```

```{toctree}
:maxdepth: 2
:caption: Development & Community

contributing
development
branching
bug-reporting
pypi
changelog
```
