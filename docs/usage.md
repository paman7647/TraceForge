# Using TraceForge

TraceForge offers two operational workflows:
1. **Interactive TTY Console**: Menu-driven interface for human investigators.
2. **Direct CLI Subcommands**: Scriptable commands for pipelines, incident response playbooks, and terminal workflows.

---

## 1. Interactive TTY Console

To launch the interactive console:

```bash
traceforge
# or
./main.sh
```

```text
╔══════════════════════════════════════════════════════════════════════╗
║                             TRACEFORGE                               ║
║           Open-Source Intelligence & Digital Forensics               ║
╠══════════════════════════════════════════════════════════════════════╣
║ Lead: Aman Kumar Pandey    Profile: PYTHON-GO    Platform: Workstation ║
╚══════════════════════════════════════════════════════════════════════╝

======================================================================
  TRACEFORGE — Interactive Operator Console
  [Active Case: None (Default Workspace)] • [Profile: PYTHON-GO]
======================================================================
  [1] New Case                 (Initialize a new forensic case)
  [2] Open Case                (Switch active case)
  [3] List Cases               (View all registered workspaces)
  [4] Add Evidence             (Ingest evidence with SHA-256 integrity hash)
  [5] Run Investigation        (Execute one of 7 analysis modules)
  [6] TraceForge Tools         (Run native first-party analytical tools)
  [7] Tool Catalog             (Search, inspect, and audit 175 tools)
  [8] Export / Reports         (Generate Markdown, HTML, CSV, STIX, MISP)
  [K] Credentials Vault        (Manage third-party OSINT API keys)
  [W] Web Console              (Launch interactive local web browser UI)
  [S] Settings                 (Configure runtime profile & fast-paths)
  [D] Doctor                   (Check environment, dependencies & runtimes)
  [L] Legal / Policy           (Responsible use, disclaimers, privacy)
  [Q] Quit
```

### Keyboard Shortcuts:
- **`1` - `8`**: Select case management, evidence ingestion, module execution, or report export.
- **`K`**: Open API Keys & OSINT Credentials Vault.
- **`W`**: Launch interactive web console (`127.0.0.1:8000`).
- **`S`**: Open runtime settings to change active profile or configure fast-path overrides.
- **`D`**: Run environment doctor diagnostics.
- **`L`**: Display responsible use, legal disclaimers, and statutory policies.
- **`Q`**: Exit cleanly.


---

## 2. Direct CLI Subcommands

For headless servers, CI/CD pipelines, and script automation, every action is available directly on the command line:

```bash
# Doctor diagnostics
traceforge doctor

# Case management
traceforge case new "Case-Alpha" --analyst "Aman"
traceforge case list
traceforge case open CASE-20260825-A1B2C3
traceforge case add-evidence ./dump.raw --desc "RAM image"

# Investigation modules
traceforge module 1 ./photo.jpg                # Image forensics
traceforge module 2 ./traffic.pcap             # Network recon
traceforge module 3 target_handle              # Identity & social
traceforge module 4 target@example.com         # Email breach
traceforge module 5 example.com                # Domain & DNS
traceforge module 6 ./report.pdf               # Document harvesting
traceforge module 7                            # OPSEC audit

# First-party analytical tools
traceforge tools asset-graph ./domains.txt --html ./graph.html
traceforge tools diff old_dns.txt new_dns.txt --domain dns
traceforge tools ioc-extract ./logs.txt --defang
traceforge tools evidence-index /evidence/directory/
traceforge tools log-triage ./access.log
traceforge tools pcap-summary ./capture.pcap
traceforge tools file-baseline /etc/ --out baseline.json
traceforge tools endpoint-inspect

# Tool catalog search
traceforge catalog "metadata"

# Export deliverables
traceforge export --redact --out ./deliverables/
```
