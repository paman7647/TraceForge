# Command Reference

Complete reference for all built-in TraceForge subcommands and options.

---

## Global Options

| Option | Description |
|---|---|
| `--version` | Display the current installed TraceForge version. |
| `--legal` | Display responsible use, legal disclaimer, and statutory compliance notices. |
| `-v`, `--verbose` | Enable runtime decision tracing (fast-path selection, execution timers). |

---

## 1. System & Diagnostics

### `traceforge doctor`
Runs environment checks, audits the toolchain, verifies package managers, inspects disk space, and tests reporting capabilities.

```bash
traceforge doctor
```

### `traceforge termux`
Displays Termux/Android status, shared storage configuration, and supported vs root-required capability boundaries.

```bash
traceforge termux
```

---

## 2. Configuration & Profiles

### `traceforge profile [name]`
View or switch the active runtime profile (`python-go`, `python`, `go`, `minimal`, `full`, `custom`).

```bash
# View active profile
traceforge profile

# Switch active profile
traceforge profile python-go
```

### `traceforge config <list|get|set|paths>`
Inspect or modify configuration keys, fast-path overrides, and storage paths.

```bash
# Display user data and workspace paths
traceforge config paths

# List all config keys
traceforge config list

# Set a feature-level runtime override (e.g. force Go for hashing)
traceforge config set hash.runtime go

# Reset override to auto
traceforge config set hash.runtime auto
```

---

## 3. Case Management

### `traceforge case new <name> [--analyst <name>]`
Create and activate a new case workspace with immutable audit logs.

```bash
traceforge case new "Incident Alpha" --analyst "Aman"
```

### `traceforge case list`
List all registered investigation cases in `workspace/`.

```bash
traceforge case list
```

### `traceforge case open <case_id>`
Switch the active case to another registered case.

```bash
traceforge case open CASE-20260825-A1B2C3
```

### `traceforge case add-evidence <path> [--desc <text>] [--case-id <id>]`
Ingest an evidence file into the case with SHA-256 integrity verification.

```bash
traceforge case add-evidence ./memory.dmp --desc "Physical RAM capture"
```

---

## 4. First-Party Analytical Tools

### `traceforge tools asset-graph [file] [--html <out.html>]`
Parse IP addresses, subdomains, and URLs from a file or stdin, extract topological connections, and export to JSON or visual interactive HTML.

```bash
traceforge tools asset-graph ./subdomains.txt --html ./network_graph.html
```

### `traceforge tools diff <file1> <file2> [--domain <name>]`
Compare two DNS, HTTP, or asset snapshots and output added, removed, and modified items.

```bash
traceforge tools diff ./dns_yesterday.txt ./dns_today.txt --domain dns
```

### `traceforge tools ioc-extract [file] [--defang] [--json]`
Extract IPv4, IPv6, domains, email addresses, and SHA-256 hashes from text or log streams.

```bash
traceforge tools ioc-extract ./incident.log --defang --json
```

### `traceforge tools evidence-index [dir] [--json]`
Recursively index a directory, computing SHA-256 digests, MIME types, and file sizes.

```bash
traceforge tools evidence-index /path/to/evidence/ --json
```

### `traceforge tools log-triage [file]`
Triage Apache/Nginx combined access logs and syslog streams for authentication failures, status code distributions, and burst anomalies.

```bash
traceforge tools log-triage /var/log/auth.log
```

### `traceforge tools pcap-summary <file>`
Dissect packet capture files, extracting conversation pairs, protocol hierarchies, DNS queries, and TLS SNI headers.

```bash
traceforge tools pcap-summary ./traffic.pcap
```

### `traceforge tools file-baseline <dir> [--out <out.json>]`
Create or compare cryptographic filesystem baselines to detect modified, deleted, or newly created files.

```bash
# Create baseline
traceforge tools file-baseline /etc/ --out /tmp/etc_baseline.json

# Compare against new state
traceforge tools file-baseline /tmp/etc_baseline.json /tmp/etc_new_baseline.json
```

### `traceforge tools endpoint-inspect`
Collect defensive host environment posture (OS, architecture, active interfaces, listening ports, Termux storage/API state).

```bash
traceforge tools endpoint-inspect
```

---

## 5. Investigation Modules

### `traceforge module <id> [target] [case_id]`
Execute one of the 7 built-in investigation modules:

```bash
traceforge module 1 ./image.jpg                # Media Forensics
traceforge module 2 ./traffic.pcap             # Network Recon & PCAP Triage
traceforge module 3 operator_handle            # Identity & Social Recon
traceforge module 4 target@example.com         # Email & Breach Intelligence
traceforge module 5 targetdomain.com           # Domain & DNS Intelligence
traceforge module 6 ./document.pdf             # Document Harvesting
traceforge module 7                            # Defensive OPSEC Audit
```

---

## 6. Case Export Subsystem

### `traceforge export [case_id] [--redact] [--out <dir>]`
Generate case reports and intelligence deliverables in Markdown, HTML, CSV, TSV, JSON, STIX 2.1, MISP, and KML formats.

```bash
# Export active case with PII redaction
traceforge export --redact

# Export specific case to a custom directory
traceforge export CASE-20260825-A1B2C3 --out /tmp/deliverables/
```

---

## 7. Tool Catalog

### `traceforge catalog [query]`
Search the 152-tool catalog by name, category, or binary.

```bash
traceforge catalog "pcap"
```
