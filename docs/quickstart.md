# Quick Start

Get from installation to a completed investigation and exported case report in five minutes.

---

## Step 1: Check System Health

Verify that TraceForge and your environment are ready:

```bash
traceforge doctor
```

Output confirms the active profile, detected toolchain, and reporting capabilities:
```text
=== TraceForge Environment & Runtime Diagnostics ===

[ Active Runtime Profile ]
  Profile          : PYTHON-GO

[ Host Platform ]
  Operating System : macOS (Sonoma 14.5)
  Architecture     : arm64
  Python Version   : 3.11.8 (in Virtualenv)
  Go Toolchain     : go1.22.2

[ First-Party Fast-Path Acceleration ]
  hash         : ✓ ACCELERATED (Go)   (Preferred: go)
  ioc          : ✓ ACCELERATED (Go)   (Preferred: go)
  pcap         : ✓ ACTIVE (PYTHON)    (Preferred: python)
```

---

## Step 2: Initialize a Case Workspace

Create a dedicated forensic workspace for your investigation:

```bash
traceforge case new "Operation Beacon" --analyst "Lead Analyst"
```

Output:
```text
[+] Created and activated case: CASE-20260825-A1B2C3 (Operation Beacon)
```

TraceForge stores case metadata, ingested evidence, findings, indicators, timeline events, and audit logs under `workspace/CASE-20260825-A1B2C3/`.

---

## Step 3: Ingest Evidence

Import an artifact (e.g. a packet capture or memory dump) into the case. TraceForge automatically computes a cryptographic SHA-256 hash and records the chain of custody:

```bash
traceforge case add-evidence ./suspicious_network.pcap --desc "Edge firewall packet capture"
```

Output:
```text
[+] Ingested evidence into CASE-20260825-A1B2C3: EVID-001 (SHA-256: 7f83b1657ff1fc53...)
```

---

## Step 4: Run First-Party Analysis Tools

### 1. Extract and Defang IOCs
Scan text files or logs for IPv4, IPv6, domains, email addresses, and SHA-256 digests:

```bash
traceforge tools ioc-extract ./firewall.log --defang
```

### 2. Dissect Network Traffic
Summarize protocols, conversations, DNS queries, and TLS SNI headers from PCAP captures:

```bash
traceforge tools pcap-summary ./suspicious_network.pcap
```

### 3. Build Asset Relationship Graph
Generate an asset connection graph and export to an interactive visual HTML file:

```bash
traceforge tools asset-graph ./subdomains.txt --html ./asset_graph.html
```

---

## Step 5: Export Case Deliverables

Export the entire case with automated PII redaction:

```bash
traceforge export --redact
```

Deliverables generated under `workspace/CASE-20260825-A1B2C3/exports/`:
- **`reports/CASE-20260825-A1B2C3.md`**: Human-readable Markdown briefing.
- **`reports/CASE-20260825-A1B2C3.html`**: Standalone dark-mode HTML report.
- **`exports/csv/`**: Relational CSV tables (`findings.csv`, `iocs.csv`, `timeline.csv`).
- **`exports/json/stix21_bundle.json`**: STIX 2.1 Threat Intelligence bundle.
- **`exports/json/misp_event.json`**: MISP Core Event JSON.
- **`exports/geo/geospatial.kml`**: Google Earth map overlay for IP geolocation.
