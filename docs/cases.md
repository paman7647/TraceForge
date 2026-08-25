# Case Management & Evidence Handling

TraceForge organizes investigations into self-contained case workspaces under `workspace/`. Every workspace preserves cryptographic evidence integrity, records an immutable audit log, and manages findings and indicators.

---

## 1. Case Lifecycle & Directory Structure

When a case is initialized, TraceForge generates a unique timestamped identifier:
```text
CASE-YYYYMMDD-<HEX6> (e.g. CASE-20260825-A1B2C3)
```

```text
workspace/CASE-20260825-A1B2C3/
├── case.json               # Canonical case metadata, findings, IOCs, and timeline
├── evidence-chain.jsonl    # Append-only cryptographic chain-of-custody audit log
├── evidence/               # Read-only ingested evidence artifacts
│   └── EVID-001/
│       ├── raw.bin
│       └── metadata.json
├── reports/                # Generated Markdown and HTML briefings
│   ├── CASE-20260825-A1B2C3.md
│   └── CASE-20260825-A1B2C3.html
└── exports/                # Export deliverables (CSV, JSON, STIX, MISP, KML)
```

---

## 2. Managing Cases via CLI

### Create a Case
```bash
traceforge case new "Operation Blue Sky" --analyst "Lead Investigator"
```

### List Registered Cases
```bash
traceforge case list
```

### Switch Active Case
```bash
traceforge case open CASE-20260825-A1B2C3
```

---

## 3. Evidence Ingestion & Cryptographic Integrity

When an investigator adds evidence to a case:
1. TraceForge reads the file in binary chunks.
2. Computes the **SHA-256 cryptographic digest**.
3. Copies the artifact into the case's private `evidence/` directory with read-only permissions (`0444`).
4. Logs an entry to `evidence-chain.jsonl`.

```bash
traceforge case add-evidence ./memory_dump.raw --desc "Volatile RAM capture from workstation"
```

Output:
```text
[+] Ingested evidence into CASE-20260825-A1B2C3: EVID-001 (SHA-256: 7f83b1657ff1fc53...)
```

---

## 4. Findings, Indicators & Timeline

Investigations record structured findings, indicators of compromise (IOCs), and timeline events:

```json
{
  "findings": [
    {
      "id": "FIND-001",
      "title": "Hidden EXIF Geolocation Found",
      "severity": "high",
      "confidence": "confirmed",
      "evidence_id": "EVID-001"
    }
  ],
  "iocs": [
    {
      "id": "IOC-001",
      "type": "ipv4",
      "value": "198.51.100.45",
      "threat_level": "critical"
    }
  ],
  "timeline": [
    {
      "id": "EVT-0001",
      "timestamp": "2026-08-25T14:30:00Z",
      "description": "Initial beaconing observed to C2 server"
    }
  ]
}
```

---

## 5. Case Archiving & Packaging

To bundle an entire case workspace into a verifiable, compressed ZIP archive:

```bash
traceforge export --out ./case_archive/
```

TraceForge computes an overall SHA-256 manifest across all case files, packages the evidence and reports, and ensures third-party reviewers can verify cryptographic integrity.
