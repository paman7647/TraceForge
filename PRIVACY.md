# Privacy & Data Handling Policy

**Version:** 1.0.0  
**Effective Date:** 2026  
**Canonical Repository:** [https://github.com/paman7647/TraceForge](https://github.com/paman7647/TraceForge)

---

## 1. Local-First Architecture & Data Sovereignty

TraceForge is architected as a **strictly local-first, offline-capable CLI and execution environment**:

* **Zero Central Telemetry:** TraceForge does not send usage metrics, telemetry, crash reports, operator identifiers, or diagnostic telemetry back to the project maintainers or any central telemetry server.
* **Local Storage Only:** All investigation metadata, ingested evidence files, forensic notes, IOCs, timeline events, reports, and generated exports remain stored exclusively on the operator's local storage or configured environment paths.
* **No Remote State Synchronization:** TraceForge does not synchronize or store case workspaces on remote servers unless explicitly configured by the operator (e.g., custom network shares or external storage scripts).

---

## 2. Information Processed by the Software

During investigation and analysis workflows, TraceForge may process user-supplied inputs and target data, including:

| Data Category | Examples | Typical Processing |
|---|---|---|
| **Technical Observables** | IP addresses, CIDR ranges, domain names, DNS records, BGP ASNs | DNS resolution, WHOIS queries, network route tracing, graph correlation |
| **Identity & Account Observables** | Usernames, social media handles, email addresses, public profile URLs | Passive registry lookup, holehe registration queries, public profile analysis |
| **Evidence Files & Media** | Images, videos, PDF documents, Office files, PCAP captures, memory dumps | Hash computation (SHA-256), EXIF extraction, string analysis, protocol dissection |
| **Forensic & Operational Logs** | Web server access logs, syslog archives, authentication logs | Anomaly detection, regex IOC extraction, timestamp normalization |
| **Operator Metadata** | Analyst name, organization name, case ID, classification (TLP), notes | Embedded in case manifests (`case.json`), exports, and investigation reports |

---

## 3. Local Directory Layout & Storage Paths

TraceForge organizes data deterministically within the filesystem:

```text
TraceForge Filesystem Footprint:
├── workspace/                      # Active and archived investigation cases
│   └── CASE-YYYYMMDD-XXXXXX/       # Case root directory
│       ├── case.json               # Canonical case metadata, findings, timeline, IOCs
│       ├── evidence/               # Read-only ingested evidence artifacts
│       ├── manifest/               # Cryptographic evidence-chain.jsonl logs
│       ├── reports/                # Generated Markdown, HTML, PDF reports
│       └── exports/                # Exported CSV, TSV, JSON, STIX, MISP, KML datasets
├── ~/.config/traceforge/           # User configuration, custom templates, environment flags
├── ~/.cache/traceforge/            # Temporary analysis artifacts and tool cache
└── ~/.local/share/traceforge/      # Persistent tool data and package provisioner state
```

### Git Repository Hygiene
* The `workspace/` directory and `.osint_venv` virtual environment are excluded by default via `.gitignore`.
* **Important:** Operators must never commit `workspace/` case directories, client data, or evidence artifacts to version control repositories.

---

## 4. Third-Party Network Interaction & External Services

While TraceForge itself collects no telemetry, executing specific modules or third-party tools within the catalog will generate outbound network traffic:

* **DNS & Infrastructure Queries:** Tools like `dig`, `whois`, `subfinder`, and `dnsrecon` transmit DNS requests to upstream resolvers. Operators should be aware that unencrypted DNS queries may expose target domains to network observers.
* **Public APIs & Threat Intelligence:** Integrating API keys for services like Shodan, VirusTotal, Censys, or AlienVault transmits queried observables (IPs, hashes, domains) to those external providers. Review the privacy policies and data retention practices of third-party services prior to querying sensitive internal assets.
* **Passive vs. Active Risk:** Running passive social queries (e.g., Sherlock, Holehe) generates HTTP GET/POST requests against third-party platforms from the operator's public IP address.

---

## 5. Personal Data Compliance & Data Protection Laws

Operators processing personal data (e.g., names, personal email addresses, mobile numbers, precise geolocation coordinates) are responsible for ensuring compliance with relevant privacy legislation, including:

* **General Data Protection Regulation (GDPR) / UK GDPR:** Ensuring a lawful basis for processing (e.g., legitimate interest, legal obligation), honoring data minimization, and maintaining appropriate technical safeguards.
* **California Consumer Privacy Act (CCPA / CPRA):** Managing personal information collection and avoiding unauthorized disclosure.
* **National Privacy Legislation:** Adhering to applicable national or state statutory privacy protections.

---

## 6. Built-in Redaction & Data Sanitization

TraceForge provides built-in mechanisms to support data minimization and privacy protection when sharing deliverables:

* **Automated Export Redaction:** Running `./main.sh export <case-id> --redact` (or `traceforge export <case-id> --redact`) triggers the deterministic redaction engine, which masks:
  * Personal and non-internal email addresses (`EMAIL-001@redacted.local`).
  * Non-loopback IPv4 addresses (`10.0.1.1`).
  * Sensitive operator notes and classified annotations.
* **Metadata Sanitization:** Module 07 provides integrations with tools like `mat2` to strip metadata from derived distribution copies without altering original evidence files.

---

## 7. Secret & Credential Management

* **Zero-Secret Commitment:** Never commit API keys, cloud tokens, database credentials, or private keys to TraceForge source trees, pull requests, or issue discussions.
* **Environment-Based Ingestion:** Provide API tokens to supported tools using environment variables (`SHODAN_API_KEY`, `VT_API_KEY`) rather than hardcoded script arguments.
* **Secure Deletion:** When an investigation closes, operators should securely wipe temporary cache files and sanitize case directories according to organizational data destruction standards.
