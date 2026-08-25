# Privacy Policy & Local Data Handling

TraceForge adheres to a **local-first, privacy-by-design** architecture.

---

## 1. Zero Cloud Telemetry

- **100% Local Processing**: All evidence parsing, hashing, timeline sorting, and report generation execute locally on the host workstation.
- **No Analytics or Phone-Home**: TraceForge does not embed tracking pixels, telemetry beacons, crash reporters, or third-party analytics.
- **No Account Required**: TraceForge does not require registration, login, or cloud accounts.

---

## 2. Evidence Storage & Redaction

- **Local Workspaces**: Case data is stored strictly in `workspace/` under the local user directory.
- **Automated PII Redaction**: The `--redact` flag automatically masks discovered IP addresses and email addresses in exported deliverables.
See [Security & Threat Model](security.md) and [Responsible Use Guidelines](responsible-use.md) for further details.
