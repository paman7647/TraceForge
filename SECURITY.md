# Security Policy

**Version:** 1.0.0  
**Canonical Repository:** [https://github.com/paman7647/TraceForge](https://github.com/paman7647/TraceForge)

---

## 1. Supported Versions

Only the latest major/minor release of TraceForge receives active security updates and vulnerability patches.

| Version | Supported Status    | Notes |
|---------|---------------------|-------|
| 1.0.x   | :white_check_mark: Supported | Current stable production branch |
| < 1.0.0 | :x: End of Life     | Pre-release / Legacy builds (unsupported) |

---

## 2. Reporting a Vulnerability

We prioritize the security of TraceForge, its operators, and the broader security community. If you identify a security vulnerability (such as command injection, path traversal, unsafe deserialization, insecure temporary file creation, formula injection in export handlers, or secret leakage risks), please report it responsibly.

### Coordinated Vulnerability Reporting Process

1. **GitHub Private Vulnerability Reporting (Preferred):**
   Navigate to the **Security** tab of the repository at `https://github.com/paman7647/TraceForge/security` and click **"Report a vulnerability"** to open a private Security Advisory.
2. **What to Include:**
   * Detailed summary of the vulnerability and its potential impact.
   * Specific file(s), line number(s), and affected functions or CLI subcommands.
   * Minimal, deterministic Proof-of-Concept (PoC) or reproduction steps.
   * Suggested remediation, patches, or defensive controls (if available).
3. **Disclosure Hygiene & Safety Rules:**
   * **No Real Credentials:** Never submit PoCs containing active API keys, real passwords, private customer data, or live breach dumps.
   * **No Public Disclosure:** Please refrain from opening public GitHub issues, PRs, or public social posts regarding unpatched vulnerabilities until the maintainers have had reasonable time to review, patch, and release an update.

---

## 3. Defensive Engineering Standards

TraceForge is engineered with strict defensive coding standards across all supported runtime interfaces:

* **Zero `eval` & Parameterized Execution:** System commands, catalog entries, and user inputs are strictly executed using structured Bash arrays (`"${cmd[@]}"`), Go typed argument slices (`exec.Command`), and Python subprocess parameter lists (`subprocess.run(list)`).
* **Defensive Path Canonicalization:** All input and output file paths are canonicalized and verified against directory traversal (`../`) and unauthorized symlink attacks.
* **CSV Formula Injection Mitigation:** All tabular export modules (CSV and TSV) automatically escape potentially executable formula trigger characters (`=`, `+`, `-`, `@`, `\t`, `\r`) by prefixing them with a single quote (`'`).
* **Evidence Chain of Custody:** Ingested evidence files are immediately hashed with SHA-256 and treated as read-only. Original files are never modified in place.
* **Dependency & Ecosystem Isolation:** External Python tools are isolated via `pipx` or a dedicated virtual environment (`.osint_venv`), preventing global system package pollution.
