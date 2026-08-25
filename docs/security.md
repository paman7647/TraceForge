# Security Policy & Vulnerability Reporting

TraceForge takes security, defensive safety, and responsible disclosure seriously.

---

## 1. Reporting a Security Vulnerability

> [!CAUTION]
> **DO NOT report security vulnerabilities via public GitHub issues, pull requests, or public discussions.**

### Preferred Reporting Method
Submit a confidential vulnerability report via **GitHub Private Vulnerability Reporting**:
1. Navigate to the **Security** tab of the repository at [https://github.com/paman7647/TraceForge/security](https://github.com/paman7647/TraceForge/security).
2. Click **"Report a vulnerability"** to open a private advisory.

### What to Include in Your Report
- Summary of the vulnerability and its potential impact.
- Affected component, module, or CLI subcommand.
- Step-by-step reproduction instructions or proof-of-concept (PoC).
- Recommended mitigation or defensive patch if available.

---

## 2. Defensive Security Architecture

TraceForge implements defensive coding practices throughout its codebase:

### Zero Command Injection
- All external tool executions in Python use structured argument lists (`subprocess.run(["tool", arg1, arg2])`) with `shell=False`.
- All shell executions in Bash use structured array expansion (`"${cmd[@]}"`).

### Zero Secret Exposure
- No credentials, tokens, or private keys are hardcoded in the codebase.
- Application logs strictly avoid printing raw secrets or authorization headers.

### CSV Formula Injection Mitigation
- Exported spreadsheet cells are sanitized against spreadsheet formula injection (`=`, `+`, `-`, `@`).

### Path Traversal Defense
- Ingested evidence filenames and case identifiers are strictly validated and canonicalized to prevent directory climbing (`../`).
