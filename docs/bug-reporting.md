# Bug Reporting & Issue Guidelines

Guidelines for reporting issues, defects, and regressions in TraceForge.

---

## 1. Where to Report Issues

| Issue Type | Target Location | Disclosure Protocol |
|---|---|---|
| **Ordinary Software Bug** | [GitHub Issues](https://github.com/paman7647/TraceForge/issues) (Target: `beta`) | Public Issue |
| **Security Vulnerability** | [GitHub Security Advisories](https://github.com/paman7647/TraceForge/security/advisories) | **Private Coordinated Disclosure** (See [Security Policy](security.md)) |
| **Feature Proposal** | [GitHub Issues](https://github.com/paman7647/TraceForge/issues) (Feature Template) | Public Discussion |

> [!CAUTION]
> **SECURITY NOTICE**: Do **NOT** open a public issue for security vulnerabilities, authentication bypasses, command injections, or sensitive data leaks. Follow the private disclosure protocol in [Security Policy](security.md).

---

## 2. Bug Target Branch Policy

When filing or testing a bug, test against the **`beta`** branch if practical:

- The `beta` branch contains the latest active fixes and pre-release code.
- If an issue is present in `master` (the stable release), declare the exact version tag (e.g. `v1.0.0`) so maintainers can assess whether to issue a patch release or integrate into `beta`.

---

## 3. Bug Report Requirements

To help maintainers reproduce and resolve the issue quickly, include the following information:

```text
1. TraceForge Version : traceforge --version (or contents of VERSION)
2. Git Branch & Commit : git rev-parse --short HEAD (e.g. beta @ a1b2c3d)
3. Operating System    : macOS (14.5 Sonoma) / Ubuntu 22.04 / Kali Linux / Termux (Android)
4. Architecture        : arm64 (Apple Silicon / Android) / x86_64
5. Runtime Versions    : Python 3.11.8, Go 1.22.2 (if applicable)
6. Termux Info         : Termux version, storage permissions (if applicable)
7. Runtime Profile     : python-go / python / minimal / full
8. Command Executed    : Exact command line used
9. Expected Behavior   : What should have happened
10. Actual Behavior    : What actually happened
11. Steps to Reproduce : Step-by-step instructions
12. Sanitized Logs     : Console output with secrets redacted
```

---

## 4. Zero Sensitive Data Policy

> [!WARNING]
> When pasting logs, stack traces, or command outputs, **always sanitize sensitive information**:
> - Redact API keys, tokens, passwords, and authorization headers.
> - Redact internal private IP addresses, sensitive hostnames, and client evidence files.
> - Never upload proprietary documents, internal PCAPs, or confidential evidence to public issue trackers.

---

## 5. Bug-Fix Lifecycle

TraceForge follows a structured bug-fix pipeline:

```text
    Bug Discovered & Reported (Target: beta)
                   │
                   ▼
       Maintainer Reproduces Issue
                   │
                   ▼
     Working Branch: fix/<issue-name>
                   │
                   ▼
  Regression Test Added in tests/ (Verifying the fix)
                   │
                   ▼
     Pull Request Targeting 'beta'
                   │
                   ▼
   Automated CI Verification (macOS, Linux, Termux)
                   │
                   ▼
        Code Review & Approval
                   │
                   ▼
        Merged into 'beta' Branch
                   │
                   ▼
  Included in next stable release PR (beta ➔ master)
```
