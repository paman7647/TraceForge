# Contributing to TraceForge

We welcome contributions from developers, DFIR specialists, OSINT researchers, and technical writers.

---

## 1. Two-Branch Contribution Workflow

TraceForge uses two permanent branches:
- **`master`**: Protected stable release branch.
- **`beta`**: Active development and integration branch.

All pull requests must target the **`beta`** branch:

```bash
# 1. Fork and clone the repository
git clone https://github.com/paman7647/TraceForge.git
cd TraceForge

# 2. Create a working branch from beta
git checkout beta
git checkout -b feature/your-feature-name

# 3. Make changes and verify functionality
traceforge doctor
traceforge tools audit --integration

# 4. Open a Pull Request targeting 'beta'
```

---

## 2. Contribution Standards

- **Portability**: Shell scripts must run on macOS (Bash 3.2) and Linux (Bash 4+). Avoid Bash 4-exclusive syntax (`declare -A`, `mapfile`).
- **Safety**: Always quote parameter expansions (`"$target"`) and use structured arrays (`"${cmd[@]}"`).
- **Verification**: Ensure all script changes pass `bash -n` syntax checks and ShellCheck static analysis.
- **Catalog Verification**: New tools added to `catalog/tools.tsv` must have verified package recipes across macOS, Linux, and Termux.


See [Branching Workflow](branching.md) and [Development Guide](development.md) for further details.
