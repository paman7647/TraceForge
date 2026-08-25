# Contributing to TraceForge

Thank you for contributing to TraceForge. We welcome pull requests, new verified tool additions, bug fixes, shell optimizations, Python/Go improvements, and documentation enhancements.

---

## 1. Development & Contribution Standards

### Git Workflow & Branching (Two-Branch Model)
1. Fork the repository on GitHub (`https://github.com/paman7647/TraceForge`).
2. Clone your fork and create a working branch **branched from `beta`**:
   ```bash
   git checkout beta
   git pull origin beta
   git checkout -b feature/add-tool-sherlock
   # or
   git checkout -b fix/macos-path-resolution
   ```
3. Keep commits atomic, well-documented, and focused on a single change.
4. Open your Pull Request **targeting the `beta` branch** (do not target `master`). See [docs/BRANCHING.md](docs/BRANCHING.md) for full branch lifecycle details.

### Shell Scripting Standards (Bash 3.2+ Portability)
* **Portability First**: The suite must execute cleanly on both macOS default `/bin/bash` (Bash 3.2) and modern Linux distributions (Bash 4.x/5.x on Ubuntu, Debian, Kali).
* **Do Not Use**: Avoid Bash 4+ exclusive syntax (associative arrays `declare -A`, `mapfile` / `readarray`, `&>>`, `|&`). Use standard POSIX/Bash 3.2 constructs.
* **Strict Quoting & Safety**: Always quote path and parameter expansions (`"$target_dir"`, `"${BASH_SOURCE[0]}"`). Use `set -Eeuo pipefail` where applicable.
* **No `eval`**: Never execute catalog strings or user input via `eval`. Always use structured Bash arrays (`safe_run_cmd` or `"${cmd_args[@]}"`).
* **ShellCheck Compliance**: All shell code must pass `shellcheck -x` with zero errors.

---

## 2. Adding a New Tool to the Catalog

TraceForge enforces a single canonical source of truth for all tools in `catalog/tools.tsv`.

### Catalog Checklist
1. **Verify Upstream Source**: The tool must be an actively maintained or historically significant utility with a public repository (GitHub, GitLab, official project site).
2. **Verify Installation Commands**:
   - Check if the package is available on Homebrew (`brew search <pkg>`).
   - Check if the package is available on Debian/Ubuntu/Kali APT (`apt-cache search <pkg>`).
   - Check PyPI (`pipx install <pkg>`), Go (`go install ...`), RubyGems (`gem install ...`), or Cargo (`cargo install ...`).
3. **Update `catalog/tools.tsv`**:
   Add the tool row with all 15 required fields:
   `id`, `name`, `binary`, `category`, `subcategory`, `ecosystem`, `mac_install`, `linux_install`, `description`, `status`, `requires_root`, `requires_api`, `requires_hardware`, `notes`, `source_url`.
4. **Regenerate Documentation**:
   ```bash
   ./scripts/generate_catalog_docs.sh
   ```
5. **Update Third-Party Notices**:
   Ensure the upstream project license is recorded in `THIRD_PARTY_NOTICES.md`.

---

## 3. Testing Requirements

Before submitting any Pull Request, you must run and pass the full automated test suite and pre-flight validation:

```bash
# 1. Run all unit and integration tests
./tests/test.sh

# 2. Run the release and repository health check
./scripts/release_check.sh
```

All 5 test suites and ShellCheck checks must complete with exit code `0`.

---

## 4. Pull Request Checklist

When submitting a Pull Request, ensure:

- [ ] All shell scripts pass `bash -n` and `shellcheck -x`.
- [ ] New catalog tools have verified installation strings on macOS and Linux.
- [ ] No hardcoded local machine paths (`/Users/`, `/home/`, `/private/`) or personal credentials are included.
- [ ] `catalog/tools.tsv`, `catalog/TOOLS.md`, and `THIRD_PARTY_NOTICES.md` are synchronized.
- [ ] All automated tests in `./tests/test.sh` pass.
- [ ] Documentation (`docs/`) is updated if features or commands were added.

---

## 5. Security, Ethics & Legal Policies

* **Vulnerability Reporting**: Please do NOT report security vulnerabilities via public GitHub issues. Use the private vulnerability reporting flow described in [SECURITY.md](SECURITY.md).
* **Responsible Use Compliance**: All contributions, modules, and catalog additions must align with our [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and [DISCLAIMER.md](DISCLAIMER.md). We do not accept contributions whose sole purpose is unauthorized exploitation, credential theft, or deliberate denial of service.

