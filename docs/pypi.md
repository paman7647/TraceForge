# PyPI Publishing & Trusted Publishing Guide

This guide covers building, testing, and publishing TraceForge to the Python Package Index (PyPI) using modern PyPA standards and GitHub Actions OIDC Trusted Publishing.

---

## 1. Distribution & Package Overview

- **PyPI Distribution Name**: `traceforge-osint`
- **Import Package**: `traceforge`
- **CLI Executable**: `traceforge`
- **Version**: `1.0.0` (synchronously bound to `VERSION` and `pyproject.toml`)

Users install TraceForge via:
```bash
pip install traceforge-osint
# or
pipx install traceforge-osint
```

And run:
```bash
traceforge --version
# or
python3 -m traceforge --version
```

---

## 2. Local Package Build & Validation

To build and validate the source distribution (`.tar.gz`) and wheel (`.whl`) locally:

```bash
# Clean, build, validate with twine, and run clean-env smoke test:
bash scripts/build_package.sh
```

This runs:
1. `python3 -m build --sdist --wheel --outdir dist/`
2. `python3 -m twine check dist/*`
3. Installs the built wheel into a temporary isolated virtual environment (`/tmp/traceforge-pypi-test-*`).
4. Executes `traceforge --version`, `traceforge --help`, catalog lookups, and standalone IOC extractions from outside the repository.

---

## 3. GitHub Actions Trusted Publishing Setup (OIDC)

TraceForge uses **PyPI Trusted Publishing**, eliminating the need for long-lived API tokens or passwords stored in GitHub Secrets.

### One-Time PyPI Configuration (Maintainer Checklist):
1. Log into [https://pypi.org](https://pypi.org) with the project owner account.
2. Navigate to **Account Settings → Publishing → Add a new publisher**.
3. Select **GitHub Actions**:
   - **PyPI Project Name**: `traceforge-osint`
   - **Owner**: `paman7647`
   - **Repository Name**: `TraceForge`
   - **Workflow name**: `publish-pypi.yml`
   - **Environment name**: `pypi`
4. Click **Add Publisher**.

---

## 4. Releasing to PyPI

When ready to publish a new official release:

```bash
# 1. Ensure beta branch passes all tests
./scripts/release_check.sh beta

# 2. Merge beta into master
git checkout master
git merge --ff-only beta

# 3. Create a semantic version release tag
git tag -a v1.0.0 -m "Release TraceForge 1.0.0"

# 4. Push tag to GitHub
git push origin master --tags
```

GitHub Actions will automatically trigger `.github/workflows/publish-pypi.yml`:
1. Check out the release tag.
2. Build the wheel and sdist.
3. Validate archives with `twine check`.
4. Publish artifacts to PyPI via OIDC token exchange.

---

## 5. Testing on TestPyPI

To test publication on TestPyPI before a production release:
1. Configure a Trusted Publisher on [https://test.pypi.org](https://test.pypi.org) for environment `testpypi`.
2. Trigger the `.github/workflows/publish-testpypi.yml` workflow via GitHub Actions **Workflow Dispatch** (manual trigger).
3. Verify test installation:
   ```bash
   pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ traceforge-osint
   ```
