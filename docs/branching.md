# Branching Model & Release Lifecycle

TraceForge uses a streamlined **two-branch Git model** designed for predictability, defensiveness, and continuous stability:

```text
                     master  (Stable Public Releases)
                       ▲
                       │  Release PR (Validated & Tagged)
                       │
                      beta   (Active Development & Release Candidates)
                   ▲   ▲   ▲
                   │   │   │  Pull Requests
              feature fix docs  (Short-Lived Working Branches)
```

| Branch | Role | Mutability | Release Policy |
|---|---|---|---|
| **`master`** | **Stable Public Release** | Protected (No direct commits) | Merged strictly from `beta` via reviewed Release PRs |
| **`beta`** | **Active Integration & RC** | Protected (CI & review required) | Merged from temporary `feature/*`, `fix/*`, `docs/*` branches |

---

## 1. Branch Roles & Rules

### `master` (Stable)
- Contains exclusively **tested, production-ready, release-tagged code**.
- Every commit on `master` corresponds to a semantic release tag (e.g. `v1.0.0`, `v1.0.1`, `v1.1.0`).
- **Zero direct pushes**: Changes enter `master` only via a reviewed and CI-verified pull request from `beta`.

### `beta` (Development & Integration)
- The default target branch for all feature additions, platform improvements, bug fixes, and documentation updates.
- Remains stable and runnable at all times (not an unstable dumping ground).
- Receives release candidate tags (e.g. `v1.1.0-beta.1`) when staging major features before merging to `master`.

---

## 2. Working Branches (Short-Lived)

All active development occurs on short-lived branches created from `beta`:

| Branch Prefix | Purpose | Example | Target |
|---|---|---|---|
| `feature/` | New tools, investigation capabilities, or export formats | `feature/termux-storage` | `beta` |
| `fix/` | Bug fixes, platform compatibility patches | `fix/catalog-tsv-parser` | `beta` |
| `docs/` | Documentation improvements, legal guides | `docs/responsible-use` | `beta` |
| `security/` | Defensive hardening and vulnerability mitigations | `security/path-traversal-guard` | `beta` |
| `hotfix/` | Urgent production fixes targeting `master` directly | `hotfix/1.0.1-export-crash` | `master` + backport |

> [!NOTE]
> Delete working branches immediately after their pull request is merged to keep the repository clean.

---

## 3. Pull Request (PR) Workflow

```text
Fork or Clone
     ↓
git checkout beta
git pull origin beta
git checkout -b feature/<name>
     ↓
Implement & Verify Functionality
     ↓
traceforge doctor
     ↓
Open Pull Request targeting 'beta'
     ↓
Automated CI Passes + Maintainer Review
     ↓
Squash / Rebase Merge into 'beta'
```

### Pull Request Rules:
1. **Target `beta`**: Normal PRs must NEVER target `master`.
2. **Verify Functionality**: Every new feature or bug fix must be tested and verified with `traceforge doctor` and catalog audits.
3. **Update Documentation & Changelog**: Document user-facing changes under `## [Unreleased]` in the repository changelog.
4. **Zero Secret Leakage**: Ensure no credentials, test tokens, or private case data exist in commits.

---

## 4. Release Promotion: `beta` ➔ `master`

When `beta` has accumulated validated features or fixes for a release:

1. **Pre-Release Freeze**: Ensure `beta` passes all validation checks on macOS, Linux, and Termux:

   ```bash
   ./scripts/release_check.sh beta
   ```
2. **Version Bump**: Update canonical `VERSION` and `pyproject.toml`:
   ```bash
   python3 scripts/bump_version.py minor  # or patch / major
   ```
3. **Changelog Finalization**: Move items from `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` in `CHANGELOG.md` and update `RELEASE_NOTES.md`.
4. **Open Release PR**: Create PR from `beta` to `master` titled `Release vX.Y.Z`.
5. **Merge & Tag**:
   ```bash
   git checkout master
   git merge --ff-only beta
   git tag -a v1.1.0 -m "Release v1.1.0"
   git push origin master --tags
   ```

---

## 5. Hotfix & Security Emergency Protocol

If a critical vulnerability or blocker affects the live `master` release:

```text
 master ➔ hotfix/<version> ➔ test ➔ PR to master ➔ tag patch release
                                           │
                                           ▼
                                 Backport merge to beta
```

1. Create a `hotfix/` branch from `master`.
2. Apply the fix and write a regression test.
3. Merge into `master` and tag the patch release (e.g. `v1.0.1`).
4. **Immediately backport the commit to `beta`** (`git checkout beta && git merge master` or `git cherry-pick`) to prevent regressions in future releases.
