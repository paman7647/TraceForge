## What changed?

Brief summary of the changes introduced in this pull request.

## Why?

Explain the motivation, linked issue, or investigative workflow improvement.

## Branch Target

- [ ] `beta` (Standard development target for all features, bug fixes, and improvements)
- [ ] `master` (Release PR only — promoting validated beta release to stable)

## Testing & Quality Checklist

- [ ] All automated tests pass (`python3 -m unittest discover -s tests` / `./tests/test.sh`)
- [ ] Pre-flight release check passes (`./scripts/release_check.sh beta`)
- [ ] Shell syntax verified (`bash -n` and `shellcheck` where applicable)
- [ ] Documentation updated in `docs/` or `README.md`
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` (if user-facing)
- [ ] Zero secrets, private tokens, passwords, or personal test artifacts committed
- [ ] Workspace remains clean of runtime artifacts

## Platform Compatibility Tested

- [ ] macOS (Apple Silicon / Intel)
- [ ] Linux (Ubuntu / Debian / Kali)
- [ ] Termux / Android
- [ ] Cross-Platform (Pure Python / Compiled Go)

## Additional Notes
