# LLDP-Runner 0.38.0 Release Status

**Release date:** 2026-10-13

**Release state:** Static-analysis release complete. Ruff lint and format gates
pass, the complete deterministic suite passes with every real installed-backend
probe executed, and the distribution builds with the exact release toolchain.
`ty check` still reports diagnostics that predate this release, so
`./scripts/check.sh` exits at its Ty step; see the validation results below.

## Source provenance

- Base release tag: `v0.37.0`
- Base commit: `37efedaa59aa90530c58b40d78a181a2e14de959`
- Lint and format commit: `b773e1f5c523fd6b397d752bc832f37af770f1f8`
- Final release tag: `v0.38.0`
- Repository: <https://github.com/robert-patrick-texas/lldp-runner>

## 0.38.0 acceptance contract

### 1. Ruff lint clean — complete

`ruff check .` reports no findings under the pinned Ruff 0.16.0 and the
unchanged `[tool.ruff]` configuration (104 findings at 0.37.0). Ruff's safe
fixes were applied, and the remaining findings were corrected by hand.
`preflight_snmp_backend` is now an explicit re-export, because `cli.py` and
`coordinator.py` import it from `lldp_runner.snmp`; removing it as unused
would break both.

### 2. Ruff format clean — complete

`ruff format --check .` reports all 150 Python files formatted (91 files
reformatted).

### 3. No new Ty diagnostics — complete

`ty check` reports 249 diagnostics, down from 251 at 0.37.0. The two removed
diagnostics are the undefined `Iterable` annotations in `classify.py` and
`discovery_diff.py`. No diagnostic is new relative to 0.37.0. Nine
constant-name `getattr`/`setattr` calls keep their original form, with `noqa`
reasons, because attribute syntax adds Ty errors there. The 249 pre-existing
diagnostics are outside the scope of this release.

### 4. Behavior unchanged — complete

No collector, worker, retry, credential, topology, output, diff, watch, or
schema logic changed. `CredentialMode` is now a `StrEnum`. Its members are
compared only by identity, and they still equal their string values.

### 5. Release metadata — complete

The application version is `0.38.0`. The constraints manifest moved to
`constraints/release-0.38.0.txt` with identical pins, and the release test now
rejects a leftover `release-0.37.0.txt`. Dependency minimums and exact Linux
pins are unchanged from 0.37.0.

## Machine-readable schema versions

Unchanged from 0.37.0:

- discovery JSON: 8
- topology graph: 2
- diff JSON: 12
- run JSON: 3
- scoreboard JSON: 1

## Dependency and release metadata

```text
cryptography>=50.0     exact pin 50.0.1
gufo-snmp>=0.12.0      exact pin 0.12.0
pysnmp>=7.1.29         exact pin 7.1.29
```

The exact manifest is `constraints/release-0.38.0.txt`.

## Validation results

All checks ran in a networked Linux environment, using a project environment
synchronized from the release constraints.

| Check | Exit | Result |
| --- | ---: | --- |
| `ruff check .` | 0 | all checks passed |
| `ruff format --check .` | 0 | 150 files already formatted |
| `ty check` | 1 | 249 diagnostics, 0 new relative to 0.37.0 |
| Full pytest (`-ra`) | 0 | 961 passed, 0 skipped, 0 failed |
| Python compilation (`src tests scripts tools`) | 0 | completed |
| Shell syntax (`scripts/*.sh`, `scripts/lrun-*`) | 0 | completed |
| `git diff --check` | 0 | completed |
| CLI `--version`, `version`, and help for all entry points | 0 | `lldp-runner 0.38.0` |
| `uv build` | 0 | `lldp_runner-0.38.0.tar.gz` and `-py3-none-any.whl` |
| `./scripts/check.sh` | 1 | Ruff steps pass; stops at the pre-existing Ty diagnostics |

The three real installed-backend probes that 0.37.0 skipped (PySNMP diagnostic,
Gufo adapter, and PySNMP with the release cryptography provider) all ran and
passed. The sdist has the single top-level directory `lldp_runner-0.38.0`.

No live network discovery was performed for this release.

## Tool environment

```text
Ubuntu 26.04.1 LTS (Linux 7.0.0-38-generic)
Python 3.13.15
uv 0.12.18
git 2.53.0
pytest 9.0.2
cryptography 50.0.1
pysnmp 7.1.29
gufo-snmp 0.12.0
ruff 0.16.0
ty 0.0.63
```

## Changed files

The lint and format commit changes 98 Python files under `src/`, `tests/`,
`scripts/`, and `tools/`. Run `git show --stat b773e1f` to list them. The
release commit changes:

```text
CHANGELOG.md
README.md
RELEASE-STATUS-0.37.0.md -> RELEASE-STATUS-0.38.0.md
constraints/release-0.37.0.txt -> constraints/release-0.38.0.txt
docs/CLI.md
docs/INSTALL.md
docs/RUN.md
docs/dev/SCHEMA.md
docs/dev/TESTING.md
pyproject.toml
src/lldp_runner/__init__.py
tests/test_defaults_cli.py
tests/test_release_constraints.py
tests/test_run_manifest.py
tests/test_snmp_pysnmp.py
```

## Operator-side qualification

Synchronize `constraints/release-0.38.0.txt` and run the test suite. Then make
one controlled discovery run with the same configuration and seeds as a recent
0.37.0 run, and compare the two with `lldp-runner diff`. Collection behavior
did not change, so the comparison should show no topology differences.
