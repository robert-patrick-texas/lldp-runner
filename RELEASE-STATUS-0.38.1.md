# LLDP-Runner 0.38.1 Release Status

**Release date:** 2026-10-13

**Release state:** Type-checking release complete. `./scripts/check.sh` passes
end to end for the first time: Ruff lint, Ruff format, Ty, and the complete
deterministic suite. The distribution builds with the exact release toolchain.

## Source provenance

- Base release tag: `v0.38.0`
- Base commit: `2edb68c637563226210b240dd4143c1e2401a0a9`
- Ty commit: `86469e713bc0db8dbe06254c59fd210bbfbe0b45`
- Script-mode test commit: `75e508e8f3ce02f5b8eeb8b5823ac69ec7ecbc49`
- Final release tag: `v0.38.1`
- Repository: <https://github.com/robert-patrick-texas/lldp-runner>

## 0.38.1 acceptance contract

### 1. Ty clean — complete

`ty check` reports no diagnostics under the pinned Ty 0.0.63 (251 at 0.38.0),
including no unused-suppression warnings.

- Annotations that disagreed with the code were corrected:
  `ArgumentParser.error` returns `NoReturn`, `Coordinator.workers` holds
  `BaseProcess` objects, the Gufo session argument builders return
  `dict[str, Any]`, and retry parameters use the new `RetryKind` and `RetryPool`
  aliases.
- Narrowing Ty could not follow was restructured without changing behavior:
  values are bound to locals before `isinstance` checks, and two comprehensions
  use assignment expressions.
- The storage roots and `discovery.workers` hold the `"auto"` sentinel until
  `load_config()` resolves it, so their declared types stay unions. Use sites
  that only run after resolution cast to the resolved type.
- Suppressions use rule-specific `# ty: ignore[rule]` comments: 22 in source
  and scripts, 21 in tests. Sixteen replace mypy-style `# type: ignore[code]`
  comments that Ty does not honor. The rest mark deliberate dynamic code
  (`int()` on SNMP or JSON values inside `try/except TypeError`, and
  attributes set on exceptions) and test doubles.

### 2. Tests strengthened, not relaxed — complete

The suite gained `is not None` and `isinstance` assertions where results are
used, including checks that resolved storage roots are `Path` objects. No
assertion was removed or weakened. Method replacement in
`test_seed_order_sampling.py` now uses `monkeypatch.setattr`.

### 3. Umask-independent script-mode tests — complete

`test_operator_scripts.py` required the SNMP diagnostics to be exactly `0755`
and their notes `0644`. Git records only the executable bit. Under the shared
`umask 0002` documented in `docs/INSTALL.md`, a fresh clone produced `0775`
files and both tests failed. The tests now check that the diagnostics are
executable, that the notes are not, and that the source archive preserves each
file's actual mode. They pass under both umasks and still fail when a
diagnostic loses its executable bit or the notes gain one.

### 4. Behavior unchanged — complete

No collector, worker, retry, credential, topology, output, diff, watch, or
schema logic changed. In the diagnostic scripts, IPv6 scope IDs are now read
when `len(sockaddr) == 4` instead of `>= 4`. IPv6 `getaddrinfo` results are
always 4-tuples, so the outcome is the same.

### 5. Release metadata — complete

The application version is `0.38.1`. The constraints manifest moved to
`constraints/release-0.38.1.txt` with identical pins, and the release test now
rejects a leftover `release-0.38.0.txt`. Dependency minimums and exact Linux
pins are unchanged.

## Machine-readable schema versions

Unchanged from 0.38.0:

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

The exact manifest is `constraints/release-0.38.1.txt`.

## Validation results

All checks ran in a networked Linux environment, using a project environment
synchronized from the release constraints.

| Check | Exit | Result |
| --- | ---: | --- |
| `./scripts/check.sh` | 0 | Ruff, format, Ty, and pytest all pass |
| `ruff check .` | 0 | all checks passed |
| `ruff format --check .` | 0 | all files already formatted |
| `ty check` | 0 | all checks passed (0 diagnostics) |
| Full pytest (`-ra`) | 0 | 961 passed, 0 skipped, 0 failed |
| Python compilation (`src tests scripts tools`) | 0 | completed |
| Shell syntax (`scripts/*.sh`, `scripts/lrun-*`) | 0 | completed |
| `git diff --check` | 0 | completed |
| CLI `--version`, `version`, and help for all entry points | 0 | `lldp-runner 0.38.1` |
| `uv build` | 0 | `lldp_runner-0.38.1.tar.gz` and `-py3-none-any.whl` |

The three real installed-backend probes (PySNMP diagnostic, Gufo adapter, and
PySNMP with the release cryptography provider) ran and passed.

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

The Ty commit changes 44 files across `src/`, `tests/`, `scripts/`, and
`tools/`. Run `git show --stat 86469e7` to list them. The script-mode test
commit changes `tests/test_operator_scripts.py`. The release commit changes:

```text
CHANGELOG.md
README.md
RELEASE-STATUS-0.38.0.md -> RELEASE-STATUS-0.38.1.md
constraints/release-0.38.0.txt -> constraints/release-0.38.1.txt
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

Synchronize `constraints/release-0.38.1.txt` and run `./scripts/check.sh`, which
should now pass on any checkout. Then make one controlled discovery run with the
same configuration and seeds as a recent 0.37.0 or 0.38.0 run, and compare them
with `lldp-runner diff`. Discovery behavior did not change, so the comparison
should show no topology differences.
