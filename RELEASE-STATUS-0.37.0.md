# LLDP-Runner 0.37.0 Release Status

**Release date:** 2026-09-07

**Release state:** Default-backend source implementation complete. Deterministic
compilation, shell, focused, full-suite, CLI, source-boundary, patch, and archive
checks are release requirements. The isolated build container cannot synchronize
the exact release toolchain, so unavailable Ruff, Ty, installed-backend, and
`uv-build==0.12.5` checks are recorded as limitations rather than passes.

## Source provenance

- Exact input archive: `/mnt/data/lldp-runner-0.36.3.tar.gz`
- Verified input SHA-256:
  `45b78cb1c95cfb6e05016ae1f0ecd4feda04b9d63d560a023c0cdeca4867c0b6`
- Exact 0.36.3 baseline Git commit:
  `d47cfcd4419e4d2b24377860c1d74a60a2aa8c0f`
- Exact 0.36.3 baseline Git tree:
  `30c6e0270764d775fb1432cd17cd2d4963922e9b`
- Exact baseline tag: `v0.36.3-exact`
- Final release tag: `v0.37.0`

## 0.37.0 acceptance contract

### 1. PySNMP built-in default — complete

An omitted `snmp.backend` setting now resolves to `pysnmp`. One canonical
`DEFAULT_SNMP_BACKEND` constant supplies the built-in configuration,
operator-facing active-command help, generated-configuration comments, and the
safe default for directly constructed run-manifest provenance.

### 2. Explicit Gufo support and precedence — complete

`gufo` remains a valid explicit backend in TOML, the
`LLDP_RUNNER_SNMP_BACKEND` environment variable, repeatable `--set` expressions,
and the dedicated `--snmp-backend` option. Existing precedence is unchanged:
built-in default, assembled TOML, environment, `--set`, then dedicated CLI.
An explicit Gufo setting always overrides the new implicit PySNMP default at the
appropriate precedence level.

### 3. Immutable run and resume behavior — complete

The selected backend remains fixed before discovery and throughout every worker
and resume. A new run using the implicit default persists `pysnmp` and resumes
under the same implicit default. A durable Gufo run cannot resume when an
omitted setting resolves to PySNMP; the mismatch fails before discovery or run
manifest mutation. Selecting Gufo explicitly permits that Gufo resume.

No automatic fallback, backend conversion, or mixed-backend operation was
introduced.

### 4. Configuration and operator surface — complete

The checked-in example, generated configuration, CLI help, environment guide,
precedence guide, run guide, installation guide, SNMP guide, architecture,
README, testing guide, schema reference, changelog, and examples identify
PySNMP as the default. Migration guidance tells operators to retain or add an
explicit Gufo selection before resuming an existing Gufo run.

### 5. Read-only and credential boundaries — complete

Read-only commands continue to load configuration with credentials disabled and
do not select, import, preflight, or construct either network backend. The
backend default change does not alter shared credential semantics or the
backend-specific Gufo/PySNMP capability maps.

### 6. Backend implementation boundaries — complete

No Gufo adapter, PySNMP adapter, backend factory, cryptography preflight,
warning filter, transport, collector, worker, retry, topology, output, diff, or
watch implementation changed. PySNMP still uses `retries=0`, and LLDP-Runner
remains the sole retry owner. Gufo remains available as the explicit rollback
backend.

### 7. Release metadata and schemas — complete

The application version is `0.37.0`. Dependency minimums and exact Linux pins
are unchanged from 0.36.3. No machine-readable schema changed merely because
the default backend changed.

## Machine-readable schema versions

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

The exact manifest is `constraints/release-0.37.0.txt`.

## Worktree validation results

All long commands write combined output to a named file under `/mnt/data` and
write the actual command status to a separate `.exit` file.

| Check | Exit | Result |
| --- | ---: | --- |
| Focused default/resume/docs tests | 0 | 103 passed |
| Full deterministic pytest | 0 | 958 passed, 3 skipped, 0 failed |
| Python compilation | 0 | completed |
| Documented shell syntax checks | 0 | completed |
| Git whitespace check | 0 | completed |
| CLI version/help/default smoke | 0 | completed |
| Source/default/schema audit | 0 | completed |
| `./scripts/check.sh` | 2 | package-index DNS unavailable |
| exact `uv build` | 2 | `uv-build>=0.12.5` unavailable |

The three deterministic skips are the real installed PySNMP diagnostic probe,
the real installed Gufo adapter probe, and the real installed PySNMP plus
release cryptography-provider probe. Fake-current-PySNMP and Gufo regression
tests remain part of the passing suite.

## Exact worktree commands

```text
python -m compileall -q src tests scripts
find scripts -type f -exec sh -c '<documented shebang syntax loop>' sh {} +
PYTHONPATH=src python -m pytest -q -ra <five focused test modules>
PYTHONPATH=src python -m pytest -q -ra --junitxml=<full result path>
git diff --check
PYTHONPATH=src python -m lldp_runner --version
PYTHONPATH=src python -m lldp_runner --help
PYTHONPATH=src python -m lldp_runner get-neighbors --help
./scripts/check.sh
uv build
```

The full JUnit result reports 961 collected tests, zero failures, zero errors,
and three skips. Therefore 958 tests passed.

## Tool environment

```text
Python 3.13.5
uv 0.10.0
git 2.47.3
pytest 9.0.2
cryptography 46.0.4
pysnmp not installed
gufo-snmp not installed
ruff not installed
ty not installed
uv-build not installed
```

The source declares and constrains cryptography 50.0.1, PySNMP 7.1.29, Gufo
SNMP 0.12.0, Ruff 0.16.0, Ty 0.0.63, and uv-build 0.12.5. The exact packages are
not cached, and package-index DNS is unavailable in this container. The complete
`./scripts/check.sh`, exact distribution build, and real installed-backend
probes must therefore be repeated in the operator's networked Linux environment.

## Changed files

```text
CHANGELOG.md
README.md
RELEASE-STATUS-0.36.3.md -> RELEASE-STATUS-0.37.0.md
configs/example.toml
constraints/release-0.36.3.txt -> constraints/release-0.37.0.txt
docs/ARCHITECTURE.md
docs/CLI.md
docs/ENVIRONMENT.md
docs/ERRORS.md
docs/INSTALL.md
docs/PLAN.md
docs/PRECEDENCE.md
docs/RUN.md
docs/SNMP.md
docs/dev/SCHEMA.md
docs/dev/TESTING.md
pyproject.toml
src/lldp_runner/__init__.py
src/lldp_runner/cli.py
src/lldp_runner/configgen.py
src/lldp_runner/defaults.py
src/lldp_runner/run_manifest.py
tests/test_defaults_cli.py
tests/test_documentation.py
tests/test_release_constraints.py
tests/test_run_manifest.py
tests/test_snmp_backend_selection.py
tests/test_snmp_pysnmp.py
```

## Operator-side qualification

Synchronize `constraints/release-0.37.0.txt`, run `./scripts/check.sh`, build and
inspect the sdist/wheel, and perform a controlled PySNMP pause/resume. Existing
production comparisons already demonstrated complete collection, correct
SNMPv3 remote engine IDs, IPv4/IPv6 operation, stable topology, clean worker
shutdown, and lower elapsed time. Gufo remains available through explicit
selection for rollback or environment-specific comparison.
