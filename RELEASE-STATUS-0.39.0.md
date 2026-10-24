# LLDP-Runner 0.39.0 Release Status

**Release date:** 2026-10-24

**Release state:** Install-layout release complete. Automatic runtime paths
follow the installation that owns them, and the shared, system, and single-user
layouts were each installed and exercised on Ubuntu 26.04.
`./scripts/check.sh` passes end to end.

## Source provenance

- Base release tag: `v0.38.1`
- Base commit: `62d2975b952f19b44034e0ba5da7c59dd79a0abb`
- Site lockfile ignored: `008f4691877f8acbbabf5a92e383bbb8f9ff7830`
- INSTALL permissions note: `1346b1ec3ad173e3c31d00282dad834650d610ae`
- Documentation index repository link:
  `955e7e466dcf276829ffcc20dc53526ed4e5b981`
- Unparseable-seed fix: `c382693d3e5718678ce02d4071f22ca9816f4d09`
- Install layouts: `91dc8d0d8fd5f4b2947b269f912d335c4e979214`
- Review hardening: `d9e2b0f983552c9818a8ecd7162e476211941050`
- No-configuration detection: `99f7cdeac0012fbf4b396bc4621948eca5641b3b`
- Final release tag: `v0.39.0`
- Repository: <https://github.com/robert-patrick-texas/lldp-runner>

## 0.39.0 acceptance contract

### 1. Install layouts — complete

`paths.persistent_root = "auto"` and `paths.scratch_root = "auto"` no longer
pick the first existing `~/lldp-runner`, `/opt/lldp-runner`, or
`/var/lib/lldp-runner` for each user. `lldp_runner.layout` derives both roots
from the primary configuration file as it was named:

```text
/opt/lldp-runner/config.toml    /opt/lldp-runner/var     /dev/shm/lldp-runner
/etc/lldp-runner/config.toml    /var/lib/lldp-runner     /run/lldp-runner
~/lldp-runner/config.toml       ~/lldp-runner/var        $XDG_RUNTIME_DIR/...
```

- Any other `<dir>/config.toml` outside the home directory is a shared install
  with data in `<dir>/var` and its own scratch name, such as
  `/dev/shm/lldp-runner-srv-lab`. Every layout falls back to
  `<persistent_root>/tmp` for scratch.
- Without a configuration file, the first installation present wins:
  `/opt/lldp-runner`, then `/var/lib/lldp-runner` or `/etc/lldp-runner`, then
  `~/lldp-runner`. A present installation whose data directory is missing or
  unwritable is an error, never a fallback to the home directory.
- Data sits in `var/` because discovery write-tests its persistent root; a
  group-writable installation directory would let operators add files that the
  maintainer or the service account later loads.
- Shared and system roots are never created on demand. `/tmp/lldp-runner` and
  `/var/tmp/lldp-runner` are no longer scratch candidates.
- Installations that still keep `runs/` and `outputs/` directly in the
  installation directory keep using them until `var/` exists. Unused history
  beside `var/`, or in `~/lldp-runner`, is reported by `paths`,
  `validate-config`, and `run`.
- `lldp-runner paths [--json]` and `scripts/lrun-paths` show the layout and
  every location without creating anything.

### 2. Launchers and helper scripts — complete

- The `lrun-*` launchers embed no installation path. They select
  `LLDP_RUNNER_CONFIG` from `.private`, then `<project>/config.toml`, then
  `/etc/lldp-runner/config.toml`, then an inherited `LLDP_RUNNER_CONFIG`, so an
  operator's personal setting cannot move a shared launcher onto another
  installation. They start in that file's directory, run through
  `uv run --project`, and run the installed `lldp-runner` when there is no
  `pyproject.toml` beside them.
- `lrun-bundle-diff` reads its source directories from `lrun-paths`.
- `svc-setup.sh` gives the units a uv cache in `/var/cache/lldp-runner/uv`.
  `example.private` sets `UV_NO_CACHE=1` when `~/.cache/uv` cannot be created
  and keeps `umask 0022` for the maintainer.

### 3. Root-run setup safety — complete

An independent review of the layout change found that `shared-setup.sh` ran
`install -d`, `chmod`, and `setfacl` as root inside group-writable runtime
directories, so a planted `var/tmp` symlink could make another directory
group-writable on the next run. It now locks each runtime root to root-only
access while it works below it; refuses symlinks, foreign owners, and
group- or world-writable parents; walks existing content only with `--repair`;
and refuses to create `var/` beside older `runs/` or `outputs/` unless
`--migrate` moves them. It no longer re-owns an existing Python directory.

### 4. Seed initialization fix — complete

An unparseable seed, such as `127.0.0.1`, raised `UnboundLocalError` and
aborted run initialization. It is now recorded as an `invalid_seed` error and
counted as skipped. The new regression test fails on the old code.

### 5. Documentation — complete

`docs/INSTALL.md` describes the three layouts and the folders each one uses,
installs the shared Python as root with `/etc/uv/uv.toml` and `/etc/profile.d`
guard rails, removes group write and world access from the installation,
replaces the ineffective `conf.d` paths step, documents upgrades and the move
into `var/`, and lists the `tzdata` prerequisite. README, CLI, ENVIRONMENT,
ARCHITECTURE, and developer docs follow the new behavior.

### 6. Behavior otherwise unchanged

Collection, worker, retry, credential, classification, topology, output, diff,
watch, and schema logic did not change.

### 7. Release metadata — complete

The application version is `0.39.0`. The constraints manifest moved to
`constraints/release-0.39.0.txt` with identical pins, and the release test now
rejects a leftover `release-0.38.1.txt`.

## Upgrade notes

- **Shared installs with `paths = "auto"`:** data now lives in
  `/opt/lldp-runner/var`. Stop the timers, make the installation root not
  group-writable, and run `scripts/shared-setup.sh --group netops --migrate`
  to move `runs/`, `outputs/`, and `tmp/` into `var/` (INSTALL.md, "Moving
  data into var/"). Until then the old location keeps working with a warning.
- **Explicit `[paths]`:** unaffected.
- **Scheduled installs:** run `svc-remove.sh` and then `svc-setup.sh`. The
  boot-time scratch entry is now `/etc/tmpfiles.d/lldp-runner-scratch.conf`,
  maintained by `shared-setup.sh`.
- **Runs without a configuration file** now use the installation present on
  the host instead of the first existing per-user candidate.

## Machine-readable schema versions

Unchanged from 0.38.1:

- discovery JSON: 8
- topology graph: 2
- diff JSON: 12
- run JSON: 3
- scoreboard JSON: 1

`lldp-runner paths --json` is new operator output, not a versioned contract.

## Dependency and release metadata

```text
cryptography>=50.0     exact pin 50.0.1
gufo-snmp>=0.12.0      exact pin 0.12.0
pysnmp>=7.1.29         exact pin 7.1.29
```

The exact manifest is `constraints/release-0.39.0.txt`.

## Validation results

The repository checks ran on the release tree in a networked Linux
environment, after `uv lock` and `uv sync --all-groups --locked`.

| Check | Exit | Result |
| --- | ---: | --- |
| `./scripts/check.sh` | 0 | Ruff, format, Ty, and pytest all pass |
| `ruff check .` | 0 | all checks passed |
| `ruff format --check .` | 0 | 152 files already formatted |
| `ty check` | 0 | all checks passed (0 diagnostics) |
| Full pytest (`-ra`) | 0 | 1011 passed, 0 skipped, 0 failed |
| Python compilation (`src tests scripts tools`) | 0 | completed |
| Shell syntax (`scripts/*.sh`, `scripts/lrun-*`) | 0 | completed |
| `git diff --check` | 0 | completed |
| CLI `--version`, `version`, and help for all entry points | 0 | `lldp-runner 0.39.0` |
| `uv build` | 0 | `lldp_runner-0.39.0.tar.gz` and `-py3-none-any.whl` |

The installation scenarios ran on the release tree (version 0.39.0) in
throwaway Ubuntu 26.04.1 containers with sudo-rs 0.2.13, Rust coreutils
0.10.0, and systemd as PID 1 where services were involved:

| Scenario | Result |
| --- | --- |
| INSTALL.md walkthrough block, extracted verbatim, run by a sudo admin outside `netops` | all steps completed |
| Scheduled discovery and maintenance services | `Result=success`; uv cache in `/var/cache/lldp-runner/uv` |
| Operators: `lrun-paths`, `lrun-show`, `lrun-get`, `lrun-watch`, `lrun-run`, `lrun-bundle-diff` | all succeeded on `/opt/lldp-runner/var` |
| Account outside `netops` | denied for the installation, `var/`, and scratch |
| Scratch removed as after a reboot | tmpfiles recreated it `root:netops 2770` with ACLs |
| Python patch upgrade 3.13.15 to 3.13.17 by root | environment used 3.13.17 without `uv sync` |
| Operator-planted `var/tmp` symlink, setup re-run with and without `--repair` | refused; target unchanged |
| Legacy install with `runs/` and `outputs/` | refused without `--migrate`; moved with it |
| Upgrade extraction plus ownership commands that skip `var/` | run data owner and mode unchanged |
| System layout, package-style venv on Ubuntu's Python 3.14.4 | discovery and viewer used `/var/lib/lldp-runner` |
| Single-user install by an account without sudo | everything stayed below the home directory |
| No configuration file: `/opt` unprepared, `/opt` prepared, system only, none | error, shared, system, user |

The container discoveries queried an `snmpd` on the container's own address,
so they exercised SNMPv2c collection and outputs but no LLDP or CDP neighbors.
No live network discovery was performed for this release. The PySNMP and Gufo
real-backend tests in the suite ran and passed.

## Tool environment

```text
Ubuntu 26.04.1 LTS (Linux 7.0.0-38-generic)
Python 3.13.15
uv 0.13.5
git 2.53.0
pytest 9.0.2
cryptography 50.0.1
pysnmp 7.1.29
gufo-snmp 0.12.0
ruff 0.16.0
ty 0.0.63
```

## Changed files

Run `git diff --stat v0.38.1 v0.39.0` for the complete list. The release commit
changes:

```text
CHANGELOG.md
README.md
RELEASE-STATUS-0.38.1.md -> RELEASE-STATUS-0.39.0.md
constraints/release-0.38.1.txt -> constraints/release-0.39.0.txt
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

Synchronize `constraints/release-0.39.0.txt`, run `./scripts/check.sh`, and run
`scripts/lrun-paths` as an operator and as the service account. Both must show
the same configuration and data locations. Then make one controlled discovery
run with the same configuration and seeds as a recent 0.38.1 run and compare
them with `lldp-runner diff`. Discovery behavior did not change, so the
comparison should show no topology differences.
