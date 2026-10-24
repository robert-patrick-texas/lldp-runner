# LLDP-Runner 0.39.1 Release Status

**Release date:** 2026-10-24

**Release state:** Developer-tool release complete. `tools/flat_graph_compare.py`
measures how far the topology graph is from replacing the flat `hosts[]` view.
Discovery, installation, and output behavior are unchanged from 0.39.0.
`./scripts/check.sh` passes end to end.

## Source provenance

- Base release tag: `v0.39.0`
- Base commit: `73fe37a51bd83a0b317c718f801bd8de0247aa2a`
- Comparison tool: `e81f27114b6043417d117d9875920f882e3f3501`
- Final release tag: `v0.39.1`
- Repository: <https://github.com/robert-patrick-texas/lldp-runner>

## 0.39.1 acceptance contract

### 1. Flat-versus-graph comparison tool — complete

`tools/flat_graph_compare.py` reads one or more `discovery.json` files, or
output directories that contain them, and derives a flat host list from
`topology_graph` alone.

- Logical systems pair with flat hosts through `host_refs`; observed systems
  pair by overlapping names, usable addresses, or MAC addresses. A graph system
  that merges several flat hosts, or a flat host that the graph splits, is
  reported once.
- It compares names, addresses, query targets, display names, classifications,
  and states, and pairs flat neighbor rows with graph relationships by local and
  remote interface and protocol. Rows that only repeat another flat host's edge
  are counted as duplicates.
- It counts host data that only the flat view carries: system details, ICMP
  results, the SNMP credential route, collection metrics, tags, classification
  reasons, first and last seen times, the seed flag, and the classification of
  systems that were never queried. These are gaps, not disagreements.
- It prints text, `--details`, or `--json`, exits 0 when the views agree, 1
  when they disagree, and 2 on unreadable or unsupported input. It reads files
  only and uses only the Python standard library.

On simulated discoveries run through the coordinator's ingestion path, a clean
network agreed completely. A switch reached through two management addresses
stayed two flat hosts, the second named only by its IP, while the graph merged
them into one system and the flat view repeated every neighbor row. No
production `discovery.json` has been compared yet.

### 2. Behavior unchanged

No source module under `src/lldp_runner/` changed apart from the version.
Collection, scheduling, install layouts, setup scripts, outputs, diff, and
schemas are the same as in 0.39.0.

### 3. Release metadata — complete

The application version is `0.39.1`. The constraints manifest moved to
`constraints/release-0.39.1.txt` with identical pins, and the release test now
rejects a leftover `release-0.39.0.txt`.

## Machine-readable schema versions

Unchanged from 0.39.0:

- discovery JSON: 8
- topology graph: 2
- diff JSON: 12
- run JSON: 3
- scoreboard JSON: 1

The comparison tool's `--json` output carries its own `report_version` (1) and
is not a release contract.

## Dependency and release metadata

```text
cryptography>=50.0     exact pin 50.0.1
gufo-snmp>=0.12.0      exact pin 0.12.0
pysnmp>=7.1.29         exact pin 7.1.29
```

The exact manifest is `constraints/release-0.39.1.txt`.

## Validation results

All checks ran on the release tree in a networked Linux environment, after
`uv lock` and `uv sync --all-groups --locked`.

| Check | Exit | Result |
| --- | ---: | --- |
| `./scripts/check.sh` | 0 | Ruff, format, Ty, and pytest all pass |
| `ruff check .` | 0 | all checks passed |
| `ruff format --check .` | 0 | 154 files already formatted |
| `ty check` | 0 | all checks passed (0 diagnostics) |
| Full pytest (`-ra`) | 0 | 1024 passed, 0 skipped, 0 failed |
| Python compilation (`src tests scripts tools`) | 0 | completed |
| Shell syntax (`scripts/*.sh`, `scripts/lrun-*`) | 0 | completed |
| `git diff --check` | 0 | completed |
| CLI `--version` and help for all entry points | 0 | `lldp-runner 0.39.1` |
| `tools/flat_graph_compare.py --help` | 0 | completed |
| `uv build` | 0 | `lldp_runner-0.39.1.tar.gz` and `-py3-none-any.whl` |

The Ubuntu 26.04 installation scenarios recorded for 0.39.0 were not repeated:
no installation, launcher, setup-script, or application code changed. No live
network discovery was performed for this release.

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

The comparison-tool commit adds `tools/flat_graph_compare.py` and
`tests/test_flat_graph_compare.py`, and updates `CHANGELOG.md`,
`docs/ROADMAP.md`, and `docs/dev/CLI-REFERENCE.md`. The release commit
changes:

```text
CHANGELOG.md
README.md
RELEASE-STATUS-0.39.0.md -> RELEASE-STATUS-0.39.1.md
constraints/release-0.39.0.txt -> constraints/release-0.39.1.txt
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

No action is needed beyond the usual `uv lock` and
`uv sync --all-groups --locked` with `constraints/release-0.39.1.txt`. To
measure the two views on a real run, execute
`python3 tools/flat_graph_compare.py /opt/lldp-runner/var/outputs/latest --details`.
