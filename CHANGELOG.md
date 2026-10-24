# Changelog

## Unreleased

- Automatic runtime paths now follow the selected configuration file's
  directory instead of the first existing `~/lldp-runner`, `/opt/lldp-runner`,
  or `/var/lib/lldp-runner`, so every operator of one installation uses the
  same data. The shared layout (`/opt/lldp-runner/config.toml`) keeps run state
  and outputs in `/opt/lldp-runner/var` and scratch data in
  `/dev/shm/lldp-runner`, falling back to `/opt/lldp-runner/var/tmp`. The
  system layout (`/etc/lldp-runner/config.toml`) uses `/var/lib/lldp-runner`
  and `/run/lldp-runner`. A configuration below the home directory uses
  `<dir>/var` and `$XDG_RUNTIME_DIR/lldp-runner`; a file directly in the home
  directory uses `~/lldp-runner/var`. Without a configuration file the first
  present installation wins: `/opt/lldp-runner`, then `/var/lib/lldp-runner`
  or `/etc/lldp-runner`, then `~/lldp-runner`. The layout follows the
  configuration path as named, without resolving symbolic links. Other
  installations get their own scratch name, such as
  `/dev/shm/lldp-runner-srv-lab`. `/tmp/lldp-runner` and `/var/tmp/lldp-runner`
  are no longer scratch candidates, shared and system roots are no longer
  created on demand, and without a configuration, installation, or usable
  home directory `auto` is an error instead of the working directory.
- Installations that still keep `runs/` and `outputs/` directly in the
  installation directory keep using them until `<dir>/var` exists. `paths`,
  `validate-config`, and `run` warn about it, and about such directories left
  beside an existing `var/` or in `~/lldp-runner` for another user
  configuration. `shared-setup.sh --migrate` moves them into `var/`.
- Add `lldp-runner paths [--json]` and `scripts/lrun-paths`, which show the
  install layout, persistent, runs, outputs, and scratch locations without
  creating anything. `validate-config` also prints the resolved roots.
- The `lrun-*` launchers no longer embed `/opt/lldp-runner`. They select
  `LLDP_RUNNER_CONFIG`, `<project>/config.toml`, or
  `/etc/lldp-runner/config.toml`, start in that file's directory so
  `seed.list` resolves beside it, and run through `uv run --project`. Without a
  `pyproject.toml` beside them they run the installed `lldp-runner` from
  `PATH`. `lrun-explain` now uses the deployed configuration as well. An
  `LLDP_RUNNER_CONFIG` inherited from the caller's environment applies only
  when the installation has no configuration, and `~` in it is expanded.
- `lrun-bundle-diff` reads the outputs and runs directories from `lrun-paths`
  unless `LLDP_RUNNER_BUNDLE_ROOT`, `LLDP_RUNNER_OUTPUTS_DIR`, or
  `LLDP_RUNNER_RUNS_DIR` is set.
- `shared-setup.sh` gains `--layout shared|system`, `--project-root`,
  `--migrate`, `--repair`, and `--print-paths`. It creates `var/{runs,outputs,
  tmp}` and the scratch root as `root:GROUP` mode `2770` without access for
  other users, and installs `/etc/tmpfiles.d/lldp-runner-scratch.conf` so the
  scratch root is recreated at boot. As root it no longer follows symlinks in
  the group-writable directories: each runtime root is locked while its
  entries are handled, symlinks and unsafe parents are refused, and existing
  content is only walked with `--repair`. It refuses to create `var/` beside
  older `runs/` or `outputs/` unless `--migrate` moves them. It no longer
  changes the owner of an existing Python directory; previously it re-owned
  `/opt/shared/python` to root, which broke the maintainer's later
  `uv python install`.
- `svc-setup.sh` defaults to the shared layout, requires the runtime roots from
  `shared-setup.sh`, no longer writes its own tmpfiles entry, and gives the
  units a uv cache in `/var/cache/lldp-runner/uv`. Without one, uv failed with
  "Failed to initialize cache" for a service account whose home is
  `/nonexistent`. `scripts/example.private` sets `UV_NO_CACHE=1` for the same
  case outside systemd, and applies `umask 0002` only to accounts other than
  the maintainer, so a synchronizing maintainer run cannot leave `.venv`
  group-writable.
- INSTALL.md covers the three layouts, installs the shared Python as root,
  adds `/etc/uv/uv.toml` and `/etc/profile.d` guard rails that keep uv-managed
  Python out of home directories, removes world access from the installation,
  and drops the `conf.d` paths step, which the primary `config.toml` silently
  overrode. It also lists the `tzdata` package: without the operating
  system's time zone database, every command failed at startup with
  `ZoneInfoNotFoundError`.
- Fix discovery aborting with `UnboundLocalError` when a seed cannot be parsed,
  for example a loopback address. The seed is recorded as an `invalid_seed`
  error and initialization continues.
- Link the source repository from the `index.html` that
  `scripts/md-to-html.sh` generates. The URL comes from the new
  `[project.urls]` `Repository` entry in `pyproject.toml`, which also adds a
  `Project-URL` to the package metadata. `--repo-url URL` or `REPO_URL`
  overrides it, an empty value omits the link, and anything other than an
  `http://` or `https://` URL is rejected.

## 0.38.1 - 2026-10-13

- Bring `ty check` to zero diagnostics under the pinned Ty 0.0.63 (251 at
  0.38.0), so `./scripts/check.sh` passes end to end. Correct annotations
  that disagreed with the code: `ArgumentParser.error` returns `NoReturn`,
  `Coordinator.workers` holds `BaseProcess` objects, and the Gufo session
  argument builders return `dict[str, Any]`.
- Add `RetryKind` and `RetryPool` type aliases in `models.py` and use them
  for retry parameters in the adaptive SNMP layer.
- Replace mypy-style `# type: ignore[code]` comments, which Ty does not
  honor, with rule-specific `# ty: ignore[rule]` comments, and mark the
  remaining deliberate dynamic conversions the same way.
- Check only the executable bit of the shipped SNMP diagnostics and their
  notes in `test_operator_scripts.py`. Git records nothing else, and the
  previous exact-mode check failed on checkouts made under the documented
  shared `umask 0002`.
- Keep dependency versions, collection, topology, output, diff, watch,
  credential, retry, and schema behavior unchanged.

## 0.38.0 - 2026-10-13

- Bring the source tree to a clean `ruff check` and `ruff format --check`
  under the pinned Ruff 0.16.0 and the existing `pyproject.toml` rules.
  Reformat 91 files and apply import sorting, `collections.abc` imports, and
  unquoted annotations.
- Import `Iterable` in `classify.py` and `discovery_diff.py`, where it was
  referenced only in annotations without being imported. Postponed annotation
  evaluation prevented a runtime failure, but type checkers and annotation
  introspection reported an undefined name.
- Make `CredentialMode` a `StrEnum`. Members still equal their string values
  and are compared by identity throughout; only `str()` of a member now
  returns its value.
- Declare `preflight_snmp_backend` an explicit re-export of
  `lldp_runner.snmp`. Keep nine constant-name `getattr`/`setattr` calls,
  with documented `noqa` reasons, where attribute syntax would introduce Ty
  errors for lazily imported cryptography submodules and dynamic exception
  attributes.
- Keep dependency versions, collection, topology, output, diff, watch,
  credential, retry, and schema behavior unchanged.

## 0.37.0 - 2026-09-07

- Change the built-in `snmp.backend` default from `gufo` to `pysnmp` after
  repeated production runs demonstrated complete collection, stable topology,
  correct SNMPv3 and IPv6 behavior, and lower elapsed time. Update generated
  configuration, CLI help, operator examples, installation guidance, and
  architecture documentation while retaining Gufo as an explicitly selectable
  backend.
- Preserve the immutable one-backend-per-run contract. Existing explicit Gufo
  configurations continue to select Gufo. An existing Gufo run must still
  resolve to `gufo` when resumed; an omitted setting now resolves to PySNMP and
  is rejected if it conflicts with durable run metadata. Do not add automatic
  fallback or mixed-backend operation.
- Add regression coverage for the new implicit default, explicit Gufo override,
  configuration and CLI precedence, generated configuration, worker binding,
  PySNMP default resume, Gufo migration rejection and explicit resume, and
  credential-free read-only command boundaries. Keep dependency versions,
  credential algorithms, retry ownership, collection, topology, output, diff,
  watch, and schema behavior unchanged.

## 0.36.3 - 2026-09-06

- Add PySNMP-only `auth_protocol = "sha256"`, mapped exactly to
  `USM_AUTH_HMAC192_SHA256`, without changing Gufo's SHA-1/MD5 capability set.
- Add PySNMP-only `priv_protocol = "aes256"` for the common Reeder key
  localization (`USM_PRIV_CFB256_AES`, also called AES-256-Cisco) and
  `aes256-blumenthal` for `USM_PRIV_CFB256_AES_BLUMENTHAL`. Keep the methods
  explicit and non-interchangeable: do not add an `aes256-reeder` alias,
  negotiate a method, downgrade a cipher, or fall back between algorithms.
  Gufo remains limited to AES-128/DES and rejects PySNMP-only values during
  configuration validation before secret resolution or network activity.
- Extend the PySNMP local capability preflight, exact upstream CFB-warning
  filter scope, standalone diagnostic, generated configuration, documentation,
  and deterministic tests for SHA-256 and both AES-256 mappings. AES-256 probes
  use a 32-byte key and 16-byte CFB IV. Keep dependencies, retry ownership,
  backend selection, discovery/topology/output behavior, and all
  machine-readable schema versions unchanged.

## 0.36.2 - 2026-09-06

- Move LLDP-Runner's local PySNMP AES capability probe to
  `cryptography.hazmat.decrepit.ciphers.modes.CFB`, eliminating the
  `CryptographyDeprecationWarning` emitted by the probe under cryptography
  50.0.1. SNMPv2c-only invocations continue to skip cryptography capability
  work entirely.
- Temporarily suppress only PySNMP 7.1.29's known AES-CFB namespace warning
  during SNMPv3 AES use. The process filter requires the exact
  `CryptographyDeprecationWarning` category, complete warning text, and
  `pysnmp.proto.secmod.rfc3826.priv.aes` origin; changed messages, other
  modules, other categories, and all unrelated warnings remain visible. The
  filter is not installed for SNMPv2c or DES routes.
- Apply the same corrected probe and narrow warning behavior to the standalone
  `pysnmp-snmp-diag.py` utility, and add deterministic regression tests for the
  import path, route scope, and exact warning-filter boundary. Keep dependency
  versions, Gufo behavior, retry ownership, discovery/topology/output behavior,
  and all machine-readable schema versions unchanged.

## 0.36.1 - 2026-09-06

- Add `cryptography>=50.0` as a runtime dependency for PySNMP SNMPv3 authPriv
  and pin `cryptography==50.0.1` in the exact Linux release constraints. This
  prevents a synchronized installation from reaching production without the
  cipher provider required by PySNMP privacy protocols.
- Preflight PySNMP authPriv locally after immutable backend/resume validation
  and before manifests, workers, seed resolution, or network requests. The
  check derives only AES-128/DES protocol names from profile-reachable and
  direct seed credentials, never resolves secrets, constructively exercises
  fixed non-secret cipher operations, and consumes no SNMP retry budget. Gufo
  and PySNMP SNMPv2c runs skip the probe.
- Normalize PySNMP's `Ciphering services not available` exception or response
  indication as the sanitized `snmp_backend_capability` category rather than a
  remote authentication or transport failure. It is not timeout-retried, while
  the existing ordered credential-route fallback behavior remains unchanged.
- Extend `pysnmp-snmp-diag.py` with the same fail-fast local privacy preflight,
  installed cryptography version reporting, and explicit
  `local_crypto_capability` failure classification.
- Add deterministic tests for startup ordering, direct credentials, secret-free
  protocol discovery, both privacy mappings, missing/old/unusable providers,
  runtime normalization, zero retry consumption, diagnostics, and the real
  installed provider when release dependencies are available. Keep Gufo,
  discovery, topology, output, diff, watch, and all schema versions unchanged.

## 0.36.0 - 2026-09-06

- Add explicit `gufo` and `pysnmp` discovery backends. Gufo remains the
  default. Configuration, `LLDP_RUNNER_SNMP_BACKEND`, `--set`, and the
  dedicated `--snmp-backend` option follow the ordinary documented precedence
  model.
- Bind exactly one backend before discovery initialization, copy that immutable
  selection into workers, and persist its name and installed package version in
  SQLite state, `run.json`, per-invocation provenance, console diagnostics, and
  `activity.log`. Resumes reject a missing or different persisted backend before
  discovery or run-manifest mutation. There is no automatic fallback or
  mixed-backend operation.
- Add the PySNMP 7.1 asyncio adapter using the credential mappings already
  validated by `scripts/pysnmp-snmp-diag.py`. Every IPv4/IPv6 transport target
  uses `retries=0`, leaving all retries and retry budgets under LLDP-Runner's
  existing adaptive layer.
- Normalize PySNMP GET, GET-MANY, and WALK varbinds to the existing collector
  contract; normalize timeout, transport, authentication, authorization,
  engine, PDU, malformed-response, and cancellation behavior without retaining
  credential values in diagnostics.
- Close each PySNMP `SnmpEngine` dispatcher deterministically after success,
  partial setup, request/open failure, and cancellation. SNMPv3 device identity
  uses only the response security context's remote `securityEngineId`, never the
  local manager engine ID.
- Validate configured and direct-seed SNMPv3 protocol names against the selected
  backend's explicit capability map, and reject unsupported credential versions
  or algorithms at each adapter boundary instead of silently substituting a
  different mapping.
- Keep stored-data and local-maintenance commands outside the runtime SNMP
  selection and factory lifecycle as well as outside credential parsing; these
  read-only paths do not import or construct either transport adapter.
- Keep Gufo behavior, collection/retry/topology/output/diff/watch behavior, and
  machine-readable schema versions unchanged. Pin the validated Linux release
  set in `constraints/release-0.36.0.txt`.

## 0.35.6 - 2026-09-05

- Add PySNMP 7.1.29 to the project dependency set and exact Linux release
  constraints so operators can validate the maintained PySNMP asyncio API in
  the same environment as LLDP-Runner.
- Add executable `scripts/pysnmp-snmp-diag.py`, a direct standalone diagnostic
  for IPv4/IPv6 literals and DNS names, SNMPv2c and the existing SNMPv3
  authPriv algorithms, repeated numeric-OID GETs, phase-specific failures,
  credential redaction, zero PySNMP transport retries, and deterministic
  dispatcher cleanup.
- Keep Gufo SNMP as the only LLDP-Runner discovery backend in this release.
  The existing `snmp.backend` setting remains restricted to `gufo`; the new
  dependency and diagnostic do not add a PySNMP backend value, automatic
  fallback, mixed-backend runs, or changes to collection and retry behavior.
- Keep output fields, durable state, identity, topology, diff behavior, and all
  machine-readable schema versions unchanged.

## 0.35.5 - 2026-09-05

- Remove the temporary compatibility-only custom fixed-field selectors
  `unknown-devices.manufacturer` and `unknown-devices.model`. Configurations
  that still name either field now fail early with an unknown-field error; use
  `json.host.system.manufacturer` and `json.host.system.model` instead.
- Make the `unknown-devices` custom fixed-field namespace exactly match the
  fixed `unknown-devices.csv` schema and remove the hidden manufacturer/model
  values from its fixed projection context. This is an intentional breaking
  configuration change.
- Keep the fixed CSV schema, canonical JSON fields, preferred-name fallback,
  collection, identity, topology, retry, dependency, and machine-readable JSON
  schema behavior unchanged.

## 0.35.4 - 2026-09-05

- Remove `manufacturer` and `model` from the fixed `unknown-devices.csv`
  schema because live unknown-neighbor rows do not populate them. Existing
  custom fixed-field selectors remain supported for compatibility, and
  canonical JSON paths remain available for explicit system-value projection.
- Extend canonical output naming so an `unknown` host with blank inbound names
  and descriptions can use one unambiguous MAC-address-typed chassis ID as its
  lowercase colon-separated `preferred_name`. Existing name aliases and other
  higher-value presentation evidence continue to win; mixed, malformed, or
  conflicting chassis evidence does not guess.
- Keep persisted aliases, resolver/graph identity, raw protocol evidence,
  collection behavior, retry budgets, dependencies, and machine-readable JSON
  schemas unchanged.

## 0.35.3 - 2026-09-05

- Replace customer- and operation-derived hostnames, DNS suffixes, management
  addresses, compact run IDs, asset labels, credential examples, serials,
  chassis values, and MAC-derived endpoint identifiers across documentation,
  examples, comments, and regression fixtures. Use role-based names, reserved
  example domains, TEST-NET/benchmark IPv4 space, `2001:db8::/32`, and clearly
  synthetic hardware identity values while preserving linked topology evidence.
- Add contributor guidance for sanitizing production-shaped fixtures. Add a
  repository-wide regression that stores removed-value fingerprints rather
  than readable identifiers, detects alternate MAC forms and compact run IDs,
  and restricts operator documentation to approved example DNS/IP namespaces.
- Keep discovery, collection, scheduling, retry, identity, graph, diff, output,
  dependency, and machine-readable schema behavior unchanged.

## 0.35.2 - 2026-09-05

- Rename the executable two-run review helper from
  `scripts/lrun-prepare-bundle` to `scripts/lrun-bundle-diff`. No compatibility
  launcher is retained. Automatic run selection, explicit A/B ordering, diff
  generation, coherent SQLite backup, environment variables, and archive
  layout are unchanged; current operator and contributor references use the new
  name.
- Add [`docs/dev/FLOW-DIAGRAMS.md`](docs/dev/FLOW-DIAGRAMS.md) with
  source-maintained Mermaid diagrams for collection, compatibility identity
  resolution, and graph rematerialization. The reference names current module
  and function boundaries, persistence points, failure paths, fallback rules,
  append-only decision lineage, and graph-publication transaction behavior.
- Link the diagrams from contributor entry points, add diagram maintenance to
  contribution review, mark the ROADMAP objective complete, and add release
  regressions for diagram anchors and the renamed script surface.

## 0.35.1 - 2026-09-05

- Move active `scoreboard.txt` and `scoreboard.json` publication to the stable
  `<scratch_root>/scoreboard/` directory. Successful completed runs archive the
  exact terminal snapshots below persistent `runs/<run-id>/`; retained per-run
  scratch receives another copy when automatic scratch cleanup is disabled.
  The live scoreboard remains after completion, and `clean` removes its reserved
  directory as part of scratch maintenance.
- Refine Watch spacing and source-error placement. Wide terminals use doubled
  gaps between Started, Elapsed, and Plan; roomy terminals add a blank row
  between the title and summary. Scoreboard-source errors appear below the
  worker table and above the footer with surrounding blank rows and bright-red
  color when enabled.
- Remove durable `runs/<run-id>/run.json.draft` after a successful completed run
  has published final provenance and closed coordinator resources.
- Expand every unfinished roadmap item with operator-oriented remaining work,
  operational benefit, and estimated implementation/validation effort.

## 0.35.0 - 2026-09-05

- Publish an atomic relative `latest` symlink below the persistent `runs/`
  directory after every successful `COMPLETED` or `COMPLETED_LIMIT` run. The
  alias is advertised only after SQLite state and configured activity logging
  are closed; startup now preflights both persistent `latest` locations, resume
  ignores the convenience link, and historical cleanup protects its target.
- Add `[paths].clean_scratch_when_completed`, enabled by default. After durable
  run/output publication and resource closure, a successful run removes its
  entire `<scratch_root>/<run-id>/` tree and removes `<scratch_root>/current`
  only when that link still selects the completed run. Paused,
  limited-for-resume, interrupted, and failed runs retain scratch data, and
  overlap guards prevent accidental deletion of persistent state or output.
- Improve canonical host `preferred_name` presentation shared by
  `discovery.json`, fixed CSVs, and custom CSVs. Recognized trailing hardware
  serial decorations such as `name(SERIAL)` are omitted from the display name;
  placeholder-only inbound observations can use one unambiguous locally
  assigned chassis string for `unknown`, or one typed canonical MAC chassis
  value for `null`/`not advertised`. Raw names, descriptions, chassis evidence,
  and identity correlation remain unchanged.

## 0.34.1 - 2026-09-03

- Refine Watch vertical spacing. A displayed `Started ... Elapsed ...` row now
  has a blank row after it. When the ordinary layout would still leave more
  than ten blank rows immediately above the footer, Watch adds a second row
  there and a second blank row on both sides of the aggregate worker summary.
- Render the title's `Run ID = <runid>` segment with the same muted semantic
  color used by footer text in full, compact, heatmap, and summary layouts.
- Add [`docs/dev/SCHEMA.md`](docs/dev/SCHEMA.md) as the current schema quick
  reference, test its version values against the implementation constants, and
  document a concise changelog policy that records schema numbers only when a
  schema changes.

## 0.34.0 - 2026-09-02

- This display-only minor release does not change discovery scheduling, SNMP
  collection, CDP/LLDP parsing, retry budgets, identity, graph semantics, or
  diff classification.
- Replace the Watch dashboard's two-line upper-left header with one justified
  four-section title row containing application name/version, Run ID, STATE,
  and update age. Reserve a blank top row plus one blank terminal cell at both
  side edges in full, compact, heatmap, and summary layouts.
- Widen and stabilize the Watch metric grid. Metric columns now depend only on
  terminal geometry, use substantially more horizontal space, and keep
  independent count/delta fields so digit growth does not move following
  columns. Roomy terminals insert a blank row between metric rows.
- Center the aggregate `Workers N: BUSY ... IDLE ... DEAD ...` line separately
  and place a blank row above and below whenever terminal height permits. Keep
  worker-cell text, density, ordering, fixed field budgets, and partial-row
  alignment unchanged.
- Make the shared `get-neighbors` and `show-neighbors` table planner expand the
  rightmost `Mgmt` column to the complete valid IPv6 address. If necessary the
  plain-text table may exceed the detected terminal width rather than replacing
  address characters with an ellipsis; IPv4 behavior remains unchanged.
- Add responsive Watch and neighbor-table regressions for equal title spacing,
  top/side borders, full/compact/heatmap title parity, version-first title
  compaction, metric stability, worker-summary spacing, and complete IPv6
  management-address output.

## 0.33.0 - 2026-09-02

- This operator-interface release does not change SNMP collection, CDP/LLDP
  parsing, scheduling, retry budgets, identity, graph semantics, or diff
  classification.
- Define the exact 0.33.0 release constraint set as Linux-validated. Remove the
  Windows-only Colorama constraint, keep the two `pyproject.toml` uv arrays in
  exact agreement with `constraints/release-0.33.0.txt`, and add a regression
  that rejects a `win32` marker in the Linux manifest.
- Add `scripts/gufo-ipv6-test.py`, `scripts/gufo-snmp-diag.py`, and
  `scripts/gufo-readme.txt` with release-tested file modes and canonical
  hyphenated names.
- Modernize `gufo-ipv6-test.py` to accept one IPv6 literal or IPv6-resolvable
  hostname, reject IPv4, preserve resolver order while deduplicating AAAA
  results, validate `SNMPCOMM` without exposing it, import Gufo after `--help`,
  probe the same canonical address unbracketed and bracketed, and return stable
  conclusive/inconclusive/configuration/interruption exit statuses.
- Complete the Watch layout objective: use the package name/version in a
  two-line upper-left header, display update age as unbounded total `mm:ss`,
  center the intact run-summary block, center worker grids without reducing
  capacity, keep partial rows aligned to the first worker column, and provide a
  tested small-terminal fallback down to 20x4 with state, run ID, age, aggregate
  worker status, and exit guidance.
- Preserve fixed-width worker cells, semantic color roles, changed-worker
  emphasis, stale/source indications, modal screens, resize/view controls,
  footer clearing, and terminal restoration.

## 0.32.9 - 2026-09-02

- This maintenance update changes compatibility identity projection without
  changing collection or comparison contracts.
- Treat LLDP and LLDPv2 chassis subtype 7 (`local`/locally assigned) as
  weak, edge-scoped evidence and operator-facing display text. It no longer
  enters the global `chassis_id` alias registry, where repeated opaque values
  could collapse unrelated endpoints into one compatibility host.
- For an otherwise anonymous endpoint, promote one explicitly typed,
  unambiguous MAC-address Port ID to a bounded `mac` identity. Candidates that
  already have a usable name, management address, or trusted chassis identity
  continue to use that device-level evidence so multi-interface systems are not
  split by per-interface Port IDs.
- Add a strong `anonymous_lldp_port_mac` derived claim while preserving the raw
  Port ID as edge evidence and the locally assigned chassis value as a weak,
  non-identity claim.
- Add `compatibility_projection_diagnostics` to topology graph output and its
  summary. A legacy flat host spanning several distinct anonymous endpoint MACs
  is reported as a warning with graph entity and source-host references; the
  diagnostic explicitly does not alter the authoritative observation graph.
- Add production-shaped identity, state, claim, graph, and public-output
  regressions. The repeated `hex:a1:00:00:00:00:00` group reprojects as 44
  distinct MAC endpoints for run 20260111-00 and 49 for run 20260111-01, with
  zero subtype-7 chassis aliases.
- Replay the supplied September 2 discovery pair and preserve its 68
  graph-backed change events, zero unmatched/ambiguous/conflicting/graph-only
  results, and `consistent` cross-view status. Existing 0.32.8 discovery files
  remain immutable; the corrected flat-host projection applies to new scans.
- Preserve discovery scheduling, SNMP and protocol collection, topology graph
  entity/relationship semantics, diff reconciliation, Gufo IPv6 containment,
  late-address recovery, and every retry budget unchanged.

## 0.32.8 - 2026-09-01

- Keep `discovery.json` at schema 8, topology graph schema 2, and `run.json`
  schema 3. Advance diff JSON to schema 12 for orthogonal relationship-change
  dimensions and graph-member-scoped change events.
- Record `change_dimensions`, `member_presence_change`, and
  `member_protocol_changes` on graph relationship comparisons. A relationship
  can now report simultaneous membership and protocol-evidence changes without
  allowing one primary status to hide the other dimension.
- Reconcile protocol, management-address, and relationship-evidence rows inside
  a `member_set_changed` relationship only when both sides identify the exact
  same remote graph component and port. Protocol transitions additionally must
  reproduce the exact per-member A/B protocol sets recorded by the graph.
- Add `graph_member_keys` to change events and their stable fingerprints so two
  different neighbors changing in one local-interface group cannot collapse
  into one event. Reciprocal observations for the same member can still fold.
- Add production-shaped regression coverage for the concurrent Cisco SEP
  `cdp,lldp` to `lldp` transition and newly observed LLDP member on `Gi1/0/6`,
  plus multiple simultaneous member-presence and protocol transitions.
- Replay production runs 20260110-01 and 20260110-00. All 89 non-stable learned
  observations reconcile to 87 graph-backed events with zero unmatched,
  ambiguous, conflicting, or graph-only events. The compound relationship keeps
  separate `member_presence` and `protocol_evidence` event dimensions.
- Keep broad supported minimums in published dependency metadata while adding
  exact uv runtime, test, static-analysis, and build constraints for the 0.32.8
  release environment. Ship the readable constraint manifest under
  `constraints/`.
- Use `filter="data"` when tests extract an operator review archive, replace the
  site-specific maintainer name in installation examples, and reject single
  quotes in paths embedded in generated systemd shell commands.
- Preserve discovery scheduling, collection behavior, Gufo IPv6 containment,
  late-address recovery, and every existing retry budget unchanged.

## 0.32.7 - 2026-09-01

- Keep `discovery.json` at schema 8, topology graph schema 2, and `run.json`
  schema 3. Advance diff JSON to schema 11 for graph-backed change events,
  compatibility-to-graph reconciliation, graph-native coverage incidents, and
  management-address collection-health transitions.
- Make graph relationship authority use the LLDP/LLDPv2 `remote_neighbor`
  subtable when schema-8 coverage is available. A partial or malformed
  `remote_management_address` walk remains a health issue but no longer makes a
  complete remote-neighbor snapshot coverage-uncertain. A genuine
  remote-neighbor failure retains exact subtable provenance.
- Cross-reference every non-stable compatibility learned-neighbor observation
  with its topology-graph relationship record. Emit stable, unique
  graph-backed change events and an explicit cross-view consistency result;
  unmatched, ambiguous, conflicting, and graph-only outcomes remain visible
  instead of being silently reconciled.
- Describe local-port changes as observed attachment changes. The structured
  result records identity continuity, movement confidence, unresolved
  directness, and `physical_topology=not_inferred`; human output uses
  `Attachment` rather than implying a confirmed physical cable move.
- Include graph-native and health-only topology collection gaps in collection
  incidents. Each incident states whether a reported difference depends on the
  gap, carries graph entity/relationship references, and distinguishes
  difference-dependent incidents from health warnings that do not qualify any
  reported change.
- Add compact management-address health comparison with A/B incomplete counts,
  persistent, new, changed, and recovered incidents plus cause breakdowns and
  transition detail. Management health remains independent of topology
  authority.
- Replay production runs 20260109-03 and 20260109-02. All 13 non-stable learned
  observations reconcile to 13 unique graph-backed events with no unmatched,
  ambiguous, conflicting, or graph-only event. The prior false
  coverage-uncertain graph relationship disappears; four genuine
  topology-sensitive collection gaps per side remain health warnings, and no
  reported change depends on them. The replay records 97 persistent malformed
  management-index cases and one timeout recovered in A.
- Preserve Gufo IPv6 containment, exact route diagnostics, late-address
  recovery, SNMP collection behavior, and every 0.32.4 retry and delayed
  stability budget unchanged.

## 0.32.6 - 2026-08-31

- Keep `discovery.json` at schema 8, topology graph schema 2, and `run.json`
  schema 3. Advance diff JSON to schema 10 for collection-timing policy,
  subtable-scoped coverage authority, relationship-evidence classification,
  attribute coverage provenance, and compact human-report controls.
- Retain collector `duration_ms` telemetry in each discovery while excluding it
  from default cross-run equality. Add `--include-collection-timing` and its
  configuration counterpart for explicit timing diagnostics. Ordinary elapsed
  time jitter no longer marks otherwise stable hosts as collection-changed.
- Use LLDP/LLDPv2 `remote_neighbor` coverage for relationship presence,
  original-LLDP `local_port` coverage for local-interface authority, and each
  protocol's `remote_management_address` coverage for management-address
  removals. Aggregate protocol status remains a health summary but no longer
  makes complete topology observations uncertain merely because an independent
  management-address walk was partial.
- Preserve semantic subtable coverage through compatibility-projection folding.
  Duplicate projections merge each coverage dimension independently, with a
  complete contributing path preventing an unrelated aggregate partial status
  from erasing authoritative neighbor or interface coverage.
- Classify stable relationships whose observer, peer, local port, remote port,
  and protocol set agree but whose names or raw protocol evidence differ as
  `relationship_evidence_changed`. The summary exposes a separate `Evidence`
  count and records `semantic_qualification=evidence_only` with no asserted
  physical-topology effect. Durable identity conflicts and actual port changes
  retain their existing higher-priority classifications.
- Propagate collection provenance for uncertain entity attributes into graph
  correspondence and collection incidents. Missing chassis/stack evidence
  caused by a failed source observation is reported as attribute uncertainty
  rather than a confirmed entity change or one-sided graph component.
- Collapse derivative coverage-uncertain rows beneath their originating
  collection incident in default human output. Add `--summary-only` for
  summaries/incidents and `--expand-collection-incidents` for the complete
  diagnostic rendering. Machine-readable JSON always retains full detail.
- Replay the supplied 20260109-01 and 20260109-00 production pair. Default diff
  size falls from about 139 MB to about 11 MB; timing-only collection churn no
  longer marks 1,368 hosts. The comparison retains one credible endpoint port
  move, one protocol transition, seven stable relationship-evidence changes,
  nineteen confirmed one-sided observations, and the existing
  `branch-access-3650-stack` LLDP structural-failure incident without
  introducing a pairing or topology regression. Gufo IPv6 containment,
  late-address recovery, and every 0.32.4 retry budget remain unchanged.

## 0.32.5 - 2026-08-31

- Contain Gufo SNMP 0.12.0 raw-IPv6 destination construction at the backend
  boundary. LLDP-Runner tries canonical unbracketed IPv6 first and performs one
  bracketed construction only for the exact confirmed
  `OSError("invalid address")` signature. The compatibility attempt does not
  consume any SNMP retry allowance, and canonical unbracketed addresses remain
  authoritative everywhere else.
- Add phase-aware SNMP backend errors and one structured record per failed
  address and credential route. JSON and CSV output now expose exact attempted
  target, address family, phase, original exception type and OS fields,
  credential provenance, operation, collector, attempt, current final state,
  and basic-route recovery metadata without inferring targets from host
  presentation fields.
- Add durable route-attempt history and bounded late-management-address
  recovery. A failed managed host may be admitted once by default when a new,
  direct, policy-permitted, previously unattempted management address arrives.
  Recovery accounting survives restart and host merges and does not replay old
  routes.
- Add explicit LLDP and LLDPv2 subtable coverage for remote-neighbor,
  management-address, and original-LLDP local-port walks. Coverage records
  status, attempts, objects, rows, duration, message, and management-address
  validity/family counts while retaining usable topology when only local-port
  resolution fails.
- Classify management-address evidence changes on an otherwise stable learned
  relationship separately from topology changes. Diff JSON schema 9 reports
  added/removed addresses by family and collection provenance; incomplete
  address-table coverage yields uncertainty, while physical moves, protocol
  transitions, and collector failures retain precedence.
- Advance `discovery.json` to schema 8 and diff JSON to schema 9. Add the direct
  Gufo diagnostic under `tools/`, update configuration and operator/developer
  documentation, and add deterministic transport, migration, recovery,
  coverage, diff, and production-replay regression tests.
- Replay the supplied 20260108-08 and 20260108-07 production states. The new
  comparison reports 10 management-address evidence changes, one protocol
  transition, one A-only learned relationship, and no fabricated physical
  moves. Both runs recover all 14 historical Gufo IPv6 constructor errors
  across seven destinations from ordered, credential-matched durable route
  evidence.

## 0.32.4 - 2026-08-30

- Keep discovery JSON at schema 7, topology graph schema 2, diff JSON schema 8,
  and `run.json` schema 3. This release changes collection resilience and
  additive retry telemetry only; identity, graph, and diff semantics remain
  unchanged.
- Allocate normal adaptive retries fairly across collector families. General
  SYSTEM-MIB, ENTITY-MIB, and IF-MIB work remains bounded by the shared target
  cap, while LLDP-family and CDP collectors receive a protected reserve that
  earlier collectors cannot consume. LLDP and LLDPv2 share one normal family;
  CDP has its own. A per-collector cap prevents one multi-walk collector from
  exhausting all available repair capacity.
- Add an operator-configurable delayed neighbor stability pass. After every
  enabled LLDP, LLDPv2, and CDP first pass completes, one shared quiet-period
  delay is applied and each protocol whose final result is a timeout or
  structurally invalid snapshot receives exactly one fresh full-protocol retry.
  The final pass uses the persistent degraded profile, reopens the backend
  session, starts at the protocol root, and suppresses nested transport or
  structural retries so persistent loss cannot multiply attempts.
- Record shared-pool, protected-reserve, collector-family, and stability retry
  accounting in adaptive session telemetry. Collection coverage now reports
  the actual number of allowed retry attempts rather than leaving a
  transport-retried collector at attempt 1; unavailable retry decisions remain
  diagnostic events but do not inflate attempt counts.
- Replay the submitted `20260108-05` versus `20260108-04` production pair. The
  known packet-loss path to `hq-access-3650-1` demonstrates why LLDP/CDP
  capacity must survive earlier ENTITY-MIB/IF-MIB failures, while the
  transient invalid `branch-access-3650-stack` LLDP snapshot demonstrates
  the bounded delayed repair case.

## 0.32.3 - 2026-08-30

- Keep discovery JSON at schema 7, topology graph schema 2, and `run.json`
  schema 3. Advance diff JSON to schema 8 for compatibility-projection
  reconciliation, independent host dimensions, optional-table row-count
  confidence, and weak-identity mobility records.
- Reconcile inactive duplicate managed-host projections before worker claims,
  defer ready rows equivalent to an active worker's projection, and perform one
  final reconciliation after workers stop. Compatible direct logical names
  (exact, or one guarded short-name/FQDN pair) plus a shared
  identity-eligible management address are required. Direct SNMP ``sysName``
  evidence takes precedence over a shadow presentation alias; conflicting
  serial, SNMP engine, strict MAC, or logical-name evidence prevents merging.
  Differing per-link chassis IDs are tolerated only under that direct
  name-and-address corroboration and remain conflicts for sparse transitive
  bridges.
  Completed results outrank failed projections, a READY alternate remains
  queryable after an equivalent route fails, and seed status/rank survive either
  merge outcome.
- Canonicalize duplicate complete managed-host rows before compatibility host
  pairing. Remap and deduplicate their neighbor references so a redundant
  projection cannot create a false one-sided host and a copied inventory of
  false one-sided neighbors. Immutable graph advertisements remain unchanged.
- Separate durable entity attributes from presentation aliases and collection
  provenance. Query target, ICMP route, SNMP row counts, retries, credential
  route, and other collector telemetry no longer inflate the confirmed host
  change count; their differences remain available in dedicated dimensions.
- Treat a complete but zero-row optional ENTITY-MIB snapshot as insufficient
  evidence that previously observed chassis or member hardware was removed.
  Report the attribute difference as collection-coverage uncertainty while a
  nonempty complete snapshot can still support a confirmed absence.
- Use one shared weak-MAC boundary in compatibility and graph diff. A unique
  cross-port observation supported only by low-entropy, multicast, locally
  administered, malformed, or otherwise weak MAC evidence becomes one
  ambiguous `candidate_move`, not confirmed A-only and B-only relationships.
- Replay the live `20260108-03` versus `20260108-02` pair: remove the
  duplicate `hq-vdc1-7nx1` host and its 28 copied neighbor losses, isolate the
  intermittent Nexus ENTITY-MIB result as attribute uncertainty, preserve one
  protocol-only
  transition, retain one confirmed older-run-only MAC endpoint observation, and
  classify `00:00:00:00:01:03` movement as ambiguous.

## 0.32.2 - 2026-08-30

- Keep discovery JSON at schema 7 and topology graph schema 2. Advance diff
  JSON to schema 7 and `run.json` to schema 3 for explicit coverage-aware
  comparison fields and finalization timing metrics.
- Propagate failed protocol/table coverage into one-sided entity and
  relationship decisions. Direct observations and recursively hidden
  descendants now use `presence_uncertain_due_to_coverage` rather than a
  confirmed addition or removal when the corresponding observer could not
  collect the needed protocol.
- Add collection-incident aggregation with originating observer, protocol,
  table, direct effects, recursive effects, and actionable queried-device
  denominators. Intentional `no_query` and `out_of_scope` populations remain
  separate from queried partial/failed devices.
- Validate complete CDP cache snapshots before materializing endpoints. A row
  missing device ID or remote port, an index mismatch, or a mid-snapshot
  partial row rejects the complete table. One bounded restart begins at the
  CDP root; repeated invalid snapshots record `structurally_invalid` coverage
  without creating identity-empty shell hosts or relationships.
- Replace the one-token target session retry policy with a persistent degraded
  transport profile, one bounded retry allowance per logical operation/table,
  and a total per-target cap. A recovered scalar or GET-MANY request no longer
  consumes the only opportunity to repair a later CDP, LLDP, or LLDPv2 table.
- Record complete retry and exhaustion context, including target, collector,
  operation, table/root OID, credential route/profile, phase, counters,
  before/after transport values, discarded partial rows, and final outcome.
  Authentication, access, and unsupported-OID failures remain non-retryable.
- Qualify graph entity and relationship correspondence as `confirmed`,
  `coverage_uncertain`, `presentation_only`, or `ambiguous` while continuing
  to report physical topology as `not_inferred`.
- Reconcile one uniquely corroborated resolved/typed-unresolved LLDP local port
  at the relationship level. The relationship remains the same and the
  local-port resolution loss is reported as presentation-only; no device-wide
  LLDP-port-number-to-ifIndex rule is created.
- Separate identity, relationship, protocol-evidence, attribute,
  presentation, and collection-coverage dimensions. Complete-coverage
  `cdp,lldp -> lldp` transitions remain protocol-evidence changes with no
  asserted physical-topology effect; collector failure makes them uncertain.
- Publish canonical `outputs/<run-id>/` paths in completion messages even when
  an installation retains a legacy symlink. Add discovery, graph resolution,
  graph serialization, output publication, finalization, and total wall-clock
  durations to `run.json` while retaining the existing logical `duration`
  definition.
- Close coordinator multiprocessing queues after workers and the log listener
  stop, preventing an otherwise completed command or test process from waiting
  on a stale queue feeder during interpreter shutdown.
- Replay the submitted `20260108-01` versus `20260108-00` evidence: all 342
  coverage-derived A-only hosts are uncertain, the two malformed CDP shells
  are invalid source evidence, the five degraded local-port relationships
  remain presentation-only, and the 12 maintenance protocol transitions keep
  no asserted physical-topology effect.

## 0.32.1 - 2026-08-29

- Advance discovery JSON to schema version 7, topology graph schema version 2,
  diff JSON to schema version 6, and `run.json` to schema version 2. Current
  release practice remains to collect two new runs after deployment rather than
  convert earlier discovery documents.
- Make graph evidence accounting complete. Every durable protocol
  advertisement is now present in the graph or in an explicit
  `advertisement_exclusions` record. A provisional compatibility host that is
  absorbed or retired can no longer remove its CDP, LLDP, or LLDPv2 evidence
  from the final graph.
- Link each protocol advertisement to the immutable SNMP-result observation
  that supplied its source-system facts. Retain a compact source-context hint
  on each advertisement instead of duplicating the complete system result for
  every neighbor row.
- Replace the graph's single authority implication with independent dimensions
  for observation completeness, observation projection, entity-resolution
  maturity, physical-topology inference, directness, and compatibility-view
  role. A complete observation projection does not claim that provisional
  entity clusters or physical cables are proven.
- Make semantic graph identifiers independent of run-local host IDs, query and
  credential routes, volatile SNMP table indexes, and input row order. Keep
  storage fingerprints separately for audit and idempotence.
- Treat one Nexus VDC observed through several management routes as one logical
  system when the normalized logical name and verified physical serial agree.
  Keep sibling VDCs with different names separate even when they share one
  Nexus 7700 chassis serial. Production fixtures record `hq-vdc2-7nx1` at
  `203.0.113.21` and `203.0.113.24`, `hq-vdc3-7nx1` at `203.0.113.22`, and
  `hq-vdc1-7nx1` at `203.0.113.23`.
- Compress the current graph projection stored in SQLite and retain a compact
  summary beside it. Existing text projections remain readable during the
  additive state migration.
- Add run-wide A/B collection-coverage summaries and an operator warning to
  diff output. Preserve per-host protocol, table, and interface-resolution
  details so collection incidents remain distinguishable from confirmed
  network changes.
- Treat a uniquely corroborated relationship as unchanged when one run has a
  resolved local-interface name and the other has only the corresponding typed
  unresolved representation. Diff JSON retains the display-only change under
  `presentation_differences` instead of classifying topology as uncertain.
- Change the built-in finalized-output directory to the intentional plural
  `outputs`. Default configuration, generated configuration, examples, help,
  tests, scripts, and current documentation use
  `<persistent_root>/outputs/<runid>/` without a singular fallback.
- Add timezone-aware `started` and `completed` values plus numeric `duration`
  seconds to `run.json`. `duration` is the nonnegative elapsed difference
  between the two persisted logical-run timestamps.
- Harden `scripts/lrun-prepare-bundle`: use only `outputs/`, create a coherent
  SQLite backup for each selected run, verify and compact the staged database,
  and exclude live WAL/SHM sidecars from the review archive.
- Expand [`docs/ROADMAP.md`](docs/ROADMAP.md) with graph inspection, Watch
  layout, performance counters, run timeboxes and alerting, storage profiles,
  and production fixtures. Add [`docs/DEV.md`](docs/DEV.md) and focused
  contributor references under `docs/dev/`. Only
  [`docs/ROADMAP.md`](docs/ROADMAP.md) is maintained; no parallel `doc/`
  documentation tree is used.

## 0.32.0 - 2026-08-29

- Advance discovery JSON to schema version 6 and diff JSON to schema version 5.
  Earlier discovery formats are not converted by this release; current
  operational practice is to collect two new runs after deployment.
- Retain immutable CDP, LLDP, and LLDPv2 advertisements before cross-protocol
  reconciliation. Store the complete raw row in SQLite, publish a compact audit
  form in discovery JSON, and derive typed claims without DNS or policy
  enrichment changing what the device actually reported.
- Publish an authoritative claims-driven `topology_graph` containing physical
  chassis, logical systems, observed systems, interface occurrences, protocol
  advertisements, logical membership, observed relationships, interface
  relationship groups, collection coverage, and a deterministic projection
  fingerprint.
- Keep physical chassis and logical systems separate. A directly collected
  serial can associate several Nexus VDC logical systems with one chassis while
  distinct names, addresses, and management agents remain separate entities.
  A physical serial alone never merges the VDCs.
- Materialize the graph deterministically from durable evidence. Replaying
  unchanged evidence is idempotent; a changed component or projection appends a
  superseding decision and transactionally replaces the current graph without
  deleting prior observations, claims, or decisions.
- Preserve a locally assigned LLDP chassis label as the operator-facing endpoint
  name when no system name is advertised, while keeping the label edge-scoped
  and ineligible to create global host identity by itself.
- Unify already-resolved local interface names across CDP ifIndex and LLDP
  local-port namespaces while retaining every source namespace. Equal unresolved
  integers remain separate typed identifiers.
- Represent interfaces with several learned systems as deterministic
  relationship groups. Preserve member multiplicity and protocol evidence,
  classify shared-chassis logical members and overlays where supported, flag
  other multi-neighbor interfaces for operator review, and leave relationship
  directness unresolved instead of guessing direct versus passed-through.
- Add graph-aware many-to-many diff correspondence. Report one-to-one,
  one-to-many, many-to-one, and many-to-many components with cluster split,
  cluster merge, cluster reassociation, duplicate projection introduction, and
  duplicate absorption outcomes. Resolver changes are separated from observed
  relationship changes and do not automatically assert physical-link churn.
- Keep the flat host and neighbor comparison as a compatibility diagnostic.
  Ignore collection-route selection (`queried_as` and ICMP route) as physical
  host change, treat ENTITY-MIB absence as `not_observed` unless collection was
  complete, and refuse to confirm a physical move from weak low-entropy,
  multicast, or locally administered MAC-only evidence.
- Record independent collection coverage for SYSTEM-MIB, ENTITY-MIB, IF-MIB,
  LLDP, LLDPv2, and CDP. Status distinguishes complete, partial, timeout,
  access-restricted, unsupported, structurally invalid, not attempted, and
  failed collection so missing data is not automatically interpreted as
  removal.
- Add `output.relationship_view` and `show-neighbors --relationship-view`.
  `sectioned` is the default and indents shared-chassis, overlay, and
  multi-neighbor observations; `combined` uses compact relationship labels and
  a legend. Both views retain unresolved directness.
- Include executable `scripts/lrun-prepare-bundle`. With no arguments it selects
  the two newest completed runs; with exactly two arguments it preserves the
  requested A/B order. The script validates matching output/runtime trees,
  writes a changes-only JSON diff, and creates one portable uncompressed tar
  archive.
- Add [`docs/ROADMAP.md`](docs/ROADMAP.md) for planned resolver, collection,
  presentation,
  validation, data-contract, and review-workflow work. Expand the architecture,
  claims, diff, names, run, CLI, primer, installation, precedence, example
  configuration, generated comments, and README documentation for the graph
  model and mixed Network Operations audience.

## 0.31.7 - 2026-08-29

- Use one adaptive SNMP transport profile for the successful target address and
  credential route across basic and detail collection. The target has one
  shared retry budget, preventing a request-level retry and a collector-level
  retry from multiplying into several attempts. Configured repeated attempts
  against the same address and credential route also reuse the degraded profile.
- On the first retry-eligible timeout or structurally incomplete table, increase
  the active request timeout by the configured multiplier (default `1.5`),
  reduce GETBULK `max_repetitions` by the configured multiplier (default `0.5`,
  rounded upward), reduce GET-MANY OID batches by the same factor, and add the
  configured inter-PDU pacing (default `100` milliseconds). The degraded
  profile remains active for later operations on that target and resets for the
  next target. A failed table attempt is discarded and restarted at its root.
- Add `snmp.retry_budget`, `snmp.retry_timeout_multiplier`,
  `snmp.retry_max_repetitions_multiplier`,
  `snmp.retry_min_max_repetitions`, and
  `snmp.retry_inter_pdu_delay_ms` to defaults, generated configuration,
  `configs/example.toml`, validation, and operator documentation.
- Persist adaptive-session telemetry, including before/after timeout,
  max-repetitions, request rate, pacing, discarded-partial-result status, and
  retry outcome, in SQLite immutable SNMP-result evidence and additive
  discovery JSON fields.
- Preserve the target-first SNMP log contract for every new retry and pacing
  event. With the normal logging prefix, records read
  `timestamp level worker logger: SNMP target=<address-or-name> <message>`, so
  concurrent worker output keeps the destination at one parseable position.
- Make merged neighbor collections independent of SNMP table row order. Use
  canonical member, protocol, address, and capability ordering while preserving
  protocol-specific raw evidence and duplicate advertisements where they are
  materially distinct.
- Parse a plausible trailing `name(serial)` advertisement into three retained
  facts: the raw advertisement, its logical base name, and a separate physical
  serial hint. The base participates in guarded CDP/LLDP name comparison and
  DNS lookup. The serial hint is a moderate, non-merging physical-container
  claim until direct evidence such as ENTITY-MIB corroborates it.
- Add an audit-only local-interface observation-group projection for interfaces
  with multiple learned members. Groups and members have deterministic
  fingerprints and canonical order, preserve raw/base names and serial hints,
  and leave direct/indirect relationship scope unclassified. They do not replace
  `learned_neighbors` or change scheduling in the 0.31 maintenance line.
- Add the [technical primer](docs/PRIMER.md), which explains SNMP table pacing,
  claims, clusters, physical versus logical entities, protocol advertisements,
  deterministic multisets, deferred reasoning, and reversible decisions for a
  mixed Network Operations audience.
- Keep discovery JSON schema version 5 and diff JSON schema version 4. The
  interface observation groups are additive shadow/audit data for the planned
  graph resolver.

## 0.31.6 - 2026-08-29

- Standardize operational SNMP log and console messages so the exact transport
  target immediately follows the `SNMP` marker. With the existing logging
  prefix, events now read `timestamp level worker logger: SNMP target=<value>
  <message>` for session retries, collector retries/failures, access denials,
  interface-resolution gaps, basic polling, and detail-session failures.
- Treat a learned edge as topologically unchanged when both runs contain the
  same typed unresolved local-port token and every normalized neighbor field is
  equal. The unresolved interface remains visible in discovery data and host
  collection coverage, but no longer turns an otherwise identical edge into an
  `uncertain` change.
- Add a narrowly guarded same-device CDP/LLDP reconciliation path for Cisco IOS
  agents that expose a resolved CDP IF-MIB port but no usable original-LLDP
  local-port name. One unresolved LLDP row can attach to one resolved CDP edge
  only when the protocol-local numeric indexes, exact remote port, and remote
  endpoint identity corroborate one unique candidate. The raw typed LLDP value
  remains in protocol details, and no device-wide `lldpLocalPort == ifIndex`
  equivalence is created.
- Validate against production runs `20260107-01` and `20260107-02`. The diff fix
  reclassifies 47 byte-for-byte stable unresolved-port edges from `uncertain` to
  `same`. Seven A-only and seven B-only Nexus/VDC edge projections remain
  intentionally unresolved because safely representing those duplicates
  requires cluster split/merge correspondence rather than another one-to-one
  pairing shortcut.
- Keep discovery JSON schema version 5 and diff JSON schema version 4.

## 0.31.5 - 2026-08-29

- Add an additive immutable evidence layer to the SQLite run database.
  Normalized candidate and SNMP-result observations use deterministic
  fingerprints, typed claims preserve raw/normalized value, provenance, scope,
  strength, identity eligibility, and context, and exact replay is idempotent.
- Add append-only resolution decisions and decision-to-claim links. A later
  cluster analysis can append a different decision that supersedes the former
  conclusion without updating or deleting the underlying observation, claims,
  or decision history. Existing host/edge tables remain the compatibility
  projection during this staged resolver migration.
- Classify strict Cisco `SEP<12-hex>` phone/video names and strict Cisco AP
  names (`APxxxx.xxxx.xxxx` or compact `AP<12-hex>`) as strong derived MAC
  evidence.
  A strict AP CDP name can reconcile with the identical LLDP MAC-address chassis
  identity without applying generic hexadecimal hostname inference.
- Keep LLDP `network_address` chassis values as weak edge-scoped claims and raw
  protocol evidence instead of admitting them as standalone global address
  aliases. Repeated/default values such as `198.51.100.3` therefore cannot merge
  endpoints observed on unrelated physical edges by chassis value alone.
- Wrap the project-owned SNMP client with adaptive timeout handling. A timeout
  during session/engine discovery, GET, GET-MANY, or WALK receives one retry
  using a fresh client and exactly 1.5 times the active timeout. A failed table
  walk is restarted from its root so partial GETNEXT/GETBULK results are not
  accepted as a complete snapshot; the increased timeout remains active for
  later operations in that device session.
- Normalize explicit `noAccess`, `authorizationError`, VACM, and equivalent
  access/view denials as `snmp_access_restricted`. Log the target, operation,
  OID context, and safe detail, persist the structured worker error, and prevent
  optional IF-MIB, LLDP local-port, or ENTITY-MIB fallback paths from silently
  converting an access restriction into an empty/unsupported table.
- Add additive migration for existing 0.31.4 state databases plus regressions
  for immutable/idempotent evidence, superseding decisions, strong/weak claim
  classification, reused network-address chassis values, Cisco AP
  reconciliation, 50-percent timeout retry (including mid-table and
  post-success timeouts), and access-restriction propagation.
- Keep discovery JSON schema version 5 and diff JSON schema version 4. The new
  evidence ledger is internal SQLite state in this maintenance release.

## 0.31.4 - 2026-08-28

- Replace one-owner IPv4/IPv6 aliases in SQLite with many-to-many host-address
  claims. A repeated usable address remains visible on every claimant but is
  treated as contested evidence and cannot select or merge all hosts that
  advertise it. Existing 0.31.3 state databases migrate their address aliases
  in place when opened.
- Keep directly advertised CDP/LLDP names distinct from DNS enrichment for
  identity assembly. Resolver names and addresses remain available for
  classification, presentation, query policy, and scheduling, but DNS-only
  convergence on a load balancer, anycast frontend, or shared address can no
  longer merge unrelated discovered devices.
- Scope LLDP chassis subtypes that are device-local (`chassis_component`,
  `interface_alias`, `port_component`, and `interface_name`) out of the global
  host-alias registry. A `network_address` chassis value participates only as
  ordinary address evidence; typed MAC and other accepted chassis evidence keep
  their existing behavior.
- Retry IF-MIB interface-name collection once after a transient timeout,
  transport failure, or incomplete-table result. Retry the original LLDP
  local-port table once independently as well. Persistent failures are recorded
  as durable collection coverage rather than being silently converted to empty
  maps or discarded topology.
- Preserve unresolved local-port namespaces as `ifIndex:<n>` or
  `lldpLocalPort:<n>`. Original LLDP no longer assumes that
  `lldpRemLocalPortNum` is an IF-MIB `ifIndex` merely because the integer
  values match.
  Per-protocol unresolved-row errors let diff classify affected topology as
  uncertain.
- Add a reciprocal `edge_context` host-pairing tier to diff. Otherwise anonymous
  hosts can pair across runs only when the same already-paired observer sees a
  unique exact endpoint MAC on the same typed local port; this evidence remains
  topology-scoped and never becomes a global alias.
- Add the learned-neighbor status `moved` when one uniquely paired endpoint
  remains the same but changes resolved local switch ports. A resolved versus
  unresolved local-port representation is reported as collection uncertainty,
  not as a physical move.
- Add explainable categorical host-pairing confidence (`verified`, `high`,
  `medium`, or `low`) with the evidence tier and tokens retained on every paired
  host. These are conservative engineering categories, not calibrated
  probabilities. The macro summary publishes confidence counts and human output
  adds a Confidence column.
- Harden cross-run conflict handling so disjoint strict SEP-derived MACs remain
  contradictory even when both records contain the same repeated address. A
  shared address with incompatible direct names and no agreeing physical
  identity is retained as an uncertain candidate rather than forced into a host
  pair.
- Advance diff JSON to schema version 4 for `moved`, `edge_context`, pairing
  confidence, and unresolved-interface coverage. Discovery JSON remains schema
  version 5.
- Validate the release against the supplied production runs 20260106-13 and
  20260106-14. The semantic result improves from 42/43 one-sided hosts and 12/9
  one-sided learned edges to 1 arrival, 2 departures, 1 endpoint move, and 8
  uncertain learned edges (six interface-resolution gaps and two protocol
  collection failures), while preserving 16,192 unchanged learned edges.

## 0.31.3 - 2026-08-28

- Prevent distinct strict Cisco `SEP<12-hex>` endpoints from collapsing into
  one discovery host merely because they advertise the same usable IP address
  or LLDP `network_address` chassis value. When both observations contain
  SEP-derived MAC identity and the MAC sets are disjoint, that hardware
  contradiction now wins over shared address/chassis evidence.
- Fix an encounter-order-dependent production failure in which nine phones at
  different sites all advertised `198.51.100.29`; whichever phone was observed
  first owned the shared address and accumulated every later SEP name/MAC. Two
  otherwise equivalent runs could therefore choose different aggregate
  `preferred_name` values and report false neighbor name changes across the
  routers that observed those phones.
- Preserve the intended 0.31.2 behavior for one Cisco endpoint across CDP/LLDP,
  short/FQDN forms, DNS-suffix changes, missing management-address rows, and
  changing network-address chassis evidence: equal strict SEP MAC identity still
  reconciles those observations to one host.
- Add a production-shaped state regression using the nine affected SEP
  identities and their repeated `198.51.100.29` address. The regression verifies
  nine durable host identities, one SEP MAC alias per host, and stable
  re-observation of the same phone.
- Discovery JSON remains schema version 5 and diff JSON remains schema version
  3; this release corrects discovery identity assembly and requires no schema
  change.

## 0.31.2 - 2026-08-28

- Add strict Cisco endpoint identity for a left-most host component matching
  `SEP` plus exactly twelve hexadecimal characters. The embedded value is
  normalized as a canonical MAC alias, so short names and FQDN forms such as
  `.voice-a...` and `.voice-b...` identify the same phone/video endpoint without
  applying generic DNS suffix stripping.
- Let strict SEP identity reconcile CDP/LLDP rows on the same local switch port
  even when the LLDP management-address subtable is temporarily unavailable.
  Generic short-name/FQDN reconciliation remains guarded by shared usable
  address evidence.
- Allow an LLDP chassis ID explicitly typed as `network_address` to participate
  as address-like same-edge corroboration while preserving its source as chassis
  evidence in protocol details.
- Stop converting LLDP/LLDPv2 management-address walk exceptions into silently
  empty address tables. Timeout and transport failures now reach the complete
  protocol retry path; a final failure is persisted so collection-aware diff can
  classify affected topology as uncertain.
- Add a dedicated `protocol_changed` neighbor diff status when a paired physical
  edge changes protocol set, such as `cdp -> cdp,lldp` or `cdp -> lldp`, and all
  remaining differences are protocol/representation evidence. Collection
  uncertainty still takes precedence when a relevant collector actually failed.
- Advance diff JSON schema to version 3. Neighbor records can include a
  structured `protocol_change` object and macro summaries count
  `protocol_changed` separately from ordinary `changed` topology. Discovery JSON
  remains schema version 5.
- Add production-shaped regressions for the 91-phone split/merge pattern seen on
  a Catalyst stack, SEP suffix transitions, missing LLDP management-address
  evidence, transport retry, strict SEP cross-run pairing, and protocol-change
  summary/uncertainty behavior.
- Update README, NAMES.md, ARCHITECTURE.md, and DIFF.md to document SEP
  identity,
  LLDP management-subtable failure semantics, edge reconciliation, and the
  distinction between topology change and protocol-evidence change.

## 0.31.1 - 2026-08-28

- Validate LLDP and LLDPv2 remote-table snapshots before admitting neighbor
  rows. A row missing the mandatory chassis-ID or Port-ID subtype/value pair
  now causes one complete protocol retry instead of becoming partial topology.
  If the retry is still incomplete, the worker records an `incomplete_table`
  collector error so diff can treat the affected protocol as uncertain.
- Preserve the full LLDP remote-row identity during table assembly. Original
  LLDP now keeps `timeMark` in the row key and LLDPv2 also keeps its destination
  MAC index context; `time_mark` remains diagnostic/volatile for diff purposes.
- Extend guarded CDP/LLDP same-edge reconciliation for endpoints whose protocols
  describe the same physical port differently. The new path requires the same
  normalized local switch interface, at least one shared usable management IP,
  and compatible names before two protocol rows can become one edge.
- Define compatible short/FQDN names narrowly: exactly one protocol may report
  a single-label host name while the other reports that exact host label plus a
  domain suffix. Two different FQDNs do not match merely because their left-most
  labels are equal, and the rule never creates a global host alias.
- Prefer the LLDP typed Port ID when a corroborated CDP/LLDP edge has different
  remote-port strings, while preserving both protocol-specific names, ports,
  addresses, chassis evidence, and descriptions under `details`.
- Add production-shaped Cisco phone regressions proving one CDP short-name row
  and one LLDP FQDN row become one learned edge and one `observed_by` edge only
  when local-port, management-address, and name evidence agree. Add negative
  tests for different addresses, different local ports, and different FQDNs.
- Update README, NAMES.md, and ARCHITECTURE.md with LLDP snapshot-race behavior,
  full-index assembly, edge-scoped short-name/FQDN corroboration, and examples
  showing how LLDP-Runner keeps protocol evidence distinct while presenting one
  physical connection.

## 0.31.0 - 2026-08-28

- Repair order-dependent host splitting when an early observation cannot own a
  duplicate global name/address alias. A later candidate can now use the
  temporary host's usable `preferred_name` and inbound observed management
  addresses as corroborating evidence, but reconciliation still requires both
  normalized name and address agreement before link-specific chassis conflicts
  can be tolerated.
- Exclude explicit missing-name sentinels such as `unknown`, `null`, `none`,
  `(none).(none)`, `n/a`, `-`, and `not advertised` from canonical name aliases
  and cross-run name identity while preserving the raw protocol/presentation
  text for diagnostics.
- Add conservative same-local-port diff fallback pairing for endpoints whose
  run-local remote host cannot be paired. Exact MAC evidence can correlate an
  anonymous edge, including the mathematically reversible IPv6 modified-EUI-64
  form of that MAC, without promoting derived MACs into global discovery
  identity.
- Retry LLDP, LLDPv2, and CDP table collection once after a timeout. A recovered
  first timeout is not persisted as an incomplete collector error; a repeated
  timeout records attempt 2 and leaves the protocol incomplete.
- Make diff consume durable host state and neighbor-collector errors as
  collection-coverage metadata. Missing/changed topology affected by a failed
  host or protocol collector is reported as `uncertain` rather than as a
  definite add/remove/change. Diff JSON schema version 2 adds per-host
  `collection_coverage`, neighbor `uncertainty_reasons`, and uncertain neighbor
  counts; discovery JSON remains schema version 5.
- Add production-shaped regressions for the Nexus leaf order-dependent split,
  anonymous MAC edges, modified-EUI-64/MAC correlation, collector timeout retry,
  failed-host topology uncertainty, and the Nexus VDC macro-diff behavior from
  the preceding releases.

## 0.30.9 - 2026-08-28

- Convert cross-document Markdown references throughout the operator and
  developer documentation into proper relative Markdown links. References from
  files below `docs/` use same-directory targets, while root documents use
  project-root-relative targets.
- Preserve literal filename examples only where the filename itself is being
  demonstrated, such as the `docs/CLI.md` -> `docs-CLI.html`
  publication-name
  example.
- Add documentation regression coverage that verifies every local Markdown
  page link
  resolves to a shipped Markdown file and that navigational page references do
  not regress to unlinked inline-code text.
- Verify `scripts/md-to-html.sh` rewrites the relative Markdown links to its
  flattened generated HTML filenames without changing discovery or diff
  behavior.

## 0.30.8 - 2026-08-28

- Prevent syntactically valid non-host IP values from becoming discovery
  identity aliases. The canonical host-address boundary rejects IPv4
  this-network,
  loopback, multicast, reserved/limited-broadcast values and IPv6 unspecified,
  loopback, and multicast values while preserving private, CGNAT, benchmark,
  documentation, and link-local unicast addresses.
- Treat CDP `cdpCacheAddress` placeholders such as `0.0.0.0` as diagnostic
  `entry_addresses` only. They are no longer promoted to remote management
  addresses, DNS/query candidates, or host aliases. Apply the same defensive
  filtering to LLDP/LLDPv2 management addresses, reusable seed address hints,
  network-address chassis IDs, and canonical state correlation.
- Harden cross-run diff pairing so historical `0.0.0.0`, `::`, broadcast,
  multicast, loopback, or other rejected address values cannot become address
  matching keys. This prevents a placeholder IP from outranking unique host-name
  evidence in older discovery files.
- Add production-shaped VMware ESXi regressions for the shared `0.0.0.0` CDP
  failure and explicit macro-diff coverage confirming the 0.30.7 Nexus VDC
  shared-serial pairing translates run-local neighbor host references without
  false `a_only`/`b_only` topology churn.
- Update [`docs/NAMES.md`](docs/NAMES.md), [`docs/DIFF.md`](docs/DIFF.md),
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and README
  with host-address eligibility, VMware sentinel behavior, and macro VDC
  guidance.

## 0.30.7 - 2026-08-28

- Fix cross-run diff host pairing for logical devices that share one physical
  chassis identity, notably Cisco Nexus 7000 VDCs. Non-unique physical
  candidates can now be narrowed by exact normalized logical-name plus
  management-address agreement while reciprocal uniqueness is retained.
- Align diff chassis-conflict handling with discovery consolidation: differing
  representative LLDP chassis IDs may be tolerated when both logical name and
  management address agree, while serial-number and SNMP-engine conflicts
  remain hard conflicts.
- Prevent shared physical Nexus serials from collapsing distinct VDCs when
  logical corroboration is absent or non-unique. This restores stable
  learned/observed_by edge pairing across runs instead of reporting unchanged
  Nexus links as paired `a_only`/`b_only` records.
- Update [`docs/DIFF.md`](docs/DIFF.md), [`docs/NAMES.md`](docs/NAMES.md), and
  README guidance for shared
  physical containers, logical-host corroboration, and conservative ambiguity
  behavior.

## 0.30.6 - 2026-08-28

- Announce run type, primary configuration, raw seed count, seed-resolution
  start/completion, and discovery start before workers begin network discovery.
- Add 30-second console seed-resolution heartbeats so large DNS-heavy startup
  phases remain visibly active even while the main thread is inside a slow
  resolver call. `activity.log` records more detailed raw/input/unique,
  queryable/unresolved, policy-state, DNS-used/skipped, and elapsed counters.
- Improve pre-worker initialization failures with explicit console and
  activity-log messages while preserving the existing detailed CLI error.
- Add `discovery.seed_dns_mode` and `--seed-dns-mode` with `resolve` as the
  default and conservative `skip-addressed` reuse for a named seed carrying a
  valid prior `queried_as` address and successful/complete state when present.
  IP-only and failed/mixed-state seeds continue through normal DNS resolution.
- Add [`docs/RUN.md`](docs/RUN.md) describing the run lifecycle and
  [`docs/DNS.md`](docs/DNS.md) describing
  resolver behavior, skip-addressed tradeoffs, local caching-stub guidance, and
  a future run-scoped internal DNS-cache consideration.

## 0.30.5 - 2026-08-27

- Reconcile CDP and LLDP observations on the same local/remote port when their
  logical names agree, including guarded Cisco Nexus NX-OS CDP `name(serial)`
  Device IDs paired with the undecorated LLDP VDC System Name. The physical
  serial suffix is retained as CDP observation evidence and is not a host alias.
- Preserve CDP `cdpCacheAddress` explicitly as `cdp.entry_addresses` while
  retaining existing remote-address evidence. When CDP and LLDP reconcile, LLDP
  management addresses are ordered first for operator-facing management display.
- Refine host identity conflict handling so matching normalized name *and* at
  least one management address can corroborate one logical host even when valid
  LLDP chassis IDs differ by link, as observed on Nexus 7000 VDCs.
- Retain the 0.30.3 false-consolidation safeguards: different chassis IDs remain
  conflicting when name/address corroboration is incomplete, malformed chassis
  values remain observation-only, and shared physical Nexus serials never merge
  distinct VDC names/addresses.
- Update [`docs/NAMES.md`](docs/NAMES.md) and architecture documentation with
  the evidence-based
  consolidation model, Nexus VDC example, duplicate-prevention goals, and
  conservative rules intended to avoid both duplicate hosts and false merges.

## 0.30.4 - 2026-08-27

- Add `app_name` and `app_version` immediately after `schema_version` in
  `run.json`; both values come from canonical package runtime metadata.
- Add a shared standard-library CSV input reader with dynamic header-based field
  positions, source-line retention, case-insensitive header matching by default,
  selectors, structural field/line limits, optional ASCII enforcement, and
  explicit rejection of multiline CSV records.
- Migrate reusable `seeds.csv` and seed-credential CSV input to the shared
  reader. Their current field names remain required, but columns may be
  reordered
  and unrelated extra columns are ignored without changing operational meaning.
- Add [`docs/CSV-INPUT.md`](docs/CSV-INPUT.md) as the common CSV input contract
  for current and
  future
  operator-supplied CSV files.

## 0.30.3 - 2026-08-27

- Fix learned-host consolidation so an LLDP/LLDPv2 chassis ID advertised as
  `mac_address` or `network_address` participates in identity correlation only
  when it actually decodes as that advertised type. Malformed `hex:...` values
  remain in neighbor observation details for troubleshooting.
- Include the chassis subtype in internal chassis aliases so equal text under
  different LLDP chassis subtypes cannot collide in the identity registry.
- Add conservative identity-conflict checks: contradictory trusted chassis IDs
  prevent a duplicate name/address from forcing a merge, and a chassis-only
  match is rejected when both names and management-address sets are non-empty
  and mutually disjoint.
- Add regression coverage based on an Aruba CX switch learning multiple Cisco
  phones with different names, management addresses, and Port IDs but the same
  malformed subtype-5 chassis value. Canonical output now retains distinct host
  references and names for those neighbors.
- Update [`docs/NAMES.md`](docs/NAMES.md) and architecture documentation for
  trusted chassis
  identity, conflict handling, and the distinction between canonical identity
  and retained observation evidence.

## 0.30.2 - 2026-08-27

- Ignore volatile SNMP neighbor-table locator values during diff comparison so
  unchanged topology is not reported merely because LLDP/LLDPv2/CDP row indexes
  changed between collections. This includes `remote_index`, `local_port_num`,
  `local_ifindex`, CDP `ifindex`, and `device_index`, including
  protocol-prefixed copies preserved in neighbor details.
- Add regression coverage based on a production-observed LLDP `remote_index`
  change while retaining comparison of semantic protocol fields such as
  `port_id_subtype_id`.
- Add executable `scripts/lrun-diff` for the deployed primary configuration. The
  launcher preserves the operator's current working directory so relative
  `--file` paths retain the documented `lldp-runner diff` semantics.

## 0.30.1 - 2026-08-27

- Fix `lldp-runner diff` host pairing performance on large inventories by
  precomputing normalized host identity evidence and using reverse indexes for
  physical, management-address, and name candidate lookup.
- Remove the accidental all-hosts Cartesian identity scan that could pin one CPU
  for many minutes during both macro and selected-host comparisons while
  preserving reciprocal uniqueness, evidence-tier ordering, and physical
  conflict safeguards.
- Add regression coverage that verifies physical identity normalization occurs
  once per host rather than once per possible A/B host pair.
- Document that 0.30.1 fixes the 0.30.0 quadratic matcher while selected
  `discovery.json` files are still loaded in memory for comparison.

## 0.30.0 - 2026-08-27

- Add `lldp-runner diff` for read-only comparison of two finalized
  `discovery.json` data sets, defaulting to latest versus previous.
- Add `--latest`, `--previous`/`--prior`, `--oldest`, repeatable `--runid`, and
  repeatable `--file` source selection with ordered A/B semantics.
- Resolve history aliases from timezone-aware completion metadata, preferring
  small `run.json` files so large historical discovery documents are not loaded
  merely to rank run history.
- Add one-to-one cross-run host pairing using physical identity, management
  addresses, then normalized name evidence, with explicit uncertain identity
  handling instead of guessing across conflicting physical evidence.
- Add macro host and learned-neighbor comparison, host-specific learned and
  `observed_by` neighbor comparison, volatile-field normalization, durable stack
  member matching, and possible-reboot uptime reporting.
- Add terminal tables with existing color policy, stable `Result:` status lines,
  exit codes for differences/errors/ambiguity/unavailable comparisons,
  `--changes-only`, and machine-readable diff JSON schema version 1.
- Add scope/provenance warnings using discovery metadata plus `run.json` config
  file and seed metadata when available.
- Add [`docs/DIFF.md`](docs/DIFF.md) with source-selection, identity evidence,
  normalization,
  output, JSON, large-file, and maintenance-workflow details.

## 0.29.8 - 2026-08-27

- Add [`docs/NAMES.md`](docs/NAMES.md) as the operator reference for seed, DNS,
  learned-neighbor,
  SNMP, and output name/address handling.
- Document intentional alias-based host folding, `preferred_name` presentation
  semantics, per-run host IDs, and the possibility that different devices using
  one duplicated name can be consolidated into one logical host.
- Recommend unique device names across the discovery scope and document
  `discovery.json` evidence operators can compare when reviewing suspected name
  collisions.

## 0.29.7 - 2026-08-27

- Rename the top-level project license from `LICENSE` to
  [`LICENSE.md`](LICENSE.md) and keep
  package metadata, README links, and documentation checks synchronized.
- Add executable `scripts/md-to-html.sh` for recursively publishing project
  Markdown as standalone HTML in a flat web directory with rewritten local
  Markdown links and a generated documentation index.
- Name HTML generated from subdirectories with hyphenated path prefixes, such
  as `docs/CLI.md` -> `docs-CLI.html`; nested path components are flattened in
  the same order.

## 0.29.6 - 2026-08-27

- Add [`docs/INSTALL.md`](docs/INSTALL.md) as the authoritative installation
  reference and reduce
  README installation content to a concise link, avoiding duplicated shared-use
  guidance.
- Rename `scripts/lldp-runner.env.example` to `scripts/example.private` and
  combine the launcher environment examples with a shared-install profile that
  lets the configured maintainer synchronize uv while operators use `--no-sync`.
- Add a copy/paste Ubuntu 24.04/26.04 LTS shared-install walkthrough covering
  group/service-account creation, operator membership, centralized uv/Python,
  source extraction, runtime permissions, config validation, and systemd timers.

## 0.29.5 - 2026-08-27

- Rename `scripts/setup-shared.sh` to `scripts/shared-setup.sh` for consistent
  noun-first operator helper naming.
- Add `scripts/svc-setup.sh` and `scripts/svc-remove.sh` to install/remove
  systemd discovery and maintenance services/timers for shared deployments.
- Default scheduled discovery to every four hours and daily clean/purge, with
  up to ten minutes of stable randomized timer delay and retention of 12 output
  directories (`latest` plus 11 additional runs).
- Install a systemd-tmpfiles rule for `scratch_root` so volatile paths such as
  `/dev/shm/lldp-runner` are recreated after reboot with the configured service
  user/group and `2775` permissions.

## 0.29.4 - 2026-08-27

- Add [`docs/PLAN.md`](docs/PLAN.md), an operator-oriented enterprise planning
  guide showing a
  scalable approach to ownership boundaries, query policy, classification,
  credential profiles/rules, evidence rules, tagging, and staged rollout.
- Document DefaultV2 as a simple default credential with narrow WTI, power, and
  Palo Alto exceptions, plus a seed-credential overlay example for special
  `ExceptionV3` devices.
- Add the planning guide to the README/documentation invariants so future
  releases keep the reference discoverable and terminal-readable.

## 0.29.3 - 2026-08-26

- Add executable `scripts/lrun-version` and `scripts/lrun-explain` launchers for
  the `version` and `explain-target` operator commands.
- Make `explain-target` read-only with respect to runtime storage and SNMP
  secrets: it no longer resolves/probes writable runtime paths and uses optional
  credential-policy loading so profile/rule selection can be explained without
  requiring community/auth/privacy secret values.
- Remove upper version caps from Python, gufo-snmp, pytest, Ruff, Ty, and
  uv_build declarations while retaining their existing minimum versions.
- Update `scripts/shared-setup.sh` to keep the former shared-site defaults as
  commented examples and use the requested development defaults for group,
  persistent root, scratch root, and shared uv Python directory.

## 0.29.2 - 2026-08-26

- Fix `lldp-runner watch` terminal teardown so both `q` and Ctrl-C erase the
  final dashboard/footer row and return the cursor to column zero before the
  shell prompt is restored. This prevents stale watch controls from remaining
  to the right of the prompt in terminals/SSH sessions that retain the curses
  screen contents.

## 0.29.1 - 2026-08-26

- Added [`docs/CREDS.md`](docs/CREDS.md), an operator-focused explanation of
  managed-device
  eligibility, normal credential policy, per-seed overlays, attempt ordering,
  success/failure behavior, resume handling, and safe credential provenance.
- Set uv project `link-mode = "copy"` so shared deployments do not depend on
  package-cache hardlinks/symlinks owned by the account that performed the sync.
- Expanded README installation guidance for centrally managed `/opt/lldp-runner`
  deployments with a shared uv-managed Python under `/opt/shared/python`.
- Added `scripts/setup-shared.sh` to prepare dedicated persistent/scratch roots
  with trusted-group ownership, setgid inheritance, and default POSIX ACLs when
  available; documented `umask 0002` as the fallback for environments without
  ACL support.
- Added `configs/conf.d/shared-paths.toml.example` and now ignore
  `scripts/.private` so shared site launcher settings are less likely to be
  committed accidentally.

## 0.29.0 - 2026-08-26

- Add repeatable `run --seed-credential-file FILENAME` overlays for protected
  `.csv` and `.json` inputs. Credential files never create discovery seeds;
  they only modify authentication attempts for matching explicit run seeds.
- Support ordered `prefer` and `exclusive` per-seed credential strategies. Rows
  may reference an existing configured credential profile or supply one direct
  SNMPv2c/SNMPv3 authPriv credential. `prefer` falls through to ordinary
  address/name/default credential policy; `exclusive` does not.
- Rename the operator-facing seed credential identifier to `credential_label`.
  Labels are optional reporting metadata, have no uniqueness requirement, and
  are never used as internal keys or profile selectors.
- Add strict first-release seed credential CSV parsing with the documented
  11-column schema, comment/blank-line handling, whitespace trimming, and file
  order as attempt order. JSON uses matching keys plus optional informational
  `source_line`; array order remains authoritative. Flexible CSV headers remain
  intentionally deferred to a future common CSV-input implementation.
- Keep direct seed credentials ephemeral: literal secrets are rejected from
  unsafe world-readable/world-writable files and are never persisted to SQLite,
  run/discovery JSON, generated CSV, trace output, or logs. Resume requires the
  applicable credential overlay again instead of checkpointing plaintext
  secrets.
- Log unmatched seed credential records at WARN activity level only and emit one
  INFO activity record with matched/unmatched counts when a credential file is
  active. These overlay diagnostics are intentionally suppressed from stderr.
- Bump `discovery.json` to schema version 5. Host/error credential provenance
  now
  distinguishes `seed-direct`, `seed-profile`, and `policy-profile`, carries the
  optional `credential_label`, and supports the `direct` credential-result
  value.

## 0.28.1 - 2026-08-26

- Expand `get-neighbors --trace`/`--tracefile` from SNMP-only diagnostics into a
  complete network trace of OS resolver operations, ICMP probes, and logical
  SNMP requests/responses. Resolver entries identify `getaddrinfo`,
  `gethostbyaddr`, and `getfqdn` calls and returned values without claiming
  packet-level DNS visibility through NSS.
- Trace concrete raw/system ICMP attempts with address family, backend,
  sequence,
  timeout, explicit reply/no-response/error results, and RTT when available. In
  automatic mode, raw-backend failure and system-ping fallback are both visible.
- Add a `TRACE SUMMARY` footer with resolver, ICMP, and logical SNMP operation
  counts plus total elapsed monotonic time.

## 0.28.0 - 2026-08-26

- Add `get-neighbors --trace` for operator-readable logical SNMP query/response
  diagnostics on stderr. Traces identify known MIB objects/tables and numeric
  OIDs, include every returned varbind, explicitly mark `NO RESPONSE`, safely
  normalize binary/control-bearing values, and redact known credential secrets.
- Add `get-neighbors --tracefile FILENAME`. Supplying the filename alone enables
  tracing to a newly truncated file; combining it with `--trace` fans identical
  trace output to both stderr and the file while normal inspection output stays
  on stdout. Trace destinations are preflighted before device network activity.
- Add the non-single-instance `scripts/lrun-purge` operator launcher for the
  `/opt/lldp-runner/config.toml` deployment convention.

## 0.27.0 - 2026-08-26

- Add schema-versioned `run.json` provenance to completed `lldp-runner run`
  outputs. It records run ID/status/timing, the starting OS account, sanitized
  CLI attributes, stdin/resolved seed inputs, recognized non-secret environment
  inputs, configuration-file provenance, and a resume-aware invocation history.
- Redact credential-bearing CLI and `--set` values as `<redacted>` before run
  provenance is written. `output.run_json_config_log = false` suppresses
  resolved primary/include/conf.d pathname detail; `run --dry-run` creates no
  `run.json`.
- Add credential-free `lldp-runner purge` for finalized output retention. The
  default keeps `latest`; `--keep N` keeps latest plus N additional recent
  output directories, and `output.purge_keep` supplies the unattended default
  (0).
- Rank purge retention by `run.json` completion time, then
  `discovery.completed`, then `discovery.generated`, then the oldest available
  filesystem mtime among run.json, discovery.json, and the output directory.
  Missing/malformed files and timestamps safely fall through to the next source.
- Add `--dry-run` to both `clean` and `purge` so cron/systemd retention policies
  can be previewed using the exact normal selection logic without deleting data.

## 0.26.0 - 2026-08-26

- Add `lldp-runner version` as an output-equivalent subcommand form of
  `lldp-runner --version`; it bypasses configuration and credentials.
- Add credential-free `lldp-runner clean` run-history maintenance. The default
  and `--all` clean persistent and scratch history while retaining the newest
  run plus `current`/`latest` targets; `--scratch` limits cleanup to scratch,
  and `--scratch --all` has the same all-area behavior as `--all`.
- Make scratch cleanup conservative on operator-selected roots by removing only
  recognizable LLDP-Runner run artifacts and leaving unrelated children alone.
- Add the non-single-instance `scripts/lrun-clean` operator launcher for the
  `/opt/lldp-runner/config.toml` deployment convention.

## 0.25.5 - 2026-08-26

- Add `configs/conf.d/custom-inventory-csv.toml.example`, which writes
  `inventory.csv` from the reusable `seeds` row source with operator-friendly
  hostname, address, platform, neighbor, and tag headers.
- Allow `source = "seeds"` custom CSV reports to select fixed `hosts.*`
  presentation fields. Seed rows already have one-to-one managed-host context,
  so this adds useful inventory projections without weakening row-grain safety.

## 0.25.4 - 2026-08-25

- Add an opportunistic one-column right watch inset to complement the existing
  left inset. Both borders are used when losing two content columns preserves
  metric/worker density and truncation behavior; otherwise the right border is
  omitted before useful information is sacrificed.

## 0.25.3 - 2026-08-25

- Add an opportunistic one-column left inset to `lldp-runner watch`. The margin
  is used only when it preserves metric density, worker view/row count,
  abbreviation state, and existing truncation behavior.
- Fill unused leading positions in fixed-width worker batch/size fields with
  `.` characters, while retaining `#` overflow markers for values that exceed
  their field budget.
- Raise the active-scoreboard stale floor from 10 to 15 seconds while retaining
  the larger-of-three-scoreboard-intervals rule. This reduces transient stale
  indications without weakening detection for slower configured publication
  intervals.

## 0.25.2 - 2026-08-25

- Refine the `lldp-runner watch` top line on wide terminals: center a neutral
  `STATE =` label, color only the run-state value, keep freshness/stale detail
  on the right, and add a blank row before Started/Elapsed/Plan when height
  permits.
- Give worker cells invariant per-mode field budgets so changing batch IDs or
  batch sizes cannot resize the worker grid. Values that exceed a compact field
  budget render explicit `#` overflow markers instead of moving columns.
- Spend tall-screen surplus height inside the worker grid. The renderer can
  distribute blank rows between worker rows, including one blank row between
  every full-grid row on a representative 126x55 terminal, while constrained
  terminals remain compressed and non-scrolling.
- Remove the redundant `Worker summary:` aggregate line from summary mode;
  worker totals remain on the section headline and summary detail is reserved
  for attention/error and changed-worker information.
- Add the interactive `h` help screen with concise definitions for every watch
  metric plus worker batch/size and configured-versus-effective worker-plan
  terminology. Any ordinary key returns from help to the live dashboard.
- Add the `h help` hint to the watch footer while retaining `m` view cycling,
  `q`/Ctrl-C exit, requested/effective worker view, and terminal geometry.

## 0.25.1 - 2026-08-25

- Make `lldp-runner watch` use spare terminal height for section spacing while
  retaining a compressed no-scroll layout when rows are constrained.
- Pad worker cells to a common per-frame width so worker columns stay aligned
  horizontally and vertically across full, compact, and heatmap views.
- Keep the watch footer on the bottom row when space permits and include the
  live terminal geometry after the worker-view detail, for example
  `worker-view auto->full (120x44)`.
- Add the interactive `m` key to cycle worker views in the stable order
  `auto -> full -> compact -> heatmap -> summary -> auto`; resize-responsive
  behavior continues whenever `auto` is selected.
- Give BUSY workers a distinct blue hue from dashboard heading/metric colors in
  both dark and light built-in palettes, with basic-color fallbacks.

## 0.25.0 - 2026-08-25

- Add a native `lldp-runner watch` interactive dashboard that reads the current
  structured scoreboard directly instead of repeatedly spawning `status`.
- Add `--worker-view auto|full|compact|heatmap|summary`. Auto responds to
  terminal resize events and selects the richest no-scroll layout that fits.
  Fixed views remain fixed while usable and explicitly warn when abbreviated.
- Keep full worker state words in every individual-worker view. Full mode shows
  worker/batch/size detail, compact keeps worker/state/size, and heatmap keeps
  worker/state while allowing 64+ workers to fit practical terminals.
- Add semantic watch highlighting for changed counters and worker records
  without transition annotations. BUSY, IDLE, DEAD, and unexpected states
  receive distinct roles while worker positions remain stable by worker ID.
- Detect stale active scoreboards after the larger of 10 seconds or three
  configured scoreboard intervals. Stale dashboards mute ordinary colors to
  grayscale while strongly emphasizing the literal `*** STALE ***` marker.
- Add dark-background and light-background watch palettes, `terminal.color`
  (`auto` or `never`), `terminal.palette` (`dark` or `light`), and watch CLI
  overrides `--palette` and `--no-color`. `NO_COLOR` remains authoritative.
- Add `scoreboard_schema = 1` to `scoreboard.json` as a versioned
  live-monitoring contract independent from `discovery.json` schema version 4.
- Make `status` and `watch` share current-scoreboard path resolution, disable
  the credential subsystem entirely, and avoid writable-directory probes so a
  read-only operator account can monitor an existing scoreboard.
- Add `scripts/lrun-watch` for `/opt/lldp-runner` deployments and document the
  dashboard, palettes, worker layouts, staleness behavior, and terminal
  fallback.

## 0.24.1 - 2026-08-25

- Add six operator-provided Bash launchers under `scripts/`: `lrun-checkconfig`,
  `lrun-dryrun`, `lrun-get`, `lrun-run`, `lrun-seedrun`, and `lrun-show`.
- Preserve the launchers' supplied `/opt/lldp-runner` command defaults, optional
  `scripts/.private` sourcing, argument forwarding, and per-script
  single-instance behavior.
- Document each launcher and call out that its fixed paths and run-policy
  arguments are deployment examples that operators should review before use.

## 0.24.0 - 2026-08-25

- Add source-aware timestamps to `get-neighbors` and `show-neighbors` table,
  detail, and CSV output. Human timestamps use `YYYY-MM-DD HH:MM:SS` in the
  configured `[time].timezone` and are right-aligned on the title line.
- Make `get-neighbors` use the most recent successful SNMP access time when
  available; results without successful device access use one captured
  result-finalization time. Rename its first CSV metadata field from `status`
  to `state` and append `timestamp` to that line.
- Make `show-neighbors` use persisted `discovery.generated` provenance. Missing
  or unusable source timestamps render as `timestamp=unknown` in CSV and
  `(json unknown-time)` in terminal output; filesystem mtime/current time are
  never substituted.
- Replace duplicated hard-coded terminal palettes with one shared semantic
  color layer. Add validated `[terminal]` color settings while preserving the
  existing colors as defaults, retaining TTY-only ANSI behavior and `NO_COLOR`.
- Add `configs/conf.d/terminal-colors.toml.example` and document terminal color
  roles, supported named colors, timestamp provenance, and timezone conversion.
- Fix `show-neighbors --detail` so it receives the effective configuration when
  rendering neighbor tables instead of raising `NameError` when neighbors are
  present.
- Keep `discovery.json` schema version 4; this release changes presentation and
  configuration only, not the persisted discovery document contract.

## 0.23.0 - 2026-08-25

- Add subtype-aware remote LLDP Port ID decoding for both LLDP-MIB and
  LLDP-V2-MIB. Port subtype names and numeric subtype IDs are preserved in
  neighbor details alongside the decoded Port ID and advertised port
  description.
- Decode binary MAC-address Port IDs to canonical colon-separated MAC text
  instead of the generic `hex:` representation. Network-address Port IDs use
  the same safe structural decoding approach.
- Bump `discovery.json` to schema version 4 for the expanded LLDP/LLDPv2
  neighbor-detail contract.
- Add `output.neighbor_local_width` and
  `output.neighbor_remote_port_width`, both defaulting to 18 columns.
- Share one bounded dynamic neighbor-table width planner between
  `get-neighbors` and `show-neighbors`; Local and Remote Port may expand when
  longer values fit while preserving a readable Neighbor column.

## 0.22.0 - 2026-08-25

- Rename the standalone `checklldp` command to `get-neighbors` and the
  standalone `showlldp` command to `show-neighbors`. The previous executable
  names are no longer installed.
- Rename `lldp-runner inspect` to `lldp-runner get-neighbors` and
  `lldp-runner show` to `lldp-runner show-neighbors` without compatibility
  aliases.
- Keep internal inspection terminology where it describes the reusable
  single-device probing implementation rather than a command name.
- Update current CLI help, documentation, examples, comments, generated
  configuration guidance, and tests to the new command vocabulary.
- Document the operational distinction prominently: `get-neighbors` actively
  probes one device with ICMP/SNMP as applicable, while `show-neighbors` reads
  finalized `discovery.json` data and disables the credential subsystem.
- Replace command-derived phrases such as `checklldp-style neighbor columns`
  with implementation-neutral `single-device neighbor columns` wording.

## 0.21.0 - 2026-08-25

- Bump `discovery.json` to schema version 3; rename
  `errors[].final_device_status` to `errors[].final_state` and normalize every
  non-null final-state value to lowercase at the canonical JSON boundary.
- Rename `unknown-devices.csv` `discovered_connections` to
  `observed_by_neighbors`, using the same canonical flattened inbound-neighbor
  formatter as `hosts.csv`.
- Add named `[output.custom_csv.<name>]` reports with explicit row sources for
  hosts, stack members, reusable seeds, unknown devices, and errors.
- Add a bounded custom field registry supporting existing fixed-CSV presentation
  fields plus approved `json.host`, `json.member`, `json.error`, and
  `json.discovery` fields.
- Support ordered custom columns, optional header labels, and controlled
  `lower`, `upper`, `origin`, join, and compact-JSON transforms while rejecting
  arbitrary expressions and ambiguous cross-row-source fields.
- Make custom reports participate in atomic output, draft/final publication,
  `write_empty_csv`, aggregated empty-file INFO logging, and stale-output
  cleanup during resumed finalization.
- Make each custom CSV `columns` list a configuration replacement list across
  includes/`conf.d`, so later definitions replace rather than append schemas.
- Add [`docs/CUSTOM-CSV.md`](docs/CUSTOM-CSV.md) and regression coverage for
  all five row grains,
  JSON-only rendering, transforms, validation, precedence, and empty-file
  policy.

## 0.20.0 - 2026-08-25

- Make all five fixed CSV outputs pure projections of the canonical discovery
  document. After that document is assembled, CSV rendering no longer queries
  SQLite state, aliases, topology edges, or errors.
- Add a reusable fixed-CSV writer that accepts a parsed schema-v2 discovery
  document, enabling post-run CSV reproduction without a `StateStore`.
- Add an end-to-end JSON-only replay regression that closes SQLite state and
  reproduces `hosts.csv`, `stack-members.csv`, `seeds.csv`,
  `unknown-devices.csv`, and `errors.csv` byte-for-byte from `discovery.json`.
- Remove the redundant `snmp_status` column from `stack-members.csv`; logical
  lowercase `state` remains repeated on each physical-member row.
- Rename unknown-device inbound chassis aggregates to `observed_chassis_ids`,
  `observed_chassis_id_subtypes`, and `observed_chassis_id_subtype_ids` so they
  are distinct from the host-level canonical `chassis_id`.
- Derive `unknown-devices.csv` protocol aggregation from canonical
  `observed_by_neighbors[].protocols[]`, using LLDP-Runner's stable protocol
  ordering rather than independently reading raw edge strings.
- Document the JSON-first output boundary as the architectural prerequisite for
  a future custom CSV field/projection registry.

## 0.19.0 - 2026-08-25

- Bump `discovery.json` to schema version 2 and make `hosts[].state` a
  canonical lowercase value while keeping internal SQLite workflow states
  uppercase for coordinator/state-machine logic.
- Reconcile direct fixed-CSV projections with JSON key names: rename
  `primary_name` to `preferred_name`; rename stack member `stack_member`,
  `member_name`, and `member_description` to `member_number`, `name`, and
  `description`; rename seeds `seed`/`query_target` to
  `preferred_name`/`queried_as`; and rename errors `error_category` to
  `category`.
- Replace `seeds.csv` `status` with direct lowercase `state`, and remove the
  redundant `hosts.csv` `snmp_status` column.
- Generate reusable seed identity/state fields from the same canonical host
  records written to `discovery.json`, reducing parallel SQLite/JSON naming
  drift. The previous seeds.csv schema is intentionally no longer accepted as
  input.

## 0.18.2 - 2026-08-24

- Right-size seed-only (`discovery.max_devices = "auto"`) execution after seed
  resolution, using the number of READY seeds, configured worker/batch ceilings,
  and `snmp.max_outstanding_devices_per_worker`.
- Keep configured scheduler values immutable while deriving per-run effective
  worker and batch sizes; recursive discovery retains its configured values.
- Balance small known seed workloads so, for example, 10 READY seeds with 64
  workers and batch size 9 run as two workers with five-device batches instead
  of launching dozens of idle processes or claiming an uneven 9+1 first wave.
- Cap effective seed-only batch size at the worker's asynchronous outstanding
  device limit so an oversized configured batch cannot unnecessarily hoard work.
- Log the seed-only execution plan at INFO level for console/activity.log output
  and expose configured/effective scheduler values in both scoreboard formats.
- Add scheduler regression coverage for low seed counts, async-capacity limits,
  balanced dispatch, recursive-mode preservation, and scoreboard rendering.

## 0.18.1 - 2026-08-24

- Make `checklldp --csv --system-only` and its `--no-neighbors` alias emit only
  the two existing system metadata comment lines, with no unused neighbor CSV
  header or neighbor records.
- Add explicit required, optional, and disabled credential-loading modes so
  commands can declare whether the SNMP credential subsystem participates.
- Run `showlldp` / `lldp-runner show` with credentials disabled: do not parse or
  build credential/profile/rule configuration, synthesize runtime credentials,
  resolve credential secrets, or validate credential policy.
- Keep live discovery and inspection credential enforcement strict, while
  retaining optional credential-aware validation for dry-run/config workflows.
- Add regression coverage proving stored-data viewing succeeds with malformed
  credential policy and incomplete runtime SNMPv3 environment variables while
  network-capable configuration loading still rejects those conditions.
- Document credential-free stored-data viewing and comments-only system CSV
  behavior for operators and future read-only command implementations.

## 0.18.0 - 2026-08-24

- Add `[time].timezone`, defaulting to `eastern`, with `utc`, `local`, and IANA
  timezone names supported consistently across logs, summaries, persisted
  timestamps, workers, scoreboards, and run-ID time expansion.
- Add `paths.run_id_format`, preserving `%Y%m%d-%H%M%S-%Z` as the default while
  allowing safe literal text, documented `strftime` directives, and one optional
  `{counter}` token.
- Implement a stateless `{counter}` allocator that renders `00` through `99`,
  selects highest matching existing counter plus one across run/output/scratch
  namespaces, and fails before discovery if the next value would exceed `99`.
- Recommend `%f` high-precision timestamps when a counter namespace can exceed
  100 runs; reject unsafe path characters, unsupported directives, repeated
  counter tokens, and timestamp-only run-ID collisions.
- Preserve the existing reverse lexical resumable-run scan; two-digit counters
  sort correctly within one naming namespace, while documentation calls out that
  mixed historical naming formats are not inherently chronological.
- Add `showlldp` / `lldp-runner show --runid RUNID` to read
  `output/<RUNID>/discovery.json`, without requiring the ID to match the current
  naming format.
- Add mutually exclusive `showlldp` / `lldp-runner show --file FILENAME` for
  arbitrary discovery JSON. Relative paths start at the current working
  directory; absolute and `~`-expanded paths are supported.
- Keep alternate viewer inputs read-only and independent of SNMP, SQLite, and
  writable discovery storage, with traversal-like run IDs rejected as CLI usage
  errors.
- Expand configuration generation, CLI/architecture documentation, and
  regression
  coverage for timezone policy, run-ID allocation/exhaustion, lexical counter
  ordering, and alternate finalized-discovery sources.

## 0.17.0 - 2026-08-24

- Add read-only `lldp-runner show` and `showlldp` commands that search the
  latest finalized `discovery.json` without opening SQLite or sending ICMP/SNMP.
- Search `preferred_name` with case-insensitive Python regular expressions and
  beginning-of-string semantics; support exact `--id` selection and explicit
  ambiguous-match output containing host IDs and preferred names.
- Add repeatable `--key KEY:PATTERN` filters for top-level/dotted JSON host
  keys,
  including deterministic array/object flattening and AND composition.
- Add repeatable `--ipv4` and `--ipv6` filters with literal-prefix matching for
  partial addresses and numeric network-membership matching for CIDRs.
- Reject invalid regex, key, CIDR, address-family, and contradictory
  `--system-only`/`--neighbors` syntax as CLI usage errors.
- Add compact table, detailed terminal, CSV, and standalone host JSON renderers;
  standalone JSON preserves the original discovery host `id`.
- Default topology display to learned neighbors, falling back to `observed_by`
  only when no learned evidence exists; explicit `--neighbors learned` never
  falls back.
- Add `--neighbors [both|learned|observed_by]`, with a bare `--neighbors`
  selecting both directions and learned always listed before observed_by.
- Keep learned-only terminal columns compatible with `checklldp` and add
  aligned,
  right-labeled `Learned`/`Observed_by` sections with contrasting bold ANSI
  colors when a color-capable terminal is in use.
- Resolve observed_by neighbor management addresses through the observer
  `host_ref`, avoiding display of an address that the observer reported for the
  selected host itself.
- Add viewer documentation and regression coverage for query composition,
  neighbor direction/fallback, machine output, color behavior, and exit status.

## 0.16.1 - 2026-08-24

- Make file-log append behavior explicit by opening enabled activity logs with
  `mode="a"`; existing per-run or centralized log content is preserved.
- Report activity-log create/append-open failures with the configured pathname
  before discovery starts, allowing CLI error handling to place the message on
  standard error without a traceback.
- Add a narrow startup storage preflight for the exact scratch run directory,
  final timestamped persistent-output directory, and output-root symlink
  publication used by `latest`.
- Exercise create, fsync, atomic rename, and cleanup during output preflight,
  while removing a newly created final-output directory after a successful
  probe so incomplete runs do not look finalized.
- Keep normal write-time error handling because preflight cannot predict later
  disk-full, quota, permission-change, or remote-filesystem failures.
- Add regression coverage and operator/developer documentation for append
  semantics, early storage failure reporting, and preflight cleanup behavior.

## 0.16.0 - 2026-08-24

- Replace the stack-specific `output.write_empty_stack_members_csv` option with
  global `output.write_empty_csv=false`, applying the same default header-only
  CSV suppression policy to all five fixed-schema CSV reports.
- Add `output.log_alert_on_empty_csv=false`. When enabled, terminal snapshot
  generation emits one INFO log record listing enabled CSV reports omitted
  because they contained zero data rows; periodic RUNNING snapshots stay quiet.
- Keep each existing `output.write_*_csv` report enable switch independent from
  the global empty-report policy. Individually disabled reports are not included
  in empty-CSV alert messages.
- Add `logging.file=true` and `logging.filename="activity.log"` while retaining
  `logging.level` and `logging.console`. Console and file destinations are now
  independently configurable.
- Resolve relative logging filenames beneath the current timestamped run
  directory, allow absolute and `~`-expanded centralized destinations, and
  reject relative `..` traversal outside the run directory.
- Report `Activity log: disabled` in the terminal run summary when file logging
  is disabled, rather than printing a path for a file that was not created.
- Expand output, runtime, logging, generated-configuration, and documentation
  regression coverage for the new policies and path semantics.
- Configuration note: v0.15.0 files that explicitly set
  `output.write_empty_stack_members_csv` must replace it with
  `output.write_empty_csv`; the removed setting is intentionally not aliased.

## 0.15.0 - 2026-08-24

- Preserve logical stack identity while collecting physical stack-member
  inventory from ENTITY-MIB, including member number, ENTITY index, name,
  description, manufacturer, model, serial, and available revision fields.
- Use standards-first ENTITY-MIB containment for switch stacks: prefer a
  `stack(11)` container with contained `chassis(3)` members and conservatively
  recognize multiple sibling chassis rows when an agent omits a stack root.
- Keep `full` mode request-compatible by deriving member inventory from the
  existing complete ENTITY walk with no extra SNMP requests; make `auto` and
  `brief` target the structural/member instances needed after class discovery.
- Add synthetic multi-vendor regression coverage for Cisco Catalyst StackWise,
  Aruba CX VSF, and Juniper EX Virtual Chassis-style ENTITY-MIB layouts while
  retaining standards-based support for other conforming manufacturers.
- Add fixed-schema `stack-members.csv`, one physical member per row, enabled by
  default with repeated logical-host context and member-specific identity.
- Add `output.write_stack_members_csv` and
  `output.write_empty_stack_members_csv`; the default omits a header-only stack
  report when no switch stacks were discovered, while operators can force it.
- Leave stack-member `uptime_seconds` empty unless a true member-specific value
  is available; do not copy the logical stack SYSTEM-MIB uptime into each row.
- Add [`docs/PRECEDENCE.md`](docs/PRECEDENCE.md) as the detailed configuration,
  include/conf.d,
  environment, command-line, seed, and credential precedence reference.
- Add a `Runtime: <start> to <end> (duration: <N>s)` standard-output line
  immediately after `Status:` for each discovery invocation, including resumes.
- Expand feature-touched documentation, docstrings, comments, and tests for
  NetOps operators and future developers.

## 0.14.0 - 2026-08-24

- Add `snmp.entity_mib_mode` with `full`, `auto`, and `brief` values while
  retaining `collect_entity_mib` as the master ENTITY-MIB enable switch.
- Keep `full` as the default and preserve the v0.13.1 complete
  `entPhysicalEntry` walk and chassis-selection behavior for unchanged sites.
- Make `brief` walk only `entPhysicalClass`, discover the agent-assigned
  chassis/stack/module index, and retrieve manufacturer, model, and serial
  number for the selected physical entity.
- Make `auto` use existing SYSTEM-MIB manufacturer/description identity to
  choose either the brief field set or a network-device profile that also
  retrieves hardware, firmware, and ENTITY software revisions.
- Prefer a root physical entity when selective mode finds multiple candidates
  by querying only their `entPhysicalContainedIn` instances; fall back to
  deterministic class/index ranking for non-conforming agents.
- Add generated/example configuration guidance, operator/developer
  documentation, and regression coverage for all ENTITY-MIB query modes.
- Add [`docs/ABOUT.md`](docs/ABOUT.md) with the project elevator summary and
  include it in the
  release documentation width/link invariants.
- Expand docstrings and implementation comments in feature-touched source so
  future developers and Network Operations staff can follow inputs, outputs,
  calling behavior, and operational reasoning.
- Align the `uv_build` constraint with the uv 0.12.5 development environment
  and retain ruff, ty, and pytest as the declared release-validation toolchain.

## 0.13.1 - 2026-08-24

- Rename the SYSTEM-MIB collection metric from `basic` to `sys`. The broader
  `Timing ms: basic=...` value remains unchanged because it includes ICMP,
  inter-wave delay, SNMP session setup, and the SYSTEM-MIB query.
- Add `--system-only` with `--no-neighbors` as an alias to `inspect` and
  `checklldp`. The mode stops after the initial SYSTEM-MIB probe and does not
  query ENTITY-MIB, IF-MIB, LLDP, LLDPv2, or CDP.
- Add `inspection.collection_mode` to inspect JSON with values `full` or
  `system_only`. System-only JSON reports only the `sys` collection metric.
- Suppress neighbor tables/sections in system-only human output so an omitted
  neighbor query is not mistaken for a completed query that returned no peers.
- Update CLI, README, architecture documentation, comments, and regression
  coverage for the new terminology and diagnostic mode.

## 0.13.0 - 2026-08-24

- Add backend-neutral per-device SNMP collection metrics for `basic`, `entity`,
  `interfaces`, `lldp`, `lldpv2`, and `cdp` collector sections.
- Count SNMP variable bindings returned before collector filtering/grouping and
  record cumulative collector elapsed milliseconds without Gufo-specific hooks.
- Add a single `SNMP obj/ms:` line to the default and detail `checklldp` human
  views, using `section=objects/duration_ms` and color emphasis for numbers.
- Always include `collection_metrics` in `checklldp --json` after SNMP collector
  work; keep the compact inspection CSV unchanged.
- Add `snmp.report_metrics=false`. Full discovery collects/persists the same
  per-host telemetry only when enabled and then adds it under each host's
  `snmp.collection_metrics` in `discovery.json`.
- Add SQLite checkpoint migration/preservation for optional metrics so older
  v0.12 run state remains resumable.
- Update generated/example configuration and operator/developer documentation
  for metrics semantics, scope, and reporting behavior.

## 0.12.2 - 2026-08-24

- Replace the Apache License 2.0 with the Unlicense and release the current
  LLDP-Runner project into the public domain.
- Remove the earlier compilation/copyright restriction from the current
  `LICENSE` because it conflicts with an unrestricted public-domain
  dedication.
- Update README and release-invariant tests so package metadata and operator
  documentation describe the Unlicense consistently.
- Keep prior CHANGELOG entries unchanged as historical records of the license
  terms shipped by those older releases.

## 0.12.1 - 2026-08-24

- Add `origin` to the fixed `seeds.csv` schema between `credential_result` and
  `status`, using the same `seed` / `learned` provenance vocabulary as
  `hosts.csv`.
- Derive seed-inventory provenance from the current run's authoritative
  `is_seed` state. A managed device learned dynamically remains `learned` for
  that run.
- Treat every row reused from `seeds.csv` as an explicit seed in the later run,
  regardless of its prior `origin`; consequently a previously learned device is
  exported as `origin=seed` after it is supplied as new input.
- Advance the strict reusable seed-input contract to the current ten-column
  schema; prior headers are intentionally not accepted as legacy input.
- Update operator/developer documentation and regression coverage for the new
  fixed schema and run-relative provenance semantics.

## 0.12.0 - 2026-08-24

- Make `discovery.json` the complete structured discovery result by adding a
  top-level `schema_version` and structured `errors` collection alongside run
  metadata and host/neighbor records.
- Define discovery JSON schema version 1 so future post-run exporters can
  distinguish incompatible document structures and derive standard reports
  without reopening SQLite state.
- Preserve complete collected system details in JSON, including hardware and
  firmware revisions, even when a convenience CSV intentionally omits them.
- Remove `hardware_revision` and `firmware_revision` from the fixed
  `hosts.csv` schema because those columns are commonly empty or low-value for
  routine operator use.
- Add `[output]` booleans `write_hosts_csv`, `write_seeds_csv`,
  `write_unknown_devices_csv`, and `write_errors_csv`; all default to `true`
  and control only whether the corresponding fixed-schema CSV is generated.
- Keep `seeds.csv` and `errors.csv` as fixed contracts rather than making their
  fields, labels, or transformations operator-configurable.
- Remove stale CSV artifacts when a resumed run disables a standard view and
  finalize only the output files enabled by the completing invocation.
- Update generated/example configuration and operator/developer documentation
  to describe the JSON contract and fixed CSV enable/suppress controls.
- Defer post-run export, arbitrary additional CSV reports, configurable column
  labels, transformations, and filters to a later release.

## 0.11.3 - 2026-08-21

- Add a `docs/` documentation set with [`CLI.md`](docs/CLI.md),
  [`ENVIRONMENT.md`](docs/ENVIRONMENT.md), and
  [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) as operator/developer references for
  the current command
  line, environment variables, concept of operations, and internal architecture.
- Rewrite the parent [`README.md`](README.md) as a concise operator entry point
  linking to
  the detailed references while preserving installation, configuration, inspect,
  discovery, guardrail, output, and development guidance.
- Reflow [`README.md`](README.md), [`CHANGELOG.md`](CHANGELOG.md), and the new
  documentation files to an
  80-column maximum for terminal readability.
- Add the project `LICENSE` with the requested Robert Patrick copyright and
  AI-assistance/compilation notice followed by the standard Apache License 2.0
  text, and update package metadata to use that license file.
- Keep this release documentation-focused with no intended discovery,
  inspection, state, or scheduling behavior changes.

## 0.11.2 - 2026-08-21

- Make no-argument `generate-config` create `./config.toml` when run from
  `~/lldp-runner`, `/opt/lldp-runner`, or `/etc/lldp-runner` and no primary
  `config.toml` already exists; otherwise retain `./lldp-runner-config.toml`.
- Reformat generated TOML for approximately 80-column readability, including
  wrapped explanatory comments and one-item-per-line formatting for long lists
  such as classification patterns.
- Add two commented tagging-rule examples to generated/example configuration so
  operators can see managed-device and managed-endpoint tag syntax without
  enabling site policy by default.
- Add maintainability comments and regression coverage for destination
  selection, safe existing-file behavior, generated TOML parsing, line wrapping,
  list formatting, and tagging examples.

## 0.11.1 - 2026-08-21

- Change human `inspect`/`checklldp` timing labels to `Ping RTT ms:` and `Timing
  ms:`, declaring milliseconds once in the field title instead of repeating `ms`
  after every numeric value.
- When ANSI color is active, emphasize only numeric timing/RTT assignment values
  so measurements stand out while labels, addresses, separators, and non-numeric
  probe states remain visually stable.
- Keep JSON timing output unchanged, including the `timings_ms` object and
  per-probe `rtt_ms` fields; CSV behavior is unchanged.
- Add maintainability comments and regression coverage for timing-unit
  placement, color emphasis, redirected/`NO_COLOR` output, and the unchanged
  JSON contract.

## 0.11.0 - 2026-08-21

- Add first-class single-device `lldp-runner inspect SEED` probing plus the
  packaged `checklldp` console entry point for quick LLDP/CDP troubleshooting
  and preflight checks before a full discovery run.
- Reuse LLDP-Runner DNS, policy, credential, ICMP, SNMP client,
  SYSTEM/IF/ENTITY, LLDP/LLDPv2/CDP, sanitation, and neighbor-merge components
  without creating SQLite state, run directories, scoreboards, snapshots, or
  recursive neighbor work.
- Add four stdout formats: terminal-aware abbreviated `table` (default),
  scrolling `detail`, compact comment-prefixed `csv`, and rich `json` aligned
  with `discovery.json` host/neighbor concepts. Human formats use ANSI color
  only on a TTY and honor `NO_COLOR`; CSV/JSON never contain color escapes. No
  inspect renderer emits blank spacer lines.
- Permit an explicitly named inspect target outside `discovery.boundaries` while
  reporting the out-of-bound condition; explicit query-policy deny rules remain
  authoritative and prevent ICMP/SNMP traffic.
- Add inspect `--dry-run`, which performs DNS and policy/credential selection
  only and never instantiates the ICMP or SNMP backends.
- Expose applicable runtime overrides to inspect/checklldp, including
  `--config`, repeatable `--set`, runtime SNMP v2c/v3 credential options,
  `--snmp-timeout`, `--per-device-rps`, and `--log-level`; discovery-only
  controls such as workers, limits, seed ordering, persistence roots, and resume
  are intentionally excluded.
- Allow `checklldp` options before or after the positional target, and allow
  inspect-local overrides after the `lldp-runner inspect` subcommand while
  preserving global `--set` values supplied before it.
- Report individual ICMP RTTs and millisecond DNS/query/basic/detail/total
  elapsed timings in human and JSON inspection output. A responding SNMP device
  with zero neighbors is successful; SNMP failure still prints available
  DNS/ICMP diagnostics and exits nonzero.
- Skip persistent/scratch auto-path resolution for inspect because the command
  is stdout-only; unrelated discovery-output permissions cannot block a
  diagnostic probe.
- Expand source docstrings/comments, CLI help, README, generated/example
  configuration query-policy guidance, and regression coverage for inspection
  behavior and output contracts.

## 0.10.1 - 2026-08-20

- Add a grep-friendly `origin` column to `hosts.csv` immediately after
  `snmp_sysname`.
- Emit exactly `seed` when the host identity was supplied as an input seed and
  `learned` when LLDP-Runner first obtained the identity through topology
  discovery.
- Keep origin as provenance rather than query state: a learned managed device
  remains `learned` after recursive polling succeeds.
- Document the new CSV field and add regression coverage for column ordering and
  both allowed values.

## 0.10.0 - 2026-08-20

- Add `discovery.seed_order = "input" | "sorted" | "random"` plus
  `--seed-order`, with ordering applied after seed-source consolidation and
  authoritative DNS/alias identity de-duplication.
- Add optional `discovery.shuffle_key` / `--shuffle-key`; explicit keys produce
  reproducible random order, while an omitted key is generated once per new run
  and persisted so pause/resume retains the same sequence.
- Persist seed scheduling rank in SQLite and prioritize READY seeds globally by
  that rank before normal cohort-based recursive neighbor work, so worker cohort
  assignment does not defeat requested input/sorted/random seed ordering.
- Add `discovery.limit_behavior = "pause" | "complete"` plus `--limit-behavior`.
  The default `pause` retains resumable `LIMIT_REACHED`; `complete` finalizes
  persistent output as `COMPLETED_LIMIT` with completion/limit metadata and is
  not selected for automatic resume.
- In `max_devices = "auto"` seed-only sampling mode, apply `max_hosts` to
  discovered non-seed identities rather than the explicit seed inventory,
  allowing large switch inventories to serve as sampling points without
  consuming the sample threshold before polling starts. Recursive mode retains
  the historical all-host guardrail semantics.
- Treat the seed-only host threshold as reached at the configured count while
  documenting that concurrent in-flight batches may overshoot it; an exact
  downstream sample-size feature remains separate from the discovery stopping
  threshold.
- Add `LLDP_RUNNER_SEED_ORDER`, `LLDP_RUNNER_SHUFFLE_KEY`, and
  `LLDP_RUNNER_LIMIT_BEHAVIOR` environment overrides and update
  generated/example configuration guidance, README examples, source
  docstrings/comments, and regression coverage.

## 0.9.0 - 2026-08-20

- Add `discovery.max_devices = "auto"` / `--max-devices auto` as explicit
  seed-only discovery: query every unique seed, retain/classify/output learned
  neighbors, and never schedule discovered non-seed neighbors for SNMP.
- Resolve the auto effective managed-device count only after seed DNS/alias
  identity de-duplication; persist the runtime discovery mode/effective count in
  run metadata for diagnostics.
- Fail before worker startup when a finite positive `max_devices` is smaller
  than the de-duplicated managed seed inventory, with operator guidance to raise
  the limit, use zero/unlimited, or choose auto seed-only mode. Rejected
  initialization is marked `SEED_LIMIT_EXCEEDED` rather than left resumable.
- Interpret `discovery.max_devices = 0` / `--max-devices 0` as unlimited
  recursive managed-device discovery and `discovery.max_hosts = 0` /
  `--max-hosts 0` as unlimited identified-host retention.
- Keep `max_hosts` independent of `max_devices`; seed-only mode may still apply
  a finite host guardrail to large neighbor populations.
- Protect resumed auto/seed-only runs by suppressing pending non-seed recursive
  work left by a previous run mode, while preserving already completed/failed
  observations and all topology evidence.
- Expand `defaults.py`, CLI help, generated configuration comments, shipped
  example configuration, README, and source docstrings/comments to document the
  behavioral difference between finite, zero/unlimited, and auto limits for
  future operators and maintainers.

## 0.8.0 - 2026-08-20

- Add `src/lldp_runner/defaults.py` as the single operator-maintainable source
  for built-in runtime configuration defaults, with comments explaining
  dynamic/default behavior and site-local packaging intent.
- Allow partial TOML configuration: site configuration overlays built-in
  defaults instead of requiring every operational section/value to be present.
- Add automatic primary-config discovery when `--config` is omitted:
  `~/lldp-runner-config.toml`, `~/lldp-runner/config.toml`,
  `/opt/lldp-runner/config.toml`, `/etc/lldp-runner/config.toml`, then
  defaults-only operation. Explicit/`LLDP_RUNNER_CONFIG` paths remain
  authoritative and fail if missing.
- Preserve `@include` and recursive sibling `conf.d/**/*.toml` behavior whenever
  an actual primary configuration file is selected.
- Treat `discovery.boundaries` as a replacement list across fragments (like
  `address_preference`) so a generated/unlimited primary default cannot
  accidentally remain active beside a narrower site boundary.
- Define effective precedence as defaults -> TOML/includes/conf.d ->
  `LLDP_RUNNER_*` environment overrides -> repeatable `--set` -> dedicated CLI
  options. `--set` parses TOML values so booleans/numbers/lists retain type.
- Add global `--version` output and regression coverage requiring package
  `__version__` and `pyproject.toml` version to remain synchronized.
- Add `generate-config [FILENAME]`, defaulting to `./lldp-runner-config.toml`,
  with commented defaults, runtime guidance, credential examples, safe refusal
  to overwrite an existing file, and support for `--set`/`--snmp.version` when
  generating.
- Add `workers = "auto"`, resolving before discovery to `(os.cpu_count() or 1) *
  4`; set built-in cohort `batch_size = 9` and
  `snmp.max_outstanding_devices_per_worker = 24`.
- Set default discovery boundaries to unlimited IPv4/IPv6 (`0.0.0.0/0`, `::/0`)
  while using conservative built-in guardrails `max_devices = 10` and `max_hosts
  = 1000`.
- Add dynamic `persistent_root = "auto"`: use the first existing
  `~/lldp-runner`, `/opt/lldp-runner`, or `/var/lib/lldp-runner`; otherwise use
  the writable current directory. An existing-but-unwritable candidate is a hard
  error and is not silently bypassed.
- Add dynamic `scratch_root = "auto"`: try `/dev/shm/lldp-runner`,
  `/tmp/lldp-runner`, `/var/tmp/lldp-runner`, then `<persistent_root>/tmp`,
  safely falling through unavailable scratch candidates.
- Add lowest-priority default SNMP credential synthesis from `SNMPCOMM` or the
  complete `SNMPUSER`/`SNMPAUTH`/`SNMPPRIV` authPriv trio, plus global
  `--snmp.community`/`--community`, `--snmp.user`, `--snmp.auth`, `--snmp.priv`,
  and `--snmp.version` options. CLI credential tokens resolve as
  environment-variable names first and literal strings second.
- When both runtime v2c and v3 credentials exist, use `snmp.version` to choose
  primary/fallback. When only one exists, use a single credential with two
  attempts instead of a duplicate fallback identity. Explicit configured
  credentials/profiles suppress runtime defaults.
- Reject incomplete default SNMPv3 authPriv credentials and provide a clear
  no-credentials error for commands that require SNMP access. `status` and
  `pause` continue to load without credential-secret availability.
- Update the shipped example configuration, environment example, bootstrap
  guidance, README, and regression suite for the defaults-first workflow.
  One-off/non-recursive discovery remains intentionally deferred to a later
  release.

## 0.7.1 - 2026-08-20

- Fix periodic seed-inventory validation so transient managed-device states such
  as `READY` and `CLAIMED` do not create durable `missing_query_target` errors
  while a worker is still establishing the successful SNMP address.
- Self-heal stale `seed_inventory_validation/missing_query_target` records left
  by earlier draft snapshots when the host now has a valid `query_target` or is
  in a nonterminal state.
- Continue validating terminal seed rows: `COMPLETE` without a target remains a
  non-recoverable state-integrity error, while `FAILED`, `NO_QUERY`, and
  `OUT_OF_SCOPE` retain explanatory diagnostics when no target was recorded.
- Add aggregated `chassis_id` to `unknown-devices.csv` immediately between
  `capabilities` and `chassis_id_subtypes`, keeping the identifier alongside its
  subtype metadata.
- Add regression coverage for stale CLAIMED snapshot cleanup, completed-target
  cleanup, unknown-device Chassis ID output/column ordering, and maintainability
  comments/docstrings around both fixes.

## 0.7.0 - 2026-08-20

- Automatically load `conf.d/**/*.toml` adjacent to the primary `config.toml`,
  recursively and in deterministic lexical relative-path order.
- Keep explicit `@include` support and allow both relative paths resolved from
  the including file and absolute paths beginning with `/`.
- De-duplicate configuration files by resolved path so a fragment is merged only
  once even when it is both explicitly included and later encountered by
  automatic `conf.d` traversal.
- Preserve include-cycle detection separately from duplicate-file suppression,
  so recursive include loops remain configuration errors.
- Apply primary-file explicit includes first, then remaining automatic `conf.d`
  fragments, then the primary file itself so operator scalar settings in
  `config.toml` remain authoritative.
- Treat only filenames ending exactly in `.toml` as automatically active
  fragments; rename bundled examples to `.toml.example` so example policy is not
  activated merely by being present.
- Standardize all seed-directory documentation/examples on
  `/opt/lldp-runner/seeds.d/`.
- Add maintainability docstrings/comments and regression coverage for recursive
  lexical ordering, nested include de-duplication, absolute includes, inactive
  non-TOML files, and primary scalar precedence.

## 0.6.0 - 2026-08-20

- Remove support for legacy seed CSV input layouts; `.csv` seed inputs must use
  the current nine-column `seeds.csv` schema exactly.
- Add `[discovery] seed_dirs`, repeatable `--seed-dir`, and
  `LLDP_RUNNER_SEED_DIRS` inputs for recursively loading seed trees.
- Process recursive seed-directory files in deterministic sorted relative-path
  order and ignore hidden files/directories, `README*`, `*.disabled`, and
  `*.note` files case-insensitively.
- Parse non-CSV seed files as one target per line, ignoring blank/comment lines
  and discarding trailing annotation beginning with comma, semicolon, or hash.
  Standard input now uses the same text-line parser.
- Treat `.csv` files found through `--seed-file` or recursive seed directories
  as strict current-format reusable seed inventories, preserving `query_target`
  and all IPv4/IPv6 hints.
- Add clear operator errors for missing seed paths, non-directory `seed_dir`
  values, malformed UTF-8 text inputs, and unsupported CSV headers rather than
  allowing a traceback or partial legacy interpretation.
- Add maintainability docstrings/comments and regression coverage for recursive
  directory traversal, skip rules, deterministic parsing, inline comments,
  current CSV address hints, CLI/config/environment directory sources, and
  legacy CSV rejection.

## 0.5.1 - 2026-08-20

- Expanded `seeds.csv` to the stable nine-column seed inventory schema.
- Added fixed lowercase seed statuses: `complete`, `failed`, `no_query`,
  `out_of_scope`, and `pending` for nonterminal draft snapshots.
- Reusable seed input now consumes the prior `query_target` plus all IPv4/IPv6
  aliases instead of reading only the `seed` column; legacy seed CSVs remain
  supported.
- Added idempotent `missing_query_target` integrity errors and operator notes
  for every managed-device seed row without a target, with COMPLETE/no-target
  treated as a non-recoverable state inconsistency.
- Seed notes now carry recorded per-device error detail when available.
- Improved identity merging so successful COMPLETE query/credential metadata is
  retained when duplicate host identities are reconciled.
- Added source docstrings/comments and regression coverage for seed schema,
  legacy input, status normalization, address reuse, error reporting, and
  query-target-preserving identity merges.

## 0.5.0 - 2026-08-20

- Replace the direction-dependent single `neighbors` field in `discovery.json`
  with two explicit topology-evidence fields on every host: `learned_neighbors`
  and `observed_by_neighbors`.
- Replace the single `neighbors` column in `hosts.csv` with `learned_neighbors`
  and `observed_by_neighbors`, so a managed device that fails or is not polled
  still shows the parent device/interface that observed it.
- Define `learned_neighbors` as relationships learned directly by querying the
  current host's CDP/LLDP/LLDPv2 tables; define `observed_by_neighbors` as
  reciprocal/inbound relationships reported by other queried managed devices.
- Render protocol provenance deterministically as `[cdp]`, `[lldp]`, `[lldpv2]`,
  or combined tags such as `[cdp,lldp]`; JSON includes both the canonical
  `protocols` array and an explicit `protocol_tag` string on each relationship.
- Preserve interface perspective in JSON: for both fields, `local_interface`
  belongs to the current host record and `remote_interface` belongs to the
  neighboring/observing host.
- Keep `unknown-devices.csv` `discovered_connections` aligned with
  inbound/observed-by topology evidence.
- Add regression coverage for unpolled endpoint/unknown children, failed managed
  children, reciprocal JSON interface direction, and deterministic combined
  CDP/LLDP protocol tags.
- Add docstrings and maintenance comments around topology-direction rendering so
  Network Operations staff and future developers can understand why inbound and
  outbound evidence are intentionally kept separate.

## 0.4.1 - 2026-08-20

- Centralize SNMP textual OCTET STRING normalization in `lldp_runner.textutil`
  and use it across LLDP, CDP, SYSTEM-MIB, ENTITY-MIB, and IF-MIB collectors.
- Preserve valid printable Unicode while normalizing embedded TAB/CR/LF to
  spaces and preventing C0/C1 control characters or surrogate code points from
  entering discovery text.
- Treat invalid UTF-8 or byte-backed values containing embedded binary controls
  as printable `hex:aa:bb:...` strings; trailing NUL padding remains accepted
  for otherwise normal SNMP text.
- Decode LLDP/LLDPv2 chassis IDs according to their advertised subtype: binary
  MAC chassis IDs become canonical colon-separated MAC addresses, recognized
  network-address chassis IDs become IPv4/IPv6 text, and malformed/binary
  text-like chassis IDs fall back to printable hexadecimal.
- Add a final recursive JSON and per-cell CSV sanitation boundary so
  older/resumed state or future collector mistakes cannot write raw
  NUL/terminal-control bytes to formal output files.
- Add regression tests for the observed FLEXIDOME-style `00 07 5f 7b 66 34`
  chassis ID, binary LLDP MAC/network identifiers, valid non-ASCII Unicode, and
  all generated CSV files remaining free of embedded control characters.
- Expand docstrings and maintenance comments in the new sanitation path and
  touched collectors/output code so Network Operations staff can follow why and
  where values are normalized.

## 0.4.0 - 2026-08-19

- Reclassify provisional managed neighbors after DNS enrichment and before state
  insertion/scheduling, so an FQDN or address learned from DNS can apply
  explicit classification policy before recursive SNMP polling.
- Add multi-value rule syntax across credential, query-policy, classification,
  and tagging policy:
  - address rules accept `networks = ["CIDR", ...]`;
  - name rules accept `patterns = ["regex", ...]`;
  - evidence/tag rules accept `name_patterns = [...]` and `networks = [...]`;
  - `field_patterns` and `detail_patterns` values may be a regex string or a
    list of regex strings.
- Alternatives inside one list use OR semantics. Distinct evidence/tag condition
  types retain AND semantics. First-match-wins remains at the rule level for
  credential/query/classification rules; tagging rules continue to accumulate.
- Preserve v0.3.x singular `network`, `pattern`, and `name_pattern` syntax and
  scalar field/detail pattern values for backward compatibility.


## 0.3.2 - 2026-08-19

- Collect the LLDP-MIB and LLDP-V2-MIB remote Chassis ID subtype alongside the
  existing Chassis ID value.
- Preserve both `chassis_id_subtype_id` (numeric) and normalized
  `chassis_id_subtype` text (`chassis_component`, `interface_alias`,
  `port_component`, `mac_address`, `network_address`, `interface_name`, `local`;
  unknown numeric values become `unknown_<id>`).
- Expose both subtype forms as normalized `field_patterns` evidence for
  `classification.evidence_rules` and `tagging.rules`.
- Preserve protocol-specific subtype evidence under keys such as
  `lldp.chassis_id_subtype`, `lldp.chassis_id_subtype_id`,
  `lldpv2.chassis_id_subtype`, and `lldpv2.chassis_id_subtype_id`.
- Add both subtype values to neighbor `details` in `discovery.json` when
  advertised, and aggregate them into `unknown-devices.csv` review columns.
- Add regression coverage for LLDP/LLDPv2 subtype collection, protocol-evidence
  preservation, classification matching, tagging matching, and JSON output.

## 0.3.1 - 2026-08-19

- Fix `status` and `pause` to load configuration through the same recursive
  `@include`-aware loader used by `run`, `validate-config`, and
  `explain-target`.
- Honor included `[paths] scratch_root`, included `[resume] pause_indicator`,
  and normal environment overrides for operational commands.
- Keep full configuration/schema validation for `status` and `pause` while
  skipping only SNMP secret-availability checks, allowing operators to control
  runs started by cron/systemd without inheriting their credential environment.
- Remove the legacy lightweight TOML-only operational-settings reader that could
  not parse `@include` directives.
- Add CLI regression coverage for `status` and `pause` using settings supplied
  entirely by chained configuration fragments.

## 0.3.0 - 2026-08-19

- Add configurable `[output] chassis_id_name_fallback` modes `disabled`,
  `name_like`, and `any`; boolean `true`/`false` remain accepted as aliases for
  `name_like`/`disabled`.
- Use hostname-like LLDP/CDP chassis IDs as presentation-name fallbacks when the
  observed/discovered name is blank, while preserving raw `observed_name` and
  never using the fallback as a DNS/SNMP target.
- Preserve a case-sensitive chassis display value separately from the normalized
  chassis identity alias.
- Add accumulating `[[tagging.rules]]` with optional category, name regex,
  network CIDR, normalized evidence fields, and protocol-specific detail fields
  using AND semantics within each rule.
- Persist de-duplicated host tags in coordinator-owned SQLite so tags survive
  snapshots, pause/resume, and host-identity merges.
- Add `tags` arrays to `discovery.json` host records and a semicolon-separated
  `tags` column to `hosts.csv`.
- Add regression coverage for Windows-style chassis-name fallback, MAC rejection
  in `name_like` mode, `any` mode, tag accumulation, tag-rule conjunctions,
  included tag fragments, and output persistence.

## 0.2.0 - 2026-08-19

- Add first-match-wins `classification.evidence_rules` with AND semantics across
  any configured `name_pattern`, management-address `network` CIDR, normalized
  CDP/LLDP `field_patterns`, and protocol-specific `detail_patterns`.
- Preserve normalized protocol-specific CDP/LLDP/LLDPv2 evidence under
  namespaced detail keys such as `lldp.remote_description` and
  `cdp.remote_platform`.
- Add recursive `@include filename` configuration composition with relative-path
  resolution, deterministic merge order, nested include support, and
  include-cycle detection.
- Concatenate rule/pattern arrays across included files while allowing the
  including file to override scalar settings; `discovery.address_preference`
  remains a replacement-order list.
- Add validation and regression coverage for evidence-rule fields, evidence
  conjunctions, first-match ordering, nested includes, relative include paths,
  and include cycles.

## 0.1.2 - 2026-08-18

- Send the configured two ICMP wake-up probes before the first SNMP attempt to
  every candidate query address, not only the first preferred address.
- Do not repeat ICMP probes for primary retries or fallback credentials that use
  the same address.
- Respect `icmp.enabled = false` and `icmp.backend = "disabled"` without sending
  probe traffic.
- Record the probed IPv4/IPv6 address with each ICMP result so multi-address
  RTT/no-response data is unambiguous.
- Add regression coverage for IPv4 failure followed by an IPv6 alternate-address
  attempt and for disabled ICMP.

## 0.1.1 - 2026-08-18

- Fix TOML `[paths]` values being retained as plain strings instead of
  `pathlib.Path` objects.
- Add regression coverage for normal-mode resume lookup and run-path
  construction using TOML-configured roots.

## 0.1.0 - 2026-08-17

- Initial lldp-runner implementation.
