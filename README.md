# LLDP-Runner

LLDP-Runner is an SNMP-based CDP/LLDP network discovery tool for Network
Operations. It starts from operator-supplied seed devices, records neighboring
hosts, classifies those hosts, and can recursively query managed network devices
that are inside discovery scope and permitted by policy.

Version 0.36.0 introduced two explicitly selectable discovery backends:
`gufo` and `pysnmp`. Version 0.37.0 makes PySNMP the built-in default after
repeated production runs demonstrated complete collection, stable topology,
correct SNMPv3 and IPv6 behavior, and lower elapsed time. Gufo remains fully
supported through explicit selection. Select one backend through `snmp.backend`,
`LLDP_RUNNER_SNMP_BACKEND`, `--set`, or `--snmp-backend`; ordinary
configuration precedence applies. The selection is bound before discovery,
inherited unchanged by every worker, and persisted with the installed backend
version in run state and `run.json`.

The default change does not rewrite an explicit `snmp.backend = "gufo"`
setting. Before resuming a run that was started with Gufo, keep or add an
explicit Gufo selection. If the setting is omitted, the effective backend now
resolves to `pysnmp`; the immutable resume check rejects that mismatch before
discovery rather than converting or mixing the existing run.

A run never falls back between libraries or mixes their observations. Every
resume must resolve to the persisted backend; a missing or different backend is
rejected before discovery starts. The PySNMP implementation uses the validated
7.1 asyncio API, IPv4 and IPv6 transport targets, `retries=0`, deterministic
engine/dispatcher cleanup, backend-neutral values and failures, and the remote
SNMPv3 response security engine ID rather than the manager's local engine ID.
LLDP-Runner's established adaptive retry layer remains the sole retry owner.

Version 0.36.1 makes PySNMP SNMPv3 authPriv self-contained and fail-fast. The
runtime now installs `cryptography>=50.0`; the exact Linux release set pins
50.0.1. Before a PySNMP run or active single-device inspection can contact the
network, LLDP-Runner constructively verifies every AES-128/DES privacy cipher
that its reachable configured or direct seed credentials may use. A missing or
unusable local provider produces the sanitized
`snmp_backend_capability` error instead of a per-device authentication failure,
and it consumes no SNMP retry budget. SNMPv2c and Gufo runs do not perform this
crypto probe.

Version 0.36.2 uses cryptography's supported decrepit namespace for the local
AES-CFB capability probe. PySNMP 7.1.29 still accesses the former namespace
during its real RFC 3826 AES operation, so LLDP-Runner temporarily suppresses
only that package's exact `CryptographyDeprecationWarning` message from the
exact PySNMP AES module. SNMPv2c and DES routes do not install the filter, and
changed or unrelated warnings remain visible. A mixed run may perform one
run-scoped authPriv preflight because other reachable routes use SNMPv3, but no
cryptography operation is part of an SNMPv2c request.

Version 0.36.3 adds PySNMP-only SHA-256 authentication and AES-256 privacy.
`auth_protocol = "sha256"` maps to `USM_AUTH_HMAC192_SHA256`.
`priv_protocol = "aes256"` deliberately means PySNMP's common Reeder key
localization (`USM_PRIV_CFB256_AES`), also known as AES-256-Cisco;
`aes256-blumenthal` selects the distinct
`USM_PRIV_CFB256_AES_BLUMENTHAL` mapping. The two AES-256 methods are not
interchangeable and LLDP-Runner never guesses, negotiates, or falls back between
them. The local provider preflight uses a 32-byte AES key for both AES-256
methods. Gufo remains limited to SHA-1/MD5 authentication and AES-128/DES
privacy, and rejects every PySNMP-only choice during configuration validation
before secret resolution or network work.

Gufo behavior and unrelated collection, scheduling, identity, graph, output,
diff, watch, and schema behavior remain unchanged. The current JSON contract
versions and implementation constants are listed in
[`docs/dev/SCHEMA.md`](docs/dev/SCHEMA.md).

The exact package set for 0.38.0 appears in both uv arrays in
`pyproject.toml` and in `constraints/release-0.38.0.txt`; published package and
development dependencies continue to declare broad supported minimums.

Three executable SNMP diagnostics and one Gufo note file are shipped under
`scripts/`:

- `gufo-ipv6-test.py` compares unbracketed and bracketed Gufo SNMP behavior for
  an IPv6 literal or every ordered unique IPv6 result of a hostname;
- `gufo-snmp-diag.py` is the detailed direct Gufo session/query diagnostic;
- `pysnmp-snmp-diag.py` is the equivalent direct PySNMP engine/transport/query
  diagnostic used to validate PySNMP independently of LLDP-Runner; and
- `gufo-readme.txt` documents safe Gufo examples and exit statuses.

All three executable diagnostics bypass LLDP-Runner and should be run in the
same Python/uv environment, on the same Linux host, and under the same
operating-system account as the application. They read credentials from the
standard `SNMPCOMM` or SNMPv3 environment variables without printing their
values.

## Documentation

The detailed project references are under `docs/`:

- [`docs/INSTALL.md`](docs/INSTALL.md) documents installation, shared uv,
  runtime permissions, launcher environment, and systemd scheduling.
- [`docs/CLI.md`](docs/CLI.md) lists command-line options and stdin behavior.
- [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md) lists environment variables.
- [`docs/SNMP.md`](docs/SNMP.md) documents backend selection, Gufo and
  PySNMP transport behavior, diagnostics, canonical IPv6 handling, failure
  phases, and bounded retry ownership.
- [`docs/ERRORS.md`](docs/ERRORS.md) documents route-level error provenance,
  secret handling, recovery metadata, and legacy migration rules.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) describes concept of
  operations, architecture, state, workers, policy, outputs, and design logic.
- [`docs/dev/FLOW-DIAGRAMS.md`](docs/dev/FLOW-DIAGRAMS.md) maps collection,
  resolver, and graph-rematerialization control and persistence flow.
- [`docs/PRIMER.md`](docs/PRIMER.md) explains SNMP table behavior, evidence,
  claims, clusters, protocol advertisements, deterministic comparison, and
  reversible decisions in Network Operations terms.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) tracks planned resolver work, production
  fixtures, open questions, and future operational features.
- [`docs/DEV.md`](docs/DEV.md) is the developer/contributor entry point and
  links to focused module, schema, testing, and release guides under
  `docs/dev/`.
- [`docs/dev/SCHEMA.md`](docs/dev/SCHEMA.md) is the concise current schema and
  implementation-constant reference.
- [`docs/ABOUT.md`](docs/ABOUT.md) provides a short package-purpose summary for
  conversations, communications, and release descriptions.
- [`docs/PRECEDENCE.md`](docs/PRECEDENCE.md) documents configuration assembly
  and the separate credential precedence/fallback model.
- [`docs/CREDS.md`](docs/CREDS.md) explains device eligibility, credential
  selection, seed overlays, success/failure handling, and safe provenance.
- [`docs/PLAN.md`](docs/PLAN.md) provides a scalable enterprise planning
  example for ownership, query, classification, credentials, and tagging.
- [`docs/CUSTOM-CSV.md`](docs/CUSTOM-CSV.md) documents custom CSV row sources,
  fields, transforms, validation, and examples.
- [`docs/CSV-INPUT.md`](docs/CSV-INPUT.md) documents shared CSV input parsing,
  flexible field positions, limits, and current consumers.
- [`docs/RUN.md`](docs/RUN.md) documents run phases, console/activity-log
  vocabulary, recursive versus seed-only modes, and initialization failures.
- [`docs/DNS.md`](docs/DNS.md) documents resolver behavior, seed DNS modes,
  caching considerations, and operational tradeoffs.
- [`docs/CLAIMS.md`](docs/CLAIMS.md) documents immutable observations, typed
  claims, evidence strength/scope, superseding decisions, and the staged
  resolver migration.
- [`docs/NAMES.md`](docs/NAMES.md) explains seed and learned names/addresses,
  host identity folding, `preferred_name`, output fields, and duplicate-name
  review guidance.
- [`docs/DIFF.md`](docs/DIFF.md) explains cross-run source selection, host
  matching, normalization, topology comparison, and machine-readable diffs.
- [`CHANGELOG.md`](CHANGELOG.md) contains release history.
- [`LICENSE.md`](LICENSE.md) contains the project licensing terms.

The current source remains authoritative when documentation and implementation
are found to disagree.

## Core architecture

LLDP-Runner uses one coordinator process as the authoritative owner of topology,
identity, scheduling, and SQLite state. Multiple worker processes perform
asynchronous ICMP and SNMP activity.

```text
seeds
  |
  v
coordinator + SQLite
  |
  +--> worker process + asyncio
  +--> worker process + asyncio
  +--> worker process + asyncio
  |
  v
record claims + resolve/project + classify + schedule
  |
  v
JSON / CSV / checkpoint / scoreboard
```

This design reduces duplicate polling decisions and allows controlled pause and
resume without requiring Redis or another external state service.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the complete execution
model.

## Installation

See [`docs/INSTALL.md`](docs/INSTALL.md) for prerequisites, single-user source
installation, the recommended shared `/opt/lldp-runner` deployment, shared uv
Python setup, group/ACL/umask guidance, `scripts/.private`, systemd scheduling,
and the Ubuntu 24.04/26.04 LTS installation walkthrough.

## Neighbor command distinction

`get-neighbors` is an active one-device diagnostic. It performs DNS, ICMP, and
SNMP as applicable, may require credentials, and never recursively queries
learned devices. The equivalent main CLI form is
`lldp-runner get-neighbors`.

`show-neighbors` is a read-only viewer for finalized `discovery.json` data. It
does not communicate with network devices and completely disables the
credential subsystem. It also stops before runtime SNMP backend selection and
never imports or constructs a transport adapter. The equivalent main CLI form is
`lldp-runner show-neighbors`.


## Read-only discovery viewer

Use `show-neighbors` or `lldp-runner show-neighbors` to search finalized
discovery output without sending ICMP or SNMP traffic. The viewer also
bypasses credential
parsing, secret resolution, runtime credential synthesis, and credential-policy
validation because stored discovery data requires no network authentication:

```bash
show-neighbors access01
show-neighbors --id 127 --detail
show-neighbors --ipv4 198.51.100.0/24
show-neighbors --ipv6 2001:db8::/32 --key 'system.model:^C9300'
show-neighbors access01 --neighbors both
show-neighbors access01 --json
show-neighbors --runid 20260102-210300-EDT access01
show-neighbors --file ./archive/discovery.json --id 127 --json
```

Name patterns use case-insensitive Python regular expressions with
beginning-of-string matching. `--key` criteria use regex search semantics,
while IPv4/IPv6 non-CIDR values are literal prefixes and CIDRs use numeric
network membership. Non-ID criteria combine with AND semantics.

Neighbor output defaults to learned neighbors and falls back to `observed_by`
only when learned evidence is absent. Explicit `--neighbors learned` never
falls back; `--neighbors observed_by` selects inbound evidence and bare
`--neighbors` means both. See [`docs/CLI.md`](docs/CLI.md) for complete
selection, output,
color, ambiguity, and exit-status behavior.

Table and detail output right-align the source timestamp on the title line.
`show-neighbors` uses `discovery.generated` from the selected JSON document and
renders `(json unknown-time)` when that provenance is unavailable. CSV uses
`timestamp=unknown` in the same case. Stored timestamps are converted through
the configured `[time].timezone` policy before display.

## Discovery run comparison

Use `lldp-runner diff` to compare finalized discovery data without contacting
network devices. With no host selector it compares the latest finalized run to
the immediately previous run. A host selector switches to one-host comparison:

```bash
lldp-runner diff
lldp-runner diff --changes-only
lldp-runner diff --summary-only
lldp-runner diff --expand-collection-incidents --changes-only
lldp-runner diff --include-collection-timing --changes-only
lldp-runner diff --runid 20260104-120000-EDT
lldp-runner diff access-sw1
lldp-runner diff --id 127 --json
```

Run-local host IDs are never assumed to identify the same device across runs.
The schema-10 diff builds graph correspondence components that can contain one
or several entities from either run. It reports cluster splits, merges,
reassociations, duplicate projections, and observed relationship-group changes.
Physical topology remains `not_inferred` while relationship directness is
unresolved. The older flat host and learned-neighbor comparison remains in diff
JSON as a compatibility diagnostic.

See [`docs/DIFF.md`](docs/DIFF.md) for source ordering, exit codes, scope
warnings, normalization, host matching, examples, and the diff JSON contract.

### Preparing a review bundle

`scripts/lrun-bundle-diff` packages two completed discoveries, their runtime
state directories, and a machine-readable changes-only diff into one
uncompressed tar archive. Runtime databases are copied through SQLite's backup
API, compacted, and integrity-checked; live WAL/SHM sidecars are excluded. With
no arguments the script selects the two latest completed runs; two explicit run
IDs preserve the requested A/B order:

```bash
./scripts/lrun-bundle-diff
./scripts/lrun-bundle-diff 20260107-06 20260107-05
```

The archive extracts with `outputs/<runid>/`, `runs/<runid>/`, and a top-level
`diff-<runid-A>-<runid-B>.changes.json`. The operator can compress, sanitize, or
transfer the tar file according to local review procedures.

## Configuration

A configuration file is optional. Built-in defaults live in:

```text
src/lldp_runner/defaults.py
```

A partial TOML file may override only the values needed by a site.
Finalized output defaults to `<persistent_root>/outputs/<runid>/`; durable
SQLite/checkpoint state defaults to `<persistent_root>/runs/<runid>/`.

When `--config` and `LLDP_RUNNER_CONFIG` are absent, LLDP-Runner searches:

```text
~/lldp-runner-config.toml
~/lldp-runner/config.toml
/opt/lldp-runner/config.toml
/etc/lldp-runner/config.toml
```

If none exists, built-in defaults are used.

Runtime precedence is:

```text
defaults.py
  -> primary TOML, @include, and conf.d
  -> LLDP_RUNNER_* environment overrides
  -> --set overrides
  -> dedicated command-line options
```

See [`docs/PRECEDENCE.md`](docs/PRECEDENCE.md) for primary-file selection,
fragment/list behavior,
credential fallback, seed aggregation, and `generate-config` exceptions.

### Timezone and run IDs

LLDP-Runner keeps Eastern time as the compatibility default but can use UTC,
the host-local timezone, or an IANA timezone throughout logs, summaries, state,
JSON timestamps, and run-ID formatting:

```toml
[time]
timezone = "eastern"

[paths]
run_id_format = "%Y%m%d-%H%M%S-%Z"
```

Valid timezone examples include `utc`, `local`, `America/Denver`, and
`Europe/London`. Run IDs may use the documented numeric/time `strftime`
directives plus one optional stateless `{counter}`. The counter is rendered as
`00` through `99`, using the highest matching existing counter plus one. If the
next value would exceed `99`, LLDP-Runner fails before discovery and recommends
a higher-precision timestamp such as `%f`. Examples include:

```toml
run_id_format = "%Y%m%d-%H%M%S"
run_id_format = "%y%m%d-{counter}"
run_id_format = "run-{counter}"
```

Counter padding keeps names such as `run-09` and `run-10` in correct lexical
order for the existing automatic-resume scan. Sites that change naming schemes
should remember that lexical ordering across different historical formats is
not guaranteed to represent chronology.

### ENTITY-MIB query scope

ENTITY-MIB enrichment remains enabled by default. The master switch and query
scope are configured independently:

```toml
[snmp]
collect_entity_mib = true
entity_mib_mode = "full"
```

`full` preserves the complete `entPhysicalEntry` walk used before v0.14.0.
`brief` discovers the physical entity index from `entPhysicalClass` and then
retrieves only manufacturer, model, and serial number. `auto` uses the
SYSTEM-MIB identity already collected for the device and adds hardware,
firmware, and ENTITY software revisions when the target looks like physical
network infrastructure; unknown or virtual systems use the brief field set.

Both selective modes discover agent-assigned ENTITY indexes rather than
assuming `entPhysicalIndex=1`. If `collect_entity_mib = false`, no ENTITY-MIB
query is made regardless of `entity_mib_mode`.

Beginning with v0.15.0, ENTITY-MIB also preserves physical stack members under
`system.stack_members` when the agent exposes useful chassis hierarchy. An
explicit `stack(11)` containing `chassis(3)` rows is preferred; multiple sibling
chassis rows provide a conservative fallback for agents that omit the stack
container. This standards-first path covers Cisco Catalyst StackWise, Aruba CX
VSF, Juniper EX Virtual Chassis, and other conforming switch platforms without
changing the logical host identity represented by the management IP/hostname.
Regression coverage explicitly includes the expected Catalyst 9200, 9300, 9500,
3650, and 3850; Aruba/HPE CX 6200 and 6300; and Juniper EX 4100, 4300, 4400,
4600, and 4650 platform families for automatic rich ENTITY identity selection.

A one-run override can be supplied without editing the site configuration:

```bash
lldp-runner --set 'snmp.entity_mib_mode="brief"' run --seed core1.example.net
```

### Generate a starting configuration

```bash
lldp-runner generate-config
```

Normally this creates:

```text
./lldp-runner-config.toml
```

When run from one of these standard directories:

```text
~/lldp-runner/
/opt/lldp-runner/
/etc/lldp-runner/
```

and `./config.toml` does not already exist, the no-argument command creates:

```text
./config.toml
```

An explicit filename may be supplied:

```bash
lldp-runner generate-config site-config.toml
```

The generator refuses to overwrite an existing destination.

The generated file contains comments explaining defaults, runtime behavior,
credentials, policy, classification, and example tagging rules.

### Configuration fragments

When an actual primary config is selected, LLDP-Runner automatically reads
`.toml` fragments from a `conf.d` directory adjacent to that primary file.

For:

```text
/opt/lldp-runner/config.toml
```

the automatic directory is:

```text
/opt/lldp-runner/conf.d/
```

Traversal is recursive and lexical by relative path.

The package's `configs/conf.d/` directory contains inactive examples with the
suffix `.toml.example`. It is not automatically associated with an unrelated
primary config elsewhere in the filesystem.

Explicit `@include` supports relative and absolute paths:

```toml
@include "siteone/query-policy.toml"
@include /opt/lldp-runner/shared-policy.toml
```

Each resolved config file is merged only once per load.

## Default filesystem behavior

Both persistent and scratch roots default to `auto`.

Persistent root checks existing locations in order:

```text
~/lldp-runner
/opt/lldp-runner
/var/lib/lldp-runner
```

The first existing location is authoritative. If it exists but is not writable,
LLDP-Runner reports an error instead of silently moving durable state elsewhere.

If none exists, the writable current working directory is used.

Scratch root checks:

```text
/dev/shm/lldp-runner
/tmp/lldp-runner
/var/tmp/lldp-runner
<persistent_root>/tmp
```

Scratch candidates may safely fall through when unavailable.

A successful terminal run publishes two relative convenience links:

```text
<persistent_root>/runs/latest   -> <run-id>
<persistent_root>/outputs/latest -> <run-id>
```

The output alias is published with completed operator files. The run-state
alias is published after the state database and configured activity log are
closed, so `runs/latest` always advertises a completed durable run directory.
Both locations are storage-preflighted before discovery starts.

Completed scratch is removed by default only after durable publication and
resource closure:

```toml
[paths]
clean_scratch_when_completed = true
```

Cleanup removes the entire `<scratch_root>/<run-id>/` tree and removes
`<scratch_root>/current` only when that symlink still points to the completed
run. This protects a newer concurrent run that may already own `current`.
The live `<scratch_root>/scoreboard/` publication is not removed automatically.
Set the option to `false` to retain completed drafts and a per-run copy of the
final scoreboard. Paused, resumable-limit, interrupted, and failed runs always
retain scratch state. Successful runs archive the final scoreboards in durable
run state regardless of this option and remove durable `run.json.draft`.

## Credentials

Explicit TOML credential profiles are intended for larger environments.

For small/default-only runs, LLDP-Runner can synthesize a lowest-priority
runtime credential profile from environment variables.

SNMPv2c:

```bash
export SNMPCOMM='example-community'
```

SNMPv3 authPriv:

```bash
export SNMPUSER='snmp-user'
export SNMPAUTH='authentication-password'
export SNMPPRIV='privacy-password'
```

All three SNMPv3 values are required together.

Command-line equivalents include:

```text
--community
--snmp.user
--snmp.auth
--snmp.priv
--snmp.version
```

Credential CLI values first act as environment-variable names. If the named
variable does not exist, the supplied token is used literally.

Environment-variable names are preferred for secrets because literal command
line values may appear in shell history or process listings.

See [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md) for all environment
variables. For the complete
operator credential-selection model, including seed overlays and learned
managed devices, see [`docs/CREDS.md`](docs/CREDS.md).

## Validate configuration

```bash
lldp-runner validate-config
```

With an explicit file:

```bash
lldp-runner \
  --config /opt/lldp-runner/config.toml \
  validate-config
```

To inspect policy selection for one target:

```bash
lldp-runner explain-target core1.example.net
```

## Single-device inspection

Use `get-neighbors` for a quick probe of one device:

```bash
get-neighbors core1.example.net
```

Equivalent long form:

```bash
lldp-runner get-neighbors core1.example.net
```

Four output modes are available:

```bash
get-neighbors core1.example.net
get-neighbors core1.example.net --detail
get-neighbors core1.example.net --csv
get-neighbors core1.example.net --json
```

The default is a compact human-readable table. `--detail` provides a scrolling
neighbor-detail view. CSV is intentionally compact. JSON is the richest format
and follows normal discovery host/neighbor concepts where practical.

Human output uses color only on an interactive terminal and honors `NO_COLOR`.
Redirected human output is plain. CSV and JSON never contain ANSI color escapes.
`terminal.color = "never"` disables configured terminal styling globally. The
existing semantic color names remain configurable for neighbor output, while
`terminal.palette = "dark"` or `"light"` selects the built-in watch dashboard
theme. See `configs/conf.d/terminal-colors.toml.example` for the complete
terminal settings.
The compact neighbor table uses 18-column Local and Remote Port baselines by
default. Configure `output.neighbor_local_width` and
`output.neighbor_remote_port_width` to change those baselines; either column can
expand dynamically when longer interface/Port ID values fit without reducing the
Neighbor column below its readable minimum.

Inspection reports individual ping RTT values, elapsed DNS/query/basic/detail
and total timing in milliseconds, plus a single `SNMP obj/ms:` line. The latter
shows SNMP objects returned and collector elapsed milliseconds for each section
that was actually queried. The SYSTEM-MIB collector is labeled `sys`, for
example `sys=6/29.3`; `Timing ms: basic=...` remains the broader probe phase.

The table/detail title includes `(collected YYYY-MM-DD HH:MM:SS)`. A successful
inspection uses the most recent successful SNMP access time. Results without a
successful SNMP access use the command result-finalization time. CSV appends
`state=...,timestamp=...` to its first metadata line. These display timestamps
use `[time].timezone`.

For a fast baseline probe that avoids device-specific interface, neighbor, and
ENTITY-MIB variation, use either equivalent option:

```bash
get-neighbors core1.example.net --system-only
get-neighbors core1.example.net --no-neighbors
```

System-only mode performs DNS, policy, ICMP, credential selection, and the
initial six-object SYSTEM-MIB query. It does not query ENTITY-MIB, IF-MIB,
LLDP, LLDPv2, or CDP.

### Network trace

`get-neighbors --trace` writes an operator-readable network trace to stderr.
It records the operating-system resolver calls used for forward/reverse and
canonical-name handling, concrete ICMP backend attempts and results, and every
logical SNMP GET/WALK operation and returned varbind. Resolver entries report
what LLDP-Runner asked the OS resolver and what it returned; they do not claim
that literal DNS
packets were sent because NSS, `/etc/hosts`, caches, or mDNS may satisfy a call.

ICMP entries show the address, protocol family, backend, sequence, timeout,
reply status, and RTT when available. SNMP entries include known MIB names and
descriptions plus numeric OIDs. Timeouts and absent responses are explicit
`NO RESPONSE`
records, returned values are normalized for safe display, and credential secrets
are never printed. The trace footer reports resolver/ICMP/SNMP operation counts
and total monotonic elapsed time.

```bash
get-neighbors core1.example.net --trace
get-neighbors core1.example.net --tracefile core1-snmp.trace
get-neighbors core1.example.net --trace --tracefile core1-snmp.trace
```

`--tracefile FILENAME` enables tracing automatically and writes a new trace file
for that invocation. Relative filenames are resolved from the current working
directory. When both options are present, identical trace content is written to
stderr and the file while normal inspection output remains on stdout.

### Inspect dry-run

```bash
get-neighbors core1.example.net --dry-run
```

Dry-run performs DNS, boundary reporting, query-policy evaluation, and
prospective credential selection without sending ICMP or SNMP traffic.

An explicit inspect target may be outside `discovery.boundaries`. The result
reports that fact, but the boundary does not block the diagnostic probe.
Explicit query-policy deny rules still prevent traffic.

Inspection does not create SQLite state, run directories, scoreboards, or
recursive neighbor queries.

See [`docs/CLI.md`](docs/CLI.md) for all `get-neighbors` options.

## Discovery run

A basic run can use one seed:

```bash
lldp-runner run --seed core1.example.net
```

Seeds are additive and may come from configuration, files, directories,
environment variables, CLI arguments, and stdin when `--stdin` is present.

```bash
lldp-runner run \
  --seed-file /srv/seeds/core.txt \
  --seed-dir /opt/lldp-runner/seeds.d \
  --seed edge1.example.net
```

### Plain seed lists

Plain-text seed files contain one target per line. Blank lines and comments
beginning with `#` or `;` are ignored. Trailing annotation beginning with a
comma, semicolon, or hash is removed.

```text
core1.example.net, inventory comment
192.0.2.10 ; temporary seed
2001:db8::10 # IPv6 seed
```

### Current seed CSV schema

Only the current `seeds.csv` field set is supported as CSV input:

```text
preferred_name,queried_as,ipv4,ipv6,credential_profile,credential_result,
origin,state,last_seen,notes
```

Columns may appear in any order and header matching is case-insensitive. Extra
columns are ignored. Legacy field names are intentionally not inferred.

### Per-seed credential overlays

`--seed-credential-file FILE` is a repeatable credential overlay for explicit
run seeds. The file does not add seeds: a credential record is used only when
its `seed` matches a seed already supplied through the normal seed channels.
Unmatched records are WARN-level activity-log entries and the activity log also
receives an INFO summary with matched/unmatched record counts. These records are
not emitted as stderr warnings.

Seed-credential CSV requires these fields, which may appear in any order:

```text
seed,credential_strategy,credential_label,credential_profile,
snmp_version,community,username,auth_password,priv_password,
auth_protocol,priv_protocol
```

Blank lines and lines whose first non-whitespace character is `#` or `;` are
skipped. Cells are trimmed. Repeated rows for one seed are attempted in file
order. `credential_strategy` defaults to `prefer`: seed-file attempts run first,
then normal credential policy. `exclusive` prevents normal-policy fallback.
`credential_label` is optional reporting text and need not be unique. It is not
a credential lookup key. A row may reference `credential_profile` or provide a
direct v2c/v3 credential, but not both.

Direct SNMPv3 credentials use the selected backend's explicit protocol map.
Both backends support `sha1`/`md5` authentication and `aes128`/`des` privacy.
PySNMP additionally supports `sha256` authentication plus `aes256` and
`aes256-blumenthal` privacy. `aes256` is the common Reeder/Cisco mapping;
`aes256-blumenthal` uses the different Blumenthal key-localization method.
Gufo rejects those PySNMP-only names before secret resolution or network work,
and unsupported names are never remapped or used as fallback aliases.

JSON files contain a top-level array whose keys use the same names. Array order
is the attempt order. Optional integer `source_line` records CSV provenance but
does not affect ordering. See `configs/seed-credentials.csv.example` and
`configs/seed-credentials.json.example`.

Literal-secret credential files must not be world-readable or world-writable.
Direct credential secrets remain process-local and are never written to
`state.db`, `run.json`, `discovery.json`, generated CSVs, traces, or activity
logs. A resumed run that previously used a seed credential overlay must be given
the overlay again; LLDP-Runner does not persist plaintext credentials for
resume.

## Discovery guardrails and modes

`discovery.max_devices` supports three meanings.

A positive integer enables normal recursive discovery with a finite
managed-device guardrail.

`0` means unlimited recursive managed-device discovery.

`"auto"` means seed-only mode:

```text
query all unique seeds
record/classify their neighbors
do not recursively SNMP-query learned non-seed neighbors
```

After seed resolution and de-duplication, LLDP-Runner can reduce the number of
worker processes and the batch size for that run. The calculation uses READY
seed count, configured worker/batch ceilings, and the per-worker asynchronous
SNMP device limit. It never increases an operator-configured limit and does not
apply to recursive discovery, where later neighbor discovery can create new
query work.

The chosen plan is logged at INFO level and shown in `scoreboard.txt` and
`scoreboard.json` as configured versus effective worker and batch values.

If a finite positive device limit is smaller than the de-duplicated managed
seed inventory, LLDP-Runner fails before workers start.

`discovery.max_hosts = 0` means unlimited host identification.

In seed-only mode, explicit seed devices do not consume the host threshold;
learned non-seed identities do.

## Seed ordering and bounded sampling

Seeds may be scheduled in:

```text
input
sorted
random
```

Example bounded randomized run:

```bash
lldp-runner run \
  --seed-file switches.txt \
  --seed-order random \
  --shuffle-key 20260821 \
  --max-devices auto \
  --max-hosts 1000 \
  --limit-behavior complete
```

`limit_behavior=complete` treats reaching a configured guardrail as an
intentional endpoint and finalizes output as `COMPLETED_LIMIT`.

Because worker results are concurrent, `max_hosts` is a stopping threshold and
may be exceeded by results already in flight. It is not an exact sample-size
feature.

## Classification and recursion

Learned identities are classified into:

```text
managed_device
managed_endpoint
unmanaged_device
unknown_device
```

Only positively managed devices are normally candidates for recursive polling.
Boundary and query-policy decisions are evaluated separately from
classification.

Classification can use addresses, names, composite protocol evidence, managed
manufacturer heuristics, endpoint patterns, unmanaged patterns, capabilities,
and DNS-enriched identity information.

Tag rules can add operator-defined labels without changing classification.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for precedence and evidence
semantics.

## Pause and resume

Request a controlled pause with:

```bash
lldp-runner pause
```

The same behavior can be requested through the configured pause indicator or
supported termination signals.

View a one-shot live status snapshot with:

```bash
lldp-runner status
lldp-runner status --json
```

For an interactive dashboard that refreshes every second by default, use:

```bash
lldp-runner watch
```

`watch` reads `<scratch_root>/scoreboard/scoreboard.json` directly through
the same configured scratch root used by `status`; neither command write-probes
discovery storage, and `watch` does not spawn `status` repeatedly. The stable
path preserves the final completed snapshot even after automatic per-run
scratch cleanup. The producer's normal publication interval remains independent
(three seconds by default).

Worker display defaults to `--worker-view auto`, which recomputes layout after
terminal resizes and selects the richest view that fits without scrolling. A
blank top row and blank left/right edge cells provide a visual border. The same
one-line title structure is used in full, compact, heatmap, and summary views:

```text
LLDP-Runner 0.38.0    Run ID = <runid>    STATE = <state>    updated <mm:ss> ago
```

The renderer distributes spare title width approximately evenly among the four
sections. Update age is total `mm:ss`, including values beyond 59 minutes.
When width contracts, excess gap space and then the version are removed before
essential run ID, state, age, or worker information.
The Run ID title segment uses the footer's muted semantic color.

The Started/Elapsed/Plan line and each metric row are centered within the
bordered content area. When width permits, Watch uses six spaces between the
three summary elements instead of the compact three-space gaps. Metric columns
use fixed geometry for the selected terminal width, separate count and delta
fields, and blank rows between metric rows when vertical space permits. The
summary has a blank row after it. If more than ten rows would otherwise remain
blank above the footer, Watch also adds a blank row between the title and
summary and a second row after the summary.

When the live scoreboard cannot be read, the bright-red `SOURCE: waiting for
current scoreboard under ...` message is placed below the worker table and
above the footer, with one blank row on each side. It does not replace the
normal state and worker layout.

The aggregate worker-status line is centered separately and receives a blank
row above and below when height permits. The same more-than-ten-row condition
adds one extra blank row on each side. Worker capacity is selected before the
grid receives its own stable centering offset. Complete worker rows therefore
have balanced outer whitespace, while a partial final row starts at the same
first worker column. Worker-cell content and density are unchanged.

The fixed `full`, `compact`, `heatmap`, and `summary` modes remain selected
while they fit. The narrow-terminal path continues
`full -> compact -> heatmap -> summary`, collapsing the header only when width
or height requires it. A screen
that cannot show individual cells receives an explicit `SMALL`/`ABBREVIATED`
indicator and preserves state, run ID, age, aggregate BUSY/IDLE/DEAD counts, and
exit guidance ahead of optional metrics. Individual-worker modes retain full
state words and stable per-mode field budgets, so batch/size digit growth cannot
resize columns mid-run. Unused numeric positions use `.` fill and over-budget
fields display `#` markers. The footer reports mode and geometry when it fits
and always keeps `q`/Ctrl-C guidance. Press `m` to cycle views and `h` for
metric/worker help.

Active `RUNNING`/`PAUSING` scoreboards become stale after the larger of fifteen
seconds or three configured scoreboard intervals without a new publication. A
stale screen mutes ordinary colors to gray while `*** STALE ***` remains
prominent. Final run states do not become stale merely because updates stop.

Paused/resumable runs preserve SQLite checkpoint state so work can continue in
a later invocation.

## Output files

Completed discovery can produce:

```text
run.json
discovery.json
hosts.csv
stack-members.csv
seeds.csv
unknown-devices.csv
errors.csv
```

`run.json` and `discovery.json` are written for completed discovery runs.
`run --dry-run` deliberately creates neither a run ID nor `run.json`. `run.json`
schema version 3 starts with `schema_version`, `app_name`, and `app_version`;
the application version comes from the package runtime version. The document
also records sanitized launch/resume provenance, OS account identity,
timezone-aware logical run timestamps, elapsed `duration` in seconds, and (by
default) the exact primary/include/conf.d files used.
Credential communities and authentication/privacy passwords are stored only as
`<redacted>`. Set `output.run_json_config_log = false` to suppress resolved
config pathname detail. `discovery.json` schema version 8 is the topology
contract. It publishes `topology_graph` beside the flat host and neighbor
compatibility projection. The graph retains raw protocol advertisements,
physical chassis, logical systems, interfaces, logical membership, observed
relationships, collection coverage, deterministic projection identity, and
separate authority dimensions for observation completeness, entity resolution,
physical topology, and directness.
Neighbor `details` now preserve LLDP/LLDPv2 `port_id`, `port_id_subtype`,
`port_id_subtype_id`, and `port_description` evidence. Binary MAC-address Port
IDs are normalized to familiar colon-separated MAC text. The document retains
lowercase `hosts[].state` and lowercase `errors[].final_state` values, along
with run metadata, complete host/neighbor records, and the structured error
stream needed for post-run reporting. Information omitted from a convenience
CSV, such as
hardware and firmware revisions, remains in JSON when it was collected.
Optional per-device SNMP collection metrics can also be recorded by setting
`snmp.report_metrics = true`; they are disabled by default.

The five CSV views retain LLDP-Runner-controlled fixed schemas. They can be
controlled with:

```toml
[output]
neighbor_local_width = 18
neighbor_remote_port_width = 18
write_hosts_csv = true
write_stack_members_csv = true
write_seeds_csv = true
write_unknown_devices_csv = true
write_errors_csv = true
write_empty_csv = false
log_alert_on_empty_csv = false
run_json_config_log = true
purge_keep = 0
```

Each CSV remains individually enabled by default, but `write_empty_csv=false`
omits any enabled report that contains zero data rows rather than creating a
header-only file. Set `write_empty_csv=true` when downstream automation needs a
predictable fixed set of CSV pathnames. If `log_alert_on_empty_csv=true`, one
INFO message is emitted for a terminal snapshot listing the enabled empty CSVs
that were not written; periodic RUNNING snapshots do not repeat the message.

Each `stack-members.csv` row repeats the logical host context and uses
member-specific manufacturer, model, serial, revision, and member-position
values. The redundant `snmp_status` column is removed; lowercase host `state`
remains available on each row. `uptime_seconds` stays blank unless a true
member-specific value is available; logical stack `sysUpTime` is not copied
into each physical member row.

To retain per-device SNMP object-count and collector-time telemetry in full
discovery JSON, enable:

```toml
[snmp]
report_metrics = true
```

`get-neighbors` always collects and reports these lightweight metrics
regardless of
this full-discovery setting. CSV schemas are unchanged by the metrics option.

`hosts.csv` uses `preferred_name` to match the JSON host key and contains the
grep-friendly `origin` field with values `seed` and `learned`. Its `state` value
is copied directly from lowercase `hosts[].state`; the former duplicate
`snmp_status` column is removed. `learned_neighbors` and
`observed_by_neighbors` remain separate. Beginning with v0.12.0,
`hardware_revision` and `firmware_revision` are not included in `hosts.csv`;
the collected values remain in `discovery.json`.

`seeds.csv` and `errors.csv` remain fixed contracts while custom reports can
select their projection fields independently. `seeds.csv` uses
`preferred_name`, `queried_as`, and lowercase `state`
to match the canonical host record, while `origin=seed|learned` remains a
deliberate transform of JSON `is_seed`. If a `learned` row is supplied as input
to a later run, it becomes `origin=seed` because it was explicitly provided for
that run. `errors.csv` uses `category` and lowercase `final_state` to match
the JSON error record.
All five fixed CSV writers consume the same in-memory document that is written
as `discovery.json`. A JSON-only replay regression test closes the SQLite state
and reproduces all five CSV files byte-for-byte from the parsed document.
`unknown-devices.csv` remains a fixed review view containing inbound protocol,
name, platform, capability, chassis, and classification evidence. The
`manufacturer` and `model` columns are omitted because unknown live-neighbor
records do not populate them. The same-source custom selectors are also
unsupported; use `json.host.system.manufacturer` or
`json.host.system.model` for any collected canonical values.
Its observed chassis aggregates are named `observed_chassis_ids`,
`observed_chassis_id_subtypes`, and `observed_chassis_id_subtype_ids`, while the
flattened inbound topology column is consistently named `observed_by_neighbors`.

Custom CSV reports are configured as named tables. Each report declares one row
source and an ordered list of fixed presentation or approved JSON fields:

```toml
[output.custom_csv.inventory]
filename = "inventory.csv"
source = "hosts"
columns = [
  { field = "hosts.preferred_name", header = "FQDN" },
  { field = "hosts.origin" },
  { field = "json.host.system.model" },
  { field = "json.host.system.serial_number", header = "serial" },
]
```

See [`docs/CUSTOM-CSV.md`](docs/CUSTOM-CSV.md) for row-grain rules, available
fields, transforms, and
configuration precedence. A seed-grain inventory example is provided at
`configs/conf.d/custom-inventory-csv.toml.example`. Custom CSV files share
`write_empty_csv` and `log_alert_on_empty_csv` with the fixed reports.

Operational artifacts include:

```text
<persistent_root>/runs/<run-id>/activity.log
<persistent_root>/runs/<run-id>/discovery-state.sqlite
<scratch_root>/scoreboard/scoreboard.txt
<scratch_root>/scoreboard/scoreboard.json
<persistent_root>/runs/<run-id>/scoreboard.txt
<persistent_root>/runs/<run-id>/scoreboard.json
```

The stable scratch files are the live status publication. The persistent copies
are the exact terminal snapshots for a completed run. Draft discovery output is
normally written under per-run scratch storage, while final operator output is
placed under the persistent output root.

`activity.log` is enabled by default but is now optional and configurable:

```toml
[logging]
level = "INFO"
console = true
file = true
filename = "activity.log"
```

Relative `filename` values are rooted beneath the current
`runs/<run-id>/` directory. Absolute paths, and `~`-expanded paths, can
direct logs to a centralized location such as `/var/log/lldprunner.log`. File
logging always appends, so a centralized file retains records from prior runs.
If an enabled file cannot be created or opened for append, LLDP-Runner exits
before discovery and reports the path error on standard error. Set `file=false`
to suppress file logging without affecting console logging. Console and file
destinations can also both be disabled when intentionally silent operation is
required.

Operational SNMP events use one target-first message convention after the
standard timestamp, level, worker process, and logger prefix:

```text
2026-08-29 08:46:58 EDT INFO lldp-worker-31 lldp_runner.worker: \
  SNMP target=198.51.100.252 neighbor collector transient failure retry \
  operation=lldp category=timeout attempt=2
```

The example is wrapped for documentation; each emitted record remains one line.
`target` is the exact name or address used by the SNMP transport. Keeping it in
the same position lets operators filter retry, timeout, access-restriction, and
collector-failure events without parsing a different message layout for each
operation.

Before workers start, LLDP-Runner also probes the exact scratch run directory
and terminal persistent-output location using the same create, fsync, and
atomic-rename pattern used by normal output. It separately verifies that the
persistent output root can publish a temporary symlink, without changing the
real `latest` link. These checks catch ordinary permission and path failures
early; later disk-full, quota, or remote-filesystem failures remain possible.

## SNMP text sanitation

LLDP-Runner normalizes SNMP textual OCTET STRING data before formal output.
Printable Unicode is retained, unsafe control characters are removed or
normalized, and binary/invalid text can fall back to printable hexadecimal.

LLDP chassis IDs use subtype-aware handling for MAC and network-address values.
LLDP and LLDPv2 Port IDs use their distinct subtype enumeration as well; in
particular, Port ID subtype 3 (`mac_address`) is decoded to canonical MAC text.
CSV and JSON apply a final output-safety pass as defense in depth.

LLDP/LLDPv2 remote rows are also checked for mandatory chassis-ID and Port-ID
subtype/value pairs. A structurally incomplete snapshot is retried once instead
of being admitted as partial topology. Full LLDP row-index context is retained
during table assembly; volatile `time_mark` values are diagnostic rather than
logical diff identity.

CDP and LLDP can describe one physical endpoint differently. When remote-port
strings differ, LLDP-Runner can still form one edge if the observations came
from the same local switch port, share a usable management IP, and have
compatible names. A single-label CDP name such as `SEP00123456000C` can match
an LLDP FQDN such as `SEP00123456000C.voice-a.example.com`. Two different
FQDNs are not matched merely by a common left-most label. The normalized edge
prefers the LLDP typed Port ID while retaining both protocols' raw evidence in
`details`.
See [`docs/NAMES.md`](docs/NAMES.md) for the complete evidence rules.

## Common commands

```bash
lldp-runner --version
lldp-runner generate-config
lldp-runner validate-config
lldp-runner explain-target core1.example.net
get-neighbors core1.example.net
get-neighbors core1.example.net --json
lldp-runner run --dry-run --seed core1.example.net
lldp-runner run --seed-dir /opt/lldp-runner/seeds.d
lldp-runner version
lldp-runner status
lldp-runner watch
lldp-runner clean
lldp-runner clean --dry-run
lldp-runner purge
lldp-runner purge --keep 3 --dry-run
lldp-runner pause
```

See [`docs/CLI.md`](docs/CLI.md) for the complete command-line reference.

## Operator launcher scripts

The `scripts/lrun-*` files are Bash convenience launchers for installations that
keep the project and primary configuration under `/opt/lldp-runner`. Each
launcher resolves the project from its own location, optionally sources
`scripts/.private`, runs through `uv`, forwards additional command-line
arguments, and can use `flock` when `SINGLE_INSTANCE=true`.
See [`docs/INSTALL.md`](docs/INSTALL.md) and `scripts/example.private` for the
shared uv and
operator-versus-maintainer launcher environment.

- `scripts/lrun-checkconfig` runs `lldp-runner validate-config` against
  `/opt/lldp-runner/config.toml`, providing a short operator command for
  checking the deployed configuration before a discovery run.
- `scripts/lrun-clean` runs `lldp-runner clean` against the deployed primary
  configuration. It permits concurrent invocation (`SINGLE_INSTANCE=false`) and
  forwards options such as `--scratch`, `--all`, or `--dry-run`.
- `scripts/lrun-diff` wraps the read-only `lldp-runner diff` command with the
  deployed primary configuration. It preserves the invoking working directory
  so relative `--file` paths continue to resolve from the operator's context.
- `scripts/lrun-dryrun` runs the normal discovery command in `--dry-run` mode
  using `/opt/lldp-runner/seed.list`, so seed/configuration behavior can be
  checked without contacting devices.
- `scripts/lrun-explain` runs `lldp-runner explain-target` and forwards the
  requested target/options, using LLDP-Runner's normal configuration discovery.
- `scripts/lrun-get` wraps `lldp-runner get-neighbors` with the deployed primary
  configuration, prints a short target notice, and passes inspection and trace
  options through unchanged.
- `scripts/lrun-purge` runs `lldp-runner purge` against the deployed primary
  configuration. It permits concurrent invocation (`SINGLE_INSTANCE=false`) and
  forwards retention options such as `--keep` and `--dry-run`.
- `scripts/lrun-run` starts a normal discovery run using
  `/opt/lldp-runner/seed.list` and enables the launcher's single-instance
  `flock` guard so a second copy fails immediately instead of overlapping.
- `scripts/lrun-seedrun` starts a single-instance seeded discovery using random
  seed ordering, shuffle key `20260102`, `max_devices=auto`, `max_hosts=150000`,
  and `limit_behavior=complete` for a bounded seed-oriented run.
- `scripts/lrun-show` wraps the read-only `lldp-runner show-neighbors` command
  with the deployed primary configuration and forwards the requested device and
  display options to the viewer.
- `scripts/lrun-version` runs `lldp-runner version` without requiring a
  configuration file.
- `scripts/lrun-watch` starts the native interactive `lldp-runner watch`
  dashboard against `/opt/lldp-runner/config.toml` and forwards optional watch
  controls such as `--worker-view`, `--palette`, and `--no-color`.
- `scripts/gufo-ipv6-test.py` bypasses LLDP-Runner and compares direct Gufo SNMP
  behavior for the same IPv6 destination in canonical unbracketed and
  transport-bracketed forms. It accepts an IPv6 literal or IPv6-resolvable
  hostname and reads its SNMPv2c community from `SNMPCOMM` without printing the
  value.
- `scripts/gufo-snmp-diag.py` is the more detailed direct Gufo diagnostic for
  session construction, open, request, and close phases.
- `scripts/pysnmp-snmp-diag.py` is the direct PySNMP counterpart for engine and
  transport-target construction, GET responses, and dispatcher cleanup. It
  bypasses LLDP-Runner and does not alter the selected discovery backend.
- `scripts/gufo-readme.txt` gives safe examples, environment guidance, and exit
  meanings for both Gufo diagnostics.
- `scripts/md-to-html.sh` recursively converts project Markdown into a flat
  standalone HTML documentation directory. Subdirectory components become
  hyphenated prefixes, such as `docs/CLI.md` -> `docs-CLI.html`.

The paths and fixed arguments near the top of each launcher are operator
configuration, not package defaults. Review them before deployment when the
project, configuration, seed file, or desired run policy differs from the
provided `/opt/lldp-runner` examples.

## Run/output retention maintenance

`lldp-runner clean` removes historical durable/scratch run state while retaining
the newest run and any run selected by scratch `current`, persistent
`runs/latest`, or finalized-output `outputs/latest`. The default behavior and
`clean --all` both clean persistent and scratch run history. `clean --scratch`
changes only scratch history; when
`--scratch` and `--all` are combined, `--all` wins. `--dry-run` uses the same
selection logic without deleting anything.

```bash
lldp-runner clean
lldp-runner clean --all
lldp-runner clean --scratch
lldp-runner clean --dry-run
```

Persistent state is cleaned below `<persistent_root>/<runs_dirname>/`. Scratch
run directories are direct children of `<scratch_root>/`, alongside `current`
and the reserved live `scoreboard/` directory. Scratch cleanup removes that
reserved scoreboard directory and recognized historical run artifacts, while
retaining unrelated shared-root data. Finalized output is not deleted by
`clean`.

`lldp-runner purge` is the separate finalized-output retention command. It acts
only below `<persistent_root>/<output_dirname>/` and never removes SQLite run
state or scratch data. With the default `output.purge_keep = 0`, `purge` keeps
the `latest` target and removes older output directories. `--keep N` retains
`latest` plus N additional timestamp-ranked output directories and overrides the
configured default. If `latest` is absent, the newest ranked output is
retained as a safe latest-equivalent. A malformed/external `latest` symlink is
an error rather than a reason to guess.

```bash
lldp-runner purge
lldp-runner purge --keep 3
lldp-runner purge --dry-run
```

Purge ordering first uses `run.json` completion time, then
`discovery.discovery.completed`, then `discovery.discovery.generated`. If those
are unavailable, LLDP-Runner uses the oldest available filesystem mtime among
`run.json`, `discovery.json`, and the output run directory. Missing or malformed
files simply fall through to the next source. Both `clean` and `purge` disable
the credential subsystem and are suitable for unattended cron/systemd
maintenance.

## Development checks

With development dependencies installed:

```bash
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

Python bytecode compilation can also be checked with:

```bash
python -m compileall -q src tests
```

## Deployment validation

Automated tests cover configuration, state, policy, classification, output,
seed handling, scheduler semantics, and inspection behavior.

CDP, LLDP, LLDPv2, SNMP timing, and vendor MIB behavior should still be
validated against representative production hardware before broad deployment.
Vendors can differ in supported objects, encodings, and table behavior.

## License

LLDP-Runner is released into the public domain under the Unlicense. See
[`LICENSE.md`](LICENSE.md) for the public-domain dedication and warranty
disclaimer.
