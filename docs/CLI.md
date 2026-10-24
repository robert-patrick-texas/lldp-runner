# LLDP-Runner command-line reference

This document describes the command-line interface shipped with LLDP-Runner.
It is based on the current parser in `src/lldp_runner/cli.py`.

Use `lldp-runner --help`, `lldp-runner COMMAND --help`, `get-neighbors --help`,
or `show-neighbors --help` for parser-generated help.

## 1. Command forms

LLDP-Runner provides these command forms:

```text
lldp-runner --version
lldp-runner version
lldp-runner [GLOBAL OPTIONS] clean [--all] [--scratch] [--dry-run]
lldp-runner [GLOBAL OPTIONS] purge [--keep NUMBER] [--dry-run]
lldp-runner [GLOBAL OPTIONS] run [RUN OPTIONS]
lldp-runner [GLOBAL OPTIONS] get-neighbors SEED [OPTIONS]
lldp-runner [GLOBAL OPTIONS] show-neighbors [OPTIONS] [PATTERN]
lldp-runner [GLOBAL OPTIONS] diff [OPTIONS] [PATTERN]
lldp-runner [GLOBAL OPTIONS] validate-config
lldp-runner [GLOBAL OPTIONS] paths [--json]
lldp-runner [GLOBAL OPTIONS] generate-config [FILENAME]
lldp-runner [GLOBAL OPTIONS] explain-target TARGET
lldp-runner [GLOBAL OPTIONS] status [--json]
lldp-runner [GLOBAL OPTIONS] watch [WATCH OPTIONS]
lldp-runner [GLOBAL OPTIONS] pause
get-neighbors [OPTIONS] SEED
show-neighbors [OPTIONS] [PATTERN]
```

`get-neighbors` is an active one-device operation. It performs ICMP/SNMP as
applicable, may require credentials, and never recursively queries learned
devices. Options may appear before or after `SEED`.

`show-neighbors` is a read-only viewer for finalized `discovery.json` data. It
does not communicate with network devices and disables the credential subsystem.

`lldp-runner diff` is a read-only comparison of two finalized discovery data
sets. It also disables credentials and performs no network activity.

## 2. Global LLDP-Runner options

### `-h`, `--help`

Show parser help and exit.

### `--version`

Show the installed LLDP-Runner version and exit. The `version` subcommand is an
exact output-equivalent convenience form.

```bash
lldp-runner --version
lldp-runner version
```

### `--config FILE`

Select the primary TOML configuration file. An explicit path is
Authoritative. If it does not exist or cannot be read, LLDP-Runner fails
instead of searching elsewhere.

```bash
lldp-runner --config /opt/lldp-runner/config.toml run \
  --seed core1.example.net
```

When omitted, LLDP-Runner checks the normal config search locations before
falling back to built-in defaults. See [PRECEDENCE.md](PRECEDENCE.md) for the
authoritative assembly order and [ENVIRONMENT.md](ENVIRONMENT.md) for
environment
details.

### `--set 'SECTION.OPTION=TOML_VALUE'`

Override one configuration value using TOML value syntax. The option is
repeatable.

```bash
lldp-runner \
  --set 'snmp.max_repetitions=20' \
  --set 'icmp.enabled=true' \
  run --seed core1.example.net
```

Standard fixed CSV views can also be suppressed for a run:

```bash
lldp-runner \
  --set 'output.write_stack_members_csv=false' \
  --set 'output.write_unknown_devices_csv=false' \
  --set 'output.write_errors_csv=false' \
  run --seed core1.example.net
```

`discovery.json` remains enabled regardless of these CSV controls. Custom CSV
reports are configured below `output.custom_csv`; see
[CUSTOM-CSV.md](CUSTOM-CSV.md).

By default, any individually enabled fixed or custom CSV with zero data rows is
omitted. Use `output.write_empty_csv=true` when automation requires a
header-only file for every enabled CSV. The optional
`output.log_alert_on_empty_csv=true` setting emits one INFO record at terminal
snapshot time listing enabled empty CSVs that were not written.

Quote string values as TOML strings:

```bash
lldp-runner --set 'logging.level="DEBUG"' validate-config
```

Dedicated CLI arguments override `--set` when both address the same setting.

### `--snmp.backend {gufo,pysnmp}`, `--snmp-backend {gufo,pysnmp}`

Select the SNMP transport implementation for the current invocation. `gufo` is
still available explicitly; an omitted value now resolves to `pysnmp`. The
value participates in the normal scalar precedence chain:
TOML, `LLDP_RUNNER_SNMP_BACKEND`, `--set`, then the dedicated option.

For a discovery run, LLDP-Runner resolves this setting before coordinator or
worker discovery begins and binds it to the logical run. Every worker uses that
same backend. A resume must resolve to the persisted backend name or it fails
before discovery and before `run.json` is changed. LLDP-Runner never falls back
from the selected package to the other package and never combines backend
evidence in one run.

The 0.37.0 default change does not override an explicit Gufo setting. To resume
an existing Gufo run, keep or add `snmp.backend = "gufo"`; an omitted backend
now resolves to `pysnmp`, so the implicit default fails the durable mismatch
check before discovery.

```bash
lldp-runner --snmp-backend pysnmp run --seed core1.example.net
lldp-runner --snmp.backend gufo get-neighbors core1.example.net
```

The selected backend name and installed package version are recorded in the
run's SQLite metadata, top-level `run.json` diagnostics, and each invocation
record. Credential values are not included.

#### ENTITY-MIB query mode through `--set`

The ENTITY-MIB collector has three query scopes:

```text
full   complete entPhysicalEntry walk; historical/default behavior
auto   discover the physical index and adapt high-value fields to device type
brief  discover the physical index and request manufacturer/model/serial only
```

For example:

```bash
get-neighbors --set 'snmp.entity_mib_mode="auto"' core1.example.net
lldp-runner --set 'snmp.entity_mib_mode="brief"' run --seed core1.example.net
```

`snmp.collect_entity_mib=false` is the master disable switch and prevents all
ENTITY-MIB queries regardless of the selected mode. `auto` and `brief` walk
only `entPhysicalClass` to discover valid agent-assigned indexes before their
targeted instance GETs; neither mode assumes that index `1` exists. Beginning
with v0.15.0, all three modes also preserve physical switch members beneath a
logical stack identity when ENTITY-MIB exposes usable chassis relationships.

### `--snmp.community VALUE`, `--community VALUE`

Provide the lowest-priority runtime SNMPv2c community. `VALUE` is first
interpreted as an environment-variable name. If that variable does not
exist, `VALUE` is used literally.

```bash
export SITE_COMM='example-community'
lldp-runner --community SITE_COMM run --seed core1.example.net
```

### `--snmp.user VALUE`, `--snmp-user VALUE`

Provide the runtime SNMPv3 authPriv username. The environment-name-first
lookup rule is the same as `--community`.

### `--snmp.auth VALUE`, `--snmp-auth VALUE`

Provide the runtime SNMPv3 authentication password.

### `--snmp.priv VALUE`, `--snmp-priv VALUE`

Provide the runtime SNMPv3 privacy password.

All three SNMPv3 values are required together.

### `--snmp.version {2c,3}`, `--snmp-version {2c,3}`

Choose the preferred runtime SNMP version when both runtime v2c and v3
credentials are available. The other version becomes fallback.

```bash
lldp-runner \
  --community SITE_COMM \
  --snmp.user SITE_USER \
  --snmp.auth SITE_AUTH \
  --snmp.priv SITE_PRIV \
  --snmp.version 3 \
  run --seed core1.example.net
```

Explicit credential profiles in TOML take precedence over synthesized
runtime credentials.

## 3. `version`

Print the same version string as `lldp-runner --version` and exit. This command
does not load credentials or require access to discovery storage.

```bash
lldp-runner version
```

## 4. `clean`

Remove historical LLDP-Runner run state while preserving the newest run and
operator-significant `current`/`latest` targets. The command disables the
credential subsystem entirely.

```bash
lldp-runner clean
lldp-runner clean --all
lldp-runner clean --scratch
lldp-runner clean --scratch --all
lldp-runner clean --dry-run
```

With no option, `clean` operates on both persistent and scratch history. `--all`
is an explicit spelling of that default. `--scratch` limits cleanup to scratch
history. When both flags are supplied, `--all` wins, so `clean --scratch --all`
has the same behavior as `clean --all`.

Persistent run state is cleaned below
`<persistent_root>/<runs_dirname>/`. Scratch run directories in the current
runtime layout are direct children of `<scratch_root>/`. The reserved
`<scratch_root>/scoreboard/` live-publication directory is removed by every
scratch cleanup, while the `<scratch_root>/current` symlink remains untouched.
The command preserves the newest run directory in each area,
the scratch `current` target, and the durable run directory corresponding to
`<persistent_root>/<runs_dirname>/latest` or
`<persistent_root>/<output_dirname>/latest` when either alias is available.
Finalized output directories and the two `latest` symlinks themselves are never
removed.

Because an explicit scratch root can be shared with other operator data, scratch
cleanup only removes directories/files recognizable as LLDP-Runner run
artifacts. Unknown scratch children are retained rather than guessed to be safe
for
deletion.

### `--all`

Clean persistent and scratch run history. This is also the default when no scope
flag is supplied. If combined with `--scratch`, `--all` takes precedence.

### `--scratch`

Clean only recognized historical scratch runs and make no change to persistent
run state.

### `--dry-run`

Run the complete retention selection and report what would be removed without
deleting any persistent or scratch artifact.

## 5. `purge`

Remove historical finalized output directories below
`<persistent_root>/<output_dirname>/`. `purge` disables credentials and does not
modify durable run state or scratch data.

With no `--keep`, the configured `output.purge_keep` value is used. Its built-in
default is 0, which keeps only the `latest` output. `--keep 3`, for example,
keeps `latest` plus the three most recent additional output directories. An
explicit CLI value overrides configuration.

```bash
lldp-runner purge
lldp-runner purge --keep 3
lldp-runner purge --dry-run
```

Retention ranking uses `run.json` completion time first, then
`discovery.completed`, then `discovery.generated`, then the oldest available
filesystem mtime among `run.json`, `discovery.json`, and the output directory.
Missing/malformed metadata falls through safely. A malformed or external
`outputs/latest` symlink is a usage error. When `latest` is absent, the newest
ranked output is retained as a safe equivalent.

### `--keep NUMBER`

Keep `latest` plus NUMBER additional recent output directories. NUMBER must be
non-negative.

### `--dry-run`

Calculate and print the same retain/remove set as normal purge without deleting
anything.

## 6. `run`

`run` starts a new recursive discovery or resumes an eligible prior run.

```bash
lldp-runner run --seed core1.example.net
```

Completed runs publish `run.json` beside `discovery.json`. The schema-versioned
document begins with `schema_version`, `app_name`, and `app_version`; the
application version is the package runtime version. It also records the fixed
SNMP backend name and installed package version at run level and for each
invocation. Provenance records logical run start/completion, the starting OS
username and UID, every resume invocation, sanitized raw/parsed CLI input,
resolved seed inputs (including stdin values), recognized non-secret LLDP-Runner
environment
inputs, and the resolved config-file chain when enabled. Credential communities
and auth/privacy password values are replaced with `<redacted>` before durable
state is written. `output.run_json_config_log=false` suppresses dynamically
resolved config pathname detail. `run --dry-run` does not allocate a run ID and
therefore creates no `run.json`.

`run.json` schema 3 preserves the logical `duration` from persisted start to
discovery completion and adds discovery, graph-resolution, graph-serialization,
output-publication, finalization, and total wall-clock durations. Completion
paths resolve retained filesystem aliases and use canonical
`outputs/<run-id>/` spelling.

After a run invocation terminates, standard output includes invocation timing
immediately after `Status:`:

```text
Run: 20260102-135700-EDT
Status: COMPLETED
Runtime: 2026-08-24 13:57:00 EDT to 2026-08-24 13:58:30 EDT (duration: 90s)
State: ...
Activity log: ...
Output: ...
```

The Runtime timestamps and duration describe the current command invocation.
When an incomplete run is resumed, they do not represent the full wall-clock
lifetime of the persisted run ID.

### Seed input options

#### `--seed TARGET`

Add one seed hostname, IPv4 address, or IPv6 address. Repeat as needed.

```bash
lldp-runner run \
  --seed core1.example.net \
  --seed 192.0.2.10 \
  --seed 2001:db8::10
```

#### `--seed-file FILE`

Read seeds from one file. Repeatable.

Files ending in `.csv` must use the current LLDP-Runner `seeds.csv` field set.
Columns may appear in any order and header matching is case-insensitive. Its
`origin` field records the prior run's provenance, but imported rows are
explicit seeds in the new run regardless of whether that value was `seed` or
`learned`. Other files use the plain-text seed parser.

```bash
lldp-runner run --seed-file /opt/lldp-runner/seeds/core.txt
```

#### `--seed-credential-file FILE`

Attach ordered SNMP credential attempts to matching explicit run seeds. The
option is repeatable and accepts `.csv` or `.json` files. It is an overlay only:
records never create seeds, trigger DNS on their own, or cause a credential-only
host to be queried. Seeds without a matching record use the existing credential
policy unchanged.

CSV requires these fields, which may appear in any order:

```text
seed,credential_strategy,credential_label,credential_profile,
snmp_version,community,username,auth_password,priv_password,
auth_protocol,priv_protocol
```

CSV blank/comment lines are skipped and cell whitespace is trimmed. Header
matching is case-insensitive, and unrelated extra columns are ignored. A missing
`seed` skips the row. A seed row with no profile or usable direct credential is
skipped with a WARN activity-log record. Repeated rows for a seed preserve
file order. See [CSV-INPUT.md](CSV-INPUT.md) for the shared CSV input contract.

JSON is a top-level array of objects. Keys match the CSV columns; the only extra
recognized key is optional positive integer `source_line`, which is provenance
metadata only. JSON array order determines credential attempt order.

`credential_strategy` defaults to `prefer`. `prefer` tries overlay records first
and then the normal address/name/default profile. `exclusive` tries only overlay
records. Conflicting explicit strategies for the same seed are errors. A
`credential_profile` row expands the named configured primary/fallback profile;
a direct row supplies v2c community or the selected backend's supported v3
authPriv fields. Gufo accepts SHA-1/MD5 with AES-128/DES. PySNMP also accepts
SHA-256 plus `aes256` (Reeder/Cisco) and `aes256-blumenthal`; it never
infers one AES-256 localization from the other. Profile and direct fields may
not be mixed on one row.

`credential_label` is optional, non-secret reporting metadata. It has no
uniqueness requirement and is never used as an internal key or profile selector.

Literal-secret files must not be world-readable or world-writable. Unmatched
records are written only to WARN-level activity logging; an INFO activity-log
message reports `X matched, Y unmatched`. Resume requires the applicable overlay
to be supplied again because direct secrets are never checkpointed.

Examples:

```bash
lldp-runner run \
  --seed-file /srv/lldp/seeds.csv \
  --seed-credential-file /etc/lldp-runner/seed-credentials.csv

chmod 0600 /etc/lldp-runner/seed-credentials.json
lldp-runner run \
  --seed core1.example.net \
  --seed-credential-file /etc/lldp-runner/seed-credentials.json
```

#### `--seed-dir DIR`

Recursively read eligible seed files from a directory. Repeatable.

```bash
lldp-runner run --seed-dir /opt/lldp-runner/seeds.d
```

Hidden files/directories, names beginning with `README`, and names ending in
`.disabled` or `.note` are ignored. CSV files use the current strict schema.
All other eligible files are parsed as plain text.

#### `--stdin`

Read additional plain-text seeds from standard input.

```bash
cat temporary-seeds.txt | lldp-runner run --stdin
```

Without `--stdin`, LLDP-Runner does not consume standard input.

### Plain-text seed line rules

Each active line contains one seed. Blank lines are skipped. Lines whose
first non-whitespace character is `#` or `;` are comments.

For active lines, text beginning with the first comma, semicolon, or hash is
removed.

```text
core1.example.net, inventory note
192.0.2.10 ; temporary seed
2001:db8::10 # IPv6 seed
# ignored comment
; ignored comment
```

The first three lines produce three seeds.

### Run lifecycle options

#### `--new-run`

Force a new run even when an incomplete resumable run exists.

#### `--no-resume`

Disable automatic resume for this invocation.

#### `--dry-run`

Apply the configured seed identity/DNS policy and print policy explanations
without sending ICMP or SNMP. At least one seed is required.

```bash
lldp-runner run --dry-run --seed core1.example.net
```

Unlike `inspect --dry-run`, normal `run --dry-run` loads the run-effective
configuration and performs normal credential validation.

`run --dry-run` also honors `discovery.seed_dns_mode`, including eligible
`skip-addressed` reusable seed rows.

### Worker and cohort options

#### `--workers N`, `--workers auto`

Override the worker-process count. `auto` resolves at runtime to:

```text
(os.cpu_count() or 1) * 4
```

#### `--batch-size N`

Override the number of device tasks assigned as one worker cohort.

#### `--max-outstanding N`

Override the maximum number of active device operations inside each worker.

### Seed scheduling options

#### `--seed-order {input,sorted,random}`

Choose scheduling order after seed consolidation and identity de-duplication.

`input` preserves first-seen input order.

`sorted` uses a case-insensitive lexical sort of resolved preferred names.

`random` uses a hash-based shuffle.

#### `--seed-dns-mode {resolve,skip-addressed}`

Control DNS behavior during initial seed identity resolution.

`resolve` is the default and performs normal resolver work for every seed.

`skip-addressed` can bypass DNS for a reusable seed that has a non-IP logical
name plus a valid prior `queried_as` address. When prior `state` metadata is
present, it must indicate `complete`/successful input; failed or conflicting
state forces fresh DNS. IP-only seeds also retain normal reverse resolution.

The option affects startup seed resolution only. Learned managed-neighbor DNS
enrichment remains controlled by `discovery.resolve_discovered_managed_names`.

```bash
lldp-runner run \
  --seed-file seeds.csv \
  --seed-dns-mode skip-addressed
```

See [DNS.md](DNS.md) for the full eligibility and operational tradeoffs.

#### `--shuffle-key KEY`

Make `--seed-order random` reproducible. If omitted, a new key is generated
for a new run and persisted so resume keeps the same ordering.

```bash
lldp-runner run \
  --seed-file switches.txt \
  --seed-order random \
  --shuffle-key 20260821
```

### Discovery guardrails

#### `--boundary CIDR`

Replace configured discovery boundaries for this invocation. Repeatable.

```bash
lldp-runner run \
  --boundary 192.0.2.0/24 \
  --boundary 2001:db8:1::/48 \
  --seed core1.example.net
```

#### `--max-devices N`

Set the managed-device query guardrail.

A positive integer enables recursive discovery up to that guardrail.

`0` disables the managed-device count guardrail.

`auto` enables seed-only mode: all unique seed devices may be queried, but
managed neighbors learned from those seeds are not recursively queried.

Because the complete SNMP query population is known after seed initialization,
LLDP-Runner right-sizes the run's execution plan before starting workers. The
effective worker count is bounded by the number of READY seed batches that can
make progress concurrently, and a small workload can also reduce batch size to
balance seeds across those workers. Configured limits are never increased.

The INFO log and live scoreboards show configured and effective workers/batch
size so the runtime optimization remains visible to operators. Recursive runs
do not use this optimization because learned neighbors can create later work.

```bash
lldp-runner run --max-devices auto --seed-file switches.txt
```

If a finite positive value is smaller than the de-duplicated managed seed
inventory, LLDP-Runner fails before workers start.

#### `--max-hosts N`

Set the identified-host guardrail. `0` disables it.

In seed-only mode, explicit seeds do not consume this threshold; discovered
non-seed identities do.

#### `--limit-behavior {pause,complete}`

Choose what reaching a finite runtime guardrail means.

`pause` produces a resumable `LIMIT_REACHED` run.

`complete` treats the threshold as intentional, finalizes output, and marks
the run `COMPLETED_LIMIT`.

```bash
lldp-runner run \
  --seed-file switches.txt \
  --seed-order random \
  --max-devices auto \
  --max-hosts 1000 \
  --limit-behavior complete
```

Because worker batches are concurrent, `max_hosts` is a stopping threshold,
not an exact output sample size.

### Run initialization messages

Before workers start, a run announces its discovery mode, configuration source,
raw seed count, seed-resolution phase, resolution result, and discovery start.
Long seed resolution emits a progress heartbeat every 30 seconds. The console
is intentionally concise; `activity.log` includes more detailed phase counters.

See [RUN.md](RUN.md) for message vocabulary, count definitions, examples, and
initialization-failure behavior.

### Filesystem options

#### `--persistent-root DIR`

Override the persistent root. The value `auto` is accepted.

#### `--scratch-root DIR`

Override the scratch/scoreboard root. The value `auto` is accepted.

### Timezone and run-ID configuration

These settings use normal TOML/`--set` configuration rather than dedicated CLI
options:

```toml
[time]
timezone = "eastern"

[paths]
run_id_format = "%Y%m%d-%H%M%S-%Z"
clean_scratch_when_completed = true
```

`time.timezone` accepts case-insensitive `eastern`, `utc`, and `local` aliases,
plus IANA names such as `America/Denver`. `local` asks the underlying host for
its timezone. The policy applies consistently to logs, runtime summaries,
persisted timestamps, workers, and run-ID time expansion.

`paths.run_id_format` accepts safe literal filename characters, `%Y`, `%y`,
`%m`, `%d`, `%H`, `%M`, `%S`, `%f`, `%j`, `%Z`, `%z`, and at most one
`{counter}`. The stateless counter is zero-padded from `00` through `99` and
uses highest matching existing counter plus one. Exhaustion is an error; use a
higher-precision time component such as `%f` when more than 100 runs can share
one namespace.

`paths.clean_scratch_when_completed` is a strict boolean and defaults to true.
After a `COMPLETED` or `COMPLETED_LIMIT` run has published durable output,
finished run provenance, archived final scoreboards, and closed SQLite/logging
resources, it removes the exact per-run scratch directory and removes
`scratch_root/current` only when the link still selects that run. The stable
`scratch_root/scoreboard` directory remains available after completion. Set the
option to false with TOML or
`--set paths.clean_scratch_when_completed=false` to retain per-run scratch
files and a copied terminal scoreboard. Paused, resumable-limit, interrupted,
and failed runs are not automatically cleaned.

### SNMP and logging options

#### `--snmp-backend {gufo,pysnmp}`

Select one SNMP backend for the complete run or resume invocation. PySNMP is
the default; Gufo remains available through explicit selection. The coordinator
persists the selected name before discovery. A different or missing persisted
backend on a real resume is a pre-discovery error; there is no automatic
fallback to the other backend.

#### `--snmp-timeout SECONDS`

Override the per-request SNMP timeout.

#### `--per-device-rps RATE`

Override the per-device SNMP request-rate limit.

#### `--log-level LEVEL`

Override the configured log level, for example `DEBUG` or `INFO`.

Console and file logging destinations are configured independently through the
normal configuration/`--set` interface:

```bash
lldp-runner \
  --set 'logging.console=false' \
  --set 'logging.file=true' \
  --set 'logging.filename="/var/log/lldprunner.log"' \
  run --seed core1.example.net
```

`logging.filename="activity.log"` is the default and resolves beneath the
current run-ID directory. Relative nested paths remain inside that run
directory. Absolute or `~`-expanded paths may target a centralized location.
Enabled file logging appends to an existing destination instead of truncating
it. If the configured file cannot be created/opened for append, `run` exits
before discovery and reports the error on standard error. When file logging is
disabled, the run summary prints `Activity log: disabled`.

`run` also preflights scratch and final persistent-output operations before
starting discovery workers. The probe exercises atomic file publication and the
output-root symlink operation used for `latest`; predictable permission/path
failures therefore stop before SNMP collection begins.

## 7. `get-neighbors`

`get-neighbors` probes exactly one target, prints the result to stdout, and
never recursively queries learned neighbors.

```bash
lldp-runner get-neighbors core1.example.net
```

It does not create discovery SQLite state, run directories, snapshots, or
scoreboards.

The explicit `get-neighbors` target may be outside
`discovery.boundaries`. The result
reports that fact, but the boundary does not block the query. Explicit
`query_policy` deny rules remain authoritative.

### `get-neighbors` runtime options

These options may be supplied after `get-neighbors` and may appear around
`SEED`:

```text
--config FILE
--set OPTION=VALUE
--snmp.community VALUE / --community VALUE
--snmp.user VALUE / --snmp-user VALUE
--snmp.auth VALUE / --snmp-auth VALUE
--snmp.priv VALUE / --snmp-priv VALUE
--snmp.backend {gufo,pysnmp} / --snmp-backend {gufo,pysnmp}
--snmp.version {2c,3} / --snmp-version {2c,3}
--snmp-timeout SECONDS
--per-device-rps RATE
--log-level LEVEL
```

Equivalent applicable global options may also appear before
`get-neighbors`.
Repeatable `--set` values before and after the subcommand are accumulated.

Discovery-only options such as workers, batch size, max devices, max hosts,
seed ordering, persistence roots, and resume controls do not apply.

### `get-neighbors` output options

#### `--format {table,detail,csv,json}`

Select one of the four inspection renderers.

`table` is the default compact human-readable view.

`detail` is a scrolling, neighbor-by-neighbor human-readable view.

`csv` emits comment-prefixed seed metadata and a compact neighbor CSV.

`json` emits the richest structured result.

Convenience aliases are available:

```text
--detail
--csv
--json
```

The format aliases are mutually exclusive.

Human output uses color only on an interactive TTY and honors `NO_COLOR`.
CSV and JSON never contain terminal color escapes. Color roles are configured
under `[terminal]`; the defaults preserve the historical LLDP-Runner palette.
When CDP and LLDP describe the same normalized local/remote link, the shared
collector can reconcile them into one neighbor row whose protocol label is
`cdp,lldp`. A plausible trailing `name(serial)` advertisement is preserved
raw while its logical base name and non-merging serial hint are recorded
separately. The base participates in guarded same-link name comparison; the
serial hint requires direct serial corroboration before it can support a
physical-chassis conclusion.
The table uses the shared `output.neighbor_local_width` and
`output.neighbor_remote_port_width` baselines (default 18 each). Local and
Remote Port expand dynamically when longer values fit while preserving at
least 18 columns for Neighbor. The rightmost `Mgmt` column keeps its normal
IPv4 width but expands to the complete text of any valid IPv6 address in the
current rows. The table may exceed the detected terminal width rather than
replace IPv6 address characters with an ellipsis. The table and detail views
also include one compact `SNMP obj/ms:` line. Each
`section=objects/ms` value
reports SNMP varbinds returned before collector filtering and elapsed collector
time. Only sections actually queried are listed. The SYSTEM-MIB metric is named
`sys`; the separate `Timing ms: basic=...` value covers the broader initial
ICMP/SNMP probe phase.

`get-neighbors` always collects these metrics. For a normal discovery run,
set `snmp.report_metrics=true` (for example with `--set`) to include the same
per-host structure in `discovery.json`. CSV output does not include the metrics.

The table and detail title line ends with a right-aligned collection timestamp:

```text
LLDP-Runner single-device inspection      (collected 2026-08-25 15:52:26)
```

When SNMP access succeeds, that timestamp is the most recent successful SNMP
access time. If the device was not successfully accessed, the timestamp is the
result-finalization time. The first CSV metadata line uses `state`, not
`status`, and appends `timestamp=YYYY-MM-DD HH:MM:SS`. Display timestamps are
converted through the effective `[time].timezone` setting.

#### `--trace` / `--tracefile FILENAME`

`--trace` writes an operator-readable resolver/ICMP/SNMP network trace to
stderr. Normal table/CSV/JSON inspection output remains on stdout, so scripts
can redirect the two streams independently.

`--tracefile FILENAME` enables tracing automatically and writes the trace to the
designated file. A relative filename is resolved from the current working
directory. The file is created/truncated before DNS, ICMP, or SNMP work starts;
if it cannot be opened, inspection exits without contacting the device.
Providing both options writes the same trace to stderr and the file.

```bash
get-neighbors core1.example.net --trace
get-neighbors core1.example.net --tracefile core1-snmp.trace
get-neighbors core1.example.net --trace --tracefile core1-snmp.trace
```

Trace begins with the operating-system resolver operations used by the
inspection (`getaddrinfo`, `gethostbyaddr`, and `getfqdn`) and their returned
names/addresses or explicit failures. These are logical resolver calls, not a
claim that literal DNS packets were emitted; NSS, `/etc/hosts`, caches, mDNS, or
other resolver backends may satisfy them.

ICMP sections identify each concrete raw/system-ping attempt, address family,
sequence, timeout, reply/no-response result, and RTT when available. In `auto`
mode, a raw-backend failure and system-ping fallback are both visible.

SNMP sections record LLDP-Runner's backend-neutral logical `GET`/`WALK`
operations, not Gufo's private GETNEXT/GETBULK packet implementation. Query
sections include the intended MIB object/table name, description, numeric OID,
address/profile, SNMP version, retry stage/attempt where applicable, and every
returned varbind. Timeouts, empty walks, and missing requested varbinds are
shown as `NO RESPONSE`. SNMP text/binary values are normalized for safe display,
and
credential secrets are replaced with `<redacted>` if they appear in an exception
message. The final `TRACE SUMMARY` reports resolver-query, ICMP-probe, and
logical-SNMP counts plus total elapsed monotonic time.

`--tracefile` without a filename is a CLI usage error.

#### `--system-only` / `--no-neighbors`

These aliases select the same diagnostic mode. The target is resolved and
checked normally through query policy, ICMP wake-up, credential selection, and
the initial SYSTEM-MIB query. The command then stops without querying:

```text
ENTITY-MIB
IF-MIB
LLDP
LLDPv2
CDP
```

This mode is useful for comparing baseline SNMP response time across different
devices without interface counts, neighbor counts, or ENTITY inventories
dominating the measurement. Human output omits the neighbor table/section. JSON
sets `inspection.collection_mode` to `system_only` and reports only attempted
metrics, normally just `sys`.

```bash
get-neighbors core1.example.net --system-only
get-neighbors --no-neighbors core1.example.net --json
```

#### `--dry-run`

Perform DNS, boundary reporting, query-policy evaluation, and prospective
credential selection without sending ICMP or SNMP traffic.

```bash
lldp-runner get-neighbors core1.example.net --dry-run --json
```

`get-neighbors --dry-run` does not require SNMP secrets to be available.

### `get-neighbors` exit behavior

A successful SNMP response with no CDP/LLDP neighbors exits successfully.

ICMP failure does not prevent SNMP attempts.

If all SNMP attempts fail, `get-neighbors` still renders available DNS,
ICMP, policy,
and attempt information, then exits nonzero.

## 8. `show-neighbors`

The stored-discovery viewer reads finalized `discovery.json` without opening
SQLite state or querying the network. It loads configuration with credentials
disabled: credential tables are not built or validated, generic SNMP credential
environment variables are not inspected, and no credential secrets are
resolved. This keeps stored-data viewing independent from unrelated SNMP policy.
With no source option it uses:

```text
<persistent_root>/<output_dirname>/latest/discovery.json
```

The equivalent command forms are:

```bash
lldp-runner show-neighbors access01
show-neighbors access01
```

`show-neighbors` accepts `--config`, `--set`, and `--persistent-root`. The
`lldp-runner show-neighbors` accepts normal global configuration options
before the subcommand and the same read-only source options after it.

### Discovery source selection

`--runid RUNID` reads one historical finalized run beneath persistent output:

```bash
show-neighbors --runid 20260102-210300-EDT access01
show-neighbors --runid run-07 --id 127 --detail
```

This resolves to:

```text
<persistent_root>/<output_dirname>/<RUNID>/discovery.json
```

The run ID is validated as one safe directory component but is not required to
match the current `paths.run_id_format`. Older runs therefore remain readable
after a site changes its naming convention.

`--file FILENAME` reads an arbitrary discovery document. Relative paths start
at the current working directory; absolute paths and `~` expansion are allowed:

```bash
show-neighbors --file ./archive/discovery.json access01
show-neighbors --file /srv/archive/site-a/discovery.json --id 127 --json
```

`--file` bypasses persistent-root source resolution, which permits examination
of exported JSON on a host without LLDP-Runner discovery storage. `--runid` and
`--file` are mutually exclusive.

### Name and ID selection

A positional pattern and `--name PATTERN` both search `preferred_name`. Matching
uses case-insensitive Python regular expressions with beginning-of-string
`re.match()` semantics. Therefore a plain partial hostname naturally behaves
like a left-prefix search:

```text
client-137001       matches client-137001.example.com
example       does not match alpha.example.org
.*example.*   matches alpha.example.org
client-13.001       matches client-137001 and client-135001
```

Python regex syntax is authoritative; shell-glob `?` semantics are not added.
Invalid regular expressions are CLI usage errors.

Use an exact persisted host ID when ambiguity is undesirable:

```bash
show-neighbors --id 127
```

`--id` is mutually exclusive with name, key, IPv4, and IPv6 criteria. It
preserves the same `id` in standalone JSON output.

When a non-ID query matches more than one host, the viewer prints the matching
IDs and preferred names and exits without choosing a record arbitrarily.

### Key criteria

`--key KEY:PATTERN` searches a top-level or dotted host-record key. It uses a
case-insensitive Python regex with search-anywhere semantics against the
selected value. Arrays and objects are flattened to deterministic text; dotted
paths can also traverse arrays of nested objects.

```bash
show-neighbors --key 'system.model:^C9300'
show-neighbors access --key 'system.manufacturer:^Cisco$'
show-neighbors --key "addresses:'192\\.0\\.2\\.1'"
```

The option is repeatable. Multiple keys and all other non-ID selectors use AND
semantics. A missing key simply means that host does not satisfy the criterion.

### IPv4 and IPv6 criteria

`--ipv4` and `--ipv6` accept either a literal text prefix or CIDR. Prefixes are
not regular expressions, so dots do not need escaping:

```bash
show-neighbors --ipv4 198.51.100
show-neighbors --ipv4 198.51.100.0/24
show-neighbors --ipv6 2001:db8
show-neighbors --ipv6 2001:db8::/32
```

CIDRs use numeric address membership, including normal IPv6 normalization.
Partial non-CIDR values use literal left-prefix matching. The two families may
be combined with each other and with name/key criteria; every supplied
criterion must match. Invalid CIDRs and address-family mismatches are usage
errors.

### Neighbor selection

With no `--neighbors` option, the viewer displays learned neighbors when any
exist. If the selected host has no learned neighbors, it falls back to
`observed_by` evidence. This makes indirectly observed/unmanaged records useful
without changing directly queried devices to an inbound topology view.

Explicit selection disables that fallback:

```text
--neighbors learned       learned only, even when empty
--neighbors observed_by   observed_by only
--neighbors both          learned first, then observed_by
--neighbors               same as --neighbors both
```

`--system-only` and `--no-neighbors` are aliases. Combining either with
`--neighbors` is a CLI usage error because the requests contradict each other.

Schema-7 learned output is rendered from the observation-complete topology
graph when that projection is available. Entity resolution remains provisional,
and relationship labels do not imply inferred physical topology or directness.
The configured layout is selected by `output.relationship_view` and can be
overridden for one command:

```bash
show-neighbors --relationship-view sectioned branch-access-3650-1
show-neighbors --relationship-view combined branch-access-3650-1
```

`sectioned` is the default. It displays ordinary observed relationships first,
then indents shared-chassis logical members, overlay observations, and
multi-neighbor discrepancies. `combined` uses one table with compact labels and
a one-line legend. Both layouts preserve `directness=unresolved`; the labels
describe graph classifications and do not assert a direct cable or downstream
path.

A port with several learned systems is retained as a review condition. This can
represent Nexus VDCs sharing one management attachment, virtual/overlay
behavior, or discovery frames forwarded by a transparent intermediate device.

Terminal neighbor tables use whitespace-padded columns. Learned-only output
retains the `get-neighbors` column order:

```text
Local  Protocol  Neighbor  Remote Port  Mgmt
```

When observed_by evidence is displayed, or both directions are selected, the
sections are visually distinct. Learned always appears first. The `Learned`
and `Observed_by` labels are right-aligned within their respective header rows
and use different bold colors on color-capable terminals. Their semantic colors
are configurable under `[terminal]`. Output remains aligned and readable when
color is disabled or `NO_COLOR` is set. The same
`output.neighbor_local_width` and `output.neighbor_remote_port_width` baselines
used by `get-neighbors` apply here; both default to 18 and can expand
dynamically when the current terminal has room. The rightmost `Mgmt` column
also expands to show a valid IPv6 address in full. Preserving the address takes
priority over constraining the plain-text table to the detected terminal
width; IPv4 column behavior remains unchanged.

### Viewer output formats

The default is a compact terminal system summary followed by the selected
neighbor table. `--detail` adds persisted host, system, SNMP, ICMP,
stack-member, and neighbor fields in a scrolling terminal view.

`--json` prints one standalone host object rather than the outer discovery
container. The persisted host ID is unchanged. `--system-only` removes the two
neighbor arrays. Otherwise the selected neighbor directions remain populated
and unselected directions are represented as empty arrays.

`--csv` prints two `#` metadata lines, a neighbor header, and one interface /
neighbor record per row. The direction field uses `learned` or `observed_by`.
With `--system-only`, only the two comment lines are written: there is no CSV
header and no neighbor row.

The table and detail title line right-aligns the selected JSON generation time,
for example `(json 2026-08-25 15:52:26)`. The source is
`discovery.generated`, converted through `[time].timezone`. If that source
timestamp is unavailable or unusable, human output shows `(json unknown-time)`
and CSV emits `timestamp=unknown`. LLDP-Runner does not substitute filesystem
mtime or the current clock for missing stored provenance.

Human output uses ANSI color only on an interactive terminal and honors
`NO_COLOR`. CSV and JSON never contain ANSI escapes. See
`configs/conf.d/terminal-colors.toml.example` for configurable terminal roles.

### Viewer exit status

```text
0  exactly one record matched and was rendered
1  no records matched
2  invalid CLI/filter/configuration/discovery input
3  more than one record matched and choices were listed
```

The viewer intentionally loads finalized JSON into memory. This keeps the
implementation dependency-free and easy to audit; streaming very large JSON
files can be added later if real deployments require it.

## 9. `diff`

`lldp-runner diff` compares two finalized discovery data sets without opening
runtime SQLite state or contacting network devices. Credential processing is
disabled. With no host selector it performs a macro host/topology comparison.
Adding a host selector performs a one-host comparison.

With no source options, A is the latest finalized run and B is the immediately
previous finalized run:

```bash
lldp-runner diff
lldp-runner diff --changes-only
```

If no previous finalized run can be resolved, the command reports that no
comparison is possible and exits with status 4.

### Diff source selection

Sources are directional and retain command-line order. The supported source
options are:

```text
--latest
--previous
--prior
--oldest
--runid RUNID
--file FILENAME
```

`--prior` is an alias for `--previous`; there is no `--last` alias. `--runid`
and `--file` are repeatable and can be mixed. One explicitly selected non-latest
source is compared as B against latest as A. With two source options, the first
is A and the second is B. `--latest` alone is an error because two different
source references are required.

History aliases use timezone-aware completed timestamps rather than lexical run
ID ordering. LLDP-Runner prefers completion metadata from each finalized
`run.json`; if that metadata is unavailable, it reads only the leading discovery
metadata as a fallback. An explicit `--file` is resolved to an absolute pathname
from the current working directory when necessary, and that absolute pathname is
shown in source headings and ambiguity messages.

### Diff host selection

A positional PATTERN, `--name`, `--key`, `--ipv4`, `--ipv6`, and `--id` retain
the same selection semantics as `show-neighbors`. Name matching is
case-insensitive `re.match()` behavior, key criteria use regex search, address
criteria use prefix or CIDR matching, non-ID criteria are AND-combined, and
`--id` remains exclusive.

The selector identifies a host only in data set A. LLDP-Runner then uses
cross-run identity evidence to locate the same logical host in B. It does not
assume that the numeric host ID is stable between runs and does not blindly
reapply a mutable selector such as software version to B.

Multiple A-side selector matches produce `Multiple records matched:` followed by
ID and preferred-name choices and exit status 3. Multiple B-side identity
matches use `Multiple records matched in <resolved-source>:`. Conflicting
identity evidence is reported as uncertain rather than arbitrarily selecting a
host.

### Diff comparison scope

Macro mode compares host records and each host's `learned_neighbors` only. It
does not compare the top-level error records, and it does not independently
traverse `observed_by_neighbors` because those records are reciprocal topology
evidence that would double-count macro changes.

Host-specific mode reports changed host details plus changes in both learned and
`observed_by` neighbors. Volatile timestamps, run-local IDs, probe RTTs, and
collector `duration_ms` values are normalized away by default. Exact durations
remain in discovery JSON and can be compared explicitly with
`--include-collection-timing`; `--no-include-collection-timing` overrides a true
configuration value. An uptime value is reported only when the chronologically
later record has a lower uptime, which is presented as a possible reboot. Stack
members are matched using durable identity where possible rather than JSON array
position.

`--changes-only` suppresses unchanged host rows from the human macro table while
preserving complete summary counts. `--summary-only` limits human output to
source/result context, summaries, warnings, and collection incidents. Default
human output collapses derivative coverage-uncertain rows beneath each incident;
`--expand-collection-incidents` restores them. The corresponding `--no-*` forms
override true configuration values. JSON always retains full detail.

### Diff output and exit status

Human output starts with resolved A/B source headings and always includes:

```text
Result: <status message>
```

Scope/provenance and collection-coverage warnings are printed immediately after
the `Result:` line.
Terminal tables use the configured semantic color roles when stdout is a TTY;
redirected output remains plain text and `NO_COLOR` is honored.

`--json` emits machine-readable diff JSON instead of human tables. It contains a
separate diff-output schema version, result status and exit code, resolved
sources, warnings, and comparison records. JSON never contains ANSI escapes.
Diff schema 12 qualifies graph entity and relationship correspondence as
`confirmed`, `coverage_uncertain`, `presentation_only`, `evidence_only`, or
`ambiguous` and aggregates derivative effects beneath their originating
collection incident. Intentional `no_query` and `out_of_scope` entities are not
counted as actively queried failures. It reports canonicalized compatibility
projections, independent aggregate-health and topology-sensitive coverage,
separate entity/presentation/collection host dimensions, attribute coverage
provenance, stable-edge evidence changes, and ambiguous weak-identity
`candidate_move` records. Schema 12 retains graph-backed events, cross-view
consistency, graph-native incident dependency, observed attachment semantics,
and management-health transitions. It additionally records orthogonal graph
relationship change dimensions, exact per-member protocol transitions, and
member-scoped event keys.

Exit statuses are:

```text
0  comparison completed with no differences
1  comparison completed and differences were found
2  usage, configuration, source, or schema error
3  host selection or identity matching returned multiple records
4  comparison could not be performed
```

Both selected discovery documents must use the currently supported discovery
schema and must have matching schema versions. See [DIFF.md](DIFF.md) for the
full
source-selection table, cross-run identity evidence tiers, normalization rules,
scope warnings, examples, and machine-readable output contract.

## 10. Standalone `get-neighbors`

The standalone `get-neighbors` entry point uses the same single-device
inspection implementation as `lldp-runner get-neighbors`.

```bash
get-neighbors core1.example.net
get-neighbors core1.example.net --detail
get-neighbors --json core1.example.net
```

Options may appear before or after `SEED`. With `--csv` combined with
`--system-only` or `--no-neighbors`, output consists only of the two existing
`#` system metadata lines. No neighbor CSV header or neighbor rows are emitted.

Supported options are:

```text
-h / --help
--version
--config FILE
--set OPTION=VALUE
--snmp.community VALUE / --community VALUE
--snmp.user VALUE / --snmp-user VALUE
--snmp.auth VALUE / --snmp-auth VALUE
--snmp.priv VALUE / --snmp-priv VALUE
--snmp.backend {gufo,pysnmp} / --snmp-backend {gufo,pysnmp}
--snmp.version {2c,3} / --snmp-version {2c,3}
--snmp-timeout SECONDS
--per-device-rps RATE
--log-level LEVEL
--format {table,detail,csv,json}
--detail
--csv
--json
--dry-run
--system-only / --no-neighbors
--trace
--tracefile FILENAME
```

## 11. `validate-config` and `paths`

Load the effective configuration, apply normal precedence, validate settings,
and validate required credential secrets.

```bash
lldp-runner validate-config
```

A specific configuration may be selected globally:

```bash
lldp-runner --config /opt/lldp-runner/config.toml validate-config
```

Global `--set` and runtime credential options also apply. After validation,
the command prints the install layout and the resolved, write-tested runtime
roots:

```text
Configuration valid: /opt/lldp-runner/config.toml
Install layout:  shared
Persistent root: /opt/lldp-runner/var
Scratch root:    /dev/shm/lldp-runner
```

### `paths [--json]`

Show where the effective configuration keeps run state, finalized outputs, and
scratch data, without creating, write-testing, or changing anything. Credentials
are not processed, so any operator can run it.

```bash
lldp-runner --config /opt/lldp-runner/config.toml paths
```

```text
Configuration:   /opt/lldp-runner/config.toml
Install layout:  shared
Persistent root: /opt/lldp-runner/var (auto)
Runs:            /opt/lldp-runner/var/runs
Outputs:         /opt/lldp-runner/var/outputs
Scratch root:    /dev/shm/lldp-runner (auto)
```

`(auto)` marks a root chosen by the install layout; `(configured)` marks one
set by configuration, environment, `--set`, or a dedicated option. For an
automatic scratch root, the command reports the location that `status` and
`watch` read: the candidate holding a current run, otherwise the first existing
candidate. `--json`
prints the same information with the keys `config_path`, `layout`,
`legacy_layout`, `persistent_root`, `persistent_root_auto`, `runs_dir`,
`outputs_dir`, `scratch_root`, and `scratch_root_auto`.

The install layout follows the primary configuration file; see
[INSTALL.md](INSTALL.md) for the shared, system, and user layouts. When
`runs/` or `outputs/` still sit directly in the installation directory and no
`var/` directory exists, the older location stays in use and the command
prints a warning on stderr. `validate-config` and `run` print the same warning.
`scripts/lrun-paths` runs this command through the shared launcher.

## 12. `generate-config [FILENAME]`

Write a documented TOML configuration starting from built-in defaults.

```bash
lldp-runner generate-config
lldp-runner generate-config site-config.toml
```

When no filename is supplied, the normal output is:

```text
./lldp-runner-config.toml
```

When the current directory is `~/lldp-runner`, `/opt/lldp-runner`, or
`/etc/lldp-runner` and `./config.toml` does not exist, the default output is:

```text
./config.toml
```

If `config.toml` already exists there, the generator uses the normal
`lldp-runner-config.toml` name rather than overwriting the primary file.

An explicit filename is used exactly as supplied. The generator refuses to
overwrite an existing destination.

Global `--set` may alter generated defaults. Global `--snmp.backend` and
`--snmp.version` may alter the generated backend and preferred SNMP version.

```bash
lldp-runner \
  --set 'discovery.max_devices="auto"' \
  --snmp.version 2c \
  generate-config sample.toml
```

## 13. `explain-target TARGET`

Print JSON describing discovery boundary, query-policy, and credential-policy
selection for one target without starting recursive discovery.

```bash
lldp-runner explain-target core1.example.net
```

Global config, `--set`, and credential options apply. The command is read-only
with respect to LLDP-Runner runtime storage: it does not require writable
persistent/scratch roots or available SNMP secret values. Credential profile and
rule definitions are still parsed because they are part of the explanation.
Target-name DNS resolution may still occur.

## 14. `status`

Display `<scratch_root>/scoreboard/scoreboard.txt`. The stable path retains the
last terminal snapshot after successful per-run scratch cleanup.

```bash
lldp-runner status
```

### `status --json`

Print the machine-readable `scoreboard.json` rather than `scoreboard.txt`.

```bash
lldp-runner status --json
```

`status` disables the credential subsystem entirely and resolves its scratch
location without a writable-directory probe. Malformed/unavailable SNMP material
or read-only access to an existing scoreboard cannot block the snapshot.

## 15. `watch`

Interactively monitor the current structured scoreboard without repeatedly
spawning `lldp-runner status`:

```bash
lldp-runner watch
```

The default terminal redraw interval is one second. Scoreboard production is
independent and remains controlled by `output.scoreboard_interval_seconds`
(three seconds by default), so elapsed/freshness indicators may redraw between
actual scoreboard publications.

Options:

```text
--interval SECONDS
--worker-view {auto,full,compact,heatmap,summary}
--palette {dark,light}
--no-color
```

`--worker-view auto` is the default. It reevaluates terminal width and height
after resize events and selects the richest individual-worker layout that fits
without scrolling. `full`, `compact`, and `heatmap` retain the selected density
when more space becomes available. If a fixed view no longer fits usefully, the
dashboard follows `full -> compact -> heatmap -> summary` and marks the
aggregate fallback explicitly as `SMALL` or `ABBREVIATED`.

At normal widths the dashboard leaves the first terminal row blank and renders
one justified title line inside one-cell left and right borders. It uses the
package's canonical application name and version:

```text
LLDP-Runner 0.39.0  Run ID = 20260111-04  STATE = RUNNING  updated 00:03 ago
```

Update age is total minutes and seconds with at least two digits in each field,
so examples include `00:07`, `03:14`, and `67:09`. The state value retains its
semantic style, and a stale active scoreboard keeps a prominent
`*** STALE ***` indication without wrapping the title. Spare title width is
distributed approximately equally among its four sections. On narrower
terminals, cosmetic gap width and then the application version are removed
before run ID, state, update age, or worker status.
The Run ID title segment uses the same muted semantic color as the footer.

Individual worker cells always spell out `BUSY`, `IDLE`, and `DEAD`; an
unexpected state uses the fixed `OTHR` token and is identified exactly in
summary attention output. The density differences are approximately:

```text
full:     [Worker 00 BUSY batch=..184 size=..8]
compact:  [00 BUSY sz=.8]
heatmap:  [00 BUSY]
summary:  aggregate counts plus attention/error and changed workers
```

Worker positions remain ordered by worker ID. Each density uses fixed field
budgets rather than deriving cell width from the largest value in the current
snapshot, so a batch or size gaining another digit cannot move the grid during
a run. Unused leading positions in bounded numeric fields use `.` fill, while
values that exceed a field render visible `#` overflow markers instead of
resizing the cell. Columns remain whitespace-aligned across rows.
State changes are emphasized without adding transition text beside the worker.
`BUSY` uses a blue hue distinct from dashboard heading/metric colors, `IDLE` a
neutral gray/default color, `DEAD` red, and unexpected states a yellow/orange
warning color.

The built-in `dark` palette is intended for black or other dark backgrounds. It
uses a bright cyan family for headings/metrics and a distinct blue for BUSY,
light gray for IDLE, bright red for DEAD, orange/yellow for unexpected/warning
state, green for success, and gray for muted stale content. The `light` palette
uses darker blue/cyan, gray, red, orange, and green foregrounds intended for
white or other light backgrounds.
The configured default is `terminal.palette`. `--palette` overrides it for one
watch session. `--no-color`, `terminal.color = "never"`, `NO_COLOR`, or a
terminal without color capability leaves text at the terminal default style.

For active `RUNNING` and `PAUSING` states, the dashboard becomes stale after
`max(15 seconds, 3 * output.scoreboard_interval_seconds)` without a new atomic
scoreboard publication. Ordinary colors are then muted to gray and the literal
`*** STALE ***` marker remains strongly emphasized. Terminal/final states do
not become stale simply because publication stops.

`watch` reopens `<scratch_root>/scoreboard/scoreboard.json` on every refresh.
A newly published run ID is detected without restarting the command and resets
the delta baseline. The stable file remains after a completed per-run scratch
tree is removed. `scoreboard.json` is versioned independently with
`scoreboard_schema = 1` beginning in LLDP-Runner 0.25.0.

The `Started ... Elapsed ... Plan ...` line is centered in the bordered
content area and has one blank row after it when height permits. When width
allows, Watch uses six spaces between its three elements, twice the compact
three-space gaps. Metric columns use terminal-geometry-based widths rather than
current values, so count and delta growth cannot move later columns. Roomy
layouts place a blank row between metric rows. After ordinary spacing is
allocated, more than ten blank rows remaining immediately above the footer add
a blank row between the title and Started line and a second row after it.

A source-read error is displayed below the worker table and above the footer,
with a blank row above and below. Its `SOURCE: waiting for current scoreboard
under ...` text uses bright red when terminal color is enabled.

The aggregate `Workers N: BUSY ... IDLE ... DEAD ...` line is centered
independently. The renderer places a blank row above and below it whenever
terminal height permits. The same more-than-ten-row condition adds a second
blank row on each side.

Worker capacity is selected before centering. The selected full, compact, or
heatmap row width receives one stable left offset for every table row. Complete
rows therefore have left/right outer whitespace that differs by at most one
column when centering is possible. A partial final row starts at the same first
worker column rather than being centered independently. The renderer does not
reduce worker density solely to create a margin when the uncentered layout is
the only representation that fits.

Narrow and short terminals retain the same four title concepts while shortening
labels and dropping the version when needed. They preserve, in order, state,
run ID, age, worker count/status, and at least an aggregate or heatmap worker
representation. No line wraps. A display as small as 20x4 avoids a title-only
screen and retains a small-terminal indication plus `q`/Ctrl-C exit guidance.
Optional metrics and cosmetic whitespace yield before those essentials. The
footer includes requested/effective mode and terminal geometry when space
permits, for example `worker-view auto->full (120x44)`, and always keeps exit
guidance when it is shown.

Press `m` to cycle `auto -> full -> compact -> heatmap -> summary -> auto`; if
the cycle returns to `auto`, resize events again select the richest view that
fits. Press `h` for one-screen metric/worker help. Modal screens preserve
normal `q`/Ctrl-C behavior.

Like `status`, `watch` disables the credential subsystem entirely and does not
write-probe the scratch path. It requires an interactive terminal; scripts and
redirected consumers should use `status` or `status --json`. Press `q` or
Ctrl-C to exit.

## 16. `pause`

Request a controlled pause of the current run by creating the configured pause
indicator in the current scratch run.

```bash
lldp-runner pause
```

SNMP secret availability is not required for `pause`.

## 17. Preparing a two-run review bundle

`scripts/lrun-bundle-diff` packages the two latest completed runs, or two
explicit run IDs, for local or external review. The prior
`lrun-prepare-bundle` filename is not shipped. It verifies that matching
finalized output and runtime-state directories are present and readable,
executes `lrun-diff --changes-only --json`, creates coherent compact SQLite
backups in a temporary staging area, and writes one uncompressed tar archive.

```bash
./scripts/lrun-bundle-diff
./scripts/lrun-bundle-diff 20260107-06 20260107-05
```

The first explicit run is data set A and the second is data set B. The archive
contains:

```text
outputs/<runid-A>/...
outputs/<runid-B>/...
runs/<runid-A>/...
runs/<runid-B>/...
./diff-<runid-A>-<runid-B>.changes.json
```

The staged SQLite databases are produced with SQLite's backup API and an
integrity check. Live `discovery-state.sqlite-wal` and
`discovery-state.sqlite-shm` sidecars are not included.

No arguments selects the two newest completed runs by the timezone-aware
`completed` timestamp in `run.json`. Any nonzero argument count other than two
is an error. The archive is deliberately uncompressed so the operator can
inspect it directly or apply the site-approved compression and transfer method.

By default the source `outputs/` and `runs/` directories come from
`scripts/lrun-paths --json`, so the bundle reads the same installation data as
`lrun-diff`. Environment overrides for nonstandard layouts are documented in the
script header. They include `LLDP_RUNNER_BUNDLE_ROOT`,
`LLDP_RUNNER_OUTPUTS_DIR`, `LLDP_RUNNER_RUNS_DIR`, `LLDP_RUNNER_PATHS_BIN`, and
`LLDP_RUNNER_BUNDLE_ARCHIVE_DIR`.

## 18. Configuration precedence

The effective runtime precedence is:

```text
defaults.py
  -> primary TOML, @include, and conf.d
  -> LLDP_RUNNER_* environment overrides
  -> repeatable --set overrides
  -> dedicated command-line options
```

Runtime synthesized SNMP credentials are lowest-priority credentials and do
not replace explicit credential/profile policy from configuration.

See [PRECEDENCE.md](PRECEDENCE.md) for the complete assembly and credential
model,
[ENVIRONMENT.md](ENVIRONMENT.md) for environment-variable details, and
[ARCHITECTURE.md](ARCHITECTURE.md) for the full execution model.
