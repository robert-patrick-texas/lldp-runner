# LLDP-Runner Run Lifecycle

## 1. Summary

A discovery run has an initialization phase before any worker sends ICMP or
SNMP traffic. LLDP-Runner announces that phase explicitly so a large seed set
or slow DNS service does not look like a stalled process.

The standard console vocabulary follows this direction of flow:

```text
Run started
    |
    v
Configuration loaded
    |
    v
Seeds loaded
    |
    v
Seed resolution started
    |
    +---- every 30 seconds when still running ----+
    |                                              |
    |     Seed resolution in progress              |
    |                                              |
    +----------------------------------------------+
    |
    v
Seed resolution complete
    |
    v
Discovery starting
    |
    v
Worker scheduling / ICMP / SNMP / topology discovery
    |
    v
Raw advertisements and table coverage finalized
    |
    v
Claims-driven topology graph materialized
    |
    v
Run completed, paused, limited, interrupted, or failed
```

`activity.log` records the same major transitions and adds machine-friendly
counts and phase details at INFO level. Console output intentionally stays
shorter.

See [DNS.md](DNS.md) for seed DNS modes and resolver considerations.

## 2. Discovery operating modes

LLDP-Runner has two discovery operating modes. Seed DNS policy is independent
of these modes.

### 2.1 Recursive discovery

Recursive discovery is used when `discovery.max_devices` is an integer.

A positive value is a managed-device query guardrail. Zero means unlimited
recursive managed-device discovery. Managed neighbors learned from queried
seeds can become later query work when boundary, classification, query policy,
and credentials permit them.

A typical first console line is:

```text
LLDP-Runner run 20260106-00 started: recursive discovery
```

### 2.2 Seed-only discovery

`discovery.max_devices = "auto"` enables seed-only discovery.

Every unique queryable seed can be queried. Learned neighbors are still
recorded, classified, and emitted in topology output, but learned non-seed
managed devices are not recursively scheduled for SNMP.

A typical first console line is:

```text
LLDP-Runner run 20260106-01 started: seed-only discovery (max_devices=auto)
```

Because the complete query population is known after seed initialization,
LLDP-Runner can reduce effective workers and batch size for small seed-only
runs without increasing configured limits.

## 3. Initialization sequence

### 3.1 Run and logging resources

LLDP-Runner allocates or resumes the run and opens state. It then resolves the
effective `snmp.backend`, binds exactly one backend to the logical run, and
validates any persisted resume value before preparing `run.json` provenance or
starting discovery. Configured logging destinations are opened before seed DNS
resolution begins.

The backend name and installed package version are retained in SQLite state,
the top-level `run.json` diagnostic object, and each invocation record. These
records contain no credential values. A selected backend import, construction,
or request failure is reported as that backend's failure; LLDP-Runner does not
try the other backend.

`run.json` uses timezone-aware ISO timestamps for `started` and `completed` and
stores `duration` as their elapsed difference in seconds. The invocation-level
runtime printed at shutdown remains separate so a resumed process can report
its own execution time without changing the logical run start.

Schema 3 additionally records `discovery_duration`,
`graph_resolution_duration`, `graph_serialization_duration`,
`output_publication_duration`, `finalization_duration`, and
`total_wall_clock_duration`. These are nonnegative wall-clock measurements for
the current invocation. The graph/publication values are subphases of
finalization; they are not added again when computing total wall clock.

This lets `activity.log` explain initialization failures that happen before any
worker starts.

### 3.2 Configuration loaded

The console identifies the primary configuration source:

```text
Configuration loaded: /opt/lldp-runner/config.toml
```

The activity log additionally records the number of assembled configuration
files and lists assembled source paths when files are present. Includes and
`conf.d` fragments therefore remain visible without filling the console.

### 3.3 Seeds loaded

LLDP-Runner first reads configured, CLI, environment, directory, file, and
optional standard-input seed sources.

The console reports the number of accepted raw records before textual seed
identity de-duplication:

```text
Seeds loaded: 12842 raw seeds
```

The activity log also reports how many input identities remain after the first
textual de-duplication stage:

```text
seed input loaded: raw=12842 input_identities=12690
```

### 3.4 Seed resolution

Seed resolution performs the authoritative initialization work that can merge
aliases into unique seed hosts. With the default DNS mode this can perform many
resolver operations.

Default mode announces:

```text
Seed resolution started: resolving names, addresses, and duplicate identities
```

With `seed_dns_mode = "skip-addressed"` it announces that eligible addressed
seeds may bypass DNS. See [DNS.md](DNS.md).

### 3.5 Thirty-second progress heartbeat

If seed resolution continues for at least 30 seconds, LLDP-Runner writes a
progress heartbeat every 30 seconds:

```text
Seed resolution in progress: 4821/12690 input identities processed (1m 00s)
Seed resolution in progress: 9617/12690 input identities processed (2m 00s)
```

The heartbeat uses a lightweight timer that does not access SQLite. It can
therefore remain visible while the initialization thread is blocked in a slow
resolver call.

The activity log includes the raw count and DNS-mode counters:

```text
seed resolution progress: processed=4821 total=12690 raw=12842 \
  dns_resolved=480 dns_skipped=4341 elapsed=60.0s
```

The example is wrapped for documentation. One activity-log event is one line.

### 3.6 Seed resolution complete

When resolution finishes, the console reports authoritative seed counts:

```text
Seed resolution complete: 12842 raw seeds -> 12604 unique seeds; \
  12598 queryable, 6 unresolved (2m 47s)
```

The example is wrapped for documentation. Console logging emits one event.

The activity log adds state and DNS details, including policy outcomes:

```text
seed resolution completed: raw=12842 input_identities=12690 processed=12690 \
  unique=12604 queryable=12598 unresolved=6 no_query=0 out_of_scope=0 \
  complete=0 failed=0 dns_resolved=531 dns_skipped=12159 elapsed=167.2s
```

### 3.7 Discovery scheduling

After initialization validation and execution-plan calculation, workers start.
Recursive discovery uses:

```text
Discovery starting: proceeding with 12604 unique seeds
```

Seed-only discovery uses:

```text
Seed-only discovery starting: proceeding with 12604 unique seeds
```

The activity log additionally records READY seeds, effective workers, and
effective batch size.

## 4. Count definitions

`raw seeds`
: Accepted seed records before textual seed-string de-duplication.

`input identities`
: Seed inputs remaining after the first textual de-duplication stage and before
  DNS/alias correlation.

`unique seeds`
: Authoritative managed seed hosts after seed name/address identity
  consolidation in state.

`queryable`
: Seed hosts in READY state after address, boundary, and query-policy checks.

`unresolved`
: Managed seed hosts with no usable IPv4 or IPv6 alias after seed resolution.

A resolved seed that is outside configured boundaries or denied by query policy
is not labeled unresolved. Those states are reported separately in
`activity.log`.

## 5. Recursive discovery console example

```text
LLDP-Runner run 20260106-00 started: recursive discovery
Configuration loaded: /opt/lldp-runner/config.toml
Seeds loaded: 12842 raw seeds
Seed resolution started: resolving names, addresses, and duplicate identities
Seed resolution in progress: 4821/12690 input identities processed (1m 00s)
Seed resolution in progress: 9617/12690 input identities processed (2m 00s)
Seed resolution complete: 12842 raw seeds -> 12604 unique seeds; \
  12598 queryable, 6 unresolved (2m 47s)
Discovery starting: proceeding with 12604 unique seeds
```

## 6. Seed-only discovery console example

```text
LLDP-Runner run 20260106-01 started: seed-only discovery (max_devices=auto)
Configuration loaded: /opt/lldp-runner/config.toml
Seeds loaded: 12842 raw seeds
Seed resolution started: resolving identities; DNS may be skipped for eligible \
  addressed seeds
Seed resolution complete: 12842 raw seeds -> 12604 unique seeds; \
  12598 queryable, 6 unresolved (8s)
Seed-only discovery starting: proceeding with 12604 unique seeds
```

The examples wrap long events for readability. Actual log records are emitted
as single events.

## 7. Activity-log example

The activity log includes standard timestamp, level, process, and logger
prefixes. The message portion for one initialization may include:

```text
run initialization: run_id=20260106-01 action=started mode=seed_only
configuration loaded: primary=/opt/lldp-runner/config.toml sources=4
seed input loaded: raw=12842 input_identities=12690
seed resolution started: raw=12842 input_identities=12690 \
  dns_mode=skip-addressed
seed resolution progress: processed=4821 total=12690 raw=12842 \
  dns_resolved=480 dns_skipped=4341 elapsed=60.0s
seed resolution completed: raw=12842 input_identities=12690 processed=12690 \
  unique=12604 queryable=12598 unresolved=6 no_query=0 out_of_scope=0 \
  complete=0 failed=0 dns_resolved=531 dns_skipped=12159 elapsed=167.2s
seed-only execution plan: 12598 READY seeds; workers 64 -> 64; \
  batch_size 9 -> 9; max_outstanding_devices_per_worker=24
discovery scheduling started: mode=seed_only seeds=12604 ready=12598 \
  workers=64 batch_size=9
```

## 8. Initialization failures

Seed resolution occurs before worker startup. A finite `max_devices` guardrail
can therefore reject the run after DNS and identity consolidation have already
completed.

Example console sequence:

```text
LLDP-Runner run 20260106-03 started: recursive discovery
Configuration loaded: /opt/lldp-runner/config.toml
Seeds loaded: 1842 raw seeds
Seed resolution started: resolving names, addresses, and duplicate identities
Seed resolution complete: 1842 raw seeds -> 1796 unique seeds; \
  1794 queryable, 2 unresolved (19s)
Run initialization failed: 1796 unique managed seed devices were supplied, \
  but discovery.max_devices is 1000. No discovery queries were started. ...
```

The activity log records the run ID, discovery mode, exception type, and full
reason. No worker ICMP or SNMP query has started when this seed-count validation
fails.

## 9. Resume behavior

A resumed run announces `resuming` rather than `started`. Active claims are
reset, newly supplied seeds are resolved, seed order is normalized, and the
current runtime guardrails and execution plan are recalculated.

The effective backend name must exactly match the name persisted for the
logical run. A different requested backend, or a real pre-0.36 run with no
backend metadata, is rejected before discovery and before run-provenance
mutation. The installed package version may differ between invocations and is
recorded per invocation, but the backend implementation cannot change.

The logical run retains its original persisted start time. The final `Runtime:`
summary continues to describe the current invocation duration.

## 10. Live watch dashboard

`lldp-runner watch` follows the structured live file at
`<scratch_root>/scoreboard/scoreboard.json`. The stable file remains readable
after a completed run even when its per-run scratch tree is removed. Watch does
not perform network discovery, invoke the credential subsystem, or write-probe
run storage. At normal widths the screen starts with a blank row,
keeps one blank cell at both side edges, and uses this justified title:

```text
LLDP-Runner 0.38.1  Run ID = 20260111-04  STATE = RUNNING  updated 00:03 ago
```

The update age uses total minutes and seconds, including values such as `67:09`.
Spare width is divided approximately equally among the four title sections.
When width is reduced, cosmetic gaps and then the application version are
cropped before run ID, state, age, or worker information.
The Run ID segment uses the same muted semantic color as the footer.

The `Started ... Elapsed ... Plan ...` line is centered independently and has
one blank row after it when height permits. When width permits, its two gaps use
six spaces rather than the compact three-space form. Metrics use broad
geometry-based columns with stable count/delta fields, and roomy terminals add a
blank row between metric rows. After ordinary spacing is allocated, more than
ten blank rows remaining immediately above the footer adds one blank row
between the title and Started line and a second row after the Started line. The
aggregate worker summary is centered with a blank row above and below when
height permits; the same roomy condition adds a second row on each side.
The worker grid is centered after full/compact/heatmap capacity is selected, so
complete rows have balanced outer whitespace and a partial final row stays
aligned with the first worker column. Worker-cell content and density are
unchanged. A live-source error is rendered in bright red when color is enabled,
below the worker table and above the footer, with a blank row on each side.

When width or height is constrained, the dashboard degrades deliberately through
`full -> compact -> heatmap -> summary`. It preserves state, run ID, age,
aggregate BUSY/IDLE/DEAD worker counts, an explicit `SMALL` or `ABBREVIATED`
indication, and `q`/Ctrl-C guidance before optional metrics. No rendered line
wraps, and very short terminals do not collapse to a title-only screen. Press
`m` to change worker view, `h` for help, and `q` or Ctrl-C to exit.

Active `RUNNING` and `PAUSING` scoreboards retain the prominent `*** STALE ***`
indicator when publication age crosses the configured stale boundary. Final
states do not become stale merely because the producer has stopped.

## 11. Related references

- [DNS.md](DNS.md) describes resolver behavior and `seed_dns_mode`.
- [NAMES.md](NAMES.md) describes name/address identity consolidation.
- [PRECEDENCE.md](PRECEDENCE.md) describes configuration and CLI precedence.
- [ARCHITECTURE.md](ARCHITECTURE.md) describes coordinator/state scheduling.
- [PRIMER.md](PRIMER.md) explains adaptive table collection and evidence terms.

## 12. Adaptive SNMP timeout, pacing, and access restrictions

`snmp.backend` selects `pysnmp` (the default) or `gufo`. Configuration-file,
environment, `--set`, and dedicated CLI precedence is resolved once before the
run starts. The bound selection is copied into every worker and checked again
at the backend factory boundary, so one run cannot use mixed transports.

A run started with Gufo remains a Gufo run. After upgrading to 0.37.0, keep an
explicit `snmp.backend = "gufo"` setting when resuming it. An omitted backend
now resolves to PySNMP, and the durable mismatch check rejects that resume
before discovery rather than changing the run's transport implementation.

PySNMP transport targets always use `retries=0`. Gufo behavior is unchanged.
For either backend, the retry policy described below remains wholly owned by
LLDP-Runner.

LLDP-Runner creates one adaptive transport state for each target address and
credential route. The same state follows a successful target from basic
SYSTEM-MIB collection into detail collection.

Retry policy has three normal boundaries:

- each logical operation/table receives its own bounded retry allowance;
- each collector family receives a bounded fair-share allowance; and
- retries consume either the shared target pool or, for LLDP-family and CDP, a
  protected neighbor reserve.

LLDP and LLDPv2 share the `lldp` normal-retry family because they are alternate
MIB generations of the same protocol. CDP has its own family. SYSTEM-MIB,
ENTITY-MIB, IF-MIB, and other collectors cannot consume the protected neighbor
reserve. With the defaults, general work can consume at most three shared
retries, while LLDP-family and CDP can consume up to two protected retries in
addition. The per-collector default of one prevents a multi-walk collector from
monopolizing either pool.

The first eligible timeout or structural table failure enters one persistent
degraded profile:

```text
timeout_after = timeout_before * retry_timeout_multiplier
max_repetitions_after = ceil(
    max_repetitions_before * retry_max_repetitions_multiplier
)
max_repetitions_after >= retry_min_max_repetitions
inter_pdu_delay_after += retry_inter_pdu_delay_ms
```

The defaults increase timeout by 50 percent, halve GETBULK work, halve GET-MANY
OID batch size, and add 100 milliseconds of pacing. Later operations on the same
target route reuse the slower profile. A new target or credential route starts
with normal configured values and fresh counters.

A failed table attempt is not a partial success. Rows returned before failure
are discarded, the backend session is reopened with the degraded profile, and
the table starts again at its root. LLDP/LLDPv2 require complete mandatory
chassis-ID and Port-ID columns. CDP requires a usable device ID and remote port
for every materialized row plus consistent cache indexes.

An optional second resilience layer handles short-lived packet loss or an agent
table that is changing while it is walked. After all enabled LLDP, LLDPv2, and
CDP first passes finish, the worker identifies only final `timeout` and
`structurally_invalid` outcomes. When at least one is eligible, it waits once
for `neighbor_stability_retry_delay_seconds`, reopens a fresh backend session
for each failed protocol, and performs exactly one complete retry from that
protocol's root. The normal operation/collector retry machinery is suppressed
during this final pass, so one stability retry cannot expand into nested
transport or structural attempts. Each protocol can receive at most one
stability retry per target.

Authentication failures, access/view restrictions, unsupported OIDs, ordinary
transport errors, and other definitive exceptions do not enter the stability
pass. Set `neighbor_stability_retry = false` to disable it or set the delay to
`0` for an immediate final pass.

The relevant configuration is:

```toml
[snmp]
backend = "pysnmp" # default; use "gufo" for an explicit Gufo run
timeout_seconds = 3.0
max_repetitions = 20
per_device_rps = 5.0
retry_per_operation = 1
retry_per_collector = 1
retry_total_cap = 3
retry_neighbor_reserve = 2
structural_table_retry = 1
retry_timeout_multiplier = 1.5
retry_max_repetitions_multiplier = 0.5
retry_min_max_repetitions = 1
retry_inter_pdu_delay_ms = 100.0
neighbor_stability_retry = true
neighbor_stability_retry_delay_seconds = 2.0
```

Operational SNMP message bodies use a stable field order:

```text
SNMP target=<address-or-name> <message>
```

The normal logging formatter supplies timestamp, level, worker, and logger. A
retry or exhaustion record includes collector, collector family, logical
operation, table, root OID, credential route/profile, collection phase, retry
pool, attempt, per-operation/collector/target counters, before/after transport
values, discarded partial rows, and final outcome. Stability records also carry
the configured quiet-period delay. The target remains the first message-body
field so concurrent worker logs are machine-searchable.

Adaptive telemetry is retained with immutable SNMP-result evidence and in the
host SNMP section of `discovery.json` when present. It records initial and
effective transport values, shared/reserved/stability counters, operation and
collector counts, retry outcomes, exhaustion reasons, and whether partial
results were discarded. `total_retries_used` includes normal and stability
retries; the pool-specific counters explain how that total was allocated.
Collection coverage `attempts` counts allowed retry attempts, including the
final stability pass, but not unavailable retry decisions.

An authenticated agent that explicitly returns `noAccess`,
`authorizationError`, or an equivalent VACM/ACL/view denial is recorded as
`snmp_access_restricted`. Access denial is not retried as a performance problem.
It remains distinct from bad credentials, transport timeout, unsupported OID,
and a successful empty optional table.

## 13. Evidence finalization and graph publication

A completed schema-7 run publishes its topology in two related forms:

```text
immutable protocol advertisements and claims
    -> supersedable graph decisions
    -> observation-complete topology_graph
    -> flat hosts/learned_neighbors compatibility projection
```

CDP, LLDP, and LLDPv2 rows are recorded before cross-protocol merging. The
materializer can therefore reconsider an earlier grouping when stronger or
conflicting evidence appears. An unchanged replay produces the same projection
fingerprint. A changed conclusion appends a decision that supersedes the prior
one and transactionally replaces the current graph without deleting history.
Every durable protocol advertisement is present in the graph or in an explicit
exclusion record. Entity resolution remains provisional, and physical topology
and directness remain uninferred unless later evidence supports them.

A local interface containing several learned systems is not automatically a
physical fan-out. The graph keeps every advertisement, flags the interface for
review, and leaves directness unresolved. Network Operations can then determine
whether the evidence represents shared Nexus management, virtual/overlay
behavior, or frames forwarded through a transparent device.

Collection coverage remains independent from topology. A table status of
`complete` can support an authoritative absence. Timeout, access restriction,
unsupported data, structural failure, or not-attempted means the value was not
observed and cannot by itself prove removal.

Finalized files are published below the effective canonical
`outputs/<run-id>/` directory. An installation may retain an older filesystem
symlink for administrative transition, but completion logs and returned paths
resolve that alias and consistently show `outputs/`. The persisted logical
`duration` ends at discovery completion; the schema-3 finalization and total
wall-clock fields make graph generation and publication visible separately.

For `COMPLETED` and `COMPLETED_LIMIT`, successful finalization ends in this
order:

```text
write final discovery/run/CSV files
  -> publish outputs/<run-id> and outputs/latest
  -> publish the terminal live scoreboard
  -> checkpoint final SQLite state and finish final run provenance
  -> close SQLite, activity log, workers, and coordinator queues
  -> archive final scoreboards in runs/<run-id>
  -> optionally archive scoreboards in scratch/<run-id>
  -> remove durable run.json.draft
  -> publish runs/latest -> <run-id>
  -> optionally remove completed per-run scratch
```

`runs/latest` and `outputs/latest` are relative sibling symlinks. Startup
preflights both aliases so a conflicting real file/directory or unsupported
symlink operation fails before SNMP work begins. Automatic resume scans only
real run-ID directories and never returns the `runs/latest` alias as a run ID.

`[paths].clean_scratch_when_completed` defaults to `true`. When enabled, the
post-close step recursively removes `<scratch_root>/<run-id>/`, including
JSON/CSV snapshots, drafts, and any future per-run transient files. It unlinks
`<scratch_root>/current` only if that link still resolves to the same run; a
newer run's alias is preserved. The live files below
`<scratch_root>/scoreboard/` remain available after completion. Final text and
JSON scoreboards are always archived below the durable run directory; when the
option is false, they are also copied to the retained scratch run directory.
The completed durable `run.json.draft` is removed after final `run.json`
publication. Non-success terminal states retain per-run scratch state for
resume and diagnostics.

## 14. Preparing consecutive runs for review

After two completed runs, create a portable review archive with:

```bash
./scripts/lrun-bundle-diff
```

To select the comparison explicitly:

```bash
./scripts/lrun-bundle-diff RUNID_A RUNID_B
```

The helper validates matching output and runtime-state trees, generates a
changes-only JSON diff, creates coherent compact SQLite backups, excludes
WAL/SHM sidecars, and packages both runs plus the diff. See
[CLI.md](CLI.md#17-preparing-a-two-run-review-bundle) for the archive layout and
environment overrides.

## Failed hosts and later addresses

A failed managed host is not automatically retried when it is observed again.
Workers persist every attempted address and non-secret credential route. The
coordinator considers a late recovery only when a later direct observation
adds a policy-permitted identity address that is absent from that history.

`discovery.late_address_recovery_attempts` controls the admission count. The
default is `1`; `0` disables it. Admission changes the host from `FAILED` to
`READY`, records a `late_address_recovery_admitted` scheduler event, and limits
the new task to the admitted addresses. The consumed count and scheduler event
survive restart. Duplicate host reconciliation keeps the maximum consumed
count so a merge cannot create more attempts.

Activity logging states the host, evidence source, newly admitted addresses,
and allowance use. Older route errors remain in output and become recovery
evidence when a later basic route succeeds.
