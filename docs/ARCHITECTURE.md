# LLDP-Runner concept of operations and architecture

This document explains what LLDP-Runner does, how its major components work,
and why the current architecture is structured the way it is. It is intended
for Network Operations staff, package maintainers, and future developers.

The document starts with the general concept of operations, then moves into
implementation detail. Current source code is authoritative when this document
and code disagree.

Source-maintained diagrams for collection, compatibility identity resolution,
and graph rematerialization are in
[`dev/FLOW-DIAGRAMS.md`](dev/FLOW-DIAGRAMS.md).

## 1. Purpose and operating model

LLDP-Runner is an SNMP-based network topology discovery tool. It starts from
one or more operator-supplied seed devices, queries those devices, learns CDP,
LLDP, and LLDPv2 neighbors, classifies the learned identities, and optionally
recurses into neighbors that policy identifies as managed network devices.

Its primary goals are:

1. Discover network topology without requiring an external state service.
2. Keep identity, scheduling, and duplicate prevention centrally controlled.
3. Query many devices concurrently without overwhelming one SNMP agent.
4. Preserve partial information when some devices or collectors fail.
5. Make pause, resume, sampling, and bounded discovery operationally safe.
6. Produce JSON and CSV outputs that are useful outside LLDP-Runner.
7. Reuse the same probing components for quick single-device inspection.

A simplified view is:

```text
operator seeds
     |
     v
+----------------+
| configuration  |
| policy/defaults|
+-------+--------+
        |
        v
+----------------+
| coordinator    |
| identity/state |
| scheduling     |
+-------+--------+
        |
        +-------------------------------+
        |                               |
        v                               v
+---------------+               +---------------+
| worker 0      |      ...      | worker N      |
| asyncio SNMP  |               | asyncio SNMP  |
+-------+-------+               +-------+-------+
        |                               |
        +---------------+---------------+
                        |
                        v
                device results
                        |
                        v
                +---------------+
                | coordinator   |
                | merge/classify|
                +-------+-------+
                        |
                        v
                more managed work
                        |
                        v
                 JSON / CSV / state
```

## 2. Discovery is graph traversal, not a strict tree walk

LLDP-Runner treats the environment as a graph.

A queried switch may report several neighbors. Two different switches may
report the same neighboring device. A device may be reached through multiple
names, management addresses, or chassis identifiers.

For that reason, discovery is not implemented as simple recursion such as:

```text
query A
  query B
    query C
      query D
```

Instead, workers discover candidate observations while the coordinator owns
canonical run state, scheduling, and graph materialization and decides what is
eligible for future work.

The traversal has breadth/wavefront characteristics, but it is not strict BFS.
Concurrency, cohort assignment, seed ranking, work stealing, and device
response time mean results can arrive in a different order from graph depth.

The important invariant is not traversal order. It is:

```text
one current schedulable identity -> at most one schedulable host record
```

## 3. Major execution modes

LLDP-Runner currently has two execution models.

### 3.1 Recursive or seed-only discovery

`lldp-runner run` creates persistent run state, starts worker processes, writes
scoreboards and snapshots, and may recurse through learned managed neighbors.

The run can operate in:

```text
finite recursive mode
unlimited recursive mode
seed-only mode
```

The selected `discovery.max_devices` value controls the mode.

### 3.2 Single-device inspection

`lldp-runner get-neighbors SEED` and `get-neighbors SEED` query one target
and print the result to stdout.

Inspection intentionally does not create:

```text
SQLite run state
run/output directories
scoreboards
snapshots
worker processes
recursive neighbor work
```

It normally reuses the same DNS, policy, credential, ICMP, SNMP, system,
interface, ENTITY-MIB, LLDP, LLDPv2, CDP, sanitation, and neighbor-merge
components used by normal discovery workers.

`--system-only` (alias `--no-neighbors`) deliberately exits the shared worker
primitive after the successful SYSTEM-MIB probe. It does not open the detail
SNMP session, so ENTITY-MIB, IF-MIB, LLDP, LLDPv2, and CDP cannot influence a
baseline response-time comparison.

This makes `get-neighbors` useful as a preflight tool before a larger discovery.

## 4. Configuration model

### 4.1 Built-in defaults

Built-in operational defaults live in:

```text
src/lldp_runner/defaults.py
```

The file is normal Python package source on purpose. Distribution maintainers
or site-local support teams may patch those defaults as part of maintaining a
site build.

A configuration file may be partial. Omitted values inherit built-in defaults.

### 4.2 Runtime precedence

The effective precedence is:

```text
defaults.py
  |
  v
primary TOML + @include + conf.d
  |
  v
LLDP_RUNNER_* environment overrides
  |
  v
--set overrides
  |
  v
dedicated command-line options
```

Higher layers override lower layers for scalar values. The authoritative
operator-facing description, including credentials and seed exceptions, is
maintained in [PRECEDENCE.md](PRECEDENCE.md).

### 4.3 Primary config discovery

When neither `--config` nor `LLDP_RUNNER_CONFIG` supplies a path, LLDP-Runner
checks:

```text
~/lldp-runner-config.toml
~/lldp-runner/config.toml
/opt/lldp-runner/config.toml
/etc/lldp-runner/config.toml
```

The first existing file is used. If none exists, built-in defaults are used.

An explicitly supplied path is authoritative. A missing explicit file is an
error rather than a reason to search elsewhere.

### 4.4 `@include`

`@include` is an LLDP-Runner preprocessing directive, not TOML syntax.

Examples:

```toml
@include "siteone/query-policy.toml"
@include /opt/lldp-runner/shared-credentials.toml
```

Relative includes are resolved relative to the file containing the directive.
Absolute paths remain absolute.

Nested includes are supported. Include cycles are rejected.

### 4.5 Automatic `conf.d`

When a real primary config file is selected, LLDP-Runner automatically scans a
`conf.d` directory adjacent to that primary file.

If the primary file is:

```text
/opt/lldp-runner/config.toml
```

then the automatic fragment directory is:

```text
/opt/lldp-runner/conf.d/
```

It is not the package's `configs/conf.d/` example directory unless the primary
config itself is inside `configs/`.

Only files ending exactly in `.toml` are active. Traversal is recursive and
files are ordered lexically by relative path.

```text
conf.d/
  10-site/
    10-credentials.toml
    20-query-policy.toml
  20-classification.toml
  z-local.toml
```

The ordering above is the processing order.

### 4.6 Include and `conf.d` de-duplication

Every resolved configuration file is loaded at most once per complete config
load.

If `a.toml` includes `z.toml`, and `z.toml` would later be found by the
`conf.d` scan, the later scan skips it.

A shared loaded-file set prevents duplicate policy rules. A separate include
stack is retained so true include cycles are still errors.

### 4.7 Merge behavior

Included/config-fragment tables merge recursively.

Most lists concatenate so policy can be split across files while retaining
first-match ordering.

Two lists intentionally replace earlier values:

```text
discovery.boundaries
discovery.address_preference
```

This prevents an unlimited default boundary from remaining active beside a
later site-specific restricted boundary.

## 5. Dynamic runtime defaults

Some defaults cannot be fully resolved until the program is running.

### 5.1 Worker count

`workers = "auto"` resolves to:

```text
(os.cpu_count() or 1) * 4
```

Workers are processes. Each worker then runs asyncio internally.

### 5.2 Persistent root

`persistent_root = "auto"` follows the install layout of the selected primary
configuration file (`lldp_runner.layout`):

```text
/etc/lldp-runner/config.toml         -> /var/lib/lldp-runner     (system)
<dir>/config.toml outside home       -> <dir>/var                (shared)
<dir>/config.toml below home         -> <dir>/var                (user)
~/lldp-runner-config.toml or no file -> ~/lldp-runner/var        (user)
```

The data directory is a subdirectory rather than `<dir>` itself because
discovery write-tests the persistent root. A group-writable installation root
would let any operator add files, such as `uv.toml` or `conf.d/`, that the
maintainer or service account later loads.

Only a user root is created on demand. Shared and system roots need
administrator-set ownership and group permissions, so a missing one is an error
that names `scripts/shared-setup.sh`. An existing but unwritable root also fails
rather than silently moving durable state elsewhere.

When `<dir>/var` does not exist but `<dir>/runs` or `<dir>/outputs` does, the
installation predates the layout and `<dir>` stays the persistent root. The
`paths`, `validate-config`, and `run` commands then warn that the directories
should move into `var/`. Symlinks such as `<dir>/runs -> var/runs` do not count,
because `var/` exists.

The read-only resolvers used by `status`, `watch`, `clean`, `purge`, `paths`,
`show-neighbors`, and `diff` apply the same layout without creating or
write-testing anything.

### 5.3 Scratch root

`scratch_root = "auto"` tries the layout's candidates, then
`<persistent_root>/tmp`:

```text
shared  /dev/shm/lldp-runner
system  /run/lldp-runner, /dev/shm/lldp-runner
user    $XDG_RUNTIME_DIR/lldp-runner (when set)
```

Scratch locations may fall through because scratch data is intentionally
relocatable. Read-only commands prefer the candidate that holds a `current`
run, so `status` and `watch` find a run that fell back to
`<persistent_root>/tmp`.

Every run uses `<scratch_root>/<run-id>/` plus an atomic relative
`<scratch_root>/current` symlink while active. Live status is published
separately below `<scratch_root>/scoreboard/`, so removal of a completed per-run
scratch tree does not remove the terminal Watch/status snapshot. For successful
terminal states, `paths.clean_scratch_when_completed = true` removes the run
tree only after durable output/state publication, scoreboard archival, and
coordinator resource closure. The current link is removed only if it still
points to the completed run, preserving a newer concurrent owner. Overlap
checks prohibit recursive cleanup when scratch resolves inside or above the
persistent run/output directories.

Inspection skips persistent/scratch probing because it produces stdout only.

## 6. Seed ingestion

### 6.1 Additive sources

A discovery run may receive seeds from:

```text
configuration discovery.seeds
configuration discovery.seed_files
configuration discovery.seed_dirs
--seed
--seed-file
--seed-dir
LLDP_RUNNER_SEEDS
LLDP_RUNNER_SEED_FILES
LLDP_RUNNER_SEED_DIRS
stdin when --stdin is present
```

The sources are consolidated before discovery initialization.

### 6.2 Plain-text input

Plain-text files contain one target per line.

Blank lines and lines beginning with `#` or `;` after whitespace are ignored.
For active lines, the first comma, semicolon, or hash starts trailing
annotation.

```text
core1.example.net, inventory comment
192.0.2.10 ; temporary seed
2001:db8::10 # IPv6 management
```

### 6.3 Seed directories

Seed directories are recursive and deterministic.

LLDP-Runner skips:

```text
hidden files
files below hidden directories
names beginning with README
names ending in .disabled
names ending in .note
```

Files ending in `.csv` use the current `seeds.csv` field set through the shared
dynamic-position CSV reader. Other files use the plain-text parser.

### 6.4 Supported seed CSV

Only the current seed inventory schema is supported:

```text
preferred_name,queried_as,ipv4,ipv6,credential_profile,credential_result,
origin,state,last_seen,notes
```

The field names are required, but columns may appear in any order. Header
matching is case-insensitive and extra columns are ignored. Legacy seed input
field names are intentionally not guessed or accepted.

A current seed row can carry a previous successful query target plus known IPv4
and IPv6 aliases. That allows a later run to retain useful management-address
hints even when DNS is temporarily unavailable.

`discovery.seed_dns_mode` controls whether initial seed resolution always uses
the resolver (`resolve`, the default) or can reuse a conservative combination
of logical name + prior `queried_as` (`skip-addressed`). A successful/complete
prior state is required when state metadata is present. IP-only and failed or
mixed-state inputs still use normal DNS. This setting does not change learned
managed-neighbor DNS enrichment. See [DNS.md](DNS.md).

## 7. Seed identity and ordering

### 7.1 First-stage consolidation

Repeated logical seed strings are merged while retaining useful address hints.

### 7.2 DNS and authoritative identity correlation

During coordinator initialization, seeds are resolved and inserted into the
central state store. Aliases can cause records to merge when evidence shows they
refer to the same host.

The final unique seed identities are known only after this stage.

The initialization phase is explicitly logged before workers start. The console
announces run type, configuration, raw seed count, seed-resolution start, a
30-second progress heartbeat for long resolution, completion counts, and the
transition to discovery. `activity.log` receives additional structured counts
and policy-state detail. See [RUN.md](RUN.md).

### 7.3 Seed ordering

Ordering is applied to the de-duplicated seed identities.

`input` keeps first-seen order.

`sorted` sorts case-insensitively by resolved preferred presentation name.

`random` computes a stable BLAKE2-based ordering from:

```text
shuffle key + normalized preferred identity
```

If no shuffle key is supplied, one is generated for a new run and persisted.
That means pause/resume does not reshuffle the remaining seeds.

Seed rank is stored in SQLite and seed work is prioritized globally by rank.
This prevents per-worker cohort ordering from defeating the requested
seed order.

## 8. Identity and duplicate prevention

The SQLite `hosts` table remains the authoritative compatibility projection
used by the current scheduler and external discovery output. Beginning with
0.31.5, immutable `observations` and typed `claims` preserve the factual input
that produced that projection, while append-only `resolution_decisions` retain
why an observation was assigned to a host and which later decision superseded
it.

Host evidence may include:

```text
directly observed names
IPv4 address claims
IPv6 address claims
chassis identity aliases
SNMP sysName
query target
```

`StateStore.upsert_candidate()` looks for aliases and address claims that
already map to hosts. Names and accepted chassis/MAC identities use globally
owned alias rows. IPv4 and IPv6 values use a many-to-many claim table: a unique
value can locate one host, while a repeated value becomes contested and cannot
merge all claimants. This prevents processing order from assigning a common
default, overlapping private, anycast, or vendor-bug address to whichever host
appeared first.

Subtype-aware chassis evidence includes its subtype, and binary MAC/network
values must decode as the advertised type before participating in correlation.
Malformed values remain observation evidence only. Device-local chassis
subtypes such as interface name/alias and port/chassis component are not global
host aliases. Beginning with 0.31.5, a network-address chassis value is a weak,
edge-scoped claim and cannot independently select or merge hosts across links.
A separately advertised management address remains an address claim. Address
claims also pass a host-eligibility boundary: unspecified,
loopback, multicast, IPv4 this-network/reserved, and limited-broadcast values
are excluded. Private, CGNAT, benchmark, and link-local unicast values remain
eligible.

Before reusing an existing host, the state store normally rejects contradictory
trusted chassis identities. A matching normalized name plus at least one shared
management address is strong logical corroboration and can override a differing
chassis ID; this supports platforms such as Nexus VDCs that advertise
link-specific LLDP chassis MACs. A chassis-only match is still rejected when
both sides have non-empty, disjoint names and management-address sets. When
multiple compatible host records are proven to represent one identity,
`StateStore._merge_hosts()` combines them.

A merge must preserve important evidence, including:

```text
seed provenance
classification
tags
neighbor edges
errors
successful query/credential metadata when available
```

The coordinator, rather than workers, performs authoritative insertion and
merging. This is a major duplicate-prevention design decision.

Learned-neighbor DNS resolution is enrichment, not equivalent to a directly
advertised identity claim. Resolver results can affect classification,
presentation, query policy, and task construction, but only the direct protocol
name is admitted to global name identity on that path. This prevents unrelated
devices whose names resolve through the same frontend from merging.

The 0.31.5 claim ledger classifies evidence independently along two axes:
strength (`strong`, `moderate`, `weak`, or `diagnostic`) and scope (`global`,
`physical_container`, `snmp_agent`, `observer`, `edge`, or `diagnostic`). Strict
Cisco `SEP<12-hex>` and Cisco AP MAC-encoded names are strong derived hardware
claims. DNS enrichment and repeated/default chassis addresses remain weak or
diagnostic. Fingerprints exclude collection time, so replaying an identical
normalized observation does not duplicate evidence. The current compatibility
projection still performs some immediate merges; [CLAIMS.md](CLAIMS.md)
describes this staged migration and its explicit limits.

See [NAMES.md](NAMES.md) for detailed name/address normalization, presentation,
identity-folding use cases, and duplicate-name collision guidance.

## 9. Host provenance

Each host has an internal `is_seed` flag.

`hosts.csv` exposes this as the grep-friendly `origin` field:

```text
seed
learned
```

`seed` means the identity was explicitly presented as input.

`learned` means LLDP-Runner first obtained the identity from topology discovery.

Origin is provenance, not current query state. A learned switch remains
`learned` after recursive polling later succeeds.

## 10. Classification model

Classification determines what LLDP-Runner believes a candidate represents.

Current categories are:

```text
managed_device
managed_endpoint
unmanaged_device
unknown_device
```

Only positively classified managed devices are normally eligible for recursive
SNMP work.

Unknown hosts are retained as evidence but are not queried merely because they
exist.

### 10.1 Classification precedence

The current classification flow is conceptually:

```text
explicit address rules
  -> explicit name rules
  -> composite evidence rules
  -> managed-endpoint patterns
  -> capability-based phone/AP inference
  -> unmanaged patterns
  -> LLDP station-only evidence
  -> managed manufacturer + network capability
  -> unknown
```

Earlier explicit rules are intended to override later heuristics.

### 10.2 DNS-enriched reclassification

A neighbor may initially be reported with a short name or only an address.
When enabled, LLDP-Runner may resolve additional managed names before final
state insertion and scheduling.

The enriched candidate is classified again before recursive polling.

This matters when site ownership policy depends on FQDN/domain naming.

### 10.3 Evidence rules

Composite evidence rules can combine conditions such as:

```text
name patterns
address networks
normalized neighbor fields
protocol-specific detail fields
```

Alternatives within a list use OR semantics. Distinct configured condition
kinds use AND semantics.

Classification rules are first-match-wins.

### 10.4 Tags

Tag rules use similar evidence but accumulate rather than stop at the first
match. Tags are de-duplicated while retaining configuration order.

## 11. Query policy and discovery boundaries

Classification answers:

```text
what kind of host is this?
```

Query policy answers:

```text
may LLDP-Runner send queries to this host?
```

Discovery boundary answers:

```text
is this address inside recursive discovery scope?
```

These are intentionally separate concepts.

A host may be classified as a managed device but still be denied by query
policy or outside the configured boundary.

### 11.1 Boundary rules

Recursive discovery requires candidate query addresses to be in configured
IPv4/IPv6 boundaries.

An explicit `get-neighbors` target is allowed outside those boundaries
for troubleshooting. The inspection result reports the boundary status.

Inspect does not bypass explicit query-policy denies.

### 11.2 Query-policy matching

Query policy supports address and name rules. Explicit rules are evaluated
according to their configured ordering and action.

The default action is configurable and is `allow` in built-in defaults.

## 12. Credential selection

### 12.1 Explicit site credentials

Configuration can define SNMPv2c and SNMPv3 authPriv credentials, named
profiles, and address/name rules selecting those profiles.

SNMPv3 supports configurable authentication/privacy protocol names while the
built-in optional-field defaults favor SHA-1 and AES-128.

### 12.2 Runtime default credentials

For simple runs, LLDP-Runner can synthesize a lowest-priority runtime profile
from:

```text
SNMPCOMM
SNMPUSER
SNMPAUTH
SNMPPRIV
```

The command-line credential options provide the same capability.

If both v2c and v3 are available, `snmp.version` selects primary and the other
version becomes fallback.

If only one version is available, the same credential is allowed two attempts.
LLDP-Runner does not create a fake second credential name for the same secret.

Explicit configured credentials/profiles suppress the synthesized runtime
profile.

### 12.3 CLI secret indirection

A CLI credential token is first interpreted as an environment-variable name.
If that variable exists, its contents are used. Otherwise the token is literal.

This permits:

```bash
export SITE_COMM='example-community'
get-neighbors --community SITE_COMM core1.example.net
```

without placing the secret directly in shell history.

## 13. Device task construction

The coordinator builds a `DeviceTask` only for a host that is eligible to query.

A task carries:

```text
host ID
preferred name
known names
ordered candidate addresses
credential-profile attempts
cohort assignment
```

Addresses are ordered according to `discovery.address_preference`.

Each address is checked against recursive boundary and query policy before it is
placed in the task attempt list.

In seed-only mode, non-seed learned neighbors are deliberately not made READY.

## 14. Multiprocessing architecture

### 14.1 Why processes

Worker processes isolate blocking/vendor-library behavior and let LLDP-Runner
use multiple CPU/process contexts while the coordinator remains a single state
owner.

The process start method is `spawn`.

Each worker has:

```text
one work queue
access to the shared result queue
access to the shared log queue
a shared pause event
```

### 14.2 Why asyncio inside workers

SNMP and ICMP are primarily I/O-bound. A worker can therefore keep multiple
devices in flight without requiring one process per target.

The architecture is:

```text
multiprocessing across workers
        +
asyncio concurrency inside each worker
```

This provides horizontal concurrency while retaining per-worker limits.

## 15. Cohorts and work stealing

Hosts receive deterministic cohort assignments. The coordinator claims READY
work for idle workers in batches according to `discovery.batch_size`.

Before a READY row is claimed, the state owner conservatively reconciles
inactive duplicate managed-host projections that have compatible direct logical
names, at least one shared identity-eligible management address, and no hard
identity conflict. Compatibility permits exact names or one short name with the
same left-most FQDN component; two FQDNs are never matched by suffix removal. A
direct SNMP `sysName` is authoritative for this narrow reconciliation even when
one temporary row carries a different shadow presentation alias. Different
per-link chassis IDs may be tolerated only when that direct logical name and a
management address agree; they remain conflicting for transitive rows that do
not share an address. Serial, SNMP-engine, strict-MAC, and logical-name
conflicts always block the merge. A
READY row is not dispatched while an equivalent projection
is already in an active worker state. After all workers stop, the coordinator
runs the same reconciliation once more before materializing final output. This
boundary prevents redundant polling without allowing a shared Nexus chassis
serial, a weak reused address, or a transitive identity-poor bridge to merge
distinct logical systems. Completed results outrank failed duplicates, while a
READY alternate outranks a failed projection so an untried route is not silently
discarded. Seed status and rank are merged independently and do not require the
seed row to win.

The state store can allow work stealing when configured, so idle workers are
not permanently blocked by uneven cohort response times.

Seed ranks take priority over normal cohort ordering for pending seed work.

## 16. Worker wavefront behavior

A worker batch has two broad phases.

### 16.1 Basic wavefront

For every unresolved device in the cohort, the worker performs one logical
credential/query attempt per wave.

Conceptually:

```text
for each unresolved device:
    if this address has not been pinged:
        send configured ICMP wake-up probes

wait configured inter-wave delay

concurrently attempt one basic SNMP query per unresolved device

for each failure:
    advance retry, fallback credential, or alternate address

repeat until success, exhaustion, or pause
```

The basic SNMP collection obtains system identity data needed to establish that
SNMP works and to guide later collection/classification.

### 16.2 ICMP behavior

Each newly selected address receives its own configured probes before its first
SNMP attempt.

Retries or fallback credentials on the same address do not trigger another
pair of wake-up probes.

ICMP is not an SNMP gate. A ping failure does not prevent SNMP from being tried.

### 16.3 Detailed collection

After basic success, each successful device runs a per-device collector chain.
Multiple successful devices can be active concurrently, bounded by
`snmp.max_outstanding_devices_per_worker`.

Within one device's chain, collection is deliberately narrow/serial enough to
avoid excessive simultaneous requests to one SNMP agent.

The detail path currently includes:

```text
optional ENTITY-MIB enrichment
IF-MIB interface collection
LLDP-MIB collection
LLDP-V2-MIB collection
CISCO-CDP-MIB collection when applicable
one shared-delay stability pass for eligible failed neighbor protocols
neighbor observation merge
```

LLDP, LLDPv2, CDP, IF-MIB, and other table operations share one degraded
transport profile for the target address and credential route. Normal retry
accounting has operation and collector-family limits plus two pools. SYSTEM-MIB,
ENTITY-MIB, IF-MIB, and other general collectors consume the shared target pool.
LLDP-family and CDP collectors first consume a protected neighbor reserve that
general work cannot use, then may fall back to the shared pool. LLDP and LLDPv2
share one normal fair-share family; CDP has its own. This prevents early
identity/interface collection or several walks inside one collector from
starving later topology protocols while keeping all normal retries bounded.

LLDP and LLDPv2 validate that every remote row contains mandatory chassis-ID
and Port-ID subtype/value pairs. CDP validates the complete cache snapshot
before
materialization: every usable row requires device ID and remote port, all
cache-indexed columns must agree, and a partial new row caused by mid-table
mutation invalidates the snapshot. A structurally invalid snapshot is discarded
and restarted from its root with the persistent degraded profile. Repeated CDP
failure records `structurally_invalid` coverage and cannot create an
identity-empty host or edge.

A management-address subtable exception is not converted into a successfully
empty LLDP table, preserving the difference between "no management address
advertised" and "management-address collection failed." Every interrupted table
discards partial rows before restart.

After all enabled neighbor collectors finish their first pass, the worker can
perform one delayed stability phase. Final timeout and structurally invalid
LLDP, LLDPv2, or CDP outcomes share one target-local quiet-period delay. Each
eligible protocol then gets one fresh session and one full collection from its
root. Normal transport and structural retries are suppressed inside that final
pass, so it cannot multiply into another retry tree. Stability accounting is
separate from the normal shared/reserved pools, and each protocol can consume it
only once. A recovered protocol replaces its failed first-pass outcome; a
persistent failure remains explicit coverage loss without affecting protocols
that completed successfully.

## 17. SNMP client abstraction

Collectors depend on the project-owned SNMP client interface rather than on
the coordinator knowing Gufo- or PySNMP-specific details.

Version 0.37.0 resolves `snmp.backend` to `gufo` or `pysnmp` after the complete
configuration precedence chain. PySNMP is the default; Gufo remains available
through explicit selection. Runtime-only selection fields bind the name and
installed distribution version once, survive the worker spawn boundary, and
reject later mutation. The factory imports only the selected adapter and
contains no exception-driven fallback.

The shared credential model is checked against an explicit capability record
for the selected adapter. Gufo accepts SHA-1/MD5 authentication and AES-128/DES
privacy. PySNMP accepts that common subset plus SHA-256 authentication,
`aes256` as the Reeder/Cisco `USM_PRIV_CFB256_AES` mapping, and
`aes256-blumenthal` as `USM_PRIV_CFB256_AES_BLUMENTHAL`. Neither adapter uses an
`else` branch to turn an unknown name into a different algorithm, and Gufo
rejects PySNMP-only names before secret or network work.

Before manifest mutation or discovery, the coordinator compares the effective
backend with SQLite run metadata. A real resume with no backend metadata, or a
resume selecting a different backend, fails. `run.json` stores the logical-run
backend plus the backend/version used by each invocation. This preserves one
transport interpretation throughout the run without changing discovery, graph,
or diff schemas.

The default change does not migrate durable state. A Gufo run must continue to
resolve explicitly to Gufo when resumed. An omitted setting now resolves to
PySNMP and is rejected against Gufo run metadata before workers or network work.

After that durable resume check, 0.37.0 derives the set of PySNMP SNMPv3
privacy algorithms reachable through configured profiles and direct seed
credentials. Only protocol names are inspected; secret accessors are never
called. If authPriv is reachable, a local preflight verifies PySNMP's supported
7.1 asyncio API, `cryptography>=50.0`, and fixed-byte
AES-128/AES-256/DES cipher operations before manifest creation, seed
resolution, workers, or network I/O. Both AES-256 localization variants use a
32-byte AES key in this provider probe; PySNMP owns the distinct localization
algorithms used for the real USM request.
Gufo and PySNMP v2c-only paths skip this preflight. A mixed run may probe
authPriv once for another reachable route, but the v2c transport does not use
cryptography. A local capability failure cannot spend transport retry budget or
be mistaken for remote authentication failure.

The 0.37.0 AES probe imports CFB from cryptography's decrepit modes namespace.
For PySNMP 7.1.29's remaining old-namespace access during a real AES
request, the adapter installs one process-level filter restricted to the exact
cryptography deprecation category, complete message, and PySNMP AES module.
It is installed only for a v3 AES-128 or AES-256 route and deliberately leaves
all neighboring warnings visible.

The PySNMP adapter owns one asynchronous `SnmpEngine` per opened route session,
uses family-specific IPv4/IPv6 targets with `retries=0`, normalizes native
varbinds and failures at the adapter boundary, and closes the dispatcher on all
exit paths. Its remote SNMPv3 engine ID is captured from the received response
security context. The local manager engine ID is never device identity.

Important SNMP controls include:

```text
snmp.backend
snmp.timeout_seconds
snmp.max_repetitions
snmp.per_device_rps
snmp.retry_per_operation
snmp.retry_per_collector
snmp.retry_total_cap
snmp.retry_neighbor_reserve
snmp.structural_table_retry
snmp.retry_timeout_multiplier
snmp.retry_max_repetitions_multiplier
snmp.retry_min_max_repetitions
snmp.retry_inter_pdu_delay_ms
snmp.neighbor_stability_retry
snmp.neighbor_stability_retry_delay_seconds
snmp.max_outstanding_devices_per_worker
snmp.inter_wave_delay_seconds
snmp.report_metrics
```

`timeout_seconds` applies to one SNMP request/response operation, not the
total time required to query a device or walk several tables. One adaptive
state belongs to one target address and credential route and follows a
successful target from basic into detail collection.

The first retry-eligible timeout or structural table failure degrades the
transport profile. The default profile multiplies timeout by `1.5`, multiplies
GETBULK `max_repetitions` and GET-MANY batch size by `0.5` with upward rounding,
and adds `100` milliseconds of pacing. The backend session is reopened using
the new values. Later operations on the same route start with that slower
profile. Each operation and collector family can retry once by default. General
collectors share three target retries; LLDP-family and CDP also share two
protected neighbor retries. A separate optional final pass waits two seconds
once per affected target and retries each eligible failed neighbor protocol
exactly once. The profile and counters reset for the next target or credential
route.

Every retry and exhaustion event records target, collector/family, logical
operation, table, root OID, credential route/profile, collection phase, pool,
attempt and retry counts, before/after timeout and work size, pacing, discarded
partial rows, and final outcome. Stability events also record the quiet-period
delay. Authentication, access restriction, unsupported OIDs, and other
definitive non-performance failures do not consume adaptive retry capacity.

Explicit `noAccess`, `authorizationError`, VACM, or equivalent access/view
denials are normalized as `snmp_access_restricted`, written to the activity log,
and retained in structured errors. Optional IF-MIB, LLDP local-port, and
ENTITY-MIB fallback paths re-raise this category rather than silently treating
it as an empty or unsupported table. An empty table or `noSuchObject` alone is
not labeled an ACL/view failure because those results can also mean the MIB is
not implemented.

Collection telemetry is backend-neutral. A wrapper around the project-owned
SNMP client counts returned varbinds from scalar, multi-get, and walk operations
before collectors filter/group them. Timers measure the complete collector call.
`get-neighbors` always keeps these metrics in memory. Full discovery
collects and
persists them only when `snmp.report_metrics=true`. This avoids Gufo-specific
request hooks and makes the telemetry reusable with a future backend.

Single-device tracing follows the complete get-neighbors network path. Resolver
helpers report the logical OS resolver calls/results, the ICMP pinger reports
concrete raw/system backend attempts and replies/timeouts, and an SNMP tracing
wrapper records each logical scalar/multi-get/walk request and every varbind
returned to LLDP-Runner. The SNMP trace deliberately does not depend on Gufo's
internal GETNEXT/GETBULK packet strategy, so diagnostics remain meaningful if
the backend changes. Resolver tracing similarly describes calls/results rather
than claiming packet-level DNS visibility through NSS.

## 18. Neighbor collection and normalization

A `NeighborObservation` captures normalized edge evidence such as:

```text
protocol
local interface
remote name
remote interface
management addresses
remote description/platform
capabilities
chassis ID
chassis ID subtype
remote Port ID and Port ID subtype evidence
protocol-specific details
```

LLDP and LLDPv2 preserve both textual chassis subtype and numeric subtype ID.
They also preserve decoded remote `port_id`, textual `port_id_subtype`, numeric
`port_id_subtype_id`, and `port_description` values in protocol/edge details.
Port ID subtype numbering is intentionally decoded separately from chassis-ID
numbering.

Local interface identity is also typed. CDP and LLDPv2 table rows use IF-MIB
`ifIndex`; original LLDP uses `lldpRemLocalPortNum`, which indexes
`lldpLocPortTable` and is not assumed to be the same numeric namespace. A
resolved row retains its operator-facing interface name and protocol index. An
unresolved row is rendered as `ifIndex:<n>` or `lldpLocalPort:<n>` rather than a
bare number that could be mistaken for a stable name.

IF-MIB interface-name collection uses the same target-level adaptive retry
policy as other SNMP operations. If the final map is unavailable, or a protocol
row cannot be mapped, the worker persists collection-coverage errors such as
`cdp_interface_resolution` or `lldp_interface_resolution`. Discovery preserves
the row instead of discarding useful topology. An identical typed unresolved
edge in two runs is stable topology; the coverage gap remains visible without
manufacturing a change.

Some Cisco IOS agents provide an IF-MIB mapping for CDP while the original LLDP
local-port table does not provide a usable name. One such unresolved LLDP row
can attach to one resolved CDP edge when exactly one
candidate has the same protocol-local numeric index, exact remote port, and
corroborating endpoint identity. The resolved CDP interface is used for the edge
projection, while the raw `lldpLocalPort:<n>` value remains in `lldp.*`
evidence.
This is a one-edge inference and never establishes a device-wide numeric
namespace equivalence.

Remote-table rows are assembled with their complete MIB index context rather
than by local/remote port alone. Original LLDP retains `timeMark`, local-port
number, and remote index in its row key. LLDPv2 also retains the local
destination-MAC index context. `time_mark` is exposed diagnostically but diff
treats it as volatile table location rather than logical topology identity.

Multiple observations that represent the same relationship can be merged while
retaining protocol provenance such as:

```text
cdp
lldp
lldpv2
cdp,lldp
```

The strict same-link reconciliation path first requires matching normalized
local and remote interfaces. Exact logical names can reconcile across protocols
even when their advertised address sets differ. A plausible trailing
`name(serial)` advertisement is separated into raw advertisement, logical base
name, and serial hint. The base can compare with an undecorated protocol name
and can be used for DNS lookup. The serial hint becomes a moderate, non-merging
physical-container claim until direct serial evidence corroborates it. This
allows separately named/addressed Nexus VDCs to share physical-chassis evidence
without collapsing their logical identities.

A second corroborated path handles endpoints for which CDP and LLDP use
different remote-port representations. For ordinary names it requires the same
normalized local switch interface, compatible names, and at least one shared
usable address. A protocol management address normally supplies that evidence;
an LLDP chassis ID explicitly typed as `network_address` can corroborate the
same address without being relabeled as a management-address TLV.

Ordinary compatible names can be exact, or one side can be a single-label short
name while the other is that exact host label followed by a domain suffix. This
is an edge-scoped rule only: two FQDNs are not matched just because their first
labels agree, and no suffix-derived global alias is created.

Cisco phones and video endpoints have a separate strict identity rule beginning
with 0.31.2. A left-most host component matching `SEP` plus exactly twelve
hexadecimal characters contributes the embedded endpoint MAC as durable
identity.
For example:

```text
CDP   SEP001234560004                  / Port 1
LLDP  SEP001234560004.voice-a.example.com  / 001234560004:P1
MAC   00:12:34:56:00:04
```

The same MAC is also derived from
`SEP001234560004.voice-b.example.net`. This is intentionally not a generic
suffix
rule. Names that do not match the exact `SEP<12-hex>` host-component pattern do
not gain MAC identity from their text.

On the same local switch interface, equal strict SEP identity can reconcile the
CDP/LLDP rows even if one collection lacks the LLDP management-address row. The
normalized edge prefers the richer LLDP typed Port ID while protocol-specific
names, ports, addresses, descriptions, capabilities, and chassis evidence remain
under `cdp.*` and `lldp.*` details. Because reconciliation occurs before state
insertion, the same decision feeds both the observer's `learned_neighbors` and
the remote host's reciprocal `observed_by_neighbors` list.

Beginning with 0.31.3, disjoint strict SEP-derived MAC identities are also an
explicit state-layer conflict. This check occurs before generic shared-address
correlation. It prevents a repeated endpoint address or `network_address`
chassis value from transitively folding unrelated phones into the first host
that claimed that address. Equal SEP MAC identity remains a strong positive
signal; different SEP MAC identity is a strong negative signal.

CDP `cdpCacheAddress` is explicitly preserved as entry-address evidence. When a
CDP observation reconciles with LLDP, the normalized edge keeps LLDP management
addresses first for human display while retaining all unique addresses and both
protocols' raw evidence.

## 19. Text and binary SNMP sanitation

SNMP OCTET STRING values are normalized centrally before entering formal output.

The sanitation path aims to:

```text
preserve valid printable Unicode
normalize embedded tab/newline separators
remove dangerous control characters
render binary/invalid UTF-8 values as printable hex
normalize binary LLDP MAC/network chassis IDs by subtype
normalize binary LLDP/LLDPv2 MAC/network Port IDs by the Port ID subtype
```

CSV and JSON output also apply a final safety boundary so resumed/older state or
a future collector mistake does not write raw control bytes into formal output.

## 20. Neighbor candidate processing

When a worker returns a neighbor, the coordinator:

```text
1. converts the observation into a candidate identity;
2. resolves/enriches managed names when configured;
3. classifies the enriched candidate;
4. computes applicable tags;
5. upserts or merges the candidate into central state;
6. records the topology edge from source to remote host;
7. decides whether the remote host may become queryable work.
```

Workers do not independently recurse.

That design avoids two workers discovering the same switch and both deciding to
query it before a central duplicate check occurs.

## 21. Topology edge direction

LLDP-Runner stores an edge from the device that reported the neighbor toward the
reported remote identity.

Outputs deliberately expose two perspectives on every host.

### 21.1 `learned_neighbors`

These are relationships learned directly by querying the current host.

```text
current host --reported--> neighbor
```

### 21.2 `observed_by_neighbors`

These are inbound observations where some other queried device reported the
current host.

```text
observer --reported--> current host
```

Keeping the two directions separate is important for failed or intentionally
unpolled hosts. Such a host may have no learned neighbors of its own but can
still have strong inbound evidence showing where it was observed.

## 22. State store

SQLite is the authoritative run/checkpoint store.

The coordinator is the only process that mutates discovery state.

Key tables include:

```text
meta                  run status and operational metadata
observations          immutable normalized collection inputs
claims                immutable typed evidence with provenance/scope/strength
resolution_decisions  append-only projection history with supersession links
decision_claims       supporting/conflicting evidence for each decision
hosts                 current compatibility projection and scheduling state
aliases               globally owned names, MACs, accepted chassis identities
host_addresses        many-to-many IPv4/IPv6 compatibility claims
host_tags             accumulated operator tags
neighbors             directed topology edges and protocol evidence
errors                structured operational/device errors
```

SQLite triggers reject UPDATE and DELETE operations against observations,
claims, resolution decisions, and their claim links. A materially different
conclusion appends a decision whose `supersedes_decision_id` points to the prior
conclusion. This makes the evidence and reasoning history reversible for audit
and future replay. The 0.31 maintenance projection does not yet rebuild
every current host/edge exclusively from the ledger.

The host projection also retains adaptive SNMP session telemetry and audit-only
local-interface observation groups. These additive records describe collection
behavior and complex many-neighbor ports; they do not replace the current
`neighbors` table or make direct/indirect graph decisions.

SQLite uses WAL behavior during normal operation and performs an explicit full
checkpoint on controlled pause/finalization.

This avoids an external Redis/database dependency while still supporting pause
and resume.

## 23. Host state lifecycle

Exact transitions depend on policy and outcomes, but the conceptual flow is:

```text
DISCOVERED
   |
   +-- policy/boundary deny ------> NO_QUERY / OUT_OF_SCOPE style state
   |
   v
READY
   |
   v
CLAIMED
   |
   +-- successful worker result --> COMPLETE
   |
   +-- exhausted worker result ---> FAILED
   |
   +-- pause/defer ---------------> READY/deferred path
```

`CLAIMED` is a transient worker ownership state. It is normal for a CLAIMED host
to have no successful `query_target` yet.

A COMPLETE managed device without a query target is an integrity error because
a successful basic SNMP query necessarily used an address.

## 24. Seed inventory validation

Periodic/final output generation checks seed inventory consistency.

Transient states such as READY or CLAIMED do not create permanent
`missing_query_target` errors merely because no successful address has been
established yet.

If an older/stale transient error exists and the host later gains a valid query
target, the stale error is removed.

Terminal inconsistencies, especially COMPLETE with no query target, remain
reportable.

## 25. Discovery guardrails

### 25.1 Finite `max_devices`

A positive value is a recursive managed-device guardrail.

After seed DNS/identity de-duplication and before workers start, LLDP-Runner
checks whether the unique managed seed inventory already exceeds the limit.

If it does, initialization fails fast with `SEED_LIMIT_EXCEEDED` rather than
querying an arbitrary subset.

### 25.2 `max_devices = 0`

Zero disables the managed-device count guardrail. Recursive discovery may
continue without a device-count ceiling, subject to other policy and limits.

### 25.3 `max_devices = "auto"`

`auto` is not just a numeric substitution. It is seed-only scheduling mode.

```text
query every unique seed
collect its CDP/LLDP neighbors
record/classify/output those neighbors
do not schedule learned non-seed neighbors for SNMP
```

The effective numeric count is recorded as the unique seed-device count for
metadata, but recursion is prevented by scheduler admission logic.

After non-seed work is suppressed, the coordinator also knows the complete
remaining SNMP workload. It derives an effective seed-only execution plan from:

```text
READY seed count
configured workers
configured batch_size
snmp.max_outstanding_devices_per_worker
```

Per-worker first-wave capacity is the smaller of configured batch size and the
per-worker asynchronous-device limit. The coordinator launches no more workers
than are needed to cover that known first wave and can reduce batch size to
balance a small seed population across those workers. It never increases a
configured limit.

For example, 10 READY seeds with 64 configured workers, batch size 9, and an
outstanding-device limit of 24 resolve to two effective workers with batch size
five. Nine READY seeds under the same settings resolve to one worker with batch
size nine.

On resume, pending non-seed work left by a prior recursive mode is suppressed
before the execution plan is recalculated from the remaining READY seeds.

### 25.4 `max_hosts`

A positive `max_hosts` limits host identification.

Zero disables the host guardrail.

In recursive mode, the guardrail counts all host identities.

In seed-only mode, explicit seeds are sampling points and do not consume the
host threshold. Learned non-seed identities do.

Because workers are concurrent, the final number can exceed the threshold when
results already in flight discover additional hosts.

`max_hosts` is therefore a stopping threshold, not an exact sample-size feature.

## 26. Limit completion behavior

`limit_behavior = "pause"` treats a reached guardrail as a resumable stop.

The final status is:

```text
LIMIT_REACHED
```

`limit_behavior = "complete"` treats the threshold as an intentional endpoint.

The final status is:

```text
COMPLETED_LIMIT
```

Normal final outputs are produced and the completion reason is recorded.

This mode is useful for bounded/randomized topology sampling.

## 27. Pause and resume

A run can be asked to pause through:

```text
lldp-runner pause
pause.request indicator file
SIGINT
SIGTERM
SIGUSR1
```

On pause request:

```text
stop dispatching new work
allow/defer bounded in-flight activity
stop workers
write/checkpoint state
write draft output and scoreboard
mark run PAUSED
```

A later invocation can find a resumable run when resume is enabled.

Active CLAIMED work is reset so it can be attempted again safely.

Worker-process death causes affected batch hosts to be deferred and the run to
move toward a controlled pause rather than silently losing the work.

## 28. Coordinator loop

The central loop is conceptually:

```text
start workers
while run is active:
    check pause indicator
    check worker health
    check limits
    dispatch READY work to idle workers
    consume returned worker batches
    process results and discovered neighbors
    periodically write scoreboard
    periodically write draft outputs

    if pausing and all workers are idle:
        stop

    if no READY/active work and workers are idle:
        complete

stop workers
checkpoint SQLite
finalize or retain draft output according to final status
```

Successful finalization also maintains two atomic relative aliases. Output
publication sets `<persistent_root>/<output_dirname>/latest` to the completed
output directory. After the state database and log listener have closed,
post-completion handling sets `<persistent_root>/<runs_dirname>/latest` to the
durable run directory and then performs optional completed-scratch cleanup.
Both alias operations are preflighted during initialization. Resume enumeration
ignores symlink entries so `runs/latest` can never be mistaken for a resumable
run ID.

The current workers return a completed batch to the coordinator rather than
streaming each individual device result as soon as that device finishes.

This is simple and deterministic, but a slow cohort member can delay visibility
of faster results from the same batch.

## 29. Timezone policy and run-ID allocation

`[time].timezone` defines one process-wide wall-clock policy for logs, terminal
summaries, persisted state/observation timestamps, scoreboards, and run-ID
`strftime` expansion. `eastern` remains the compatibility default; `utc`,
`local`, and IANA names such as `America/Denver` are supported. Because workers
use multiprocessing `spawn`, each worker initializes the configured timezone
before logging or collecting timestamped observations.

`paths.run_id_format` defaults to `%Y%m%d-%H%M%S-%Z`, preserving historical
names. The formatter accepts safe literal filename characters, documented
`strftime` directives, and at most one `{counter}` token. Counter allocation is
stateless: LLDP-Runner scans run/state, final-output, and scratch namespaces,
uses the highest matching integer plus one, and renders `00` through `99`. A
next value above `99` fails before discovery and directs the operator to review
`paths.runs_dirname`/`paths.run_id_format` or use a higher-precision timestamp.

Two-digit padding preserves lexical numeric order within one counter namespace,
so the existing reverse lexical automatic-resume scan works for names such as
`run-09` and `run-10`. The same shortcut cannot infer chronology across mixed
historical naming schemes; sites should keep an incomplete resumable namespace
lexically ordered when changing formats.

## 30. Scoreboards and activity logging

Workers send log records to a central log queue. The coordinator owns the
listener and independently enables console and file destinations.

The defaults are:

```toml
[logging]
level = "INFO"
console = true
file = true
filename = "activity.log"
```

A relative `filename` is resolved beneath the current run-ID directory. An
absolute pathname is used directly so an operator can centralize
logs, for example under `/var/log`. `~` is expanded before the relative versus
absolute decision. Relative paths containing `..` are rejected so a relative
name cannot silently escape the run directory. Enabled file logs are opened
explicitly in append mode; an existing centralized file is never truncated.
An append-open failure is raised during coordinator construction, before workers
start, and is reported by the CLI on standard error.

When `file=false`, no file handler or file parent directory is created and the
terminal summary reports `Activity log: disabled`. When both `console=false`
and `file=false`, the logging queue is still drained safely but records have no
external destination.

The live scoreboard is written below `<scratch_root>/scoreboard/` in text and
JSON forms. The scoreboard includes configured/effective worker and batch
values for the current execution plan; seed-only runs also show the READY seed
count used to right-size the plan. This shared publication survives successful
per-run scratch cleanup.

`lldp-runner status` reads the stable text scoreboard.

`lldp-runner status --json` reads the stable JSON scoreboard.

`lldp-runner watch` reopens the JSON scoreboard on each source refresh and
renders a no-scroll interactive terminal dashboard. Reopening is important
because scoreboards are atomically published with `os.replace`; a changed run
ID lets the monitor follow a new run without relying on the `current` symlink.
The watcher compares structured snapshots rather than terminal text, so metric
and worker changes can be emphasized semantically.

After `COMPLETED` or `COMPLETED_LIMIT`, the exact in-memory terminal snapshot is
atomically archived as `scoreboard.txt` and `scoreboard.json` below the durable
run directory. When automatic completed-scratch cleanup is disabled, the same
snapshot is also archived below the per-run scratch directory. Retaining the
rendered snapshot avoids a race in which a later run replaces the shared live
files before archival.

Beginning in v0.25.0 the live JSON scoreboard declares
`scoreboard_schema = 1`. This version is independent from the canonical
`discovery.json` schema. The first watch schema contains run/start/state/timing,
aggregate counters, execution-plan data, and per-worker state/batch/size data.

`status` and `watch` validate applicable configuration with the credential
subsystem disabled entirely and resolve scratch storage without write-probing
it. That mode also stops before runtime SNMP backend selection; read-only
commands never construct or initialize either transport adapter. `clean` and
`purge` use the same disabled configuration mode for local retention
maintenance. `clean` removes durable/scratch run history
below `<persistent_root>/<runs_dirname>/` and recognized historical scratch run
directories directly below `<scratch_root>/`. It also removes the dedicated
`<scratch_root>/scoreboard/` publication directory. Historical cleanup preserves
the newest run plus the runs selected by scratch `current` and durable-output
`latest`. Finalized
output directories are not removed by `clean`. `purge` acts only on finalized
output directories and preserves `latest` plus the configured/CLI additional
retention count. `pause` does not require currently available SNMP secrets but
remains a run-control operation rather than a read-only viewer.

## 31. Draft and final output

During a running discovery, LLDP-Runner periodically writes draft files,
normally in scratch storage.

On successful completion or intentional completed-limit termination, final files
are copied/moved into the run-ID persistent output directory and the
`latest` symlink is updated.

Paused/limit/interrupted runs retain state and draft material suitable for
review and, where applicable, resume.

Coordinator construction performs a narrow storage preflight before discovery.
It verifies atomic file output in the exact scratch run directory and the final
run-ID persistent-output directory, then verifies temporary symlink
publication in the output root. A newly created final-output directory is
removed after a successful probe so preflight does not create a false completed
run. SQLite state creation and the activity-log append-open provide their own
early exercised path checks. Preflight reduces predictable end-of-run failures
but cannot guarantee later capacity, quota, or remote-filesystem availability.

## 32. Formal output files

### 32.0 `run.json`

Completed discovery runs publish schema-versioned `run.json` launch provenance
beside `discovery.json`. The first keys are `schema_version`, `app_name`, and
`app_version`; application identity comes from the package runtime constants.
The document records logical run ID/status, timezone-aware `started` and
`completed` timestamps, elapsed `duration` in seconds, the OS account that
started the run, and a resume-aware `invocations[]` history. Schema 3 also
records these nonnegative wall-clock phase metrics:

```text
discovery_duration
graph_resolution_duration
graph_serialization_duration
output_publication_duration
finalization_duration
total_wall_clock_duration
```

`duration` retains the established persisted logical boundary from `started` to
discovery-complete `completed`. `discovery_duration` measures the active
invocation to worker shutdown. `finalization_duration` measures from that
boundary through graph/output generation, publication, checkpointing, and final
scoreboard work. `total_wall_clock_duration` is their combined invocation
interval. The graph and publication fields are measured subphases of
finalization rather than additional time.

Each invocation retains sanitized raw and parsed command-line input, resolved
seed inputs, stdin seed values, recognized non-secret LLDP-Runner environment
inputs, and the resolved primary/include/conf.d configuration path chain when
`output.run_json_config_log=true` (the default).

Credential communities plus SNMP authentication/privacy password values are
replaced with the literal `<redacted>` before provenance is persisted. The
durable in-progress form lives with run state as `run.json.draft`; draft output
can carry the same filename suffix. A completed run publishes `run.json` into
the final output directory, then removes the durable `run.json.draft` during
post-close finalization. Paused, interrupted, failed, and resumable-limit runs
retain their drafts. `run --dry-run` allocates no run ID and creates no
`run.json`. `run.json` has its own schema version independent of discovery JSON.

### 32.1 `discovery.json`

This is the canonical structured discovery result and is always generated.

The top-level structure is versioned. The current writer publishes schema 8:

```text
schema_version
discovery
topology_graph
hosts
errors
```

`schema_version` identifies the external document contract. Schema 8 places a
claims-driven graph beside the flat host/neighbor compatibility projection.
The graph has its own internal schema version and contains physical chassis,
logical and observed systems, canonical interface occurrences, protocol
advertisements, logical membership, observed relationship groups, collection
coverage, explicit advertisement exclusions, and a deterministic projection
fingerprint. It can also carry compatibility-projection diagnostics when a
legacy flat host spans several distinct anonymous graph endpoint MACs; these
diagnostics do not change graph authority or relationship materialization.

Raw CDP, LLDP, and LLDPv2 advertisements are recorded before cross-protocol
reconciliation. Every durable advertisement appears in the graph or in an
explicit exclusion record. Graph conclusions are append-only decisions; a
changed conclusion supersedes the earlier decision and transactionally
replaces the current projection without deleting evidence or history.
Authority is reported by dimension. The observation projection can be complete
while entity resolution remains provisional and physical topology/directness
remain uninferred.

A schema version changes when consumers must distinguish an incompatible
document structure or value representation. The current reader intentionally
does not convert discovery files from earlier releases.

`discovery` contains run and sampling metadata such as boundaries, seed order,
shuffle key, effective device mode, configured thresholds, limit behavior,
counts, and completion reason.

Each host record contains identity, classification, tags, state, seed
provenance, names/addresses, ICMP results, complete collected system detail,
credential outcome, learned neighbors, and inbound observations. Raw structured
values are retained rather than flattened into CSV strings. When
`snmp.report_metrics=true`, queried hosts can additionally include
`snmp.collection_metrics`, keyed by `sys`, `entity`, `interfaces`, `lldp`,
`lldpv2`, and `cdp` only when those sections were attempted. `sys` represents
the initial SYSTEM-MIB collector, while the human `Timing ms: basic=...` field
represents the broader ICMP/session/system-probe phase. Each metric contains
`objects` and `duration_ms`.

`errors` contains the structured per-host and global error stream. Host-bound
errors use `host_ref` to associate them with a host record. Worker errors retain
the exact `attempted_target`, address family, transport phase, exception type
and OS fields, non-secret credential route, operation, collector, attempt,
message, recovery metadata, and lowercase final host state. The host-level
`query_target` remains separate successful-route context.

Schema version 3 is the direct source for all fixed and custom CSV views. After
LLDP-Runner assembles and sanitizes the canonical discovery document, fixed CSV
rendering receives only that document and configuration; it does not query
SQLite again. Host `state` is canonical lowercase output, and direct CSV
projections use the same leaf key names as JSON. A JSON-only replay regression
test verifies all five fixed CSV files can be reproduced after StateStore is
closed. Custom CSV reports use the same canonical document and never reopen
SQLite state.

### 32.2 `hosts.csv`

This is a compact, fixed-schema host inventory. Direct projections use JSON
field names such as `preferred_name`, `queried_as`, and `state`. `state` is
lowercase in both JSON and CSV, and the former duplicate `snmp_status` column
is removed.

The `origin` column contains `seed` or `learned` and is a deliberate transform
of JSON `is_seed`. Two topology-summary columns remain separate:

```text
learned_neighbors
observed_by_neighbors
```

Beginning with v0.12.0, `hardware_revision` and `firmware_revision` are omitted
from this convenience view. They remain under the host `system` object in
`discovery.json` when collected.

### 32.3 `stack-members.csv`

This fixed-schema physical inventory emits one switch-stack member per row.
Logical-device context such as `preferred_name`, `queried_as`, classification,
tags, state, management addresses, credential outcome, and topology summaries
is intentionally repeated so each row remains useful without a join.

Member-specific direct projections use JSON key names including
`member_number`, `entity_index`, `name`, and `description`. Other member columns
include manufacturer, model, software version, serial number, hardware revision,
firmware revision, and `uptime_seconds`. The redundant `snmp_status` column is
removed; logical host `state` remains available on every member row. The serial
number is the preferred durable physical identity; stack position and ENTITY
index are observations that can change after replacement, renumbering, or
reboot.

ENTITY-MIB does not define a portable per-member uptime object. LLDP-Runner
therefore leaves `uptime_seconds` empty unless a true member-specific value is
available; it never copies the logical stack's SYSTEM-MIB uptime into every
physical row.

### 32.4 `seeds.csv`

Despite its historical filename, this file is a reusable managed-device seed
inventory rather than a record limited only to original input seeds.

The schema is:

```text
preferred_name,queried_as,ipv4,ipv6,credential_profile,credential_result,
origin,state,last_seen,notes
```

The `origin` column uses the same `seed` or `learned` values as `hosts.csv`.
It describes provenance for the run that wrote the inventory; it is not imported
as authoritative state. If a `learned` row is supplied to a later run, that row
is an explicit seed in the new run and is therefore exported as `origin=seed`.

The file can also carry successful management-address hints into later runs.

### 32.5 `unknown-devices.csv`

This report concentrates evidence for identities that could not be positively
classified.

Its fixed schema is:

```text
preferred_name,ipv4,ipv6,last_seen,protocols,observed_names,
remote_platforms,remote_descriptions,capabilities,observed_chassis_ids,
observed_chassis_id_subtypes,observed_chassis_id_subtype_ids,
observed_by_neighbors,classification_reason
```

It includes protocols, observed names, remote platform/description,
capabilities, observed chassis ID/subtype aggregates, inbound connections, and
classification reasoning. The consistently blank `manufacturer` and `model`
columns are not part of this review view. The same-source custom fields are not
part of the supported fixed-field namespace. Any such values present in a
canonical host remain available through explicit `json.host.system.*` custom
projections.

The flattened inbound topology field is named `observed_by_neighbors`, matching
`hosts.csv` and the JSON key. The aggregate columns are named
`observed_chassis_ids`, `observed_chassis_id_subtypes`, and
`observed_chassis_id_subtype_ids` so they cannot be confused with the canonical
host-level `chassis_id`. Protocol aggregation is derived from
`observed_by_neighbors[].protocols[]` in the discovery document.

### 32.6 `errors.csv`

This fixed report contains structured per-host and global errors. The `category`
header directly matches `errors[].category`; `final_state` directly matches the
lowercase JSON key when a terminal disposition is known. Other columns include
operation, credential stage/attempt when applicable, and recoverability. The
same underlying error data is also present in `discovery.json`.

### 32.7 JSON-first fixed CSV projection

The output boundary is intentionally one-way:

```text
SQLite discovery state
         |
         v
canonical discovery document
         |
         +--> discovery.json
         +--> hosts.csv
         +--> stack-members.csv
         +--> seeds.csv
         +--> unknown-devices.csv
         +--> errors.csv
         +--> configured custom CSV reports
```

SQLite supplies the collected state needed to assemble the canonical document.
After that document exists, CSV projection helpers operate only on the
JSON-compatible host/error structures. Derived fields such as `origin`, uptime
seconds, flattened neighbors, seed notes, and unknown-device evidence are
presentation transforms over those structures rather than parallel database
queries. The custom CSV registry reuses this same one-way boundary.

### 32.8 CSV enable/suppress controls

The standard CSV schemas remain owned by LLDP-Runner. Operators may suppress an
unneeded view without redefining its columns:

```toml
[output]
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

`run_json_config_log` controls whether resolved config pathnames are retained in
run provenance. `purge_keep` is the default number of additional finalized
output directories kept beyond `latest` when `purge --keep` is omitted.

`discovery.json` is unconditional and cannot be disabled by these settings.
Each fixed-schema CSV remains individually enabled by default. Custom reports
use their own `enabled` value. With the default
`write_empty_csv=false`, an enabled report with zero data rows is omitted rather
than written as a header-only file. `write_empty_csv=true` forces enabled empty
fixed or custom reports to be created with their configured headers.

When `log_alert_on_empty_csv=true`, terminal snapshot generation emits one INFO
record listing all enabled CSV reports omitted because they had zero rows.
Periodic `RUNNING` draft snapshots deliberately suppress that notice so a long
discovery does not repeat the same empty-report message every snapshot cycle.
An individually disabled report is not considered an empty suppressed report
and therefore is not included in the alert.

### 32.9 Finalized-output retention

`lldp-runner purge` only considers real child directories below
`<persistent_root>/<output_dirname>/`; it never deletes SQLite run state or
scratch data. The `latest` symlink target is always protected, and `--keep N`
protects N additional timestamp-ranked directories. Without `--keep`,
`output.purge_keep` supplies that number and defaults to 0. If `latest` is
absent, the newest ranked output is preserved as a safe equivalent. An existing
malformed, non-symlink, or external `latest` path is an error rather than a
condition to guess through.

Ordering first attempts `run.json` completion time, then
`discovery.completed`, then `discovery.generated`. If metadata is absent or
malformed, the fallback is the oldest available filesystem modification time
among `run.json`, `discovery.json`, and the output run directory. Equal
timestamps use the run ID as a deterministic tie-breaker. `purge --dry-run`
computes this exact retention set without deleting directories.

### 32.10 Custom CSV projection framework

Named custom reports live below `output.custom_csv`. Each report declares one
row source so row cardinality remains explicit: `hosts`, `stack-members`,
`seeds`, `unknown-devices`, or `errors`. Columns may select fields from the
matching fixed presentation namespace or from approved canonical JSON contexts.

```text
hosts.<fixed-field>
stack-members.<fixed-field>
seeds.<fixed-field>
unknown-devices.<fixed-field>
errors.<fixed-field>

json.host.<path>
json.member.<path>
json.error.<path>
json.discovery.<path>
```

Structured JSON arrays/objects require a controlled transform such as compact
JSON or an approved join operation. Arbitrary Python expressions, templates, or
`eval()` are intentionally unsupported. Column order follows configuration
order, custom headers are optional, and duplicate headers are rejected.

Custom filenames are single relative `.csv` names within the run output
directory. They cannot collide with standard LLDP-Runner output names. Custom
reports participate in atomic writes, draft/final publication, empty-file
suppression, and empty-file INFO reporting. See
[CUSTOM-CSV.md](CUSTOM-CSV.md) for the
operator-facing field registry and examples.

## 33. Single-device inspect architecture

Inspection is implemented in memory.

Conceptually:

```text
input target
   |
   v
DNS resolution + reverse-DNS display enrichment
   |
   v
boundary reporting + query-policy decision
   |
   v
credential selection
   |
   +---- --dry-run ----> render policy/DNS result
   |
   v
build one DeviceTask
   |
   v
process_single_device()
   |
   +--> ICMP wake-up
   +--> basic SNMP
   +--> detail collectors
   +--> merged neighbors
   |
   v
classify neighbor evidence for presentation
   |
   v
render table/detail/CSV/JSON to stdout
```

The same `process_single_device()` primitive normally uses the worker basic and
detail paths. This reduces the chance that `get-neighbors` succeeds under
behavior
that differs materially from a full discovery worker. In `system_only` mode,
the primitive intentionally returns after the basic phase and never invokes the
detail collector chain.

## 34. Inspect output contract

Four formats are supported.

### 34.1 Table

The default human view is compact and terminal-width aware.

It shows basic target/system information, DNS, ping RTTs, query timing, a single
`SNMP obj/ms:` collector-metrics line, and normally a neighbor table. Metric
pairs are rendered as `section=objects/duration_ms`; numeric values receive
terminal color emphasis when color is active. System-only mode omits the
neighbor table because no neighbor collectors were attempted.

The title line also includes a right-aligned
`(collected YYYY-MM-DD HH:MM:SS)` value. Successful SNMP collection uses the
worker's most recent SNMP `last_seen`; results without successful SNMP access
use one finalization timestamp captured by the inspection result. The timestamp
is converted through the configured wall-clock timezone before presentation.

### 34.2 Detail

The detail view is a scrolling, semi-structured neighbor-by-neighbor report
inspired by common network CLI neighbor-detail commands. System-only mode keeps
the target/system section but omits ENTITY-derived revision fields and all
neighbor sections.

### 34.3 CSV

CSV begins with `#` metadata lines followed by a compact fixed neighbor table.
Machine-readable values are not truncated based on terminal width.
The first line uses `state` for the inspection state and appends a display
`timestamp` using the same collection/finalization provenance as human output.

### 34.4 JSON

JSON is the richest inspect form and deliberately follows `discovery.json`
concepts where practical.

Top-level keys are:

```text
inspection
host
errors
```

Timing remains under `timings_ms`, and individual ping probes use `rtt_ms`.
`inspection.collection_mode` is `full` or `system_only`. The host `snmp` object
always includes `collection_metrics` when an inspection actually performed SNMP
collector work. CSV intentionally omits this telemetry.

## 35. Terminal color and stream behavior

Human `get-neighbors`, `show-neighbors`, and `lldp-runner diff` output uses
ANSI color only when stdout is a TTY.

`NO_COLOR` disables color.

Redirected human output is automatically plain text.

CSV and JSON never contain ANSI color escapes.

One shared terminal-style module resolves semantic color roles from the
`[terminal]` configuration table. The defaults preserve the former hard-coded
palette: cyan headings/learned sections, green success/metrics, yellow
warnings, red failures, and magenta observed/inspection-neighbor emphasis.
Only validated named colors are accepted; raw ANSI strings are not config data.

Inspect diagnostics/logging go to stderr so redirected stdout remains parseable.

## 36. Finalized discovery viewer

`show-neighbors` and `lldp-runner show-neighbors` are intentionally
separate from the active
discovery and single-device inspection paths. They read only finalized
`discovery.json` data and do not open SQLite, create run directories, or send
network traffic. Configuration loading uses `CredentialMode.DISABLED`, so the
viewer does not build credential/profile/rule objects, synthesize runtime
credentials, resolve credential secrets, or validate credential policy. This
mode is reusable by future stored-data commands that have no network role.

The viewer has two internal responsibilities. `discovery_query.py` locates and
validates the current JSON contract, compiles name/key/address criteria, and
returns zero, one, or multiple host records. `discovery_view_output.py` renders
one selected record as a compact table, detailed terminal text, CSV, or
standalone JSON.

Table/detail output right-aligns the selected document's
`discovery.generated` value as `(json YYYY-MM-DD HH:MM:SS)` after converting
the instant through `[time].timezone`. Missing, malformed, or timezone-naive
source timestamps are rendered as `(json unknown-time)`. CSV uses
`timestamp=unknown` in that case. The viewer never substitutes file mtime or
the current clock because those would invent provenance not present in JSON.

Name matching uses case-insensitive Python regex with `re.match()` semantics.
Key filters use regex `search()` semantics after deterministic JSON-value
flattening. IPv4/IPv6 criteria use literal textual prefix matching unless CIDR
notation is present, in which case Python `ipaddress` network membership is
used. Every non-ID criterion is AND-combined; exact ID selection is deliberately
exclusive so an operator cannot believe an ignored filter was applied.

Topology direction is preserved from `discovery.json`. The normal display uses
learned neighbors when present and falls back to `observed_by` only for a host
without learned evidence. An explicit direction never falls back. When both
directions are requested, learned is always rendered first. Observed_by
management addresses are looked up through the neighbor `host_ref` so the
viewer reports the observer's management address rather than reusing an address
that the observer reported for the selected host.

Read-only path resolution deliberately does not call the runtime writable path
resolver. The default source is `outputs/latest/discovery.json`; `--runid`
selects
`outputs/<run-id>/discovery.json`, while `--file` resolves an operator pathname
independently of persistent storage. An operator only needs read access to the
selected finalized JSON, even when that account could not start a new run.

### 36.1 Finalized discovery comparison

`lldp-runner diff` extends the read-only discovery path to compare two
finalized discovery data sets. It also loads configuration with
`CredentialMode.DISABLED` and performs no network activity. The comparison
implementation is split between `discovery_diff.py`, which resolves sources,
pairs cross-run host identities, normalizes records, and computes deltas, and
`discovery_diff_output.py`, which renders human or machine-readable results.

Run-history aliases are ordered by timezone-aware completion metadata. The
resolver prefers the small `run.json` file in each finalized run directory and
uses only the leading discovery metadata as a fallback, avoiding full loads of
large historical discovery files merely to rank history. Once two sources are
selected, the comparison itself loads their supported discovery documents.

Host IDs are run-local. Graph diff therefore performs component correspondence
before consulting the flat compatibility projection. Entity components can be
one-to-one, one-to-many, many-to-one, or many-to-many and can
report `cluster_split`, `cluster_merge`, `cluster_reassociated`,
`duplicate_projection_introduced`, or `absorbed_duplicate`. These resolver
outcomes do not by themselves assert physical-link churn.

Relationship groups compare canonical multisets of observed members. A change
in protocol evidence, duplicate projection count, or resolver membership is
separate from physical topology. Since directness remains unresolved, diff uses
`physical_topology_assessment=not_inferred` when observed member sets change.
The flat schema-4-style host and neighbor comparison remains in the same output
as a compatibility diagnostic and for detailed host attributes.

Volatile timing fields and collection-route choices are normalized away. All
collector `duration_ms` leaves are ignored by default while remaining intact in
the source discovery documents. An explicit timing-comparison option includes
them for diagnostics. A lower uptime on the chronologically later record remains
a possible reboot.

Diff derives protocol/table coverage from durable host state, graph coverage,
and structured collector errors. If one run observes an entity or relationship
through protocol P on observer S, while paired observer S failed to collect P
in the other run, the one-sided result is coverage-uncertain rather than a
definite addition or removal. The same incident propagates through recursive
discovery provenance so downstream entities do not become false confirmed
changes. Raw error message text is not compared.

Graph entity and relationship correspondence carries one semantic qualification:
`confirmed`, `coverage_uncertain`, `presentation_only`, `evidence_only`, or
`ambiguous`. `evidence_only` means the relationship itself is stable while
non-authoritative name or raw protocol evidence changed. Collection incidents
aggregate the originating observer/protocol/table and their direct, recursive,
and attribute effects. Intentional `no_query` and `out_of_scope` populations
remain separate from actively queried partial/failed devices.

Typed unresolved interface-map coverage has the same conservative effect. When
one uniquely paired endpoint changes between two resolved local ports, diff
reports `moved`. When one run has a resolved interface name and the other has a
typed unresolved LLDP representation that is uniquely corroborated by remote
identity and remote port, the relationship remains `same`; the resolution loss
is `presentation_only`. This edge-scoped rule never creates a global
LLDP-local-port-number-to-ifIndex mapping.

Diff JSON schema 12 exposes graph correspondence, relationship-group outcomes,
subtable-scoped coverage authority, timing-comparison policy, semantic
qualifications, incident aggregation, compatibility pairing confidence,
canonical compatibility-projection groups, independent host dimensions,
attribute provenance, evidence changes, candidate moves, graph-backed change
events, explicit cross-view consistency, orthogonal relationship-change
dimensions, and graph-member-scoped event identity.

Compatibility macro diff performs an additional in-memory fold of duplicate
complete managed-host rows before one-to-one pairing. It requires compatible
direct logical names plus a shared host-eligible management address and rejects
hard identity conflicts. Exact names are compatible; one short name may match
the same left-most FQDN component, but two FQDNs are never matched by suffix
removal. Neighbor host references are remapped and duplicate rows are
deduplicated only in that diagnostic projection; graph advertisements remain
immutable and observation-complete.

Weak MAC-only cross-port correspondence is represented as an ambiguous
`candidate_move`. The graph does not convert a low-entropy, multicast, locally
administered, malformed, or otherwise weak identifier into proof of endpoint or
cable movement. Likewise, a successful zero-row optional ENTITY-MIB snapshot
does not prove chassis/member removal; diff reports attribute coverage
uncertainty instead of a confirmed managed-host change.

When a remote host cannot be globally paired, a same-local-port fallback can
use unique MAC evidence to correlate the edge. An exact IPv6 modified-EUI-64
IID can be reversed to its MAC for this edge-local purpose; the derived value is
not promoted into the global discovery alias namespace.

`run.json` metadata can also warn when config-file path order or seed inputs
differ. Discovery metadata supplies effective scope details such as boundaries
and limits. These warnings provide context but do not prove whether a file at
the same pathname had identical content across runs. See [DIFF.md](DIFF.md)
for the
operator contract.

## 37. Error philosophy

LLDP-Runner tries to preserve useful partial data rather than turning every
optional collector failure into a failed device.

Examples:

```text
DNS fails but a carried-forward seed IP exists -> query can still proceed
ICMP fails but SNMP responds                  -> device can still succeed
ENTITY-MIB enrichment fails                  -> basic discovery can continue
LLDP times out once, retry succeeds      -> recovered without coverage loss
LLDP fails after retry but CDP works     -> CDP neighbors are retained
SNMP basic exhausts all attempts              -> device is FAILED
```

Errors are structured whenever practical so operators can distinguish timeout,
authentication, access/view restriction, transport, unsupported OID, and other
categories.

Secrets are redacted from worker exception messages before they reach output.

## 38. Performance model

LLDP-Runner is primarily network-I/O bound, so low CPU utilization does not by
itself mean the tool is underutilizing the host.

Important throughput controls include:

```text
workers
batch_size
max_outstanding_devices_per_worker
per_device_rps
SNMP timeout and adaptive retry
max_repetitions
ENTITY-MIB enablement
snapshot interval
```

More workers are not always faster. Device response time, SNMP rate limits,
network latency, cohort stragglers, and the central output/state workload can
be the dominant factors.

In seed-only mode, each worker can process its assigned batch asynchronously.
Starting one process per seed is therefore usually wasteful when a smaller
worker set can place the same seeds in flight. LLDP-Runner right-sizes this
known workload after initialization, using the smaller of batch size and the
per-worker outstanding-device limit as first-wave capacity. Recursive discovery
keeps configured scheduler limits because its future work is not known yet.

Starting a later run with a reusable `seeds.csv` can improve ramp-up because
many known managed devices become initial seeds rather than having to be
rediscovered serially from one edge of the graph.

## 39. Why the coordinator is intentionally topology-specific

The current coordinator is designed around:

```text
host identity
neighbor edges
classification
recursive scheduling
seed ordering
run checkpoints
```

Low-level components such as the SNMP client and collectors are more reusable.

Future non-topology SNMP projects should avoid forcing unrelated concepts such
as route tables or interface counters into neighbor-recursion abstractions.

A likely future reuse boundary is below the topology coordinator:

```text
             shared SNMP/session components
               /                    \
              /                      \
     LLDP-Runner topology       future collectors
```

The single-device inspect refactor is already a step in that direction because
it exposes worker collection behavior without requiring recursive state.

## 40. Module map

The most important package modules are:

```text
cli.py
  command parsing and command dispatch

config.py
  config discovery, include/conf.d loading, precedence, validation

defaults.py
  built-in operator-maintainable defaults

configgen.py
  commented generated configuration

csv_input.py
  shared dynamic-position CSV parsing and structural validation

seeds.py
  seed files, directories, seed CSV semantics, text parsing

identity.py
  seed/discovered-name DNS and identity helpers

policy.py
  boundary, query-policy, and credential-policy decisions

classify.py
  host classification and tagging logic

coordinator.py
  single-owner graph state, scheduling, run lifecycle

state.py
  SQLite schema, host/alias/edge/error persistence and merges

worker.py
  multiprocessing worker and async device collection flow

snmp/
  project-owned SNMP abstraction, active Gufo backend, and telemetry

collectors/
  SYSTEM, IF, ENTITY, LLDP/LLDPv2, and CDP collection

icmp.py
  asynchronous ICMP probes

textutil.py
  SNMP/output text sanitation

outputs.py
  discovery JSON/CSV generation and finalization

scoreboard.py
  live run status output

inspection.py
  one-device in-memory inspection orchestration

inspection_output.py
  table, detail, CSV, and JSON inspect renderers

discovery_query.py
  read-only discovery.json loading, validation, and host filtering

discovery_view_output.py
  stored-discovery table, detail, CSV, and JSON renderers

discovery_diff.py
  source resolution, cross-run identity pairing, normalization, and deltas

discovery_diff_output.py
  terminal and machine-readable discovery comparison rendering
```

## 41. Core invariants for maintainers

Future changes should preserve these principles unless a deliberate design
change is documented.

### 40.1 One authoritative state owner

Workers should return observations. The coordinator should decide identity,
state transitions, edge insertion, and recursive scheduling.

### 40.2 Unknown is not permission to query

A newly observed host is not recursively queried merely because it exists.
Classification and query policy must positively permit that work.

### 40.3 Boundary and query policy are different controls

Recursive scope and explicit query prohibition must not be conflated.

### 40.4 `max_devices = "auto"` is a scheduling mode

Do not reduce it to a numeric comparison. Non-seed neighbors must remain
recordable without becoming worker work.

### 40.5 Zero means unlimited for host/device guardrails

Guardrail checks must explicitly ignore zero rather than interpreting it as a
limit of zero objects.

### 40.6 Seed origin is provenance

A learned device does not become `origin=seed` because it was later queried.

### 40.7 COMPLETE implies a successful query target

A COMPLETE managed device with no query target indicates inconsistent state.
Transient READY/CLAIMED states do not have this invariant.

### 40.8 Machine-readable output must remain clean

CSV/JSON should never depend on terminal width or contain ANSI color escapes.

### 40.9 Do not silently add legacy input compatibility

Current documented input formats are the supported formats. If a future change
would require accepting an older/legacy input format, that compatibility should
be an explicit design decision rather than an automatic extension.

### 40.10 Selective ENTITY-MIB queries must discover indexes

`entPhysicalIndex` is agent-assigned and must not be assumed to be `1` or
contiguous. `auto` and `brief` therefore walk only `entPhysicalClass`, select
chassis/stack/module candidates, and use targeted instance GETs after an index
is known. If multiple candidates exist, `entPhysicalContainedIn` is requested
only for those candidates so a root physical entity can be preferred.

`full` remains the compatibility/default path and continues to walk the entire
`entPhysicalEntry` subtree. `collect_entity_mib=false` bypasses all three modes.

## 42. High-level discovery pseudocode

```text
config = load_defaults_and_operator_overrides()
seeds = collect_all_seed_sources()

state = open_or_resume_sqlite_run()
for seed in seeds:
    resolve_identity(seed)
    upsert_seed_into_state()

order_unique_seeds()
resolve_max_device_mode()
fail_fast_if_finite_limit_is_smaller_than_seed_inventory()

start_worker_processes()

while not finished:
    check_pause_worker_health_and_limits()

    for idle_worker in workers:
        batch = claim_ready_hosts()
        tasks = build_policy_permitted_tasks(batch)
        send_to_worker(tasks)

    for returned_batch in result_queue:
        for device_result in returned_batch:
            persist_device_result()
            for neighbor in device_result.neighbors:
                candidate = enrich_and_classify(neighbor)
                remote_id = upsert_or_merge(candidate)
                persist_edge(device_result.host_id, remote_id)
                schedule_if_queryable(remote_id)

    periodically_write_scoreboard_and_draft_output()

stop_workers()
checkpoint_state()
finalize_or_preserve_draft_output()
```

## 43. High-level worker pseudocode

```text
async process_batch(tasks):
    results = create_deferred_results(tasks)

    unresolved = tasks
    while unresolved:
        ping_newly_selected_addresses(unresolved)
        await one_basic_snmp_attempt_for_each(unresolved)
        advance_retry_fallback_or_address_on_failure()
        remove_successes_and_exhausted_tasks()

    concurrently for each successful device:
        optionally_collect_entity_mib(full|auto|brief)
        collect_interfaces()
        collect_lldp()
        collect_lldpv2()
        collect_cdp_when_applicable()
        merge_neighbor_observations()

    return complete_batch_results
```

### 42.1 ENTITY-MIB detail collection

The basic SYSTEM-MIB phase completes before detail collection. That ordering is
important for `auto`: manufacturer and `sysDescr` are already available, so the
collector can choose a device-aware query plan without another identity probe.

`full` performs the historical `entPhysicalEntry` walk and applies the same
logical chassis/stack/module ranking used in v0.13.1. Stack-member inventory is
parsed from that already-returned table, so enabling v0.15.0 member reporting
does not add SNMP requests to full mode.

`brief` and `auto` first walk the single `entPhysicalClass` column. Candidate
structure is then retrieved with targeted `entPhysicalContainedIn`,
`entPhysicalParentRelPos`, `entPhysicalName`, and `entPhysicalDescr` GETs as
needed. A standards-conforming `stack(11)` containing `chassis(3)` rows is
preferred. Multiple sibling chassis rows are a conservative fallback for agents
that expose physical members but omit an explicit stack container.

The brief identity field set is `entPhysicalSerialNum`, `entPhysicalMfgName`,
and `entPhysicalModelName`. The auto network-device profile adds
`entPhysicalHardwareRev`, `entPhysicalFirmwareRev`, and
`entPhysicalSoftwareRev`. Identity GETs cover the selected logical physical
entity and every detected member index. Unknown and virtual identities stay on
the brief profile so auto mode is conservative when device type cannot be
established.

Member numbering prefers non-negative `entPhysicalParentRelPos`. When a switch
agent does not provide useful relative positions, LLDP-Runner conservatively
recognizes common labels such as switch/member/chassis/FPC/slot followed by a
number. This fallback supports real-world variation without binding the core
algorithm to Cisco StackWise, Aruba CX VSF, Juniper EX Virtual Chassis, or any
other proprietary stack MIB. Conforming ENTITY-MIB implementations from other
manufacturers receive the same standards-first treatment. Expected auto-rich
platform regression coverage includes Cisco Catalyst 9200/9300/9500/3650/3850,
Aruba/HPE CX 6200/6300, and Juniper EX 4100/4300/4400/4600/4650 families.

`entPhysicalIndex` and stack-member position are observations, not durable
physical identities. The per-member chassis serial is retained so inventory
consumers can distinguish a stable logical management IP/hostname from the set
of physical switches currently composing that stack. ENTITY-MIB provides no
portable per-member uptime, so output leaves it unknown unless a future/profile
collector obtains a genuine member-specific value.

The collector consumes the project-owned SNMP client protocol, so
`CountingSnmpClient` measures class walks and targeted GETs without backend-
specific instrumentation. This makes `get-neighbors` and optional discovery
metrics
useful for comparing object counts and elapsed time among the three modes.

## 44. Operational reasoning behind the architecture

The architecture intentionally trades some implementation simplicity for
operational predictability.

A single state owner reduces duplicate polling and race-prone graph decisions.

SQLite provides durable checkpoints without requiring another service.

Multiprocessing isolates workers, while asyncio makes each worker efficient for
network I/O.

Policy is evaluated centrally so recursive behavior remains explainable.

Outputs preserve inbound topology evidence even when a remote device is not
queried or fails.

Seed-only mode and randomized ordering support bounded sampling without turning
learned neighbors into accidental recursive work.

Single-device inspection reuses real worker collection code so troubleshooting
also exercises code used by full discovery.

These decisions are intended to make LLDP-Runner understandable and safe for
Network Operations while leaving lower-level collection components available
for future reuse.

## 0.32.5 transport and recovery boundaries

The Gufo adapter owns destination syntax. Identity and coordinator layers pass
canonical unbracketed IP text. For the exact Gufo 0.12.0 raw-IPv6 constructor
failure, the adapter alone performs one bracketed construction attempt. This is
not visible as a second coordinator route or adaptive SNMP retry.

Worker failures cross the process boundary as structured values rather than as
messages that later code must parse. SQLite stores route errors separately from
the host's successful query presentation and maintains durable route-attempt
history.

Late-address recovery is a coordinator/state transaction. It never modifies
worker retry budgets. The state store verifies the current failed state,
consumed allowance, and unattempted addresses before it atomically records an
admission and returns the host to `READY`.

LLDP collection coverage has two levels. The aggregate protocol record answers
whether the protocol observation is complete enough for broad comparison.
Nested subtable records preserve the independent remote-neighbor,
remote-management-address, and original-LLDP local-port outcomes needed for
precise uncertainty and address-evidence decisions.

## 0.32.6 comparison authority boundaries

Comparison authority follows the smallest collection unit that can answer the
question. LLDP/LLDPv2 `remote_neighbor` coverage decides relationship presence;
original-LLDP `local_port` coverage and row-level resolution decide whether a
local interface is authoritative; and `remote_management_address` coverage
decides whether an address removal is authoritative. Aggregate protocol status
remains useful health telemetry but cannot override a complete semantic
subtable.

Compatibility-projection folding preserves these dimensions. A duplicate host
projection can contribute complete neighbor coverage while another contributes
a partial management-address result; the merged view retains both facts rather
than reducing all LLDP authority to the worst aggregate status.

Attribute differences can be derived from neighbor evidence rather than a local
ENTITY-MIB table. Field comparison therefore carries provenance and exact
coverage sources. Graph comparison receives the same source map so a missing
identity-derived component is coverage-uncertain when its observer failed,
instead of becoming a confirmed one-sided entity.

Human rendering is a view over the complete comparison. Default output collapses
derivative uncertain rows beneath collection incidents, summary-only output
omits row detail, and expanded output restores it. None of these options removes
structured JSON evidence or changes comparison status.

## 0.32.7 cross-view reconciliation boundaries

The compatibility projection and topology graph remain separate semantic views.
Compatibility rows are observer-directional; graph relationship records group
immutable protocol observations by local interface. After both views complete
their conservative comparison, the reconciliation layer joins them without
creating new identity or topology evidence.

Every non-stable compatibility learned-neighbor row is matched to graph members
using observer host references, typed local interface, paired remote host
references, remote port, strict MAC evidence, names, and protocol set. Unique
change events preserve all contributing compatibility and graph references.
Unmatched, ambiguous, conflicting, and graph-only records are reported as
cross-view inconsistency instead of being forced into agreement.

Graph LLDP authority is read from `remote_neighbor` when schema-8 subtable
coverage exists. A management-address-only partial result remains aggregate
health but cannot downgrade a complete relationship snapshot. A true
remote-neighbor failure remains coverage-uncertain with exact
`lldp.remote_neighbor` or `lldpv2.remote_neighbor` provenance.

Collection incidents include graph-native sources and state whether any reported
difference depends on the gap. Health-only gaps remain visible without making a
stable relationship look changed. Management-address health is compared in a
separate persistence/new/recovery dimension.

A local-interface transition is an observed attachment change. LLDP-Runner can
confirm continuity of the observed endpoint identity and the changed observer
port, but it retains unresolved directness and does not infer physical cable
movement, intermediate devices, or layer-1 topology.

## 0.32.8 compound relationship-change dimensions

A graph relationship is still assigned one concise primary `status`, but that
status is no longer the only description of change. Schema 12 adds
`change_dimensions`, `member_presence_change`, and `member_protocol_changes` to
each relationship comparison. A local-interface group can therefore record a
new or missing member and a protocol-set transition for another stable member
at the same time.

Member evidence is keyed by the remote correspondence component and normalized
remote port. Reconciliation of a protocol transition inside a primary
`member_set_changed` record requires that exact key and the exact A/B protocol
sets. Management-address and relationship-evidence rows likewise require one
exact member present on both sides with an unchanged protocol set. This avoids
using unrelated membership churn as generic proof for an evidence change.

Change-event fingerprints include `graph_member_keys`. Distinct remote members
inside one relationship group remain distinct events, while repeated or
reciprocal compatibility observations for the same member can share one event.
Dimension claims are tracked independently. If compatibility rows explain only
member presence, an unrepresented protocol-evidence dimension remains a
`graph_only` event and keeps cross-view status at `attention_required`.

## 0.32.9 locally assigned chassis and anonymous endpoint identity

LLDP chassis subtype 7 is locally assigned. Its syntax can be valid and its text
can be useful to an operator without being unique outside the advertising
agent's local context. The compatibility resolver therefore retains subtype-7
values in raw neighbor evidence and as weak edge-scoped claims, but no longer
registers them in the global `chassis_id` alias namespace.

An otherwise anonymous LLDP or LLDPv2 endpoint can still receive stable bounded
identity when its Port ID is explicitly typed as a MAC address. The value must
be a complete conventional MAC representation, and every retained typed
LLDP/LLDPv2 representation must agree. The compatibility host receives that
canonical `mac` alias and the claim ledger records a strong derived
`anonymous_lldp_port_mac` claim. A usable direct name, management address, or
trusted chassis identity takes precedence; per-interface Port IDs do not split a
named or addressed multi-interface device.

The topology graph already creates separate `endpoint:mac:<value>` observed
entities for these anonymous typed Port IDs. Graph materialization now compares
that authoritative endpoint set with the merged host/neighbor compatibility
projection. If one legacy compatibility host refers to several distinct
anonymous endpoint MAC entities under locally assigned chassis evidence, the
graph publishes `compatibility_projection_diagnostics` and appends a component
decision. The warning records the compatibility host reference, endpoint MACs,
graph entity keys, observer references, and edge count, while declaring
`authoritative_graph_impact=none`.

This maintenance rule does not rewrite archived 0.32.8 discovery files or split
an already-persisted compatibility host in place. It applies while new
observations are projected during a 0.32.9 scan. Replaying an older state can
surface the diagnostic so operators can distinguish a legacy flat-host
aggregate from the unchanged authoritative graph.
