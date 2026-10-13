# Custom CSV Output

LLDP-Runner 0.29.0 can generate operator-defined CSV reports from the same
canonical discovery document written as `discovery.json`. Custom CSV rendering
never reopens SQLite state and therefore follows the same JSON-first output
boundary as the five fixed CSV reports.

## 1. Configuration shape

Each report is a named child table below `output.custom_csv`:

```toml
[output.custom_csv.inventory]
enabled = true
filename = "inventory.csv"
source = "hosts"
columns = [
  { field = "hosts.preferred_name", header = "FQDN" },
  { field = "hosts.origin" },
  { field = "json.host.system.model" },
  { field = "json.host.system.serial_number", header = "serial" },
]
```

The table name (`inventory` above) is an LLDP-Runner configuration identifier.
It is not written into the CSV. `filename` must be one relative `.csv` filename
inside the current run output directory. Absolute paths, path separators, `..`,
and names colliding with LLDP-Runner's standard outputs are rejected.

`enabled` defaults to `true`. Disabled custom reports are not written.

## 2. Row sources

Every custom CSV declares one `source`. The source defines what one output row
represents and prevents ambiguous cross-record joins.

```text
hosts            one hosts[] record
stack-members    one system.stack_members[] record plus parent-host context
seeds            one reusable managed-device seed row
unknown-devices  one host classified as unknown_device
errors           one errors[] record
```

A report cannot combine independent row grains. For example, an `errors` source
cannot select a `hosts.model` field because one host may have many errors.

## 3. Fixed presentation fields

Each source exposes the fields from its LLDP-Runner fixed CSV using the source
name as a namespace. These fields preserve existing presentation transforms.

Examples:

```text
hosts.preferred_name
hosts.origin
hosts.uptime_seconds
hosts.learned_neighbors
hosts.observed_by_neighbors

stack-members.member_number
stack-members.model
stack-members.serial_number

seeds.preferred_name
seeds.notes

unknown-devices.protocols
unknown-devices.observed_chassis_ids
unknown-devices.observed_by_neighbors

errors.category
errors.final_state
```

The default output header is the field leaf name. For example,
`hosts.preferred_name` defaults to `preferred_name`. Set `header` when a site
needs another label such as `FQDN`.

The fixed `unknown-devices.csv` review file omits `manufacturer` and `model`.
The same-source fields `unknown-devices.manufacturer` and
`unknown-devices.model` are not supported and fail configuration validation as
unknown fields. Use `json.host.system.manufacturer` and
`json.host.system.model` when an explicit canonical system-value projection is
required.

`preferred_name` is normalized once while the canonical discovery document is
built, before fixed or custom CSV rendering. Therefore
`hosts.preferred_name` and `json.host.preferred_name` agree: both omit a
recognized trailing hardware serial decoration and can use one unambiguous
typed chassis value for narrowly defined unnamed or placeholder-only records.
For `unknown`, a MAC chassis fallback requires blank observed names and remote
descriptions. The operation does not rewrite raw protocol evidence or identity
aliases. See [NAMES.md](NAMES.md) for the exact guarded rules.

The `seeds` source may additionally select `hosts.<field>` fixed presentation
fields. This is safe because each reusable seed row maps one-to-one to a managed
host, so the row grain does not change. It is useful for inventory exports that
need host system, address, tag, or neighbor summaries while excluding
non-managed rows. See
`configs/conf.d/custom-inventory-csv.toml.example` for a complete
`inventory.csv` example.

Fixed presentation fields cannot receive an additional `transform`. Select a
`json.*` field when another controlled transformation is needed.

## 4. Canonical JSON fields

Direct JSON fields use explicit row contexts:

```text
json.host.<path>
json.member.<path>
json.error.<path>
json.discovery.<path>
```

`json.host` is available to `hosts`, `stack-members`, `seeds`, and
`unknown-devices`. `json.member` is available only to `stack-members`.
`json.error` is available only to `errors`. `json.discovery` metadata is
available to every source.

The registry is intentionally bounded. A key merely existing somewhere in
`discovery.json` does not automatically make it a supported custom field.
This keeps row semantics and transforms reviewable before they become an
operator-facing contract.

### 4.1 Host JSON fields

Supported host paths include:

```text
id
preferred_name
queried_as
snmp_sysname
classification
state
is_seed
first_seen
last_seen
last_seen_source
chassis_id
classification_reason
tags
names
addresses.ipv4
addresses.ipv6
icmp
learned_neighbors
observed_by_neighbors
system.sys_name
system.sys_descr
system.sys_object_id
system.sys_uptime_ticks
system.sys_contact
system.sys_location
system.manufacturer
system.model
system.version
system.serial_number
system.hardware_revision
system.firmware_revision
system.entity_software_revision
system.snmp_engine_id
system.stack_members
snmp.credential_profile
snmp.credential_result
snmp.collection_metrics
```

### 4.2 Stack-member JSON fields

Supported `json.member` paths are:

```text
entity_index
member_number
name
description
manufacturer
model
serial_number
hardware_revision
firmware_revision
software_revision
uptime_seconds
```

### 4.3 Error JSON fields

Supported `json.error` paths are:

```text
host_ref
device
query_target
timestamp
operation
category
credential_profile
credential_stage
attempt
message
recoverable
final_state
```

### 4.4 Discovery metadata

Supported `json.discovery` paths include:

```text
run_id
status
started
completed
generated
boundaries
discovery_mode
effective_max_devices
configured_max_devices
configured_max_hosts
seed_order
shuffle_key
limit_behavior
limit_reason
completion_reason
snmp_report_metrics
counts
```

## 5. Controlled transforms

Scalar JSON values can be written directly. Boolean values are written as
lowercase `true` or `false` when no transform is selected.

The following controlled transforms are available:

```text
lower            lowercase a scalar value
upper            uppercase a scalar value
origin           boolean true/false -> seed/learned
join:semicolon   join an approved scalar array with semicolons
join:comma       join an approved scalar array with commas
json             compact JSON encoding for an approved list/object
```

Structured arrays and objects require an explicit allowed transform. This
prevents Python list/dict representations from leaking into CSV cells and makes
the serialized value deterministic.

For example:

```toml
columns = [
  { field = "json.host.tags", transform = "join:semicolon" },
  { field = "json.host.addresses.ipv4", transform = "join:semicolon" },
  { field = "json.host.is_seed", transform = "origin", header = "origin" },
  { field = "json.discovery.counts", transform = "json" },
]
```

LLDP-Runner does not execute arbitrary Python, templates, `eval()`, or other
operator-supplied expressions as custom CSV transforms.

## 6. Header and ordering rules

The order of entries in `columns` is the exact CSV column order. If `header` is
omitted, the leaf field name is used. Header labels must be non-empty and must
be unique within one report, compared case-insensitively.

Example:

```toml
columns = [
  { field = "hosts.preferred_name", header = "FQDN" },
  { field = "hosts.queried_as", header = "management_target" },
  { field = "hosts.model" },
  { field = "hosts.serial_number", header = "serial" },
]
```

produces:

```text
FQDN,management_target,model,serial
```

## 7. Empty files and publication

Custom reports use the same output lifecycle as fixed CSVs:

```text
atomic temporary write + fsync + replace
periodic draft snapshots
final persistent publication
output.write_empty_csv
output.log_alert_on_empty_csv
```

With the default `output.write_empty_csv=false`, an enabled custom report whose
source has zero rows is not written. If empty-file alerting is enabled, fixed
and custom suppressed reports are combined into the terminal INFO message for
the final snapshot.

Custom CSVs are written beneath the current run output directory and are
published with the other run artifacts. A resumed run removes a stale custom
report from its persistent output directory when that report is later disabled
or suppressed as empty.

## 8. Configuration precedence

Named custom tables merge like other configuration tables. A later file can
change one scalar such as `enabled` without repeating the entire definition.
The `columns` list is a replacement list, not an accumulating policy list.

For example, an included file can define:

```toml
[output.custom_csv.inventory]
filename = "inventory.csv"
source = "hosts"
columns = [
  { field = "hosts.preferred_name" },
  { field = "hosts.state" },
]
```

and the primary file can replace only the selected columns:

```toml
[output.custom_csv.inventory]
columns = [
  { field = "hosts.preferred_name" },
  { field = "json.host.system.model" },
]
```

The resulting report has exactly those two columns.

## 9. Design boundary

Custom CSV is intentionally a projection feature, not a join/query language.
If a requested value has unclear row cardinality or cannot be mapped cleanly to
one source record, it should remain unavailable until LLDP-Runner defines an
operator-safe semantic for it.
