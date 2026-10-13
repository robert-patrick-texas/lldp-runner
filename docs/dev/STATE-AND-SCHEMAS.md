# State and Schema Reference

For the compact list of current JSON contract versions and top-level sections,
start with [`SCHEMA.md`](SCHEMA.md). This document focuses on durable state,
evidence history, migrations, and the reasoning behind those contracts.

## Current external contracts

The current LLDP-Runner release publishes independently versioned contracts:

- `run.json` schema 3 for invocation provenance and lifecycle timing;
- `discovery.json` schema 8 for completed discovery and compatibility views;
- topology graph schema 2 embedded in `discovery.json`;
- diff JSON schema 12 for cross-run comparison; and
- the separately versioned active-run scoreboard.

Advancing one contract does not require changing every other contract. A
version changes when consumers must distinguish an incompatible structure or
meaning. LLDP-Runner validates supported discovery schemas strictly and does
not silently convert older discovery JSON.

## SQLite responsibilities

SQLite is the durable run/checkpoint store. Major families include:

- compatibility hosts, many-to-many addresses, aliases, and neighbors;
- immutable observations, typed claims, and protocol advertisements;
- collection metrics, adaptive-session telemetry, and table coverage;
- append-only resolution and graph-component decisions;
- the compact current graph projection;
- route-attempt history; and
- scheduler admission events.

Immutable evidence and decision history must not be updated or deleted. A new
interpretation appends a superseding decision.

## Route attempts and late recovery

`route_attempts` records the normalized destination, family, non-secret
credential source/profile/label/stage, attempt, outcome, category, and time for
each basic SNMP route. It never contains community, authentication, or privacy
material.

`hosts.late_recovery_used` persists the bounded admission count. A
`scheduler_events` row records each accepted late-address recovery with the new
address, evidence source, prior state, and remaining allowance. Host merges
move route history and events to the winner and retain the maximum consumed
allowance; they do not add allowances or recreate attempted routes.

## Structured errors

The `errors` table stores host context separately from exact worker-route
provenance. New columns include `attempted_target`, `address_family`, `phase`,
module-qualified exception type, OS error fields, redacted exception arguments,
collector, and existing credential-route labels. Output derives `final_state`
from the current host row at snapshot time, so a historical failure remains
present without claiming that a later-recovered host is still failed.

## LLDP coverage

Schema 8 retains aggregate `lldp` and `lldpv2` coverage and adds nested
subtables. Original LLDP exposes `local_port`, `remote_neighbor`, and
`remote_management_address`; LLDPv2 exposes `remote_neighbor` and
`remote_management_address`. Each record contains status, attempts, object and
row counts, duration, and message. Management-address coverage also records
valid, rejected, malformed, IPv4, and IPv6 counts.

A complete zero-row management table is authoritative empty evidence. Timeout,
access restriction, malformed-index degradation, interruption, and other
incomplete outcomes are not equivalent to an empty table.

## Graph authority dimensions

Do not use one Boolean to imply more certainty than the data supports. Current
graph output reports:

- observation completeness;
- observation projection status;
- entity-resolution maturity;
- physical-topology inference status;
- directness status; and
- compatibility-projection role.

An observation-complete graph may still have provisional entity resolution and
unresolved directness.

## 0.32.9 compatibility identity projection

Schema versions remain unchanged. New candidate projection no longer admits
LLDP/LLDPv2 locally assigned chassis subtype 7 into the global `chassis_id`
alias namespace. The raw value remains in protocol advertisements, neighbor
details, and a weak edge-scoped claim.

When no usable direct name, host-eligible management address, or trusted
chassis alias exists, one unambiguous typed MAC-address Port ID can create a
canonical `mac` alias and a strong derived `anonymous_lldp_port_mac` claim. The
fallback is deliberately unavailable to named or addressed candidates so a
multi-interface device is not split by its interface Port IDs.

Topology graph schema 2 adds optional
`compatibility_projection_diagnostics` and the corresponding summary count.
These records diagnose legacy flat hosts that span several distinct anonymous
`endpoint:mac:` graph entities under locally assigned chassis evidence. They
are derived diagnostics, not graph-materialization input, and explicitly carry
`authoritative_graph_impact=none`.

## Diff schema 10

Diff schema 10 leaves discovery state unchanged. It records whether collection
`duration_ms` was included, separates aggregate protocol health from
relationship/interface/management-address authority, adds
`relationship_evidence_changed` and `evidence_only`, and retains field-level
attribute provenance and coverage sources. Human-render controls do not remove
data: JSON always serializes the complete comparison.



## Diff schema 11

Diff schema 11 leaves discovery schema 8, topology graph schema 2, and run
schema 3 unchanged. It adds stable compatibility-observation,
graph-relationship, and
change-event references; explicit cross-view consistency; graph-native and
health-only collection incidents; observed-attachment semantics; and compact
management-address health transitions.

The graph uses LLDP/LLDPv2 `remote_neighbor` subtable status as relationship
coverage authority. Aggregate partial status caused only by
`remote_management_address` cannot make a complete graph relationship uncertain.
A true remote-neighbor failure retains exact subtable provenance.

`change_events[]` is the unique event inventory. Compatibility rows remain
observer-directional diagnostics and graph relationship groups retain immutable
member evidence. The reconciliation layer does not modify discovery state or
promote weak evidence into identity.

## Diff schema 12

Diff schema 12 leaves discovery schema 8, topology graph schema 2, and run
schema 3 unchanged. Relationship comparisons add `change_dimensions`,
`member_presence_change`, and `member_protocol_changes`. These fields preserve
simultaneous membership and protocol-evidence transitions that one primary
relationship `status` cannot express alone.

Change events add `graph_member_keys` and `graph_change_dimensions`. Event keys
are scoped by both the graph relationship and exact remote graph member, so
distinct neighbors on one local interface do not collapse. Reconciliation of
compound records requires exact remote component, remote port, and protocol-set
corroboration. Unclaimed reportable dimensions remain explicit graph-only
events rather than being hidden by another matched dimension.


## Migration practice

State migrations are additive. Opening a 0.32.4 database creates the new route,
scheduler, error-provenance, and late-recovery structures without deleting
prior evidence. Historical Gufo IPv6 errors are enriched only when one unique
persisted session route corroborates the exact constructor signature; ambiguous
records remain null rather than borrowing the host presentation target.

Tests cover fresh creation, immediate-predecessor migration, restart, merges,
and deterministic state-to-output regeneration. Production replay regenerates
schema-8 output from copied state databases; it does not claim legacy discovery
JSON compatibility.
