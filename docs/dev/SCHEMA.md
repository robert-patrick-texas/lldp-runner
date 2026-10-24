# Schema Quick Reference

This page lists the current machine-readable contracts shipped by
LLDP-Runner 0.39.1. It is a quick index for developers, test authors, and
external consumers. See
[`STATE-AND-SCHEMAS.md`](STATE-AND-SCHEMAS.md) for durable-state, migration,
and evidence-history details.

## Current versions

| Contract | Version field | Current version |
| --- | --- | ---: |
| `discovery.json` | `schema_version` | 8 |
| Embedded topology graph | `topology_graph.schema_version` | 2 |
| Diff JSON | `schema_version` | 12 |
| `run.json` | `schema_version` | 3 |
| Active-run `scoreboard.json` | `scoreboard_schema` | 1 |

The application release version is independent of these contracts. A display,
documentation, or packaging release does not advance a schema unless a consumer
must distinguish a changed structure or meaning.

## `discovery.json` schema 8

Purpose: canonical completed discovery output and compatibility inventory.

Top-level sections:

```text
schema_version
discovery
topology_graph
hosts
errors
```

`discovery` contains run metadata, configured limits, boundaries, counts, and
completion context. `hosts` contains the compatibility host projection,
classification, identity evidence, collected system details, and learned and
`observed_by` neighbors. `errors` contains structured collection and run errors.
The embedded graph is described separately below.

The current reader requires schema 8. It does not silently translate older
`discovery.json` formats.

Implementation constant:
`lldp_runner.outputs.DISCOVERY_JSON_SCHEMA_VERSION`.

## Topology graph schema 2

Purpose: claims-driven entity, interface, advertisement, membership, and
relationship projection embedded under `discovery.json.topology_graph`.

Important sections include:

```text
schema_version
authority
directness_policy
entities
interfaces
advertisements
memberships
relationships
relationship_groups
advertisement_exclusions
collection_coverage
projection_fingerprint
summary
```

The graph reports observation, entity-resolution, directness, physical-topology,
and compatibility-projection authority separately. Its deterministic fingerprint
excludes run-local compatibility references that are not stable graph identity.

Implementation constant:
`lldp_runner.topology_graph.TOPOLOGY_GRAPH_SCHEMA_VERSION`.

## Diff JSON schema 12

Purpose: machine-readable comparison of two supported discovery documents.

Top-level sections:

```text
schema_version
result
mode
sources
warnings
comparison
```

`comparison` contains host, learned-neighbor, graph relationship, collection
coverage, health, change-event, and cross-view reconciliation results selected
by the requested diff mode. Schema 12 includes member-scoped graph event keys
and orthogonal relationship-change dimensions.

Implementation constant:
`lldp_runner.discovery_diff.DIFF_JSON_SCHEMA_VERSION`.

## `run.json` schema 3

Purpose: sanitized invocation provenance and lifecycle timing for one logical
run, including resume invocations.

The document begins with `schema_version`, `app_name`, and `app_version`, then
records run identity, the selected SNMP backend name and installed package
version, state, timestamps, duration fields, launch identity, configuration
provenance, and an append-only `invocations` array. Each invocation also records
its installed version of the run's fixed backend. Credential and password values
are redacted before persistence.

The backend fields use the existing schema-3 diagnostic/provenance extension
points. Discovery, topology, diff, run, and scoreboard schema numbers therefore
remain unchanged in 0.37.0.

Implementation constant:
`lldp_runner.run_manifest.RUN_JSON_SCHEMA_VERSION`.

## `scoreboard.json` schema 1

Purpose: compact, atomically published live status consumed by
`lldp-runner status --json` and `lldp-runner watch`.

It records run identity, start/update times, state, elapsed time, discovery
counters, worker status, and the effective execution plan when available. The
live file remains as the terminal snapshot after completion, and an identical
copy is archived with durable completed-run state. It remains a status contract,
not a canonical completed discovery artifact.

Implementation constant: `lldp_runner.scoreboard.SCOREBOARD_SCHEMA`.

## Version-change checklist

When a schema changes:

1. Advance only the affected implementation constant.
2. Update its writer, reader validation, fixtures, and public documentation.
3. Add positive coverage for the new form and rejection coverage for unsupported
   forms.
4. Update this page and add one schema-change note to
   [`CHANGELOG.md`](../../CHANGELOG.md).
5. Do not repeat unchanged schema numbers in later changelog entries.
