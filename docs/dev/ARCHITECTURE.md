# Contributor Architecture Map

For end-to-end collection, resolver, and graph-rematerialization paths, see
[`FLOW-DIAGRAMS.md`](FLOW-DIAGRAMS.md). Its Mermaid source names the
implementation and persistence boundaries summarized here.

## Runtime ownership

The CLI builds validated configuration and run paths. The coordinator owns
SQLite, scheduling, graph state, final output, and run lifecycle. Worker
processes perform network I/O and return `DeviceResult` objects. Workers do not
write canonical topology state directly.

## Evidence flow

```text
collector table rows
    -> protocol observations
    -> immutable SQLite observations
    -> typed claims
    -> candidate components
    -> append-only decisions
    -> current graph projection
    -> compatibility host/neighbor view
```

A collector should retain raw values and MIB index context. A normalizer can add
canonical values, but it must not destroy the source representation. A resolver
may associate observations, but that association remains a decision that later
evidence can supersede.

## Process boundaries

- `cli.py` and `config.py`: operator input and validation.
- `coordinator.py`: run orchestration, ownership, scheduling, finalization.
- `worker.py`: one-device collection workflow.
- `collectors/` and `snmp/`: protocol interaction and structured table data.
- `state.py`: SQLite schema and transactional state operations.
- `topology_graph.py`: deferred graph materialization.
- `topology_graph_diff.py`: graph component correspondence.
- `outputs.py`: canonical discovery and report production.

## Safety boundaries

- Credential selection and secret resolution are isolated from read-only
  commands.
- Failed or partial SNMP tables carry coverage status.
- Immutable observations and decisions cannot be updated in place.
- Graph IDs are semantic; SQLite row IDs are run-local implementation details.
- Compatibility projections are diagnostic while graph entity resolution is
  provisional.
