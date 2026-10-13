# Module Reference

This is a concise map, not generated API documentation. Read module docstrings
and tests before changing behavior.

## Entry points and operator commands

- `__main__.py`, `cli.py`: main command parser and dispatch.
- `inspection.py`, `inspection_output.py`: active single-device inspection.
- `discovery_query.py`, `discovery_view_output.py`: read-only discovery viewer.
- `discovery_diff.py`, `discovery_diff_output.py`: cross-run comparison.
- `watch.py`, `scoreboard.py`: running-state terminal display and snapshots.
- `cleanup.py`, `purge.py`: conservative run-state/scratch and finalized-output
  retention maintenance.

## Configuration and runtime setup

- `defaults.py`: canonical defaults.
- `config.py`: TOML/include/environment/CLI assembly and validation.
- `configgen.py`: generated configuration and explanatory comments.
- `runtime.py`: run paths, storage preflight, atomic `latest` publication, and
  guarded completed-scratch cleanup.
- `runid.py`: run-ID generation and validation.
- `run_manifest.py`: sanitized `run.json` provenance and timing.
- `logging_setup.py`, `terminal_style.py`: logs and terminal presentation.

## Collection

- `worker.py`: ICMP/SNMP workflow and result packaging.
- `icmp.py`: reachability probes.
- `snmp/base.py`: client protocol boundary and backend-neutral failures.
- `snmp/selection.py`: validated, once-bound backend identity and package
  version diagnostics.
- `snmp/preflight.py`: secret-free discovery of reachable authPriv protocol
  requirements and selected-backend startup capability checks.
- `snmp/gufo.py`: Gufo SNMP adapter and contained IPv6 compatibility boundary.
- `snmp/pysnmp.py`: PySNMP 7.1 asyncio adapter, native value/error
  normalization, cryptography provider probes, remote engine-ID observation,
  and deterministic dispatcher cleanup.
- `snmp/__init__.py`: no-fallback backend factory wiring.
- `snmp/resilience.py`: bounded adaptive timeout, work-size, and pacing logic.
- `snmp/metrics.py`, `snmp/trace.py`: measurements and trace context.
- `collectors/system.py`: SYSTEM-MIB.
- `collectors/interfaces.py`: IF-MIB mapping.
- `collectors/entity.py`: ENTITY-MIB physical inventory.
- `collectors/cdp.py`: Cisco Discovery Protocol tables.
- `collectors/lldp.py`: LLDP and LLDPv2 tables.
- `collectors/__init__.py`: collector coordination and guarded reconciliation.

## Identity and graph reasoning

- `identity.py`: normalization and strict vendor identity parsers.
- `claims.py`: immutable claims and stable fingerprints.
- `topology_shadow.py`: pre-activation observation-group analysis.
- `topology_graph.py`: current evidence-graph materializer.
- `topology_graph_diff.py`: N:M graph correspondence.
- `neighbor_table.py`: deterministic terminal neighbor rendering.
- `classify.py`, `policy.py`: device role and query eligibility.

## Durable data and outputs

- `state.py`: SQLite schema, claims, advertisements, decisions, and projection.
- `models.py`: shared dataclasses and collection-coverage structures.
- `outputs.py`: canonical discovery JSON, normalized host presentation, and
  fixed/custom CSV rendering.
- `csv_input.py`, `csv_fields.py`: shared CSV parsing and field definitions.
- `seeds.py`, `seed_credentials.py`: seed ingestion and credential overlays.

## Script launchers

Scripts under `scripts/` are operator conveniences. Most invoke the installed
Python entry point. `lrun-bundle-diff` is a standalone review-bundle helper;
`gufo-snmp-diag.py`, `gufo-ipv6-test.py`, and `pysnmp-snmp-diag.py` probe their
libraries directly without entering LLDP-Runner's collection path. Service and
bootstrap scripts manage deployment and systemd integration. See
[`CLI-REFERENCE.md`](CLI-REFERENCE.md).
