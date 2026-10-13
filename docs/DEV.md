# Developer and Contributor Guide

This document is the starting point for people who maintain, review, test, or
extend LLDP-Runner. It assumes familiarity with enterprise networking and basic
Python concepts, but it does not assume prior knowledge of the codebase.

## Read these documents first

1. [`PRIMER.md`](PRIMER.md) explains SNMP collection, evidence, claims,
   clusters, and reversible decisions in operational terms.
2. [`ARCHITECTURE.md`](ARCHITECTURE.md) describes the complete runtime and data
   flow.
3. [`dev/ARCHITECTURE.md`](dev/ARCHITECTURE.md) provides a shorter contributor
   map of the code.
4. [`dev/FLOW-DIAGRAMS.md`](dev/FLOW-DIAGRAMS.md) maps collection, resolver,
   and graph-rematerialization flow to current source boundaries.
5. [`dev/MODULES.md`](dev/MODULES.md) identifies the purpose of each package and
   module family.
6. [`dev/SCHEMA.md`](dev/SCHEMA.md) lists current JSON contract versions and
   their main sections.
7. [`dev/STATE-AND-SCHEMAS.md`](dev/STATE-AND-SCHEMAS.md) explains durable
   state, immutable evidence, graph materialization, and migration practice.
8. [`dev/TESTING.md`](dev/TESTING.md) describes test layers and release gates.
9. [`dev/RELEASES.md`](dev/RELEASES.md) describes patch and source-bundle
   preparation.
10. [`dev/CONTRIBUTING.md`](dev/CONTRIBUTING.md) lists coding and review
    practices.

## Development model

LLDP-Runner is a coordinator/worker application:

```text
CLI and configuration
        |
        v
coordinator + SQLite state
        |
        +--> worker processes
        |      +--> ICMP
        |      +--> SNMP SYSTEM-MIB
        |      +--> IF-MIB / ENTITY-MIB
        |      +--> CDP / LLDP / LLDPv2
        |
        v
immutable observations and claims
        |
        v
deferred entity and relationship resolution
        |
        v
graph + compatibility projection + reports
```

The coordinator is the only process that mutates canonical state. Workers
collect facts and return structured results. This boundary reduces duplicate
scheduling decisions and makes pause/resume behavior auditable.

## Core development rules

- Preserve raw protocol evidence before reasoning.
- Do not use one normalized string as proof of global identity without checking
  its type, scope, provenance, and conflicts.
- Do not silently convert collection failure into an empty successful result.
- Treat table completeness as a first-class fact.
- Keep graph decisions deterministic and independent of row arrival order.
- Record a superseding decision instead of rewriting decision history.
- Use explicit names for SNMP namespaces such as `ifIndex` and
  `lldpLocalPort`; equal numbers in different namespaces are not automatically
  the same interface.
- Keep operator logs target-first for SNMP events.
- Add docstrings and comments that explain both what code does and why the
  network behavior requires it.
- Update tests, examples, generated configuration text, and operator docs in the
  same change as behavior.

## Common commands

From the source root with the project environment active:

```bash
python -m compileall -q src tests
pytest -q
bash -n scripts/lrun-bundle-diff
```

When installed development tools are available:

```bash
ruff check src tests
ruff format --check src tests
ty check
```

See [`dev/TESTING.md`](dev/TESTING.md) before interpreting a successful unit
test as release readiness. Network protocol work also requires
production-shaped fixtures and, where possible, two consecutive live discovery
runs.
