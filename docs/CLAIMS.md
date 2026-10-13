# Immutable Observations, Claims, and Resolution Decisions

## 1. Purpose

LLDP-Runner collects descriptions of the same network entity from sources that
do not use one common identity model. CDP, LLDP, LLDPv2, IF-MIB, ENTITY-MIB,
SYSTEM-MIB, DNS, seed input, and the SNMP transport can each provide useful but
partially scoped evidence. A normalized value is not automatically a globally
unique device identifier.

LLDP-Runner uses an evidence-first resolver model. SQLite retains each factual
observation, the typed claims derived from it, and the append-only decisions
that materialize the current graph. The older `hosts`, aliases, addresses, and
neighbors tables remain a scheduling and diagnostic compatibility projection.
Discovery JSON schema 8 publishes the claims-driven observation graph and
separately states whether its observations are complete, entity resolution is
provisional, physical topology is inferred, and directness is known.

## 2. Data flow

```text
raw protocol / seed / SNMP result
              |
              v
normalized immutable observation
              |
              v
typed claims with provenance, scope, and strength
              |
              v
candidate cluster analysis
              |
              v
append-only resolution decision
              |
              v
current graph projection
              |
              +--> compatibility host / edge views
```

Observations and claims answer, “What was reported?” A resolution decision
answers, “How did this version interpret the evidence?” Keeping those
questions separate is required for deterministic replay and later reassessment.

## 3. Idempotence and immutability

Each normalized observation receives a deterministic SHA-256 fingerprint.
Collection time is intentionally excluded from the fingerprint. Replaying the
same normalized observation during one run therefore finds the existing row
instead of appending duplicate logical evidence.

Claims receive fingerprints derived from their observation plus canonical claim
content. SQLite triggers reject UPDATE and DELETE against immutable evidence and
decision tables, including:

```text
observations
claims
resolution_decisions
decision_claims
protocol_advertisements
graph_component_decisions
```

A changed conclusion is not an update. It is a new resolution decision with a
`supersedes_decision_id` reference to the former decision. The complete history
remains available for audit and future resolver replay.

## 4. Claim dimensions

A claim has a type/subtype, raw and normalized values, provenance, scope,
strength, identity eligibility, and optional context.

Strength categories are:

```text
strong       direct or strict hardware/agent evidence
moderate     useful direct identity evidence such as a device name
weak         potentially reused evidence such as an address
diagnostic   retained for explanation, not canonical identity
```

Scope categories are:

```text
global              potentially identifies one entity across the network
physical_container  applies to a chassis or physical inventory container
snmp_agent           applies to one logical SNMP engine/context
observer             meaningful in one observing-device context
edge                 meaningful only for one physical adjacency
diagnostic           enrichment or raw context only
```

The scope is as important as strength. An exact value can be strong within one
edge and still be unsafe as a global alias.

## 5. Strong strict identities

LLDP-Runner enforces narrowly defined vendor identifiers when their format
unambiguously carries a hardware MAC:

```text
SEP001122334455                  -> 00:11:22:33:44:55
SEP001122334455.example.com      -> 00:11:22:33:44:55
AP0012.3456.A001                 -> 00:12:34:56:a0:01
AP00123456A001.example.com       -> 00:12:34:56:a0:01
```

The parsers require exact formats. They do not infer MAC identity from arbitrary
hexadecimal hostname suffixes. A strict Cisco AP CDP name can therefore
corroborate the exact MAC-address chassis value supplied by LLDP, just as strict
SEP identity reconciles phone short and FQDN forms.

A trailing parenthesized alphanumeric token is handled separately. For example,
`hq-vdc2-7nx1.example.com(SERIAL000001)` produces an immutable raw-name claim,
a logical base-name claim, and a moderate physical-container serial-hint claim.
The base name can compare with an undecorated CDP, LLDP, or LLDPv2 name. The
serial hint cannot independently merge hosts; direct serial evidence must
corroborate it before it can support a physical-chassis conclusion.

Beginning with 0.32.9, one explicitly typed LLDP/LLDPv2 MAC-address Port ID can
produce a strong `anonymous_lldp_port_mac` hardware claim when the candidate has
no usable direct name, management address, or trusted chassis alias. This is a
bounded endpoint rule, not a declaration that every Port ID globally identifies
a device. Named and addressed multi-interface systems retain their device-level
identity and keep each Port ID as edge evidence.

## 6. Weak and scoped evidence

The following must not independently force a global merge:

```text
DNS-only names or addresses
contested/reused management addresses
LLDP network_address chassis values
LLDP interface_name/interface_alias/port_component values
LLDP locally assigned chassis subtype 7 values
unresolved local-port numbers
edge-scoped remote Port IDs outside their observer/port context
```

An LLDP `network_address` chassis value is retained as a weak edge claim and in
raw neighbor details. It does not enter global IPv4/IPv6 host lookup merely
because its syntax is a valid address. A distinct LLDP/CDP management-address
field remains a separate direct address claim.

A locally assigned chassis label remains a weak, non-identity edge claim even
when it resembles a hostname or an opaque hardware token. If the same anonymous
observation also contains one unambiguous typed MAC-address Port ID, the claim
ledger retains both facts: the chassis value stays scoped, while the derived MAC
claim can identify that endpoint in the compatibility projection.

## 7. Graph materialization and authority dimensions

LLDP-Runner retains raw CDP, LLDP, and LLDPv2 rows before compatibility merging.
The materializer reads those immutable advertisements and produces:

```text
physical chassis
logical systems and SNMP-agent projections
logical membership
interfaces
protocol advertisements
observed relationships
local-interface relationship groups
collection coverage
```

The current graph is replaced in one SQLite transaction only after new
component decisions have been appended. A stable projection-level decision
lineage ensures that a later split or merge supersedes the former graph even
when the affected component keys change. An unchanged replay appends nothing.

Discovery JSON includes the current graph, its projection fingerprint, a
summary, explicit advertisement exclusions, and an authority object. A complete
observation projection means every durable advertisement appears in the graph
or has a recorded exclusion reason. It does not mean that every entity cluster,
physical cable, or direct/indirect relationship has been proven. Flat host and
neighbor records remain available for operator familiarity, CSV output,
scheduling, and side-by-side diagnostics.

The graph can also publish `compatibility_projection_diagnostics`. A warning is
emitted when a legacy flat host spans several distinct anonymous endpoint MAC
entities because repeated locally assigned chassis evidence was previously
treated as global identity. The diagnostic includes the affected compatibility
host, graph entities, endpoint MACs, and observer references. It never rewrites
raw evidence or weakens the authoritative observation graph.

The authority dimensions are intentionally independent:

```text
observation_completeness
observation_projection
entity_resolution
physical_topology
directness
compatibility_projection
```

This prevents one Boolean from implying more certainty than the collected
evidence supports.

## 8. Conservative reasoning boundaries

The resolver intentionally stops short of several unsafe conclusions:

- A protocol advertisement is not automatically a direct physical cable.
- Several advertisements on one interface are kept as one observation group and
  flagged for operator review.
- Tunnel and overlay interfaces remain distinct from physical-looking ports.
- A physical serial can place several logical systems under one chassis without
  merging those logical systems together.
- A shared address, DNS result, or LLDP network-address chassis value cannot
  independently establish global equality.
- A locally assigned chassis value cannot independently establish global
  equality, even when many observations repeat the same text.
- A typed Port-ID MAC becomes compatibility identity only for an otherwise
  anonymous endpoint; it does not split named devices by interface.
- A low-entropy or virtual MAC-like value can correlate evidence without proving
  a physical port move.
- Missing data proves removal only when the responsible collection coverage is
  complete.

Cross-protocol reconciliation is a materialized decision, not destruction of
the original rows. The graph can therefore be rebuilt when later evidence
changes the conclusion.

## 9. Remaining resolver work

The compatibility scheduler still creates provisional host rows while a run is
in progress. The graph unifies already-resolved interface names across IF-MIB,
CDP, and LLDP evidence while preserving every raw namespace. Future work maps
additional unresolved protocol indexes through IF-STACK and ENTITY-MIB evidence
and attaches SNMP results to explicit agent/context objects before projecting
them into logical systems.

The detailed work queue and production fixtures are in
[`ROADMAP.md`](ROADMAP.md). Regression testing continues to require order
randomization: equal input sets must produce equal graph output regardless of
ingestion order.
