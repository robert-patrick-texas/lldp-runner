# LLDP-Runner Roadmap

This file tracks planned work, unresolved design questions, production-derived
fixtures, and ideas that may become future features. It is a working outline,
not a release promise. Items can move, split, or be removed when live network
evidence shows that another design is safer.

Released behavior is documented in the source, operator documentation, and
[`CHANGELOG.md`](../CHANGELOG.md). An unchecked roadmap item is not implemented
unless a later release entry says otherwise.

Each unfinished item includes three planning notes: **Remaining work** describes
the implementation boundary, **Operational benefit** explains why an operator
might prioritize it, and **Estimated effort** is a relative engineering estimate
that includes implementation, tests, documentation, and production validation.

## Guiding principles

- Preserve what each device reported before applying identity or topology
  reasoning.
- Treat CDP, LLDP, LLDPv2, IF-MIB, ENTITY-MIB, DNS, and seed input as typed
  evidence with provenance and scope.
- Prefer an explicit ambiguous or conflicted result over a confident false
  merge.
- Make repeated processing idempotent: replaying the same evidence produces the
  same graph.
- Keep reasoning reversible: stronger or conflicting evidence can supersede an
  earlier decision without deleting history.
- Separate collection coverage from topology state. A failed query means “not
  observed,” not necessarily “removed.”
- Keep physical chassis, logical systems, SNMP agents, interfaces, protocol
  advertisements, and relationships as separate concepts.
- Preserve deterministic ordering for output, tests, and cross-run comparison.
- Explain advanced resolver behavior in terms useful to Network Operations
  staff while retaining enough precision for engineering and architecture
  review.

## Current graph-integrity work

### Immutable collection boundary

- [x] Retain CDP, LLDP, and LLDPv2 advertisements before compatibility
  reconciliation.
- [x] Record typed immutable claims with provenance, scope, and strength.
- [x] Make observation replay idempotent through deterministic fingerprints.
- [x] Reference the immutable SNMP result that supplied each protocol
  advertisement so retirement of a provisional compatibility host cannot erase
  source context.
- [x] Account for every durable protocol advertisement in the graph or emit an
  explicit machine-readable exclusion reason.
- [x] Record per-table collection coverage such as complete, complete-empty,
  timeout, access-restricted, unsupported, structurally invalid, and not
  attempted.
- [x] Reject incomplete CDP snapshots before endpoint/relationship
  materialization and restart the complete table from its root.
- [ ] Persist every native collector row and complete MIB index tuple before
  protocol-specific row assembly.
  - **Remaining work:** Extend the collection-state schema and each
    CDP/LLDP/LLDPv2 collector so the unassembled native row, including every
    index component, is committed before normalization or filtering.
  - **Operational benefit:** Investigators could reconstruct exactly what the
    agent returned and distinguish device data defects from parser or
    row-assembly defects.
  - **Estimated effort:** Large - requires schema work, collector changes,
    replay tooling, storage-size review, and production fixtures.
- [ ] Record the exact credential route, SNMP context, table root OID, attempt,
  request count, and adaptive transport profile for every table collection.
  - **Remaining work:** Define one table-attempt provenance record and populate
    it on success, empty results, retries, and terminal failures across every
    collector path.
  - **Operational benefit:** Operators could explain why one table succeeded or
    failed on a particular route without correlating several log streams
    manually.
  - **Estimated effort:** Medium to large - cross-cuts session routing,
    collectors, SQLite persistence, schemas, and diagnostics.
- [ ] Add vendor-table coverage families as additional collectors are
  introduced.
  - **Remaining work:** Specify coverage states and provenance fields for each
    future vendor-specific MIB family, then connect them to uncertainty and diff
    reporting.
  - **Operational benefit:** New collectors would not silently weaken topology
    conclusions when a proprietary table is absent, partial, or inaccessible.
  - **Estimated effort:** Ongoing medium effort per collector family after the
    shared coverage contract is established.

### Graph authority and materialization

- [x] Publish an observation-complete graph projection when every durable
  advertisement is represented or explicitly excluded.
- [x] Report graph authority as separate dimensions:
  - observation completeness;
  - observation projection status;
  - entity-resolution maturity;
  - physical-topology inference status;
  - directness status; and
  - compatibility-projection role.
- [x] Keep physical chassis and logical systems as separate entity types.
- [x] Represent several logical systems as members of one physical chassis when
  directly collected serial evidence corroborates the relationship.
- [x] Represent local-interface observation groups and retain all protocol
  members.
- [x] Flag a local interface that reports several systems for operator review.
- [x] Leave relationship directness unresolved rather than guessing.
- [x] Store graph decisions append-only and permit a later decision to
  supersede an earlier decision.
- [x] Store the current graph projection in compact form rather than duplicating
  one large plain-text graph document inside SQLite.
- [ ] Attach every SNMP response to an explicit SNMP-agent/context entity before
  projecting it into a logical or physical system.
  - **Remaining work:** Model SNMP engine, address, credential route, and
    context as a first-class graph entity and route all collected evidence
    through that entity before system resolution.
  - **Operational benefit:** This would separate the device that answered a
    query from the logical or physical systems inferred from its data,
    especially for VDCs and shared management planes.
  - **Estimated effort:** Large - foundational graph/schema work with broad
    resolver, projection, diff, and migration impact.
- [ ] Rematerialize only the affected connected component after a decision is
  superseded.
  - **Remaining work:** Track decision dependencies and component membership so
    replacing one claim invalidates and rebuilds only graph objects reachable
    from that decision.
  - **Operational benefit:** Large runs would resolve faster and operator
    assertions could be applied without rebuilding the complete graph.
  - **Estimated effort:** Large - requires dependency indexing, deterministic
    incremental algorithms, rollback tests, and performance measurement.
- [ ] Generate the compatibility host and neighbor projection from the graph
  instead of maintaining two independent interpretations.
  - **Remaining work:** Replace the legacy compatibility resolver as a parallel
    authority with a deterministic graph-to-host projection that preserves
    current output contracts where intended.
  - **Operational benefit:** One interpretation would drive discovery.json, CSV,
    and graph views, reducing cross-view disagreement and duplicate bug fixes.
  - **Estimated effort:** Very large - high-risk architectural convergence
    requiring extensive production replay and deliberate compatibility
    decisions.
- [ ] Add operator-supplied topology assertions and exceptions as typed,
  auditable claims rather than destructive overrides.
  - **Remaining work:** Design configuration/input syntax, validity periods,
    provenance, conflict handling, and explain output for assertions such as
    known chassis membership or non-direct links.
  - **Operational benefit:** Network Operations could encode verified site
    knowledge while preserving device evidence and seeing where an assertion
    changes resolution.
  - **Estimated effort:** Large - needs a claim contract, validation,
    persistence, graph integration, CLI tooling, and safety documentation.

### Stable identifiers and deterministic replay

- [x] Distinguish content fingerprints, advertisement occurrences, semantic
  entity/relationship identities, and run-local SQLite IDs.
- [x] Exclude volatile SNMP table indexes and run-local host IDs from semantic
  graph identity.
- [x] Keep equivalent graph identities stable when query route, credential
  route, table order, or provisional compatibility-host ID changes.
- [x] Sort multi-neighbor member collections independently of device-returned
  row order.
- [ ] Randomize complete evidence-ingestion order in every graph release gate
  and require byte-equivalent graph output.
  - **Remaining work:** Add repeatable shuffled-replay test passes over
    representative fixtures and normalize all ordering that still depends on
    insertion sequence.
  - **Operational benefit:** This would catch nondeterministic graph IDs or
    relationships before release and make repeated runs easier to compare.
  - **Estimated effort:** Medium - mostly test/replay infrastructure, followed
    by potentially substantial fixes when instability is found.
- [ ] Add a persistent diagnostic that identifies which claims caused an entity
  or relationship key to change between equivalent runs.
  - **Remaining work:** Store key-derivation inputs and expose an explanation
    comparing old and new claim sets whenever a semantic key changes
    unexpectedly.
  - **Operational benefit:** Operators and developers could trace identity churn
    to one concrete piece of evidence instead of reverse-engineering hashes.
  - **Estimated effort:** Medium to large - requires stable explanation records,
    diff presentation, and retention-size controls.

### Graph-aware diff

- [x] Support one-to-one, one-to-many, many-to-one, and many-to-many entity
  correspondence components.
- [x] Report cluster split, cluster merge, cluster reassociation, duplicate
  projection introduction, and duplicate absorption.
- [x] Compare interface member collections without depending on SNMP row order.
- [x] Avoid claiming physical topology changes while directness is unresolved.
- [x] Summarize collection-coverage incidents at the top of diff JSON and retain
  per-host coverage details.
- [x] Propagate observer protocol/table failures through one-sided entity,
  relationship, and recursive-descendant presence decisions.
- [x] Qualify graph correspondence as confirmed, coverage-uncertain,
  presentation-only, or ambiguous without asserting physical topology.
- [x] Treat a uniquely corroborated resolved-versus-unresolved local-port name
  difference as presentation coverage rather than topology change.
- [ ] Add an operator-focused component view for large many-to-many results.
  - **Remaining work:** Create a compact terminal/JSON presentation that groups
    the A and B entities, correspondence reasons, conflicts, and affected links
    for one component.
  - **Operational benefit:** Complex split/merge results would become reviewable
    without reading raw graph-diff structures.
  - **Estimated effort:** Medium - primarily renderer and CLI work after the
    current correspondence data is normalized for presentation.
- [ ] Add component-level confidence dimensions for identity, cluster integrity,
  interface resolution, relationship evidence, and collection coverage.
  - **Remaining work:** Define categorical values and derivation rules for each
    dimension, persist them in diff output, and explain supporting and limiting
    evidence.
  - **Operational benefit:** Operators could distinguish a strong identity match
    with weak collection coverage from a genuinely ambiguous match.
  - **Estimated effort:** Large - requires an engineering confidence model,
    fixtures, schema changes, and calibrated operator wording.
- [ ] Add calibrated numeric probabilities only after a labeled validation set
  is available; categorical engineering confidence remains the default.
  - **Remaining work:** Build and label a representative truth set, choose
    measurable outcomes, validate calibration, and define how probabilities
    coexist with categorical safety states.
  - **Operational benefit:** A numeric score would be meaningful and testable
    rather than an arbitrary confidence-looking number.
  - **Estimated effort:** Very large and data-dependent - blocked on sanitized
    labeled fixtures and sustained validation work.

## Sanitized topology regression fixtures

These sanitized examples are regression-fixture input and design constraints.
They are not hard-coded naming or addressing rules.

### Nexus 7700 VDC management identities

- `hq-vdc2-7nx1` uses `203.0.113.21` on SVI interface VLAN 61.
- `hq-vdc2-7nx1` uses `203.0.113.24` on `mgmt0`.
- `hq-vdc3-7nx1` uses `203.0.113.22` on `mgmt0`.
- `hq-vdc1-7nx1` uses `203.0.113.23` on `mgmt0` for that VDC instance.
- The VDCs are separate logical systems on one physical Nexus 7700 chassis.
- One VDC can legitimately have more than one management route or interface.
  Same logical name plus the same verified physical serial can associate those
  routes with one VDC without merging sibling VDCs.
- A Catalyst port connected to shared Nexus `mgmt0` can report several VDC
  advertisements on one physical management attachment.
- The operator-facing default should show one physical chassis with indented
  logical VDC members.
- Site naming conventions such as `hq-vdc<n>-7nx1` are useful display hints but
  are never universal identity rules.

### `hq-vdc1-7nx1` duplicate compatibility projection

The sanitized regression fixture contains two compatibility records with:

- query target `203.0.113.23`;
- SNMP sysName `hq-vdc1-7nx1`;
- physical serial `SERIAL000001`;
- the exact same sysUpTime sample; and
- the same 28 learned-neighbor rows.

The address is confirmed as `mgmt0` for the `hq-vdc1-7nx1` VDC. The graph
represents one logical VDC and retains both source projections as evidence.
Version 0.32.3 also prevents an inactive equivalent row from being claimed,
defers a READY duplicate while its equivalent projection is active, reconciles
remaining duplicates before final output, and folds duplicate complete rows in
the compatibility diff. The graph remains the immutable evidence boundary; the
compatibility scheduler is not yet graph-derived.

Useful future diagnostics still include:

- SNMP engine ID and context name for each attempted route;
- seed, DNS, alias, and observed-neighbor paths that selected the same target;
- a collection-session ID showing whether both projections consumed one SNMP
  response; and
- a resolver explanation that identifies why the duplicate was absorbed.

### Transparent discovery-protocol forwarding

A sanitized fixture records a former pass-through-CDP condition at
`hq-edge-router-01`. The intervening switch was configured to block CDP, so
downstream Nexus advertisements no longer appear on the router port.

The general case remains valid: an unmanaged switch, transparent bridge, or
misconfigured device can forward CDP or LLDP frames. LLDP-Runner therefore
retains multi-neighbor observations and does not infer direct versus downstream
solely from protocol type. A future directness classifier requires independent
corroboration and an operator-visible explanation.

### Virtual endpoint movement

`00:00:00:00:01:03` appears on more than one switch port and is likely
associated with a virtual appliance on VMware ESXi. Such a low-entropy token
may identify one logical workload while that workload shifts between
hypervisor uplinks. It is insufficient by itself to prove a physical endpoint
move.

Future modeling should distinguish:

- logical workload movement;
- hypervisor uplink selection;
- a physical device move; and
- repeated placeholder or implementation-local identifiers.

### End-user workstation appearance

`workstation-01` is a generic end-user endpoint that remained connected to
`branch-floor2-3560-1` across a reboot. The fixture should be reported as an
endpoint appearance or renewed observation, not as resolver churn.

### Intermittent ENTITY-MIB collection

`hq-dc-leaf-02` represents a Nexus-class switch with intermittent ENTITY-MIB
results. Missing rows may arise from device software, network conditions, rate
limiting, or other external factors. A missing member row is not a
confirmed hardware removal unless ENTITY-MIB coverage is complete.

## Operator presentation

- [x] Provide a sectioned relationship view and a combined labeled view.
- [x] Default to physical/chassis-oriented sections with logical, overlay, or
  multi-neighbor members indented beneath.
- [x] Leave unresolved directness visible instead of presenting it as fact.
- [ ] Refine labels after production use without implying unresolved directness.
  - **Remaining work:** Collect operator feedback on current relationship-group
    terms, revise labels and help text, and preserve explicit
    unresolved/ambiguous states.
  - **Operational benefit:** Routine reviews would use vocabulary that matches
    Network Operations practice without overstating physical adjacency.
  - **Estimated effort:** Small to medium - presentation and documentation
    changes, but requires production feedback and regression review.
- [ ] Add a physical-chassis detail view with logical VDC members.
  - **Remaining work:** Add a graph inspection renderer that selects one
    physical chassis and nests its logical systems, management agents,
    interfaces, evidence, and coverage.
  - **Operational benefit:** Shared-chassis platforms such as Nexus VDC
    deployments would be understandable as one container with distinct
    operational members.
  - **Estimated effort:** Medium - reuses existing graph entities but needs
    selection semantics, CLI output, and production-shaped tests.
- [ ] Add an interface-discrepancy report listing every port with more than one
  observed neighbor.
  - **Remaining work:** Build a report over local-interface observation groups,
    classify duplicate/protocol/forwarding cases, and link each row to
    supporting evidence.
  - **Operational benefit:** Operators could focus immediately on ports that may
    represent shared media, transparent forwarding, duplicate advertisements, or
    data defects.
  - **Estimated effort:** Medium - query/report implementation plus careful
    classification and fixture coverage.
- [ ] Add filters for entity type, cluster integrity, coverage state, and
  relationship-group classification.
  - **Remaining work:** Define composable CLI filters for graph views, validate
    values, and ensure terminal, JSON, and CSV presentations apply the same
    selection rules.
  - **Operational benefit:** Large topology reviews could be narrowed to
    actionable categories such as conflicted endpoints or coverage-uncertain
    links.
  - **Estimated effort:** Medium - mostly shared filtering and presentation work
    with schema-aware tests.

### Future graph inspection command

A graph-focused operator command is planned after the graph projection and
stable IDs complete another production-validation cycle. The preferred command
family is:

```text
lldp-runner graph show
lldp-runner graph explain
lldp-runner graph audit
lldp-runner graph export
lldp-runner graph diff
```

An optional `scripts/lrun-graph` launcher may invoke the same subcommands. It
must not implement a second diff engine. `graph diff` should call the same graph
correspondence library used by `lldp-runner diff`.

Planned behavior:

- `show`: render entities, interfaces, memberships, and relationship groups;
- `explain`: list supporting, conflicting, ignored, and superseded claims for a
  selected result;
- `audit`: report unaccounted evidence, conflicts, contested claims, duplicate
  projections, and unstable identifiers;
- `export`: emit normalized graph JSON or documented CSV views; and
- `diff`: provide a graph-focused presentation of the existing many-to-many
  comparison.

## Watch display and live performance visibility

### Watch layout

- [x] Leave a blank top row and blank left/right edge cells, then use one
  justified four-section title line when width permits:

  ```text
  <app> <version>    Run ID = <runid>    STATE = <state>    updated <age> ago
  ```

- [x] Use broader geometry-based metric columns and add blank rows between
  metric rows when vertical space permits.
- [x] Center the aggregate worker summary with a blank row above and below when
  height permits, while preserving worker-cell content and density.
- [x] Center the worker-status table with approximately equal whitespace at the
  left and right content borders.
- [x] Provide a clear narrow-terminal fallback that first crops cosmetic title
  spacing and the version, while preserving state, run ID, age, and worker
  information without wrapping into unreadable columns.

### Performance counters

- [ ] Track discovery, graph resolution, graph materialization, output
  serialization, finalization, and total wall-clock durations separately.
  - **Remaining work:** Complete phase boundaries for all listed stages, define
    whether phases overlap, and persist consistent monotonic measurements on
    every terminal path.
  - **Operational benefit:** Operators could identify whether a slow run is
    caused by network collection, graph work, or output/storage finalization.
  - **Estimated effort:** Medium - some timing exists already, but boundaries,
    naming, failure paths, tests, and documentation remain incomplete.
- [ ] Track per-target and per-collector timing, retries, degraded-session time,
  partial-table restarts, PDU counts, object counts, and queue wait time.
  - **Remaining work:** Instrument worker/session/collector boundaries and
    aggregate detailed measurements without making high-volume runs excessively
    large or slow.
  - **Operational benefit:** Troubleshooting could distinguish slow devices,
    congested queues, retry-heavy tables, and inefficient transport profiles.
  - **Estimated effort:** Large - broad instrumentation, storage design,
    overhead testing, and operator aggregation are required.
- [ ] Display selected counters in `lldp-runner watch`.
  - **Remaining work:** Choose a bounded set of stable live counters, add them
    to the scoreboard contract, and design responsive full/compact renderings.
  - **Operational benefit:** Operators could see the current bottleneck and
    retry/coverage trend without opening logs during a run.
  - **Estimated effort:** Medium - depends on performance-counter definitions
    and requires scoreboard schema plus Watch layout work.
- [ ] Write a concise final summary to console and `activity.log`.
  - **Remaining work:** Define a stable completion summary covering phase
    durations, retry/coverage highlights, and the slowest actionable causes
    without duplicating full reports.
  - **Operational benefit:** The end of every run would immediately show where
    time was spent and whether performance warrants investigation.
  - **Estimated effort:** Small to medium after aggregate counters exist; mainly
    summary selection, rendering, and tests.
- [ ] Persist enough aggregate metrics in `run.json` to compare completed runs
  without loading the full discovery document.
  - **Remaining work:** Select versioned run-level metrics, populate them for
    all completed states, and update diff/reporting consumers and schema
    documentation.
  - **Operational benefit:** Historical performance and health trends could be
    computed cheaply from small manifests.
  - **Estimated effort:** Medium - run-manifest schema change, aggregation,
    compatibility policy, and regression tests.
- [ ] Produce a ranked “slowest targets and causes” section for operator
      review.
  - **Remaining work:** Aggregate per-target measurements, define deterministic
    ranking/tie rules, identify dominant causes, and cap output to a useful top
    set.
  - **Operational benefit:** Network Operations could prioritize devices or
    paths that have the greatest effect on run duration.
  - **Estimated effort:** Medium after detailed timing exists; ranking accuracy
    and cause attribution need production validation.

### Run timeboxes and alerts

- [ ] Add a warning threshold that emits an operator alert while discovery
  continues.
  - **Remaining work:** Add validated configuration, monotonic threshold
    evaluation, one-shot/repeat policy, and a non-disruptive alert event while
    workers continue.
  - **Operational benefit:** Operators could react to unexpectedly long runs
    before the maintenance window is consumed.
  - **Estimated effort:** Medium - coordinator policy, logging/manifest events,
    CLI/config docs, and deterministic time-based tests.
- [ ] Add a maximum threshold at which the coordinator pauses admission of new
  work while active workers drain safely.
  - **Remaining work:** Define terminal/resumable status semantics and stop
    dispatching new targets at the limit while allowing active claims to settle
    and checkpoint.
  - **Operational benefit:** A run could respect a hard operational window
    without abruptly killing SNMP work or corrupting resume state.
  - **Estimated effort:** Large - touches scheduling, pause/resume, status
    reporting, finalization, and failure/restart testing.
- [ ] Add an automatic threshold that alerts when elapsed time exceeds a
  configurable percentage above a robust baseline from prior `run.json` files.
  - **Remaining work:** Load comparable historical manifests, select matching
    run classes, compute a robust baseline, and apply a configurable deviation
    policy.
  - **Operational benefit:** Alerts would adapt to the site's normal scale
    instead of requiring one fixed duration for every discovery mode.
  - **Estimated effort:** Large - depends on aggregate run metrics and needs
    history selection, statistical safeguards, and operator explanation.
- [ ] Require a minimum history count before using historical thresholds.
  - **Remaining work:** Add a configurable sample floor and explicit
    insufficient-history status to the baseline evaluator.
  - **Operational benefit:** New installations or changed run profiles would not
    trigger misleading alerts from one or two atypical runs.
  - **Estimated effort:** Small once historical thresholding exists;
    configuration and edge-case tests are straightforward.
- [ ] Prefer a median or percentile baseline over a simple average so failed or
  exceptional runs do not distort the comparison.
  - **Remaining work:** Choose and document the statistic, exclude
    non-comparable terminal states, and test behavior with outliers and sparse
    history.
  - **Operational benefit:** The automatic threshold would represent normal
    operations more reliably when past runs include incidents.
  - **Estimated effort:** Small to medium within the historical-alert feature;
    requires careful comparability rules more than code volume.
- [ ] Support optional alert transports for journald, syslog, and email.
  - **Remaining work:** Design a transport-neutral alert event, implement opt-in
    adapters, validate delivery configuration, and avoid exposing secrets in
    logs or manifests.
  - **Operational benefit:** Sites could route run warnings into existing
    operational notification systems rather than watching a terminal.
  - **Estimated effort:** Medium to large - journald/syslog are moderate;
    reliable email configuration, security, and testing add effort.
- [ ] Record every threshold decision in the run log and manifest.
  - **Remaining work:** Persist threshold type, configured value, measured
    value, baseline inputs, action, and timestamp for both triggered and
    suppressed decisions.
  - **Operational benefit:** Post-run review could explain exactly why an alert
    or automatic pause did or did not occur.
  - **Estimated effort:** Small to medium after threshold features exist;
    requires a versioned manifest representation and redaction review.

## Collection and transport

- [x] Increase timeout by 50 percent after a retry-eligible timeout.
- [x] Reduce GETBULK `max_repetitions` or GET-MANY batch size by 50 percent.
- [x] Add inter-PDU pacing after a target demonstrates difficulty.
- [x] Keep the degraded profile scoped to one address and credential route.
- [x] Give each logical operation/table a bounded retry allowance while
  enforcing a total target-route cap.
- [x] Restart an interrupted table from its root and discard partial rows.
- [x] Distinguish authentication, access restriction, timeout, unsupported OID,
  structural failure, and transport failure.
- [x] Record collector, operation, table/root OID, credential route, phase,
  counters, transport values, discarded rows, and outcome for every retry or
  exhaustion event.
- [ ] Add optional long-term per-device transport-profile hints without allowing
  stale performance data to override current configuration.
  - **Remaining work:** Define hint persistence, freshness/decay, address and
    credential scoping, operator reset controls, and strict configuration
    precedence.
  - **Operational benefit:** Known slow or PDU-sensitive devices could start
    closer to a reliable profile and reduce avoidable first-attempt failures.
  - **Estimated effort:** Large - needs durable history, safe invalidation,
    routing identity, policy controls, and extensive production testing.
- [ ] Evaluate adaptive reduction triggered by `tooBig`, repeated truncation,
  and measured response size, not only timeout.
  - **Remaining work:** Collect reproducible fixtures for these signals, define
    bounded profile changes, and verify that a complete table restart remains
    deterministic.
  - **Operational benefit:** The collector could recover faster from agent/PDU
    limits that do not present as timeouts.
  - **Estimated effort:** Medium - targeted transport logic and tests, with
    device-specific validation needed before enabling by default.
- [ ] Evaluate bounded jitter for large concurrent fleets to avoid synchronized
  retries.
  - **Remaining work:** Model retry synchronization, choose a deterministic or
    bounded-random delay policy, and confirm it does not harm reproducibility or
    timeboxes.
  - **Operational benefit:** Large fleets would be less likely to create retry
    bursts against shared network paths or management infrastructure.
  - **Estimated effort:** Small to medium implementation, but meaningful load
    testing is required to justify and tune it.

## Identity and claim analysis

- [x] Enforce strict Cisco SEP phone/video MAC identities.
- [x] Enforce strict Cisco AP name-to-MAC identities.
- [x] Parse trailing `name(serial)` advertisements non-destructively.
- [x] Keep network-address chassis values weak and scoped.
- [x] Keep DNS results as enrichment rather than direct identity equality.
- [ ] Add frequency-aware evidence weight so common defaults contribute less
  than rare values.
  - **Remaining work:** Measure value frequency in a bounded scope, define safe
    weighting categories, and prevent frequency from overriding hard conflicts
    or typed strong evidence.
  - **Operational benefit:** Repeated vendor defaults and low-entropy
    placeholders would be less likely to cause accidental identity merges.
  - **Estimated effort:** Large - requires statistics, resolver-policy design,
    explainability, and labeled production validation.
- [ ] Add explicit contested-claim objects and operator reports.
  - **Remaining work:** Create a first-class record for mutually incompatible
    claims, preserve all provenance, connect it to affected entities, and render
    actionable reports.
  - **Operational benefit:** Conflicts would be visible and auditable instead of
    inferred indirectly from cluster outcomes or logs.
  - **Estimated effort:** Medium to large - schema, resolver, graph projection,
    output, and diff changes.
- [ ] Promote directly collected SNMP engine IDs, ENTITY-MIB serials, and
  context identifiers into deferred re-resolution.
  - **Remaining work:** Trigger a bounded second resolution pass when late
    strong identifiers arrive, while recording which prior decisions are
    reconsidered.
  - **Operational benefit:** Entities initially formed from weak advertisements
    could be corrected when authoritative device evidence becomes available
    later in the run.
  - **Estimated effort:** Large - dependency-aware resolver work with ordering,
    split/merge, and replay-idempotence risks.
- [ ] Split a materialized cluster when later strong evidence contradicts an
  earlier weak union.
  - **Remaining work:** Replace irreversible union behavior with
    provenance-backed components that can retract a weak edge and
    deterministically rematerialize resulting clusters.
  - **Operational benefit:** The system could recover from early ambiguous
    evidence instead of carrying a false merge through final output.
  - **Estimated effort:** Very large - core resolver redesign requiring
    append-only decisions, incremental rematerialization, and extensive truth
    fixtures.
- [ ] Represent physical container, line card, stack member, logical context,
  virtual machine, and endpoint roles where MIB evidence supports them.
  - **Remaining work:** Define entity/relationship types and vendor-neutral
    evidence rules, then map ENTITY-MIB and protocol observations without
    fabricating unsupported hierarchy.
  - **Operational benefit:** Inventory and topology views could distinguish
    hardware containment, logical tenancy, and endpoint attachment accurately.
  - **Estimated effort:** Very large and incremental - each role needs schema,
    collector mappings, resolver rules, output, and vendor fixtures.

## Quality measurement

- [ ] Maintain a production-derived, sanitized golden fixture set.
  - **Remaining work:** Establish a repeatable sanitization/review process,
    truth annotations, versioning, and release-gate selection for representative
    network cases.
  - **Operational benefit:** Resolver and diff changes could be measured against
    real complexity without exposing operational identifiers or relying only on
    synthetic examples.
  - **Estimated effort:** Large initial effort plus ongoing maintenance;
    requires operator review and secure data-handling procedures.
- [ ] Measure pairwise precision and recall for entity clustering.
  - **Remaining work:** Label same/different entity pairs in golden fixtures and
    add an automated evaluator with per-scenario breakdowns.
  - **Operational benefit:** Release reviews would quantify false merges and
    false splits rather than relying solely on aggregate output counts.
  - **Estimated effort:** Medium after a labeled fixture set exists; evaluator
    code is modest but labels are labor-intensive.
- [ ] Measure B-cubed precision, recall, and F1 for cluster quality.
  - **Remaining work:** Add per-item cluster scoring against labeled truth and
    report macro/weighted results alongside pairwise metrics.
  - **Operational benefit:** Large and imbalanced clusters would be assessed
    more fairly, exposing errors hidden by pair counts alone.
  - **Estimated effort:** Small to medium after labels and identity mappings
    exist.
- [ ] Measure relationship and move-event precision/recall separately.
  - **Remaining work:** Label true links and true cross-run moves, then score
    relationship existence, endpoints, ports, and event classification
    independently.
  - **Operational benefit:** Topology accuracy and change-detection accuracy
    would be visible separately from entity clustering quality.
  - **Estimated effort:** Large - requires multi-run truth fixtures, event
    matching rules, and careful uncertainty treatment.
- [ ] Report order-invariance, replay-idempotence, contested-claim, unresolved-
  interface, and hard-conflict counts per run.
  - **Remaining work:** Define each metric precisely, calculate it during
    replay/materialization, and publish both totals and links to affected
    objects.
  - **Operational benefit:** Every run would expose graph-health indicators that
    make silent instability or unresolved evidence easy to spot.
  - **Estimated effort:** Medium - mostly graph audit aggregation and output
    once contested claims and shuffled replay are available.
- [ ] Add a run quality report beside `discovery.json`.
  - **Remaining work:** Design a compact versioned artifact summarizing
    coverage, graph integrity, uncertainty, conflicts, and validation metrics
    with drill-down references.
  - **Operational benefit:** Operators could judge whether a run is trustworthy
    before using it for inventory or change decisions.
  - **Estimated effort:** Medium to large - depends on agreed quality metrics
    and requires schema, output, docs, and consumer tests.
- [ ] Calibrate any future numeric confidence score against labeled fixtures;
  do not present an uncalibrated heuristic as a probability.
  - **Remaining work:** Select calibration methods and acceptance criteria,
    evaluate by scenario/vendor class, and document limitations and
    recalibration triggers.
  - **Operational benefit:** Displayed probabilities would have an empirical
    interpretation and would not create false operational certainty.
  - **Estimated effort:** Very large and ongoing - blocked on sufficient labeled
    data and statistically meaningful validation.

## Data contracts, storage, and scale

- [x] Publish separate graph authority dimensions.
- [x] Expose many-to-many graph correspondence in diff JSON.
- [x] Store the current graph projection in compressed form in SQLite.
- [x] Prepare review bundles using a coherent compact SQLite backup and omit
  live WAL/SHM sidecars.
- [ ] Make normalized SQLite evidence and graph tables the durable authority.
  - **Remaining work:** Complete normalized schemas, transactional
    materialization, integrity constraints, and readers so all final artifacts
    can be regenerated from SQLite alone.
  - **Operational benefit:** Runs would have one durable source of truth
    suitable for replay, partial inspection, and scalable tooling.
  - **Estimated effort:** Very large - major storage migration affecting
    collectors, graph builders, outputs, resume, diff, and release
    compatibility.
- [ ] Add output profiles such as `standard`, `forensic`, and `compatibility`.
  - **Remaining work:** Define profile contents and precedence, keep required
    canonical artifacts explicit, and validate unsupported combinations.
  - **Operational benefit:** Operators could choose compact routine output or
    richer investigative evidence without hand-editing many settings.
  - **Estimated effort:** Medium - configuration and output orchestration work
    after artifact boundaries are settled.
- [ ] Keep default `discovery.json` compact while allowing an optional forensic
  artifact with complete raw evidence.
  - **Remaining work:** Specify a separate versioned forensic contract, generate
    it from durable native evidence, and add size/redaction controls.
  - **Operational benefit:** Routine consumers would retain manageable files
    while incident reviews could access lossless collection details.
  - **Estimated effort:** Large - depends on native-row persistence and requires
    schema, storage, performance, and privacy work.
- [ ] Avoid storing a second complete graph JSON document when normalized graph
  tables can reproduce it.
  - **Remaining work:** Move remaining graph consumers to normalized tables and
    retain only necessary indexes/caches with regeneration checks.
  - **Operational benefit:** Persistent run size and write amplification would
    fall without sacrificing reproducibility.
  - **Estimated effort:** Large - blocked on normalized SQLite authority and
    requires reader/performance migration.
- [ ] Deduplicate repeated descriptions and large evidence payloads through
  content-addressed records.
  - **Remaining work:** Identify high-volume repeated values, define canonical
    hashing and reference tables, and preserve transparent export/replay
    behavior.
  - **Operational benefit:** Large runs could use substantially less disk and
    memory when many devices advertise identical platform or description text.
  - **Estimated effort:** Medium to large - schema migration, garbage/reference
    integrity, and benchmark work.
- [ ] Evaluate a separate graph artifact when embedded discovery JSON size
  materially affects operations.
  - **Remaining work:** Measure production document size and consumer cost,
    define a split contract and discovery-to-graph reference, and test atomic
    publication.
  - **Operational benefit:** Graph-aware tools could load only the data they
    need while compatibility consumers retain a smaller discovery document.
  - **Estimated effort:** Medium design study; large implementation if evidence
    shows a separate artifact is warranted.
- [ ] Add streaming graph readers so large comparisons do not require loading
  the complete document at once.
  - **Remaining work:** Create iterator/index-based readers and refactor diff
    algorithms to operate on bounded partitions while preserving deterministic
    correspondence.
  - **Operational benefit:** Very large run comparisons would use predictable
    memory and start producing diagnostics sooner.
  - **Estimated effort:** Very large - algorithm and storage changes with
    demanding correctness/performance tests.
- [ ] Document stable field namespaces for custom graph CSV exports.
  - **Remaining work:** Define row grains, field paths, null semantics,
    transforms, and versioning for entity, interface, claim, and relationship
    sources.
  - **Operational benefit:** Operators could build durable graph reports without
    depending on internal Python or SQLite names.
  - **Estimated effort:** Medium - contract/documentation work plus projection
    implementation and regression tests.
- [ ] Add schema migration tooling only when backward compatibility becomes an
  operator requirement.
  - **Remaining work:** First define supported source/target versions, backup
    and failure behavior, then implement explicit migrations with validation and
    rollback guidance.
  - **Operational benefit:** Sites retaining old durable state could upgrade
    deliberately without silently interpreting incompatible data.
  - **Estimated effort:** Large when activated; intentionally deferred to avoid
    permanent migration burden before a concrete requirement exists.

## Bundle preparation and review workflow

- [x] Include `scripts/lrun-bundle-diff`.
- [x] Select the two latest completed runs when no run IDs are supplied.
- [x] Accept exactly two explicit run IDs in A/B order.
- [x] Validate matching `outputs/<runid>` and `runs/<runid>` trees.
- [x] Generate `lrun-diff --changes-only --json` and package both runs plus the
  diff in one uncompressed tar archive.
- [x] Create a coherent, compact SQLite backup in the staging area.
- [x] Exclude `discovery-state.sqlite-wal` and `discovery-state.sqlite-shm`.
- [ ] Add an optional compression flag if operator workflow shows it is useful.
  - **Remaining work:** Choose supported formats and filename behavior, preserve
    deterministic bundle contents, and verify downstream review/extraction
    tooling.
  - **Operational benefit:** Large review bundles could transfer faster and
    consume less storage when operators prefer compressed archives.
  - **Estimated effort:** Small - launcher/script option and tests, contingent
    on confirming operational demand.
- [ ] Add optional redaction/sanitization profiles for external review.
  - **Remaining work:** Define fields requiring masking, stable pseudonymization
    where cross-file joins matter, secret guarantees, and a verification report.
  - **Operational benefit:** Support bundles could be shared outside the
    operational enclave with lower disclosure risk while retaining diagnostic
    structure.
  - **Estimated effort:** Large and security-sensitive - requires threat review,
    cross-artifact consistency, tests, and clear limitations.

## Developer and contributor documentation

- [x] Provide [`DEV.md`](DEV.md) as the contributor entry point.
- [x] Provide focused references under `docs/dev/` for architecture, modules,
  command/script surfaces, state and schemas, testing, releases, and
  contribution guidelines.
- [ ] Generate a checked module/function index from source docstrings during
  release validation.
  - **Remaining work:** Build a deterministic documentation generator, define
    which public/internal symbols are indexed, and fail validation on stale
    generated output.
  - **Operational benefit:** Contributors could locate implementation entry
    points quickly and documentation drift would be detected automatically.
  - **Estimated effort:** Medium - generator, curated visibility rules, release
    integration, and initial docstring cleanup.
- [x] Add source-maintained diagrams for collection flow, resolver flow, and
  graph rematerialization in
  [`dev/FLOW-DIAGRAMS.md`](dev/FLOW-DIAGRAMS.md).
- [ ] Add a contributor checklist for schema changes, CLI changes, logging,
  documentation, fixtures, and release artifacts.
  - **Remaining work:** Codify required version decisions, compatibility review,
    tests, docs, changelog, fixtures, packaging, and clean-archive checks in one
    release checklist.
  - **Operational benefit:** Maintenance releases would be less likely to omit a
    consumer contract, operator document, or validation artifact.
  - **Estimated effort:** Small - documentation and release-process integration,
    followed by routine upkeep.

## Open design questions

- What evidence is sufficient to promote an observed relationship from
  `directness=unresolved` to direct or indirect?
- How should operator-confirmed topology assertions expire or be revalidated?
- When several VDCs share `mgmt0`, should the physical attachment remain one
  interface group with several logical memberships, or become a dedicated
  attachment entity?
- How should tunnels and other multipoint overlays be summarized without
  implying physical adjacency?
- When one logical workload appears through several hypervisor uplinks, which
  view best serves operations: workload movement, current forwarding path, or
  both?
- Which ENTITY-MIB absence conditions are authoritative on vendors that expose
  incomplete or inconsistent tables despite successful SNMP responses?
- At what scale should graph storage move from embedded discovery JSON to a
  separate indexed artifact?
- Which graph explanation details are useful at the terminal, and which belong
  only in JSON or an audit report?
