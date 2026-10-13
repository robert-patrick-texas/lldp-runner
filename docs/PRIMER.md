# LLDP-Runner technical primer

This primer explains the ideas behind LLDP-Runner's collection and identity
work. It is written for Network Operations staff who understand enterprise
routing, switching, addressing, and SNMP but may not work with Python or data
science every day.

The detailed implementation is described in [ARCHITECTURE.md](ARCHITECTURE.md).
The durable evidence model is described in [CLAIMS.md](CLAIMS.md).

## 1. Why network discovery is an evidence problem

A switch, router, phone, access point, hypervisor, or appliance can describe
itself in several ways:

- SNMP `sysName`
- CDP Device ID
- LLDP System Name
- LLDP Chassis ID
- CDP or LLDP management addresses
- IF-MIB interface names and indexes
- ENTITY-MIB serial numbers
- SNMP engine ID
- DNS names and addresses
- Neighbor Port ID values

These values are not guaranteed to be complete, current, unique, or formatted
the same way. One physical chassis can host several logical systems, such as
Cisco Nexus virtual device contexts (VDCs). One physical link can carry several
protocol advertisements. A low-end bridge can forward discovery frames rather
than consume them. A phone can advertise a default address while its name and
Port ID identify a different endpoint.

LLDP-Runner therefore treats collected values as **evidence**, not immediate
proof that two rows are the same host.

## 2. SNMP table collection and GETBULK

An SNMP table is normally collected through several protocol exchanges. With
SNMPv2c and SNMPv3, GETBULK asks the agent to return several table values in one
response.

`max_repetitions` controls how much repeated table data is requested in one
GETBULK operation:

- A larger value can finish a table with fewer network exchanges.
- A larger value asks the device to assemble and transmit a larger response.
- A smaller value lowers the work and response size of each exchange.
- A smaller value can require more exchanges to finish the same table.

A device may time out because it is busy, has a slow control plane, must search
a large MIB view, is protecting itself with rate limits, or cannot produce a
large response before the manager's timeout expires.

LLDP-Runner uses a per-target adaptive profile. The first retry-eligible failure
uses the configured policy to:

1. Increase the active timeout.
2. Reduce GETBULK `max_repetitions`.
3. Reduce GET-MANY OID batch size by the same work factor.
4. Add request pacing.
5. Restart an incomplete table from its root.
6. Keep the slower profile for later operations on that target.
7. Reset to normal defaults for the next target.

The default transition is:

```text
timeout:             2.0 seconds -> 3.0 seconds
max_repetitions:     25          -> 13
inter-PDU delay:     0 ms        -> 100 ms
normal retry limit:  1 per operation and collector family
general retry pool:  3 shared tokens for the target route
neighbor reserve:    2 protected LLDP-family/CDP tokens
```

Odd repetition counts round upward so `25 * 0.5` becomes `13`. The configured
minimum prevents the value from falling below an operator-approved floor.

### Why retry allocation must be bounded and fair

A request wrapper and a protocol collector can both be tempted to retry the
same failure. Without shared state, one apparent retry can become several
network attempts. LLDP-Runner keeps the decision in one per-target object so
session setup, GET, GET-MANY, WALK, and structural table validation cannot
independently multiply retries.

A single undifferentiated target cap can create the opposite problem: early
SYSTEM-MIB, ENTITY-MIB, or IF-MIB failures can consume every retry before LLDP
or CDP is reached. LLDP-Runner therefore combines a shared general pool with a
protected neighbor reserve and a per-collector fair-share limit. Original LLDP
and LLDPv2 share the LLDP family; CDP has a separate family. Earlier collectors
cannot spend the protected reserve.

### Why the final stability retry is delayed and separate

Packet loss can outlast an immediate retry, and a live LLDP/CDP table can change
while several columns are being walked. When enabled, LLDP-Runner waits until
all first-pass neighbor collectors finish, pauses once for the target, and gives
each timed-out or structurally invalid protocol one fresh full-protocol attempt.
This stability pass has separate accounting so a depleted normal pool cannot
block it. Nested transport and structural retries are disabled inside the pass,
which makes the extra work exactly bounded at one attempt per eligible protocol.

Access restrictions, authentication failures, unsupported objects, and other
definitive errors are not stability-retry candidates.

### Why partial table rows are discarded

A timeout in the middle of a table does not prove that the rows already returned
form a complete snapshot. Accepting them would make missing rows look like real
network removals. LLDP-Runner discards the failed attempt and restarts the table
from its first requested OID with the degraded profile.

### Access restrictions are not performance failures

Successful authentication does not guarantee access to every OID. VACM views,
ACLs, and device policy can return errors such as `noAccess` or
`authorizationError`.

LLDP-Runner records these as `snmp_access_restricted`. It does not retry them as
though the agent were merely slow. Operators can then distinguish:

```text
bad credentials
transport timeout
access/view restriction
unsupported OID
empty but successful table
structurally incomplete table
```

## 3. Observation, claim, cluster, and decision

These terms have distinct meanings.

### Observation

An **observation** is a factual record of what one collection operation
returned.
Examples:

```text
CDP advertised device ID hq-vdc2-7nx1.example.com(SERIAL000001)
LLDP local-port index 13 advertised remote port Te1/0/47
SNMP query to 198.18.0.10 returned sysName switch1.example.com
```

Observations are immutable. New information does not rewrite old evidence.

### Claim

A **claim** is a typed interpretation derived from an observation. It retains
its source and scope. Examples:

```text
name claim:               hq-vdc2-7nx1.example.com
serial-hint claim:        SERIAL000001
endpoint-MAC claim:       00:12:34:56:00:04
edge-scoped address:      198.51.100.3
SNMP-agent engine ID:     8000000903...
```

A claim records whether it is strong or weak and whether its scope is global,
physical-chassis, logical-agent, edge, or diagnostic.

### Candidate cluster

A **candidate cluster** is a group of observations that may describe the same
physical or logical entity. Clustering is a question for analysis, not a fact
reported directly by a protocol.

### Resolution decision

A **resolution decision** records the current conclusion, the supporting claims,
and any conflicting claims. Decisions are append-only. A newer decision can
supersede an older one when stronger evidence arrives.

This gives LLDP-Runner a reversible reasoning path:

```text
immutable observations
        |
        v
typed claims
        |
        v
candidate cluster
        |
        v
resolution decision A
        |
        +---- new contradictory evidence
        v
resolution decision B, superseding A
```

## 4. Strong and weak evidence

Evidence strength depends on both its value and its scope.

### Examples of strong evidence

- A strict Cisco phone name `SEP` plus exactly 12 hexadecimal characters
- A strict Cisco AP name whose dotted or compact value encodes a MAC address
- A directly collected SNMP engine ID within its administrative scope
- A trustworthy physical serial number
- An exact typed endpoint MAC on one physical edge

Strong evidence can still conflict. Two different strict SEP MACs must not merge
because they advertise the same default IP address.

### Examples of weak or scoped evidence

- A common or repeated IP address
- An LLDP `network_address` chassis value
- An LLDP interface-name chassis value such as `vmnic2`
- A DNS address reached through a load balancer or shared frontend
- A short name without address or topology corroboration
- A numeric LLDP local-port index with no MIB mapping

Weak evidence remains valuable for display, troubleshooting, and candidate
selection. It simply cannot override contradictory strong evidence.

## 5. Physical chassis, logical agents, and protocol advertisements

A flat `host` row is not enough to describe every network system.

Consider a Cisco Nexus chassis with several VDCs:

```text
physical Nexus chassis
    |
    +-- logical VDC A
    +-- logical VDC B
    +-- logical VDC C
```

The VDCs can share a physical serial and management attachment while retaining
separate logical names, addresses, SNMP agents, and topology roles. Sharing the
serial should associate them with one chassis, not merge the VDCs into one
logical host.

A local interface can also receive several advertisements:

```text
local interface observation group
    |
    +-- direct LLDP advertisement
    +-- direct CDP advertisement
    +-- advertisement from another logical agent on the same chassis
    +-- indirect CDP/LLDP frame forwarded by an intermediate bridge
```

A protocol advertisement is evidence about a relationship. It is not always a
complete statement of one direct physical cable.

LLDP-Runner records each raw protocol advertisement before cross-protocol
reasoning. The graph accounts for every durable advertisement or gives an
explicit exclusion reason. Complex ports retain all members in a deterministic
interface observation group. Entity resolution remains provisional,
relationship scope is `observed`, and directness remains `unresolved`; the
resolver does not guess whether an advertisement is a direct cable, a logical
member, a passed-through frame, or an overlay relationship.

## 6. Decorated system names

Some devices advertise a name followed by a serial-like token:

```text
hq-vdc2-7nx1.example.com(SERIAL000001)
```

LLDP-Runner retains three facts:

```text
raw advertisement:  hq-vdc2-7nx1.example.com(SERIAL000001)
logical base name:   hq-vdc2-7nx1.example.com
serial hint:         SERIAL000001
```

The logical base is used for guarded CDP/LLDP comparison and DNS lookup. The
serial hint is stored separately and does not merge physical chassis by itself.
A direct ENTITY-MIB serial or other reliable source can later corroborate it.

Generic parenthesized text is not automatically stripped. A suffix must be a
plausible terminal alphanumeric serial token, and the remaining base must still
be a usable identity name.

## 7. Interface namespaces

The same integer can mean different things in different MIB tables.

Examples:

```text
IF-MIB ifIndex:             13
LLDP lldpRemLocalPortNum:   13
```

Equal integers do not establish that these are the same namespace. LLDP-Runner
therefore preserves unresolved values with a type:

```text
ifIndex:13
lldpLocalPort:13
```

When protocol rows already contain the same resolved name, such as `Gi0/0/3`,
the graph uses one interface occurrence and preserves the original IF-MIB or
LLDP namespace as evidence. When CDP and LLDP identify one unique endpoint,
exact remote port, and matching protocol-local numeric index, LLDP-Runner can
also attach the unresolved LLDP row to the resolved CDP edge. This is an
edge-scoped conclusion. It does not create a device-wide rule that all LLDP
local-port numbers equal IF-MIB indexes.

## 8. Deterministic sets and multisets

SNMP agents do not have to return table rows in the same order on every run.
Order must therefore not decide identity or topology.

LLDP-Runner compares canonical keys and emits a stable sort order. Conceptually:

```text
directness or scope
logical base name
physical or logical identity
remote port
protocol set
strong endpoint identity
immutable fingerprint
```

A **set** records unique members. A **multiset** also records how many times a
member occurs. Multisets matter when duplicate advertisements are materially
separate evidence. Sorting is for stable display and serialization; matching is
based on keys and evidence, not list position.

A critical regression property is **order invariance**:

> The same observations must produce the same normalized collection, claims,
> groups, and decisions regardless of ingestion order.

## 9. Deferred reasoning and reversible outcomes

Immediate merging is attractive because it is simple, but it can make an early
weak assumption difficult to undo. Deferred reasoning stores observations first
and decides after more context is available.

Examples of information that may change a decision:

- A later SNMP query returns a conflicting engine ID.
- ENTITY-MIB returns a physical serial.
- Another switch observes the same endpoint MAC on an incompatible location.
- A repeated address becomes contested by several devices.
- A logical VDC is associated with a known physical chassis.
- A direct LLDP adjacency explains why downstream CDP frames were observed.

A reversible resolver does not delete the earlier conclusion. It appends a new
decision, records why it supersedes the old decision, and rematerializes the
current host and edge view from the latest valid decisions.

## 10. Confidence is multi-dimensional

One number cannot explain every uncertainty. Useful dimensions include:

```text
identity-match confidence
cluster integrity
physical-edge confidence
local-port resolution confidence
collection coverage
```

For example, two runs can show the same typed `lldpLocalPort:13` edge with high
physical continuity while the friendly interface-name resolution remains
incomplete. The topology can be stable even though one display attribute is
unresolved.

Likewise, a cross-run pair can have a high match score while one side contains a
conflicted cluster. The cluster conflict should prevent an ordinary field-by-
field host comparison.

## 11. Operational reading of current output

When a target enters adaptive slowdown, logs use this field order:

```text
SNMP target=<address-or-name> <message>
```

A representative retry event is:

```text
SNMP target=198.18.0.10 adaptive retry operation=WALK \
category=timeout attempt=2 timeout=2.000->3.000 \
max_repetitions=25->13 inter_pdu_delay_ms=0.000->100.000 \
per_device_rps=5.000->3.333 partial_result_discarded=true
```

The same facts are retained in adaptive session telemetry in SQLite and
`discovery.json` when a retry occurs. The host SNMP section retains the compact
interface-group audit view, while the top-level schema-7 `topology_graph`
provides the observation projection and reports separate authority dimensions
for completeness, entity resolution, physical topology, and directness.

These records explain collection behavior; they are not themselves proof of a
physical topology change. A graph relationship is an observed advertisement
until independent evidence establishes a stronger physical interpretation.
