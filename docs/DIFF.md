# Comparing Discovery Runs

## 1. Summary

`lldp-runner diff` compares finalized LLDP-Runner discovery results without
contacting network devices. It is a read-only command and disables the
credential subsystem.

The command has two operating modes:

1. With no host selector, it performs a macro comparison of the host inventory
   and each host's authoritative `learned_neighbors` records.
2. With a host selector, it selects exactly one host from data set A, identifies
   the same logical host in data set B, and reports changed host details plus
   learned and `observed_by` neighbor changes for that host.

The default comparison is the latest finalized run against the finalized run
immediately before it. If no prior run is available, LLDP-Runner exits without
attempting a comparison and reports:

```text
Result: No comparison possible: no prior finalized discovery run is available.
```

A successful comparison uses these exit codes:

| Exit | Meaning |
| ---: | --- |
| `0` | Comparison completed and no differences were found. |
| `1` | Comparison completed and differences were found. |
| `2` | Usage, configuration, source, or schema error. |
| `3` | Host selection or B-side matching returned multiple records. |
| `4` | A valid comparison could not be made. |

Human output always includes a `Result: <status message>` line. This gives
scripts a stable text marker in addition to the exit status. `--json` instead
places the same state under the JSON `result` object so the output remains valid
JSON.

## 2. Data set A and data set B

The comparison is directional. LLDP-Runner labels the first data set A and the
second data set B. A and B do not have to be in chronological order when the
operator explicitly identifies both sources.

Source selection follows this table:

| Operator input | Data set A and data set B |
| --- | --- |
| no source | A = latest; B = previous |
| `--previous` | A = latest; B = previous |
| `--prior` | A = latest; B = previous |
| `--oldest` | A = latest; B = oldest |
| one `--runid R` | A = latest; B = run R |
| one `--file F` | A = latest; B = file F |
| `--latest` only | error; a second source is required |
| two source options | first is A; second is B |

The source options are:

```text
--latest
--previous
--prior
--oldest
--runid RUNID
--file FILENAME
```

`--prior` is an alias for `--previous`. There is intentionally no `--last`
alias because `last` can be interpreted as either newest or oldest.

`--runid` and `--file` are repeatable. They can also be mixed. For example:

```bash
lldp-runner diff --runid 20260105-120000-EDT \
  --runid 20260104-120000-EDT

lldp-runner diff --file ./after/discovery.json \
  --file /srv/archive/before/discovery.json

lldp-runner diff --runid 20260105-120000-EDT \
  --file /srv/archive/reference.json
```

When two source options are supplied, command-line order is authoritative.
Two references that resolve to the same discovery file are rejected.

## 3. How run history is ordered

Run IDs are configurable and are not used as timestamps for history ordering.
`--latest`, `--previous`/`--prior`, and `--oldest` are resolved by a
timezone-aware completed timestamp.

For each finalized `<persistent_root>/<output_dirname>/<RUNID>/` directory,
LLDP-Runner first reads the small `run.json` file and uses its `completed`
value. Current completed runs are expected to publish this file beside
`discovery.json`.

If `run.json` is unavailable or does not contain a usable aware completion
time, LLDP-Runner reads only the leading `discovery` metadata object from
`discovery.json` as a compatibility fallback. It does not load the entire
historical discovery document merely to decide which run is latest or oldest.
This matters when a discovery file is hundreds of megabytes or several
gigabytes.

A finalized directory that has no timezone-aware completion timestamp cannot
be safely placed in `--latest`, `--previous`, or `--oldest` chronology and is
not used by those aliases. It can still be selected explicitly by `--runid`.

## 4. Arbitrary files

`--file FILENAME` allows a discovery document outside the normal run-history
directory.

An absolute pathname is used directly. A relative pathname starts from the
operator's current working directory. Human source headings and ambiguity
messages always show the resolved absolute pathname, for example:

```text
A: --file /srv/archive/site-a/discovery.json
   /srv/archive/site-a/discovery.json
```

If a `run.json` file is beside an explicitly selected discovery file,
LLDP-Runner uses its available completion and scope/provenance metadata. The
source remains labeled `--file <absolute-path>` rather than being rewritten to
a run-ID source.

## 5. Schema requirements

Both selected files must use the discovery JSON schema supported by the
installed LLDP-Runner release, and the schema versions must match.

The current implementation compares discovery schema version 8 documents. The
command does not add legacy schema conversion or silently normalize older
discovery formats.

The machine-readable diff has an independent schema version. The current writer
emits diff JSON schema version 12. Schema 12 retains schema-11 graph-backed
events and consistency semantics and adds orthogonal relationship-change
dimensions, exact per-member presence and protocol transitions, and
`graph_member_keys` on change events. The flat host and neighbor result remains
a compatibility diagnostic inside the same document.

## 6. Why host IDs cannot be compared directly

`hosts[].id` is an unambiguous reference inside one `discovery.json`, but it is
run-local. Host 17 in one run is not assumed to be host 17 in another run.

`preferred_name` also cannot be treated as a unique cross-run key. It is a
presentation field and is not guaranteed to be unique. See
[NAMES.md](NAMES.md) for
the complete name and alias model.

For those reasons, graph diff builds correspondence components that can contain
one or several entities from either run. The flat compatibility comparison
still builds a one-to-one host map for its diagnostic host and neighbor tables.

## 7. Cross-run host matching

Host matching uses the strongest shared evidence available. The evidence tiers
are evaluated in this order:

| Tier | Evidence used |
| --- | --- |
| Physical | serial, SNMP engine ID, chassis ID, stack-member serials |
| Address | shared normalized management IPv4 or IPv6 address |
| Name | names, `preferred_name`, `snmp_sysname`, system `sys_name` |
| Edge context | paired observer + same typed local port + exact endpoint MAC |

Names are normalized case-insensitively and without a trailing dot for this
matching step. IP addresses are normalized to canonical host-eligible address
text. Sentinel/group values such as `0.0.0.0`, `::`, `255.255.255.255`,
loopback, multicast, IPv4 this-network, and reserved IPv4 values are ignored as
cross-run address keys even when an older discovery file contains them.
Placeholder physical values such as `unknown`, `none`, `n/a`, and `-` are not
used as durable identity evidence.

Automatic pairing is one-to-one. A host is paired only when the strongest
remaining candidate is unique from both directions. This prevents an early
weak name match from consuming a B-side record that has stronger physical
evidence for another A-side host.

Address evidence is not assumed to be globally unique. When one address maps to
several candidates, an exact normalized name can narrow the set; otherwise the
association remains uncertain. This mirrors discovery 0.31.4, which preserves
repeated addresses as contested claims instead of assigning them to whichever
host happened to be processed first.

A physical token is not always a logical-host key. When one physical candidate
set contains several records sharing the same chassis/container evidence,
LLDP-Runner can narrow that set only when a candidate also shares both a
normalized logical name and at least one normalized management address. This
allows logical devices such as Cisco Nexus VDCs to remain separate even though
they share one physical chassis serial. If name-plus-address corroboration is
still non-unique, diff keeps the match uncertain rather than selecting one.

Beginning with 0.30.1, LLDP-Runner normalizes each host's identity evidence once
and builds reverse indexes for physical tokens, management addresses, and names.
Candidate lookup uses those indexes rather than testing every host in A against
every host in B. This preserves reciprocal uniqueness and conflict rules while
avoiding the quadratic CPU behavior present in 0.30.0 on large inventories. A
selected-host diff still indexes both host inventories once so run-local
neighbor references can be mapped safely across the two data sets.

Beginning with 0.31.4, a second conservative pass can pair a host that has no
globally useful physical, address, or name token. The same already-paired
observer must report the remote endpoint on the same **typed** local port and
with the same exact MAC-derived endpoint token, and the candidate must be unique
from both directions. This `edge_context` evidence is deliberately local to the
topology relationship. It is not promoted to a global alias and cannot pair an
endpoint seen on a different switch port merely because a MAC-like value appears
somewhere else.

### 7.1 Physical conflicts and logical corroboration

LLDP-Runner deliberately prefers `identity uncertain` over a false assertion
that two records represent the same device.

Different non-empty serial numbers or SNMP engine IDs remain hard conflicts. A
matching address or name cannot override either conflict.

Chassis IDs need more context. Some platforms, notably Cisco Nexus VDCs, can
advertise different valid LLDP chassis MACs on different links to the same
logical device. A chassis-ID disagreement can therefore be overridden only when
both a normalized logical name and at least one normalized management address
also agree. Name-only or address-only agreement is insufficient.

The same logical corroboration is used when a physical serial maps to several
cross-run candidates. For example, one Nexus chassis serial can belong to VDCs
`vdc1`, `vdc2`, and `vdc3`. The shared serial establishes a physical-container
relationship, while the matching VDC name plus management address identifies
which logical host should be paired. Different VDC names/addresses remain
separate even though the chassis serial is identical.

This mirrors the discovery-time consolidation rule documented in
[NAMES.md](NAMES.md): logical corroboration can tolerate link-specific chassis
variation, but it does not make shared physical-container evidence sufficient
for merging discrete logical hosts.

This does not reverse identity folding that already occurred during discovery.
If two real devices using one duplicate name were already consolidated into a
single host record, the diff command only has the canonical JSON evidence to
work with. It cannot reconstruct identities that were lost before output.

Operators should continue to use unique device names throughout the network and
should correct devices that advertise duplicate, non-unique names.

### 7.2 Pairing confidence

Every successful host pair records its evidence tier, exact normalized evidence
tokens, and one categorical confidence value:

| Confidence | Meaning |
| --- | --- |
| `verified` | Exact serial, SNMP engine ID, or strict SEP-derived MAC |
| `high` | Other physical identity, or reciprocal unique edge-context evidence |
| `medium` | Unique shared management address without exact-name corroboration |
| `low` | Name-only reciprocal unique pairing |

An address pair narrowed by an exact normalized name is `high`. Ambiguous hosts
remain `uncertain`; they are not assigned a confidence value merely to force a
decision.

These labels are explainable engineering categories, not calibrated
probabilities. A value such as `high` means that the current resolver used a
strong, conservative rule. It does not mean that a statistically measured
percentage of all such pairs is correct. Calibrated probabilities require a
labeled reference corpus and reliability testing outside the comparison itself.

Macro JSON publishes counts under `summary.host_pairing_confidence`, while every
paired host contains `match.tier`, `match.confidence`, and `match.evidence`.


### 7.3 Graph correspondence

Discovery schema 8 contains `topology_graph`. Diff compares graph entities as
connected correspondence components instead of forcing every record into a
one-to-one row.

The graph carries independent authority dimensions. An observation-complete
projection can still have provisional entity resolution, uninferred physical
topology, and unresolved directness. Diff preserves those distinctions rather
than treating the graph as one all-or-nothing truth value.

Possible component outcomes include:

```text
same
same_ambiguous
cluster_split
cluster_merge
cluster_reassociated
absorbed_duplicate
duplicate_projection_introduced
candidate_move
a_only
b_only
changed
```

A split or merge describes how resolver projections correspond across runs. It
is not automatically a physical-link change. For example, one prior projection
of a Nexus VDC may become two duplicate projections in the current run while
both contain the same learned relationships. Diff reports the cluster split and
duplicate relationship projection without claiming that dozens of cables were
added.

Relationship groups compare a canonical local-interface occurrence and a
multiset of learned members. SNMP table row order does not participate in the
comparison. Several equal projected groups are counted as duplicate projection,
not as additional physical relationships.

Graph output separates these questions:

```text
has_resolution_differences
has_observed_relationship_differences
physical_topology_assessment
```

`physical_topology_assessment` remains `not_inferred` when observed members
change because graph relationships intentionally retain
`directness=unresolved`. It becomes `no_change_indicated` when only resolver or
duplicate-projection correspondence changed.

The graph preserves physical chassis and logical systems separately. Several
Nexus VDC logical systems can therefore be members of one chassis without being
merged into one logical host.

When the same weak MAC-only observed system appears uniquely on different local
ports, graph diff emits one `candidate_move` relationship correspondence with
`semantic_qualification=ambiguous`. Low-entropy, multicast, locally
administered, malformed, and otherwise weak MAC values can be repeated by
virtual appliances or vendor defaults, so this correspondence records a review
candidate rather than two confirmed one-sided relationships or proof of a
physical endpoint move.
## 8. Macro comparison

With no host selector, `lldp-runner diff` performs a macro comparison.

```bash
lldp-runner diff
lldp-runner diff --previous
lldp-runner diff --oldest
lldp-runner diff --runid 20260104-120000-EDT
lldp-runner diff --changes-only
```

The macro comparison uses the same cross-run host map as selected-host diff.
In particular, shared-serial Nexus VDCs are paired by logical name plus
management address before learned-neighbor host references are translated. This
prevents an unchanged VDC topology from appearing as matching `a_only` and
`b_only` rows merely because run-local host IDs changed. A genuinely changed
representative chassis ID can still appear as a host-field difference.

Before one-to-one compatibility pairing, macro diff folds duplicate complete
managed-host rows only when they share one exact normalized logical system name,
at least one host-eligible management address, and no contradictory durable
identity evidence. Learned and observed-by references are remapped to the
canonical row and duplicate neighbor projections are removed. This step changes
only the diagnostic compatibility view; immutable advertisements and graph
evidence remain untouched. Shared physical serial evidence alone never folds
different Nexus VDC names.

The macro comparison evaluates:

- hosts present in both data sets;
- host-record detail differences;
- hosts present only in A;
- hosts present only in B;
- hosts whose cross-run identity is uncertain; and
- authoritative learned-neighbor topology for paired hosts.

It does not compare error message text as topology. It does use host state and
neighbor-collector errors to determine whether one side had complete topology
coverage. See [section 14](#collection-completeness-and-uncertainty).

The terminal output begins with source and result information, then a count
summary. A representative summary is:

```text
A: --runid 20260105-160000-EDT
   /var/lib/lldp-runner/outputs/20260105-160000-EDT/discovery.json
B: --runid 20260105-120000-EDT
   /var/lib/lldp-runner/outputs/20260105-120000-EDT/discovery.json
Result: Differences found

Summary
Category           Same  Changed  Moved  Protocol  A only  B only  Uncertain
-----------------  ----  -------  -----  --------  ------  ------  ---------
Hosts               418        2      0         0       1       0          1
Learned neighbors  3021        1      1         3       2       0          4
```

The host table then identifies which logical hosts are the same, changed,
present on only one side, or uncertain. `Host D` is the count of normalized
host-detail differences. `Nbr D` counts all non-`same` learned-neighbor rows,
including ordinary changes, protocol-set changes, one-sided rows, and uncertain
rows.

```text
Status     Confidence  A ID  A name      B ID  B name      Host D  Nbr D
---------  ----------  ----  ----------  ----  ----------  ------  -----
same       verified      14  core-rtr1     11  core-rtr1        0      0
changed    high          18  access-sw1    15  access-sw1       2      1
A only     -             27  new-sw3        -  -                -      4
uncertain  ambiguous     31  phone-01       ?  28:phone-01      ?      ?
```

When learned topology differs for a paired host, a second table shows the
changed connection. A uniquely identified endpoint that changes resolved local
switch ports is reported as `moved` rather than as unrelated A-only and B-only
rows. Remote-port and other attribute changes remain visible as field
differences.

Color supplements the textual status when standard output is an interactive
terminal. The existing LLDP-Runner terminal color policy, `terminal.color`, and
`NO_COLOR` behavior are reused. Redirected and JSON output contains no ANSI
escape sequences.

## 9. Why macro topology uses learned neighbors only

`learned_neighbors` is the authoritative direction reported by the queried
host. `observed_by_neighbors` is the reciprocal presentation of that same
stored topology evidence.

Walking both arrays for every host would count many physical observations
twice. Macro topology comparison therefore uses only `learned_neighbors`.

Host-specific comparison is different: both learned and `observed_by`
directions are useful when investigating one device, so both are displayed
there.

## 10. Neighbor matching

Neighbor `host_ref` values are run-local host IDs and are never compared
numerically across runs. They are translated through the cross-run host map.

For a paired local host, the normal edge identity is:

```text
local interface + paired remote host identity
```

This allows a change in the remote port to appear as a changed field on the
same connection.

Beginning with 0.31.4, diff also has a conservative cross-local-port path. The
remote host must already be paired, each side must contain exactly one row for
that relationship, and the remote Port ID or another strong endpoint MAC token
must agree. When both local interfaces are resolved names and differ, the row is
reported as `moved`. If either side is an unresolved numeric identifier, the row
is `uncertain` instead because collection did not prove a physical move.

Where several parallel records have the same local/remote identity,
LLDP-Runner first uses an exact remote-interface match to avoid arbitrary
pairing. It does not invent a match when the remaining evidence is not unique.

If the remote host itself could not be paired across runs, diff has one narrow
same-edge fallback. The local interface must agree and the two records must
share a unique strong MAC token. A MAC can come directly from the remote Port
ID/chassis/remote-interface evidence, or from the exact reversible IPv6
modified-EUI-64 encoding containing the inserted `ff:fe` octets. This fallback
does not create a global host alias and cannot match an arbitrary IPv6 suffix.

The rule is useful for endpoints that alternate between a MAC Port ID and a
link-local modified-EUI-64 address. The records become one comparable edge
rather than an unrelated A-only/B-only pair; any other changed advertised
fields remain visible as normal field differences.

Protocols, addresses, capabilities, and other set-like values are compared in
stable order so list ordering by itself is not treated as a network change.

### 10.1 Typed local-port evidence

SNMP exposes several local-port namespaces. In particular, original LLDP's
`lldpRemLocalPortNum` indexes `lldpLocPortTable`; it is not automatically an
IF-MIB `ifIndex`. LLDP-Runner therefore compares typed forms:

```text
name:Gi1/0/10
ifIndex:17
lldpLocalPort:14
```

A resolved row can carry its display name together with the applicable typed
indexes, allowing a healthy collection to explain a later unresolved row. Diff
never equates `ifIndex:14` with `lldpLocalPort:14` merely because the integers
match.

Discovery writes unresolved values explicitly as `ifIndex:<n>` or
`lldpLocalPort:<n>` and persists per-protocol interface-resolution coverage. A
bare numeric representation is usable only when protocol detail supplies its
namespace.

Two rows with the same typed unresolved local-port token and otherwise identical
normalized edge evidence are the same observed relationship. A resolved and a
typed-unresolved row can also correspond when one edge-scoped match is uniquely
corroborated by all of the following:

- the same paired observing entity;
- the same typed LLDP local-port number;
- the same strong remote identity and remote port; and
- no competing relationship match.

That result uses `semantic_qualification: "presentation_only"`. The relationship
status remains `same`; `port_resolution` identifies the degraded side; and the
raw display change remains under `presentation_differences`. This rule does not
create a device-wide equivalence between LLDP local-port numbers and IF-MIB
ifIndex values.

A changed relationship remains uncertain when an unresolved port prevents a
unique edge-level conclusion.

### 10.2 Protocol-set changes

Beginning with 0.31.2, diff separates a change in discovery-protocol evidence
from an ordinary topology change when the physical relationship is otherwise
the same. `compare_neighbors` has already paired the same remote host on the
normalized local interface before this classification is considered.

Examples include:

```text
cdp -> cdp,lldp
cdp,lldp -> cdp
lldp -> cdp,lldp
cdp -> lldp
```

A paired row receives status `protocol_changed` when the protocol sets differ
and the remaining field differences are protocol/representation evidence,
such as
the preferred remote name/Port ID, observed address set, capabilities, or
protocol-specific `details`. The full field differences remain present for
review; the status says the edge itself was not interpreted as moved or
replaced.

This is especially useful for Cisco phones. CDP may report:

```text
SEP001234560004 / Port 1
```

while LLDP reports:

```text
SEP001234560004.voice-a.example.com / 001234560004:P1
```

If a later run gains or loses one protocol while the endpoint and local switch
port remain paired, macro and host-specific diff report the protocol transition
explicitly instead of counting it as an ordinary `changed` topology row. The
macro summary places these rows in the `Protocol` column.

Collection uncertainty has higher priority. If the missing protocol is also
recorded as a failed collector on that side, the row remains `uncertain` because
diff cannot assert that the protocol evidence actually disappeared from the
network.

Diff JSON represents a protocol-set transition with a structured object on the
paired compatibility neighbor row:

```json
"protocol_change": {
  "a": ["cdp", "lldp"],
  "b": ["cdp"]
}
```

The macro summary also exposes `learned_neighbors.protocol_changed`.

## 11. Host-specific comparison

A host selector changes the command from macro mode to host mode. The selector
syntax intentionally matches `show-neighbors`:

```text
PATTERN
--name PATTERN
--id NUM
--key KEY:PATTERN
--ipv4 PREFIX|CIDR
--ipv6 PREFIX|CIDR
```

The positional pattern and `--name` are alternate forms. Name matching is a
case-insensitive Python regular expression matched from the beginning of
`preferred_name`.

`--key`, `--ipv4`, and `--ipv6` are repeatable and AND-combined. `--id` is
mutually exclusive with the other filters.

Examples:

```bash
lldp-runner diff access-sw1
lldp-runner diff --name '^access-sw1(\.|$)'
lldp-runner diff --id 127
lldp-runner diff --key 'system.model:^C9300'
lldp-runner diff --ipv4 198.51.100.0/24 --key 'tags:site:west'
```

### 11.1 Selection always starts in A

The operator selector is applied only to data set A. It must identify exactly
one A-side host.

If the selector matches more than one A record, LLDP-Runner follows the
`show-neighbors` ambiguity style:

```text
Multiple records matched:
 ID  Preferred name
---  ----------------------------------------
 17  access-sw1.example.com
 31  access-sw1
```

If no A record matches, the result states that no match in the first data set
was found to compare and exits with status 4.

### 11.2 Finding the B-side host

After one A host is selected, LLDP-Runner does not blindly reuse its numeric ID
or repeat a possibly changed selector against B. It uses the same cross-run
identity matcher as macro mode.

This is important for cases such as:

- `--id 17`, because IDs can change between runs;
- `--key 'system.version:^17\.9'`, when maintenance upgraded the device;
- a hostname selector when the device was renamed; and
- a management-address selector when the device address changed.

If several B records remain plausible, the message contains the resolved B
source rather than the alias originally typed by the operator:

```text
Multiple records matched in --runid 20260105-120000-EDT:
 ID  Preferred name
---  ----------------------------------------
 28  access-sw1.example.com
 41  access-sw1
```

For `--file`, that heading uses the complete resolved absolute pathname.

A single B candidate with conflicting physical identity is reported as
`Identity uncertain` rather than as a successful match. If there is no B-side
candidate, LLDP-Runner reports that no match in the second data set was found
to compare and exits with status 4.

## 12. Host-specific output

Once the selected host is paired, the terminal view displays only changed host
fields and neighbor changes. A representative result is:

```text
A: --runid 20260105-160000-EDT
   /var/lib/lldp-runner/outputs/20260105-160000-EDT/discovery.json
B: --runid 20260105-120000-EDT
   /var/lib/lldp-runner/outputs/20260105-120000-EDT/discovery.json
Result: Differences found

Host: A 18 access-sw1  <->  B 15 access-sw1

Host detail changes
Field                                      A             B
-----------------------------------------  ------------  ------------
system.version                             17.12         17.9
system.sys_uptime_ticks (possible reboot)  120000        9000000

Learned neighbor changes
...

Observed_by neighbor changes
...
```

A host with no changed details and no changed neighbors produces
`Result: No differences` and exit status 0.

## 13. Normalization and intentionally ignored differences

A useful run comparison must suppress values that naturally change every run.
The default comparison policy is summarized here:

| Data element | Treatment |
| --- | --- |
| `hosts[].id` | ignored; run-local identity |
| `first_seen`, `last_seen` | ignored |
| neighbor `host_ref` | translated through host pairing |
| neighbor `last_seen` | ignored |
| ICMP `timestamp` | ignored |
| ICMP `rtt_ms` | ignored as volatile measurement |
| ICMP address/status/error | compared |
| system uptime | only reports a possible reboot |
| SNMP metrics, row counts, retries | collection dimension only |
| collector `duration_ms` | ignored by default; opt-in diagnostic |
| query route, ICMP path, credential route | collection dimension only |
| names, addresses, preferred presentation | presentation dimension only |
| neighbor `protocol_tag` | ignored as derived text |
| SNMP neighbor table indexes | ignored as volatile row locators |
| protocols and tags | compared without list-order noise |
| IPv4/IPv6 address lists | presentation comparison without list-order noise |
| stack members | keyed by durable member evidence |
| `errors[]` | message text ignored; collection coverage derived from errors |

Exact collector durations remain in both input discovery documents. Diff
recursively omits every `duration_ms` leaf by default because ordinary elapsed
jitter is not a semantic host, topology, or coverage change. Use
`--include-collection-timing` or `diff.include_collection_timing=true` only when
collector timing itself is under review. The negative command-line form can
explicitly override a true configuration value.

Neighbor collectors preserve some SNMP table-location evidence in
`details` for troubleshooting. These values identify an agent's table row at
collection time rather than durable topology. Diff therefore ignores generic
and protocol-prefixed copies of LLDP/LLDPv2 `remote_index`, LLDP/LLDPv2
`time_mark`, LLDP `local_port_num`, LLDPv2 `local_ifindex`, and CDP
`ifindex`/`device_index`. A change in one of these values alone does not make a
neighbor `changed`. Semantic identifiers such as `port_id_subtype_id`,
`chassis_id_subtype_id`, and LLDPv2 destination-MAC context remain comparable.

A raw uptime increase is expected and is not a difference. If both data sets
have usable completion times and the chronologically later run reports a lower
uptime than the older run, LLDP-Runner emits a `possible reboot` difference.
This rule also applies to stack-member uptime when the same durable member can
be identified.

Stack members are keyed first by serial number, then member number, then entity
index, with weaker fallbacks only when those values are absent. A member
replacement can therefore appear as removed/added physical-member information
instead of a misleading list-position change.

## 14. Collection completeness and uncertainty

Diff separates a network observation from the ability to collect it. A
successful basic SNMP query does not prove that every CDP, LLDP, LLDPv2,
IF-MIB, or ENTITY-MIB table completed.

Schema-8 discoveries retain structured table coverage and durable errors. Diff
uses structured coverage first and errors only as a compatibility fallback.
Relevant incomplete conditions include:

- an actively queried source host that is partial or failed;
- a failed, timed-out, access-restricted, unsupported, or structurally invalid
  protocol/table collection;
- incomplete local-interface resolution; and
- a recursively hidden observer or descendant that was not reachable because
  an upstream discovery observation was unavailable.

For a one-sided entity or relationship E observed through protocol P on
observer S, diff asks whether paired observer S collected P in the other run. If
that collection failed, E is not a confirmed addition or removal. It is emitted
with:

```text
presence_status: uncertain
presence_confidence: coverage_uncertain
semantic_qualification: coverage_uncertain
coverage_source: observer/protocol/table/incident
```

The same rule is propagated through discovery provenance. For example, if A
could discover managed switch B through LLDP but the paired A-side observer lost
LLDP in the other run, B and endpoints visible only below B remain
coverage-uncertain. The original observation is retained; uncertainty does not
erase evidence.

A genuinely absent endpoint remains confirmed one-sided when the paired
observer and required protocol/table coverage are complete. Intentional
`no_query` endpoints and `out_of_scope` entities do not count as queried-device
collection failures. Coverage summaries separate protocol health from topology
authority:

```text
actively_queried_count
aggregate_complete_queried_count
aggregate_partial_or_failed_queried_count
topology_complete_queried_count
topology_affected_queried_count
management_address_only_incomplete_count
other_health_only_incomplete_count
no_query_count
out_of_scope_count
obscured_downstream_count
```

For LLDP and LLDPv2, `remote_neighbor` is authoritative for relationship
presence. Original LLDP `local_port` plus row-level resolution is authoritative
for the local interface. `remote_management_address` is authoritative only for
management-address additions and removals. An aggregate `partial` result caused
solely by the management-address table remains an operator-visible health issue,
but it does not make complete remote-neighbor or local-port evidence uncertain.
When duplicate compatibility projections are folded, each semantic coverage
dimension is merged independently; one complete contributing path is not erased
by an unrelated aggregate partial result.

Collection incidents aggregate derivative impact beneath one originating
observer/protocol/table failure. Each incident records direct and recursive
relationship effects, affected remote entities, affected attributes, and stable
incident context. Top-level warnings are populated when those incidents
materially limit interpretation.

Terminal output prints aggregate-health and topology-authority denominators,
graph semantic-qualification counts, and the twelve highest-impact collection
incidents. Default human output collapses derivative coverage-uncertain rows
beneath those incidents. JSON output retains every incident and all derivative
entity, relationship, attribute, and recursive-path details.

CDP snapshots are structurally valid only when every materialized row has a
usable device ID and remote port and all cache-indexed columns agree. A failed
snapshot is discarded and restarted from its root. Repeated failure records
`structurally_invalid` coverage and does not create an identity-empty shell host
or relationship. LLDP and LLDPv2 retain their mandatory chassis-ID and Port-ID
snapshot boundary.

Protocol transitions are also coverage-aware. With complete collection,
`cdp,lldp -> lldp` is a protocol-evidence change with
`physical_topology_effect: "none"`. If CDP failed on the side missing CDP, the
transition is coverage-uncertain instead of a confirmed protocol removal.

ENTITY-MIB and stack attributes follow the same rule. Missing optional hardware
rows are confirmed removed only when corresponding table coverage is complete
and the successful snapshot contains at least one row. A complete zero-row
ENTITY-MIB walk is not authoritative negative evidence because supported
platforms can intermittently return an empty optional table without a transport
error. The field result is `not_observed`, and the paired host contributes to
the attribute-uncertain dimension rather than the confirmed host-change count.

Diff JSON schema 12 retains this context under paths including:

```text
comparison.presence_uncertain[]
comparison.collection_incidents[]
comparison.collection_incidents[].reported_difference_depends_on_gap
comparison.change_events[]
comparison.cross_view_consistency
comparison.management_address_health
comparison.hosts[].collection_coverage
comparison.hosts[].learned_neighbors[].uncertainty_reasons
comparison.hosts[].learned_neighbors[].graph_relationship_refs
comparison.topology_graph.entity_correspondence[].semantic_qualification
comparison.topology_graph.relationship_groups[].semantic_qualification
comparison.topology_graph.relationship_groups[].compatibility_observation_refs
comparison.topology_graph.relationship_groups[].change_dimensions
comparison.topology_graph.relationship_groups[].member_presence_change
comparison.topology_graph.relationship_groups[].member_protocol_changes
comparison.change_events[].graph_member_keys
comparison.change_events[].graph_change_dimensions
comparison.summary.collection_coverage
comparison.summary.collection_incidents
comparison.summary.change_events
comparison.summary.cross_view_consistency
comparison.summary.management_address_health
comparison.summary.topology_graph.entity_qualifications
comparison.summary.topology_graph.relationship_qualifications
comparison.summary.compatibility_projection
comparison.summary.host_dimensions
comparison.projection_reconciliation
```

An uncertain result remains a difference for exit-status purposes because the
operator still needs to repeat or investigate collection. The qualification
prevents the report from claiming that physical topology definitely changed.

## 15. Scope and provenance warnings

Two discovery outputs can differ because the network changed, because discovery
coverage changed, or both. The diff command therefore compares available scope
metadata and emits a warning when important context differs.

Warnings appear immediately after the `Result:` line. They do not stop the
comparison or change the exit code by themselves. One warning reports discovery
scope/provenance differences. Collection warnings distinguish a gap that
qualifies a reported difference from a health-only topology gap that remains
operationally relevant but does not affect any reported change.

From `discovery.json`, the command considers fields including:

```text
status
boundaries
discovery_mode
effective_max_devices
configured_max_devices
configured_max_hosts
seed_order
limit_behavior
limit_reason
completion_reason
```

When `run.json` is available for both sources, LLDP-Runner also compares the
recorded ordered configuration-file path list and the consolidated sequence of
recorded seed inputs.

A warning can therefore look like:

```text
Result: Differences found
Warning: Compared runs used different discovery scope/provenance metadata (...).
```

The comparison still proceeds because the operator may intentionally be
comparing unlike discovery scopes.

`run.json` records configuration pathnames, not an immutable historical copy of
every config file. If `/etc/lldp-runner/config.toml` changed in place between
runs, identical pathnames do not prove identical contents. Similarly, not every
collector-related setting is represented as a dedicated discovery metadata
field. Scope warnings are useful evidence, not proof that two runs used exactly
identical runtime policy.

## 16. `--changes-only`

Macro mode normally includes paired hosts that compare as `same`. This gives an
operator positive confirmation that devices remained present and unchanged.

`--changes-only` suppresses unchanged host rows and unchanged neighbor details:

```bash
lldp-runner diff --changes-only
lldp-runner diff --id 127 --changes-only
```

By default, derivative coverage-uncertain compatibility and graph rows are
collapsed beneath the originating collection incident. The final note reports
how many rows were collapsed. Use `--expand-collection-incidents` to restore
those rows. Use `--summary-only` when only source/result context, summaries,
warnings, and collection incidents are needed:

```bash
lldp-runner diff --changes-only --summary-only
lldp-runner diff --changes-only --expand-collection-incidents
```

These are human-rendering controls only. `--json` always contains the complete
structured comparison, and summary counts always describe the complete
comparison rather than only visible rows.

## 17. Machine-readable `--json`

`--json` replaces terminal tables with one valid JSON object:

```bash
lldp-runner diff --json
lldp-runner diff --id 127 --json
lldp-runner diff --changes-only --json
```

The top-level structure is:

```json
{
  "schema_version": 12,
  "result": {
    "status": "differences_found",
    "message": "Differences found",
    "exit_code": 1
  },
  "mode": "macro",
  "sources": {
    "a": {},
    "b": {}
  },
  "warnings": [],
  "comparison": {}
}
```

`result.status` is the stable machine status. `result.message` corresponds to
the human `Result:` message, and `result.exit_code` mirrors process status.

Source objects contain the resolved label, absolute discovery pathname, run ID
when known, and completion timestamp when available. Comparison detail uses
run-local IDs only as labels inside each A/B record; cross-run association is
represented explicitly by correspondence records.

Schema 12 keeps these result dimensions separate instead of collapsing them
into one physical change count:

1. entity identity;
2. observed relationship;
3. protocol-evidence set;
4. device or endpoint attributes;
5. presentation-only differences; and
6. collection coverage.

Each graph entity/relationship correspondence carries `presence_confidence`,
`semantic_qualification`, optional `coverage_sources`, and
`physical_topology_effect`. Schema 10 introduced `evidence_only`; schema 11
added stable references joining compatibility rows to graph relationships and
unique change events. Schema 12 adds relationship `change_dimensions`, exact
member-presence and protocol details, and event `graph_member_keys`. Field-level
attribute uncertainty retains `provenance` and exact `coverage_sources`. The
graph-level `physical_topology_assessment` remains `not_inferred`.

For a local-port transition, schema 11 and later use
`event_type=observed_attachment_changed`. The event records identity continuity,
movement confidence, `relationship_scope=observed`, `directness=unresolved`, and
`physical_topology=not_inferred`. It does not claim that a physical cable moved.

`comparison.cross_view_consistency` counts matched, unmatched, ambiguous,
conflicting, and graph-only results. A confirmed compatibility change cannot be
silently reconciled to an ambiguous or coverage-uncertain graph record. The
operator receives `attention_required` instead.

Diff JSON versioning is independent of discovery JSON versioning. Scripts
should check both the process result and diff `schema_version`.

## 18. Large discovery files

History alias resolution is intentionally lightweight: it uses `run.json` or a
small leading discovery metadata read rather than loading every historical
`discovery.json`.

The actual comparison is different. Host and neighbor records from the two
selected discovery documents must be available for cross-run pairing and
one-to-one topology comparison. Versions 0.30.1 and later use indexed in-memory
host identity matching, but still use the standard Python JSON loader for the
two
selected files. Very large discovery documents can therefore require more memory
than their on-disk size while the comparison is running.

Operators comparing multi-gigabyte discovery files should run the command on a
system with sufficient memory. A future streaming/indexed comparison design can
reduce this requirement without changing the operator-facing diff contract.

## 19. Recommended maintenance workflow

For shared installations, `scripts/lrun-diff` supplies the deployed primary
configuration and forwards all diff options. Unlike most `lrun-*` launchers, it
preserves the operator's current working directory so relative `--file` sources
resolve exactly as documented for `lldp-runner diff`.

A typical post-maintenance check is:

```bash
# Before maintenance
lldp-runner run ...

# Perform maintenance, then run discovery again.
lldp-runner run ...

# Compare the latest finalized run with the prior finalized run.
lldp-runner diff

# Focus on changes when the full inventory is large.
lldp-runner diff --changes-only

# Investigate one affected device.
lldp-runner diff access-sw1
```

A no-difference result is useful evidence that the recorded host and learned
neighbor topology remained stable. It is not a proof that every network path or
service was healthy: the result is limited to what the two discovery runs
collected and to the scope under which they ran.

## Relationship-evidence changes

Diff schema 10 adds `relationship_evidence_changed` for a relationship that is
already paired to the same observer and remote entity on the same local and
remote ports with the same protocol set, but whose remaining differences are
limited to non-authoritative presentation or raw protocol evidence. Examples
include a short endpoint name becoming an FQDN, a protocol sentinel being
replaced by a usable advertised address, or a peer display name gaining a
serial-number suffix.

The row is counted in the `Evidence` column rather than generic `Changed`. Its
semantic qualification is `evidence_only`, relationship presence remains
confirmed and the same, and `physical_topology_effect` is `none`. Complete field
differences remain available in JSON and human detail.

The rule is intentionally conservative. Two conflicting usable chassis
identifiers, a different durable endpoint identity, a changed resolved local
port, or a protocol-set transition is not reduced to evidence drift. Collection
uncertainty, physical movement, and protocol transition retain precedence.

## Management-address evidence changes

Diff schema 10 separates a management-address observation change from a
physical relationship change. The status is `management_address_changed` only
when the paired learned relationship remains stable after host and edge
matching and no higher-priority condition applies.

The record includes the A and B address sets plus explicit `before` (B) and
`after` (A) sets. `added` means present in A but not B; `removed` means present
in B but not A. Additions and removals are also grouped by IPv4 and IPv6. The
record includes confidence, rationale, collection provenance for each
participating protocol's remote-management-address subtable, and
`physical_topology_effect = "none"`.

Precedence is conservative:

1. Collection failure or incomplete required coverage can make the row
   `uncertain`.
2. A confirmed move remains a move.
3. A protocol-set transition remains `protocol_changed`.
4. Only then can an address-only evidence change receive its own status.

A successful empty management-address walk is authoritative empty evidence.
An access restriction, timeout, malformed index set, partial result, or failed
walk is not an authoritative empty table and must not be rendered as ordinary
address churn.

The 0.32.6 production replay of 20260109-01 against 20260109-00 produced one
credible endpoint local-port move, one protocol transition, seven
relationship-evidence changes, nineteen confirmed one-sided learned
observations, and no generic learned-neighbor `changed` rows. One structurally
invalid LLDP remote-neighbor snapshot remains a collection incident and makes
its direct and recursive effects uncertain. Management-only partial walks remain
visible in health counts but do not contaminate complete relationship coverage.

## 0.32.7 graph-backed reconciliation and production replay

Schema 11 treats the compatibility projection and topology graph as two views of
the same immutable observations. Every non-stable learned-neighbor row receives
`compatibility_observation_key`, `graph_relationship_refs`, `graph_event_ref`,
and `cross_view_consistency`. Graph relationship records carry the reverse
compatibility-observation and change-event references.

`comparison.change_events[]` is the unique audit unit. Directional compatibility
rows remain available for familiar troubleshooting, but reciprocal or graph-half
records can be grouped into one event when they represent the same observed
change. Event records preserve all backing graph and compatibility references.

Collection incidents include graph-native relationship/entity references and
`reported_difference_depends_on_gap`. Health-only incidents remain visible even
when no changed row relies on the missing table. Management-address health is
reported separately as persistent, new in A, recovered in A, or changed, with
cause counts and transition detail.

The 0.32.7 production replay of 20260109-03 against 20260109-02 reconciles
all 13 non-stable learned observations to 13 graph-backed events: two observed
attachment changes, two protocol-evidence changes, two A-only observations, and
seven B-only observations. There are no unmatched, ambiguous, conflicting, or
graph-only events. Four genuine topology-sensitive collection gaps on each side
remain health warnings, but no reported difference depends on them. The
management-address health comparison records 97 persistent malformed-index
cases and one timeout recovered in A.

## 0.32.8 compound relationship reconciliation and production replay

Schema 12 preserves the relationship group's concise primary status while also
serializing every independently detected change dimension. A primary
`member_set_changed` row can therefore contain both `member_presence` and
`protocol_evidence`. `member_presence_change` identifies A-only and B-only graph
members. `member_protocol_changes` identifies stable members whose protocol sets
differ between runs.

Protocol reconciliation inside such a compound relationship is deliberately
strict. Both compatibility sides must select the same remote correspondence
component and normalized remote port, and the compatibility protocol sets must
match the graph member on each side. The exact transition must also appear in
`member_protocol_changes`. Stable management-address and raw-evidence changes
may use the same paired-member path only when their protocol sets are unchanged.

Each change event carries `graph_member_keys`. Two neighbors changing in one
local-interface group cannot collapse merely because they share a graph
relationship record and event type. The same graph member can still aggregate
multiple directional compatibility observations. Unclaimed member-presence,
protocol-evidence, or candidate-attachment dimensions remain graph-only events.

The 0.32.8 production replay of 20260110-01 against 20260110-00 reconciles all
89 non-stable learned observations to 87 graph-backed events. All 89
observations are matched, and there are zero unmatched, ambiguous, conflicting,
or graph-only events. One relationship on `Gi1/0/6` carries both
`member_presence` and `protocol_evidence`: the existing Cisco SEP endpoint
changes from `cdp,lldp` in B to `lldp` in A while another LLDP member is newly
observed in A. The two dimensions produce separate, exact member-scoped events.

## 0.32.9 compatibility identity maintenance

Version 0.32.9 does not change diff schema 12 or any graph relationship/change
event rule. It changes how new scans project otherwise anonymous LLDP/LLDPv2
observations into flat compatibility hosts: locally assigned chassis subtype 7
is no longer a global alias. One exact typed MAC-address Port ID can identify
that anonymous endpoint.

Consequently, a comparison between two newly collected 0.32.9 scans can show
more precise `hosts` and `unknown-devices` counts than equivalent 0.32.8 scans.
Several distinct anonymous endpoint MACs that formerly appeared as attachments
on one aggregate host now appear as separate compatibility hosts. This is an
identity-projection correction, not topology churn. The authoritative graph
already represented those distinct endpoint MAC entities and relationships.

Replaying the immutable 20260111-01 and 20260111-00 discovery documents keeps
their 68 graph-backed change events, matches all compatibility observations, and
retains `cross_view_consistency.status=consistent`. The input documents still
contain the flat host projection produced by 0.32.8; `diff` never rewrites an
archived discovery. Replaying copied 0.32.8 SQLite state under 0.32.9 can
publish a compatibility-projection diagnostic that identifies legacy
aggregate hosts while leaving graph authority unchanged.
