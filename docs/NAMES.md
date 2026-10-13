# Device Names, Addresses, and Host Identity

## 1. Summary

LLDP-Runner treats a discovered network as a graph of logical hosts and
connections. A switch, router, or other device can be observed from several
places and under several names or management addresses. The coordinator tries
to fold those observations into one host record so that one physical device is
not repeatedly scheduled and reported as several independent devices.

The main rules are:

1. Directly advertised names, host-eligible addresses, strict SEP-derived MACs,
   and appropriately scoped trusted chassis IDs are identity evidence.
2. Names are normalized for identity comparison by trimming whitespace,
   removing a trailing dot, and converting to lowercase.
3. IP addresses are normalized to canonical IPv4 or IPv6 text.
4. LLDP/LLDPv2 chassis IDs advertised as MAC or network addresses must decode as
   that advertised type before they are trusted for identity correlation;
   device-local chassis subtypes, including locally assigned subtype 7, are not
   global host aliases.
5. A candidate that shares compatible normalized identity evidence with an
   existing host can be associated with that host.
6. Evidence from several observations can therefore accumulate on one logical
   host as additional names, addresses, chassis information, tags, and edges.
7. `preferred_name` is an operator-facing presentation value. It is not a
   database key and is not guaranteed to be unique.
8. `snmp_sysname` is collected device data and is separate from
   `preferred_name`.
9. `discovery.json` contains the richest identity and observation evidence.
   Fixed CSV files are convenience projections and do not contain every
   identity detail.
10. Repeated addresses are retained as contested claims on every observed host;
    they are not assigned to whichever host happened to be processed first.
11. DNS-derived names and addresses can affect classification, presentation,
    query policy, and scheduling, but DNS enrichment alone does not merge two
    discovered hosts.

This folding behavior intentionally supports the common case where the same
switch or router is learned by several neighboring devices. Versions 0.30.3
through 0.30.5 add conservative evidence checks so malformed or contradictory
chassis information cannot silently override distinct identities, while strong
name-plus-management-address agreement can still identify one logical host on
platforms that advertise link-specific chassis identifiers.

Duplicate device names remain inherently ambiguous when stronger contradictory
evidence is unavailable. LLDP-Runner does not enforce globally unique names.
Operators should configure every device on the network with a unique name and
should change devices that use duplicate, non-unique names. Further identity
correlation refinement remains an acknowledged area for future review.

## 2. Identity versus presentation

Several fields that look similar serve different purposes.

### 2.1 Internal host ID

Every host in one run has an integer SQLite ID. The same value is written as
`hosts[].id` in `discovery.json` and is referenced by topology `host_ref`
values.

The ID is the unambiguous host reference inside one discovery document. It is
not intended to be a permanent inventory identifier across separate runs.

### 2.2 Identity aliases

The coordinator maintains globally owned normalized aliases for:

```text
name
mac
chassis_id
```

Names, MACs, and accepted chassis identities can belong to only one host in the
run. IPv4 and IPv6 values are stored separately as many-to-many host-address
claims. A unique address can still help locate one host, but once several hosts
claim the same value it becomes contested and cannot force them into one record.
Together these records drive identity correlation and duplicate prevention.

The `mac` alias namespace is used by the strict Cisco `SEP<12-hex>` and AP
naming rules described below. Beginning with 0.32.9, it is also used for one
explicitly typed MAC-address LLDP/LLDPv2 Port ID when the candidate is otherwise
anonymous. It represents exact hardware evidence, not a generic MAC guess from
arbitrary text. A named or addressed device does not acquire global identity
from each of its per-interface Port IDs.

### 2.3 `preferred_name`

`preferred_name` is the best current presentation label for a logical host. It
is useful for humans, CSV output, sorting, and messages, but it does not have a
uniqueness constraint.

Two top-level host records can therefore have the same `preferred_name`. The
most obvious example is two separate identities that both have no usable name
and are rendered as `unknown`.

Normal observations carrying the same actual name alias are usually folded
before output, so duplicate meaningful `preferred_name` values are less common
than duplicate `unknown` values. That is an implementation consequence, not a
promise that `preferred_name` is unique.

### 2.4 `snmp_sysname`

`snmp_sysname` is the SYSTEM-MIB `sysName` learned from a successful SNMP
query. It is retained separately because the queried device can report a name
that differs from the seed string, DNS result, or neighbor-advertised name.

A successful query may add the normalized `sysName` as a name alias when that
alias is not already owned by another host. It does not automatically replace
`preferred_name`.

If another host already owns the same normalized name alias, the later
`sysName` alias insertion is ignored rather than moving the alias or forcing a
new host merge. The separate `snmp_sysname` field remains useful evidence for
operator review.

### 2.5 Query target

`queried_as` is the address retained from worker execution. On a successful
query it is the management address that answered SNMP. On a complete failure,
it can be the first permitted attempted address. Hosts that were not queryable
can have no `queried_as` value.

`queried_as` is not a host identity key. The host can have several known
management addresses while only one address appears in `queried_as`.

## 3. Operator-supplied seed input

### 3.1 Seed sources

A run can receive explicit seeds from configuration, command-line options,
files, directories, environment variables, reusable `seeds.csv`, and stdin.
All normal seed sources are consolidated before discovery begins.

A plain seed target can be a hostname, FQDN, IPv4 address, or IPv6 address.

### 3.2 Plain-text name input

For a hostname or FQDN seed, LLDP-Runner removes surrounding whitespace. A
trailing dot is not retained in the DNS candidate used for presentation.

A short name can also be tried with each configured
`discovery.dns_suffixes` value. For every DNS candidate that resolves,
LLDP-Runner can collect:

```text
the candidate name
an operating-system canonical/FQDN result
canonical names returned by address resolution
IPv4 addresses
IPv6 addresses
```

The name list and address list are de-duplicated while preserving useful
resolver evidence.

The initial preferred presentation is the first available name containing a
dot, otherwise the first available name. If DNS does not produce a usable
address, the input name is still retained as identity evidence, but the managed
seed cannot be queried until a usable management address is known.

### 3.3 Direct IP input

An IP seed is normalized with Python IP-address rules. Brackets around an IPv6
literal are removed and IPv6 text is canonicalized.

LLDP-Runner attempts reverse resolution. If a PTR name is returned, that name
becomes the initial preferred presentation and is retained as a name alias. If
reverse resolution fails, the normalized IP address is the initial
`preferred_name`.

The input IP address remains an address alias in either case.

### 3.4 Reusable `seeds.csv` input

The supported seed CSV can carry:

```text
preferred_name
queried_as
ipv4
ipv6
credential_profile
credential_result
origin
state
last_seen
notes
```

For identity input, `preferred_name` is normally the seed string. If it is
empty, a valid `queried_as` value can be used as the seed fallback.

`queried_as`, `ipv4`, and `ipv6` can contribute management-address hints from a
previous run. Those valid address hints are combined with fresh DNS results.
This is intentional so a later run can still reach a device when DNS is
temporarily incomplete.

The previous CSV `origin` does not remain authoritative. Any row supplied as
input to a new run is an explicit seed in that new run.

### 3.5 First-stage seed consolidation

Before DNS/state correlation, repeated logical seed strings are consolidated
case-insensitively. Address hints and parse diagnostics from repeated rows are
combined.

For example, two current-format CSV rows whose seed string is the same
`access-sw1` are treated as one seed input even if one row carries
`192.0.2.10` and the other carries `192.0.2.20`.

Later identity correlation can also merge different seed strings when DNS or
another alias shows that they refer to the same host.

## 4. Learned device input

### 4.1 Neighbor evidence

A successful CDP, LLDP, or LLDPv2 collection can create a learned candidate
with evidence such as:

```text
remote name
management addresses
chassis ID and subtype
remote port information
platform and description
capabilities
observing host and local interface
protocol-specific details
```

The observation becomes both identity evidence for the remote logical host and
an edge showing which queried host observed it.

### 4.2 Learned managed devices

LLDP-Runner first classifies the learned candidate. If it is a
`managed_device`, has a remote name, and
`discovery.resolve_discovered_managed_names` is enabled, the coordinator tries
DNS resolution for that learned name.

Resolver names and addresses are added to the enriched candidate and the
candidate is classified again. This allows DNS-provided FQDN/address evidence
to affect presentation, ownership classification, query policy, and recursive
scheduling. Beginning with 0.31.4, only the directly advertised protocol name
is admitted to global name identity during this path. DNS-only agreement cannot
merge unrelated devices that happen to resolve through the same load balancer,
anycast frontend, or shared service address.

If the learned managed host has one or more permitted management addresses, the
coordinator treats them as alternate addresses for the same logical device.
They are ordered by `discovery.address_preference` and then numerically within
an address family when a worker task is built.

### 4.3 Learned unmanaged and unknown devices

A candidate that is not classified as `managed_device` is not DNS-enriched by
this learned-name path. Its advertised name, observed management addresses,
and chassis ID still participate in identity correlation.

An unmanaged or unknown device with only a name can therefore still be folded
with later observations of that normalized name even though LLDP-Runner does
not query it.

### 4.4 Observations with no normal identity

A learned neighbor can occasionally have no usable name, address, or chassis
ID. LLDP-Runner creates a synthetic observation alias derived from the edge so
the evidence can still be represented without inventing a device name.

Such observations do not automatically correlate across unrelated edges
because there is no shared normal identity alias proving that they are the same
remote device.

### 4.5 Same-link protocol reconciliation

A queried device can advertise the same physical topology edge through more than
one discovery protocol. LLDP-Runner first attempts to reconcile those collector
rows before the remote host is inserted into authoritative state. A reconciled
edge records multiple protocols, for example:

```text
cdp,lldp
```

This prevents one physical connection from appearing twice merely because both
CDP and LLDP describe it. Protocol-specific evidence remains under keys such as
`cdp.*` and `lldp.*` so the original advertisements can still be reviewed.

There are two guarded reconciliation paths.

The strict path requires the same normalized local interface and remote
interface. Exact logical names can then reconcile directly. A device can also
append a serial-like token to an advertised name. Cisco Nexus
NX-OS commonly advertises a VDC through CDP as:

```text
hq-vdc2-7nx1.example.com(SERIAL000001)
```

while LLDP advertises the logical VDC System Name as:

```text
hq-vdc2-7nx1.example.com
```

LLDP-Runner preserves the raw advertisement and parses a plausible final
`(serial)` token into a separate logical base name and serial hint. The parser
requires a nonempty usable base and an alphanumeric token of 6 through 32
characters containing at least one digit. Text that does not meet that narrow
shape remains an ordinary raw name.

For a CDP/LLDP pair on the same normalized local and remote interfaces, the
logical base can compare with the undecorated name. This is deliberately an
edge-scoped rule. The serial hint is a moderate physical-container claim, not a
global host alias, because several VDCs can share one physical Nexus chassis
serial. A direct ENTITY-MIB or other trustworthy serial observation is needed
before the hint can support a physical-chassis conclusion.

The corroborated path handles devices whose protocols describe the same remote
port differently. For ordinary names it requires all of the following:

```text
CDP compared with LLDP or LLDPv2
same normalized local switch interface
at least one identical usable address
compatible protocol names
```

Usable address evidence normally comes from a protocol management-address field.
An LLDP chassis ID explicitly typed as `network_address` can also corroborate
the same address while remaining separately identified as chassis evidence in
the raw protocol details.

Compatible ordinary names include an exact normalized match. They also include
one single-label short name and one FQDN whose left-most host component is
exactly that short name. For example:

```text
CDP: phone1
LLDP: phone1.example.com
```

The ordinary rule does **not** strip arbitrary domain suffixes. Two different
FQDNs such as these remain different names even though the left-most labels
match:

```text
phone1.site-a.example.com
phone1.site-b.example.com
```

Likewise, an ordinary short/FQDN pair does not reconcile when the address
evidence differs or when the observations came from different local switch
ports. These restrictions keep generic DNS-name inference local to one strongly
corroborated physical edge.

Beginning with 0.31.2, Cisco `SEP` endpoints have a separate stronger identity
rule. If the left-most host component is exactly `SEP` followed by twelve
hexadecimal characters, those characters are decoded as the endpoint MAC. For
example, all of these contribute the same canonical MAC identity:

```text
SEP001234560004
SEP001234560004.voice-a.example.com
SEP001234560004.voice-b.example.net

00:12:34:56:00:04
```

This rule is intended for Cisco phones and Cisco video endpoints that advertise
the standard `SEP<MAC>` form. It is deliberately strict: LLDP-Runner does not
derive MAC identity from arbitrary names that merely end in hexadecimal text.

On the same local switch interface, matching strict SEP MAC identity is enough
to reconcile CDP and LLDP/LLDPv2 even when one protocol temporarily lacks a
management-address row. This covers a production pattern such as:

```text
CDP   SEP001234560004                  / Port 1
LLDP  SEP001234560004.voice-a.example.com  / 001234560004:P1
```

It also keeps the same physical endpoint when its reported DNS suffix changes
between `.voice-a...` and `.voice-b...`. The suffix remains useful for
presentation and
raw protocol evidence; the embedded SEP MAC supplies durable endpoint identity.

Beginning with 0.31.3, contradictory strict SEP MAC identities are a hard host
identity boundary. Two phones such as `SEP001234560001` and
`SEP001234560006` cannot become one host merely because both advertise the same
usable address or the same LLDP chassis ID typed as `network_address`. This
matters for endpoint software that reports a repeated/default address across
physically unrelated phones. Shared address evidence remains useful for normal
correlation, but it cannot override two different SEP-derived hardware MACs.

When remote-port strings differ on a corroborated CDP/LLDP edge, LLDP-Runner
prefers the LLDP typed Port ID for the normalized edge. The CDP and LLDP names,
ports, addresses, descriptions, capabilities, and chassis evidence are retained
under their protocol-specific `details` keys.

Because edge reconciliation happens before authoritative state insertion, one
reconciled physical connection produces one `learned_neighbors` row on the
observer and one reciprocal `observed_by_neighbors` row on the remote host. The
protocol list still shows that both CDP and LLDP contributed evidence.

CISCO-CDP-MIB `cdpCacheAddress` is retained as CDP entry-address evidence. It
can differ from the Primary Management Address printed by Cisco CLI. When a
CDP row reconciles with LLDP, LLDP management-address evidence is ordered first
for operator-facing display while all unique observed addresses remain available
in structured output and host correlation.

### 4.6 LLDP snapshot integrity

An LLDP remote table is obtained through multiple SNMP requests and columns. A
neighbor can be inserted, removed, or rebuilt while the walk is in progress. In
that case a collector can observe later columns from a row without having seen
its mandatory chassis-ID or Port-ID fields during the same walk.

Beginning with 0.31.1, LLDP-Runner does not convert such a partial row into host
or topology identity. Original LLDP and LLDPv2 require both mandatory identifier
pairs:

```text
chassis-ID subtype + chassis-ID
Port-ID subtype + Port-ID
```

If any pair is incomplete, the worker retries the complete protocol collector
once, including the management-address walk. A second structurally incomplete
snapshot is recorded as an `incomplete_table` collector error. Diff can then
classify topology affected by that failed protocol as uncertain instead of
presenting a partial table as definite network change.

Beginning with 0.31.2, an exception while walking the LLDP or LLDPv2
management-address subtable is also no longer converted into an empty address
set. Timeout and transport failures trigger the same complete-protocol retry. A
final failure is persisted as protocol collection loss, allowing diff to mark
affected topology uncertain. A successfully empty management-address table is
still valid and is distinct from a failed table walk.

LLDP-Runner also preserves the complete remote-row index while assembling table
columns. Original LLDP keeps `timeMark`, local-port number, and remote index as
one row key. LLDPv2 additionally keeps its local destination-MAC index context.
The `time_mark` value is retained for diagnostics but treated as volatile by
diff because it is a table locator rather than logical topology identity.

## 5. Internal normalization

### 5.1 Name normalization

Name aliases are normalized as follows:

```text
trim surrounding whitespace
remove trailing dots
convert to lowercase
```

Therefore these values represent the same name alias:

```text
ACCESS-SW1
access-sw1
access-sw1.
```

A short name and an FQDN are not equal merely because they look related:

```text
access-sw1
access-sw1.example.net
```

They become connected when DNS or another observation supplies shared evidence,
such as both names on one candidate or the same management address.

This global alias rule is separate from the generic edge-scoped reconciliation
in [section 4.5](#45-same-link-protocol-reconciliation). On one already
corroborated CDP/LLDP edge, a single-label short name can match the identical
left-most host component of an FQDN when local-port and address evidence also
agree. That generic edge decision does not register a suffix-derived global name
alias.

Strict Cisco `SEP<12-hex>` names are the narrow exception. The embedded twelve
hexadecimal characters become a canonical `mac` identity alias, so the short
form and FQDN forms can converge globally on the same Cisco endpoint without
asserting that their DNS suffixes are generally interchangeable.

### 5.2 Address normalization and host eligibility

IPv4 and IPv6 aliases are parsed with Python's standard `ipaddress` module and
emitted in canonical notation. LLDP-Runner does not rely on regular-expression
shape checks alone: several values are syntactically valid IP addresses but are
not plausible addresses for one remote host.

The canonical identity boundary rejects malformed addresses and these non-host
classes:

```text
IPv4 0.0.0.0/8       this-network / unspecified semantics
IPv4 127.0.0.0/8     loopback
IPv4 224.0.0.0/4     multicast
IPv4 240.0.0.0/4     reserved, including 255.255.255.255
IPv6 ::               unspecified
IPv6 ::1              loopback
IPv6 ff00::/8         multicast
```

IPv4-mapped IPv6 forms inherit the rejection semantics of their embedded IPv4
address, so an encoded limited-broadcast or reserved IPv4 value cannot bypass
the same boundary.

Private IPv4, CGNAT, benchmark/documentation ranges, IPv4 link-local, IPv6 ULA,
and IPv6 link-local remain eligible. LLDP-Runner can legitimately observe or
operate with those values; using a simple `is_global` test would incorrectly
discard useful management or control-plane evidence such as `169.254.100.10`.

A bare address does not carry a subnet prefix, so LLDP-Runner cannot safely
infer whether an otherwise valid unicast value such as `192.0.2.255` is a
directed
broadcast for the remote subnet. Boundary and query policy remain separate from
identity-address eligibility.

The same eligibility check is applied defensively at collector, seed, canonical
alias, network-address chassis-ID, and cross-run diff boundaries. For CDP, a
parsed `cdpCacheAddress` sentinel such as `0.0.0.0` remains visible under
`cdp.entry_addresses` for diagnostics but is omitted from `remote_addresses` and
cannot become an IPv4/IPv6 host alias.

A DNS name resolving to several eligible addresses can make all of those values
available to the same enriched candidate for policy and querying. Learned-host
identity remains anchored in directly observed evidence; DNS expansion by
itself is not permission to merge two established hosts.

Address claims are many-to-many beginning with 0.31.4. The first observation of
an address can still locate one host efficiently. If a later incompatible host
advertises the same value, both claims are retained and the address becomes
contested. Subsequent candidates need a unique name, MAC, chassis, or other
corroboration rather than inheriting whichever host first owned the address.

### 5.3 Chassis normalization

LLDP-Runner treats the chassis subtype as part of chassis identity. Equal text
advertised under different chassis subtypes therefore does not automatically
refer to the same internal alias.

Subtype-aware binary identifiers receive additional validation:

```text
mac_address     must decode as a six-octet MAC address
network_address must decode as a host-eligible IPv4 or IPv6 address
```

If an agent advertises one of those subtypes but LLDP-Runner can only preserve
the raw value as diagnostic `hex:...` text, that value remains in the neighbor
observation details but is not admitted to the canonical host identity registry.
This is intentionally conservative: malformed repeated values must not collapse
otherwise unrelated neighbors.

Not every syntactically valid chassis subtype has network-wide scope. Beginning
with 0.31.4, `chassis_component`, `interface_alias`, `port_component`, and
`interface_name` remain observation/agent-local evidence and are not registered
as global host aliases. Beginning with 0.31.5, a `network_address` chassis value
is retained as a weak edge-scoped claim and raw protocol evidence, but does not
enter the global IPv4/IPv6 identity lookup by itself. A separately advertised
management address remains its own direct address claim. These boundaries
prevent values such as VMware `vmnic2` or a repeated/default
`198.51.100.3` chassis value from merging unrelated endpoints at different
physical edges.

Beginning with 0.32.9, locally assigned chassis subtype 7 follows the same
scoped rule. A vendor-supplied local label or opaque value remains in raw
neighbor details and can still be shown to an operator, but it cannot select or
merge hosts across unrelated interfaces. Subtype 7 expressly permits local
assignment and therefore does not establish network-wide uniqueness.

For an otherwise anonymous observation, LLDP-Runner can use one exact,
explicitly typed MAC-address Port ID as bounded endpoint identity. The subtype
must identify a MAC address, the value must be a complete unambiguous MAC, and
all retained LLDP/LLDPv2 typed representations must agree. This fallback is not
used when a usable direct name, management address, or trusted chassis alias is
already available. If neither strong device identity nor a typed Port-ID MAC is
available, the compatibility projection retains its observation-scoped
fallback.

For accepted global chassis identity evidence, a separate case-preserving
display form is retained so canonical output can show the device-supplied
chassis value. LLDP and LLDPv2 always preserve chassis subtype evidence in
neighbor details even when that subtype is not eligible for global identity.
A locally assigned chassis label can be used as the operator-facing display name
when no system name is advertised. The label remains edge-scoped and cannot
become global identity evidence by itself.

## 6. Host correlation and intentional folding

### 6.1 Why folding exists

Network topology is a graph. It is normal for the same switch or router to be
reported by several neighboring devices.

For example:

```text
core-a learns dist-1 at 192.0.2.10
core-b learns dist-1 at 192.0.2.10
access-a learns dist-1 by chassis ID
```

Creating three top-level host records would inflate inventory counts and could
schedule redundant SNMP work. LLDP-Runner instead accumulates matching evidence
into one authoritative host whenever its identity aliases connect the
observations.

This design supports:

```text
one device observed from many links
one device with short and fully qualified names
one device with IPv4 and IPv6 management addresses
one device with more than one management address
one device first learned by name and later learned by chassis ID
one learned device that later overlaps an explicit seed
```

### 6.2 Alias matching

When a candidate reaches the state store, LLDP-Runner looks up its normalized
identity aliases and address claims. A unique address can identify one existing
host, but a value already claimed by several hosts is contested and is not used
to select all of them.

If none of the compatible aliases belong to an existing host, a new host is
created. If compatible aliases belong to an existing host, the new evidence can
be folded into that logical host. If one candidate connects aliases that already
belong to several compatible host records, the coordinator can merge those
records so the graph has one logical identity. The merge preserves important
topology, classification, seed, tag, error, and successful query evidence.

The coordinator protects host IDs actively owned by workers rather than
invalidating an in-flight task. A later observation can reconcile records when
it is safe to do so.

### 6.3 Identity conflict protection and corroboration

LLDP-Runner deliberately balances two failure modes:

```text
too little consolidation  -> duplicate records for one logical host
too much consolidation    -> multiple discrete hosts incorrectly become one
```

No single evidence type is universally authoritative on every platform. Chassis
IDs are useful physical evidence, but some systems advertise different valid
LLDP chassis MACs on different links. Names and addresses are useful logical
evidence, but duplicate names and reused addresses can also exist. Correlation
therefore considers combinations of evidence rather than assuming one field is
always decisive.

The current conflict policy can be summarized as follows:

| Evidence | Default decision |
| --- | --- |
| Name + address match; chassis matches | Fold |
| Name + address match; chassis differs | Fold |
| Name matches; address and chassis differ | Keep separate |
| Address matches; name and chassis differ | Keep separate / unresolved |
| Address matches; names conflict | Keep separate; retain address claims |
| Names + addresses differ; chassis matches | Keep separate |
| Device-local chassis text matches | Keep separate without other identity |
| Anonymous typed Port-ID MAC matches | Fold that endpoint |
| Anonymous typed Port-ID MAC differs | Keep separate |
| Only malformed chassis matches | Keep separate |
| Nexus physical serial matches; VDC identity differs | Keep separate |

A candidate with a different trusted chassis identity is therefore normally
considered contradictory. The important exception is when both a normalized
name and at least one normalized management address already agree. That pair of
logical identity signals is strong enough to support platforms such as Nexus
7000 VDCs whose LLDP chassis MAC can vary by link.

A chassis-only match remains rejected when both sides have non-empty names and
management-address sets and those sets are disjoint. This retains the safeguards
for devices that reuse, misencode, or otherwise advertise non-unique chassis
information.

For example, these observations remain separate:

```text
phone-a / 192.0.2.10 / chassis 00:11:22:33:44:55
phone-b / 192.0.2.20 / chassis 00:11:22:33:44:55
```

The shared chassis value has no corroboration because both the names and
management addresses disagree.

By contrast, these observations can fold normally even when the chassis value
changes between links:

```text
dist-1 / 192.0.2.10 / chassis 00:11:22:33:44:55
dist-1 / 192.0.2.10 / chassis 00:11:22:33:44:66
```

The matching name and management address corroborate one logical device. Both
observation-specific chassis values remain available for review.

### 6.4 Duplicate names remain an ambiguity

The conflict checks do not make names globally unique. Two devices using the
same name can be consolidated when no contradictory trusted chassis identity is
available. This is necessary for common cases where one observation supplies a
name and another later adds a management address.

For example:

```text
name=access-sw1
ipv4=192.0.2.10
```

and later:

```text
name=access-sw1
ipv4=192.0.2.20
```

can still become one logical host when there is no stronger physical evidence
showing that the observations describe different devices. Operators should not
therefore use `preferred_name` as a unique key, and all managed devices should
be configured with unique names.

### 6.5 VMware ESXi CDP sentinel example

Some VMware ESXi CDP advertisements contain no usable Entry address. On certain
Cisco SNMP agents, that absence is represented by `cdpCacheAddress=0.0.0.0`.
Several unrelated ESXi systems can therefore all appear with distinct CDP Device
IDs but the same syntactically valid placeholder address.

Before 0.30.8, `0.0.0.0` could enter the IPv4 alias registry and connect those
discrete systems into one host record. The resulting aggregate could accumulate
many unrelated ESXi names, allowing an operator-facing preferred name from one
site to appear on a neighbor observed at another site.

Beginning with 0.30.8, `0.0.0.0` is diagnostic evidence only. Distinct ESXi CDP
names remain distinct hosts unless some other valid identity evidence connects
them. Repeated observations of the same ESXi Device ID can still fold normally
through the shared name alias.

### 6.6 Cisco Nexus VDC example

Cisco Nexus 7000-series Virtual Device Contexts illustrate why LLDP-Runner must
distinguish physical-chassis evidence from logical-host identity. One physical
Nexus can host several separately named and addressed VDCs, for example:

```text
hq-vdc1-7nx1.example.com
hq-vdc2-7nx1.example.com
hq-vdc3-7nx1.example.com
```

CDP can append the same physical serial token to all three Device IDs while LLDP
advertises the undecorated VDC System Names. The VDCs remain separate hosts
because their logical names and management addresses differ. The shared
physical serial is not promoted into the host alias registry.

The same VDC can also be connected by several links while advertising a
different valid LLDP chassis MAC on each link. When its normalized VDC name and
management address agree, LLDP-Runner allows those observations to fold into one
logical host and retains each link-specific chassis value in its edge details.

This treatment avoids both sides of the consolidation problem: duplicate CDP
and LLDP rows for one VDC are reduced to one edge, while different VDCs on the
same physical Nexus remain discrete logical hosts.

Cross-run `lldp-runner diff` applies the same distinction. A serial shared by
several VDC host records is treated as physical-container evidence rather than
a sufficient logical-host key. Diff narrows those candidates using matching
normalized VDC name plus management address. A per-link chassis-ID difference
can be tolerated under that same two-signal corroboration, while serial or SNMP
engine conflicts remain blocking evidence. See [DIFF.md](DIFF.md) for the
complete
cross-run pairing rules.

### 6.7 Order-independent bridge reconciliation

The global alias table intentionally gives each normalized name and accepted
chassis identity one owner. Address claims are many-to-many in 0.31.4. During
concurrent recursive discovery, an early contradictory observation can still
create a temporary split host whose duplicate name cannot own the
already-registered alias.

Version 0.31.0 introduced later strong-evidence repair, and 0.31.4 applies it
across the global-name and many-to-many address model. Conflict evaluation can
use a temporary host's usable `preferred_name` and management addresses retained
on inbound neighbor observations even when the name could not own the global
alias or the address is contested.

The repair remains conservative. A later candidate must connect the records
with both:

```text
same normalized logical name
+
at least one shared usable management address
```

Only then can link-specific chassis disagreement be tolerated and the temporary
records merged. Duplicate name alone is not a reconciliation trigger. This
removes observation-order dependence for Nexus-style logical devices without
turning `preferred_name` into a unique key.

### 6.8 Placeholder names are diagnostic, not identity

Some protocols or devices explicitly advertise missing-value text instead of
omitting a name. Common examples include:

```text
unknown
null
none
(none)
(none).(none)
n/a
na
-
not advertised
```

Beginning with 0.31.0 these values are not admitted into the canonical `name`
alias namespace and are not used as cross-run name evidence. The raw protocol
field can remain visible in neighbor details or presentation output so the
operator can see what the device actually advertised.

This boundary prevents a repeated placeholder such as `null` from becoming a
global correlation key for unrelated endpoints. It does not reject arbitrary
generic strings merely because they are poor naming practice; only explicit
missing-value sentinels receive this treatment.

### 6.9 Malformed chassis example

A production case that motivated the 0.30.3 safeguards involved several Cisco
phones learned through LLDP from the same switch. The phones supplied different
system names, management IPv4 addresses, and Port IDs, while their collected
chassis field repeated the same malformed subtype-5 diagnostic value:

```text
SEP...A / 192.0.2.191 / hex:15:00:00:00:00:00
SEP...B / 192.0.2.206 / hex:15:00:00:00:00:00
SEP...C / 192.0.2.115 / hex:15:00:00:00:00:00
```

Because subtype 5 means `network_address`, the `hex:...` value is retained as
observation evidence but is not eligible to identify a canonical host. The
three names and management addresses therefore remain separate host records,
and `show-neighbors` can render the same distinct names collected by
`get-neighbors`.

## 7. How `preferred_name` is selected

`preferred_name` is generated in stages rather than being a single raw input
field.

### 7.1 New explicit seed

For a hostname seed, resolver output prefers an available FQDN-like name, then
another name. For an IP seed, a reverse-resolved name is preferred when
available; otherwise the normalized IP address is used.

### 7.2 New learned host

For a learned candidate, presentation prefers:

```text
an available name containing a dot
otherwise the first available name
otherwise the first management address
otherwise unknown
```

### 7.3 Later observations

An `unknown` presentation can be replaced when better evidence appears. The
state preference heuristic also favors a later candidate containing a dot over
an existing dotless presentation, while excluding colon-bearing IPv6 text. An
IPv4 address contains dots too, so a state row can temporarily prefer an IPv4
value when a later address-only observation is connected to a dotless name.

Canonical output corrects the important presentation case: when normalized
name aliases exist and the stored presentation is an IP or `unknown`, output
promotes an actual name alias. Otherwise the existing presentation normally
remains stable rather than changing whenever another alias is learned.

This means `preferred_name` is not a deterministic sort of every known alias.
Observation order and which useful presentation was established first can
matter.

### 7.4 Output-time name promotion

When canonical output is assembled, a stored `unknown` or IP presentation can
be promoted to an available normalized name alias. An FQDN-like alias is
preferred when one exists.

The optional `output.chassis_id_name_fallback` policy can also use a suitable
chassis ID as the displayed name when there is no real observed/resolved name
and the stored presentation is missing, `unknown`, or an IP address.

A genuine observed name outranks chassis fallback.

Canonical output then applies four narrowly scoped presentation corrections
that are shared by `discovery.json`, fixed CSVs, and custom CSV projections:

1. A recognized trailing hardware serial decoration is omitted from the display
   value. For example, `hq-vdc1-7nx1.example.com(SERIAL000001)` is presented as
   `hq-vdc1-7nx1.example.com`. The guarded parser requires a plausible
   alphanumeric serial token containing a digit; ordinary descriptive
   parentheses are not cropped. The raw advertisement/serial claim remains
   available as evidence.
2. When the resulting name is `unknown`, every inbound observed name and remote
   description is blank, and all inbound chassis evidence is locally assigned
   and yields exactly one value, that string is used as the display name.
   Locally assigned subtype 7 remains edge-scoped and is not promoted into
   global identity merely because it is useful for output review.
3. Under the same blank-name and blank-description conditions, one unambiguous
   MAC-address-typed chassis value is the next fallback for `unknown`. It is
   rendered as a canonical lowercase, colon-separated MAC address. A nonblank
   observed name or description prevents this substitution.
4. When the resulting name is `null` or `not advertised`, all nonblank inbound
   names and descriptions contain only those placeholders, and all inbound
   chassis evidence is MAC-address typed and yields exactly one value, the
   canonical colon-separated MAC is used as the display name.

The chassis substitutions require one unambiguous value and consistent subtype
evidence. Conflicting candidates or mixed subtype classes leave the placeholder
unchanged rather than guessing. These rules run after normal alias promotion
and alter only the canonical presentation field; raw protocol names,
descriptions, chassis subtypes/values, aliases, and topology identity decisions
remain unchanged.

### 7.5 Why it is not unique

`preferred_name` has no uniqueness constraint and must not be treated as a
primary key by operators or downstream applications.

Possible duplicate presentation values include:

```text
multiple separate unknown identities rendered as unknown
records created from distinct evidence that happen to present the same label
CSV rows repeated by a one-to-many output such as switch stack members
```

In the normal neighbor path, two candidates carrying the exact same normalized
name alias are usually folded into one host rather than emitted as two hosts.
That behavior still does not turn `preferred_name` itself into a unique field.

## 8. Name and address output in `discovery.json`

`discovery.json` is the canonical result and the best place to investigate
identity questions.

A host contains fields including:

```text
id
preferred_name
queried_as
snmp_sysname
classification
state
is_seed
names
addresses.ipv4
addresses.ipv6
chassis_id
learned_neighbors
observed_by_neighbors
```

### 8.1 `names`

`names` contains normalized name aliases associated with the logical host.
Because aliases are normalized for matching, these values are normally
lowercase and have no trailing dot.

The list can contain more than one name, such as a short name plus an FQDN.

### 8.2 `addresses`

`addresses.ipv4` and `addresses.ipv6` contain the known normalized management
address aliases associated with the host. More than one address is normal and
can represent dual-stack or multi-address management for one device.

When duplicate device names have caused unintended folding, multiple addresses
can instead be evidence that several physical devices were consolidated.
Context is required.

### 8.3 `chassis_id`

The canonical host object has one top-level `chassis_id` field representing
chassis evidence accepted for host identity. Neighbor edge details retain the
observation-specific chassis value and subtype even when that value was rejected
as malformed or contradictory identity evidence.

Therefore a malformed subtype-aware chassis value can appear under a neighbor's
`details` while being absent from the referenced host's top-level `chassis_id`.
That distinction is intentional and keeps diagnostic collector evidence without
allowing it to consolidate unrelated devices.

### 8.4 Topology evidence

`learned_neighbors` describes devices learned by the current queried host.
`observed_by_neighbors` describes inbound evidence where another queried host
reported the current host.

Neighbor records preserve useful observation evidence including:

```text
host_ref
observed_name
observed_addresses
protocols
interfaces
protocol-specific names and addresses
protocol-specific chassis/Port ID details
```

For reconciled CDP/LLDP edges, `observed_addresses` is a de-duplicated union
with LLDP management addresses ordered before CDP entry addresses. Raw evidence
remains distinguishable under protocol-specific fields such as
`lldp.remote_addresses`, `cdp.remote_addresses`, and `cdp.entry_addresses`.

The details can include chassis ID/subtype and LLDP Port ID information. This
observation-level evidence is particularly useful when a logical host has
several addresses or appears at several network locations.

## 9. Name and address output in fixed CSV files

Fixed CSV files are generated from the canonical discovery document. They are
intentionally flatter than JSON.

### 9.1 `hosts.csv`

`hosts.csv` has one row per logical host. Useful identity/presentation columns
include:

```text
preferred_name
queried_as
snmp_sysname
origin
classification
state
ipv4
ipv6
learned_neighbors
observed_by_neighbors
```

The `ipv4` and `ipv6` columns join multiple addresses with semicolons.

The fixed file does not include the JSON host `id` or a top-level chassis ID.
A consumer that requires an unambiguous per-run host reference should use
`discovery.json` or configure a custom CSV field such as `json.host.id`.

### 9.2 `stack-members.csv`

This file has one row per physical stack member. Logical-host fields including
`preferred_name`, `queried_as`, IPv4/IPv6 addresses, and state are repeated for
every member.

`preferred_name` is therefore intentionally repeated even when there is no
identity collision.

### 9.3 `seeds.csv`

Despite its filename, this is the reusable managed-device inventory. It
includes both original seeds and learned managed devices.

Its identity/presentation fields are:

```text
preferred_name
queried_as
ipv4
ipv6
origin
state
```

`preferred_name` is not a unique row key. If reused as later input, rows are
processed under the seed-input rules described earlier in this document.

### 9.4 `unknown-devices.csv`

This file concentrates review evidence for `unknown_device` records. In
addition to `preferred_name`, addresses, and inbound topology, it includes
aggregated observation fields such as:

```text
observed_names
observed_chassis_ids
observed_chassis_id_subtypes
observed_chassis_id_subtype_ids
```

Those fields make this CSV especially useful for reviewing unnamed or
incompletely identified neighbors. The fixed view intentionally omits
`manufacturer` and `model` because live unknown-neighbor records do not populate
those system fields. The same-source `unknown-devices.manufacturer` and
`unknown-devices.model` selectors are not accepted. Use the canonical JSON
selectors `json.host.system.manufacturer` and `json.host.system.model` when a
record contains those values.

### 9.5 `errors.csv`

`errors.csv` can contain repeated `device` values because one host can have many
errors and because the device label is a presentation value. `query_target`
records address context when available.

The `device` column must not be treated as a unique host key.

### 9.6 Custom CSV output

Custom CSV reports can project canonical JSON fields. A site that needs a
per-run identity column can include `json.host.id` together with
`json.host.preferred_name`, address fields, and other required evidence.

Both `hosts.preferred_name` and `json.host.preferred_name` read the same
canonical output-time value, including guarded serial-suffix removal and the
unambiguous placeholder chassis fallbacks described in section 7.4.

The JSON host ID is reliable only within that discovery result. Sites that need
cross-run durable inventory correlation should use their own authoritative
inventory identity and compare several LLDP-Runner evidence fields rather than
assuming either `id` or `preferred_name` is permanent.

## 10. Use cases

### 10.1 Same physical switch learned from several devices

Incoming evidence:

```text
core-a -> dist-1 / 192.0.2.10
core-b -> dist-1 / 192.0.2.10
access-a -> dist-1 / chassis 00:11:22:33:44:55
```

Expected behavior:

- shared aliases connect the observations;
- LLDP-Runner intentionally folds them into one logical host;
- topology edges from all observing devices are retained;
- the host can accumulate several names and management addresses;
- only one logical host is eligible for recursive scheduling.

This is the primary reason identity folding exists.

### 10.2 Same learned name with different IP addresses

Incoming evidence:

```text
access-sw1 / 192.0.2.10
access-sw1 / 192.0.2.20
```

Current behavior:

- both observations share `name=access-sw1` after normalization;
- the second observation can reuse the existing logical host;
- both addresses can become aliases of that one host;
- worker scheduling treats the addresses as alternate management addresses for
  one device;
- one top-level host row is normally emitted rather than two.

If those IPs actually belong to two devices with a duplicated network name,
the output can incorrectly consolidate the two devices.

### 10.3 Same learned name, no IP address, different chassis IDs

Incoming evidence:

```text
phone-01 / no management address / trusted chassis A
phone-01 / no management address / trusted chassis B
```

Current behavior:

- the shared normalized name initially points toward the existing logical host;
- the different trusted chassis identity is treated as contradictory evidence;
- the observations remain separate host records rather than being folded by the
  duplicate name.

If the chassis values are absent or are malformed subtype-aware values that are
not trusted for identity, the duplicate name remains ambiguous and can still
consolidate the observations.

### 10.4 Different names with the same management address

Incoming evidence:

```text
dist-1 / 192.0.2.10
dist-1.example.net / 192.0.2.10
```

Current behavior:

- the shared normalized IP address is strong connecting evidence in the current
  alias model;
- the observations are folded into one logical host;
- both names can be retained in `names`;
- an FQDN-like value can become the preferred presentation.

This is a normal and desirable merge for short-name/FQDN aliases.

### 10.5 Different names and addresses with the same chassis ID

Incoming evidence:

```text
dist-old / 192.0.2.10 / trusted chassis A
dist-new / 192.0.2.11 / trusted chassis A
```

Current behavior:

- the shared chassis ID is the only matching identity evidence;
- both sides have non-empty names and management addresses;
- both the name sets and address sets are disjoint;
- LLDP-Runner conservatively keeps the records separate.

This can split a device that was simultaneously renamed and re-addressed, but it
avoids silently merging two devices when an agent reuses a chassis identifier.
When trusted chassis IDs conflict, automatic reconciliation requires both a
shared normalized name and at least one shared management address.

### 10.6 Nexus VDC seen through CDP and LLDP

Incoming evidence on one source port:

```text
LLDP  hq-vdc2-7nx1.example.com                 Eth1/2  192.0.2.46
CDP   hq-vdc2-7nx1.example.com(SERIAL000001)   Eth1/2  198.51.100.17
```

Current behavior:

- matching normalized local and remote interfaces identify one candidate edge;
- the guarded decorated-name parser separates logical base and serial hint;
- the undecorated VDC name is used as the logical comparison name;
- the raw CDP Device ID and entry address remain under `cdp.*` details;
- the serial hint remains non-merging unless direct serial evidence
  corroborates it;
- LLDP management addresses are ordered first in the merged observation;
- both protocols are retained as `cdp,lldp`.

If another link to that same VDC has the same logical name and management
address but a different valid LLDP chassis MAC, the host can still fold because
name-plus-address evidence corroborates one logical device. A different VDC that
shares only the physical Nexus serial remains a separate host.

### 10.7 Short name and FQDN without connecting DNS evidence

Incoming evidence:

```text
access-sw1
access-sw1.example.net
```

The strings are different normalized name aliases. LLDP-Runner does not infer
that one is a suffix-expanded form of the other by text alone.

If configured DNS resolution supplies a shared address or supplies both name
forms on one candidate, the identities can merge. If DNS does not connect the
evidence, separate records are possible.

### 10.8 No name and no address, but a chassis ID exists

Incoming evidence:

```text
no name / no address / trusted chassis A
```

A trusted chassis ID is sufficient identity evidence. Repeated observations of
that same typed chassis alias can fold into the same logical host. If a binary
MAC/network chassis value is malformed, it is not trusted and the edge-derived
synthetic observation identity is used instead.

### 10.9 No name, no address, and no chassis ID

There is no normal identity alias to correlate. LLDP-Runner uses an
edge-derived synthetic observation alias so the neighbor can still be recorded.
Different unrelated edges are not automatically folded merely because both
lack identity information.

### 10.10 Two separate identities both render as `unknown`

Two hosts can have different chassis or synthetic observation identities while
both have no usable operator-facing name.

The top-level output can therefore legitimately contain:

```text
host id 101 -> preferred_name=unknown
host id 145 -> preferred_name=unknown
```

This directly demonstrates why `preferred_name` is not unique.

### 10.11 Duplicate explicit seed names in reusable inventory

If two imported seed rows use the same logical seed name, first-stage seed
consolidation combines them. Their address hints can become one seed's set of
addresses before coordinator identity correlation begins.

Operators should not represent two physical devices with the same seed name and
expect separate discovery records merely because different IP columns are
present.

### 10.12 Duplicate SNMP `sysName` values

Two queried hosts can return the same `snmp_sysname`. The field remains visible
on each queried host record.

A newly learned `sysName` can be added as a normalized name alias only when that
alias is available. If another host already owns it, the later alias insertion
is ignored. `snmp_sysname` is therefore useful as a conflict indicator and must
not be treated as a uniqueness guarantee.

## 11. Operator review for suspected duplicate names

### 11.1 Network naming recommendation

Every managed and unmanaged device that advertises a device name should use a
unique name across the discovery scope.

Operators should change the configured name of devices that reuse a duplicate,
non-unique name. Unique naming improves LLDP/CDP interpretation, DNS behavior,
SNMP troubleshooting, inventory correlation, and LLDP-Runner identity quality.

LLDP-Runner does not currently enforce this requirement. The current behavior
should therefore be treated as a reason to correct network naming, not as a
substitute for unique device configuration.

### 11.2 Start with `discovery.json`

When a host looks suspicious, compare more than `preferred_name`:

```text
hosts[].id
hosts[].preferred_name
hosts[].snmp_sysname
hosts[].names
hosts[].addresses
hosts[].chassis_id
hosts[].queried_as
hosts[].learned_neighbors
hosts[].observed_by_neighbors
```

For inbound observations, compare `observed_name`, `observed_addresses`,
interfaces, protocols, and `details.chassis_id` where present.

A host carrying several addresses is not automatically wrong. Routers,
switches, stacks, and dual-stack devices commonly have several valid management
addresses. Suspicion increases when the addresses, chassis evidence, physical
ports, SNMP system identity, or network location are inconsistent with one
physical device.

### 11.3 Find duplicate presentation names

A simple first check is:

```bash
jq -r '.hosts[].preferred_name' discovery.json | sort | uniq -d
```

This finds duplicate top-level presentation values. It does not find the more
important case where two physical devices have already been folded into one
host because they advertised the same name.

### 11.4 Review one suspicious logical host

For a suspected name, inspect the full canonical record:

```bash
jq '.hosts[] | select(.preferred_name == "access-sw1")' discovery.json
```

Pay particular attention to:

```text
multiple unexpected management subnets
an SNMP sysName that conflicts with neighbor-advertised names
inbound observations from incompatible physical locations
multiple observation-specific chassis IDs
unexpectedly different remote Port IDs or descriptions
```

For `unknown_device` records, `unknown-devices.csv` also provides flattened
`observed_names` and observed chassis aggregates for convenient review.

### 11.5 Fixed CSV consumers

Do not use `preferred_name` alone as a database key when importing fixed CSV
files.

If a workflow requires an unambiguous per-run host reference, use
`discovery.json` or a custom CSV containing `json.host.id`. When matching across
runs, combine authoritative site inventory with names, addresses, SNMP
`sysName`, chassis/serial information, and topology context as appropriate.

### 11.6 Deterministic interface observation groups

A local interface can legitimately contain more than one protocol
advertisement. Examples include several Nexus VDC logical agents sharing one
physical management attachment and CDP or LLDP frames forwarded by an
intermediate transparent device. LLDP-Runner preserves all members in one
deterministic graph relationship group. Observation completeness is independent
from provisional entity resolution and unresolved directness.

Members are compared and rendered in a canonical order based on normalized
identity, protocol, remote port, multiplicity, and immutable evidence
fingerprints. SNMP table row order therefore cannot create a topology
difference. A group with several systems is marked for operator review and uses
`directness=unresolved`; LLDP-Runner does not label a member direct, downstream,
or passed through without independent evidence.

The flat `hosts[].learned_neighbors` array remains a compatibility projection.
Cross-run graph correspondence can describe a one-to-many split, many-to-one
merge, many-to-many reassociation, or duplicate absorption without forcing the
result into a one-host-to-one-host table.

Before compatibility macro diff performs one-to-one pairing, it conservatively
folds duplicate complete managed-host rows supported by compatible direct
logical names and at least one shared host-eligible management address. Exact
names are compatible, and one short name may match the same left-most component
of one FQDN. Two FQDNs are never matched merely by removing their suffixes.
Conflicting serial, SNMP-engine, strict MAC, chassis, or logical-name evidence
prevents the fold. Neighbor references are remapped and duplicate projected rows
are removed
only for the diagnostic comparison; immutable graph advertisements remain
unchanged. During discovery, the state owner applies the same conservative
name-and-address boundary before worker claims and after worker shutdown to
reduce redundant SNMP collection.

## 12. Current safeguards, limitations, and future review

The current evidence-strength boundaries include:

```text
malformed subtype-aware chassis ID -> retain as observation evidence only
conflicting trusted chassis IDs -> keep identities separate
chassis-only match + disjoint names and addresses -> keep identities separate
device-local chassis subtype -> never a global host alias
anonymous typed Port-ID MAC -> bounded identity when no stronger alias exists
named/addressed Port-ID MAC -> edge evidence, not host identity
repeated address -> retain as contested claim, not a forced merge
DNS-only agreement -> enrichment only, not a host union
disjoint strict SEP MACs -> hard identity conflict
weak/low-entropy MAC-only cross-port match -> ambiguous candidate_move only
complete empty optional ENTITY-MIB table -> not proof of hardware removal
```

The schema-7 graph is intentionally conservative. It separates physical
chassis, logical systems, observed systems, interfaces, advertisements, and
relationships, but it does not yet provide a calibrated probability for every
possible name/address/topology conflict. Duplicate names remain weak evidence;
physical serials associate logical systems with a chassis but do not merge the
logical systems themselves.

Diff exposes categorical pairing confidence and the exact evidence used. Those
categories improve explainability but are not calibrated probabilities
and do not replace operator validation against authoritative inventory.

Future review can consider broader evidence weighting, collision warnings, or
additional identity output without discarding the useful graph folding behavior
that prevents normal duplicate polling. Any stricter rule must account for the
legitimate fact that a router or switch can have several addresses, names,
interfaces, and observation paths.

The operational rule remains straightforward:

**Use unique device names throughout the network and correct duplicate names
when they are found.**

## 13. Related references

- [RUN.md](RUN.md) describes the run phases around seed identity resolution.
- [DNS.md](DNS.md) describes startup seed DNS modes and the supplied
  name/address
  evidence that can be reused without changing learned-neighbor DNS enrichment.
- [DIFF.md](DIFF.md) describes cross-run host matching and identity uncertainty.
