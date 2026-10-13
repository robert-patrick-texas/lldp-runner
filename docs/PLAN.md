# Enterprise Configuration Planning Guide

This guide shows one practical way to configure LLDP-Runner for a large
enterprise where Network Operations (NetOps) manages part of the network and
customers or other teams manage the rest.

The example is intentionally policy-oriented. Replace every example hostname,
CIDR, environment-variable name, and secret source with values appropriate for
your site.

The main design goal is to keep the configuration understandable over time:

```text
classification  decides what a discovered neighbor represents
query policy    decides whether LLDP-Runner may contact it
credentials     decide how an allowed managed device authenticates
tagging         adds operator/reporting labels without changing query behavior
```

Do not use credentials to decide ownership. Do not use tags to decide whether a
device may be queried. Keeping these jobs separate makes policy easier to audit.

For the detailed credential execution model, also read [CREDS.md](CREDS.md).

## 1. Start with ownership boundaries

Before writing TOML, list the enterprise facts that change slowly:

- NetOps infrastructure IPv4 and IPv6 management ranges;
- customer or other-team address ranges that must not be queried;
- dedicated endpoint ranges for phones, wireless, printers, or workstations;
- stable NetOps naming conventions;
- stable unmanaged/customer naming conventions;
- device families that require credentials other than the normal default; and
- the small set of exceptional devices that need host-specific credentials.

Prefer a subnet or naming convention over a list of individual hosts whenever
that convention is trustworthy. Individual-host policy should be the exception.

This example uses documentation-only networks:

```text
192.0.2.0/25          normal NetOps infrastructure
192.0.2.128/27        NetOps WTI remote consoles
192.0.2.160/27        NetOps UPS/PDU equipment
192.0.2.192/27        NetOps Palo Alto firewalls
198.51.100.0/25       customer/unmanaged phones
198.51.100.128/25     customer/unmanaged wireless endpoints
203.0.113.0/25        office printer networks
203.0.113.128/25      other customer-managed equipment
2001:db8:100::/48     normal NetOps infrastructure IPv6
2001:db8:110::/48     NetOps WTI IPv6
2001:db8:120::/48     NetOps UPS/PDU IPv6
2001:db8:130::/48     NetOps firewall IPv6
2001:db8:200::/56     customer/unmanaged phones IPv6
2001:db8:201::/56     customer/unmanaged wireless IPv6
2001:db8:300::/48     other customer-managed equipment IPv6
```

If one subnet contains mixed ownership, do not classify the entire subnet as
managed or unmanaged merely for convenience. Use naming/evidence rules there.

## 2. Keep the seed inventory deliberate

Seeds are explicit starting points and are treated as managed devices. Keep the
seed list limited to devices NetOps actually intends to contact.

A good large-site seed list normally includes stable core/distribution devices
from each major location plus any exceptional device that must receive a
seed-credential overlay.

For example:

```text
core-01.example.net
core-02.example.net
dist-east-01.example.net
dist-west-01.example.net
exception-device-01.example.net
exception-device-02.example.net
```

Do not add customer devices merely because they are visible in topology.
Learned neighbors can still be retained in discovery output without becoming
seeds.

A seed-credential file is an overlay, not another seed list. Therefore
`exception-device-01.example.net` must exist in a normal seed source before a
matching seed-credential record can affect it.

## 3. Use a broad enterprise boundary and a narrow query policy

`discovery.boundaries` determines recursive discovery scope. It is reasonable
to cover the enterprise-routed space that can contain topology neighbors, but
a production site should normally avoid the built-in `0.0.0.0/0` and `::/0`
defaults.

Query policy should then provide a second, stricter safety layer. For an
enterprise with substantial customer-owned equipment, a default-deny query
policy is easier to reason about than trying to enumerate every possible
unmanaged device.

Conceptually:

```text
inside enterprise boundary
  + classified managed_device
  + query policy allows contact
  = eligible for recursive SNMP
```

Known customer/unmanaged networks should be explicit denies. Known NetOps
management networks should be allows. Trusted NetOps naming conventions can be
allow rules for managed devices that appear outside a known management subnet.

One-off addresses can use `/32` IPv4 or `/128` IPv6 rules. That is preferable
to inventing a hostname pattern for a device that is exceptional only by
address. A most-specific deny will override a broader address allow.

## 4. Make one credential the ordinary default

The example enterprise uses these credential families:

```text
DefaultV2      SNMPv2c, normal switches/routers, and unknown new NetOps devices
ConsoleV2  SNMPv2c, WTI DSM remote console appliances
PowerV2    SNMPv2c, APC/Eaton UPS and PDU devices
FirewallV3   SNMPv3 authPriv, Palo Alto firewalls
ExceptionV3 SNMPv3 authPriv, explicit exception seed devices
```

Keep DefaultV2 as the configured default profile. Do not create a broad
DefaultV2 address rule; the default profile already provides that behavior.
Then define only the narrower WTI, power, and firewall exceptions.

This gives the credential decision a simple shape:

```text
specific device-family address rule
  -> specific device-family name rule
  -> DefaultV2 default profile
```

The special `ExceptionV3` profile is intentionally not selected by normal
credential rules. It is reached only through the seed-credential overlay.

## 5. Recommended example configuration

The following example is one complete policy-oriented `config.toml`. It omits
unrelated tuning options so the ownership and credential decisions remain easy
to see.

For a mature site, the rule sections can be moved to lexical `conf.d` files such
as `10-credentials.toml`, `20-query-policy.toml`,
`30-classification.toml`, and `40-tagging.toml`. See
[PRECEDENCE.md](PRECEDENCE.md) before splitting ordered rule lists.

```toml
[paths]
persistent_root = "/var/lib/lldp-runner"
scratch_root = "/var/tmp/lldp-runner"

[time]
timezone = "America/Denver"

[discovery]
boundaries = [
  "192.0.2.0/24",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "2001:db8::/32",
]
seed_files = ["/opt/lldp-runner/seeds.txt"]
workers = "auto"
batch_size = 9
max_devices = 0
max_hosts = 200000
address_preference = ["ipv4", "ipv6"]
resolve_discovered_managed_names = true

[snmp]
backend = "pysnmp"
version = "3"
timeout_seconds = 3.0
max_repetitions = 20

[icmp]
enabled = true
probes = 2
backend = "auto"

[logging]
level = "INFO"
console = true
file = true
filename = "activity.log"

[credentials.default-v2]
version = "v2c"
community_env = "LLDP_SNMP_DEFAULT"

[credentials.console-v2]
version = "v2c"
community_env = "LLDP_SNMP_CONSOLE"

[credentials.power-v2]
version = "v2c"
community_env = "LLDP_SNMP_POWER"

[credentials.firewall-v3]
version = "v3"
username = "snmp-firewall"
auth_password_env = "LLDP_SNMP_FIREWALL_AUTH"
priv_password_env = "LLDP_SNMP_FIREWALL_PRIV"
auth_protocol = "sha1"
priv_protocol = "aes128"

[credentials.exception-v3]
version = "v3"
username = "snmp-exception"
auth_password_env = "LLDP_SNMP_EXCEPTION_AUTH"
priv_password_env = "LLDP_SNMP_EXCEPTION_PRIV"
auth_protocol = "sha1"
priv_protocol = "aes128"

[credential_profiles.default]
primary = "default-v2"
primary_attempts = 2

[credential_profiles.console]
primary = "console-v2"
primary_attempts = 2

[credential_profiles.power]
primary = "power-v2"
primary_attempts = 2

[credential_profiles.firewall]
primary = "firewall-v3"
primary_attempts = 2

[credential_profiles.exception]
primary = "exception-v3"
primary_attempts = 2

[credential_rules]
default_profile = "default"

[[credential_rules.address]]
networks = ["192.0.2.128/27", "2001:db8:110::/48"]
profile = "console"

[[credential_rules.address]]
networks = ["192.0.2.160/27", "2001:db8:120::/48"]
profile = "power"

[[credential_rules.address]]
networks = ["192.0.2.192/27", "2001:db8:130::/48"]
profile = "firewall"

[[credential_rules.name]]
patterns = ["(?i)^wti-", "(?i)^dsm-"]
profile = "console"

[[credential_rules.name]]
patterns = ["(?i)^(ups|pdu)-", "(?i)^(apc|eaton)-"]
profile = "power"

[[credential_rules.name]]
patterns = ["(?i)^(pa|palo|fw)-"]
profile = "firewall"

[query_policy]
default_action = "deny"

[[query_policy.address_rules]]
networks = [
  "198.51.100.0/24",
  "203.0.113.0/24",
  "2001:db8:200::/56",
  "2001:db8:201::/56",
  "2001:db8:300::/48",
]
action = "deny"

[[query_policy.address_rules]]
networks = [
  "192.0.2.0/24",
  "2001:db8:100::/48",
  "2001:db8:110::/48",
  "2001:db8:120::/48",
  "2001:db8:130::/48",
]
action = "allow"

[[query_policy.name_rules]]
patterns = [
  "(?i)^(cust|customer|tenant|dept)-",
  "(?i)\\.(customer|tenant)\\.example$",
]
action = "deny"

[[query_policy.name_rules]]
patterns = [
  "(?i)^(core|dist|access|edge|rtr|sw)-",
  "(?i)^(wti|dsm|ups|pdu|apc|eaton)-",
  "(?i)^(pa|palo|fw)-",
]
action = "allow"

[classification]
managed_manufacturers = [
  "Cisco",
  "Juniper",
  "Arista",
  "Aruba",
  "HPE",
  "Palo Alto Networks",
]
managed_endpoint_patterns = [
  "(?i)\\bCisco\\s+(IP\\s+)?Phone\\b",
  "(?i)\\bSEP[0-9A-F]{12}\\b",
  "(?i)\\bAIR-[A-Z0-9-]+\\b",
  "(?i)\\b(Cisco|Juniper|Mist).*\\bAP\\b",
  "(?i)\\bvIPer\\b",
]
unmanaged_patterns = [
  "(?i)\\bprinter\\b",
  "(?i)\\bworkstation\\b",
  "(?i)\\bWindows\\b",
]

[[classification.address_rules]]
networks = [
  "198.51.100.0/25",
  "198.51.100.128/25",
  "2001:db8:200::/56",
  "2001:db8:201::/56",
]
category = "unmanaged_device"

[[classification.address_rules]]
networks = ["203.0.113.0/25"]
category = "unmanaged_device"

[[classification.address_rules]]
networks = ["203.0.113.128/25", "2001:db8:300::/48"]
category = "unmanaged_device"

[[classification.address_rules]]
networks = [
  "192.0.2.0/24",
  "2001:db8:100::/48",
  "2001:db8:110::/48",
  "2001:db8:120::/48",
  "2001:db8:130::/48",
]
category = "managed_device"

[[classification.name_rules]]
patterns = [
  "(?i)^(cust|customer|tenant|dept)-",
  "(?i)\\.(customer|tenant)\\.example$",
]
category = "unmanaged_device"

[[classification.name_rules]]
patterns = [
  "(?i)^(core|dist|access|edge|rtr|sw)-",
  "(?i)^(wti|dsm|ups|pdu|apc|eaton)-",
  "(?i)^(pa|palo|fw)-",
]
category = "managed_device"

[[classification.name_rules]]
patterns = ["(?i)^SEP[0-9A-F]{12}$", "(?i)^(ap|wap)-"]
category = "managed_endpoint"

[[classification.evidence_rules]]
label = "windows-workstation"
category = "unmanaged_device"
field_patterns = { remote_description = ["(?i)Windows"] }

[[tagging.rules]]
label = "managed-phone-by-name"
category = "managed_endpoint"
name_patterns = ["(?i)^SEP[0-9A-F]{12}$", "(?i)^VIPER-"]
tags = ["netops:phone"]

[[tagging.rules]]
label = "managed-phone-by-capability"
category = "managed_endpoint"
field_patterns = { capabilities = ["(?i)telephone"] }
tags = ["netops:phone"]

[[tagging.rules]]
label = "unmanaged-phone-ranges"
category = "unmanaged_device"
networks = ["198.51.100.0/25", "2001:db8:200::/56"]
tags = ["unmanaged:phone"]

[[tagging.rules]]
label = "managed-wifi-by-name"
category = "managed_endpoint"
name_patterns = ["(?i)^(ap|wap)-", "(?i)^AIR-"]
tags = ["netops:wifi"]

[[tagging.rules]]
label = "managed-wifi-by-capability"
category = "managed_endpoint"
field_patterns = { capabilities = ["(?i)wlanAccessPoint"] }
tags = ["netops:wifi"]

[[tagging.rules]]
label = "windows-workstation"
category = "unmanaged_device"
field_patterns = { remote_description = ["(?i)Windows"] }
tags = ["workstation"]

[[tagging.rules]]
label = "office-printer-ranges"
category = "unmanaged_device"
networks = ["203.0.113.0/25"]
tags = ["role:office-printer"]
```

## 6. Why the credential rules are deliberately short

Credential address rules have priority over credential name rules. Name rules
have priority over `credential_rules.default_profile`.

For this reason the example uses only narrow address exceptions:

```text
WTI management range   -> ConsoleV2
power management range -> PowerV2
firewall range         -> FirewallV3
anything else allowed  -> DefaultV2
```

Name rules provide the same exception when a device is outside one of those
known subnets. DefaultV2 does not need its own catch-all rule because it is
already the default profile.

This scales better than one credential rule per host and gives newly discovered
NetOps infrastructure a reasonable first credential without changing policy.

Do not add a fallback from DefaultV2 to every special credential. That causes
every ordinary device to receive unnecessary authentication attempts. Use a
specific profile only where address/name policy identifies the device family.

## 7. Use seed credentials only for true exceptions

The `ExceptionV3` devices are a good seed-overlay use case because there are
only a few of them and the credential should not become a general site rule.

Keep the actual credential in the normal credential/profile configuration so
its secrets can come from environment variables. Then let the seed-credential
file select that profile.

Example `/etc/lldp-runner/seed-credentials.json`:

```json
[
  {
    "seed": "exception-device-01.example.net",
    "credential_strategy": "exclusive",
    "credential_label": "exception-profile",
    "credential_profile": "exception"
  },
  {
    "seed": "exception-device-02.example.net",
    "credential_strategy": "exclusive",
    "credential_label": "exception-profile",
    "credential_profile": "exception"
  }
]
```

Run with:

```bash
uv run lldp-runner --config /opt/lldp-runner/config.toml \
  run --seed-credential-file /etc/lldp-runner/seed-credentials.json
```

`exclusive` means LLDP-Runner will use only the overlay-selected profile for
those seeds. It will not fall through to DefaultV2. Use `prefer` instead when
the special credential should be attempted first but ordinary policy is an
allowed fallback.

The same `credential_label` can be reused on both rows. It is reporting
metadata, not an internal identifier.

Remember that the overlay does not create seeds. If `exception-device-01` is
absent from every normal seed input, its credential row is unmatched and no
query is created for it.

Unmatched records are written to activity logging at WARN level. When a
seed-credential file is active, the activity log also contains the INFO summary
of matched and unmatched records.

## 8. Use classification to express ownership

The classification order matters:

```text
most-specific address rule
  -> first matching name rule
  -> first matching evidence rule
  -> endpoint/unmanaged/manufacturer heuristics
  -> unknown
```

The example therefore uses address rules only where a subnet has a stable
ownership meaning.

Dedicated customer phone, customer wireless, printer, and customer-device
ranges become `unmanaged_device` immediately. Dedicated NetOps management
ranges become `managed_device`.

Managed phones and access points do not need a dedicated managed-device address
rule. They can be recognized as `managed_endpoint` from stable names, endpoint
patterns, or LLDP capabilities. Because explicit unmanaged address rules run
first, customer phone/AP ranges remain unmanaged even when endpoint evidence is
present.

On mixed-use networks, prefer name or evidence rules instead of a broad address
classification. A rule that classifies an entire mixed subnet as managed can
cause customer equipment to become eligible for recursive polling.

## 9. Use evidence rules for facts learned from neighbors

Evidence rules are useful when ownership cannot be determined from one name or
subnet alone. They can combine names, networks, normalized neighbor fields, and
protocol-specific details.

Alternatives within one list are OR conditions. Different condition types are
AND conditions.

For example, if printers share a mixed subnet with other equipment, replace the
printer address classification with something more specific:

```toml
[[classification.evidence_rules]]
label = "office-printer-evidence"
category = "unmanaged_device"
networks = ["203.0.113.0/25"]
[classification.evidence_rules.field_patterns]
remote_description = [
  "(?i)printer",
  "(?i)HP LaserJet",
  "(?i)Lexmark",
]
```

That means both the network and printer evidence must match.

The Windows rule in the main example similarly classifies a workstation from
neighbor system-description evidence before the generic heuristics are needed.

Do not use an evidence rule merely to duplicate a reliable dedicated subnet or
stable naming rule. Extra rules make future troubleshooting harder.

## 10. Keep query policy stricter than classification

Classification says what LLDP-Runner thinks a neighbor is. Query policy says
whether LLDP-Runner is allowed to contact it.

A default-deny query policy is recommended for this mixed-ownership example.
It provides protection if a classifier is later broadened accidentally.

Address rules are most-specific-first. A specific customer deny can therefore
sit inside a broader permitted enterprise range and still win.

Name rules are first-match-wins and are evaluated only when no address rule
matches. Put specific denies before broader name allows when patterns might
overlap.

A credential match never overrides query policy.

## 11. Use tagging only for reporting and downstream workflows

Tags do not make a host managed and do not authorize a query. They are a safe
way to add ownership/service labels after classification.

This example produces:

```text
managed phones           netops:phone
customer/unmanaged phones unmanaged:phone
managed wireless APs     netops:wifi
Windows workstations     workstation
office printers             role:office-printer
```

Multiple matching tag rules accumulate tags and de-duplicate repeated values.
That is why a phone can be recognized by either its name or LLDP capability
without creating duplicate `netops:phone` values.

## 12. Understand what is queried

Explicit seeds are always treated as managed-device candidates, but they still
need an address, boundary/query-policy permission, and available guardrail
capacity before SNMP is attempted.

Learned neighbors are different. A learned neighbor is recursively scheduled
only when it is positively classified as `managed_device` and is allowed by the
boundary and query policy.

The normal flow is:

```text
seed
  -> query seed
  -> collect LLDP/CDP neighbors
  -> classify each learned neighbor
  -> retain every neighbor in topology
  -> query only eligible managed_device neighbors
  -> repeat
```

`managed_endpoint`, `unmanaged_device`, and `unknown_device` records remain in
output but are not recursively SNMP-polled merely because they were learned.

## 13. Understand credential success and failure

For an ordinary device, LLDP-Runner selects one profile from
address/name/default credential policy. It then tries that profile's primary
credential and fallback, when configured, according to the profile attempt
counts.

For a seed overlay with `prefer`, overlay attempts come first and normal policy
is appended. With `exclusive`, normal policy is not appended.

The first successful basic SYSTEM-MIB query establishes the credential for that
device/address. LLDP-Runner stops trying other credentials and reuses the
successful credential for detailed ENTITY/IF/LLDP/CDP collection.

A failure in an optional detail collector does not cause LLDP-Runner to try a
new credential after SYSTEM-MIB already succeeded.

If all credential attempts fail for one management address, LLDP-Runner can
advance to the next permitted candidate address. If every attempt/address is
exhausted, the device remains failed and the safe credential provenance/error
information is retained without storing secret values.

See [CREDS.md](CREDS.md) for the complete attempt sequence and provenance
fields.

## 14. Stage the rollout instead of starting unlimited

For a large enterprise, do not begin by recursively polling every candidate.
Validate policy in stages.

First validate configuration syntax and representative policy decisions:

```bash
uv run lldp-runner --config /opt/lldp-runner/config.toml validate-config

uv run lldp-runner --config /opt/lldp-runner/config.toml \
  explain-target core-01.example.net

uv run lldp-runner --config /opt/lldp-runner/config.toml \
  explain-target customer-switch-01.customer.example
```

Then run seed-only discovery by temporarily using:

```toml
[discovery]
max_devices = "auto"
```

Seed-only mode queries every explicit seed but records learned neighbors without
recursively polling them. Review `discovery.json`, unknown devices, tags,
classification reasons, and activity logs.

Next use a finite recursive limit with:

```toml
[discovery]
max_devices = 500
limit_behavior = "complete"
```

Increase only after the managed/unmanaged boundary looks correct. An established
site can later use `max_devices = 0` for unlimited recursive managed-device
polling while keeping `max_hosts` as a safety guardrail.

## 15. Prefer explainable rules over clever rules

A maintainable enterprise configuration normally has:

- a small number of dedicated address ownership rules;
- a small number of stable naming rules;
- evidence rules only for cases that genuinely need multiple facts;
- one ordinary default credential profile;
- a few device-family credential exceptions;
- seed overlays only for exceptional hosts; and
- tags for reporting rather than policy control.

Avoid large lists of individual hostnames unless there is no scalable ownership
signal. Individual exceptions tend to become stale and are difficult to audit.

## 16. Suggested file layout after the policy stabilizes

A shared installation can keep policy readable with this structure:

```text
/opt/lldp-runner/config.toml
/opt/lldp-runner/seeds.txt
/opt/lldp-runner/conf.d/10-credentials.toml
/opt/lldp-runner/conf.d/20-query-policy.toml
/opt/lldp-runner/conf.d/30-classification.toml
/opt/lldp-runner/conf.d/40-tagging.toml
/etc/lldp-runner/seed-credentials.csv
```

The seed-credential file is secret-bearing input when it contains literal
credentials. Even when it only names a configured profile, protecting it is a
good operational habit because it reveals special device mappings.

Keep credential secrets in protected environment/service configuration where
possible. Do not put communities/auth/privacy passwords into the normal seed
list, source control, generated reports, or general-purpose inventory files.

## 17. Ongoing maintenance checklist

When adding a new device family or customer network, ask these questions in
order:

1. Is the device NetOps-managed, a managed endpoint, or unmanaged?
2. Is there a stable subnet or naming convention that expresses that ownership?
3. Should query policy explicitly allow or deny the range/name?
4. Does the device use the default or need one family-specific profile?
5. Is this truly a per-seed exception that belongs in a credential overlay?
6. Does the device need a reporting tag?
7. Can the rule be tested with `explain-target` before a production run?
8. Does a seed-only or bounded run confirm the expected classification?

When a new customer range appears, it is usually better to add one explicit
unmanaged/query-deny network than to add every customer hostname individually.
When a new NetOps platform uses the default credential and follows existing
naming/range conventions, no credential change should be needed at all.
