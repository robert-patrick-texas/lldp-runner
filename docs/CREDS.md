# Credential Selection and Seed Credential Overlays

This document explains how LLDP-Runner decides which SNMP credential to try.
It is written for operators who maintain seed lists, credential profiles, and
credential policy.

The short version is:

```text
normal seed / learned managed device
  -> choose a management address
  -> check discovery boundary and query policy
  -> choose a credential route
  -> try credentials in order until SYSTEM-MIB succeeds or all attempts fail
```

For an explicit seed with a matching seed-credential overlay, the overlay can
change only the credential route. It does not make a new seed and it does not
change discovery boundaries, query policy, or device classification.

## 1. Which devices are candidates for SNMP

LLDP-Runner starts with explicit seeds. Seeds may come from configuration,
`--seed`, seed files, seed directories, environment inputs, reusable
`seeds.csv`, and stdin when requested.

An explicit seed is treated as a `managed_device`. This means LLDP-Runner will
try to schedule it, but a seed is not guaranteed to receive SNMP traffic. The
seed still needs:

- at least one usable management address;
- an address inside the configured discovery boundary;
- permission from query policy; and
- room under the applicable discovery guardrails.

`max_devices=auto` is seed-only mode. Explicit seeds can be queried, but learned
non-seed devices are retained as topology records and are not recursively
queried.

In normal recursive mode, learned neighbors can also become SNMP candidates.
LLDP-Runner classifies each learned neighbor before it can be scheduled.

## 2. What makes a learned device managed

Classification is separate from credential selection. Credential policy does
not make an unknown or unmanaged neighbor into a managed device.

For learned neighbors, classification is evaluated in this general order:

1. explicit address classification rules;
2. explicit name classification rules;
3. explicit evidence rules;
4. managed-endpoint patterns and endpoint capabilities;
5. unmanaged patterns and station-only capability;
6. managed-manufacturer plus network-device capability; then
7. `unknown_device` when there is not enough evidence to query safely.

The built-in managed-manufacturer list includes Cisco, Juniper, Arista, Aruba,
and HPE. The heuristic requires network-device capability evidence such as
router, bridge, or switch.

Explicit classification rules can override the heuristics. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the complete classification model.

When configured, LLDP-Runner may resolve a learned managed name and classify it
again. DNS can therefore provide an address or FQDN that matches an explicit
classification rule before the device is scheduled.

Only `managed_device` records are normally eligible for recursive SNMP polling.
`managed_endpoint`, `unmanaged_device`, and `unknown_device` records remain in
topology/output data but are not recursively queried.

## 3. Boundary and query policy come before credentials

For each candidate management address, LLDP-Runner first checks the discovery
boundary and query policy. Credentials are considered only for an address that
is permitted by both checks.

This distinction is important:

```text
classification says: this looks like managed infrastructure
boundary says:       this address is in discovery scope
query policy says:   LLDP-Runner may contact it
credentials say:     these are the SNMP credentials to try
```

A credential profile never overrides a boundary or an explicit query deny.

## 4. Normal configured credential policy

Larger sites normally define named credentials, profiles, and credential rules
in TOML.

A credential contains the SNMP authentication material. A profile describes an
ordered primary credential and optional fallback credential.

For SNMPv3 authPriv, both adapters accept `sha1` or `md5` for
`auth_protocol` and `aes128` or `des` for `priv_protocol`. PySNMP additionally
accepts `sha256` authentication and two explicit AES-256 privacy methods:

```text
aes256              USM_PRIV_CFB256_AES, Reeder localization, aka AES-256-Cisco
aes256-blumenthal   USM_PRIV_CFB256_AES_BLUMENTHAL
```

`aes256` is the intentionally preferred short name for the more common
Reeder/Cisco method. The Blumenthal method derives the localized privacy key
differently and must be selected by its full name. LLDP-Runner never guesses or
falls back between them, and `aes256-reeder` is not a compatibility alias. Gufo
rejects `sha256`, `aes256`, and `aes256-blumenthal` during validation before
secret resolution or network activity. The same backend-specific validation
applies to direct seed credentials.

When PySNMP is selected, LLDP-Runner examines only the version/privacy-protocol
metadata of credentials reachable through any profile plus direct credentials
in the supplied seed overlay. Before discovery, it verifies the installed
cryptography provider can perform each reachable AES-128, AES-256, or DES
cipher. Credential values are
not resolved, logged, or passed to the preflight. An unusable local provider
therefore fails once at startup rather than looking like invalid credentials on
every device. Gufo and PySNMP v2c-only credential sets do not run this crypto
check. A mixed run can still probe authPriv once for another reachable route;
that does not add cryptography to the v2c request path.

Example:

```toml
[credentials.site-v3]
version = "v3"
username_env = "SITE_SNMP_USER"
auth_password_env = "SITE_SNMP_AUTH"
priv_password_env = "SITE_SNMP_PRIV"
auth_protocol = "sha256"       # PySNMP only
priv_protocol = "aes256"       # Reeder/Cisco; PySNMP only

[credentials.site-v2]
version = "v2c"
community_env = "SITE_SNMP_COMMUNITY"

[credential_profiles.campus]
primary = "site-v3"
fallback = "site-v2"
primary_attempts = 1
fallback_attempts = 1
```

When normal credential policy is used for an address, profile selection is:

```text
most-specific matching credential address rule
  -> first matching credential name rule
  -> credential_rules.default_profile
```

After a profile is selected, its primary credential is attempted first. If the
configured retry count is exhausted and a fallback exists, the fallback is
attempted next.

## 5. Runtime default credentials

When no explicit credentials or credential profiles are configured,
LLDP-Runner may synthesize a `runtime-default` profile from generic runtime
inputs.

SNMPv2c:

```text
SNMPCOMM
--community / --snmp.community
```

SNMPv3 authPriv:

```text
SNMPUSER  SNMPAUTH  SNMPPRIV
--snmp-user / --snmp.user
--snmp-auth / --snmp.auth
--snmp-priv / --snmp.priv
```

If explicit credential/profile policy exists, that policy is authoritative and
the generic runtime profile is not synthesized.

See [PRECEDENCE.md](PRECEDENCE.md) for the complete credential precedence rules.

## 6. Per-seed credential overlay

`run --seed-credential-file FILE` adds an ordered credential overlay for
explicit seeds. The option may be repeated and accepts `.csv` or `.json` files.

A seed-credential file is not a seed source.

```text
normal seed inputs determine WHAT may be queried
seed-credential files modify HOW matching seeds authenticate
```

If a record exists only in a seed-credential file and the seed is not present in
the normal seed set, LLDP-Runner does not resolve, ping, or query that record.

Unmatched overlay records are written to activity logging at WARN level. When
one or more credential files are active, the activity log also receives one
INFO summary showing matched and unmatched record counts. Unmatched records are
not printed as stderr warnings.

## 7. Overlay record fields

The current CSV format requires these fields in any column order:

```text
seed,credential_strategy,credential_label,credential_profile,
snmp_version,community,username,auth_password,priv_password,
auth_protocol,priv_protocol
```

CSV header matching is case-insensitive and unrelated extra columns are
ignored. See [CSV-INPUT.md](CSV-INPUT.md) for common parsing and safety rules.

JSON uses the same field names in a top-level array. Optional `source_line` is
provenance only; JSON array order remains the credential-attempt order.

Important fields:

`seed`
: Matches an already-established explicit run seed. A record without a seed is
  skipped.

`credential_strategy`
: `prefer` or `exclusive`. Blank means `prefer`.

`credential_label`
: Optional human-readable reporting label. It is not a profile selector or
  internal key, and it does not need to be unique.

`credential_profile`
: Name of an existing configured credential profile to try for this seed.

Direct credential fields
: `snmp_version`, `community`, `username`, `auth_password`, `priv_password`,
  `auth_protocol`, and `priv_protocol` describe an ephemeral direct credential.
  Protocol names must be supported by the selected run-wide SNMP backend.

A row may reference a configured `credential_profile` or contain direct
credential material, but not both.

## 8. `prefer` versus `exclusive`

With `credential_strategy=prefer`, overlay attempts are tried first. If they all
fail, normal configured credential policy is appended.

```text
seed overlay attempt 1
  -> seed overlay attempt 2
  -> normal policy profile primary
  -> normal policy profile fallback
  -> next permitted management address
```

With `credential_strategy=exclusive`, only the overlay attempts are allowed.
Normal credential policy is not appended.

```text
seed overlay attempt 1
  -> seed overlay attempt 2
  -> next permitted management address
```

An exclusive overlay is useful when an operator must guarantee that a seed is
never queried with general site credentials.

## 9. `seed-direct`, `seed-profile`, and `policy-profile`

LLDP-Runner records safe credential provenance without storing secret values.

`seed-direct`
: The successful attempt used direct SNMP credential material from a matching
  seed-credential record.

`seed-profile`
: The matching seed-credential record named a configured credential profile.
  That profile supplied the actual primary/fallback credentials.

`policy-profile`
: The credential profile came from normal address/name/default credential
  policy rather than a seed overlay.

`credential_label` is independent of these values. For example, many unrelated
seed rows may all use the label `alpha` without creating a conflict.

## 10. Meaning of `credential_result`

`credential_result` tells which kind or stage of credential actually succeeded.

```text
primary   configured profile primary credential succeeded
fallback  configured profile fallback credential succeeded
direct    direct seed credential succeeded
failed    no permitted credential attempt succeeded
```

Typical combinations are:

```text
credential_source=seed-direct
credential_result=direct
credential_profile=<blank>
credential_label=alpha
```

```text
credential_source=seed-profile
credential_result=fallback
credential_profile=campus
credential_label=alpha
```

```text
credential_source=policy-profile
credential_result=primary
credential_profile=branch-default
credential_label=<blank>
```

## 11. What happens when SNMP succeeds

The first successful basic SYSTEM-MIB collection establishes the credential for
that device/address.

Once basic SYSTEM-MIB succeeds:

1. LLDP-Runner stops trying other credentials for that device;
2. the successful address and credential are retained;
3. detail collectors reuse the same credential; and
4. safe credential provenance is stored with the device result.

LLDP-Runner does not try another fallback credential merely because an optional
detail collector such as ENTITY-MIB, IF-MIB, LLDP, LLDPv2, or CDP fails. Basic
SNMP already proved that the credential works. Detail failures are recorded as
collector errors instead.

An ICMP reply does not count as SNMP credential success. ICMP is reachability
information; credential success requires the basic SNMP query to succeed.

## 12. What happens when an SNMP attempt fails

When a basic SNMP attempt fails, LLDP-Runner records a safe error category and
moves through the configured attempt sequence.

For a configured profile the order is:

```text
primary retry count
  -> fallback retry count, when configured
  -> next credential route
  -> next permitted management address
```

A direct seed credential is one credential route. If it fails, LLDP-Runner moves
to the next seed credential record, normal policy when strategy is `prefer`, or
the next management address as applicable.

If every permitted attempt is exhausted, the device is marked failed from the
SNMP perspective and `credential_result` is `failed`.

Errors may record the profile name, credential source, and safe
`credential_label`. Communities and SNMPv3 authentication/privacy passwords are
not written to discovery output or activity logs.

## 13. Address order and credentials

Management addresses are de-duplicated and ordered by
`discovery.address_preference`, then numerically within an address family.

The credential route is evaluated for each permitted address. This matters
because normal credential address rules can select different profiles for two
addresses belonging to the same device.

ICMP probes are performed once for a newly selected address, not once for every
credential retry on that same address.

## 14. Overlay matching and identity merging

Seed-credential matching occurs only after the normal seed set has been
established. Matching uses normalized seed identity without performing extra DNS
queries merely to match a credential record.

Repeated credential rows for one seed are preserved in file/record order.
Repeated `credential_label` values are legal.

If explicit seed aliases later converge on one device, compatible `prefer`
records can be combined. Conflicting strategies, or ambiguous converged
exclusive bindings, are rejected rather than silently weakening the operator's
credential intent.

## 15. Pause and resume

Direct seed credentials are intentionally ephemeral. LLDP-Runner does not store
plaintext seed credential secrets in SQLite so that they can be recovered later.

A resumed run that previously required seed-credential input requires the
corresponding credential input again. If an exclusive binding is missing on
resume, LLDP-Runner fails clearly instead of silently reverting to general site
credential policy.

## 16. Secret handling

Prefer environment-backed secrets in normal credential configuration:

```toml
community_env = "SITE_COMMUNITY"
auth_password_env = "SITE_AUTH"
priv_password_env = "SITE_PRIV"
```

Direct seed-credential files are secret-bearing files. Protect them with
appropriate ownership and permissions. LLDP-Runner rejects unsafe
world-readable/world-writable literal-secret files.

Direct secrets are not intentionally written to:

- `run.json`;
- `discovery.json`;
- generated CSV output;
- SQLite credential result metadata;
- activity logs; or
- `get-neighbors --trace` output.

Known secrets in backend error text are replaced with `<redacted>` before the
error is recorded or displayed.

## 17. Commands that do not use credentials

The following local/read-only commands disable the credential subsystem:

```text
show-neighbors
status
watch
clean
purge
version
```

They do not synthesize runtime credentials, resolve credential secret
environment variables, or validate credential policy because they do not query
network devices.

`get-neighbors` is a network command and uses the normal configured/runtime
credential decision path. The run-only seed credential overlay does not turn a
credential-file row into a single-device inspection target.

## 18. Operator checklist

When a device does not query as expected, check these decisions in order:

1. Is it an explicit seed or classified `managed_device`?
2. Does it have a usable management address?
3. Is the address inside discovery boundaries?
4. Does query policy allow the address/name?
5. If it is a seed, did a seed-credential overlay match it?
6. Is the overlay `prefer` or `exclusive`?
7. If a profile is used, which address/name/default rule selected it?
8. Did primary, fallback, or direct credential succeed?
9. If all attempts failed, inspect activity/error output for timeout,
   authentication, transport, or unsupported-device evidence.

Use `lldp-runner explain-target` to inspect normal policy selection for a
target. Use `get-neighbors --trace` for a detailed single-device network/SNMP
diagnostic.
Remember that `get-neighbors` does not consume run seed-credential overlays.

For configuration assembly and precedence, see
[PRECEDENCE.md](PRECEDENCE.md). For all
run and credential-file options, see [CLI.md](CLI.md).
