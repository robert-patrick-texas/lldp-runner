# LLDP-Runner DNS Behavior

## 1. Summary

DNS is part of LLDP-Runner identity enrichment and can occur both before worker
startup and while discovery is in flight. Large seed inventories and large
recursive discoveries can therefore generate substantial resolver traffic.

The default seed policy remains fresh resolution:

```toml
[discovery]
seed_dns_mode = "resolve"
```

Operators that reuse a current `seeds.csv` inventory can optionally use the
conservative addressed-seed fast path:

```toml
[discovery]
seed_dns_mode = "skip-addressed"
```

or:

```bash
lldp-runner run --seed-dns-mode skip-addressed --seed-file seeds.csv
```

This option affects initial seed resolution only. It is not a global no-DNS
mode and does not disable learned managed-neighbor DNS enrichment.

## 2. Where DNS can occur

### 2.1 Seed initialization

The normal `resolve` mode resolves every seed during coordinator
initialization. Hostname seeds can cause forward/canonical-name resolution.
IP-address seeds can cause reverse resolution for presentation and identity
enrichment.

This phase happens before discovery workers start. With thousands of seeds,
resolver latency can make startup take minutes. See [RUN.md](RUN.md) for the
30-second seed-resolution progress heartbeat.

### 2.2 Learned managed neighbors

When `discovery.resolve_discovered_managed_names = true`, a learned neighbor
classified as a managed device can receive DNS enrichment before final
classification and scheduling.

That behavior is independent of `seed_dns_mode`.

### 2.3 Diagnostic commands

Commands such as `get-neighbors --dry-run` and tracing can also exercise the
operating-system resolver as part of target explanation and collection.

## 3. Resolver implementation

LLDP-Runner uses operating-system resolver interfaces such as `getaddrinfo`,
`getfqdn`, and reverse lookup. The effective answer can therefore come from DNS,
`/etc/hosts`, NSS modules, a local stub resolver, or another configured name
service.

LLDP-Runner should not claim that every resolver operation emitted a literal DNS
packet.

## 4. `seed_dns_mode = "resolve"`

`resolve` is the default and preserves normal fresh resolver behavior.

A reusable seed row can contain a prior `queried_as` and known IPv4/IPv6
aliases. LLDP-Runner keeps those supplied addresses and combines them with fresh
resolver results.

Advantages include:

- detecting new DNS addresses at startup;
- refreshing canonical/reverse names;
- obtaining names useful to name-based policy or credential rules;
- adding DNS evidence that can help identity consolidation.

Costs include resolver load and startup latency on large inventories.

## 5. `seed_dns_mode = "skip-addressed"`

`skip-addressed` is a selective optimization. A seed bypasses DNS only when all
applicable conservative eligibility conditions are satisfied.

### 5.1 Eligibility

An eligible seed must have:

1. a non-IP logical seed/preferred name;
2. a valid `queried_as` IPv4 or IPv6 address from input; and
3. when prior state is available, a successful state (`complete` or `success`).

If prior state is absent, the name plus valid `queried_as` evidence is accepted.
If merged seed sources carry conflicting prior states, LLDP-Runner treats the
state as mixed and performs DNS normally.

A failed, blocked, or otherwise non-successful prior state does not authorize
the fast path.

### 5.2 What is reused

The eligible seed keeps:

- its supplied logical name;
- `queried_as` as the first known address hint;
- supplied IPv4 aliases; and
- supplied IPv6 aliases.

The scheduler can still try other supplied addresses according to normal
address preference and policy. Skipping DNS does not mean that only
`queried_as` may be queried.

### 5.3 What is not refreshed

For an eligible skipped seed, startup does not independently discover:

- a changed forward-DNS address;
- a changed canonical name;
- reverse-DNS names; or
- additional resolver aliases not already in the seed inventory.

Operators should understand that the mode favors inventory reuse and startup
speed over fresh DNS validation.

## 6. Inputs that still use DNS

Even in `skip-addressed` mode, normal resolution is retained when:

- `queried_as` is missing;
- the seed itself is only an IP address;
- the carried prior state is failed or otherwise non-successful;
- conflicting prior states were merged from multiple seed sources; or
- the input does not satisfy the conservative fast-path checks.

IP-only rows intentionally keep reverse/canonical resolution because a learned
name can affect presentation, identity matching, query policy, and credential
selection.

## 7. Policy and credential implications

Skipping seed DNS does not bypass boundary or query policy. LLDP-Runner still
evaluates the supplied addresses and known names normally.

A stale seed inventory can nevertheless have operational consequences. For
example, DNS may already point to a renumbered address that is not present in
the reused inventory, or a newly resolved name might have selected a different
name-based policy or credential rule.

Use `skip-addressed` when the supplied inventory is sufficiently current for
the intended run.

## 8. `seeds.csv` provenance

Current reusable `seeds.csv` input includes fields such as:

```text
preferred_name
queried_as
ipv4
ipv6
state
```

`queried_as` has strong provenance after a successful run because it is the
address that answered the device query. For unsuccessful rows it can instead be
an attempted address. That is why a non-successful `state` forces fresh DNS in
`skip-addressed` mode.

See [CSV-INPUT.md](CSV-INPUT.md) for position-independent seed CSV parsing.

## 9. Resolver volume and local caching

A discovery scan can generate high resolver volume:

- during startup while seed identities are resolved; and
- during in-flight recursive discovery as new managed names are learned.

Use a local caching stub resolver on the LLDP-Runner host for large scans.
A local cache can reduce repeated upstream DNS traffic and improve response
latency without changing LLDP-Runner's resolver semantics.

Examples of local caching approaches vary by operating system and site policy;
LLDP-Runner intentionally relies on the host resolver configuration rather than
requiring one specific caching product.

## 10. Future consideration: LLDP-Runner DNS cache

A future release should consider a run-scoped internal DNS cache so repeated
forward, reverse, and canonical-name lookups can be reused within one discovery
without depending entirely on external resolver caching.

Such a cache would need explicit rules for positive and negative lifetimes,
address/name normalization, concurrency, trace visibility, and behavior across
pause/resume. It is intentionally not part of the current release.

Until then, large deployments should strongly consider a local caching stub
resolver and can use `skip-addressed` for current reusable seed inventories.

## 11. Related references

- [RUN.md](RUN.md) describes startup phases and progress reporting.
- [NAMES.md](NAMES.md) describes name/address identity correlation.
- [CREDS.md](CREDS.md) describes name/address credential selection.
- [PRECEDENCE.md](PRECEDENCE.md) describes configuration override order.
