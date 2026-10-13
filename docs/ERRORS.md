# Error provenance and recovery

## Route errors are not host presentation

A host can have several permitted addresses and credential routes. Every
worker-originated failed attempt is therefore stored as its own error record.
The failed destination is `attempted_target`; it is not reconstructed from the
host's successful `query_target`.

A structured error can contain:

- `attempted_target` and `address_family`;
- `phase`, `operation`, and `collector`;
- module-qualified `exception_type`, `exception_errno`,
  `exception_strerror`, and redacted `exception_args`;
- credential profile, stage, source, and non-secret label;
- attempt number, category, message, and recoverability;
- the host's current `final_state` when output is generated.

Fields remain null when evidence is unavailable. LLDP-Runner does not parse a
generic message or copy a host-level target merely to fill them.

## Secret handling

Communities, usernames, authentication passwords, and privacy passwords are
removed before exception text or arguments cross the worker boundary. Direct
seed credentials remain in memory only. Route history persists non-secret
profile, stage, source, and label information, never credential material.

Both supported SNMP backends normalize their native failures at the project
boundary. Timeout, UDP/address transport, authentication, authorization, local
backend capability, engine/security indication, PDU-status, and
malformed-response failures retain stable project types beneath
`SnmpBackendError`. PySNMP cancellation remains an `asyncio.CancelledError` so
task cancellation is never mistaken for an agent or network failure. Its
dispatcher is still closed on the cancellation path.

`snmp_backend_capability` means the selected library cannot perform required
work in the local runtime. In 0.37.0, PySNMP authPriv startup verifies the
installed `cryptography>=50.0` provider with fixed non-secret
AES-128/AES-256/DES operations. A missing, old, or unusable provider fails
before network discovery.
The adapter also maps PySNMP's runtime `Ciphering services not available`
indication to this category. It is not a timeout, does not consume an adaptive
request retry, and is not misreported as bad device credentials. Error text is
sanitized before persistence.

## Late-address recovery

A managed host that reaches `FAILED` can later receive a new direct,
identity-eligible management address from another observation. The coordinator
may admit a bounded recovery task when the address is:

- permitted by discovery boundaries and query policy;
- not present in durable route-attempt history; and
- allowed by `discovery.late_address_recovery_attempts`.

The default allowance is one and `0` disables the behavior. Admission is an
atomic SQLite event. The counter survives restart, and merging duplicate host
projections keeps the maximum consumed count rather than adding allowances.
Repeated advertisements of an attempted address do not requeue the host.

The recovery task contains only the newly admitted addresses. Existing failed
errors remain durable. If a later basic route succeeds, output marks the older
basic-route error with `recovered=true` and `recovered_by_target`. Detail-table
warnings are not relabeled as route recovery.

## Legacy Gufo IPv6 migration

Opening a 0.32.4 run database under 0.32.5 can enrich only the exact historical
Gufo constructor signature `OSError: invalid address`. A target is assigned
only when persisted SNMP session telemetry supplies one unique IPv6 route whose
credential profile and stage agree with the error. Ambiguous rows remain
unstructured. The host's presentation `query_target` is never used as a guess.

## Operator use

Start with `category`, `phase`, `attempted_target`, and `exception_type` in
`errors.csv`. Use `discovery.json` when exception arguments, recovery metadata,
or nested collection coverage are needed. Run diagnostics and activity logs
identify the selected backend and installed package version plus the same
canonical route and phase without exposing secrets.
