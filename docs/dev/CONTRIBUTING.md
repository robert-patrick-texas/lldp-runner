# Contribution Guidelines

## Code style

- Use clear names and complete docstrings for public and non-obvious internal
  behavior.
- Add comments that explain network/protocol reasons, not line-by-line Python.
- Keep functions focused and type annotations accurate.
- Prefer standard-library behavior unless a dependency provides a clear
  operational advantage.
- Preserve deterministic ordering in serialized output.

## Network correctness

- Distinguish protocol index namespaces.
- Preserve raw values and provenance.
- Validate complete tables before accepting negative evidence.
- Apply hard identity conflicts before accumulated weak matches.
- Never use DNS-only agreement, a common address, or a locally scoped chassis
  value as unrestricted physical-host equality.
- Treat ambiguous many-neighbor ports as observations until evidence supports a
  stronger interpretation.

## Operator experience

- SNMP logs place `SNMP target=<value>` in a consistent position.
- Errors identify operation, target, category, attempt, and relevant table/OID.
- Configuration comments explain practical effects and safe ranges.
- Documentation uses present-tense behavior; release history belongs in
  [`CHANGELOG.md`](../../CHANGELOG.md).
- Terminal output remains readable for Network Operations staff who are not
  Python developers.

## Review checklist

- Behavior and failure modes are tested.
- Output and schema changes are documented.
- Examples and generated configuration are updated.
- Collection, resolver, or graph-flow changes update
  [`FLOW-DIAGRAMS.md`](FLOW-DIAGRAMS.md).
- No compatibility alias is added unless the operator requires it.
- Security-sensitive values are redacted.
- New evidence rules include positive, negative, conflict, and order-randomized
  fixtures.

## Sanitized examples and fixtures

Do not commit customer or production identifiers, even when they appear only in
an example, comment, test, release note, or captured diagnostic. This includes:

- hostnames, DNS suffixes, usernames, site codes, and asset labels;
- public or private management addresses and operation-derived run IDs;
- hardware serials, chassis identifiers, and MAC-derived endpoint names; and
- organization-specific credential, classification, or tag labels.

Use role-based names such as `hq-core-01`, `branch-access-01`, and
`client-001`. Use `example.com`, `example.net`, `example.org`, or the reserved
`.example` namespace for DNS examples. Use TEST-NET IPv4 ranges and
`2001:db8::/32` for documentation addresses. The benchmarking range
`198.18.0.0/15` is suitable when a test specifically needs non-public lab
addressing.

Keep linked evidence internally consistent. When replacing an endpoint name,
also replace its addresses, serial, chassis value, CDP/LLDP details, expected
output, and any diff fixture that refers to the same logical system. Synthetic
MAC examples should remain valid for the behavior under test without copying a
captured device identifier.

Before submitting a change, run the complete test suite. The sanitized-example
regression scans shipped text, documentation namespaces, alternate MAC forms,
and compact run IDs so previously removed operation-derived values do not
return.
