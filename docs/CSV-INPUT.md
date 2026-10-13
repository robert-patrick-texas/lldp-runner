# CSV Input

## 1. Summary

LLDP-Runner uses one shared CSV input layer for reusable seed inventories,
seed-credential overlays, and future operator-supplied CSV inputs.

The reader resolves fields by header name rather than physical column position.
Operators may therefore reorder supported columns without changing how the file
is interpreted.

The shared layer owns CSV syntax, source filtering, structural limits, field
selection, and source-line diagnostics. Individual callers still decide what a
blank value means and whether a parsed value is valid for that feature.

CSV output is separate. Fixed output files keep their documented column order.
This document describes CSV files read by LLDP-Runner.

## 2. Standard CSV behavior

Parsing uses Python's standard-library `csv` module.

The default delimiter is a comma. A caller may select another single-character
delimiter such as a semicolon or pipe. Multi-character delimiters are not
supported.

Standard CSV quoting and quote escaping apply. For example:

```csv
name,notes
switch1,"Distribution switch, Building A"
switch2,"He said ""hello"""
```

The parsed `notes` values are:

```text
Distribution switch, Building A
He said "hello"
```

An apostrophe in an ordinary value has no special meaning.

## 3. Physical records

One physical input line is one CSV record.

Multiline quoted fields are not supported and generate an error.

Blank physical lines are skipped. By default, a line is also skipped when its
first non-whitespace character is `#`. A caller may configure additional
comment prefixes where an existing input format requires them.

The reader accepts strict UTF-8 input and removes an optional UTF-8 BOM. It does
not use replacement decoding for invalid UTF-8.

An optional ASCII-only mode rejects non-ASCII parsed values. It does not
transliterate or silently rewrite them.

NUL input is rejected.

## 4. Header processing

The first nonblank, noncomment record is the header.

Header matching is case-insensitive by default. For example, these names match
the same requested field:

```text
preferred_name
PREFERRED_NAME
Preferred_Name
```

A caller may require case-sensitive matching.

A blank header field is always an error:

```text
name,,ipv4
```

A duplicate header field is also an error. Duplicate detection follows the
active case policy. With the default case-insensitive policy, this is invalid:

```text
name,ipv4,NAME
```

A caller may provide an ordered selector list. Only selected fields are
returned, and returned dictionary insertion order follows the selector order.
Unselected columns are discarded.

If no selector list is supplied, all header fields are returned in header
order.

A caller controls whether a requested field missing from the header is an
error. When missing fields are permitted, the requested dictionary key is
returned with a blank string value.

## 5. Data rows and blank values

Blank parsed field values are always accepted by the common reader. The caller
must decide whether a blank field is meaningful, optional, or invalid.

When `error_on_column_mismatch` is false, a data row may contain fewer columns
than the header. Missing header positions are returned as blank strings.

For example:

```csv
name,ipv4,notes
switch1,198.18.0.1
```

produces the equivalent of:

```text
name  = switch1
ipv4  = 198.18.0.1
notes = <blank>
```

When `error_on_column_mismatch` is true, any data-row width different from the
header width is an error.

Extra data columns are silently discarded by default. Selector use also drops
all unselected columns.

## 6. Field-count controls

Callers may set an absolute minimum and/or maximum number of parsed fields per
record.

A caller also controls whether violating those bounds raises an error. When
maximum-field violations are not errors and extra-field dropping is enabled,
fields beyond the maximum are discarded.

These limits are structural checks. They do not decide whether a particular
named field may be blank.

## 7. Physical line-length controls

The default maximum physical line length is 65,535 characters.

An overlong line normally raises an error with the pathname and physical source
line number. A caller may instead request lossy cropping at the configured
length.

Cropping occurs before CSV parsing. If cropping cuts a quoted field and leaves
invalid CSV syntax, parsing still fails. LLDP-Runner does not attempt to repair
a damaged or truncated CSV record.

## 8. Source-line information

Every returned record retains its original physical source line number. Blank
and comment lines do not renumber later records.

This permits callers such as seed-credential processing to report an exact
pathname and source line when semantic validation fails.

## 9. Current `seeds.csv` input

Reusable seed input requires the current field set:

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

The fields may appear in any order and header matching is case-insensitive.
Additional unrelated columns are ignored.

The generated `seeds.csv` output remains in its fixed documented order. An
operator may reorder those columns before using the file as input to a later
run.

The reusable `state` and `queried_as` values can participate in the optional
`discovery.seed_dns_mode = "skip-addressed"` startup fast path. The shared CSV
reader only returns those named values; DNS eligibility and prior-state
semantics remain responsibilities of seed resolution. See [DNS.md](DNS.md).

Legacy field names are not inferred. For example, old `seed`, `query_target`,
or `status` names do not substitute for the current `preferred_name`,
`queried_as`, and `state` fields.

## 10. Current seed-credential CSV input

Seed-credential CSV requires the current field set:

```text
seed
credential_strategy
credential_label
credential_profile
snmp_version
community
username
auth_password
priv_password
auth_protocol
priv_protocol
```

These fields may also appear in any order and use case-insensitive header
matching. Additional unrelated columns are ignored.

The seed-credential caller continues to accept both `#` and `;` comment lines.
Record order, after comments and blank lines are skipped, remains credential
attempt order.

Credential-specific validation remains outside the CSV reader. For example,
profile names, strategy values, v2c/v3 requirements, backend-specific algorithm
names, and secret-file permission checks are still enforced by the credential
subsystem. Gufo accepts SHA-1/MD5 with AES-128/DES; PySNMP additionally accepts
SHA-256, `aes256` for Reeder/Cisco localization, and
`aes256-blumenthal`. No AES-256 alias or automatic localization fallback is
inferred by the CSV layer.

## 11. Future CSV inputs

Future LLDP-Runner CSV readers should use this shared layer rather than parsing
column positions independently.

A new caller should specify only the structural behavior it needs, including:

- selected fields;
- delimiter;
- case-sensitive or case-insensitive header matching;
- minimum and maximum field counts;
- whether field-count violations are errors;
- maximum physical line length;
- whether overlong lines may be cropped;
- whether extra fields may be dropped;
- whether missing requested header fields are errors; and
- whether data-row width must match the header.

Feature-specific meaning and validation should stay with the feature that owns
the data.
