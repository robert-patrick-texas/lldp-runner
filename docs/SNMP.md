# SNMP backends, retries, diagnostics, and IPv6 compatibility

## Backend ownership and selection

LLDP-Runner owns a small asynchronous SNMP client interface. Version 0.36.0
introduced two discovery implementations, and 0.37.0 retains both:

- `pysnmp`, the default PySNMP 7.1 asyncio `v3arch` adapter;
- `gufo`, the unchanged Gufo SNMP adapter selected explicitly when needed.

Choose one backend with `snmp.backend`, `LLDP_RUNNER_SNMP_BACKEND`,
`--set 'snmp.backend="..."'`, or the dedicated `--snmp-backend` option. The
normal setting precedence in [PRECEDENCE.md](PRECEDENCE.md) applies, so the
dedicated option has final say.

The 0.37.0 default change does not rewrite an explicit Gufo selection. A run
started with Gufo remains a Gufo run: its resume must still resolve to `gufo`.
When the backend setting is omitted, it now resolves to `pysnmp`, so attempting
to resume durable Gufo state under the implicit default fails before discovery.
LLDP-Runner never converts an existing run or falls back between libraries.

The effective choice is normalized and bound once after configuration assembly
and validation. Spawned workers receive that same runtime binding. The factory
imports and constructs only the selected implementation; an import, open, or
request failure never tries the other library. A logical run therefore cannot
contain mixed-backend evidence.

The backend name and installed distribution version are persisted in SQLite run
metadata and in the top-level and per-invocation `run.json` records. They are
also announced in normal run diagnostics. Credential material is not included.
A resume must resolve to the same persisted backend name. A different name, or
a real older checkpoint with no backend metadata, is rejected before discovery
and before the run manifest is changed. The installed version is recorded for
each resume invocation because an operator may have upgraded the selected
package between invocations.

## PySNMP 7.1 adapter

The PySNMP adapter reuses the mappings validated by
`scripts/pysnmp-snmp-diag.py`:

```text
SNMPv2c  CommunityData(community, mpModel=1)
SNMPv3   UsmUserData(username, authKey=..., privKey=...,
                     authProtocol=..., privProtocol=...)
IPv4     await UdpTransportTarget.create((address, port), ..., retries=0)
IPv6     await Udp6TransportTarget.create((address, port), ..., retries=0)
```

SNMPv3 algorithm names are backend-specific and are validated before secrets
or network activity:

| Configuration value | Gufo | PySNMP mapping |
| --- | :---: | --- |
| `auth_protocol = "sha1"` | yes | `USM_AUTH_HMAC96_SHA` |
| `auth_protocol = "md5"` | yes | `USM_AUTH_HMAC96_MD5` |
| `auth_protocol = "sha256"` | no | `USM_AUTH_HMAC192_SHA256` |
| `priv_protocol = "aes128"` | yes | `USM_PRIV_CFB128_AES` |
| `priv_protocol = "des"` | yes | `USM_PRIV_CBC56_DES` |
| `priv_protocol = "aes256"` | no | `USM_PRIV_CFB256_AES` |
| `priv_protocol = "aes256-blumenthal"` | no | Blumenthal AES-256 |

`aes256` is intentionally the shorter name for the more common Reeder key
localization, also called AES-256-Cisco. `aes256-blumenthal` selects
`USM_PRIV_CFB256_AES_BLUMENTHAL` with the different Blumenthal key-localization
method. They are not interchangeable;
LLDP-Runner does not accept `aes256-reeder` as an alias and never probes,
negotiates, downgrades, or falls back between privacy algorithms. Gufo remains
limited to SHA-1/MD5 authentication and AES-128/DES privacy. Configuration
credentials and direct seed credentials are checked against the selected
adapter's explicit capability map, and each adapter repeats the validation at
its own boundary.

### PySNMP authPriv cryptography preflight

PySNMP delegates strong SNMPv3 privacy ciphers to the installed `cryptography`
provider. LLDP-Runner 0.37.0 declares `cryptography>=50.0`; the exact Linux
release constraints pin 50.0.1. Package metadata alone is not enough to prove
that the provider and its native bindings can execute every configured cipher,
so active PySNMP startup performs a constructive local check.

After backend selection and durable resume-backend validation, but before a run
manifest, worker process, DNS seed resolution, ICMP request, or SNMP request,
the coordinator gathers only non-secret metadata from:

- every credential referenced by a configured profile, including profiles that
  a protected seed overlay could select; and
- every direct SNMPv3 seed credential parsed for this invocation.

For each distinct reachable privacy protocol, the preflight encrypts fixed
non-secret bytes with the corresponding AES-128 or AES-256 CFB primitive, or
the DES-compatible TripleDES CBC primitive. AES-128 uses a 16-byte key;
`aes256` and `aes256-blumenthal` use a 32-byte key and the same 16-byte AES CFB
IV. The AES-256 localization distinction is implemented by PySNMP after this
local provider check. The AES probe imports CFB from
`cryptography.hazmat.decrepit.ciphers.modes`, which is the supported location
for this legacy-but-protocol-required mode in cryptography 50. It does not
read a community, username, authentication password, or privacy password. It
creates no `SnmpEngine` or transport and consumes no LLDP-Runner retry
allowance. Active `get-neighbors` performs the same check because it bypasses
the coordinator. Dry-run and stored-data commands do not.

Missing/old cryptography, a failed provider import, or an unusable cipher raises
the sanitized `SnmpBackendCapabilityError` and stops the invocation before
network discovery. Gufo and PySNMP SNMPv2c-only invocations do not require this
probe. A mixed discovery configuration may perform one startup probe because a
different reachable credential route uses SNMPv3 authPriv; that does not use
cryptography in any SNMPv2c packet or request path.

### Temporary PySNMP AES warning filter

PySNMP 7.1.29 still references CFB through cryptography's former primitives
namespace while performing its AES privacy operations. Version 0.36.3 installs
a temporary process warning filter only when a PySNMP SNMPv3 AES-128 or AES-256
route is constructed. The filter matches all three of these attributes exactly:

- category: `cryptography.utils.CryptographyDeprecationWarning`;
- complete message: the known CFB-moved/removal warning emitted by
  cryptography 50.0.1;
- origin module: `pysnmp.proto.secmod.rfc3826.priv.aes`.

The filter is not installed for SNMPv2c or DES routes. A changed upstream
message, the same category from another module, another category from the same
module, and every unrelated warning remain visible. Remove the compatibility
filter after LLDP-Runner's minimum PySNMP release adopts the decrepit CFB
import.

If a provider becomes unavailable after a successful preflight, the adapter
also recognizes PySNMP's `Ciphering services not available` indication as the
stable `snmp_backend_capability` category. It is not treated as a timeout and
therefore does not consume an adaptive request retry; ordinary configured
credential-route fallback behavior remains unchanged.

Every target has PySNMP internal retries disabled. LLDP-Runner's adaptive
wrapper remains the only retry owner, so operation, collector, shared,
neighbor-reserve, structural, and stability budgets retain their established
meaning.

GET, GET-MANY, and GETBULK WALK responses are converted at the adapter boundary.
Numeric OIDs become unprefixed dotted strings, octet-like values become bytes,
numeric application values become integers, and OID/IP values become strings.
SNMP exception sentinels remain typed so established collector and access checks
can recognize them.

Raised exceptions and response errors are mapped to stable timeout, transport,
authentication, authorization, local backend capability, engine, PDU, or
malformed-response causes inside the normal phase-aware `SnmpBackendError`.
Configured credential values are removed from backend text before it crosses
that boundary. Cancellation is not converted into an ordinary failure.

One `SnmpEngine` belongs to each opened adapter session. Its observer and
asynchronous dispatcher are released deterministically after success, partial
setup, open/request failure, close failure, and cancellation. SNMPv3 engine
identity comes only from `securityEngineId` in the received response security
context. The local manager engine ID is never reported as the remote device ID.

## Canonical addresses

IPv4 and IPv6 management addresses remain canonical, unbracketed IP text in:

- identity and alias processing;
- coordinator scheduling and duplicate prevention;
- SQLite host, route-attempt, and error records;
- activity logs and operator messages;
- `discovery.json`, fixed CSV files, and diff output.

Brackets are transport syntax, not part of an IPv6 identity. PySNMP receives the
canonical address in its family-specific target. Gufo retains the narrowly
scoped compatibility handling below.

## Gufo SNMP 0.12.0 IPv6 boundary

Gufo SNMP 0.12.0 builds its native destination from `addr` and `port`. A raw
IPv6 literal can therefore be rejected during `SnmpSession` construction with
the exact exception `OSError("invalid address")`.

LLDP-Runner contains that behavior at the Gufo boundary:

1. Construct the Gufo session with the canonical unbracketed address.
2. Only when the address is IPv6 and construction raises the exact confirmed
   exception, construct once more with `[address]`.
3. Continue to report and persist the canonical unbracketed address.

IPv4 is never bracketed. An unrelated constructor exception does not activate
the compatibility path. A successful bracketed construction is the same logical
route, not an SNMP retry, and consumes no adaptive, structural, collector,
target, or stability retry allowance. If both forms fail, the final error
preserves the bracketed failure as its cause and the original raw-address
failure as context.

The same boundary applies to SNMPv2c and SNMPv3 because address construction is
independent of the security model.

## Phase and error model

Backend failures carry one of these stable phases:

- `resolve`: address normalization or resolution before session construction;
- `session_construct`: selected-backend object/engine construction;
- `session_open`: transport/security setup or asynchronous session entry;
- `request`: GET, GET-MANY, or WALK work;
- `session_close`: asynchronous session/dispatcher shutdown.

A valid normalized destination rejected during construction uses the category
`snmp_session_address_error`. Timeouts, access restrictions, authentication
failures, transport errors, and structural collector outcomes retain their
established categories even when the project-owned wrapper supplies phase and
backend-neutral cause metadata.

## Bounded retry model

The established retry budgets are unchanged. Normal adaptive retries are
bounded per operation, per collector family, and by the target shared and
neighbor-reserve pools. Structural table retries restart the whole affected
collector snapshot. Optional delayed neighbor stability retries remain one
final pass per failed neighbor protocol.

Original LLDP local-port collection retains its existing independent one-retry
behavior. It does not consume adaptive retry capacity, and persistent failure
keeps valid remote-neighbor rows with typed unresolved local-port identifiers.

## Direct standalone diagnostics

The release ships three executable diagnostics under `scripts/`. All bypass
LLDP-Runner's wrapper, coordinator, credential policy, retry accounting, and
collectors. Run them in the same Python/uv environment, under the same
operating-system account, and on the same Linux host as LLDP-Runner.

### PySNMP compatibility diagnostic

`scripts/pysnmp-snmp-diag.py` is the direct PySNMP compatibility diagnostic.
It uses the maintained `pysnmp.hlapi.v3arch.asyncio` API directly and can
resolve IPv4 or IPv6 literals and hostnames, use SNMPv2c or SNMPv3 authPriv,
query multiple numeric OIDs, and repeat each destination with a fresh
`SnmpEngine` and
transport target. Every PySNMP target uses `retries=0`, so `--repeat` is the
only repetition performed by the script. Each engine dispatcher is closed on
success and after transport or request failure.

Credentials come only from `SNMPCOMM` or `SNMPUSER`/`SNMPAUTH`/`SNMPPRIV`.
Configured values are redacted from exceptions and are never printed. The
script distinguishes engine construction, transport-target construction, GET,
and dispatcher-close failures. It accepts SHA-1, MD5, and SHA-256
authentication plus AES-128, DES, `aes256` Reeder/Cisco, and
`aes256-blumenthal` privacy so an operator can validate the exact PySNMP route
before using it in discovery. In 0.36.3 the diagnostic performs the same
fixed-byte local privacy-cipher preflight before DNS or SNMP and prints the
installed cryptography version. Missing or unusable crypto support is reported
once as a `local_crypto_capability` configuration failure rather than once per
device.

The diagnostic deliberately does not present the local manager engine ID as the
remote authoritative SNMPv3 engine ID. The integrated 0.36.3 backend captures
that value from the received response security context instead.

Safe examples are:

```bash
SNMPCOMM='community' ./scripts/pysnmp-snmp-diag.py 192.0.2.10
SNMPCOMM='community' ./scripts/pysnmp-snmp-diag.py 2001:db8::10
SNMPCOMM='community' ./scripts/pysnmp-snmp-diag.py switch.example.net -6
SNMPUSER='user' SNMPAUTH='authpass' SNMPPRIV='privpass' \
  ./scripts/pysnmp-snmp-diag.py switch.example.net --snmp-version 3 -6
SNMPUSER='user' SNMPAUTH='authpass' SNMPPRIV='privpass' \
  ./scripts/pysnmp-snmp-diag.py switch.example.net --snmp-version 3 \
  --auth-protocol sha256 --priv-protocol aes256
```

Exit status 0 means every requested engine/target/GET/close sequence succeeded;
1 means at least one query sequence failed; 2 means usage, resolution,
credential, import, or API compatibility failed; and 130 means interruption.

### Gufo diagnostics

`scripts/gufo-snmp-diag.py` is the detailed diagnostic. It can resolve IPv4 or
IPv6 literals and hostnames, use SNMPv2c or SNMPv3 authPriv, query multiple
numeric OIDs, repeat fresh sessions, and distinguish constructor, open, request,
and close failures. It reads credentials only from `SNMPCOMM` or the documented
SNMPv3 environment variables, redacts configured values from diagnostics, and
returns zero only when every requested session and GET succeeds.

`scripts/gufo-ipv6-test.py` is deliberately narrower. It accepts one unbracketed
IPv6 literal or a hostname with at least one IPv6 result, rejects IPv4, resolves
only `AF_INET6`, normalizes and deduplicates addresses in resolver order, and
reads its SNMPv2c community from `SNMPCOMM`. For each canonical address it runs
an unbracketed probe and then a bracketed probe against the same destination.
The brackets exist only at this direct Gufo transport boundary.

A normal Gufo 0.12.0 compatibility result is an unbracketed constructor failure
with `invalid address` followed by bracketed success. The focused script treats
that as a conclusive successful diagnostic and prints `brackets required` with
exit status 0. Two successes produce `brackets not required`; a failed bracketed
probe or inconsistent result returns 1. Usage, IPv6/DNS, credential, and Gufo
import/configuration failures return 2, and operator interruption returns 130.
Neither script prints credential values.

Help is available without importing either SNMP package:

```text
python scripts/gufo-ipv6-test.py --help
python scripts/gufo-snmp-diag.py --help
python scripts/pysnmp-snmp-diag.py --help
```

See `scripts/gufo-readme.txt` for safe invocations. A real focused IPv6
result is host-specific diagnostic evidence; it does not by itself change
LLDP-Runner's canonical unbracketed address representation or its narrowly
contained Gufo
transport compatibility layer.
