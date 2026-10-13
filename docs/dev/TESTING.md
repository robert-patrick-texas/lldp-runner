# Testing Guide

## Test layers

1. Unit tests validate normalization, collectors, identity rules, claims, state,
   graph construction, diff, and rendering.
2. Integration tests validate coordinator lifecycle, output publication,
   launcher scripts, and archive behavior.
3. Production-shaped fixtures reproduce vendor and topology conditions such as
   Nexus VDCs, strict Cisco endpoints, incomplete tables, reused addresses,
   transparent protocol forwarding, and virtual workloads.
4. Two consecutive live runs validate behavior under real timing, SNMP agents,
   DNS, and topology variance.

## Required local checks

```bash
python -m compileall -q src tests scripts
pytest -q
find scripts -type f -exec sh -c '
  for file do
    case "$(head -n 1 "$file")" in
      *bash*) bash -n "$file" ;;
    esac
  done
' sh {} +
```

Run the complete static gate when installed:

```bash
ruff check
ruff format --check
ty check
```

Record unavailable tools as not run; do not report them as passes.

## Graph release gates

- Every immutable advertisement is materialized or explicitly excluded.
- Replaying the same evidence is idempotent.
- Randomized input order produces equivalent semantic output.
- Retiring a provisional host does not erase evidence.
- Same VDC across multiple routes remains one logical entity.
- Sibling VDCs sharing a chassis remain separate logical entities.
- 1:1, 1:N, N:1, and N:M correspondence are tested.
- A superseding decision retains history.
- Coverage failure does not become a confirmed removal.
- Run-local IDs and volatile table indexes do not control semantic IDs.

## Release artifact checks

- Patch applies cleanly to the exact base archive.
- Patched tree matches the staged source tree.
- Archive extracts under one versioned root.
- Extracted tree matches the staged tree.
- Tests and compile checks pass from the fresh archive.
- No `.git`, virtual environment, cache, bytecode, build, or distribution
  artifacts are packaged.
- SHA-256 hashes are generated after final artifact creation.

## 0.32.5 focused release tests

The transport suite uses deterministic fake Gufo modules and sessions. It
covers IPv4, compressed and expanded IPv6, scoped IPv6, SNMPv2c, SNMPv3,
constructor/open/request/close failures, exact fallback activation, unrelated
errors, double failure, secret redaction, and unchanged adaptive retry counts.

State and coordinator tests cover cross-family late recovery, repeated and
policy-rejected addresses, restart persistence, host merges, route-error output,
and conservative 0.32.4 Gufo error migration. LLDP tests exercise each subtable
independently. Diff tests distinguish address evidence, uncertainty, moves, and
protocol transitions.

The release replay regenerates schema-8 output from fresh copies of both
supplied SQLite states. A second independent regeneration must match every CSV
byte for byte and the JSON documents semantically after removing only the
`discovery.generated` timestamp. Diff schema 9 is then run over the regenerated
outputs.

## 0.32.6 focused release tests

Diff tests verify recursive timing normalization and explicit timing inclusion,
configuration/CLI positive and negative overrides, subtable-scoped relationship,
interface, and management-address authority, and semantic coverage preservation
through duplicate compatibility-projection folding.

Relationship tests keep usable identity conflicts out of evidence-only
classification while accepting stable name/raw-evidence drift. Attribute tests
carry nested chassis/stack provenance into incidents and graph components.
Renderer tests cover compact default output, summary-only output, and expanded
incident detail while asserting that JSON remains complete.

The production gate compares 20260109-01 (A) with 20260109-00 (B) twice and
requires byte-identical diff JSON. Default comparison must omit timing-only
churn, report no false `lldp/interfaces` complete incident, retain the one
structurally invalid `branch-access-3650-stack` remote-neighbor incident,
and preserve the confirmed move, protocol transition, evidence changes, and
one-sided observations. A separate timing-enabled comparison verifies that
the diagnostic switch restores collector-duration differences without changing
discovery or retry behavior.

## 0.32.7 focused release tests

Graph tests verify that complete LLDP/LLDPv2 `remote_neighbor` coverage remains
authoritative when only management-address collection is partial, while a true
remote-neighbor timeout remains coverage-uncertain with exact subtable
provenance.

Reconciliation tests cover observed attachment changes backed by graph halves,
protocol-evidence transitions, unavailable graph input, reverse
cross-references, unique event keys, and explicit consistency outcomes. Macro
tests cover
management-health persistence/recovery, graph-native health incidents, and the
`reported_difference_depends_on_gap` boundary. Renderer tests verify the
`Attachment`, graph-backed event, management-health, and incident-dependency
summaries.

The production gate compares 20260109-03 (A) with 20260109-02 (B) repeatedly and
from a fresh release archive. It requires 13 non-stable learned observations to
reconcile to 13 unique graph-backed events with zero unmatched, ambiguous,
conflicting, or graph-only event. Four topology-sensitive collection gaps per
side must remain health-only, and management health must report 97 persistent
malformed-index cases plus one timeout recovered in A. SNMP collection, Gufo,
worker/coordinator, late-recovery, and retry files must remain byte-identical to
0.32.6.

## 0.32.8 focused release tests

Graph tests cover pure protocol transitions and compound relationship groups
with simultaneous member-presence and protocol-evidence changes. They assert
deterministic `change_dimensions`, exact A-only/B-only member detail, and exact
per-member A/B protocol sets.

Reconciliation tests reproduce the 20260110 Cisco SEP case, reject generic
`member_set_changed` records as proof of an unrelated protocol transition, keep
an unclaimed protocol dimension graph-only, match stable raw-evidence rows
inside compound groups, and exercise several simultaneous A-only, B-only, and
protocol transitions on one local port. Event tests verify that distinct graph
members receive distinct keys while one member can retain reciprocal
compatibility references.

The production gate compares 20260110-01 (A) with 20260110-00 (B) repeatedly
and from a fresh release archive. It requires all 89 non-stable learned
observations to match 87 graph-backed events with zero unmatched, ambiguous,
conflicting, or graph-only result. The one compound relationship must expose
both `member_presence` and `protocol_evidence`, with exact member-scoped events.
Discovery scheduling, Gufo behavior, collector output, and retry budgets remain
unchanged from 0.32.7.

## 0.38.0 focused release tests

0.38.0 is a static-analysis release. `ruff check .` and
`ruff format --check .` must pass with the pinned Ruff version, and `ty check`
must report no diagnostic that was absent from the 0.37.0 baseline. The
complete deterministic suite must pass with no assertion relaxed; only version
identity and the release-constraint manifest name changed in test
expectations.

## 0.37.0 focused release tests

Backend-selection tests require an omitted `snmp.backend` setting to resolve to
PySNMP while both `pysnmp` and `gufo` remain valid explicit values. Generated
configuration and active-command help must identify PySNMP as the default.
File, environment, `--set`, and dedicated CLI precedence continue to determine
one immutable backend before discovery.

Resume tests create durable PySNMP and Gufo runs. A PySNMP run started under the
implicit default must resume through the same implicit default. A Gufo run must
reject an implicit PySNMP resume before discovery or manifest mutation, then
resume successfully when Gufo is selected explicitly. Worker binding, backend
factory isolation, no-fallback behavior, and read-only command bypass remain
required regression gates.

The default-only release must not alter backend capability maps, credential
validation, cryptography preflight, warning handling, internal-retry ownership,
collectors, topology, outputs, schemas, or exact dependency versions.

## 0.36.3 focused release tests

0.36.3 retains the complete backend-selection, resume, provider, warning, and
cleanup gates. Backend capability tests require Gufo to accept only SHA-1/MD5
with AES-128/DES while PySNMP additionally accepts SHA-256 with `aes256`
Reeder/Cisco or `aes256-blumenthal`. Configured credentials, direct seed
credentials, and both adapter boundaries must reject unknown names and the
unsupported `aes256-reeder` alias before network work.

Fake-current-PySNMP tests require exact mappings to
`USM_AUTH_HMAC192_SHA256`, `USM_PRIV_CFB256_AES`, and
`USM_PRIV_CFB256_AES_BLUMENTHAL`. The two AES-256 privacy names remain distinct
through configuration, capability preflight, and `UsmUserData`. Provider tests
require a 32-byte AES key and 16-byte CFB IV for both methods, while AES-128
continues to use a 16-byte key. All three AES routes install only the exact
known PySNMP warning filter; v2c and DES do not, and unrelated warnings remain
visible.

The standalone diagnostic must accept the same canonical PySNMP names, reject
`aes256-reeder`, retain `retries=0`, redact all secrets, and close every engine
dispatcher. Existing Gufo, retry, read-only-command, schema, documentation, and
full repository tests remain release gates.

## 0.36.2 focused release tests

0.36.2 retains the complete 0.36.1 provider and backend gates. New deterministic
tests make cryptography deprecations fatal inside the local AES probe and prove
that the probe imports `cryptography.hazmat.decrepit.ciphers.modes.CFB` without
touching the former primitives export.

Warning-filter tests emit the exact PySNMP 7.1.29 warning plus three neighboring
variants. Only the warning with the exact
`CryptographyDeprecationWarning` category, complete message, and
`pysnmp.proto.secmod.rfc3826.priv.aes` origin may disappear; a changed message,
changed module, and changed category must remain observable. Route-scope tests
prove the filter is installed for v3 AES but not SNMPv2c or DES. The standalone
diagnostic repeats the same probe-path and warning-boundary assertions.

## 0.36.1 focused release tests

0.36.1 retains all 0.36.0 selection, persistence, lifecycle, and normalization
gates and adds PySNMP authPriv provider qualification. Release metadata tests
require `cryptography>=50.0`, `pysnmp>=7.1.29`, and `gufo-snmp>=0.12.0` in the
broad project dependency set, with `cryptography==50.0.1`, `pysnmp==7.1.29`,
and `gufo-snmp==0.12.0` in both exact Linux constraint locations.

Deterministic preflight tests prove that Gufo and PySNMP v2c skip the crypto
probe; only profile-reachable and direct seed SNMPv3 privacy protocols are
included; secret accessors are not called; AES-128 and DES are probed once each;
missing/old/unusable providers raise a sanitized backend-capability error before
manifest/network work; resume mismatch validation precedes the probe; and
provider failures consume no adaptive request retry. The installed-package gate
must execute both cipher primitives when PySNMP and the exact cryptography
dependency are present. The standalone diagnostic has matching local-preflight,
classification, and installed-provider tests.

## 0.36.0 focused release tests

Backend-selection tests require Gufo to remain the default while `gufo` and
`pysnmp` are both valid explicit values. They exercise file, environment,
`--set`, and dedicated-option precedence; reject unknown values; prove the
selection cannot change after binding; and prove a selected backend failure
never constructs or falls back to the other package.

Credential tests validate configured credentials and direct seed credentials
against the selected backend's explicit authPriv capability map. Direct adapter
tests reject unknown credential versions and protocol names, preventing an
unsupported value from reaching an implementation-specific fallback branch.
Read-only `show-neighbors` and `status` tests replace both backend selection and
factory entry points with failures and prove those command paths do not enter
either boundary.

Run/resume tests persist backend name and installed version in SQLite and
`run.json`, accept a same-backend resume, and reject a mismatch before discovery
or manifest mutation. A real older resumable state without backend metadata is
rejected rather than guessed. Serialized diagnostics are checked for absence of
credential material.

Deterministic PySNMP tests inject a fake current
`pysnmp.hlapi.v3arch.asyncio` API. They cover the diagnostic-script v2c and v3
credential mappings, IPv4/IPv6 transport targets, `retries=0`, GET/GET-MANY/WALK
normalization, remote response `securityEngineId`, timeout, transport, security,
PDU, and malformed-response normalization, secret redaction, task cancellation,
and dispatcher cleanup after success and every partial/failing setup or request
path. Adaptive-layer coverage proves LLDP-Runner still owns the only retry.
Existing Gufo and resilience suites remain regression gates.

## 0.35.6 focused release tests

Release metadata tests require `pysnmp>=7.1.29` in the broad project dependency
set and `pysnmp==7.1.29` in both exact Linux constraint locations. Operator
script tests require `scripts/pysnmp-snmp-diag.py` to be present with mode
`0755`, compile, and display help without importing PySNMP.

Deterministic diagnostic tests inject a fake current PySNMP asyncio API and
cover IPv4/IPv6 transport selection, `CommunityData(..., mpModel=1)`, SNMPv3
authentication/privacy mappings, `lookupMib=False`, transport `retries=0`,
engine and PDU errors, exact failure phases, secret redaction, and dispatcher
closure. A separate API-shape test imports the real package when available and
skips when release dependencies are not installed. Live-network compatibility
remains an operator validation step and is not represented as an offline pass.

## 0.35.5 focused release tests

Custom-CSV validation must reject `unknown-devices.manufacturer` and
`unknown-devices.model` as unknown fixed fields. A separate positive regression
must prove that `json.host.system.manufacturer` and
`json.host.system.model` still render canonical system values for an unknown
host. The unknown-device fixed-field registry and row projection must contain
only the fields emitted by `unknown-devices.csv`; no compatibility-only system
keys may remain.

## 0.35.4 focused release tests

Output tests require the fixed `unknown-devices.csv` field list to omit
`manufacturer` and `model`. Preferred-name tests cover the guarded MAC-address
fallback independently of the custom fixed-field namespace.

Preferred-name tests build an `unknown` host with no inbound name or description
and one MAC-address-typed chassis value. The canonical colon-separated MAC must
appear identically in `discovery.json`, `hosts.csv`, `unknown-devices.csv`, and
fixed/JSON custom projections while persisted state remains `unknown`. Guard
cases retain `unknown` for nonblank name/description evidence, mixed subtypes,
malformed MACs, or more than one canonical chassis candidate.

## 0.35.3 focused release tests

The release gate scans every shipped UTF-8 file for fingerprints of removed
operation-derived identifiers. It also checks alternate MAC representations,
compact operation-date run IDs, and documentation IP/DNS namespaces. The
sanitized topology fixtures must continue to pass their original resolver,
graph, collection, and diff assertions.

## 0.35.2 focused release tests

Operator-script tests require `scripts/lrun-bundle-diff` to be executable,
exercise its automatic and explicit run-selection paths, and assert that the
former `lrun-prepare-bundle` path and stray `lrun-prepare-diff` spelling are
absent.
Documentation and examples must use the new command name; historical changelog
entries remain unchanged.

Documentation tests require one source-maintained reference containing
Mermaid diagrams for collection flow, resolver flow, and graph
rematerialization. The reference must name the coordinator, worker, immutable
evidence, compatibility resolver, graph builder, decision-history, and current
projection anchors that exist in source. The developer entry point and concise
architecture map must link to it, and the ROADMAP objective must be complete.

## 0.35.1 focused release tests

Scoreboard tests require active text/JSON publication below the stable
`<scratch_root>/scoreboard/` directory and exact terminal-snapshot archival in
persistent run state. Completed-run integration verifies that automatic per-run
scratch cleanup leaves the live scoreboard in place, that disabling cleanup
adds a per-run scratch copy, and that successful finalization removes durable
`run.json.draft`. Run-ID tests reserve the live `scoreboard` directory name.

Status and Watch tests use the stable source without a `current` symlink. Watch
layout regressions require six-space Started/Elapsed/Plan gaps when width
allows,
a second title-to-summary blank row only when more than ten footer rows remain,
and a bright-red source error below the worker table with blank rows above and
below. Small-screen degradation remains bounded and non-wrapping.

Cleanup tests require both normal and dry-run scratch maintenance to select the
reserved live scoreboard directory without treating it as a historical run or
following a symlink. Documentation tests require every unfinished ROADMAP item
to include remaining work, operational benefit, and estimated effort.

## 0.35.0 focused release tests

Runtime-path tests require both persistent `latest` locations to be
storage-preflighted, reject a real file/directory occupying either alias, and
verify that the shared publisher atomically replaces a relative symlink. Resume
tests ensure `runs/latest` is never returned as a run ID. Cleanup tests require
the alias target to be protected independently from `outputs/latest`.

Completed-run tests assert that `COMPLETED_LIMIT` follows the same successful
post-close sequence as an ordinary completion: coordinator resources close,
`runs/latest` is published, and enabled scratch cleanup runs. Scratch tests
remove arbitrary nested transient artifacts and the exact matching `current`
link, preserve a newer run's `current` link, and reject any path overlap with
persistent run/output storage. Configuration tests require the new setting to
default true and accept only a boolean.

Output tests build anonymous local-chassis and placeholder MAC-chassis records
plus a Nexus-style decorated name. They require one canonical `preferred_name`
across `discovery.json`, `hosts.csv`, `unknown-devices.csv`, fixed-field custom
CSV selection, and `json.host.preferred_name`, while persisted state and raw
name/description/chassis evidence remain unchanged. Production-output replay
counts the same three rule populations in the supplied 20260112-00 data and
checks that no unrelated preferred names change.

## 0.32.9 focused release tests

Identity tests assert that locally assigned chassis subtype 7 never enters the
global alias registry. Strict MAC normalization accepts only complete compact,
colon, hyphen, or dotted forms. Typed Port-ID selection requires an explicit
MAC-address subtype and rejects conflicting LLDP/LLDPv2 representations.

State and claim tests reproduce the production `hex:a1:00:00:00:00:00`
condition. Distinct typed Port-ID MACs must create distinct anonymous hosts,
repeated observations of the same MAC must return the same host, the local
chassis value must remain a weak edge-scoped claim, and a named endpoint must
continue to use its name instead of acquiring per-interface MAC identity.

Public-output tests require separate `hosts[]` and `unknown-devices.csv`
rows for the anonymous endpoints, matching `endpoint:mac:<value>` graph
entities, and no compatibility-projection warning for newly corrected state.
A graph-only fixture simulates legacy aggregate state and requires one explicit
diagnostic plus an append-only component decision without changing
advertisement accounting.

The production gate extracts the repeated local-chassis group from runs
20260111-00 and 20260111-01 and reprojects it through fresh 0.32.9 state. The 44
and 49 distinct typed Port-ID MACs must produce 44 and 49 distinct compatibility
hosts, respectively, with zero subtype-7 chassis aliases. Diff replay of the
immutable discovery pair must retain 68 graph-backed events, zero unmatched,
ambiguous, conflicting, or graph-only records, and a `consistent` cross-view
status. SNMP collection, Gufo handling, and retry budgets remain unchanged from
0.32.8.

## 0.34.1 focused release tests

Watch title tests require the Run ID span to use the same `muted` semantic role
as visible footer text. Layout tests verify one blank row after a displayed
Started/Elapsed summary and one row around the aggregate worker summary on a
normal 120x44 screen. The production-shaped 223x69 fixture requires two rows in
all three locations after ordinary layout leaves more than ten rows above the
footer. A direct spacing-policy test verifies that ten remaining rows do not
trigger the extra spacing and eleven do.

Documentation tests load the five implementation constants and compare them
with the current-version table in [`SCHEMA.md`](SCHEMA.md). The normal Markdown
width and existence gate includes the new quick reference.

## 0.34.0 focused release tests

Watch tests assert a blank top row, one-cell side borders, and one title line
containing application name/version, Run ID, STATE, and total-minute update
age. Wide title-gap tests allow at most one column of difference among the
three gaps. Narrow tests require cosmetic spacing and the version to yield
before state, run ID, age, and worker status.

Metric tests verify wider geometry-based columns, deterministic column starts,
separate count/delta budgets, and blank rows between metric rows on tall
screens. The aggregate worker summary must be centered independently with a
blank row above and below when height permits. Existing worker-cell strings,
fixed numeric budgets, view density, complete-row centering, partial-row
alignment, source/stale roles, color behavior, modal controls, footer clearing,
and terminal restoration remain covered. Responsive fixtures include 20x4,
30x8, 42x10, 63x24, 64x24, 80x24, 100x30, 120x44, 126x55, and the production
223x69 shape.

Shared neighbor-table tests pass long IPv6 management addresses through the
width planner and both public output paths. Every IPv6 character must remain
visible in the rightmost `Mgmt` column, with no trailing ellipsis, even when the
resulting plain-text table exceeds the detected terminal width. IPv4 behavior
and existing Local/Remote Port width rules remain covered.

The 0.33.0 Linux-constraint and Gufo diagnostic tests remain active.

## Sanitized-example regression

`tests/test_sanitized_examples.py` scans every shipped UTF-8 file for previously
removed operation-derived identifiers. The deny set is stored as digests, so
the test does not preserve readable customer values. It also verifies that
operator documentation uses approved example DNS and IP namespaces.

When adding a production-shaped regression, rematerialize it with synthetic
names, addresses, serials, endpoint identifiers, run IDs, credentials, and tag
labels before committing it. Preserve the relationships and conflict behavior
that make the fixture useful, not the originating environment's identifiers.
