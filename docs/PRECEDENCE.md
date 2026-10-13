# Configuration and Credential Precedence

This document describes how LLDP-Runner selects, assembles, and prioritizes
configuration inputs. It also documents the separate credential
fallback model because credentials intentionally do not follow the ordinary
scalar-setting precedence chain.

## 1. Primary configuration selection

Primary-file selection happens before configuration values are merged.
LLDP-Runner uses the first applicable source in this order:

```text
--config FILE
  -> LLDP_RUNNER_CONFIG
  -> ~/lldp-runner-config.toml
  -> ~/lldp-runner/config.toml
  -> /opt/lldp-runner/config.toml
  -> /etc/lldp-runner/config.toml
  -> no primary file; use built-in defaults
```

An explicitly selected file is authoritative. If `--config` names a missing
file, LLDP-Runner reports an error instead of searching another location. The
same rule applies when `LLDP_RUNNER_CONFIG` names a missing file.

## 2. Assembling the selected configuration bundle

When a primary file exists, LLDP-Runner builds one site configuration bundle
before applying environment or command-line overrides.

The bundle is assembled in this order:

```text
primary-file @include entries, in written order
  -> remaining conf.d/**/*.toml files, in lexical relative-path order
  -> primary TOML contents
```

The automatic `conf.d` directory is adjacent to the selected primary file. For
example:

```text
/opt/lldp-runner/config.toml
/opt/lldp-runner/conf.d/10-site.toml
/opt/lldp-runner/conf.d/20-policy.toml
```

`conf.d` traversal is recursive. Only filenames ending exactly in `.toml` are
active. Files such as `site.toml.example`, `site.toml.disabled`, or `SITE.TOML`
are not loaded automatically.

A primary-file `@include` may use a relative or absolute path. Relative paths
are resolved from the including file's directory. Included files can include
other files.

For every individual file, its own includes are merged before that file's TOML
content. Therefore the including file wins for conflicting scalar values.

Each resolved configuration file is loaded only once during one configuration
load. Include cycles are rejected.

## 3. Scalar configuration precedence

After the file bundle is assembled, ordinary configuration values use this
precedence from lowest to highest:

```text
built-in defaults.py
  -> assembled primary-file configuration bundle
  -> supported LLDP_RUNNER_* environment overrides
  -> repeatable --set SECTION.OPTION=TOML_VALUE overrides
  -> dedicated command-line options
  -> effective runtime configuration
```

For scalar values, a later source wins. This includes `time.timezone`,
`paths.run_id_format`, and `snmp.backend`; they can be supplied through TOML or
`--set` like other ordinary configuration values.

For example, if the following inputs are all present:

```text
config.toml:                   snmp.timeout_seconds = 1.0
LLDP_RUNNER_SNMP_TIMEOUT:      2.0
--set snmp.timeout_seconds=3.0
--snmp-timeout:                4.0
```

then the effective value is `4.0`.

Backend selection follows the same chain:

```text
built-in default:               pysnmp
config.toml:                   snmp.backend = "gufo"
LLDP_RUNNER_SNMP_BACKEND:      pysnmp
--set 'snmp.backend="gufo"'
--snmp-backend:                pysnmp
```

The effective value is `pysnmp`. It is bound before discovery and persisted for
the logical run. Later worker construction cannot change it, and a resume that
resolves to a different backend fails before discovery. This precedence model
does not imply fallback: only the final selected backend is imported or used.

`--set` values use TOML value syntax. Strings should therefore be quoted:

```bash
lldp-runner \
  --set 'snmp.entity_mib_mode="brief"' \
  --set 'logging.level="DEBUG"' \
  run --seed core1.example.net
```

Repeated `--set` expressions are processed in order. If a dotted path is set
more than once, the last assignment wins.

Only supported `LLDP_RUNNER_*` variables are translated into ordinary config
settings. LLDP-Runner does not infer arbitrary configuration paths from unknown
environment-variable names.

## 4. Tables and lists inside the file bundle

TOML tables merge recursively.

Most lists concatenate while `@include` and `conf.d` fragments are assembled.
This behavior allows ordered rule sets to be split across files without losing
earlier rules.

Examples include classification, tagging, query-policy, and credential-policy
rule lists. Where a policy is first-match-wins, earlier list entries retain
higher evaluation priority even though later files override scalar settings.

The following lists are replacement exceptions within the site bundle:

```text
discovery.boundaries
discovery.address_preference
output.custom_csv.<name>.columns
```

A custom CSV column list is one complete ordered schema. A later primary or
fragment definition replaces the earlier list instead of appending columns.

Also, an explicitly configured list replaces the corresponding list from
`defaults.py`. Site boundaries therefore do not accidentally retain the built-in
unrestricted boundary list.

## 5. Dedicated command-line options

A dedicated CLI option has the highest ordinary setting priority when it maps
to the same configuration value.

Examples include:

```text
--workers
--batch-size
--seed-order
--seed-dns-mode
--shuffle-key
--limit-behavior
--persistent-root
--scratch-root
--boundary
--max-devices
--max-hosts
--snmp-backend
--snmp-timeout
--per-device-rps
--max-outstanding
--log-level
--snmp-version
```

A useful operator model is:

> Files establish site policy, environment adapts the process, `--set` makes
> arbitrary invocation-specific changes, and dedicated CLI options have final
> say for the settings they expose.

## 6. Credential precedence is separate

SNMP credentials intentionally use a different model from ordinary scalar
configuration.

For the operator-focused device/credential decision flow, see
[CREDS.md](CREDS.md).

Explicit credential policy is defined through TOML tables such as:

```toml
[credentials.site-v3]
version = "v3"
username_env = "SITE_SNMP_USER"
auth_password_env = "SITE_SNMP_AUTH"
priv_password_env = "SITE_SNMP_PRIV"

[credential_profiles.default]
primary = "site-v3"
```

If any explicit credentials or credential profiles are configured,
LLDP-Runner does not synthesize its generic `runtime-default` profile from the
runtime credential environment variables or credential CLI options.

This makes explicit site credential policy authoritative.

## 7. Runtime credential fallback

When no explicit credential/profile policy exists, LLDP-Runner may synthesize
runtime credentials from these generic environment variables:

```text
SNMPCOMM
SNMPUSER
SNMPAUTH
SNMPPRIV
```

The corresponding runtime CLI options are:

```text
--community / --snmp.community
--snmp-user / --snmp.user
--snmp-auth / --snmp.auth
--snmp-priv / --snmp.priv
```

For a corresponding runtime credential value, the CLI token has priority over
the generic environment variable.

A CLI credential token is first treated as an environment-variable name. For
example:

```bash
export SITE_COMMUNITY='example-secret'
lldp-runner --community SITE_COMMUNITY run --seed core1.example.net
```

uses the value of `SITE_COMMUNITY`. If no environment variable with that name
exists, the token itself is treated as the literal credential value.

When both complete SNMPv3 and SNMPv2c runtime credentials exist, `snmp.version`
or `--snmp-version` determines which version is primary. The other version is
used as fallback. The default preference is SNMPv3.

If only one complete runtime credential type is available, it is used as the
primary runtime credential.

## 8. Explicit credential secret indirection

Explicit credential definitions can independently use environment-backed secret
fields such as:

```text
community_env
username_env
auth_password_env
priv_password_env
```

Those environment variables supply secret values to the selected credential.
They are not ordinary `LLDP_RUNNER_*` configuration overlays and do not change
the configuration precedence described in Section 3.

## 9. Non-network commands can disable credentials entirely

Credential-aware commands use one of two normal modes. Network-capable commands
require usable credentials, while credential-aware dry runs can validate policy
without requiring live secrets. Stored-data and local-maintenance commands can
use a third, disabled mode when credentials have no role in the operation.

`show-neighbors`, `lldp-runner show-neighbors`, `lldp-runner diff`,
`lldp-runner status`, `lldp-runner watch`, `lldp-runner clean`, and
`lldp-runner purge` use disabled credential mode. In
that mode LLDP-Runner does not build credential/profile/rule objects, synthesize
runtime
credentials from `SNMPCOMM` or `SNMPUSER`/`SNMPAUTH`/`SNMPPRIV`, resolve secret
environment variables, or validate credential policy. Other applicable
configuration is still assembled and validated normally.

This separation is intentional so read-only viewers and local filesystem
maintenance can reuse the same credential-free configuration path without
weakening credential enforcement for commands that contact devices.

## 10. Seeds are additive runtime inputs

Seed inputs are collected rather than treated as scalar overrides. Discovery
can combine configured seeds, CLI seed options, seed-related environment
variables, and stdin when requested.

After collection, logical seed identities are de-duplicated while preserving
the first occurrence's ordering and source attribution. A CLI seed therefore
does not replace configured seeds.

## 11. generate-config is intentionally different

`lldp-runner generate-config` does not load an automatically discovered site
configuration and does not apply the normal environment overlay.

Its effective generation model is:

```text
built-in defaults
  -> --set generation overrides
  -> applicable dedicated generation options
```

This prevents the current production configuration from silently becoming the
basis of a supposedly clean generated configuration.

## 12. Condensed operational model

For normal runtime commands, remember these three separate decisions:

```text
SELECT PRIMARY FILE
  --config
    > LLDP_RUNNER_CONFIG
    > first existing search-path file
    > no file

ASSEMBLE SITE FILES
  @include files
    -> conf.d files
    -> primary file contents

BUILD EFFECTIVE SETTINGS
  defaults
    -> assembled site files
    -> supported LLDP_RUNNER_* environment overrides
    -> --set overrides
    -> dedicated CLI overrides
```

Network-capable commands then apply the distinct explicit-policy or
runtime-fallback credential model before validation and network activity.
Stored-data/local commands such as `show-neighbors`, `diff`, `status`,
`watch`, and `clean` explicitly disable the credential subsystem instead.
`version` exits
before configuration loading at all.

## Per-seed credential overlay precedence

`run --seed-credential-file` is separate from configuration assembly. Normal
seed sources determine which hosts are seeds; credential files only modify the
credential attempt chain for matching explicit seeds.

For a matched seed with `credential_strategy=prefer`, the order is:

```text
seed-credential rows, in file/record order
  -> each credential_profile row's configured primary/fallback attempts
     or the row's one direct credential attempt
  -> ordinary address/name/default credential-profile policy
```

For `exclusive`, the ordinary policy step is omitted. An unmatched credential
record is never promoted into the seed set. JSON array order and CSV row order
are authoritative; `credential_label` and JSON `source_line` do not participate
in precedence or identity.
