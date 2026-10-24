# LLDP-Runner environment-variable reference

This document lists environment variables currently recognized by
LLDP-Runner. It separates configuration overrides, seed inputs, credentials,
and terminal behavior because they have different precedence and scope.

## 1. Precedence

For normal configuration values, precedence is:

```text
defaults.py
  -> primary TOML, @include, and conf.d
  -> LLDP_RUNNER_* environment overrides
  -> repeatable --set overrides
  -> dedicated command-line options
```

Runtime SNMP credential variables are used only when explicit credential
profiles are not already defined by configuration.

## 2. Primary configuration selection

### `LLDP_RUNNER_CONFIG`

Select the primary TOML configuration when `--config` is not supplied.

```bash
export LLDP_RUNNER_CONFIG=/opt/lldp-runner/config.toml
lldp-runner validate-config
```

An explicit `--config` takes precedence. An explicit path from either source
is authoritative and must exist.

This variable applies to commands that load runtime configuration, including
`run`, `get-neighbors`, `validate-config`, `explain-target`, `status`, `watch`,
`clean`, and `pause`. The `version` subcommand and `--version` do not load
runtime configuration.

`generate-config` does not use an existing primary configuration as its input;
it starts from built-in defaults plus supported generation overrides.

## 3. Discovery and filesystem overrides

These variables overlay the matching configuration settings.

### `LLDP_RUNNER_ROOT`

Override `paths.persistent_root`. The value `auto` selects the install layout's
root, such as `/opt/lldp-runner/var` for `/opt/lldp-runner/config.toml`; see
[INSTALL.md](INSTALL.md).

```bash
export LLDP_RUNNER_ROOT=/srv/lldp-runner
```

Operational effect is primarily on full discovery and commands that resolve
run storage. Single-device inspect deliberately skips persistent-path probing.

### `LLDP_RUNNER_SCRATCH_ROOT`

Override `paths.scratch_root`.

```bash
export LLDP_RUNNER_SCRATCH_ROOT=/dev/shm/lldp-runner
```

`run`, `status`, `watch`, `clean`, and `pause` use the scratch root. Inspect
does not create or probe discovery scratch storage. `clean` resolves the
configured scratch namespace without credential processing and removes only
recognized
LLDP-Runner historical scratch artifacts.

### `LLDP_RUNNER_WORKERS`

Override `discovery.workers`.

Accepted values are a positive integer or `auto`.

```bash
export LLDP_RUNNER_WORKERS=auto
```

`auto` resolves to `(os.cpu_count() or 1) * 4` on the running host.

### `LLDP_RUNNER_BATCH_SIZE`

Override `discovery.batch_size`.

```bash
export LLDP_RUNNER_BATCH_SIZE=9
```

### `LLDP_RUNNER_SEED_ORDER`

Override `discovery.seed_order`.

Accepted values are `input`, `sorted`, and `random`.

```bash
export LLDP_RUNNER_SEED_ORDER=random
```

### `LLDP_RUNNER_SEED_DNS_MODE`

Override `discovery.seed_dns_mode`.

Accepted values are `resolve` and `skip-addressed`.

```bash
export LLDP_RUNNER_SEED_DNS_MODE=skip-addressed
```

`skip-addressed` applies only to eligible startup seeds. It does not disable
DNS enrichment for learned managed neighbors. See [DNS.md](DNS.md).

### `LLDP_RUNNER_SHUFFLE_KEY`

Set the reproducible key used by random seed ordering.

```bash
export LLDP_RUNNER_SHUFFLE_KEY=20260821
```

When random ordering is selected and this value is absent, a new key is
generated for a new run and persisted for resume.

### `LLDP_RUNNER_LIMIT_BEHAVIOR`

Override `discovery.limit_behavior`.

Accepted values are `pause` and `complete`.

```bash
export LLDP_RUNNER_LIMIT_BEHAVIOR=complete
```

### `LLDP_RUNNER_BOUNDARIES`

Replace `discovery.boundaries` with a comma-separated CIDR list.

```bash
export LLDP_RUNNER_BOUNDARIES='192.0.2.0/24,2001:db8:1::/48'
```

For recursive `run`, these boundaries control which addresses may be queried.
For `get-neighbors`, the explicit target may be outside the boundary, but
the result
reports the boundary decision.

### `LLDP_RUNNER_MAX_DEVICES`

Override `discovery.max_devices`.

Accepted values are a non-negative integer or `auto`.

```bash
export LLDP_RUNNER_MAX_DEVICES=20
export LLDP_RUNNER_MAX_DEVICES=0
export LLDP_RUNNER_MAX_DEVICES=auto
```

A positive value is a recursive managed-device guardrail. `0` is unlimited.
`auto` enables seed-only polling and suppresses recursive neighbor queries.

### `LLDP_RUNNER_MAX_HOSTS`

Override `discovery.max_hosts`.

### `LLDP_RUNNER_LATE_ADDRESS_RECOVERY_ATTEMPTS`

Override `discovery.late_address_recovery_attempts`. The value is an integer
from `0` through `3`. The default is `1`; `0` disables failed-host admission
from later direct, policy-permitted, previously unattempted management
addresses. This setting does not change SNMP retry budgets.


```bash
export LLDP_RUNNER_MAX_HOSTS=1000
```

`0` disables the identified-host count guardrail.

## 4. SNMP and ICMP runtime overrides

### `LLDP_RUNNER_SNMP_BACKEND`

Override `snmp.backend`. Accepted values are `gufo` and `pysnmp`; PySNMP is the
built-in default. Existing Gufo runs still require an explicit effective Gufo
selection when resumed.

```bash
export LLDP_RUNNER_SNMP_BACKEND=pysnmp
```

`--set` can override this environment value, and the dedicated
`--snmp-backend` option has final ordinary-setting precedence. The effective
backend is fixed before discovery and persisted for resume. This variable never
requests automatic fallback or mixed-backend operation.

### `LLDP_RUNNER_SNMP_TIMEOUT`

Override `snmp.timeout_seconds`.

```bash
export LLDP_RUNNER_SNMP_TIMEOUT=2.0
```

This is a per-request SNMP timeout, not a whole-device timeout.

### `LLDP_RUNNER_SNMP_RPS`

Override `snmp.per_device_rps`.

```bash
export LLDP_RUNNER_SNMP_RPS=5.0
```

### `LLDP_RUNNER_SNMP_MAX_OUTSTANDING`

Override `snmp.max_outstanding_devices_per_worker`.

```bash
export LLDP_RUNNER_SNMP_MAX_OUTSTANDING=24
```

This primarily affects full discovery worker concurrency. The inspect path
uses the same worker primitives but only supplies one device.

### `LLDP_RUNNER_ICMP_TIMEOUT`

Override `icmp.timeout_seconds`.

```bash
export LLDP_RUNNER_ICMP_TIMEOUT=1.0
```

This affects normal discovery and real single-device inspection when ICMP is
enabled.

## 5. Output and logging overrides

### `LLDP_RUNNER_LOG_LEVEL`

Override `logging.level`.

```bash
export LLDP_RUNNER_LOG_LEVEL=DEBUG
```

For `get-neighbors`, diagnostics are written to stderr so stdout remains
usable for redirected table, detail, CSV, or JSON data.

### `LLDP_RUNNER_SNAPSHOT_INTERVAL`

Override `output.snapshot_interval_seconds`.

```bash
export LLDP_RUNNER_SNAPSHOT_INTERVAL=120
```

This applies to full discovery snapshots.

### `LLDP_RUNNER_SCOREBOARD_INTERVAL`

Override `output.scoreboard_interval_seconds`.

```bash
export LLDP_RUNNER_SCOREBOARD_INTERVAL=3
```

This applies to full discovery scoreboard refreshes.

## 6. Seed input variables

The following variables are additive seed sources for `lldp-runner run`.
They do not apply to `get-neighbors`, which accepts one explicit target.

### `LLDP_RUNNER_SEEDS`

Provide inline seeds separated by commas and/or newlines.

```bash
export LLDP_RUNNER_SEEDS='core1.example.net,core2.example.net'
```

### `LLDP_RUNNER_SEED_FILES`

Provide a platform path-list of seed files. On Linux, entries are separated by
`:` because the parser uses `os.pathsep`.

```bash
export LLDP_RUNNER_SEED_FILES='/srv/seeds/core.txt:/srv/seeds/edge.csv'
```

CSV files must use the current strict `seeds.csv` schema. Other files use the
plain-text seed parser.

### `LLDP_RUNNER_SEED_DIRS`

Provide a platform path-list of recursively scanned seed directories.

```bash
export LLDP_RUNNER_SEED_DIRS='/opt/lldp-runner/seeds.d:/srv/extra-seeds'
```

Seed-directory skip and parsing rules are described in [CLI.md](CLI.md).

## 7. Default runtime SNMP credentials

These variables provide the lowest-priority default credentials for small or
simple runs that do not define explicit credential profiles.

### `SNMPCOMM`

Provide the default SNMPv2c community string.

```bash
export SNMPCOMM='example-community'
```

### `SNMPUSER`

Provide the SNMPv3 authPriv username.

### `SNMPAUTH`

Provide the SNMPv3 authentication password.

### `SNMPPRIV`

Provide the SNMPv3 privacy password.

All three v3 variables are required together.

```bash
export SNMPUSER='snmp-user'
export SNMPAUTH='authentication-password'
export SNMPPRIV='privacy-password'
```

When both v2c and v3 credentials are present, `snmp.version` determines the
primary version and the other becomes fallback. When only one version is
available, LLDP-Runner uses that credential for two attempts rather than
creating a duplicate fallback credential.

Explicit TOML credentials and credential profiles take precedence and suppress
synthesis of the runtime-default credential profile.

## 8. Credential-table secret variables

Explicit TOML credential entries may refer to site-defined environment-variable
names rather than embedding secrets in the file.

Example:

```toml
[credentials.site-v3]
version = "v3"
username_env = "SITE_SNMP_USER"
auth_password_env = "SITE_SNMP_AUTH"
priv_password_env = "SITE_SNMP_PRIV"
```

The names `SITE_SNMP_USER`, `SITE_SNMP_AUTH`, and `SITE_SNMP_PRIV` are examples;
any environment-variable names may be configured in these fields.

The same concept applies to an SNMPv2c `community_env` field.

## 9. Environment indirection for credential CLI arguments

Credential command-line arguments use an environment-name-first rule.

```bash
export SITE_COMM='example-community'
get-neighbors --community SITE_COMM core1.example.net
```

Because `SITE_COMM` exists, its contents become the community string.

If no environment variable named by the token exists, the token itself is
used literally:

```bash
get-neighbors --community literal-community core1.example.net
```

Environment-variable names are preferable for secrets because literal
command-line values may appear in shell history or process listings.

## 10. Terminal color control

### `NO_COLOR`

When present in the environment, disable terminal color/styling in
`get-neighbors`, `show-neighbors`, and the interactive `watch` dashboard.

```bash
NO_COLOR=1 get-neighbors core1.example.net
```

Human output is also automatically colorless when stdout is not a TTY.
CSV and JSON output never contain ANSI color codes.

Terminal styling is configured under `[terminal]`, not through additional
LLDP_RUNNER_* environment variables. `color = "auto"` enables styling only when
terminal capabilities permit it; `color = "never"` disables styling.
`palette = "dark"` (default) or `"light"` selects the built-in watch dashboard
theme. The existing named semantic colors configure neighbor-oriented output.

The shipped example is:

```text
configs/conf.d/terminal-colors.toml.example
```

Supported names are `black`, `red`, `green`, `yellow`, `blue`, `magenta`,
`cyan`, `white`, `default`, and `none`. `default` selects the terminal default
foreground color. `none` leaves that semantic role uncolored while preserving
applicable emphasis when styling is enabled. `NO_COLOR` remains authoritative
over all configured color and palette choices.

## 11. Standard process environment with indirect effects

LLDP-Runner also relies on normal operating-system behavior for items such as
home-directory expansion and executable lookup. For example, the invoking
user's home directory determines `~` in config and path search locations.

These are not LLDP-Runner-specific configuration variables and are therefore
not part of the supported `LLDP_RUNNER_*` interface.
