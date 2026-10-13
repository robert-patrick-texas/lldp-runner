# Installing LLDP-Runner

This document is the installation reference for LLDP-Runner. It covers a simple
single-user source installation and the recommended centrally managed model for
multiple NetOps operators on one Linux server.

The examples assume Ubuntu Linux 24.04 LTS or 26.04 LTS, a project installed at
`/opt/lldp-runner`, a shared uv-managed Python under `/opt/shared/python`, a
trusted operator group named `netops`, and an LLDP-Runner service account named
`lldp-runner`.

## Requirements

LLDP-Runner requires Python 3.13 or newer.

The installed project dependencies are:

```text
cryptography >=50.0
gufo-snmp >=0.12.0
pysnmp >=7.1.29
```

Version 0.37.0 can use Gufo or PySNMP for discovery. PySNMP is the built-in
default; Gufo remains supported through explicit selection. Both packages are
installed so one backend can be selected before a run with `snmp.backend`,
`LLDP_RUNNER_SNMP_BACKEND`, or `--snmp-backend`. A resume must use the backend
stored by that run; LLDP-Runner never falls back between them.

Upgrading does not rewrite an explicit `snmp.backend = "gufo"` setting. Before
resuming an existing Gufo run, ensure the effective backend still resolves to
`gufo`. Omitting it now selects PySNMP; the immutable resume check will reject
the mismatch before discovery.

PySNMP SNMPv3 authPriv also requires a usable local cryptography provider.
0.37.0 declares `cryptography>=50.0` and pins 50.0.1 in the exact Linux release
constraints. Before a PySNMP discovery run or active `get-neighbors` request,
LLDP-Runner performs fixed-byte AES-128/AES-256/DES operations for every
privacy mapping that reachable credentials may use. This check resolves no
secrets and sends no packets. A failure stops startup with a sanitized local
backend-capability error instead of producing one cipher failure for every
device. Gufo and PySNMP
SNMPv2c-only invocations skip this probe. A mixed run can still execute one
startup probe for another reachable SNMPv3 route; the SNMPv2c request path does
not use cryptography. Version 0.37.0 imports the probe's CFB mode from
cryptography's decrepit namespace and narrowly filters only PySNMP 7.1.29's
known exact AES warning during real authPriv requests. Gufo accepts only
SHA-1/MD5 authentication and AES-128/DES privacy. PySNMP also accepts SHA-256
authentication, `aes256` for the common Reeder/Cisco AES-256 mapping, and
`aes256-blumenthal` for the distinct Blumenthal localization; incompatible Gufo
credentials fail validation before secrets or network access.

Development tooling declared in `pyproject.toml` includes pytest, Ruff, and Ty.
The build backend requires `uv_build >=0.12.5`. Project dependency declarations
set supported minimum versions without upper version caps so newer compatible
Python/tool releases can be tested without first changing package metadata.

The package installs three console entry points:

```text
lldp-runner
get-neighbors
show-neighbors
```

## Simple single-user source installation

For a workstation or other installation used by one account:

```bash
cd /opt/lldp-runner
uv sync --all-groups
uv run lldp-runner --version
```

For a runtime-only environment, use `uv sync --no-dev` instead of
`--all-groups`. The latter also installs pytest, Ruff, and Ty for maintenance.

## Why a shared installation needs explicit paths

A centrally managed installation needs more planning than a single-user uv
project. uv-managed Python normally lives below the installing user's home
directory. A shared project virtual environment can therefore point at a Python
runtime that another operator cannot traverse after the original account is
changed or removed.

For shared operation:

- keep the project under `/opt/lldp-runner`;
- install uv itself in a system/shared executable path;
- install uv-managed Python under `/opt/shared/python`;
- use explicit shared `persistent_root` and `scratch_root` paths;
- keep project source and `.venv` writable only by a maintainer when practical;
- give operators read/execute access to the project and shared Python;
- give operators/services group write access to runtime roots; and
- use `scripts/.private` so ordinary operators do not synchronize `.venv`.

The project sets `tool.uv.link-mode = "copy"` in `pyproject.toml`, so package
files are copied into the environment instead of depending on cache links owned
by one account.

## Shared uv and Python installation

Install uv itself somewhere every operator/service can execute it, such as
`/usr/local/bin`. Then install the managed Python into the shared directory.
The Python version below is an example pin; another Python 3.13-or-newer release
may be used when required by site standards.

```bash
export UV_PYTHON_INSTALL_DIR=/opt/shared/python

uv python install \
    --install-dir "$UV_PYTHON_INSTALL_DIR" \
    --no-bin \
    3.13.5

UV_PYTHON_INSTALL_DIR=/opt/shared/python uv python dir

export UV_LINK_MODE=copy
cd /opt/lldp-runner
uv sync --all-groups
```

`UV_PYTHON_INSTALL_DIR` must be visible to later uv commands that need to find
that managed Python. `UV_LINK_MODE=copy` is equivalent to the project setting
and is useful when installation commands are executed explicitly.

## Operator group and shared runtime directories

Create a trusted operator group and add all accounts that are allowed to use
LLDP-Runner. Group membership normally takes effect after a new login/session.

The shipped helper prepares runtime roots, repairs group ownership on existing
content, applies setgid directories, and adds default POSIX ACLs when `setfacl`
is available:

```bash
sudo /opt/lldp-runner/scripts/shared-setup.sh \
    --group netops \
    --persistent-root /var/lib/lldp-runner \
    --scratch-root /dev/shm/lldp-runner \
    --python-dir /opt/shared/python
```

The helper deliberately does not create the Unix group or add users. Identity
management remains an explicit administrator responsibility.

Use explicit shared runtime paths instead of leaving path selection at `auto`:

```toml
[paths]
persistent_root = "/var/lib/lldp-runner"
scratch_root = "/dev/shm/lldp-runner"
```

See `configs/conf.d/shared-paths.toml.example` for a reusable fragment. Explicit
paths prevent different users from selecting different home-directory or other
automatic runtime locations.

All users/services that run discovery, resume runs, clean state, or purge output
need appropriate group access. LLDP-Runner performs real create/remove write
probes for `persistent_root` and `scratch_root`; read access is not sufficient.

Setgid keeps new runtime entries in the shared group, but it does not guarantee
group write permission when a process uses `umask 0022`. The helper uses default
ACLs when available. Without POSIX ACL tools, use `umask 0002` for every shell,
cron, or service invocation. The equivalent systemd setting is `UMask=0002`.

## Shared launcher environment

The `lrun-*` launchers source `scripts/.private` when present. The release ships
`scripts/example.private` as a starting point for a centrally managed site.
Copy it to `.private`, review it, and protect the deployed copy:

```bash
cd /opt/lldp-runner
cp scripts/example.private scripts/.private
chown lldp-maintainer:netops scripts/.private
chmod 0640 scripts/.private
```

The example uses `lldp-maintainer` as the designated maintainer. For that
account, `UV_RUN_ARGS=()` permits normal `uv run` synchronization. Every other
operator and the `lldp-runner` service account receives:

```bash
UV_RUN_ARGS=(--no-sync)
```

This lets ordinary operators use the centrally prepared `.venv` without asking
uv to install, remove, or update packages. After an LLDP-Runner upgrade or
intentional dependency change, the maintainer must run `uv sync` before other
operators use the no-sync launchers.

The published dependency declarations retain supported minimum versions. For
maintainer-managed release environments, `[tool.uv]` applies exact runtime,
test, static-analysis, and build constraints. The same selections are listed in
`constraints/release-0.38.1.txt` for review. Run `uv lock`, then
`uv sync --all-groups --locked`, after extracting a release. This creates one
site lockfile from the release constraints and prevents later synchronization
from silently selecting a different tested toolchain. A deliberate dependency
upgrade should update the constraints, regenerate the lock, and rerun the full
release gate before ordinary `--no-sync` use resumes.

After synchronization, verify the three backend packages before production
discovery:

```bash
uv run python - <<'PY'
import importlib.metadata

for package in ("cryptography", "gufo-snmp", "pysnmp"):
    print(package, importlib.metadata.version(package))
PY

uv run ./scripts/pysnmp-snmp-diag.py DEVICE --snmp-version 3
```

The diagnostic reads `SNMPUSER`, `SNMPAUTH`, and `SNMPPRIV` from its
environment, performs the same local privacy-cipher preflight before DNS or
SNMP, and prints the installed cryptography version without printing credential
values.

`scripts/.private` also exports the shared Python location and copy link
mode and sets `umask 0002`. It is ignored by Git so site settings or
secrets are not accidentally committed. Avoid putting secrets there unless the
file permissions and group membership are appropriate for those secrets.

Direct `uv run` commands that bypass `lrun-*` need equivalent environment
settings. For a shared instance, they should also explicitly use
`--config /opt/lldp-runner/config.toml` or set `LLDP_RUNNER_CONFIG`; otherwise
normal config discovery can select a per-user configuration first.

## Project and credential-file ownership

For a centrally managed installation, keep `/opt/lldp-runner` and its `.venv`
writable only by package/application maintainers when practical. The operator
group normally needs read/execute access to code and Python. Runtime
write access belongs on the configured persistent/scratch roots instead.

Credential-bearing files deserve stricter treatment than runtime output. A
seed-credential file can be `root:netops` mode `0640` only when every member of
that group is authorized to use the secrets. Use a narrower group
when credential access should be more restricted. Do not store credential files
in group-writable runtime directories merely for convenience.

## Scheduled operation with systemd

For a shared Linux server, LLDP-Runner ships helpers that install the
recommended systemd schedule. Run `shared-setup.sh` first, then install the
units/timers:

```bash
sudo /opt/lldp-runner/scripts/svc-setup.sh \
    --service-user lldp-runner \
    --group netops \
    --project-root /opt/lldp-runner \
    --persistent-root /var/lib/lldp-runner \
    --scratch-root /dev/shm/lldp-runner \
    --python-dir /opt/shared/python \
    --purge-keep 11
```

The service account must already exist and be a member of the configured group.
`svc-setup.sh` refuses to create accounts/change memberships. If generated units
already exist, setup stops and instructs the administrator to remove them first.

The default schedule starts discovery at 00:00, 04:00, 08:00, 12:00, 16:00,
and 20:00, plus daily maintenance at 02:30. Both timers use a stable randomized
delay of up to ten minutes. Override it with `--random-delay MINUTES` or
`LLDP_RUNNER_RANDOM_DELAY_MINUTES`.

Daily maintenance runs `lrun-clean` and then `lrun-purge`. `--purge-keep 11`
means `latest` plus 11 additional output directories, for 12 total outputs.
Discovery and maintenance share one `flock` under `scratch_root`, so they wait
for one another instead of modifying run/output state concurrently.

When scratch storage is `/dev/shm`, it disappears at reboot. Writable
LLDP-Runner commands can create a missing explicit scratch root, but process
creation inherits the process's ownership/mode. `svc-setup.sh`
therefore installs `/etc/tmpfiles.d/lldp-runner.conf` and invokes
`systemd-tmpfiles --create` so the scratch root is recreated with the service
user, operator group, and mode `2775`.

Remove only the generated scheduling configuration with:

```bash
sudo /opt/lldp-runner/scripts/svc-remove.sh
```

Removal preserves persistent output/run state, the existing scratch directory,
and the service account/group.

## Ubuntu 24.04/26.04 LTS shared installation walkthrough

The following example starts with an LLDP-Runner source `tar.gz` in the current
directory. It uses `lldp-maintainer` as the designated maintainer and
`operator1` and `operator2` as example operators. Review account names,
paths, Python version, configuration, and credential policy before pasting
commands into a production server.

Run the administrative portions from a sudo-capable account. Before copying the
block, set `CONFIG_SOURCE` and `SEED_SOURCE` to approved site files. A site
using `@include` or additional configuration fragments must install those
files too.

```bash
# ---------------------------------------------------------------------------
# 0. Review these site-specific inputs before doing anything destructive.
# ---------------------------------------------------------------------------
ARCHIVE="$PWD/lldp-runner-0.38.1.tar.gz"
CONFIG_SOURCE="/path/to/approved-config.toml"
SEED_SOURCE="/path/to/approved-seed.list"
DEVELOPER="lldp-maintainer"
OPERATORS=(operator1 operator2)
PYTHON_VERSION="3.13.5"

[[ -f "$ARCHIVE" ]] || { echo "Missing archive: $ARCHIVE" >&2; exit 1; }
[[ -f "$CONFIG_SOURCE" ]] || {
    echo "Set CONFIG_SOURCE to an approved LLDP-Runner config." >&2
    exit 1
}
[[ -f "$SEED_SOURCE" ]] || {
    echo "Set SEED_SOURCE to an approved LLDP-Runner seed file." >&2
    exit 1
}
id "$DEVELOPER" >/dev/null 2>&1 || {
    echo "Developer account does not exist: $DEVELOPER" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Install basic operating-system prerequisites.
# ---------------------------------------------------------------------------
sudo apt-get update
sudo apt-get install -y ca-certificates curl acl util-linux

# ---------------------------------------------------------------------------
# 2. Create the trusted NetOps group when it does not already exist.
# ---------------------------------------------------------------------------
getent group netops >/dev/null || sudo groupadd netops

# ---------------------------------------------------------------------------
# 3. Create the non-login LLDP-Runner service account when it does not exist.
#    Its primary group is netops so scheduled discovery inherits that group.
# ---------------------------------------------------------------------------
if ! getent passwd lldp-runner >/dev/null; then
    sudo useradd \
        --system \
        --gid netops \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        lldp-runner
fi

# ---------------------------------------------------------------------------
# 4. Add the maintainer and example operators to netops.
#    Replace OPERATORS above with the actual site account list.
# ---------------------------------------------------------------------------
for user in "$DEVELOPER" "${OPERATORS[@]}"; do
    if id "$user" >/dev/null 2>&1; then
        sudo usermod -aG netops "$user"
    else
        printf 'WARNING: user %s does not exist; group membership skipped.\n' \
            "$user" >&2
    fi
done

# The service account must also be a member of netops.
id -nG lldp-runner | tr ' ' '\n' | grep -Fxq netops || {
    echo "lldp-runner is not a member of netops" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# 5. Install uv in a shared executable location.
#    UV_NO_MODIFY_PATH prevents edits to the administrator's shell profile.
# ---------------------------------------------------------------------------
curl -LsSf https://astral.sh/uv/install.sh | \
    sudo env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh

/usr/local/bin/uv --version

# ---------------------------------------------------------------------------
# 6. Extract the bundled release under /opt/lldp-runner.
#    Archive executable bits are preserved; ownership moves to the maintainer.
# ---------------------------------------------------------------------------
sudo install -d -o "$DEVELOPER" -g netops -m 0755 /opt/lldp-runner
sudo tar -xzf "$ARCHIVE" -C /opt/lldp-runner --strip-components=1
sudo chown -R "$DEVELOPER":netops /opt/lldp-runner
sudo chmod -R u+rwX,g+rX,o+rX /opt/lldp-runner

# The chmod above only adds permissions. An archive with group-writable
# modes, such as GitHub's automatic "Source code" download, leaves the code
# writable by every netops member. Depending on local site requirements,
# consider removing group and other write access so only the maintainer can
# change the installed code:
# sudo chmod -R go-w /opt/lldp-runner

# ---------------------------------------------------------------------------
# 7. Prepare shared Python and synchronize the project as the maintainer.
# ---------------------------------------------------------------------------
sudo install -d -o "$DEVELOPER" -g netops -m 0755 /opt/shared/python

sudo -u "$DEVELOPER" env \
    UV_PYTHON_INSTALL_DIR=/opt/shared/python \
    UV_LINK_MODE=copy \
    /usr/local/bin/uv python install \
        --install-dir /opt/shared/python \
        --no-bin \
        "$PYTHON_VERSION"

sudo -u "$DEVELOPER" env \
    UV_PYTHON_INSTALL_DIR=/opt/shared/python \
    UV_LINK_MODE=copy \
    /usr/local/bin/uv lock \
        --directory /opt/lldp-runner

sudo -u "$DEVELOPER" env \
    UV_PYTHON_INSTALL_DIR=/opt/shared/python \
    UV_LINK_MODE=copy \
    /usr/local/bin/uv sync \
        --directory /opt/lldp-runner \
        --all-groups \
        --locked

# ---------------------------------------------------------------------------
# 8. Install the launcher environment. Change its maintainer account if
#    DEVELOPER differs from the shipped neutral example.
# ---------------------------------------------------------------------------
sudo install \
    -o "$DEVELOPER" \
    -g netops \
    -m 0640 \
    /opt/lldp-runner/scripts/example.private \
    /opt/lldp-runner/scripts/.private

# ---------------------------------------------------------------------------
# 9. Install the approved site config and seed list used by lrun-run.
# ---------------------------------------------------------------------------
sudo install -o "$DEVELOPER" -g netops -m 0640 \
    "$CONFIG_SOURCE" /opt/lldp-runner/config.toml
sudo install -o "$DEVELOPER" -g netops -m 0640 \
    "$SEED_SOURCE" /opt/lldp-runner/seed.list

# Add explicit shared runtime paths without duplicating them in the site file.
sudo install -d -o "$DEVELOPER" -g netops -m 0755 \
    /opt/lldp-runner/conf.d
sudo -u "$DEVELOPER" tee \
    /opt/lldp-runner/conf.d/10-shared-paths.toml >/dev/null <<'EOF_PATHS'
[paths]
persistent_root = "/var/lib/lldp-runner"
scratch_root = "/dev/shm/lldp-runner"
EOF_PATHS
sudo chown "$DEVELOPER":netops \
    /opt/lldp-runner/conf.d/10-shared-paths.toml
sudo chmod 0640 /opt/lldp-runner/conf.d/10-shared-paths.toml

# ---------------------------------------------------------------------------
# 10. Prepare group-writable runtime roots.
# ---------------------------------------------------------------------------
sudo /opt/lldp-runner/scripts/shared-setup.sh \
    --group netops \
    --persistent-root /var/lib/lldp-runner \
    --scratch-root /dev/shm/lldp-runner \
    --python-dir /opt/shared/python

# ---------------------------------------------------------------------------
# 11. Validate configuration and seed behavior before enabling services.
# ---------------------------------------------------------------------------
sudo -u lldp-runner \
    /opt/lldp-runner/scripts/lrun-version

sudo -u lldp-runner \
    /opt/lldp-runner/scripts/lrun-checkconfig

sudo -u lldp-runner \
    /opt/lldp-runner/scripts/lrun-dryrun

# ---------------------------------------------------------------------------
# 12. Review maintenance selection without deleting anything.
# ---------------------------------------------------------------------------
sudo -u lldp-runner \
    /opt/lldp-runner/scripts/lrun-clean --dry-run

sudo -u lldp-runner \
    /opt/lldp-runner/scripts/lrun-purge --keep 11 --dry-run

# ---------------------------------------------------------------------------
# 13. Install and enable the systemd discovery/maintenance timers.
# ---------------------------------------------------------------------------
sudo /opt/lldp-runner/scripts/svc-setup.sh \
    --service-user lldp-runner \
    --group netops \
    --project-root /opt/lldp-runner \
    --persistent-root /var/lib/lldp-runner \
    --scratch-root /dev/shm/lldp-runner \
    --python-dir /opt/shared/python \
    --purge-keep 11

# ---------------------------------------------------------------------------
# 14. Verify installed schedules and inspect service logs.
# ---------------------------------------------------------------------------
systemctl list-timers 'lldp-runner-*'
systemctl status lldp-runner-run.timer lldp-runner-maintenance.timer
journalctl -u lldp-runner-run.service -n 50 --no-pager
journalctl -u lldp-runner-maintenance.service -n 50 --no-pager
```

New group membership is normally visible only after users start a new login
session. Before enabling production discovery, test `lrun-dryrun`, validate
credential/query/classification policy, confirm seed inputs, and verify that the
service account can write both configured runtime roots.

## Maintaining the shared installation

The designated maintainer should update the source, lock/environment, and Python
packages. A typical post-upgrade synchronization is:

```bash
export UV_PYTHON_INSTALL_DIR=/opt/shared/python
export UV_LINK_MODE=copy
umask 0002

cd /opt/lldp-runner
uv sync --all-groups
uv run pytest
```

Ordinary operators should continue using the `lrun-*` launchers. Because the
example `.private` gives non-maintainers `UV_RUN_ARGS=(--no-sync)`, operational
commands use the environment prepared by the maintainer without modifying it.

After changing generated service/timer settings, use `svc-remove.sh` and then
`svc-setup.sh` rather than manually editing generated unit files.
