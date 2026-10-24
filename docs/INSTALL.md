# Installing LLDP-Runner

This document is the installation reference for LLDP-Runner. It covers the
recommended shared installation under `/opt/lldp-runner` for a group of NetOps
operators, a system layout for distribution packages, and a single-user
installation below a home directory.

The shared examples assume Ubuntu Linux 24.04 LTS or 26.04 LTS, a project
installed at `/opt/lldp-runner`, a shared uv-managed Python under
`/opt/shared/python`, a trusted operator group named `netops`, and an
LLDP-Runner service account named `lldp-runner`.

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

The default `time.timezone` (`eastern`) and other IANA zone names need the
operating system's time zone database. Minimal Ubuntu images, such as
containers, may not include it; without it every command fails at startup
with `ZoneInfoNotFoundError`. Install the `tzdata` package on such hosts.


## Install layouts

An installation is defined by its primary configuration file. While
`paths.persistent_root` and `paths.scratch_root` keep their default value
`auto`, LLDP-Runner places runtime data with that file, so every operator of
one installation reads and writes the same data:

- **shared** (the default deployment): `/opt/lldp-runner/config.toml`, or any
  `<dir>/config.toml` outside the invoking user's home directory. Persistent
  root `<dir>/var`; scratch root `/dev/shm/lldp-runner`.
- **system** (distribution packages): `/etc/lldp-runner/config.toml`.
  Persistent root `/var/lib/lldp-runner`; scratch root `/run/lldp-runner`, then
  `/dev/shm/lldp-runner`.
- **user** (one account): `~/lldp-runner/config.toml` or another configuration
  below the home directory, `~/lldp-runner-config.toml`, or no configuration
  file at all. Persistent root `<dir>/var`, or `~/lldp-runner/var` without a
  file; scratch root `$XDG_RUNTIME_DIR/lldp-runner`.

Every layout falls back to `<persistent_root>/tmp` when its preferred scratch
root is unavailable. The persistent root holds `runs/` (run state, activity
logs) and `outputs/` (finalized `discovery.json`, CSV files, and `latest`
links).

A shared installation therefore uses these folders:

```text
/opt/lldp-runner/              code, .venv, launchers, config.toml, conf.d/,
                               seed.list, scripts/.private
/opt/lldp-runner/var/runs/     run state and activity logs
/opt/lldp-runner/var/outputs/  finalized outputs and the latest link
/opt/lldp-runner/var/tmp/      scratch fallback
/dev/shm/lldp-runner/          scratch: current run, scoreboard, drafts
/opt/shared/python/            uv-managed Python
/usr/local/bin/uv              uv
```

Data lives in a `var/` subdirectory, not in `/opt/lldp-runner` itself, because
discovery write-tests its persistent root. A group-writable installation
directory would let any operator add files, such as `uv.toml` or `conf.d/`,
that the maintainer's next `uv sync` or the service account's next run would
load. Only `var/` and the scratch root are writable by the operator group.

Sites that depend on the older `/opt/lldp-runner/runs` and
`/opt/lldp-runner/outputs` locations can add compatibility links:

```bash
sudo ln -s var/runs /opt/lldp-runner/runs
sudo ln -s var/outputs /opt/lldp-runner/outputs
```

An installation that still keeps real `runs/` and `outputs/` directories
directly in `<dir>`, with no `<dir>/var`, keeps using them and prints a warning.
See [Moving data into var/](#moving-data-into-var) to convert it.

Explicit values always win over the layout. Set `[paths]` in the primary
`config.toml` (it overrides `conf.d` fragments), or use `LLDP_RUNNER_ROOT` and
`LLDP_RUNNER_SCRATCH_ROOT`, which override the file. Check the effective
locations at any time without creating anything:

```bash
/opt/lldp-runner/scripts/lrun-paths
lldp-runner --config /opt/lldp-runner/config.toml paths --json
```

## Single-user installation

For a workstation or a restricted host where one account runs LLDP-Runner,
install the project below the home directory. The default uv-managed Python
below the home directory is fine here because no other account uses it.

```bash
mkdir -p ~/lldp-runner
tar -xzf lldp-runner-0.38.1.tar.gz -C ~/lldp-runner --strip-components=1
cd ~/lldp-runner
uv sync --no-dev
uv run lldp-runner generate-config
uv run lldp-runner paths
```

`generate-config` writes `~/lldp-runner/config.toml`. The user layout keeps run
state and outputs in `~/lldp-runner/var`, created on first use, and scratch data
in `$XDG_RUNTIME_DIR/lldp-runner` (or `~/lldp-runner/var/tmp` when no session
runtime directory exists, such as under cron). The `scripts/lrun-*` launchers
select `~/lldp-runner/config.toml` automatically.

Use `uv sync --all-groups` instead of `--no-dev` to also install pytest, Ruff,
and Ty for maintenance.

## Why a shared installation needs a shared Python

uv-managed Python normally lives below the installing user's home directory.
Ubuntu creates home directories with mode `0750`, so a shared project
environment that points at such a Python fails for every other operator with
`Permission denied`. The same failure appears when the original account is
changed or removed.

For shared operation:

- keep the project under `/opt/lldp-runner`;
- install uv itself in a system/shared executable path;
- install uv-managed Python under `/opt/shared/python`, owned by root;
- keep project source and `.venv` writable only by a maintainer;
- give the operator group read/execute access to the project and no access to
  other users;
- give operators/services group write access only to `var/` and the scratch
  root; and
- use `scripts/.private` so ordinary operators do not synchronize `.venv`.

The project sets `tool.uv.link-mode = "copy"` in `pyproject.toml`, so package
files are copied into the environment instead of depending on cache links owned
by one account.

## Shared uv and Python installation

Install uv itself somewhere every operator/service can execute it, such as
`/usr/local/bin`. Then install the managed Python into the shared directory as
root. The Python version below is an example pin; another Python 3.13-or-newer
release may be used when required by site standards.

```bash
sudo install -d -o root -g root -m 0755 /opt/shared/python

sudo env UV_PYTHON_INSTALL_DIR=/opt/shared/python \
    /usr/local/bin/uv python install \
        --install-dir /opt/shared/python \
        --no-bin \
        3.13.17
```

uv installs each patch release in its own directory and maintains a
minor-version link that project environments refer to:

```text
/opt/shared/python/cpython-3.13.17-linux-x86_64-gnu/
/opt/shared/python/cpython-3.13-linux-x86_64-gnu -> cpython-3.13.17-...
/opt/lldp-runner/.venv/bin/python
    -> /opt/shared/python/cpython-3.13-linux-x86_64-gnu/bin/python3.13
```

`--no-bin` keeps uv from adding `python3.13` links to root's `~/.local/bin`.
Installing a later 3.13 patch the same way moves the minor-version link, so the
project environment uses the new interpreter without another `uv sync`.

`UV_PYTHON_INSTALL_DIR` must be visible to every later uv command that needs
to find that managed Python. uv's `uv.toml` cannot set it, so add two
server-wide guard rails:

```bash
sudo install -d -m 0755 /etc/uv
sudo tee /etc/uv/uv.toml >/dev/null <<'EOF'
python-downloads = "manual"
python-preference = "only-managed"
EOF

echo 'export UV_PYTHON_INSTALL_DIR=/opt/shared/python' | \
    sudo tee /etc/profile.d/uv-shared-python.sh >/dev/null
```

`python-downloads = "manual"` stops uv from silently downloading a Python into
a home directory when `UV_PYTHON_INSTALL_DIR` is missing, for example after
`sudo -u` or in a script; the command fails with a hint instead. Explicit
`uv python install` still works. `python-preference = "only-managed"` keeps uv
from selecting the operating system's Python, which is 3.14 on Ubuntu 26.04.
The profile script sets the shared directory for login shells. These settings
apply to every uv user on the server.

## Operator group and shared runtime directories

Create a trusted operator group and add all accounts that are allowed to use
LLDP-Runner. Group membership normally takes effect after a new login/session.

The shipped helper creates the runtime directories, repairs group ownership on
existing content, applies setgid directories, removes access for other users,
and adds default POSIX ACLs when `setfacl` is available:

```bash
sudo /opt/lldp-runner/scripts/shared-setup.sh --group netops
```

With the defaults (`--layout shared --project-root /opt/lldp-runner`) it
prepares:

```text
/opt/lldp-runner/var             root:netops 2770 (+ default ACLs)
/opt/lldp-runner/var/runs        root:netops 2770
/opt/lldp-runner/var/outputs     root:netops 2770
/opt/lldp-runner/var/tmp         root:netops 2770
/dev/shm/lldp-runner             root:netops 2770
/etc/tmpfiles.d/lldp-runner-scratch.conf
```

`/dev/shm` is cleared at every reboot. The tmpfiles entry recreates the scratch
root with the same ownership, mode, and ACLs at boot, so the first operator to
run after a reboot cannot create it with private permissions. `--layout system`
prepares `/var/lib/lldp-runner` and `/run/lldp-runner` instead. The helper
refuses a runtime root that equals or contains the project root.

It creates `/opt/shared/python` root-owned when it is missing and otherwise
leaves its ownership alone. It warns when that directory or the project root is
group- or world-writable.

The helper deliberately does not create the Unix group or add users. Identity
management remains an explicit administrator responsibility.

Keep the automatic values in the site configuration:

```toml
[paths]
persistent_root = "auto"
scratch_root = "auto"
```

A configuration created by `generate-config` already contains these lines.
Because the primary `config.toml` overrides `conf.d` fragments, do not try to
set shared paths in a fragment while `config.toml` sets them too.

All users/services that run discovery, resume runs, clean state, or purge output
need appropriate group access. LLDP-Runner performs real create/remove write
probes for `persistent_root` and `scratch_root`; read access is not sufficient.
Read-only commands such as `show-neighbors`, `status`, and `paths` need only
group read access.

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

uv needs a writable cache directory even for `--no-sync` runs. A service
account whose home is `/nonexistent` cannot create `~/.cache/uv`, so
`example.private` sets `UV_NO_CACHE=1` whenever that directory cannot be
created. The systemd units installed by `svc-setup.sh` set `UV_CACHE_DIR`
instead.

The launchers select `/opt/lldp-runner/config.toml` automatically (see
[CLI.md](CLI.md) and the launcher headers), so the shared configuration and its
`var/` data apply to every operator. Set `LLDP_RUNNER_CONFIG` in `.private`
only to use a different file.

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
normal config discovery can select a per-user configuration first, and with it
per-user data.

## Project and credential-file ownership

For a centrally managed installation, keep `/opt/lldp-runner` and its `.venv`
writable only by the maintainer. The operator group needs read/execute access
to code and Python; other users need none:

```bash
sudo chown -R lldp-maintainer:netops /opt/lldp-runner
sudo chmod -R u+rwX,g+rX,g-w,o-rwx /opt/lldp-runner
```

Run `shared-setup.sh` after such recursive changes; it restores the group
write access of `var/`.

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
    --python-dir /opt/shared/python \
    --purge-keep 11
```

The service account must already exist and be a member of the configured group.
`svc-setup.sh` refuses to create accounts/change memberships. If generated units
already exist, setup stops and instructs the administrator to remove them first.
It also stops when the scratch root (default `/dev/shm/lldp-runner`) or the
persistent root (default `<project-root>/var`) does not exist yet.

The default schedule starts discovery at 00:00, 04:00, 08:00, 12:00, 16:00,
and 20:00, plus daily maintenance at 02:30. Both timers use a stable randomized
delay of up to ten minutes. Override it with `--random-delay MINUTES` or
`LLDP_RUNNER_RANDOM_DELAY_MINUTES`.

Daily maintenance runs `lrun-clean` and then `lrun-purge`. `--purge-keep 11`
means `latest` plus 11 additional output directories, for 12 total outputs.
Discovery and maintenance share one `flock` under the scratch root, so they wait
for one another instead of modifying run/output state concurrently.

The units run as the service account with `UMask=0002`, the shared Python
location, and a uv cache in `/var/cache/lldp-runner/uv` that systemd creates
through `CacheDirectory=`. The scratch root is recreated at boot by the
tmpfiles entry that `shared-setup.sh` installs.

Remove only the generated scheduling configuration with:

```bash
sudo /opt/lldp-runner/scripts/svc-remove.sh
```

Removal preserves persistent output/run state, the existing scratch directory,
its tmpfiles entry, and the service account/group.

## System layout for distribution packages

A distribution package should not install into `/opt`; Debian policy, for
example, reserves it for the local administrator. Use the system layout
instead:

- install the Python package so the `lldp-runner`, `get-neighbors`, and
  `show-neighbors` entry points are on `PATH`, for example in `/usr/bin`;
- ship `/etc/lldp-runner/config.toml` with `persistent_root = "auto"` and
  `scratch_root = "auto"`, which select `/var/lib/lldp-runner` and
  `/run/lldp-runner`;
- create `/var/lib/lldp-runner/{runs,outputs,tmp}` and a tmpfiles entry for
  `/run/lldp-runner`, owned by the package's service group with mode `2770`
  (`scripts/shared-setup.sh --layout system --group GROUP` performs both); and
- optionally ship the `lrun-*` launchers, for example in
  `/usr/share/lldp-runner/scripts`. Without a `pyproject.toml` beside them they
  run the installed `lldp-runner` from `PATH` and select
  `/etc/lldp-runner/config.toml`.

The layout constants live in `lldp_runner/defaults.py` (`SYSTEM_CONFIG_DIR`,
`SYSTEM_PERSISTENT_ROOT`, `SYSTEM_SCRATCH_ROOTS`, and related names), so a
distribution that needs different locations can change them in one place. Units
for a package can follow the ones `svc-setup.sh` generates, with
`ExecStart=` calling `/usr/bin/lldp-runner` directly.

## Ubuntu 24.04/26.04 LTS shared installation walkthrough

The following example starts with an LLDP-Runner source `tar.gz` in the current
directory. It uses `lldp-maintainer` as the designated maintainer and
`operator1` and `operator2` as example operators. Review account names,
paths, Python version, configuration, and credential policy before pasting
commands into a production server.

Ubuntu 26.04 uses `sudo-rs` and the Rust coreutils; the commands below work
with them and with the classic tools on 24.04.

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
PYTHON_VERSION="3.13.17"

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
sudo apt-get install -y ca-certificates curl acl util-linux tzdata

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
# 5. Install uv in a shared executable location, plus the server-wide guard
#    rails that keep uv-managed Python out of home directories.
#    UV_NO_MODIFY_PATH prevents edits to the administrator's shell profile.
# ---------------------------------------------------------------------------
curl -LsSf https://astral.sh/uv/install.sh | \
    sudo env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh

/usr/local/bin/uv --version

sudo install -d -m 0755 /etc/uv
sudo tee /etc/uv/uv.toml >/dev/null <<'EOF_UV'
python-downloads = "manual"
python-preference = "only-managed"
EOF_UV
echo 'export UV_PYTHON_INSTALL_DIR=/opt/shared/python' | \
    sudo tee /etc/profile.d/uv-shared-python.sh >/dev/null

# ---------------------------------------------------------------------------
# 6. Extract the bundled release under /opt/lldp-runner.
#    Ownership moves to the maintainer; netops may read, other users may not.
# ---------------------------------------------------------------------------
sudo install -d -o "$DEVELOPER" -g netops -m 0750 /opt/lldp-runner
sudo tar -xzf "$ARCHIVE" -C /opt/lldp-runner --strip-components=1
sudo chown -R "$DEVELOPER":netops /opt/lldp-runner
sudo chmod -R u+rwX,g+rX,g-w,o-rwx /opt/lldp-runner

# ---------------------------------------------------------------------------
# 7. Install the shared Python as root, then lock and synchronize the project
#    as the maintainer.
# ---------------------------------------------------------------------------
sudo install -d -o root -g root -m 0755 /opt/shared/python

sudo env UV_PYTHON_INSTALL_DIR=/opt/shared/python \
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

# The environment must point at the shared Python, never a home directory.
grep '^home = /opt/shared/python/' /opt/lldp-runner/.venv/pyvenv.cfg

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
#    Keep [paths] at "auto" so data goes to /opt/lldp-runner/var.
# ---------------------------------------------------------------------------
sudo install -o "$DEVELOPER" -g netops -m 0640 \
    "$CONFIG_SOURCE" /opt/lldp-runner/config.toml
sudo install -o "$DEVELOPER" -g netops -m 0640 \
    "$SEED_SOURCE" /opt/lldp-runner/seed.list

grep -E '^(persistent_root|scratch_root) *=' /opt/lldp-runner/config.toml || \
    echo 'No [paths] roots set: the automatic paths apply.'

# ---------------------------------------------------------------------------
# 10. Prepare the group-writable runtime directories and the boot-time
#     scratch entry.
# ---------------------------------------------------------------------------
sudo /opt/lldp-runner/scripts/shared-setup.sh --group netops

# ---------------------------------------------------------------------------
# 11. Validate paths, configuration, and seed behavior before enabling
#     services.
# ---------------------------------------------------------------------------
sudo -u lldp-runner \
    /opt/lldp-runner/scripts/lrun-version

sudo -u lldp-runner \
    /opt/lldp-runner/scripts/lrun-paths

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

When extracting a new release over `/opt/lldp-runner`, repeat the ownership
commands from step 6 and then run `shared-setup.sh` again, so `var/` keeps its
group write access.

Python patch releases are installed by root as in step 7 with the new version.
The minor-version link moves to the new patch, and the project environment uses
it immediately. Remove an old patch once nothing else depends on it:

```bash
sudo env UV_PYTHON_INSTALL_DIR=/opt/shared/python \
    /usr/local/bin/uv python uninstall --install-dir /opt/shared/python 3.13.15
```

Ordinary operators should continue using the `lrun-*` launchers. Because the
example `.private` gives non-maintainers `UV_RUN_ARGS=(--no-sync)`, operational
commands use the environment prepared by the maintainer without modifying it.

After changing generated service/timer settings, use `svc-remove.sh` and then
`svc-setup.sh` rather than manually editing generated unit files.

## Moving data into var/

Older shared installations kept `runs/` and `outputs/` directly in
`/opt/lldp-runner`, which required a group-writable installation directory.
LLDP-Runner keeps using that location, with a warning, until
`/opt/lldp-runner/var` exists. To convert:

```bash
sudo systemctl stop lldp-runner-run.timer lldp-runner-maintenance.timer
sudo install -d -o root -g netops -m 2770 /opt/lldp-runner/var
sudo mv /opt/lldp-runner/runs /opt/lldp-runner/outputs /opt/lldp-runner/var/
sudo chmod -R g-w /opt/lldp-runner
sudo /opt/lldp-runner/scripts/shared-setup.sh --group netops
/opt/lldp-runner/scripts/lrun-paths
sudo systemctl start lldp-runner-run.timer lldp-runner-maintenance.timer
```

Keep the timers stopped and start no runs until the move is complete: once
`var/` exists, LLDP-Runner uses it, and runs left in the old location are no
longer resumed, diffed, or purged. Sites that set explicit paths, such as
`/var/lib/lldp-runner`, are not affected; either keep the explicit `[paths]` or
move the data and return to `auto`.

If the old scheduling was installed by an earlier `svc-setup.sh`, also run
`svc-remove.sh` and then `svc-setup.sh`. The earlier helper owned
`/etc/tmpfiles.d/lldp-runner.conf`; `shared-setup.sh` now maintains
`/etc/tmpfiles.d/lldp-runner-scratch.conf` instead.
