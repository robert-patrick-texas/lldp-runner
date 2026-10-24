#!/usr/bin/env bash

# Prepare dedicated LLDP-Runner runtime directories for a trusted operator group.
# Run this script with sudo/root before using a centrally managed installation.

set -euo pipefail

# Defaults for the shared layout: one installation under /opt/lldp-runner whose
# runtime data lives in /opt/lldp-runner/var and whose scratch data lives in
# /dev/shm/lldp-runner. These match LLDP-Runner's automatic paths for
# /opt/lldp-runner/config.toml, so the site config can keep paths = "auto".
LAYOUT="${LLDP_RUNNER_LAYOUT:-shared}"
GROUP_NAME="${LLDP_RUNNER_GROUP:-netops}"
PROJECT_ROOT="${LLDP_RUNNER_PROJECT_ROOT:-/opt/lldp-runner}"
PERSISTENT_ROOT="${LLDP_RUNNER_PERSISTENT_ROOT:-}"
SCRATCH_ROOT="${LLDP_RUNNER_SCRATCH_ROOT:-}"
PYTHON_DIR="${UV_PYTHON_INSTALL_DIR:-/opt/shared/python}"

# Recreates the scratch root with the same ownership after a reboot clears
# /dev/shm or /run. svc-setup.sh relies on this entry for scheduled runs.
TMPFILES_FILE="/etc/tmpfiles.d/lldp-runner-scratch.conf"

usage()
{
    cat <<'USAGE'
Usage: sudo scripts/shared-setup.sh [options]

Options:
  --layout shared|system   shared: data in <project-root>/var (default)
                           system: data in /var/lib/lldp-runner
  --group NAME             Trusted LLDP-Runner operator group (default: netops).
  --project-root PATH      Shared installation directory (default: /opt/lldp-runner).
  --persistent-root PATH   Override the persistent_root directory.
  --scratch-root PATH      Override the scratch_root directory.
  --python-dir PATH        Shared uv-managed Python installation directory.
  -h, --help               Show this help.

Defaults may also be supplied with:
  LLDP_RUNNER_LAYOUT
  LLDP_RUNNER_GROUP
  LLDP_RUNNER_PROJECT_ROOT
  LLDP_RUNNER_PERSISTENT_ROOT
  LLDP_RUNNER_SCRATCH_ROOT
  UV_PYTHON_INSTALL_DIR
USAGE
}

die()
{
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

warn()
{
    printf 'Warning: %s\n' "$*" >&2
}

while (($#)); do
    case "$1" in
        --layout)
            (($# >= 2)) || die "--layout requires a value"
            LAYOUT="$2"
            shift 2
            ;;
        --group)
            (($# >= 2)) || die "--group requires a value"
            GROUP_NAME="$2"
            shift 2
            ;;
        --project-root)
            (($# >= 2)) || die "--project-root requires a value"
            PROJECT_ROOT="$2"
            shift 2
            ;;
        --persistent-root)
            (($# >= 2)) || die "--persistent-root requires a value"
            PERSISTENT_ROOT="$2"
            shift 2
            ;;
        --scratch-root)
            (($# >= 2)) || die "--scratch-root requires a value"
            SCRATCH_ROOT="$2"
            shift 2
            ;;
        --python-dir)
            (($# >= 2)) || die "--python-dir requires a value"
            PYTHON_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

paths_overridden=false
if [[ -n "$PERSISTENT_ROOT" || -n "$SCRATCH_ROOT" ]]; then
    paths_overridden=true
fi

case "$LAYOUT" in
    shared)
        : "${PERSISTENT_ROOT:=${PROJECT_ROOT}/var}"
        : "${SCRATCH_ROOT:=/dev/shm/lldp-runner}"
        ;;
    system)
        : "${PERSISTENT_ROOT:=/var/lib/lldp-runner}"
        : "${SCRATCH_ROOT:=/run/lldp-runner}"
        ;;
    *)
        die "--layout must be 'shared' or 'system'; a single-user install needs no setup"
        ;;
esac

[[ ${EUID} -eq 0 ]] || die "run this script with sudo or as root"
getent group "$GROUP_NAME" >/dev/null || \
    die "group '$GROUP_NAME' does not exist; create it before running this script"

for path in "$PROJECT_ROOT" "$PERSISTENT_ROOT" "$SCRATCH_ROOT" "$PYTHON_DIR"; do
    [[ "$path" = /* ]] || die "path must be absolute: $path"
    [[ "$path" != "/" ]] || die "refusing to use / as a managed path: $path"
    [[ "$path" != *[[:space:]]* ]] || die "paths may not contain whitespace: $path"
done
[[ "$PERSISTENT_ROOT" != "$SCRATCH_ROOT" ]] || \
    die "persistent_root and scratch_root must be different directories"

# A group-writable installation root would let any operator add files that the
# maintainer or the service account later loads, such as uv.toml or conf.d/.
# Runtime data therefore lives in its own subdirectory.
project_resolved="$(realpath -m -- "$PROJECT_ROOT")"
for root in "$PERSISTENT_ROOT" "$SCRATCH_ROOT"; do
    resolved="$(realpath -m -- "$root")"
    case "$project_resolved/" in
        "$resolved"/*)
            die "runtime root $root must not be the project root or one of its parents; use ${PROJECT_ROOT}/var"
            ;;
    esac
done

# The shared interpreter is centrally maintained and owned by root. Operators
# need read/execute access but never modify it. An existing directory is left
# exactly as the administrator created it.
if [[ ! -e "$PYTHON_DIR" ]]; then
    install -d -o root -g root -m 0755 "$PYTHON_DIR"
elif [[ -n "$(find "$PYTHON_DIR" -maxdepth 0 -perm /022)" ]]; then
    warn "$PYTHON_DIR is group- or world-writable; members could replace the interpreter"
fi

if [[ -d "$PROJECT_ROOT" && -n "$(find "$PROJECT_ROOT" -maxdepth 0 -perm /022)" ]]; then
    warn "$PROJECT_ROOT is group- or world-writable; only its maintainer should change it"
fi

# Runtime roots are group writable, setgid, and closed to other users. Existing
# runtime content is also normalized because an installation may be converted
# from single-user use or from an older, world-readable layout.
install -d -o root -g "$GROUP_NAME" -m 2770 "$PERSISTENT_ROOT"
install -d -o root -g "$GROUP_NAME" -m 2770 "$SCRATCH_ROOT"
install -d -o root -g "$GROUP_NAME" -m 2770 \
    "$PERSISTENT_ROOT/runs" "$PERSISTENT_ROOT/outputs" "$PERSISTENT_ROOT/tmp"

for root in "$PERSISTENT_ROOT" "$SCRATCH_ROOT"; do
    chgrp -R "$GROUP_NAME" "$root"
    chmod -R g+rwX,o-rwx "$root"
    find "$root" -type d -exec chmod g+s {} +
done

# Default ACLs are stronger than relying on every user's shell/service umask.
# They keep new files group writable and new directories group traversable.
acl_line=""
if command -v setfacl >/dev/null 2>&1; then
    for root in "$PERSISTENT_ROOT" "$SCRATCH_ROOT"; do
        find "$root" -type d -exec \
            setfacl -m g::rwx,m::rwx,o::-,d:g::rwx,d:m::rwx,d:o::- {} +
        find "$root" -type f -exec setfacl -m g::rw,m::rw,o::- {} +
    done
    acl_line="a+ $SCRATCH_ROOT - - - - d:g::rwx,d:m::rwx,d:o::-,g::rwx,m::rwx,o::-"
    acl_note="default POSIX ACLs applied"
else
    acl_note="setfacl not found; configure umask 0002 for every LLDP-Runner process"
fi

{
    printf '# Managed by LLDP-Runner scripts/shared-setup.sh\n'
    printf 'd %s 2770 root %s - -\n' "$SCRATCH_ROOT" "$GROUP_NAME"
    if [[ -n "$acl_line" ]]; then
        printf '%s\n' "$acl_line"
    fi
} > "$TMPFILES_FILE"
chmod 0644 "$TMPFILES_FILE"
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create "$TMPFILES_FILE"
    tmpfiles_note="$TMPFILES_FILE (applied)"
else
    tmpfiles_note="$TMPFILES_FILE (systemd-tmpfiles not found; recreate $SCRATCH_ROOT after reboot)"
fi

cat <<EOF_SUMMARY
Shared LLDP-Runner directories prepared.

Install layout:   $LAYOUT
Operator group:   $GROUP_NAME
Persistent root:  $PERSISTENT_ROOT (runs/, outputs/, tmp/)
Scratch root:     $SCRATCH_ROOT
Boot recreation:  $tmpfiles_note
uv Python dir:    $PYTHON_DIR
Permissions:      setgid + group read/write, no access for others; $acl_note

EOF_SUMMARY
if [[ "$paths_overridden" == true ]]; then
    cat <<EOF_PATHS
These are not the automatic paths for this layout. Set them in the primary
config.toml (conf.d fragments cannot override it):

[paths]
persistent_root = "$PERSISTENT_ROOT"
scratch_root = "$SCRATCH_ROOT"

EOF_PATHS
elif [[ "$LAYOUT" == shared ]]; then
    printf 'LLDP-Runner selects these paths for %s/config.toml while\n' "$PROJECT_ROOT"
    printf '[paths] keeps the "auto" values.\n\n'
else
    printf 'LLDP-Runner selects these paths for /etc/lldp-runner/config.toml while\n'
    printf '[paths] keeps the "auto" values.\n\n'
fi
cat <<EOF_SUMMARY
Check the result with: scripts/lrun-paths

All operators/services must be members of '$GROUP_NAME'.
Do not place seed-credential files in these writable runtime roots unless every
member of the operator group is intentionally allowed to read those secrets.
EOF_SUMMARY
