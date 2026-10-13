#!/usr/bin/env bash

# Prepare dedicated LLDP-Runner runtime directories for a trusted operator group.
# Run this script with sudo/root before using a centrally managed installation.

set -euo pipefail

# Example production/shared-install defaults. Uncomment and adjust these values
# when preparing a stable centrally managed deployment.
# GROUP_NAME="${LLDP_RUNNER_GROUP:-lldp-runner}"
# PERSISTENT_ROOT="${LLDP_RUNNER_PERSISTENT_ROOT:-/var/lib/lldp-runner}"
# SCRATCH_ROOT="${LLDP_RUNNER_SCRATCH_ROOT:-/var/tmp/lldp-runner}"
# PYTHON_DIR="${UV_PYTHON_INSTALL_DIR:-/opt/shared/python}"

# Development defaults used by the project today. These paths and group names
# are subject to change and should be reviewed before using this helper at a site.
GROUP_NAME="${LLDP_RUNNER_GROUP:-netops}"
PERSISTENT_ROOT="${LLDP_RUNNER_PERSISTENT_ROOT:-/opt/lldp-runner}"
SCRATCH_ROOT="${LLDP_RUNNER_SCRATCH_ROOT:-/dev/shm/lldp-runner}"
PYTHON_DIR="${UV_PYTHON_INSTALL_DIR:-/opt/shared/python}"

usage()
{
    cat <<'USAGE'
Usage: sudo scripts/shared-setup.sh [options]

Options:
  --group NAME             Trusted LLDP-Runner operator group.
  --persistent-root PATH   Shared persistent_root directory.
  --scratch-root PATH      Shared scratch_root directory.
  --python-dir PATH        Shared uv-managed Python installation directory.
  -h, --help               Show this help.

Defaults may also be supplied with:
  LLDP_RUNNER_GROUP
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

while (($#)); do
    case "$1" in
        --group)
            (($# >= 2)) || die "--group requires a value"
            GROUP_NAME="$2"
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

[[ ${EUID} -eq 0 ]] || die "run this script with sudo or as root"
getent group "$GROUP_NAME" >/dev/null || \
    die "group '$GROUP_NAME' does not exist; create it before running this script"

for root in "$PERSISTENT_ROOT" "$SCRATCH_ROOT"; do
    [[ "$root" = /* ]] || die "runtime root must be an absolute path: $root"
    [[ "$root" != "/" ]] || die "refusing to use / as a runtime root"
done
[[ "$PERSISTENT_ROOT" != "$SCRATCH_ROOT" ]] || \
    die "persistent_root and scratch_root must be different directories"
[[ "$PYTHON_DIR" = /* ]] || die "python directory must be an absolute path"
[[ "$PYTHON_DIR" != "/" ]] || die "refusing to use / as the Python directory"

# The shared interpreter is centrally maintained. Operators need read/execute
# access but do not need to modify it during ordinary LLDP-Runner execution.
install -d -o root -g "$GROUP_NAME" -m 0755 "$PYTHON_DIR"

# Runtime roots are group writable and setgid. Existing runtime content is also
# normalized because an installation may be converted from single-user use.
install -d -o root -g "$GROUP_NAME" -m 2775 "$PERSISTENT_ROOT"
install -d -o root -g "$GROUP_NAME" -m 2775 "$SCRATCH_ROOT"
install -d -o root -g "$GROUP_NAME" -m 2775 \
    "$PERSISTENT_ROOT/runs" "$PERSISTENT_ROOT/outputs"

for root in "$PERSISTENT_ROOT" "$SCRATCH_ROOT"; do
    chgrp -R "$GROUP_NAME" "$root"
    chmod -R g+rwX "$root"
    find "$root" -type d -exec chmod g+s {} +
done

# Default ACLs are stronger than relying on every user's shell/service umask.
# They keep new files group writable and new directories group traversable.
if command -v setfacl >/dev/null 2>&1; then
    for root in "$PERSISTENT_ROOT" "$SCRATCH_ROOT"; do
        find "$root" -type d -exec \
            setfacl -m g::rwx,m::rwx,d:g::rwx,d:m::rwx {} +
        find "$root" -type f -exec setfacl -m g::rw,m::rw {} +
    done
    acl_note="default POSIX ACLs applied"
else
    acl_note="setfacl not found; configure umask 0002 for every LLDP-Runner process"
fi

cat <<EOF_SUMMARY
Shared LLDP-Runner directories prepared.

Operator group:   $GROUP_NAME
Persistent root:  $PERSISTENT_ROOT
Scratch root:     $SCRATCH_ROOT
uv Python dir:    $PYTHON_DIR
Permissions:      setgid + group read/write; $acl_note

Configure LLDP-Runner explicitly, for example:

[paths]
persistent_root = "$PERSISTENT_ROOT"
scratch_root = "$SCRATCH_ROOT"

All operators/services must be members of '$GROUP_NAME'.
Do not place seed-credential files in these writable runtime roots unless every
member of the operator group is intentionally allowed to read those secrets.
EOF_SUMMARY
