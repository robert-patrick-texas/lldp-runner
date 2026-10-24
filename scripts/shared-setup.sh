#!/usr/bin/env bash

# Prepare dedicated LLDP-Runner runtime directories for a trusted operator group.
# Run this script with sudo/root before using a centrally managed installation.
#
# Operators can write to the runtime directories, so this script never follows
# a symlink there as root. Each runtime root is locked to root-only access while
# its contents are handled, an existing entry must be a real directory, and the
# recursive permission repair of existing content only runs with --repair or
# --migrate.

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
REPAIR=false
MIGRATE=false
PRINT_PATHS=false

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
  --migrate                Move runs/, outputs/, and tmp/ from the project root
                           into <project-root>/var (implies --repair).
  --repair                 Also normalize group ownership, permissions, and ACLs
                           of existing content. Run it only while no LLDP-Runner
                           process or operator session uses these directories.
  --print-paths            Print the runtime roots this setup would use and exit.
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

# Scratch directory name for a shared installation. /opt/lldp-runner keeps the
# plain name; any other installation appends its path so two installations on
# one host never share scratch. Must match lldp_runner.layout.scratch_name().
scratch_name()
{
    local root="$1"
    local text

    if [[ "$root" == /opt/lldp-runner ]]; then
        printf 'lldp-runner'
        return
    fi
    text="${root#/}"
    text="${text//\//-}"
    text="$(printf '%s' "$text" | LC_ALL=C sed 's/[^A-Za-z0-9._-]/_/g')"
    printf 'lldp-runner-%s' "$text"
}

lldp_runner_running()
{
    pgrep -f -- 'lldp-runner (run|clean|purge)( |$)' >/dev/null 2>&1
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
        --migrate)
            MIGRATE=true
            REPAIR=true
            shift
            ;;
        --repair)
            REPAIR=true
            shift
            ;;
        --print-paths)
            PRINT_PATHS=true
            shift
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

# Strip trailing slashes so the defaults match LLDP-Runner's normalized paths.
while [[ "$PROJECT_ROOT" == */ && "$PROJECT_ROOT" != / ]]; do
    PROJECT_ROOT="${PROJECT_ROOT%/}"
done

paths_overridden=false
if [[ -n "$PERSISTENT_ROOT" || -n "$SCRATCH_ROOT" ]]; then
    paths_overridden=true
fi

case "$LAYOUT" in
    shared)
        : "${PERSISTENT_ROOT:=${PROJECT_ROOT}/var}"
        : "${SCRATCH_ROOT:=/dev/shm/$(scratch_name "$PROJECT_ROOT")}"
        ;;
    system)
        : "${PERSISTENT_ROOT:=/var/lib/lldp-runner}"
        : "${SCRATCH_ROOT:=/run/lldp-runner}"
        ;;
    *)
        die "--layout must be 'shared' or 'system'; a single-user install needs no setup"
        ;;
esac

if [[ "$PRINT_PATHS" == true ]]; then
    printf 'persistent_root=%s\nscratch_root=%s\n' "$PERSISTENT_ROOT" "$SCRATCH_ROOT"
    exit 0
fi

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

# Older shared installations kept run history directly in the project root.
# Creating var/ beside it would silently hide that history from LLDP-Runner.
legacy_names=()
if [[ "$LAYOUT" == shared && "$PERSISTENT_ROOT" == "${PROJECT_ROOT}/var" \
        && ! -e "$PERSISTENT_ROOT" ]]; then
    for name in runs outputs tmp; do
        if [[ -d "${PROJECT_ROOT}/${name}" && ! -L "${PROJECT_ROOT}/${name}" ]]; then
            legacy_names+=("$name")
        fi
    done
fi
if (( ${#legacy_names[@]} )) && [[ "$MIGRATE" != true ]]; then
    die "${PROJECT_ROOT} still holds ${legacy_names[*]} from an older layout; stop the LLDP-Runner timers and rerun with --migrate to move them into ${PERSISTENT_ROOT}"
fi
if [[ "$LAYOUT" == shared && -d "$PERSISTENT_ROOT" ]]; then
    for name in runs outputs; do
        if [[ -d "${PROJECT_ROOT}/${name}" && ! -L "${PROJECT_ROOT}/${name}" ]]; then
            warn "${PROJECT_ROOT}/${name} is not used because ${PERSISTENT_ROOT} exists; move its contents into ${PERSISTENT_ROOT}/${name}"
        fi
    done
fi
if [[ "$REPAIR" == true ]] && lldp_runner_running; then
    die "an LLDP-Runner run, clean, or purge is in progress; stop it and its timers before --repair or --migrate"
fi

# Refuse runtime roots whose parent lets non-root accounts replace them, unless
# the parent is sticky (such as /dev/shm), where only the owner can do so.
check_parent()
{
    local parent
    parent="$(dirname -- "$1")"
    [[ -d "$parent" ]] || die "parent directory of $1 does not exist: $parent"
    if [[ -n "$(find "$parent" -maxdepth 0 -perm /022 ! -perm -1000)" ]]; then
        die "$parent is group- or world-writable; remove that access before preparing $1"
    fi
}

# Create a runtime root, or accept an existing real directory owned by root,
# and leave it locked (root:GROUP 0700) so no operator can change its entries
# while this script works below it.
lock_root()
{
    local root="$1"

    check_parent "$root"
    if [[ ! -e "$root" && ! -L "$root" ]]; then
        mkdir -m 0700 -- "$root" 2>/dev/null || true
    fi
    [[ ! -L "$root" ]] || die "$root is a symbolic link; replace it with a directory or pass its target"
    [[ -d "$root" ]] || die "$root is not a directory"
    [[ -O "$root" ]] || die "$root is owned by $(stat -c %U -- "$root"), not root; remove it or change its owner to root first"
    chmod 0700 -- "$root"
    chgrp -- "$GROUP_NAME" "$root"
}

# Create or fix one directory inside a locked runtime root.
prepare_child()
{
    local child="$1"

    [[ ! -L "$child" ]] || die "$child is a symbolic link; remove it and rerun"
    if [[ -e "$child" && ! -d "$child" ]]; then
        die "$child is not a directory"
    fi
    install -d -o root -g "$GROUP_NAME" -m 2770 -- "$child"
}

# Group read/write for existing content, without following symlinks during the
# walk. Only reached with --repair or --migrate, while the root is locked.
repair_tree()
{
    local root="$1"

    chgrp -R -- "$GROUP_NAME" "$root"
    chmod -R g+rwX,o-rwx -- "$root"
    find "$root" -mindepth 1 -type d -exec chmod g+s {} +
    if command -v setfacl >/dev/null 2>&1; then
        find "$root" -mindepth 1 -type d -exec \
            setfacl -m g::rwx,m::rwx,o::-,d:g::rwx,d:m::rwx,d:o::- {} +
        find "$root" -mindepth 1 -type f -exec setfacl -m g::rw,m::rw,o::- {} +
    fi
}

# Final mode and ACLs of a runtime root itself, which unlocks it.
unlock_root()
{
    local root="$1"

    chmod 2770 -- "$root"
    if command -v setfacl >/dev/null 2>&1; then
        setfacl -m g::rwx,m::rwx,o::-,d:g::rwx,d:m::rwx,d:o::- -- "$root"
    fi
}

# The shared interpreter is centrally maintained and owned by root. Operators
# need read/execute access but never modify it. An existing directory is left
# exactly as the administrator created it.
if [[ ! -e "$PYTHON_DIR" ]]; then
    install -d -o root -g root -m 0755 -- "$PYTHON_DIR"
elif [[ -n "$(find "$PYTHON_DIR" -maxdepth 0 -perm /022)" ]]; then
    warn "$PYTHON_DIR is group- or world-writable; members could replace the interpreter"
fi

if [[ -d "$PROJECT_ROOT" && -n "$(find "$PROJECT_ROOT" -maxdepth 0 -perm /022)" ]]; then
    warn "$PROJECT_ROOT is group- or world-writable; only its maintainer should change it"
fi

lock_root "$PERSISTENT_ROOT"
for name in "${legacy_names[@]}"; do
    # The project root is not writable by operators (checked above), and the
    # destination is locked, so neither side of the move can be swapped.
    [[ ! -e "${PERSISTENT_ROOT}/${name}" ]] || \
        die "${PERSISTENT_ROOT}/${name} already exists; merge ${PROJECT_ROOT}/${name} by hand"
    mv -- "${PROJECT_ROOT}/${name}" "${PERSISTENT_ROOT}/${name}"
done
for name in runs outputs tmp; do
    prepare_child "${PERSISTENT_ROOT}/${name}"
done
lock_root "$SCRATCH_ROOT"

acl_note="setfacl not found; configure umask 0002 for every LLDP-Runner process"
if command -v setfacl >/dev/null 2>&1; then
    acl_note="default POSIX ACLs applied"
fi
if [[ "$REPAIR" == true ]]; then
    repair_tree "$PERSISTENT_ROOT"
    repair_tree "$SCRATCH_ROOT"
    acl_note="$acl_note; existing content repaired"
else
    for name in runs outputs tmp; do
        if command -v setfacl >/dev/null 2>&1; then
            setfacl -m g::rwx,m::rwx,o::-,d:g::rwx,d:m::rwx,d:o::- -- \
                "${PERSISTENT_ROOT}/${name}"
        fi
    done
fi
unlock_root "$PERSISTENT_ROOT"
unlock_root "$SCRATCH_ROOT"

acl_line=""
if command -v setfacl >/dev/null 2>&1; then
    acl_line="a+ $SCRATCH_ROOT - - - - d:g::rwx,d:m::rwx,d:o::-,g::rwx,m::rwx,o::-"
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
if (( ${#legacy_names[@]} )); then
    printf 'Migrated:         %s from %s\n' "${legacy_names[*]}" "$PROJECT_ROOT"
fi
printf '\n'
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
