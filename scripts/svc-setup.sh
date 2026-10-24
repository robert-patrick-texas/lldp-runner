#!/usr/bin/env bash

# Install LLDP-Runner systemd discovery/maintenance services and timers.
# Run with sudo/root on systemd-based Linux hosts.

set -euo pipefail

# Defaults for the shared layout prepared by scripts/shared-setup.sh: the
# installation in /opt/lldp-runner, runtime data in /opt/lldp-runner/var, and
# scratch data in /dev/shm/lldp-runner. Review them before use at a site.
SERVICE_USER="${LLDP_RUNNER_SERVICE_USER:-lldp-runner}"
GROUP_NAME="${LLDP_RUNNER_GROUP:-netops}"
PROJECT_ROOT="${LLDP_RUNNER_PROJECT_ROOT:-/opt/lldp-runner}"
PERSISTENT_ROOT="${LLDP_RUNNER_PERSISTENT_ROOT:-}"
SCRATCH_ROOT="${LLDP_RUNNER_SCRATCH_ROOT:-/dev/shm/lldp-runner}"
PYTHON_DIR="${UV_PYTHON_INSTALL_DIR:-/opt/shared/python}"
RANDOM_DELAY_MINUTES="${LLDP_RUNNER_RANDOM_DELAY_MINUTES:-10}"
RUN_CALENDAR="${LLDP_RUNNER_RUN_CALENDAR:-*-*-* 00,04,08,12,16,20:00:00}"
MAINT_CALENDAR="${LLDP_RUNNER_MAINT_CALENDAR:-*-*-* 02:30:00}"
# purge --keep is additional retention beyond latest. 11 => 12 outputs total.
PURGE_KEEP="${LLDP_RUNNER_PURGE_KEEP:-11}"

SYSTEMD_DIR="/etc/systemd/system"
# Written by svc-setup.sh before shared-setup.sh took over boot-time scratch
# recreation (lldp-runner-scratch.conf). svc-remove.sh still removes it.
LEGACY_TMPFILES_FILE="/etc/tmpfiles.d/lldp-runner.conf"
# The service account has no writable home, so uv's cache lives here instead.
CACHE_DIRECTORY_NAME="lldp-runner"
UNIT_NAMES=(
    lldp-runner-run.service
    lldp-runner-run.timer
    lldp-runner-maintenance.service
    lldp-runner-maintenance.timer
)

usage() {
    cat <<'USAGE'
Usage: sudo scripts/svc-setup.sh [options]

Options:
  --service-user NAME       Service account (default: lldp-runner).
  --group NAME              Required service group (default: netops).
  --project-root PATH       LLDP-Runner project root.
  --persistent-root PATH    Configured persistent_root (default: PROJECT/var).
  --scratch-root PATH       Configured scratch_root; holds the schedule lock
                            (default: /dev/shm/lldp-runner).
  --python-dir PATH         Shared uv-managed Python directory.
  --random-delay MINUTES    Timer random delay, 0 or greater (default: 10).
  --run-calendar SPEC       systemd OnCalendar for discovery.
  --maintenance-calendar SPEC
                            systemd OnCalendar for clean/purge.
  --purge-keep NUMBER       Additional outputs beyond latest (default: 11).
  -h, --help                Show this help.
USAGE
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

while (($#)); do
    case "$1" in
        --service-user) (($# >= 2)) || die "--service-user requires a value"; SERVICE_USER="$2"; shift 2 ;;
        --group) (($# >= 2)) || die "--group requires a value"; GROUP_NAME="$2"; shift 2 ;;
        --project-root) (($# >= 2)) || die "--project-root requires a value"; PROJECT_ROOT="$2"; shift 2 ;;
        --persistent-root) (($# >= 2)) || die "--persistent-root requires a value"; PERSISTENT_ROOT="$2"; shift 2 ;;
        --scratch-root) (($# >= 2)) || die "--scratch-root requires a value"; SCRATCH_ROOT="$2"; shift 2 ;;
        --python-dir) (($# >= 2)) || die "--python-dir requires a value"; PYTHON_DIR="$2"; shift 2 ;;
        --random-delay) (($# >= 2)) || die "--random-delay requires a value"; RANDOM_DELAY_MINUTES="$2"; shift 2 ;;
        --run-calendar) (($# >= 2)) || die "--run-calendar requires a value"; RUN_CALENDAR="$2"; shift 2 ;;
        --maintenance-calendar) (($# >= 2)) || die "--maintenance-calendar requires a value"; MAINT_CALENDAR="$2"; shift 2 ;;
        --purge-keep) (($# >= 2)) || die "--purge-keep requires a value"; PURGE_KEEP="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

: "${PERSISTENT_ROOT:=${PROJECT_ROOT}/var}"

[[ ${EUID} -eq 0 ]] || die "run this script with sudo or as root"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
command -v flock >/dev/null 2>&1 || die "flock is required"
getent passwd "$SERVICE_USER" >/dev/null || die "service user '$SERVICE_USER' does not exist"
getent group "$GROUP_NAME" >/dev/null || die "group '$GROUP_NAME' does not exist"
id -nG "$SERVICE_USER" | tr ' ' '\n' | grep -Fxq "$GROUP_NAME" || \
    die "service user '$SERVICE_USER' is not a member of group '$GROUP_NAME'"
[[ "$RANDOM_DELAY_MINUTES" =~ ^[0-9]+$ ]] || die "--random-delay must be a non-negative integer"
[[ "$PURGE_KEEP" =~ ^[0-9]+$ ]] || die "--purge-keep must be a non-negative integer"

for path in "$PROJECT_ROOT" "$PERSISTENT_ROOT" "$SCRATCH_ROOT" "$PYTHON_DIR"; do
    [[ "$path" = /* ]] || die "path must be absolute: $path"
    [[ "$path" != "/" ]] || die "refusing to use / as a managed path"
    [[ "$path" != *[[:space:]%]* ]] || die "paths may not contain whitespace or %: $path"
    [[ "$path" != *"'"* ]] || die "paths may not contain single quotes: $path"
done
[[ -x "$PROJECT_ROOT/scripts/lrun-run" ]] || die "missing executable: $PROJECT_ROOT/scripts/lrun-run"
[[ -x "$PROJECT_ROOT/scripts/lrun-clean" ]] || die "missing executable: $PROJECT_ROOT/scripts/lrun-clean"
[[ -x "$PROJECT_ROOT/scripts/lrun-purge" ]] || die "missing executable: $PROJECT_ROOT/scripts/lrun-purge"
[[ -d "$SCRATCH_ROOT" ]] || \
    die "scratch root $SCRATCH_ROOT does not exist; run scripts/shared-setup.sh first"
[[ -d "$PERSISTENT_ROOT" ]] || \
    die "persistent root $PERSISTENT_ROOT does not exist; run scripts/shared-setup.sh first"

for unit in "${UNIT_NAMES[@]}"; do
    [[ ! -e "$SYSTEMD_DIR/$unit" ]] || \
        die "$unit is already installed; run scripts/svc-remove.sh first"
    if systemctl list-unit-files --no-legend "$unit" 2>/dev/null | grep -q "^$unit"; then
        die "$unit is already registered; run scripts/svc-remove.sh first"
    fi
done
[[ ! -e "$LEGACY_TMPFILES_FILE" ]] || \
    die "$LEGACY_TMPFILES_FILE already exists; run scripts/svc-remove.sh first"

cat > "$SYSTEMD_DIR/lldp-runner-run.service" <<EOF_UNIT
[Unit]
Description=LLDP-Runner network discovery
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=$SERVICE_USER
Group=$GROUP_NAME
WorkingDirectory=$PROJECT_ROOT
Environment=UV_PYTHON_INSTALL_DIR=$PYTHON_DIR
Environment=UV_LINK_MODE=copy
Environment=UV_CACHE_DIR=/var/cache/$CACHE_DIRECTORY_NAME/uv
CacheDirectory=$CACHE_DIRECTORY_NAME
CacheDirectoryMode=0750
UMask=0002
TimeoutStartSec=infinity
ExecStart=/usr/bin/flock --exclusive $SCRATCH_ROOT/.schedule.lock $PROJECT_ROOT/scripts/lrun-run
EOF_UNIT

cat > "$SYSTEMD_DIR/lldp-runner-run.timer" <<EOF_UNIT
[Unit]
Description=Run LLDP-Runner discovery every four hours

[Timer]
OnCalendar=$RUN_CALENDAR
RandomizedDelaySec=${RANDOM_DELAY_MINUTES}min
FixedRandomDelay=true
Persistent=true
AccuracySec=1min
Unit=lldp-runner-run.service

[Install]
WantedBy=timers.target
EOF_UNIT

cat > "$SYSTEMD_DIR/lldp-runner-maintenance.service" <<EOF_UNIT
[Unit]
Description=LLDP-Runner daily clean and purge

[Service]
Type=oneshot
User=$SERVICE_USER
Group=$GROUP_NAME
WorkingDirectory=$PROJECT_ROOT
Environment=UV_PYTHON_INSTALL_DIR=$PYTHON_DIR
Environment=UV_LINK_MODE=copy
Environment=UV_CACHE_DIR=/var/cache/$CACHE_DIRECTORY_NAME/uv
CacheDirectory=$CACHE_DIRECTORY_NAME
CacheDirectoryMode=0750
UMask=0002
TimeoutStartSec=infinity
ExecStart=/usr/bin/flock --exclusive $SCRATCH_ROOT/.schedule.lock /bin/bash -c '$PROJECT_ROOT/scripts/lrun-clean && $PROJECT_ROOT/scripts/lrun-purge --keep $PURGE_KEEP'
EOF_UNIT

cat > "$SYSTEMD_DIR/lldp-runner-maintenance.timer" <<EOF_UNIT
[Unit]
Description=Run LLDP-Runner maintenance daily

[Timer]
OnCalendar=$MAINT_CALENDAR
RandomizedDelaySec=${RANDOM_DELAY_MINUTES}min
FixedRandomDelay=true
Persistent=true
AccuracySec=1min
Unit=lldp-runner-maintenance.service

[Install]
WantedBy=timers.target
EOF_UNIT

systemctl daemon-reload
systemctl enable --now lldp-runner-run.timer lldp-runner-maintenance.timer

cat <<EOF_SUMMARY
LLDP-Runner systemd scheduling installed.

Service user:       $SERVICE_USER
Service group:      $GROUP_NAME
Project root:       $PROJECT_ROOT
Persistent root:    $PERSISTENT_ROOT
Scratch root:       $SCRATCH_ROOT
Discovery schedule: $RUN_CALENDAR (+0-${RANDOM_DELAY_MINUTES}m randomized delay)
Maintenance:        $MAINT_CALENDAR (+0-${RANDOM_DELAY_MINUTES}m randomized delay)
Purge retention:    latest + $PURGE_KEEP additional output directories

Use 'systemctl list-timers lldp-runner-*' to review the schedules.
Use scripts/svc-remove.sh before reinstalling or changing generated units.
EOF_SUMMARY
