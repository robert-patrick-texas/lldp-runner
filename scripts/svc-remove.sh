#!/usr/bin/env bash

# Remove LLDP-Runner systemd discovery/maintenance services and timers.
# Runtime/output data is intentionally preserved.

set -euo pipefail

# Defaults matching svc-setup.sh. Only the summary below uses them.
SERVICE_USER="${LLDP_RUNNER_SERVICE_USER:-lldp-runner}"
GROUP_NAME="${LLDP_RUNNER_GROUP:-netops}"
SCRATCH_ROOT="${LLDP_RUNNER_SCRATCH_ROOT:-/dev/shm/lldp-runner}"

SYSTEMD_DIR="/etc/systemd/system"
# Written by older svc-setup.sh versions. The scratch entry that shared-setup.sh
# now maintains (lldp-runner-scratch.conf) is left in place.
TMPFILES_FILE="/etc/tmpfiles.d/lldp-runner.conf"
UNIT_NAMES=(
    lldp-runner-run.service
    lldp-runner-run.timer
    lldp-runner-maintenance.service
    lldp-runner-maintenance.timer
)

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || die "run this script with sudo or as root"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"

systemctl disable --now lldp-runner-run.timer lldp-runner-maintenance.timer 2>/dev/null || true
systemctl stop lldp-runner-run.service lldp-runner-maintenance.service 2>/dev/null || true
for unit in "${UNIT_NAMES[@]}"; do
    rm -f -- "$SYSTEMD_DIR/$unit"
done
rm -f -- "$TMPFILES_FILE"
systemctl daemon-reload
systemctl reset-failed lldp-runner-run.service lldp-runner-maintenance.service 2>/dev/null || true

cat <<EOF_SUMMARY
LLDP-Runner systemd scheduling removed.
Runtime/output data was preserved, including scratch root: $SCRATCH_ROOT
Service account/group were not removed: $SERVICE_USER / $GROUP_NAME
EOF_SUMMARY
