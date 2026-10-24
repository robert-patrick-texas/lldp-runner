#!/bin/sh
set -eu

PROJECT_DIR=${PROJECT_DIR:-/opt/lldp-runner}

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is required. Install the current Astral uv release before running this script." >&2
    exit 1
fi

# Runtime directories are not created here. LLDP-Runner places them with the
# installation's config.toml; a shared install prepares them with
# scripts/shared-setup.sh (see docs/INSTALL.md).
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"
uv sync --all-groups

echo "Environment synchronized."
echo "Run: uv run lldp-runner generate-config"
echo "Then edit the generated TOML as needed, or run from built-in defaults with SNMPCOMM/SNMPUSER credentials."
echo "Check where runtime data will go with: uv run lldp-runner paths"
