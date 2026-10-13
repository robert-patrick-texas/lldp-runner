#!/bin/sh
set -eu

if [ -n "${PROJECT_DIR:-}" ]; then
    cd "$PROJECT_DIR"
else
    SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    cd "$SCRIPT_DIR/.."
fi

uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
