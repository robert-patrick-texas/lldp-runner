"""Seed inventory parsing and recursive seed-directory discovery.

This module keeps seed ingestion rules out of the CLI so operators and future
maintainers have one place to understand exactly which input formats are
accepted. Reusable ``seeds.csv`` input uses the shared dynamic CSV reader, so
the current field names are required but their physical column order is not.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

from lldp_runner.csv_input import read_csv_rows
from lldp_runner.identity import normalize_host_address
from lldp_runner.models import SeedInput

SEED_CSV_COLUMNS = [
    "preferred_name",
    "queried_as",
    "ipv4",
    "ipv6",
    "credential_profile",
    "credential_result",
    "origin",
    "state",
    "last_seen",
    "notes",
]


def _normalize_seed_address(
    value: str, *, family: int | None = None
) -> tuple[str | None, str | None]:
    """Normalize an address imported from the supported seed CSV format.

    A malformed cell is retained as a parse error on the resulting SeedInput
    instead of aborting an otherwise useful row. This lets Network Operations
    see and correct bad inventory data while still using the valid aliases on
    the same row.
    """

    text = value.strip().strip("[]")
    if not text:
        return None, None
    try:
        normalized = normalize_host_address(text)
    except ValueError as exc:
        return None, str(exc)
    address = ipaddress.ip_address(normalized)
    if family is not None and address.version != family:
        return None, f"address {value!r} is IPv{address.version}, expected IPv{family}"
    return normalized, None


def _split_seed_address_cell(value: str) -> list[str]:
    """Split LLDP-Runner's semicolon-separated IPv4/IPv6 seed columns."""

    return [part.strip() for part in value.split(";") if part.strip()]


def _seed_from_csv_row(row: dict[str, str | None], source: Path) -> SeedInput | None:
    """Build one SeedInput from a row using the current seeds.csv schema."""

    raw_seed = str(row.get("preferred_name") or "").strip()
    raw_target = str(row.get("queried_as") or "").strip()
    # Generated seed inventories always carry a presentation seed name. For a
    # hand-edited current-format row, however, a confirmed query target still
    # provides enough identity to proceed, so it is used as a safe fallback.
    seed = raw_seed or raw_target
    if not seed:
        return None

    # ``origin`` describes provenance in the run that wrote this inventory, but
    # it is deliberately not carried into SeedInput.  Once a row is supplied as
    # input to a later run, that identity is an explicit seed for the new run,
    # regardless of whether its prior inventory row said ``seed`` or ``learned``.
    prior_state = str(row.get("state") or "").strip().casefold() or None
    item = SeedInput(seed=seed, prior_state=prior_state, source=str(source))
    if raw_target:
        target, error = _normalize_seed_address(raw_target)
        if target:
            item.query_target = target
        if error:
            item.parse_errors.append(f"queried_as: {error}")

    for key, family, destination in (("ipv4", 4, item.ipv4), ("ipv6", 6, item.ipv6)):
        for raw_address in _split_seed_address_cell(str(row.get(key) or "")):
            address, error = _normalize_seed_address(raw_address, family=family)
            if address and address not in destination:
                destination.append(address)
            if error:
                item.parse_errors.append(f"{key}: {error}")
    return item


def _read_seed_csv(path: Path) -> list[SeedInput]:
    """Read the current reusable seed schema by header name, not position.

    The shared CSV reader intentionally lets operators reorder columns while
    this caller still requires every field in :data:`SEED_CSV_COLUMNS`. Extra
    columns are ignored, and short records receive blank values for omitted
    trailing cells so seed-specific semantics remain in this module.
    """

    rows = read_csv_rows(
        path,
        fields=SEED_CSV_COLUMNS,
        error_on_missing_fields=True,
        error_on_column_mismatch=False,
        drop_extra_fields=True,
    )
    records: list[SeedInput] = []
    for parsed in rows:
        item = _seed_from_csv_row(parsed.values, path)
        if item is not None:
            records.append(item)
    return records


def parse_text_seed_line(line: str) -> str | None:
    """Return the seed target carried by one plain-text input line.

    Plain seed files intentionally accept light operator annotation. Blank
    lines and lines whose first non-whitespace character is ``#`` or ``;`` are
    ignored. For active lines, the first comma, semicolon, or hash begins
    trailing metadata/comment text and is discarded. The remaining target is
    stripped before use.

    Examples::

        switch1.net.example.com, primary core       -> switch1.net.example.com
        198.18.10.5 ; temporary seed                -> 198.18.10.5
        2001:db8::10 # IPv6 seed                   -> 2001:db8::10
        ; disabled by operator                      -> ignored
    """

    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")):
        return None

    cut = len(line)
    for marker in (",", ";", "#"):
        index = line.find(marker)
        if index >= 0:
            cut = min(cut, index)
    seed = line[:cut].strip()
    return seed or None


def _read_text_seed_file(path: Path) -> list[SeedInput]:
    """Read a UTF-8 text seed file using the common line/comment rules."""

    text = path.read_text(encoding="utf-8-sig")
    records: list[SeedInput] = []
    for line in text.splitlines():
        seed = parse_text_seed_line(line)
        if seed:
            records.append(SeedInput(seed=seed, source=str(path)))
    return records


def read_seed_file(path: Path) -> list[SeedInput]:
    """Read one supported seed file based on its filename suffix.

    ``*.csv`` means the current LLDP-Runner seed inventory field set. Every other
    filename is treated as plain UTF-8 text containing one target per line.
    """

    source = path.expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"seed file not found: {source}")
    if source.suffix.casefold() == ".csv":
        return _read_seed_csv(source)
    return _read_text_seed_file(source)


def _skip_directory_seed_file(root: Path, path: Path) -> bool:
    """Return True when a recursively discovered seed file must be ignored."""

    relative = path.relative_to(root)
    # Hidden directories are skipped as well as hidden files. This prevents a
    # seed tree containing .git/.svn/editor metadata from unexpectedly becoming
    # discovery input merely because recursion is enabled.
    if any(part.startswith(".") for part in relative.parts):
        return True
    name = path.name.casefold()
    return name.startswith("readme") or name.endswith(".disabled") or name.endswith(".note")


def read_seed_directory(path: Path) -> list[SeedInput]:
    """Recursively read all eligible files under a seed directory.

    Files are processed in deterministic, case-insensitive relative-path order
    so repeated runs see the same seed-source precedence. CSV files use the
    current ``seeds.csv`` field set in any column order; every other eligible
    file uses the plain-text parser.
    """

    root = path.expanduser()
    if not root.exists():
        raise FileNotFoundError(f"seed directory not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"seed directory is not a directory: {root}")

    files = [
        candidate
        for candidate in root.rglob("*")
        if candidate.is_file() and not _skip_directory_seed_file(root, candidate)
    ]
    files.sort(
        key=lambda item: (
            item.relative_to(root).as_posix().casefold(),
            item.relative_to(root).as_posix(),
        )
    )

    records: list[SeedInput] = []
    for candidate in files:
        records.extend(read_seed_file(candidate))
    return records


def merge_seed_inputs(values: list[SeedInput]) -> list[SeedInput]:
    """De-duplicate logical seeds while preserving address hints from all sources."""

    merged: dict[str, SeedInput] = {}
    order: list[str] = []
    for value in values:
        key = value.seed.strip().casefold()
        if not key:
            continue
        if key not in merged:
            merged[key] = SeedInput(
                seed=value.seed.strip(),
                query_target=value.query_target,
                ipv4=list(value.ipv4),
                ipv6=list(value.ipv6),
                prior_state=value.prior_state,
                source=value.source,
                parse_errors=list(value.parse_errors),
            )
            order.append(key)
            continue
        current = merged[key]
        if current.query_target is None and value.query_target is not None:
            current.query_target = value.query_target
        if current.prior_state is None and value.prior_state is not None:
            current.prior_state = value.prior_state
        elif (
            current.prior_state is not None
            and value.prior_state is not None
            and current.prior_state != value.prior_state
        ):
            # Conflicting historical states must not accidentally authorize the
            # skip-addressed DNS fast path after textual seed de-duplication.
            current.prior_state = "mixed"
        current.ipv4 = list(dict.fromkeys([*current.ipv4, *value.ipv4]))
        current.ipv6 = list(dict.fromkeys([*current.ipv6, *value.ipv6]))
        current.parse_errors = list(dict.fromkeys([*current.parse_errors, *value.parse_errors]))
    return [merged[key] for key in order]


def seed_directories_from_environment(value: str) -> list[Path]:
    """Split an environment path-list into seed directories."""

    return [Path(part) for part in value.split(os.pathsep) if part]
