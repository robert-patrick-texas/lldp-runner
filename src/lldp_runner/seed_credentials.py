"""Secure per-seed SNMP credential overlay parsing and matching helpers.

Seed-credential files never create discovery seeds. They describe ordered SNMP
credential attempts that may be attached to explicit seeds supplied through the
normal seed channels. CSV input uses the shared dynamic-position parser so
field order can change without changing credential-overlay semantics.
"""

from __future__ import annotations

import ipaddress
import json
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

from lldp_runner.config import AppConfig
from lldp_runner.csv_input import read_csv_rows
from lldp_runner.models import DirectCredential
from lldp_runner.snmp.selection import (
    selected_snmp_backend,
    validate_snmp_v3_protocols,
)

SEED_CREDENTIAL_COLUMNS = [
    "seed",
    "credential_strategy",
    "credential_label",
    "credential_profile",
    "snmp_version",
    "community",
    "username",
    "auth_password",
    "priv_password",
    "auth_protocol",
    "priv_protocol",
]
_JSON_KEYS = set(SEED_CREDENTIAL_COLUMNS) | {"source_line"}


@dataclass(slots=True)
class SeedCredentialRecord:
    """One ordered credential attempt associated with a seed identity."""

    seed: str
    strategy: Literal["prefer", "exclusive"]
    credential_label: str | None
    credential_profile: str | None
    direct_credential: DirectCredential | None
    source: Path
    source_line: int | None
    order: int


@dataclass(slots=True)
class SeedCredentialLoad:
    """Parsed credential records plus non-fatal warnings for activity logging."""

    records: list[SeedCredentialRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files: tuple[Path, ...] = ()


def normalize_seed_key(value: str) -> str:
    """Return a network-free canonical key for hostname or IP seed matching."""

    text = value.strip().strip("[]")
    try:
        return f"ip:{ipaddress.ip_address(text)}"
    except ValueError:
        return f"name:{text.rstrip('.').casefold()}"


def _csv_rows(path: Path) -> list[tuple[int, dict[str, str]]]:
    """Read credential rows by field name while retaining physical line numbers.

    The overlay requires the complete current field set, but columns may appear
    in any order and unrelated extra columns are ignored. Historical semicolon
    comment lines remain accepted by this caller in addition to the common hash
    comment convention.
    """

    return [
        (parsed.line_number, parsed.values)
        for parsed in read_csv_rows(
            path,
            fields=SEED_CREDENTIAL_COLUMNS,
            comment_prefixes=("#", ";"),
            error_on_missing_fields=True,
            error_on_column_mismatch=False,
            drop_extra_fields=True,
        )
    ]


def _json_rows(path: Path) -> list[tuple[int | None, dict[str, str]]]:
    """Read the JSON array form using the same field names as CSV."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"seed credential JSON {path}: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError(f"seed credential JSON {path} must contain a top-level array")

    rows: list[tuple[int | None, dict[str, str]]] = []
    for index, item in enumerate(payload, 1):
        if not isinstance(item, dict):
            raise ValueError(f"seed credential JSON {path}: item {index} must be an object")
        item = cast(dict[str, Any], item)
        unknown = set(item) - _JSON_KEYS
        if unknown:
            raise ValueError(
                f"seed credential JSON {path}: item {index} has unknown keys: "
                f"{', '.join(sorted(unknown))}"
            )
        source_line = item.get("source_line")
        if source_line is not None and (
            not isinstance(source_line, int) or isinstance(source_line, bool) or source_line < 1
        ):
            raise ValueError(
                f"seed credential JSON {path}: item {index} source_line must be a positive integer"
            )
        row: dict[str, str] = {}
        for name in SEED_CREDENTIAL_COLUMNS:
            value = item.get(name, "")
            if value is None:
                value = ""
            if not isinstance(value, str):
                raise ValueError(
                    f"seed credential JSON {path}: item {index} {name} must be a string or null"
                )
            row[name] = value.strip()
        rows.append((source_line, row))
    return rows


def _literal_secret_present(row: dict[str, str]) -> bool:
    return any(row.get(name) for name in ("community", "auth_password", "priv_password"))


def _validate_secret_file_permissions(path: Path, *, required: bool) -> None:
    """Reject unsafe world access when a file contains literal SNMP secrets."""

    if not required:
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IROTH | stat.S_IWOTH):
        raise ValueError(
            f"seed credential file containing literal secrets must not be "
            f"world-readable or world-writable: {path}"
        )


def _build_direct_credential(
    row: dict[str, str], *, internal_name: str, context: str, backend: str
) -> DirectCredential | None:
    """Validate one backend-compatible direct row and return its credential."""

    profile = row["credential_profile"]
    direct_fields = {
        name: row[name]
        for name in (
            "snmp_version",
            "community",
            "username",
            "auth_password",
            "priv_password",
            "auth_protocol",
            "priv_protocol",
        )
    }
    if profile:
        if any(direct_fields.values()):
            raise ValueError(
                f"{context}: credential_profile cannot be combined with direct SNMP credential fields"
            )
        return None

    if not any(direct_fields.values()):
        return None

    community = row["community"]
    v3_material = any(
        row[name]
        for name in ("username", "auth_password", "priv_password", "auth_protocol", "priv_protocol")
    )
    if community and v3_material:
        raise ValueError(f"{context}: community cannot be combined with SNMPv3 credential fields")

    version = row["snmp_version"].casefold()
    if not version:
        version = "v2c" if community else "v3"
    if version not in {"v2c", "v3"}:
        raise ValueError(f"{context}: snmp_version must be v2c or v3")

    if version == "v2c":
        if not community:
            raise ValueError(f"{context}: SNMPv2c requires community")
        if v3_material:
            raise ValueError(f"{context}: SNMPv2c row contains SNMPv3-only fields")
        return DirectCredential(name=internal_name, version="v2c", community=community)

    if community:
        raise ValueError(f"{context}: SNMPv3 row cannot contain community")
    missing = [name for name in ("username", "auth_password", "priv_password") if not row[name]]
    if missing:
        raise ValueError(f"{context}: SNMPv3 authPriv requires {', '.join(missing)}")
    try:
        auth_protocol, priv_protocol = validate_snmp_v3_protocols(
            backend,
            auth_protocol=row["auth_protocol"] or "sha1",
            priv_protocol=row["priv_protocol"] or "aes128",
        )
    except ValueError as exc:
        raise ValueError(f"{context}: {exc}") from exc
    return DirectCredential(
        name=internal_name,
        version="v3",
        username=row["username"],
        auth_password=row["auth_password"],
        priv_password=row["priv_password"],
        auth_protocol=auth_protocol,
        priv_protocol=priv_protocol,
    )


def load_seed_credential_files(paths: list[Path], config: AppConfig) -> SeedCredentialLoad:
    """Parse ordered CSV/JSON credential overlay files without matching seeds yet."""

    # Direct credential rows must be interpreted by the same immutable backend
    # selected for the run.  Calling the selection helper here also catches an
    # accidental post-load mutation before any credential material is consumed.
    backend = selected_snmp_backend(config.snmp).name
    result = SeedCredentialLoad(files=tuple(path.expanduser() for path in paths))
    pending: list[tuple[Path, int | None, dict[str, str], int]] = []
    order = 0
    for raw_path in result.files:
        path = raw_path
        if not path.is_file():
            raise FileNotFoundError(f"seed credential file not found: {path}")
        suffix = path.suffix.casefold()
        if suffix == ".csv":
            rows = _csv_rows(path)
        elif suffix == ".json":
            rows = _json_rows(path)
        else:
            raise ValueError(f"seed credential file must end in .csv or .json: {path}")
        _validate_secret_file_permissions(
            path, required=any(_literal_secret_present(row) for _line, row in rows)
        )
        for source_line, row in rows:
            order += 1
            pending.append((path, source_line, row, order))

    # Resolve strategy per seed. Blank means prefer unless another row for the
    # same seed explicitly declares exclusive. Conflicting explicit values fail.
    explicit_strategy: dict[str, str] = {}
    for path, source_line, row, _order in pending:
        seed = row["seed"].strip()
        if not seed:
            continue
        strategy = row["credential_strategy"].casefold()
        if strategy and strategy not in {"prefer", "exclusive"}:
            where = f"{path}:{source_line}" if source_line else str(path)
            raise ValueError(f"{where}: credential_strategy must be prefer or exclusive")
        if strategy:
            key = normalize_seed_key(seed)
            previous = explicit_strategy.get(key)
            if previous is not None and previous != strategy:
                raise ValueError(
                    f"seed credential records for {seed!r} use conflicting strategies "
                    f"{previous!r} and {strategy!r}"
                )
            explicit_strategy[key] = strategy

    direct_counter = 0
    for path, source_line, row, record_order in pending:
        seed = row["seed"].strip()
        if not seed:
            continue
        where = f"{path}:{source_line}" if source_line else f"{path}:record {record_order}"
        profile = row["credential_profile"] or None
        if profile is not None and profile not in config.credential_profiles:
            raise ValueError(f"{where}: unknown credential_profile {profile!r}")
        direct_counter += 1
        direct = _build_direct_credential(
            row,
            internal_name=f"seed-direct-{direct_counter}",
            context=where,
            backend=backend,
        )
        if profile is None and direct is None:
            result.warnings.append(
                f"seed credential record {where} for {seed!r} has no credential data; skipped"
            )
            continue
        key = normalize_seed_key(seed)
        strategy = explicit_strategy.get(key, "prefer")
        result.records.append(
            SeedCredentialRecord(
                seed=seed,
                strategy=strategy,  # ty: ignore[invalid-argument-type]
                credential_label=row["credential_label"] or None,
                credential_profile=profile,
                direct_credential=direct,
                source=path,
                source_line=source_line,
                order=record_order,
            )
        )
    return result
