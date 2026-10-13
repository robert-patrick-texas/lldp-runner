"""Sanitized run-launch provenance persisted as ``run.json``.

The discovery document describes topology results. ``run.json`` instead describes
how the logical run was launched, including every resume invocation. Secret values
are redacted before anything is written to durable state so later output copying
cannot accidentally expose credentials.
"""

from __future__ import annotations

import json
import os
import pwd
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from lldp_runner import APP_NAME, __version__
from lldp_runner.config import AppConfig
from lldp_runner.defaults import DEFAULT_SNMP_BACKEND
from lldp_runner.models import SeedInput
from lldp_runner.snmp.selection import selected_snmp_backend
from lldp_runner.timeutil import iso_now

RUN_JSON_SCHEMA_VERSION = 3
RUN_JSON_NAME = "run.json"
RUN_JSON_DRAFT_NAME = "run.json.draft"
REDACTED = "<redacted>"
RUN_TIMING_FIELDS = (
    "discovery_duration",
    "graph_resolution_duration",
    "graph_serialization_duration",
    "output_publication_duration",
    "finalization_duration",
    "total_wall_clock_duration",
)


def _parse_aware_iso(value: str | None) -> datetime | None:
    """Parse one timezone-aware ISO timestamp without guessing missing offsets."""

    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def _duration_seconds(started: str | None, completed: str | None) -> float | None:
    """Return elapsed wall-clock seconds between persisted run timestamps."""

    started_at = _parse_aware_iso(started)
    completed_at = _parse_aware_iso(completed)
    if started_at is None or completed_at is None:
        return None
    return round(max(0.0, (completed_at - started_at).total_seconds()), 3)


_SECRET_OPTIONS = {
    "--snmp.community",
    "--community",
    "--snmp.auth",
    "--snmp-auth",
    "--snmp.priv",
    "--snmp-priv",
}
_SECRET_ARGUMENT_NAMES = {"snmp_community", "snmp_auth", "snmp_priv"}
_RECOGNIZED_ENVIRONMENT = {
    "LLDP_RUNNER_CONFIG",
    "LLDP_RUNNER_ROOT",
    "LLDP_RUNNER_SCRATCH_ROOT",
    "LLDP_RUNNER_WORKERS",
    "LLDP_RUNNER_BATCH_SIZE",
    "LLDP_RUNNER_SEED_ORDER",
    "LLDP_RUNNER_SHUFFLE_KEY",
    "LLDP_RUNNER_LIMIT_BEHAVIOR",
    "LLDP_RUNNER_LOG_LEVEL",
    "LLDP_RUNNER_BOUNDARIES",
    "LLDP_RUNNER_MAX_DEVICES",
    "LLDP_RUNNER_MAX_HOSTS",
    "LLDP_RUNNER_SNMP_BACKEND",
    "LLDP_RUNNER_SNMP_TIMEOUT",
    "LLDP_RUNNER_SNMP_RPS",
    "LLDP_RUNNER_SNMP_MAX_OUTSTANDING",
    "LLDP_RUNNER_ICMP_TIMEOUT",
    "LLDP_RUNNER_SNAPSHOT_INTERVAL",
    "LLDP_RUNNER_SCOREBOARD_INTERVAL",
    "LLDP_RUNNER_SEEDS",
    "LLDP_RUNNER_SEED_FILES",
    "LLDP_RUNNER_SEED_DIRS",
}
_SECRET_FIELD_NAMES = {
    "community",
    "auth",
    "auth_password",
    "priv",
    "priv_password",
    "password",
    "secret",
    "token",
}


@dataclass(frozen=True, slots=True)
class InvocationProvenance:
    """Sanitized launch attributes for one ``run``/resume process invocation."""

    username: str
    uid: int
    effective_uid: int
    started: str
    argv: tuple[str, ...]
    arguments: dict[str, Any]
    environment: dict[str, str]
    seed_inputs: tuple[dict[str, Any], ...]
    stdin_seeds: tuple[str, ...]
    config_files_logged: bool
    config_files: tuple[str, ...]
    snmp_backend_name: str = DEFAULT_SNMP_BACKEND
    snmp_backend_version: str = "unknown"


def _account_identity() -> tuple[str, int, int]:
    """Return passwd-database username plus real/effective numeric user IDs."""

    uid = os.getuid()
    effective_uid = os.geteuid()
    try:
        username = pwd.getpwuid(effective_uid).pw_name
    except KeyError:
        username = str(effective_uid)
    return username, uid, effective_uid


def _set_path_is_secret(expression: str) -> bool:
    """Return whether one ``--set`` assignment targets a secret-bearing field."""

    if "=" not in expression:
        return False
    dotted = expression.split("=", 1)[0].strip().casefold()
    parts = [part.strip() for part in dotted.split(".") if part.strip()]
    if not parts:
        return False
    # Any assignment beneath the credential object can legally use a TOML inline
    # table, so redact the complete value even when the leaf is not itself named
    # community/password. This deliberately favors provenance safety over detail.
    if parts[0] == "credentials":
        return True
    return parts[-1] in _SECRET_FIELD_NAMES


def _redact_set_expression(expression: str) -> str:
    """Preserve the configured option path while masking a secret TOML value."""

    if not _set_path_is_secret(expression) or "=" not in expression:
        return expression
    dotted = expression.split("=", 1)[0].strip()
    return f"{dotted}={REDACTED}"


def sanitize_argv(argv: Sequence[str]) -> list[str]:
    """Return raw command arguments with credential-bearing values redacted."""

    result: list[str] = []
    redact_next = False
    set_next = False
    for token in argv:
        if redact_next:
            result.append(REDACTED)
            redact_next = False
            continue
        if set_next:
            result.append(_redact_set_expression(token))
            set_next = False
            continue

        if token in _SECRET_OPTIONS:
            result.append(token)
            redact_next = True
            continue
        if token == "--set":
            result.append(token)
            set_next = True
            continue

        matched_secret = False
        for option in _SECRET_OPTIONS:
            prefix = f"{option}="
            if token.startswith(prefix):
                result.append(f"{option}={REDACTED}")
                matched_secret = True
                break
        if matched_secret:
            continue
        if token.startswith("--set="):
            result.append("--set=" + _redact_set_expression(token[len("--set=") :]))
            continue
        result.append(token)
    return result


def _jsonable(value: Any) -> Any:
    """Convert CLI/config values to JSON-safe primitives without stringifying nulls."""

    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def sanitize_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Return meaningful parsed CLI attributes with all known secrets masked."""

    result: dict[str, Any] = {}
    for name, value in arguments.items():
        if value is None or value is False or value == []:
            continue
        if name in _SECRET_ARGUMENT_NAMES:
            result[name] = REDACTED
            continue
        if name == "set":
            result[name] = [_redact_set_expression(str(item)) for item in value]
            continue
        result[name] = _jsonable(value)
    return result


def _seed_record(seed: SeedInput) -> dict[str, Any]:
    """Serialize one consolidated seed input, retaining its provenance and hints."""

    record: dict[str, Any] = {"seed": seed.seed}
    if seed.source:
        record["source"] = seed.source
    if seed.query_target:
        record["query_target"] = seed.query_target
    if seed.prior_state:
        record["prior_state"] = seed.prior_state
    if seed.ipv4:
        record["ipv4"] = list(seed.ipv4)
    if seed.ipv6:
        record["ipv6"] = list(seed.ipv6)
    if seed.parse_errors:
        record["parse_errors"] = list(seed.parse_errors)
    return record


def build_invocation_provenance(
    config: AppConfig,
    *,
    argv: Sequence[str],
    arguments: Mapping[str, Any],
    seeds: Sequence[SeedInput],
    stdin_seeds: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
) -> InvocationProvenance:
    """Build one sanitized invocation record before discovery starts."""

    env = os.environ if env is None else env
    username, uid, effective_uid = _account_identity()
    config_files = (
        tuple(str(path) for path in config.config_files)
        if config.output.run_json_config_log
        else ()
    )
    environment = {name: str(env[name]) for name in sorted(_RECOGNIZED_ENVIRONMENT) if name in env}
    backend = selected_snmp_backend(config.snmp)
    return InvocationProvenance(
        username=username,
        uid=uid,
        effective_uid=effective_uid,
        started=iso_now(),
        argv=tuple(sanitize_argv(argv)),
        arguments=sanitize_arguments(arguments),
        environment=environment,
        seed_inputs=tuple(_seed_record(seed) for seed in seeds),
        stdin_seeds=tuple(str(seed) for seed in stdin_seeds),
        config_files_logged=bool(config.output.run_json_config_log),
        config_files=config_files,
        snmp_backend_name=backend.name,
        snmp_backend_version=backend.version,
    )


def _atomic_json(path: Path, payload: Mapping[str, Any], *, indent: int) -> None:
    """Write one provenance document atomically and durably."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=indent, sort_keys=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _app_metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a manifest with canonical application metadata after schema version.

    Reconstructing the small top-level mapping keeps ``app_name`` and
    ``app_version`` in the requested stable location even when an older durable
    schema-1 manifest is resumed after an LLDP-Runner upgrade.
    """

    result: dict[str, Any] = {
        "schema_version": payload["schema_version"],
        "app_name": APP_NAME,
        "app_version": __version__,
    }
    for key, value in payload.items():
        if key not in {"schema_version", "app_name", "app_version"}:
            result[key] = value
    return result


def _load_manifest(path: Path) -> dict[str, Any] | None:
    """Load an existing durable manifest, returning ``None`` when absent."""

    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OSError(f"unable to read existing run provenance {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise OSError(f"existing run provenance is not a JSON object: {path}")
    if payload.get("schema_version") != RUN_JSON_SCHEMA_VERSION:
        raise OSError(
            "unsupported run.json schema in durable run state: "
            f"{payload.get('schema_version')!r}; expected {RUN_JSON_SCHEMA_VERSION}"
        )
    return _app_metadata(payload)


def begin_run_manifest(
    path: Path,
    *,
    run_id: str,
    started: str | None,
    status: str,
    invocation: InvocationProvenance,
    indent: int,
    resuming_existing: bool = False,
) -> int:
    """Create/update durable run provenance and append the current invocation."""

    payload = _load_manifest(path)
    identity = {
        "username": invocation.username,
        "uid": invocation.uid,
        "effective_uid": invocation.effective_uid,
    }
    if payload is None:
        payload = {
            "schema_version": RUN_JSON_SCHEMA_VERSION,
            "app_name": APP_NAME,
            "app_version": __version__,
            "run_id": run_id,
            "snmp_backend": {
                "name": invocation.snmp_backend_name,
                "version": invocation.snmp_backend_version,
            },
            "status": status,
            "started": started,
            "completed": None,
            "duration": None,
            **{field: None for field in RUN_TIMING_FIELDS},
            "started_by": (
                {
                    "username": "unknown",
                    "uid": None,
                    "effective_uid": None,
                    "provenance": "pre-run.json resume",
                }
                if resuming_existing
                else identity
            ),
            "config_files_logged": invocation.config_files_logged,
            "config_files": list(invocation.config_files),
            "invocations": [],
        }
    elif payload.get("run_id") != run_id:
        raise OSError(
            f"run provenance ID mismatch in {path}: {payload.get('run_id')!r} != {run_id!r}"
        )

    backend_record = payload.get("snmp_backend")
    if backend_record is None:
        # Real resumable runs are checked against SQLite metadata by Coordinator
        # before this point. This assignment only supports focused embedders that
        # construct a manifest directly.
        payload["snmp_backend"] = {
            "name": invocation.snmp_backend_name,
            "version": invocation.snmp_backend_version,
        }
    elif not isinstance(backend_record, dict):
        raise OSError(f"invalid snmp_backend object in {path}")
    elif backend_record.get("name") != invocation.snmp_backend_name:
        raise OSError(
            "SNMP backend mismatch in run provenance: "
            f"persisted {backend_record.get('name')!r}, "
            f"requested {invocation.snmp_backend_name!r}"
        )
    else:
        # Keep the logical run's backend name fixed while reporting the package
        # version installed for the current invocation.
        backend_record["version"] = invocation.snmp_backend_version

    invocations = payload.setdefault("invocations", [])
    if not isinstance(invocations, list):
        raise OSError(f"invalid invocations array in {path}")
    sequence = len(invocations) + 1
    invocation_record = {
        "sequence": sequence,
        **identity,
        "started": invocation.started,
        "ended": None,
        "argv": list(invocation.argv),
        "arguments": invocation.arguments,
        "environment": invocation.environment,
        "seed_inputs": list(invocation.seed_inputs),
        "stdin_seeds": list(invocation.stdin_seeds),
        "config_files_logged": invocation.config_files_logged,
        "snmp_backend": {
            "name": invocation.snmp_backend_name,
            "version": invocation.snmp_backend_version,
        },
    }
    if invocation.config_files_logged:
        invocation_record["config_files"] = list(invocation.config_files)
        known = payload.setdefault("config_files", [])
        if isinstance(known, list):
            for item in invocation.config_files:
                if item not in known:
                    known.append(item)
        payload["config_files_logged"] = True
    invocations.append(invocation_record)
    payload["status"] = status
    if started is not None:
        payload["started"] = started
    payload["completed"] = None
    payload["duration"] = None
    for field in RUN_TIMING_FIELDS:
        payload[field] = None
    _atomic_json(path, payload, indent=indent)
    return sequence


def update_run_manifest(
    path: Path,
    *,
    sequence: int,
    status: str,
    started: str | None,
    completed: str | None,
    invocation_ended: str | None,
    indent: int,
    phase_metrics: Mapping[str, float | int | None] | None = None,
) -> dict[str, Any]:
    """Update logical/invocation timing and return the persisted document."""

    payload = _load_manifest(path)
    if payload is None:
        raise OSError(f"run provenance missing: {path}")
    payload["status"] = status
    payload["started"] = started
    payload["completed"] = completed
    payload["duration"] = _duration_seconds(started, completed)
    if phase_metrics is not None:
        unknown = sorted(set(phase_metrics) - set(RUN_TIMING_FIELDS))
        if unknown:
            raise ValueError("unsupported run timing field(s): " + ", ".join(unknown))
        for field in RUN_TIMING_FIELDS:
            value = phase_metrics.get(field)
            payload[field] = None if value is None else round(max(0.0, float(value)), 3)
    invocations = payload.get("invocations")
    if not isinstance(invocations, list):
        raise OSError(f"invalid invocations array in {path}")
    match = next(
        (
            item
            for item in invocations
            if isinstance(item, dict) and item.get("sequence") == sequence
        ),
        None,
    )
    if match is None:
        raise OSError(f"run invocation {sequence} missing from {path}")
    if invocation_ended is not None:
        match["ended"] = invocation_ended
    _atomic_json(path, payload, indent=indent)
    return payload


def publish_run_manifest(
    durable_path: Path,
    directory: Path,
    *,
    draft: bool,
    indent: int,
) -> Path:
    """Publish the current durable provenance beside discovery output."""

    payload = _load_manifest(durable_path)
    if payload is None:
        raise OSError(f"run provenance missing: {durable_path}")
    output = directory / (RUN_JSON_DRAFT_NAME if draft else RUN_JSON_NAME)
    _atomic_json(output, payload, indent=indent)
    return output
