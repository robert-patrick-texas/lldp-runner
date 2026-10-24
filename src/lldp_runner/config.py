"""TOML configuration loading, validation, and environment overrides."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import tempfile
import tomllib
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field, fields
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from lldp_runner.csv_fields import FIXED_FIELDS_BY_SOURCE, validate_field_reference
from lldp_runner.defaults import (
    CONFIG_SEARCH_PATHS,
    CREDENTIAL_AUTH_PROTOCOL_DEFAULT,
    CREDENTIAL_FALLBACK_ATTEMPTS_DEFAULT,
    CREDENTIAL_PRIMARY_ATTEMPTS_DEFAULT,
    CREDENTIAL_PRIV_PROTOCOL_DEFAULT,
    DEFAULT_SNMP_ENV,
    DEFAULTS,
    TERMINAL_COLOR_NAMES,
)
from lldp_runner.layout import InstallLayout, select_layout
from lldp_runner.runid import validate_run_id_format
from lldp_runner.timeutil import configure_timezone, normalize_timezone_name


class ConfigError(ValueError):
    """Invalid lldp-runner configuration."""


class CredentialMode(StrEnum):
    """Control how configuration loading interacts with SNMP credentials.

    ``REQUIRED`` is for commands that may communicate with devices and therefore
    need usable credentials. ``OPTIONAL`` preserves credential policy parsing and
    runtime synthesis while permitting missing secrets, which is useful for dry-run
    policy inspection. ``DISABLED`` is for read-only commands that consume stored
    data and must not parse, synthesize, resolve, or validate credential policy.
    """

    REQUIRED = "required"
    OPTIONAL = "optional"
    DISABLED = "disabled"


@dataclass(slots=True)
class PathsConfig:
    """Filesystem locations and run-ID naming settings for discovery state."""

    persistent_root: Path | str = DEFAULTS["paths"]["persistent_root"]
    scratch_root: Path | str = DEFAULTS["paths"]["scratch_root"]
    runs_dirname: str = DEFAULTS["paths"]["runs_dirname"]
    output_dirname: str = DEFAULTS["paths"]["output_dirname"]
    clean_scratch_when_completed: bool = DEFAULTS["paths"]["clean_scratch_when_completed"]
    run_id_format: str = DEFAULTS["paths"]["run_id_format"]

    def __post_init__(self) -> None:
        """Normalize explicit path strings while preserving the ``auto`` sentinel.

        Returns:
            ``None``. Explicit path values are expanded in place; runtime path
            selection resolves ``auto`` later.
        """

        # Preserve the operator-facing sentinel until runtime path selection.
        # Concrete paths are normalized immediately so downstream code sees
        # pathlib.Path after _resolve_runtime_values() completes.
        if str(self.persistent_root).lower() != "auto":
            self.persistent_root = Path(self.persistent_root).expanduser()
        if str(self.scratch_root).lower() != "auto":
            self.scratch_root = Path(self.scratch_root).expanduser()


@dataclass(slots=True)
class TimeConfig:
    """Project-wide wall-clock timezone policy.

    ``timezone`` accepts the convenience aliases ``eastern``, ``utc``, and
    ``local`` plus IANA names such as ``America/Denver``.  Runtime loading
    normalizes/validates the value and initializes each process's time helpers.
    """

    timezone: str = DEFAULTS["time"]["timezone"]

    def __post_init__(self) -> None:
        """Normalize surrounding whitespace without changing IANA name case."""

        self.timezone = str(self.timezone).strip()


@dataclass(slots=True)
class DiscoveryConfig:
    """Coordinator scheduling, seed, scope, and recursion configuration."""

    boundaries: list[str] = field(default_factory=lambda: list(DEFAULTS["discovery"]["boundaries"]))
    seeds: list[str] = field(default_factory=lambda: list(DEFAULTS["discovery"]["seeds"]))
    seed_files: list[str] = field(default_factory=lambda: list(DEFAULTS["discovery"]["seed_files"]))
    seed_dirs: list[str] = field(default_factory=lambda: list(DEFAULTS["discovery"]["seed_dirs"]))
    seed_order: str = DEFAULTS["discovery"]["seed_order"]
    seed_dns_mode: str = DEFAULTS["discovery"]["seed_dns_mode"]
    shuffle_key: str | int = DEFAULTS["discovery"]["shuffle_key"]
    limit_behavior: str = DEFAULTS["discovery"]["limit_behavior"]
    # "auto" until _resolve_runtime_values() replaces it with an integer.
    workers: int | str = DEFAULTS["discovery"]["workers"]
    batch_size: int = DEFAULTS["discovery"]["batch_size"]
    max_devices: int | str = DEFAULTS["discovery"]["max_devices"]
    max_hosts: int = DEFAULTS["discovery"]["max_hosts"]
    late_address_recovery_attempts: int = DEFAULTS["discovery"]["late_address_recovery_attempts"]
    address_preference: list[str] = field(
        default_factory=lambda: list(DEFAULTS["discovery"]["address_preference"])
    )
    work_stealing: bool = DEFAULTS["discovery"]["work_stealing"]
    dns_suffixes: list[str] = field(
        default_factory=lambda: list(DEFAULTS["discovery"]["dns_suffixes"])
    )
    resolve_discovered_managed_names: bool = DEFAULTS["discovery"][
        "resolve_discovered_managed_names"
    ]


@dataclass(slots=True)
class SnmpConfig:
    """SNMP transport limits and collector behavior used by network commands."""

    backend: str = DEFAULTS["snmp"]["backend"]
    port: int = DEFAULTS["snmp"]["port"]
    version: str = DEFAULTS["snmp"]["version"]
    timeout_seconds: float = DEFAULTS["snmp"]["timeout_seconds"]
    max_repetitions: int = DEFAULTS["snmp"]["max_repetitions"]
    retry_per_operation: int = DEFAULTS["snmp"]["retry_per_operation"]
    retry_per_collector: int = DEFAULTS["snmp"]["retry_per_collector"]
    retry_total_cap: int = DEFAULTS["snmp"]["retry_total_cap"]
    retry_neighbor_reserve: int = DEFAULTS["snmp"]["retry_neighbor_reserve"]
    structural_table_retry: int = DEFAULTS["snmp"]["structural_table_retry"]
    retry_timeout_multiplier: float = DEFAULTS["snmp"]["retry_timeout_multiplier"]
    retry_max_repetitions_multiplier: float = DEFAULTS["snmp"]["retry_max_repetitions_multiplier"]
    retry_min_max_repetitions: int = DEFAULTS["snmp"]["retry_min_max_repetitions"]
    retry_inter_pdu_delay_ms: float = DEFAULTS["snmp"]["retry_inter_pdu_delay_ms"]
    neighbor_stability_retry: bool = DEFAULTS["snmp"]["neighbor_stability_retry"]
    neighbor_stability_retry_delay_seconds: float = DEFAULTS["snmp"][
        "neighbor_stability_retry_delay_seconds"
    ]
    per_device_rps: float = DEFAULTS["snmp"]["per_device_rps"]
    max_outstanding_devices_per_worker: int = DEFAULTS["snmp"]["max_outstanding_devices_per_worker"]
    inter_wave_delay_seconds: float = DEFAULTS["snmp"]["inter_wave_delay_seconds"]
    collect_entity_mib: bool = DEFAULTS["snmp"]["collect_entity_mib"]
    entity_mib_mode: str = DEFAULTS["snmp"]["entity_mib_mode"]
    report_metrics: bool = DEFAULTS["snmp"]["report_metrics"]
    # Runtime-only binding. These fields are deliberately excluded from TOML
    # construction and are copied into spawned workers with the AppConfig object.
    selected_backend: str | None = field(default=None, init=False, repr=False, compare=False)
    selected_backend_version: str | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Normalize operator-facing SNMP mode values after TOML construction.

        ``entity_mib_mode`` is case-insensitive for operator convenience.  The
        normalized value is validated centrally by :func:`validate_config` so
        downstream collectors can compare a stable lowercase string.
        """

        self.backend = str(self.backend).strip().casefold()
        self.entity_mib_mode = str(self.entity_mib_mode).casefold()


@dataclass(slots=True)
class IcmpConfig:
    """ICMP reachability-probe settings applied before or alongside SNMP."""

    enabled: bool = DEFAULTS["icmp"]["enabled"]
    probes: int = DEFAULTS["icmp"]["probes"]
    timeout_seconds: float = DEFAULTS["icmp"]["timeout_seconds"]
    inter_probe_delay_seconds: float = DEFAULTS["icmp"]["inter_probe_delay_seconds"]
    backend: str = DEFAULTS["icmp"]["backend"]  # auto, raw, system, disabled


@dataclass(slots=True)
class CustomCsvColumnConfig:
    """One ordered column in an operator-defined CSV output.

    Args:
        field: Registered fixed-field or canonical JSON field reference.
        header: Optional output header label. When omitted, the field leaf name
            is used so direct JSON projections retain canonical naming.
        transform: Optional controlled transform for a ``json.*`` field.
    """

    field: str
    header: str | None = None
    transform: str | None = None


@dataclass(slots=True)
class CustomCsvConfig:
    """One named custom CSV report rendered from the discovery document.

    Args:
        name: Configuration-table name used in validation and diagnostics.
        filename: Relative CSV filename written inside the run output directory.
        source: Row grain: hosts, stack-members, seeds, unknown-devices, or errors.
        columns: Ordered column definitions controlling selection and headers.
        enabled: Whether the custom report participates in snapshots/final output.
    """

    name: str
    filename: str
    source: str
    columns: list[CustomCsvColumnConfig]
    enabled: bool = True


@dataclass(slots=True)
class OutputConfig:
    """Discovery output cadence plus fixed and custom CSV rendering settings."""

    draft_in_scratch: bool = DEFAULTS["output"]["draft_in_scratch"]
    snapshot_interval_seconds: float = DEFAULTS["output"]["snapshot_interval_seconds"]
    scoreboard_interval_seconds: float = DEFAULTS["output"]["scoreboard_interval_seconds"]
    pretty_json_indent: int = DEFAULTS["output"]["pretty_json_indent"]
    run_json_config_log: bool = DEFAULTS["output"]["run_json_config_log"]
    purge_keep: int = DEFAULTS["output"]["purge_keep"]
    neighbor_local_width: int = DEFAULTS["output"]["neighbor_local_width"]
    neighbor_remote_port_width: int = DEFAULTS["output"]["neighbor_remote_port_width"]
    relationship_view: str = DEFAULTS["output"]["relationship_view"]
    chassis_id_name_fallback: str | bool = DEFAULTS["output"]["chassis_id_name_fallback"]
    # Standard CSV schemas remain version-controlled by LLDP-Runner. Individual
    # booleans control fixed report presence; custom definitions add site-specific
    # projections. One global policy controls header-only files for both groups.
    write_hosts_csv: bool = DEFAULTS["output"]["write_hosts_csv"]
    write_stack_members_csv: bool = DEFAULTS["output"]["write_stack_members_csv"]
    write_seeds_csv: bool = DEFAULTS["output"]["write_seeds_csv"]
    write_unknown_devices_csv: bool = DEFAULTS["output"]["write_unknown_devices_csv"]
    write_errors_csv: bool = DEFAULTS["output"]["write_errors_csv"]
    write_empty_csv: bool = DEFAULTS["output"]["write_empty_csv"]
    log_alert_on_empty_csv: bool = DEFAULTS["output"]["log_alert_on_empty_csv"]
    custom_csv: dict[str, CustomCsvConfig] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Normalize the chassis-ID fallback into its internal string mode.

        Returns:
            ``None``. The configured value is normalized in place for later
            validation and output-name fallback decisions.
        """

        # Accept the early boolean form for operator convenience while exposing
        # explicit modes for predictable behavior. True means the safer
        # name-like mode; False disables the fallback.
        if self.chassis_id_name_fallback is True:
            self.chassis_id_name_fallback = "name_like"
        elif self.chassis_id_name_fallback is False:
            self.chassis_id_name_fallback = "disabled"
        else:
            self.chassis_id_name_fallback = str(self.chassis_id_name_fallback).lower()
        self.relationship_view = str(self.relationship_view).strip().casefold()


@dataclass(slots=True)
class DiffConfig:
    """Read-only cross-run comparison and terminal-detail policy."""

    include_collection_timing: bool = DEFAULTS["diff"]["include_collection_timing"]
    summary_only: bool = DEFAULTS["diff"]["summary_only"]
    expand_collection_incidents: bool = DEFAULTS["diff"]["expand_collection_incidents"]


@dataclass(slots=True)
class TerminalConfig:
    """Semantic colors used by human-readable terminal output.

    The renderers accept symbolic names instead of raw escape sequences so a
    configuration file cannot inject arbitrary terminal-control bytes. ANSI is
    still emitted only for an interactive TTY and remains disabled by
    ``NO_COLOR``.
    """

    color: str = DEFAULTS["terminal"]["color"]
    palette: str = DEFAULTS["terminal"]["palette"]
    heading_color: str = DEFAULTS["terminal"]["heading_color"]
    success_color: str = DEFAULTS["terminal"]["success_color"]
    warning_color: str = DEFAULTS["terminal"]["warning_color"]
    error_color: str = DEFAULTS["terminal"]["error_color"]
    learned_color: str = DEFAULTS["terminal"]["learned_color"]
    observed_by_color: str = DEFAULTS["terminal"]["observed_by_color"]
    inspection_neighbor_color: str = DEFAULTS["terminal"]["inspection_neighbor_color"]
    metric_color: str = DEFAULTS["terminal"]["metric_color"]

    def __post_init__(self) -> None:
        """Normalize configured color names for validation and renderer lookup."""

        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            setattr(self, field_name, str(value).strip().casefold())


@dataclass(slots=True)
class ResumeConfig:
    """Pause/resume lease and indicator settings for persistent runs."""

    default_resume: bool = DEFAULTS["resume"]["default_resume"]
    lease_seconds: int = DEFAULTS["resume"]["lease_seconds"]
    pause_indicator: str = DEFAULTS["resume"]["pause_indicator"]


@dataclass(slots=True)
class CredentialConfig:
    """One named SNMPv2c or SNMPv3 credential definition and secret sources."""

    name: str
    version: str
    community_env: str | None = None
    community: str | None = None
    username_env: str | None = None
    username: str | None = None
    auth_password_env: str | None = None
    auth_password: str | None = None
    priv_password_env: str | None = None
    priv_password: str | None = None
    auth_protocol: str = CREDENTIAL_AUTH_PROTOCOL_DEFAULT
    priv_protocol: str = CREDENTIAL_PRIV_PROTOCOL_DEFAULT

    def secret(self, field_name: str, env: Mapping[str, str] | None = None) -> str | None:
        """Resolve one credential field, preferring its configured environment variable.

        Args:
            field_name: Credential attribute such as ``community`` or
                ``auth_password``.
            env: Environment mapping to read; defaults to :data:`os.environ`.

        Returns:
            The environment-backed or directly configured secret, or ``None``.
        """

        env = os.environ if env is None else env
        direct = getattr(self, field_name)
        env_name = getattr(self, f"{field_name}_env")
        if env_name:
            return env.get(env_name)
        return direct


@dataclass(slots=True)
class CredentialProfile:
    """Ordered primary/fallback credential attempts for one policy profile."""

    name: str
    primary: str
    fallback: str | None = None
    primary_attempts: int = CREDENTIAL_PRIMARY_ATTEMPTS_DEFAULT
    fallback_attempts: int = CREDENTIAL_FALLBACK_ATTEMPTS_DEFAULT


def _rule_values(single: str | None, plural: list[str]) -> list[str]:
    """Return de-duplicated singular/plural rule values in deterministic order."""
    values: list[str] = []
    if single is not None and str(single).strip():
        values.append(str(single))
    for value in plural:
        text = str(value)
        if text.strip() and text not in values:
            values.append(text)
    return values


def _pattern_values(value: str | list[str]) -> list[str]:
    """Normalize a field/detail pattern value to a list while accepting legacy strings."""
    if isinstance(value, str):
        return [value]
    return list(value)


@dataclass(slots=True)
class AddressCredentialRule:
    """Map one or more management-address networks to a credential profile."""

    profile: str
    network: str | None = None
    networks: list[str] = field(default_factory=list)

    def network_values(self) -> list[str]:
        """Return this rule's de-duplicated network selectors in policy order."""

        return _rule_values(self.network, self.networks)


@dataclass(slots=True)
class NameCredentialRule:
    """Map one or more hostname regex patterns to a credential profile."""

    profile: str
    pattern: str | None = None
    patterns: list[str] = field(default_factory=list)

    def pattern_values(self) -> list[str]:
        """Return this rule's de-duplicated regex selectors in policy order."""

        return _rule_values(self.pattern, self.patterns)


@dataclass(slots=True)
class CredentialRules:
    """Default and ordered address/name rules for credential-profile selection."""

    default_profile: str = DEFAULTS["credential_rules"]["default_profile"]
    address: list[AddressCredentialRule] = field(default_factory=list)
    name: list[NameCredentialRule] = field(default_factory=list)


@dataclass(slots=True)
class QueryAddressRule:
    """Permit or deny network queries for one or more address networks."""

    action: str
    network: str | None = None
    networks: list[str] = field(default_factory=list)

    def network_values(self) -> list[str]:
        """Return this rule's de-duplicated network selectors in policy order."""

        return _rule_values(self.network, self.networks)


@dataclass(slots=True)
class QueryNameRule:
    """Permit or deny network queries for matching hostname patterns."""

    action: str
    pattern: str | None = None
    patterns: list[str] = field(default_factory=list)

    def pattern_values(self) -> list[str]:
        """Return this rule's de-duplicated regex selectors in policy order."""

        return _rule_values(self.pattern, self.patterns)


@dataclass(slots=True)
class QueryPolicyConfig:
    """Default query action plus ordered address and hostname policy rules."""

    default_action: str = DEFAULTS["query_policy"]["default_action"]
    address_rules: list[QueryAddressRule] = field(default_factory=list)
    name_rules: list[QueryNameRule] = field(default_factory=list)


@dataclass(slots=True)
class ClassificationAddressRule:
    """Assign a discovery category to one or more address networks."""

    category: str
    network: str | None = None
    networks: list[str] = field(default_factory=list)

    def network_values(self) -> list[str]:
        """Return this rule's de-duplicated network selectors in policy order."""

        return _rule_values(self.network, self.networks)


@dataclass(slots=True)
class ClassificationNameRule:
    """Assign a discovery category to matching hostname patterns."""

    category: str
    pattern: str | None = None
    patterns: list[str] = field(default_factory=list)

    def pattern_values(self) -> list[str]:
        """Return this rule's de-duplicated regex selectors in policy order."""

        return _rule_values(self.pattern, self.patterns)


@dataclass(slots=True)
class ClassificationEvidenceRule:
    """Classify observed neighbor evidence using combined match criteria."""

    category: str
    label: str | None = None
    name_pattern: str | None = None
    name_patterns: list[str] = field(default_factory=list)
    network: str | None = None
    networks: list[str] = field(default_factory=list)
    field_patterns: dict[str, str | list[str]] = field(default_factory=dict)
    detail_patterns: dict[str, str | list[str]] = field(default_factory=dict)

    def name_pattern_values(self) -> list[str]:
        """Return de-duplicated name regexes used to evaluate this evidence rule."""

        return _rule_values(self.name_pattern, self.name_patterns)

    def network_values(self) -> list[str]:
        """Return this rule's de-duplicated network selectors in policy order."""

        return _rule_values(self.network, self.networks)


@dataclass(slots=True)
class ClassificationConfig:
    """Ordered classification rules and manufacturer/pattern defaults."""

    address_rules: list[ClassificationAddressRule] = field(default_factory=list)
    name_rules: list[ClassificationNameRule] = field(default_factory=list)
    evidence_rules: list[ClassificationEvidenceRule] = field(default_factory=list)
    managed_manufacturers: list[str] = field(
        default_factory=lambda: list(DEFAULTS["classification"]["managed_manufacturers"])
    )
    managed_endpoint_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULTS["classification"]["managed_endpoint_patterns"])
    )
    unmanaged_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULTS["classification"]["unmanaged_patterns"])
    )


@dataclass(slots=True)
class TagRule:
    """Attach operator tags when configured identity/evidence criteria match."""

    tags: list[str]
    label: str | None = None
    category: str | None = None
    name_pattern: str | None = None
    name_patterns: list[str] = field(default_factory=list)
    network: str | None = None
    networks: list[str] = field(default_factory=list)
    field_patterns: dict[str, str | list[str]] = field(default_factory=dict)
    detail_patterns: dict[str, str | list[str]] = field(default_factory=dict)

    def name_pattern_values(self) -> list[str]:
        """Return de-duplicated name regexes used to evaluate this evidence rule."""

        return _rule_values(self.name_pattern, self.name_patterns)

    def network_values(self) -> list[str]:
        """Return this rule's de-duplicated network selectors in policy order."""

        return _rule_values(self.network, self.networks)


@dataclass(slots=True)
class TaggingConfig:
    """Ordered tag rules applied to discovered host records."""

    rules: list[TagRule] = field(default_factory=list)


@dataclass(slots=True)
class NeighborConfig:
    """Protocol enablement and CDP manufacturer-selection settings."""

    enable_lldp: bool = DEFAULTS["neighbors"]["enable_lldp"]
    enable_lldpv2: bool = DEFAULTS["neighbors"]["enable_lldpv2"]
    cdp_for_cisco: bool = DEFAULTS["neighbors"]["cdp_for_cisco"]
    cdp_manufacturers: list[str] = field(
        default_factory=lambda: list(DEFAULTS["neighbors"]["cdp_manufacturers"])
    )


@dataclass(slots=True)
class LoggingConfig:
    """Runtime log destinations and formatting severity.

    ``console`` and ``file`` are independent switches. ``filename`` is resolved
    by :func:`lldp_runner.runtime.make_run_paths`: relative paths live beneath the
    current run-ID directory, while absolute paths are used verbatim for
    operators that centralize LLDP-Runner logs.
    """

    level: str = DEFAULTS["logging"]["level"]
    console: bool = DEFAULTS["logging"]["console"]
    file: bool = DEFAULTS["logging"]["file"]
    filename: str = DEFAULTS["logging"]["filename"]


@dataclass(slots=True)
class AppConfig:
    """Complete typed LLDP-Runner configuration consumed by command/runtime code."""

    paths: PathsConfig
    time: TimeConfig
    discovery: DiscoveryConfig
    snmp: SnmpConfig
    icmp: IcmpConfig
    output: OutputConfig
    diff: DiffConfig
    resume: ResumeConfig
    credentials: dict[str, CredentialConfig]
    credential_profiles: dict[str, CredentialProfile]
    credential_rules: CredentialRules
    query_policy: QueryPolicyConfig
    classification: ClassificationConfig
    tagging: TaggingConfig
    neighbors: NeighborConfig
    logging: LoggingConfig
    terminal: TerminalConfig
    config_path: Path | None = None
    config_files: tuple[Path, ...] = ()
    # The primary file as the operator or launcher named it, made absolute but
    # with symbolic links kept. The install layout follows this location.
    config_location: Path | None = None


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    """Return one top-level configuration table by name.

    Args:
        data: Parsed/merged configuration mapping.
        name: Top-level TOML table name.

    Returns:
        The table mapping, or an empty mapping when omitted.

    Raises:
        ConfigError: If the named value is present but is not a TOML table.
    """

    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a table")
    return value


def _build_dataclass(cls: type[Any], data: dict[str, Any]) -> Any:
    """Construct a typed config dataclass after rejecting unknown option names.

    Args:
        cls: Dataclass type representing one configuration section or rule.
        data: Parsed option values passed as constructor keyword arguments.

    Returns:
        An instance of ``cls`` populated from ``data``.

    Raises:
        ConfigError: If ``data`` contains an unsupported setting name.
        TypeError: If a supplied value is incompatible with construction.
    """

    # Runtime-only ``init=False`` fields must never become accepted TOML keys.
    allowed = {item.name for item in fields(cls) if item.init}
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"Unknown settings for {cls.__name__}: {', '.join(sorted(unknown))}")
    return cls(**data)


def _reject_unknown_keys(data: Mapping[str, Any], allowed: set[str], context: str) -> None:
    """Reject ignored/typo keys in manually assembled configuration sections."""

    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"Unknown settings for {context}: {', '.join(sorted(unknown))}")


_REPLACE_LIST_PATHS = {
    ("discovery", "address_preference"),
    # Boundaries are one complete scope definition, not an accumulating rule list.
    # Replacement is especially important now that generated/default configs use
    # 0.0.0.0/0 and ::/0; concatenating those with a fragment would defeat a
    # site fragment that intentionally narrows recursive discovery.
    ("discovery", "boundaries"),
}


def _merge_config_data(
    base: dict[str, Any], overlay: dict[str, Any], *, path: tuple[str, ...] = ()
) -> dict[str, Any]:
    """Merge included TOML data deterministically.

    Tables merge recursively. Lists concatenate so rule and pattern files can be
    split across includes while preserving first-match-wins order. Discovery
    boundaries/address preference and each custom CSV ``columns`` list are complete
    definitions, so a later file replaces those lists rather than concatenating them.
    Scalar values from later includes override earlier includes, and the including
    file itself is applied last.
    """
    result = dict(base)
    for key, value in overlay.items():
        item_path = (*path, key)
        current = result.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            result[key] = _merge_config_data(current, value, path=item_path)
        elif isinstance(current, list) and isinstance(value, list):
            custom_csv_columns = (
                len(item_path) == 4
                and item_path[0] == "output"
                and item_path[1] == "custom_csv"
                and item_path[3] == "columns"
            )
            if item_path in _REPLACE_LIST_PATHS or custom_csv_columns:
                result[key] = list(value)
            else:
                result[key] = [*current, *value]
        else:
            result[key] = value
    return result


def _include_target(line: str, *, source: Path, line_number: int) -> str | None:
    """Parse one optional LLDP-Runner ``@include`` preprocessor directive.

    Args:
        line: Source line to inspect.
        source: File path used in diagnostics.
        line_number: One-based source line number.

    Returns:
        The include target string, or ``None`` for an ordinary TOML line.

    Raises:
        ConfigError: If an include directive is malformed.
    """

    stripped = line.strip()
    if not stripped.startswith("@include"):
        return None
    try:
        tokens = shlex.split(stripped, comments=True, posix=True)
    except ValueError as exc:
        raise ConfigError(f"{source}:{line_number}: invalid @include directive: {exc}") from exc
    if len(tokens) != 2 or tokens[0] != "@include":
        raise ConfigError(
            f'{source}:{line_number}: expected @include filename or @include "filename"'
        )
    return tokens[1]


def _parse_config_document(path: Path) -> tuple[list[str], dict[str, Any]]:
    """Parse one configuration document while separating ``@include`` directives.

    ``@include`` is an LLDP-Runner preprocessor directive rather than TOML syntax.
    Keeping directive parsing in one helper gives explicit includes and automatic
    ``conf.d`` fragments identical behavior and preserves useful TOML line numbers
    when a configuration error is reported.
    """

    text = path.read_text(encoding="utf-8")
    includes: list[str] = []
    local_lines: list[str] = []
    for line_number, line in enumerate(text.splitlines(keepends=True), start=1):
        target = _include_target(line, source=path, line_number=line_number)
        if target is None:
            local_lines.append(line)
        else:
            includes.append(target)
            # Preserve source line numbers for TOML parser diagnostics.
            local_lines.append("\n" if line.endswith("\n") else "")

    try:
        local = tomllib.loads("".join(local_lines))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"TOML parse error in {path}: {exc}") from exc
    return includes, local


def _resolve_include_path(target: str, *, source: Path) -> Path:
    """Resolve an include relative to its containing file, or preserve an absolute path."""

    include_path = Path(target).expanduser()
    if not include_path.is_absolute():
        include_path = source.parent / include_path
    return include_path


def _load_config_fragment(
    path: Path,
    *,
    loaded: set[Path],
    stack: tuple[Path, ...],
    sources: list[Path],
) -> dict[str, Any]:
    """Load one TOML fragment once, recursively honoring its explicit includes.

    ``loaded`` is shared by the complete top-level load. This is important when a
    file is both named by ``@include`` and present below ``conf.d``: the explicit
    include establishes its position in policy order and the later directory scan
    must not append the same rules a second time. ``stack`` is intentionally
    separate from ``loaded`` so recursive include cycles remain configuration
    errors rather than being mistaken for harmless duplicate references.
    """

    resolved = path.expanduser().resolve()
    if resolved in stack:
        chain = " -> ".join(str(x) for x in (*stack, resolved))
        raise ConfigError(f"configuration include cycle detected: {chain}")
    if resolved in loaded:
        return {}
    if not resolved.is_file():
        raise ConfigError(f"configuration file not found: {resolved}")

    includes, local = _parse_config_document(resolved)
    merged: dict[str, Any] = {}
    next_stack = (*stack, resolved)
    for target in includes:
        included = _load_config_fragment(
            _resolve_include_path(target, source=resolved),
            loaded=loaded,
            stack=next_stack,
            sources=sources,
        )
        merged = _merge_config_data(merged, included)

    # Mark a fragment loaded only after it and its include chain parse
    # successfully. This avoids hiding a malformed file behind the dedupe set.
    loaded.add(resolved)
    sources.append(resolved)
    return _merge_config_data(merged, local)


def _conf_d_files(primary_config: Path) -> list[Path]:
    """Return active ``conf.d`` TOML fragments in deterministic lexical order.

    The automatic directory is always adjacent to the primary configuration
    file. Only names ending exactly in ``.toml`` are active. Sorting by POSIX
    relative path makes directory names participate in ordering, so for example
    ``10-site/a.toml`` is loaded before ``z.toml`` in the top-level directory.
    """

    conf_dir = primary_config.parent / "conf.d"
    if not conf_dir.exists():
        return []
    if not conf_dir.is_dir():
        raise ConfigError(f"configuration fragment path is not a directory: {conf_dir}")

    files = [item for item in conf_dir.rglob("*") if item.is_file() and item.name.endswith(".toml")]
    return sorted(files, key=lambda item: item.relative_to(conf_dir).as_posix())


def _load_toml_with_includes(path: Path) -> tuple[dict[str, Any], tuple[Path, ...]]:
    """Load the primary TOML document, explicit includes, and sibling ``conf.d``.

    Precedence/order is deliberate:

    1. explicit ``@include`` directives in the primary file, in directive order;
    2. remaining ``conf.d/**/*.toml`` files, in lexical relative-path order;
    3. the primary ``config.toml`` document itself.

    Explicit includes inside fragments are evaluated at the point their parent
    fragment is read. A process-wide ``loaded`` set guarantees that the same
    resolved file is merged only once, even when an earlier file includes a
    fragment that the later automatic ``conf.d`` traversal would otherwise find.
    """

    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ConfigError(f"configuration file not found: {resolved}")

    includes, local = _parse_config_document(resolved)
    loaded: set[Path] = set()
    sources: list[Path] = []
    merged: dict[str, Any] = {}
    root_stack = (resolved,)

    # Primary-file includes retain their explicit order and take their position
    # before automatic conf.d fragments. Relative includes use config.toml's
    # directory; absolute includes remain absolute.
    for target in includes:
        included = _load_config_fragment(
            _resolve_include_path(target, source=resolved),
            loaded=loaded,
            stack=root_stack,
            sources=sources,
        )
        merged = _merge_config_data(merged, included)

    for fragment in _conf_d_files(resolved):
        included = _load_config_fragment(fragment, loaded=loaded, stack=root_stack, sources=sources)
        merged = _merge_config_data(merged, included)

    loaded.add(resolved)
    sources.append(resolved)
    return _merge_config_data(merged, local), tuple(sources)


def discover_config_path(
    explicit: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> Path | None:
    """Return the operator-selected or first discovered primary config file.

    An explicit ``--config`` path (or the existing ``LLDP_RUNNER_CONFIG``
    environment variable) is authoritative: a missing file is an error rather
    than a reason to silently search another location. When neither is supplied,
    the ordered paths in :mod:`lldp_runner.defaults` are searched and ``None``
    means LLDP-Runner should operate from built-in defaults.

    The returned path is absolute but keeps symbolic links: the install layout
    follows the path as named, and :func:`load_config` resolves it for reading.
    """

    env = os.environ if env is None else env
    selected = explicit or env.get("LLDP_RUNNER_CONFIG")
    if selected:
        path = Path(selected).expanduser()
        if not path.is_file():
            raise ConfigError(f"configuration file not found: {path}")
        return Path(os.path.abspath(path))

    for candidate in CONFIG_SEARCH_PATHS:
        path = Path(candidate).expanduser()
        if path.is_file():
            return Path(os.path.abspath(path))
    return None


def _merge_default_overlay(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Overlay site/operator data onto defaults without concatenating lists.

    Include/conf.d fragments intentionally concatenate most lists to preserve
    ordered policy composition. Defaults are different: an explicitly supplied
    list replaces the default list. Otherwise a configured boundary list would,
    for example, accidentally retain the default 0.0.0.0/0 and ::/0 scopes.
    """

    result = deepcopy(base)
    for key, value in overlay.items():
        current = result.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            result[key] = _merge_default_overlay(current, value)
        else:
            result[key] = deepcopy(value)
    return result


def _set_dotted_value(data: dict[str, Any], dotted: str, value: Any) -> None:
    """Assign one TOML-style dotted option path into a raw configuration mapping."""

    parts = [part.strip() for part in dotted.split(".")]
    if not parts or any(not part for part in parts):
        raise ConfigError(f"invalid --set option path {dotted!r}")
    cursor = data
    for part in parts[:-1]:
        existing = cursor.get(part)
        if existing is None:
            child: dict[str, Any] = {}
            cursor[part] = child
            cursor = child
        elif isinstance(existing, dict):
            cursor = existing
        else:
            raise ConfigError(f"cannot set {dotted!r}: {part!r} is already a non-table value")
    cursor[parts[-1]] = value


def parse_set_overrides(expressions: list[str] | None) -> dict[str, Any]:
    """Parse repeatable ``--set section.option=value`` expressions as TOML values.

    Requiring TOML syntax prevents ambiguous coercion. Numeric and boolean values
    work naturally; string values should be quoted, for example
    ``--set 'logging.level="DEBUG"'`` or ``--set 'discovery.workers="auto"'``.
    """

    result: dict[str, Any] = {}
    for expression in expressions or []:
        if "=" not in expression:
            raise ConfigError(f"invalid --set {expression!r}; expected section.option = TOML_VALUE")
        dotted, raw_value = expression.split("=", 1)
        dotted = dotted.strip()
        raw_value = raw_value.strip()
        if not dotted or not raw_value:
            raise ConfigError(f"invalid --set {expression!r}; expected section.option = TOML_VALUE")
        try:
            value = tomllib.loads(f"value = {raw_value}\n")["value"]
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(
                f"invalid TOML value in --set {expression!r}: {exc}; "
                'quote string values such as "auto" or "DEBUG"'
            ) from exc
        _set_dotted_value(result, dotted, value)
    return result


def _environment_overlay(env: Mapping[str, str]) -> dict[str, Any]:
    """Translate established LLDP_RUNNER_* environment variables into config data."""

    overlay: dict[str, Any] = {}

    def assign(path: str, value: Any) -> None:
        """Store one environment-derived value at its dotted config path.

        Args:
            path: Destination such as ``snmp.timeout_seconds``.
            value: Parsed value to place in the overlay.

        Returns:
            ``None``. The enclosing ``overlay`` mapping is mutated.
        """

        _set_dotted_value(overlay, path, value)

    if value := env.get("LLDP_RUNNER_ROOT"):
        assign("paths.persistent_root", value)
    if value := env.get("LLDP_RUNNER_SCRATCH_ROOT"):
        assign("paths.scratch_root", value)
    if value := env.get("LLDP_RUNNER_WORKERS"):
        assign("discovery.workers", value if value.lower() == "auto" else int(value))
    if value := env.get("LLDP_RUNNER_BATCH_SIZE"):
        assign("discovery.batch_size", int(value))
    if value := env.get("LLDP_RUNNER_SEED_ORDER"):
        assign("discovery.seed_order", value.lower())
    if value := env.get("LLDP_RUNNER_SEED_DNS_MODE"):
        assign("discovery.seed_dns_mode", value.lower())
    if value := env.get("LLDP_RUNNER_SHUFFLE_KEY"):
        assign("discovery.shuffle_key", value)
    if value := env.get("LLDP_RUNNER_LIMIT_BEHAVIOR"):
        assign("discovery.limit_behavior", value.lower())
    if value := env.get("LLDP_RUNNER_LOG_LEVEL"):
        assign("logging.level", value.upper())
    if value := env.get("LLDP_RUNNER_BOUNDARIES"):
        assign("discovery.boundaries", [x.strip() for x in value.split(",") if x.strip()])
    if value := env.get("LLDP_RUNNER_MAX_DEVICES"):
        # Keep the operator-facing ``auto`` sentinel intact until the coordinator
        # knows the de-duplicated runtime seed count. Numeric zero means unlimited.
        assign("discovery.max_devices", value if value.lower() == "auto" else int(value))
    if value := env.get("LLDP_RUNNER_MAX_HOSTS"):
        assign("discovery.max_hosts", int(value))
    if value := env.get("LLDP_RUNNER_LATE_ADDRESS_RECOVERY_ATTEMPTS"):
        assign("discovery.late_address_recovery_attempts", int(value))
    if value := env.get("LLDP_RUNNER_SNMP_BACKEND"):
        assign("snmp.backend", value)
    if value := env.get("LLDP_RUNNER_SNMP_TIMEOUT"):
        assign("snmp.timeout_seconds", float(value))
    if value := env.get("LLDP_RUNNER_SNMP_RPS"):
        assign("snmp.per_device_rps", float(value))
    if value := env.get("LLDP_RUNNER_SNMP_MAX_OUTSTANDING"):
        assign("snmp.max_outstanding_devices_per_worker", int(value))
    if value := env.get("LLDP_RUNNER_ICMP_TIMEOUT"):
        assign("icmp.timeout_seconds", float(value))
    if value := env.get("LLDP_RUNNER_SNAPSHOT_INTERVAL"):
        assign("output.snapshot_interval_seconds", float(value))
    if value := env.get("LLDP_RUNNER_SCOREBOARD_INTERVAL"):
        assign("output.scoreboard_interval_seconds", float(value))
    return overlay


def _dedicated_overlay(overrides: Mapping[str, Any]) -> dict[str, Any]:
    """Translate dedicated CLI arguments into their configuration paths."""

    overlay: dict[str, Any] = {}
    mapping = {
        "persistent_root": "paths.persistent_root",
        "scratch_root": "paths.scratch_root",
        "workers": "discovery.workers",
        "batch_size": "discovery.batch_size",
        "seed_order": "discovery.seed_order",
        "seed_dns_mode": "discovery.seed_dns_mode",
        "shuffle_key": "discovery.shuffle_key",
        "limit_behavior": "discovery.limit_behavior",
        "boundaries": "discovery.boundaries",
        "max_devices": "discovery.max_devices",
        "max_hosts": "discovery.max_hosts",
        "snmp_backend": "snmp.backend",
        "snmp_timeout": "snmp.timeout_seconds",
        "per_device_rps": "snmp.per_device_rps",
        "max_outstanding": "snmp.max_outstanding_devices_per_worker",
        "log_level": "logging.level",
        "snmp_version": "snmp.version",
    }
    for source, target in mapping.items():
        value = overrides.get(source)
        if value is None or value == []:
            continue
        if source == "log_level":
            value = str(value).upper()
        _set_dotted_value(overlay, target, value)
    return overlay


def _build_app(
    raw: dict[str, Any],
    *,
    config_path: Path | None,
    config_files: tuple[Path, ...] = (),
    credential_mode: CredentialMode = CredentialMode.REQUIRED,
) -> AppConfig:
    """Construct the typed application model from a complete raw configuration.

    Args:
        raw: Fully merged configuration mapping.
        config_path: Selected primary configuration path, if one exists.
        credential_mode: Determines whether credential tables are built at all.
            ``DISABLED`` deliberately ignores credential/profile/rule contents so
            stored-data readers cannot be blocked by unrelated SNMP policy.

    Returns:
        Typed application configuration ready for runtime normalization.

    Raises:
        ConfigError: If an applicable configuration section is malformed.
    """

    known_sections = set(DEFAULTS)
    unknown_sections = set(raw) - known_sections
    if unknown_sections:
        raise ConfigError(
            "Unknown top-level configuration sections: " + ", ".join(sorted(unknown_sections))
        )

    paths = _build_dataclass(PathsConfig, _section(raw, "paths"))
    time_cfg = _build_dataclass(TimeConfig, _section(raw, "time"))
    discovery = _build_dataclass(DiscoveryConfig, _section(raw, "discovery"))
    snmp = _build_dataclass(SnmpConfig, _section(raw, "snmp"))
    icmp = _build_dataclass(IcmpConfig, _section(raw, "icmp"))
    output_raw = dict(_section(raw, "output"))
    custom_csv_raw = output_raw.pop("custom_csv", {})
    if not isinstance(custom_csv_raw, dict):
        raise ConfigError("[output.custom_csv] must be a table")
    custom_csv: dict[str, CustomCsvConfig] = {}
    for name, item in custom_csv_raw.items():
        if not isinstance(item, dict):
            raise ConfigError(f"[output.custom_csv.{name}] must be a table")
        item_data = dict(item)
        columns_raw = item_data.pop("columns", None)
        if not isinstance(columns_raw, list):
            raise ConfigError(f"output.custom_csv.{name}.columns must be an array of inline tables")
        columns: list[CustomCsvColumnConfig] = []
        for index, column in enumerate(columns_raw, start=1):
            if not isinstance(column, dict):
                raise ConfigError(f"output.custom_csv.{name}.columns[{index}] must be a table")
            columns.append(_build_dataclass(CustomCsvColumnConfig, cast(dict[str, Any], column)))
        custom_csv[name] = _build_dataclass(
            CustomCsvConfig,
            {"name": name, "columns": columns, **item_data},
        )
    output = _build_dataclass(OutputConfig, {**output_raw, "custom_csv": custom_csv})
    diff = _build_dataclass(DiffConfig, _section(raw, "diff"))
    terminal = _build_dataclass(TerminalConfig, _section(raw, "terminal"))
    resume = _build_dataclass(ResumeConfig, _section(raw, "resume"))
    neighbors = _build_dataclass(NeighborConfig, _section(raw, "neighbors"))
    logging_cfg = _build_dataclass(LoggingConfig, _section(raw, "logging"))

    credentials: dict[str, CredentialConfig] = {}
    profiles: dict[str, CredentialProfile] = {}
    cred_rules = CredentialRules()
    if credential_mode is not CredentialMode.DISABLED:
        credential_data = _section(raw, "credentials")
        for name, item in credential_data.items():
            if not isinstance(item, dict):
                raise ConfigError(f"[credentials.{name}] must be a table")
            credentials[name] = _build_dataclass(CredentialConfig, {"name": name, **item})

        profile_data = _section(raw, "credential_profiles")
        for name, item in profile_data.items():
            if not isinstance(item, dict):
                raise ConfigError(f"[credential_profiles.{name}] must be a table")
            profiles[name] = _build_dataclass(CredentialProfile, {"name": name, **item})

        cr = _section(raw, "credential_rules")
        _reject_unknown_keys(cr, {"default_profile", "address", "name"}, "CredentialRules")
        cred_rules = CredentialRules(
            default_profile=str(
                cr.get(
                    "default_profile",
                    DEFAULTS["credential_rules"]["default_profile"],
                )
            ),
            address=[_build_dataclass(AddressCredentialRule, x) for x in cr.get("address", [])],
            name=[_build_dataclass(NameCredentialRule, x) for x in cr.get("name", [])],
        )

    qp = _section(raw, "query_policy")
    _reject_unknown_keys(qp, {"default_action", "address_rules", "name_rules"}, "QueryPolicyConfig")
    query_policy = QueryPolicyConfig(
        default_action=str(qp.get("default_action", "allow")),
        address_rules=[_build_dataclass(QueryAddressRule, x) for x in qp.get("address_rules", [])],
        name_rules=[_build_dataclass(QueryNameRule, x) for x in qp.get("name_rules", [])],
    )

    cc = _section(raw, "classification")
    _reject_unknown_keys(
        cc,
        {
            "address_rules",
            "name_rules",
            "evidence_rules",
            "managed_manufacturers",
            "managed_endpoint_patterns",
            "unmanaged_patterns",
        },
        "ClassificationConfig",
    )
    evidence_rules: list[ClassificationEvidenceRule] = []
    for item in cc.get("evidence_rules", []):
        if not isinstance(item, dict):
            raise ConfigError("classification.evidence_rules entries must be tables")
        evidence_rules.append(_build_dataclass(ClassificationEvidenceRule, item))

    classification = ClassificationConfig(
        address_rules=[
            _build_dataclass(ClassificationAddressRule, x) for x in cc.get("address_rules", [])
        ],
        name_rules=[_build_dataclass(ClassificationNameRule, x) for x in cc.get("name_rules", [])],
        evidence_rules=evidence_rules,
        managed_manufacturers=list(
            cc.get("managed_manufacturers", DEFAULTS["classification"]["managed_manufacturers"])
        ),
        managed_endpoint_patterns=list(
            cc.get(
                "managed_endpoint_patterns", DEFAULTS["classification"]["managed_endpoint_patterns"]
            )
        ),
        unmanaged_patterns=list(
            cc.get("unmanaged_patterns", DEFAULTS["classification"]["unmanaged_patterns"])
        ),
    )

    tc = _section(raw, "tagging")
    _reject_unknown_keys(tc, {"rules"}, "TaggingConfig")
    tag_rules: list[TagRule] = []
    for item in tc.get("rules", []):
        if not isinstance(item, dict):
            raise ConfigError("tagging.rules entries must be tables")
        tag_rules.append(_build_dataclass(TagRule, item))
    tagging = TaggingConfig(rules=tag_rules)

    return AppConfig(
        paths=paths,
        time=time_cfg,
        discovery=discovery,
        snmp=snmp,
        icmp=icmp,
        output=output,
        diff=diff,
        resume=resume,
        credentials=credentials,
        credential_profiles=profiles,
        credential_rules=cred_rules,
        query_policy=query_policy,
        classification=classification,
        tagging=tagging,
        neighbors=neighbors,
        logging=logging_cfg,
        terminal=terminal,
        config_path=config_path,
        config_files=config_files,
    )


def _probe_writable_directory(path: Path, *, create: bool, label: str) -> Path:
    """Ensure a runtime directory exists and can create child entries.

    A real create/remove probe is stronger than ``os.access`` and closely matches
    what LLDP-Runner will need to do for run/output/scratch directories.
    """

    try:
        if create:
            path.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            raise ConfigError(f"{label} directory does not exist: {path}")
        if not path.is_dir():
            raise ConfigError(f"{label} is not a directory: {path}")
        probe = Path(tempfile.mkdtemp(prefix=".lldp-runner-write-test-", dir=path))
        probe.rmdir()
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError(f"{label} directory is not writable: {path}: {exc}") from exc
    return path.resolve()


def install_layout(config: AppConfig) -> InstallLayout:
    """Return the automatic install layout implied by ``config``'s primary file."""

    return select_layout(
        config.config_location or config.config_path,
        runs_dirname=config.paths.runs_dirname,
        output_dirname=config.paths.output_dirname,
    )


def _resolve_persistent_root(value: Path | str, *, layout: InstallLayout) -> Path:
    """Resolve explicit/automatic persistent storage according to site-safe rules.

    An automatic shared or system root is never created here: its group ownership
    and permissions belong to the administrator's setup step, and a root created
    by whichever operator ran first would lock the others out.
    """

    if str(value).lower() != "auto":
        return _probe_writable_directory(
            Path(value).expanduser(), create=True, label="persistent_root"
        )

    if layout.persistent_root is None:
        raise ConfigError(f"persistent_root cannot be chosen automatically: {layout.unavailable}")
    try:
        return _probe_writable_directory(
            layout.persistent_root,
            create=layout.create_persistent,
            label="persistent_root",
        )
    except ConfigError as exc:
        if layout.create_persistent:
            raise
        hint = (
            "run scripts/shared-setup.sh to create it"
            if layout.name == "shared"
            else "create it with the package's setup"
        )
        raise ConfigError(
            f"{exc}\nThe {layout.name} install layout keeps runtime data in "
            f"{layout.persistent_root}; {hint}, or set paths.persistent_root."
        ) from exc


def _resolve_scratch_root(
    value: Path | str,
    *,
    persistent_root: Path,
    layout: InstallLayout,
) -> Path:
    """Resolve scratch storage, falling through temporary candidates when needed."""

    if str(value).lower() != "auto":
        return _probe_writable_directory(
            Path(value).expanduser(), create=True, label="scratch_root"
        )

    for candidate in layout.scratch_candidates:
        if not candidate.parent.is_dir():
            continue
        try:
            return _probe_writable_directory(candidate, create=True, label="scratch_root")
        except ConfigError:
            # Scratch is relocatable by design, so unlike persistent state it is
            # safe to try the next temporary filesystem candidate.
            continue

    return _probe_writable_directory(
        layout.scratch_fallback(persistent_root), create=True, label="scratch_root"
    )


def resolve_existing_persistent_root(value: Path | str, *, layout: InstallLayout) -> Path:
    """Resolve persistent storage without creating or write-probing it.

    Read-only and cleanup commands need the same authoritative persistent-root
    selection as discovery while avoiding side effects before their own operation
    begins. Explicit paths are normalized directly; ``auto`` uses the install
    layout's root whether or not it exists yet.
    """

    if str(value).lower() != "auto":
        return Path(value).expanduser().resolve()

    if layout.persistent_root is None:
        raise ConfigError(f"persistent_root cannot be chosen automatically: {layout.unavailable}")
    root = layout.persistent_root.resolve()
    if root.exists() and not root.is_dir():
        raise ConfigError(f"persistent_root is not a directory: {root}")
    return root


def resolve_readonly_scratch_root(
    value: Path | str,
    *,
    persistent_root: Path | str,
    layout: InstallLayout,
) -> Path:
    """Resolve the scratch scoreboard location without creating or write-probing it.

    Read-only operator commands must follow the same configured/automatic namespace
    as discovery while remaining usable by an account that has read access but no
    permission to create files. For ``auto``, an existing candidate carrying a
    ``current`` run wins; otherwise normal temporary-root ordering is preserved.
    """

    if str(value).lower() != "auto":
        return Path(value).expanduser().resolve()

    candidates = [item for item in layout.scratch_candidates if item.parent.is_dir()]
    if str(persistent_root).lower() == "auto":
        if layout.persistent_root is None:
            raise ConfigError(
                f"persistent_root cannot be chosen automatically: {layout.unavailable}"
            )
        persistent = layout.persistent_root
    else:
        persistent = Path(persistent_root).expanduser()
    candidates.append(layout.scratch_fallback(persistent))

    for candidate in candidates:
        if (candidate / "current").exists():
            return candidate.resolve()
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    # Preserve deterministic auto selection for the eventual operator error even
    # when no scoreboard directory exists yet; do not create the candidate.
    return candidates[0].resolve()


def _resolve_runtime_values(config: AppConfig, *, resolve_paths: bool = True) -> None:
    """Resolve dynamic defaults and normalize runtime-only operator values.

    Seed ordering and limit behavior are normalized here so scheduler code sees
    canonical lowercase values regardless of whether they came from TOML, the
    environment, ``--set``, or dedicated command-line options. ``resolve_paths``
    is false for commands that must not create or write-probe discovery storage,
    including stdout-only inspection and the finalized-discovery viewer.
    """

    try:
        configure_timezone(config.time.timezone)
    except ValueError as exc:
        raise ConfigError(f"time.timezone: {exc}") from exc

    config.discovery.seed_order = str(config.discovery.seed_order).lower()
    config.discovery.seed_dns_mode = str(config.discovery.seed_dns_mode).lower()
    config.discovery.limit_behavior = str(config.discovery.limit_behavior).lower()

    workers = config.discovery.workers
    if isinstance(workers, str) and workers.lower() == "auto":
        config.discovery.workers = (os.cpu_count() or 1) * 4
    else:
        try:
            config.discovery.workers = int(workers)
        except (TypeError, ValueError) as exc:
            raise ConfigError("discovery.workers must be an integer or 'auto'") from exc

    if not resolve_paths:
        # Inspection is stdout-only and the discovery viewer is read-only. Neither
        # should fail because an unrelated discovery output directory is unwritable.
        # Full run/status/pause paths keep normal writable path resolution.
        return

    layout = install_layout(config)
    try:
        persistent = _resolve_persistent_root(config.paths.persistent_root, layout=layout)
    except ConfigError as exc:
        if config.config_path is None:
            raise ConfigError(
                f"{exc}\nNo configuration file was specified or found. "
                "Run 'lldp-runner generate-config' to create a starter configuration in the current directory, "
                "edit paths.persistent_root as needed, and run again."
            ) from exc
        raise
    config.paths.persistent_root = persistent
    config.paths.scratch_root = _resolve_scratch_root(
        config.paths.scratch_root, persistent_root=persistent, layout=layout
    )


def _resolve_secret_argument(value: str | None, env: Mapping[str, str]) -> str | None:
    """Resolve a CLI credential token as ENV-VAR-NAME first, literal second."""

    if value is None:
        return None
    return env[value] if value in env else value


def _synthesize_runtime_credentials(
    config: AppConfig,
    *,
    env: Mapping[str, str],
    credential_overrides: Mapping[str, str | None],
) -> None:
    """Create the lowest-priority default credential profile when needed.

    Any explicitly configured credential or profile suppresses this mechanism.
    When only one SNMP credential version is available, two attempts are assigned
    to that single credential instead of pretending the fallback is a different
    credential. When both are available, ``snmp.version`` selects primary/fallback.
    """

    if config.credentials or config.credential_profiles:
        return

    community_token = credential_overrides.get("community")
    user_token = credential_overrides.get("username")
    auth_token = credential_overrides.get("auth_password")
    priv_token = credential_overrides.get("priv_password")

    community = (
        _resolve_secret_argument(community_token, env)
        if community_token is not None
        else env.get(DEFAULT_SNMP_ENV["community"])
    )
    username = (
        _resolve_secret_argument(user_token, env)
        if user_token is not None
        else env.get(DEFAULT_SNMP_ENV["username"])
    )
    auth_password = (
        _resolve_secret_argument(auth_token, env)
        if auth_token is not None
        else env.get(DEFAULT_SNMP_ENV["auth_password"])
    )
    priv_password = (
        _resolve_secret_argument(priv_token, env)
        if priv_token is not None
        else env.get(DEFAULT_SNMP_ENV["priv_password"])
    )

    v3_values = (username, auth_password, priv_password)
    if any(v3_values) and not all(v3_values):
        missing = [
            name
            for name, value in zip(("SNMPUSER", "SNMPAUTH", "SNMPPRIV"), v3_values, strict=True)
            if not value
        ]
        raise ConfigError(
            "default SNMPv3 authPriv credentials are incomplete; missing " + ", ".join(missing)
        )

    available: dict[str, str] = {}
    if community:
        name = "runtime-v2c"
        config.credentials[name] = CredentialConfig(name=name, version="v2c", community=community)
        available["2c"] = name
    if all(v3_values):
        name = "runtime-v3"
        config.credentials[name] = CredentialConfig(
            name=name,
            version="v3",
            username=username,
            auth_password=auth_password,
            priv_password=priv_password,
        )
        available["3"] = name

    if not available:
        return

    preferred = str(config.snmp.version).lower()
    if preferred not in {"2c", "3"}:
        raise ConfigError("snmp.version must be '2c' or '3'")

    if len(available) == 1:
        primary = next(iter(available.values()))
        profile = CredentialProfile(
            name="runtime-default",
            primary=primary,
            fallback=None,
            primary_attempts=2,
            fallback_attempts=1,
        )
    else:
        fallback_version = "3" if preferred == "2c" else "2c"
        profile = CredentialProfile(
            name="runtime-default",
            primary=available[preferred],
            fallback=available[fallback_version],
            primary_attempts=1,
            fallback_attempts=1,
        )
    config.credential_profiles[profile.name] = profile


def load_config(
    path: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
    set_expressions: list[str] | None = None,
    credential_overrides: Mapping[str, str | None] | None = None,
    credential_mode: CredentialMode = CredentialMode.REQUIRED,
    resolve_paths: bool = True,
) -> AppConfig:
    """Load defaults, site files, environment, and command-line overrides.

    Args:
        path: Selected primary configuration file, or ``None`` for defaults only.
        env: Environment mapping used for ordinary overrides and, unless disabled,
            credential synthesis/secret resolution.
        overrides: Dedicated command-line configuration values.
        set_expressions: Repeatable dotted ``--set`` assignments.
        credential_overrides: Runtime SNMP credential CLI values. These are ignored
            completely when ``credential_mode`` is ``DISABLED``.
        credential_mode: ``REQUIRED`` for network commands, ``OPTIONAL`` for
            credential-aware dry runs, or ``DISABLED`` for stored-data readers.
        resolve_paths: Resolve/probe writable discovery paths when ``True``.

    Returns:
        Validated effective application configuration.

    Raises:
        ConfigError: If applicable configuration is invalid or required runtime
            values cannot be resolved.

    ``path=None`` means no primary configuration file was found and built-in
    defaults should be used. A non-None path must exist; discovery of a path is
    handled by :func:`discover_config_path` so callers can distinguish an absent
    config from an explicitly missing one. ``resolve_paths=False`` preserves path
    values without testing or creating discovery storage.
    """

    env = os.environ if env is None else env
    config_path = Path(path).expanduser().resolve() if path is not None else None
    if config_path is not None:
        site_raw, config_files = _load_toml_with_includes(config_path)
    else:
        site_raw, config_files = {}, ()

    raw = _merge_default_overlay(DEFAULTS, site_raw)
    raw = _merge_default_overlay(raw, _environment_overlay(env))
    raw = _merge_default_overlay(raw, parse_set_overrides(set_expressions))
    raw = _merge_default_overlay(raw, _dedicated_overlay(overrides or {}))

    try:
        app = _build_app(
            raw,
            config_path=config_path,
            config_files=config_files,
            credential_mode=credential_mode,
        )
    except TypeError as exc:
        raise ConfigError(
            f"configuration contains an invalid setting or value type: {exc}"
        ) from exc
    if path is not None:
        app.config_location = Path(os.path.abspath(Path(path).expanduser()))
    _resolve_runtime_values(app, resolve_paths=resolve_paths)
    if credential_mode is not CredentialMode.DISABLED:
        _synthesize_runtime_credentials(
            app,
            env=env,
            credential_overrides=credential_overrides or {},
        )
    try:
        validate_config(app, env=env, credential_mode=credential_mode)
    except TypeError as exc:
        raise ConfigError(f"configuration contains a value with an invalid type: {exc}") from exc
    if credential_mode is not CredentialMode.DISABLED:
        # Resolve once after all precedence layers and validation. The
        # runtime-only binding is inherited by spawned workers and rejects any
        # later mutation. Stored-data readers intentionally skip even this
        # transport-selection boundary; they neither need nor initialize an
        # SNMP backend.
        from lldp_runner.snmp.selection import select_snmp_backend

        select_snmp_backend(app.snmp)
    return app


def validate_config(
    config: AppConfig,
    *,
    env: Mapping[str, str] | None = None,
    credential_mode: CredentialMode = CredentialMode.REQUIRED,
) -> None:
    """Validate a fully assembled runtime configuration before command execution.

    Args:
        config: Typed application configuration after defaults/overrides merge.
        env: Environment used to resolve secret-backed credentials when credentials
            are enabled.
        credential_mode: Credential validation policy. ``DISABLED`` skips every
            credential/profile/rule check for commands that cannot use SNMP.

    Returns:
        ``None`` when all settings and policy rules are valid.

    Raises:
        ConfigError: If one or more configuration errors are detected.
    """

    env = os.environ if env is None else env
    errors: list[str] = []

    try:
        validate_run_id_format(config.paths.run_id_format)
    except (TypeError, ValueError) as exc:
        errors.append(str(exc))
    if not isinstance(config.paths.clean_scratch_when_completed, bool):
        errors.append("paths.clean_scratch_when_completed must be true or false")
    try:
        normalize_timezone_name(config.time.timezone)
    except (TypeError, ValueError) as exc:
        errors.append(f"time.timezone: {exc}")

    if not config.discovery.boundaries:
        errors.append("discovery.boundaries must contain at least one CIDR")
    for cidr in config.discovery.boundaries:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            errors.append(f"invalid discovery boundary {cidr!r}: {exc}")

    if cast(int, config.discovery.workers) < 1:
        errors.append("discovery.workers must be >= 1")
    if config.discovery.batch_size < 1:
        errors.append("discovery.batch_size must be >= 1")
    if config.discovery.seed_order not in {"input", "sorted", "random"}:
        errors.append("discovery.seed_order must be input, sorted, or random")
    if config.discovery.seed_dns_mode not in {"resolve", "skip-addressed"}:
        errors.append("discovery.seed_dns_mode must be resolve or skip-addressed")
    if isinstance(config.discovery.shuffle_key, bool) or not isinstance(
        config.discovery.shuffle_key, (str, int)
    ):
        errors.append("discovery.shuffle_key must be a string or integer")
    if config.discovery.limit_behavior not in {"pause", "complete"}:
        errors.append("discovery.limit_behavior must be pause or complete")
    max_devices = config.discovery.max_devices
    if isinstance(max_devices, str):
        if max_devices.lower() != "auto":
            errors.append("discovery.max_devices must be a non-negative integer or 'auto'")
    elif isinstance(max_devices, bool) or not isinstance(max_devices, int):
        errors.append("discovery.max_devices must be a non-negative integer or 'auto'")
    elif max_devices < 0:
        errors.append("discovery.max_devices must be >= 0 or 'auto'")
    if isinstance(config.discovery.max_hosts, bool) or not isinstance(
        config.discovery.max_hosts, int
    ):
        errors.append("discovery.max_hosts must be a non-negative integer")
    elif config.discovery.max_hosts < 0:
        errors.append("discovery.max_hosts must be >= 0")
    recovery_attempts = config.discovery.late_address_recovery_attempts
    if isinstance(recovery_attempts, bool) or not isinstance(recovery_attempts, int):
        errors.append("discovery.late_address_recovery_attempts must be an integer from 0 to 3")
    elif not 0 <= recovery_attempts <= 3:
        errors.append("discovery.late_address_recovery_attempts must be from 0 to 3")
    for field_name in (
        "include_collection_timing",
        "summary_only",
        "expand_collection_incidents",
    ):
        if not isinstance(getattr(config.diff, field_name), bool):
            errors.append(f"diff.{field_name} must be a boolean")
    if config.snmp.backend not in {"gufo", "pysnmp"}:
        errors.append("snmp.backend must be gufo or pysnmp")
    if str(config.snmp.version).lower() not in {"2c", "3"}:
        errors.append("snmp.version must be 2c or 3")
    if not 1 <= config.snmp.port <= 65535:
        errors.append("snmp.port must be between 1 and 65535")
    if config.snmp.timeout_seconds <= 0:
        errors.append("snmp.timeout_seconds must be > 0")
    if config.snmp.max_repetitions < 1:
        errors.append("snmp.max_repetitions must be >= 1")
    for field_name in (
        "retry_per_operation",
        "retry_per_collector",
        "retry_total_cap",
        "retry_neighbor_reserve",
        "structural_table_retry",
    ):
        value = getattr(config.snmp, field_name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"snmp.{field_name} must be a non-negative integer")
    if (
        isinstance(config.snmp.retry_per_operation, int)
        and isinstance(config.snmp.retry_total_cap, int)
        and not isinstance(config.snmp.retry_per_operation, bool)
        and not isinstance(config.snmp.retry_total_cap, bool)
        and config.snmp.retry_per_operation > config.snmp.retry_total_cap
    ):
        errors.append("snmp.retry_per_operation must be <= snmp.retry_total_cap")
    if (
        isinstance(config.snmp.structural_table_retry, int)
        and isinstance(config.snmp.retry_total_cap, int)
        and not isinstance(config.snmp.structural_table_retry, bool)
        and not isinstance(config.snmp.retry_total_cap, bool)
        and config.snmp.structural_table_retry > config.snmp.retry_total_cap
    ):
        errors.append("snmp.structural_table_retry must be <= snmp.retry_total_cap")
    if (
        isinstance(config.snmp.retry_per_collector, int)
        and isinstance(config.snmp.retry_total_cap, int)
        and isinstance(config.snmp.retry_neighbor_reserve, int)
        and not isinstance(config.snmp.retry_per_collector, bool)
        and not isinstance(config.snmp.retry_total_cap, bool)
        and not isinstance(config.snmp.retry_neighbor_reserve, bool)
        and config.snmp.retry_per_collector
        > config.snmp.retry_total_cap + config.snmp.retry_neighbor_reserve
    ):
        errors.append(
            "snmp.retry_per_collector must be <= snmp.retry_total_cap + snmp.retry_neighbor_reserve"
        )
    if (
        isinstance(config.snmp.retry_timeout_multiplier, bool)
        or not isinstance(config.snmp.retry_timeout_multiplier, (int, float))
        or config.snmp.retry_timeout_multiplier <= 1
    ):
        errors.append("snmp.retry_timeout_multiplier must be a number > 1")
    if (
        isinstance(config.snmp.retry_max_repetitions_multiplier, bool)
        or not isinstance(config.snmp.retry_max_repetitions_multiplier, (int, float))
        or not 0 < config.snmp.retry_max_repetitions_multiplier < 1
    ):
        errors.append("snmp.retry_max_repetitions_multiplier must be a number > 0 and < 1")
    retry_floor_valid = (
        not isinstance(config.snmp.retry_min_max_repetitions, bool)
        and isinstance(config.snmp.retry_min_max_repetitions, int)
        and config.snmp.retry_min_max_repetitions >= 1
    )
    if not retry_floor_valid:
        errors.append("snmp.retry_min_max_repetitions must be an integer >= 1")
    elif config.snmp.retry_min_max_repetitions > config.snmp.max_repetitions:
        errors.append("snmp.retry_min_max_repetitions must be <= snmp.max_repetitions")
    if (
        isinstance(config.snmp.retry_inter_pdu_delay_ms, bool)
        or not isinstance(config.snmp.retry_inter_pdu_delay_ms, (int, float))
        or config.snmp.retry_inter_pdu_delay_ms < 0
    ):
        errors.append("snmp.retry_inter_pdu_delay_ms must be a number >= 0")
    if not isinstance(config.snmp.neighbor_stability_retry, bool):
        errors.append("snmp.neighbor_stability_retry must be true or false")
    if (
        isinstance(config.snmp.neighbor_stability_retry_delay_seconds, bool)
        or not isinstance(config.snmp.neighbor_stability_retry_delay_seconds, (int, float))
        or config.snmp.neighbor_stability_retry_delay_seconds < 0
    ):
        errors.append("snmp.neighbor_stability_retry_delay_seconds must be a number >= 0")
    if config.snmp.per_device_rps <= 0:
        errors.append("snmp.per_device_rps must be > 0")
    if config.snmp.max_outstanding_devices_per_worker < 1:
        errors.append("snmp.max_outstanding_devices_per_worker must be >= 1")
    if config.snmp.inter_wave_delay_seconds < 0:
        errors.append("snmp.inter_wave_delay_seconds must be >= 0")
    if not isinstance(config.snmp.collect_entity_mib, bool):
        errors.append("snmp.collect_entity_mib must be true or false")
    if config.snmp.entity_mib_mode not in {"full", "auto", "brief"}:
        errors.append("snmp.entity_mib_mode must be full, auto, or brief")
    if not isinstance(config.snmp.report_metrics, bool):
        errors.append("snmp.report_metrics must be true or false")
    if config.icmp.probes != 2:
        errors.append("icmp.probes must be 2 for the current discovery policy")
    if config.icmp.timeout_seconds <= 0:
        errors.append("icmp.timeout_seconds must be > 0")
    if config.icmp.inter_probe_delay_seconds < 0:
        errors.append("icmp.inter_probe_delay_seconds must be >= 0")
    if config.output.snapshot_interval_seconds <= 0:
        errors.append("output.snapshot_interval_seconds must be > 0")
    if config.output.scoreboard_interval_seconds <= 0:
        errors.append("output.scoreboard_interval_seconds must be > 0")
    for name in (
        "write_hosts_csv",
        "write_stack_members_csv",
        "write_seeds_csv",
        "write_unknown_devices_csv",
        "write_errors_csv",
        "write_empty_csv",
        "log_alert_on_empty_csv",
        "run_json_config_log",
    ):
        if not isinstance(getattr(config.output, name), bool):
            errors.append(f"output.{name} must be true or false")
    if (
        isinstance(config.output.purge_keep, bool)
        or not isinstance(config.output.purge_keep, int)
        or config.output.purge_keep < 0
    ):
        errors.append("output.purge_keep must be a non-negative integer")
    if (
        not isinstance(config.output.neighbor_local_width, int)
        or isinstance(config.output.neighbor_local_width, bool)
        or not 5 <= config.output.neighbor_local_width <= 40
    ):
        errors.append("output.neighbor_local_width must be an integer from 5 through 40")
    if (
        not isinstance(config.output.neighbor_remote_port_width, int)
        or isinstance(config.output.neighbor_remote_port_width, bool)
        or not 11 <= config.output.neighbor_remote_port_width <= 40
    ):
        errors.append("output.neighbor_remote_port_width must be an integer from 11 through 40")
    if config.output.relationship_view not in {"sectioned", "combined"}:
        errors.append("output.relationship_view must be sectioned or combined")
    if config.output.chassis_id_name_fallback not in {"disabled", "name_like", "any"}:
        errors.append("output.chassis_id_name_fallback must be disabled, name_like, or any")
    if config.terminal.color not in {"auto", "never"}:
        errors.append("terminal.color must be auto or never")
    if config.terminal.palette not in {"dark", "light"}:
        errors.append("terminal.palette must be dark or light")
    for name in (
        "heading_color",
        "success_color",
        "warning_color",
        "error_color",
        "learned_color",
        "observed_by_color",
        "inspection_neighbor_color",
        "metric_color",
    ):
        value = getattr(config.terminal, name)
        if value not in TERMINAL_COLOR_NAMES:
            choices = ", ".join(sorted(TERMINAL_COLOR_NAMES))
            errors.append(f"terminal.{name} must be one of: {choices}")

    fixed_names = {
        "discovery.json",
        "hosts.csv",
        "stack-members.csv",
        "seeds.csv",
        "unknown-devices.csv",
        "errors.csv",
    }
    custom_filenames: set[str] = set()
    for name, custom in config.output.custom_csv.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name):
            errors.append(
                f"output.custom_csv.{name}: name must contain only letters, "
                "numbers, underscore, or hyphen and start with a letter/number"
            )
        if not isinstance(custom.enabled, bool):
            errors.append(f"output.custom_csv.{name}.enabled must be true or false")
        filename = str(custom.filename).strip()
        filename_path = Path(filename)
        if (
            not isinstance(custom.filename, str)
            or not filename
            or filename_path.is_absolute()
            or filename_path.name != filename
            or filename in {".", ".."}
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.csv", filename) is None
        ):
            errors.append(
                f"output.custom_csv.{name}.filename must be one portable relative .csv filename"
            )
        filename_key = filename.casefold()
        if filename_key in {value.casefold() for value in fixed_names}:
            errors.append(
                f"output.custom_csv.{name}.filename collides with standard output {filename!r}"
            )
        if filename_key in custom_filenames:
            errors.append(
                f"output.custom_csv.{name}.filename duplicates another custom output: {filename!r}"
            )
        custom_filenames.add(filename_key)
        source = str(custom.source).strip()
        if not isinstance(custom.source, str) or source not in FIXED_FIELDS_BY_SOURCE:
            errors.append(
                f"output.custom_csv.{name}.source must be one of: "
                + ", ".join(FIXED_FIELDS_BY_SOURCE)
            )
        if not custom.columns:
            errors.append(f"output.custom_csv.{name}.columns must not be empty")
        headers: set[str] = set()
        for index, column in enumerate(custom.columns, start=1):
            field_name = str(column.field).strip()
            header = column.header if column.header is not None else field_name.rsplit(".", 1)[-1]
            if not field_name:
                errors.append(f"output.custom_csv.{name}.columns[{index}].field must not be empty")
                continue
            if (
                not isinstance(header, str)
                or not header.strip()
                or re.search(r"[\x00-\x1f\x7f]", header) is not None
            ):
                errors.append(
                    f"output.custom_csv.{name}.columns[{index}].header must be "
                    "non-empty printable text"
                )
            else:
                header_key = header.casefold()
                if header_key in headers:
                    errors.append(f"output.custom_csv.{name}: duplicate output header {header!r}")
                headers.add(header_key)
            if column.transform is not None and not isinstance(column.transform, str):
                errors.append(
                    f"output.custom_csv.{name}.columns[{index}].transform must be a string"
                )
                continue
            try:
                validate_field_reference(source, field_name, column.transform)
            except ValueError as exc:
                errors.append(f"output.custom_csv.{name}.columns[{index}]: {exc}")

    if config.resume.lease_seconds < 1:
        errors.append("resume.lease_seconds must be >= 1")
    if config.icmp.backend not in {"auto", "raw", "system", "disabled"}:
        errors.append("icmp.backend must be auto, raw, system, or disabled")
    for name in ("console", "file"):
        if not isinstance(getattr(config.logging, name), bool):
            errors.append(f"logging.{name} must be true or false")
    if not isinstance(config.logging.filename, str) or not config.logging.filename.strip():
        errors.append("logging.filename must be a non-empty path string")
    else:
        configured_log_path = Path(config.logging.filename)
        try:
            expanded_log_path = configured_log_path.expanduser()
        except RuntimeError as exc:
            errors.append(f"logging.filename cannot expand user home: {exc}")
        else:
            if not expanded_log_path.is_absolute() and ".." in configured_log_path.parts:
                errors.append(
                    "logging.filename relative paths must remain inside the current run directory"
                )

    if credential_mode is not CredentialMode.DISABLED:
        for name, cred in config.credentials.items():
            if cred.version not in {"v2c", "v3"}:
                errors.append(f"credential {name}: version must be v2c or v3")
                continue
            if cred.version == "v2c":
                if credential_mode is CredentialMode.REQUIRED and not cred.secret("community", env):
                    errors.append(f"credential {name}: v2c community is not available")
            else:
                # Credential names are shared across the application, but each
                # transport adapter owns its concrete algorithm mapping. Validate
                # against the selected implementation rather than a generic set
                # that could silently drift away from one backend.
                from lldp_runner.snmp.selection import validate_snmp_v3_protocols

                try:
                    validate_snmp_v3_protocols(
                        config.snmp.backend,
                        auth_protocol=cred.auth_protocol,
                        priv_protocol=cred.priv_protocol,
                    )
                except ValueError as exc:
                    errors.append(f"credential {name}: {exc}")
                if credential_mode is CredentialMode.REQUIRED:
                    for field_name in ("username", "auth_password", "priv_password"):
                        if not cred.secret(field_name, env):
                            errors.append(f"credential {name}: v3 {field_name} is not available")

        for name, profile in config.credential_profiles.items():
            if profile.primary not in config.credentials:
                errors.append(f"profile {name}: unknown primary credential {profile.primary!r}")
            if profile.fallback and profile.fallback not in config.credentials:
                errors.append(f"profile {name}: unknown fallback credential {profile.fallback!r}")
            if profile.primary_attempts < 1:
                errors.append(f"profile {name}: primary_attempts must be >= 1")
            if profile.fallback:
                if profile.fallback_attempts < 1:
                    errors.append(f"profile {name}: fallback_attempts must be >= 1")
                if profile.fallback_attempts > profile.primary_attempts:
                    errors.append(
                        f"profile {name}: fallback_attempts may not exceed primary_attempts"
                    )

        if config.credentials and not config.credential_profiles:
            errors.append("credentials are configured but no credential_profiles are defined")
        if config.credential_profiles:
            if config.credential_rules.default_profile not in config.credential_profiles:
                errors.append(
                    "credential_rules.default_profile references unknown profile "
                    f"{config.credential_rules.default_profile!r}"
                )
        elif credential_mode is CredentialMode.REQUIRED and not config.credentials:
            errors.append(
                "no SNMP credentials are available; define credential profiles in TOML, "
                "set SNMPCOMM, or set the SNMPUSER/SNMPAUTH/SNMPPRIV environment variables "
                "(the equivalent command-line credential options are also supported)"
            )

    def validate_networks(values: list[str], context: str) -> None:
        """Append validation errors for an empty or malformed CIDR rule list.

        Args:
            values: CIDR strings supplied by one rule.
            context: Human-readable rule label for error messages.

        Returns:
            ``None``. Problems are appended to the enclosing ``errors`` list.
        """

        if not values:
            errors.append(f"{context} must define network or networks")
            return
        for network in values:
            try:
                ipaddress.ip_network(network, strict=False)
            except (ValueError, TypeError) as exc:
                errors.append(f"{context} network {network!r}: {exc}")

    def validate_regexes(values: list[str], context: str) -> None:
        """Append validation errors for an empty or invalid regex rule list.

        Args:
            values: Regular-expression strings supplied by one rule.
            context: Human-readable rule label for error messages.

        Returns:
            ``None``. Problems are appended to the enclosing ``errors`` list.
        """

        if not values:
            errors.append(f"{context} must define pattern or patterns")
            return
        for pattern in values:
            try:
                re.compile(pattern)
            except (re.error, TypeError) as exc:
                errors.append(f"{context} regex {pattern!r}: {exc}")

    if credential_mode is not CredentialMode.DISABLED:
        for rule in config.credential_rules.address:
            validate_networks(rule.network_values(), "credential address rule")
            if rule.profile not in config.credential_profiles:
                errors.append(
                    f"credential address rule references unknown profile {rule.profile!r}"
                )
        for rule in config.credential_rules.name:
            validate_regexes(rule.pattern_values(), "credential name rule")
            if rule.profile not in config.credential_profiles:
                errors.append(f"credential name rule references unknown profile {rule.profile!r}")

    valid_actions = {"allow", "deny"}
    if config.query_policy.default_action not in valid_actions:
        errors.append("query_policy.default_action must be allow or deny")
    for rule in config.query_policy.address_rules:
        validate_networks(rule.network_values(), "query address rule")
        if rule.action not in valid_actions:
            errors.append("query address rule action must be allow or deny")
    for rule in config.query_policy.name_rules:
        validate_regexes(rule.pattern_values(), "query name rule")
        if rule.action not in valid_actions:
            errors.append("query name rule action must be allow or deny")

    categories = {"managed_device", "managed_endpoint", "unmanaged_device", "unknown_device"}
    for rule in config.classification.address_rules:
        validate_networks(rule.network_values(), "classification address rule")
        if rule.category not in categories:
            errors.append(f"classification address rule has invalid category {rule.category!r}")
    for rule in config.classification.name_rules:
        validate_regexes(rule.pattern_values(), "classification name rule")
        if rule.category not in categories:
            errors.append(f"classification name rule has invalid category {rule.category!r}")

    evidence_fields = {
        "remote_description",
        "remote_platform",
        "chassis_id",
        "chassis_id_subtype",
        "chassis_id_subtype_id",
        "local_interface",
        "local_interface_raw",
        "remote_interface",
        "remote_interface_raw",
        "protocol",
        "capabilities",
    }

    def validate_pattern_mapping(
        mapping: dict[str, str | list[str]],
        context: str,
        *,
        allowed_fields: set[str] | None = None,
    ) -> None:
        """Validate field/detail regex mappings used by evidence and tag rules.

        Args:
            mapping: Field/detail names mapped to one regex or a regex list.
            context: Human-readable rule label for diagnostics.
            allowed_fields: Optional whitelist for first-class evidence fields.

        Returns:
            ``None``. Problems are appended to the enclosing ``errors`` list.
        """

        if not isinstance(mapping, dict):
            errors.append(f"{context} must be a table")
            return
        for field_name, value in mapping.items():
            if allowed_fields is not None and field_name not in allowed_fields:
                errors.append(f"{context} has unsupported field {field_name!r}")
            if not str(field_name).strip():
                errors.append(f"{context} has an empty field/detail key")
            try:
                patterns = _pattern_values(value)
            except (TypeError, ValueError) as exc:
                errors.append(f"{context} {field_name!r} must be a regex string or list: {exc}")
                continue
            if not patterns:
                errors.append(f"{context} {field_name!r} must contain at least one regex")
                continue
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except (re.error, TypeError) as exc:
                    errors.append(f"{context} regex {field_name}={pattern!r}: {exc}")

    for index, rule in enumerate(config.classification.evidence_rules, start=1):
        label = rule.label or f"#{index}"
        if rule.category not in categories:
            errors.append(
                f"classification evidence rule {label} has invalid category {rule.category!r}"
            )
        name_patterns = rule.name_pattern_values()
        networks = rule.network_values()
        if not any((name_patterns, networks, rule.field_patterns, rule.detail_patterns)):
            errors.append(
                f"classification evidence rule {label} must define at least one matching condition"
            )
        if name_patterns:
            validate_regexes(name_patterns, f"classification evidence rule {label} name")
        if networks:
            validate_networks(networks, f"classification evidence rule {label}")
        validate_pattern_mapping(
            rule.field_patterns,
            f"classification evidence rule {label} field_patterns",
            allowed_fields=evidence_fields,
        )
        validate_pattern_mapping(
            rule.detail_patterns,
            f"classification evidence rule {label} detail_patterns",
        )

    for index, rule in enumerate(config.tagging.rules, start=1):
        label = rule.label or f"#{index}"
        if not rule.tags:
            errors.append(f"tagging rule {label} must define at least one tag")
        for tag in rule.tags:
            if not isinstance(tag, str) or not tag.strip():
                errors.append(f"tagging rule {label} contains an empty or invalid tag")
        if rule.category is not None and rule.category not in categories:
            errors.append(f"tagging rule {label} has invalid category {rule.category!r}")
        name_patterns = rule.name_pattern_values()
        networks = rule.network_values()
        if not any(
            (rule.category, name_patterns, networks, rule.field_patterns, rule.detail_patterns)
        ):
            errors.append(f"tagging rule {label} must define at least one matching condition")
        if name_patterns:
            validate_regexes(name_patterns, f"tagging rule {label} name")
        if networks:
            validate_networks(networks, f"tagging rule {label}")
        validate_pattern_mapping(
            rule.field_patterns,
            f"tagging rule {label} field_patterns",
            allowed_fields=evidence_fields,
        )
        validate_pattern_mapping(
            rule.detail_patterns,
            f"tagging rule {label} detail_patterns",
        )

    for pattern in [
        *config.classification.managed_endpoint_patterns,
        *config.classification.unmanaged_patterns,
    ]:
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"classification regex {pattern!r}: {exc}")

    if errors:
        raise ConfigError("Configuration validation failed:\n- " + "\n- ".join(errors))


def defaults_with_set_overrides(set_expressions: list[str] | None = None) -> dict[str, Any]:
    """Return a copy of built-in defaults with optional --set values applied.

    ``generate-config`` uses this helper so the file it writes is derived from
    the same defaults and TOML value parser used by a real run. Constructing the
    typed model catches unknown setting names without resolving paths or requiring
    credentials, which keeps configuration generation safe and side-effect free.
    """

    raw = _merge_default_overlay(DEFAULTS, parse_set_overrides(set_expressions))
    try:
        app = _build_app(raw, config_path=None, credential_mode=CredentialMode.OPTIONAL)
        workers = app.discovery.workers
        if isinstance(workers, str) and workers.lower() == "auto":
            app.discovery.workers = (os.cpu_count() or 1) * 4
        else:
            app.discovery.workers = int(workers)
        validate_config(app, env={}, credential_mode=CredentialMode.OPTIONAL)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"generated configuration override has an invalid value: {exc}") from exc
    return raw
