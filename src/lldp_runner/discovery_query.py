"""Read-only search helpers for persisted LLDP-Runner discovery JSON.

The discovery viewer deliberately consumes the durable ``discovery.json``
contract instead of opening SQLite state. This keeps ``show-neighbors`` useful for
operators who have read-only access to finalized output and prevents an
interactive lookup from mutating or depending on discovery runtime state.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lldp_runner.config import AppConfig, ConfigError, resolve_existing_persistent_root
from lldp_runner.outputs import DISCOVERY_JSON_SCHEMA_VERSION
from lldp_runner.runid import validate_run_id_component


class DiscoveryQueryError(ValueError):
    """Invalid discovery input, query syntax, or persisted JSON structure."""


@dataclass(slots=True, frozen=True)
class KeyCriterion:
    """One dotted-key regular-expression criterion.

    Args:
        key: Top-level or dotted host-record key path to inspect.
        pattern_text: Operator-provided Python regular-expression text.
        pattern: Compiled case-insensitive regular expression used with search
            semantics against the selected value's deterministic text form.
    """

    key: str
    pattern_text: str
    pattern: re.Pattern[str]


@dataclass(slots=True, frozen=True)
class AddressCriterion:
    """One IPv4/IPv6 prefix or CIDR selection criterion.

    Args:
        family: Address family, either ``4`` or ``6``.
        text: Original operator input used in diagnostics.
        network: Parsed CIDR network when CIDR notation was supplied.
        prefix: Normalized literal prefix when partial-address matching is used.
    """

    family: int
    text: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    prefix: str | None = None


@dataclass(slots=True)
class DiscoveryDocument:
    """Validated finalized discovery document and host lookup index.

    Args:
        path: Filesystem path from which the JSON document was loaded.
        payload: Complete parsed discovery document.
        hosts: Validated host dictionaries in persisted output order.
        hosts_by_id: Integer-ID lookup used by exact ID queries and neighbor
            management-address correlation during rendering.
    """

    path: Path
    payload: dict[str, Any]
    hosts: list[dict[str, Any]]
    hosts_by_id: dict[int, dict[str, Any]]


@dataclass(slots=True)
class QueryCriteria:
    """Compiled AND-combined host-selection criteria.

    Args:
        host_id: Exact host ID, mutually exclusive with every other criterion.
        name_pattern: Case-insensitive preferred-name regex used with ``match``.
        key_criteria: Repeatable dotted-key regex criteria using AND semantics.
        address_criteria: Repeatable IPv4/IPv6 prefix or CIDR criteria using AND
            semantics. Each individual criterion may match any address of its
            corresponding family on the host.
    """

    host_id: int | None = None
    name_pattern: re.Pattern[str] | None = None
    key_criteria: tuple[KeyCriterion, ...] = ()
    address_criteria: tuple[AddressCriterion, ...] = ()


def _readonly_persistent_root(config: AppConfig) -> Path:
    """Resolve the persistent root without creating or write-probing storage."""

    try:
        return resolve_existing_persistent_root(config.paths.persistent_root)
    except ConfigError as exc:
        raise DiscoveryQueryError(str(exc)) from exc


def resolve_discovery_path(
    config: AppConfig,
    *,
    run_id: str | None = None,
    filename: str | Path | None = None,
) -> Path:
    """Resolve latest, run-ID, or arbitrary-file discovery input.

    Args:
        config: Effective read-only configuration used for persistent-root and
            output-directory names when ``filename`` is not supplied.
        run_id: Optional exact run directory beneath persistent output.  The ID
            is validated only as a safe path component, not against the current
            ``run_id_format``, so historical runs remain queryable after a site
            changes its naming convention.
        filename: Optional operator-selected discovery JSON path.  Relative paths
            start at the current working directory; ``~`` and absolute paths are
            supported.

    Returns:
        Resolved filesystem path to a discovery JSON document.

    Raises:
        DiscoveryQueryError: If ``run_id`` and ``filename`` are both supplied or
            the run ID is not a safe single path component.
    """

    if run_id is not None and filename is not None:
        raise DiscoveryQueryError("--runid and --file are mutually exclusive")
    if filename is not None:
        path = Path(filename).expanduser()
        return (Path.cwd() / path).resolve() if not path.is_absolute() else path.resolve()

    root = _readonly_persistent_root(config)
    output_root = root / config.paths.output_dirname
    if run_id is None:
        return output_root / "latest" / "discovery.json"
    try:
        safe_run_id = validate_run_id_component(run_id, label="--runid")
    except ValueError as exc:
        raise DiscoveryQueryError(str(exc)) from exc
    return output_root / safe_run_id / "discovery.json"


def default_discovery_path(config: AppConfig) -> Path:
    """Return the default finalized ``latest/discovery.json`` pathname."""

    return resolve_discovery_path(config)


def load_discovery_document(
    config: AppConfig,
    *,
    run_id: str | None = None,
    filename: str | Path | None = None,
) -> DiscoveryDocument:
    """Load and validate a selected finalized discovery JSON document.

    Args:
        config: Effective read-only configuration used for source resolution.
        run_id: Optional exact persistent-output run ID.
        filename: Optional relative/absolute standalone JSON pathname.

    Returns:
        :class:`DiscoveryDocument` with a stable integer host-ID index.

    Raises:
        DiscoveryQueryError: If source selection is invalid, the file is missing,
            unreadable/malformed, uses an unsupported schema, or contains
            structurally invalid host records.
    """

    path = resolve_discovery_path(config, run_id=run_id, filename=filename)
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError as exc:
        raise DiscoveryQueryError(f"discovery.json not found: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DiscoveryQueryError(f"unable to read discovery.json {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise DiscoveryQueryError(f"discovery.json root must be an object: {path}")
    schema_version = payload.get("schema_version")
    if schema_version != DISCOVERY_JSON_SCHEMA_VERSION:
        raise DiscoveryQueryError(
            "unsupported discovery.json schema_version "
            f"{schema_version!r}; expected {DISCOVERY_JSON_SCHEMA_VERSION}"
        )
    raw_hosts = payload.get("hosts")
    if not isinstance(raw_hosts, list):
        raise DiscoveryQueryError("discovery.json hosts must be an array")

    hosts: list[dict[str, Any]] = []
    hosts_by_id: dict[int, dict[str, Any]] = {}
    for position, item in enumerate(raw_hosts):
        if not isinstance(item, dict):
            raise DiscoveryQueryError(
                f"discovery.json hosts[{position}] must be an object"
            )
        host_id = item.get("id")
        if not isinstance(host_id, int) or isinstance(host_id, bool):
            raise DiscoveryQueryError(
                f"discovery.json hosts[{position}].id must be an integer"
            )
        if host_id in hosts_by_id:
            raise DiscoveryQueryError(f"duplicate discovery host id: {host_id}")
        hosts.append(item)
        hosts_by_id[host_id] = item
    return DiscoveryDocument(path, payload, hosts, hosts_by_id)


def _compile_regex(pattern: str, *, description: str) -> re.Pattern[str]:
    """Compile one case-insensitive Python regex with an operator-facing error.

    Args:
        pattern: Regular-expression text supplied by the operator.
        description: Criterion label included when compilation fails.

    Returns:
        Compiled case-insensitive Python regular expression.

    Raises:
        DiscoveryQueryError: If ``pattern`` is empty or invalid Python regex.
    """

    if pattern == "":
        raise DiscoveryQueryError(f"{description} pattern must not be empty")
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise DiscoveryQueryError(f"invalid {description} regex {pattern!r}: {exc}") from exc


def _unquote_pattern(value: str) -> str:
    """Remove one balanced quote pair around a ``--key`` pattern when present.

    Args:
        value: Pattern substring after the first ``:`` in ``KEY:PATTERN``.

    Returns:
        Pattern without a matching outer single/double quote pair. Shell quoting
        normally removes these already; accepting an inner pair also supports the
        documented ``--key \"addresses:'192\\.0\\.2'\"`` style.
    """

    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_key_criterion(expression: str) -> KeyCriterion:
    """Parse ``KEY:PATTERN`` into a compiled dotted-key criterion.

    Args:
        expression: Operator argument such as ``system.model:^C9300``.

    Returns:
        Compiled :class:`KeyCriterion`.

    Raises:
        DiscoveryQueryError: If key/pattern syntax or regex syntax is invalid.
    """

    key, separator, raw_pattern = expression.partition(":")
    key = key.strip()
    if not separator or not key:
        raise DiscoveryQueryError(
            f"invalid --key {expression!r}; expected KEY:PATTERN"
        )
    if any(not part for part in key.split(".")):
        raise DiscoveryQueryError(f"invalid --key path {key!r}")
    pattern_text = _unquote_pattern(raw_pattern.strip())
    pattern = _compile_regex(pattern_text, description=f"--key {key}")
    return KeyCriterion(key=key, pattern_text=pattern_text, pattern=pattern)


def _validate_ipv4_prefix(value: str) -> str:
    """Validate and normalize an operator IPv4 literal-prefix criterion.

    Args:
        value: Partial or complete dotted-decimal text without CIDR notation.

    Returns:
        Original stripped prefix when every supplied octet is syntactically valid.

    Raises:
        DiscoveryQueryError: If the partial IPv4 expression cannot be a prefix of
            a valid dotted-decimal IPv4 address.
    """

    text = value.strip()
    if not text or not re.fullmatch(r"[0-9.]+", text):
        raise DiscoveryQueryError(f"invalid --ipv4 prefix {value!r}")
    parts = text.split(".")
    if len(parts) > 4 or any(part == "" for part in parts[:-1]):
        raise DiscoveryQueryError(f"invalid --ipv4 prefix {value!r}")
    numeric = [part for part in parts if part != ""]
    if any(len(part) > 3 or int(part) > 255 for part in numeric):
        raise DiscoveryQueryError(f"invalid --ipv4 prefix {value!r}")
    return text


def _validate_ipv6_prefix(value: str) -> str:
    """Validate an IPv6 textual prefix without requiring a complete address.

    Args:
        value: Partial or complete IPv6 text without CIDR notation.

    Returns:
        Lowercased literal prefix suitable for case-insensitive startswith matching.

    Raises:
        DiscoveryQueryError: If unsupported characters or no colon are present.

    Full-address and CIDR validation is delegated to :mod:`ipaddress`. For partial
    prefixes, restricting the alphabet while requiring ``:`` preserves useful
    operator inputs such as ``2001:db8`` without inventing normalization that
    could change literal-prefix semantics.
    """

    text = value.strip()
    if not text or ":" not in text or not re.fullmatch(r"[0-9A-Fa-f:.]+", text):
        raise DiscoveryQueryError(f"invalid --ipv6 prefix {value!r}")
    if ":::" in text or text.count("::") > 1:
        raise DiscoveryQueryError(f"invalid --ipv6 prefix {value!r}")

    # A literal prefix may be incomplete, so ipaddress cannot validate every
    # useful operator input. Still reject impossible hextets/group counts early
    # so malformed filtering syntax is never silently treated as ordinary text.
    halves = text.split("::")
    groups = [part for half in halves for part in half.split(":") if part]
    if any("." not in group and len(group) > 4 for group in groups):
        raise DiscoveryQueryError(f"invalid --ipv6 prefix {value!r}")
    explicit_groups = len(groups)
    if ("::" in text and explicit_groups > 7) or ("::" not in text and explicit_groups > 8):
        raise DiscoveryQueryError(f"invalid --ipv6 prefix {value!r}")
    return text.casefold()


def parse_address_criterion(value: str, *, family: int) -> AddressCriterion:
    """Parse one IPv4/IPv6 literal-prefix or CIDR selection criterion.

    Args:
        value: Operator-supplied partial address, full address, or CIDR.
        family: Required address family, ``4`` for ``--ipv4`` or ``6`` for
            ``--ipv6``.

    Returns:
        Parsed :class:`AddressCriterion` using network-membership semantics for
        CIDRs and literal startswith semantics otherwise.

    Raises:
        DiscoveryQueryError: If syntax is invalid or the CIDR uses the wrong
            address family.
    """

    text = value.strip()
    if family not in {4, 6}:
        raise DiscoveryQueryError(f"unsupported address family: {family}")
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise DiscoveryQueryError(
                f"invalid --ipv{family} CIDR {value!r}: {exc}"
            ) from exc
        if network.version != family:
            raise DiscoveryQueryError(
                f"--ipv{family} requires an IPv{family} CIDR, got {value!r}"
            )
        return AddressCriterion(family=family, text=text, network=network)

    prefix = _validate_ipv4_prefix(text) if family == 4 else _validate_ipv6_prefix(text)
    return AddressCriterion(family=family, text=text, prefix=prefix)


def build_query_criteria(
    *,
    host_id: int | None,
    name: str | None,
    key_expressions: Sequence[str],
    ipv4_values: Sequence[str],
    ipv6_values: Sequence[str],
) -> QueryCriteria:
    """Compile CLI search inputs into one validated AND-combined query.

    Args:
        host_id: Exact host ID, or ``None``.
        name: Preferred-name regex, or ``None``.
        key_expressions: Repeatable ``KEY:PATTERN`` expressions.
        ipv4_values: Repeatable IPv4 literal-prefix/CIDR values.
        ipv6_values: Repeatable IPv6 literal-prefix/CIDR values.

    Returns:
        Validated :class:`QueryCriteria` ready for host matching.

    Raises:
        DiscoveryQueryError: If no criterion is present, exact ID is combined
            with another criterion, or any filter syntax is invalid.
    """

    has_other = bool(name or key_expressions or ipv4_values or ipv6_values)
    if host_id is not None:
        if host_id < 0:
            raise DiscoveryQueryError("--id must be a non-negative integer")
        if has_other:
            raise DiscoveryQueryError(
                "--id is mutually exclusive with name, --key, --ipv4, and --ipv6 filters"
            )
        return QueryCriteria(host_id=host_id)
    if not has_other:
        raise DiscoveryQueryError(
            "a host selector is required: PATTERN, --name, --id, --key, --ipv4, or --ipv6"
        )

    name_pattern = _compile_regex(name, description="name") if name is not None else None
    keys = tuple(parse_key_criterion(item) for item in key_expressions)
    addresses = tuple(
        [parse_address_criterion(item, family=4) for item in ipv4_values]
        + [parse_address_criterion(item, family=6) for item in ipv6_values]
    )
    return QueryCriteria(
        name_pattern=name_pattern,
        key_criteria=keys,
        address_criteria=addresses,
    )


def _values_for_key(value: Any, parts: Sequence[str]) -> list[Any]:
    """Resolve a dotted key path, traversing arrays of nested mappings.

    Args:
        value: Current host-record value or nested container.
        parts: Remaining dotted-key path components.

    Returns:
        All values reached by the path. When an intermediate value is a list,
        each element is traversed independently so paths such as
        ``system.stack_members.model`` can naturally examine every member.
    """

    if not parts:
        return [value]
    if isinstance(value, Mapping):
        key = parts[0]
        if key not in value:
            return []
        return _values_for_key(value[key], parts[1:])
    if isinstance(value, list):
        results: list[Any] = []
        for item in value:
            results.extend(_values_for_key(item, parts))
        return results
    return []


def _flatten_value(value: Any) -> str:
    """Convert one arbitrary JSON value to deterministic searchable text.

    Args:
        value: Scalar, array, or object selected from a host record.

    Returns:
        Stable single-line text. Objects use sorted JSON keys so matching does not
        depend on dictionary insertion order; strings remain unquoted for natural
        operator regexes.
    """

    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def _matches_key(host: Mapping[str, Any], criterion: KeyCriterion) -> bool:
    """Return whether one host satisfies one dotted-key regex criterion."""

    values = _values_for_key(host, criterion.key.split("."))
    return any(criterion.pattern.search(_flatten_value(value)) for value in values)


def _matches_address(host: Mapping[str, Any], criterion: AddressCriterion) -> bool:
    """Return whether one host address satisfies one prefix/CIDR criterion."""

    addresses = host.get("addresses")
    if not isinstance(addresses, Mapping):
        return False
    values = addresses.get("ipv4" if criterion.family == 4 else "ipv6", [])
    if not isinstance(values, list):
        return False
    for value in values:
        text = str(value)
        if criterion.network is not None:
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue
            if address.version == criterion.family and address in criterion.network:
                return True
        elif criterion.prefix is not None:
            candidate = text if criterion.family == 4 else text.casefold()
            if candidate.startswith(criterion.prefix):
                return True
    return False


def host_matches(host: Mapping[str, Any], criteria: QueryCriteria) -> bool:
    """Return whether a host satisfies every compiled selection criterion.

    Args:
        host: One validated discovery host record.
        criteria: Exact-ID or AND-combined name/key/address criteria.

    Returns:
        ``True`` when the record is selected. Name regex uses beginning-of-string
        ``match`` semantics; key regexes use ``search`` semantics; address filters
        use literal-prefix or CIDR membership semantics.
    """

    if criteria.host_id is not None:
        return host.get("id") == criteria.host_id
    if criteria.name_pattern is not None:
        preferred_name = str(host.get("preferred_name") or "")
        if criteria.name_pattern.match(preferred_name) is None:
            return False
    if not all(_matches_key(host, item) for item in criteria.key_criteria):
        return False
    return all(_matches_address(host, item) for item in criteria.address_criteria)


def select_hosts(document: DiscoveryDocument, criteria: QueryCriteria) -> list[dict[str, Any]]:
    """Select host records in stable ID order using compiled criteria.

    Args:
        document: Validated discovery document.
        criteria: Query criteria from :func:`build_query_criteria`.

    Returns:
        Matching host dictionaries sorted numerically by their unique ``id``.
    """

    if criteria.host_id is not None:
        host = document.hosts_by_id.get(criteria.host_id)
        return [host] if host is not None else []
    return sorted(
        (host for host in document.hosts if host_matches(host, criteria)),
        key=lambda item: int(item["id"]),
    )
