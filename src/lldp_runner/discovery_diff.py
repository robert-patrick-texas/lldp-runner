"""Read-only comparison of finalized LLDP-Runner discovery documents.

The diff feature deliberately works from durable ``discovery.json`` and optional
``run.json`` metadata. It never opens discovery SQLite state, resolves credentials,
or contacts network devices. Cross-run host IDs are run-local, so pairing uses
stable identity evidence and refuses to guess when evidence is ambiguous.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from lldp_runner.claims import stable_fingerprint
from lldp_runner.config import AppConfig, ConfigError, resolve_existing_persistent_root
from lldp_runner.diff_reconciliation import reconcile_compatibility_and_graph
from lldp_runner.discovery_query import (
    DiscoveryDocument,
    QueryCriteria,
    load_discovery_document,
    select_hosts,
)
from lldp_runner.identity import (
    cisco_sep_mac,
    normalize_host_address,
    normalize_identity_name,
    weak_mobility_mac,
)
from lldp_runner.outputs import DISCOVERY_JSON_SCHEMA_VERSION
from lldp_runner.runid import validate_run_id_component
from lldp_runner.topology_graph_diff import compare_topology_graphs

DIFF_JSON_SCHEMA_VERSION = 12

# Neighbor collectors preserve SNMP table indexes as troubleshooting evidence in
# discovery.json. These values locate rows inside an agent at collection time;
# they are not durable topology identity and may change between otherwise
# equivalent runs after table churn or a device restart. Keep the list explicit
# so semantic identifiers such as port/chassis subtype IDs remain comparable.
_VOLATILE_NEIGHBOR_DETAIL_FIELDS = frozenset(
    {
        "device_index",
        "ifindex",
        "local_ifindex",
        "local_port_num",
        "remote_index",
        "time_mark",
    }
)

SourceKind = Literal["latest", "previous", "oldest", "runid", "file"]
EvidenceTier = Literal["physical", "address", "name", "edge_context"]
MatchConfidence = Literal["verified", "high", "medium", "low"]


class DiscoveryDiffError(ValueError):
    """Invalid diff source selection or comparison input."""


class DiscoveryDiffUnavailable(DiscoveryDiffError):
    """A valid comparison cannot be made because required history is absent."""


@dataclass(frozen=True, slots=True)
class DiffSourceSpec:
    """One operator-provided source selector in command-line order."""

    kind: SourceKind
    value: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedDiffSource:
    """One concrete discovery input after aliases such as ``--latest`` resolve."""

    path: Path
    label: str
    run_id: str | None = None
    completed: datetime | None = None
    run_metadata: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class HostPair:
    """One unambiguous cross-run logical-host association."""

    a: dict[str, Any]
    b: dict[str, Any]
    tier: EvidenceTier
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AmbiguousHostMatch:
    """One A-side host whose remaining B-side identity candidates are uncertain."""

    a: dict[str, Any]
    candidates: tuple[dict[str, Any], ...]
    tier: EvidenceTier
    conflicting_identity: bool


@dataclass(frozen=True, slots=True)
class HostPairing:
    """One-to-one pairing result for all hosts in two discovery documents."""

    pairs: tuple[HostPair, ...]
    ambiguous: tuple[AmbiguousHostMatch, ...]
    a_only: tuple[dict[str, Any], ...]
    b_only: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class FieldDifference:
    """One normalized field difference between paired records."""

    path: str
    a: Any
    b: Any
    kind: str = "changed"
    provenance: str | None = None
    coverage_sources: tuple[_CoverageSource, ...] = ()


@dataclass(frozen=True, slots=True)
class NeighborDifference:
    """One learned/observed-by neighbor difference for a paired host."""

    status: str
    a: dict[str, Any] | None
    b: dict[str, Any] | None
    differences: tuple[FieldDifference, ...] = ()
    presentation_differences: tuple[FieldDifference, ...] = ()
    uncertainty_reasons: tuple[str, ...] = ()
    protocol_change: tuple[tuple[str, ...], tuple[str, ...]] | None = None
    semantic_qualification: str = "confirmed"
    presence_status: str = "same"
    presence_confidence: str = "confirmed"
    coverage_sources: tuple[_CoverageSource, ...] = ()
    management_address_change: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class _CoverageSource:
    """One collection incident that limits a cross-run presence conclusion.

    Host IDs are run-local, so both sides of the paired observer are retained.
    The deterministic incident key lets reports aggregate hundreds of derivative
    entities under one failed collector instead of presenting each missing row as
    an independent network event.
    """

    incident_key: str
    missing_side: str
    present_observer_id: int
    present_observer_name: str
    missing_observer_id: int
    missing_observer_name: str
    protocol: str
    table: str
    status: str
    message: str | None = None
    origin: str = "direct"
    recursive_path: tuple[tuple[int, str], ...] = ()

    def as_recursive(self, host_id: int, host_name: str) -> _CoverageSource:
        """Extend the original incident through one recursive discovery hop."""

        return replace(
            self,
            origin="recursive",
            recursive_path=(*self.recursive_path, (host_id, host_name)),
        )

    def to_json(self) -> dict[str, Any]:
        """Return stable machine-readable incident provenance."""

        present_side = "b" if self.missing_side == "a" else "a"
        return {
            "incident_key": self.incident_key,
            "missing_side": self.missing_side,
            "observer": {
                present_side: {
                    "id": self.present_observer_id,
                    "preferred_name": self.present_observer_name,
                },
                self.missing_side: {
                    "id": self.missing_observer_id,
                    "preferred_name": self.missing_observer_name,
                },
            },
            "protocol": self.protocol,
            "table": self.table,
            "status": self.status,
            "message": self.message,
            "origin": self.origin,
            "recursive_path": [
                {"id": host_id, "preferred_name": host_name}
                for host_id, host_name in self.recursive_path
            ],
        }


@dataclass(frozen=True, slots=True)
class _HostCollectionCoverage:
    """Neighbor-collection completeness for one host in one discovery run."""

    host_state: str
    query_disposition: str = "queried_complete"
    all_neighbors_incomplete: bool = False
    failed_protocols: frozenset[str] = frozenset()
    unresolved_interface_protocols: frozenset[str] = frozenset()
    table_statuses: tuple[tuple[str, str], ...] = ()
    table_row_counts: tuple[tuple[str, int], ...] = ()
    table_messages: tuple[tuple[str, str], ...] = ()
    neighbor_statuses: tuple[tuple[str, str], ...] = ()
    neighbor_messages: tuple[tuple[str, str], ...] = ()
    neighbor_sources: tuple[tuple[str, str], ...] = ()
    interface_statuses: tuple[tuple[str, str], ...] = ()
    interface_messages: tuple[tuple[str, str], ...] = ()
    interface_sources: tuple[tuple[str, str], ...] = ()
    management_address_statuses: tuple[tuple[str, str], ...] = ()
    management_address_messages: tuple[tuple[str, str], ...] = ()
    management_address_sources: tuple[tuple[str, str], ...] = ()
    reasons: tuple[str, ...] = ()

    def status_for(self, table: str) -> str | None:
        """Return the recorded status for one independently collected table."""

        return dict(self.table_statuses).get(table.casefold())

    def authoritative_negative(self, table: str) -> bool:
        """Return whether absence from ``table`` may be treated as observed."""

        status = self.status_for(table)
        if status is not None:
            if status != "complete":
                return False
            # ENTITY-MIB is optional and several production platforms can return
            # an intermittently empty snapshot without a transport error.  An
            # empty complete walk therefore cannot prove that previously observed
            # chassis/member hardware was removed. A nonempty complete snapshot
            # can still prove that a specific former member is absent.
            if table.casefold() == "entity" and self.row_count_for(table) == 0:
                return False
            return True
        # Schema-7 discoveries normally record every attempted table.  Retain a
        # conservative compatibility boundary for compact fixtures and manually
        # authored documents: a completed host with no error for this protocol is
        # treated as complete, while failed/no-query hosts never provide a trusted
        # negative observation.
        return (
            self.host_state == "complete"
            and not self.all_neighbors_incomplete
            and table.casefold() not in self.failed_protocols
        )

    def message_for(self, table: str) -> str | None:
        """Return the durable collector message for one table, when available."""

        return dict(self.table_messages).get(table.casefold())

    def row_count_for(self, table: str) -> int | None:
        """Return the durable successful row count for one table when recorded."""

        return dict(self.table_row_counts).get(table.casefold())

    def management_address_status_for(self, protocol: str) -> str | None:
        """Return management-address subtable status with schema-7 fallback.

        Schema 8 discovery records expose an independent LLDP/LLDPv2
        management-address subtable. Historical schema-7 documents only expose
        aggregate protocol coverage, which is the best available provenance for
        replaying those completed runs.
        """

        name = protocol.casefold()
        explicit = dict(self.management_address_statuses).get(name)
        if explicit is not None:
            return explicit
        return self.status_for(name)

    def neighbor_status_for(self, protocol: str) -> str | None:
        """Return relationship-presence coverage for one neighbor protocol.

        Discovery schema 8 exposes LLDP/LLDPv2 ``remote_neighbor`` separately
        from management-address collection.  Older documents and CDP use the
        aggregate protocol table as the compatibility boundary.
        """

        name = protocol.casefold()
        explicit = dict(self.neighbor_statuses).get(name)
        if explicit is not None:
            return explicit
        return self.status_for(name)

    def neighbor_message_for(self, protocol: str) -> str | None:
        """Return the most specific relationship-presence collector message."""

        name = protocol.casefold()
        return dict(self.neighbor_messages).get(name) or self.message_for(name)

    def neighbor_source_for(self, protocol: str) -> str:
        """Return the table name authoritative for relationship presence."""

        name = protocol.casefold()
        return dict(self.neighbor_sources).get(name, name)

    def authoritative_neighbor_negative(self, protocol: str) -> bool:
        """Return whether a missing neighbor row is a confirmed observation."""

        status = self.neighbor_status_for(protocol)
        if status is not None:
            return status == "complete"
        return self.authoritative_negative(protocol)

    def interface_status_for(self, protocol: str) -> str | None:
        """Return local-interface resolution coverage for one protocol."""

        name = protocol.casefold()
        explicit = dict(self.interface_statuses).get(name)
        if explicit is not None:
            return explicit
        if name in self.unresolved_interface_protocols:
            return self.status_for("interfaces") or "unresolved"
        return "complete"

    def interface_message_for(self, protocol: str) -> str | None:
        """Return the most specific local-interface coverage message."""

        name = protocol.casefold()
        return dict(self.interface_messages).get(name) or self.message_for("interfaces")

    def interface_source_for(self, protocol: str) -> str:
        """Return the table name authoritative for local-interface resolution."""

        name = protocol.casefold()
        return dict(self.interface_sources).get(name, "interfaces")

    def management_address_message_for(self, protocol: str) -> str | None:
        """Return the most specific durable management-table message."""

        name = protocol.casefold()
        return dict(self.management_address_messages).get(name) or self.message_for(name)

    def management_address_source_for(self, protocol: str) -> str:
        """Identify whether evidence came from a subtable or legacy aggregate."""

        return dict(self.management_address_sources).get(
            protocol.casefold(), "protocol_aggregate_legacy"
        )

    def authoritative_management_addresses(self, protocol: str) -> bool:
        """Return whether absence from one management table is authoritative."""

        status = self.management_address_status_for(protocol)
        if status is not None:
            return status == "complete"
        return self.authoritative_negative(protocol)

    def to_json(self) -> dict[str, Any]:
        """Return stable machine-readable coverage metadata for diff schema 8."""

        return {
            "host_state": self.host_state,
            "query_disposition": self.query_disposition,
            "neighbor_collection_complete": not self.all_neighbors_incomplete
            and not self.failed_protocols
            and not self.unresolved_interface_protocols,
            "failed_protocols": sorted(self.failed_protocols),
            "unresolved_interface_protocols": sorted(self.unresolved_interface_protocols),
            "tables": dict(self.table_statuses),
            "table_row_counts": dict(self.table_row_counts),
            "table_messages": dict(self.table_messages),
            "neighbor_tables": {
                protocol: {
                    "status": status,
                    "message": dict(self.neighbor_messages).get(protocol),
                    "source": dict(self.neighbor_sources).get(protocol, protocol),
                }
                for protocol, status in self.neighbor_statuses
            },
            "interface_tables": {
                protocol: {
                    "status": status,
                    "message": dict(self.interface_messages).get(protocol),
                    "source": dict(self.interface_sources).get(protocol, "interfaces"),
                }
                for protocol, status in self.interface_statuses
            },
            "management_address_tables": {
                protocol: {
                    "status": status,
                    "message": dict(self.management_address_messages).get(protocol),
                    "source": dict(self.management_address_sources).get(
                        protocol, "protocol_aggregate_legacy"
                    ),
                }
                for protocol, status in self.management_address_statuses
            },
            "reasons": list(self.reasons),
        }


_COMPLETE_COLLECTION = _HostCollectionCoverage(host_state="complete")


@dataclass(frozen=True, slots=True)
class _CompatibilityProjection:
    """Canonical in-memory host projection used only by macro diff.

    Discovery JSON intentionally retains compatibility hosts independently from
    the claims-driven graph.  Concurrent recursive discovery can therefore leave
    two fully queried rows for one logical managed system.  Macro diff reconciles
    only uniquely corroborated complete managed projections before one-to-one
    pairing; raw discovery evidence and graph host references remain untouched.
    """

    document: DiscoveryDocument
    coverage: dict[int, _HostCollectionCoverage]
    id_map: dict[int, int]
    members_by_id: dict[int, tuple[int, ...]]
    groups: tuple[dict[str, Any], ...]
    raw_host_count: int

    @property
    def canonical_host_count(self) -> int:
        return len(self.document.hosts)

    @property
    def absorbed_host_count(self) -> int:
        return self.raw_host_count - self.canonical_host_count


@dataclass(frozen=True, slots=True)
class _OneSidedPresenceAssessment:
    """Coverage qualification for a host projected in only one discovery run."""

    side: str
    host: dict[str, Any]
    presence_status: str
    presence_confidence: str
    semantic_qualification: str
    reasons: tuple[str, ...] = ()
    coverage_sources: tuple[_CoverageSource, ...] = ()

    @property
    def coverage_uncertain(self) -> bool:
        """Return whether absence from the other run is coverage-limited."""

        return self.presence_confidence == "coverage_uncertain"


@dataclass(slots=True)
class DiffOutcome:
    """Complete comparison result consumed by terminal and JSON renderers."""

    status: str
    message: str
    exit_code: int
    mode: str
    source_a: ResolvedDiffSource | None = None
    source_b: ResolvedDiffSource | None = None
    warnings: tuple[str, ...] = ()
    data: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class _HistoryRun:
    run_id: str
    path: Path
    completed: datetime
    run_metadata: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class _PairCandidate:
    host: dict[str, Any]
    tier: EvidenceTier
    evidence: tuple[str, ...]
    conflicting_identity: bool


_EVIDENCE_TIERS: tuple[EvidenceTier, ...] = ("physical", "address", "name")
_SCOPE_DISCOVERY_FIELDS = (
    "status",
    "boundaries",
    "discovery_mode",
    "effective_max_devices",
    "configured_max_devices",
    "configured_max_hosts",
    "seed_order",
    "limit_behavior",
    "limit_reason",
    "completion_reason",
)
_HOST_IGNORED_KEYS = {
    "id",
    # Compatibility presentation and collection provenance are compared in
    # dedicated dimensions below.  They must not turn an otherwise stable
    # managed system into a confirmed device-attribute change.
    "preferred_name",
    "names",
    "addresses",
    "classification_reason",
    "state",
    "is_seed",
    "first_seen",
    "last_seen",
    "last_seen_source",
    # These values describe how the collector reached an already identified
    # entity.  Address membership is compared separately under ``addresses``.
    "queried_as",
    "icmp",
    "snmp",
    "learned_neighbors",
    "observed_by_neighbors",
}
_TIMESTAMP_KEYS = {"timestamp", "first_seen", "last_seen", "generated", "completed", "started"}


def _parse_aware_datetime(value: object) -> datetime | None:
    """Parse a timezone-aware ISO timestamp, returning ``None`` when unusable."""

    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def _read_json_object(path: Path) -> dict[str, Any] | None:
    """Best-effort read of a small JSON metadata object such as ``run.json``."""

    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _read_discovery_metadata_prefix(path: Path) -> dict[str, Any] | None:
    """Read only the leading discovery metadata object from a large JSON file.

    Current discovery output writes ``schema_version`` and ``discovery`` before the
    potentially huge ``hosts`` and ``errors`` arrays. History resolution should not
    deserialize gigabytes merely to rank finalized runs, so this helper incrementally
    reads the beginning of the file and asks ``JSONDecoder`` to decode just the value
    following the top-level ``"discovery"`` key. ``run.json`` remains the preferred
    source; this is a compatibility fallback for finalized directories missing it.
    """

    if not path.is_file():
        return None
    decoder = json.JSONDecoder()
    buffer = ""
    marker = '"discovery"'
    try:
        with path.open("r", encoding="utf-8") as handle:
            while len(buffer) < 8 * 1024 * 1024:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                buffer += chunk
                position = buffer.find(marker)
                if position < 0:
                    continue
                colon = buffer.find(":", position + len(marker))
                if colon < 0:
                    continue
                candidate = buffer[colon + 1 :].lstrip()
                try:
                    value, _end = decoder.raw_decode(candidate)
                except json.JSONDecodeError:
                    continue
                return value if isinstance(value, dict) else None
    except (OSError, UnicodeError):
        return None
    return None


def _completed_for_run(directory: Path, run_metadata: dict[str, Any] | None) -> datetime | None:
    """Return the authoritative completed timestamp for one finalized run."""

    if run_metadata is not None:
        completed = _parse_aware_datetime(run_metadata.get("completed"))
        if completed is not None:
            return completed
    metadata = _read_discovery_metadata_prefix(directory / "discovery.json")
    if metadata is None:
        return None
    return _parse_aware_datetime(metadata.get("completed"))


def _persistent_output_root(config: AppConfig) -> Path:
    """Resolve the configured persistent output root without creating anything."""

    try:
        path = resolve_existing_persistent_root(config.paths.persistent_root)
    except (ConfigError, OSError, ValueError) as exc:
        raise DiscoveryDiffError(str(exc)) from exc
    output = path / config.paths.output_dirname
    if not output.is_dir():
        raise DiscoveryDiffError(f"persistent output directory not found: {output}")
    return output


def _history_runs(config: AppConfig) -> list[_HistoryRun]:
    """Return finalized output directories ranked by timezone-aware completion."""

    output_root = _persistent_output_root(config)
    runs: list[_HistoryRun] = []
    for entry in output_root.iterdir():
        if entry.name == "latest" or entry.is_symlink() or not entry.is_dir():
            continue
        discovery = entry / "discovery.json"
        if not discovery.is_file():
            continue
        run_metadata = _read_json_object(entry / "run.json")
        completed = _completed_for_run(entry, run_metadata)
        if completed is None:
            # History aliases are chronology operations. A directory without a
            # timezone-aware finalization timestamp cannot be ordered safely.
            continue
        runs.append(_HistoryRun(entry.name, discovery, completed, run_metadata))
    runs.sort(key=lambda item: (item.completed.timestamp(), item.run_id))
    return runs


def _run_source(entry: _HistoryRun) -> ResolvedDiffSource:
    return ResolvedDiffSource(
        path=entry.path.resolve(),
        label=f"--runid {entry.run_id}",
        run_id=entry.run_id,
        completed=entry.completed,
        run_metadata=entry.run_metadata,
    )


def _resolve_source(config: AppConfig, spec: DiffSourceSpec) -> ResolvedDiffSource:
    """Resolve one source selector to a concrete discovery file and display label."""

    if spec.kind in {"latest", "previous", "oldest"}:
        history = _history_runs(config)
        if not history:
            raise DiscoveryDiffUnavailable(
                "No comparison possible: no finalized discovery runs are available."
            )
        if spec.kind == "latest":
            return _run_source(history[-1])
        if spec.kind == "oldest":
            return _run_source(history[0])
        if len(history) < 2:
            raise DiscoveryDiffUnavailable(
                "No comparison possible: no prior finalized discovery run is available."
            )
        return _run_source(history[-2])

    if spec.kind == "runid":
        assert spec.value is not None
        try:
            run_id = validate_run_id_component(spec.value, label="--runid")
        except ValueError as exc:
            raise DiscoveryDiffError(str(exc)) from exc
        directory = _persistent_output_root(config) / run_id
        path = directory / "discovery.json"
        metadata = _read_json_object(directory / "run.json")
        return ResolvedDiffSource(
            path=path.resolve(),
            label=f"--runid {run_id}",
            run_id=run_id,
            completed=_completed_for_run(directory, metadata),
            run_metadata=metadata,
        )

    if spec.kind == "file":
        assert spec.value is not None
        raw = Path(spec.value).expanduser()
        path = (Path.cwd() / raw).resolve() if not raw.is_absolute() else raw.resolve()
        metadata = _read_json_object(path.parent / "run.json")
        completed = None
        if metadata is not None:
            completed = _parse_aware_datetime(metadata.get("completed"))
        return ResolvedDiffSource(
            path=path,
            label=f"--file {path}",
            completed=completed,
            run_metadata=metadata,
        )

    raise DiscoveryDiffError(f"unsupported diff source kind: {spec.kind}")


def resolve_diff_sources(
    config: AppConfig,
    specs: Sequence[DiffSourceSpec],
) -> tuple[ResolvedDiffSource, ResolvedDiffSource]:
    """Resolve the operator's zero/one/two-source syntax into ordered A and B.

    No sources means latest versus previous. One non-latest source means latest
    versus that source. Two sources preserve command-line order. ``--latest`` alone
    is rejected because it does not identify a second data set.
    """

    supplied = list(specs)
    if len(supplied) > 2:
        raise DiscoveryDiffError("exactly two or fewer data-set references may be supplied")
    if not supplied:
        supplied = [DiffSourceSpec("latest"), DiffSourceSpec("previous")]
    elif len(supplied) == 1:
        if supplied[0].kind == "latest":
            raise DiscoveryDiffError(
                "two different run references are necessary; --latest must be used "
                "with --previous/--prior, --oldest, --runid RUNID, or --file FILENAME"
            )
        supplied = [DiffSourceSpec("latest"), supplied[0]]

    first = _resolve_source(config, supplied[0])
    second = _resolve_source(config, supplied[1])
    if first.path == second.path:
        raise DiscoveryDiffError(
            f"two different data sets are required; both references resolve to {first.path}"
        )
    return first, second


def _source_with_document_metadata(
    source: ResolvedDiffSource,
    document: DiscoveryDocument,
) -> ResolvedDiffSource:
    """Fill file-source completion/run ID from loaded discovery metadata if needed."""

    discovery = document.payload.get("discovery")
    if not isinstance(discovery, Mapping):
        return source
    completed = source.completed or _parse_aware_datetime(discovery.get("completed"))
    run_id = source.run_id
    if run_id is None and isinstance(discovery.get("run_id"), str):
        run_id = str(discovery["run_id"])
    return replace(source, completed=completed, run_id=run_id)


def _norm_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().rstrip(".").casefold()
    return text or None


def _identity_text(value: object) -> str | None:
    """Normalize durable identity text while rejecting common placeholder values."""

    if value is None:
        return None
    return normalize_identity_name(str(value))


def _norm_address(value: object) -> str | None:
    """Normalize only addresses safe as cross-run host identity evidence."""

    if value is None:
        return None
    try:
        return normalize_host_address(str(value).strip())
    except ValueError:
        return None


def _system(host: Mapping[str, Any]) -> Mapping[str, Any]:
    value = host.get("system")
    return value if isinstance(value, Mapping) else {}


def _physical_groups(host: Mapping[str, Any]) -> dict[str, set[str]]:
    """Return comparable durable identity groups for conflict-aware pairing."""

    system = _system(host)
    serials: set[str] = set()
    serial = _identity_text(system.get("serial_number"))
    if serial:
        serials.add(serial)
    members = system.get("stack_members")
    if isinstance(members, list):
        for member in members:
            if isinstance(member, Mapping):
                value = _identity_text(member.get("serial_number"))
                if value:
                    serials.add(value)
    sep_macs: set[str] = set()
    sep_values: list[object] = [host.get("preferred_name"), host.get("snmp_sysname")]
    names = host.get("names")
    if isinstance(names, list):
        sep_values.extend(names)
    sep_values.append(system.get("sys_name"))
    for value in sep_values:
        if value is None:
            continue
        mac = cisco_sep_mac(str(value))
        if mac is not None:
            sep_macs.add(mac)

    groups = {
        "serial": serials,
        "engine": set(),
        "chassis": set(),
        "sep_mac": sep_macs,
    }
    engine = _identity_text(system.get("snmp_engine_id"))
    if engine:
        groups["engine"].add(engine)
    chassis = _identity_text(host.get("chassis_id"))
    if chassis:
        groups["chassis"].add(chassis)
    return groups


def _address_tokens(host: Mapping[str, Any]) -> set[str]:
    addresses = host.get("addresses")
    if not isinstance(addresses, Mapping):
        return set()
    result: set[str] = set()
    for family in ("ipv4", "ipv6"):
        values = addresses.get(family)
        if not isinstance(values, list):
            continue
        for value in values:
            normalized = _norm_address(value)
            if normalized:
                result.add(f"{family}:{normalized}")
    return result


def _name_tokens(host: Mapping[str, Any]) -> set[str]:
    values: list[object] = [host.get("preferred_name"), host.get("snmp_sysname")]
    names = host.get("names")
    if isinstance(names, list):
        values.extend(names)
    system = _system(host)
    values.append(system.get("sys_name"))
    result: set[str] = set()
    for value in values:
        if value is None:
            continue
        normalized = normalize_identity_name(str(value))
        if normalized is None:
            continue
        result.add(f"name:{normalized}")
    return result


@dataclass(frozen=True, slots=True)
class _HostIdentity:
    """Precomputed identity evidence for one host record.

    A discovery document can contain thousands of hosts. Rebuilding these sets for
    every possible A/B pair made the 0.30.0 matcher quadratic even when every host
    had an obvious unique identity. Keep normalized evidence beside the host so each
    value is parsed once per comparison instead.
    """

    host: dict[str, Any]
    host_id: int
    physical_groups: dict[str, frozenset[str]]
    physical: frozenset[str]
    addresses: frozenset[str]
    names: frozenset[str]

    def tokens(self, tier: EvidenceTier) -> frozenset[str]:
        """Return normalized tokens for one evidence tier."""

        if tier == "physical":
            return self.physical
        if tier == "address":
            return self.addresses
        return self.names


@dataclass(slots=True)
class _IdentityCatalog:
    """Host identities plus reverse indexes used for near-linear pairing."""

    records: dict[int, _HostIdentity]
    indexes: dict[EvidenceTier, dict[str, set[int]]]

    @classmethod
    def build(cls, hosts: Sequence[dict[str, Any]]) -> _IdentityCatalog:
        """Normalize each host once and build token-to-host reverse indexes."""

        records: dict[int, _HostIdentity] = {}
        indexes: dict[EvidenceTier, dict[str, set[int]]] = {
            "physical": defaultdict(set),
            "address": defaultdict(set),
            "name": defaultdict(set),
        }
        for host in hosts:
            identity = _build_host_identity(host)
            records[identity.host_id] = identity
            for tier in _EVIDENCE_TIERS:
                for token in identity.tokens(tier):
                    indexes[tier][token].add(identity.host_id)
        return cls(records=records, indexes=indexes)

    def remove(self, host_id: int) -> None:
        """Remove one paired host from the active reverse indexes."""

        identity = self.records[host_id]
        for tier in _EVIDENCE_TIERS:
            for token in identity.tokens(tier):
                owners = self.indexes[tier].get(token)
                if owners is None:
                    continue
                owners.discard(host_id)
                if not owners:
                    del self.indexes[tier][token]


def _build_host_identity(host: dict[str, Any]) -> _HostIdentity:
    """Precompute normalized physical, address, and name evidence for one host."""

    raw_groups = _physical_groups(host)
    groups = {key: frozenset(values) for key, values in raw_groups.items()}
    physical = frozenset(f"{kind}:{value}" for kind, values in groups.items() for value in values)
    return _HostIdentity(
        host=host,
        host_id=int(host["id"]),
        physical_groups=groups,
        physical=physical,
        addresses=frozenset(_address_tokens(host)),
        names=frozenset(_name_tokens(host)),
    )


def _complete_managed_projection(host: Mapping[str, Any]) -> bool:
    """Return whether a host is eligible for conservative duplicate folding."""

    return (
        str(host.get("classification") or "").casefold() == "managed_device"
        and str(host.get("state") or "").casefold() == "complete"
        and bool(str(host.get("queried_as") or "").strip())
    )


def _projection_logical_names(host: Mapping[str, Any]) -> frozenset[str]:
    """Return direct normalized names for one complete managed projection.

    Only the device's own SNMP name and the selected compatibility presentation
    participate. DNS and neighbor-advertised aliases remain useful evidence, but
    they are too broad for destructive within-run compatibility folding.
    """

    system = _system(host)
    return frozenset(
        normalized
        for value in (
            system.get("sys_name"),
            host.get("snmp_sysname"),
            host.get("preferred_name"),
        )
        if value is not None
        if (normalized := normalize_identity_name(str(value))) is not None
    )


def _normalized_name_sets_compatible(left: frozenset[str], right: frozenset[str]) -> bool:
    """Return whether exact or guarded short/FQDN names can be one system."""

    if left & right:
        return True
    for left_name in left:
        for right_name in right:
            left_short = "." not in left_name
            right_short = "." not in right_name
            if left_short == right_short:
                continue
            if left_short and right_name.startswith(left_name + "."):
                return True
            if right_short and left_name.startswith(right_name + "."):
                return True
    return False


def _projection_duplicate_components(
    hosts: Sequence[dict[str, Any]],
) -> list[tuple[str, list[int], list[str]]]:
    """Find duplicate complete managed rows by direct name plus shared address.

    A shared physical serial is deliberately insufficient because Nexus VDCs on
    one chassis expose the same container identity. Compatible direct logical
    names, at least one shared host-eligible address, and absence of hard identity
    conflicts are all required. One short name may match the same left-most FQDN
    component, but two FQDNs never match merely by suffix removal.
    """

    identities: dict[int, _HostIdentity] = {}
    logical_names: dict[int, frozenset[str]] = {}
    for host in hosts:
        host_id = host.get("id")
        names = _projection_logical_names(host)
        if (
            _complete_managed_projection(host)
            and isinstance(host_id, int)
            and not isinstance(host_id, bool)
            and names
        ):
            identities[host_id] = _build_host_identity(host)
            logical_names[host_id] = names

    address_owners: dict[str, list[int]] = defaultdict(list)
    for host_id, identity in identities.items():
        for address in identity.addresses:
            address_owners[address].append(host_id)

    adjacency: dict[int, set[int]] = defaultdict(set)
    edge_addresses: dict[tuple[int, int], set[str]] = defaultdict(set)
    checked: set[tuple[int, int]] = set()
    for host_ids in address_owners.values():
        ordered = sorted(set(host_ids))
        for index, left_id in enumerate(ordered):
            left = identities[left_id]
            for right_id in ordered[index + 1 :]:
                pair = (left_id, right_id)
                if pair in checked:
                    continue
                checked.add(pair)
                right = identities[right_id]
                shared_addresses = left.addresses & right.addresses
                if (
                    not shared_addresses
                    or not _normalized_name_sets_compatible(
                        logical_names[left_id], logical_names[right_id]
                    )
                    or _identity_conflict(left, right)
                ):
                    continue
                adjacency[left_id].add(right_id)
                adjacency[right_id].add(left_id)
                edge_addresses[pair].update(shared_addresses)

    components: list[tuple[str, list[int], list[str]]] = []
    seen: set[int] = set()
    for start in sorted(adjacency):
        if start in seen:
            continue
        stack = [start]
        seen.add(start)
        members: list[int] = []
        while stack:
            current = stack.pop()
            members.append(current)
            for neighbor in sorted(adjacency.get(current, set())):
                if neighbor not in seen:
                    seen.add(neighbor)
                    stack.append(neighbor)
        if len(members) < 2:
            continue
        ordered_members = sorted(members)
        # A sparse short-name row can bridge two incompatible FQDNs, just as a
        # sparse identity row can bridge contradictory serials. Reject the whole
        # component rather than choosing either side arbitrarily.
        if any(
            not _normalized_name_sets_compatible(logical_names[left_id], logical_names[right_id])
            or _identity_conflict(identities[left_id], identities[right_id])
            for index, left_id in enumerate(ordered_members)
            for right_id in ordered_members[index + 1 :]
        ):
            continue
        addresses = sorted(
            {
                value
                for index, left_id in enumerate(ordered_members)
                for right_id in ordered_members[index + 1 :]
                for value in edge_addresses.get((left_id, right_id), set())
            }
        )
        all_names = {name for member_id in ordered_members for name in logical_names[member_id]}
        logical_name = min(all_names, key=lambda value: ("." not in value, value))
        components.append((logical_name, ordered_members, addresses))
    return components


def _projection_winner(hosts: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Choose a deterministic, evidence-rich representative for one component."""

    def rank(host: dict[str, Any]) -> tuple[int, int, int, int]:
        identity = _build_host_identity(host)
        return (
            len(identity.names) + len(identity.addresses) + len(identity.physical),
            int(bool(host.get("is_seed"))),
            len(host.get("learned_neighbors") or []),
            -int(host["id"]),
        )

    return max(hosts, key=rank)


def _merge_unique_list(values: Iterable[Any]) -> list[Any]:
    """Return stable unique JSON-compatible values without assuming hashability."""

    result: list[Any] = []
    seen: set[str] = set()
    for value in values:
        fingerprint = stable_fingerprint(_stable_value(value))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(copy.deepcopy(value))
    return result


def _merge_projection_hosts(
    members: Sequence[dict[str, Any]], winner: dict[str, Any]
) -> dict[str, Any]:
    """Merge corroborated compatibility rows without changing raw graph evidence."""

    merged = copy.deepcopy(winner)
    for field in ("names", "tags", "icmp"):
        merged[field] = _merge_unique_list(
            value
            for member in members
            for value in (member.get(field) if isinstance(member.get(field), list) else [])
        )

    merged_addresses: dict[str, list[str]] = {}
    for family in ("ipv4", "ipv6"):
        merged_addresses[family] = sorted(
            {
                str(value)
                for member in members
                for value in (
                    member.get("addresses", {}).get(family, [])
                    if isinstance(member.get("addresses"), Mapping)
                    and isinstance(member.get("addresses", {}).get(family), list)
                    else []
                )
            }
        )
    merged["addresses"] = merged_addresses

    for section in ("learned_neighbors", "observed_by_neighbors"):
        merged[section] = [
            copy.deepcopy(row)
            for member in members
            for row in (member.get(section) if isinstance(member.get(section), list) else [])
            if isinstance(row, Mapping)
        ]

    winner_system = merged.get("system")
    winner_system = dict(winner_system) if isinstance(winner_system, Mapping) else {}
    stack_members = _merge_unique_list(
        value
        for member in members
        for value in (
            member.get("system", {}).get("stack_members", [])
            if isinstance(member.get("system"), Mapping)
            and isinstance(member.get("system", {}).get("stack_members"), list)
            else []
        )
    )
    if stack_members:
        winner_system["stack_members"] = stack_members
    for member in members:
        system = member.get("system")
        if not isinstance(system, Mapping):
            continue
        for key, value in system.items():
            if key == "stack_members":
                continue
            current = winner_system.get(key)
            if (
                current is None or current == "" or current == [] or current == {}
            ) and value not in {None, ""}:
                winner_system[key] = copy.deepcopy(value)
    merged["system"] = winner_system
    return merged


def _merge_projection_coverage(
    rows: Sequence[_HostCollectionCoverage],
) -> _HostCollectionCoverage:
    """Combine duplicate collection paths, preferring any complete table path."""

    if not rows:
        return _COMPLETE_COLLECTION
    if len(rows) == 1:
        # Canonicalization also passes ordinary one-to-one hosts through this
        # helper. Preserve their exact schema-8 semantic subtable boundaries;
        # rebuilding only aggregate fields would silently discard the
        # remote-neighbor/local-port/management-address distinction.
        return rows[0]

    def merge_dimension(
        names: Sequence[str],
        *,
        status_getter: Callable[[_HostCollectionCoverage, str], str | None],
        message_getter: Callable[[_HostCollectionCoverage, str], str | None],
        source_getter: Callable[[_HostCollectionCoverage, str], str],
    ) -> tuple[
        tuple[tuple[str, str], ...],
        tuple[tuple[str, str], ...],
        tuple[tuple[str, str], ...],
    ]:
        """Merge one semantic coverage dimension across duplicate projections."""

        statuses: list[tuple[str, str]] = []
        messages: list[tuple[str, str]] = []
        sources: list[tuple[str, str]] = []
        for name in sorted(set(names)):
            candidates = [
                (status_getter(row, name), row)
                for row in rows
                if status_getter(row, name) is not None
            ]
            if not candidates:
                continue
            selected_status = (
                "complete"
                if any(status == "complete" for status, _row in candidates)
                else next(
                    (status for status, _row in candidates if status != "not_attempted"),
                    "not_attempted",
                )
            )
            selected_row = next(row for status, row in candidates if status == selected_status)
            statuses.append((name, selected_status))
            message = message_getter(selected_row, name)
            if message:
                messages.append((name, message))
            sources.append((name, source_getter(selected_row, name)))
        return tuple(statuses), tuple(messages), tuple(sources)

    table_names = sorted({name for row in rows for name, _status in row.table_statuses})
    statuses: list[tuple[str, str]] = []
    row_counts: list[tuple[str, int]] = []
    messages: list[tuple[str, str]] = []
    for table in table_names:
        values = [row.status_for(table) for row in rows]
        concrete = [value for value in values if value is not None]
        status = "complete" if "complete" in concrete else concrete[0] if concrete else "unknown"
        statuses.append((table, status))
        complete_counts = [
            row.row_count_for(table)
            for row in rows
            if row.status_for(table) == "complete" and row.row_count_for(table) is not None
        ]
        if complete_counts:
            # Duplicate projections are alternative successful observations of
            # one logical system.  Preserve the richest complete snapshot for
            # optional-inventory confidence while leaving count differences in
            # the separate collection dimension.
            row_counts.append((table, max(complete_counts)))
        if status != "complete":
            message = next(
                (row.message_for(table) for row in rows if row.message_for(table)),
                None,
            )
            if message:
                messages.append((table, message))
    state_priority = {
        "complete": 0,
        "failed": 1,
        "no_query": 2,
        "out_of_scope": 3,
    }
    host_state = min(
        (row.host_state for row in rows),
        key=lambda value: state_priority.get(value, 99),
    )
    failed_protocols = (
        frozenset.intersection(*(row.failed_protocols for row in rows)) if rows else frozenset()
    )
    unresolved = (
        frozenset.intersection(*(row.unresolved_interface_protocols for row in rows))
        if rows
        else frozenset()
    )
    neighbor_statuses, neighbor_messages, neighbor_sources = merge_dimension(
        [name for row in rows for name, _status in row.neighbor_statuses],
        status_getter=lambda row, name: row.neighbor_status_for(name),
        message_getter=lambda row, name: row.neighbor_message_for(name),
        source_getter=lambda row, name: row.neighbor_source_for(name),
    )
    interface_statuses, interface_messages, interface_sources = merge_dimension(
        [name for row in rows for name, _status in row.interface_statuses],
        status_getter=lambda row, name: row.interface_status_for(name),
        message_getter=lambda row, name: row.interface_message_for(name),
        source_getter=lambda row, name: row.interface_source_for(name),
    )
    management_statuses, management_messages, management_sources = merge_dimension(
        [name for row in rows for name, _status in row.management_address_statuses],
        status_getter=lambda row, name: row.management_address_status_for(name),
        message_getter=lambda row, name: row.management_address_message_for(name),
        source_getter=lambda row, name: row.management_address_source_for(name),
    )
    return _HostCollectionCoverage(
        host_state=host_state,
        query_disposition=(
            "queried_complete"
            if any(row.query_disposition == "queried_complete" for row in rows)
            else rows[0].query_disposition
        ),
        all_neighbors_incomplete=all(row.all_neighbors_incomplete for row in rows),
        failed_protocols=failed_protocols,
        unresolved_interface_protocols=unresolved,
        table_statuses=tuple(statuses),
        table_row_counts=tuple(row_counts),
        table_messages=tuple(messages),
        neighbor_statuses=neighbor_statuses,
        neighbor_messages=neighbor_messages,
        neighbor_sources=neighbor_sources,
        interface_statuses=interface_statuses,
        interface_messages=interface_messages,
        interface_sources=interface_sources,
        management_address_statuses=management_statuses,
        management_address_messages=management_messages,
        management_address_sources=management_sources,
        reasons=tuple(dict.fromkeys(reason for row in rows for reason in row.reasons)),
    )


def _canonicalize_compatibility_projection(
    document: DiscoveryDocument,
    coverage: Mapping[int, _HostCollectionCoverage],
) -> _CompatibilityProjection:
    """Fold uniquely corroborated duplicate managed rows for macro comparison."""

    raw_hosts = document.hosts
    components = _projection_duplicate_components(raw_hosts)
    id_map = {
        int(host["id"]): int(host["id"])
        for host in raw_hosts
        if isinstance(host.get("id"), int) and not isinstance(host.get("id"), bool)
    }
    groups: list[dict[str, Any]] = []
    members_by_id: dict[int, tuple[int, ...]] = {host_id: (host_id,) for host_id in id_map}
    group_by_member: dict[int, tuple[int, ...]] = {}
    winner_by_group: dict[tuple[int, ...], dict[str, Any]] = {}
    hosts_by_id = {int(host["id"]): host for host in raw_hosts}
    for logical_name, member_ids, shared_addresses in components:
        members = [hosts_by_id[host_id] for host_id in member_ids]
        winner = _projection_winner(members)
        canonical_id = int(winner["id"])
        member_tuple = tuple(member_ids)
        winner_by_group[member_tuple] = _merge_projection_hosts(members, winner)
        members_by_id[canonical_id] = member_tuple
        for member_id in member_ids:
            id_map[member_id] = canonical_id
            group_by_member[member_id] = member_tuple
        groups.append(
            {
                "canonical_id": canonical_id,
                "absorbed_ids": [
                    member_id for member_id in member_ids if member_id != canonical_id
                ],
                "preferred_name": winner.get("preferred_name"),
                "logical_name": logical_name,
                "shared_addresses": shared_addresses,
                "reason": "compatible direct logical names plus shared management address",
            }
        )

    canonical_hosts: list[dict[str, Any]] = []
    emitted_groups: set[tuple[int, ...]] = set()
    for host in raw_hosts:
        host_id = int(host["id"])
        group = group_by_member.get(host_id)
        if group is None:
            canonical_hosts.append(host)
            continue
        if group in emitted_groups:
            continue
        canonical_hosts.append(winner_by_group[group])
        emitted_groups.add(group)

    for host in canonical_hosts:
        for section in ("learned_neighbors", "observed_by_neighbors"):
            rows = host.get(section)
            if not isinstance(rows, list):
                continue
            deduplicated: dict[str, dict[str, Any]] = {}
            for raw in rows:
                if not isinstance(raw, Mapping):
                    continue
                row = copy.deepcopy(dict(raw))
                remote_id = row.get("host_ref")
                if isinstance(remote_id, int) and not isinstance(remote_id, bool):
                    row["host_ref"] = id_map.get(remote_id, remote_id)
                fingerprint = stable_fingerprint(
                    {
                        "host_ref": row.get("host_ref"),
                        "neighbor": _normalize_neighbor(row),
                    }
                )
                deduplicated.setdefault(fingerprint, row)
            host[section] = [deduplicated[key] for key in sorted(deduplicated)]

    canonical_coverage: dict[int, _HostCollectionCoverage] = {}
    coverage_groups: dict[int, list[_HostCollectionCoverage]] = defaultdict(list)
    for host_id, row in coverage.items():
        coverage_groups[id_map.get(host_id, host_id)].append(row)
    for canonical_id, rows in coverage_groups.items():
        canonical_coverage[canonical_id] = _merge_projection_coverage(rows)

    payload = dict(document.payload)
    payload["hosts"] = canonical_hosts
    canonical_document = DiscoveryDocument(
        path=document.path,
        payload=payload,
        hosts=canonical_hosts,
        hosts_by_id={int(host["id"]): host for host in canonical_hosts},
    )
    return _CompatibilityProjection(
        document=canonical_document,
        coverage=canonical_coverage,
        id_map=id_map,
        members_by_id=members_by_id,
        groups=tuple(sorted(groups, key=lambda item: int(item["canonical_id"]))),
        raw_host_count=len(raw_hosts),
    )


def _shared_logical_evidence(
    a: _HostIdentity, b: _HostIdentity
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return shared normalized name and address evidence for logical identity.

    Discovery can represent one logical device with several physical observations.
    Cisco Nexus VDCs are the important production example: several VDCs share one
    chassis serial, while one VDC can expose different LLDP chassis MACs on different
    links.  Exact agreement on both a logical name and a management-address token is
    therefore the corroboration used to distinguish the logical host from its shared
    physical container.
    """

    return tuple(sorted(a.names & b.names)), tuple(sorted(a.addresses & b.addresses))


def _name_token_sets_compatible(left: frozenset[str], right: frozenset[str]) -> bool:
    """Return whether direct normalized name tokens can describe one host."""

    return _normalized_name_sets_compatible(
        frozenset(value.removeprefix("name:") for value in left),
        frozenset(value.removeprefix("name:") for value in right),
    )


def _identity_conflict(a: _HostIdentity, b: _HostIdentity) -> bool:
    """Return true when durable identity evidence contradicts a host pairing.

    Serial and SNMP-engine conflicts remain hard conflicts. Chassis IDs are normally
    durable too, but discovery permits a chassis-only disagreement when either exact
    logical name plus management address agrees or both sides encode the same strict
    Cisco SEP MAC. Mirror those boundaries here so diff does not split Nexus VDCs or
    Cisco phones/video endpoints because their representative chassis evidence changed.
    """

    for key in ("serial", "engine", "sep_mac"):
        if (
            a.physical_groups[key]
            and b.physical_groups[key]
            and a.physical_groups[key].isdisjoint(b.physical_groups[key])
        ):
            return True

    # A shared address is weak evidence when the two records also carry
    # incompatible direct names and no strong physical identity agrees. This
    # protects comparisons of schema-v5 files whose address lists can include a
    # DNS frontend, overlapping private value, or repeated vendor default.
    if (
        a.addresses & b.addresses
        and a.names
        and b.names
        and not (a.physical & b.physical)
        and not _name_token_sets_compatible(a.names, b.names)
    ):
        return True

    a_chassis = a.physical_groups["chassis"]
    b_chassis = b.physical_groups["chassis"]
    if a_chassis and b_chassis and a_chassis.isdisjoint(b_chassis):
        shared_sep_macs = a.physical_groups["sep_mac"] & b.physical_groups["sep_mac"]
        shared_names, shared_addresses = _shared_logical_evidence(a, b)
        if not shared_sep_macs and not (shared_names and shared_addresses):
            return True
    return False


def _refine_shared_physical_candidates(
    identity: _HostIdentity,
    candidate_ids: set[int],
    other: _IdentityCatalog,
) -> set[int]:
    """Narrow non-unique physical-container matches with logical evidence.

    A physical serial is usually an excellent host key, but on systems such as Cisco
    Nexus with VDCs the same chassis serial legitimately belongs to several logical
    hosts.  When a physical lookup returns more than one candidate, keep only
    candidates that also share at least one normalized name and one management
    address.  If that corroboration is still non-unique, return every corroborated
    candidate and let the reciprocal-uniqueness rule report ambiguity rather than
    guessing.

    The refinement never broadens the physical candidate set and never overrides a
    serial or SNMP-engine conflict.
    """

    if len(candidate_ids) <= 1:
        return candidate_ids
    corroborated: set[int] = set()
    for host_id in candidate_ids:
        candidate = other.records[host_id]
        shared_names, shared_addresses = _shared_logical_evidence(identity, candidate)
        if shared_names and shared_addresses and not _identity_conflict(identity, candidate):
            corroborated.add(host_id)
    return corroborated or candidate_ids


def _refine_shared_address_candidates(
    identity: _HostIdentity,
    candidate_ids: set[int],
    other: _IdentityCatalog,
) -> set[int]:
    """Narrow a repeated-address candidate set with exact logical-name evidence.

    Discovery 0.31.4 can retain one observed address on more than one host rather
    than assigning it to whichever host was encountered first.  When that value
    is contested across runs, an exact normalized name can still select one
    reciprocal candidate.  Without unique corroboration, keep the full set and
    let ordinary ambiguity handling refuse to guess.
    """

    if len(candidate_ids) <= 1 or not identity.names:
        return candidate_ids
    corroborated = {
        host_id
        for host_id in candidate_ids
        if identity.names & other.records[host_id].names
        and not _identity_conflict(identity, other.records[host_id])
    }
    return corroborated or candidate_ids


def _indexed_candidates(
    identity: _HostIdentity,
    other: _IdentityCatalog,
) -> list[_PairCandidate]:
    """Return strongest-tier candidates using reverse indexes, not a full scan.

    Candidate IDs are obtained by looking up only the selected host's tokens. This
    changes the common unique-identity case from every-host-vs-every-host work to
    work proportional to the number of hosts plus the number of actual token matches.
    Non-unique physical-container candidates are narrowed by shared logical name and
    management-address evidence before reciprocal uniqueness is evaluated.
    """

    for tier in _EVIDENCE_TIERS:
        tokens = identity.tokens(tier)
        if not tokens:
            continue
        candidate_ids: set[int] = set()
        for token in tokens:
            candidate_ids.update(other.indexes[tier].get(token, ()))
        if not candidate_ids:
            continue
        used_logical_refinement = False
        if tier == "physical":
            original_candidate_ids = set(candidate_ids)
            candidate_ids = _refine_shared_physical_candidates(identity, candidate_ids, other)
            used_logical_refinement = candidate_ids != original_candidate_ids
        elif tier == "address":
            original_candidate_ids = set(candidate_ids)
            candidate_ids = _refine_shared_address_candidates(identity, candidate_ids, other)
            used_logical_refinement = candidate_ids != original_candidate_ids
        candidates: list[_PairCandidate] = []
        for host_id in sorted(candidate_ids):
            candidate = other.records[host_id]
            evidence = set(tokens & candidate.tokens(tier))
            if tier in {"physical", "address"} and used_logical_refinement:
                shared_names, shared_addresses = _shared_logical_evidence(identity, candidate)
                # Include corroborating logical tokens only when they actually
                # narrowed a shared physical-container candidate set.  Ordinary
                # physical matches keep the existing diff JSON evidence shape.
                evidence.update(shared_names)
                evidence.update(shared_addresses)
            candidates.append(
                _PairCandidate(
                    candidate.host,
                    tier,
                    tuple(sorted(evidence)),
                    _identity_conflict(identity, candidate),
                )
            )
        return candidates
    return []


def _learned_neighbor_rows(host: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return canonical learned-neighbor dictionaries from one host record."""

    values = host.get("learned_neighbors")
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def _edge_context_pair_ids(
    source_pairs: Sequence[HostPair],
    remaining_a: Mapping[int, _HostIdentity],
    remaining_b: Mapping[int, _HostIdentity],
) -> list[tuple[int, int, tuple[str, ...]]]:
    """Find reciprocal anonymous-host pairs through already paired observers.

    A host with no globally useful name, address, serial, or chassis token can
    still be identified conservatively when the same already-paired switch sees
    it on the same local port with the same exact typed endpoint MAC.  This is a
    topology-scoped association only; it does not promote that MAC into a global
    alias or match across a different observing port.
    """

    a_candidates: dict[int, set[int]] = defaultdict(set)
    b_candidates: dict[int, set[int]] = defaultdict(set)
    evidence: dict[tuple[int, int], set[str]] = defaultdict(set)

    for source_pair in source_pairs:
        a_source_id = int(source_pair.a["id"])
        b_source_id = int(source_pair.b["id"])
        right_index: dict[tuple[str, str], set[int]] = defaultdict(set)
        for row in _learned_neighbor_rows(source_pair.b):
            remote_id = row.get("host_ref")
            if not isinstance(remote_id, int) or remote_id not in remaining_b:
                continue
            local_tokens = _neighbor_local_tokens(row)
            if not local_tokens:
                continue
            for local_token in local_tokens:
                for token in _neighbor_strong_edge_tokens(row):
                    right_index[(local_token, token)].add(remote_id)

        for row in _learned_neighbor_rows(source_pair.a):
            a_remote_id = row.get("host_ref")
            if not isinstance(a_remote_id, int) or a_remote_id not in remaining_a:
                continue
            local_tokens = _neighbor_local_tokens(row)
            if not local_tokens:
                continue
            for local_token in local_tokens:
                for token in _neighbor_strong_edge_tokens(row):
                    for b_remote_id in right_index.get((local_token, token), ()):
                        a_candidates[a_remote_id].add(b_remote_id)
                        b_candidates[b_remote_id].add(a_remote_id)
                        evidence[(a_remote_id, b_remote_id)].update(
                            {
                                f"observer:{a_source_id}->{b_source_id}",
                                f"local:{local_token}",
                                token,
                            }
                        )

    pairs: list[tuple[int, int, tuple[str, ...]]] = []
    for a_id, candidate_ids in sorted(a_candidates.items()):
        if len(candidate_ids) != 1:
            continue
        b_id = next(iter(candidate_ids))
        if b_candidates.get(b_id) != {a_id}:
            continue
        if _identity_conflict(remaining_a[a_id], remaining_b[b_id]):
            continue
        pairs.append((a_id, b_id, tuple(sorted(evidence[(a_id, b_id)]))))
    return pairs


def pair_hosts(a_hosts: Sequence[dict[str, Any]], b_hosts: Sequence[dict[str, Any]]) -> HostPairing:
    """Pair hosts one-to-one using indexed physical, address, then name evidence.

    Automatic pairing retains the reciprocal-uniqueness rule at the strongest
    evidence tier available to each remaining record. Shared physical-container
    evidence can be narrowed by exact logical name plus management-address agreement
    so Nexus VDCs remain distinct while still pairing across runs. Serial and SNMP
    engine conflicts remain hard conflicts; a chassis-only mismatch may be overridden
    by that same name-plus-address corroboration. Reverse indexes avoid a Cartesian
    scan on large inventories.
    """

    a_catalog = _IdentityCatalog.build(a_hosts)
    b_catalog = _IdentityCatalog.build(b_hosts)
    remaining_a = dict(a_catalog.records)
    remaining_b = dict(b_catalog.records)
    pairs: list[HostPair] = []

    while True:
        a_candidates = {
            host_id: _indexed_candidates(identity, b_catalog)
            for host_id, identity in remaining_a.items()
        }
        b_candidates = {
            host_id: _indexed_candidates(identity, a_catalog)
            for host_id, identity in remaining_b.items()
        }
        new_pairs: list[tuple[int, int, _PairCandidate]] = []
        for a_id, candidates in a_candidates.items():
            if len(candidates) != 1 or candidates[0].conflicting_identity:
                continue
            candidate = candidates[0]
            b_id = int(candidate.host["id"])
            reverse = b_candidates.get(b_id, [])
            if (
                len(reverse) == 1
                and not reverse[0].conflicting_identity
                and int(reverse[0].host["id"]) == a_id
            ):
                new_pairs.append((a_id, b_id, candidate))
        if not new_pairs:
            break
        for a_id, b_id, candidate in new_pairs:
            a_identity = remaining_a.pop(a_id, None)
            b_identity = remaining_b.pop(b_id, None)
            if a_identity is None or b_identity is None:
                continue
            a_catalog.remove(a_id)
            b_catalog.remove(b_id)
            pairs.append(
                HostPair(a_identity.host, b_identity.host, candidate.tier, candidate.evidence)
            )

    # A second conservative pass can pair otherwise anonymous hosts through the
    # topology reported by already paired observers.  Repeat to a fixed point so
    # a newly paired managed intermediary can itself provide context, while every
    # association still requires reciprocal uniqueness.
    while True:
        contextual = _edge_context_pair_ids(pairs, remaining_a, remaining_b)
        if not contextual:
            break
        for a_id, b_id, evidence in contextual:
            a_identity = remaining_a.pop(a_id, None)
            b_identity = remaining_b.pop(b_id, None)
            if a_identity is None or b_identity is None:
                continue
            a_catalog.remove(a_id)
            b_catalog.remove(b_id)
            pairs.append(
                HostPair(
                    a_identity.host,
                    b_identity.host,
                    "edge_context",
                    evidence,
                )
            )

    ambiguous: list[AmbiguousHostMatch] = []
    referenced_b: set[int] = set()
    for a_identity in sorted(remaining_a.values(), key=lambda item: item.host_id):
        candidates = _indexed_candidates(a_identity, b_catalog)
        if not candidates:
            continue
        referenced_b.update(int(item.host["id"]) for item in candidates)
        ambiguous.append(
            AmbiguousHostMatch(
                a=a_identity.host,
                candidates=tuple(
                    sorted((item.host for item in candidates), key=lambda item: int(item["id"]))
                ),
                tier=candidates[0].tier,
                conflicting_identity=any(item.conflicting_identity for item in candidates),
            )
        )

    ambiguous_a_ids = {int(item.a["id"]) for item in ambiguous}
    a_only = tuple(
        identity.host
        for identity in sorted(remaining_a.values(), key=lambda item: item.host_id)
        if identity.host_id not in ambiguous_a_ids
    )
    b_only = tuple(
        identity.host
        for identity in sorted(remaining_b.values(), key=lambda item: item.host_id)
        if identity.host_id not in referenced_b
    )
    pairs.sort(key=lambda item: int(item.a["id"]))
    return HostPairing(tuple(pairs), tuple(ambiguous), a_only, b_only)


def _stable_value(value: Any) -> Any:
    """Normalize JSON values so set-like list ordering does not create false diffs."""

    if isinstance(value, Mapping):
        return {str(key): _stable_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_stable_value(item) for item in value]
        try:
            return sorted(
                normalized,
                key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False),
            )
        except TypeError:
            return normalized
    return value


def _member_key(member: Mapping[str, Any], position: int) -> str:
    """Choose the most durable available stack-member key."""

    serial = _norm_text(member.get("serial_number"))
    if serial:
        return f"serial={serial}"
    number = member.get("member_number")
    if number is not None:
        return f"member={number}"
    entity = member.get("entity_index")
    if entity is not None:
        return f"entity={entity}"
    name = _norm_text(member.get("name"))
    if name:
        return f"name={name}#{position}"
    return f"position={position}"


def _normalize_icmp(value: Any) -> dict[str, Any]:
    """Keep reachability outcome while dropping timestamp and RTT measurement noise."""

    if not isinstance(value, list):
        return {}
    result: dict[str, Any] = {}
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            continue
        address = _norm_address(item.get("address")) or str(item.get("address") or index)
        result[address] = {
            str(key): _stable_value(field)
            for key, field in item.items()
            if key not in {"timestamp", "rtt_ms", "address"}
        }
    return dict(sorted(result.items()))


def _normalize_stack_members(value: Any) -> dict[str, Any]:
    if not isinstance(value, list):
        return {}
    result: dict[str, Any] = {}
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            continue
        key = _member_key(item, index)
        record = {
            str(name): _stable_value(field)
            for name, field in item.items()
            if name not in _TIMESTAMP_KEYS and name != "uptime_seconds"
        }
        # Duplicate fallback keys are unusual but possible; retain both without
        # pretending they describe one physical member.
        unique = key
        suffix = 2
        while unique in result:
            unique = f"{key}#{suffix}"
            suffix += 1
        result[unique] = record
    return dict(sorted(result.items()))


def _normalize_host(host: Mapping[str, Any]) -> dict[str, Any]:
    """Return durable entity/attribute data for the physical-change dimension.

    Compatibility aliases, query route, collection coverage, retries, and table
    row counts are intentionally excluded. They remain available through the
    presentation and collection dimensions so observation drift cannot inflate
    the confirmed managed-host change count.
    """

    result: dict[str, Any] = {}
    for key, value in host.items():
        if key in _HOST_IGNORED_KEYS:
            continue
        if key == "system" and isinstance(value, Mapping):
            system: dict[str, Any] = {}
            for system_key, system_value in value.items():
                if system_key == "sys_uptime_ticks":
                    continue
                if system_key == "stack_members":
                    system[system_key] = _normalize_stack_members(system_value)
                elif system_key not in _TIMESTAMP_KEYS:
                    system[system_key] = _stable_value(system_value)
            result[key] = system
            continue
        if key == "snmp":
            # Credential selection, retry history, table row counts, and route
            # telemetry describe how this observation was collected. They remain
            # available under collection_coverage and run diagnostics, but do not
            # represent a persistent property of the physical/logical host.
            continue
        if key not in _TIMESTAMP_KEYS:
            result[key] = _stable_value(value)
    return result


def _normalize_host_presentation(host: Mapping[str, Any]) -> dict[str, Any]:
    """Return aliases and labels used to present a paired host.

    Recursive discovery order can move a link-local or protocol-observed alias
    between temporary projections. The canonical projection pass removes
    corroborated duplicates first; any residual alias difference is still useful
    evidence, but it is not a physical device-attribute change.
    """

    names = host.get("names")
    addresses = host.get("addresses")
    result: dict[str, Any] = {
        "preferred_name": str(host.get("preferred_name") or ""),
        "names": _stable_value(names if isinstance(names, list) else []),
        "addresses": _stable_value(addresses if isinstance(addresses, Mapping) else {}),
    }
    reason = host.get("classification_reason")
    if reason not in (None, "", []):
        result["classification_reason"] = _stable_value(reason)
    return result


def _without_collection_volatility(
    value: Any,
    *,
    include_timing: bool,
) -> Any:
    """Recursively remove non-semantic collection telemetry.

    Each discovery retains exact collector durations for troubleshooting.  They
    are ordinary wall-clock jitter rather than evidence that collection status,
    coverage, route, or retry behavior changed, so default cross-run comparison
    omits every ``duration_ms`` leaf.  Operators can explicitly include timing
    when diagnosing collector performance.
    """

    if isinstance(value, Mapping):
        return {
            str(key): _without_collection_volatility(item, include_timing=include_timing)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in _TIMESTAMP_KEYS and (include_timing or str(key) != "duration_ms")
        }
    if isinstance(value, list):
        return _stable_value(
            [_without_collection_volatility(item, include_timing=include_timing) for item in value]
        )
    return value


def _normalize_host_collection(
    host: Mapping[str, Any],
    *,
    include_timing: bool,
) -> dict[str, Any]:
    """Return query-route and collection facts without physical interpretation."""

    result: dict[str, Any] = {
        "state": str(host.get("state") or "").casefold(),
        "is_seed": bool(host.get("is_seed")),
        "queried_as": str(host.get("queried_as") or ""),
        "icmp": _normalize_icmp(host.get("icmp")),
    }
    snmp = host.get("snmp")
    if isinstance(snmp, Mapping):
        normalized_snmp: dict[str, Any] = {}
        for key in (
            "credential_source",
            "credential_profile",
            "credential_label",
            "credential_result",
            "collection_coverage",
        ):
            if key in snmp:
                normalized_snmp[key] = _without_collection_volatility(
                    snmp[key], include_timing=include_timing
                )
        sessions = snmp.get("adaptive_sessions")
        if isinstance(sessions, list):
            normalized_sessions: list[dict[str, Any]] = []
            for raw_session in sessions:
                if not isinstance(raw_session, Mapping):
                    continue
                session: dict[str, Any] = {
                    key: _without_collection_volatility(
                        raw_session[key], include_timing=include_timing
                    )
                    for key in (
                        "target",
                        "credential_profile",
                        "credential_route",
                        "degraded",
                        "total_retries_used",
                        "effective_timeout_seconds",
                        "effective_max_repetitions",
                        "effective_inter_pdu_delay_ms",
                    )
                    if key in raw_session
                }
                events = raw_session.get("events")
                if isinstance(events, list):
                    session["events"] = [
                        {
                            key: _without_collection_volatility(
                                event[key], include_timing=include_timing
                            )
                            for key in (
                                "collector",
                                "logical_operation",
                                "table_name",
                                "root_oid",
                                "category",
                                "retry_kind",
                                "final_outcome",
                            )
                            if key in event
                        }
                        for event in events
                        if isinstance(event, Mapping)
                    ]
                normalized_sessions.append(session)
            normalized_snmp["adaptive_sessions"] = _stable_value(normalized_sessions)
        result["snmp"] = normalized_snmp
    return result


def _compare_normalized_dimension(
    left: Mapping[str, Any], right: Mapping[str, Any]
) -> tuple[FieldDifference, ...]:
    """Compare one normalized host dimension as deterministic flattened fields."""

    a_fields = _flatten(left)
    b_fields = _flatten(right)
    return tuple(
        FieldDifference(path, a_fields.get(path), b_fields.get(path))
        for path in sorted(set(a_fields) | set(b_fields))
        if a_fields.get(path) != b_fields.get(path)
    )


def compare_host_presentation_fields(
    a: Mapping[str, Any], b: Mapping[str, Any]
) -> tuple[FieldDifference, ...]:
    """Compare aliases and labels separately from entity attributes."""

    return _compare_normalized_dimension(
        _normalize_host_presentation(a), _normalize_host_presentation(b)
    )


def compare_host_collection_fields(
    a: Mapping[str, Any],
    b: Mapping[str, Any],
    *,
    include_timing: bool = False,
) -> tuple[FieldDifference, ...]:
    """Compare collection/provenance facts separately from entity attributes.

    Args:
        a: Newer/A-side host record.
        b: Older/B-side host record.
        include_timing: Include collector ``duration_ms`` leaves.  False keeps
            default diffs semantic and stable while each source discovery still
            preserves its exact timings.
    """

    return _compare_normalized_dimension(
        _normalize_host_collection(a, include_timing=include_timing),
        _normalize_host_collection(b, include_timing=include_timing),
    )


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten normalized mappings into stable dotted paths for operator output."""

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        if not value and prefix:
            result[prefix] = {}
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else str(key)
            result.update(_flatten(value[key], child))
        return result
    return {prefix: value}


def _uptime_ticks(host: Mapping[str, Any]) -> int | None:
    value = _system(host).get("sys_uptime_ticks")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value)) if value is not None else None
    except ValueError:
        return None


def _member_uptime(host: Mapping[str, Any]) -> dict[str, int]:
    members = _system(host).get("stack_members")
    if not isinstance(members, list):
        return {}
    result: dict[str, int] = {}
    for index, member in enumerate(members):
        if not isinstance(member, Mapping):
            continue
        value = member.get("uptime_seconds")
        if isinstance(value, bool) or value is None:
            continue
        try:
            result[_member_key(member, index)] = int(value)
        except (TypeError, ValueError):
            continue
    return result


def _later_source_is_a(a_completed: datetime | None, b_completed: datetime | None) -> bool | None:
    if a_completed is None or b_completed is None or a_completed == b_completed:
        return None
    return a_completed > b_completed


def compare_host_fields(
    a: Mapping[str, Any],
    b: Mapping[str, Any],
    *,
    a_completed: datetime | None,
    b_completed: datetime | None,
    a_coverage: _HostCollectionCoverage = _COMPLETE_COLLECTION,
    b_coverage: _HostCollectionCoverage = _COMPLETE_COLLECTION,
) -> tuple[FieldDifference, ...]:
    """Compare normalized host fields and report uptime only as a reboot indicator."""

    left = _flatten(_normalize_host(a))
    right = _flatten(_normalize_host(b))
    differences: list[FieldDifference] = []
    for path in sorted(set(left) | set(right)):
        a_value = left.get(path)
        b_value = right.get(path)
        if a_value != b_value:
            kind = "changed"
            if path == "system.stack_members" or path.startswith("system.stack_members."):
                a_missing = a_value is None or a_value == {}
                b_missing = b_value is None or b_value == {}
                if a_missing and not a_coverage.authoritative_negative("entity"):
                    kind = "not_observed"
                elif b_missing and not b_coverage.authoritative_negative("entity"):
                    kind = "not_observed"
            differences.append(
                FieldDifference(
                    path,
                    a_value,
                    b_value,
                    kind,
                    "entity_mib" if path.startswith("system.stack_members") else None,
                )
            )

    later_is_a = _later_source_is_a(a_completed, b_completed)
    a_uptime = _uptime_ticks(a)
    b_uptime = _uptime_ticks(b)
    if later_is_a is not None and a_uptime is not None and b_uptime is not None:
        later = a_uptime if later_is_a else b_uptime
        older = b_uptime if later_is_a else a_uptime
        if later < older:
            differences.append(
                FieldDifference(
                    "system.sys_uptime_ticks (possible reboot)",
                    a_uptime,
                    b_uptime,
                    "reboot",
                )
            )

    a_members = _member_uptime(a)
    b_members = _member_uptime(b)
    if later_is_a is not None:
        for key in sorted(set(a_members) & set(b_members)):
            a_value = a_members[key]
            b_value = b_members[key]
            later = a_value if later_is_a else b_value
            older = b_value if later_is_a else a_value
            if later < older:
                differences.append(
                    FieldDifference(
                        f"system.stack_members.{key}.uptime_seconds (possible reboot)",
                        a_value,
                        b_value,
                        "reboot",
                    )
                )
    return tuple(differences)


def _neighbor_endpoint_key(
    neighbor: Mapping[str, Any], host_map: Mapping[int, int]
) -> tuple[str, int] | None:
    host_ref = neighbor.get("host_ref")
    if not isinstance(host_ref, int) or isinstance(host_ref, bool):
        return None
    mapped = host_map.get(host_ref)
    if mapped is None:
        return None
    local = str(
        neighbor.get("local_interface") or neighbor.get("local_interface_raw") or ""
    ).casefold()
    return local, mapped


def _neighbor_local_tokens(neighbor: Mapping[str, Any]) -> set[str]:
    """Return typed local-port tokens for cross-run edge reconciliation.

    A resolved interface name and its protocol table indexes can coexist in one
    row.  Retaining both lets a good run map a later unresolved ``ifIndex`` or
    ``lldpLocalPort`` back to the same physical port without ever equating those
    two numeric namespaces directly.
    """

    result: set[str] = set()
    local_value = neighbor.get("local_interface") or neighbor.get("local_interface_raw")
    if local_value is not None:
        text = str(local_value).strip()
        folded = text.casefold()
        if folded.startswith("ifindex:"):
            suffix = folded.split(":", 1)[1]
            if suffix.isdigit():
                result.add(f"ifindex:{int(suffix)}")
        elif folded.startswith("lldplocalport:"):
            suffix = folded.split(":", 1)[1]
            if suffix.isdigit():
                result.add(f"lldplocalport:{int(suffix)}")
        elif not text.isdigit() and text:
            result.add(f"name:{folded}")

    details = neighbor.get("details")
    if isinstance(details, Mapping):
        for key, value in details.items():
            suffix = str(key).rsplit(".", 1)[-1]
            if suffix not in {"ifindex", "local_ifindex", "local_port_num"}:
                continue
            try:
                number = int(value)
            except (TypeError, ValueError, OverflowError):
                continue
            namespace = "lldplocalport" if suffix == "local_port_num" else "ifindex"
            result.add(f"{namespace}:{number}")

    # Historical schema-v5 rows used a bare integer when mapping failed. Infer
    # its namespace only when the row carries the corresponding typed detail.
    if local_value is not None and str(local_value).strip().isdigit():
        number = int(str(local_value).strip())
        typed = {
            token for token in result if token in {f"ifindex:{number}", f"lldplocalport:{number}"}
        }
        result.update(typed)
    return result


def _neighbor_local_unresolved(neighbor: Mapping[str, Any]) -> bool:
    """Return whether a neighbor row lacks a resolved local interface name."""

    details = neighbor.get("details")
    if isinstance(details, Mapping) and details.get("local_interface_resolved") is False:
        return True
    value = neighbor.get("local_interface") or neighbor.get("local_interface_raw")
    if value is None:
        return True
    text = str(value).strip().casefold()
    return (
        not text
        or text.isdigit()
        or text.startswith("ifindex:")
        or text.startswith("lldplocalport:")
    )


def _neighbor_remote_port_key(neighbor: Mapping[str, Any]) -> str | None:
    """Return a normalized remote-port representation when one is present."""

    value = neighbor.get("remote_interface") or neighbor.get("remote_interface_raw")
    if value is None:
        return None
    text = str(value).strip().casefold()
    return text or None


def _combine_neighbor_rows(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Coalesce split protocol rows for one already-identified physical edge.

    This is a diff-only view.  It is used when one run has a merged CDP/LLDP row
    and the other run split those advertisements solely because local interface
    resolution failed.  Raw protocol details remain in the combined mapping.
    """

    if len(rows) == 1:
        return rows[0]
    preferred = next(
        (row for row in rows if _neighbor_protocols(row) & {"lldp", "lldpv2"}),
        rows[0],
    )
    result = dict(preferred)
    protocols: set[str] = set()
    addresses: list[Any] = []
    details: dict[str, Any] = {}
    for row in rows:
        protocols.update(_neighbor_protocols(row))
        values = row.get("observed_addresses")
        if isinstance(values, list):
            addresses.extend(values)
        row_details = row.get("details")
        if isinstance(row_details, Mapping):
            for key, value in row_details.items():
                details.setdefault(str(key), value)
    order = {"cdp": 0, "lldp": 1, "lldpv2": 2}
    result["protocols"] = sorted(protocols, key=lambda value: (order.get(value, 99), value))
    result["protocol_tag"] = f"[{','.join(result['protocols'])}]"
    result["observed_addresses"] = list(dict.fromkeys(addresses))
    result["details"] = details

    resolved = next((row for row in rows if not _neighbor_local_unresolved(row)), None)
    if resolved is not None:
        result["local_interface"] = resolved.get("local_interface")
        result["local_interface_raw"] = resolved.get("local_interface_raw")
    return result


def _can_coalesce_protocol_rows(
    a_item: Mapping[str, Any], candidates: Sequence[dict[str, Any]]
) -> bool:
    """Return whether candidates are the split form of one merged protocol row.

    Coalescing is valid only when the A-side row already represents multiple
    protocols and the disjoint candidate rows reproduce that exact protocol set.
    A single-protocol row beside separate CDP and LLDP rows must select its own
    protocol peer rather than consuming both physical-edge advertisements.
    """

    expected = _neighbor_protocols(a_item)
    if len(candidates) < 2 or len(expected) < 2:
        return False
    seen: set[str] = set()
    for item in candidates:
        protocols = _neighbor_protocols(item)
        if not protocols or seen & protocols:
            return False
        seen.update(protocols)
    return seen == expected


_MAC_TEXT = re.compile(r"(?i)^[0-9a-f]{2}(?P<sep>[:-])[0-9a-f]{2}(?:(?P=sep)[0-9a-f]{2}){4}$")
_MAC_DOTTED = re.compile(r"(?i)^[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}$")


def _normalized_mac(value: object) -> str | None:
    """Return canonical MAC text when ``value`` is an unambiguous MAC address."""

    if value is None:
        return None
    text = str(value).strip()
    if _MAC_TEXT.fullmatch(text):
        compact = text.replace(":", "").replace("-", "")
    elif _MAC_DOTTED.fullmatch(text):
        compact = text.replace(".", "")
    else:
        return None
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).lower()


def _modified_eui64_mac(value: object) -> str | None:
    """Recover a MAC only from the exact IPv6 modified-EUI-64 IID pattern.

    The IID must contain the inserted ``ff:fe`` octets.  This is a reversible
    encoding, unlike heuristic guesses based on arbitrary IPv6 suffixes, so it is
    suitable as same-edge corroboration without becoming a global host alias.
    """

    if value is None:
        return None
    try:
        address = ipaddress.IPv6Address(str(value).strip().strip("[]"))
    except ipaddress.AddressValueError:
        return None
    iid = address.packed[8:]
    if iid[3:5] != b"\xff\xfe":
        return None
    raw = bytes([iid[0] ^ 0x02, iid[1], iid[2], iid[5], iid[6], iid[7]])
    return raw.hex(":")


def _neighbor_strong_edge_tokens(neighbor: Mapping[str, Any]) -> set[str]:
    """Return strong endpoint tokens usable only after local-port agreement.

    These tokens intentionally do not participate in global host pairing.  They
    exist to correlate an otherwise-unpaired edge when two runs expose the same
    physical endpoint through different LLDP representations, such as a MAC Port
    ID in one run and its exact modified-EUI-64 IPv6 address in another.
    """

    result: set[str] = set()
    for key in ("remote_interface", "remote_interface_raw"):
        mac = _normalized_mac(neighbor.get(key))
        if mac:
            result.add(f"mac:{mac}")

    details = neighbor.get("details")
    if isinstance(details, Mapping):
        for key in (
            "chassis_id",
            "port_id",
            "lldp.chassis_id",
            "lldp.port_id",
        ):
            mac = _normalized_mac(details.get(key))
            if mac:
                result.add(f"mac:{mac}")

    addresses = neighbor.get("observed_addresses")
    if isinstance(addresses, list):
        for value in addresses:
            mac = _modified_eui64_mac(value)
            if mac:
                result.add(f"mac:{mac}")
    for key in ("name", "observed_name"):
        mac = _modified_eui64_mac(neighbor.get(key))
        if mac:
            result.add(f"mac:{mac}")
    return result


def _weak_move_identity(neighbor: Mapping[str, Any]) -> bool:
    """Return whether edge identity is too weak to prove a physical port move.

    Low-entropy locally assigned values are common in virtual appliances and can
    appear through several hypervisor uplinks.  They may correlate observations,
    but they do not prove that one physical endpoint moved between switch ports.
    """

    tokens = _neighbor_strong_edge_tokens(neighbor)
    macs = {token.removeprefix("mac:") for token in tokens if token.startswith("mac:")}
    if not macs:
        return True
    return all(weak_mobility_mac(mac) for mac in macs)


def _fallback_neighbor_candidate(
    a_item: Mapping[str, Any],
    right: list[dict[str, Any]],
    right_used: set[int],
) -> int | None:
    """Pair an unpaired remote host only with unique strong same-port evidence."""

    local_tokens = _neighbor_local_tokens(a_item)
    if not local_tokens:
        return None
    a_tokens = _neighbor_strong_edge_tokens(a_item)
    if not a_tokens:
        return None
    candidates: list[int] = []
    for index, b_item in enumerate(right):
        if index in right_used:
            continue
        if not (local_tokens & _neighbor_local_tokens(b_item)):
            continue
        if a_tokens & _neighbor_strong_edge_tokens(b_item):
            candidates.append(index)
    return candidates[0] if len(candidates) == 1 else None


def _coalesce_left_protocol_rows(
    primary_index: int,
    left: Sequence[dict[str, Any]],
    b_item: Mapping[str, Any],
    left_used: set[int],
    a_to_b_host_ids: Mapping[int, int],
) -> list[int]:
    """Return split A-side rows that reproduce one merged B-side edge.

    A failed local-interface map can keep CDP and LLDP observations separate even
    though a healthy comparison run contains one merged row.  The merged row
    retains each protocol's typed local index, so require every selected A row to
    intersect that typed evidence, map to the same canonical remote host, and
    contribute a disjoint part of the exact B-side protocol set.  Any duplicate
    protocol candidate makes the association ambiguous and leaves the rows alone.
    """

    expected = _neighbor_protocols(b_item)
    primary_protocols = _neighbor_protocols(left[primary_index])
    if len(expected) < 2 or primary_protocols == expected:
        return [primary_index]
    b_ref = b_item.get("host_ref")
    if not isinstance(b_ref, int) or isinstance(b_ref, bool):
        return [primary_index]
    b_local_tokens = _neighbor_local_tokens(b_item)
    if not b_local_tokens:
        return [primary_index]

    eligible: list[int] = []
    occurrences: dict[str, int] = defaultdict(int)
    for index, item in enumerate(left):
        if index in left_used:
            continue
        a_ref = item.get("host_ref")
        if not isinstance(a_ref, int) or isinstance(a_ref, bool):
            continue
        if a_to_b_host_ids.get(a_ref) != b_ref:
            continue
        protocols = _neighbor_protocols(item)
        if not protocols or not protocols <= expected:
            continue
        if not (_neighbor_local_tokens(item) & b_local_tokens):
            continue
        eligible.append(index)
        for protocol in protocols:
            occurrences[protocol] += 1

    if primary_index not in eligible:
        return [primary_index]
    if set(occurrences) != expected or any(count != 1 for count in occurrences.values()):
        return [primary_index]
    return sorted(eligible)


def _cross_local_neighbor_candidate(
    a_item: Mapping[str, Any],
    left: Sequence[dict[str, Any]],
    right: Sequence[dict[str, Any]],
    right_used: set[int],
    a_to_b_host_ids: Mapping[int, int],
) -> int | None:
    """Pair one unique endpoint across different local-port representations.

    This path is deliberately narrower than ordinary edge matching.  The remote
    canonical host must already be paired, each side must contain exactly one row
    for that relationship, and the endpoint must retain an exact remote-port or
    strong MAC token.  A resolved-to-resolved difference is then a port move;
    an unresolved numeric side is collection uncertainty instead.
    """

    a_ref = a_item.get("host_ref")
    if not isinstance(a_ref, int) or isinstance(a_ref, bool):
        return None
    mapped = a_to_b_host_ids.get(a_ref)
    if mapped is None:
        return None

    left_for_remote = [
        item
        for item in left
        if isinstance(item.get("host_ref"), int)
        and a_to_b_host_ids.get(int(item["host_ref"])) == mapped
    ]
    right_for_remote = [
        (index, item)
        for index, item in enumerate(right)
        if index not in right_used and item.get("host_ref") == mapped
    ]
    if len(left_for_remote) != 1 or len(right_for_remote) != 1:
        return None

    index, b_item = right_for_remote[0]
    if _neighbor_local_tokens(a_item) & _neighbor_local_tokens(b_item):
        return None
    strong_match = bool(_neighbor_strong_edge_tokens(a_item) & _neighbor_strong_edge_tokens(b_item))
    remote_port_match = _neighbor_remote_port_key(a_item) is not None and _neighbor_remote_port_key(
        a_item
    ) == _neighbor_remote_port_key(b_item)
    return index if strong_match or remote_port_match else None


def _normalize_neighbor_details(value: Any) -> Any:
    """Remove volatile collector table indexes from neighbor detail evidence.

    Protocol evidence is currently stored with keys such as
    ``lldp.remote_index`` alongside the generic ``remote_index`` key. Handle
    both forms, and recurse through mappings so future nested detail structures
    receive the same normalization without ignoring unrelated ``*_id`` fields.
    """

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value):
            name = str(key)
            if name.rsplit(".", 1)[-1] in _VOLATILE_NEIGHBOR_DETAIL_FIELDS:
                continue
            result[name] = _normalize_neighbor_details(value[key])
        return result
    if isinstance(value, list):
        return _stable_value([_normalize_neighbor_details(item) for item in value])
    return value


def _normalize_neighbor(neighbor: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in neighbor.items():
        if key in {"host_ref", "last_seen", "protocol_tag"} or key in _TIMESTAMP_KEYS:
            continue
        if key == "details":
            result[key] = _normalize_neighbor_details(value)
        else:
            result[key] = _stable_value(value)
    return result


def _neighbor_differences(
    a: Mapping[str, Any], b: Mapping[str, Any]
) -> tuple[FieldDifference, ...]:
    left = _flatten(_normalize_neighbor(a))
    right = _flatten(_normalize_neighbor(b))
    return tuple(
        FieldDifference(path, left.get(path), right.get(path))
        for path in sorted(set(left) | set(right))
        if left.get(path) != right.get(path)
    )


_LOCAL_INTERFACE_PRESENTATION_FIELDS = frozenset(
    {
        "local_interface",
        "local_interface_raw",
        "local_interface_resolved",
        "local_interface_namespace",
        "local_port_map_failed",
        "local_interface_resolution_method",
        "local_interface_resolution_source",
    }
)


def _local_interface_presentation_difference(value: FieldDifference) -> bool:
    """Return whether a difference only describes local-port presentation.

    Friendly interface names, typed unresolved indexes, and the method used to
    obtain them describe how LLDP-Runner rendered one side of an already paired
    relationship. They do not independently prove a topology change. Protocol
    table indexes are normalized separately as volatile collection evidence.
    """

    leaf = value.path.rsplit(".", 1)[-1]
    return leaf in _LOCAL_INTERFACE_PRESENTATION_FIELDS


def _neighbor_protocols(neighbor: Mapping[str, Any] | None) -> set[str]:
    """Return normalized protocol names carried by one canonical neighbor row."""

    if neighbor is None:
        return set()
    values = neighbor.get("protocols")
    if not isinstance(values, list):
        return set()
    return {str(value).casefold() for value in values if value}


_PROTOCOL_EVIDENCE_TOP_LEVEL_FIELDS = frozenset(
    {
        "name",
        "observed_addresses",
        "observed_name",
        "protocol_tag",
        "protocols",
        "remote_interface",
        "remote_interface_raw",
    }
)


def _protocol_transition(
    a: Mapping[str, Any], b: Mapping[str, Any]
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Return a normalized protocol-set transition when the sets differ."""

    left = tuple(sorted(_neighbor_protocols(a)))
    right = tuple(sorted(_neighbor_protocols(b)))
    return (left, right) if left != right else None


def _protocol_evidence_only(
    differences: tuple[FieldDifference, ...],
) -> bool:
    """Return whether all row changes are protocol/representation evidence.

    ``compare_neighbors`` has already paired the same remote host on the same
    normalized local interface. A protocol-set transition can legitimately change
    the preferred remote name/port, observed address set, and any protocol-specific
    detail fields without changing that physical relationship. Structural fields
    outside this allow-list keep the ordinary ``changed`` status.
    """

    if not differences:
        return False
    for difference in differences:
        path = difference.path
        if path.startswith("details."):
            continue
        if path in _PROTOCOL_EVIDENCE_TOP_LEVEL_FIELDS:
            continue
        return False
    return True


_MANAGEMENT_ADDRESS_PATH = re.compile(
    r"^(?:observed_addresses|details(?:\.[^.]+)*\.remote_addresses)$"
)


_RELATIONSHIP_EVIDENCE_FIELDS = frozenset(
    {
        "name",
        "observed_name",
        "observed_addresses",
        "details.address_type",
        "details.entry_addresses",
        "details.remote_addresses",
        "details.chassis_id",
        "details.remote_name",
    }
)
_RELATIONSHIP_EVIDENCE_DETAIL_LEAVES = frozenset(
    {
        "address_type",
        "entry_addresses",
        "remote_addresses",
        "chassis_id",
        "remote_name",
    }
)


def _relationship_evidence_only(
    differences: Sequence[FieldDifference],
) -> bool:
    """Return whether a paired stable edge changed only diagnostic evidence.

    At this point the comparator has already paired the same observer, typed
    local port, remote host, remote port, and protocol set.  Name presentation,
    raw protocol address/chassis evidence, and sentinel-to-valid address changes
    may still differ between snapshots without moving or replacing the observed
    relationship.  Keep this allow-list deliberately narrow so structural port
    or identity changes continue to use ordinary topology classifications.
    """

    if not differences:
        return False
    for difference in differences:
        path = difference.path
        if path == "details.chassis_id" or (
            path.startswith("details.") and path.endswith(".chassis_id")
        ):
            # A sentinel/missing network-address chassis value becoming usable
            # (or the reverse) is evidence quality on an already paired edge.
            # Two distinct usable chassis values remain a generic relationship
            # change because they can indicate that identity pairing deserves
            # operator review.
            usable = 0
            for value in (difference.a, difference.b):
                try:
                    normalize_host_address(str(value))
                except (TypeError, ValueError):
                    continue
                usable += 1
            if usable < 2:
                continue
            return False
        if path in _RELATIONSHIP_EVIDENCE_FIELDS:
            continue
        if path.startswith("details.") and path.rsplit(".", 1)[-1] in (
            _RELATIONSHIP_EVIDENCE_DETAIL_LEAVES
        ):
            continue
        return False
    return True


def _management_address_difference_path(path: str) -> bool:
    """Return whether one flattened field represents management-IP evidence."""

    return bool(_MANAGEMENT_ADDRESS_PATH.fullmatch(path))


def _management_address_only(
    differences: Sequence[FieldDifference],
) -> bool:
    """Return whether every material row change is management-address evidence."""

    return bool(differences) and all(
        _management_address_difference_path(item.path) for item in differences
    )


def _neighbor_management_addresses(neighbor: Mapping[str, Any]) -> tuple[str, ...]:
    """Return canonical valid IPs from generic and protocol-specific evidence."""

    values: list[object] = []
    observed = neighbor.get("observed_addresses")
    if isinstance(observed, list):
        values.extend(observed)

    def collect(value: Any, *, key: str | None = None) -> None:
        if isinstance(value, Mapping):
            for child_key, child_value in value.items():
                collect(child_value, key=str(child_key))
            return
        if key == "remote_addresses" and isinstance(value, list):
            values.extend(value)

    details = neighbor.get("details")
    if isinstance(details, Mapping):
        collect(details)

    normalized: list[str] = []
    for value in values:
        try:
            address = normalize_host_address(str(value))
        except (TypeError, ValueError):
            continue
        if address not in normalized:
            normalized.append(address)
    return tuple(
        sorted(
            normalized,
            key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))),
        )
    )


def _addresses_by_family(values: Sequence[str]) -> dict[str, list[str]]:
    """Partition canonical addresses into stable IPv4 and IPv6 arrays."""

    ipv4: list[str] = []
    ipv6: list[str] = []
    for value in values:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            continue
        (ipv4 if parsed.version == 4 else ipv6).append(str(parsed))
    return {"ipv4": ipv4, "ipv6": ipv6}


def _management_address_change_payload(
    a: Mapping[str, Any],
    b: Mapping[str, Any],
    a_coverage: _HostCollectionCoverage,
    b_coverage: _HostCollectionCoverage,
) -> dict[str, Any]:
    """Describe management-address additions/removals and their provenance."""

    after = set(_neighbor_management_addresses(a))
    before = set(_neighbor_management_addresses(b))

    def address_key(value: str) -> tuple[int, int]:
        return (
            ipaddress.ip_address(value).version,
            int(ipaddress.ip_address(value)),
        )

    added = tuple(sorted(after - before, key=address_key))
    removed = tuple(sorted(before - after, key=address_key))
    protocols = tuple(sorted(_neighbor_protocols(a) | _neighbor_protocols(b)))
    coverage: dict[str, Any] = {}
    authoritative = True
    for protocol in protocols:
        a_status = a_coverage.management_address_status_for(protocol)
        b_status = b_coverage.management_address_status_for(protocol)
        a_complete = a_coverage.authoritative_management_addresses(protocol)
        b_complete = b_coverage.authoritative_management_addresses(protocol)
        authoritative = authoritative and a_complete and b_complete
        coverage[protocol] = {
            "a": {
                "status": a_status,
                "source": a_coverage.management_address_source_for(protocol),
                "message": a_coverage.management_address_message_for(protocol),
            },
            "b": {
                "status": b_status,
                "source": b_coverage.management_address_source_for(protocol),
                "message": b_coverage.management_address_message_for(protocol),
            },
        }
    if not protocols:
        authoritative = a_coverage.host_state == "complete" and b_coverage.host_state == "complete"
    confidence = "confirmed" if authoritative else "coverage_uncertain"
    rationale = (
        "paired relationship is unchanged and both relevant management-address "
        "collection boundaries are complete"
        if authoritative
        else "paired relationship is unchanged, but at least one relevant "
        "management-address collection boundary is incomplete"
    )
    return {
        "a": list(sorted(after, key=address_key)),
        "b": list(sorted(before, key=address_key)),
        "before": list(sorted(before, key=address_key)),
        "after": list(sorted(after, key=address_key)),
        "added": list(added),
        "removed": list(removed),
        "added_by_family": _addresses_by_family(added),
        "removed_by_family": _addresses_by_family(removed),
        "confidence": confidence,
        "rationale": rationale,
        "protocol_coverage": coverage,
    }


def _management_address_coverage_sources(
    a: Mapping[str, Any],
    b: Mapping[str, Any],
    a_coverage: _HostCollectionCoverage,
    b_coverage: _HostCollectionCoverage,
    *,
    a_observer: Mapping[str, Any] | None,
    b_observer: Mapping[str, Any] | None,
) -> tuple[_CoverageSource, ...]:
    """Return subtable incidents that prevent a confirmed address transition."""

    if a_observer is None or b_observer is None:
        return ()
    sources: list[_CoverageSource] = []
    protocols = sorted(_neighbor_protocols(a) | _neighbor_protocols(b))
    for missing_side, present_observer, missing_observer, coverage in (
        ("a", b_observer, a_observer, a_coverage),
        ("b", a_observer, b_observer, b_coverage),
    ):
        for protocol in protocols:
            if coverage.authoritative_management_addresses(protocol):
                continue
            present_id = present_observer.get("id")
            missing_id = missing_observer.get("id")
            if not isinstance(present_id, int) or isinstance(present_id, bool):
                continue
            if not isinstance(missing_id, int) or isinstance(missing_id, bool):
                continue
            status = coverage.management_address_status_for(protocol) or "unknown"
            source_kind = coverage.management_address_source_for(protocol)
            table = (
                f"{protocol}.remote_management_address" if source_kind == "subtable" else protocol
            )
            payload = {
                "missing_side": missing_side,
                "missing_observer_id": missing_id,
                "protocol": protocol,
                "table": table,
                "status": status,
            }
            sources.append(
                _CoverageSource(
                    incident_key="coverage:" + stable_fingerprint(payload)[:24],
                    missing_side=missing_side,
                    present_observer_id=present_id,
                    present_observer_name=str(
                        present_observer.get("preferred_name")
                        or present_observer.get("snmp_sysname")
                        or "unknown"
                    ),
                    missing_observer_id=missing_id,
                    missing_observer_name=str(
                        missing_observer.get("preferred_name")
                        or missing_observer.get("snmp_sysname")
                        or "unknown"
                    ),
                    protocol=protocol,
                    table=table,
                    status=status,
                    message=coverage.management_address_message_for(protocol),
                )
            )
    return _deduplicate_coverage_sources(sources)


def _missing_side_uncertainty(
    present: Mapping[str, Any],
    missing: _HostCollectionCoverage,
    *,
    missing_side: str,
) -> tuple[str, ...]:
    """Explain when one-sided topology may be caused by incomplete collection."""

    reasons: list[str] = []
    if missing.all_neighbors_incomplete:
        reasons.append(f"{missing_side} host neighbor collection incomplete")
    present_protocols = _neighbor_protocols(present)
    for protocol in sorted(missing.failed_protocols & present_protocols):
        reasons.append(f"{missing_side} {protocol} collection failed")
    for protocol in sorted(missing.unresolved_interface_protocols & present_protocols):
        reasons.append(f"{missing_side} {protocol} local interface unresolved")
    return tuple(dict.fromkeys(reasons))


def _missing_side_coverage_sources(
    present: Mapping[str, Any],
    missing: _HostCollectionCoverage,
    *,
    present_observer: Mapping[str, Any] | None,
    missing_observer: Mapping[str, Any] | None,
    missing_side: str,
) -> tuple[_CoverageSource, ...]:
    """Return structured incident provenance for one absent neighbor row."""

    if present_observer is None or missing_observer is None:
        return ()
    sources: list[_CoverageSource] = []
    for protocol in sorted(_neighbor_protocols(present)):
        source = _coverage_source(
            present_observer=present_observer,
            missing_observer=missing_observer,
            missing_side=missing_side.casefold(),
            protocol=protocol,
            coverage=missing,
        )
        if source is not None:
            sources.append(source)
    return _deduplicate_coverage_sources(sources)


def _changed_neighbor_uncertainty(
    a: Mapping[str, Any],
    b: Mapping[str, Any],
    a_coverage: _HostCollectionCoverage,
    b_coverage: _HostCollectionCoverage,
) -> tuple[str, ...]:
    """Explain paired-row changes that coincide with failed protocol coverage."""

    reasons: list[str] = []
    if a_coverage.all_neighbors_incomplete:
        reasons.append("A host neighbor collection incomplete")
    if b_coverage.all_neighbors_incomplete:
        reasons.append("B host neighbor collection incomplete")
    a_protocols = _neighbor_protocols(a)
    b_protocols = _neighbor_protocols(b)
    for protocol in sorted(a_coverage.failed_protocols):
        if protocol in b_protocols and protocol not in a_protocols:
            reasons.append(f"A {protocol} collection failed")
    for protocol in sorted(b_coverage.failed_protocols):
        if protocol in a_protocols and protocol not in b_protocols:
            reasons.append(f"B {protocol} collection failed")
    for protocol in sorted(a_coverage.unresolved_interface_protocols & a_protocols):
        reasons.append(f"A {protocol} local interface unresolved")
    for protocol in sorted(b_coverage.unresolved_interface_protocols & b_protocols):
        reasons.append(f"B {protocol} local interface unresolved")
    return tuple(dict.fromkeys(reasons))


def _changed_neighbor_coverage_sources(
    a: Mapping[str, Any],
    b: Mapping[str, Any],
    a_coverage: _HostCollectionCoverage,
    b_coverage: _HostCollectionCoverage,
    *,
    a_observer: Mapping[str, Any] | None,
    b_observer: Mapping[str, Any] | None,
) -> tuple[_CoverageSource, ...]:
    """Return failed-table provenance for a paired neighbor evidence change."""

    if a_observer is None or b_observer is None:
        return ()
    a_protocols = _neighbor_protocols(a)
    b_protocols = _neighbor_protocols(b)
    sources: list[_CoverageSource] = []
    for protocol in sorted(b_protocols - a_protocols):
        source = _coverage_source(
            present_observer=b_observer,
            missing_observer=a_observer,
            missing_side="a",
            protocol=protocol,
            coverage=a_coverage,
        )
        if source is not None:
            sources.append(source)
    for protocol in sorted(a_protocols - b_protocols):
        source = _coverage_source(
            present_observer=a_observer,
            missing_observer=b_observer,
            missing_side="b",
            protocol=protocol,
            coverage=b_coverage,
        )
        if source is not None:
            sources.append(source)
    # A protocol row can still be present while its local IF-MIB name lookup is
    # incomplete.  That is a collection incident affecting the quality of the
    # protocol projection, not proof that the observed relationship disappeared.
    for protocol in sorted(a_coverage.unresolved_interface_protocols & a_protocols):
        source = _interface_resolution_coverage_source(
            present_observer=b_observer,
            missing_observer=a_observer,
            missing_side="a",
            protocol=protocol,
            coverage=a_coverage,
        )
        if source is not None:
            sources.append(source)
    for protocol in sorted(b_coverage.unresolved_interface_protocols & b_protocols):
        source = _interface_resolution_coverage_source(
            present_observer=a_observer,
            missing_observer=b_observer,
            missing_side="b",
            protocol=protocol,
            coverage=b_coverage,
        )
        if source is not None:
            sources.append(source)
    return _deduplicate_coverage_sources(sources)


_RESOLUTION_DEGRADED_EVIDENCE_FIELDS = frozenset(
    {
        "details.capabilities",
        "details.protocols",
    }
)


def _resolution_degraded_evidence_only(
    differences: Sequence[FieldDifference],
) -> bool:
    """Return whether only the merged protocol projection changed.

    When CDP cannot resolve an IF-MIB name but LLDP still identifies the same
    local port, remote entity, and remote port, the compatibility merger may
    select LLDP-only capabilities as its generic detail values.  Those generic
    fields describe evidence/presentation; they do not make the already paired
    relationship uncertain.
    """

    return bool(differences) and all(
        item.path in _RESOLUTION_DEGRADED_EVIDENCE_FIELDS for item in differences
    )


def _invalid_identity_empty_neighbor(neighbor: Mapping[str, Any]) -> bool:
    """Return whether a row lacks the minimum remote identity CDP requires."""

    if _neighbor_protocols(neighbor) != {"cdp"}:
        return False
    name = str(neighbor.get("name") or "").strip().casefold()
    if name not in {"", "unknown", "none", "null", "n/a", "-"}:
        return False
    if neighbor.get("observed_name") or neighbor.get("observed_addresses"):
        return False
    if neighbor.get("remote_interface") or neighbor.get("remote_interface_raw"):
        return False
    details = neighbor.get("details")
    details = details if isinstance(details, Mapping) else {}
    return not bool(details.get("device_id") or details.get("cdp.device_id"))


def _neighbor_semantics(
    *,
    status: str,
    presentation_differences: Sequence[FieldDifference] = (),
    coverage_sources: Sequence[_CoverageSource] = (),
    ambiguity: bool = False,
    continuity_confirmed: bool = False,
) -> tuple[str, str, str]:
    """Return qualification, presence status, and confidence for one edge."""

    if coverage_sources:
        if continuity_confirmed:
            return "coverage_uncertain", "same", "coverage_uncertain"
        return "coverage_uncertain", "uncertain", "coverage_uncertain"
    if ambiguity or status == "uncertain":
        return "ambiguous", "uncertain", "ambiguous"
    if status == "same" and presentation_differences:
        return "presentation_only", "same", "confirmed"
    if status == "relationship_evidence_changed":
        # The same observer, typed local port, remote entity, remote port, and
        # protocol set have already been established.  Only display/raw
        # protocol evidence differs, so preserve it as a change without
        # presenting it as a changed relationship.
        return "evidence_only", "same", "confirmed"
    if status in {
        "same",
        "protocol_changed",
        "management_address_changed",
    }:
        return "confirmed", "same", "confirmed"
    if status in {"a_only", "b_only"}:
        return "confirmed", status, "confirmed"
    return "confirmed", "changed", "confirmed"


def compare_neighbors(
    a_neighbors: Any,
    b_neighbors: Any,
    *,
    a_to_b_host_ids: Mapping[int, int],
    b_to_a_host_ids: Mapping[int, int],
    a_coverage: _HostCollectionCoverage = _COMPLETE_COLLECTION,
    b_coverage: _HostCollectionCoverage = _COMPLETE_COLLECTION,
    a_observer: Mapping[str, Any] | None = None,
    b_observer: Mapping[str, Any] | None = None,
) -> tuple[NeighborDifference, ...]:
    """Compare one direction of neighbor evidence without relying on run-local IDs."""

    left = (
        [item for item in a_neighbors if isinstance(item, dict)]
        if isinstance(a_neighbors, list)
        else []
    )
    right = (
        [item for item in b_neighbors if isinstance(item, dict)]
        if isinstance(b_neighbors, list)
        else []
    )
    left_used: set[int] = set()
    right_used: set[int] = set()
    results: list[NeighborDifference] = []

    # Group candidates by typed local-port evidence plus cross-run paired remote
    # identity. A resolved row contributes both its display name and protocol
    # indexes, allowing it to match a historical bare numeric row without ever
    # treating ifIndex and lldpLocalPort as the same namespace.
    right_groups: dict[tuple[str, int], set[int]] = defaultdict(set)
    for index, item in enumerate(right):
        host_ref = item.get("host_ref")
        if not isinstance(host_ref, int) or host_ref not in b_to_a_host_ids:
            continue
        for token in _neighbor_local_tokens(item):
            right_groups[(token, host_ref)].add(index)

    for a_index, original_a_item in enumerate(left):
        if a_index in left_used:
            continue
        a_item = original_a_item
        a_ref = a_item.get("host_ref")
        mapped = (
            a_to_b_host_ids.get(a_ref)
            if isinstance(a_ref, int) and not isinstance(a_ref, bool)
            else None
        )
        candidate_set: set[int] = set()
        if mapped is not None:
            for token in _neighbor_local_tokens(a_item):
                candidate_set.update(right_groups.get((token, mapped), ()))
        candidates = sorted(index for index in candidate_set if index not in right_used)
        selected_indices: list[int] = []
        matched_cross_local = False
        if len(candidates) == 1:
            selected_indices = [candidates[0]]
        elif len(candidates) > 1:
            candidate_rows = [right[index] for index in candidates]
            a_protocols = _neighbor_protocols(a_item)
            protocol_exact = [
                idx for idx in candidates if _neighbor_protocols(right[idx]) == a_protocols
            ]
            if len(protocol_exact) == 1:
                selected_indices = [protocol_exact[0]]
            elif _can_coalesce_protocol_rows(a_item, candidate_rows):
                selected_indices = candidates
            a_remote = _neighbor_remote_port_key(a_item)
            exact = [
                idx
                for idx in candidates
                if a_remote is not None and _neighbor_remote_port_key(right[idx]) == a_remote
            ]
            if not selected_indices and len(exact) == 1:
                selected_indices = [exact[0]]
        if not selected_indices:
            selected = _fallback_neighbor_candidate(a_item, right, right_used)
            if selected is not None:
                selected_indices = [selected]
        if not selected_indices:
            selected = _cross_local_neighbor_candidate(
                a_item,
                left,
                right,
                right_used,
                a_to_b_host_ids,
            )
            if selected is not None:
                selected_indices = [selected]
                matched_cross_local = True
        if not selected_indices:
            reasons = _missing_side_uncertainty(a_item, b_coverage, missing_side="B")
            coverage_sources = _missing_side_coverage_sources(
                a_item,
                b_coverage,
                present_observer=a_observer,
                missing_observer=b_observer,
                missing_side="B",
            )
            invalid_observation = _invalid_identity_empty_neighbor(a_item)
            if invalid_observation:
                reasons = tuple(
                    dict.fromkeys((*reasons, "CDP row lacks mandatory remote identity and port"))
                )
            status = "uncertain" if coverage_sources or reasons or invalid_observation else "a_only"
            qualification, presence_status, presence_confidence = _neighbor_semantics(
                status=status,
                coverage_sources=coverage_sources,
                ambiguity=invalid_observation or (bool(reasons) and not coverage_sources),
            )
            results.append(
                NeighborDifference(
                    status,
                    a_item,
                    None,
                    uncertainty_reasons=reasons,
                    semantic_qualification=qualification,
                    presence_status=presence_status,
                    presence_confidence=presence_confidence,
                    coverage_sources=coverage_sources,
                )
            )
            continue
        right_used.update(selected_indices)
        selected_rows = [right[index] for index in selected_indices]
        b_item = _combine_neighbor_rows(selected_rows)
        if len(selected_rows) == 1:
            left_indices = _coalesce_left_protocol_rows(
                a_index, left, b_item, left_used, a_to_b_host_ids
            )
            if len(left_indices) > 1:
                left_used.update(left_indices)
                a_item = _combine_neighbor_rows([left[index] for index in left_indices])
        differences = _neighbor_differences(a_item, b_item)
        presentation_differences: tuple[FieldDifference, ...] = ()
        resolution_mismatch = _neighbor_local_unresolved(a_item) != any(
            _neighbor_local_unresolved(item) for item in selected_rows
        )
        if differences:
            presentation_differences = tuple(
                item for item in differences if _local_interface_presentation_difference(item)
            )
            # A matching typed local-port token proves the same attachment
            # point even if the merged row selected a different protocol's
            # namespace label.  Keep that namespace/method drift in the
            # presentation dimension regardless of whether either side was
            # ultimately unresolved.
            if presentation_differences and (
                _neighbor_local_tokens(a_item) & _neighbor_local_tokens(b_item)
            ):
                differences = tuple(
                    item
                    for item in differences
                    if not _local_interface_presentation_difference(item)
                )
        protocol_change = _protocol_transition(a_item, b_item)
        management_address_change = (
            _management_address_change_payload(a_item, b_item, a_coverage, b_coverage)
            if _management_address_only(differences)
            else None
        )
        continuity_confirmed_despite_resolution = bool(
            resolution_mismatch
            and protocol_change is None
            and not matched_cross_local
            and _resolution_degraded_evidence_only(differences)
            and (
                a_coverage.unresolved_interface_protocols
                or b_coverage.unresolved_interface_protocols
            )
        )
        coverage_sources = (
            _changed_neighbor_coverage_sources(
                a_item,
                b_item,
                a_coverage,
                b_coverage,
                a_observer=a_observer,
                b_observer=b_observer,
            )
            if differences
            else ()
        )
        if management_address_change is not None:
            coverage_sources = _deduplicate_coverage_sources(
                (
                    *coverage_sources,
                    *_management_address_coverage_sources(
                        a_item,
                        b_item,
                        a_coverage,
                        b_coverage,
                        a_observer=a_observer,
                        b_observer=b_observer,
                    ),
                )
            )
        reasons = list(
            _changed_neighbor_uncertainty(a_item, b_item, a_coverage, b_coverage)
            if differences
            else ()
        )
        # An unresolved namespace is a limitation of port presentation, not a
        # topology difference by itself.  When both runs contain the same typed
        # local-port token and the complete normalized edge is unchanged, report
        # the edge as stable while retaining the host-level collection coverage.
        # Resolution uncertainty matters only when some edge evidence actually
        # differs and therefore needs a resolved physical port to interpret it.
        if differences and _neighbor_local_unresolved(a_item):
            reasons.append("A local interface unresolved")
        if differences and any(_neighbor_local_unresolved(item) for item in selected_rows):
            reasons.append("B local interface unresolved")
        if (
            management_address_change is not None
            and management_address_change.get("confidence") != "confirmed"
        ):
            reasons.append("management-address collection coverage is incomplete")
        reasons_tuple = tuple(dict.fromkeys(reasons))
        status = "same"
        if continuity_confirmed_despite_resolution:
            # Keep protocol/capability projection deltas available for audit,
            # but relationship continuity is established by the paired observer,
            # local port, remote entity, and remote port.
            status = "same"
        elif reasons_tuple:
            status = "uncertain"
        elif matched_cross_local and differences:
            if _weak_move_identity(a_item) or _weak_move_identity(b_item):
                status = "uncertain"
                reasons_tuple = ("remote identity is insufficient to confirm a physical port move",)
            else:
                status = "moved"
        elif differences and protocol_change is not None and _protocol_evidence_only(differences):
            # Protocol-set transitions take precedence even when the selected
            # protocol representation also changes management-address evidence.
            status = "protocol_changed"
        elif management_address_change is not None:
            status = "management_address_changed"
        elif differences and _relationship_evidence_only(differences):
            status = "relationship_evidence_changed"
        elif differences:
            status = "changed"
        qualification, presence_status, presence_confidence = _neighbor_semantics(
            status=status,
            presentation_differences=presentation_differences,
            coverage_sources=coverage_sources,
            ambiguity=status == "uncertain" and not coverage_sources,
            continuity_confirmed=(
                continuity_confirmed_despite_resolution or management_address_change is not None
            ),
        )
        results.append(
            NeighborDifference(
                status=status,
                a=a_item,
                b=b_item,
                differences=differences,
                presentation_differences=presentation_differences,
                uncertainty_reasons=reasons_tuple,
                protocol_change=protocol_change,
                semantic_qualification=qualification,
                presence_status=presence_status,
                presence_confidence=presence_confidence,
                coverage_sources=coverage_sources,
                management_address_change=management_address_change,
            )
        )

    for index, b_item in enumerate(right):
        if index not in right_used:
            reasons = _missing_side_uncertainty(b_item, a_coverage, missing_side="A")
            coverage_sources = _missing_side_coverage_sources(
                b_item,
                a_coverage,
                present_observer=b_observer,
                missing_observer=a_observer,
                missing_side="A",
            )
            invalid_observation = _invalid_identity_empty_neighbor(b_item)
            if invalid_observation:
                reasons = tuple(
                    dict.fromkeys((*reasons, "CDP row lacks mandatory remote identity and port"))
                )
            status = "uncertain" if coverage_sources or reasons or invalid_observation else "b_only"
            qualification, presence_status, presence_confidence = _neighbor_semantics(
                status=status,
                coverage_sources=coverage_sources,
                ambiguity=invalid_observation or (bool(reasons) and not coverage_sources),
            )
            results.append(
                NeighborDifference(
                    status,
                    None,
                    b_item,
                    uncertainty_reasons=reasons,
                    semantic_qualification=qualification,
                    presence_status=presence_status,
                    presence_confidence=presence_confidence,
                    coverage_sources=coverage_sources,
                )
            )
    return tuple(results)


def _scope_seed_set(metadata: Mapping[str, Any] | None) -> tuple[str, ...] | None:
    if metadata is None:
        return None
    invocations = metadata.get("invocations")
    if not isinstance(invocations, list):
        return None
    values: list[str] = []
    for invocation in invocations:
        if not isinstance(invocation, Mapping):
            continue
        seeds = invocation.get("seed_inputs")
        if isinstance(seeds, list):
            for seed in seeds:
                if isinstance(seed, Mapping) and seed.get("seed") is not None:
                    text = str(seed["seed"])
                    if text not in values:
                        values.append(text)
    return tuple(values)


def _scope_config_files(metadata: Mapping[str, Any] | None) -> tuple[str, ...] | None:
    if metadata is None or not metadata.get("config_files_logged"):
        return None
    values = metadata.get("config_files")
    if not isinstance(values, list):
        return None
    return tuple(str(value) for value in values)


def scope_warnings(
    a_document: DiscoveryDocument,
    b_document: DiscoveryDocument,
    a_source: ResolvedDiffSource,
    b_source: ResolvedDiffSource,
) -> tuple[str, ...]:
    """Describe scope/provenance differences that can affect topology interpretation."""

    differences: list[str] = []
    a_discovery = a_document.payload.get("discovery")
    b_discovery = b_document.payload.get("discovery")
    if isinstance(a_discovery, Mapping) and isinstance(b_discovery, Mapping):
        for field in _SCOPE_DISCOVERY_FIELDS:
            if _stable_value(a_discovery.get(field)) != _stable_value(b_discovery.get(field)):
                differences.append(f"discovery.{field}")

    a_configs = _scope_config_files(a_source.run_metadata)
    b_configs = _scope_config_files(b_source.run_metadata)
    if a_configs is not None and b_configs is not None and a_configs != b_configs:
        differences.append("run.json config_files")

    a_seeds = _scope_seed_set(a_source.run_metadata)
    b_seeds = _scope_seed_set(b_source.run_metadata)
    if a_seeds is not None and b_seeds is not None and a_seeds != b_seeds:
        differences.append("run.json seed_inputs")

    if not differences:
        return ()
    fields = ", ".join(differences)
    return (
        "Compared runs used different discovery scope/provenance metadata "
        f"({fields}). Missing hosts or neighbors may reflect discovery coverage "
        "rather than a network change.",
    )


def _host_identity(host: Mapping[str, Any]) -> dict[str, Any]:
    return {"id": host.get("id"), "preferred_name": host.get("preferred_name")}


def _field_diff_json(value: FieldDifference) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": value.path,
        "a": value.a,
        "b": value.b,
        "kind": value.kind,
    }
    if value.provenance is not None:
        result["provenance"] = value.provenance
    if value.coverage_sources:
        sources = [source.to_json() for source in value.coverage_sources]
        result["coverage_source"] = sources[0] if len(sources) == 1 else None
        result["coverage_sources"] = sources
    return result


def _neighbor_json(value: NeighborDifference) -> dict[str, Any]:
    protocol_change = None
    if value.protocol_change is not None:
        protocol_change = {
            "a": list(value.protocol_change[0]),
            "b": list(value.protocol_change[1]),
        }
    coverage_sources = [source.to_json() for source in value.coverage_sources]
    return {
        "status": value.status,
        "presence_status": value.presence_status,
        "presence_confidence": value.presence_confidence,
        "semantic_qualification": value.semantic_qualification,
        "a": value.a,
        "b": value.b,
        "differences": [_field_diff_json(item) for item in value.differences],
        "presentation_differences": [
            _field_diff_json(item) for item in value.presentation_differences
        ],
        "uncertainty_reasons": list(value.uncertainty_reasons),
        "coverage_source": coverage_sources[0] if len(coverage_sources) == 1 else None,
        "coverage_sources": coverage_sources,
        "protocol_change": protocol_change,
        "management_address_change": value.management_address_change,
        "physical_topology_effect": (
            "none"
            if value.status
            in {
                "same",
                "protocol_changed",
                "management_address_changed",
                "relationship_evidence_changed",
            }
            or value.management_address_change is not None
            or value.semantic_qualification == "presentation_only"
            else "not_inferred"
        ),
    }


def _collection_coverage(
    document: DiscoveryDocument,
) -> dict[int, _HostCollectionCoverage]:
    """Build semantic collection boundaries from durable coverage and errors.

    LLDP schema-8 coverage separates three independent questions: whether a
    remote relationship row was observed, whether its local interface was
    resolved, and whether remote management addresses were collected.  An
    incomplete management-address walk must not invalidate an otherwise complete
    remote-neighbor or local-port snapshot.  Aggregate protocol status remains
    available for run-health reporting and schema-7 compatibility.
    """

    mutable: dict[int, dict[str, Any]] = {}
    for host in document.hosts:
        host_id = host.get("id")
        if not isinstance(host_id, int) or isinstance(host_id, bool):
            continue
        state = str(host.get("state") or "unknown").casefold()
        if state == "no_query":
            query_disposition = "no_query"
        elif state == "out_of_scope":
            query_disposition = "out_of_scope"
        elif state == "complete":
            query_disposition = "queried_complete"
        else:
            query_disposition = "queried_partial_or_failed"
        incomplete = query_disposition == "queried_partial_or_failed"
        record: dict[str, Any] = {
            "host_state": state,
            "query_disposition": query_disposition,
            "all": incomplete,
            "protocols": set(),
            "interfaces": set(),
            "tables": {},
            "row_counts": {},
            "messages": {},
            "neighbor_statuses": {},
            "neighbor_messages": {},
            "neighbor_sources": {},
            "interface_statuses": {},
            "interface_messages": {},
            "interface_sources": {},
            "management_statuses": {},
            "management_messages": {},
            "management_sources": {},
            "reasons": [f"queried host state is {state}"] if incomplete else [],
        }
        mutable[host_id] = record

        snmp = host.get("snmp")
        coverage = snmp.get("collection_coverage") if isinstance(snmp, Mapping) else None
        if not isinstance(coverage, Mapping):
            continue

        for section, raw in coverage.items():
            if not isinstance(raw, Mapping):
                continue
            table = str(section).casefold()
            status = str(raw.get("status") or "unknown").casefold()
            resolution = str(raw.get("resolution_status") or "not_applicable").casefold()
            record["tables"][table] = status
            row_count = raw.get("row_count")
            if isinstance(row_count, int) and not isinstance(row_count, bool):
                record["row_counts"][table] = max(0, row_count)
            if raw.get("message"):
                record["messages"][table] = str(raw.get("message"))
                record["reasons"].append(f"{table}: {raw.get('message')}")

            if table not in {"lldp", "lldpv2", "cdp"}:
                continue

            subtables = raw.get("subtables")
            subtables = subtables if isinstance(subtables, Mapping) else {}
            remote = subtables.get("remote_neighbor")
            remote = remote if isinstance(remote, Mapping) else None
            management = subtables.get("remote_management_address")
            management = management if isinstance(management, Mapping) else None
            local_port = subtables.get("local_port")
            local_port = local_port if isinstance(local_port, Mapping) else None

            if remote is not None:
                neighbor_status = str(remote.get("status") or "unknown").casefold()
                neighbor_source = f"{table}.remote_neighbor"
                neighbor_message = str(remote.get("message")) if remote.get("message") else None
            else:
                neighbor_status = status
                neighbor_source = table
                neighbor_message = str(raw.get("message")) if raw.get("message") else None
            record["neighbor_statuses"][table] = neighbor_status
            record["neighbor_sources"][table] = neighbor_source
            if neighbor_message:
                record["neighbor_messages"][table] = neighbor_message
            if neighbor_status not in {"complete", "not_attempted"}:
                record["protocols"].add(table)
                record["reasons"].append(f"{neighbor_source} collector {neighbor_status}")

            if management is not None:
                management_status = str(management.get("status") or "unknown").casefold()
                record["management_statuses"][table] = management_status
                record["management_sources"][table] = "subtable"
                if management.get("message"):
                    record["management_messages"][table] = str(management.get("message"))
            else:
                record["management_statuses"][table] = status
                record["management_sources"][table] = "protocol_aggregate_legacy"

            interface_status = "complete"
            interface_source = neighbor_source
            interface_message: str | None = None
            if table == "lldp" and local_port is not None:
                local_status = str(local_port.get("status") or "unknown").casefold()
                local_resolution = str(
                    local_port.get("resolution_status") or "not_applicable"
                ).casefold()
                if local_status not in {"complete", "not_attempted"}:
                    interface_status = local_status
                    interface_source = "lldp.local_port"
                    interface_message = (
                        str(local_port.get("message")) if local_port.get("message") else None
                    )
                elif local_resolution in {"partial", "unresolved"}:
                    interface_status = local_resolution
                    interface_source = "lldp.local_port"
                    interface_message = (
                        str(local_port.get("message")) if local_port.get("message") else None
                    )
            if interface_status == "complete":
                remote_resolution = (
                    str(remote.get("resolution_status") or "not_applicable").casefold()
                    if remote is not None
                    else resolution
                )
                if neighbor_status not in {"complete", "not_attempted"}:
                    interface_status = neighbor_status
                    interface_source = neighbor_source
                    interface_message = neighbor_message
                elif remote_resolution in {"partial", "unresolved"}:
                    interface_status = remote_resolution
                    interface_source = neighbor_source
                    interface_message = neighbor_message
            record["interface_statuses"][table] = interface_status
            record["interface_sources"][table] = interface_source
            if interface_message:
                record["interface_messages"][table] = interface_message
            if interface_status not in {"complete", "not_attempted"}:
                record["interfaces"].add(table)
                record["reasons"].append(f"{interface_source} local interface {interface_status}")

    errors = document.payload.get("errors")
    if isinstance(errors, list):
        for error in errors:
            if not isinstance(error, Mapping):
                continue
            host_ref = error.get("host_ref")
            if not isinstance(host_ref, int) or isinstance(host_ref, bool):
                continue
            record = mutable.get(host_ref)
            if record is None:
                continue
            operation = str(error.get("operation") or "").casefold()
            category = str(error.get("category") or "unknown").casefold()
            if operation in {"lldp", "lldpv2", "cdp"}:
                explicit = record["neighbor_statuses"].get(operation)
                # A complete schema-8 remote-neighbor subtable is authoritative
                # even when the aggregate protocol emitted an error for another
                # subtable.  Legacy documents still fall back to the error.
                if explicit is None or explicit not in {"complete", "not_attempted"}:
                    record["protocols"].add(operation)
                    record["reasons"].append(f"{operation} collector {category}")
            elif operation in {
                "lldp_interface_resolution",
                "lldpv2_interface_resolution",
                "cdp_interface_resolution",
            }:
                protocol = operation.removesuffix("_interface_resolution")
                explicit = record["interface_statuses"].get(protocol)
                if explicit is None or explicit not in {"complete", "not_attempted"}:
                    record["interfaces"].add(protocol)
                    record["reasons"].append(f"{protocol} local interface resolution {category}")
            elif operation == "interfaces":
                record["reasons"].append(f"IF-MIB interface collector {category}")
            elif operation == "snmp_detail_session":
                record["all"] = True
                record["reasons"].append(f"detail session {category}")

    return {
        host_id: _HostCollectionCoverage(
            host_state=str(values["host_state"]),
            query_disposition=str(values["query_disposition"]),
            all_neighbors_incomplete=bool(values["all"]),
            failed_protocols=frozenset(values["protocols"]),
            unresolved_interface_protocols=frozenset(values["interfaces"]),
            table_statuses=tuple(sorted(values["tables"].items())),
            table_row_counts=tuple(sorted(values["row_counts"].items())),
            table_messages=tuple(sorted(values["messages"].items())),
            neighbor_statuses=tuple(sorted(values["neighbor_statuses"].items())),
            neighbor_messages=tuple(sorted(values["neighbor_messages"].items())),
            neighbor_sources=tuple(sorted(values["neighbor_sources"].items())),
            interface_statuses=tuple(sorted(values["interface_statuses"].items())),
            interface_messages=tuple(sorted(values["interface_messages"].items())),
            interface_sources=tuple(sorted(values["interface_sources"].items())),
            management_address_statuses=tuple(sorted(values["management_statuses"].items())),
            management_address_messages=tuple(sorted(values["management_messages"].items())),
            management_address_sources=tuple(sorted(values["management_sources"].items())),
            reasons=tuple(dict.fromkeys(str(item) for item in values["reasons"])),
        )
        for host_id, values in mutable.items()
    }


def _collection_coverage_summary(
    coverage: Mapping[int, _HostCollectionCoverage],
    *,
    obscured_downstream_count: int = 0,
) -> dict[str, Any]:
    """Summarize run-wide collection incidents without flattening their causes.

    The host/neighbor comparison still carries per-host coverage details.  This
    compact summary gives operators an early warning that a large block of diff
    results may be downstream of one or more collection incidents instead of a
    physical network change.
    """

    actively_queried = 0
    aggregate_complete_queried = 0
    aggregate_partial_or_failed_queried = 0
    topology_complete_queried = 0
    topology_affected_queried = 0
    management_address_only_incomplete = 0
    other_health_only_incomplete = 0
    failed_protocol_counts: dict[str, int] = defaultdict(int)
    unresolved_interface_counts: dict[str, int] = defaultdict(int)
    host_state_counts: dict[str, int] = defaultdict(int)
    table_status_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for item in coverage.values():
        host_state_counts[item.host_state] += 1
        queried = item.host_state not in {"no_query", "out_of_scope"}
        interface_status = item.status_for("interfaces")
        topology_incomplete = queried and (
            item.host_state != "complete"
            or bool(item.failed_protocols)
            or bool(item.unresolved_interface_protocols)
            or (
                interface_status is not None
                and interface_status not in {"complete", "not_attempted"}
            )
        )
        aggregate_incomplete = queried and (
            item.host_state != "complete"
            or any(
                status not in {"complete", "not_attempted"}
                for _table, status in item.table_statuses
            )
            or bool(item.unresolved_interface_protocols)
        )
        incomplete_tables = {
            table
            for table, status in item.table_statuses
            if status not in {"complete", "not_attempted"}
        }
        management_only = bool(incomplete_tables) and all(
            table in {"lldp", "lldpv2"}
            and item.neighbor_status_for(table) in {"complete", "not_attempted"}
            and item.interface_status_for(table) in {"complete", "not_attempted"}
            and item.management_address_status_for(table) not in {"complete", "not_attempted"}
            for table in incomplete_tables
        )
        if queried:
            actively_queried += 1
            if topology_incomplete:
                topology_affected_queried += 1
            else:
                topology_complete_queried += 1
            if aggregate_incomplete:
                aggregate_partial_or_failed_queried += 1
            else:
                aggregate_complete_queried += 1
            if aggregate_incomplete and not topology_incomplete and management_only:
                management_address_only_incomplete += 1
            elif aggregate_incomplete and not topology_incomplete:
                other_health_only_incomplete += 1
        for protocol in item.failed_protocols:
            failed_protocol_counts[protocol] += 1
        for protocol in item.unresolved_interface_protocols:
            unresolved_interface_counts[protocol] += 1
        for table, status in item.table_statuses:
            table_status_counts[table][status] += 1

    return {
        "host_count": len(coverage),
        "actively_queried_count": actively_queried,
        # Preserve the schema-9 aggregate-health names for machine consumers.
        # Schema 10 adds explicit topology-sensitive counts so management-only
        # subtable gaps do not masquerade as relationship uncertainty.
        "complete_queried_count": aggregate_complete_queried,
        "partial_or_failed_queried_count": aggregate_partial_or_failed_queried,
        "aggregate_complete_queried_count": aggregate_complete_queried,
        "aggregate_partial_or_failed_queried_count": (aggregate_partial_or_failed_queried),
        "topology_complete_queried_count": topology_complete_queried,
        "topology_affected_queried_count": topology_affected_queried,
        "management_address_only_incomplete_count": (management_address_only_incomplete),
        "other_health_only_incomplete_count": other_health_only_incomplete,
        # ``affected_host_count`` remains the concise warning denominator.  It
        # now deliberately means topology-sensitive coverage, while aggregate
        # health remains available through the explicit fields above.
        "affected_host_count": topology_affected_queried,
        "no_query_count": host_state_counts.get("no_query", 0),
        "out_of_scope_count": host_state_counts.get("out_of_scope", 0),
        "obscured_downstream_count": obscured_downstream_count,
        "host_states": dict(sorted(host_state_counts.items())),
        "failed_protocols": dict(sorted(failed_protocol_counts.items())),
        "unresolved_interfaces": dict(sorted(unresolved_interface_counts.items())),
        "table_statuses": {
            table: dict(sorted(statuses.items()))
            for table, statuses in sorted(table_status_counts.items())
        },
    }


def _management_address_health_issue(
    coverage: _HostCollectionCoverage,
    protocol: str,
) -> dict[str, Any] | None:
    """Return one independently scoped management-address collection issue.

    Failures inherited from an incomplete remote-neighbor snapshot are excluded:
    they are topology-sensitive incidents, not management-address-only health.
    """

    status = coverage.management_address_status_for(protocol)
    if status in {None, "complete", "not_attempted"}:
        return None
    if coverage.neighbor_status_for(protocol) not in {"complete", "not_attempted"}:
        return None
    if coverage.interface_status_for(protocol) not in {"complete", "not_attempted"}:
        return None
    message = coverage.management_address_message_for(protocol)
    text = str(message or "").casefold()
    if "malformed" in text and "index" in text:
        cause = "malformed_index"
    elif status == "timeout" or "timeout" in text:
        cause = "timeout"
    elif "access" in text or "authorization" in text:
        cause = "access_restricted"
    elif "unsupported" in text or "not supported" in text:
        cause = "unsupported"
    elif status == "partial":
        cause = "partial"
    else:
        cause = status
    source = coverage.management_address_source_for(protocol)
    table = f"{protocol}.remote_management_address" if source == "subtable" else protocol
    return {
        "protocol": protocol,
        "table": table,
        "status": status,
        "cause": cause,
        "message": message,
        "coverage_source": source,
    }


def _management_address_health_comparison(
    pairing: HostPairing,
    a_coverage: Mapping[int, _HostCollectionCoverage],
    b_coverage: Mapping[int, _HostCollectionCoverage],
) -> dict[str, Any]:
    """Summarize persistent, new, and recovered management-table health gaps."""

    persistent: defaultdict[str, int] = defaultdict(int)
    new_in_a: defaultdict[str, int] = defaultdict(int)
    recovered_in_a: defaultdict[str, int] = defaultdict(int)
    changed: defaultdict[str, int] = defaultdict(int)
    a_count = 0
    b_count = 0
    transitions: list[dict[str, Any]] = []
    for pair in pairing.pairs:
        a_item = a_coverage.get(int(pair.a["id"]), _COMPLETE_COLLECTION)
        b_item = b_coverage.get(int(pair.b["id"]), _COMPLETE_COLLECTION)
        for protocol in ("lldp", "lldpv2"):
            a_issue = _management_address_health_issue(a_item, protocol)
            b_issue = _management_address_health_issue(b_item, protocol)
            a_count += a_issue is not None
            b_count += b_issue is not None
            if a_issue is not None and b_issue is not None:
                persistent[str(a_issue["cause"])] += 1
                classification = "persistent"
                if a_issue["status"] != b_issue["status"] or a_issue["cause"] != b_issue["cause"]:
                    changed[f"{b_issue['cause']}->{a_issue['cause']}"] += 1
                    classification = "changed"
            elif a_issue is not None:
                new_in_a[str(a_issue["cause"])] += 1
                classification = "new_in_a"
            elif b_issue is not None:
                recovered_in_a[str(b_issue["cause"])] += 1
                classification = "recovered_in_a"
            else:
                continue
            if classification != "persistent":
                transitions.append(
                    {
                        "classification": classification,
                        "protocol": protocol,
                        "host": {
                            "a": _host_identity(pair.a),
                            "b": _host_identity(pair.b),
                        },
                        "a": copy.deepcopy(a_issue),
                        "b": copy.deepcopy(b_issue),
                    }
                )
    transitions.sort(
        key=lambda item: (
            str(item["classification"]),
            str(item["host"]["a"].get("preferred_name") or "").casefold(),
            str(item["protocol"]),
        )
    )
    persistent_count = sum(persistent.values())
    return {
        "a_incomplete_count": a_count,
        "b_incomplete_count": b_count,
        "persistent_count": persistent_count,
        "new_in_a_count": sum(new_in_a.values()),
        "recovered_in_a_count": sum(recovered_in_a.values()),
        "changed_count": sum(changed.values()),
        "persistent_by_cause": dict(sorted(persistent.items())),
        "new_in_a_by_cause": dict(sorted(new_in_a.items())),
        "recovered_in_a_by_cause": dict(sorted(recovered_in_a.items())),
        "changed_by_cause": dict(sorted(changed.items())),
        "transitions": transitions,
    }


def _collection_coverage_warnings(
    a_coverage: Mapping[int, _HostCollectionCoverage],
    b_coverage: Mapping[int, _HostCollectionCoverage],
) -> tuple[str, ...]:
    """Return one concise warning when either run has collection incidents."""

    a_summary = _collection_coverage_summary(a_coverage)
    b_summary = _collection_coverage_summary(b_coverage)
    a_affected = int(a_summary["affected_host_count"])
    b_affected = int(b_summary["affected_host_count"])
    if not a_affected and not b_affected:
        return ()
    return (
        "Collection coverage is incomplete for topology-sensitive observations on "
        f"A={a_affected} and B={b_affected} actively queried host(s). "
        "Affected differences may describe missing observations rather than a "
        "confirmed network change; inspect comparison.summary.collection_coverage "
        "and each host's collection_coverage details.",
    )


def _effective_table_status(
    coverage: _HostCollectionCoverage,
    protocol: str,
) -> str:
    """Return an operator-facing status for one protocol collection boundary."""

    table = protocol.casefold()
    explicit = coverage.neighbor_status_for(table)
    if explicit is not None:
        return explicit
    if table in coverage.failed_protocols:
        return "failed"
    if coverage.all_neighbors_incomplete:
        return coverage.host_state or "incomplete"
    return "complete"


def _coverage_source(
    *,
    present_observer: Mapping[str, Any],
    missing_observer: Mapping[str, Any],
    missing_side: str,
    protocol: str,
    coverage: _HostCollectionCoverage,
) -> _CoverageSource | None:
    """Build one source when the paired observer lacks authoritative coverage."""

    if coverage.authoritative_neighbor_negative(protocol):
        return None
    present_id = present_observer.get("id")
    missing_id = missing_observer.get("id")
    if not isinstance(present_id, int) or isinstance(present_id, bool):
        return None
    if not isinstance(missing_id, int) or isinstance(missing_id, bool):
        return None
    status = _effective_table_status(coverage, protocol)
    table = coverage.neighbor_source_for(protocol)
    payload = {
        "missing_side": missing_side,
        "missing_observer_id": missing_id,
        "protocol": protocol,
        "table": table,
        "status": status,
    }
    return _CoverageSource(
        incident_key="coverage:" + stable_fingerprint(payload)[:24],
        missing_side=missing_side,
        present_observer_id=present_id,
        present_observer_name=str(
            present_observer.get("preferred_name")
            or present_observer.get("snmp_sysname")
            or "unknown"
        ),
        missing_observer_id=missing_id,
        missing_observer_name=str(
            missing_observer.get("preferred_name")
            or missing_observer.get("snmp_sysname")
            or "unknown"
        ),
        protocol=protocol,
        table=table,
        status=status,
        message=coverage.neighbor_message_for(protocol),
    )


def _interface_resolution_coverage_source(
    *,
    present_observer: Mapping[str, Any],
    missing_observer: Mapping[str, Any],
    missing_side: str,
    protocol: str,
    coverage: _HostCollectionCoverage,
) -> _CoverageSource | None:
    """Build incident provenance for protocol rows with unresolved local ports."""

    status = coverage.interface_status_for(protocol)
    if status in {None, "complete", "not_attempted"}:
        return None
    present_id = present_observer.get("id")
    missing_id = missing_observer.get("id")
    if not isinstance(present_id, int) or isinstance(present_id, bool):
        return None
    if not isinstance(missing_id, int) or isinstance(missing_id, bool):
        return None
    table = coverage.interface_source_for(protocol)
    payload = {
        "missing_side": missing_side,
        "missing_observer_id": missing_id,
        "protocol": protocol,
        "table": table,
        "status": status,
    }
    return _CoverageSource(
        incident_key="coverage:" + stable_fingerprint(payload)[:24],
        missing_side=missing_side,
        present_observer_id=present_id,
        present_observer_name=str(
            present_observer.get("preferred_name")
            or present_observer.get("snmp_sysname")
            or "unknown"
        ),
        missing_observer_id=missing_id,
        missing_observer_name=str(
            missing_observer.get("preferred_name")
            or missing_observer.get("snmp_sysname")
            or "unknown"
        ),
        protocol=protocol,
        table=table,
        status=status,
        message=coverage.interface_message_for(protocol),
    )


def _deduplicate_coverage_sources(
    sources: Sequence[_CoverageSource],
) -> tuple[_CoverageSource, ...]:
    """Return deterministic unique incident paths without losing provenance."""

    unique: dict[str, _CoverageSource] = {}
    for source in sources:
        key = json.dumps(source.to_json(), sort_keys=True, separators=(",", ":"))
        unique.setdefault(key, source)
    return tuple(unique[key] for key in sorted(unique))


def _identity_empty_legacy_observation(host: Mapping[str, Any]) -> bool:
    """Return whether a historical one-sided host came from an empty CDP row.

    Collection prevents these shells at materialization time. The diff still has
    to replay 0.32.1 evidence safely, so an old row with neither device ID nor
    usable endpoint identity is classified as invalid source evidence instead of
    a confirmed newly present entity.
    """

    preferred = str(host.get("preferred_name") or "").strip().casefold()
    names = host.get("names")
    addresses = host.get("addresses")
    address_values: list[Any] = []
    if isinstance(addresses, Mapping):
        for value in addresses.values():
            if isinstance(value, list):
                address_values.extend(value)
    if preferred not in {"", "unknown", "none", "null", "n/a", "-"}:
        return False
    if isinstance(names, list) and any(str(value).strip() for value in names):
        return False
    if any(str(value).strip() for value in address_values):
        return False
    if host.get("chassis_id") or host.get("snmp_sysname"):
        return False
    if str(host.get("last_seen_source") or "").casefold() != "cdp":
        return False
    observed_by = host.get("observed_by_neighbors")
    rows = observed_by if isinstance(observed_by, list) else []
    if not rows:
        return False
    for row in rows:
        if not isinstance(row, Mapping) or _neighbor_protocols(row) != {"cdp"}:
            return False
        details = row.get("details")
        details = details if isinstance(details, Mapping) else {}
        if row.get("observed_name") or row.get("observed_addresses"):
            return False
        if details.get("device_id") or details.get("cdp.device_id"):
            return False
    return True


def _one_sided_presence_assessments(
    *,
    present_hosts: Sequence[Mapping[str, Any]],
    present_only: Sequence[Mapping[str, Any]],
    present_to_missing: Mapping[int, int],
    missing_hosts_by_id: Mapping[int, Mapping[str, Any]],
    missing_coverage: Mapping[int, _HostCollectionCoverage],
    observed_side: str,
    missing_side: str,
) -> dict[int, _OneSidedPresenceAssessment]:
    """Qualify one-sided hosts using direct and recursive discovery provenance.

    A paired observer whose protocol table failed cannot supply a trustworthy
    negative observation.  Endpoints seen through that table, and descendants
    reached only by recursively discovering one of those endpoints, remain
    durable observations but are not confirmed additions or removals.
    """

    present_by_id = {
        int(host["id"]): host
        for host in present_hosts
        if isinstance(host.get("id"), int) and not isinstance(host.get("id"), bool)
    }
    only_by_id = {
        int(host["id"]): host
        for host in present_only
        if isinstance(host.get("id"), int) and not isinstance(host.get("id"), bool)
    }
    direct_sources: dict[int, tuple[_CoverageSource, ...]] = {}
    recursive_dependencies: dict[int, tuple[int, ...]] = {}

    for host_id, host in only_by_id.items():
        sources: list[_CoverageSource] = []
        dependencies: set[int] = set()
        observed_by = host.get("observed_by_neighbors")
        rows = observed_by if isinstance(observed_by, list) else []
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            observer_id = row.get("host_ref")
            if not isinstance(observer_id, int) or isinstance(observer_id, bool):
                continue
            if observer_id in only_by_id:
                dependencies.add(observer_id)
                continue
            missing_observer_id = present_to_missing.get(observer_id)
            if missing_observer_id is None:
                continue
            present_observer = present_by_id.get(observer_id)
            missing_observer = missing_hosts_by_id.get(missing_observer_id)
            if present_observer is None or missing_observer is None:
                continue
            opposite_coverage = missing_coverage.get(missing_observer_id, _COMPLETE_COLLECTION)
            for protocol in sorted(_neighbor_protocols(row)):
                source = _coverage_source(
                    present_observer=present_observer,
                    missing_observer=missing_observer,
                    missing_side=missing_side,
                    protocol=protocol,
                    coverage=opposite_coverage,
                )
                if source is not None:
                    sources.append(source)
        direct_sources[host_id] = _deduplicate_coverage_sources(sources)
        recursive_dependencies[host_id] = tuple(sorted(dependencies))

    assessments: dict[int, _OneSidedPresenceAssessment] = {}
    for host_id, host in sorted(only_by_id.items()):
        if direct_sources[host_id]:
            assessments[host_id] = _OneSidedPresenceAssessment(
                side=observed_side,
                host=dict(host),
                presence_status="uncertain",
                presence_confidence="coverage_uncertain",
                semantic_qualification="coverage_uncertain",
                reasons=(
                    "presence in the other run is not observable because the paired observer protocol table is incomplete",
                ),
                coverage_sources=direct_sources[host_id],
            )

    # Resolve descendants to a fixed point. Each pass can expose one additional
    # level below a managed observer hidden by the original collection incident.
    while True:
        changed = False
        for host_id, host in sorted(only_by_id.items()):
            if host_id in assessments:
                continue
            inherited: list[_CoverageSource] = []
            for dependency in recursive_dependencies[host_id]:
                parent = assessments.get(dependency)
                if parent is None or not parent.coverage_uncertain:
                    continue
                parent_host = only_by_id[dependency]
                for original in parent.coverage_sources:
                    source = original
                    if not source.recursive_path:
                        source = source.as_recursive(
                            dependency,
                            str(parent_host.get("preferred_name") or "unknown"),
                        )
                    inherited.append(
                        source.as_recursive(
                            host_id,
                            str(host.get("preferred_name") or "unknown"),
                        )
                    )
            if inherited:
                assessments[host_id] = _OneSidedPresenceAssessment(
                    side=observed_side,
                    host=dict(host),
                    presence_status="uncertain",
                    presence_confidence="coverage_uncertain",
                    semantic_qualification="coverage_uncertain",
                    reasons=(
                        "recursive discovery provenance is downstream of an incomplete observer protocol table",
                    ),
                    coverage_sources=_deduplicate_coverage_sources(inherited),
                )
                changed = True
        if not changed:
            break

    for host_id, host in sorted(only_by_id.items()):
        if host_id in assessments:
            continue
        if _identity_empty_legacy_observation(host):
            assessments[host_id] = _OneSidedPresenceAssessment(
                side=observed_side,
                host=dict(host),
                presence_status="uncertain",
                presence_confidence="ambiguous",
                semantic_qualification="ambiguous",
                reasons=(
                    "legacy CDP observation lacks mandatory device ID and remote port identity",
                ),
            )
            continue
        side_status = f"{observed_side}_only"
        assessments[host_id] = _OneSidedPresenceAssessment(
            side=observed_side,
            host=dict(host),
            presence_status=side_status,
            presence_confidence="confirmed",
            semantic_qualification="confirmed",
        )
    return assessments


def _one_sided_host_payload(
    assessment: _OneSidedPresenceAssessment,
) -> dict[str, Any]:
    """Render one one-sided host with explicit presence semantics."""

    host = assessment.host
    learned = host.get("learned_neighbors")
    learned_rows = learned if isinstance(learned, list) else []
    side_status = f"{assessment.side}_only"
    sources = [source.to_json() for source in assessment.coverage_sources]
    return {
        **_host_identity(host),
        "observed_side": assessment.side,
        "would_have_been": side_status,
        "presence_status": assessment.presence_status,
        "presence_confidence": assessment.presence_confidence,
        "semantic_qualification": assessment.semantic_qualification,
        "uncertainty_reasons": list(assessment.reasons),
        "coverage_source": sources[0] if len(sources) == 1 else None,
        "coverage_sources": sources,
        "learned_neighbor_count": len(learned_rows),
        "learned_neighbors": learned_rows,
    }


def _incident_record(
    records: dict[str, dict[str, Any]], source: Mapping[str, Any]
) -> dict[str, Any]:
    """Return the mutable aggregate for one originating coverage incident."""

    key = str(source.get("incident_key") or "")
    if key not in records:
        records[key] = {
            "incident_key": key,
            "missing_side": source.get("missing_side"),
            "observer": copy.deepcopy(source.get("observer")),
            "protocol": source.get("protocol"),
            "table": source.get("table"),
            "status": source.get("status"),
            "message": source.get("message"),
            "source_views": set(),
            "affected_entities": {},
            "affected_relationships": set(),
            "recursive_relationships": set(),
            "recursive_descendants": {},
            "recursive_paths": set(),
            "affected_graph_entities": set(),
            "affected_graph_relationships": set(),
            "dependent_difference_refs": set(),
        }
    return records[key]


def _graph_entity_keys_by_host(graph: object) -> dict[int, tuple[str, ...]]:
    """Return topology-graph entity keys indexed by compatibility host reference."""

    if not isinstance(graph, Mapping):
        return {}
    values: defaultdict[int, set[str]] = defaultdict(set)
    entities = graph.get("entities")
    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, Mapping):
            continue
        entity_key = str(entity.get("entity_key") or "")
        refs = entity.get("host_refs")
        for host_id in refs if isinstance(refs, list) else []:
            if isinstance(host_id, int) and not isinstance(host_id, bool):
                values[host_id].add(entity_key)
    return {host_id: tuple(sorted(entity_keys)) for host_id, entity_keys in values.items()}


def _topology_health_sources(
    *,
    side: str,
    coverage: Mapping[int, _HostCollectionCoverage],
    hosts_by_id: Mapping[int, Mapping[str, Any]],
    peer_hosts_by_id: Mapping[int, Mapping[str, Any]],
    host_map: Mapping[int, int],
    graph: object,
    peer_graph: object,
) -> list[dict[str, Any]]:
    """Return every topology-sensitive collection gap, even without a diff row.

    A collection incident is operationally relevant even when the compared runs
    happen to contain no relationship whose reported change depends on it.  The
    graph-native health inventory lets the report distinguish that benign case
    from a difference that is genuinely coverage-qualified.
    """

    peer_side = "b" if side == "a" else "a"
    entity_keys = _graph_entity_keys_by_host(graph)
    peer_entity_keys = _graph_entity_keys_by_host(peer_graph)
    sources: list[dict[str, Any]] = []
    for host_id, item in sorted(coverage.items()):
        if item.query_disposition in {"no_query", "out_of_scope"}:
            continue
        host = hosts_by_id.get(host_id, {})
        peer_id = host_map.get(host_id)
        peer = peer_hosts_by_id.get(peer_id, {}) if peer_id is not None else {}
        issues: dict[tuple[str, str, str], str | None] = {}
        if item.host_state != "complete":
            status = item.status_for("system") or item.host_state or "failed"
            issues[("system", "system", status)] = item.message_for("system")
        for protocol in sorted(item.failed_protocols):
            status = item.neighbor_status_for(protocol) or "failed"
            table = item.neighbor_source_for(protocol)
            issues[(protocol, table, status)] = item.neighbor_message_for(protocol)
        for protocol in sorted(item.unresolved_interface_protocols):
            status = item.interface_status_for(protocol) or "unresolved"
            table = item.interface_source_for(protocol)
            issues[(protocol, table, status)] = item.interface_message_for(protocol)
        interface_status = item.status_for("interfaces")
        if interface_status not in {None, "complete", "not_attempted"}:
            issues[("interfaces", "interfaces", interface_status)] = item.message_for("interfaces")
        for (protocol, table, status), message in sorted(issues.items()):
            payload = {
                "missing_side": side,
                "missing_observer_id": host_id,
                "protocol": protocol,
                "table": table,
                "status": status,
            }
            observer = {
                side: {
                    **_host_identity(host),
                    "entity_keys": list(entity_keys.get(host_id, ())),
                },
                peer_side: {
                    **_host_identity(peer),
                    "entity_keys": list(peer_entity_keys.get(peer_id, ()))
                    if peer_id is not None
                    else [],
                },
            }
            sources.append(
                {
                    "incident_key": "coverage:" + stable_fingerprint(payload)[:24],
                    "missing_side": side,
                    "observer": observer,
                    "protocol": protocol,
                    "table": table,
                    "status": status,
                    "message": message,
                    "origin": "direct",
                    "recursive_path": [],
                    "source_kind": "topology_graph_health",
                    "query_disposition": item.query_disposition,
                }
            )
    return sources


def _relationship_impact_key(comparison: Mapping[str, Any], neighbor: Mapping[str, Any]) -> str:
    """Return a stable key for one derivative relationship comparison row."""

    def compact(row: Any) -> dict[str, Any] | None:
        if not isinstance(row, Mapping):
            return None
        return {
            "host_ref": row.get("host_ref"),
            "local_interface": row.get("local_interface"),
            "remote_interface": row.get("remote_interface"),
            "protocols": sorted(str(value) for value in row.get("protocols", []))
            if isinstance(row.get("protocols"), list)
            else [],
        }

    return stable_fingerprint(
        {
            "observer_a": comparison.get("a"),
            "observer_b": comparison.get("b"),
            "a": compact(neighbor.get("a")),
            "b": compact(neighbor.get("b")),
        }
    )


def _aggregate_collection_incidents(
    comparisons: Sequence[Mapping[str, Any]],
    assessments: Sequence[_OneSidedPresenceAssessment],
    *,
    graph_comparison: Mapping[str, Any] | None = None,
    health_sources: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Aggregate derivative uncertainty beneath each failed collector/table.

    A single failed LLDP table can hide hundreds of rows. Operators need one
    actionable incident with impact counts, not hundreds of apparently unrelated
    topology alarms. The detailed host and neighbor records still retain their
    individual provenance.
    """

    records: dict[str, dict[str, Any]] = {}
    for source in health_sources:
        record = _incident_record(records, source)
        record["source_views"].add("topology_graph_health")

    for assessment in assessments:
        if not assessment.coverage_uncertain:
            continue
        host_id = assessment.host.get("id")
        entity_key = f"{assessment.side}:{host_id}"
        entity = {
            "observed_side": assessment.side,
            **_host_identity(assessment.host),
        }
        for source in assessment.coverage_sources:
            payload = source.to_json()
            record = _incident_record(records, payload)
            record["source_views"].add("compatibility_projection")
            learned = assessment.host.get("learned_neighbors")
            rows = learned if isinstance(learned, list) else []
            for index, row in enumerate(rows):
                if not isinstance(row, Mapping):
                    continue
                record["recursive_relationships"].add(
                    stable_fingerprint(
                        {
                            "observed_side": assessment.side,
                            "source_host_id": host_id,
                            "row_index": index,
                            "target_host_ref": row.get("host_ref"),
                            "local_interface": row.get("local_interface"),
                            "remote_interface": row.get("remote_interface"),
                            "protocols": sorted(_neighbor_protocols(row)),
                        }
                    )
                )
            if source.origin == "recursive":
                record["recursive_descendants"][entity_key] = entity
                path = json.dumps(
                    payload.get("recursive_path", []),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                record["recursive_paths"].add(path)
            else:
                record["affected_entities"][entity_key] = entity

    for comparison in comparisons:
        host_differences = comparison.get("host_differences")
        for difference in host_differences if isinstance(host_differences, list) else []:
            if not isinstance(difference, Mapping):
                continue
            sources = difference.get("coverage_sources")
            if not isinstance(sources, list) or not sources:
                continue
            for source in sources:
                if not isinstance(source, Mapping):
                    continue
                record = _incident_record(records, source)
                record["source_views"].add("compatibility_projection")
                attribute_key = stable_fingerprint(
                    {
                        "a": comparison.get("a"),
                        "b": comparison.get("b"),
                        "path": difference.get("path"),
                    }
                )
                record.setdefault("affected_attributes", {})[attribute_key] = {
                    "a": copy.deepcopy(comparison.get("a")),
                    "b": copy.deepcopy(comparison.get("b")),
                    "path": difference.get("path"),
                }
        for section in ("learned_neighbors", "observed_by_neighbors"):
            neighbors = comparison.get(section)
            for neighbor in neighbors if isinstance(neighbors, list) else []:
                if not isinstance(neighbor, Mapping):
                    continue
                sources = neighbor.get("coverage_sources")
                if not isinstance(sources, list) or not sources:
                    continue
                relationship_key = _relationship_impact_key(comparison, neighbor)
                for source in sources:
                    if not isinstance(source, Mapping):
                        continue
                    record = _incident_record(records, source)
                    record["source_views"].add("compatibility_projection")
                    record["affected_relationships"].add(relationship_key)
                    record["dependent_difference_refs"].add(f"compatibility:{relationship_key}")

    graph_comparison = graph_comparison or {}
    for section, reference_field in (
        ("entity_correspondence", "component_key"),
        ("relationship_groups", "relationship_component_key"),
    ):
        values = graph_comparison.get(section)
        for item in values if isinstance(values, list) else []:
            if not isinstance(item, Mapping):
                continue
            sources = item.get("coverage_sources")
            if not isinstance(sources, list) or not sources:
                continue
            reference = str(item.get(reference_field) or "")
            status = str(item.get("status") or "unknown")
            is_difference = status not in {"same", "same_ambiguous"}
            for source in sources:
                if not isinstance(source, Mapping):
                    continue
                record = _incident_record(records, source)
                record["source_views"].add("topology_graph")
                if section == "entity_correspondence":
                    record["affected_graph_entities"].add(reference)
                else:
                    record["affected_graph_relationships"].add(reference)
                if is_difference:
                    record["dependent_difference_refs"].add(f"topology_graph:{reference}")

    result: list[dict[str, Any]] = []
    for key in sorted(records):
        record = records[key]
        entities = list(record.pop("affected_entities").values())
        relationships = record.pop("affected_relationships")
        recursive_relationships = record.pop("recursive_relationships")
        descendants = list(record.pop("recursive_descendants").values())
        attributes = list(record.pop("affected_attributes", {}).values())
        paths = [json.loads(value) for value in sorted(record.pop("recursive_paths"))]
        graph_entities = sorted(record.pop("affected_graph_entities"))
        graph_relationships = sorted(record.pop("affected_graph_relationships"))
        dependent_differences = sorted(record.pop("dependent_difference_refs"))
        source_views = sorted(record.pop("source_views"))
        result.append(
            {
                **record,
                "source_views": source_views,
                "reported_difference_depends_on_gap": bool(dependent_differences),
                "dependent_difference_count": len(dependent_differences),
                "dependent_difference_refs": dependent_differences,
                "affected_graph_entity_count": len(graph_entities),
                "affected_graph_relationship_count": len(graph_relationships),
                "affected_graph_entity_refs": graph_entities,
                "affected_graph_relationship_refs": graph_relationships,
                "affected_relationship_count": len(relationships),
                "recursive_relationship_count": len(recursive_relationships),
                "total_affected_relationship_count": len(relationships)
                + len(recursive_relationships),
                "affected_remote_entity_count": len(entities),
                "recursive_descendant_count": len(descendants),
                "total_affected_entity_count": len(entities) + len(descendants),
                "affected_attribute_count": len(attributes),
                "affected_attributes": attributes,
                "affected_remote_entities": sorted(
                    entities,
                    key=lambda item: (
                        str(item.get("observed_side")),
                        int(item.get("id")) if isinstance(item.get("id"), int) else -1,
                    ),
                ),
                "recursive_descendants": sorted(
                    descendants,
                    key=lambda item: (
                        str(item.get("observed_side")),
                        int(item.get("id")) if isinstance(item.get("id"), int) else -1,
                    ),
                ),
                "recursive_paths": paths,
            }
        )
    return sorted(
        result,
        key=lambda item: (
            not bool(item["reported_difference_depends_on_gap"]),
            -int(item["affected_relationship_count"]),
            -int(item["total_affected_entity_count"]),
            str(item["incident_key"]),
        ),
    )


def _neighbor_chassis_values(neighbor: Mapping[str, Any]) -> set[str]:
    """Return normalized chassis values carried by one observed-by row."""

    details = neighbor.get("details")
    if not isinstance(details, Mapping):
        return set()
    values: set[str] = set()

    def collect(value: Any, *, key: str | None = None) -> None:
        if key is not None and key.rsplit(".", 1)[-1] == "chassis_id":
            if value not in (None, ""):
                values.add(str(value).strip().casefold())
            return
        if isinstance(value, Mapping):
            for child_key, child_value in value.items():
                collect(child_value, key=str(child_key))

    collect(details)
    return values


def _attribute_observation_coverage_sources(
    *,
    present_host: Mapping[str, Any],
    missing_host: Mapping[str, Any],
    present_to_missing: Mapping[int, int],
    present_hosts_by_id: Mapping[int, Mapping[str, Any]],
    missing_hosts_by_id: Mapping[int, Mapping[str, Any]],
    missing_coverage: Mapping[int, _HostCollectionCoverage],
    present_only_assessments: Mapping[int, _OneSidedPresenceAssessment],
    missing_side: str,
) -> tuple[_CoverageSource, ...]:
    """Trace a missing host chassis attribute to its LLDP observation source.

    A paired endpoint may remain visible through CDP while the LLDP observer
    that supplied its MAC chassis identity is absent behind an upstream
    collection incident. In that case ``None`` means not observed, not a
    confirmed chassis removal. Provenance is deliberately limited to an exact
    chassis value carried by an LLDP/LLDPv2 observed-by row.
    """

    chassis = present_host.get("chassis_id")
    if chassis in (None, ""):
        return ()
    target = str(chassis).strip().casefold()
    rows = present_host.get("observed_by_neighbors")
    if not isinstance(rows, list):
        return ()
    sources: list[_CoverageSource] = []
    for row in rows:
        if not isinstance(row, Mapping) or target not in _neighbor_chassis_values(row):
            continue
        observer_ref = row.get("host_ref")
        if not isinstance(observer_ref, int) or isinstance(observer_ref, bool):
            continue
        protocols = _neighbor_protocols(row) & {"lldp", "lldpv2"}
        if not protocols:
            continue
        missing_ref = present_to_missing.get(observer_ref)
        if missing_ref is not None:
            present_observer = present_hosts_by_id.get(observer_ref)
            missing_observer = missing_hosts_by_id.get(missing_ref)
            coverage = missing_coverage.get(missing_ref, _COMPLETE_COLLECTION)
            if present_observer is None or missing_observer is None:
                continue
            for protocol in sorted(protocols):
                source = _coverage_source(
                    present_observer=present_observer,
                    missing_observer=missing_observer,
                    missing_side=missing_side,
                    protocol=protocol,
                    coverage=coverage,
                )
                if source is not None:
                    sources.append(source)
            continue
        assessment = present_only_assessments.get(observer_ref)
        if assessment is None or not assessment.coverage_uncertain:
            continue
        host_id = missing_host.get("id")
        host_name = str(
            missing_host.get("preferred_name") or present_host.get("preferred_name") or "unknown"
        )
        if isinstance(host_id, int) and not isinstance(host_id, bool):
            sources.extend(
                source.as_recursive(host_id, host_name) for source in assessment.coverage_sources
            )
        else:
            sources.extend(assessment.coverage_sources)
    return _deduplicate_coverage_sources(sources)


def _qualify_host_attribute_differences(
    differences: Sequence[FieldDifference],
    *,
    pair: HostPair,
    a_to_b: Mapping[int, int],
    b_to_a: Mapping[int, int],
    a_hosts_by_id: Mapping[int, Mapping[str, Any]],
    b_hosts_by_id: Mapping[int, Mapping[str, Any]],
    a_coverage: Mapping[int, _HostCollectionCoverage],
    b_coverage: Mapping[int, _HostCollectionCoverage],
    a_presence: Mapping[int, _OneSidedPresenceAssessment],
    b_presence: Mapping[int, _OneSidedPresenceAssessment],
) -> tuple[FieldDifference, ...]:
    """Qualify LLDP-derived chassis gaps with collection provenance."""

    qualified: list[FieldDifference] = []
    for difference in differences:
        if difference.path != "chassis_id" or difference.kind != "changed":
            qualified.append(difference)
            continue
        sources: tuple[_CoverageSource, ...] = ()
        if difference.a in (None, "") and difference.b not in (None, ""):
            sources = _attribute_observation_coverage_sources(
                present_host=pair.b,
                missing_host=pair.a,
                present_to_missing=b_to_a,
                present_hosts_by_id=b_hosts_by_id,
                missing_hosts_by_id=a_hosts_by_id,
                missing_coverage=a_coverage,
                present_only_assessments=b_presence,
                missing_side="a",
            )
        elif difference.b in (None, "") and difference.a not in (None, ""):
            sources = _attribute_observation_coverage_sources(
                present_host=pair.a,
                missing_host=pair.b,
                present_to_missing=a_to_b,
                present_hosts_by_id=a_hosts_by_id,
                missing_hosts_by_id=b_hosts_by_id,
                missing_coverage=b_coverage,
                present_only_assessments=a_presence,
                missing_side="b",
            )
        qualified.append(
            replace(
                difference,
                kind="not_observed",
                provenance="neighbor_observation",
                coverage_sources=sources,
            )
            if sources
            else difference
        )
    return tuple(qualified)


def _attribute_uncertainty_by_host(
    comparisons: Sequence[Mapping[str, Any]],
) -> tuple[dict[int, list[dict[str, Any]]], dict[int, list[dict[str, Any]]]]:
    """Return graph-ready coverage sources for both projections of each pair.

    A missing attribute can make the value-bearing side produce an identity
    component that has no counterpart at all.  Associate the provenance with
    both run-local host projections so graph comparison can qualify either a
    changed component or an identity-derived one-sided component.
    """

    by_side: dict[str, dict[int, list[dict[str, Any]]]] = {"a": {}, "b": {}}
    for comparison in comparisons:
        differences = comparison.get("host_differences")
        if not isinstance(differences, list):
            continue
        for difference in differences:
            if not isinstance(difference, Mapping) or difference.get("kind") != "not_observed":
                continue
            sources = difference.get("coverage_sources")
            if not isinstance(sources, list):
                continue
            for source in sources:
                if not isinstance(source, Mapping):
                    continue
                payload = copy.deepcopy(dict(source))
                payload["attribute_path"] = str(difference.get("path") or "")
                payload["attribute_provenance"] = str(difference.get("provenance") or "unknown")
                for side in ("a", "b"):
                    identity = comparison.get(side)
                    if not isinstance(identity, Mapping):
                        continue
                    host_id = identity.get("id")
                    if not isinstance(host_id, int) or isinstance(host_id, bool):
                        continue
                    bucket = by_side[side].setdefault(host_id, [])
                    if payload not in bucket:
                        bucket.append(copy.deepcopy(payload))
    return by_side["a"], by_side["b"]


def _match_confidence(pair: HostPair) -> MatchConfidence:
    """Return a conservative categorical confidence for one host association.

    These labels are explainable engineering categories, not calibrated
    probabilities.  Strong self/hardware identifiers are ``verified``; unique
    topology-scoped MAC evidence and other physical evidence are ``high``; a
    unique address is ``medium`` unless an exact name also corroborates it; and
    name-only pairing remains ``low``.
    """

    evidence = set(pair.evidence)
    if any(token.startswith(("serial:", "engine:", "sep_mac:")) for token in evidence):
        return "verified"
    if pair.tier in {"physical", "edge_context"}:
        return "high"
    if pair.tier == "address":
        return "high" if any(token.startswith("name:") for token in evidence) else "medium"
    return "low"


def _comparison_payload(
    pair: HostPair,
    *,
    a_completed: datetime | None,
    b_completed: datetime | None,
    a_to_b: Mapping[int, int],
    b_to_a: Mapping[int, int],
    include_observed_by: bool,
    include_collection_timing: bool,
    a_coverage: Mapping[int, _HostCollectionCoverage],
    b_coverage: Mapping[int, _HostCollectionCoverage],
    a_hosts_by_id: Mapping[int, Mapping[str, Any]],
    b_hosts_by_id: Mapping[int, Mapping[str, Any]],
    a_presence: Mapping[int, _OneSidedPresenceAssessment],
    b_presence: Mapping[int, _OneSidedPresenceAssessment],
) -> dict[str, Any]:
    a_host_coverage = a_coverage.get(int(pair.a["id"]), _COMPLETE_COLLECTION)
    b_host_coverage = b_coverage.get(int(pair.b["id"]), _COMPLETE_COLLECTION)
    fields = compare_host_fields(
        pair.a,
        pair.b,
        a_completed=a_completed,
        b_completed=b_completed,
        a_coverage=a_host_coverage,
        b_coverage=b_host_coverage,
    )
    fields = _qualify_host_attribute_differences(
        fields,
        pair=pair,
        a_to_b=a_to_b,
        b_to_a=b_to_a,
        a_hosts_by_id=a_hosts_by_id,
        b_hosts_by_id=b_hosts_by_id,
        a_coverage=a_coverage,
        b_coverage=b_coverage,
        a_presence=a_presence,
        b_presence=b_presence,
    )
    presentation_fields = compare_host_presentation_fields(pair.a, pair.b)
    collection_fields = compare_host_collection_fields(
        pair.a,
        pair.b,
        include_timing=include_collection_timing,
    )
    definite_fields = tuple(item for item in fields if item.kind != "not_observed")
    uncertain_fields = tuple(item for item in fields if item.kind == "not_observed")
    learned = compare_neighbors(
        pair.a.get("learned_neighbors"),
        pair.b.get("learned_neighbors"),
        a_to_b_host_ids=a_to_b,
        b_to_a_host_ids=b_to_a,
        a_coverage=a_host_coverage,
        b_coverage=b_host_coverage,
        a_observer=pair.a,
        b_observer=pair.b,
    )
    observed = ()
    if include_observed_by:
        observed = compare_neighbors(
            pair.a.get("observed_by_neighbors"),
            pair.b.get("observed_by_neighbors"),
            a_to_b_host_ids=a_to_b,
            b_to_a_host_ids=b_to_a,
            a_coverage=a_host_coverage,
            b_coverage=b_host_coverage,
            a_observer=pair.a,
            b_observer=pair.b,
        )
    learned_deltas = sum(item.status != "same" for item in learned)
    observed_deltas = sum(item.status != "same" for item in observed)
    learned_uncertain = sum(item.status == "uncertain" for item in learned)
    observed_uncertain = sum(item.status == "uncertain" for item in observed)
    definite_neighbor_delta = any(
        item.status
        in {
            "changed",
            "moved",
            "protocol_changed",
            "management_address_changed",
            "relationship_evidence_changed",
            "a_only",
            "b_only",
        }
        for item in (*learned, *observed)
    )
    if definite_fields or definite_neighbor_delta:
        status = "changed"
    elif uncertain_fields or learned_uncertain or observed_uncertain:
        status = "uncertain"
    elif presentation_fields and collection_fields:
        status = "presentation_and_collection_only"
    elif presentation_fields:
        status = "presentation_only"
    elif collection_fields:
        status = "collection_only"
    else:
        status = "same"
    return {
        "status": status,
        "host_status": (
            "changed" if definite_fields else "uncertain" if uncertain_fields else "same"
        ),
        "a": _host_identity(pair.a),
        "b": _host_identity(pair.b),
        "match": {
            "tier": pair.tier,
            "confidence": _match_confidence(pair),
            "evidence": list(pair.evidence),
        },
        "collection_coverage": {
            "a": a_host_coverage.to_json(),
            "b": b_host_coverage.to_json(),
        },
        "host_differences": [_field_diff_json(item) for item in fields],
        "presentation_status": "changed" if presentation_fields else "same",
        "presentation_differences": [_field_diff_json(item) for item in presentation_fields],
        "collection_status": "changed" if collection_fields else "same",
        "collection_differences": [_field_diff_json(item) for item in collection_fields],
        "learned_neighbors": [_neighbor_json(item) for item in learned],
        "observed_by_neighbors": [_neighbor_json(item) for item in observed],
        "host_difference_count": len(fields),
        "host_definite_difference_count": len(definite_fields),
        "host_uncertain_difference_count": len(uncertain_fields),
        "presentation_difference_count": len(presentation_fields),
        "collection_difference_count": len(collection_fields),
        "learned_neighbor_difference_count": learned_deltas,
        "observed_by_neighbor_difference_count": observed_deltas,
        "learned_neighbor_uncertain_count": learned_uncertain,
        "observed_by_neighbor_uncertain_count": observed_uncertain,
    }


def _load_pair(
    config: AppConfig,
    source_a: ResolvedDiffSource,
    source_b: ResolvedDiffSource,
) -> tuple[
    DiscoveryDocument,
    DiscoveryDocument,
    ResolvedDiffSource,
    ResolvedDiffSource,
    dict[int, _HostCollectionCoverage],
    dict[int, _HostCollectionCoverage],
]:
    a_document = load_discovery_document(config, filename=source_a.path)
    b_document = load_discovery_document(config, filename=source_b.path)
    a_schema = a_document.payload.get("schema_version")
    b_schema = b_document.payload.get("schema_version")
    if a_schema != b_schema:
        raise DiscoveryDiffError(
            f"discovery.json schema versions differ: A={a_schema!r}, B={b_schema!r}"
        )
    if a_schema != DISCOVERY_JSON_SCHEMA_VERSION:
        raise DiscoveryDiffError(
            f"unsupported discovery.json schema_version {a_schema!r}; "
            f"expected {DISCOVERY_JSON_SCHEMA_VERSION}"
        )
    source_a = _source_with_document_metadata(source_a, a_document)
    source_b = _source_with_document_metadata(source_b, b_document)
    a_coverage = _collection_coverage(a_document)
    b_coverage = _collection_coverage(b_document)
    # Error message text remains outside the comparison contract.  Coverage has
    # already retained the small host/protocol completeness facts needed by diff,
    # so release the potentially large raw arrays before host comparison.
    a_document.payload["errors"] = []
    b_document.payload["errors"] = []
    return a_document, b_document, source_a, source_b, a_coverage, b_coverage


def macro_diff(
    config: AppConfig,
    source_a: ResolvedDiffSource,
    source_b: ResolvedDiffSource,
    *,
    changes_only: bool,
    include_collection_timing: bool = False,
) -> DiffOutcome:
    """Compare host records and authoritative learned-neighbor topology for two runs."""

    (
        a_document,
        b_document,
        source_a,
        source_b,
        a_coverage,
        b_coverage,
    ) = _load_pair(config, source_a, source_b)
    a_projection = _canonicalize_compatibility_projection(a_document, a_coverage)
    b_projection = _canonicalize_compatibility_projection(b_document, b_coverage)
    a_document = a_projection.document
    b_document = b_projection.document
    a_coverage = a_projection.coverage
    b_coverage = b_projection.coverage
    pairing = pair_hosts(a_document.hosts, b_document.hosts)
    a_to_b = {int(pair.a["id"]): int(pair.b["id"]) for pair in pairing.pairs}
    b_to_a = {value: key for key, value in a_to_b.items()}
    a_hosts_by_id = {
        int(host["id"]): host
        for host in a_document.hosts
        if isinstance(host.get("id"), int) and not isinstance(host.get("id"), bool)
    }
    b_hosts_by_id = {
        int(host["id"]): host
        for host in b_document.hosts
        if isinstance(host.get("id"), int) and not isinstance(host.get("id"), bool)
    }
    a_presence = _one_sided_presence_assessments(
        present_hosts=a_document.hosts,
        present_only=pairing.a_only,
        present_to_missing=a_to_b,
        missing_hosts_by_id=b_hosts_by_id,
        missing_coverage=b_coverage,
        observed_side="a",
        missing_side="b",
    )
    b_presence = _one_sided_presence_assessments(
        present_hosts=b_document.hosts,
        present_only=pairing.b_only,
        present_to_missing=b_to_a,
        missing_hosts_by_id=a_hosts_by_id,
        missing_coverage=a_coverage,
        observed_side="b",
        missing_side="a",
    )
    confirmed_a_only = [
        host
        for host in pairing.a_only
        if a_presence[int(host["id"])].presence_confidence == "confirmed"
    ]
    confirmed_b_only = [
        host
        for host in pairing.b_only
        if b_presence[int(host["id"])].presence_confidence == "confirmed"
    ]
    uncertain_presence = [
        _one_sided_host_payload(a_presence[int(host["id"])])
        for host in pairing.a_only
        if a_presence[int(host["id"])].presence_confidence != "confirmed"
    ] + [
        _one_sided_host_payload(b_presence[int(host["id"])])
        for host in pairing.b_only
        if b_presence[int(host["id"])].presence_confidence != "confirmed"
    ]
    all_comparisons = [
        _comparison_payload(
            pair,
            a_completed=source_a.completed,
            b_completed=source_b.completed,
            a_to_b=a_to_b,
            b_to_a=b_to_a,
            include_observed_by=False,
            include_collection_timing=include_collection_timing,
            a_coverage=a_coverage,
            b_coverage=b_coverage,
            a_hosts_by_id=a_hosts_by_id,
            b_hosts_by_id=b_hosts_by_id,
            a_presence=a_presence,
            b_presence=b_presence,
        )
        for pair in pairing.pairs
    ]
    a_attribute_uncertainty, b_attribute_uncertainty = _attribute_uncertainty_by_host(
        all_comparisons
    )

    def expand_attribute_sources(
        values: Mapping[int, Sequence[Mapping[str, Any]]],
        members_by_id: Mapping[int, tuple[int, ...]],
    ) -> dict[int, Sequence[Mapping[str, Any]]]:
        expanded: dict[int, Sequence[Mapping[str, Any]]] = {}
        for host_id, sources in values.items():
            for member_id in members_by_id.get(host_id, (host_id,)):
                expanded[member_id] = sources
        return expanded

    # Reconciliation needs stable graph rows as well as changed rows because a
    # management-address or presentation-only compatibility change can map to a
    # structurally unchanged graph relationship.  Apply the operator's
    # changes-only projection only after the two views have been cross-linked.
    graph_comparison = compare_topology_graphs(
        a_document.payload.get("topology_graph"),
        b_document.payload.get("topology_graph"),
        changes_only=False,
        a_uncertain_host_refs={
            member_id
            for host_id, assessment in a_presence.items()
            if assessment.coverage_uncertain
            for member_id in a_projection.members_by_id.get(host_id, (host_id,))
        },
        b_uncertain_host_refs={
            member_id
            for host_id, assessment in b_presence.items()
            if assessment.coverage_uncertain
            for member_id in b_projection.members_by_id.get(host_id, (host_id,))
        },
        a_attribute_uncertainty=expand_attribute_sources(
            a_attribute_uncertainty, a_projection.members_by_id
        ),
        b_attribute_uncertainty=expand_attribute_sources(
            b_attribute_uncertainty, b_projection.members_by_id
        ),
    )
    one_sided_learned_observation_count = sum(
        len(host.get("learned_neighbors", []))
        for host in (*confirmed_a_only, *confirmed_b_only)
        if isinstance(host.get("learned_neighbors"), list)
    ) + sum(int(item["learned_neighbor_count"]) for item in uncertain_presence)
    reconciliation = reconcile_compatibility_and_graph(
        all_comparisons,
        graph_comparison,
        a_members_by_id=a_projection.members_by_id,
        b_members_by_id=b_projection.members_by_id,
        changes_only=changes_only,
        unrepresented_one_sided_observation_count=(one_sided_learned_observation_count),
    )
    health_sources = [
        *_topology_health_sources(
            side="a",
            coverage=a_coverage,
            hosts_by_id=a_hosts_by_id,
            peer_hosts_by_id=b_hosts_by_id,
            host_map=a_to_b,
            graph=a_document.payload.get("topology_graph"),
            peer_graph=b_document.payload.get("topology_graph"),
        ),
        *_topology_health_sources(
            side="b",
            coverage=b_coverage,
            hosts_by_id=b_hosts_by_id,
            peer_hosts_by_id=a_hosts_by_id,
            host_map=b_to_a,
            graph=b_document.payload.get("topology_graph"),
            peer_graph=a_document.payload.get("topology_graph"),
        ),
    ]
    collection_incidents = _aggregate_collection_incidents(
        all_comparisons,
        [*a_presence.values(), *b_presence.values()],
        graph_comparison=graph_comparison,
        health_sources=health_sources,
    )
    comparisons = (
        [item for item in all_comparisons if item["status"] != "same"]
        if changes_only
        else all_comparisons
    )

    changed_hosts = sum(item["host_status"] == "changed" for item in all_comparisons)
    uncertain_paired_hosts = sum(item["host_status"] == "uncertain" for item in all_comparisons)
    same_hosts = sum(item["host_status"] == "same" for item in all_comparisons)
    presentation_changed_hosts = sum(
        item["presentation_status"] == "changed" for item in all_comparisons
    )
    collection_changed_hosts = sum(
        item["collection_status"] == "changed" for item in all_comparisons
    )
    learned_same = sum(
        neighbor["status"] == "same"
        for item in all_comparisons
        for neighbor in item["learned_neighbors"]
    )
    learned_changed = sum(
        neighbor["status"] == "changed"
        for item in all_comparisons
        for neighbor in item["learned_neighbors"]
    )
    learned_moved = sum(
        neighbor["status"] == "moved"
        for item in all_comparisons
        for neighbor in item["learned_neighbors"]
    )
    learned_protocol_changed = sum(
        neighbor["status"] == "protocol_changed"
        for item in all_comparisons
        for neighbor in item["learned_neighbors"]
    )
    learned_management_address_changed = sum(
        neighbor["status"] == "management_address_changed"
        for item in all_comparisons
        for neighbor in item["learned_neighbors"]
    )
    learned_relationship_evidence_changed = sum(
        neighbor["status"] == "relationship_evidence_changed"
        for item in all_comparisons
        for neighbor in item["learned_neighbors"]
    )
    learned_a_only = sum(
        neighbor["status"] == "a_only"
        for item in all_comparisons
        for neighbor in item["learned_neighbors"]
    )
    learned_b_only = sum(
        neighbor["status"] == "b_only"
        for item in all_comparisons
        for neighbor in item["learned_neighbors"]
    )
    learned_uncertain = sum(
        neighbor["status"] == "uncertain"
        for item in all_comparisons
        for neighbor in item["learned_neighbors"]
    )
    learned_a_only += sum(
        len(host.get("learned_neighbors", []))
        for host in confirmed_a_only
        if isinstance(host.get("learned_neighbors"), list)
    )
    learned_b_only += sum(
        len(host.get("learned_neighbors", []))
        for host in confirmed_b_only
        if isinstance(host.get("learned_neighbors"), list)
    )
    learned_uncertain += sum(int(item["learned_neighbor_count"]) for item in uncertain_presence)

    ambiguities = [
        {
            "a": _host_identity(item.a),
            "candidates": [_host_identity(host) for host in item.candidates],
            "tier": item.tier,
            "conflicting_identity": item.conflicting_identity,
        }
        for item in pairing.ambiguous
    ]
    compatibility_differences = bool(
        changed_hosts
        or uncertain_paired_hosts
        or presentation_changed_hosts
        or collection_changed_hosts
        or confirmed_a_only
        or confirmed_b_only
        or uncertain_presence
        or pairing.ambiguous
        or learned_changed
        or learned_moved
        or learned_protocol_changed
        or learned_management_address_changed
        or learned_relationship_evidence_changed
        or learned_a_only
        or learned_b_only
        or learned_uncertain
    )
    # Graph-aware correspondence is the preferred entity/relationship view.
    # Entity resolution remains provisional and the graph does not infer
    # physical topology or directness. The flat host/neighbor result remains an
    # operator diagnostic during the transition, but duplicate projections no
    # longer determine whether the observed graph changed.
    has_differences = bool(
        graph_comparison.get("has_differences")
        if graph_comparison.get("available")
        else compatibility_differences
    ) or bool(
        changed_hosts
        or uncertain_paired_hosts
        or presentation_changed_hosts
        or collection_changed_hosts
        or learned_management_address_changed
        or learned_relationship_evidence_changed
    )
    incident_relationships = sum(
        int(item["total_affected_relationship_count"]) for item in collection_incidents
    )
    incident_entities = sum(
        int(item["affected_remote_entity_count"]) for item in collection_incidents
    )
    dependent_incidents = sum(
        bool(item.get("reported_difference_depends_on_gap")) for item in collection_incidents
    )
    health_only_incidents = len(collection_incidents) - dependent_incidents
    incident_observers: dict[str, set[tuple[object, object]]] = {
        "a": set(),
        "b": set(),
    }
    for item in collection_incidents:
        side = str(item.get("missing_side") or "").casefold()
        observers = item.get("observer")
        selected = observers.get(side) if isinstance(observers, Mapping) else None
        if side in incident_observers and isinstance(selected, Mapping):
            incident_observers[side].add((selected.get("id"), selected.get("preferred_name")))
    if dependent_incidents:
        incident_warning = (
            (
                "Collection coverage is incomplete for reported differences: "
                f"{dependent_incidents} collection incident(s) qualify "
                f"{incident_relationships} relationship "
                f"comparison(s) and {incident_entities} one-sided entity presence "
                "result(s); inspect comparison.collection_incidents."
            ),
        )
    elif collection_incidents:
        incident_warning = (
            (
                "Collection coverage is incomplete for topology-sensitive health "
                "observations. Gaps remain visible as warnings "
                f"on A={len(incident_observers['a'])} and "
                f"B={len(incident_observers['b'])} observer(s), but no reported "
                "difference depends on those gaps."
            ),
        )
    else:
        incident_warning = ()
    projection_warning = (
        (
            (
                "Compatibility projection reconciliation absorbed "
                f"{a_projection.absorbed_host_count} A-side and "
                f"{b_projection.absorbed_host_count} B-side duplicate fully "
                "queried managed-host row(s); raw graph evidence is unchanged."
            ),
        )
        if a_projection.absorbed_host_count or b_projection.absorbed_host_count
        else ()
    )
    consistency = reconciliation["cross_view_consistency"]
    consistency_warning = (
        (
            (
                "Compatibility and topology-graph change views require attention: "
                f"unmatched={consistency['unmatched_observation_count']}, "
                f"ambiguous={consistency['ambiguous_observation_count']}, "
                f"conflicting={consistency['conflicting_observation_count']}, "
                f"unrepresented-one-sided="
                f"{consistency['unrepresented_one_sided_observation_count']}, and "
                f"graph-only={consistency['graph_only_event_count']}; inspect "
                "comparison.cross_view_consistency and comparison.change_events."
            ),
        )
        if consistency["status"] == "attention_required"
        else ()
    )
    warnings = (
        *scope_warnings(a_document, b_document, source_a, source_b),
        *incident_warning,
        *projection_warning,
        *consistency_warning,
    )
    b_obscured = sum(
        any(source.origin == "recursive" for source in assessment.coverage_sources)
        for assessment in a_presence.values()
        if assessment.coverage_uncertain
    )
    a_obscured = sum(
        any(source.origin == "recursive" for source in assessment.coverage_sources)
        for assessment in b_presence.values()
        if assessment.coverage_uncertain
    )
    coverage_uncertain_count = sum(
        assessment.coverage_uncertain for assessment in (*a_presence.values(), *b_presence.values())
    )
    invalid_source_evidence_count = sum(
        assessment.semantic_qualification == "ambiguous"
        for assessment in (*a_presence.values(), *b_presence.values())
    )
    pairing_confidence = {
        confidence: sum(_match_confidence(pair) == confidence for pair in pairing.pairs)
        for confidence in ("verified", "high", "medium", "low")
    }
    management_address_health = _management_address_health_comparison(
        pairing,
        a_coverage,
        b_coverage,
    )
    data = {
        "options": {
            "changes_only": changes_only,
            "include_collection_timing": include_collection_timing,
        },
        "summary": {
            "topology_graph": graph_comparison.get("summary", {}),
            "change_events": reconciliation["change_event_summary"],
            "cross_view_consistency": consistency,
            "compatibility_projection_has_differences": compatibility_differences,
            "compatibility_projection": {
                "a": {
                    "raw_host_count": a_projection.raw_host_count,
                    "canonical_host_count": a_projection.canonical_host_count,
                    "duplicate_group_count": len(a_projection.groups),
                    "absorbed_host_count": a_projection.absorbed_host_count,
                },
                "b": {
                    "raw_host_count": b_projection.raw_host_count,
                    "canonical_host_count": b_projection.canonical_host_count,
                    "duplicate_group_count": len(b_projection.groups),
                    "absorbed_host_count": b_projection.absorbed_host_count,
                },
            },
            "host_pairing_confidence": pairing_confidence,
            "collection_coverage": {
                "a": _collection_coverage_summary(a_coverage, obscured_downstream_count=a_obscured),
                "b": _collection_coverage_summary(b_coverage, obscured_downstream_count=b_obscured),
            },
            "management_address_health": {
                key: value
                for key, value in management_address_health.items()
                if key != "transitions"
            },
            "collection_incidents": {
                "incident_count": len(collection_incidents),
                "reported_difference_dependent_incident_count": (dependent_incidents),
                "health_only_incident_count": health_only_incidents,
                "topology_gap_observer_count": {
                    side: len(values) for side, values in incident_observers.items()
                },
                "total_affected_relationship_count": incident_relationships,
                "directly_affected_relationship_count": sum(
                    int(item["affected_relationship_count"]) for item in collection_incidents
                ),
                "recursive_relationship_count": sum(
                    int(item["recursive_relationship_count"]) for item in collection_incidents
                ),
                "affected_remote_entity_count": incident_entities,
                "recursive_descendant_count": sum(
                    int(item["recursive_descendant_count"]) for item in collection_incidents
                ),
                "affected_attribute_count": sum(
                    int(item.get("affected_attribute_count", 0)) for item in collection_incidents
                ),
            },
            "hosts": {
                "same": same_hosts,
                "changed": changed_hosts,
                "a_only": len(confirmed_a_only),
                "b_only": len(confirmed_b_only),
                "coverage_uncertain": coverage_uncertain_count,
                "invalid_source_evidence": invalid_source_evidence_count,
                "identity_ambiguous": len(pairing.ambiguous),
                "attribute_uncertain": uncertain_paired_hosts,
                "uncertain": len(pairing.ambiguous)
                + len(uncertain_presence)
                + uncertain_paired_hosts,
            },
            "host_dimensions": {
                "entity_attributes": {
                    "same": same_hosts,
                    "changed": changed_hosts,
                    "uncertain": uncertain_paired_hosts,
                },
                "presentation": {
                    "same": len(all_comparisons) - presentation_changed_hosts,
                    "changed": presentation_changed_hosts,
                },
                "collection": {
                    "same": len(all_comparisons) - collection_changed_hosts,
                    "changed": collection_changed_hosts,
                },
            },
            "learned_neighbors": {
                "same": learned_same,
                "changed": learned_changed,
                "moved": learned_moved,
                "protocol_changed": learned_protocol_changed,
                "management_address_changed": learned_management_address_changed,
                "relationship_evidence_changed": (learned_relationship_evidence_changed),
                "a_only": learned_a_only,
                "b_only": learned_b_only,
                "uncertain": learned_uncertain,
            },
        },
        "topology_graph": graph_comparison,
        "change_events": reconciliation["change_events"],
        "cross_view_consistency": consistency,
        "projection_reconciliation": {
            "a": list(a_projection.groups),
            "b": list(b_projection.groups),
        },
        "collection_incidents": collection_incidents,
        "management_address_health": management_address_health,
        "hosts": comparisons,
        "a_only": [
            _one_sided_host_payload(a_presence[int(host["id"])]) for host in confirmed_a_only
        ],
        "b_only": [
            _one_sided_host_payload(b_presence[int(host["id"])]) for host in confirmed_b_only
        ],
        "presence_uncertain": uncertain_presence,
        "uncertain": ambiguities,
    }
    return DiffOutcome(
        status="differences_found" if has_differences else "no_differences",
        message="Differences found" if has_differences else "No differences",
        exit_code=1 if has_differences else 0,
        mode="macro",
        source_a=source_a,
        source_b=source_b,
        warnings=warnings,
        data=data,
    )


def host_diff(
    config: AppConfig,
    source_a: ResolvedDiffSource,
    source_b: ResolvedDiffSource,
    criteria: QueryCriteria,
    *,
    changes_only: bool,
    include_collection_timing: bool = False,
) -> DiffOutcome:
    """Compare one A-selected host with its evidence-matched B-side counterpart."""

    (
        a_document,
        b_document,
        source_a,
        source_b,
        a_coverage,
        b_coverage,
    ) = _load_pair(config, source_a, source_b)
    warnings = (
        *scope_warnings(a_document, b_document, source_a, source_b),
        *_collection_coverage_warnings(a_coverage, b_coverage),
    )
    graph_comparison = compare_topology_graphs(
        a_document.payload.get("topology_graph"),
        b_document.payload.get("topology_graph"),
        changes_only=changes_only,
    )
    matches = select_hosts(a_document, criteria)
    if not matches:
        return DiffOutcome(
            "no_match_first_data_set",
            "No match in the first data set was found to compare",
            4,
            "host",
            source_a,
            source_b,
            warnings,
            {"matches": []},
        )
    if len(matches) > 1:
        return DiffOutcome(
            "multiple_matches_first_data_set",
            "Multiple records matched",
            3,
            "host",
            source_a,
            source_b,
            warnings,
            {"matches": [_host_identity(host) for host in matches], "data_set": "a"},
        )

    selected = matches[0]
    pairing = pair_hosts(a_document.hosts, b_document.hosts)
    pair = next((item for item in pairing.pairs if item.a is selected), None)
    ambiguous = next((item for item in pairing.ambiguous if item.a is selected), None)
    if ambiguous is not None:
        multiple = len(ambiguous.candidates) > 1
        return DiffOutcome(
            "multiple_matches_second_data_set"
            if multiple
            else "identity_uncertain_second_data_set",
            "Multiple records matched in the second data set"
            if multiple
            else "Identity uncertain in the second data set",
            3 if multiple else 4,
            "host",
            source_a,
            source_b,
            warnings,
            {
                "selected": _host_identity(selected),
                "matches": [_host_identity(host) for host in ambiguous.candidates],
                "data_set": "b",
                "tier": ambiguous.tier,
                "conflicting_identity": ambiguous.conflicting_identity,
            },
        )
    if pair is None:
        return DiffOutcome(
            "no_match_second_data_set",
            "No match in the second data set was found to compare",
            4,
            "host",
            source_a,
            source_b,
            warnings,
            {"selected": _host_identity(selected)},
        )

    a_to_b = {int(item.a["id"]): int(item.b["id"]) for item in pairing.pairs}
    b_to_a = {value: key for key, value in a_to_b.items()}
    a_hosts_by_id = {
        int(host["id"]): host
        for host in a_document.hosts
        if isinstance(host.get("id"), int) and not isinstance(host.get("id"), bool)
    }
    b_hosts_by_id = {
        int(host["id"]): host
        for host in b_document.hosts
        if isinstance(host.get("id"), int) and not isinstance(host.get("id"), bool)
    }
    a_presence = _one_sided_presence_assessments(
        present_hosts=a_document.hosts,
        present_only=pairing.a_only,
        present_to_missing=a_to_b,
        missing_hosts_by_id=b_hosts_by_id,
        missing_coverage=b_coverage,
        observed_side="a",
        missing_side="b",
    )
    b_presence = _one_sided_presence_assessments(
        present_hosts=b_document.hosts,
        present_only=pairing.b_only,
        present_to_missing=b_to_a,
        missing_hosts_by_id=a_hosts_by_id,
        missing_coverage=a_coverage,
        observed_side="b",
        missing_side="a",
    )
    comparison = _comparison_payload(
        pair,
        a_completed=source_a.completed,
        b_completed=source_b.completed,
        a_to_b=a_to_b,
        b_to_a=b_to_a,
        include_observed_by=True,
        include_collection_timing=include_collection_timing,
        a_coverage=a_coverage,
        b_coverage=b_coverage,
        a_hosts_by_id=a_hosts_by_id,
        b_hosts_by_id=b_hosts_by_id,
        a_presence=a_presence,
        b_presence=b_presence,
    )
    a_attribute_uncertainty, b_attribute_uncertainty = _attribute_uncertainty_by_host([comparison])
    if a_attribute_uncertainty or b_attribute_uncertainty:
        graph_comparison = compare_topology_graphs(
            a_document.payload.get("topology_graph"),
            b_document.payload.get("topology_graph"),
            changes_only=changes_only,
            a_attribute_uncertainty=a_attribute_uncertainty,
            b_attribute_uncertainty=b_attribute_uncertainty,
        )
    if changes_only:
        comparison["learned_neighbors"] = [
            item for item in comparison["learned_neighbors"] if item["status"] != "same"
        ]
        comparison["observed_by_neighbors"] = [
            item for item in comparison["observed_by_neighbors"] if item["status"] != "same"
        ]
    changed = comparison["status"] != "same"
    return DiffOutcome(
        "differences_found" if changed else "no_differences",
        "Differences found" if changed else "No differences",
        1 if changed else 0,
        "host",
        source_a,
        source_b,
        warnings,
        {
            "options": {
                "changes_only": changes_only,
                "include_collection_timing": include_collection_timing,
            },
            "host": comparison,
            "topology_graph": graph_comparison,
            "collection_coverage": {
                "a": _collection_coverage_summary(a_coverage),
                "b": _collection_coverage_summary(b_coverage),
            },
        },
    )


def outcome_json(outcome: DiffOutcome) -> dict[str, Any]:
    """Return a stable machine-readable representation of one diff outcome."""

    def source(value: ResolvedDiffSource | None) -> dict[str, Any] | None:
        if value is None:
            return None
        return {
            "label": value.label,
            "path": str(value.path),
            "run_id": value.run_id,
            "completed": value.completed.isoformat() if value.completed else None,
        }

    return {
        "schema_version": DIFF_JSON_SCHEMA_VERSION,
        "result": {
            "status": outcome.status,
            "message": outcome.message,
            "exit_code": outcome.exit_code,
        },
        "mode": outcome.mode,
        "sources": {"a": source(outcome.source_a), "b": source(outcome.source_b)},
        "warnings": list(outcome.warnings),
        "comparison": outcome.data or {},
    }
