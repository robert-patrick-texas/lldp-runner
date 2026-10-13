"""Shared data models passed between coordinator and workers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

type HostCategory = Literal[
    "managed_device", "managed_endpoint", "unmanaged_device", "unknown_device"
]


@dataclass(slots=True)
class SeedInput:
    """One logical seed and any previously known management-address hints.

    Plain seed lists populate only :attr:`seed`.  LLDP-Runner's reusable
    ``seeds.csv`` can additionally carry the address that worked on the prior
    run plus all known IPv4/IPv6 aliases.  Keeping those values together avoids
    turning one CSV row into several unrelated seed records and lets a later
    run continue even when DNS is temporarily unavailable.
    """

    seed: str
    query_target: str | None = None
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    prior_state: str | None = None
    source: str | None = None
    parse_errors: list[str] = field(default_factory=list)

    def addresses(self) -> list[str]:
        """Return unique address hints, keeping the prior query target first."""

        values = [self.query_target, *self.ipv4, *self.ipv6]
        return list(dict.fromkeys(value for value in values if value))


@dataclass(slots=True)
class PingProbe:
    status: Literal["reply", "no-response", "error", "skipped"]
    timestamp: str
    address: str | None = None
    rtt_ms: float | None = None
    error: str | None = None


@dataclass(slots=True)
class DirectCredential:
    """Ephemeral direct SNMP credential loaded from a seed-credential file.

    Unlike configured credentials, direct credentials have no environment-backed
    fields. The shape intentionally mirrors the subset consumed by the SNMP
    backend while keeping the model independent from the configuration module.
    """

    name: str
    version: str
    community: str | None = None
    username: str | None = None
    auth_password: str | None = None
    priv_password: str | None = None
    auth_protocol: str = "sha1"
    priv_protocol: str = "aes128"

    def secret(self, field_name: str, env: Any | None = None) -> str | None:
        """Return one direct credential field; ``env`` is intentionally ignored."""

        return getattr(self, field_name)


@dataclass(slots=True)
class TargetAttempt:
    """One ordered credential route for one management address.

    A target route references either a configured credential profile or one
    ephemeral direct credential loaded from a seed-credential file. Direct
    secrets live only in the in-memory/multiprocessing task and are never
    written to state or discovery output.
    """

    address: str
    credential_profile: str | None = None
    direct_credential: DirectCredential | None = None
    credential_source: Literal["seed-direct", "seed-profile", "policy-profile"] = (
        "policy-profile"
    )
    credential_label: str | None = None


@dataclass(slots=True)
class DeviceTask:
    host_id: int
    preferred_name: str
    names: list[str]
    addresses: list[str]
    attempts: list[TargetAttempt]
    cohort: int


@dataclass(slots=True)
class StackMemberDetails:
    """Physical switch member discovered beneath one logical stack identity.

    Args:
        entity_index: Agent-assigned ENTITY-MIB index for this chassis row.
        member_number: Relative stack/member position when the agent exposes it.
        name: ENTITY-MIB physical name for operator correlation.
        description: ENTITY-MIB physical description for operator correlation.
        manufacturer: Manufacturer reported for the physical member.
        model: Product/model identifier reported for the physical member.
        serial_number: Chassis serial number; normally the durable member identity.
        hardware_revision: Member hardware revision when queried/implemented.
        firmware_revision: Member firmware revision when queried/implemented.
        software_revision: Member software revision when queried/implemented.
        uptime_seconds: Member-specific uptime when a supported source provides it.

    ENTITY-MIB itself has no standardized per-member uptime object, so the uptime
    field is normally ``None`` for the standards-only collector. It exists in the
    durable model and fixed CSV schema so a future vendor-specific collector can
    populate a true member value without changing downstream output contracts.
    """

    entity_index: int
    member_number: int | None = None
    name: str | None = None
    description: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    serial_number: str | None = None
    hardware_revision: str | None = None
    firmware_revision: str | None = None
    software_revision: str | None = None
    uptime_seconds: float | None = None


@dataclass(slots=True)
class SystemDetails:
    """Logical managed-device identity enriched by SNMP collectors.

    The top-level model/serial fields retain LLDP-Runner's historical meaning for
    compatibility. ``stack_members`` is additive physical inventory so a change
    in stack primary does not erase the serial identities of the other chassis.
    """

    sys_name: str | None = None
    sys_descr: str | None = None
    sys_object_id: str | None = None
    sys_uptime_ticks: int | None = None
    sys_contact: str | None = None
    sys_location: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    version: str | None = None
    serial_number: str | None = None
    hardware_revision: str | None = None
    firmware_revision: str | None = None
    entity_software_revision: str | None = None
    snmp_engine_id: str | None = None
    stack_members: list[StackMemberDetails] = field(default_factory=list)


@dataclass(slots=True)
class NeighborObservation:
    protocol: str
    local_interface: str | None
    local_interface_raw: str | None
    remote_name: str | None
    remote_interface: str | None
    remote_interface_raw: str | None
    remote_addresses: list[str] = field(default_factory=list)
    remote_description: str | None = None
    remote_platform: str | None = None
    capabilities: list[str] = field(default_factory=list)
    chassis_id: str | None = None
    chassis_id_subtype: str | None = None
    chassis_id_subtype_id: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return this dataclass as a recursively serializable dictionary.

        Returns:
            A dictionary suitable for state persistence or structured output.
        """

        return asdict(self)


@dataclass(slots=True)
class WorkerError:
    """One collection failure with exact route and backend provenance.

    ``attempted_target`` belongs to this individual failed route. It is not the
    host-level successful ``query_target`` and must never be reconstructed from
    that presentation field. Exception arguments are already secret-redacted
    strings before this object crosses a process or persistence boundary.
    """

    operation: str
    category: str
    message: str
    timestamp: str
    attempted_target: str | None = None
    address_family: Literal["ipv4", "ipv6"] | None = None
    phase: Literal[
        "resolve",
        "session_construct",
        "session_open",
        "request",
        "session_close",
    ] | None = None
    exception_type: str | None = None
    exception_errno: int | None = None
    exception_strerror: str | None = None
    exception_args: list[str] = field(default_factory=list)
    credential_profile: str | None = None
    credential_stage: str | None = None
    credential_source: str | None = None
    credential_label: str | None = None
    attempt: int | None = None
    collector: str | None = None
    recoverable: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return this dataclass as a recursively serializable dictionary.

        Returns:
            A dictionary suitable for state persistence or structured output.
        """

        return asdict(self)


@dataclass(slots=True)
class SnmpRetryEvent:
    """One bounded adaptive SNMP retry decision for a target/credential route.

    The event records enough context to explain which collector and table caused
    a retry without exposing credential secrets.  ``per_operation_retry_count``
    and ``total_target_retry_count`` are separate because one recovered scalar
    request must not consume the only opportunity to restart a later neighbor
    table. ``retry_pool`` and ``collector_family`` explain fair allocation across
    the shared pool, protected neighbor reserve, and delayed stability pass.
    """

    sequence: int
    target: str
    collector: str
    logical_operation: str
    table_name: str
    root_oid: str | None
    credential_route: str | None
    credential_profile: str | None
    collection_phase: str
    category: str
    retry_kind: Literal["transport", "structural", "stability"]
    retry_allowed: bool
    attempt: int
    per_operation_retry_count: int
    total_target_retry_count: int
    timeout_before_seconds: float
    timeout_after_seconds: float
    max_repetitions_before: int
    max_repetitions_after: int
    inter_pdu_delay_before_ms: float
    inter_pdu_delay_after_ms: float
    per_device_rps_before: float
    per_device_rps_after: float
    partial_rows_discarded: bool
    retry_pool: Literal[
        "shared", "neighbor_reserve", "stability", "none"
    ] = "shared"
    collector_family: str | None = None
    per_collector_retry_count: int = 0
    delay_before_retry_seconds: float = 0.0
    final_outcome: Literal[
        "pending", "succeeded", "failed", "unavailable"
    ] = "pending"
    outcome_type: str | None = None


@dataclass(slots=True)
class SnmpSessionTelemetry:
    """Effective adaptive transport profile used for one SNMP destination.

    One record belongs to one target and credential route.  The transport profile
    is degraded at most once and then reused by later operations. Retry limits
    and usage are reported at operation, collector-family, shared-pool,
    protected-reserve, and stability scope so Network Operations can distinguish
    a slow device from an unbounded retry loop.
    """

    target: str
    credential_route: str | None
    credential_profile: str | None
    initial_timeout_seconds: float
    effective_timeout_seconds: float
    initial_max_repetitions: int
    effective_max_repetitions: int
    initial_per_device_rps: float
    effective_per_device_rps: float
    effective_inter_pdu_delay_ms: float
    retry_per_operation: int
    structural_table_retry: int
    retry_total_cap: int
    total_retries_used: int
    degraded: bool
    operation_retry_counts: dict[str, int] = field(default_factory=dict)
    events: list[SnmpRetryEvent] = field(default_factory=list)
    retry_per_collector: int = 0
    retry_neighbor_reserve: int = 0
    shared_retries_used: int = 0
    neighbor_reserve_used: int = 0
    stability_retries_used: int = 0
    collector_retry_counts: dict[str, int] = field(default_factory=dict)
    stability_retry_counts: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class CollectionMetric:
    """SNMP objects returned and elapsed time for one collector section.

    The object count represents variable bindings returned by the agent before
    the collector filters or groups them.  Duration is cumulative when a section
    needs more than one attempt (notably the SYSTEM-MIB credential/address phase).
    """

    objects: int = 0
    duration_ms: float = 0.0

    def add(self, objects: int, duration_ms: float) -> None:
        """Accumulate one collector/attempt measurement into this section."""

        self.objects += max(0, int(objects))
        self.duration_ms = round(self.duration_ms + max(0.0, float(duration_ms)), 3)


@dataclass(slots=True)
class CollectionCoverage:
    """Outcome for one independently collected MIB table or claim family.

    A missing value is authoritative only when the responsible collection is
    marked ``complete``.  Other statuses preserve the distinction between an
    empty table, a timeout, an access restriction, an unsupported object, and a
    collection that was intentionally not attempted.
    """

    status: Literal[
        "complete",
        "partial",
        "timeout",
        "access_restricted",
        "unsupported",
        "structurally_invalid",
        "not_attempted",
        "failed",
    ]
    attempts: int = 1
    object_count: int = 0
    row_count: int | None = None
    resolution_status: Literal["resolved", "partial", "unresolved", "not_applicable"] = (
        "not_applicable"
    )
    message: str | None = None
    duration_ms: float = 0.0
    valid_address_count: int | None = None
    ipv4_address_count: int | None = None
    ipv6_address_count: int | None = None
    rejected_address_count: int | None = None
    malformed_index_count: int | None = None
    subtables: dict[str, CollectionCoverage] = field(default_factory=dict)

    @property
    def authoritative_negative(self) -> bool:
        """Return whether absence may be interpreted as a completed observation."""

        return self.status == "complete"


@dataclass(slots=True)
class DeviceResult:
    host_id: int
    status: Literal["success", "failed", "deferred"]
    query_target: str | None = None
    credential_profile: str | None = None
    credential_source: str | None = None
    credential_label: str | None = None
    credential_result: Literal["primary", "fallback", "direct", "failed"] | None = None
    ping_probes: list[PingProbe] = field(default_factory=list)
    system: SystemDetails | None = None
    # Raw protocol rows are retained before any CDP/LLDP reconciliation.
    # The compatibility ``neighbors`` list remains the current merged projection.
    raw_neighbors: list[NeighborObservation] = field(default_factory=list)
    neighbors: list[NeighborObservation] = field(default_factory=list)
    errors: list[WorkerError] = field(default_factory=list)
    collection_metrics: dict[str, CollectionMetric] = field(default_factory=dict)
    collection_coverage: dict[str, CollectionCoverage] = field(default_factory=dict)
    snmp_sessions: list[SnmpSessionTelemetry] = field(default_factory=list)
    # Compatibility interface groups remain useful as a compact audit view.
    # The schema-7 observation graph is rebuilt from ``raw_neighbors``. Entity
    # resolution remains provisional even when every raw advertisement is
    # accounted for.
    interface_observation_groups: list[dict[str, Any]] = field(default_factory=list)
    last_seen: str | None = None
    last_seen_source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return this dataclass as a recursively serializable dictionary.

        Returns:
            A dictionary suitable for state persistence or structured output.
        """

        return asdict(self)


@dataclass(slots=True)
class Candidate:
    names: list[str] = field(default_factory=list)
    # ``names`` and ``addresses`` contain every value useful for classification,
    # presentation, and query construction.  The optional identity lists narrow
    # those sets to values observed directly from the protocol/device. DNS
    # enrichment is intentionally excluded from global identity correlation
    # because unrelated devices can resolve through the same load balancer,
    # proxy, anycast service, or shared frontend address.
    identity_names: list[str] | None = None
    addresses: list[str] = field(default_factory=list)
    identity_addresses: list[str] | None = None
    category: HostCategory = "unknown_device"
    reason: list[str] = field(default_factory=list)
    source_host_id: int | None = None
    protocol: str | None = None
    local_interface: str | None = None
    local_interface_raw: str | None = None
    remote_interface: str | None = None
    remote_interface_raw: str | None = None
    remote_description: str | None = None
    remote_platform: str | None = None
    capabilities: list[str] = field(default_factory=list)
    chassis_id: str | None = None
    chassis_id_subtype: str | None = None
    chassis_id_subtype_id: int | None = None
    protocols: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
