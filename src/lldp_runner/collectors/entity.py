"""ENTITY-MIB identity enrichment and physical stack-member inventory.

LLDP-Runner uses ENTITY-MIB in three query modes. ``full`` preserves the
historical complete ``entPhysicalEntry`` walk. ``auto`` and ``brief`` first walk
``entPhysicalClass`` so the collector can discover the agent-assigned indexes
instead of assuming fixed values, then issue targeted GET operations.

Stack inventory is standards-first. RFC 6933 models a stack as a ``stack(11)``
physical entity containing ``chassis(3)`` entities and provides
``entPhysicalParentRelPos`` for relative placement. Some agents omit the stack
container, so LLDP-Runner also recognizes multiple useful chassis siblings as a
conservative fallback. Cisco Catalyst StackWise, Aruba CX VSF, Juniper EX
Virtual Chassis, and other vendors can therefore use the same ENTITY-MIB path
when their agents expose standards-based physical inventory.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, replace
from typing import Literal, Protocol, cast

from lldp_runner.models import StackMemberDetails, SystemDetails
from lldp_runner.snmp.resilience import SnmpAccessRestrictedError
from lldp_runner.textutil import snmp_text

ENT_PHYSICAL_ENTRY = "1.3.6.1.2.1.47.1.1.1.1"
ENT_PHYSICAL_CONTAINED_IN = f"{ENT_PHYSICAL_ENTRY}.4"
ENT_PHYSICAL_CLASS = f"{ENT_PHYSICAL_ENTRY}.5"

# ENTITY-MIB entPhysicalEntry column numbers used by LLDP-Runner. Keeping the
# mapping near the query plans helps NetOps staff correlate packet captures and
# MIB-browser output with the Python implementation.
COL_DESCR = 2
COL_CONTAINED_IN = 4
COL_CLASS = 5
COL_PARENT_REL_POS = 6
COL_NAME = 7
COL_HARDWARE_REV = 8
COL_FIRMWARE_REV = 9
COL_SOFTWARE_REV = 10
COL_SERIAL_NUMBER = 11
COL_MANUFACTURER = 12
COL_MODEL_NAME = 13

CLASS_CHASSIS = 3
CLASS_MODULE = 9
CLASS_STACK = 11

# The rank intentionally preserves the pre-0.14 full-mode chassis preference.
_CLASS_RANK = {CLASS_CHASSIS: 0, CLASS_STACK: 1, CLASS_MODULE: 2}

# Selective collection always obtains identity values useful for inventory.
# ``auto`` adds revision fields for physical network infrastructure.
_BRIEF_COLUMNS = (
    COL_SERIAL_NUMBER,
    COL_MANUFACTURER,
    COL_MODEL_NAME,
)
_AUTO_RICH_COLUMNS = (
    COL_HARDWARE_REV,
    COL_FIRMWARE_REV,
    COL_SOFTWARE_REV,
    *_BRIEF_COLUMNS,
)

# Structural columns are cheap targeted GETs after class discovery. They let the
# collector distinguish an overall stack from member chassis without walking
# every fan, power supply, port, sensor, and transceiver in ENTITY-MIB.
_STRUCTURE_COLUMNS = (
    COL_CONTAINED_IN,
    COL_PARENT_REL_POS,
    COL_NAME,
    COL_DESCR,
)

_AUTO_RICH_MANUFACTURERS = frozenset(
    {
        "arista",
        "aruba",
        "cisco",
        "f5",
        "gigamon",
        "juniper",
        "kemp",
        "palo alto networks",
        "wti",
    }
)
_AUTO_NETWORK_MARKERS = (
    "arubaos",
    "aos-cx",
    "big-ip",
    "comware",
    "firewall",
    "cisco ios",
    "ios xe",
    "ios xr",
    "junos",
    "network switch",
    "nx-os",
    "pan-os",
    "procurve",
    "router",
    "switch",
)
_AUTO_VIRTUAL_MARKERS = (
    "hypervisor",
    "virtual appliance",
    "virtual machine",
    "vmware",
    "vsphere",
)

_MEMBER_NUMBER_PATTERN = re.compile(
    r"\b(?:switch|member|chassis|fpc|slot)\s*[-:#]?\s*(\d+)\b",
    re.IGNORECASE,
)


type EntityMibMode = Literal["full", "auto", "brief"]


class EntityClient(Protocol):
    """SNMP operations required by ENTITY-MIB enrichment."""

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        """Return values for requested numeric OID instances.

        Args:
            oids: Fully qualified numeric OID instances to retrieve.

        Returns:
            Mapping from returned numeric OID strings to decoded SNMP values.
        """
        ...

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        """Return every varbind below one numeric OID subtree.

        Args:
            oid: Numeric subtree root to walk.

        Returns:
            Ordered ``(oid, value)`` pairs returned by the SNMP backend.
        """
        ...


@dataclass(frozen=True, slots=True)
class EntityQueryPlan:
    """Selective ENTITY-MIB fields chosen for one discovered device type."""

    name: str
    columns: tuple[int, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class PhysicalEntity:
    """Structural information for one relevant ENTITY-MIB physical row.

    Args:
        entity_index: Agent-assigned ``entPhysicalIndex``.
        entity_class: Numeric ``entPhysicalClass`` value.
        contained_in: Parent ``entPhysicalIndex`` or zero for a root entity.
        parent_rel_pos: Relative position within the parent, when implemented.
        name: Human-readable ``entPhysicalName``.
        description: Human-readable ``entPhysicalDescr``.

    The object is intentionally limited to structure. Identity fields such as
    serial/model are kept in the normal column mappings so full and selective
    modes can share the same member-building code.
    """

    entity_index: int
    entity_class: int
    contained_in: int | None = None
    parent_rel_pos: int | None = None
    name: str | None = None
    description: str | None = None


def _text(value: object | None) -> str | None:
    """Normalize one textual ENTITY-MIB value.

    Args:
        value: Raw decoded SNMP value, or ``None`` when omitted.

    Returns:
        Sanitized text suitable for output/state, or ``None`` when blank.
    """

    return snmp_text(value)


def _number(value: object | None) -> int | None:
    """Convert an ENTITY-MIB integer-like value to ``int`` when possible.

    Args:
        value: Raw decoded SNMP value, commonly an integer or numeric string.

    Returns:
        Integer value, or ``None`` when conversion is not possible.
    """

    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _entry_instance(column: int, entity_index: int) -> str:
    """Build one fully qualified ``entPhysicalEntry`` instance OID.

    Args:
        column: Numeric ``entPhysicalEntry`` column identifier.
        entity_index: Agent-assigned ``entPhysicalIndex`` value.

    Returns:
        Numeric OID string for the requested column/index instance.
    """

    return f"{ENT_PHYSICAL_ENTRY}.{column}.{entity_index}"


def _parse_full_rows(rows: list[tuple[str, object]]) -> dict[int, dict[int, object]]:
    """Group a complete ``entPhysicalEntry`` walk by entity index.

    Args:
        rows: Varbinds returned from walking :data:`ENT_PHYSICAL_ENTRY`.

    Returns:
        Mapping of ``entPhysicalIndex`` to column/value mappings. Malformed or
        out-of-subtree rows are ignored defensively.
    """

    grouped: dict[int, dict[int, object]] = defaultdict(dict)
    prefix = f"{ENT_PHYSICAL_ENTRY}."
    for oid, value in rows:
        if not oid.startswith(prefix):
            continue
        suffix = oid[len(prefix) :].split(".")
        if len(suffix) < 2 or not suffix[0].isdigit() or not suffix[1].isdigit():
            continue
        column, entity_index = int(suffix[0]), int(suffix[1])
        grouped[entity_index][column] = value
    return grouped


def _select_full_columns(
    grouped: dict[int, dict[int, object]],
) -> dict[int, object] | None:
    """Select the historical full-mode system identity row.

    Args:
        grouped: Parsed full-table rows keyed by ENTITY-MIB index.

    Returns:
        Chosen row's column mapping, or ``None`` when no useful physical row
        exists.

    Chassis is still ranked ahead of stack and module rows so ``full`` does not
    change the top-level identity behavior operators had before stack inventory
    was added. Member inventory is additive and does not redefine those fields.
    """

    candidates: list[tuple[int, int, dict[int, object]]] = []
    for entity_index, columns in grouped.items():
        entity_class = _number(columns.get(COL_CLASS))
        if entity_class not in _CLASS_RANK:
            continue
        if not (
            _text(columns.get(COL_MODEL_NAME))
            or _text(columns.get(COL_DESCR))
            or _text(columns.get(COL_NAME))
        ):
            continue
        candidates.append((_CLASS_RANK[entity_class], entity_index, columns))
    if not candidates:
        return None
    _rank, _index, columns = min(candidates, key=lambda value: (value[0], value[1]))
    return columns


def _entity_from_columns(
    entity_index: int,
    entity_class: int,
    columns: dict[int, object],
) -> PhysicalEntity:
    """Create structural metadata from one parsed ENTITY-MIB row.

    Args:
        entity_index: Row's ``entPhysicalIndex``.
        entity_class: Numeric class already validated by the caller.
        columns: Column/value mapping for the physical row.

    Returns:
        Immutable :class:`PhysicalEntity` used for hierarchy decisions.
    """

    return PhysicalEntity(
        entity_index=entity_index,
        entity_class=entity_class,
        contained_in=_number(columns.get(COL_CONTAINED_IN)),
        parent_rel_pos=_number(columns.get(COL_PARENT_REL_POS)),
        name=_text(columns.get(COL_NAME)),
        description=_text(columns.get(COL_DESCR)),
    )


def _physical_entities_from_full_rows(
    grouped: dict[int, dict[int, object]],
) -> list[PhysicalEntity]:
    """Extract chassis/stack/module structure from a complete table walk.

    Args:
        grouped: Parsed full ENTITY-MIB rows.

    Returns:
        Relevant physical entities sorted by ``entPhysicalIndex``.
    """

    entities: list[PhysicalEntity] = []
    for entity_index, columns in grouped.items():
        entity_class = _number(columns.get(COL_CLASS))
        if entity_class not in _CLASS_RANK:
            continue
        entities.append(_entity_from_columns(entity_index, entity_class, columns))
    return sorted(entities, key=lambda entity: entity.entity_index)


def _parse_class_candidates(rows: list[tuple[str, object]]) -> list[PhysicalEntity]:
    """Extract relevant physical entities from an ``entPhysicalClass`` walk.

    Args:
        rows: Varbinds returned from walking :data:`ENT_PHYSICAL_CLASS`.

    Returns:
        Chassis, stack, and module candidates sorted by index. Duplicate,
        malformed, and unsupported class rows are ignored.
    """

    prefix = f"{ENT_PHYSICAL_CLASS}."
    candidates: dict[int, int] = {}
    for oid, value in rows:
        if not oid.startswith(prefix):
            continue
        suffix = oid[len(prefix) :]
        if not suffix.isdigit():
            continue
        entity_class = _number(value)
        if entity_class in _CLASS_RANK:
            candidates[int(suffix)] = entity_class
    return [
        PhysicalEntity(entity_index=index, entity_class=entity_class)
        for index, entity_class in sorted(candidates.items())
    ]


async def _collect_structure(
    client: EntityClient,
    candidates: list[PhysicalEntity],
) -> list[PhysicalEntity]:
    """Retrieve hierarchy/name fields needed to recognize stack members.

    Args:
        client: Open SNMP client for the target device.
        candidates: Relevant rows discovered through ``entPhysicalClass``.

    Returns:
        Candidates enriched with containment/position/name/description. A single
        candidate is returned unchanged because it cannot represent a multi-member
        stack and avoiding the GET keeps standalone selective queries inexpensive.

    SNMP failures are tolerated here. Identity enrichment is optional and a
    standards-incomplete agent can still provide the top-level row selected by
    class/index ranking.
    """

    if len(candidates) <= 1:
        return candidates

    oids = [
        _entry_instance(column, candidate.entity_index)
        for candidate in candidates
        for column in _STRUCTURE_COLUMNS
    ]
    try:
        values = await client.get_many(oids)
    except SnmpAccessRestrictedError:
        raise
    except Exception:
        return candidates

    enriched: list[PhysicalEntity] = []
    for candidate in candidates:
        index = candidate.entity_index
        enriched.append(
            replace(
                candidate,
                contained_in=_number(
                    values.get(_entry_instance(COL_CONTAINED_IN, index))
                ),
                parent_rel_pos=_number(
                    values.get(_entry_instance(COL_PARENT_REL_POS, index))
                ),
                name=_text(values.get(_entry_instance(COL_NAME, index))),
                description=_text(values.get(_entry_instance(COL_DESCR, index))),
            )
        )
    return enriched


def _select_selective_entity(candidates: list[PhysicalEntity]) -> PhysicalEntity | None:
    """Choose the best overall physical row for selective top-level identity.

    Args:
        candidates: Relevant ENTITY-MIB rows with structure when available.

    Returns:
        Selected physical entity, or ``None`` when no candidate exists.

    Root containment outranks class so an explicit ``stack(11)`` root is selected
    ahead of a contained member chassis. If containment is unavailable, the
    historical class rank and index provide deterministic behavior.
    """

    if not candidates:
        return None

    def rank(candidate: PhysicalEntity) -> tuple[int, int, int]:
        """Return root/class/index sort keys for one physical candidate."""

        root_rank = 0 if candidate.contained_in == 0 else 1
        return root_rank, _CLASS_RANK[candidate.entity_class], candidate.entity_index

    return min(candidates, key=rank)


def _auto_query_plan(system: SystemDetails) -> EntityQueryPlan:
    """Choose an auto-mode field set from existing SYSTEM-MIB identity.

    Args:
        system: Basic SYSTEM-MIB details populated before ENTITY-MIB collection.

    Returns:
        Named selective query plan describing fields to retrieve and why.

    Auto mode sends no additional identity probe. Virtualization markers force
    the conservative brief profile; known network vendors and network-OS markers
    enable revision fields useful to NetOps inventory.
    """

    manufacturer = (system.manufacturer or "").casefold()
    description = (system.sys_descr or "").casefold()

    if any(marker in description for marker in _AUTO_VIRTUAL_MARKERS):
        return EntityQueryPlan(
            name="auto-brief-virtual",
            columns=_BRIEF_COLUMNS,
            reason="SYSTEM-MIB description indicates a virtualized device",
        )

    rich_manufacturer = manufacturer in _AUTO_RICH_MANUFACTURERS
    hpe_network_device = manufacturer == "hpe" and any(
        marker in description for marker in _AUTO_NETWORK_MARKERS
    )
    network_description = any(marker in description for marker in _AUTO_NETWORK_MARKERS)
    if rich_manufacturer or hpe_network_device or network_description:
        return EntityQueryPlan(
            name="auto-rich-network",
            columns=_AUTO_RICH_COLUMNS,
            reason="SYSTEM-MIB identity indicates physical network infrastructure",
        )

    return EntityQueryPlan(
        name="auto-brief-conservative",
        columns=_BRIEF_COLUMNS,
        reason="device type is unknown or does not benefit from revision queries",
    )


def _query_plan(mode: EntityMibMode, system: SystemDetails) -> EntityQueryPlan:
    """Translate a selective mode into the field set to request.

    Args:
        mode: Validated ``auto`` or ``brief`` ENTITY-MIB mode.
        system: Basic identity used by ``auto`` to select a device profile.

    Returns:
        Selective query plan for the chosen mode.

    Raises:
        ValueError: If called with the non-selective ``full`` mode.
    """

    if mode == "brief":
        return EntityQueryPlan(
            name="brief",
            columns=_BRIEF_COLUMNS,
            reason="operator requested common high-value chassis identity only",
        )
    if mode == "auto":
        return _auto_query_plan(system)
    raise ValueError(f"selective ENTITY-MIB mode required, got {mode!r}")


def _infer_member_number(entity: PhysicalEntity) -> int | None:
    """Return the most useful standards-first member position.

    Args:
        entity: Chassis row with optional hierarchy/name fields.

    Returns:
        ``entPhysicalParentRelPos`` when non-negative. If the agent leaves that
        field unknown, a conservative member/switch/chassis/FPC/slot number parsed
        from the ENTITY name/description is returned; otherwise ``None``.

    Relative position is preferred because it is the standard hierarchy field.
    The textual fallback improves interoperability with agents that expose useful
    labels but do not populate ``entPhysicalParentRelPos``.
    """

    if entity.parent_rel_pos is not None and entity.parent_rel_pos >= 0:
        return entity.parent_rel_pos
    text = " ".join(value for value in (entity.name, entity.description) if value)
    match = _MEMBER_NUMBER_PATTERN.search(text)
    return int(match.group(1)) if match else None


def _member_entity_candidates(entities: list[PhysicalEntity]) -> list[PhysicalEntity]:
    """Identify chassis rows that represent physical stack members.

    Args:
        entities: Relevant ENTITY-MIB rows with containment when available.

    Returns:
        Candidate member chassis. An explicit ``stack(11)`` containing chassis
        rows is authoritative. Otherwise two or more sibling chassis rows are a
        conservative standards-oriented fallback for agents without a stack row.

    A single standalone chassis is never emitted as a stack member. This keeps
    ``stack-members.csv`` focused on multi-member logical devices.
    """

    chassis = [entity for entity in entities if entity.entity_class == CLASS_CHASSIS]
    stack_indexes = {
        entity.entity_index for entity in entities if entity.entity_class == CLASS_STACK
    }
    explicit_members = [
        entity for entity in chassis if entity.contained_in in stack_indexes
    ]
    if explicit_members:
        return explicit_members

    siblings: dict[int | None, list[PhysicalEntity]] = defaultdict(list)
    for entity in chassis:
        siblings[entity.contained_in].append(entity)
    groups = [group for group in siblings.values() if len(group) >= 2]
    if not groups:
        return []
    # Prefer the largest sibling group; index ordering makes ties deterministic.
    return min(
        groups,
        key=lambda group: (
            -len(group),
            min(entity.entity_index for entity in group),
        ),
    )


def _stack_member_from_columns(
    entity: PhysicalEntity,
    columns: dict[int, object],
) -> StackMemberDetails:
    """Build one physical member inventory record from ENTITY-MIB values.

    Args:
        entity: Structural chassis information for the member.
        columns: Identity/revision columns for the same ``entPhysicalIndex``.

    Returns:
        Structured stack-member details suitable for discovery state and output.

    ENTITY-MIB has no standardized per-member uptime object. ``uptime_seconds``
    therefore remains ``None`` here rather than copying the logical stack's
    ``sysUpTime`` and incorrectly presenting it as member-specific runtime.
    """

    return StackMemberDetails(
        entity_index=entity.entity_index,
        member_number=_infer_member_number(entity),
        name=entity.name,
        description=entity.description,
        manufacturer=_text(columns.get(COL_MANUFACTURER)),
        model=_text(columns.get(COL_MODEL_NAME)),
        serial_number=_text(columns.get(COL_SERIAL_NUMBER)),
        hardware_revision=_text(columns.get(COL_HARDWARE_REV)),
        firmware_revision=_text(columns.get(COL_FIRMWARE_REV)),
        software_revision=_text(columns.get(COL_SOFTWARE_REV)),
        uptime_seconds=None,
    )


def _member_has_identity(member: StackMemberDetails) -> bool:
    """Return whether a candidate row has enough content to be useful output.

    Args:
        member: Candidate stack-member record.

    Returns:
        ``True`` when serial/model/manufacturer/name/description provides useful
        physical inventory evidence.
    """

    return any(
        (
            member.serial_number,
            member.model,
            member.manufacturer,
            member.name,
            member.description,
        )
    )


def _sort_members(members: list[StackMemberDetails]) -> list[StackMemberDetails]:
    """Sort physical members by stack position and then ENTITY index.

    Args:
        members: Unordered member records.

    Returns:
        Deterministic list with known member positions first. Zero-based Juniper
        positions and one-based Cisco/Aruba positions are both preserved.
    """

    return sorted(
        members,
        key=lambda member: (
            member.member_number is None,
            member.member_number if member.member_number is not None else 0,
            member.entity_index,
        ),
    )


def _build_stack_members(
    entities: list[PhysicalEntity],
    columns_by_index: dict[int, dict[int, object]],
) -> list[StackMemberDetails]:
    """Create useful stack-member inventory from hierarchy and identity data.

    Args:
        entities: Relevant physical rows describing stack/chassis structure.
        columns_by_index: Identity values keyed by ``entPhysicalIndex``.

    Returns:
        Sorted member records. For fallback sibling detection, at least two useful
        members must survive identity filtering; an explicit stack container may
        yield one surviving member when the agent reports an incomplete stack.
    """

    candidates = _member_entity_candidates(entities)
    if not candidates:
        return []

    explicit_stack = any(
        candidate.contained_in is not None
        and any(
            entity.entity_class == CLASS_STACK
            and entity.entity_index == candidate.contained_in
            for entity in entities
        )
        for candidate in candidates
    )
    members = [
        _stack_member_from_columns(
            entity,
            columns_by_index.get(entity.entity_index, {}),
        )
        for entity in candidates
    ]
    useful = [member for member in members if _member_has_identity(member)]
    if not explicit_stack and len(useful) < 2:
        return []
    return _sort_members(useful)


async def _collect_selective(
    client: EntityClient,
    system: SystemDetails,
    mode: EntityMibMode,
) -> tuple[dict[int, object] | None, list[StackMemberDetails]]:
    """Collect targeted top-level identity plus physical stack members.

    Args:
        client: Open SNMP client for the target device.
        system: Basic device identity used by ``auto`` query planning.
        mode: ``auto`` or ``brief`` selective behavior.

    Returns:
        ``(overall_columns, stack_members)``. The overall mapping may be ``None``
        when no usable physical candidate exists. Stack members are empty for a
        standalone device or when the agent does not expose useful member rows.
    """

    class_rows = await client.walk(ENT_PHYSICAL_CLASS)
    candidates = _parse_class_candidates(class_rows)
    entities = await _collect_structure(client, candidates)
    overall = _select_selective_entity(entities)
    if overall is None:
        return None, []

    member_entities = _member_entity_candidates(entities)
    indexes = list(
        dict.fromkeys(
            [overall.entity_index, *(entity.entity_index for entity in member_entities)]
        )
    )
    plan = _query_plan(mode, system)
    oids = [
        _entry_instance(column, entity_index)
        for entity_index in indexes
        for column in plan.columns
    ]
    values = await client.get_many(oids)
    columns_by_index: dict[int, dict[int, object]] = {}
    for entity_index in indexes:
        columns_by_index[entity_index] = {
            column: values[oid]
            for column in plan.columns
            if (oid := _entry_instance(column, entity_index)) in values
        }

    members = _build_stack_members(entities, columns_by_index)
    return columns_by_index.get(overall.entity_index), members


def _apply_identity_columns(system: SystemDetails, columns: dict[int, object]) -> None:
    """Apply one selected ENTITY-MIB row to mutable system identity state.

    Args:
        system: Device identity object to enrich in place.
        columns: ENTITY-MIB column/value mapping for one physical entity.

    Returns:
        ``None``. Existing manufacturer/version values are preserved according to
        the historical LLDP-Runner enrichment rules.
    """

    manufacturer = _text(columns.get(COL_MANUFACTURER))
    model = _text(columns.get(COL_MODEL_NAME))
    if manufacturer and not system.manufacturer:
        system.manufacturer = manufacturer
    if model:
        system.model = model
    system.serial_number = _text(columns.get(COL_SERIAL_NUMBER)) or system.serial_number
    system.hardware_revision = (
        _text(columns.get(COL_HARDWARE_REV)) or system.hardware_revision
    )
    system.firmware_revision = (
        _text(columns.get(COL_FIRMWARE_REV)) or system.firmware_revision
    )
    system.entity_software_revision = (
        _text(columns.get(COL_SOFTWARE_REV)) or system.entity_software_revision
    )
    if not system.version and system.entity_software_revision:
        system.version = system.entity_software_revision


async def enrich_system_from_entity_mib(
    client: EntityClient,
    system: SystemDetails,
    mode: EntityMibMode | str = "full",
) -> None:
    """Enrich logical system identity and discover physical stack members.

    Args:
        client: Open project SNMP client. ``full`` needs ``walk``; selective modes
            use ``walk`` plus targeted ``get_many`` operations.
        system: SYSTEM-MIB identity to enrich in place. ``auto`` examines its
            manufacturer/description to choose a selective query profile.
        mode: ``full`` preserves the complete historical ``entPhysicalEntry``
            walk, ``auto`` chooses a device-aware selective field set, and
            ``brief`` retrieves common high-value identity fields only.

    Returns:
        ``None``. Top-level values and ``system.stack_members`` are updated in
        place. Stack-member records represent physical chassis while the parent
        ``SystemDetails`` continues to represent the managed logical platform.

    Raises:
        ValueError: If ``mode`` is not ``full``, ``auto``, or ``brief``.
        Exception: SNMP transport/backend failures are allowed to reach the caller,
            which records optional ENTITY-MIB collection failures and telemetry.
    """

    normalized_mode = str(mode).casefold()
    if normalized_mode not in {"full", "auto", "brief"}:
        raise ValueError(
            "ENTITY-MIB mode must be 'full', 'auto', or 'brief'; "
            f"got {mode!r}"
        )

    if normalized_mode == "full":
        rows = await client.walk(ENT_PHYSICAL_ENTRY)
        grouped = _parse_full_rows(rows)
        columns = _select_full_columns(grouped)
        entities = _physical_entities_from_full_rows(grouped)
        system.stack_members = _build_stack_members(entities, grouped)
    else:
        columns, members = await _collect_selective(
            client,
            system,
            cast(EntityMibMode, normalized_mode),
        )
        system.stack_members = members

    if columns:
        _apply_identity_columns(system, columns)
