"""ENTITY-MIB query-mode behavior and identity enrichment regression tests."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence

import pytest

from lldp_runner.collectors.entity import (
    COL_CONTAINED_IN,
    COL_DESCR,
    COL_FIRMWARE_REV,
    COL_HARDWARE_REV,
    COL_MANUFACTURER,
    COL_MODEL_NAME,
    COL_NAME,
    COL_PARENT_REL_POS,
    COL_SERIAL_NUMBER,
    COL_SOFTWARE_REV,
    ENT_PHYSICAL_CLASS,
    ENT_PHYSICAL_ENTRY,
    enrich_system_from_entity_mib,
)
from lldp_runner.models import SystemDetails


def _oid(column: int, index: int) -> str:
    """Return one numeric entPhysicalEntry instance used by fake agents."""

    return f"{ENT_PHYSICAL_ENTRY}.{column}.{index}"


class FakeEntityClient:
    """Small programmable SNMP client that records ENTITY-MIB operations."""

    def __init__(
        self,
        *,
        walks: Mapping[str, Sequence[tuple[str, object]]] | None = None,
        values: Mapping[str, object] | None = None,
        fail_containment: bool = False,
    ) -> None:
        """Initialize fake walk/value responses for one test scenario.

        Args:
            walks: Mapping of subtree OID to the rows returned by ``walk``.
            values: Mapping of instance OID to values returned by ``get_many``.
            fail_containment: Raise on a multi-candidate containment lookup to
                exercise the collector's deterministic fallback behavior.
        """

        self.walks = walks or {}
        self.values = values or {}
        self.fail_containment = fail_containment
        self.calls: list[tuple[str, object]] = []

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        """Record and return the configured subtree rows."""

        self.calls.append(("walk", oid))
        return list(self.walks.get(oid, []))

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        """Record requested instances and return only configured values."""

        self.calls.append(("get_many", list(oids)))
        if self.fail_containment and any(
            oid.startswith(f"{ENT_PHYSICAL_ENTRY}.{COL_CONTAINED_IN}.") for oid in oids
        ):
            raise RuntimeError("agent rejected ENTITY structure lookup")
        return {oid: self.values[oid] for oid in oids if oid in self.values}


def test_full_mode_preserves_historical_complete_entry_walk() -> None:
    """Full mode must retain the v0.13.1 query shape and enrichment semantics."""

    rows = [
        (_oid(5, 1), 3),
        (_oid(2, 1), "Main chassis"),
        (_oid(8, 1), "A2"),
        (_oid(9, 1), "F3"),
        (_oid(10, 1), "17.12.4"),
        (_oid(11, 1), "SER123"),
        (_oid(12, 1), "Cisco Systems"),
        (_oid(13, 1), "C9300-48P"),
        (_oid(5, 2), 9),
        (_oid(13, 2), "Line card"),
    ]
    client = FakeEntityClient(walks={ENT_PHYSICAL_ENTRY: rows})
    system = SystemDetails()

    asyncio.run(enrich_system_from_entity_mib(client, system, "full"))

    assert client.calls == [("walk", ENT_PHYSICAL_ENTRY)]
    assert system.manufacturer == "Cisco Systems"
    assert system.model == "C9300-48P"
    assert system.serial_number == "SER123"
    assert system.hardware_revision == "A2"
    assert system.firmware_revision == "F3"
    assert system.entity_software_revision == "17.12.4"
    assert system.version == "17.12.4"


def test_full_mode_keeps_existing_manufacturer_and_prefers_chassis_rank() -> None:
    """Historical full selection still ranks chassis ahead of stack/module rows."""

    rows = [
        (_oid(5, 20), 11),
        (_oid(13, 20), "Stack root"),
        (_oid(11, 20), "STACKSER"),
        (_oid(5, 3), 3),
        (_oid(13, 3), "Chassis member"),
        (_oid(11, 3), "CHASSISSER"),
        (_oid(12, 3), "Agent Manufacturer"),
    ]
    client = FakeEntityClient(walks={ENT_PHYSICAL_ENTRY: rows})
    system = SystemDetails(manufacturer="Cisco")

    asyncio.run(enrich_system_from_entity_mib(client, system))

    assert system.manufacturer == "Cisco"
    assert system.model == "Chassis member"
    assert system.serial_number == "CHASSISSER"


def test_brief_mode_walks_class_then_gets_only_common_identity_fields() -> None:
    """Brief mode should avoid a full table walk and request three chassis values."""

    index = 42
    client = FakeEntityClient(
        walks={ENT_PHYSICAL_CLASS: [(f"{ENT_PHYSICAL_CLASS}.{index}", 3)]},
        values={
            _oid(COL_SERIAL_NUMBER, index): "SER42",
            _oid(COL_MANUFACTURER, index): "Arista Networks",
            _oid(COL_MODEL_NAME, index): "DCS-7050SX3",
        },
    )
    system = SystemDetails()

    asyncio.run(enrich_system_from_entity_mib(client, system, "brief"))

    assert client.calls == [
        ("walk", ENT_PHYSICAL_CLASS),
        (
            "get_many",
            [
                _oid(COL_SERIAL_NUMBER, index),
                _oid(COL_MANUFACTURER, index),
                _oid(COL_MODEL_NAME, index),
            ],
        ),
    ]
    assert system.serial_number == "SER42"
    assert system.manufacturer == "Arista Networks"
    assert system.model == "DCS-7050SX3"
    assert system.hardware_revision is None
    assert system.firmware_revision is None
    assert system.entity_software_revision is None


def test_selective_mode_prefers_root_stack_over_contained_chassis() -> None:
    """Containment should locate the overall root rather than guessing an index."""

    stack_index = 100
    chassis_index = 7
    client = FakeEntityClient(
        walks={
            ENT_PHYSICAL_CLASS: [
                (f"{ENT_PHYSICAL_CLASS}.{chassis_index}", 3),
                (f"{ENT_PHYSICAL_CLASS}.{stack_index}", 11),
            ]
        },
        values={
            _oid(COL_CONTAINED_IN, chassis_index): stack_index,
            _oid(COL_CONTAINED_IN, stack_index): 0,
            _oid(COL_SERIAL_NUMBER, stack_index): "STACK100",
            _oid(COL_MANUFACTURER, stack_index): "Cisco",
            _oid(COL_MODEL_NAME, stack_index): "StackWise Virtual",
        },
    )
    system = SystemDetails()

    asyncio.run(enrich_system_from_entity_mib(client, system, "brief"))

    assert client.calls[1] == (
        "get_many",
        [
            _oid(COL_CONTAINED_IN, chassis_index),
            _oid(COL_PARENT_REL_POS, chassis_index),
            _oid(COL_NAME, chassis_index),
            _oid(COL_DESCR, chassis_index),
            _oid(COL_CONTAINED_IN, stack_index),
            _oid(COL_PARENT_REL_POS, stack_index),
            _oid(COL_NAME, stack_index),
            _oid(COL_DESCR, stack_index),
        ],
    )
    assert client.calls[2] == (
        "get_many",
        [
            _oid(COL_SERIAL_NUMBER, stack_index),
            _oid(COL_MANUFACTURER, stack_index),
            _oid(COL_MODEL_NAME, stack_index),
            _oid(COL_SERIAL_NUMBER, chassis_index),
            _oid(COL_MANUFACTURER, chassis_index),
            _oid(COL_MODEL_NAME, chassis_index),
        ],
    )
    assert system.serial_number == "STACK100"


def test_selective_mode_falls_back_when_containment_lookup_fails() -> None:
    """A broken containment column should not discard otherwise usable identity."""

    client = FakeEntityClient(
        walks={
            ENT_PHYSICAL_CLASS: [
                (f"{ENT_PHYSICAL_CLASS}.9", 9),
                (f"{ENT_PHYSICAL_CLASS}.5", 3),
            ]
        },
        values={
            _oid(COL_SERIAL_NUMBER, 5): "SER5",
            _oid(COL_MODEL_NAME, 5): "Fallback chassis",
        },
        fail_containment=True,
    )
    system = SystemDetails()

    asyncio.run(enrich_system_from_entity_mib(client, system, "brief"))

    assert system.model == "Fallback chassis"
    assert system.serial_number == "SER5"


def test_auto_mode_uses_rich_revision_profile_for_network_device() -> None:
    """Known physical network identity should add revision OIDs in auto mode."""

    index = 21
    client = FakeEntityClient(
        walks={ENT_PHYSICAL_CLASS: [(f"{ENT_PHYSICAL_CLASS}.{index}", 3)]},
        values={
            _oid(COL_HARDWARE_REV, index): "R01",
            _oid(COL_FIRMWARE_REV, index): "F01",
            _oid(COL_SOFTWARE_REV, index): "17.15.1",
            _oid(COL_SERIAL_NUMBER, index): "CISCO21",
            _oid(COL_MANUFACTURER, index): "Cisco Systems, Inc.",
            _oid(COL_MODEL_NAME, index): "C9500-24Y4C",
        },
    )
    system = SystemDetails(
        manufacturer="Cisco",
        sys_descr="Cisco IOS XE Software, Version 17.15.1",
    )

    asyncio.run(enrich_system_from_entity_mib(client, system, "auto"))

    assert client.calls[1] == (
        "get_many",
        [
            _oid(COL_HARDWARE_REV, index),
            _oid(COL_FIRMWARE_REV, index),
            _oid(COL_SOFTWARE_REV, index),
            _oid(COL_SERIAL_NUMBER, index),
            _oid(COL_MANUFACTURER, index),
            _oid(COL_MODEL_NAME, index),
        ],
    )
    assert system.hardware_revision == "R01"
    assert system.firmware_revision == "F01"
    assert system.entity_software_revision == "17.15.1"
    assert system.version == "17.15.1"


@pytest.mark.parametrize(
    ("manufacturer", "sys_descr", "model"),
    [
        ("Cisco", "Cisco IOS XE Catalyst 9200 switch", "C9200-48P"),
        ("Cisco", "Cisco IOS XE Catalyst 9300 switch", "C9300-48P"),
        ("Cisco", "Cisco IOS XE Catalyst 9500 switch", "C9500-24Y4C"),
        ("Cisco", "Cisco IOS XE Catalyst 3650 switch", "WS-C3650-48PS"),
        ("Cisco", "Cisco IOS XE Catalyst 3850 switch", "WS-C3850-48P"),
        ("Aruba", "ArubaOS-CX 6300 Switch", "JL658A 6300M"),
        ("HPE", "HPE ArubaOS-CX 6200 Switch", "JL725A 6200F"),
        ("Juniper", "Junos EX4100 switch", "EX4100-48P"),
        ("Juniper", "Junos EX4300 switch", "EX4300-48P"),
        ("Juniper", "Junos EX4400 switch", "EX4400-48P"),
        ("Juniper", "Junos EX4600 switch", "EX4600-40F"),
        ("Juniper", "Junos EX4650 switch", "EX4650-48Y"),
    ],
)
def test_auto_mode_recognizes_expected_stack_platform_families(
    manufacturer: str,
    sys_descr: str,
    model: str,
) -> None:
    """Expected Cisco/Aruba/HPE/Juniper stack families use rich auto identity.

    The physical stack algorithm itself is standards-first and model-independent.
    This matrix guards the separate auto-profile decision so common operational
    switch families do not regress to brief identity collection accidentally.
    """

    index = 31
    client = FakeEntityClient(
        walks={ENT_PHYSICAL_CLASS: [(f"{ENT_PHYSICAL_CLASS}.{index}", 3)]},
        values={
            _oid(COL_HARDWARE_REV, index): "R01",
            _oid(COL_FIRMWARE_REV, index): "F01",
            _oid(COL_SOFTWARE_REV, index): "1.0",
            _oid(COL_SERIAL_NUMBER, index): f"SER-{model}",
            _oid(COL_MANUFACTURER, index): manufacturer,
            _oid(COL_MODEL_NAME, index): model,
        },
    )
    system = SystemDetails(manufacturer=manufacturer, sys_descr=sys_descr)

    asyncio.run(enrich_system_from_entity_mib(client, system, "auto"))

    requested = client.calls[1][1]
    assert isinstance(requested, list)
    assert _oid(COL_HARDWARE_REV, index) in requested
    assert _oid(COL_FIRMWARE_REV, index) in requested
    assert _oid(COL_SOFTWARE_REV, index) in requested
    assert system.model == model


def test_auto_mode_uses_brief_profile_for_unknown_or_virtual_device() -> None:
    """Unknown/virtual systems should avoid low-value revision requests in auto."""

    for system in (
        SystemDetails(sys_descr="Generic SNMP agent"),
        SystemDetails(manufacturer="VMware", sys_descr="VMware virtual appliance"),
    ):
        index = 8
        client = FakeEntityClient(
            walks={ENT_PHYSICAL_CLASS: [(f"{ENT_PHYSICAL_CLASS}.{index}", 3)]},
            values={
                _oid(COL_SERIAL_NUMBER, index): "SER8",
                _oid(COL_MANUFACTURER, index): "Example",
                _oid(COL_MODEL_NAME, index): "Virtual-ish",
            },
        )

        asyncio.run(enrich_system_from_entity_mib(client, system, "auto"))

        assert client.calls[1] == (
            "get_many",
            [
                _oid(COL_SERIAL_NUMBER, index),
                _oid(COL_MANUFACTURER, index),
                _oid(COL_MODEL_NAME, index),
            ],
        )


def test_auto_hpe_network_description_enables_rich_profile() -> None:
    """HPE enterprise identity becomes rich only when the system looks network-like."""

    index = 4
    client = FakeEntityClient(
        walks={ENT_PHYSICAL_CLASS: [(f"{ENT_PHYSICAL_CLASS}.{index}", 3)]},
    )
    system = SystemDetails(manufacturer="HPE", sys_descr="HPE ProCurve Switch")

    asyncio.run(enrich_system_from_entity_mib(client, system, "auto"))

    requested = client.calls[1][1]
    assert isinstance(requested, list)
    assert _oid(COL_HARDWARE_REV, index) in requested
    assert _oid(COL_SOFTWARE_REV, index) in requested


def test_full_mode_collects_cisco_stackwise_member_inventory() -> None:
    """Full mode reuses its complete walk for Cisco Catalyst stack members."""

    stack_index = 100
    rows = [
        (_oid(5, stack_index), 11),
        (_oid(4, stack_index), 0),
        (_oid(7, stack_index), "Switch Stack"),
        (_oid(5, 10), 3),
        (_oid(4, 10), stack_index),
        (_oid(6, 10), 1),
        (_oid(7, 10), "Switch 1"),
        (_oid(11, 10), "FCW-C9300-01"),
        (_oid(12, 10), "Cisco Systems, Inc."),
        (_oid(13, 10), "C9300-48P"),
        (_oid(8, 10), "V02"),
        (_oid(5, 20), 3),
        (_oid(4, 20), stack_index),
        (_oid(6, 20), 2),
        (_oid(7, 20), "Switch 2"),
        (_oid(11, 20), "FCW-C9300-02"),
        (_oid(12, 20), "Cisco Systems, Inc."),
        (_oid(13, 20), "C9300-48P"),
        (_oid(8, 20), "V03"),
    ]
    client = FakeEntityClient(walks={ENT_PHYSICAL_ENTRY: rows})
    system = SystemDetails(manufacturer="Cisco")

    asyncio.run(enrich_system_from_entity_mib(client, system, "full"))

    assert client.calls == [("walk", ENT_PHYSICAL_ENTRY)]
    assert [member.member_number for member in system.stack_members] == [1, 2]
    assert [member.model for member in system.stack_members] == [
        "C9300-48P",
        "C9300-48P",
    ]
    assert [member.serial_number for member in system.stack_members] == [
        "FCW-C9300-01",
        "FCW-C9300-02",
    ]


def test_auto_mode_collects_aruba_cx_vsf_member_inventory() -> None:
    """Aruba CX VSF uses the same standards-based stack/chassis hierarchy."""

    stack_index = 500
    member_indexes = (510, 520)
    values = {
        _oid(COL_CONTAINED_IN, stack_index): 0,
        _oid(COL_NAME, stack_index): "VSF Stack",
        _oid(COL_CONTAINED_IN, 510): stack_index,
        _oid(COL_PARENT_REL_POS, 510): 1,
        _oid(COL_NAME, 510): "Member 1",
        _oid(COL_CONTAINED_IN, 520): stack_index,
        _oid(COL_PARENT_REL_POS, 520): 2,
        _oid(COL_NAME, 520): "Member 2",
    }
    for index, serial in zip(member_indexes, ("CN-CX6300-01", "CN-CX6300-02"), strict=True):
        values.update(
            {
                _oid(COL_MANUFACTURER, index): "Aruba",
                _oid(COL_MODEL_NAME, index): "JL658A 6300M",
                _oid(COL_SERIAL_NUMBER, index): serial,
                _oid(COL_HARDWARE_REV, index): "R01",
                _oid(COL_SOFTWARE_REV, index): "FL.10.15",
            }
        )
    client = FakeEntityClient(
        walks={
            ENT_PHYSICAL_CLASS: [
                (f"{ENT_PHYSICAL_CLASS}.{stack_index}", 11),
                (f"{ENT_PHYSICAL_CLASS}.510", 3),
                (f"{ENT_PHYSICAL_CLASS}.520", 3),
            ]
        },
        values=values,
    )
    system = SystemDetails(manufacturer="Aruba", sys_descr="ArubaOS-CX switch")

    asyncio.run(enrich_system_from_entity_mib(client, system, "auto"))

    assert all(call != ("walk", ENT_PHYSICAL_ENTRY) for call in client.calls)
    assert [member.member_number for member in system.stack_members] == [1, 2]
    assert [member.serial_number for member in system.stack_members] == [
        "CN-CX6300-01",
        "CN-CX6300-02",
    ]
    assert all(member.software_revision == "FL.10.15" for member in system.stack_members)


def test_auto_mode_collects_juniper_virtual_chassis_without_stack_root() -> None:
    """Juniper-like sibling chassis remain discoverable without stack(11)."""

    values = {
        _oid(COL_CONTAINED_IN, 1000): 0,
        _oid(COL_PARENT_REL_POS, 1000): -1,
        _oid(COL_NAME, 1000): "FPC 0",
        _oid(COL_MANUFACTURER, 1000): "Juniper Networks",
        _oid(COL_MODEL_NAME, 1000): "EX4400-48MP",
        _oid(COL_SERIAL_NUMBER, 1000): "JNPR-EX4400-0",
        _oid(COL_CONTAINED_IN, 2000): 0,
        _oid(COL_PARENT_REL_POS, 2000): -1,
        _oid(COL_NAME, 2000): "FPC 1",
        _oid(COL_MANUFACTURER, 2000): "Juniper Networks",
        _oid(COL_MODEL_NAME, 2000): "EX4400-48MP",
        _oid(COL_SERIAL_NUMBER, 2000): "JNPR-EX4400-1",
    }
    client = FakeEntityClient(
        walks={
            ENT_PHYSICAL_CLASS: [
                (f"{ENT_PHYSICAL_CLASS}.1000", 3),
                (f"{ENT_PHYSICAL_CLASS}.2000", 3),
            ]
        },
        values=values,
    )
    system = SystemDetails(manufacturer="Juniper", sys_descr="Junos EX4400 switch")

    asyncio.run(enrich_system_from_entity_mib(client, system, "auto"))

    assert [member.member_number for member in system.stack_members] == [0, 1]
    assert [member.serial_number for member in system.stack_members] == [
        "JNPR-EX4400-0",
        "JNPR-EX4400-1",
    ]


def test_selective_mode_ignores_malformed_or_irrelevant_class_rows() -> None:
    """Malformed rows and non-chassis classes must not trigger targeted GETs."""

    client = FakeEntityClient(
        walks={
            ENT_PHYSICAL_CLASS: [
                (ENT_PHYSICAL_CLASS, 3),
                (f"{ENT_PHYSICAL_CLASS}.bad", 3),
                (f"{ENT_PHYSICAL_CLASS}.12", 10),
                ("1.3.6.1.4.1.999.1", 3),
            ]
        }
    )
    system = SystemDetails()

    asyncio.run(enrich_system_from_entity_mib(client, system, "brief"))

    assert client.calls == [("walk", ENT_PHYSICAL_CLASS)]
    assert system.model is None
    assert system.serial_number is None


def test_invalid_entity_mode_is_rejected_defensively() -> None:
    """Direct collector callers receive a useful error for unsupported modes."""

    client = FakeEntityClient()
    with pytest.raises(ValueError, match=r"full.*auto.*brief"):
        asyncio.run(enrich_system_from_entity_mib(client, SystemDetails(), "fast"))


def test_worker_entity_switch_and_mode_forwarding(config, monkeypatch) -> None:
    """Worker detail collection honors the master switch and forwards the mode."""

    import lldp_runner.worker as worker
    from lldp_runner.models import DeviceTask

    class FakeDetailClient:
        """Minimal async context manager because collectors are monkeypatched."""

        async def __aenter__(self):
            """Return the fake open client used by the worker detail chain."""

            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            """Close the fake client without suppressing exceptions."""

            return None

    async def fake_interfaces(_client):
        """Avoid unrelated IF-MIB traffic while exercising ENTITY dispatch."""

        return {}

    modes: list[str] = []

    async def fake_entity(_client, _system, mode):
        """Record the mode passed from worker configuration to the collector."""

        modes.append(mode)

    monkeypatch.setattr(
        worker,
        "create_snmp_client",
        lambda *_args, **_kwargs: FakeDetailClient(),
    )
    monkeypatch.setattr(worker, "collect_interfaces", fake_interfaces)
    monkeypatch.setattr(worker, "enrich_system_from_entity_mib", fake_entity)
    config.neighbors.enable_lldp = False
    config.neighbors.enable_lldpv2 = False
    config.neighbors.cdp_for_cisco = False
    config.neighbors.cdp_manufacturers = []
    config.snmp.entity_mib_mode = "brief"

    task = DeviceTask(
        host_id=1,
        preferred_name="switch1.example.net",
        names=["switch1.example.net"],
        addresses=["198.18.0.1"],
        attempts=[],
        cohort=0,
    )
    basic = worker._SuccessfulBasic(
        address="198.18.0.1",
        profile_name="default",
        credential=config.credentials[config.credential_profiles["default"].primary],
        credential_result="primary",
        credential_source="policy-profile",
        credential_label=None,
        system=SystemDetails(),
    )

    config.snmp.collect_entity_mib = False
    asyncio.run(worker._collect_detail(config, task, basic, []))
    assert modes == []

    config.snmp.collect_entity_mib = True
    asyncio.run(worker._collect_detail(config, task, basic, []))
    assert modes == ["brief"]
