from __future__ import annotations

import asyncio

import pytest

from lldp_runner.collectors.cdp import (
    CDP_CACHE_ENTRY,
    CdpSnapshotIncompleteError,
    collect_cdp,
)
from lldp_runner.collectors.lldp import (
    LLDP_LOC_PORT_ENTRY,
    LLDP_REM_ENTRY,
    LLDP_REM_MAN_ADDR_ENTRY,
    collect_lldp,
)


class FakeWalker:
    def __init__(self, rows):
        self.rows = rows

    async def walk(self, oid):
        return self.rows.get(oid, [])


def test_cdp_collection():
    rows = {
        CDP_CACHE_ENTRY: [
            (f"{CDP_CACHE_ENTRY}.4.101.1", bytes([198, 18, 20, 2])),
            (f"{CDP_CACHE_ENTRY}.6.101.1", b"switch2.net.example.com"),
            (f"{CDP_CACHE_ENTRY}.7.101.1", b"GigabitEthernet1/0/48"),
            (f"{CDP_CACHE_ENTRY}.8.101.1", b"cisco C9300-48P"),
            (f"{CDP_CACHE_ENTRY}.9.101.1", bytes([0x09])),
        ]
    }
    observations = asyncio.run(
        collect_cdp(FakeWalker(rows), {101: ("GigabitEthernet1/0/1", "Gi1/0/1")})
    )
    assert len(observations) == 1
    obs = observations[0]
    assert obs.remote_name == "switch2.net.example.com"
    assert obs.remote_addresses == ["198.18.20.2"]
    assert obs.details["device_id"] == "switch2.net.example.com"
    assert obs.details["entry_addresses"] == ["198.18.20.2"]
    assert obs.local_interface == "Gi1/0/1"
    assert obs.remote_interface == "Gi1/0/48"
    assert "router" in obs.capabilities and "switch" in obs.capabilities


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        (
            [(f"{CDP_CACHE_ENTRY}.7.101.1", b"Gi1/0/48")],
            "device_id",
        ),
        (
            [(f"{CDP_CACHE_ENTRY}.6.101.1", b"switch2")],
            "remote_port",
        ),
    ],
)
def test_cdp_snapshot_requires_device_id_and_remote_port(rows, expected) -> None:
    """Identity-empty CDP cache rows must never materialize shell endpoints."""

    with pytest.raises(CdpSnapshotIncompleteError, match=expected):
        asyncio.run(collect_cdp(FakeWalker({CDP_CACHE_ENTRY: rows}), {}))


def test_cdp_snapshot_rejects_mismatched_cache_index_columns() -> None:
    """Optional index columns cannot disagree with the row's OID index."""

    rows = {
        CDP_CACHE_ENTRY: [
            (f"{CDP_CACHE_ENTRY}.1.101.1", 102),
            (f"{CDP_CACHE_ENTRY}.2.101.1", 1),
            (f"{CDP_CACHE_ENTRY}.6.101.1", b"switch2"),
            (f"{CDP_CACHE_ENTRY}.7.101.1", b"Gi1/0/48"),
        ]
    }

    with pytest.raises(CdpSnapshotIncompleteError, match="index mismatch"):
        asyncio.run(collect_cdp(FakeWalker(rows), {}))


def test_cdp_mid_table_mutation_rejects_entire_snapshot() -> None:
    """A partial new row invalidates the complete cache snapshot."""

    rows = {
        CDP_CACHE_ENTRY: [
            (f"{CDP_CACHE_ENTRY}.6.101.1", b"switch2"),
            (f"{CDP_CACHE_ENTRY}.7.101.1", b"Gi1/0/48"),
            # Later columns from a newly inserted row arrived without its
            # mandatory identity columns while the walk was in progress.
            (f"{CDP_CACHE_ENTRY}.8.2006.2472", b"Cisco IOS"),
            (f"{CDP_CACHE_ENTRY}.9.2006.2472", bytes([0x01])),
        ]
    }

    with pytest.raises(CdpSnapshotIncompleteError, match=r"2006\.2472"):
        asyncio.run(collect_cdp(FakeWalker(rows), {}))


def test_cdp_non_host_entry_address_is_diagnostic_only():
    """CDP 0.0.0.0/limited-broadcast values cannot become remote identity."""

    for raw in (bytes([0, 0, 0, 0]), bytes([255, 255, 255, 255])):
        rows = {
            CDP_CACHE_ENTRY: [
                (f"{CDP_CACHE_ENTRY}.4.101.1", raw),
                (f"{CDP_CACHE_ENTRY}.6.101.1", b"esxi-a.example.com"),
                (f"{CDP_CACHE_ENTRY}.7.101.1", b"vmnic0"),
                (f"{CDP_CACHE_ENTRY}.8.101.1", b"VMware ESXi"),
            ]
        }
        observation = asyncio.run(
            collect_cdp(
                FakeWalker(rows),
                {101: ("TwentyFiveGigE1/0/1", "Twe1/0/1")},
            )
        )[0]

        parsed = str(raw[0]) + "." + ".".join(str(item) for item in raw[1:])
        assert observation.remote_addresses == []
        assert observation.details["entry_addresses"] == [parsed]


def test_lldp_management_filter_rejects_non_host_values_but_keeps_link_local():
    """LLDP management-address indexes use the same host-eligibility boundary."""

    ipv6_unspecified = ".".join(["0"] * 16)
    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"ESXI-A"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"vmnic0"),
            (f"{LLDP_REM_ENTRY}.9.123.7.1", b"esxi-a.example.com"),
        ],
        LLDP_REM_MAN_ADDR_ENTRY: [
            (f"{LLDP_REM_MAN_ADDR_ENTRY}.3.123.7.1.1.4.0.0.0.0", 2),
            (
                f"{LLDP_REM_MAN_ADDR_ENTRY}.3.123.7.1.1.4.255.255.255.255",
                2,
            ),
            (f"{LLDP_REM_MAN_ADDR_ENTRY}.3.123.7.1.2.16.{ipv6_unspecified}", 2),
            (f"{LLDP_REM_MAN_ADDR_ENTRY}.3.123.7.1.1.4.169.254.100.10", 2),
        ],
    }

    collection = asyncio.run(collect_lldp(FakeWalker(rows), {}))
    observation = collection[0]
    assert observation.remote_addresses == ["169.254.100.10"]
    management = collection.subtable_coverage["remote_management_address"]
    assert management.status == "complete"
    assert management.attempts == 1
    assert management.object_count == 4
    assert management.row_count == 4
    assert management.valid_address_count == 1
    assert management.ipv4_address_count == 1
    assert management.ipv6_address_count == 0
    assert management.rejected_address_count == 3
    assert management.malformed_index_count == 0
    assert management.duration_ms >= 0


def test_lldp_collection_with_management_address():
    rows = {
        LLDP_LOC_PORT_ENTRY: [
            (f"{LLDP_LOC_PORT_ENTRY}.3.7", b"GigabitEthernet1/0/7"),
        ],
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"LABPC-P123456"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"GigabitEthernet1/0/48"),
            (f"{LLDP_REM_ENTRY}.9.123.7.1", b"dist2.net.example.com"),
            (f"{LLDP_REM_ENTRY}.10.123.7.1", b"Juniper Networks EX4300"),
            (f"{LLDP_REM_ENTRY}.12.123.7.1", bytes([0x28])),
        ],
        LLDP_REM_MAN_ADDR_ENTRY: [
            (f"{LLDP_REM_MAN_ADDR_ENTRY}.3.123.7.1.1.4.198.18.20.3", 2),
        ],
    }
    observations = asyncio.run(collect_lldp(FakeWalker(rows), {}))
    assert len(observations) == 1
    assert set(observations.subtable_coverage) == {
        "local_port",
        "remote_neighbor",
        "remote_management_address",
    }
    assert observations.subtable_coverage["local_port"].status == "complete"
    assert observations.subtable_coverage["remote_neighbor"].row_count == 1
    management = observations.subtable_coverage["remote_management_address"]
    assert management.status == "complete"
    assert management.valid_address_count == 1
    assert management.ipv4_address_count == 1
    obs = observations[0]
    assert obs.remote_name == "dist2.net.example.com"
    assert obs.remote_addresses == ["198.18.20.3"]
    assert obs.local_interface == "Gi1/0/7"
    assert obs.chassis_id == "LABPC-P123456"
    assert obs.chassis_id_subtype_id == 7
    assert obs.chassis_id_subtype == "local"
    assert set(obs.capabilities) == {"bridge", "router"}


def test_lldp_mac_port_id_uses_port_subtype_and_preserves_details():
    """A Windows-style binary MAC Port ID is rendered as canonical MAC text."""

    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"WINDOWS-HOST"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 3),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", bytes.fromhex("8c04baa31a0d")),
            (f"{LLDP_REM_ENTRY}.8.123.7.1", b"Ethernet adapter"),
            (f"{LLDP_REM_ENTRY}.9.123.7.1", b"workstation.example.com"),
        ],
    }
    observations = asyncio.run(
        collect_lldp(FakeWalker(rows), {7: ("GigabitEthernet1/0/7", "Gi1/0/7")})
    )

    obs = observations[0]
    assert obs.remote_interface == "8c:04:ba:a3:1a:0d"
    assert obs.remote_interface_raw == "8c:04:ba:a3:1a:0d"
    assert obs.details["port_id"] == "8c:04:ba:a3:1a:0d"
    assert obs.details["port_id_subtype"] == "mac_address"
    assert obs.details["port_id_subtype_id"] == 3
    assert obs.details["port_description"] == "Ethernet adapter"


def test_lldpv2_collection_with_ifindex_and_management_address():
    from lldp_runner.collectors.lldp import (
        LLDPV2_REM_ENTRY,
        LLDPV2_REM_MAN_ADDR_ENTRY,
        collect_lldpv2,
    )

    # Index shape: timeMark, localIfIndex, localDestMACAddress components, remIndex.
    remote_index = "123.101.6.0.17.34.51.68.85.1"
    rows = {
        LLDPV2_REM_ENTRY: [
            (f"{LLDPV2_REM_ENTRY}.5.{remote_index}", 4),
            (f"{LLDPV2_REM_ENTRY}.6.{remote_index}", b"00:11:22:33:44:55"),
            (f"{LLDPV2_REM_ENTRY}.7.{remote_index}", 5),
            (f"{LLDPV2_REM_ENTRY}.8.{remote_index}", b"Ethernet2/3"),
            (f"{LLDPV2_REM_ENTRY}.10.{remote_index}", b"leaf2.net.example.com"),
            (f"{LLDPV2_REM_ENTRY}.11.{remote_index}", b"Arista 7050SX3"),
            (f"{LLDPV2_REM_ENTRY}.13.{remote_index}", bytes([0x28])),
        ],
        LLDPV2_REM_MAN_ADDR_ENTRY: [
            (
                f"{LLDPV2_REM_MAN_ADDR_ENTRY}.3.{remote_index}.1.4.198.18.30.2",
                2,
            ),
        ],
    }
    observations = asyncio.run(collect_lldpv2(FakeWalker(rows), {101: ("Ethernet1", "Eth1")}))
    assert len(observations) == 1
    obs = observations[0]
    assert obs.local_interface == "Eth1"
    assert obs.remote_name == "leaf2.net.example.com"
    assert obs.remote_interface == "Eth2/3"
    assert obs.remote_addresses == ["198.18.30.2"]
    assert obs.chassis_id_subtype_id == 4
    assert obs.chassis_id_subtype == "mac_address"
    assert obs.details["port_id"] == "Ethernet2/3"
    assert obs.details["port_id_subtype"] == "interface_name"
    assert obs.details["port_id_subtype_id"] == 5
    assert set(obs.capabilities) == {"bridge", "router"}
    assert set(observations.subtable_coverage) == {
        "remote_neighbor",
        "remote_management_address",
    }
    management = observations.subtable_coverage["remote_management_address"]
    assert management.status == "complete"
    assert management.row_count == 1
    assert management.valid_address_count == 1
    assert management.ipv4_address_count == 1


def test_merge_neighbor_observations_preserves_protocol_specific_evidence():
    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    lldp = NeighborObservation(
        protocol="lldp",
        local_interface="Gi1/0/1",
        local_interface_raw="GigabitEthernet1/0/1",
        remote_name="hq-spare-access-6300",
        remote_interface="1/1/48",
        remote_interface_raw="1/1/48",
        remote_addresses=["198.18.40.10"],
        remote_description="HPE ANW JL660A FL.10.16.1051",
        capabilities=["bridge"],
        chassis_id="00:11:22:33:44:55",
        chassis_id_subtype="local",
        chassis_id_subtype_id=7,
        details={"local_port_num": 1},
    )
    cdp = NeighborObservation(
        protocol="cdp",
        local_interface="Gi1/0/1",
        local_interface_raw="GigabitEthernet1/0/1",
        remote_name="hq-spare-access-6300",
        remote_interface="1/1/48",
        remote_interface_raw="1/1/48",
        remote_addresses=["198.18.40.10"],
        remote_description="ArubaOS-CX",
        remote_platform="HPE JL660A",
        capabilities=["switch"],
        chassis_id="00:11:22:33:44:55",
        details={"address_type": "ip"},
    )

    merged = merge_neighbor_observations([lldp, cdp])
    assert len(merged) == 1
    details = merged[0].details
    assert details["protocols"] == ["cdp", "lldp"]
    assert details["lldp.remote_description"] == "HPE ANW JL660A FL.10.16.1051"
    assert details["lldp.chassis_id_subtype"] == "local"
    assert details["lldp.chassis_id_subtype_id"] == 7
    assert details["cdp.remote_platform"] == "HPE JL660A"
    assert details["cdp.address_type"] == "ip"


def test_lldp_binary_chassis_id_is_printable_hex():
    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"\x00\x07_{f4"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"1/1/1"),
        ],
    }
    observations = asyncio.run(collect_lldp(FakeWalker(rows), {7: ("Gi1/0/7", "Gi1/0/7")}))
    assert observations[0].chassis_id == "hex:00:07:5f:7b:66:34"
    assert observations[0].chassis_id_subtype == "local"


def test_lldpv2_binary_mac_chassis_id_is_canonical_text():
    from lldp_runner.collectors.lldp import LLDPV2_REM_ENTRY, collect_lldpv2

    remote_index = "123.101.6.0.17.34.51.68.85.1"
    rows = {
        LLDPV2_REM_ENTRY: [
            (f"{LLDPV2_REM_ENTRY}.5.{remote_index}", 4),
            (f"{LLDPV2_REM_ENTRY}.6.{remote_index}", bytes.fromhex("8c04baa31a0d")),
            (f"{LLDPV2_REM_ENTRY}.7.{remote_index}", 3),
            (f"{LLDPV2_REM_ENTRY}.8.{remote_index}", bytes.fromhex("001122334455")),
        ],
    }
    observations = asyncio.run(collect_lldpv2(FakeWalker(rows), {101: ("Ethernet1", "Eth1")}))
    assert observations[0].chassis_id == "8c:04:ba:a3:1a:0d"
    assert observations[0].chassis_id_subtype_id == 4
    assert observations[0].remote_interface == "00:11:22:33:44:55"
    assert observations[0].details["port_id_subtype"] == "mac_address"
    assert observations[0].details["port_id_subtype_id"] == 3


def test_merge_nexus_vdc_cdp_lldp_same_link_uses_logical_name():
    """NX-OS CDP name(serial) and LLDP System Name should form one edge."""

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    lldp = NeighborObservation(
        protocol="lldp",
        local_interface="Hu1/0/25",
        local_interface_raw="HundredGigE1/0/25",
        remote_name="hq-vdc2-7nx1.net.example.com",
        remote_interface="Eth1/2",
        remote_interface_raw="Eth1/2",
        remote_addresses=["203.0.113.24", "2001:db8:113d:61::1000:46"],
        remote_description="Cisco NX-OS(tm) n7700, Software Version 8.4(12)",
        capabilities=["bridge", "router"],
        chassis_id="00:12:34:56:b0:01",
        chassis_id_subtype="mac_address",
        chassis_id_subtype_id=4,
        details={"local_port_num": 26, "remote_index": 5},
    )
    cdp = NeighborObservation(
        protocol="cdp",
        local_interface="Hu1/0/25",
        local_interface_raw="HundredGigE1/0/25",
        remote_name="hq-vdc2-7nx1.net.example.com(SERIAL000001)",
        remote_interface="Eth1/2",
        remote_interface_raw="Ethernet1/2",
        remote_addresses=["203.0.113.103"],
        remote_description="Cisco Nexus Operating System (NX-OS) Software, Version 8.4(12)",
        remote_platform="N77-C7718",
        capabilities=["router", "switch"],
        details={
            "ifindex": 26,
            "device_index": 13,
            "device_id": "hq-vdc2-7nx1.net.example.com(SERIAL000001)",
            "entry_addresses": ["203.0.113.103"],
        },
    )

    merged = merge_neighbor_observations([lldp, cdp])

    assert len(merged) == 1
    obs = merged[0]
    assert obs.remote_name == "hq-vdc2-7nx1.net.example.com"
    assert obs.remote_addresses == [
        "2001:db8:113d:61::1000:46",
        "203.0.113.24",
        "203.0.113.103",
    ]
    assert obs.details["protocols"] == ["cdp", "lldp"]
    assert obs.details["cdp.remote_name"] == ("hq-vdc2-7nx1.net.example.com(SERIAL000001)")
    assert obs.details["cdp.device_id"] == ("hq-vdc2-7nx1.net.example.com(SERIAL000001)")
    assert obs.details["cdp.entry_addresses"] == ["203.0.113.103"]
    assert obs.details["lldp.chassis_id"] == "00:12:34:56:b0:01"


def test_merge_does_not_strip_nonserial_parenthesized_name():
    """Parentheses alone must not become a name-normalization heuristic."""

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    lldp = NeighborObservation(
        protocol="lldp",
        local_interface="Gi1/0/1",
        local_interface_raw="Gi1/0/1",
        remote_name="printer-a.example.com",
        remote_interface="eth0",
        remote_interface_raw="eth0",
        remote_addresses=["198.18.70.10"],
        remote_description="Generic endpoint",
    )
    cdp = NeighborObservation(
        protocol="cdp",
        local_interface="Gi1/0/1",
        local_interface_raw="Gi1/0/1",
        remote_name="printer-a.example.com(ROOM1)",
        remote_interface="eth0",
        remote_interface_raw="eth0",
        remote_addresses=["198.18.70.11"],
        remote_description="Generic endpoint",
        remote_platform="Generic",
    )

    assert len(merge_neighbor_observations([lldp, cdp])) == 2


def test_lldp_incomplete_snapshot_rejects_partial_remote_row():
    """Later LLDP columns without mandatory IDs must trigger a full retry."""

    import pytest

    from lldp_runner.collectors.lldp import LldpSnapshotIncompleteError

    rows = {
        LLDP_REM_ENTRY: [
            # This reproduces the production partial-row shape: later columns
            # arrived, but chassis/port identity columns were absent.
            (f"{LLDP_REM_ENTRY}.9.0.27.2037", b"WTC45AB1D5ECFA"),
            (f"{LLDP_REM_ENTRY}.10.0.27.2037", b"DellThinOS 2502"),
            (f"{LLDP_REM_ENTRY}.12.0.27.2037", bytes([0x01])),
        ],
    }

    with pytest.raises(LldpSnapshotIncompleteError, match="mandatory"):
        asyncio.run(collect_lldp(FakeWalker(rows), {}))


def test_lldp_preserves_time_mark_and_keeps_management_on_full_index():
    """LLDP table assembly must not discard the timeMark index component."""

    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.100.7.1", 4),
            (f"{LLDP_REM_ENTRY}.5.100.7.1", bytes.fromhex("001122334455")),
            (f"{LLDP_REM_ENTRY}.6.100.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.100.7.1", b"Ethernet1"),
            (f"{LLDP_REM_ENTRY}.9.100.7.1", b"leaf-a.example.com"),
            (f"{LLDP_REM_ENTRY}.4.200.7.1", 4),
            (f"{LLDP_REM_ENTRY}.5.200.7.1", bytes.fromhex("001122334466")),
            (f"{LLDP_REM_ENTRY}.6.200.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.200.7.1", b"Ethernet2"),
            (f"{LLDP_REM_ENTRY}.9.200.7.1", b"leaf-b.example.com"),
        ],
        LLDP_REM_MAN_ADDR_ENTRY: [
            (f"{LLDP_REM_MAN_ADDR_ENTRY}.3.100.7.1.1.4.198.18.1.10", 2),
            (f"{LLDP_REM_MAN_ADDR_ENTRY}.3.200.7.1.1.4.198.18.1.20", 2),
        ],
    }

    observations = asyncio.run(collect_lldp(FakeWalker(rows), {}))

    assert len(observations) == 2
    by_name = {item.remote_name: item for item in observations}
    assert by_name["leaf-a.example.com"].details["time_mark"] == 100
    assert by_name["leaf-a.example.com"].remote_addresses == ["198.18.1.10"]
    assert by_name["leaf-b.example.com"].details["time_mark"] == 200
    assert by_name["leaf-b.example.com"].remote_addresses == ["198.18.1.20"]


def test_lldpv2_preserves_destination_mac_index_details():
    """LLDPv2 keeps destination-MAC context instead of collapsing row indexes."""

    from lldp_runner.collectors.lldp import LLDPV2_REM_ENTRY, collect_lldpv2

    remote_index = "123.101.6.0.17.34.51.68.85.1"
    rows = {
        LLDPV2_REM_ENTRY: [
            (f"{LLDPV2_REM_ENTRY}.5.{remote_index}", 4),
            (f"{LLDPV2_REM_ENTRY}.6.{remote_index}", bytes.fromhex("001122334455")),
            (f"{LLDPV2_REM_ENTRY}.7.{remote_index}", 5),
            (f"{LLDPV2_REM_ENTRY}.8.{remote_index}", b"Ethernet2/3"),
        ],
    }

    observation = asyncio.run(collect_lldpv2(FakeWalker(rows), {101: ("Ethernet1", "Eth1")}))[0]

    assert observation.details["time_mark"] == 123
    assert observation.details["local_dest_mac"] == "00:11:22:33:44:55"


def test_merge_phone_short_name_and_fqdn_on_same_port_and_address():
    """CDP short name and LLDP FQDN for one phone should become one edge."""

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    cdp = NeighborObservation(
        protocol="cdp",
        local_interface="Gi1/0/8",
        local_interface_raw="GigabitEthernet1/0/8",
        remote_name="SEP00123456000C",
        remote_interface="Port 1",
        remote_interface_raw="Port 1",
        remote_addresses=["198.51.100.33"],
        remote_description="Cisco IP Phone 8841",
        remote_platform="Cisco IP Phone 8841",
        details={"device_id": "SEP00123456000C"},
    )
    lldp = NeighborObservation(
        protocol="lldp",
        local_interface="Gi1/0/8",
        local_interface_raw="GigabitEthernet1/0/8",
        remote_name="SEP00123456000C.voice-a.example.com",
        remote_interface="00123456000C:P1",
        remote_interface_raw="00123456000C:P1",
        remote_addresses=["198.51.100.33"],
        remote_description="Cisco IP Phone 8841, V1",
        capabilities=["bridge", "telephone"],
        chassis_id="198.51.100.33",
        chassis_id_subtype="network_address",
        chassis_id_subtype_id=5,
        details={"port_id": "00123456000C:P1"},
    )

    merged = merge_neighbor_observations([cdp, lldp])

    assert len(merged) == 1
    observation = merged[0]
    assert observation.remote_name == "SEP00123456000C.voice-a.example.com"
    assert observation.remote_interface == "00123456000C:P1"
    assert observation.remote_addresses == ["198.51.100.33"]
    assert observation.details["protocols"] == ["cdp", "lldp"]
    assert observation.details["cdp.remote_interface"] == "Port 1"
    assert observation.details["lldp.remote_interface"] == "00123456000C:P1"


def test_merge_short_fqdn_rule_requires_same_port_address_and_one_short_name():
    """Edge-scoped host-label matching must not become global suffix stripping."""

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    def observation(
        protocol: str,
        local: str,
        name: str,
        remote_port: str,
        address: str,
    ) -> NeighborObservation:
        return NeighborObservation(
            protocol=protocol,
            local_interface=local,
            local_interface_raw=local,
            remote_name=name,
            remote_interface=remote_port,
            remote_interface_raw=remote_port,
            remote_addresses=[address],
        )

    # Same host-label representation, but different address.
    assert (
        len(
            merge_neighbor_observations(
                [
                    observation("cdp", "Gi1/0/8", "PHONE1", "Port 1", "198.18.1.10"),
                    observation(
                        "lldp", "Gi1/0/8", "PHONE1.example.com", "PHONE1:P1", "198.18.1.11"
                    ),
                ]
            )
        )
        == 2
    )

    # Same address/name representation, but learned on different local ports.
    assert (
        len(
            merge_neighbor_observations(
                [
                    observation("cdp", "Gi1/0/8", "PHONE1", "Port 1", "198.18.1.10"),
                    observation(
                        "lldp", "Gi1/0/9", "PHONE1.example.com", "PHONE1:P1", "198.18.1.10"
                    ),
                ]
            )
        )
        == 2
    )

    # Two FQDNs in different domains never match merely by left-most label.
    assert (
        len(
            merge_neighbor_observations(
                [
                    observation(
                        "cdp", "Gi1/0/8", "PHONE1.site-a.example.com", "Port 1", "198.18.1.10"
                    ),
                    observation(
                        "lldp", "Gi1/0/8", "PHONE1.site-b.example.net", "PHONE1:P1", "198.18.1.10"
                    ),
                ]
            )
        )
        == 2
    )


def test_lldp_management_walk_failure_is_not_silently_converted_to_empty_table():
    """A failed management subtable must reach worker retry/coverage handling."""

    class FailingManagementWalker(FakeWalker):
        async def walk(self, oid):
            if oid == LLDP_REM_MAN_ADDR_ENTRY:
                raise TimeoutError("management table timeout")
            return await super().walk(oid)

    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.0.1.1", 5),
            (f"{LLDP_REM_ENTRY}.5.0.1.1", bytes([1, 4, 10, 248, 15, 173])),
            (f"{LLDP_REM_ENTRY}.6.0.1.1", 7),
            (f"{LLDP_REM_ENTRY}.7.0.1.1", b"001234560004:P1"),
            (f"{LLDP_REM_ENTRY}.9.0.1.1", b"SEP001234560004.voice-a.example.com"),
        ]
    }

    import pytest

    with pytest.raises(TimeoutError, match="management table timeout") as raised:
        asyncio.run(collect_lldp(FailingManagementWalker(rows), {}))
    coverage = raised.value.lldp_subtable_coverage
    assert coverage["remote_neighbor"].status == "complete"
    assert coverage["remote_neighbor"].row_count == 1
    assert coverage["remote_management_address"].status == "timeout"
    assert coverage["remote_management_address"].attempts == 1
    assert coverage["remote_management_address"].row_count is None
    assert coverage["remote_management_address"].message == "TimeoutError: management table timeout"


def test_merge_sep_phone_without_lldp_management_address_uses_embedded_mac():
    """Production SEP identity merges CDP/LLDP despite a missing LLDP man-address row."""

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    cdp = NeighborObservation(
        protocol="cdp",
        local_interface="Gi1/0/1",
        local_interface_raw="GigabitEthernet1/0/1",
        remote_name="SEP001234560004",
        remote_interface="Port 1",
        remote_interface_raw="Port 1",
        remote_addresses=["198.51.100.173"],
        remote_description="sip88xx.12-0-7MPP0501-20260317-aa82ce7433.loads",
    )
    lldp = NeighborObservation(
        protocol="lldp",
        local_interface="Gi1/0/1",
        local_interface_raw="GigabitEthernet1/0/1",
        remote_name="SEP001234560004.voice-a.example.com",
        remote_interface="001234560004:P1",
        remote_interface_raw="001234560004:P1",
        remote_addresses=[],
        remote_description="Cisco IP Phone 8841, V1",
        chassis_id="198.51.100.173",
        chassis_id_subtype="network_address",
        chassis_id_subtype_id=5,
        details={"port_id": "001234560004:P1"},
    )

    merged = merge_neighbor_observations([cdp, lldp])

    assert len(merged) == 1
    assert merged[0].remote_name == "SEP001234560004.voice-a.example.com"
    assert merged[0].remote_interface == "001234560004:P1"
    assert merged[0].details["protocols"] == ["cdp", "lldp"]


def test_merge_sep_phone_accepts_different_suffixes_only_for_same_sep_mac():
    """Webex/guest suffix transitions do not create a second physical endpoint."""

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    def obs(protocol: str, name: str, port: str) -> NeighborObservation:
        return NeighborObservation(
            protocol=protocol,
            local_interface="Gi1/0/1",
            local_interface_raw="Gi1/0/1",
            remote_name=name,
            remote_interface=port,
            remote_interface_raw=port,
        )

    assert (
        len(
            merge_neighbor_observations(
                [
                    obs("cdp", "SEP001234560004.voice-a.example.com", "Port 1"),
                    obs("lldp", "SEP001234560004.voice-b.example.net", "001234560004:P1"),
                ]
            )
        )
        == 1
    )
    assert (
        len(
            merge_neighbor_observations(
                [
                    obs("cdp", "SEP001234560004.voice-a.example.com", "Port 1"),
                    obs("lldp", "SEP001234560003.voice-b.example.net", "001234560003:P1"),
                ]
            )
        )
        == 2
    )


def test_cdp_unresolved_local_interface_retains_ifindex_namespace() -> None:
    rows = {
        CDP_CACHE_ENTRY: [
            (f"{CDP_CACHE_ENTRY}.6.101.1", b"endpoint-a"),
            (f"{CDP_CACHE_ENTRY}.7.101.1", b"Port 1"),
        ]
    }

    observation = asyncio.run(collect_cdp(FakeWalker(rows), {}))[0]

    assert observation.local_interface == "ifIndex:101"
    assert observation.local_interface_raw == "ifIndex:101"
    assert observation.details["local_interface_resolved"] is False
    assert observation.details["local_interface_namespace"] == "ifIndex"


def test_lldp_unresolved_local_interface_retains_lldp_port_namespace() -> None:
    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"endpoint-a"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"Port 1"),
            (f"{LLDP_REM_ENTRY}.9.123.7.1", b"endpoint-a"),
        ]
    }

    observation = asyncio.run(collect_lldp(FakeWalker(rows), {}))[0]

    assert observation.local_interface == "lldpLocalPort:7"
    assert observation.local_interface_raw == "lldpLocalPort:7"
    assert observation.details["local_interface_resolved"] is False
    assert observation.details["local_interface_namespace"] == "lldpLocalPort"


def test_lldpv2_unresolved_local_interface_retains_ifindex_namespace() -> None:
    from lldp_runner.collectors.lldp import LLDPV2_REM_ENTRY, collect_lldpv2

    remote_index = "123.101.6.0.17.34.51.68.85.1"
    rows = {
        LLDPV2_REM_ENTRY: [
            (f"{LLDPV2_REM_ENTRY}.5.{remote_index}", 4),
            (f"{LLDPV2_REM_ENTRY}.6.{remote_index}", b"00:11:22:33:44:55"),
            (f"{LLDPV2_REM_ENTRY}.7.{remote_index}", 5),
            (f"{LLDPV2_REM_ENTRY}.8.{remote_index}", b"Ethernet2/3"),
            (f"{LLDPV2_REM_ENTRY}.10.{remote_index}", b"endpoint-a"),
        ]
    }

    observation = asyncio.run(collect_lldpv2(FakeWalker(rows), {}))[0]

    assert observation.local_interface == "ifIndex:101"
    assert observation.local_interface_raw == "ifIndex:101"
    assert observation.details["local_interface_resolved"] is False
    assert observation.details["local_interface_namespace"] == "ifIndex"


def test_lldp_local_port_number_is_never_assumed_to_be_ifindex() -> None:
    """Original LLDP and IF-MIB indexes remain distinct numeric namespaces."""

    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"endpoint-a"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"Port 1"),
            (f"{LLDP_REM_ENTRY}.9.123.7.1", b"endpoint-a"),
        ]
    }

    observation = asyncio.run(
        collect_lldp(
            FakeWalker(rows),
            {7: ("GigabitEthernet9/9/9", "Gi9/9/9")},
        )
    )[0]

    assert observation.local_interface == "lldpLocalPort:7"
    assert observation.details["local_interface_namespace"] == "lldpLocalPort"
    assert observation.details["local_interface_resolved"] is False


def test_lldp_local_port_map_retries_once_before_using_typed_index() -> None:
    """A transient local-port walk failure must not create false port churn."""

    rows = {
        LLDP_LOC_PORT_ENTRY: [
            (f"{LLDP_LOC_PORT_ENTRY}.3.7", b"GigabitEthernet1/0/7"),
        ],
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"endpoint-a"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"Port 1"),
            (f"{LLDP_REM_ENTRY}.9.123.7.1", b"endpoint-a"),
        ],
    }

    class FlakyLocalPortWalker(FakeWalker):
        def __init__(self, values):
            super().__init__(values)
            self.local_port_calls = 0

        async def walk(self, oid):
            if oid == LLDP_LOC_PORT_ENTRY:
                self.local_port_calls += 1
                if self.local_port_calls == 1:
                    raise TimeoutError("temporary LLDP local-port timeout")
            return await super().walk(oid)

    walker = FlakyLocalPortWalker(rows)
    collection = asyncio.run(collect_lldp(walker, {}))
    observation = collection[0]

    assert walker.local_port_calls == 2
    assert collection.subtable_coverage["local_port"].status == "complete"
    assert collection.subtable_coverage["local_port"].attempts == 2
    assert observation.local_interface == "Gi1/0/7"
    assert observation.details["local_interface_resolved"] is True
    assert observation.details["local_port_map_failed"] is False


def test_lldp_empty_management_table_is_complete_not_unknown() -> None:
    """A successful zero-row walk is authoritative negative evidence."""

    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"endpoint-a"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"Port 1"),
        ],
        LLDP_REM_MAN_ADDR_ENTRY: [],
    }

    collection = asyncio.run(collect_lldp(FakeWalker(rows), {}))
    coverage = collection.subtable_coverage["remote_management_address"]
    assert coverage.status == "complete"
    assert coverage.object_count == 0
    assert coverage.row_count == 0
    assert coverage.valid_address_count == 0
    assert coverage.rejected_address_count == 0
    assert coverage.malformed_index_count == 0


def test_lldp_malformed_management_index_is_partial_and_counted() -> None:
    """Malformed indexes are not silently represented as an empty table."""

    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"endpoint-a"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"Port 1"),
        ],
        LLDP_REM_MAN_ADDR_ENTRY: [
            (f"{LLDP_REM_MAN_ADDR_ENTRY}.3.123.7.1.1.4.192.0.2.10", 2),
            (f"{LLDP_REM_MAN_ADDR_ENTRY}.3.123.7.1.1.4.192.0.2", 2),
            (f"{LLDP_REM_MAN_ADDR_ENTRY}.3.123.7.1.9.3.1.2.3", 2),
        ],
    }

    collection = asyncio.run(collect_lldp(FakeWalker(rows), {}))
    coverage = collection.subtable_coverage["remote_management_address"]
    assert collection[0].remote_addresses == ["192.0.2.10"]
    assert coverage.status == "partial"
    assert coverage.row_count == 3
    assert coverage.valid_address_count == 1
    assert coverage.ipv4_address_count == 1
    assert coverage.rejected_address_count == 0
    assert coverage.malformed_index_count == 2
    assert "malformed management-address index" in (coverage.message or "")


def test_lldp_local_port_access_restriction_is_visible_without_retry() -> None:
    """Access restriction is observable and does not consume the timeout retry."""

    from lldp_runner.snmp.resilience import SnmpAccessRestrictedError

    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"endpoint-a"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"Port 1"),
        ],
    }

    class RestrictedLocalPortWalker(FakeWalker):
        def __init__(self, values):
            super().__init__(values)
            self.local_port_calls = 0

        async def walk(self, oid):
            if oid == LLDP_LOC_PORT_ENTRY:
                self.local_port_calls += 1
                raise SnmpAccessRestrictedError("WALK", (oid,), "not in view")
            return await super().walk(oid)

    walker = RestrictedLocalPortWalker(rows)
    collection = asyncio.run(collect_lldp(walker, {}))
    assert walker.local_port_calls == 1
    assert collection.subtable_coverage["local_port"].status == "access_restricted"
    assert collection.subtable_coverage["local_port"].attempts == 1
    assert collection[0].details["local_port_map_failed"] is True


def test_lldp_persistent_local_port_map_failure_retains_remote_rows() -> None:
    """Two failed map walks retain typed topology plus explicit coverage data."""

    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"endpoint-a"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"Port 1"),
            (f"{LLDP_REM_ENTRY}.9.123.7.1", b"endpoint-a"),
        ],
    }

    class FailedLocalPortWalker(FakeWalker):
        def __init__(self, values):
            super().__init__(values)
            self.local_port_calls = 0

        async def walk(self, oid):
            if oid == LLDP_LOC_PORT_ENTRY:
                self.local_port_calls += 1
                raise TimeoutError("persistent LLDP local-port timeout")
            return await super().walk(oid)

    walker = FailedLocalPortWalker(rows)
    collection = asyncio.run(collect_lldp(walker, {}))
    observation = collection[0]

    assert walker.local_port_calls == 2
    local_coverage = collection.subtable_coverage["local_port"]
    assert local_coverage.status == "timeout"
    assert local_coverage.attempts == 2
    assert "persistent LLDP local-port timeout" in (local_coverage.message or "")
    assert collection.subtable_coverage["remote_neighbor"].status == "complete"
    assert observation.local_interface == "lldpLocalPort:7"
    assert observation.details["local_interface_resolved"] is False
    assert observation.details["local_interface_namespace"] == "lldpLocalPort"
    assert observation.details["local_port_map_failed"] is True


def test_merge_neighbor_observations_resolves_lldp_port_from_guarded_cdp_edge():
    """Stable CDP evidence can resolve one otherwise typed LLDP local index.

    Cisco 891 agents can expose the remote LLDP row while omitting a usable
    lldpLocPortId/Desc value.  Numeric equality alone remains insufficient; this
    regression also requires the same exact remote endpoint and remote port.
    """

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    lldp = NeighborObservation(
        protocol="lldp",
        local_interface="lldpLocalPort:13",
        local_interface_raw="lldpLocalPort:13",
        remote_name="branch-access-3650-1.net.example.com",
        remote_interface="Te1/0/47",
        remote_interface_raw="Te1/0/47",
        remote_addresses=["198.51.100.215"],
        chassis_id="70:7d:b9:70:54:80",
        chassis_id_subtype="mac_address",
        chassis_id_subtype_id=4,
        details={
            "local_port_num": 13,
            "local_interface_resolved": False,
            "local_interface_namespace": "lldpLocalPort",
        },
    )
    cdp = NeighborObservation(
        protocol="cdp",
        local_interface="Gi7",
        local_interface_raw="GigabitEthernet7",
        remote_name="branch-access-3650-1.net.example.com",
        remote_interface="Te1/0/47",
        remote_interface_raw="TenGigabitEthernet1/0/47",
        remote_addresses=["198.51.100.215"],
        details={
            "ifindex": 13,
            "local_interface_resolved": True,
            "local_interface_namespace": "ifIndex",
        },
    )

    from copy import deepcopy

    for rows in ([lldp, cdp], [cdp, lldp]):
        merged = merge_neighbor_observations(deepcopy(rows))

        assert len(merged) == 1
        edge = merged[0]
        assert edge.local_interface == "Gi7"
        assert edge.local_interface_raw == "GigabitEthernet7"
        assert set(edge.details["protocols"]) == {"lldp", "cdp"}
        assert edge.details["lldp.local_interface"] == "lldpLocalPort:13"
        assert edge.details["cdp.local_interface"] == "Gi7"
        assert edge.details["local_interface_resolved"] is True
        assert edge.details["local_interface_resolution_method"] == ("cross_protocol_same_endpoint")
        assert edge.details["local_interface_resolution_source"] == "cdp"


def test_merge_neighbor_observations_does_not_assume_lldp_index_is_ifindex():
    """Different numeric namespaces do not merge without complete corroboration."""

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    lldp = NeighborObservation(
        protocol="lldp",
        local_interface="lldpLocalPort:13",
        local_interface_raw="lldpLocalPort:13",
        remote_name="branch-access-3650-1.net.example.com",
        remote_interface="Te1/0/47",
        remote_interface_raw="Te1/0/47",
        remote_addresses=["198.51.100.215"],
        details={"local_port_num": 13, "local_interface_resolved": False},
    )
    cdp = NeighborObservation(
        protocol="cdp",
        local_interface="Gi7",
        local_interface_raw="GigabitEthernet7",
        remote_name="branch-access-3650-1.net.example.com",
        remote_interface="Te1/0/47",
        remote_interface_raw="TenGigabitEthernet1/0/47",
        remote_addresses=["198.51.100.215"],
        details={"ifindex": 99, "local_interface_resolved": True},
    )

    assert len(merge_neighbor_observations([lldp, cdp])) == 2


def test_neighbor_merge_is_byte_stable_across_input_order() -> None:
    """SNMP table row order cannot change the normalized neighbor collection."""

    from copy import deepcopy
    from dataclasses import asdict
    from itertools import permutations

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    values = [
        NeighborObservation(
            protocol="cdp",
            local_interface="Gi1/0/1",
            local_interface_raw="GigabitEthernet1/0/1",
            remote_name="switch-a.example.com(SERIAL123)",
            remote_interface="Eth1/1",
            remote_interface_raw="Ethernet1/1",
            remote_addresses=["198.18.0.10"],
            details={"device_id": "switch-a.example.com(SERIAL123)"},
        ),
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/1",
            local_interface_raw="GigabitEthernet1/0/1",
            remote_name="switch-a.example.com",
            remote_interface="Eth1/1",
            remote_interface_raw="Eth1/1",
            remote_addresses=["2001:db8::10", "198.18.0.10"],
            chassis_id="00:11:22:33:44:55",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/2",
            local_interface_raw="GigabitEthernet1/0/2",
            remote_name="switch-b.example.com",
            remote_interface="Eth1/2",
            remote_interface_raw="Eth1/2",
            remote_addresses=["198.18.0.20"],
        ),
    ]

    rendered = {
        repr([asdict(item) for item in merge_neighbor_observations(deepcopy(list(order)))])
        for order in permutations(values)
    }

    assert len(rendered) == 1


def test_neighbor_merge_uses_full_record_tiebreak_for_duplicate_rows() -> None:
    """Different duplicate rows merge identically regardless of arrival order."""

    from copy import deepcopy
    from dataclasses import asdict
    from itertools import permutations

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    rows = [
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/1",
            local_interface_raw="GigabitEthernet1/0/1",
            remote_name="switch-a.example.com",
            remote_interface="Eth1/1",
            remote_interface_raw="Ethernet1/1",
            remote_addresses=["198.18.0.11", "198.18.0.10"],
            remote_description="description-b",
            capabilities=["router", "bridge"],
            chassis_id="00:11:22:33:44:55",
            details={"source_note": "z"},
        ),
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/1",
            local_interface_raw="GigabitEthernet1/0/1",
            remote_name="switch-a.example.com",
            remote_interface="Eth1/1",
            remote_interface_raw="Ethernet1/1",
            remote_addresses=["198.18.0.10", "198.18.0.11"],
            remote_description="description-a",
            capabilities=["bridge", "router"],
            chassis_id="00:11:22:33:44:55",
            details={"source_note": "a"},
        ),
    ]

    rendered = {
        repr([asdict(item) for item in merge_neighbor_observations(deepcopy(list(order)))])
        for order in permutations(rows)
    }

    assert len(rendered) == 1


def test_neighbor_merge_ignores_set_like_field_order_inside_rows() -> None:
    """Address/capability order cannot select a different duplicate base row."""

    from copy import deepcopy
    from dataclasses import asdict

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    first_run = [
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/1",
            local_interface_raw="GigabitEthernet1/0/1",
            remote_name="switch-a.example.com",
            remote_interface="Eth1/1",
            remote_interface_raw="Ethernet1/1",
            remote_addresses=["198.18.0.11", "198.18.0.10"],
            remote_description="description-b",
            capabilities=["router", "bridge"],
            chassis_id="00:11:22:33:44:55",
        ),
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/1",
            local_interface_raw="GigabitEthernet1/0/1",
            remote_name="switch-a.example.com",
            remote_interface="Eth1/1",
            remote_interface_raw="Ethernet1/1",
            remote_addresses=["198.18.0.10", "198.18.0.11"],
            remote_description="description-a",
            capabilities=["bridge", "router"],
            chassis_id="00:11:22:33:44:55",
        ),
    ]
    second_run = deepcopy(first_run)
    for row in second_run:
        row.remote_addresses.reverse()
        row.capabilities.reverse()

    first = [asdict(item) for item in merge_neighbor_observations(first_run)]
    second = [asdict(item) for item in merge_neighbor_observations(second_run)]

    assert first == second


def test_lldp_subtable_attempts_include_adaptive_walk_retry() -> None:
    """Subtable telemetry counts a transport retry that sent another walk."""

    from types import SimpleNamespace

    rows = {
        LLDP_REM_ENTRY: [
            (f"{LLDP_REM_ENTRY}.4.123.7.1", 7),
            (f"{LLDP_REM_ENTRY}.5.123.7.1", b"endpoint-a"),
            (f"{LLDP_REM_ENTRY}.6.123.7.1", 5),
            (f"{LLDP_REM_ENTRY}.7.123.7.1", b"Port 1"),
        ],
    }

    class AdaptiveLookingWalker(FakeWalker):
        def __init__(self, values):
            super().__init__(values)
            self.state = SimpleNamespace(events=[])

        async def walk(self, oid):
            if oid == LLDP_REM_ENTRY:
                self.state.events.append(
                    SimpleNamespace(
                        retry_allowed=True,
                        logical_operation="WALK",
                        root_oid=oid,
                    )
                )
            return await super().walk(oid)

    collection = asyncio.run(collect_lldp(AdaptiveLookingWalker(rows), {}))
    assert collection.subtable_coverage["remote_neighbor"].attempts == 2
    assert collection.subtable_coverage["local_port"].attempts == 1
    management = collection.subtable_coverage["remote_management_address"]
    assert management.attempts == 1
