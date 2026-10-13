"""Audit-only local-interface observation grouping regression coverage."""

from __future__ import annotations

from copy import deepcopy
from itertools import permutations

from lldp_runner.models import NeighborObservation
from lldp_runner.topology_shadow import build_interface_observation_groups


def _observations() -> list[NeighborObservation]:
    return [
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi0/0/3",
            local_interface_raw="GigabitEthernet0/0/3",
            remote_name="hq-access-r05-4400.net.example.com",
            remote_interface="ge-0/0/0",
            remote_interface_raw="ge-0/0/0",
            remote_addresses=["198.18.0.2"],
            chassis_id="00:11:22:33:44:55",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
        NeighborObservation(
            protocol="cdp",
            local_interface="Gi0/0/3",
            local_interface_raw="GigabitEthernet0/0/3",
            remote_name="hq-vdc2-7nx1.net.example.com(SERIAL000001)",
            remote_interface="mgmt0",
            remote_interface_raw="mgmt0",
            remote_addresses=["198.18.1.10"],
        ),
        NeighborObservation(
            protocol="cdp",
            local_interface="Gi0/0/3",
            local_interface_raw="GigabitEthernet0/0/3",
            remote_name="hq-vdc2-7nx2.net.example.com(SERIAL000003)",
            remote_interface="mgmt0",
            remote_interface_raw="mgmt0",
            remote_addresses=["198.18.1.11"],
        ),
    ]


def test_shadow_group_preserves_many_members_and_is_order_independent() -> None:
    """A direct/indirect-looking interface group remains factual and stable."""

    variants = [
        build_interface_observation_groups(100, deepcopy(list(order)))
        for order in permutations(_observations())
    ]

    assert all(value == variants[0] for value in variants[1:])
    assert len(variants[0]) == 1
    group = variants[0][0]
    assert group["analysis_status"] == "shadow"
    assert group["cardinality"] == "many"
    assert group["member_count"] == 3
    assert [member["remote_base_name"] for member in group["members"]] == [
        "hq-access-r05-4400.net.example.com",
        "hq-vdc2-7nx1.net.example.com",
        "hq-vdc2-7nx2.net.example.com",
    ]
    members_by_name = {
        member["remote_base_name"]: member for member in group["members"]
    }
    assert (
        members_by_name["hq-vdc2-7nx1.net.example.com"]["serial_hint"]
        == "SERIAL000001"
    )
    assert all(
        member["relationship_scope"] == "unclassified"
        for member in group["members"]
    )


def test_shadow_groups_omit_simple_one_neighbor_interfaces() -> None:
    """The audit view stays concise when no many-neighbor analysis is needed."""

    assert build_interface_observation_groups(100, _observations()[:1]) == []

def test_shadow_group_fingerprint_ignores_run_local_source_id() -> None:
    """The same nested interface group remains comparable across run host IDs."""

    left = build_interface_observation_groups(100, _observations())[0]
    right = build_interface_observation_groups(9000, _observations())[0]

    assert left["source_host_id"] == 100
    assert right["source_host_id"] == 9000
    assert left["group_fingerprint"] == right["group_fingerprint"]
