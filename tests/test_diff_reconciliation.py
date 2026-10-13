"""Cross-view event reconciliation and attachment-semantics tests."""

from __future__ import annotations

from typing import Any

from lldp_runner.diff_reconciliation import reconcile_compatibility_and_graph


def _member(remote: str, port: str, protocols: list[str]) -> dict[str, Any]:
    return {
        "remote_component_key": remote,
        "remote_entity_key": remote,
        "remote_display_name": "endpoint",
        "remote_host_refs": [],
        "remote_identity": {"strict_macs": [port], "names": []},
        "remote_interface": port,
        "protocols": protocols,
        "evidence_advertisement_keys": [],
    }


def _group(
    observer: int,
    local: str,
    remote: str,
    port: str,
    protocols: list[str],
) -> dict[str, Any]:
    return {
        "group_key": f"group-{observer}-{local}",
        "source_entity_key": f"source-{observer}",
        "source_display_name": "switch",
        "source_host_refs": [observer],
        "local_interface": local,
        "members": [_member(remote, port, protocols)],
        "member_signatures": [[remote, port, protocols]],
    }


def _add_member(
    group: dict[str, Any],
    remote: str,
    port: str,
    protocols: list[str],
) -> None:
    """Add one graph member while keeping compact fixture signatures aligned."""

    group["members"].append(_member(remote, port, protocols))
    group["member_signatures"].append([remote, port.casefold(), protocols])


def _relationship(
    key: str,
    status: str,
    *,
    a_group: dict[str, Any] | None = None,
    b_group: dict[str, Any] | None = None,
    qualification: str = "confirmed",
) -> dict[str, Any]:
    return {
        "relationship_component_key": key,
        "status": status,
        "semantic_qualification": qualification,
        "physical_topology_effect": (
            "none" if status == "protocol_evidence_changed" else "not_inferred"
        ),
        "a_groups": [a_group] if a_group else [],
        "b_groups": [b_group] if b_group else [],
        "coverage_sources": [],
    }


def _neighbor(
    host_ref: int,
    local: str,
    port: str,
    protocols: list[str],
) -> dict[str, Any]:
    return {
        "host_ref": host_ref,
        "name": "endpoint",
        "local_interface": local,
        "remote_interface": port,
        "protocols": protocols,
        "details": {"port_id": port},
    }


def test_reconciliation_folds_two_graph_halves_into_one_attachment_event() -> None:
    """A directional port change is one event backed by both graph records."""

    port = "fc:4c:ea:c6:b4:2d"
    comparison = {
        "a": {"id": 1, "preferred_name": "switch"},
        "b": {"id": 10, "preferred_name": "switch"},
        "learned_neighbors": [
            {
                "status": "moved",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "not_inferred",
                "a": _neighbor(2, "Gi1/0/10", port, ["lldp"]),
                "b": _neighbor(20, "Gi1/0/12", port, ["lldp"]),
            }
        ],
    }
    graph = {
        "available": True,
        "entity_correspondence": [],
        "relationship_groups": [
            _relationship(
                "rel-a",
                "a_only",
                a_group=_group(1, "Gi1/0/10", "remote", port, ["lldp"]),
            ),
            _relationship(
                "rel-b",
                "b_only",
                b_group=_group(10, "Gi1/0/12", "remote", port, ["lldp"]),
            ),
        ],
    }

    result = reconcile_compatibility_and_graph(
        [comparison],
        graph,
        a_members_by_id={1: (1,), 2: (2,)},
        b_members_by_id={10: (10,), 20: (20,)},
        changes_only=True,
    )

    consistency = result["cross_view_consistency"]
    assert consistency["status"] == "consistent"
    assert consistency["matched_observation_count"] == 1
    assert consistency["change_event_count"] == 1
    event = result["change_events"][0]
    assert event["event_type"] == "observed_attachment_changed"
    assert event["graph_relationship_refs"] == ["rel-a", "rel-b"]
    assert event["attachment_change"] == {
        "kind": "local_interface_changed",
        "a_local_interface": "Gi1/0/10",
        "b_local_interface": "Gi1/0/12",
        "remote_interface": port,
        "identity_continuity": "confirmed",
        "movement_confidence": "confirmed",
        "relationship_scope": "observed",
        "directness": "unresolved",
        "physical_topology": "not_inferred",
    }
    row = comparison["learned_neighbors"][0]
    assert row["change_scope"] == "observed_attachment"
    assert row["cross_view_consistency"] == "matched"
    assert row["graph_relationship_refs"] == ["rel-a", "rel-b"]
    assert graph["relationship_groups"][0]["change_event_refs"] == [
        event["event_key"]
    ]


def test_reconciliation_links_protocol_transition_to_one_graph_event() -> None:
    """Protocol evidence changes remain non-physical and uniquely cross-linked."""

    a_group = _group(1, "Gi1/0/1", "remote", "Gi0", ["cdp", "lldp"])
    b_group = _group(10, "Gi1/0/1", "remote", "Gi0", ["lldp"])
    graph = {
        "available": True,
        "entity_correspondence": [],
        "relationship_groups": [
            _relationship(
                "rel-protocol",
                "protocol_evidence_changed",
                a_group=a_group,
                b_group=b_group,
            )
        ],
    }
    comparison = {
        "a": {"id": 1, "preferred_name": "switch"},
        "b": {"id": 10, "preferred_name": "switch"},
        "learned_neighbors": [
            {
                "status": "protocol_changed",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "none",
                "a": _neighbor(2, "Gi1/0/1", "Gi0", ["cdp", "lldp"]),
                "b": _neighbor(20, "Gi1/0/1", "Gi0", ["lldp"]),
            }
        ],
    }

    result = reconcile_compatibility_and_graph(
        [comparison],
        graph,
        a_members_by_id={1: (1,), 2: (2,)},
        b_members_by_id={10: (10,), 20: (20,)},
        changes_only=False,
    )

    assert result["cross_view_consistency"]["status"] == "consistent"
    assert result["change_events"][0]["event_type"] == "protocol_evidence_changed"
    assert result["change_events"][0]["physical_topology_effect"] == "none"
    assert graph["relationship_groups"][0]["compatibility_observation_refs"]


def test_reconciliation_matches_protocol_change_inside_member_set_change() -> None:
    """A stable member's protocol transition survives concurrent port membership churn.

    This is the compact regression for production runs 20260110-01 and
    20260110-00: one Cisco SEP endpoint lost CDP evidence while an unrelated
    LLDP member appeared on the same switch interface.  The graph's primary
    status remains ``member_set_changed``, but its exact per-member protocol
    dimension backs the compatibility protocol event.
    """

    phone_port = "00123456000F:P1"
    extra_port = "a0:b4:37:00:13:d4"
    a_group = _group(1, "Gi1/0/6", "phone", phone_port, ["lldp"])
    _add_member(a_group, "extra", extra_port, ["lldp"])
    b_group = _group(10, "Gi1/0/6", "phone", phone_port, ["cdp", "lldp"])
    relationship = _relationship(
        "rel-compound",
        "member_set_changed",
        a_group=a_group,
        b_group=b_group,
    )
    relationship.update(
        {
            "change_dimensions": ["member_presence", "protocol_evidence"],
            "member_presence_change": {
                "a_only": [
                    {
                        "remote_component_key": "extra",
                        "remote_interface": extra_port,
                        "protocols": ["lldp"],
                    }
                ],
                "b_only": [],
            },
            "member_protocol_changes": [
                {
                    "remote_component_key": "phone",
                    "remote_interface": phone_port.casefold(),
                    "a_protocols": ["lldp"],
                    "b_protocols": ["cdp", "lldp"],
                }
            ],
        }
    )
    graph = {
        "available": True,
        "entity_correspondence": [],
        "relationship_groups": [relationship],
    }
    comparison = {
        "a": {"id": 1, "preferred_name": "branch-access-9300-1.example.com"},
        "b": {"id": 10, "preferred_name": "branch-access-9300-1.example.com"},
        "learned_neighbors": [
            {
                "status": "protocol_changed",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "none",
                "a": _neighbor(2, "Gi1/0/6", phone_port, ["lldp"]),
                "b": _neighbor(
                    20, "Gi1/0/6", phone_port, ["cdp", "lldp"]
                ),
            },
            {
                "status": "a_only",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "not_inferred",
                "a": _neighbor(3, "Gi1/0/6", extra_port, ["lldp"]),
                "b": None,
            },
        ],
    }

    result = reconcile_compatibility_and_graph(
        [comparison],
        graph,
        a_members_by_id={1: (1,), 2: (2,), 3: (3,)},
        b_members_by_id={10: (10,), 20: (20,)},
        changes_only=True,
    )

    consistency = result["cross_view_consistency"]
    assert consistency["status"] == "consistent"
    assert consistency["matched_observation_count"] == 2
    assert consistency["unmatched_observation_count"] == 0
    assert consistency["graph_only_event_count"] == 0
    assert consistency["change_event_count"] == 2
    protocol_event = next(
        event
        for event in result["change_events"]
        if event["event_type"] == "protocol_evidence_changed"
    )
    assert protocol_event["graph_relationship_refs"] == ["rel-compound"]
    assert protocol_event["graph_change_dimensions"] == ["protocol_evidence"]
    assert protocol_event["physical_topology_effect"] == "none"
    assert relationship["change_event_refs"] == sorted(
        event["event_key"] for event in result["change_events"]
    )


def test_reconciliation_handles_multiple_changes_within_one_port_group() -> None:
    """Several independent member transitions reconcile without cross-member proof."""

    phone_one = "001122334455:P1"
    phone_two = "66778899AABB:P1"
    removed_port = "00:aa:00:aa:00:aa"
    added_port = "00:bb:00:bb:00:bb"
    a_group = _group(1, "Gi1/0/7", "phone-one", phone_one, ["lldp"])
    _add_member(a_group, "phone-two", phone_two, ["cdp", "lldp"])
    _add_member(a_group, "removed", removed_port, ["lldp"])
    b_group = _group(10, "Gi1/0/7", "phone-one", phone_one, ["cdp", "lldp"])
    _add_member(b_group, "phone-two", phone_two, ["lldp"])
    _add_member(b_group, "added", added_port, ["lldp"])
    relationship = _relationship(
        "rel-many",
        "member_set_changed",
        a_group=a_group,
        b_group=b_group,
    )
    relationship.update(
        {
            "change_dimensions": ["member_presence", "protocol_evidence"],
            "member_presence_change": {
                "a_only": [
                    {
                        "remote_component_key": "removed",
                        "remote_interface": removed_port,
                        "protocols": ["lldp"],
                    }
                ],
                "b_only": [
                    {
                        "remote_component_key": "added",
                        "remote_interface": added_port,
                        "protocols": ["lldp"],
                    }
                ],
            },
            "member_protocol_changes": [
                {
                    "remote_component_key": "phone-one",
                    "remote_interface": phone_one.casefold(),
                    "a_protocols": ["lldp"],
                    "b_protocols": ["cdp", "lldp"],
                },
                {
                    "remote_component_key": "phone-two",
                    "remote_interface": phone_two.casefold(),
                    "a_protocols": ["cdp", "lldp"],
                    "b_protocols": ["lldp"],
                },
            ],
        }
    )
    comparison = {
        "a": {"id": 1, "preferred_name": "switch"},
        "b": {"id": 10, "preferred_name": "switch"},
        "learned_neighbors": [
            {
                "status": "protocol_changed",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "none",
                "a": _neighbor(2, "Gi1/0/7", phone_one, ["lldp"]),
                "b": _neighbor(20, "Gi1/0/7", phone_one, ["cdp", "lldp"]),
            },
            {
                "status": "protocol_changed",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "none",
                "a": _neighbor(3, "Gi1/0/7", phone_two, ["cdp", "lldp"]),
                "b": _neighbor(30, "Gi1/0/7", phone_two, ["lldp"]),
            },
            {
                "status": "a_only",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "not_inferred",
                "a": _neighbor(4, "Gi1/0/7", removed_port, ["lldp"]),
                "b": None,
            },
            {
                "status": "b_only",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "not_inferred",
                "a": None,
                "b": _neighbor(40, "Gi1/0/7", added_port, ["lldp"]),
            },
        ],
    }

    result = reconcile_compatibility_and_graph(
        [comparison],
        {
            "available": True,
            "entity_correspondence": [],
            "relationship_groups": [relationship],
        },
        a_members_by_id={1: (1,), 2: (2,), 3: (3,), 4: (4,)},
        b_members_by_id={10: (10,), 20: (20,), 30: (30,), 40: (40,)},
        changes_only=True,
    )

    consistency = result["cross_view_consistency"]
    assert consistency["status"] == "consistent"
    assert consistency["matched_observation_count"] == 4
    assert consistency["graph_only_event_count"] == 0
    assert consistency["change_event_count"] == 4
    assert sorted(
        event["event_type"] for event in result["change_events"]
    ) == [
        "observed_in_a_only",
        "observed_in_b_only",
        "protocol_evidence_changed",
        "protocol_evidence_changed",
    ]
    protocol_events = [
        event
        for event in result["change_events"]
        if event["event_type"] == "protocol_evidence_changed"
    ]
    assert all(
        event["graph_change_dimensions"] == ["protocol_evidence"]
        for event in protocol_events
    )


def test_reconciliation_rejects_unproven_protocol_change_on_member_set_record() -> None:
    """A member-set change is not generic proof of an unrelated protocol change."""

    port = "00123456000F:P1"
    a_group = _group(1, "Gi1/0/6", "phone", port, ["lldp"])
    b_group = _group(10, "Gi1/0/6", "phone", port, ["cdp", "lldp"])
    relationship = _relationship(
        "rel-members-only",
        "member_set_changed",
        a_group=a_group,
        b_group=b_group,
    )
    relationship.update(
        {
            "change_dimensions": ["member_presence"],
            "member_presence_change": {"a_only": [], "b_only": []},
            "member_protocol_changes": [],
        }
    )
    comparison = {
        "a": {"id": 1, "preferred_name": "switch"},
        "b": {"id": 10, "preferred_name": "switch"},
        "learned_neighbors": [
            {
                "status": "protocol_changed",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "none",
                "a": _neighbor(2, "Gi1/0/6", port, ["lldp"]),
                "b": _neighbor(20, "Gi1/0/6", port, ["cdp", "lldp"]),
            }
        ],
    }

    result = reconcile_compatibility_and_graph(
        [comparison],
        {
            "available": True,
            "entity_correspondence": [],
            "relationship_groups": [relationship],
        },
        a_members_by_id={1: (1,), 2: (2,)},
        b_members_by_id={10: (10,), 20: (20,)},
        changes_only=True,
    )

    consistency = result["cross_view_consistency"]
    assert consistency["status"] == "attention_required"
    assert consistency["conflicting_observation_count"] == 1
    assert comparison["learned_neighbors"][0]["graph_relationship_refs"] == []


def test_reconciliation_keeps_unclaimed_compound_dimension_graph_only() -> None:
    """Claiming member presence does not hide an unrepresented protocol dimension."""

    phone_port = "00123456000F:P1"
    extra_port = "a0:b4:37:00:13:d4"
    a_group = _group(1, "Gi1/0/6", "phone", phone_port, ["lldp"])
    _add_member(a_group, "extra", extra_port, ["lldp"])
    b_group = _group(10, "Gi1/0/6", "phone", phone_port, ["cdp", "lldp"])
    relationship = _relationship(
        "rel-partially-represented",
        "member_set_changed",
        a_group=a_group,
        b_group=b_group,
    )
    relationship.update(
        {
            "change_dimensions": ["member_presence", "protocol_evidence"],
            "member_presence_change": {
                "a_only": [
                    {
                        "remote_component_key": "extra",
                        "remote_interface": extra_port,
                        "protocols": ["lldp"],
                    }
                ],
                "b_only": [],
            },
            "member_protocol_changes": [
                {
                    "remote_component_key": "phone",
                    "remote_interface": phone_port.casefold(),
                    "a_protocols": ["lldp"],
                    "b_protocols": ["cdp", "lldp"],
                }
            ],
        }
    )
    comparison = {
        "a": {"id": 1, "preferred_name": "switch"},
        "b": {"id": 10, "preferred_name": "switch"},
        "learned_neighbors": [
            {
                "status": "a_only",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "not_inferred",
                "a": _neighbor(3, "Gi1/0/6", extra_port, ["lldp"]),
                "b": None,
            }
        ],
    }

    result = reconcile_compatibility_and_graph(
        [comparison],
        {
            "available": True,
            "entity_correspondence": [],
            "relationship_groups": [relationship],
        },
        a_members_by_id={1: (1,), 3: (3,)},
        b_members_by_id={10: (10,)},
        changes_only=True,
    )

    consistency = result["cross_view_consistency"]
    assert consistency["status"] == "attention_required"
    assert consistency["matched_observation_count"] == 1
    assert consistency["graph_only_event_count"] == 1
    graph_only = next(
        event
        for event in result["change_events"]
        if event["cross_view_consistency"] == "graph_only"
    )
    assert graph_only["event_type"] == "graph_protocol_evidence_changed"
    assert graph_only["graph_change_dimensions"] == ["protocol_evidence"]


def test_reconciliation_matches_relationship_evidence_inside_member_set_change() -> None:
    """Raw evidence drift can map to a stable member in a compound relationship."""

    stable_port = "Gi0"
    extra_port = "00:11:22:33:44:55"
    a_group = _group(1, "Gi1/0/9", "stable", stable_port, ["lldp"])
    _add_member(a_group, "extra", extra_port, ["lldp"])
    b_group = _group(10, "Gi1/0/9", "stable", stable_port, ["lldp"])
    relationship = _relationship(
        "rel-evidence-compound",
        "member_set_changed",
        a_group=a_group,
        b_group=b_group,
    )
    relationship.update(
        {
            "change_dimensions": ["member_presence"],
            "member_presence_change": {
                "a_only": [
                    {
                        "remote_component_key": "extra",
                        "remote_interface": extra_port,
                        "protocols": ["lldp"],
                    }
                ],
                "b_only": [],
            },
            "member_protocol_changes": [],
        }
    )
    comparison = {
        "a": {"id": 1, "preferred_name": "switch"},
        "b": {"id": 10, "preferred_name": "switch"},
        "learned_neighbors": [
            {
                "status": "relationship_evidence_changed",
                "semantic_qualification": "evidence_only",
                "physical_topology_effect": "none",
                "a": _neighbor(2, "Gi1/0/9", stable_port, ["lldp"]),
                "b": _neighbor(20, "Gi1/0/9", stable_port, ["lldp"]),
            },
            {
                "status": "a_only",
                "semantic_qualification": "confirmed",
                "physical_topology_effect": "not_inferred",
                "a": _neighbor(3, "Gi1/0/9", extra_port, ["lldp"]),
                "b": None,
            },
        ],
    }

    result = reconcile_compatibility_and_graph(
        [comparison],
        {
            "available": True,
            "entity_correspondence": [],
            "relationship_groups": [relationship],
        },
        a_members_by_id={1: (1,), 2: (2,), 3: (3,)},
        b_members_by_id={10: (10,), 20: (20,)},
        changes_only=True,
    )

    assert result["cross_view_consistency"]["status"] == "consistent"
    evidence_row = comparison["learned_neighbors"][0]
    assert evidence_row["cross_view_consistency"] == "matched"
    assert evidence_row["graph_relationship_refs"] == ["rel-evidence-compound"]


def test_reconciliation_reports_unavailable_graph_without_false_conflict() -> None:
    """Compact fixtures without graph data remain valid compatibility comparisons."""

    comparison = {
        "a": {"id": 1, "preferred_name": "switch"},
        "b": {"id": 10, "preferred_name": "switch"},
        "learned_neighbors": [
            {
                "status": "a_only",
                "semantic_qualification": "confirmed",
                "a": _neighbor(2, "Gi1/0/1", "Gi0", ["lldp"]),
                "b": None,
            }
        ],
    }
    result = reconcile_compatibility_and_graph(
        [comparison],
        {"available": False, "relationship_groups": []},
        a_members_by_id={},
        b_members_by_id={},
        changes_only=True,
    )

    assert result["cross_view_consistency"]["status"] == "unavailable"
    assert result["cross_view_consistency"]["unmatched_observation_count"] == 0
    assert comparison["learned_neighbors"][0]["cross_view_consistency"] == "unavailable"
    assert result["change_events"] == []


def test_reconciliation_does_not_overclaim_unrepresented_one_sided_rows() -> None:
    """One-sided-host rows make the cross-view result explicitly incomplete."""

    result = reconcile_compatibility_and_graph(
        [],
        {"available": True, "relationship_groups": []},
        a_members_by_id={},
        b_members_by_id={},
        changes_only=True,
        unrepresented_one_sided_observation_count=2,
    )

    consistency = result["cross_view_consistency"]
    assert consistency["status"] == "attention_required"
    assert consistency["compatibility_observation_count"] == 2
    assert consistency["reconciled_compatibility_observation_count"] == 0
    assert consistency["unrepresented_one_sided_observation_count"] == 2
    assert consistency["all_reported_changes_graph_backed"] is False
