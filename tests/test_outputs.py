import logging
from pathlib import Path

from lldp_runner.config import CustomCsvColumnConfig, CustomCsvConfig
from lldp_runner.models import Candidate
from lldp_runner.outputs import (
    OUTPUT_NAMES,
    STACK_MEMBERS_CSV_FIELDS,
    UNKNOWN_DEVICES_CSV_FIELDS,
    finalize_to_persistent,
    write_fixed_csv_outputs,
    write_outputs,
)
from lldp_runner.state import StateStore


def test_outputs_and_latest_symlink(tmp_path: Path, config):
    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-08-17 00:00:00 EDT")
    state.upsert_candidate(
        Candidate(names=["unknown1"], addresses=["198.18.5.5"], category="unknown_device")
    )
    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="run1", status="COMPLETED", draft=False)
    output_root = tmp_path / "outputs"
    final = output_root / "run1"
    latest = output_root / "latest"
    output_root.mkdir()
    finalize_to_persistent(scratch, final, latest)
    expected = {"discovery.json", "hosts.csv", "unknown-devices.csv"}
    for name in expected:
        assert (final / name).exists()
    for name in set(OUTPUT_NAMES) - expected:
        assert not (final / name).exists()
    assert latest.is_symlink()
    assert latest.resolve() == final.resolve()
    state.close()


def test_unknown_devices_csv_schema_omits_empty_system_identity_columns() -> None:
    """The unknown review view excludes manufacturer/model placeholders."""

    assert UNKNOWN_DEVICES_CSV_FIELDS == [
        "preferred_name",
        "ipv4",
        "ipv6",
        "last_seen",
        "protocols",
        "observed_names",
        "remote_platforms",
        "remote_descriptions",
        "capabilities",
        "observed_chassis_ids",
        "observed_chassis_id_subtypes",
        "observed_chassis_id_subtype_ids",
        "observed_by_neighbors",
        "classification_reason",
    ]


def test_preferred_name_output_normalization_and_typed_chassis_fallbacks(
    tmp_path: Path,
    config,
) -> None:
    """All CSV projections share the canonical best-available host display name."""

    import csv
    import json

    from lldp_runner.models import NeighborObservation

    config.output.chassis_id_name_fallback = "disabled"
    config.output.custom_csv["preferred-names"] = CustomCsvConfig(
        name="preferred-names",
        filename="preferred-names.csv",
        source="hosts",
        columns=[
            CustomCsvColumnConfig(field="hosts.preferred_name"),
            CustomCsvColumnConfig(
                field="json.host.preferred_name",
                header="json_preferred_name",
            ),
        ],
    )
    config.output.custom_csv["unknown-preferred-names"] = CustomCsvConfig(
        name="unknown-preferred-names",
        filename="unknown-preferred-names.csv",
        source="unknown-devices",
        columns=[
            CustomCsvColumnConfig(field="unknown-devices.preferred_name"),
            CustomCsvColumnConfig(
                field="json.host.preferred_name",
                header="json_preferred_name",
            ),
        ],
    )
    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-09-05 00:00:00 EDT")
    source_id = state.upsert_candidate(
        Candidate(
            names=["access-sw1.net.example.com"],
            addresses=["198.18.40.1"],
            category="managed_device",
        )
    )

    local_id = state.upsert_candidate(
        Candidate(
            category="unknown_device",
            source_host_id=source_id,
            protocol="lldp",
            chassis_id="opaque-local-1701",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
        ),
        preferred_name="unknown",
        synthetic_alias="output-local-1701",
    )
    state.add_neighbor(
        source_id,
        local_id,
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/1",
            local_interface_raw="Gi1/0/1",
            remote_name=None,
            remote_interface=None,
            remote_interface_raw=None,
            remote_description=None,
            chassis_id="opaque-local-1701",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
        ),
    )

    blank_mac_id = state.upsert_candidate(
        Candidate(
            category="unknown_device",
            source_host_id=source_id,
            protocol="lldp",
            chassis_id="02-34-56-78-9A-BC",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
        preferred_name="unknown",
        synthetic_alias="output-mac-023456789abc",
    )
    state.add_neighbor(
        source_id,
        blank_mac_id,
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/4",
            local_interface_raw="Gi1/0/4",
            remote_name=None,
            remote_interface=None,
            remote_interface_raw=None,
            remote_description=None,
            chassis_id="02-34-56-78-9A-BC",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
    )

    mac_id = state.upsert_candidate(
        Candidate(
            category="unknown_device",
            source_host_id=source_id,
            protocol="lldp",
            chassis_id="00-12-34-56-B0-01",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
        preferred_name="null",
    )
    state.add_neighbor(
        source_id,
        mac_id,
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/2",
            local_interface_raw="Gi1/0/2",
            remote_name="null",
            remote_interface=None,
            remote_interface_raw=None,
            remote_description="not advertised",
            chassis_id="00-12-34-56-B0-01",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
    )

    not_advertised_id = state.upsert_candidate(
        Candidate(
            category="unknown_device",
            source_host_id=source_id,
            protocol="lldp",
            chassis_id="0011.2233.4455",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
        preferred_name="not advertised",
        synthetic_alias="output-mac-001122334455",
    )
    state.add_neighbor(
        source_id,
        not_advertised_id,
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/3",
            local_interface_raw="Gi1/0/3",
            remote_name="not advertised",
            remote_interface=None,
            remote_interface_raw=None,
            remote_description="null",
            chassis_id="0011.2233.4455",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
    )

    decorated_id = state.upsert_candidate(
        Candidate(
            names=["hq-vdc1-7nx1.net.example.com(SERIAL000001)"],
            category="unknown_device",
        ),
        preferred_name="hq-vdc1-7nx1.net.example.com(SERIAL000001)",
    )

    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="run1", status="COMPLETED", draft=False)

    payload = json.loads((scratch / "discovery.json").read_text(encoding="utf-8"))
    by_id = {int(host["id"]): host for host in payload["hosts"]}
    expected = {
        local_id: "opaque-local-1701",
        blank_mac_id: "02:34:56:78:9a:bc",
        mac_id: "00:12:34:56:b0:01",
        not_advertised_id: "00:11:22:33:44:55",
        decorated_id: "hq-vdc1-7nx1.net.example.com",
    }
    assert {host_id: by_id[host_id]["preferred_name"] for host_id in expected} == expected

    # Raw evidence remains diagnostic and identity state is not rewritten merely
    # to improve the exported display field.
    assert by_id[mac_id]["observed_by_neighbors"][0]["observed_name"] == "null"
    assert (
        by_id[mac_id]["observed_by_neighbors"][0]["details"]["remote_description"]
        == "not advertised"
    )
    assert state.host_row(blank_mac_id)["preferred_name"] == "unknown"
    assert state.host_row(mac_id)["preferred_name"] == "null"

    for filename in ("hosts.csv", "unknown-devices.csv"):
        with (scratch / filename).open(encoding="utf-8", newline="") as handle:
            values = {row["preferred_name"] for row in csv.DictReader(handle)}
        assert set(expected.values()).issubset(values)

    with (scratch / "preferred-names.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        custom_rows = list(csv.DictReader(handle))
    custom_pairs = {
        (row["preferred_name"], row["json_preferred_name"])
        for row in custom_rows
    }
    assert {(value, value) for value in expected.values()}.issubset(custom_pairs)

    with (scratch / "unknown-preferred-names.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        unknown_custom_rows = list(csv.DictReader(handle))
    unknown_custom_pairs = {
        (row["preferred_name"], row["json_preferred_name"])
        for row in unknown_custom_rows
    }
    assert {(value, value) for value in expected.values()} == unknown_custom_pairs
    state.close()


def test_preferred_name_output_fallback_refuses_mixed_or_ambiguous_chassis() -> None:
    """Placeholder output never guesses across conflicting chassis evidence."""

    from lldp_runner.outputs import _output_preferred_name

    mixed = [
        {
            "observed_name": None,
            "details": {
                "chassis_id": "local-one",
                "chassis_id_subtype": "local",
                "chassis_id_subtype_id": 7,
            },
        },
        {
            "observed_name": None,
            "details": {
                "chassis_id": "00:11:22:33:44:55",
                "chassis_id_subtype": "mac_address",
                "chassis_id_subtype_id": 4,
            },
        },
    ]
    assert _output_preferred_name("unknown", mixed) == "unknown"

    repeated_mac = [
        {
            "observed_name": None,
            "details": {
                "chassis_id": value,
                "chassis_id_subtype": "mac_address",
                "chassis_id_subtype_id": 4,
            },
        }
        for value in ("02-34-56-78-9A-BC", "0234.5678.9abc")
    ]
    assert _output_preferred_name("unknown", repeated_mac) == (
        "02:34:56:78:9a:bc"
    )

    described_mac = [
        {
            "observed_name": None,
            "details": {
                "remote_description": "Printer adapter",
                "chassis_id": "02:34:56:78:9a:bc",
                "chassis_id_subtype": "mac_address",
                "chassis_id_subtype_id": 4,
            },
        }
    ]
    assert _output_preferred_name("unknown", described_mac) == "unknown"

    named_mac = [
        {
            "observed_name": "printer-01",
            "details": {
                "chassis_id": "02:34:56:78:9a:bc",
                "chassis_id_subtype": "mac_address",
                "chassis_id_subtype_id": 4,
            },
        }
    ]
    assert _output_preferred_name("unknown", named_mac) == "unknown"

    ambiguous_mac = [
        {
            "observed_name": "null",
            "details": {
                "remote_description": "not advertised",
                "chassis_id": value,
                "chassis_id_subtype": "mac_address",
                "chassis_id_subtype_id": 4,
            },
        }
        for value in ("00:11:22:33:44:55", "00:11:22:33:44:66")
    ]
    assert _output_preferred_name("null", ambiguous_mac) == "null"

    malformed_mac = [
        *ambiguous_mac[:1],
        {
            "observed_name": "not advertised",
            "details": {
                "remote_description": "null",
                "chassis_id": "malformed-mac",
                "chassis_id_subtype": "mac_address",
                "chassis_id_subtype_id": 4,
            },
        },
    ]
    assert _output_preferred_name("not advertised", malformed_mac) == (
        "not advertised"
    )
    assert _output_preferred_name("switch (lab)", []) == "switch (lab)"


def test_chassis_id_name_fallback_and_tags_in_outputs(tmp_path: Path, config):
    import csv
    import json

    from lldp_runner.models import NeighborObservation

    config.output.chassis_id_name_fallback = "name_like"
    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-08-19 00:00:00 EDT")

    source_id = state.upsert_candidate(
        Candidate(
            names=["access-sw1.net.example.com"],
            addresses=["198.18.10.10"],
            category="managed_device",
        )
    )
    remote = Candidate(
        category="unknown_device",
        source_host_id=source_id,
        protocol="lldp",
        chassis_id="LABPC-P123456",
        tags=["endpoint:windows", "tenant:a"],
    )
    remote_id = state.upsert_candidate(remote)
    state.add_neighbor(
        source_id,
        remote_id,
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/5",
            local_interface_raw="Gi1/0/5",
            remote_name=None,
            remote_interface="8c:04:ba:a3:1a:0d",
            remote_interface_raw="8c:04:ba:a3:1a:0d",
            chassis_id="LABPC-P123456",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
            details={
                "port_id": "8c:04:ba:a3:1a:0d",
                "port_id_subtype": "mac_address",
                "port_id_subtype_id": 3,
                "port_description": "Ethernet adapter",
            },
        ),
    )

    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="run1", status="COMPLETED", draft=False)

    payload = json.loads((scratch / "discovery.json").read_text(encoding="utf-8"))
    hosts = {int(item["id"]): item for item in payload["hosts"]}
    assert hosts[remote_id]["preferred_name"] == "LABPC-P123456"
    assert hosts[remote_id]["tags"] == ["endpoint:windows", "tenant:a"]
    source_neighbor = hosts[source_id]["learned_neighbors"][0]
    assert source_neighbor["name"] == "LABPC-P123456"
    assert source_neighbor["observed_name"] is None
    assert source_neighbor["details"]["chassis_id"] == "LABPC-P123456"
    assert source_neighbor["details"]["chassis_id_subtype"] == "local"
    assert source_neighbor["details"]["chassis_id_subtype_id"] == 7
    assert source_neighbor["details"]["port_id"] == "8c:04:ba:a3:1a:0d"
    assert source_neighbor["details"]["port_id_subtype"] == "mac_address"
    assert source_neighbor["details"]["port_id_subtype_id"] == 3
    assert source_neighbor["details"]["port_description"] == "Ethernet adapter"
    assert hosts[source_id]["observed_by_neighbors"] == []

    # The unpolled child still carries the reciprocal relationship learned from
    # the managed parent.  This is the condition that the old single `neighbors`
    # CSV field could lose when the child happened to be classified as managed.
    observed_by = hosts[remote_id]["observed_by_neighbors"][0]
    assert observed_by["host_ref"] == source_id
    assert observed_by["name"] == "access-sw1.net.example.com"
    assert observed_by["classification"] == "managed_device"
    assert observed_by["local_interface"] == "8c:04:ba:a3:1a:0d"
    assert observed_by["remote_interface"] == "Gi1/0/5"
    assert observed_by["protocols"] == ["lldp"]
    assert observed_by["protocol_tag"] == "[lldp]"
    assert hosts[remote_id]["learned_neighbors"] == []

    with (scratch / "hosts.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    row = next(item for item in rows if item["preferred_name"] == "LABPC-P123456")
    assert row["tags"] == "endpoint:windows;tenant:a"
    assert row["learned_neighbors"] == ""
    assert row["observed_by_neighbors"] == (
        "access-sw1.net.example.com:Gi1/0/5=8c:04:ba:a3:1a:0d[lldp]"
    )

    # The dedicated unknown review output also carries aggregated subtype evidence.
    with (scratch / "unknown-devices.csv").open(encoding="utf-8", newline="") as fh:
        unknown_rows = list(csv.DictReader(fh))
    unknown = next(item for item in unknown_rows if item["preferred_name"] == "LABPC-P123456")
    assert list(unknown.keys()) == UNKNOWN_DEVICES_CSV_FIELDS
    assert "manufacturer" not in unknown
    assert "model" not in unknown
    assert (
        list(unknown.keys()).index("observed_chassis_ids")
        == list(unknown.keys()).index("capabilities") + 1
    )
    assert unknown["observed_chassis_ids"] == "LABPC-P123456"
    assert unknown["observed_chassis_id_subtypes"] == "local"
    assert unknown["observed_chassis_id_subtype_ids"] == "7"
    assert "discovered_connections" not in unknown
    assert unknown["observed_by_neighbors"] == (
        "access-sw1.net.example.com:Gi1/0/5=8c:04:ba:a3:1a:0d[lldp]"
    )
    state.close()


def test_repeated_local_chassis_endpoints_remain_distinct_in_public_outputs(
    tmp_path: Path, config
):
    """Typed Port-ID MACs keep anonymous subtype-7 endpoints one-to-one."""

    import csv
    import json

    from lldp_runner.models import DeviceResult, NeighborObservation, SystemDetails
    from lldp_runner.timeutil import iso_now

    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-09-02 00:00:00 EDT")
    source_id = state.upsert_candidate(
        Candidate(
            names=["access-sw1.example.com"],
            addresses=["198.18.10.10"],
            category="managed_device",
        ),
        is_seed=True,
    )

    observations = []
    remote_ids = []
    for local_interface, mac in (
        ("Gi1/0/5", "10:98:19:4d:2f:97"),
        ("Gi1/0/6", "08:92:04:f6:d6:f4"),
    ):
        details = {
            "port_id": mac,
            "port_id_subtype": "mac_address",
            "port_id_subtype_id": 3,
        }
        observation = NeighborObservation(
            protocol="lldp",
            local_interface=local_interface,
            local_interface_raw=local_interface,
            remote_name=None,
            remote_interface=mac,
            remote_interface_raw=mac,
            chassis_id="hex:a1:00:00:00:00:00",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
            details=details,
        )
        remote_id = state.upsert_candidate(
            Candidate(
                category="unknown_device",
                source_host_id=source_id,
                protocol="lldp",
                local_interface=local_interface,
                remote_interface=mac,
                chassis_id=observation.chassis_id,
                chassis_id_subtype=observation.chassis_id_subtype,
                chassis_id_subtype_id=observation.chassis_id_subtype_id,
                details=details,
            )
        )
        state.add_neighbor(source_id, remote_id, observation)
        observations.append(observation)
        remote_ids.append(remote_id)

    state.apply_device_result(
        DeviceResult(
            host_id=source_id,
            status="success",
            query_target="198.18.10.10",
            system=SystemDetails(
                sys_name="access-sw1.example.com",
                serial_number="ACCESS-SW1",
            ),
            raw_neighbors=observations,
            neighbors=observations,
            last_seen=iso_now(),
        )
    )
    scratch = tmp_path / "scratch"
    write_outputs(
        state,
        config,
        scratch,
        run_id="local-chassis",
        status="COMPLETED",
        draft=False,
    )

    assert len(set(remote_ids)) == 2
    payload = json.loads((scratch / "discovery.json").read_text(encoding="utf-8"))
    unknown_hosts = [
        item for item in payload["hosts"] if item["classification"] == "unknown_device"
    ]
    assert len(unknown_hosts) == 2
    graph = payload["topology_graph"]
    assert graph["summary"]["compatibility_projection_diagnostics"] == 0
    assert graph["compatibility_projection_diagnostics"] == []
    assert {
        item["entity_key"]
        for item in graph["entities"]
        if item["entity_type"] == "observed_system"
    } == {
        "endpoint:mac:08:92:04:f6:d6:f4",
        "endpoint:mac:10:98:19:4d:2f:97",
    }

    with (scratch / "unknown-devices.csv").open(encoding="utf-8", newline="") as fh:
        unknown_rows = list(csv.DictReader(fh))
    assert len(unknown_rows) == 2
    state.close()


def test_name_like_chassis_fallback_rejects_mac_but_any_accepts_it(tmp_path: Path, config):
    import csv

    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(Candidate(chassis_id="8c:04:ba:a3:1a:0d"))
    scratch = tmp_path / "scratch"

    config.output.chassis_id_name_fallback = "name_like"
    write_outputs(state, config, scratch, run_id="run1", status="RUNNING", draft=False)
    with (scratch / "hosts.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert next(item for item in rows if item["classification"] == "unknown_device")["preferred_name"] == "unknown"

    config.output.chassis_id_name_fallback = "any"
    write_outputs(state, config, scratch, run_id="run1", status="RUNNING", draft=False)
    with (scratch / "hosts.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert next(item for item in rows if item["classification"] == "unknown_device")["preferred_name"] == "8c:04:ba:a3:1a:0d"
    assert state.host_row(host_id)["preferred_name"] == "unknown"
    state.close()


def test_all_csv_outputs_strip_embedded_control_characters(tmp_path: Path, config):
    """CSV artifacts must remain normal UTF-8 text even with dirty legacy state."""

    import json
    import unicodedata

    from lldp_runner.models import NeighborObservation

    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-08-20 06:00:00 EDT")

    # Inject controls directly into coordinator state to simulate a checkpoint
    # created by an older release before SNMP collector sanitation existed.  The
    # output layer must still make every CSV safe for grep/awk and line parsers.
    source_id = state.upsert_candidate(
        Candidate(
            names=["core\x00\x07-switch.net.example.com"],
            addresses=["198.18.10.10"],
            category="managed_device",
            tags=["site:\x1bcontrol"],
        )
    )
    remote_id = state.upsert_candidate(
        Candidate(
            chassis_id="camera\x00\x07-id",
            category="unknown_device",
            source_host_id=source_id,
            protocol="lldp",
        )
    )
    state.add_neighbor(
        source_id,
        remote_id,
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/5\x00",
            local_interface_raw="GigabitEthernet1/0/5\x07",
            remote_name="camera\x00\x07",
            remote_interface="eth0\x1b",
            remote_interface_raw="eth0\tport",
            remote_description="FLEXIDOME\x00 IP 7000\nVR",
            remote_platform="Bosch\u0085Camera",
            chassis_id="camera\x00\x07-id",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
        ),
    )
    state.add_error(
        source_id,
        "lldp\x00walk",
        "timeout\x07",
        "agent\x00 timed out\tthen\nrecovered\u0085",
    )

    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="controls", status="COMPLETED", draft=False)

    for name in ("hosts.csv", "seeds.csv", "unknown-devices.csv", "errors.csv"):
        raw = (scratch / name).read_bytes()
        assert b"\x00" not in raw, name
        text = raw.decode("utf-8")
        # CR/LF are legitimate CSV record separators.  No other Unicode control
        # character may survive inside an emitted field.
        bad = [
            char
            for char in text
            if unicodedata.category(char) == "Cc" and char not in {"\r", "\n"}
        ]
        assert not bad, (name, bad)

    # JSON has its own escaping rules, but the final output safety pass should
    # remove the controls rather than leaving \u0000/\u0007 artifacts behind.
    json_text = (scratch / "discovery.json").read_text(encoding="utf-8")
    assert "\\u0000" not in json_text
    assert "\\u0007" not in json_text
    json.loads(json_text)
    state.close()


def test_bidirectional_neighbor_fields_preserve_failed_managed_child_and_protocol_tags(
    tmp_path: Path, config
):
    """CSV/JSON must keep inbound evidence even when a managed child has no own walk.

    A child can be positively classified as a managed switch and still fail its SNMP
    poll.  The parent-to-child LLDP/CDP observation is real topology evidence and must
    remain visible under `observed_by_neighbors` even though the child's
    `learned_neighbors` list is empty.
    """

    import csv
    import json

    from lldp_runner.models import NeighborObservation

    state = StateStore(tmp_path / "state.sqlite")
    parent_id = state.upsert_candidate(
        Candidate(
            names=["parent-sw.net.example.com"],
            addresses=["198.18.10.1"],
            category="managed_device",
        )
    )
    child_id = state.upsert_candidate(
        Candidate(
            names=["child-sw.net.example.com"],
            addresses=["198.18.10.2"],
            category="managed_device",
            source_host_id=parent_id,
            protocol="lldp",
        )
    )
    state.add_neighbor(
        parent_id,
        child_id,
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/48",
            local_interface_raw="GigabitEthernet1/0/48",
            remote_name="child-sw.net.example.com",
            remote_interface="Gi1/0/24",
            remote_interface_raw="GigabitEthernet1/0/24",
            details={"protocols": ["lldp", "cdp"]},
        ),
    )
    # Simulate a managed child whose own SNMP work did not produce topology.  The
    # exact failed state is not important to edge storage; it proves output no longer
    # chooses direction solely from classification.
    state.conn.execute("UPDATE hosts SET state='FAILED' WHERE id=?", (child_id,))
    state.conn.commit()

    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="run1", status="COMPLETED", draft=False)

    payload = json.loads((scratch / "discovery.json").read_text(encoding="utf-8"))
    hosts = {int(item["id"]): item for item in payload["hosts"]}

    assert "neighbors" not in hosts[parent_id]
    assert hosts[parent_id]["learned_neighbors"][0]["protocols"] == ["cdp", "lldp"]
    assert hosts[parent_id]["learned_neighbors"][0]["protocol_tag"] == "[cdp,lldp]"
    assert hosts[parent_id]["observed_by_neighbors"] == []

    assert hosts[child_id]["learned_neighbors"] == []
    reverse = hosts[child_id]["observed_by_neighbors"][0]
    assert reverse["name"] == "parent-sw.net.example.com"
    assert reverse["local_interface"] == "Gi1/0/24"
    assert reverse["remote_interface"] == "Gi1/0/48"
    assert reverse["protocols"] == ["cdp", "lldp"]
    assert reverse["protocol_tag"] == "[cdp,lldp]"

    with (scratch / "hosts.csv").open(encoding="utf-8", newline="") as fh:
        rows = {row["preferred_name"]: row for row in csv.DictReader(fh)}

    parent = rows["parent-sw.net.example.com"]
    assert parent["learned_neighbors"] == (
        "Gi1/0/48=child-sw.net.example.com:Gi1/0/24[cdp,lldp]"
    )
    assert parent["observed_by_neighbors"] == ""

    child = rows["child-sw.net.example.com"]
    assert child["learned_neighbors"] == ""
    assert child["observed_by_neighbors"] == (
        "parent-sw.net.example.com:Gi1/0/48=Gi1/0/24[cdp,lldp]"
    )
    state.close()


def test_hosts_csv_origin_distinguishes_seed_from_learned(tmp_path: Path, config):
    """hosts.csv exposes stable textual provenance instead of a Boolean flag.

    Origin describes how an identity entered the topology, not whether it was later
    queried. This lets operators grep for ``seed``/``learned`` while preserving the
    internal ``is_seed`` state as the authoritative source.
    """

    import csv

    state = StateStore(tmp_path / "state.sqlite")
    state.upsert_candidate(
        Candidate(names=["seed-sw.example.net"], category="managed_device"),
        is_seed=True,
    )
    learned_id = state.upsert_candidate(
        Candidate(names=["learned-sw.example.net"], category="managed_device")
    )
    # Successful recursive polling changes operational state, not provenance.
    state.conn.execute("UPDATE hosts SET state='COMPLETE' WHERE id=?", (learned_id,))
    state.conn.commit()

    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="origin", status="COMPLETED", draft=False)

    with (scratch / "hosts.csv").open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames is not None
        assert reader.fieldnames.index("origin") == reader.fieldnames.index("snmp_sysname") + 1
        assert reader.fieldnames.index("classification") == reader.fieldnames.index("origin") + 1
        rows = {row["preferred_name"]: row for row in reader}

    assert rows["seed-sw.example.net"]["origin"] == "seed"
    assert rows["learned-sw.example.net"]["origin"] == "learned"
    assert {row["origin"] for row in rows.values()} <= {"seed", "learned"}
    state.close()



def test_discovery_json_is_complete_structured_output_contract(tmp_path: Path, config):
    """JSON preserves data needed to recreate the fixed standard CSV views later."""

    import csv
    import json

    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(
            names=["seed-sw.example.net"],
            addresses=["198.18.40.10"],
            category="managed_device",
        ),
        is_seed=True,
    )
    state.conn.execute(
        """
        UPDATE hosts
        SET state='COMPLETE', query_target='198.18.40.10',
            credential_profile='site', credential_result='primary',
            system_json=?
        WHERE id=?
        """,
        (
            json.dumps(
                {
                    "manufacturer": "HPE",
                    "model": "CX6300",
                    "serial_number": "ABC123",
                    "hardware_revision": "R02",
                    "firmware_revision": "FL.10.15",
                    "sys_uptime_ticks": 12345,
                }
            ),
            host_id,
        ),
    )
    state.conn.commit()
    state.add_error(
        host_id,
        "entity",
        "optional_walk_failed",
        "ENTITY-MIB walk unavailable",
        recoverable=True,
        final_device_status="COMPLETE",
    )

    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="json-contract", status="COMPLETED", draft=False)

    payload = json.loads((scratch / "discovery.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == 8
    assert set(payload) == {"schema_version", "discovery", "hosts", "errors", "topology_graph"}
    assert payload["topology_graph"]["authority"]["observation_projection"] == "authoritative"
    assert payload["topology_graph"]["schema_version"] == 2

    host = next(item for item in payload["hosts"] if item["id"] == host_id)
    assert host["is_seed"] is True
    assert host["state"] == "complete"
    assert host["queried_as"] == "198.18.40.10"
    assert host["addresses"]["ipv4"] == ["198.18.40.10"]
    assert host["snmp"] == {
        "credential_source": None,
        "credential_profile": "site",
        "credential_label": None,
        "credential_result": "primary",
    }
    # These values were intentionally removed only from hosts.csv.  JSON retains
    # full collected system detail for later site/customer-specific exporters.
    assert host["system"]["hardware_revision"] == "R02"
    assert host["system"]["firmware_revision"] == "FL.10.15"

    error = payload["errors"][0]
    assert error["host_ref"] == host_id
    assert error["device"] == "seed-sw.example.net"
    assert error["query_target"] == "198.18.40.10"
    assert error["operation"] == "entity"
    assert error["category"] == "optional_walk_failed"
    assert error["recoverable"] is True
    assert error["final_state"] == "complete"
    assert "final_device_status" not in error

    with (scratch / "errors.csv").open(encoding="utf-8", newline="") as fh:
        error_rows = list(csv.DictReader(fh))
    assert error_rows[0]["final_state"] == "complete"
    assert "final_device_status" not in error_rows[0]

    with (scratch / "hosts.csv").open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames is not None
        assert "preferred_name" in reader.fieldnames
        assert "primary_name" not in reader.fieldnames
        assert "hardware_revision" not in reader.fieldnames
        assert "firmware_revision" not in reader.fieldnames
        assert "serial_number" in reader.fieldnames
        assert "snmp_status" not in reader.fieldnames

    state.close()


def test_stack_members_csv_is_one_physical_switch_per_row(tmp_path: Path, config):
    """Stack inventory repeats logical host context with member-specific identity."""

    import csv
    import json

    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(
            names=["access-stack.example.net"],
            addresses=["198.18.50.10"],
            category="managed_device",
        ),
        is_seed=True,
    )
    system = {
        "sys_name": "access-stack",
        "manufacturer": "Cisco",
        "model": "C9300-48P",
        "version": "17.15.3",
        "serial_number": "LOGICAL-PRIMARY",
        "sys_uptime_ticks": 900000,
        "stack_members": [
            {
                "entity_index": 1001,
                "member_number": 1,
                "name": "Switch 1",
                "description": "Cisco Catalyst 9300 member 1",
                "manufacturer": "Cisco Systems, Inc.",
                "model": "C9300-48P",
                "serial_number": "FCW00000001",
                "hardware_revision": "V02",
                "firmware_revision": "17.15.3r",
                "software_revision": "17.15.3",
                "uptime_seconds": None,
            },
            {
                "entity_index": 2001,
                "member_number": 2,
                "name": "Switch 2",
                "description": "Cisco Catalyst 9300 member 2",
                "manufacturer": "Cisco Systems, Inc.",
                "model": "C9300-48P",
                "serial_number": "FCW00000002",
                "hardware_revision": "V03",
                "firmware_revision": "17.15.3r",
                "software_revision": "17.15.3",
                "uptime_seconds": None,
            },
        ],
    }
    state.conn.execute(
        """
        UPDATE hosts SET state='COMPLETE', query_target='198.18.50.10',
            snmp_sysname='access-stack', credential_profile='site',
            credential_result='primary', system_json=? WHERE id=?
        """,
        (json.dumps(system), host_id),
    )
    state.conn.commit()

    scratch = tmp_path / "scratch"
    written = write_outputs(
        state, config, scratch, run_id="stack", status="COMPLETED", draft=False
    )

    assert "stack-members.csv" in {path.name for path in written}
    with (scratch / "stack-members.csv").open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == STACK_MEMBERS_CSV_FIELDS
        rows = list(reader)

    assert len(rows) == 2
    assert "member_number" in STACK_MEMBERS_CSV_FIELDS
    assert "name" in STACK_MEMBERS_CSV_FIELDS
    assert "description" in STACK_MEMBERS_CSV_FIELDS
    assert "stack_member" not in STACK_MEMBERS_CSV_FIELDS
    assert "member_name" not in STACK_MEMBERS_CSV_FIELDS
    assert "member_description" not in STACK_MEMBERS_CSV_FIELDS
    assert "snmp_status" not in STACK_MEMBERS_CSV_FIELDS
    assert {row["preferred_name"] for row in rows} == {"access-stack.example.net"}
    assert [row["member_number"] for row in rows] == ["1", "2"]
    assert [row["entity_index"] for row in rows] == ["1001", "2001"]
    assert [row["serial_number"] for row in rows] == [
        "FCW00000001",
        "FCW00000002",
    ]
    assert all(row["model"] == "C9300-48P" for row in rows)
    assert all(row["version"] == "17.15.3" for row in rows)
    # sysUpTime belongs to the logical stack. Do not mislabel 9000 seconds as the
    # uptime of each member when ENTITY-MIB supplied no member-specific value.
    assert all(row["uptime_seconds"] == "" for row in rows)

    payload = json.loads((scratch / "discovery.json").read_text(encoding="utf-8"))
    host = next(item for item in payload["hosts"] if item["id"] == host_id)
    assert len(host["system"]["stack_members"]) == 2
    state.close()


def test_fixed_csv_outputs_are_reproducible_from_discovery_json_alone(
    tmp_path: Path, config
):
    """Every fixed CSV must be reproducible after SQLite state is unavailable.

    This is the architectural gate for future custom CSV support: once the
    canonical discovery document exists, no fixed projection may depend on
    StateStore rows, edges, aliases, or errors.
    """

    import json

    from lldp_runner.models import NeighborObservation

    state = StateStore(tmp_path / "state.sqlite")
    source_id = state.upsert_candidate(
        Candidate(
            names=["stack.example.net"],
            addresses=["198.18.60.10"],
            category="managed_device",
        ),
        is_seed=True,
    )
    system = {
        "manufacturer": "Cisco",
        "model": "C9300-48P",
        "version": "17.15.3",
        "sys_uptime_ticks": 123400,
        "stack_members": [
            {
                "entity_index": 1001,
                "member_number": 1,
                "name": "Switch 1",
                "description": "Catalyst member",
                "manufacturer": "Cisco",
                "model": "C9300-48P",
                "software_revision": "17.15.3",
                "serial_number": "SERIAL-1",
                "hardware_revision": "V02",
                "firmware_revision": "17.15.3r",
                "uptime_seconds": None,
            }
        ],
    }
    state.conn.execute(
        """
        UPDATE hosts SET state='COMPLETE', query_target='198.18.60.10',
            credential_profile='site', credential_result='primary', system_json=?
        WHERE id=?
        """,
        (json.dumps(system), source_id),
    )
    state.conn.commit()

    unknown_id = state.upsert_candidate(
        Candidate(
            chassis_id="unknown-chassis",
            category="unknown_device",
            source_host_id=source_id,
            protocol="lldp",
        )
    )
    state.add_neighbor(
        source_id,
        unknown_id,
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/1",
            local_interface_raw="Gi1/0/1",
            remote_name="endpoint.example.net",
            remote_interface="eth0",
            remote_interface_raw="eth0",
            remote_platform="endpoint-platform",
            remote_description="endpoint description",
            chassis_id="unknown-chassis",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
            capabilities=["bridge"],
            details={"protocols": ["lldp", "cdp"]},
        ),
    )
    state.add_error(
        source_id,
        "entity",
        "optional_walk_failed",
        "optional ENTITY-MIB data unavailable",
        recoverable=True,
        final_device_status="COMPLETE",
    )

    normal = tmp_path / "normal"
    written = write_outputs(
        state, config, normal, run_id="json-only", status="COMPLETED", draft=False
    )
    expected_csvs = {path.name for path in written if path.suffix == ".csv"}
    assert expected_csvs == {
        "hosts.csv",
        "stack-members.csv",
        "seeds.csv",
        "unknown-devices.csv",
        "errors.csv",
    }

    document = json.loads((normal / "discovery.json").read_text(encoding="utf-8"))
    unknown_record = next(
        record
        for record in document["hosts"]
        if record["classification"] == "unknown_device"
    )
    assert unknown_record["observed_by_neighbors"][0]["protocols"] == ["cdp", "lldp"]
    state.close()

    replay = tmp_path / "json-only-replay"
    replayed = write_fixed_csv_outputs(document, config, replay)
    assert {path.name for path in replayed} == expected_csvs
    for name in sorted(expected_csvs):
        assert (replay / name).read_bytes() == (normal / name).read_bytes(), name

    import csv

    with (normal / "unknown-devices.csv").open(encoding="utf-8", newline="") as fh:
        unknown_rows = list(csv.DictReader(fh))
    assert unknown_rows[0]["protocols"] == "cdp;lldp"



def test_empty_fixed_csv_files_are_suppressed_by_default(tmp_path: Path, config):
    """One global policy omits every enabled fixed CSV with zero data rows."""

    state = StateStore(tmp_path / "state.sqlite")
    state.upsert_candidate(
        Candidate(names=["standalone.example.net"], category="managed_device"),
        is_seed=True,
    )
    scratch = tmp_path / "scratch"

    written = write_outputs(
        state, config, scratch, run_id="empty-stack", status="RUNNING", draft=False
    )
    assert config.output.write_stack_members_csv is True
    assert config.output.write_empty_csv is False
    assert {path.name for path in written} == {
        "discovery.json",
        "hosts.csv",
        "seeds.csv",
    }
    for name in ("stack-members.csv", "unknown-devices.csv", "errors.csv"):
        assert not (scratch / name).exists()

    config.output.write_empty_csv = True
    write_outputs(
        state, config, scratch, run_id="empty-stack", status="RUNNING", draft=False
    )
    assert all((scratch / name).exists() for name in OUTPUT_NAMES)

    config.output.write_stack_members_csv = False
    write_outputs(
        state, config, scratch, run_id="empty-stack", status="RUNNING", draft=False
    )
    assert not (scratch / "stack-members.csv").exists()
    state.close()


def test_standard_csv_files_can_be_individually_suppressed(tmp_path: Path, config):
    """CSV output controls suppress presence only; discovery.json is unconditional."""

    state = StateStore(tmp_path / "state.sqlite")
    state.upsert_candidate(
        Candidate(names=["host.example.net"], category="managed_device"),
        is_seed=True,
    )
    scratch = tmp_path / "scratch"

    # Force all empty fixed CSVs on for the first snapshot so this test can verify
    # stale-file cleanup for every individually disabled report.
    config.output.write_empty_csv = True
    write_outputs(state, config, scratch, run_id="outputs", status="RUNNING", draft=False)
    assert all((scratch / name).exists() for name in OUTPUT_NAMES)

    config.output.write_hosts_csv = False
    config.output.write_stack_members_csv = False
    config.output.write_seeds_csv = False
    config.output.write_unknown_devices_csv = False
    config.output.write_errors_csv = True
    written = write_outputs(
        state, config, scratch, run_id="outputs", status="COMPLETED", draft=False
    )

    assert [path.name for path in written] == ["discovery.json", "errors.csv"]
    assert (scratch / "discovery.json").exists()
    assert (scratch / "errors.csv").exists()
    assert not (scratch / "hosts.csv").exists()
    assert not (scratch / "stack-members.csv").exists()
    assert not (scratch / "seeds.csv").exists()
    assert not (scratch / "unknown-devices.csv").exists()
    state.close()


def test_global_empty_csv_policy_removes_stale_header_only_files(tmp_path: Path, config):
    """Switching the global policy off removes earlier header-only CSV artifacts."""

    state = StateStore(tmp_path / "state.sqlite")
    scratch = tmp_path / "scratch"

    config.output.write_empty_csv = True
    written = write_outputs(
        state, config, scratch, run_id="empty", status="RUNNING", draft=False
    )
    assert {path.name for path in written} == set(OUTPUT_NAMES)

    config.output.write_empty_csv = False
    written = write_outputs(
        state, config, scratch, run_id="empty", status="COMPLETED", draft=False
    )
    assert [path.name for path in written] == ["discovery.json"]
    for name in OUTPUT_NAMES[1:]:
        assert not (scratch / name).exists()
    state.close()


def test_empty_csv_alert_is_aggregated_only_for_terminal_snapshots(
    tmp_path: Path,
    config,
    caplog,
):
    """Optional alerts list enabled empty reports once and ignore draft snapshots."""

    state = StateStore(tmp_path / "state.sqlite")
    state.upsert_candidate(
        Candidate(names=["standalone.example.net"], category="managed_device"),
        is_seed=True,
    )
    scratch = tmp_path / "scratch"
    config.output.log_alert_on_empty_csv = True
    caplog.set_level(logging.INFO, logger="lldp_runner.outputs")

    write_outputs(
        state, config, scratch, run_id="alert", status="RUNNING", draft=True
    )
    assert "empty csv not written" not in caplog.text

    write_outputs(
        state, config, scratch, run_id="alert", status="PAUSED", draft=True
    )
    messages = [
        record.getMessage()
        for record in caplog.records
        if "empty csv not written" in record.getMessage()
    ]
    assert messages == [
        "empty csv not written for stack-members.csv, unknown-devices.csv, errors.csv"
    ]

    caplog.clear()
    config.output.write_errors_csv = False
    write_outputs(
        state, config, scratch, run_id="alert", status="COMPLETED", draft=False
    )
    assert [
        record.getMessage()
        for record in caplog.records
        if "empty csv not written" in record.getMessage()
    ] == ["empty csv not written for stack-members.csv, unknown-devices.csv"]
    state.close()


def test_finalize_accepts_enabled_output_subset(tmp_path: Path):
    """Final persistence requires JSON but permits intentionally suppressed CSVs."""

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "discovery.json").write_text("{}\n", encoding="utf-8")
    (scratch / "hosts.csv").write_text("preferred_name\n", encoding="utf-8")

    final = tmp_path / "outputs" / "run1"
    final.mkdir(parents=True)
    # Simulate a partial prior finalization from an invocation where seeds.csv was
    # enabled. The retry below disables it and must remove the stale artifact.
    (final / "seeds.csv").write_text("preferred_name\n", encoding="utf-8")
    latest = tmp_path / "outputs" / "latest"
    finalize_to_persistent(
        scratch,
        final,
        latest,
        output_names=["discovery.json", "hosts.csv"],
    )

    assert (final / "discovery.json").exists()
    assert (final / "hosts.csv").exists()
    assert not (final / "seeds.csv").exists()
    assert latest.resolve() == final.resolve()


def test_distinct_neighbors_with_malformed_network_chassis_stay_separate(
    tmp_path: Path, config
):
    """Canonical output must retain each Aruba-learned phone as its own host."""

    import json

    from lldp_runner.models import NeighborObservation

    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-08-27 03:00:00 EDT")
    source_id = state.upsert_candidate(
        Candidate(
            names=["branch-access-6300-2.net.example.com"],
            addresses=["203.0.113.11"],
            category="managed_device",
        )
    )
    phones = (
        ("1/1/3", "SEP00123456000D.voice.example.net", "192.0.2.191", "00123456000D:P1"),
        ("1/1/19", "SEP001234560011.voice.example.net", "192.0.2.206", "001234560011:P1"),
        ("1/1/22", "SEP001234560009.voice.example.net", "192.0.2.115", "001234560009:P1"),
    )
    remote_ids = []
    for local_port, name, address, remote_port in phones:
        candidate = Candidate(
            names=[name],
            addresses=[address],
            category="managed_endpoint",
            source_host_id=source_id,
            protocol="lldp",
            chassis_id="hex:15:00:00:00:00:00",
            chassis_id_subtype="network_address",
            chassis_id_subtype_id=5,
        )
        remote_id = state.upsert_candidate(
            candidate,
            preferred_name=name,
            synthetic_alias=f"edge:{source_id}:lldp:{local_port}:{remote_port}",
        )
        remote_ids.append(remote_id)
        state.add_neighbor(
            source_id,
            remote_id,
            NeighborObservation(
                protocol="lldp",
                local_interface=local_port,
                local_interface_raw=local_port,
                remote_name=name,
                remote_interface=remote_port,
                remote_interface_raw=remote_port,
                remote_addresses=[address],
                chassis_id="hex:15:00:00:00:00:00",
                chassis_id_subtype="network_address",
                chassis_id_subtype_id=5,
                details={
                    "chassis_id": "hex:15:00:00:00:00:00",
                    "chassis_id_subtype": "network_address",
                    "chassis_id_subtype_id": 5,
                },
            ),
        )

    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="run1", status="COMPLETED", draft=False)
    payload = json.loads((scratch / "discovery.json").read_text(encoding="utf-8"))
    source = next(item for item in payload["hosts"] if item["id"] == source_id)
    learned = source["learned_neighbors"]

    assert len(set(remote_ids)) == 3
    learned_by_port = {item["local_interface"]: item for item in learned}
    assert {
        port: learned_by_port[port]["name"] for port, _name, _address, _remote in phones
    } == {port: name for port, name, _address, _remote in phones}
    assert {
        port: learned_by_port[port]["observed_name"]
        for port, _name, _address, _remote in phones
    } == {port: name for port, name, _address, _remote in phones}
    assert len({item["host_ref"] for item in learned}) == 3
    assert all(
        item["details"]["chassis_id"] == "hex:15:00:00:00:00:00"
        for item in learned
    )
    hosts = {item["id"]: item for item in payload["hosts"]}
    assert all(hosts[remote_id]["chassis_id"] is None for remote_id in remote_ids)
    state.close()


def test_nexus_vdc_cdp_lldp_edges_consolidate_without_merging_other_vdcs(
    tmp_path: Path, config
):
    """Nexus VDC edge evidence should merge per link and per logical VDC only."""

    import json

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-08-27 21:50:00 EDT")
    source_id = state.upsert_candidate(
        Candidate(
            names=["hq-core-9500-1.net.example.com"],
            addresses=["203.0.113.101"],
            category="managed_device",
        )
    )

    raw: list[NeighborObservation] = []
    for local, remote, chassis in (
        ("Hu1/0/25", "Eth1/2", "00:12:34:56:b0:01"),
        ("Hu1/0/26", "Eth2/2", "00:12:34:56:b0:02"),
    ):
        raw.append(
            NeighborObservation(
                protocol="lldp",
                local_interface=local,
                local_interface_raw=local,
                remote_name="hq-vdc2-7nx1.net.example.com",
                remote_interface=remote,
                remote_interface_raw=remote,
                remote_addresses=[
                    "203.0.113.24",
                    "2001:db8:113d:61::1000:46",
                ],
                remote_description="Cisco NX-OS(tm) n7700, Version 8.4(12)",
                capabilities=["bridge", "router"],
                chassis_id=chassis,
                chassis_id_subtype="mac_address",
                chassis_id_subtype_id=4,
            )
        )
        raw.append(
            NeighborObservation(
                protocol="cdp",
                local_interface=local,
                local_interface_raw=local,
                remote_name="hq-vdc2-7nx1.net.example.com(SERIAL000001)",
                remote_interface=remote,
                remote_interface_raw=remote.replace("Eth", "Ethernet"),
                remote_addresses=["203.0.113.103"],
                remote_description=(
                    "Cisco Nexus Operating System (NX-OS) Software, Version 8.4(12)"
                ),
                remote_platform="N77-C7718",
                capabilities=["router", "switch"],
                details={
                    "device_id": "hq-vdc2-7nx1.net.example.com(SERIAL000001)",
                    "entry_addresses": ["203.0.113.103"],
                },
            )
        )

    # A different VDC on the same physical chassis serial must remain distinct.
    raw.extend(
        [
            NeighborObservation(
                protocol="lldp",
                local_interface="Hu1/0/21",
                local_interface_raw="Hu1/0/21",
                remote_name="hq-vdc1-7nx1.net.example.com",
                remote_interface="Eth6/22",
                remote_interface_raw="Eth6/22",
                remote_addresses=["203.0.113.23"],
                remote_description="Cisco NX-OS(tm) n7700, Version 8.4(12)",
                capabilities=["bridge", "router"],
                chassis_id="84:8a:8d:0e:bf:98",
                chassis_id_subtype="mac_address",
                chassis_id_subtype_id=4,
            ),
            NeighborObservation(
                protocol="cdp",
                local_interface="Hu1/0/21",
                local_interface_raw="Hu1/0/21",
                remote_name="hq-vdc1-7nx1.net.example.com(SERIAL000001)",
                remote_interface="Eth6/22",
                remote_interface_raw="Ethernet6/22",
                remote_addresses=["203.0.113.102"],
                remote_description=(
                    "Cisco Nexus Operating System (NX-OS) Software, Version 8.4(12)"
                ),
                remote_platform="N77-C7718",
                capabilities=["router", "switch"],
                details={
                    "device_id": "hq-vdc1-7nx1.net.example.com(SERIAL000001)",
                    "entry_addresses": ["203.0.113.102"],
                },
            ),
        ]
    )

    merged = merge_neighbor_observations(raw)
    assert len(merged) == 3

    remote_ids: list[int] = []
    for obs in merged:
        candidate = Candidate(
            names=[obs.remote_name] if obs.remote_name else [],
            addresses=list(obs.remote_addresses),
            category="managed_device",
            source_host_id=source_id,
            protocol=obs.protocol,
            local_interface=obs.local_interface,
            remote_interface=obs.remote_interface,
            remote_description=obs.remote_description,
            remote_platform=obs.remote_platform,
            capabilities=list(obs.capabilities),
            chassis_id=obs.chassis_id,
            chassis_id_subtype=obs.chassis_id_subtype,
            chassis_id_subtype_id=obs.chassis_id_subtype_id,
            protocols=list(obs.details.get("protocols", [obs.protocol])),
            details=dict(obs.details),
        )
        remote_id = state.upsert_candidate(candidate, preferred_name=obs.remote_name)
        remote_ids.append(remote_id)
        state.add_neighbor(source_id, remote_id, obs)

    remote_by_name: dict[str, list[int]] = {}
    for observation, remote_id in zip(merged, remote_ids, strict=True):
        remote_by_name.setdefault(observation.remote_name or "", []).append(remote_id)
    vdc2_ids = remote_by_name["hq-vdc2-7nx1.net.example.com"]
    vdc1_ids = remote_by_name["hq-vdc1-7nx1.net.example.com"]
    assert len(vdc2_ids) == 2
    assert len(vdc1_ids) == 1
    assert vdc2_ids[0] == vdc2_ids[1]
    assert vdc1_ids[0] != vdc2_ids[0]
    vdc1_id = vdc1_ids[0]

    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="run1", status="COMPLETED", draft=False)
    payload = json.loads((scratch / "discovery.json").read_text(encoding="utf-8"))
    source = next(item for item in payload["hosts"] if item["id"] == source_id)
    learned = {item["local_interface"]: item for item in source["learned_neighbors"]}

    assert len(learned) == 3
    for local in ("Hu1/0/25", "Hu1/0/26"):
        item = learned[local]
        assert item["protocols"] == ["cdp", "lldp"]
        assert item["name"] == "hq-vdc2-7nx1.net.example.com"
        assert item["observed_name"] == "hq-vdc2-7nx1.net.example.com"
        assert item["observed_addresses"] == [
            "2001:db8:113d:61::1000:46",
            "203.0.113.24",
            "203.0.113.103",
        ]
        assert item["details"]["cdp.remote_name"] == (
            "hq-vdc2-7nx1.net.example.com(SERIAL000001)"
        )
        assert item["details"]["cdp.entry_addresses"] == ["203.0.113.103"]

    assert learned["Hu1/0/21"]["name"] == "hq-vdc1-7nx1.net.example.com"
    assert learned["Hu1/0/21"]["host_ref"] != learned["Hu1/0/25"]["host_ref"]
    state.close()


def test_phone_cdp_lldp_edge_is_single_in_learned_and_observed_by(tmp_path: Path, config):
    """One physical phone edge should not duplicate learned/observed_by topology."""

    import json

    from lldp_runner.collectors import merge_neighbor_observations
    from lldp_runner.models import NeighborObservation

    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-08-28 05:15:00 EDT")
    source_id = state.upsert_candidate(
        Candidate(
            names=["branch-access-3650-stack-2.net.example.com"],
            addresses=["203.0.113.26"],
            category="managed_device",
        )
    )

    raw = [
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/8",
            local_interface_raw="GigabitEthernet1/0/8",
            remote_name="SEP00123456000C.voice-a.example.com",
            remote_interface="00123456000C:P1",
            remote_interface_raw="00123456000C:P1",
            remote_addresses=["198.51.100.33"],
            remote_description="Cisco IP Phone 8841, V1",
            chassis_id="198.51.100.33",
            chassis_id_subtype="network_address",
            chassis_id_subtype_id=5,
            details={"port_id": "00123456000C:P1"},
        ),
        NeighborObservation(
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
        ),
    ]

    merged = merge_neighbor_observations(raw)
    assert len(merged) == 1
    obs = merged[0]
    remote_id = state.upsert_candidate(
        Candidate(
            names=[obs.remote_name] if obs.remote_name else [],
            addresses=list(obs.remote_addresses),
            category="unknown_device",
            source_host_id=source_id,
            protocol=obs.protocol,
            local_interface=obs.local_interface,
            remote_interface=obs.remote_interface,
            remote_description=obs.remote_description,
            remote_platform=obs.remote_platform,
            capabilities=list(obs.capabilities),
            chassis_id=obs.chassis_id,
            chassis_id_subtype=obs.chassis_id_subtype,
            chassis_id_subtype_id=obs.chassis_id_subtype_id,
            protocols=list(obs.details.get("protocols", [obs.protocol])),
            details=dict(obs.details),
        ),
        preferred_name=obs.remote_name,
    )
    state.add_neighbor(source_id, remote_id, obs)

    scratch = tmp_path / "scratch"
    write_outputs(state, config, scratch, run_id="run1", status="COMPLETED", draft=False)
    document = json.loads((scratch / "discovery.json").read_text(encoding="utf-8"))
    hosts = {item["id"]: item for item in document["hosts"]}

    learned = hosts[source_id]["learned_neighbors"]
    observed_by = hosts[remote_id]["observed_by_neighbors"]
    assert len(learned) == 1
    assert len(observed_by) == 1
    assert learned[0]["protocols"] == ["cdp", "lldp"]
    assert observed_by[0]["protocols"] == ["cdp", "lldp"]
    assert learned[0]["name"] == "SEP00123456000C.voice-a.example.com"
    assert learned[0]["remote_interface"] == "00123456000C:P1"
    state.close()
