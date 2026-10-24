"""tools/flat_graph_compare.py: derive flat hosts from the graph and compare them."""

from __future__ import annotations

import copy
import importlib.util
import json
import socket
import subprocess
import sys
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any

import pytest

from lldp_runner.classify import Classifier
from lldp_runner.collectors import merge_neighbor_observations
from lldp_runner.coordinator import Coordinator
from lldp_runner.models import DeviceResult, NeighborObservation, SeedInput, SystemDetails
from lldp_runner.outputs import write_outputs
from lldp_runner.policy import PolicyEngine
from lldp_runner.state import StateStore
from lldp_runner.timeutil import iso_now
from lldp_runner.topology_shadow import build_interface_observation_groups

TOOL = Path(__file__).parents[1] / "tools" / "flat_graph_compare.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("flat_graph_compare_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


def _neighbor(
    protocol: str,
    local: str,
    name: str | None,
    remote: str,
    *,
    address: str | None = None,
    chassis: str | None = None,
) -> NeighborObservation:
    return NeighborObservation(
        protocol=protocol,
        local_interface=local,
        local_interface_raw=local,
        remote_name=name,
        remote_interface=remote,
        remote_interface_raw=remote,
        remote_addresses=[address] if address else [],
        capabilities=["bridge", "router"],
        chassis_id=chassis,
        chassis_id_subtype="mac_address" if chassis else None,
        chassis_id_subtype_id=4 if chassis else None,
    )


def _devices() -> dict[str, dict[str, Any]]:
    """Three switches, an endpoint pair on one port, a phone, and a failed switch."""

    return {
        "198.18.1.1": {
            "system": SystemDetails(
                sys_name="core1.net.example.com",
                serial_number="FOCCORE0001",
                snmp_engine_id="80000009030000aa00000010",
            ),
            "raw": [
                _neighbor(
                    "cdp", "Te1/1/1", "dist1.net.example.com", "Te1/0/1", address="198.18.1.2"
                ),
                _neighbor(
                    "lldp",
                    "Te1/1/1",
                    "dist1.net.example.com",
                    "Te1/0/1",
                    address="198.18.1.2",
                    chassis="00:aa:00:00:00:20",
                ),
                _neighbor(
                    "lldp", "Te1/1/2", "dist2.net.example.com", "Te1/0/1", address="198.18.1.3"
                ),
                _neighbor("cdp", "Gi1/0/10", "SEP001122334455", "Port 1", address="198.18.5.10"),
                _neighbor("lldp", "Gi1/0/11", "printer-3f", "eth0", chassis="00:bb:00:00:00:11"),
                _neighbor("lldp", "Gi1/0/11", "camera-lobby", "eth0", chassis="00:bb:00:00:00:12"),
            ],
        },
        "198.18.1.2": {
            "system": SystemDetails(sys_name="dist1.net.example.com", serial_number="FOCDIST0001"),
            "raw": [
                _neighbor(
                    "cdp", "Te1/0/1", "core1.net.example.com", "Te1/1/1", address="198.18.1.1"
                ),
                _neighbor(
                    "lldp",
                    "Te1/0/1",
                    "core1.net.example.com",
                    "Te1/1/1",
                    address="198.18.1.1",
                    chassis="00:aa:00:00:00:10",
                ),
            ],
        },
        "198.18.1.3": {"status": "failed"},
    }


def _discover(config, tmp_path: Path, monkeypatch, seeds: list[str], devices) -> dict[str, Any]:
    """Run the coordinator's real ingestion with simulated device results."""

    def no_dns(*args: Any, **kwargs: Any) -> Any:
        raise socket.gaierror(socket.EAI_NONAME, "no DNS in tests")

    monkeypatch.setattr("lldp_runner.identity.socket.getaddrinfo", no_dns)
    monkeypatch.setattr("lldp_runner.identity.socket.gethostbyaddr", no_dns)

    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.paths = SimpleNamespace(run_id="compare", scratch_dir=tmp_path / "scratch")
    coordinator.resume = False
    coordinator.state = StateStore(tmp_path / "state.sqlite")
    coordinator.policy = PolicyEngine(config)
    coordinator.classifier = Classifier(config)
    coordinator.seed_only = False
    coordinator.effective_max_devices = None
    coordinator.pause_event = Event()
    coordinator.limit_reached = False
    coordinator.limit_reason = None
    coordinator.started_text = "test"
    coordinator.initialize([SeedInput(seed) for seed in seeds])

    state = coordinator.state
    done: set[str] = set()
    progress = True
    while progress:
        progress = False
        for row in state.all_hosts():
            _names, addresses, _chassis = state.aliases_for_host(int(row["id"]))
            target = next((item for item in addresses if item in devices), None)
            if target is None or target in done:
                continue
            done.add(target)
            progress = True
            spec = devices[target]
            host_id = int(row["id"])
            if spec.get("status") == "failed":
                coordinator._process_result(
                    DeviceResult(host_id=host_id, status="failed", query_target=target)
                )
                continue
            merged = merge_neighbor_observations(copy.deepcopy(spec["raw"]))
            coordinator._process_result(
                DeviceResult(
                    host_id=host_id,
                    status="success",
                    query_target=target,
                    credential_profile="default",
                    credential_result="primary",
                    system=spec["system"],
                    raw_neighbors=copy.deepcopy(spec["raw"]),
                    neighbors=merged,
                    interface_observation_groups=build_interface_observation_groups(
                        host_id, merged
                    ),
                    last_seen=iso_now(),
                )
            )
    output = tmp_path / "output"
    write_outputs(state, config, output, run_id="compare", status="COMPLETED", draft=False)
    state.close()
    return json.loads((output / "discovery.json").read_text(encoding="utf-8"))


def test_views_from_one_real_discovery_agree(config, tmp_path: Path, monkeypatch) -> None:
    """The real ingestion path gives matching systems and neighbors in both views."""

    payload = _discover(config, tmp_path, monkeypatch, ["198.18.1.1"], _devices())

    report = tool.compare(payload, source="sample")

    systems = report["systems"]
    assert systems["flat_hosts"] == systems["graph_systems"] == 6
    assert systems["matched_one_to_one"] == 6
    assert systems["logical_systems"] == 3
    assert systems["observed_systems"] == 3
    assert systems["physical_chassis"] == 2
    assert not systems["merged_in_graph"] and not systems["flat_only"]
    assert not any(report["host_fields"].values()), report["host_fields"]
    neighbors = report["neighbors"]
    assert neighbors["flat_rows"] == neighbors["graph_relationships"] == neighbors["matched"] == 6
    assert report["agree"] is True
    # Observed systems carry no classification in the graph: a gap, not a conflict.
    assert report["flat_only_data"]["observed_classification"] == 3
    assert report["flat_only_data"]["system_details"] == 2


def test_duplicate_flat_host_is_reported_as_merged_in_the_graph(
    config, tmp_path: Path, monkeypatch
) -> None:
    """One switch reached through two addresses: the graph merges, the flat view does not."""

    devices = _devices()
    devices["198.18.2.1"] = devices["198.18.1.1"]

    payload = _discover(config, tmp_path, monkeypatch, ["198.18.1.1", "198.18.2.1"], devices)
    report = tool.compare(payload)

    merged = report["systems"]["merged_in_graph"]
    assert len(merged) == 1
    assert merged[0]["graph"] == "core1.net.example.com (logical_system)"
    assert len(merged[0]["flat"]) == 2
    neighbors = report["neighbors"]
    assert neighbors["matched"] == neighbors["graph_relationships"]
    # The duplicate host repeats all five of the core switch's neighbor rows.
    assert len(neighbors["flat_duplicates"]) == 5
    assert neighbors["flat_only"] == neighbors["graph_only"] == []
    assert report["agree"] is False


def _payload() -> dict[str, Any]:
    """A minimal hand-built discovery.json with one switch and one endpoint."""

    return {
        "schema_version": 8,
        "discovery": {"run_id": "minimal"},
        "hosts": [
            {
                "id": 1,
                "preferred_name": "sw1",
                "queried_as": "192.0.2.1",
                "classification": "managed_device",
                "state": "complete",
                "names": ["sw1"],
                "addresses": {"ipv4": ["192.0.2.1"], "ipv6": []},
                "chassis_id": None,
                "system": {"sys_name": "sw1"},
                "snmp": {"credential_result": "primary"},
                "learned_neighbors": [
                    {
                        "host_ref": 2,
                        "name": "phone1",
                        "local_interface": "Gi1/0/1",
                        "local_interface_raw": "GigabitEthernet1/0/1",
                        "remote_interface": "Port 1",
                        "remote_interface_raw": "Port 1",
                        "protocols": ["cdp"],
                    }
                ],
                "observed_by_neighbors": [],
            },
            {
                "id": 2,
                "preferred_name": "phone1",
                "queried_as": None,
                "classification": "managed_endpoint",
                "state": "no_query",
                "names": ["phone1"],
                "addresses": {"ipv4": ["192.0.2.50"], "ipv6": []},
                "chassis_id": None,
                "learned_neighbors": [],
                "observed_by_neighbors": [],
            },
        ],
        "topology_graph": {
            "schema_version": 2,
            "authority": {
                "observation_completeness": "complete",
                "entity_resolution": "provisional",
            },
            "entities": [
                {
                    "entity_key": "logical:sw1",
                    "entity_type": "logical_system",
                    "display_name": "sw1",
                    "host_refs": [1],
                    "identity": {
                        "names": ["sw1"],
                        "addresses": ["192.0.2.1"],
                        "query_targets": ["192.0.2.1"],
                    },
                    "classifications": ["managed_device"],
                    "states": ["complete"],
                },
                {
                    "entity_key": "observed:phone1",
                    "entity_type": "observed_system",
                    "display_name": "phone1",
                    "host_refs": [],
                    "identity": {"names": ["phone1"], "addresses": ["192.0.2.50"]},
                    "classifications": [],
                    "states": [],
                },
            ],
            "interfaces": [
                {
                    "interface_key": "interface:gi1",
                    "owner_entity_key": "logical:sw1",
                    "name": "Gi1/0/1",
                    "raw_identifiers": ["GigabitEthernet1/0/1"],
                }
            ],
            "relationships": [
                {
                    "source_entity_key": "logical:sw1",
                    "interface_key": "interface:gi1",
                    "remote_entity_key": "observed:phone1",
                    "remote_name": "phone1",
                    "remote_interface": "Port 1",
                    "protocols": ["cdp"],
                }
            ],
        },
    }


def test_minimal_matching_payload_agrees() -> None:
    report = tool.compare(_payload())

    assert report["agree"] is True
    assert report["systems"]["matched_one_to_one"] == 2
    assert report["neighbors"]["matched"] == 1


def test_missing_and_extra_relationships_are_reported() -> None:
    payload = _payload()
    relationship = payload["topology_graph"]["relationships"][0]
    relationship["remote_interface"] = "Port 2"

    report = tool.compare(payload)

    assert len(report["neighbors"]["flat_only"]) == 1
    assert len(report["neighbors"]["graph_only"]) == 1
    assert report["agree"] is False


def test_protocol_and_field_differences_are_reported() -> None:
    payload = _payload()
    payload["topology_graph"]["relationships"][0]["protocols"] = ["cdp", "lldp"]
    payload["topology_graph"]["entities"][0]["identity"]["addresses"].append("192.0.2.9")
    payload["topology_graph"]["entities"][0]["states"] = ["failed"]

    report = tool.compare(payload)

    assert len(report["neighbors"]["protocols_differ"]) == 1
    assert report["host_fields"]["addresses"][0]["graph"] == ["192.0.2.1", "192.0.2.9"]
    assert report["host_fields"]["state"][0]["flat"] == "complete"


def test_flat_host_split_into_two_graph_systems() -> None:
    """Two observed systems that both match one flat host are a split, not two matches."""

    payload = _payload()
    second = copy.deepcopy(payload["topology_graph"]["entities"][1])
    second["entity_key"] = "observed:phone1-second-mac"
    second["identity"] = {"names": [], "addresses": ["192.0.2.50"]}
    payload["topology_graph"]["entities"].append(second)

    report = tool.compare(payload)

    split = report["systems"]["split_in_graph"]
    assert split == [
        {
            "flat": "phone1 (host 2)",
            "graph": ["phone1 (observed_system)", "phone1 (observed_system)"],
        }
    ]


def test_unmatched_systems_are_flat_only_or_graph_only() -> None:
    payload = _payload()
    payload["hosts"][1]["names"] = ["handset-9"]
    payload["hosts"][1]["preferred_name"] = "handset-9"
    payload["hosts"][1]["addresses"]["ipv4"] = ["192.0.2.99"]

    report = tool.compare(payload)

    assert report["systems"]["flat_only"] == ["handset-9 (host 2)"]
    assert report["systems"]["graph_only"] == ["phone1 (observed_system)"]


def test_placeholder_addresses_never_pair_systems() -> None:
    payload = _payload()
    payload["hosts"][1]["names"] = []
    payload["hosts"][1]["preferred_name"] = "unknown"
    payload["hosts"][1]["addresses"]["ipv4"] = ["0.0.0.0"]
    payload["topology_graph"]["entities"][1]["identity"] = {"addresses": ["0.0.0.0"]}
    payload["topology_graph"]["entities"][1]["display_name"] = "observed"

    report = tool.compare(payload)

    assert report["systems"]["flat_only"] == ["unknown (host 2)"]
    assert report["systems"]["graph_only"] == ["observed (observed_system)"]


def _write(tmp_path: Path, payload: dict[str, Any], name: str = "run") -> Path:
    directory = tmp_path / name
    directory.mkdir()
    (directory / "discovery.json").write_text(json.dumps(payload), encoding="utf-8")
    return directory


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args], check=False, text=True, capture_output=True
    )


def test_command_line_reports_and_exit_codes(tmp_path: Path) -> None:
    agreeing = _write(tmp_path, _payload(), "agree")
    differing_payload = _payload()
    differing_payload["topology_graph"]["relationships"] = []
    differing = _write(tmp_path, differing_payload, "differ")

    result = _run(str(agreeing))
    assert result.returncode == 0, result.stderr
    assert "matched one to one               2" in result.stdout
    assert "Result: systems, host fields, and neighbors agree." in result.stdout

    result = _run(str(differing / "discovery.json"), "--details")
    assert result.returncode == 1
    assert "Flat-only neighbor rows (1)" in result.stdout

    result = _run(str(agreeing), str(differing), "--json")
    assert result.returncode == 1
    reports = json.loads(result.stdout)
    assert [report["agree"] for report in reports] == [True, False]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"schema_version": 7}, "discovery schema 7 is not supported"),
        ({"topology_graph": {"schema_version": 1}}, "topology graph schema 1 is not supported"),
    ],
)
def test_unsupported_schemas_exit_2(tmp_path: Path, change: dict[str, Any], message: str) -> None:
    payload = _payload()
    payload.update(change)

    result = _run(str(_write(tmp_path, payload)))

    assert result.returncode == 2
    assert message in result.stderr


def test_missing_file_exits_2(tmp_path: Path) -> None:
    result = _run(str(tmp_path / "missing"))

    assert result.returncode == 2
    assert "file not found" in result.stderr


def test_tool_uses_only_the_standard_library() -> None:
    """The tool must run on any discovery.json without LLDP-Runner installed."""

    result = subprocess.run(
        [sys.executable, "-I", "-S", str(TOOL), "--help"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert (
        "lldp_runner"
        not in TOOL.read_text(encoding="utf-8").split('"""', 2)[2].split("import", 1)[0]
    )
