from __future__ import annotations

import asyncio
import json

from lldp_runner.models import Candidate, CollectionMetric, DeviceResult, SystemDetails
from lldp_runner.outputs import write_outputs
from lldp_runner.snmp.metrics import CountingSnmpClient
from lldp_runner.state import StateStore
from lldp_runner.worker import _measured_collection


class _FakeClient:
    """Small backend-neutral client used to prove varbind counting semantics."""

    async def get(self, oid: str) -> object:
        return f"value:{oid}"

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        # Simulate an agent omitting one requested scalar.
        return {oid: index for index, oid in enumerate(oids[:-1])}

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        size = {"one": 3, "two": 2}.get(oid, 0)
        return [(f"{oid}.{index}", index) for index in range(size)]

    def engine_id_hex(self) -> str | None:
        return "80000001"


async def _two_walk_collector(client: CountingSnmpClient) -> list[tuple[str, object]]:
    first = await client.walk("one")
    second = await client.walk("two")
    return [*first, *second]


def test_counting_client_counts_returned_varbinds_not_requested_oids() -> None:
    async def exercise() -> int:
        client = CountingSnmpClient(_FakeClient())  # ty: ignore[invalid-argument-type]
        await client.get("scalar")
        await client.get_many(["a", "b", "c"])
        await client.walk("one")
        return client.objects

    # 1 scalar + 2 values actually returned by get_many + 3 walked varbinds.
    assert asyncio.run(exercise()) == 6


def test_measured_collection_aggregates_objects_across_multiple_walks() -> None:
    result = DeviceResult(host_id=1, status="success")

    async def exercise() -> None:
        rows = await _measured_collection(
            "lldp",
            result,
            _FakeClient(),
            _two_walk_collector,
        )
        assert len(rows) == 5

    asyncio.run(exercise())
    metric = result.collection_metrics["lldp"]
    assert metric.objects == 5
    assert metric.duration_ms >= 0.0


def test_discovery_json_reports_metrics_only_when_enabled(tmp_path, config) -> None:
    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(
            names=["switch1.net.example.com"],
            addresses=["198.18.10.10"],
            category="managed_device",
        ),
        is_seed=True,
    )
    state.apply_device_result(
        DeviceResult(
            host_id=host_id,
            status="success",
            query_target="198.18.10.10",
            credential_profile="default",
            credential_result="primary",
            system=SystemDetails(sys_name="switch1.net.example.com"),
            collection_metrics={
                "sys": CollectionMetric(objects=6, duration_ms=12.4),
                "lldpv2": CollectionMetric(objects=0, duration_ms=201.3),
            },
        )
    )

    disabled = tmp_path / "disabled"
    config.snmp.report_metrics = False
    write_outputs(state, config, disabled, run_id="metrics", status="COMPLETED", draft=False)
    payload = json.loads((disabled / "discovery.json").read_text(encoding="utf-8"))
    assert payload["discovery"]["snmp_report_metrics"] is False
    assert "collection_metrics" not in payload["hosts"][0]["snmp"]

    enabled = tmp_path / "enabled"
    config.snmp.report_metrics = True
    write_outputs(state, config, enabled, run_id="metrics", status="COMPLETED", draft=False)
    payload = json.loads((enabled / "discovery.json").read_text(encoding="utf-8"))
    assert payload["discovery"]["snmp_report_metrics"] is True
    metrics = payload["hosts"][0]["snmp"]["collection_metrics"]
    assert metrics["sys"] == {"objects": 6, "duration_ms": 12.4}
    assert metrics["lldpv2"] == {"objects": 0, "duration_ms": 201.3}
    state.close()
