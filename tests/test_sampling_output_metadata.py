from __future__ import annotations

import json
from pathlib import Path

from lldp_runner.outputs import write_outputs
from lldp_runner.state import StateStore


def test_discovery_json_records_sampling_methodology(config, tmp_path: Path) -> None:
    config.discovery.max_devices = "auto"
    config.discovery.max_hosts = 1000
    config.discovery.seed_order = "random"
    config.discovery.shuffle_key = "operator-key"
    config.discovery.limit_behavior = "complete"

    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-08-20T21:00:00-04:00")
    state.set_meta("discovery_mode", "seed_only")
    state.set_meta("effective_max_devices", "2500")
    state.set_meta("seed_order", "random")
    state.set_meta("seed_shuffle_key", "operator-key")
    state.set_meta("limit_reason", "max_hosts")
    state.set_meta("completion_reason", "max_hosts")

    output_dir = tmp_path / "outputs"
    write_outputs(
        state,
        config,
        output_dir,
        run_id="sample-run",
        status="COMPLETED_LIMIT",
        draft=False,
    )

    payload = json.loads((output_dir / "discovery.json").read_text(encoding="utf-8"))
    metadata = payload["discovery"]
    assert metadata["seed_order"] == "random"
    assert metadata["shuffle_key"] == "operator-key"
    assert metadata["limit_behavior"] == "complete"
    assert metadata["limit_reason"] == "max_hosts"
    assert metadata["completion_reason"] == "max_hosts"
    assert metadata["configured_max_devices"] == "auto"
    assert metadata["configured_max_hosts"] == 1000
    state.close()
