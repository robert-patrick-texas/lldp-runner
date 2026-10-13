from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass

import pytest

from lldp_runner import inspection, inspection_output
from lldp_runner.cli import _get_neighbors_parser, _parser
from lldp_runner.identity import ResolvedIdentity
from lldp_runner.inspection import InspectionResult, ReverseDnsResult, inspect_target
from lldp_runner.inspection_output import render_csv, render_detail, render_json, render_table
from lldp_runner.models import (
    CollectionMetric,
    DeviceResult,
    NeighborObservation,
    PingProbe,
    SystemDetails,
)
from lldp_runner.timeutil import configure_timezone, iso_now


@dataclass
class _Stream:
    tty: bool

    def isatty(self) -> bool:
        return self.tty


def _sample_result() -> InspectionResult:
    device = DeviceResult(
        host_id=0,
        status="success",
        query_target="198.18.10.10",
        credential_profile="default",
        credential_result="primary",
        ping_probes=[
            PingProbe(
                status="reply",
                timestamp=iso_now(),
                address="198.18.10.10",
                rtt_ms=1.234,
            ),
            PingProbe(
                status="reply",
                timestamp=iso_now(),
                address="198.18.10.10",
                rtt_ms=1.456,
            ),
        ],
        system=SystemDetails(
            sys_name="switch1.net.example.com",
            sys_descr="Cisco IOS XE\nCatalyst switch",
            manufacturer="Cisco",
            model="C9300-48P",
            version="17.15.3",
            sys_location="LAB",
        ),
        neighbors=[
            NeighborObservation(
                protocol="lldp",
                local_interface="Te1/0/4",
                local_interface_raw="TenGigabitEthernet1/0/4",
                remote_name="linux01.net.example.com",
                remote_interface="eno1",
                remote_interface_raw="eno1",
                remote_addresses=["198.18.10.50", "2001:db8::50"],
                remote_description="Linux host",
                remote_platform="Linux",
                capabilities=["stationOnly"],
                chassis_id="0c:c4:7a:75:57:f6",
                chassis_id_subtype="mac_address",
                chassis_id_subtype_id=4,
                details={"protocols": ["lldp"], "remote_index": 1},
            )
        ],
        last_seen=iso_now(),
        last_seen_source="snmp",
        collection_metrics={
            "sys": CollectionMetric(objects=6, duration_ms=12.4),
            "entity": CollectionMetric(objects=67, duration_ms=803.2),
            "interfaces": CollectionMetric(objects=48, duration_ms=601.1),
            "lldp": CollectionMetric(objects=91, duration_ms=1002.8),
            "lldpv2": CollectionMetric(objects=0, duration_ms=201.3),
        },
    )
    return InspectionResult(
        input_target="switch1.net.example.com",
        preferred_name="switch1.net.example.com",
        names=["switch1.net.example.com"],
        addresses=["198.18.10.10"],
        forward_dns=["switch1.net.example.com -> 198.18.10.10"],
        reverse_dns=[ReverseDnsResult(address="198.18.10.10", name="switch1.net.example.com")],
        dns_errors=[],
        policies=[],
        dry_run=False,
        status="success",
        device=device,
        dns_duration_ms=2.5,
        query_duration_ms=125.75,
        total_duration_ms=128.25,
        probe_timings={"basic_phase": 40.0, "detail_phase": 85.75},
    )


def test_get_neighbors_accepts_options_before_or_after_target() -> None:
    parser = _get_neighbors_parser()
    before = parser.parse_args(["--json", "--community", "SITE_COMM", "router1"])
    after = parser.parse_args(["router1", "--json", "--community", "SITE_COMM"])

    assert before.target == after.target == "router1"
    assert before.inspect_format == after.inspect_format == "json"
    assert before.snmp_community == after.snmp_community == "SITE_COMM"


def test_get_neighbors_system_only_aliases_work_before_or_after_target() -> None:
    parser = _get_neighbors_parser()
    before = parser.parse_args(["--system-only", "router1"])
    after = parser.parse_args(["router1", "--no-neighbors"])

    assert before.target == after.target == "router1"
    assert before.system_only is True
    assert after.system_only is True


def test_lldp_runner_get_neighbors_accumulates_set_before_and_after_subcommand(monkeypatch) -> None:
    from lldp_runner import cli

    args = cli._parser().parse_args(
        [
            "--set",
            "snmp.max_repetitions=19",
            "get-neighbors",
            "router1",
            "--set",
            "snmp.timeout_seconds=2.0",
            "--dry-run",
        ]
    )
    captured: dict[str, object] = {}

    def fake_load_app(namespace, **kwargs):
        captured["set"] = list(namespace.set)
        raise ValueError("stop after merge")

    monkeypatch.setattr(cli, "_load_app", fake_load_app)
    with pytest.raises(SystemExit):
        cli._execute_inspect(args, cli._parser())
    assert captured["set"] == [
        "snmp.max_repetitions=19",
        "snmp.timeout_seconds=2.0",
    ]


def test_lldp_runner_get_neighbors_accepts_applicable_options_after_target() -> None:
    args = _parser().parse_args(
        [
            "get-neighbors",
            "router1",
            "--community",
            "public",
            "--set",
            "snmp.max_repetitions=11",
            "--detail",
        ]
    )
    assert args.command == "get-neighbors"
    assert args.target == "router1"
    assert args.snmp_community == "public"
    assert args.set == []
    assert args.inspect_set == ["snmp.max_repetitions=11"]
    assert args.inspect_format == "detail"


@pytest.mark.parametrize("dry_run", [False, True])
def test_get_neighbors_preflights_only_active_network_requests(
    monkeypatch,
    config,
    capsys,
    dry_run: bool,
) -> None:
    """Active inspection checks local crypto before query; dry-run stays local."""

    from lldp_runner import cli

    events: list[str] = []
    monkeypatch.setattr(cli, "_load_app", lambda *_args, **_kwargs: config)

    def preflight(_config) -> None:
        events.append("preflight")

    def inspect(*_args, **_kwargs):
        events.append("inspect")
        return type("Inspection", (), {"exit_code": 0})()

    monkeypatch.setattr(cli, "preflight_snmp_backend", preflight)
    monkeypatch.setattr(cli, "inspect_target_sync", inspect)
    monkeypatch.setattr(cli, "render_inspection", lambda *_args, **_kwargs: "RESULT")
    parser = cli._get_neighbors_parser()
    argv = ["router1"] + (["--dry-run"] if dry_run else [])

    assert cli._execute_inspect(parser.parse_args(argv), parser) == 0
    assert events == (["inspect"] if dry_run else ["preflight", "inspect"])
    assert capsys.readouterr().out == "RESULT\n"


def test_inspect_query_policy_reports_boundary_but_does_not_enforce_it(config) -> None:
    rows = inspection._policy_rows(
        config,
        ["outside.net.example.com"],
        ["203.0.113.10"],
    )
    assert len(rows) == 1
    assert rows[0].boundary_allowed is False
    assert rows[0].query_allowed is True
    assert rows[0].credential_profile == "default"


def test_inspect_still_honors_explicit_query_policy_deny(config) -> None:
    rows = inspection._policy_rows(config, ["printer-lab"], ["198.18.10.20"])
    assert rows[0].boundary_allowed is True
    assert rows[0].query_allowed is False
    assert "deny" in rows[0].query_reason


def test_inspect_dry_run_stops_before_worker_probe(monkeypatch, config) -> None:
    monkeypatch.setattr(
        inspection,
        "resolve_seed",
        lambda target, suffixes: ResolvedIdentity(
            target,
            "outside.net.example.com",
            ["outside.net.example.com"],
            ["203.0.113.10"],
        ),
    )
    monkeypatch.setattr(
        inspection,
        "_reverse_dns",
        lambda addresses: [ReverseDnsResult(address=addresses[0], name="outside.net.example.com")],
    )
    monkeypatch.setattr(
        inspection,
        "_forward_dns_for_display",
        lambda *args: ["outside.net.example.com -> 203.0.113.10"],
    )

    async def forbidden(*args, **kwargs):
        raise AssertionError("dry-run must not invoke ICMP/SNMP worker probing")

    monkeypatch.setattr(inspection, "process_single_device", forbidden)
    result = asyncio.run(inspect_target(config, "outside.net.example.com", dry_run=True))

    assert result.status == "dry_run"
    assert result.device is None
    assert result.policies[0].boundary_allowed is False
    assert result.policies[0].query_allowed is True
    assert result.exit_code == 0


def test_inspect_real_probe_reuses_worker_result_and_timings(monkeypatch, config) -> None:
    monkeypatch.setattr(
        inspection,
        "resolve_seed",
        lambda target, suffixes: ResolvedIdentity(
            target,
            "switch1.net.example.com",
            ["switch1.net.example.com"],
            ["198.18.10.10"],
        ),
    )
    monkeypatch.setattr(inspection, "_reverse_dns", lambda addresses: [])
    monkeypatch.setattr(inspection, "_forward_dns_for_display", lambda *args: [])
    sample = _sample_result().device
    assert sample is not None
    sample.last_seen = "2026-08-25T18:03:04-04:00"
    sample.last_seen_source = "snmp"

    async def fake_probe(config_arg, task, pause_event, *, system_only=False):
        assert task.attempts[0].address == "198.18.10.10"
        assert system_only is False
        return sample, {"basic_phase": 12.5, "detail_phase": 31.25}

    monkeypatch.setattr(inspection, "process_single_device", fake_probe)
    result = asyncio.run(inspect_target(config, "switch1.net.example.com"))

    assert result.status == "success"
    assert result.device is sample
    assert result.collected_at == "2026-08-25T18:03:04-04:00"
    assert result.probe_timings == {"basic_phase": 12.5, "detail_phase": 31.25}
    assert result.query_duration_ms >= 0
    assert result.exit_code == 0


def test_inspect_without_successful_snmp_uses_finalization_time(monkeypatch, config) -> None:
    """Unresolved/error results use a live configured-zone presentation time."""

    monkeypatch.setattr(
        inspection,
        "resolve_seed",
        lambda target, suffixes: ResolvedIdentity(target, target, [target], []),
    )
    monkeypatch.setattr(inspection, "_reverse_dns", lambda addresses: [])
    monkeypatch.setattr(inspection, "_forward_dns_for_display", lambda *args: [])
    monkeypatch.setattr(
        inspection,
        "iso_now",
        lambda: "2026-08-25T18:04:05-04:00",
    )

    result = asyncio.run(inspect_target(config, "missing.example.com"))

    assert result.status == "unresolved"
    assert result.collected_at == "2026-08-25T18:04:05-04:00"


def test_system_only_passes_mode_to_worker_and_json(monkeypatch, config) -> None:
    monkeypatch.setattr(
        inspection,
        "resolve_seed",
        lambda target, suffixes: ResolvedIdentity(
            target,
            "switch1.net.example.com",
            ["switch1.net.example.com"],
            ["198.18.10.10"],
        ),
    )
    monkeypatch.setattr(inspection, "_reverse_dns", lambda addresses: [])
    monkeypatch.setattr(inspection, "_forward_dns_for_display", lambda *args: [])
    sample = _sample_result().device
    assert sample is not None
    sample.neighbors = []
    sample.collection_metrics = {
        "sys": CollectionMetric(objects=6, duration_ms=12.4),
    }

    async def fake_probe(config_arg, task, pause_event, *, system_only=False):
        assert system_only is True
        return sample, {"basic_phase": 40.0, "detail_phase": 0.0}

    monkeypatch.setattr(inspection, "process_single_device", fake_probe)
    result = asyncio.run(
        inspect_target(config, "switch1.net.example.com", system_only=True)
    )

    assert result.system_only is True
    payload = json.loads(render_json(config, result))
    assert payload["inspection"]["collection_mode"] == "system_only"
    assert payload["host"]["snmp"]["collection_metrics"] == {
        "sys": {"objects": 6, "duration_ms": 12.4}
    }


def test_system_only_human_views_omit_neighbor_sections(config) -> None:
    result = _sample_result()
    result.system_only = True
    assert result.device is not None
    result.device.neighbors = []
    result.device.collection_metrics = {
        "sys": CollectionMetric(objects=6, duration_ms=12.4)
    }
    result.probe_timings = {"basic_phase": 40.0, "detail_phase": 0.0}

    table = render_table(config, result, stream=_Stream(False))
    detail = render_detail(config, result, stream=_Stream(False))

    assert "SNMP obj/ms:     sys=6/12.4" in table
    assert "SNMP obj/ms:     sys=6/12.4" in detail
    assert "Local            Protocol" not in table
    assert "No CDP/LLDP neighbors were returned" not in table
    assert "Neighbors (" not in detail
    assert "Serial:" not in detail
    assert "Hardware rev:" not in detail
    assert "Firmware rev:" not in detail


def test_csv_system_only_emits_only_two_metadata_comments(config) -> None:
    """System-only get-neighbors CSV must not imply a neighbor table exists.

    The sample result deliberately retains a learned neighbor so this regression
    proves ``--system-only`` controls the schema rather than relying on an empty
    neighbor result set.
    """

    result = _sample_result()
    result.system_only = True

    csv_text = render_csv(config, result)
    lines = csv_text.splitlines()

    assert len(lines) == 2
    assert all(line.startswith("# ") for line in lines)
    assert "local_interface,protocol,neighbor" not in csv_text
    assert "Te1/0/4" not in csv_text


def test_renderers_have_no_blank_spacer_lines_and_expose_timing(config, monkeypatch) -> None:
    result = _sample_result()
    monkeypatch.delenv("NO_COLOR", raising=False)

    table = render_table(config, result, stream=_Stream(False))
    detail = render_detail(config, result, stream=_Stream(False))
    csv_text = render_csv(config, result)
    json_text = render_json(config, result)

    for rendered in (table, detail, csv_text, json_text):
        assert "\n\n" not in rendered

    assert "Ping RTT ms:" in table
    assert "198.18.10.10=1.234" in table
    assert "Timing ms:" in table
    assert "query=125.750" in table
    assert "query=125.750 ms" not in table
    assert (
        "SNMP obj/ms:     sys=6/12.4; entity=67/803.2; "
        "interfaces=48/601.1; lldp=91/1002.8; lldpv2=0/201.3"
    ) in table
    assert table.index("Timing ms:") < table.index("SNMP obj/ms:") < table.index("SNMP profile:")
    assert "Ping RTT ms:" in detail
    assert "198.18.10.10=1.234" in detail
    assert "Timing ms:" in detail
    assert "query=125.750" in detail
    assert "query=125.750 ms" not in detail
    assert "SNMP obj/ms:" in detail
    assert detail.index("Timing ms:") < detail.index("SNMP obj/ms:") < detail.index("SNMP profile:")
    assert "SNMP obj/ms:" not in csv_text
    assert csv_text.splitlines()[0].startswith("# target=")
    assert ",state=success,timestamp=" in csv_text.splitlines()[0]
    assert ",status=" not in csv_text.splitlines()[0]
    assert "local_interface,protocol,neighbor,remote_interface,address,platform" in csv_text

    payload = json.loads(json_text)
    assert payload["inspection"]["timings_ms"]["query"] == 125.75
    assert payload["host"]["icmp"][0]["rtt_ms"] == 1.234
    assert payload["host"]["snmp"]["collection_metrics"]["lldpv2"] == {
        "objects": 0,
        "duration_ms": 201.3,
    }
    assert payload["host"]["learned_neighbors"][0]["local_interface"] == "Te1/0/4"
    assert payload["host"]["learned_neighbors"][0]["classification"] == "unmanaged_device"


def test_get_neighbors_table_uses_configured_and_dynamic_interface_widths(
    config, monkeypatch
) -> None:
    """Configured baselines and shared dynamic growth apply to get-neighbors."""

    result = _sample_result()
    assert result.device is not None
    result.device.neighbors[0].remote_interface = "Port-Identifier-Longer-Than-Eighteen"
    result.device.neighbors[0].remote_interface_raw = (
        "Port-Identifier-Longer-Than-Eighteen"
    )
    config.output.neighbor_local_width = 24
    monkeypatch.setattr(
        inspection_output.shutil,
        "get_terminal_size",
        lambda fallback: os.terminal_size((120, 24)),
    )

    rendered = render_table(config, result, stream=_Stream(False))
    header = next(line for line in rendered.splitlines() if line.startswith("Local"))
    assert header.index("Protocol") == 25
    assert "Port-Identifier-Longer-Than-Eighteen" in rendered


def test_get_neighbors_table_displays_complete_ipv6_management_address(
    config, monkeypatch
) -> None:
    """The rightmost Mgmt cell preserves a long IPv6 address without ellipsis."""

    result = _sample_result()
    assert result.device is not None
    address = "2001:db8:8000:da02:1234:5678:9abc:def0"
    result.device.neighbors[0].remote_addresses = [address]
    monkeypatch.setattr(
        inspection_output.shutil,
        "get_terminal_size",
        lambda fallback: os.terminal_size((120, 24)),
    )

    rendered = render_table(config, result, stream=_Stream(False))

    assert address in rendered
    assert f"{address[:-4]}…" not in rendered


def test_human_color_requires_tty_and_honors_no_color(config, monkeypatch) -> None:
    result = _sample_result()
    monkeypatch.delenv("NO_COLOR", raising=False)
    colored = render_table(config, result, stream=_Stream(True))
    assert "\x1b[" in colored
    # Timing labels remain plain while the numeric assignment values receive
    # emphasis. This keeps the line readable and makes measurements stand out.
    assert "Ping RTT ms:" in colored
    assert "Timing ms:" in colored
    assert "=\x1b[1m\x1b[32m1.234\x1b[0m" in colored
    assert "query=\x1b[1m\x1b[32m125.750\x1b[0m" in colored
    assert "sys=\x1b[1m\x1b[32m6\x1b[0m/\x1b[1m\x1b[32m12.4\x1b[0m" in colored
    assert "\x1b[" not in render_table(config, result, stream=_Stream(False))

    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b[" not in render_table(config, result, stream=_Stream(True))
    assert "\x1b[" not in render_detail(config, result, stream=_Stream(True))


def test_get_neighbors_timestamp_is_timezone_converted_and_right_aligned(
    config, monkeypatch
) -> None:
    """Table/detail/CSV reuse one configured-zone collection timestamp."""

    result = _sample_result()
    result.collected_at = "2026-08-25T21:52:26+00:00"
    configure_timezone("America/Denver")
    monkeypatch.setattr(
        inspection_output.shutil,
        "get_terminal_size",
        lambda fallback: os.terminal_size((100, 24)),
    )

    table = render_table(config, result, stream=_Stream(False))
    detail = render_detail(config, result, stream=_Stream(False))
    csv_text = render_csv(config, result)

    expected = "(collected 2026-08-25 15:52:26)"
    assert table.splitlines()[0].endswith(expected)
    assert detail.splitlines()[0].endswith(expected)
    assert len(table.splitlines()[0]) == 100
    assert csv_text.splitlines()[0].endswith(
        "state=success,timestamp=2026-08-25 15:52:26"
    )


def test_get_neighbors_terminal_colors_are_configurable(config, monkeypatch) -> None:
    """Semantic terminal settings replace the previous hard-coded colors."""

    result = _sample_result()
    config.terminal.heading_color = "blue"
    config.terminal.metric_color = "red"
    config.terminal.inspection_neighbor_color = "yellow"
    monkeypatch.delenv("NO_COLOR", raising=False)

    rendered = render_table(config, result, stream=_Stream(True))

    assert "\x1b[1m\x1b[34mLLDP-Runner single-device inspection" in rendered
    assert "=\x1b[1m\x1b[31m1.234\x1b[0m" in rendered
    assert "\x1b[33mlldp" in rendered


def test_csv_and_json_never_emit_color(config, monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    result = _sample_result()
    assert "\x1b[" not in render_csv(config, result)
    assert "\x1b[" not in render_json(config, result)


def test_inspect_config_loading_skips_discovery_path_resolution(monkeypatch) -> None:
    import lldp_runner.config as config_module

    def forbidden(*args, **kwargs):
        raise AssertionError("inspect must not resolve persistent/scratch paths")

    monkeypatch.setattr(config_module, "_resolve_persistent_root", forbidden)
    config = config_module.load_config(
        None,
        env={"SNMPCOMM": "public"},
        resolve_paths=False,
    )
    assert config.paths.persistent_root == "auto"
    assert config.paths.scratch_root == "auto"


def test_project_exposes_get_neighbors_console_script() -> None:
    import tomllib
    from pathlib import Path

    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["scripts"]["get-neighbors"] == "lldp_runner.cli:get_neighbors_main"


def test_successful_device_with_no_neighbors_is_not_a_failure() -> None:
    result = _sample_result()
    assert result.device is not None
    result.device.neighbors = []
    assert result.exit_code == 0


def test_failed_snmp_result_is_renderable_but_returns_nonzero(config) -> None:
    result = _sample_result()
    assert result.device is not None
    result.status = "failed"
    result.device.status = "failed"
    result.device.system = None
    result.device.neighbors = []
    text = render_table(config, result, stream=_Stream(False))
    assert "State:           failed" in text
    assert "Ping RTT ms:" in text
    assert result.exit_code == 1
