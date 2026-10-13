"""Regression coverage for get-neighbors logical SNMP tracing."""

from __future__ import annotations

import asyncio
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from lldp_runner import cli
from lldp_runner.snmp.trace import SnmpTrace, TraceContext


class _FakeClient:
    def __init__(self) -> None:
        self.engine = "800000090300001122334455"

    async def get(self, oid: str) -> object:
        return b"switch\x1b[31m"

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        return {
            oids[0]: b"Cisco IOS XE",
            oids[1]: "router1.example.net",
        }

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        return [
            (f"{oid}.1", b"GigabitEthernet1/0/1"),
            (f"{oid}.2", b"GigabitEthernet1/0/2"),
        ]

    def engine_id_hex(self) -> str | None:
        return self.engine


class _TimeoutClient(_FakeClient):
    async def walk(self, oid: str) -> list[tuple[str, object]]:
        raise TimeoutError("community secret-value timed out")


def _context(*, redactions: tuple[str, ...] = ()) -> TraceContext:
    return TraceContext(
        address="198.18.10.10",
        profile="default",
        credential="default-v2",
        snmp_version="v2c",
        phase="detail collectors",
        stage="primary",
        attempt=1,
        redactions=redactions,
    )


def test_trace_records_named_queries_walk_rows_and_safe_values() -> None:
    stream = io.StringIO()
    trace = SnmpTrace([stream], input_target="router1")
    client = trace.wrap(_FakeClient(), _context())

    async def exercise() -> None:
        await client.get_many(
            [
                "1.3.6.1.2.1.1.1.0",
                "1.3.6.1.2.1.1.5.0",
                "1.3.6.1.2.1.1.6.0",
            ]
        )
        await client.walk("1.3.6.1.2.1.31.1.1.1.1")
        await client.get("1.0.8802.1.1.2.1.4.1.1.7.0.7.1")

    asyncio.run(exercise())
    trace.finish()
    text = stream.getvalue()

    assert "SNMP SESSION 1" in text
    assert "Name:        sysDescr" in text
    assert "Description: System description" in text
    assert "OID:         1.3.6.1.2.1.1.1.0" in text
    assert "Value:       Cisco IOS XE" in text
    assert "Name:        ifName" in text
    assert "OID:         1.3.6.1.2.1.31.1.1.1.1.2" in text
    assert "Value:       GigabitEthernet1/0/2" in text
    assert "Name:        lldpRemPortId" in text
    # The ESC byte is rendered safely instead of becoming a terminal sequence.
    assert "Value:       hex:73:77:69:74:63:68:1b:5b:33:31:6d" in text
    assert "requested OID returned no varbind" in text
    assert "Logical SNMP queries: 5" in text


def test_trace_records_timeout_as_no_response_and_redacts_secret() -> None:
    stream = io.StringIO()
    trace = SnmpTrace([stream], input_target="router1")
    client = trace.wrap(_TimeoutClient(), _context(redactions=("secret-value",)))

    with pytest.raises(TimeoutError):
        asyncio.run(client.walk("1.0.8802.1.1.2.1.4.1.1"))

    text = stream.getvalue()
    assert "NO RESPONSE" in text
    assert "TimeoutError:" in text
    assert "<redacted>" in text
    assert "secret-value" not in text


def test_tracefile_requires_filename_with_operator_friendly_error(capsys) -> None:
    parser = cli._get_neighbors_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["router1", "--tracefile"])

    assert exc_info.value.code == 2
    assert (
        "--tracefile requires a filename to be identified for output"
        in capsys.readouterr().err
    )


def test_tracefile_empty_filename_is_rejected(monkeypatch, config) -> None:
    monkeypatch.setattr(cli, "_load_app", lambda *_args, **_kwargs: config)
    parser = cli._get_neighbors_parser()
    args = parser.parse_args(["router1", "--tracefile", ""])

    with pytest.raises(SystemExit) as exc_info:
        cli._execute_inspect(args, parser)
    assert exc_info.value.code == 2


def test_tracefile_alone_writes_file_and_both_options_fan_out(
    monkeypatch, config, tmp_path: Path, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_load_app", lambda *_args, **_kwargs: config)

    def fake_inspect(
        config_arg,
        target,
        *,
        dry_run=False,
        system_only=False,
        trace=None,
    ):
        assert trace is not None
        trace._line("TRACE-MARKER")
        return SimpleNamespace(exit_code=0)

    monkeypatch.setattr(cli, "inspect_target_sync", fake_inspect)
    monkeypatch.setattr(cli, "render_inspection", lambda *_args, **_kwargs: "RESULT")

    parser = cli._get_neighbors_parser()
    args = parser.parse_args(["router1", "--tracefile", "trace-only.txt"])
    assert cli._execute_inspect(args, parser) == 0
    first = capsys.readouterr()
    assert first.out == "RESULT\n"
    assert "TRACE-MARKER" not in first.err
    file_text = (tmp_path / "trace-only.txt").read_text(encoding="utf-8")
    assert "TRACE-MARKER" in file_text
    assert "Trace complete:" in file_text

    args = parser.parse_args(
        ["router1", "--trace", "--tracefile", "trace-both.txt"]
    )
    assert cli._execute_inspect(args, parser) == 0
    second = capsys.readouterr()
    assert second.out == "RESULT\n"
    assert "TRACE-MARKER" in second.err
    assert "TRACE-MARKER" in (tmp_path / "trace-both.txt").read_text(encoding="utf-8")


def test_tracefile_open_failure_occurs_before_inspection(monkeypatch, config, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "_load_app", lambda *_args, **_kwargs: config)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("inspection must not begin when trace file cannot open")

    monkeypatch.setattr(cli, "inspect_target_sync", forbidden)
    parser = cli._get_neighbors_parser()
    args = parser.parse_args(
        ["router1", "--tracefile", str(tmp_path / "missing" / "trace.txt")]
    )

    with pytest.raises(SystemExit) as exc_info:
        cli._execute_inspect(args, parser)
    assert exc_info.value.code == 2

class _FakeSnmpContext:
    def __init__(self, client: object) -> None:
        self.client = client

    async def __aenter__(self) -> object:
        return self.client

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


def test_single_device_worker_wires_trace_through_system_collection(
    monkeypatch, config
) -> None:
    from lldp_runner import worker
    from lldp_runner.models import DeviceTask, TargetAttempt

    class BasicClient:
        async def get_many(self, oids: list[str]) -> dict[str, object]:
            values: dict[str, object] = {oid: "" for oid in oids}
            values["1.3.6.1.2.1.1.1.0"] = "Cisco IOS XE"
            values["1.3.6.1.2.1.1.2.0"] = "1.3.6.1.4.1.9.1.1745"
            values["1.3.6.1.2.1.1.5.0"] = "switch1"
            return values

        async def get(self, oid: str) -> object:
            return ""

        async def walk(self, oid: str) -> list[tuple[str, object]]:
            return []

        def engine_id_hex(self) -> str | None:
            return None

    monkeypatch.setattr(
        worker,
        "create_snmp_client",
        lambda *_args, **_kwargs: _FakeSnmpContext(BasicClient()),
    )
    config.icmp.enabled = False
    config.snmp.inter_wave_delay_seconds = 0
    task = DeviceTask(
        host_id=1,
        preferred_name="switch1",
        names=["switch1"],
        addresses=["198.18.10.10"],
        attempts=[TargetAttempt(address="198.18.10.10", credential_profile="default")],
        cohort=0,
    )
    stream = io.StringIO()
    trace = SnmpTrace([stream], input_target="switch1")

    device, _timings = asyncio.run(
        worker.process_single_device(
            config,
            task,
            SimpleNamespace(is_set=lambda: False),
            system_only=True,
            trace=trace,
        )
    )

    assert device.status == "success"
    text = stream.getvalue()
    assert "Phase:       basic SYSTEM-MIB" in text
    assert "Profile:     default" in text
    assert "Credential:  default-v3" in text
    assert "SNMP version: v3" in text
    assert "Name:        sysName" in text
    assert "Value:       switch1" in text


def test_network_trace_records_resolver_queries_and_results(monkeypatch) -> None:
    from lldp_runner import identity, inspection

    stream = io.StringIO()
    trace = SnmpTrace([stream], input_target="router1")

    def fake_getaddrinfo(name, _port, *, type):
        assert type > 0
        suffix = "10" if name == "router1" else "11"
        return [
            (2, 2, 17, "", (f"198.18.0.{suffix}", 0)),
            (10, 2, 17, "", (f"2001:db8::{suffix}", 0, 0, 0)),
        ]

    monkeypatch.setattr(identity.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        identity.socket,
        "getfqdn",
        lambda name: f"{name}.canonical.example.net",
    )
    resolved = identity.resolve_seed(
        "router1", ["example.net"], trace=trace
    )
    assert "198.18.0.10" in resolved.addresses

    monkeypatch.setattr(
        inspection.socket,
        "gethostbyaddr",
        lambda address: ("router1.example.net", ["alias.example.net"], [address]),
    )
    reverse = inspection._reverse_dns(["198.18.0.10"], trace=trace)
    assert reverse[0].name == "router1.example.net"
    trace.finish()
    text = stream.getvalue()

    assert "LLDP-Runner get-neighbors network trace" in text
    assert "DNS / RESOLVER QUERY 0001" in text
    assert "Operation:   getaddrinfo" in text
    assert "Source:      input hostname" in text
    assert "Source:      configured DNS suffix candidate" in text
    assert "Operation:   getfqdn" in text
    assert "Operation:   gethostbyaddr" in text
    assert "IPv4:        198.18.0.10" in text
    assert "PTR name:    router1.example.net" in text
    assert "DNS/resolver queries: 5" in text


def test_network_trace_records_system_icmp_echo_reply(monkeypatch, config) -> None:
    from lldp_runner import icmp

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return b"64 bytes from host: time=1.427 ms\n", b""

    async def fake_subprocess(*_args, **_kwargs):
        return FakeProcess()

    monkeypatch.setattr(icmp.shutil, "which", lambda name: "/bin/ping")
    monkeypatch.setattr(icmp.asyncio, "create_subprocess_exec", fake_subprocess)
    config.icmp.enabled = True
    config.icmp.backend = "system"
    config.icmp.timeout_seconds = 1.0
    stream = io.StringIO()
    trace = SnmpTrace([stream], input_target="198.18.0.10")
    pinger = icmp.AsyncIcmpPinger(config.icmp, trace=trace)

    probe = asyncio.run(pinger.probe("198.18.0.10", 2))
    trace.finish()
    assert probe.status == "reply"
    text = stream.getvalue()
    assert "ICMP PROBE 0001" in text
    assert "Type:        Echo request" in text
    assert "Protocol:    ICMP IPv4" in text
    assert "Backend:     system ping" in text
    assert "Sequence:    2" in text
    assert "Type:        Echo reply" in text
    assert "RTT:         1.427 ms" in text
    assert "Result:      REPLY" in text
    assert "ICMP probes:          1" in text


def test_network_trace_summary_uses_monotonic_elapsed(monkeypatch) -> None:
    import lldp_runner.snmp.trace as trace_module

    times = iter([100.0, 106.842])
    monkeypatch.setattr(trace_module.time, "monotonic", lambda: next(times))
    stream = io.StringIO()
    trace = SnmpTrace([stream], input_target="router1")
    trace.finish()
    text = stream.getvalue()

    assert "TRACE SUMMARY" in text
    assert "DNS/resolver queries: 0" in text
    assert "ICMP probes:          0" in text
    assert "Logical SNMP queries: 0" in text
    assert "Total elapsed:        6.842s" in text


def test_network_trace_records_icmp_timeout_as_no_response(monkeypatch, config) -> None:
    from lldp_runner import icmp

    class FakeProcess:
        returncode = 1

        async def communicate(self):
            return b"", b""

    async def fake_subprocess(*_args, **_kwargs):
        return FakeProcess()

    monkeypatch.setattr(icmp.shutil, "which", lambda name: "/bin/ping")
    monkeypatch.setattr(icmp.asyncio, "create_subprocess_exec", fake_subprocess)
    config.icmp.enabled = True
    config.icmp.backend = "system"
    stream = io.StringIO()
    trace = SnmpTrace([stream], input_target="198.18.0.10")
    pinger = icmp.AsyncIcmpPinger(config.icmp, trace=trace)

    probe = asyncio.run(pinger.probe("198.18.0.10", 1))
    assert probe.status == "no-response"
    text = stream.getvalue()
    assert "NO RESPONSE" in text
    assert "Result:      TIMEOUT" in text
