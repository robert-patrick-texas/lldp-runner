"""Regression coverage for read-only discovery search and rendering."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from lldp_runner import discovery_view_output
from lldp_runner.cli import main, show_neighbors_main
from lldp_runner.config import ConfigError, CredentialMode, load_config
from lldp_runner.discovery_query import (
    DiscoveryQueryError,
    build_query_criteria,
    load_discovery_document,
    select_hosts,
)
from lldp_runner.discovery_view_output import (
    render_csv,
    render_json,
    render_selected_host,
    render_table,
    selected_neighbor_sections,
)


class _Tty:
    """Minimal stream stand-in that enables ANSI rendering in unit tests."""

    def isatty(self) -> bool:
        """Report an interactive terminal so color output is exercised."""

        return True


class _Plain:
    """Minimal non-TTY stream stand-in for visible-width assertions."""

    def isatty(self) -> bool:
        """Report a redirected/non-interactive output stream."""

        return False


def _host(
    host_id: int,
    name: str,
    *,
    ipv4: list[str] | None = None,
    ipv6: list[str] | None = None,
    learned: list[dict[str, object]] | None = None,
    observed_by: list[dict[str, object]] | None = None,
    model: str = "C9300-48P",
) -> dict[str, object]:
    """Build one compact discovery.json host fixture with real schema fields."""

    return {
        "id": host_id,
        "preferred_name": name,
        "queried_as": (ipv4 or ipv6 or [None])[0],
        "snmp_sysname": name.split(".")[0],
        "classification": "managed_device",
        "classification_reason": ["fixture"],
        "tags": ["site:lab"],
        "state": "complete",
        "is_seed": host_id == 1,
        "first_seen": "2026-08-24 18:00:00 EDT",
        "last_seen": "2026-08-24 18:00:01 EDT",
        "last_seen_source": "snmp",
        "names": [name],
        "addresses": {"ipv4": ipv4 or [], "ipv6": ipv6 or []},
        "chassis_id": f"chassis-{host_id}",
        "icmp": [{"status": "reply", "rtt_ms": 1.2}],
        "system": {
            "sys_name": name.split(".")[0],
            "sys_descr": "fixture switch",
            "sys_object_id": "1.3.6.1.4.1.9.1.1234",
            "sys_uptime_ticks": 12345,
            "manufacturer": "Cisco",
            "model": model,
            "version": "17.12",
            "serial_number": f"SERIAL{host_id}",
            "stack_members": [],
        },
        "snmp": {"credential_profile": "site", "credential_result": "primary"},
        "learned_neighbors": learned or [],
        "observed_by_neighbors": observed_by or [],
    }


def _neighbor(
    host_ref: int,
    name: str,
    *,
    local: str,
    remote: str,
    address: str,
) -> dict[str, object]:
    """Build one learned/reciprocal neighbor record in discovery.json format."""

    return {
        "host_ref": host_ref,
        "name": name,
        "classification": "managed_device",
        "local_interface": local,
        "local_interface_raw": local,
        "remote_interface": remote,
        "remote_interface_raw": remote,
        "protocols": ["lldp"],
        "protocol_tag": "[lldp]",
        "observed_name": name,
        "observed_addresses": [address],
        "details": {"remote_platform": "fixture"},
        "last_seen": "2026-08-24 18:00:01 EDT",
    }


def _write_discovery(root: Path) -> Path:
    """Write a representative finalized discovery document beneath outputs/latest."""

    learned = _neighbor(
        3,
        "alpha.example.org",
        local="Gi1/0/1",
        remote="Gi1/0/48",
        address="192.168.20.3",
    )
    observed = _neighbor(
        1,
        "client-137001.example.com",
        local="Gi1/0/24",
        remote="Gi1/0/2",
        address="198.51.100.22",
    )
    hosts = [
        _host(
            1,
            "client-137001.example.com",
            ipv4=["198.51.100.22"],
            ipv6=["2001:db8:1::22"],
            learned=[learned],
        ),
        _host(
            2,
            "client-135001.example.com",
            ipv4=["198.51.100.212"],
            ipv6=["2001:db8:2::212"],
            observed_by=[observed],
            model="CX6300",
        ),
        _host(
            3,
            "alpha.example.org",
            ipv4=["192.168.20.3"],
            ipv6=["2001:db8::3"],
            model="EX4400",
        ),
    ]
    latest = root / "outputs" / "latest"
    latest.mkdir(parents=True)
    path = latest / "discovery.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 8,
                "discovery": {
                    "run_id": "fixture",
                    "status": "COMPLETED",
                    "generated": "2026-08-25T19:52:26+00:00",
                },
                "hosts": hosts,
                "errors": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


def _config(tmp_path: Path):
    """Load a read-only-friendly config pointing at the fixture persistent root."""

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'''[paths]
persistent_root = "{tmp_path}"
scratch_root = "{tmp_path / "scratch"}"

[logging]
console = false
file = false
''',
        encoding="utf-8",
    )
    return load_config(config_path, credential_mode=CredentialMode.DISABLED, resolve_paths=False)


def test_name_regex_is_case_insensitive_and_left_anchored(tmp_path: Path) -> None:
    """Preferred-name regex uses re.match semantics rather than shell glob syntax."""

    _write_discovery(tmp_path)
    document = load_discovery_document(_config(tmp_path))

    criteria = build_query_criteria(
        host_id=None,
        name="client-13.001",
        key_expressions=[],
        ipv4_values=[],
        ipv6_values=[],
    )
    assert [host["id"] for host in select_hosts(document, criteria)] == [1, 2]

    criteria = build_query_criteria(
        host_id=None,
        name="abc",
        key_expressions=[],
        ipv4_values=[],
        ipv6_values=[],
    )
    assert select_hosts(document, criteria) == []

    criteria = build_query_criteria(
        host_id=None,
        name=r".*example\.org$",
        key_expressions=[],
        ipv4_values=[],
        ipv6_values=[],
    )
    assert [host["id"] for host in select_hosts(document, criteria)] == [3]


def test_id_is_exact_and_mutually_exclusive_with_other_filters(tmp_path: Path) -> None:
    """Exact IDs select one record and cannot silently ignore other criteria."""

    _write_discovery(tmp_path)
    document = load_discovery_document(_config(tmp_path))
    criteria = build_query_criteria(
        host_id=2,
        name=None,
        key_expressions=[],
        ipv4_values=[],
        ipv6_values=[],
    )
    assert [host["preferred_name"] for host in select_hosts(document, criteria)] == [
        "client-135001.example.com"
    ]

    with pytest.raises(DiscoveryQueryError, match="mutually exclusive"):
        build_query_criteria(
            host_id=2,
            name="A13",
            key_expressions=[],
            ipv4_values=[],
            ipv6_values=[],
        )


def test_key_filters_flatten_values_and_and_combine(tmp_path: Path) -> None:
    """Dotted and mapping-valued key regexes are repeatable AND criteria."""

    _write_discovery(tmp_path)
    document = load_discovery_document(_config(tmp_path))
    criteria = build_query_criteria(
        host_id=None,
        name="client-13",
        key_expressions=[r"system.model:^C9300", r"addresses:'198\.51\.100\.22'"],
        ipv4_values=[],
        ipv6_values=[],
    )
    assert [host["id"] for host in select_hosts(document, criteria)] == [1]


def test_ipv4_ipv6_prefix_and_cidr_filters_and_combine(tmp_path: Path) -> None:
    """Address selectors support literal prefixes, CIDRs, both families, and AND."""

    _write_discovery(tmp_path)
    document = load_discovery_document(_config(tmp_path))

    prefix = build_query_criteria(
        host_id=None,
        name=None,
        key_expressions=[],
        ipv4_values=["198.51.100"],
        ipv6_values=[],
    )
    assert [host["id"] for host in select_hosts(document, prefix)] == [1, 2]

    cidr = build_query_criteria(
        host_id=None,
        name=None,
        key_expressions=[],
        ipv4_values=["198.51.100.0/24"],
        ipv6_values=["2001:db8::/32"],
    )
    assert [host["id"] for host in select_hosts(document, cidr)] == [1, 2]

    combined = build_query_criteria(
        host_id=None,
        name="client-137",
        key_expressions=["system.manufacturer:^cisco$"],
        ipv4_values=["198.51.100.0/24"],
        ipv6_values=["2001:db8:1::/48"],
    )
    assert [host["id"] for host in select_hosts(document, combined)] == [1]


def test_invalid_filter_syntax_fails_instead_of_degrading_to_literal() -> None:
    """Malformed regex/CIDR/family inputs are explicit query errors."""

    with pytest.raises(DiscoveryQueryError, match="invalid name regex"):
        build_query_criteria(
            host_id=None,
            name="[unterminated",
            key_expressions=[],
            ipv4_values=[],
            ipv6_values=[],
        )
    with pytest.raises(DiscoveryQueryError, match="CIDR"):
        build_query_criteria(
            host_id=None,
            name=None,
            key_expressions=[],
            ipv4_values=["198.51.100.0/99"],
            ipv6_values=[],
        )
    with pytest.raises(DiscoveryQueryError, match="IPv4 CIDR"):
        build_query_criteria(
            host_id=None,
            name=None,
            key_expressions=[],
            ipv4_values=["2001:db8::/32"],
            ipv6_values=[],
        )
    with pytest.raises(DiscoveryQueryError, match="ipv6 prefix"):
        build_query_criteria(
            host_id=None,
            name=None,
            key_expressions=[],
            ipv4_values=[],
            ipv6_values=["2607:::f368"],
        )


def test_neighbor_default_fallback_and_explicit_learned_never_falls_back(tmp_path: Path) -> None:
    """Only implicit mode falls from an empty learned list to observed_by."""

    _write_discovery(tmp_path)
    document = load_discovery_document(_config(tmp_path))
    host = document.hosts_by_id[2]

    assert selected_neighbor_sections(host, None)[0][0] == "observed_by"
    assert selected_neighbor_sections(host, "learned") == [("learned", [])]
    both = selected_neighbor_sections(host, "both")
    assert [direction for direction, _ in both] == ["learned", "observed_by"]


def test_terminal_neighbor_sections_are_aligned_labeled_and_colored(tmp_path: Path) -> None:
    """Both directions render learned first with distinct bold section colors."""

    _write_discovery(tmp_path)
    config = _config(tmp_path)
    document = load_discovery_document(config)
    host = document.hosts_by_id[1]
    host["observed_by_neighbors"] = [
        _neighbor(
            2,
            "client-135001.example.com",
            local="Gi1/0/2",
            remote="Gi1/0/24",
            address="198.51.100.22",
        )
    ]

    rendered = render_table(
        config,
        document,
        host,
        neighbor_mode="both",
        system_only=False,
        stream=_Tty(),
    )
    plain = rendered.replace("\x1b[0m", "")
    assert rendered.index("Learned") < rendered.index("Observed_by")
    assert "\x1b[1m\x1b[36mLearned" in rendered
    assert "\x1b[1m\x1b[35mObserved_by" in rendered
    assert "Local" in plain and "Protocol" in plain and "Remote Port" in plain

    learned_only = render_table(
        config,
        document,
        host,
        neighbor_mode="learned",
        system_only=False,
        stream=_Tty(),
    )
    assert "Observed_by" not in learned_only
    assert "Learned" not in learned_only
    assert "Local" in learned_only


def test_show_neighbors_timestamp_uses_json_time_and_right_aligns(
    tmp_path: Path, monkeypatch
) -> None:
    """Stored JSON provenance is timezone-converted for table/detail/CSV output."""

    _write_discovery(tmp_path)
    config = _config(tmp_path)
    document = load_discovery_document(config)
    host = document.hosts_by_id[1]
    monkeypatch.setattr(
        discovery_view_output.shutil,
        "get_terminal_size",
        lambda fallback: os.terminal_size((100, 24)),
    )

    table = render_table(
        config,
        document,
        host,
        neighbor_mode="learned",
        system_only=False,
        stream=_Plain(),
    )
    detail = render_selected_host(
        config,
        document,
        host,
        output_format="detail",
        neighbor_mode="learned",
        system_only=False,
        json_indent=2,
        stream=_Plain(),
    )
    csv_text = render_csv(document, host, neighbor_mode="learned", system_only=False)

    expected = "(json 2026-08-25 15:52:26)"
    assert table.splitlines()[0].endswith(expected)
    assert detail.splitlines()[0].endswith(expected)
    assert len(table.splitlines()[0]) == 100
    assert csv_text.splitlines()[0].endswith("state=complete,timestamp=2026-08-25 15:52:26")
    assert "Neighbor 1" in detail


def test_show_neighbors_missing_json_timestamp_uses_unknown_markers(tmp_path: Path) -> None:
    """Missing JSON provenance is never replaced with filesystem/current time."""

    _write_discovery(tmp_path)
    config = _config(tmp_path)
    document = load_discovery_document(config)
    discovery = document.payload["discovery"]
    assert isinstance(discovery, dict)
    discovery.pop("generated")
    host = document.hosts_by_id[1]

    table = render_table(
        config,
        document,
        host,
        neighbor_mode="learned",
        system_only=False,
        stream=_Plain(),
    )
    csv_text = render_csv(document, host, neighbor_mode="learned", system_only=False)

    assert table.splitlines()[0].endswith("(json unknown-time)")
    assert csv_text.splitlines()[0].endswith("state=complete,timestamp=unknown")


def test_show_neighbors_terminal_colors_are_configurable(tmp_path: Path) -> None:
    """Learned/observed_by and headings use semantic config color values."""

    _write_discovery(tmp_path)
    config = _config(tmp_path)
    document = load_discovery_document(config)
    host = document.hosts_by_id[1]
    host["observed_by_neighbors"] = [
        _neighbor(
            2,
            "client-135001.example.com",
            local="Gi1/0/2",
            remote="Gi1/0/24",
            address="198.51.100.22",
        )
    ]
    config.terminal.heading_color = "blue"
    config.terminal.learned_color = "yellow"
    config.terminal.observed_by_color = "red"

    rendered = render_table(
        config,
        document,
        host,
        neighbor_mode="both",
        system_only=False,
        stream=_Tty(),
    )

    assert "\x1b[1m\x1b[34mLLDP-Runner discovery record" in rendered
    assert "\x1b[1m\x1b[33mLearned" in rendered
    assert "\x1b[1m\x1b[31mObserved_by" in rendered


def test_show_neighbors_table_shares_dynamic_interface_widths(tmp_path: Path, monkeypatch) -> None:
    """show-neighbors uses the same configured/dynamic width policy as probing."""

    _write_discovery(tmp_path)
    config = _config(tmp_path)
    config.output.neighbor_local_width = 24
    document = load_discovery_document(config)
    host = document.hosts_by_id[1]
    long_port = "Port-Identifier-Longer-Than-Eighteen"
    host["learned_neighbors"][0]["remote_interface"] = long_port
    host["learned_neighbors"][0]["remote_interface_raw"] = long_port
    monkeypatch.setattr(
        discovery_view_output.shutil,
        "get_terminal_size",
        lambda fallback: os.terminal_size((120, 24)),
    )

    rendered = render_table(
        config,
        document,
        host,
        neighbor_mode="learned",
        system_only=False,
    )
    header = next(line for line in rendered.splitlines() if line.startswith("Local"))
    assert header.index("Protocol") == 25
    assert long_port in rendered


def test_show_neighbors_table_displays_complete_ipv6_management_address(
    tmp_path: Path, monkeypatch
) -> None:
    """Stored neighbor rows retain the entire IPv6 Mgmt value at the right edge."""

    _write_discovery(tmp_path)
    config = _config(tmp_path)
    document = load_discovery_document(config)
    host = document.hosts_by_id[1]
    address = "2001:db8:8000:da02:1234:5678:9abc:def0"
    host["learned_neighbors"][0]["observed_addresses"] = [address]
    monkeypatch.setattr(
        discovery_view_output.shutil,
        "get_terminal_size",
        lambda fallback: os.terminal_size((120, 24)),
    )

    rendered = render_table(
        config,
        document,
        host,
        neighbor_mode="learned",
        system_only=False,
    )

    assert address in rendered
    assert f"{address[:-4]}…" not in rendered


def test_observed_by_mgmt_resolves_observer_host_address(tmp_path: Path) -> None:
    """Observed_by rows display the observer's management address via host_ref."""

    _write_discovery(tmp_path)
    config = _config(tmp_path)
    document = load_discovery_document(config)
    host = document.hosts_by_id[2]
    rendered = render_table(
        config,
        document,
        host,
        neighbor_mode="observed_by",
        system_only=False,
    )
    assert "Observed_by" in rendered
    assert "198.51.100.22" in rendered


def test_csv_system_only_is_comments_only_and_json_is_standalone(tmp_path: Path) -> None:
    """System-only CSV omits header/rows and JSON preserves the selected ID only."""

    _write_discovery(tmp_path)
    document = load_discovery_document(_config(tmp_path))
    host = document.hosts_by_id[1]

    csv_text = render_csv(document, host, neighbor_mode=None, system_only=True)
    assert csv_text.count("\n") == 1
    assert csv_text.startswith("# id=1,")
    assert "direction,local_interface" not in csv_text

    json_text = render_json(host, neighbor_mode=None, system_only=True, indent=2)
    payload = json.loads(json_text)
    assert payload["id"] == 1
    assert "hosts" not in payload
    assert "learned_neighbors" not in payload
    assert "observed_by_neighbors" not in payload


def test_cli_lists_ambiguous_matches_with_ids_and_names(tmp_path: Path, capsys) -> None:
    """Ambiguous selection never picks an arbitrary host for a renderer."""

    _write_discovery(tmp_path)
    with pytest.raises(SystemExit) as exc:
        show_neighbors_main(["--persistent-root", str(tmp_path), "client-13.001"])

    assert exc.value.code == 3
    output = capsys.readouterr().out
    assert "Multiple records matched" in output
    assert "1  client-137001.example.com" in output
    assert "2  client-135001.example.com" in output


def test_show_neighbors_detail_with_neighbors_receives_effective_config(
    tmp_path: Path, capsys
) -> None:
    """Detail rendering with neighbors must not reference an unbound config."""

    _write_discovery(tmp_path)
    show_neighbors_main(["--persistent-root", str(tmp_path), "--id", "1", "--detail"])

    output = capsys.readouterr().out
    assert "LLDP-Runner discovery record" in output
    assert "Neighbor 1" in output
    assert "Remote port:" not in output  # Stored detail uses persisted key names.


def test_graph_relationship_views_are_sectioned_or_combined(tmp_path: Path) -> None:
    """Authoritative graph views expose ambiguity without guessing directness."""

    _write_discovery(tmp_path)
    config = _config(tmp_path)
    document = load_discovery_document(config)
    host = document.hosts_by_id[1]
    document.payload["topology_graph"] = {
        "schema_version": 2,
        "authority": {
            "observation_completeness": "complete",
            "observation_projection": "authoritative",
            "entity_resolution": "provisional",
            "physical_topology": "not_inferred",
            "directness": "unresolved",
            "compatibility_projection": "diagnostic",
        },
        "entities": [
            {
                "entity_key": "logical:source",
                "entity_type": "logical_system",
                "display_name": "client-137001.example.com",
                "host_refs": [1],
                "identity": {"addresses": ["198.51.100.22"]},
            },
            {
                "entity_key": "logical:left",
                "entity_type": "logical_system",
                "display_name": "hq-vdc2-7nx1",
                "host_refs": [2],
                "identity": {"addresses": ["203.0.113.24"]},
            },
            {
                "entity_key": "logical:right",
                "entity_type": "logical_system",
                "display_name": "hq-vdc3-7nx1",
                "host_refs": [3],
                "identity": {"addresses": ["203.0.113.21"]},
            },
        ],
        "relationship_groups": [
            {
                "group_key": "group:1",
                "source_entity_key": "logical:source",
                "interface_key": "interface:1",
                "local_interface": "Gi0/0/3",
                "classification": "multiple_neighbor_observations",
                "members": [
                    {
                        "remote_entity_key": "logical:left",
                        "remote_name": "hq-vdc2-7nx1",
                        "remote_interface": "mgmt0",
                        "protocols": ["cdp"],
                        "multiplicity": 1,
                    },
                    {
                        "remote_entity_key": "logical:right",
                        "remote_name": "hq-vdc3-7nx1",
                        "remote_interface": "mgmt0",
                        "protocols": ["cdp"],
                        "multiplicity": 1,
                    },
                ],
            }
        ],
    }

    sectioned = render_table(
        config,
        document,
        host,
        neighbor_mode="learned",
        relationship_view="sectioned",
        system_only=False,
        stream=_Plain(),
    )
    assert "Multiple neighbor observations (directness unresolved)" in sectioned
    assert "Review required" in sectioned
    assert "hq-vdc2-7nx1" in sectioned
    assert "hq-vdc3-7nx1" in sectioned

    combined = render_table(
        config,
        document,
        host,
        neighbor_mode="learned",
        relationship_view="combined",
        system_only=False,
        stream=_Plain(),
    )
    assert "Relationship labels:" in combined
    assert "M:cdp" in combined
    assert "directness is not inferred" not in combined


def test_cli_relationship_view_overrides_configuration(tmp_path: Path, capsys) -> None:
    """The dedicated CLI control accepts either graph relationship layout."""

    _write_discovery(tmp_path)
    show_neighbors_main(
        [
            "--persistent-root",
            str(tmp_path),
            "--id",
            "1",
            "--relationship-view",
            "combined",
        ]
    )
    assert "LLDP-Runner discovery record" in capsys.readouterr().out


def test_lldp_runner_show_neighbors_supports_combined_filters(tmp_path: Path, capsys) -> None:
    """The main CLI subcommand shares the standalone show-neighbors query contract."""

    _write_discovery(tmp_path)
    main(
        [
            "show-neighbors",
            "--persistent-root",
            str(tmp_path),
            "--name",
            "client-13",
            "--ipv4",
            "198.51.100.0/24",
            "--key",
            "system.model:^C9300",
            "--json",
            "--system-only",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["id"] == 1
    assert payload["preferred_name"] == "client-137001.example.com"


def test_cli_rejects_system_only_neighbors_and_invalid_regex(tmp_path: Path, capsys) -> None:
    """Contradictory neighbor controls and bad filters are argparse usage errors."""

    _write_discovery(tmp_path)
    with pytest.raises(SystemExit) as exc:
        show_neighbors_main(
            [
                "--persistent-root",
                str(tmp_path),
                "--id",
                "1",
                "--system-only",
                "--neighbors",
                "learned",
            ]
        )
    assert exc.value.code == 2
    assert "cannot be combined" in capsys.readouterr().err

    with pytest.raises(SystemExit) as exc:
        show_neighbors_main(["--persistent-root", str(tmp_path), "[bad"])
    assert exc.value.code == 2
    assert "invalid name regex" in capsys.readouterr().err


def test_viewer_can_select_runid_or_arbitrary_file(tmp_path: Path, monkeypatch, capsys) -> None:
    """Alternate viewer inputs preserve the same query/rendering contract."""

    latest = _write_discovery(tmp_path)
    run_path = tmp_path / "outputs" / "run-07" / "discovery.json"
    run_path.parent.mkdir(parents=True)
    run_path.write_bytes(latest.read_bytes())

    config = _config(tmp_path)
    by_run = load_discovery_document(config, run_id="run-07")
    assert by_run.path == run_path
    assert by_run.hosts_by_id[1]["preferred_name"] == "client-137001.example.com"

    archive = tmp_path / "archive" / "saved.json"
    archive.parent.mkdir()
    archive.write_bytes(latest.read_bytes())
    monkeypatch.chdir(tmp_path)
    show_neighbors_main(["--file", "archive/saved.json", "--id", "1", "--json"])
    assert json.loads(capsys.readouterr().out)["id"] == 1


def test_viewer_source_options_are_exclusive_and_runid_is_one_component(
    tmp_path: Path, capsys
) -> None:
    """Source ambiguity and traversal-like run IDs fail as CLI usage errors."""

    _write_discovery(tmp_path)
    with pytest.raises(SystemExit) as exc:
        show_neighbors_main(
            [
                "--persistent-root",
                str(tmp_path),
                "--runid",
                "run-01",
                "--file",
                "saved.json",
                "--id",
                "1",
            ]
        )
    assert exc.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err

    with pytest.raises(SystemExit) as exc:
        show_neighbors_main(
            ["--persistent-root", str(tmp_path), "--runid", "../run-01", "--id", "1"]
        )
    assert exc.value.code == 2
    assert "one non-empty path component" in capsys.readouterr().err


def test_file_source_does_not_require_persistent_root_to_exist(tmp_path: Path, capsys) -> None:
    """An exported discovery file is usable independently of persistent storage."""

    source_root = tmp_path / "source"
    latest = _write_discovery(source_root)
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'[paths]\npersistent_root = "{tmp_path / "missing-root"}"\n',
        encoding="utf-8",
    )
    show_neighbors_main(
        [
            "--config",
            str(config_path),
            "--file",
            str(latest),
            "--id",
            "2",
            "--json",
        ]
    )
    assert json.loads(capsys.readouterr().out)["id"] == 2


def test_show_neighbors_ignores_entire_credential_subsystem(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Stored-data viewing is independent of malformed or partial SNMP policy.

    This covers both configured credential structures and generic runtime SNMP
    environment variables. A network-capable load of the same configuration
    remains strict, proving that the bypass is scoped to ``CredentialMode.DISABLED``.
    """

    source_root = tmp_path / "source"
    discovery_file = _write_discovery(source_root)
    config_path = tmp_path / "viewer.toml"
    config_path.write_text(
        """
[credentials.broken]
version = "v3"
unsupported_setting = true

[credential_profiles.broken]
primary = "missing-credential"

[credential_rules]
unsupported_rule_setting = true
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("SNMPUSER", "partial-v3-user")
    monkeypatch.delenv("SNMPAUTH", raising=False)
    monkeypatch.delenv("SNMPPRIV", raising=False)

    def fail_backend_boundary(*_args, **_kwargs):
        raise AssertionError("read-only show-neighbors entered the SNMP backend")

    monkeypatch.setattr(
        "lldp_runner.snmp.selection.select_snmp_backend",
        fail_backend_boundary,
    )
    monkeypatch.setattr(
        "lldp_runner.snmp.create_snmp_client",
        fail_backend_boundary,
    )
    monkeypatch.setattr(
        "lldp_runner.cli.preflight_snmp_backend",
        fail_backend_boundary,
    )

    show_neighbors_main(
        [
            "--config",
            str(config_path),
            "--file",
            str(discovery_file),
            "--id",
            "1",
            "--json",
        ]
    )
    assert json.loads(capsys.readouterr().out)["id"] == 1

    with pytest.raises(ConfigError) as exc_info:
        load_config(
            config_path,
            env={"SNMPUSER": "partial-v3-user"},
            credential_mode=CredentialMode.REQUIRED,
            resolve_paths=False,
        )
    assert "credential" in str(exc_info.value).lower()


def test_disabled_credential_mode_does_not_synthesize_runtime_credentials() -> None:
    """Read-only config loading never inspects partial generic SNMP variables."""

    config = load_config(
        None,
        env={"SNMPUSER": "partial-v3-user"},
        credential_mode=CredentialMode.DISABLED,
        resolve_paths=False,
    )

    assert config.credentials == {}
    assert config.credential_profiles == {}
    assert config.credential_rules.address == []
    assert config.credential_rules.name == []
