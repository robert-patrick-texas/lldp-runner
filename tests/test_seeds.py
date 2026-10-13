"""Regression coverage for reusable seed inventory input/output behavior."""

from __future__ import annotations

import csv
from argparse import Namespace
from pathlib import Path

import pytest

from lldp_runner.cli import _collect_seeds, _read_seed_file
from lldp_runner.models import Candidate, SeedInput
from lldp_runner.outputs import write_outputs
from lldp_runner.seeds import SEED_CSV_COLUMNS, parse_text_seed_line, read_seed_directory
from lldp_runner.state import StateStore


def test_seed_csv_input_reuses_query_target_and_all_address_aliases(tmp_path: Path) -> None:
    """A generated seed inventory must remain useful when DNS later becomes unavailable."""

    path = tmp_path / "seeds.csv"
    path.write_text(
        "preferred_name,queried_as,ipv4,ipv6,credential_profile,credential_result,origin,state,last_seen,notes\n"
        "switch1.net.example.com,198.18.20.17,198.18.20.17;198.18.20.18,"
        "2001:db8:100::17,default,primary,learned,complete,2026-08-20T09:00:00-04:00,\n",
        encoding="utf-8",
    )

    seeds = _read_seed_file(path)

    assert len(seeds) == 1
    assert seeds[0].seed == "switch1.net.example.com"
    assert seeds[0].query_target == "198.18.20.17"
    assert seeds[0].ipv4 == ["198.18.20.17", "198.18.20.18"]
    assert seeds[0].ipv6 == ["2001:db8:100::17"]
    assert seeds[0].prior_state == "complete"
    assert seeds[0].addresses() == [
        "198.18.20.17",
        "198.18.20.18",
        "2001:db8:100::17",
    ]


def test_seed_csv_filters_non_host_address_hints(tmp_path: Path) -> None:
    """Reusable inventory cannot reintroduce sentinel/broadcast host aliases."""

    path = tmp_path / "bogus-addresses.csv"
    path.write_text(
        "preferred_name,queried_as,ipv4,ipv6,credential_profile,credential_result,"
        "origin,state,last_seen,notes\n"
        "esxi-a.example.com,0.0.0.0,0.0.0.0;255.255.255.255;169.254.100.10,"
        "::;fe80::1,default,primary,learned,complete,2026-08-28T02:55:00-04:00,\n",
        encoding="utf-8",
    )

    seed = _read_seed_file(path)[0]

    assert seed.query_target is None
    assert seed.ipv4 == ["169.254.100.10"]
    assert seed.ipv6 == ["fe80::1"]
    assert any("unspecified address" in error for error in seed.parse_errors)
    assert any("limited-broadcast address" in error for error in seed.parse_errors)


def test_seed_csv_input_rejects_previous_0182_schema(tmp_path: Path) -> None:
    """The v0.18.2 seed schema is rejected after JSON/CSV name reconciliation."""

    path = tmp_path / "previous-seeds.csv"
    path.write_text(
        "seed,query_target,ipv4,ipv6,credential_profile,credential_result,"
        "origin,status,last_seen,notes\n"
        "switch1.net.example.com,198.18.20.17,198.18.20.17,,default,"
        "primary,seed,complete,2026-08-20T09:00:00-04:00,\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing expected header field"):
        _read_seed_file(path)


def test_seed_csv_input_accepts_reordered_case_insensitive_columns(tmp_path: Path) -> None:
    """Reusable seed CSV input is keyed by header name rather than position."""

    path = tmp_path / "reordered-seeds.csv"
    path.write_text(
        "NOTES,IPV6,PREFERRED_NAME,STATE,IPV4,ORIGIN,LAST_SEEN,"
        "CREDENTIAL_RESULT,QUERIED_AS,CREDENTIAL_PROFILE,ignored\n"
        "note,2001:db8:100::17,switch1.net.example.com,complete,"
        "198.18.20.17;198.18.20.18,learned,2026-08-20T09:00:00-04:00,"
        "primary,198.18.20.17,default,discard me\n",
        encoding="utf-8",
    )

    seeds = _read_seed_file(path)

    assert len(seeds) == 1
    assert seeds[0].seed == "switch1.net.example.com"
    assert seeds[0].query_target == "198.18.20.17"
    assert seeds[0].ipv4 == ["198.18.20.17", "198.18.20.18"]
    assert seeds[0].ipv6 == ["2001:db8:100::17"]


def test_plain_seed_lines_trim_metadata_and_comments() -> None:
    """Text seed parsing keeps only the target before comma/semicolon/hash metadata."""

    assert (
        parse_text_seed_line("  switch1.net.example.com, core switch  ")
        == "switch1.net.example.com"
    )
    assert parse_text_seed_line("198.18.10.5 ; temporary") == "198.18.10.5"
    assert parse_text_seed_line("2001:db8::10 # IPv6 target") == "2001:db8::10"
    assert parse_text_seed_line("  ; disabled by operator") is None
    assert parse_text_seed_line("  # comment") is None
    assert parse_text_seed_line("   ") is None
    assert parse_text_seed_line(", comment without a seed") is None


def test_seed_directory_recurses_and_skips_control_files(tmp_path: Path) -> None:
    """Recursive seed directories read eligible files and ignore operator control files."""

    root = tmp_path / "seeds.d"
    (root / "sub").mkdir(parents=True)
    (root / ".hidden-dir").mkdir()

    (root / "10-core.txt").write_text(
        "core1.net.example.com, primary core\n ; comment line\n198.18.10.11 # address seed\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text("do not parse me\n", encoding="utf-8")
    (root / "20-old.disabled").write_text("disabled.example.com\n", encoding="utf-8")
    (root / "30-notes.note").write_text("notes.example.com\n", encoding="utf-8")
    (root / ".hidden").write_text("hidden.example.com\n", encoding="utf-8")
    (root / ".hidden-dir" / "hosts.txt").write_text("hidden-dir.example.com\n", encoding="utf-8")
    (root / "sub" / "20-edge.list").write_text(
        "edge1.net.example.com ; access\n2001:db8::20\n",
        encoding="utf-8",
    )
    (root / "sub" / "30-inventory.csv").write_text(
        ",".join(SEED_CSV_COLUMNS) + "\n"
        "switch2.net.example.com,198.18.20.17,198.18.20.17;198.18.20.18,"
        "2001:db8:100::17,default,primary,learned,complete,2026-08-20T09:00:00-04:00,\n",
        encoding="utf-8",
    )

    seeds = read_seed_directory(root)

    assert [seed.seed for seed in seeds] == [
        "core1.net.example.com",
        "198.18.10.11",
        "edge1.net.example.com",
        "2001:db8::20",
        "switch2.net.example.com",
    ]
    csv_seed = seeds[-1]
    assert csv_seed.query_target == "198.18.20.17"
    assert csv_seed.ipv4 == ["198.18.20.17", "198.18.20.18"]
    assert csv_seed.ipv6 == ["2001:db8:100::17"]


def test_collect_seeds_adds_config_cli_and_environment_directories(
    tmp_path: Path, config, monkeypatch
) -> None:
    """Seed directories are additive across configuration, CLI, and environment sources."""

    config_dir = tmp_path / "config-seeds"
    cli_dir = tmp_path / "cli-seeds"
    env_dir = tmp_path / "env-seeds"
    for directory, value in (
        (config_dir, "config-router.net.example.com"),
        (cli_dir, "cli-router.net.example.com"),
        (env_dir, "env-router.net.example.com"),
    ):
        directory.mkdir()
        (directory / "targets.txt").write_text(value + "\n", encoding="utf-8")

    config.discovery.seed_dirs = [str(config_dir)]
    monkeypatch.setenv("LLDP_RUNNER_SEED_DIRS", str(env_dir))
    args = Namespace(seed=[], seed_file=[], seed_dir=[str(cli_dir)], stdin=False)

    seeds = _collect_seeds(args, config)

    assert [seed.seed for seed in seeds] == [
        "config-router.net.example.com",
        "cli-router.net.example.com",
        "env-router.net.example.com",
    ]


def test_collect_seeds_reports_raw_count_before_textual_deduplication(config, monkeypatch) -> None:
    """Startup reporting distinguishes raw records from input identity de-duplication."""

    config.discovery.seeds = ["switch1.net.example.com", "switch1.net.example.com"]
    monkeypatch.delenv("LLDP_RUNNER_SEEDS", raising=False)
    args = Namespace(seed=["switch2.net.example.com"], seed_file=[], seed_dir=[], stdin=False)
    raw_counts: list[int] = []

    seeds = _collect_seeds(args, config, raw_count_capture=raw_counts)

    assert raw_counts == [3]
    assert [seed.seed for seed in seeds] == [
        "switch1.net.example.com",
        "switch2.net.example.com",
    ]


def test_seed_directory_rejects_legacy_csv_in_nested_tree(tmp_path: Path) -> None:
    """A legacy CSV cannot bypass the current-schema requirement via seed_dir."""

    root = tmp_path / "seeds.d"
    root.mkdir()
    (root / "old.csv").write_text(
        "seed,query_target,status\nold.example.com,198.18.10.1,complete\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing expected header field"):
        read_seed_directory(root)


def test_coordinator_seed_add_uses_csv_address_hints_when_dns_has_no_addresses(
    tmp_path: Path, config, monkeypatch
) -> None:
    """A prior query target keeps a seed queryable even during a DNS outage."""

    from lldp_runner.classify import Classifier
    from lldp_runner.coordinator import Coordinator
    from lldp_runner.identity import ResolvedIdentity
    from lldp_runner.models import SeedInput

    state = StateStore(tmp_path / "state.sqlite")
    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.classifier = Classifier(config)
    coordinator.state = state
    scheduled: list[int] = []
    coordinator._schedule_if_queryable = scheduled.append

    monkeypatch.setattr(
        "lldp_runner.identity.resolve_seed",
        lambda seed, suffixes: ResolvedIdentity(
            original=seed,
            preferred_name=seed,
            names=[seed],
            addresses=[],
            errors=["temporary DNS failure"],
        ),
    )

    coordinator._add_seed(
        SeedInput(
            seed="switch1.net.example.com",
            query_target="198.18.20.17",
            ipv4=["198.18.20.18"],
            source="seeds.csv",
        )
    )

    hosts = state.all_hosts()
    assert len(hosts) == 1
    _names, addresses, _chassis = state.aliases_for_host(int(hosts[0]["id"]))
    assert addresses == ["198.18.20.17", "198.18.20.18"]
    assert scheduled == [int(hosts[0]["id"])]
    state.close()


def test_skip_addressed_seed_dns_reuses_confirmed_inventory_without_resolver(
    tmp_path: Path, config, monkeypatch
) -> None:
    """A complete reusable seed can bypass DNS while keeping all supplied addresses."""

    from lldp_runner.classify import Classifier
    from lldp_runner.coordinator import Coordinator

    config.discovery.seed_dns_mode = "skip-addressed"
    state = StateStore(tmp_path / "state.sqlite")
    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.classifier = Classifier(config)
    coordinator.state = state
    scheduled: list[int] = []
    coordinator._schedule_if_queryable = scheduled.append

    def fail_resolver(*args, **kwargs):
        del args, kwargs
        raise AssertionError("resolver must not be called for eligible skip-addressed seed")

    monkeypatch.setattr("lldp_runner.identity.resolve_seed", fail_resolver)

    action = coordinator._add_seed(
        SeedInput(
            seed="switch1.net.example.com",
            query_target="198.18.20.17",
            ipv4=["198.18.20.18"],
            prior_state="complete",
            source="seeds.csv",
        )
    )

    assert action == "skipped"
    host = state.all_hosts()[0]
    names, addresses, _chassis = state.aliases_for_host(int(host["id"]))
    assert names == ["switch1.net.example.com"]
    assert addresses == ["198.18.20.17", "198.18.20.18"]
    assert scheduled == [int(host["id"])]
    state.close()


def test_skip_addressed_seed_dns_falls_back_for_failed_prior_state(
    tmp_path: Path, config, monkeypatch
) -> None:
    """A failed historical row receives fresh DNS even when queried_as is present."""

    from lldp_runner.classify import Classifier
    from lldp_runner.coordinator import Coordinator
    from lldp_runner.identity import ResolvedIdentity

    config.discovery.seed_dns_mode = "skip-addressed"
    state = StateStore(tmp_path / "state.sqlite")
    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.classifier = Classifier(config)
    coordinator.state = state
    coordinator._schedule_if_queryable = lambda host_id: None
    calls: list[str] = []

    def resolver(seed, suffixes):
        del suffixes
        calls.append(seed)
        return ResolvedIdentity(seed, seed, [seed], ["198.18.20.19"])

    monkeypatch.setattr("lldp_runner.identity.resolve_seed", resolver)

    action = coordinator._add_seed(
        SeedInput(
            seed="switch1.net.example.com",
            query_target="198.18.20.17",
            prior_state="failed",
        )
    )

    assert action == "resolved"
    assert calls == ["switch1.net.example.com"]
    state.close()


def test_skip_addressed_seed_dns_does_not_skip_ip_only_input(
    tmp_path: Path, config, monkeypatch
) -> None:
    """An IP-only row keeps reverse/canonical resolver behavior for name enrichment."""

    from lldp_runner.classify import Classifier
    from lldp_runner.coordinator import Coordinator
    from lldp_runner.identity import ResolvedIdentity

    config.discovery.seed_dns_mode = "skip-addressed"
    state = StateStore(tmp_path / "state.sqlite")
    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.classifier = Classifier(config)
    coordinator.state = state
    coordinator._schedule_if_queryable = lambda host_id: None
    calls: list[str] = []

    def resolver(seed, suffixes):
        del suffixes
        calls.append(seed)
        return ResolvedIdentity(
            seed,
            "switch1.net.example.com",
            ["switch1.net.example.com"],
            [seed],
        )

    monkeypatch.setattr("lldp_runner.identity.resolve_seed", resolver)

    coordinator._add_seed(
        SeedInput(
            seed="198.18.20.17",
            query_target="198.18.20.17",
            prior_state="complete",
        )
    )

    assert calls == ["198.18.20.17"]
    state.close()


def test_seed_csv_output_has_stable_schema_statuses_and_missing_target_error(
    tmp_path: Path, config
) -> None:
    """Seed output carries aliases and explains blank targets in terminal states."""

    state = StateStore(tmp_path / "state.sqlite")
    complete = state.upsert_candidate(
        Candidate(
            names=["complete.net.example.com"],
            addresses=["198.18.10.1", "2001:db8::10"],
            category="managed_device",
        ),
        is_seed=True,
    )
    state.conn.execute(
        """
        UPDATE hosts SET state='COMPLETE', query_target='198.18.10.1',
            credential_profile='default', credential_result='primary'
        WHERE id=?
        """,
        (complete,),
    )
    state.conn.commit()

    failed = state.upsert_candidate(
        Candidate(
            names=["failed.net.example.com"],
            addresses=["198.18.10.2"],
            category="managed_device",
        )
    )
    state.conn.execute(
        "UPDATE hosts SET state='FAILED', query_target='198.18.10.2' WHERE id=?",
        (failed,),
    )
    state.conn.commit()
    state.add_error(
        failed,
        "snmp_basic",
        "timeout",
        "request timed out",
        final_device_status="FAILED",
    )

    no_query = state.upsert_candidate(
        Candidate(names=["blocked.net.example.com"], category="managed_device")
    )
    state.conn.execute("UPDATE hosts SET state='NO_QUERY' WHERE id=?", (no_query,))
    state.conn.commit()

    out_of_scope = state.upsert_candidate(
        Candidate(
            names=["outside.net.example.com"],
            addresses=["203.0.113.5"],
            category="managed_device",
        )
    )
    state.conn.execute("UPDATE hosts SET state='OUT_OF_SCOPE' WHERE id=?", (out_of_scope,))
    state.conn.commit()

    inconsistent = state.upsert_candidate(
        Candidate(
            names=["inconsistent-complete.net.example.com"],
            addresses=["198.18.10.9"],
            category="managed_device",
        )
    )
    state.conn.execute(
        "UPDATE hosts SET state='COMPLETE', query_target=NULL WHERE id=?",
        (inconsistent,),
    )
    state.conn.commit()

    output = tmp_path / "outputs"
    write_outputs(state, config, output, run_id="run1", status="COMPLETED", draft=False)
    # A second snapshot must not duplicate integrity errors.
    write_outputs(state, config, output, run_id="run1", status="COMPLETED", draft=False)

    with (output / "seeds.csv").open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == [
            "preferred_name",
            "queried_as",
            "ipv4",
            "ipv6",
            "credential_profile",
            "credential_result",
            "origin",
            "state",
            "last_seen",
            "notes",
        ]
        rows = {row["preferred_name"]: row for row in reader}

    assert rows["complete.net.example.com"]["origin"] == "seed"
    assert rows["complete.net.example.com"]["state"] == "complete"
    assert rows["complete.net.example.com"]["queried_as"] == "198.18.10.1"
    assert rows["complete.net.example.com"]["ipv4"] == "198.18.10.1"
    assert rows["complete.net.example.com"]["ipv6"] == "2001:db8::10"

    assert rows["failed.net.example.com"]["origin"] == "learned"
    assert rows["failed.net.example.com"]["state"] == "failed"
    assert "snmp_basic/timeout: request timed out" in rows["failed.net.example.com"]["notes"]
    assert rows["blocked.net.example.com"]["state"] == "no_query"
    assert "missing_query_target" in rows["blocked.net.example.com"]["notes"]
    assert rows["outside.net.example.com"]["state"] == "out_of_scope"

    broken = rows["inconsistent-complete.net.example.com"]
    assert broken["state"] == "complete"
    assert broken["queried_as"] == ""
    assert "internally inconsistent" in broken["notes"]

    missing_errors = [
        row
        for row in state.errors_for_host(inconsistent)
        if row["category"] == "missing_query_target"
    ]
    assert len(missing_errors) == 1
    assert not bool(missing_errors[0]["recoverable"])

    with (output / "errors.csv").open(encoding="utf-8", newline="") as fh:
        reported = list(csv.DictReader(fh))
    assert any(
        row["device"] == "inconsistent-complete.net.example.com"
        and row["category"] == "missing_query_target"
        for row in reported
    )
    state.close()


def test_reused_learned_seed_row_becomes_seed_in_later_run(
    tmp_path: Path, config, monkeypatch
) -> None:
    """Prior ``learned`` provenance must not survive explicit reuse as seed input.

    The origin column describes how an identity entered the *current* run. A
    learned managed device written by run one therefore becomes an explicit seed
    when that row is supplied to run two.
    """

    from lldp_runner.classify import Classifier
    from lldp_runner.coordinator import Coordinator
    from lldp_runner.identity import ResolvedIdentity

    inventory = tmp_path / "seeds.csv"
    inventory.write_text(
        ",".join(SEED_CSV_COLUMNS)
        + "\n"
        + "learned-switch.net.example.com,198.18.20.30,198.18.20.30,,"
        + "default,primary,learned,complete,2026-08-24T05:00:00-04:00,\n",
        encoding="utf-8",
    )
    imported = _read_seed_file(inventory)
    assert len(imported) == 1

    state = StateStore(tmp_path / "run-two.sqlite")
    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.classifier = Classifier(config)
    coordinator.state = state
    coordinator._schedule_if_queryable = lambda _host_id: None

    monkeypatch.setattr(
        "lldp_runner.identity.resolve_seed",
        lambda seed, suffixes: ResolvedIdentity(
            original=seed,
            preferred_name=seed,
            names=[seed],
            addresses=[],
            errors=[],
        ),
    )

    coordinator._add_seed(imported[0])
    row = state.all_hosts()[0]
    assert bool(row["is_seed"])

    output = tmp_path / "run-two-output"
    write_outputs(state, config, output, run_id="run-two", status="RUNNING", draft=False)
    with (output / "seeds.csv").open(encoding="utf-8", newline="") as fh:
        exported = next(csv.DictReader(fh))
    assert exported["origin"] == "seed"
    state.close()


def test_seed_integrity_ignores_transient_states_and_clears_stale_snapshot_error(
    tmp_path: Path, config
) -> None:
    """CLAIMED without a target is normal and must not become a permanent error.

    This reproduces the v0.7.0 failure mode where a periodic draft snapshot could
    persist ``missing_query_target`` while a worker still owned the device.  The
    same host could later complete successfully yet keep the obsolete error in
    seeds.csv notes.
    """

    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(
            names=["worker-active.net.example.com"],
            addresses=["198.18.20.21"],
            category="managed_device",
        )
    )
    state.conn.execute("UPDATE hosts SET state='CLAIMED', query_target=NULL WHERE id=?", (host_id,))
    state.conn.commit()

    # Simulate the stale diagnostic a v0.7.0 draft snapshot could have persisted.
    state.ensure_error(
        host_id,
        "seed_inventory_validation",
        "missing_query_target",
        "managed device status CLAIMED has no query_target at snapshot time",
        recoverable=True,
        final_device_status="CLAIMED",
    )

    output = tmp_path / "outputs"
    write_outputs(state, config, output, run_id="run1", status="RUNNING", draft=False)
    assert not [
        row
        for row in state.errors_for_host(host_id)
        if row["operation"] == "seed_inventory_validation"
        and row["category"] == "missing_query_target"
    ]

    # Once the worker succeeds, a valid target must also keep that stale condition
    # cleared from both errors.csv and seeds.csv notes.
    state.conn.execute(
        "UPDATE hosts SET state='COMPLETE', query_target='198.18.20.21' WHERE id=?",
        (host_id,),
    )
    state.conn.commit()
    state.ensure_error(
        host_id,
        "seed_inventory_validation",
        "missing_query_target",
        "managed device status CLAIMED has no query_target at snapshot time",
        recoverable=True,
        final_device_status="CLAIMED",
    )
    write_outputs(state, config, output, run_id="run1", status="COMPLETED", draft=False)

    with (output / "seeds.csv").open(encoding="utf-8", newline="") as fh:
        row = next(csv.DictReader(fh))
    assert row["state"] == "complete"
    assert row["queried_as"] == "198.18.20.21"
    assert "missing_query_target" not in row["notes"]

    # With the v0.16 global empty-CSV policy, successfully clearing the only
    # diagnostic means errors.csv itself is omitted rather than header-only.
    assert not (output / "errors.csv").exists()
    state.close()
