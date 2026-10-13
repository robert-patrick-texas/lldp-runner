from __future__ import annotations

from pathlib import Path

import pytest

from lldp_runner.config import (
    ConfigError,
    CredentialMode,
    load_config,
    validate_config,
)
from lldp_runner.runtime import (
    allocate_run_id,
    clean_completed_scratch,
    ensure_run_directories,
    find_resumable_run,
    make_run_paths,
    publish_latest_symlink,
)


def test_toml_paths_are_normalized_to_path(config_file: Path) -> None:
    config = load_config(config_file)

    assert isinstance(config.paths.persistent_root, Path)
    assert isinstance(config.paths.scratch_root, Path)


def test_runtime_path_operations_work_with_toml_paths(config_file: Path) -> None:
    config = load_config(config_file)

    assert find_resumable_run(config) is None

    paths = make_run_paths(config, "20260101-103600")
    assert paths.run_dir == config.paths.persistent_root / "runs" / "20260101-103600"
    assert paths.scratch_dir == config.paths.scratch_root / "20260101-103600"
    assert paths.scoreboard_dir == config.paths.scratch_root / "scoreboard"
    assert paths.run_latest_link == config.paths.persistent_root / "runs" / "latest"
    assert paths.latest_link == config.paths.persistent_root / "outputs" / "latest"


def test_reserved_scoreboard_name_cannot_be_used_as_run_id(config) -> None:
    """The live publication directory cannot also become per-run scratch."""

    config.paths.run_id_format = "scoreboard"
    with pytest.raises(ValueError, match="reserved scratch name: scoreboard"):
        allocate_run_id(config)

    with pytest.raises(ValueError, match="reserved scratch name: scoreboard"):
        make_run_paths(config, "scoreboard")


def test_run_directory_setup_preflights_storage_without_empty_final_output(
    config_file: Path,
) -> None:
    """Successful preflight leaves no fake completed output directory behind."""

    config = load_config(config_file)
    paths = make_run_paths(config, "20260102-160900-EDT")
    prior_output = paths.output_root / "20260102-150000-EDT"
    prior_output.mkdir(parents=True)
    paths.latest_link.symlink_to(prior_output.name)

    ensure_run_directories(paths)

    assert paths.run_dir.is_dir()
    assert paths.scratch_dir.is_dir()
    assert paths.scoreboard_dir.is_dir()
    assert paths.output_root.is_dir()
    assert not paths.output_run_dir.exists()
    current = paths.scratch_dir.parent / "current"
    assert current.is_symlink()
    assert current.resolve() == paths.scratch_dir.resolve()
    assert not list(paths.scratch_dir.glob(".lldp-runner-preflight-*"))
    assert not list(paths.scoreboard_dir.glob(".lldp-runner-preflight-*"))
    assert not list(paths.output_root.glob(".lldp-runner-*-preflight-*"))
    assert not list(paths.run_dir.parent.glob(".lldp-runner-*-preflight-*"))


def test_run_storage_preflight_preserves_existing_output_directory(
    config_file: Path,
) -> None:
    """A resumable/partial final directory is tested but never removed."""

    config = load_config(config_file)
    paths = make_run_paths(config, "20260102-161000-EDT")
    paths.output_run_dir.mkdir(parents=True)
    sentinel = paths.output_run_dir / "prior-output.txt"
    sentinel.write_text("keep me\n", encoding="utf-8")

    ensure_run_directories(paths)

    assert paths.output_run_dir.is_dir()
    assert sentinel.read_text(encoding="utf-8") == "keep me\n"


def test_run_storage_preflight_rejects_non_symlink_latest_path(
    config_file: Path,
) -> None:
    """A conflicting real `latest` directory fails before discovery starts."""

    config = load_config(config_file)
    paths = make_run_paths(config, "20260102-161050-EDT")
    paths.output_root.mkdir(parents=True, exist_ok=True)
    paths.latest_link.mkdir()

    with pytest.raises(
        OSError,
        match="persistent output latest path exists and is not a symlink",
    ):
        ensure_run_directories(paths)

    assert paths.latest_link.is_dir()
    assert not (paths.scratch_dir.parent / "current").exists()


def test_run_storage_preflight_rejects_non_symlink_run_latest_path(
    config_file: Path,
) -> None:
    """A real ``runs/latest`` entry cannot be silently replaced after discovery."""

    config = load_config(config_file)
    paths = make_run_paths(config, "20260102-161055-EDT")
    paths.run_dir.parent.mkdir(parents=True, exist_ok=True)
    paths.run_latest_link.mkdir()

    with pytest.raises(
        OSError,
        match="persistent run latest path exists and is not a symlink",
    ):
        ensure_run_directories(paths)

    assert paths.run_latest_link.is_dir()
    assert not (paths.scratch_dir.parent / "current").exists()


def test_publish_latest_symlink_atomically_replaces_prior_target(tmp_path: Path) -> None:
    """The shared publisher keeps a relative link and replaces only symlinks."""

    root = tmp_path / "runs"
    prior = root / "run-prior"
    completed = root / "run-completed"
    prior.mkdir(parents=True)
    completed.mkdir()
    latest = root / "latest"
    latest.symlink_to(prior.name)

    publish_latest_symlink(latest, completed)

    assert latest.is_symlink()
    assert latest.readlink() == Path(completed.name)
    assert latest.resolve() == completed.resolve()


def test_clean_completed_scratch_removes_exact_current_and_all_artifacts(
    config_file: Path,
) -> None:
    """Successful cleanup removes drafts, nested files, alias, and run directory."""

    config = load_config(config_file)
    paths = make_run_paths(config, "20260112-00")
    paths.run_dir.mkdir(parents=True)
    paths.output_run_dir.mkdir(parents=True)
    paths.scratch_dir.mkdir(parents=True)
    (paths.scratch_dir / "discovery.json").write_text("{}\n", encoding="utf-8")
    (paths.scratch_dir / "hosts.csv.draft").write_text("draft\n", encoding="utf-8")
    nested = paths.scratch_dir / "future-artifacts"
    nested.mkdir()
    (nested / "scoreboard.txt").write_text("status\n", encoding="utf-8")
    current = paths.scratch_dir.parent / "current"
    current.symlink_to(paths.scratch_dir.name)
    paths.scoreboard_dir.mkdir()
    (paths.scoreboard_dir / "scoreboard.json").write_text("{}\n", encoding="utf-8")

    clean_completed_scratch(paths)

    assert not paths.scratch_dir.exists()
    assert not current.exists()
    assert not current.is_symlink()
    assert paths.scoreboard_dir.is_dir()
    assert (paths.scoreboard_dir / "scoreboard.json").exists()


def test_clean_completed_scratch_preserves_current_owned_by_newer_run(
    config_file: Path,
) -> None:
    """Concurrent completion cannot remove another run's scratch alias."""

    config = load_config(config_file)
    paths = make_run_paths(config, "20260112-00")
    paths.run_dir.mkdir(parents=True)
    paths.output_run_dir.mkdir(parents=True)
    paths.scratch_dir.mkdir(parents=True)
    newer = paths.scratch_dir.parent / "20260112-01"
    newer.mkdir(parents=True)
    current = paths.scratch_dir.parent / "current"
    current.symlink_to(newer.name)

    clean_completed_scratch(paths)

    assert not paths.scratch_dir.exists()
    assert current.is_symlink()
    assert current.resolve() == newer.resolve()


def test_clean_completed_scratch_refuses_persistent_overlap(config_file: Path) -> None:
    """A dangerous path configuration cannot recursively delete durable state."""

    config = load_config(config_file)
    paths = make_run_paths(config, "20260112-00")
    paths.scratch_dir = paths.run_dir
    paths.run_dir.mkdir(parents=True)

    with pytest.raises(OSError, match="overlaps persistent storage"):
        clean_completed_scratch(paths)

    assert paths.run_dir.is_dir()


def test_run_storage_preflight_reports_persistent_output_write_failure(
    config_file: Path, monkeypatch
) -> None:
    """Atomic-output permission errors fail before scratch current is published."""

    config = load_config(config_file)
    paths = make_run_paths(config, "20260102-161100-EDT")
    original_open = Path.open

    def controlled_open(path: Path, *args, **kwargs):
        """Simulate an OS permission failure only for the final-output probe."""

        if (
            path.parent == paths.output_run_dir
            and path.name.startswith(".lldp-runner-preflight-")
        ):
            raise PermissionError("simulated persistent-output permission failure")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", controlled_open)

    with pytest.raises(
        OSError,
        match="persistent output directory cannot support atomic file output",
    ):
        ensure_run_directories(paths)

    assert not (paths.scratch_dir.parent / "current").exists()
    assert not paths.output_run_dir.exists()


def test_output_chassis_fallback_boolean_true_normalizes_to_name_like(config_file: Path):
    text = config_file.read_text(encoding="utf-8")
    text = text.replace(
        "[output]\n",
        "[output]\nchassis_id_name_fallback = true\n",
        1,
    )
    config_file.write_text(text, encoding="utf-8")
    loaded = load_config(config_file)
    assert loaded.output.chassis_id_name_fallback == "name_like"


def test_clean_scratch_default_and_type_validation(config) -> None:
    """Completed-run scratch cleanup is on by default and strictly boolean."""

    assert config.paths.clean_scratch_when_completed is True

    config.paths.clean_scratch_when_completed = "yes"  # type: ignore[assignment]
    with pytest.raises(ConfigError, match="clean_scratch_when_completed"):
        validate_config(config)



def test_neighbor_table_width_defaults_and_validation(config):
    """Table baselines default to 18 and reject unusable column widths."""

    from lldp_runner.config import ConfigError, validate_config

    assert config.output.neighbor_local_width == 18
    assert config.output.neighbor_remote_port_width == 18

    config.output.neighbor_local_width = 4
    with pytest.raises(ConfigError, match="neighbor_local_width"):
        validate_config(config)

    config.output.neighbor_local_width = 18
    config.output.neighbor_remote_port_width = 10
    with pytest.raises(ConfigError, match="neighbor_remote_port_width"):
        validate_config(config)


def test_terminal_color_defaults_and_validation(config):
    """Terminal colors keep the historical palette and reject unknown names."""

    from lldp_runner.config import ConfigError, validate_config

    assert config.terminal.color == "auto"
    assert config.terminal.palette == "dark"
    assert config.terminal.heading_color == "cyan"
    assert config.terminal.success_color == "green"
    assert config.terminal.warning_color == "yellow"
    assert config.terminal.error_color == "red"
    assert config.terminal.learned_color == "cyan"
    assert config.terminal.observed_by_color == "magenta"
    assert config.terminal.inspection_neighbor_color == "magenta"
    assert config.terminal.metric_color == "green"

    config.terminal.heading_color = "ultraviolet"
    with pytest.raises(ConfigError, match="terminal.heading_color"):
        validate_config(config)


def test_terminal_colors_load_from_toml_case_insensitively(config_file: Path) -> None:
    """Site TOML can override semantic color roles with normalized names."""

    with config_file.open("a", encoding="utf-8") as handle:
        handle.write(
            '\n[terminal]\nheading_color = "BLUE"\n'
            'observed_by_color = "RED"\nmetric_color = "none"\n'
        )

    loaded = load_config(config_file)

    assert loaded.terminal.heading_color == "blue"
    assert loaded.terminal.observed_by_color == "red"
    assert loaded.terminal.metric_color == "none"


def test_validate_config_accepts_chassis_id_subtype_evidence_fields(config):
    from lldp_runner.config import ClassificationEvidenceRule, TagRule, validate_config

    config.classification.evidence_rules = [
        ClassificationEvidenceRule(
            category="unmanaged_device",
            field_patterns={
                "chassis_id_subtype": r"^local$",
                "chassis_id_subtype_id": r"^7$",
            },
        )
    ]
    config.tagging.rules = [
        TagRule(
            field_patterns={"chassis_id_subtype": r"^(?:local|mac_address)$"},
            tags=["lldp:chassis-subtype-known"],
        )
    ]
    validate_config(config)


def test_toml_rule_lists_load_and_validate(config_file: Path) -> None:
    text = config_file.read_text(encoding="utf-8")
    text += r'''

[[query_policy.name_rules]]
patterns = ['(?i)\.ops\.example\.com$', '(?i)\.external\.example\.org$']
action = 'deny'

[[classification.address_rules]]
networks = ['198.18.220.0/24', '198.18.221.0/24']
category = 'unmanaged_device'

[[classification.name_rules]]
patterns = ['(?i)\.ops\.example\.com$', '(?i)\.branch\.example\.net$']
category = 'unmanaged_device'

[[classification.evidence_rules]]
label = 'multi-evidence'
category = 'managed_device'
name_patterns = ['(?i)-6300(?:\.|$)', '(?i)-6200(?:\.|$)']
networks = ['198.18.40.0/24', '198.18.41.0/24']
field_patterns = { remote_description = ['(?i)^HPE\s+ANW\s+JL', '(?i)^Aruba\s+JL'] }

[[tagging.rules]]
label = 'voice-groups'
category = 'managed_endpoint'
name_patterns = ['(?i)^SEP', '(?i)^VIPER-']
networks = ['198.18.64.0/20', '198.18.80.0/20']
field_patterns = { remote_description = ['(?i)Cisco.*Phone', '(?i)General Dynamics'] }
tags = ['service:voice']
'''
    config_file.write_text(text, encoding="utf-8")
    loaded = load_config(config_file)
    assert loaded.query_policy.name_rules[-1].pattern_values() == [
        r"(?i)\.ops\.example\.com$",
        r"(?i)\.external\.example\.org$",
    ]
    assert loaded.classification.address_rules[-1].network_values() == [
        "198.18.220.0/24",
        "198.18.221.0/24",
    ]
    assert loaded.classification.evidence_rules[-1].name_pattern_values()[1].startswith("(?i)-6200")


def test_discovery_seed_dirs_load_from_toml(config_file: Path) -> None:
    """The recursive seed directory list is a first-class discovery setting."""

    text = config_file.read_text(encoding="utf-8")
    text = text.replace(
        '[discovery]\n',
        '[discovery]\nseed_dirs = ["/opt/lldp-runner/seeds.d", "/srv/netops/seeds"]\n',
        1,
    )
    config_file.write_text(text, encoding="utf-8")

    loaded = load_config(config_file)

    assert loaded.discovery.seed_dirs == [
        "/opt/lldp-runner/seeds.d",
        "/srv/netops/seeds",
    ]



def test_partial_output_csv_controls_inherit_other_defaults(tmp_path: Path):
    """Operators may suppress fixed CSV views without defining the full output table."""

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[output]
write_hosts_csv = false
write_errors_csv = false
""".lstrip(),
        encoding="utf-8",
    )
    config = load_config(config_file, credential_mode=CredentialMode.OPTIONAL, resolve_paths=False)
    assert config.output.write_hosts_csv is False
    assert config.output.write_errors_csv is False
    assert config.output.write_stack_members_csv is True
    assert config.output.write_seeds_csv is True
    assert config.output.write_unknown_devices_csv is True
    assert config.output.write_empty_csv is False
    assert config.output.log_alert_on_empty_csv is False


def test_output_csv_controls_require_boolean_values(tmp_path: Path):
    """Quoted strings must not silently act as truthy CSV enable switches."""

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        '[output]\nwrite_hosts_csv = "false"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="write_hosts_csv must be true or false"):
        load_config(
            config_file,
            credential_mode=CredentialMode.OPTIONAL,
            resolve_paths=False,
        )


def test_csv_output_controls_require_boolean_values(tmp_path: Path):
    """CSV enable, empty-file, and empty-alert controls are strict Booleans."""

    for option in (
        "write_stack_members_csv",
        "write_empty_csv",
        "log_alert_on_empty_csv",
    ):
        config_file = tmp_path / f"{option}.toml"
        config_file.write_text(
            f'[output]\n{option} = "false"\n',
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match=f"{option} must be true or false"):
            load_config(
                config_file,
                credential_mode=CredentialMode.OPTIONAL,
                resolve_paths=False,
            )


def test_removed_stack_specific_empty_csv_setting_is_rejected(tmp_path: Path):
    """The v0.15 stack-only empty-file option is intentionally not retained."""

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        "[output]\nwrite_empty_stack_members_csv = false\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="write_empty_stack_members_csv"):
        load_config(config_file, credential_mode=CredentialMode.OPTIONAL, resolve_paths=False)


def test_logging_destination_defaults_and_runtime_paths(
    config_file: Path,
    tmp_path: Path,
    monkeypatch,
):
    """Relative log names live in the run while absolute names remain centralized."""

    config = load_config(config_file)
    assert config.logging.console is False
    assert config.logging.file is True
    assert config.logging.filename == "activity.log"

    paths = make_run_paths(config, "20260102-145100-EDT")
    assert paths.activity_log == (
        config.paths.persistent_root
        / "runs"
        / "20260102-145100-EDT"
        / "activity.log"
    ).resolve()

    config.logging.filename = "logs/netops.log"
    paths = make_run_paths(config, "20260102-145200-EDT")
    assert paths.activity_log == (
        config.paths.persistent_root
        / "runs"
        / "20260102-145200-EDT"
        / "logs"
        / "netops.log"
    ).resolve()

    absolute = tmp_path / "central" / "lldprunner.log"
    config.logging.filename = str(absolute)
    paths = make_run_paths(config, "20260102-145300-EDT")
    assert paths.activity_log == absolute.resolve()

    home = tmp_path / "operator-home"
    monkeypatch.setenv("HOME", str(home))
    config.logging.filename = "~/logs/lldprunner.log"
    paths = make_run_paths(config, "20260102-145350-EDT")
    assert paths.activity_log == (home / "logs" / "lldprunner.log").resolve()

    config.logging.file = False
    paths = make_run_paths(config, "20260102-145400-EDT")
    assert paths.activity_log is None


def test_logging_destination_controls_are_validated(tmp_path: Path):
    """Invalid Boolean, empty, and escaping relative log paths fail early."""

    cases = [
        ('[logging]\nfile = "true"\n', "logging.file must be true or false"),
        ('[logging]\nconsole = "false"\n', "logging.console must be true or false"),
        ('[logging]\nfilename = ""\n', "logging.filename must be a non-empty"),
        (
            '[logging]\nfilename = "../lldprunner.log"\n',
            "relative paths must remain inside the current run directory",
        ),
    ]
    for index, (text, message) in enumerate(cases):
        config_file = tmp_path / f"invalid-logging-{index}.toml"
        config_file.write_text(text, encoding="utf-8")
        with pytest.raises(ConfigError, match=message):
            load_config(config_file, credential_mode=CredentialMode.OPTIONAL, resolve_paths=False)


def test_snmp_report_metrics_requires_boolean_value(tmp_path: Path):
    """Quoted strings must not silently enable optional discovery telemetry."""

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        '[snmp]\nreport_metrics = "false"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="snmp.report_metrics must be true or false"):
        load_config(
            config_file,
            credential_mode=CredentialMode.OPTIONAL,
            resolve_paths=False,
        )


def test_entity_mib_mode_accepts_all_supported_values_and_normalizes_case(
    tmp_path: Path,
) -> None:
    """Operators may select full, auto, or brief without case sensitivity."""

    for value in ("full", "AUTO", "Brief"):
        config_file = tmp_path / f"{value}.toml"
        config_file.write_text(
            f'[snmp]\nentity_mib_mode = "{value}"\n',
            encoding="utf-8",
        )
        loaded = load_config(
            config_file,
            credential_mode=CredentialMode.OPTIONAL,
            resolve_paths=False,
        )
        assert loaded.snmp.entity_mib_mode == value.casefold()


def test_entity_mib_mode_rejects_unknown_value(tmp_path: Path) -> None:
    """Invalid modes fail configuration validation before network I/O begins."""

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        '[snmp]\nentity_mib_mode = "fast"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="entity_mib_mode must be full, auto, or brief"):
        load_config(
            config_file,
            credential_mode=CredentialMode.OPTIONAL,
            resolve_paths=False,
        )


def test_collect_entity_mib_requires_boolean_value(tmp_path: Path) -> None:
    """The master ENTITY-MIB enable switch must remain a real TOML boolean."""

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        '[snmp]\ncollect_entity_mib = "false"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="snmp.collect_entity_mib must be true or false"):
        load_config(
            config_file,
            credential_mode=CredentialMode.OPTIONAL,
            resolve_paths=False,
        )


def test_default_and_custom_run_id_formats_allocate_safely(config_file: Path, monkeypatch) -> None:
    """Run IDs preserve the historic default and support stateless counters."""

    from datetime import datetime
    from zoneinfo import ZoneInfo

    import lldp_runner.runtime as runtime_module
    from lldp_runner.runtime import allocate_run_id

    config = load_config(config_file)
    fixed = datetime(2026, 1, 2, 21, 3, 17, 123456, tzinfo=ZoneInfo("America/New_York"))
    monkeypatch.setattr(runtime_module, "now", lambda: fixed)

    assert allocate_run_id(config) == "20260102-210317-EST"

    config.paths.run_id_format = "%Y%m%d-%H%M%S"
    assert allocate_run_id(config) == "20260102-210317"

    config.paths.run_id_format = "run-{counter}"
    runs_root = config.paths.persistent_root / config.paths.runs_dirname
    runs_root.mkdir(parents=True, exist_ok=True)
    (runs_root / "run-00").mkdir()
    (runs_root / "run-09").mkdir()
    assert allocate_run_id(config) == "run-10"


def test_counter_namespace_is_timestamp_scoped_and_exhausts_at_99(
    config_file: Path, monkeypatch
) -> None:
    """Counters are stateless, zero-padded, namespace-scoped, and bounded."""

    from datetime import datetime
    from zoneinfo import ZoneInfo

    import lldp_runner.runtime as runtime_module
    from lldp_runner.runtime import allocate_run_id

    config = load_config(config_file)
    config.paths.run_id_format = "%y%m%d-{counter}"
    fixed = datetime(2026, 1, 2, 21, 3, 17, tzinfo=ZoneInfo("America/New_York"))
    monkeypatch.setattr(runtime_module, "now", lambda: fixed)
    runs_root = config.paths.persistent_root / config.paths.runs_dirname
    runs_root.mkdir(parents=True, exist_ok=True)
    (runs_root / "260101-99").mkdir()
    (runs_root / "260102-03").mkdir()
    assert allocate_run_id(config) == "260102-04"

    (runs_root / "260102-99").mkdir()
    with pytest.raises(ValueError, match="next counter would exceed 99") as exc:
        allocate_run_id(config)
    assert "paths.runs_dirname" in str(exc.value)
    assert "higher-precision timestamp" in str(exc.value)


def test_run_id_format_validation_rejects_unsafe_or_ambiguous_values(tmp_path: Path) -> None:
    """Formats cannot become paths or contain ambiguous counter/directive syntax."""

    invalid = [
        'run_id_format = "../run-{counter}"',
        'run_id_format = "run-{counter}-{counter}"',
        'run_id_format = "%Q-{counter}"',
    ]
    for index, assignment in enumerate(invalid):
        path = tmp_path / f"invalid-runid-{index}.toml"
        path.write_text(f"[paths]\n{assignment}\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="run_id_format"):
            load_config(path, credential_mode=CredentialMode.OPTIONAL, resolve_paths=False)


def test_two_digit_counter_names_sort_newest_first_for_resume(config_file: Path) -> None:
    """Zero padding preserves the existing reverse lexical resume shortcut."""

    import sqlite3

    config = load_config(config_file)
    runs_root = config.paths.persistent_root / config.paths.runs_dirname
    for run_id in ("run-09", "run-10"):
        run_dir = runs_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(run_dir / "discovery-state.sqlite")
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT INTO meta(key, value) VALUES('status', 'PAUSED')")
        conn.commit()
        conn.close()

    assert find_resumable_run(config) == "run-10"


def test_find_resumable_run_never_returns_runs_latest_alias(config_file: Path) -> None:
    """The completed-run convenience symlink is not itself a resumable run ID."""

    import sqlite3

    config = load_config(config_file)
    runs_root = config.paths.persistent_root / config.paths.runs_dirname
    run_dir = runs_root / "20260112-00"
    run_dir.mkdir(parents=True)
    conn = sqlite3.connect(run_dir / "discovery-state.sqlite")
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO meta(key, value) VALUES('status', 'PAUSED')")
    conn.commit()
    conn.close()
    (runs_root / "latest").symlink_to(run_dir.name)

    assert find_resumable_run(config) == run_dir.name


def test_terminal_watch_palette_and_color_policy_validation(config):
    """Watch palette and global color policy accept only documented values."""

    from lldp_runner.config import ConfigError, validate_config

    config.terminal.palette = "paper"
    with pytest.raises(ConfigError, match="terminal.palette"):
        validate_config(config)
    config.terminal.palette = "dark"
    config.terminal.color = "always"
    with pytest.raises(ConfigError, match="terminal.color"):
        validate_config(config)


def test_terminal_color_never_disables_tty_styling(config) -> None:
    """The configured global color policy overrides an otherwise interactive TTY."""

    from lldp_runner.terminal_style import use_color

    class Tty:
        def isatty(self) -> bool:
            return True

    config.terminal.color = "never"
    assert use_color(Tty(), config.terminal) is False



def test_adaptive_snmp_retry_defaults_and_validation(config) -> None:
    """Adaptive slowdown policy is bounded and internally consistent."""

    from lldp_runner.config import ConfigError, validate_config

    assert config.snmp.retry_per_operation == 1
    assert config.snmp.retry_total_cap == 3
    assert config.snmp.structural_table_retry == 1
    assert config.snmp.retry_timeout_multiplier == 1.5
    assert config.snmp.retry_max_repetitions_multiplier == 0.5
    assert config.snmp.retry_min_max_repetitions == 1
    assert config.snmp.retry_inter_pdu_delay_ms == 100.0
    validate_config(config)

    config.snmp.retry_timeout_multiplier = 1.0
    with pytest.raises(ConfigError, match="retry_timeout_multiplier"):
        validate_config(config)
    config.snmp.retry_timeout_multiplier = 1.5

    config.snmp.retry_max_repetitions_multiplier = 1.0
    with pytest.raises(ConfigError, match="retry_max_repetitions_multiplier"):
        validate_config(config)
    config.snmp.retry_max_repetitions_multiplier = 0.5

    config.snmp.retry_min_max_repetitions = config.snmp.max_repetitions + 1
    with pytest.raises(ConfigError, match="retry_min_max_repetitions"):
        validate_config(config)
    config.snmp.retry_min_max_repetitions = 1

    config.snmp.retry_inter_pdu_delay_ms = -1.0
    with pytest.raises(ConfigError, match="retry_inter_pdu_delay_ms"):
        validate_config(config)
    config.snmp.retry_inter_pdu_delay_ms = 100.0

    for field_name, invalid_value in (
        ("retry_per_operation", "1"),
        ("retry_total_cap", "3"),
        ("structural_table_retry", "1"),
        ("retry_timeout_multiplier", "1.5"),
        ("retry_max_repetitions_multiplier", "0.5"),
        ("retry_min_max_repetitions", 1.5),
        ("retry_inter_pdu_delay_ms", "100"),
    ):
        original = getattr(config.snmp, field_name)
        setattr(config.snmp, field_name, invalid_value)
        with pytest.raises(ConfigError, match=field_name):
            validate_config(config)
        setattr(config.snmp, field_name, original)


def test_adaptive_snmp_retry_options_load_from_toml(config_file: Path) -> None:
    """Site configuration can tune one target's bounded degraded profile."""

    text = config_file.read_text(encoding="utf-8")
    text = text.replace(
        "[snmp]\n",
        "[snmp]\n"
        "retry_per_operation = 2\n"
        "retry_total_cap = 4\n"
        "structural_table_retry = 2\n"
        "retry_timeout_multiplier = 1.75\n"
        "retry_max_repetitions_multiplier = 0.4\n"
        "retry_min_max_repetitions = 2\n"
        "retry_inter_pdu_delay_ms = 250.0\n",
        1,
    )
    config_file.write_text(text, encoding="utf-8")

    loaded = load_config(config_file)

    assert loaded.snmp.retry_per_operation == 2
    assert loaded.snmp.retry_total_cap == 4
    assert loaded.snmp.structural_table_retry == 2
    assert loaded.snmp.retry_timeout_multiplier == 1.75
    assert loaded.snmp.retry_max_repetitions_multiplier == 0.4
    assert loaded.snmp.retry_min_max_repetitions == 2
    assert loaded.snmp.retry_inter_pdu_delay_ms == 250.0


def test_canonical_operator_path_resolves_retained_output_symlink(
    tmp_path: Path,
) -> None:
    """Operator paths use the effective outputs directory behind a legacy alias."""

    from lldp_runner.runtime import canonical_operator_path

    canonical = tmp_path / "outputs"
    canonical.mkdir()
    legacy = tmp_path / "output"
    legacy.symlink_to(canonical.name, target_is_directory=True)

    assert canonical_operator_path(legacy / "run-01") == canonical / "run-01"


@pytest.mark.parametrize(
    ("field_name", "value", "expected"),
    [
        (
            "retry_per_collector",
            -1,
            "snmp.retry_per_collector must be a non-negative integer",
        ),
        (
            "retry_neighbor_reserve",
            -1,
            "snmp.retry_neighbor_reserve must be a non-negative integer",
        ),
        (
            "neighbor_stability_retry",
            "yes",
            "snmp.neighbor_stability_retry must be true or false",
        ),
        (
            "neighbor_stability_retry_delay_seconds",
            -0.1,
            "snmp.neighbor_stability_retry_delay_seconds must be a number >= 0",
        ),
    ],
)
def test_validate_app_config_rejects_invalid_new_retry_controls(
    field_name: str,
    value: object,
    expected: str,
    config,
) -> None:
    setattr(config.snmp, field_name, value)

    with pytest.raises(ConfigError, match=expected.replace(".", r"\.")):
        validate_config(config)


def test_validate_app_config_rejects_collector_limit_above_available_pools(
    config,
) -> None:
    config.snmp.retry_total_cap = 1
    config.snmp.retry_neighbor_reserve = 1
    config.snmp.retry_per_collector = 3

    with pytest.raises(
        ConfigError,
        match=(
            r"snmp\.retry_per_collector must be <= "
            r"snmp\.retry_total_cap \+ snmp\.retry_neighbor_reserve"
        ),
    ):
        validate_config(config)
