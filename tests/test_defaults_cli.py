from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import lldp_runner.config as config_module
from lldp_runner.cli import _default_generated_config_path, main
from lldp_runner.config import (
    ConfigError,
    CredentialMode,
    discover_config_path,
    load_config,
)


def _isolate_auto_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Keep dynamic path tests away from real user/system directories."""

    scratch_base = tmp_path / "scratch-base"
    scratch_base.mkdir()
    monkeypatch.setattr(config_module, "PERSISTENT_ROOT_AUTO_CANDIDATES", ())
    monkeypatch.setattr(config_module, "SCRATCH_ROOT_AUTO_BASES", (str(scratch_base),))
    monkeypatch.chdir(tmp_path)
    return scratch_base


def test_default_only_runtime_resolves_dynamic_values(monkeypatch, tmp_path: Path) -> None:
    scratch_base = _isolate_auto_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(config_module.os, "cpu_count", lambda: 6)

    config = load_config(None, env={"SNMPCOMM": "public"})

    assert config.config_path is None
    assert config.discovery.workers == 24
    assert config.discovery.batch_size == 9
    assert config.discovery.max_devices == 10
    assert config.discovery.max_hosts == 1000
    assert config.discovery.boundaries == ["0.0.0.0/0", "::/0"]
    assert config.snmp.max_outstanding_devices_per_worker == 24
    assert config.snmp.collect_entity_mib is True
    assert config.snmp.entity_mib_mode == "full"
    assert config.paths.persistent_root == tmp_path.resolve()
    assert config.paths.scratch_root == (scratch_base / "lldp-runner").resolve()


def test_partial_config_inherits_defaults_and_replaces_default_lists(
    monkeypatch, tmp_path: Path
) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)
    path = tmp_path / "partial.toml"
    path.write_text(
        '''[discovery]\nbatch_size = 11\nboundaries = ["192.0.2.0/24"]\n''',
        encoding="utf-8",
    )

    config = load_config(path, env={"SNMPCOMM": "public"})

    assert config.discovery.batch_size == 11
    assert config.discovery.boundaries == ["192.0.2.0/24"]
    assert config.discovery.max_devices == 10
    assert config.snmp.max_repetitions == 20
    assert config.snmp.retry_per_operation == 1
    assert config.snmp.retry_per_collector == 1
    assert config.snmp.retry_total_cap == 3
    assert config.snmp.retry_neighbor_reserve == 2
    assert config.snmp.structural_table_retry == 1
    assert config.snmp.retry_timeout_multiplier == 1.5
    assert config.snmp.retry_max_repetitions_multiplier == 0.5
    assert config.snmp.retry_min_max_repetitions == 1
    assert config.snmp.retry_inter_pdu_delay_ms == 100.0
    assert config.snmp.neighbor_stability_retry is True
    assert config.snmp.neighbor_stability_retry_delay_seconds == 2.0


def test_precedence_config_environment_set_then_dedicated(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)
    path = tmp_path / "config.toml"
    path.write_text("[snmp]\ntimeout_seconds = 1.0\n", encoding="utf-8")

    config = load_config(
        path,
        env={"SNMPCOMM": "public", "LLDP_RUNNER_SNMP_TIMEOUT": "2.0"},
        set_expressions=["snmp.timeout_seconds=3.0"],
        overrides={"snmp_timeout": 4.0},
    )

    assert config.snmp.timeout_seconds == 4.0


def test_discover_config_uses_first_existing_candidate(monkeypatch, tmp_path: Path) -> None:
    first = tmp_path / "first.toml"
    second = tmp_path / "second.toml"
    second.write_text("[logging]\nlevel='INFO'\n", encoding="utf-8")
    monkeypatch.setattr(config_module, "CONFIG_SEARCH_PATHS", (str(first), str(second)))

    assert discover_config_path(None, env={}) == second.resolve()

    first.write_text("[logging]\nlevel='DEBUG'\n", encoding="utf-8")
    assert discover_config_path(None, env={}) == first.resolve()


def test_explicit_missing_config_is_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="configuration file not found"):
        discover_config_path(tmp_path / "missing.toml", env={})


def test_existing_auto_persistent_permission_error_does_not_fall_through(
    monkeypatch, tmp_path: Path
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(
        config_module,
        "PERSISTENT_ROOT_AUTO_CANDIDATES",
        (str(first), str(second)),
    )
    calls: list[Path] = []

    def fake_probe(path: Path, *, create: bool, label: str) -> Path:
        calls.append(path)
        if path == first:
            raise ConfigError(f"{label} directory is not writable: {path}")
        return path

    monkeypatch.setattr(config_module, "_probe_writable_directory", fake_probe)

    with pytest.raises(ConfigError, match="not writable"):
        config_module._resolve_persistent_root("auto")
    assert calls == [first]


def test_defaults_only_persistent_error_mentions_generate_config(monkeypatch, tmp_path: Path) -> None:
    candidate = tmp_path / "existing"
    candidate.mkdir()
    monkeypatch.setattr(config_module, "PERSISTENT_ROOT_AUTO_CANDIDATES", (str(candidate),))

    def fail_probe(path: Path, *, create: bool, label: str) -> Path:
        raise ConfigError(f"{label} directory is not writable: {path}")

    monkeypatch.setattr(config_module, "_probe_writable_directory", fail_probe)

    with pytest.raises(ConfigError, match="lldp-runner generate-config"):
        load_config(None, env={}, credential_mode=CredentialMode.OPTIONAL)


def test_runtime_v2c_only_uses_single_credential_two_attempts(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)

    config = load_config(None, env={"SNMPCOMM": "public"})
    profile = config.credential_profiles["runtime-default"]

    assert profile.primary == "runtime-v2c"
    assert profile.primary_attempts == 2
    assert profile.fallback is None
    assert config.credentials["runtime-v2c"].community == "public"


def test_runtime_v3_primary_and_v2c_fallback(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)
    env = {
        "SNMPCOMM": "public",
        "SNMPUSER": "operator",
        "SNMPAUTH": "auth-secret",
        "SNMPPRIV": "priv-secret",
    }

    config = load_config(None, env=env)
    profile = config.credential_profiles["runtime-default"]

    assert profile.primary == "runtime-v3"
    assert profile.fallback == "runtime-v2c"


def test_snmp_version_2c_reverses_runtime_primary_fallback(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)
    env = {
        "SNMPCOMM": "public",
        "SNMPUSER": "operator",
        "SNMPAUTH": "auth-secret",
        "SNMPPRIV": "priv-secret",
    }

    config = load_config(None, env=env, overrides={"snmp_version": "2c"})
    profile = config.credential_profiles["runtime-default"]

    assert profile.primary == "runtime-v2c"
    assert profile.fallback == "runtime-v3"


def test_cli_secret_token_prefers_environment_variable(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)

    config = load_config(
        None,
        env={"MY_COMMUNITY": "secret-community"},
        credential_overrides={"community": "MY_COMMUNITY"},
    )

    assert config.credentials["runtime-v2c"].community == "secret-community"


def test_cli_secret_token_falls_back_to_literal(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)

    config = load_config(
        None,
        env={},
        credential_overrides={"community": "literal-community"},
    )

    assert config.credentials["runtime-v2c"].community == "literal-community"


def test_incomplete_runtime_v3_credentials_are_rejected(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)

    with pytest.raises(ConfigError, match="incomplete"):
        load_config(None, env={"SNMPUSER": "operator", "SNMPAUTH": "auth-only"})


def test_explicit_credentials_suppress_runtime_defaults(config_file: Path) -> None:
    config = load_config(
        config_file,
        env={
            "SNMPCOMM": "runtime-community",
            "SNMPUSER": "runtime-user",
            "SNMPAUTH": "runtime-auth",
            "SNMPPRIV": "runtime-priv",
        },
    )

    assert "runtime-v2c" not in config.credentials
    assert "runtime-v3" not in config.credentials
    assert "runtime-default" not in config.credential_profiles


def test_set_can_override_arbitrary_normal_config_value(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)

    config = load_config(
        None,
        env={"SNMPCOMM": "public"},
        set_expressions=[
            "snmp.max_repetitions=37",
            'snmp.entity_mib_mode="BRIEF"',
            'logging.level="DEBUG"',
            'discovery.workers="auto"',
            "icmp.enabled=false",
        ],
    )

    assert config.snmp.max_repetitions == 37
    assert config.snmp.entity_mib_mode == "brief"
    assert config.logging.level == "DEBUG"
    assert config.discovery.workers == (config_module.os.cpu_count() or 1) * 4
    assert config.icmp.enabled is False


def test_version_option_outputs_and_exits(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "lldp-runner 0.37.0"


def test_version_command_matches_version_option(capsys) -> None:
    """The subcommand is an exact operator-friendly alias for --version output."""

    main(["version"])
    command_output = capsys.readouterr().out.strip()

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    option_output = capsys.readouterr().out.strip()

    assert command_output == option_output == "lldp-runner 0.37.0"


def test_version_command_does_not_load_config(monkeypatch, capsys) -> None:
    """Version remains available even when the configured file is unusable."""

    monkeypatch.setenv("LLDP_RUNNER_CONFIG", "/definitely/missing/lldp-runner.toml")
    main(["version"])
    assert capsys.readouterr().out.strip() == "lldp-runner 0.37.0"


def test_generate_config_writes_commented_defaults_and_honors_set(
    tmp_path: Path, capsys
) -> None:
    output = tmp_path / "generated.toml"

    main([
        "--set",
        "snmp.max_repetitions=31",
        "generate-config",
        str(output),
    ])

    text = output.read_text(encoding="utf-8")
    parsed = tomllib.loads(text)
    assert parsed["discovery"]["workers"] == "auto"
    assert parsed["discovery"]["batch_size"] == 9
    assert parsed["discovery"]["boundaries"] == ["0.0.0.0/0", "::/0"]
    assert parsed["snmp"]["backend"] == "pysnmp"
    assert "pysnmp (default) or gufo" in text
    assert parsed["snmp"]["max_repetitions"] == 31
    assert parsed["snmp"]["retry_per_operation"] == 1
    assert parsed["snmp"]["retry_per_collector"] == 1
    assert parsed["snmp"]["retry_total_cap"] == 3
    assert parsed["snmp"]["retry_neighbor_reserve"] == 2
    assert parsed["snmp"]["structural_table_retry"] == 1
    assert parsed["snmp"]["retry_timeout_multiplier"] == 1.5
    assert parsed["snmp"]["retry_max_repetitions_multiplier"] == 0.5
    assert parsed["snmp"]["retry_min_max_repetitions"] == 1
    assert parsed["snmp"]["retry_inter_pdu_delay_ms"] == 100.0
    assert parsed["snmp"]["neighbor_stability_retry"] is True
    assert parsed["snmp"]["neighbor_stability_retry_delay_seconds"] == 2.0
    assert parsed["snmp"]["collect_entity_mib"] is True
    assert parsed["snmp"]["entity_mib_mode"] == "full"
    assert parsed["snmp"]["report_metrics"] is False
    assert parsed["output"]["neighbor_local_width"] == 18
    assert parsed["output"]["neighbor_remote_port_width"] == 18
    assert parsed["output"]["write_hosts_csv"] is True
    assert parsed["output"]["write_stack_members_csv"] is True
    assert parsed["output"]["write_seeds_csv"] is True
    assert parsed["output"]["write_unknown_devices_csv"] is True
    assert parsed["output"]["write_errors_csv"] is True
    assert parsed["output"]["write_empty_csv"] is False
    assert parsed["output"]["log_alert_on_empty_csv"] is False
    assert parsed["terminal"]["color"] == "auto"
    assert parsed["terminal"]["palette"] == "dark"
    assert parsed["terminal"]["heading_color"] == "cyan"
    assert parsed["terminal"]["success_color"] == "green"
    assert parsed["terminal"]["warning_color"] == "yellow"
    assert parsed["terminal"]["error_color"] == "red"
    assert parsed["terminal"]["learned_color"] == "cyan"
    assert parsed["terminal"]["observed_by_color"] == "magenta"
    assert parsed["terminal"]["inspection_neighbor_color"] == "magenta"
    assert parsed["terminal"]["metric_color"] == "green"
    assert parsed["paths"]["clean_scratch_when_completed"] is True
    assert parsed["paths"]["run_id_format"] == "%Y%m%d-%H%M%S-%Z"
    assert parsed["time"]["timezone"] == "eastern"
    assert parsed["logging"]["console"] is True
    assert parsed["logging"]["file"] is True
    assert parsed["logging"]["filename"] == "activity.log"
    assert "discovery.json is always written" in text
    assert "Runtime precedence" in text
    assert "no automatic fallback or mixed-backend operation" in text
    assert "sha256 with aes256 (Reeder/Cisco)" in text
    assert "aes256-blumenthal" in text
    assert "SNMPCOMM" in text
    assert "On this host, workers = \"auto\" currently resolves to" in text
    assert f"Generated configuration: {output.resolve()}" in capsys.readouterr().out


def test_generate_config_refuses_to_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "existing.toml"
    output.write_text("existing\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["generate-config", str(output)])

    assert exc.value.code == 2
    assert output.read_text(encoding="utf-8") == "existing\n"


def test_generate_config_default_filename_is_current_directory(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    monkeypatch.chdir(tmp_path)

    main(["generate-config"])

    output = tmp_path / "lldp-runner-config.toml"
    assert output.is_file()
    assert f"Generated configuration: {output.resolve()}" in capsys.readouterr().out


def test_generate_config_prefers_primary_name_in_user_standard_directory(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    standard = home / "lldp-runner"
    standard.mkdir(parents=True)

    destination = _default_generated_config_path(cwd=standard, home=home)

    assert destination == standard / "config.toml"


def test_generate_config_does_not_replace_existing_primary_name(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    standard = home / "lldp-runner"
    standard.mkdir(parents=True)
    (standard / "config.toml").write_text("[logging]\nlevel = \"INFO\"\n")

    destination = _default_generated_config_path(cwd=standard, home=home)

    assert destination == standard / "lldp-runner-config.toml"


def test_generate_config_recognizes_system_standard_directories(tmp_path: Path) -> None:
    home = tmp_path / "home"

    # These paths need not exist for directory-name recognition; resolve() is
    # intentionally non-strict. If a real config.toml exists on the test host,
    # the safe fallback filename is expected instead of an overwrite target.
    for standard in (Path("/opt/lldp-runner"), Path("/etc/lldp-runner")):
        destination = _default_generated_config_path(cwd=standard, home=home)
        if (standard / "config.toml").exists():
            assert destination == standard / "lldp-runner-config.toml"
        else:
            assert destination == standard / "config.toml"


def test_dotted_community_cli_resolves_environment_variable(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("SITE_COMMUNITY", "secret-community")
    for name in ("LLDP_RUNNER_CONFIG", "SNMPCOMM", "SNMPUSER", "SNMPAUTH", "SNMPPRIV"):
        monkeypatch.delenv(name, raising=False)

    main(["--snmp.community", "SITE_COMMUNITY", "validate-config"])

    assert "Configuration valid: built-in defaults" in capsys.readouterr().out


def test_project_dependencies_have_minimums_without_upper_caps() -> None:
    """Package metadata should permit future compatible dependency/tool versions."""

    project = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert project["project"]["requires-python"] == ">=3.13"
    specifications = [
        *project["project"]["dependencies"],
        *project["dependency-groups"]["dev"],
        *project["build-system"]["requires"],
    ]
    assert all(">=" in item for item in specifications)
    assert all("<" not in item for item in specifications)


def test_release_dependency_constraints_are_exact_and_documented() -> None:
    """Keep broad package support separate from reproducible release tooling."""

    root = Path(__file__).parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    runtime_constraints = project["tool"]["uv"]["constraint-dependencies"]
    build_constraints = project["tool"]["uv"][
        "build-constraint-dependencies"
    ]
    expected = [
        "cryptography==50.0.1",
        "gufo-snmp==0.12.0",
        "pysnmp==7.1.29",
        "iniconfig==2.3.0",
        "packaging==25.0",
        "pluggy==1.6.0",
        "pygments==2.20.0",
        "pytest==9.0.2",
        "ruff==0.16.0",
        "ty==0.0.63",
        "uv-build==0.12.5",
    ]
    assert runtime_constraints == expected[:-1]
    assert build_constraints == expected[-1:]
    assert all("==" in item for item in expected)

    manifest = root / "constraints" / "release-0.37.0.txt"
    pinned_lines = [
        line
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    assert pinned_lines == expected


def test_project_and_package_versions_stay_in_sync() -> None:
    from lldp_runner import __version__

    project = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert project["project"]["version"] == __version__ == "0.37.0"
    assert (
        project["project"]["scripts"]["show-neighbors"]
        == "lldp_runner.cli:show_neighbors_main"
    )
    assert project["tool"]["uv"]["link-mode"] == "copy"


def test_set_wrong_value_type_reports_configuration_error(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)

    with pytest.raises(ConfigError, match="invalid type"):
        load_config(
            None,
            env={"SNMPCOMM": "public"},
            set_expressions=['snmp.timeout_seconds="slow"'],
        )


def test_generate_config_rejects_invalid_set_type(tmp_path: Path) -> None:
    output = tmp_path / "invalid.toml"

    with pytest.raises(SystemExit) as exc:
        main([
            "--set",
            'snmp.timeout_seconds="slow"',
            "generate-config",
            str(output),
        ])

    assert exc.value.code == 2
    assert not output.exists()


def test_max_device_auto_and_zero_limit_values_are_valid(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)

    auto = load_config(
        None,
        env={"SNMPCOMM": "public", "LLDP_RUNNER_MAX_DEVICES": "auto"},
    )
    assert auto.discovery.max_devices == "auto"

    unlimited = load_config(
        None,
        env={
            "SNMPCOMM": "public",
            "LLDP_RUNNER_MAX_DEVICES": "0",
            "LLDP_RUNNER_MAX_HOSTS": "0",
        },
    )
    assert unlimited.discovery.max_devices == 0
    assert unlimited.discovery.max_hosts == 0


def test_set_supports_auto_and_independent_zero_host_guardrail(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)

    config = load_config(
        None,
        env={"SNMPCOMM": "public"},
        set_expressions=['discovery.max_devices="auto"', "discovery.max_hosts=0"],
    )

    assert config.discovery.max_devices == "auto"
    assert config.discovery.max_hosts == 0


def test_generated_config_documents_limit_modes(tmp_path: Path) -> None:
    output = tmp_path / "generated.toml"

    main(["generate-config", str(output)])

    text = output.read_text(encoding="utf-8")
    assert "0 = unlimited" in text
    assert "recursive discovery." in text
    assert "Set to 'auto' for seed-only discovery" in text
    assert "0 disables this guardrail" in text


def test_generated_config_wraps_long_lines_and_pattern_lists(tmp_path: Path) -> None:
    output = tmp_path / "generated.toml"
    main(["generate-config", str(output)])

    text = output.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert max(map(len, lines)) <= 80
    assert 'managed_endpoint_patterns = [' in text
    assert '  "(?i)\\\\bCisco\\\\s+(IP\\\\s+)?Phone\\\\b",' in text
    assert 'managed_endpoint_patterns = ["' not in text


def test_generated_config_contains_commented_tagging_examples(tmp_path: Path) -> None:
    output = tmp_path / "generated.toml"
    main(["generate-config", str(output)])

    text = output.read_text(encoding="utf-8")
    assert text.count("# [[tagging.rules]]") == 2
    assert '# label = "infrastructure-role"' in text
    assert '# tags = ["role:infrastructure"]' in text
    assert '# label = "voice-endpoints"' in text
    assert '# tags = ["service:voice"]' in text
    # Commented examples must not alter the parsed active tagging configuration.
    assert tomllib.loads(text)["tagging"] == {}


def test_seed_order_sampling_options_follow_runtime_precedence(monkeypatch, tmp_path: Path) -> None:
    _isolate_auto_paths(monkeypatch, tmp_path)

    config = load_config(
        None,
        env={
            "SNMPCOMM": "public",
            "LLDP_RUNNER_SEED_ORDER": "random",
            "LLDP_RUNNER_SEED_DNS_MODE": "skip-addressed",
            "LLDP_RUNNER_SHUFFLE_KEY": "env-key",
            "LLDP_RUNNER_LIMIT_BEHAVIOR": "pause",
        },
        set_expressions=[
            'discovery.seed_order="input"',
            'discovery.seed_dns_mode="resolve"',
        ],
        overrides={
            "seed_order": "sorted",
            "seed_dns_mode": "skip-addressed",
            "shuffle_key": "cli-key",
            "limit_behavior": "complete",
        },
    )

    assert config.discovery.seed_order == "sorted"
    assert config.discovery.seed_dns_mode == "skip-addressed"
    assert config.discovery.shuffle_key == "cli-key"
    assert config.discovery.limit_behavior == "complete"


def test_generated_config_contains_seed_sampling_controls(tmp_path: Path) -> None:
    output = tmp_path / "generated.toml"
    main(["generate-config", str(output)])
    parsed = tomllib.loads(output.read_text(encoding="utf-8"))

    assert parsed["discovery"]["seed_order"] == "input"
    assert parsed["discovery"]["seed_dns_mode"] == "resolve"
    assert parsed["discovery"]["shuffle_key"] == ""
    assert parsed["discovery"]["limit_behavior"] == "pause"


def test_run_parser_accepts_seed_dns_mode_override() -> None:
    """The dedicated run option exposes both supported seed DNS policies."""

    from lldp_runner.cli import _parser

    parsed = _parser().parse_args(
        ["run", "--seed-dns-mode", "skip-addressed", "--seed", "switch1"]
    )

    assert parsed.seed_dns_mode == "skip-addressed"


@pytest.mark.parametrize(
    "argv",
    [
        ["--snmp-backend", "pysnmp", "run", "--seed", "switch1"],
        ["run", "--snmp-backend", "pysnmp", "--seed", "switch1"],
        ["--snmp.backend", "pysnmp", "run", "--seed", "switch1"],
    ],
)
def test_run_parser_accepts_global_or_local_backend_selection(argv: list[str]) -> None:
    """Both documented spellings select one backend around the subcommand."""

    from lldp_runner.cli import _parser

    assert _parser().parse_args(argv).snmp_backend == "pysnmp"


def test_active_command_help_identifies_pysnmp_as_the_default() -> None:
    """Global and standalone active-command help must match built-in defaults."""

    from lldp_runner.cli import _get_neighbors_parser, _parser

    expected = "SNMP transport backend for this invocation (default: pysnmp)"
    assert expected in " ".join(_parser().format_help().split())
    assert expected in " ".join(_get_neighbors_parser().format_help().split())


@pytest.mark.parametrize("backend", ["gufo", "pysnmp"])
def test_generate_config_honors_dedicated_backend_selection(
    tmp_path: Path,
    backend: str,
) -> None:
    output = tmp_path / f"{backend}.toml"

    main(["--snmp-backend", backend, "generate-config", str(output)])

    parsed = tomllib.loads(output.read_text(encoding="utf-8"))
    assert parsed["snmp"]["backend"] == backend
