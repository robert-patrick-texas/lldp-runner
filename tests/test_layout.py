"""Install-layout selection for automatic persistent and scratch roots."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import lldp_runner.config as config_module
import lldp_runner.layout as layout_module
from lldp_runner.cli import main
from lldp_runner.config import (
    ConfigError,
    CredentialMode,
    discover_config_path,
    install_layout,
    load_config,
    resolve_existing_persistent_root,
    resolve_readonly_scratch_root,
)
from lldp_runner.layout import scratch_name, select_layout


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Move the home directory and per-user runtime directory below tmp_path."""

    path = tmp_path / "home" / "operator"
    path.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    for name in ("LLDP_RUNNER_CONFIG", "LLDP_RUNNER_ROOT", "LLDP_RUNNER_SCRATCH_ROOT"):
        monkeypatch.delenv(name, raising=False)
    return path.resolve()


@pytest.fixture
def shared_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Treat tmp_path/opt/lldp-runner as the default shared installation."""

    install = (tmp_path / "opt" / "lldp-runner").resolve()
    install.mkdir(parents=True)
    shm = tmp_path / "shm"
    shm.mkdir()
    monkeypatch.setattr(layout_module, "SHARED_DEFAULT_INSTANCE_DIR", str(install))
    monkeypatch.setattr(layout_module, "SHARED_SCRATCH_BASES", (str(shm),))
    return install


def _config(directory: Path, name: str = "config.toml", text: str = "") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path.resolve()


def test_shared_layout_keeps_data_in_var_beside_the_config(home: Path, tmp_path: Path) -> None:
    install = (tmp_path / "srv" / "lab").resolve()

    layout = select_layout(_config(install))

    assert layout.name == "shared"
    assert layout.persistent_root == install / "var"
    assert layout.scratch_fallback(install / "var") == install / "var" / "tmp"
    assert layout.create_persistent is False
    assert layout.legacy is False
    assert layout.unused_history == ()


def test_default_shared_install_uses_plain_scratch_name() -> None:
    layout = select_layout(Path("/opt/lldp-runner/config.toml"))

    assert layout.persistent_root == Path("/opt/lldp-runner/var")
    assert layout.scratch_candidates == (Path("/dev/shm/lldp-runner"),)


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ("/opt/lldp-runner", "lldp-runner"),
        ("/srv/lab", "lldp-runner-srv-lab"),
        ("/opt/lldp-runner-test", "lldp-runner-opt-lldp-runner-test"),
        ("/data/net ops/lldp", "lldp-runner-data-net_ops-lldp"),
    ],
)
def test_every_other_shared_install_gets_its_own_scratch_name(base: str, expected: str) -> None:
    """Two installations on one host must never share a current run or scoreboard."""

    name = scratch_name(Path(base), default=Path("/opt/lldp-runner"), relative_to=Path("/"))

    assert name == expected
    assert select_layout(Path(base) / "config.toml").scratch_candidates == (
        Path("/dev/shm") / expected,
    )


def test_system_layout_uses_fhs_locations(home: Path) -> None:
    layout = select_layout(Path("/etc/lldp-runner/config.toml"))

    assert layout.name == "system"
    assert layout.persistent_root == Path("/var/lib/lldp-runner")
    assert layout.scratch_candidates == (Path("/run/lldp-runner"),)
    assert layout.create_persistent is False


def test_layout_follows_the_config_path_as_named_not_its_symlink_target(
    home: Path, tmp_path: Path
) -> None:
    """A config.toml that links into a home directory keeps its installation."""

    install = (tmp_path / "opt" / "lldp-runner").resolve()
    install.mkdir(parents=True)
    target = _config(home / "managed-configs", "lab.toml")
    link = install / "config.toml"
    link.symlink_to(target)
    (install / "var").mkdir()

    found = discover_config_path(link, env={})
    assert found == link
    layout = select_layout(found)
    assert layout.name == "shared"
    assert layout.persistent_root == install / "var"

    config = load_config(link, env={}, credential_mode=CredentialMode.OPTIONAL)
    assert config.config_path == target
    assert config.config_location == link
    assert config.paths.persistent_root == install / "var"


def test_user_layout_for_config_below_home_uses_runtime_dir(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "run-user"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))

    default = select_layout(_config(home / "lldp-runner"))
    other = select_layout(_config(home / "projects" / "lab"))

    assert default.name == "user"
    assert default.persistent_root == home / "lldp-runner" / "var"
    assert default.scratch_candidates == (runtime / "lldp-runner",)
    assert default.create_persistent is True
    assert other.persistent_root == home / "projects" / "lab" / "var"
    assert other.scratch_candidates == (runtime / "lldp-runner-projects-lab",)


def test_user_layout_without_runtime_dir_falls_back_below_var(home: Path) -> None:
    layout = select_layout(_config(home / "projects" / "lab"))

    assert layout.name == "user"
    assert layout.scratch_candidates == ()


@pytest.mark.parametrize("config_name", [None, "lldp-runner-config.toml", "site.toml"])
def test_no_config_or_a_file_directly_in_home_use_the_user_instance(
    home: Path, config_name: str | None
) -> None:
    """$HOME itself is never the installation directory."""

    (home / "outputs").mkdir()  # unrelated directory that must not look like history
    path = None if config_name is None else _config(home, config_name)

    layout = select_layout(path)

    assert layout.name == "user"
    assert layout.persistent_root == home / "lldp-runner" / "var"
    assert layout.legacy is False
    assert layout.unused_history == ()


def test_home_of_slash_does_not_turn_every_install_into_a_user_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", "/")

    assert select_layout(_config(tmp_path / "opt" / "lldp-runner")).name == "shared"


def test_no_config_without_usable_home_has_no_automatic_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """HOME=/ must never turn the working directory, such as /, into a data root."""

    monkeypatch.setenv("HOME", "/")
    monkeypatch.delenv("LLDP_RUNNER_ROOT", raising=False)
    monkeypatch.chdir("/")

    assert select_layout(None).persistent_root is None

    with pytest.raises(ConfigError, match="cannot be chosen automatically"):
        load_config(None, env={}, credential_mode=CredentialMode.OPTIONAL)

    data = tmp_path / "data"
    config = load_config(
        None,
        env={"LLDP_RUNNER_ROOT": str(data)},
        credential_mode=CredentialMode.OPTIONAL,
    )
    assert config.paths.persistent_root == data.resolve()


def test_legacy_runs_and_outputs_stay_in_place_until_var_exists(home: Path, tmp_path: Path) -> None:
    install = (tmp_path / "opt" / "lldp-runner").resolve()
    path = _config(install)
    (install / "runs").mkdir()
    (install / "outputs").mkdir()

    legacy = select_layout(path)
    assert legacy.legacy is True
    assert legacy.persistent_root == install
    assert legacy.unused_history == ()

    (install / "var").mkdir()
    current = select_layout(path)
    assert current.legacy is False
    assert current.persistent_root == install / "var"
    # The old directories are now reported instead of silently ignored.
    assert current.unused_history == (install / "runs", install / "outputs")


def test_site_symlinks_to_var_are_not_mistaken_for_history(home: Path, tmp_path: Path) -> None:
    install = (tmp_path / "opt" / "lldp-runner").resolve()
    path = _config(install)
    for name in ("runs", "outputs"):
        (install / "var" / name).mkdir(parents=True)
        (install / name).symlink_to(Path("var") / name)

    layout = select_layout(path)

    assert layout.legacy is False
    assert layout.unused_history == ()
    assert layout.persistent_root == install / "var"


def test_old_user_history_is_reported_for_another_user_install(home: Path) -> None:
    """The previous auto rule always used ~/lldp-runner; keep that history visible."""

    (home / "lldp-runner" / "runs").mkdir(parents=True)

    layout = select_layout(_config(home / "configs", "lab.toml"))

    assert layout.persistent_root == home / "configs" / "var"
    assert layout.unused_history == (home / "lldp-runner" / "runs",)


def test_shared_scratch_falls_back_to_var_tmp(
    home: Path, shared_install: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (shared_install / "var").mkdir()
    # The preferred tmpfs base does not exist on this host.
    monkeypatch.setattr(layout_module, "SHARED_SCRATCH_BASES", (str(tmp_path / "no-shm"),))

    config = load_config(_config(shared_install), env={}, credential_mode=CredentialMode.OPTIONAL)

    assert config.paths.persistent_root == shared_install / "var"
    assert config.paths.scratch_root == shared_install / "var" / "tmp"


def test_shared_scratch_prefers_tmpfs_candidate(
    home: Path, shared_install: Path, tmp_path: Path
) -> None:
    (shared_install / "var").mkdir()

    config = load_config(_config(shared_install), env={}, credential_mode=CredentialMode.OPTIONAL)

    assert config.paths.scratch_root == (tmp_path / "shm" / "lldp-runner").resolve()


def test_user_layout_creates_its_data_directory(home: Path) -> None:
    config = load_config(
        _config(home / "lldp-runner"), env={}, credential_mode=CredentialMode.OPTIONAL
    )

    assert config.paths.persistent_root == home / "lldp-runner" / "var"
    assert (home / "lldp-runner" / "var").is_dir()
    assert config.paths.scratch_root == home / "lldp-runner" / "var" / "tmp"


def test_explicit_paths_ignore_the_layout(home: Path, tmp_path: Path) -> None:
    data = tmp_path / "srv" / "lldp"
    scratch = tmp_path / "scratch"
    path = _config(
        tmp_path / "opt" / "lldp-runner",
        text=f'[paths]\npersistent_root = "{data}"\nscratch_root = "{scratch}"\n',
    )

    config = load_config(path, env={}, credential_mode=CredentialMode.OPTIONAL)

    assert config.paths.persistent_root == data.resolve()
    assert config.paths.scratch_root == scratch.resolve()


def test_readonly_resolvers_follow_the_layout_without_creating(
    home: Path, shared_install: Path, tmp_path: Path
) -> None:
    path = _config(shared_install)
    config = load_config(path, env={}, credential_mode=CredentialMode.DISABLED, resolve_paths=False)
    layout = install_layout(config)

    persistent = resolve_existing_persistent_root("auto", layout=layout)
    assert persistent == shared_install / "var"
    assert not persistent.exists()

    # An interrupted run left its current link in the fallback; status follows it.
    (persistent / "tmp" / "current").mkdir(parents=True)
    (tmp_path / "shm" / "lldp-runner").mkdir()
    scratch = resolve_readonly_scratch_root("auto", persistent_root="auto", layout=layout)
    assert scratch == persistent / "tmp"


def test_paths_command_reports_layout_without_creating(
    home: Path, shared_install: Path, tmp_path: Path, capsys
) -> None:
    path = _config(shared_install)

    main(["--config", str(path), "paths", "--json"])

    report = json.loads(capsys.readouterr().out)
    var = shared_install / "var"
    assert report == {
        "config_path": str(path),
        "layout": "shared",
        "legacy_layout": False,
        "persistent_root": str(var),
        "persistent_root_auto": True,
        "runs_dir": str(var / "runs"),
        "outputs_dir": str(var / "outputs"),
        "scratch_root": str(tmp_path / "shm" / "lldp-runner"),
        "scratch_root_auto": True,
        "unused_history": [],
    }
    assert not var.exists()

    main(["--config", str(path), "paths"])
    text = capsys.readouterr().out
    assert f"Persistent root: {var} (auto)" in text
    assert f"Outputs:         {var / 'outputs'}" in text


def test_paths_command_warns_about_legacy_layout(home: Path, tmp_path: Path, capsys) -> None:
    install = (tmp_path / "opt" / "lldp-runner").resolve()
    path = _config(install)
    (install / "runs").mkdir()

    main(["--config", str(path), "paths", "--json"])

    captured = capsys.readouterr()
    assert json.loads(captured.out)["legacy_layout"] is True
    assert "Move them into" in captured.err
    assert str(install / "var") in captured.err


def test_paths_command_warns_about_history_left_beside_var(
    home: Path, tmp_path: Path, capsys
) -> None:
    install = (tmp_path / "opt" / "lldp-runner").resolve()
    path = _config(install)
    (install / "runs").mkdir()
    (install / "var").mkdir()

    main(["--config", str(path), "paths", "--json"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["legacy_layout"] is False
    assert report["unused_history"] == [str(install / "runs")]
    assert "is not used" in captured.err


def test_validate_config_prints_resolved_paths(
    home: Path, shared_install: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    (shared_install / "var").mkdir()
    path = _config(shared_install)
    monkeypatch.setattr(layout_module, "SHARED_SCRATCH_BASES", ())
    monkeypatch.setenv("SNMPCOMM", "public")

    main(["--config", str(path), "validate-config"])

    text = capsys.readouterr().out
    var = shared_install / "var"
    assert f"Configuration valid: {path}" in text
    assert "Install layout:  shared" in text
    assert f"Persistent root: {var}" in text
    assert f"Scratch root:    {var / 'tmp'}" in text


def test_config_module_no_longer_exposes_global_candidate_lists() -> None:
    """Callers must pass a layout; the old per-user candidate list is gone."""

    assert not hasattr(config_module, "PERSISTENT_ROOT_AUTO_CANDIDATES")
    assert not hasattr(config_module, "SCRATCH_ROOT_AUTO_BASES")
