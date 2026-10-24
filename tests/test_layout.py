"""Install-layout selection for automatic persistent and scratch roots."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import lldp_runner.config as config_module
import lldp_runner.layout as layout_module
from lldp_runner.cli import main
from lldp_runner.config import (
    CredentialMode,
    install_layout,
    load_config,
    resolve_existing_persistent_root,
    resolve_readonly_scratch_root,
)
from lldp_runner.layout import select_layout


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


def _config(directory: Path, name: str = "config.toml", text: str = "") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path.resolve()


def test_shared_layout_keeps_data_in_var_beside_the_config(home: Path, tmp_path: Path) -> None:
    install = tmp_path / "opt" / "lldp-runner"

    layout = select_layout(_config(install))

    assert layout.name == "shared"
    assert layout.persistent_root == install.resolve() / "var"
    assert layout.scratch_candidates == (Path("/dev/shm/lldp-runner"),)
    assert layout.scratch_fallback(layout.persistent_root) == install.resolve() / "var" / "tmp"
    assert layout.create_persistent is False
    assert layout.legacy is False


def test_system_layout_uses_fhs_locations(home: Path) -> None:
    layout = select_layout(Path("/etc/lldp-runner/config.toml"))

    assert layout.name == "system"
    assert layout.persistent_root == Path("/var/lib/lldp-runner")
    assert layout.scratch_candidates == (
        Path("/run/lldp-runner"),
        Path("/dev/shm/lldp-runner"),
    )
    assert layout.create_persistent is False


def test_user_layout_for_config_below_home_uses_runtime_dir(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "run-user"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))

    layout = select_layout(_config(home / "lldp-runner"))

    assert layout.name == "user"
    assert layout.persistent_root == home / "lldp-runner" / "var"
    assert layout.scratch_candidates == (runtime / "lldp-runner",)
    assert layout.create_persistent is True


def test_user_layout_without_runtime_dir_falls_back_below_var(home: Path) -> None:
    layout = select_layout(_config(home / "projects" / "lab"))

    assert layout.name == "user"
    assert layout.scratch_candidates == ()
    assert layout.scratch_fallback(layout.persistent_root) == (
        home / "projects" / "lab" / "var" / "tmp"
    )


@pytest.mark.parametrize("config_name", [None, "lldp-runner-config.toml"])
def test_no_config_and_home_file_config_use_the_user_instance(
    home: Path, config_name: str | None
) -> None:
    path = None if config_name is None else _config(home, config_name)

    layout = select_layout(path)

    assert layout.name == "user"
    assert layout.persistent_root == home / "lldp-runner" / "var"


def test_home_of_slash_does_not_turn_every_install_into_a_user_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", "/")

    assert select_layout(_config(tmp_path / "opt" / "lldp-runner")).name == "shared"


def test_legacy_runs_and_outputs_stay_in_place_until_var_exists(home: Path, tmp_path: Path) -> None:
    install = tmp_path / "opt" / "lldp-runner"
    path = _config(install)
    (install / "runs").mkdir()
    (install / "outputs").mkdir()

    legacy = select_layout(path)
    assert legacy.legacy is True
    assert legacy.persistent_root == install.resolve()

    (install / "var").mkdir()
    current = select_layout(path)
    assert current.legacy is False
    assert current.persistent_root == install.resolve() / "var"


def test_site_symlinks_to_var_are_not_mistaken_for_legacy_data(home: Path, tmp_path: Path) -> None:
    install = tmp_path / "opt" / "lldp-runner"
    path = _config(install)
    for name in ("runs", "outputs"):
        (install / "var" / name).mkdir(parents=True)
        (install / name).symlink_to(Path("var") / name)

    layout = select_layout(path)

    assert layout.legacy is False
    assert layout.persistent_root == install.resolve() / "var"


def test_shared_scratch_falls_back_to_var_tmp(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install = tmp_path / "opt" / "lldp-runner"
    (install / "var").mkdir(parents=True)
    path = _config(install)
    # The preferred tmpfs parent does not exist on this host.
    monkeypatch.setattr(
        layout_module, "SHARED_SCRATCH_ROOTS", (str(tmp_path / "no-shm" / "lldp-runner"),)
    )

    config = load_config(path, env={}, credential_mode=CredentialMode.OPTIONAL)

    assert config.paths.persistent_root == install.resolve() / "var"
    assert config.paths.scratch_root == install.resolve() / "var" / "tmp"


def test_shared_scratch_prefers_tmpfs_candidate(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install = tmp_path / "opt" / "lldp-runner"
    (install / "var").mkdir(parents=True)
    shm = tmp_path / "shm"
    shm.mkdir()
    monkeypatch.setattr(layout_module, "SHARED_SCRATCH_ROOTS", (str(shm / "lldp-runner"),))

    config = load_config(_config(install), env={}, credential_mode=CredentialMode.OPTIONAL)

    assert config.paths.scratch_root == (shm / "lldp-runner").resolve()


def test_user_layout_creates_its_data_directory(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(layout_module, "SHARED_SCRATCH_ROOTS", ())

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
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install = tmp_path / "opt" / "lldp-runner"
    path = _config(install)
    shm = tmp_path / "shm"
    shm.mkdir()
    monkeypatch.setattr(layout_module, "SHARED_SCRATCH_ROOTS", (str(shm / "lldp-runner"),))
    config = load_config(path, env={}, credential_mode=CredentialMode.DISABLED, resolve_paths=False)
    layout = install_layout(config)

    persistent = resolve_existing_persistent_root("auto", layout=layout)
    assert persistent == install.resolve() / "var"
    assert not persistent.exists()

    # An interrupted run left its current link in the fallback; status follows it.
    (persistent / "tmp" / "current").mkdir(parents=True)
    (shm / "lldp-runner").mkdir()
    scratch = resolve_readonly_scratch_root("auto", persistent_root="auto", layout=layout)
    assert scratch == persistent / "tmp"


def test_paths_command_reports_layout_without_creating(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    install = tmp_path / "opt" / "lldp-runner"
    path = _config(install)
    (tmp_path / "shm").mkdir()
    monkeypatch.setattr(
        layout_module, "SHARED_SCRATCH_ROOTS", (str(tmp_path / "shm" / "lldp-runner"),)
    )

    main(["--config", str(path), "paths", "--json"])

    report = json.loads(capsys.readouterr().out)
    var = install.resolve() / "var"
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
    }
    assert not var.exists()

    main(["--config", str(path), "paths"])
    text = capsys.readouterr().out
    assert f"Persistent root: {var} (auto)" in text
    assert f"Outputs:         {var / 'outputs'}" in text


def test_paths_command_warns_about_legacy_layout(home: Path, tmp_path: Path, capsys) -> None:
    install = tmp_path / "opt" / "lldp-runner"
    path = _config(install)
    (install / "runs").mkdir()

    main(["--config", str(path), "paths", "--json"])

    captured = capsys.readouterr()
    assert json.loads(captured.out)["legacy_layout"] is True
    assert "Move them into" in captured.err
    assert str(install.resolve() / "var") in captured.err


def test_validate_config_prints_resolved_paths(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    install = tmp_path / "opt" / "lldp-runner"
    (install / "var").mkdir(parents=True)
    path = _config(install)
    monkeypatch.setattr(layout_module, "SHARED_SCRATCH_ROOTS", ())
    monkeypatch.setenv("SNMPCOMM", "public")

    main(["--config", str(path), "validate-config"])

    text = capsys.readouterr().out
    var = install.resolve() / "var"
    assert f"Configuration valid: {path}" in text
    assert "Install layout:  shared" in text
    assert f"Persistent root: {var}" in text
    assert f"Scratch root:    {var / 'tmp'}" in text


def test_config_module_no_longer_exposes_global_candidate_lists() -> None:
    """Callers must pass a layout; the old per-user candidate list is gone."""

    assert not hasattr(config_module, "PERSISTENT_ROOT_AUTO_CANDIDATES")
    assert not hasattr(config_module, "SCRATCH_ROOT_AUTO_BASES")
