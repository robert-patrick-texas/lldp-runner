"""Selection, precedence, persistence, and resume invariants for SNMP backends."""

from __future__ import annotations

import asyncio
import json
import pickle
import sys
import types
from pathlib import Path

import pytest

from lldp_runner.config import ConfigError, CredentialMode, SnmpConfig, load_config
from lldp_runner.coordinator import Coordinator
from lldp_runner.models import DirectCredential, SeedInput
from lldp_runner.run_manifest import build_invocation_provenance
from lldp_runner.runtime import make_run_paths
from lldp_runner.snmp import create_snmp_client
from lldp_runner.snmp import selection as selection_module
from lldp_runner.snmp.selection import selected_snmp_backend


def _minimal_config(
    path: Path,
    *,
    backend: str | None = "gufo",
) -> Path:
    """Write a small config, optionally omitting the backend to test defaults."""

    lines = [
        "[paths]",
        f'persistent_root = "{path.parent / "persistent"}"',
        f'scratch_root = "{path.parent / "scratch"}"',
    ]
    if backend is not None:
        lines.extend(("[snmp]", f'backend = "{backend}"'))
    lines.extend(("[logging]", "file = false", "console = false", ""))
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _load(path: Path, **kwargs):
    return load_config(
        path,
        credential_mode=CredentialMode.OPTIONAL,
        resolve_paths=False,
        **kwargs,
    )


def test_pysnmp_is_default_and_both_backends_are_explicitly_selectable(
    tmp_path: Path,
) -> None:
    default = load_config(
        None,
        env={},
        credential_mode=CredentialMode.OPTIONAL,
        resolve_paths=False,
    )
    assert default.snmp.backend == "pysnmp"
    assert selected_snmp_backend(default.snmp).name == "pysnmp"

    gufo = _load(_minimal_config(tmp_path / "gufo.toml", backend="gufo"), env={})
    pysnmp = _load(_minimal_config(tmp_path / "pysnmp.toml", backend="pysnmp"), env={})
    assert selected_snmp_backend(gufo.snmp).name == "gufo"
    assert selected_snmp_backend(pysnmp.snmp).name == "pysnmp"


def test_read_only_loading_does_not_bind_or_initialize_snmp_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Credential-disabled readers stop before transport selection."""

    def fail_selection(_config: SnmpConfig) -> None:
        raise AssertionError("read-only configuration selected an SNMP backend")

    monkeypatch.setattr(selection_module, "select_snmp_backend", fail_selection)
    config = load_config(
        _minimal_config(tmp_path / "reader.toml", backend=None),
        env={},
        credential_mode=CredentialMode.DISABLED,
        resolve_paths=False,
    )

    assert config.snmp.backend == "pysnmp"
    assert config.snmp.selected_backend is None
    assert config.snmp.selected_backend_version is None


@pytest.mark.parametrize(
    ("backend", "distribution", "version"),
    [
        ("gufo", "gufo-snmp", "0.12.0"),
        ("pysnmp", "pysnmp", "7.1.29"),
    ],
)
def test_backend_version_comes_from_selected_distribution_metadata(
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    distribution: str,
    version: str,
) -> None:
    """Selection records only the chosen package version without importing it."""

    looked_up: list[str] = []

    def fake_version(name: str) -> str:
        looked_up.append(name)
        return version

    monkeypatch.setattr(selection_module.importlib.metadata, "version", fake_version)
    config = SnmpConfig(backend=backend)

    selected = selection_module.select_snmp_backend(config)

    assert selected.name == backend
    assert selected.version == version
    assert looked_up == [distribution]


def test_backend_precedence_file_environment_set_and_dedicated_cli(
    tmp_path: Path,
) -> None:
    path = _minimal_config(tmp_path / "config.toml", backend="gufo")
    config = _load(
        path,
        env={"LLDP_RUNNER_SNMP_BACKEND": "pysnmp"},
        set_expressions=['snmp.backend="gufo"'],
        overrides={"snmp_backend": "pysnmp"},
    )
    assert config.snmp.backend == "pysnmp"
    assert config.snmp.selected_backend == "pysnmp"


def test_explicit_gufo_dedicated_option_overrides_the_pysnmp_default(
    tmp_path: Path,
) -> None:
    """The new default must not weaken normal dedicated-option precedence."""

    path = _minimal_config(tmp_path / "implicit.toml", backend=None)
    config = _load(
        path,
        env={"LLDP_RUNNER_SNMP_BACKEND": "pysnmp"},
        set_expressions=['snmp.backend="pysnmp"'],
        overrides={"snmp_backend": "gufo"},
    )
    assert config.snmp.backend == "gufo"
    assert selected_snmp_backend(config.snmp).name == "gufo"


def test_invalid_backend_is_rejected_during_configuration_validation(
    tmp_path: Path,
) -> None:
    path = _minimal_config(tmp_path / "invalid.toml", backend="automatic")
    with pytest.raises(ConfigError, match=r"snmp\.backend must be gufo or pysnmp"):
        _load(path, env={})


def _v3_config(
    path: Path,
    *,
    backend: str,
    auth_protocol: str,
    priv_protocol: str,
) -> Path:
    """Write one complete authPriv configuration for capability tests."""

    path.write_text(
        "\n".join(
            (
                "[snmp]",
                f'backend = "{backend}"',
                "[credentials.site-v3]",
                'version = "v3"',
                'username = "operator"',
                'auth_password = "auth-secret"',
                'priv_password = "priv-secret"',
                f'auth_protocol = "{auth_protocol}"',
                f'priv_protocol = "{priv_protocol}"',
                "[credential_profiles.default]",
                'primary = "site-v3"',
                "[credential_rules]",
                'default_profile = "default"',
                "",
            )
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("auth_protocol", "priv_protocol"),
    [
        ("sha256", "aes128"),
        ("sha1", "aes256"),
        ("sha256", "aes256-blumenthal"),
    ],
)
def test_pysnmp_accepts_explicit_sha256_and_aes256_mappings(
    tmp_path: Path,
    auth_protocol: str,
    priv_protocol: str,
) -> None:
    """PySNMP-only algorithms are preserved as canonical credential values."""

    config = load_config(
        _v3_config(
            tmp_path / f"pysnmp-{auth_protocol}-{priv_protocol}.toml",
            backend="pysnmp",
            auth_protocol=auth_protocol,
            priv_protocol=priv_protocol,
        ),
        env={},
        resolve_paths=False,
    )

    credential = config.credentials["site-v3"]
    assert credential.auth_protocol == auth_protocol
    assert credential.priv_protocol == priv_protocol


@pytest.mark.parametrize(
    ("field", "auth_protocol", "priv_protocol"),
    [
        ("auth_protocol", "sha256", "aes128"),
        ("priv_protocol", "sha1", "aes256"),
        ("priv_protocol", "sha1", "aes256-blumenthal"),
    ],
)
def test_gufo_rejects_pysnmp_only_v3_algorithms_early(
    tmp_path: Path,
    field: str,
    auth_protocol: str,
    priv_protocol: str,
) -> None:
    """Gufo never downgrades, remaps, or hands unsupported crypto to workers."""

    path = _v3_config(
        tmp_path / f"gufo-{field}-{priv_protocol}.toml",
        backend="gufo",
        auth_protocol=auth_protocol,
        priv_protocol=priv_protocol,
    )
    with pytest.raises(ConfigError, match=rf"SNMP backend 'gufo'.*{field}"):
        load_config(path, env={}, resolve_paths=False)


@pytest.mark.parametrize("backend", ["gufo", "pysnmp"])
@pytest.mark.parametrize(
    ("field", "auth_protocol", "priv_protocol"),
    [
        ("auth_protocol", "sha512", "aes128"),
        ("priv_protocol", "sha1", "aes192"),
        ("priv_protocol", "sha1", "aes256-reeder"),
    ],
)
def test_unknown_v3_protocol_names_are_rejected_for_both_backends(
    tmp_path: Path,
    backend: str,
    field: str,
    auth_protocol: str,
    priv_protocol: str,
) -> None:
    """Only documented canonical spellings are accepted; no alias is guessed."""

    path = _v3_config(
        tmp_path / f"{backend}-{field}-{priv_protocol}.toml",
        backend=backend,
        auth_protocol=auth_protocol,
        priv_protocol=priv_protocol,
    )
    with pytest.raises(ConfigError, match=rf"SNMP backend '{backend}'.*{field}"):
        load_config(path, env={}, resolve_paths=False)


def test_runtime_backend_binding_fields_are_not_valid_toml_options(
    tmp_path: Path,
) -> None:
    path = _minimal_config(tmp_path / "invalid-runtime.toml")
    path.write_text(
        path.read_text(encoding="utf-8") + 'selected_backend = "pysnmp"\n',
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="selected_backend"):
        _load(path, env={})


def test_selected_backend_cannot_change_after_runtime_binding(tmp_path: Path) -> None:
    config = _load(_minimal_config(tmp_path / "config.toml"), env={})
    assert selected_snmp_backend(config.snmp).name == "gufo"
    config.snmp.backend = "pysnmp"
    with pytest.raises(ValueError, match="selection is fixed"):
        selected_snmp_backend(config.snmp)


def test_bound_backend_survives_worker_pickle_boundary(tmp_path: Path) -> None:
    """Spawned-worker serialization retains the coordinator's exact selection."""

    config = _load(
        _minimal_config(tmp_path / "config.toml", backend="pysnmp"),
        env={},
    )
    config.snmp.selected_backend_version = "7.1.29"

    worker_config = pickle.loads(pickle.dumps(config))

    assert selected_snmp_backend(worker_config.snmp).name == "pysnmp"
    assert worker_config.snmp.selected_backend_version == "7.1.29"


def test_same_backend_resume_succeeds_and_mismatch_fails_before_manifest(
    tmp_path: Path,
) -> None:
    path = _minimal_config(tmp_path / "config.toml", backend="gufo")
    first_config = _load(path, env={})
    first_config.snmp.selected_backend_version = "0.12.0"
    paths = make_run_paths(first_config, "backend-resume")
    first = Coordinator(first_config, paths, resume=False)
    try:
        first.initialize([SeedInput("198.18.0.1")])
        assert first.state.get_meta("snmp_backend") == "gufo"
        assert first.state.get_meta("snmp_backend_version") == "0.12.0"
    finally:
        first.close()

    same_config = _load(path, env={})
    same_config.snmp.selected_backend_version = "0.12.0"
    resumed = Coordinator(same_config, paths, resume=True)
    resumed.close()

    mismatch_config = _load(
        path,
        env={"LLDP_RUNNER_SNMP_BACKEND": "pysnmp"},
    )
    mismatch_config.snmp.selected_backend_version = "7.1.29"
    assert not (paths.run_dir / "run.json.draft").exists()
    with pytest.raises(ValueError, match="cannot resume with a different"):
        Coordinator(mismatch_config, paths, resume=True)
    assert not (paths.run_dir / "run.json.draft").exists()


def test_default_change_requires_explicit_gufo_for_an_existing_gufo_resume(
    tmp_path: Path,
) -> None:
    """The 0.37 default must not silently change a Gufo run during resume."""

    gufo_path = _minimal_config(tmp_path / "gufo.toml", backend="gufo")
    first_config = _load(gufo_path, env={})
    first_config.snmp.selected_backend_version = "0.12.0"
    paths = make_run_paths(first_config, "gufo-before-default-change")
    first = Coordinator(first_config, paths, resume=False)
    try:
        first.initialize([SeedInput("198.18.0.10")])
        assert first.state.get_meta("snmp_backend") == "gufo"
    finally:
        first.close()

    implicit_path = _minimal_config(tmp_path / "implicit.toml", backend=None)
    implicit_pysnmp = _load(implicit_path, env={})
    implicit_pysnmp.snmp.selected_backend_version = "7.1.29"
    assert selected_snmp_backend(implicit_pysnmp.snmp).name == "pysnmp"
    with pytest.raises(ValueError, match="cannot resume with a different"):
        Coordinator(implicit_pysnmp, paths, resume=True)

    explicit_gufo = _load(gufo_path, env={})
    explicit_gufo.snmp.selected_backend_version = "0.12.0"
    resumed = Coordinator(explicit_gufo, paths, resume=True)
    resumed.close()


def test_new_default_pysnmp_run_resumes_without_an_explicit_backend(
    tmp_path: Path,
) -> None:
    """Omitting the backend consistently selects PySNMP for a new run/resume."""

    path = _minimal_config(tmp_path / "implicit.toml", backend=None)
    first_config = _load(path, env={})
    first_config.snmp.selected_backend_version = "7.1.29"
    assert selected_snmp_backend(first_config.snmp).name == "pysnmp"
    paths = make_run_paths(first_config, "pysnmp-default-resume")
    first = Coordinator(first_config, paths, resume=False)
    try:
        first.initialize([SeedInput("198.18.0.11")])
        assert first.state.get_meta("snmp_backend") == "pysnmp"
    finally:
        first.close()

    resume_config = _load(path, env={})
    resume_config.snmp.selected_backend_version = "7.1.29"
    resumed = Coordinator(resume_config, paths, resume=True)
    resumed.close()


def test_real_pre_036_resume_without_backend_metadata_is_rejected(tmp_path: Path) -> None:
    config = _load(_minimal_config(tmp_path / "config.toml"), env={})
    paths = make_run_paths(config, "old-run")
    paths.run_dir.mkdir(parents=True)
    from lldp_runner.state import StateStore

    state = StateStore(paths.state_path)
    state.set_meta("run_id", paths.run_id)
    state.close()

    with pytest.raises(ValueError, match="without persisted SNMP backend metadata"):
        Coordinator(config, paths, resume=True)


def test_backend_diagnostics_are_durable_and_do_not_contain_secrets(
    tmp_path: Path,
) -> None:
    path = _minimal_config(tmp_path / "config.toml", backend="pysnmp")
    config = _load(path, env={})
    config.snmp.selected_backend_version = "7.1.29"
    provenance = build_invocation_provenance(
        config,
        argv=["run", "--snmp-backend", "pysnmp"],
        arguments={"command": "run", "snmp_backend": "pysnmp"},
        seeds=[],
        env={"SNMPCOMM": "do-not-persist"},
    )
    paths = make_run_paths(config, "diagnostic-run")
    coordinator = Coordinator(
        config,
        paths,
        resume=False,
        invocation_provenance=provenance,
    )
    try:
        payload = json.loads((paths.run_dir / "run.json.draft").read_text(encoding="utf-8"))
        assert payload["snmp_backend"] == {"name": "pysnmp", "version": "7.1.29"}
        assert payload["invocations"][0]["snmp_backend"] == payload["snmp_backend"]
        rendered = json.dumps(payload)
        assert "do-not-persist" not in rendered
        assert coordinator.state.get_meta("snmp_backend") == "pysnmp"
        assert coordinator.state.get_meta("snmp_backend_version") == "7.1.29"
    finally:
        coordinator.close()


@pytest.mark.parametrize("backend", ["gufo", "pysnmp"])
def test_factory_never_falls_back_or_mixes_backends(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    """A selected backend failure must never instantiate the other package."""

    config = _load(
        _minimal_config(tmp_path / f"{backend}.toml", backend=backend),
        env={},
    )
    constructed = {"gufo": 0, "pysnmp": 0}

    def backend_class(name: str):
        class SelectedBackend:
            def __init__(self, *args, **kwargs) -> None:
                constructed[name] += 1

            async def __aenter__(self):
                if name == backend:
                    raise RuntimeError(f"{name} selected backend failed")
                raise AssertionError("unselected backend was instantiated")

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

        return SelectedBackend

    gufo_module = types.ModuleType("lldp_runner.snmp.gufo")
    gufo_module.GufoSnmpClient = backend_class("gufo")
    pysnmp_module = types.ModuleType("lldp_runner.snmp.pysnmp")
    pysnmp_module.PySnmpClient = backend_class("pysnmp")
    monkeypatch.setitem(sys.modules, "lldp_runner.snmp.gufo", gufo_module)
    monkeypatch.setitem(sys.modules, "lldp_runner.snmp.pysnmp", pysnmp_module)

    credential = DirectCredential(
        name="test",
        version="v2c",
        community="not-persisted",
    )
    client = create_snmp_client(config, "192.0.2.100", credential)

    async def exercise() -> None:
        async with client:
            pass

    with pytest.raises(RuntimeError, match=f"{backend} selected backend failed"):
        asyncio.run(exercise())
    assert constructed[backend] == 1
    other = "pysnmp" if backend == "gufo" else "gufo"
    assert constructed[other] == 0
