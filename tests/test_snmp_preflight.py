"""Pre-discovery SNMP backend capability checks and lifecycle boundaries."""

from __future__ import annotations

from pathlib import Path

import pytest

from lldp_runner import coordinator as coordinator_module
from lldp_runner.config import CredentialConfig, CredentialMode, load_config
from lldp_runner.coordinator import Coordinator
from lldp_runner.models import DirectCredential
from lldp_runner.runtime import make_run_paths
from lldp_runner.seed_credentials import SeedCredentialLoad, SeedCredentialRecord
from lldp_runner.snmp.base import SnmpBackendCapabilityError
from lldp_runner.snmp.preflight import (
    preflight_snmp_backend,
    required_authpriv_protocols,
)


def _write_config(
    path: Path,
    *,
    backend: str,
    include_v3: bool = False,
    auth_protocol: str = "sha1",
    priv_protocol: str = "aes128",
) -> Path:
    """Write a minimal config whose named v3 credential is profile-reachable."""

    lines = [
        "[paths]",
        f'persistent_root = "{path.parent / "persistent"}"',
        f'scratch_root = "{path.parent / "scratch"}"',
        "[snmp]",
        f'backend = "{backend}"',
        "[logging]",
        "file = false",
        "console = false",
    ]
    if include_v3:
        lines.extend(
            [
                "[credentials.site-v3]",
                'version = "v3"',
                'username = "operator"',
                'auth_password = "not-read-by-preflight"',
                'priv_password = "not-read-by-preflight"',
                f'auth_protocol = "{auth_protocol}"',
                f'priv_protocol = "{priv_protocol}"',
                "[credentials.dormant-v3]",
                'version = "v3"',
                'username = "dormant"',
                'auth_password = "dormant-auth"',
                'priv_password = "dormant-priv"',
                'auth_protocol = "md5"',
                'priv_protocol = "des"',
                "[credential_profiles.default]",
                'primary = "site-v3"',
                "[credential_rules]",
                'default_profile = "default"',
            ]
        )
    path.write_text("\n".join((*lines, "")), encoding="utf-8")
    return path


def _load(path: Path):
    return load_config(
        path,
        env={},
        credential_mode=CredentialMode.OPTIONAL,
        resolve_paths=False,
    )


def test_required_authpriv_protocols_include_reachable_and_direct_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _load(_write_config(tmp_path / "pysnmp.toml", backend="pysnmp", include_v3=True))
    direct = DirectCredential(
        name="seed-direct",
        version="v3",
        username="seed-user",
        auth_password="seed-auth",
        priv_password="seed-priv",
        auth_protocol="md5",
        priv_protocol="des",
    )

    def fail_secret_access(
        _credential: CredentialConfig,
        _field_name: str,
        _env: object = None,
    ) -> str | None:
        raise AssertionError("preflight accessed credential secret material")

    monkeypatch.setattr(CredentialConfig, "secret", fail_secret_access)

    assert required_authpriv_protocols(config) == ("aes128",)
    assert required_authpriv_protocols(config, direct_credentials=(direct,)) == (
        "aes128",
        "des",
    )


def test_required_authpriv_protocols_preserve_both_aes256_mappings(
    tmp_path: Path,
) -> None:
    """Keep Reeder/Cisco and Blumenthal routes distinct in run preflight."""

    config = _load(
        _write_config(
            tmp_path / "pysnmp-aes256.toml",
            backend="pysnmp",
            include_v3=True,
            auth_protocol="sha256",
            priv_protocol="aes256",
        )
    )
    direct = DirectCredential(
        name="seed-direct-blumenthal",
        version="v3",
        username="seed-user",
        auth_password="seed-auth",
        priv_password="seed-priv",
        auth_protocol="sha256",
        priv_protocol="aes256-blumenthal",
    )

    assert required_authpriv_protocols(config, direct_credentials=(direct,)) == (
        "aes256",
        "aes256-blumenthal",
    )


def test_pysnmp_preflight_delegates_distinct_protocols_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _load(_write_config(tmp_path / "pysnmp.toml", backend="pysnmp", include_v3=True))
    observed: list[tuple[str, ...]] = []

    from lldp_runner.snmp import pysnmp as pysnmp_module

    monkeypatch.setattr(
        pysnmp_module,
        "preflight_pysnmp_authpriv",
        lambda protocols: observed.append(tuple(protocols)),
    )

    assert preflight_snmp_backend(config) == ("aes128",)
    assert observed == [("aes128",)]


def test_gufo_and_pysnmp_v2c_do_not_require_crypto_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from lldp_runner.snmp import pysnmp as pysnmp_module

    monkeypatch.setattr(
        pysnmp_module,
        "preflight_pysnmp_authpriv",
        lambda _protocols: (_ for _ in ()).throw(
            AssertionError("authPriv preflight unexpectedly executed")
        ),
    )
    gufo = _load(_write_config(tmp_path / "gufo.toml", backend="gufo"))
    pysnmp_v2 = _load(_write_config(tmp_path / "pysnmp-v2.toml", backend="pysnmp"))

    assert preflight_snmp_backend(gufo) == ()
    assert preflight_snmp_backend(pysnmp_v2) == ()


def test_coordinator_supplies_direct_protocol_metadata_before_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _load(_write_config(tmp_path / "pysnmp.toml", backend="pysnmp"))
    direct = DirectCredential(
        name="seed-direct",
        version="v3",
        username="seed-user",
        auth_password="seed-auth",
        priv_password="seed-priv",
        priv_protocol="des",
    )
    seed_load = SeedCredentialLoad(
        records=[
            SeedCredentialRecord(
                seed="192.0.2.1",
                strategy="exclusive",
                credential_label="direct",
                credential_profile=None,
                direct_credential=direct,
                source=tmp_path / "seed-credentials.csv",
                source_line=2,
                order=1,
            )
        ]
    )
    observed: list[tuple[DirectCredential, ...]] = []

    def fake_preflight(_config, *, direct_credentials=()):
        observed.append(tuple(direct_credentials))
        return ("des",)

    monkeypatch.setattr(coordinator_module, "preflight_snmp_backend", fake_preflight)
    paths = make_run_paths(config, "direct-preflight")
    coordinator = Coordinator(
        config,
        paths,
        resume=False,
        seed_credential_load=seed_load,
    )
    try:
        assert observed == [(direct,)]
        assert coordinator.snmp_preflight_protocols == ("des",)
    finally:
        coordinator.close()


def test_preflight_failure_closes_state_and_precedes_manifest_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _load(_write_config(tmp_path / "pysnmp.toml", backend="pysnmp"))
    paths = make_run_paths(config, "failed-preflight")

    def fail_preflight(_config, *, direct_credentials=()):
        assert tuple(direct_credentials) == ()
        raise SnmpBackendCapabilityError(
            "PySNMP authPriv preflight failed: local cipher capability unavailable"
        )

    monkeypatch.setattr(coordinator_module, "preflight_snmp_backend", fail_preflight)

    with pytest.raises(SnmpBackendCapabilityError, match="cipher capability"):
        Coordinator(config, paths, resume=False)

    assert not (paths.run_dir / "run.json.draft").exists()
    # The failed constructor must not retain an open SQLite handle. A second
    # local open/close confirms the coordinator released its state ownership.
    from lldp_runner.state import StateStore

    state = StateStore(paths.state_path)
    state.close()


def test_resume_backend_mismatch_is_rejected_before_capability_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gufo = _load(_write_config(tmp_path / "gufo.toml", backend="gufo"))
    paths = make_run_paths(gufo, "resume-order")
    first = Coordinator(gufo, paths, resume=False)
    try:
        first.state.set_meta("run_id", paths.run_id)
    finally:
        first.close()

    pysnmp = _load(_write_config(tmp_path / "pysnmp.toml", backend="pysnmp"))

    def unexpected_preflight(_config, *, direct_credentials=()):
        raise AssertionError("preflight ran before durable resume mismatch validation")

    monkeypatch.setattr(
        coordinator_module,
        "preflight_snmp_backend",
        unexpected_preflight,
    )

    with pytest.raises(ValueError, match="cannot resume with a different"):
        Coordinator(pysnmp, paths, resume=True)
