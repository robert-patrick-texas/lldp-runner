from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from lldp_runner.classify import Classifier
from lldp_runner.coordinator import Coordinator
from lldp_runner.models import DeviceTask, SeedInput, TargetAttempt
from lldp_runner.policy import PolicyEngine
from lldp_runner.seed_credentials import (
    SEED_CREDENTIAL_COLUMNS,
    SeedCredentialLoad,
    load_seed_credential_files,
)
from lldp_runner.state import StateStore
from lldp_runner.worker import _BasicState


def _secure_write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def _coordinator(config, tmp_path: Path, load: SeedCredentialLoad, *, resume: bool = False):
    scratch = tmp_path / "scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.paths = SimpleNamespace(run_id="seed-cred-test", scratch_dir=scratch)
    coordinator.resume = resume
    coordinator.seed_credential_load = load
    coordinator.seed_credential_bindings = {}
    coordinator.state = StateStore(tmp_path / "state.sqlite")
    coordinator.policy = PolicyEngine(config)
    coordinator.classifier = Classifier(config)
    coordinator.seed_only = isinstance(config.discovery.max_devices, str) and (
        config.discovery.max_devices.lower() == "auto"
    )
    coordinator.effective_max_devices = None
    coordinator.pause_event = Event()
    coordinator.limit_reached = False
    coordinator.limit_reason = None
    coordinator.started_text = "test"
    return coordinator


def test_csv_parser_preserves_order_comments_and_reused_labels(tmp_path: Path, config) -> None:
    path = _secure_write(
        tmp_path / "seed-creds.csv",
        "# protected credential overlay\n"
        + ",".join(SEED_CREDENTIAL_COLUMNS)
        + "\n"
        + "198.18.20.1,prefer,alpha,,v2c,first,,,,,\n"
        + " ; disabled row\n"
        + "198.18.20.1,,alpha,specific,,,,,,,\n"
        + "198.18.20.2,exclusive,alpha,,v2c,second,,,,,\n",
    )

    loaded = load_seed_credential_files([path], config)

    assert [record.seed for record in loaded.records] == [
        "198.18.20.1",
        "198.18.20.1",
        "198.18.20.2",
    ]
    assert [record.credential_label for record in loaded.records] == ["alpha", "alpha", "alpha"]
    assert [record.strategy for record in loaded.records] == ["prefer", "prefer", "exclusive"]
    assert loaded.records[0].direct_credential is not None
    assert loaded.records[1].credential_profile == "specific"


def test_csv_parser_accepts_reordered_case_insensitive_columns(tmp_path: Path, config) -> None:
    """Credential CSV field positions are resolved dynamically from the header."""

    path = _secure_write(
        tmp_path / "reordered.csv",
        "COMMUNITY,SEED,CREDENTIAL_LABEL,SNMP_VERSION,CREDENTIAL_STRATEGY,"
        "CREDENTIAL_PROFILE,USERNAME,AUTH_PASSWORD,PRIV_PASSWORD,"
        "AUTH_PROTOCOL,PRIV_PROTOCOL,ignored\n"
        "secret,198.18.20.1,alpha,v2c,prefer,,,,,,,discard me\n",
    )

    loaded = load_seed_credential_files([path], config)

    assert len(loaded.records) == 1
    record = loaded.records[0]
    assert record.seed == "198.18.20.1"
    assert record.source_line == 2
    assert record.credential_label == "alpha"
    assert record.direct_credential is not None
    assert record.direct_credential.community == "secret"


def test_json_array_order_controls_attempt_order_not_source_line(tmp_path: Path, config) -> None:
    path = _secure_write(
        tmp_path / "seed-creds.json",
        json.dumps(
            [
                {
                    "seed": "198.18.20.1",
                    "credential_strategy": "prefer",
                    "credential_label": "first",
                    "snmp_version": "v2c",
                    "community": "one",
                    "source_line": 99,
                },
                {
                    "seed": "198.18.20.1",
                    "credential_label": "second",
                    "credential_profile": "specific",
                    "source_line": 2,
                },
            ]
        ),
    )

    loaded = load_seed_credential_files([path], config)

    assert [record.credential_label for record in loaded.records] == ["first", "second"]
    assert [record.source_line for record in loaded.records] == [99, 2]


def test_seed_present_but_without_credential_data_warns_and_skips(tmp_path: Path, config) -> None:
    path = _secure_write(
        tmp_path / "empty.csv",
        ",".join(SEED_CREDENTIAL_COLUMNS) + "\n198.18.20.1,prefer,alpha,,,,,,,,\n",
    )

    loaded = load_seed_credential_files([path], config)

    assert loaded.records == []
    assert len(loaded.warnings) == 1
    assert "has no credential data; skipped" in loaded.warnings[0]


def test_literal_secret_file_rejects_world_readable_permissions(tmp_path: Path, config) -> None:
    path = tmp_path / "unsafe.csv"
    path.write_text(
        ",".join(SEED_CREDENTIAL_COLUMNS) + "\n198.18.20.1,prefer,alpha,,v2c,secret,,,,,\n",
        encoding="utf-8",
    )
    path.chmod(0o644)

    with pytest.raises(ValueError, match="world-readable or world-writable"):
        load_seed_credential_files([path], config)


def test_unmatched_records_log_only_and_never_create_seeds(
    tmp_path: Path, config, caplog: pytest.LogCaptureFixture
) -> None:
    path = _secure_write(
        tmp_path / "overlay.csv",
        ",".join(SEED_CREDENTIAL_COLUMNS)
        + "\n198.18.20.1,prefer,alpha,,v2c,first,,,,,\n"
        + "198.18.20.99,prefer,unused,,v2c,second,,,,,\n",
    )
    loaded = load_seed_credential_files([path], config)
    coordinator = _coordinator(config, tmp_path, loaded)

    with caplog.at_level("INFO"):
        coordinator.initialize([SeedInput("198.18.20.1")])

    assert coordinator.state.seed_device_count() == 1
    assert coordinator.state.host_count() == 1
    assert "seed credential record unmatched" in caplog.text
    assert "seed credential bindings: 1 matched, 1 unmatched" in caplog.text
    coordinator.state.close()


def test_prefer_and_exclusive_compile_to_ordered_task_attempts(tmp_path: Path, config) -> None:
    path = _secure_write(
        tmp_path / "overlay.csv",
        ",".join(SEED_CREDENTIAL_COLUMNS)
        + "\n198.18.20.1,prefer,alpha,,v2c,first,,,,,\n"
        + "198.18.20.1,,beta,specific,,,,,,,\n"
        + "198.18.20.2,exclusive,gamma,,v2c,second,,,,,\n",
    )
    loaded = load_seed_credential_files([path], config)
    coordinator = _coordinator(config, tmp_path, loaded)
    coordinator.initialize([SeedInput("198.18.20.1"), SeedInput("198.18.20.2")])

    by_name = {str(row["preferred_name"]): int(row["id"]) for row in coordinator.state.seed_hosts()}
    prefer_task = coordinator._build_task(by_name["198.18.20.1"])
    exclusive_task = coordinator._build_task(by_name["198.18.20.2"])
    assert prefer_task is not None
    assert exclusive_task is not None

    assert [
        (item.credential_source, item.credential_label, item.credential_profile)
        for item in prefer_task.attempts
    ] == [
        ("seed-direct", "alpha", None),
        ("seed-profile", "beta", "specific"),
        ("policy-profile", None, "default"),
    ]
    assert [
        (item.credential_source, item.credential_label) for item in exclusive_task.attempts
    ] == [("seed-direct", "gamma")]
    coordinator.state.close()


def test_worker_state_advances_direct_then_profile_without_label_identity(config) -> None:
    from lldp_runner.models import DirectCredential

    direct = DirectCredential(name="internal-one", version="v2c", community="private")
    task = DeviceTask(
        host_id=1,
        preferred_name="seed",
        names=["seed"],
        addresses=["198.18.20.1"],
        attempts=[
            TargetAttempt(
                address="198.18.20.1",
                direct_credential=direct,
                credential_source="seed-direct",
                credential_label="alpha",
            ),
            TargetAttempt(
                address="198.18.20.1",
                credential_profile="default",
                credential_source="policy-profile",
            ),
        ],
        cohort=0,
    )
    state = _BasicState(task=task, errors=[])

    first = state.current(config)
    assert first.credential_result == "direct"
    assert first.credential_label == "alpha"
    state.advance(config)
    second = state.current(config)
    assert second.credential_result == "primary"
    assert second.profile_name == "default"
    assert second.address == first.address


def test_resume_requires_seed_credential_overlay_again(tmp_path: Path, config) -> None:
    path = _secure_write(
        tmp_path / "overlay.csv",
        ",".join(SEED_CREDENTIAL_COLUMNS) + "\n198.18.20.1,exclusive,alpha,,v2c,private,,,,,\n",
    )
    loaded = load_seed_credential_files([path], config)
    first = _coordinator(config, tmp_path, loaded)
    first.initialize([SeedInput("198.18.20.1")])
    first.state.close()

    resumed = _coordinator(config, tmp_path, SeedCredentialLoad(), resume=True)
    with pytest.raises(ValueError, match="requires seed credential input"):
        resumed.initialize([])
    resumed.state.close()


def test_conflicting_strategy_for_same_seed_is_rejected(tmp_path: Path, config) -> None:
    path = _secure_write(
        tmp_path / "conflict.csv",
        ",".join(SEED_CREDENTIAL_COLUMNS)
        + "\n198.18.20.1,prefer,one,,v2c,first,,,,,\n"
        + "198.18.20.1,exclusive,two,,v2c,second,,,,,\n",
    )

    with pytest.raises(ValueError, match="conflicting strategies"):
        load_seed_credential_files([path], config)


def test_profile_and_direct_fields_are_mutually_exclusive(tmp_path: Path, config) -> None:
    path = _secure_write(
        tmp_path / "mixed.csv",
        ",".join(SEED_CREDENTIAL_COLUMNS)
        + "\n198.18.20.1,prefer,alpha,specific,v2c,private,,,,,\n",
    )

    with pytest.raises(ValueError, match="cannot be combined"):
        load_seed_credential_files([path], config)


@pytest.mark.parametrize("priv_protocol", ["aes256", "aes256-blumenthal"])
def test_direct_v3_pysnmp_accepts_sha256_and_aes256_variants(
    tmp_path: Path,
    config,
    priv_protocol: str,
) -> None:
    """Seed-direct credentials use the same PySNMP capability mapping."""

    selected_config = deepcopy(config)
    selected_config.snmp.backend = "pysnmp"
    selected_config.snmp.selected_backend = None
    selected_config.snmp.selected_backend_version = None
    path = _secure_write(
        tmp_path / f"pysnmp-{priv_protocol}.csv",
        ",".join(SEED_CREDENTIAL_COLUMNS)
        + f"\n198.18.20.1,exclusive,strong,,v3,,operator,auth,priv,sha256,{priv_protocol}\n",
    )

    loaded = load_seed_credential_files([path], selected_config)

    direct = loaded.records[0].direct_credential
    assert direct is not None
    assert direct.auth_protocol == "sha256"
    assert direct.priv_protocol == priv_protocol


@pytest.mark.parametrize(
    ("field", "auth_protocol", "priv_protocol"),
    [
        ("auth_protocol", "sha256", "aes128"),
        ("priv_protocol", "sha1", "aes256"),
        ("priv_protocol", "sha1", "aes256-blumenthal"),
    ],
)
def test_direct_v3_gufo_rejects_pysnmp_only_algorithms_early(
    tmp_path: Path,
    config,
    field: str,
    auth_protocol: str,
    priv_protocol: str,
) -> None:
    """Direct seed overlays cannot bypass Gufo's narrower crypto support."""

    selected_config = deepcopy(config)
    selected_config.snmp.backend = "gufo"
    selected_config.snmp.selected_backend = None
    selected_config.snmp.selected_backend_version = None
    path = _secure_write(
        tmp_path / f"gufo-{field}-{priv_protocol}.csv",
        ",".join(SEED_CREDENTIAL_COLUMNS)
        + f"\n198.18.20.1,exclusive,bad,,v3,,operator,auth,priv,{auth_protocol},{priv_protocol}\n",
    )

    with pytest.raises(ValueError, match=rf"SNMP backend 'gufo'.*{field}"):
        load_seed_credential_files([path], selected_config)


def test_seed_credential_loading_rejects_backend_mutation_after_selection(
    tmp_path: Path,
    config,
) -> None:
    """Seed overlays cannot reinterpret credentials through a backend switch."""

    assert config.snmp.selected_backend == "gufo"
    config.snmp.backend = "pysnmp"
    path = _secure_write(
        tmp_path / "mutated-backend.csv",
        ",".join(SEED_CREDENTIAL_COLUMNS) + "\n198.18.20.1,exclusive,alpha,,v2c,private,,,,,\n",
    )

    with pytest.raises(ValueError, match="SNMP backend selection is fixed"):
        load_seed_credential_files([path], config)
