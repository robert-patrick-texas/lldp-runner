"""Operator-defined CSV output rendered from canonical discovery JSON."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from lldp_runner.config import ConfigError, CredentialMode, load_config
from lldp_runner.outputs import write_custom_csv_outputs


def _document() -> dict:
    """Return a compact schema-v3 document covering every custom row source."""

    return {
        "schema_version": 8,
        "discovery": {
            "run_id": "run-07",
            "status": "COMPLETED",
            "started": "2026-08-25T00:00:00-04:00",
            "completed": "2026-08-25T00:00:10-04:00",
            "generated": "2026-08-25T00:00:10-04:00",
            "boundaries": ["192.0.2.0/24"],
            "counts": {"complete": 2},
        },
        "hosts": [
            {
                "id": 1,
                "preferred_name": "stack01.example.net",
                "queried_as": "192.0.2.10",
                "snmp_sysname": "stack01",
                "classification": "managed_device",
                "classification_reason": ["system-manufacturer"],
                "tags": ["access", "site-a"],
                "state": "complete",
                "is_seed": True,
                "first_seen": "2026-08-25T00:00:01-04:00",
                "last_seen": "2026-08-25T00:00:05-04:00",
                "last_seen_source": "snmp",
                "names": ["stack01.example.net"],
                "addresses": {"ipv4": ["192.0.2.10"], "ipv6": []},
                "chassis_id": "stack-chassis",
                "icmp": [],
                "system": {
                    "manufacturer": "Cisco",
                    "model": "C9300-48P",
                    "version": "17.15",
                    "serial_number": "STACKSERIAL",
                    "sys_uptime_ticks": 1200,
                    "stack_members": [
                        {
                            "entity_index": 1001,
                            "member_number": 1,
                            "name": "Switch 1",
                            "description": "C9300 member",
                            "manufacturer": "Cisco",
                            "model": "C9300-48P",
                            "serial_number": "MEMBER01",
                            "hardware_revision": "V02",
                            "firmware_revision": "17.15",
                            "software_revision": "17.15",
                            "uptime_seconds": None,
                        }
                    ],
                },
                "snmp": {
                    "credential_profile": "default",
                    "credential_result": "primary",
                },
                "learned_neighbors": [],
                "observed_by_neighbors": [],
            },
            {
                "id": 2,
                "preferred_name": "unknown-device",
                "queried_as": None,
                "snmp_sysname": None,
                "classification": "unknown_device",
                "classification_reason": ["neighbor-only"],
                "tags": [],
                "state": "no_query",
                "is_seed": False,
                "first_seen": "2026-08-25T00:00:02-04:00",
                "last_seen": "2026-08-25T00:00:03-04:00",
                "last_seen_source": "lldp",
                "names": [],
                "addresses": {"ipv4": ["192.0.2.99"], "ipv6": []},
                "chassis_id": "unknown-chassis",
                "icmp": [],
                "system": {},
                "snmp": {"credential_profile": None, "credential_result": None},
                "learned_neighbors": [],
                "observed_by_neighbors": [
                    {
                        "host_ref": 1,
                        "name": "stack01.example.net",
                        "classification": "managed_device",
                        "local_interface": "eth0",
                        "local_interface_raw": "eth0",
                        "remote_interface": "Gi1/0/1",
                        "remote_interface_raw": "Gi1/0/1",
                        "protocols": ["cdp", "lldp"],
                        "protocol_tag": "[cdp,lldp]",
                        "observed_name": "unknown-device",
                        "observed_addresses": ["192.0.2.99"],
                        "details": {
                            "chassis_id": "unknown-chassis",
                            "chassis_id_subtype": "local",
                            "chassis_id_subtype_id": 7,
                        },
                        "last_seen": "2026-08-25T00:00:03-04:00",
                    }
                ],
            },
        ],
        "errors": [
            {
                "host_ref": 1,
                "device": "stack01.example.net",
                "query_target": "192.0.2.10",
                "timestamp": "2026-08-25T00:00:04-04:00",
                "operation": "entity",
                "category": "optional_walk_failed",
                "credential_profile": "default",
                "credential_stage": "primary",
                "attempt": 1,
                "message": "optional data unavailable",
                "recoverable": True,
                "final_state": "complete",
            }
        ],
    }


def _config(tmp_path: Path, body: str):
    """Load one custom-output configuration without credential/path requirements."""

    path = tmp_path / "config.toml"
    path.write_text(body.lstrip(), encoding="utf-8")
    return load_config(
        path,
        credential_mode=CredentialMode.OPTIONAL,
        resolve_paths=False,
    )


def test_custom_hosts_csv_supports_fixed_json_transforms_and_headers(tmp_path: Path) -> None:
    """One host row can mix fixed semantics, JSON scalars, transforms, and metadata."""

    config = _config(
        tmp_path,
        """
[output.custom_csv.inventory]
filename = "inventory.csv"
source = "hosts"
columns = [
  { field = "hosts.preferred_name", header = "FQDN" },
  { field = "hosts.origin" },
  { field = "json.host.system.model" },
  { field = "json.host.addresses.ipv4", transform = "join:semicolon", header = "management_target" },
  { field = "json.host.is_seed", transform = "origin", header = "source" },
  { field = "json.discovery.run_id" },
]
""",
    )

    paths = write_custom_csv_outputs(_document(), config, tmp_path / "out")
    assert [path.name for path in paths] == ["inventory.csv"]
    with paths[0].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0] == {
        "FQDN": "stack01.example.net",
        "origin": "seed",
        "model": "C9300-48P",
        "management_target": "192.0.2.10",
        "source": "seed",
        "run_id": "run-07",
    }
    assert rows[1]["FQDN"] == "unknown-device"
    assert rows[1]["origin"] == "learned"


def test_seed_source_can_project_fixed_host_inventory_fields(tmp_path: Path) -> None:
    """Seed rows can reuse fixed host presentation fields without changing grain."""

    example = (
        Path(__file__).resolve().parents[1]
        / "configs"
        / "conf.d"
        / "custom-inventory-csv.toml.example"
    )
    config = load_config(
        example,
        credential_mode=CredentialMode.DISABLED,
        resolve_paths=False,
    )
    custom = config.output.custom_csv["inventory"]
    assert custom.source == "seeds"
    assert custom.filename == "inventory.csv"
    assert [column.field for column in custom.columns] == [
        "hosts.preferred_name",
        "hosts.queried_as",
        "hosts.ipv4",
        "hosts.ipv6",
        "hosts.serial_number",
        "hosts.model",
        "hosts.version",
        "hosts.learned_neighbors",
        "hosts.observed_by_neighbors",
        "hosts.tags",
    ]
    assert [column.header for column in custom.columns] == [
        "hostname",
        "management_ip",
        "ipv4",
        "ipv6",
        "serial_number",
        "model",
        "version",
        "learned_neighbors",
        "observed_by_neighbors",
        "tags",
    ]

    paths = write_custom_csv_outputs(_document(), config, tmp_path / "out")
    assert [path.name for path in paths] == ["inventory.csv"]
    with paths[0].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == [
        {
            "hostname": "stack01.example.net",
            "management_ip": "192.0.2.10",
            "ipv4": "192.0.2.10",
            "ipv6": "",
            "serial_number": "STACKSERIAL",
            "model": "C9300-48P",
            "version": "17.15",
            "learned_neighbors": "",
            "observed_by_neighbors": "",
            "tags": "access;site-a",
        }
    ]


def test_custom_row_sources_preserve_fixed_row_grain(tmp_path: Path) -> None:
    """Stack, seed, unknown, and error sources each produce their natural rows."""

    config = _config(
        tmp_path,
        """
[output.custom_csv.members]
filename = "members.csv"
source = "stack-members"
columns = [
  { field = "stack-members.preferred_name" },
  { field = "json.member.member_number" },
  { field = "json.member.serial_number", header = "serial" },
]

[output.custom_csv.seed_export]
filename = "seed-export.csv"
source = "seeds"
columns = [
  { field = "seeds.preferred_name" },
  { field = "seeds.notes" },
]

[output.custom_csv.unknown]
filename = "unknown.csv"
source = "unknown-devices"
columns = [
  { field = "unknown-devices.preferred_name" },
  { field = "unknown-devices.observed_by_neighbors" },
]

[output.custom_csv.err]
filename = "err.csv"
source = "errors"
columns = [
  { field = "errors.category" },
  { field = "json.error.final_state" },
]
""",
    )

    out = tmp_path / "out"
    write_custom_csv_outputs(_document(), config, out)
    assert (out / "members.csv").read_text(encoding="utf-8").splitlines() == [
        "preferred_name,member_number,serial",
        "stack01.example.net,1,MEMBER01",
    ]
    assert "optional_walk_failed" in (out / "seed-export.csv").read_text(encoding="utf-8")
    assert "stack01.example.net:Gi1/0/1=eth0[cdp,lldp]" in (out / "unknown.csv").read_text(
        encoding="utf-8"
    )
    assert (out / "err.csv").read_text(encoding="utf-8").splitlines() == [
        "category,final_state",
        "optional_walk_failed,complete",
    ]


def test_custom_csv_validation_rejects_ambiguous_or_unsafe_definitions(tmp_path: Path) -> None:
    """Invalid paths, structured values, duplicate headers, and filenames fail early."""

    cases = [
        (
            'filename = "hosts.csv"\nsource = "hosts"\ncolumns = [{ field = "hosts.preferred_name" }]',
            "collides with standard output",
        ),
        (
            'filename = "../escape.csv"\nsource = "hosts"\ncolumns = [{ field = "hosts.preferred_name" }]',
            "portable relative .csv filename",
        ),
        (
            'filename = "x.csv"\nsource = "hosts"\ncolumns = [{ field = "json.host.tags" }]',
            "contains a JSON list",
        ),
        (
            'filename = "x.csv"\nsource = "hosts"\ncolumns = [{ field = "errors.category" }]',
            "expected hosts.<field>",
        ),
        (
            'filename = "x.csv"\nsource = "hosts"\ncolumns = [{ field = "hosts.preferred_name", header = "same" }, { field = "hosts.state", header = "SAME" }]',
            "duplicate output header",
        ),
    ]
    for index, (body, message) in enumerate(cases):
        config_file = tmp_path / f"bad-{index}.toml"
        config_file.write_text(
            f"[output.custom_csv.bad]\n{body}\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match=message):
            load_config(
                config_file,
                credential_mode=CredentialMode.OPTIONAL,
                resolve_paths=False,
            )


@pytest.mark.parametrize(
    "field_name",
    ["unknown-devices.manufacturer", "unknown-devices.model"],
)
def test_unknown_device_removed_fixed_system_fields_are_rejected(
    tmp_path: Path,
    field_name: str,
) -> None:
    """Removed same-source fields fail configuration validation immediately."""

    config_file = tmp_path / f"removed-{field_name.rsplit('.', 1)[-1]}.toml"
    config_file.write_text(
        "\n".join(
            [
                "[output.custom_csv.unknown_system]",
                'filename = "unknown-system.csv"',
                'source = "unknown-devices"',
                f'columns = [{{ field = "{field_name}" }}]',
                "",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError) as excinfo:
        load_config(
            config_file,
            credential_mode=CredentialMode.OPTIONAL,
            resolve_paths=False,
        )

    assert f"unknown field {field_name!r}" in str(excinfo.value)


def test_unknown_device_custom_system_fields_require_json_paths(
    tmp_path: Path,
) -> None:
    """Canonical JSON paths remain available after fixed selectors are removed."""

    document = _document()
    unknown = next(host for host in document["hosts"] if host["classification"] == "unknown_device")
    unknown["system"] = {
        "manufacturer": "Example Devices",
        "model": "Endpoint-100",
    }
    config = _config(
        tmp_path,
        """
[output.custom_csv.unknown_system]
filename = "unknown-system.csv"
source = "unknown-devices"
columns = [
  { field = "json.host.system.manufacturer", header = "manufacturer" },
  { field = "json.host.system.model", header = "model" },
]
""",
    )

    paths = write_custom_csv_outputs(document, config, tmp_path / "out")
    assert [path.name for path in paths] == ["unknown-system.csv"]
    assert paths[0].read_text(encoding="utf-8").splitlines() == [
        "manufacturer,model",
        "Example Devices,Endpoint-100",
    ]


def test_custom_csv_columns_replace_across_includes(tmp_path: Path) -> None:
    """Later custom column lists replace earlier definitions instead of appending."""

    include = tmp_path / "base.toml"
    include.write_text(
        """
[output.custom_csv.inventory]
filename = "inventory.csv"
source = "hosts"
columns = [
  { field = "hosts.preferred_name" },
  { field = "hosts.state" },
]
""".lstrip(),
        encoding="utf-8",
    )
    primary = tmp_path / "config.toml"
    primary.write_text(
        """
@include "base.toml"

[output.custom_csv.inventory]
columns = [
  { field = "json.host.system.model" },
]
""".lstrip(),
        encoding="utf-8",
    )

    config = load_config(
        primary,
        credential_mode=CredentialMode.OPTIONAL,
        resolve_paths=False,
    )
    custom = config.output.custom_csv["inventory"]
    assert custom.filename == "inventory.csv"
    assert custom.source == "hosts"
    assert [column.field for column in custom.columns] == ["json.host.system.model"]


def test_custom_csv_uses_global_empty_file_policy(tmp_path: Path) -> None:
    """Custom reports share write_empty_csv behavior with the five fixed reports."""

    config = _config(
        tmp_path,
        """
[output]
write_empty_csv = false

[output.custom_csv.no_errors]
filename = "no-errors.csv"
source = "errors"
columns = [{ field = "errors.category" }]
""",
    )
    document = _document()
    document["errors"] = []
    out = tmp_path / "out"

    assert write_custom_csv_outputs(document, config, out) == []
    assert not (out / "no-errors.csv").exists()

    config.output.write_empty_csv = True
    paths = write_custom_csv_outputs(document, config, out)
    assert [path.name for path in paths] == ["no-errors.csv"]
    assert (out / "no-errors.csv").read_text(encoding="utf-8") == "category\n"


def test_custom_csv_is_published_and_stale_disabled_file_is_removed(
    tmp_path: Path,
) -> None:
    """Custom filenames participate in final publication and resume cleanup."""

    from lldp_runner.outputs import OUTPUT_NAMES, finalize_to_persistent

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "discovery.json").write_text("{}\n", encoding="utf-8")
    (scratch / "inventory.csv").write_text("name\nsw1\n", encoding="utf-8")
    output_root = tmp_path / "outputs"
    final = output_root / "run-01"
    final.mkdir(parents=True)
    latest = output_root / "latest"

    finalize_to_persistent(
        scratch,
        final,
        latest,
        output_names=["discovery.json", "inventory.csv"],
        known_output_names=[*OUTPUT_NAMES, "inventory.csv"],
    )
    assert (final / "inventory.csv").read_text(encoding="utf-8") == "name\nsw1\n"

    (scratch / "inventory.csv").unlink()
    finalize_to_persistent(
        scratch,
        final,
        latest,
        output_names=["discovery.json"],
        known_output_names=[*OUTPUT_NAMES, "inventory.csv"],
    )
    assert not (final / "inventory.csv").exists()


def test_empty_alert_accumulator_can_combine_custom_with_fixed_reports(
    tmp_path: Path,
    caplog,
) -> None:
    """Normal write_outputs can emit one aggregate fixed/custom empty CSV notice."""

    import logging

    from lldp_runner.models import Candidate
    from lldp_runner.outputs import write_outputs
    from lldp_runner.state import StateStore

    config = _config(
        tmp_path,
        """
[output]
log_alert_on_empty_csv = true
write_empty_csv = false

[output.custom_csv.errors_short]
filename = "errors-short.csv"
source = "errors"
columns = [{ field = "errors.category" }]
""",
    )
    state = StateStore(tmp_path / "state.sqlite")
    state.upsert_candidate(
        Candidate(names=["seed.example.net"], category="managed_device"),
        is_seed=True,
    )
    caplog.set_level(logging.INFO, logger="lldp_runner.outputs")

    write_outputs(
        state,
        config,
        tmp_path / "out",
        run_id="run-08",
        status="COMPLETED",
        draft=False,
    )
    messages = [record.getMessage() for record in caplog.records]
    empty_messages = [message for message in messages if "empty csv not written" in message]
    assert len(empty_messages) == 1
    assert "stack-members.csv" in empty_messages[0]
    assert "errors.csv" in empty_messages[0]
    assert "errors-short.csv" in empty_messages[0]
    state.close()
