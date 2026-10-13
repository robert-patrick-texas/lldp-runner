from __future__ import annotations

from pathlib import Path

import pytest

from lldp_runner.config import AppConfig, load_config


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        f'''
[paths]
persistent_root = "{tmp_path / 'opt'}"
scratch_root = "{tmp_path / 'shm'}"

[discovery]
boundaries = ["198.18.0.0/15", "198.51.100.0/24", "2001:db8::/32"]
workers = 2
batch_size = 4
dns_suffixes = ["net.example.com"]

[snmp]
backend = "gufo"

[icmp]
probes = 2
backend = "disabled"

[output]
draft_in_scratch = true
snapshot_interval_seconds = 120.0
scoreboard_interval_seconds = 3.0

[resume]
default_resume = true

[logging]
level = "INFO"
console = false

[neighbors]
enable_lldp = true
enable_lldpv2 = true
cdp_for_cisco = true
cdp_manufacturers = ["Cisco"]

[credentials.default-v3]
version = "v3"
username = "user"
auth_password = "authpassword"
priv_password = "privpassword"
auth_protocol = "sha1"
priv_protocol = "aes128"

[credentials.default-v2]
version = "v2c"
community = "community"

[credentials.specific-v2]
version = "v2c"
community = "specific"

[credential_profiles.default]
primary = "default-v3"
fallback = "default-v2"
primary_attempts = 2
fallback_attempts = 1

[credential_profiles.specific]
primary = "specific-v2"
primary_attempts = 1

[credential_rules]
default_profile = "default"

[[credential_rules.address]]
network = "198.18.0.0/15"
profile = "default"

[[credential_rules.address]]
network = "198.18.36.0/24"
profile = "specific"

[[credential_rules.name]]
pattern = "^core-"
profile = "specific"

[[credential_rules.name]]
pattern = ".*"
profile = "default"

[query_policy]
default_action = "allow"

[[query_policy.address_rules]]
network = "198.18.200.0/24"
action = "deny"

[[query_policy.name_rules]]
pattern = "^printer-"
action = "deny"

[classification]
managed_manufacturers = ["Cisco", "Juniper", "Arista", "Aruba", "HPE"]

[[classification.name_rules]]
pattern = "^managed-fw-"
category = "managed_device"
''',
        encoding="utf-8",
    )
    return path


@pytest.fixture
def config(config_file: Path) -> AppConfig:
    return load_config(config_file)
