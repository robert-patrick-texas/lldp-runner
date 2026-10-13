from __future__ import annotations

from pathlib import Path

import pytest

from lldp_runner.config import ConfigError, load_config


def test_includes_chain_and_merge_rule_order(config_file: Path, tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "second.toml").write_text(
        '''
[[classification.evidence_rules]]
label = "specific-hpe"
category = "managed_device"
name_pattern = '(?i)-6300(?:\\.|$)'
field_patterns = { remote_description = '(?i)^HPE\\s+ANW\\s+JL' }
''',
        encoding="utf-8",
    )
    (rules_dir / "first.toml").write_text(
        '''
@include second.toml

[logging]
level = "DEBUG"

[[classification.evidence_rules]]
label = "general-spare"
category = "unmanaged_device"
name_pattern = '(?i)-spare-'
''',
        encoding="utf-8",
    )
    original = config_file.read_text(encoding="utf-8")
    config_file.write_text(
        '@include "rules/first.toml"\n' + original,
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert [rule.label for rule in config.classification.evidence_rules] == [
        "specific-hpe",
        "general-spare",
    ]
    # The including file is applied last for scalar settings.
    assert config.logging.level == "INFO"


def test_include_paths_are_relative_to_each_including_file(config_file: Path, tmp_path: Path) -> None:
    nested = tmp_path / "conf.d" / "nested"
    nested.mkdir(parents=True)
    (nested / "rule.toml").write_text(
        '''
[[classification.evidence_rules]]
label = "nested-rule"
category = "managed_endpoint"
name_pattern = '(?i)^SEP[0-9A-F]{12}(?:\\.|$)'
''',
        encoding="utf-8",
    )
    (tmp_path / "conf.d" / "entry.toml").write_text(
        '@include "nested/rule.toml"\n',
        encoding="utf-8",
    )
    config_file.write_text(
        '@include "conf.d/entry.toml"\n' + config_file.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    config = load_config(config_file)
    assert config.classification.evidence_rules[0].label == "nested-rule"


def test_include_cycle_is_rejected(tmp_path: Path) -> None:
    a = tmp_path / "a.toml"
    b = tmp_path / "b.toml"
    a.write_text('@include "b.toml"\n', encoding="utf-8")
    b.write_text('@include "a.toml"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="include cycle"):
        load_config(a)


def test_evidence_rule_rejects_unsupported_field(config_file: Path) -> None:
    config_file.write_text(
        config_file.read_text(encoding="utf-8")
        + '''

[[classification.evidence_rules]]
category = "managed_device"
field_patterns = { made_up_field = 'anything' }
''',
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="unsupported field"):
        load_config(config_file)


def test_included_tagging_rules_are_concatenated_in_include_order(tmp_path: Path):
    from lldp_runner.config import load_config

    base = tmp_path / "base.toml"
    first = tmp_path / "10-tags.toml"
    second = tmp_path / "20-tags.toml"

    # Reuse the complete test fixture shape by writing the minimum valid config
    # directly; tag fragments only contribute tagging.rules arrays.
    first.write_text(
        '''
[[tagging.rules]]
label = "voice"
category = "managed_endpoint"
tags = ["service:voice"]
''',
        encoding="utf-8",
    )
    second.write_text(
        '''
[[tagging.rules]]
label = "tenant-a"
name_pattern = '(?i)^SEP'
tags = ["tenant:a"]
''',
        encoding="utf-8",
    )
    base.write_text(
        f'''@include "{first.name}"
@include "{second.name}"

[paths]
persistent_root = "{tmp_path / 'opt'}"
scratch_root = "{tmp_path / 'shm'}"
[discovery]
boundaries = ["198.18.0.0/15"]
[snmp]
backend = "gufo"
[icmp]
probes = 2
backend = "disabled"
[output]
[resume]
[neighbors]
[logging]
console = false
[credentials.default]
version = "v2c"
community = "test"
[credential_profiles.default]
primary = "default"
[credential_rules]
default_profile = "default"
[query_policy]
[classification]
''',
        encoding="utf-8",
    )

    loaded = load_config(base)
    assert [rule.label for rule in loaded.tagging.rules] == ["voice", "tenant-a"]


def test_conf_d_is_loaded_recursively_in_lexical_relative_path_order(
    config_file: Path,
) -> None:
    """Automatic conf.d traversal orders the complete relative path lexically."""

    conf_d = config_file.parent / "conf.d"
    (conf_d / "10-subdir").mkdir(parents=True)
    (conf_d / "10-subdir" / "20-rule.toml").write_text(
        '''
[[classification.evidence_rules]]
label = "subdir-first"
category = "managed_device"
name_pattern = '^subdir-'
''',
        encoding="utf-8",
    )
    (conf_d / "a.toml").write_text(
        '''
[[classification.evidence_rules]]
label = "a-second"
category = "managed_device"
name_pattern = '^a-'
''',
        encoding="utf-8",
    )
    (conf_d / "z.toml").write_text(
        '''
[[classification.evidence_rules]]
label = "z-third"
category = "managed_device"
name_pattern = '^z-'
''',
        encoding="utf-8",
    )

    loaded = load_config(config_file)

    assert [rule.label for rule in loaded.classification.evidence_rules] == [
        "subdir-first",
        "a-second",
        "z-third",
    ]


def test_conf_d_only_auto_loads_files_ending_exactly_in_dot_toml(config_file: Path) -> None:
    """Non-TOML notes/examples below conf.d are inert unless explicitly included."""

    conf_d = config_file.parent / "conf.d"
    conf_d.mkdir()
    (conf_d / "10-active.toml").write_text(
        '''
[[classification.evidence_rules]]
label = "active"
category = "managed_device"
name_pattern = '^active-'
''',
        encoding="utf-8",
    )
    # These files deliberately contain invalid TOML. If automatic discovery
    # accidentally reads either one, load_config() will fail rather than pass.
    (conf_d / "20-disabled.toml.disabled").write_text("this is not = toml [", encoding="utf-8")
    (conf_d / "30-example.toml.example").write_text("this is not = toml [", encoding="utf-8")
    (conf_d / "40-upper.TOML").write_text("this is not = toml [", encoding="utf-8")

    loaded = load_config(config_file)

    assert [rule.label for rule in loaded.classification.evidence_rules] == ["active"]


def test_conf_d_fragment_includes_later_fragment_only_once(config_file: Path) -> None:
    """An explicit include fixes rule position and suppresses later auto-loading."""

    conf_d = config_file.parent / "conf.d"
    conf_d.mkdir()
    (conf_d / "a.toml").write_text(
        '''@include "z.toml"

[[classification.evidence_rules]]
label = "a-rule"
category = "managed_device"
name_pattern = '^a-'
''',
        encoding="utf-8",
    )
    (conf_d / "z.toml").write_text(
        '''
[[classification.evidence_rules]]
label = "z-rule"
category = "managed_device"
name_pattern = '^z-'
''',
        encoding="utf-8",
    )

    loaded = load_config(config_file)

    # a.toml is encountered first lexically. Its include is merged before a's
    # local rules; z.toml is then skipped when the directory scan reaches it.
    assert [rule.label for rule in loaded.classification.evidence_rules] == [
        "z-rule",
        "a-rule",
    ]


def test_primary_include_suppresses_duplicate_conf_d_load(config_file: Path) -> None:
    """A file explicitly included by config.toml is not appended again by conf.d."""

    conf_d = config_file.parent / "conf.d"
    conf_d.mkdir()
    (conf_d / "z.toml").write_text(
        '''
[[classification.evidence_rules]]
label = "z-rule"
category = "managed_device"
name_pattern = '^z-'
''',
        encoding="utf-8",
    )
    config_file.write_text(
        '@include "conf.d/z.toml"\n' + config_file.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    loaded = load_config(config_file)

    assert [rule.label for rule in loaded.classification.evidence_rules] == ["z-rule"]


def test_absolute_include_path_is_supported(config_file: Path, tmp_path: Path) -> None:
    """@include accepts an absolute filename as well as relative filenames."""

    absolute_fragment = tmp_path / "outside" / "query.policy.toml"
    absolute_fragment.parent.mkdir()
    absolute_fragment.write_text(
        '''
[[query_policy.name_rules]]
pattern = '(?i)\\.external\\.example$'
action = 'deny'
''',
        encoding="utf-8",
    )
    config_file.write_text(
        f'@include "{absolute_fragment}"\n' + config_file.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    loaded = load_config(config_file)

    assert loaded.query_policy.name_rules[0].pattern == r"(?i)\.external\.example$"


def test_primary_config_scalar_overrides_automatic_conf_d_scalar(config_file: Path) -> None:
    """The primary config remains authoritative for scalar settings."""

    conf_d = config_file.parent / "conf.d"
    conf_d.mkdir()
    (conf_d / "10-logging.toml").write_text(
        '[logging]\nlevel = "DEBUG"\n',
        encoding="utf-8",
    )

    loaded = load_config(config_file)

    assert loaded.logging.level == "INFO"


def test_conf_d_path_must_be_a_directory(config_file: Path) -> None:
    """A file named conf.d is an operator error rather than something to ignore."""

    (config_file.parent / "conf.d").write_text("not a directory", encoding="utf-8")

    with pytest.raises(ConfigError, match="fragment path is not a directory"):
        load_config(config_file)


def test_primary_boundaries_replace_fragment_boundaries(tmp_path: Path) -> None:
    """Discovery scope is one operational list, not an accumulating policy array."""

    conf_d = tmp_path / "conf.d"
    conf_d.mkdir()
    (conf_d / "10-scope.toml").write_text(
        '[discovery]\nboundaries = ["192.0.2.0/24"]\n',
        encoding="utf-8",
    )
    root = tmp_path / "config.toml"
    root.write_text(
        '''[paths]\npersistent_root = "{root}"\nscratch_root = "{scratch}"\n\n[discovery]\nboundaries = ["198.51.100.0/24"]\n\n[credentials.v2]\nversion = "v2c"\ncommunity = "public"\n\n[credential_profiles.default]\nprimary = "v2"\n\n[credential_rules]\ndefault_profile = "default"\n'''.format(
            root=tmp_path / "root",
            scratch=tmp_path / "scratch",
        ),
        encoding="utf-8",
    )

    loaded = load_config(root)

    assert loaded.discovery.boundaries == ["198.51.100.0/24"]
