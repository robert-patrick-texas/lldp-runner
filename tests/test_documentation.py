"""Release-documentation invariants for operator-facing project files."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTATION_FILES = (
    ROOT / "README.md",
    ROOT / "docs" / "INSTALL.md",
    ROOT / "CHANGELOG.md",
    ROOT / "docs" / "CLI.md",
    ROOT / "docs" / "ENVIRONMENT.md",
    ROOT / "docs" / "SNMP.md",
    ROOT / "docs" / "ERRORS.md",
    ROOT / "docs" / "ARCHITECTURE.md",
    ROOT / "docs" / "ABOUT.md",
    ROOT / "docs" / "PRECEDENCE.md",
    ROOT / "docs" / "CREDS.md",
    ROOT / "docs" / "PLAN.md",
    ROOT / "docs" / "CUSTOM-CSV.md",
    ROOT / "docs" / "CSV-INPUT.md",
    ROOT / "docs" / "RUN.md",
    ROOT / "docs" / "DNS.md",
    ROOT / "docs" / "CLAIMS.md",
    ROOT / "docs" / "PRIMER.md",
    ROOT / "docs" / "ROADMAP.md",
    ROOT / "docs" / "NAMES.md",
    ROOT / "docs" / "DIFF.md",
    ROOT / "docs" / "dev" / "ARCHITECTURE.md",
    ROOT / "docs" / "dev" / "CLI-REFERENCE.md",
    ROOT / "docs" / "dev" / "CONTRIBUTING.md",
    ROOT / "docs" / "dev" / "FLOW-DIAGRAMS.md",
    ROOT / "docs" / "dev" / "MODULES.md",
    ROOT / "docs" / "dev" / "RELEASES.md",
    ROOT / "docs" / "dev" / "SCHEMA.md",
    ROOT / "docs" / "dev" / "STATE-AND-SCHEMAS.md",
    ROOT / "docs" / "dev" / "TESTING.md",
    ROOT / "LICENSE.md",
)


def test_documentation_files_exist_and_stay_within_terminal_width() -> None:
    """Keep the requested terminal-readable documentation width as a guardrail."""

    for path in DOCUMENTATION_FILES:
        assert path.is_file(), path
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            assert len(line) <= 80, f"{path}:{line_number} is {len(line)} columns"


def test_unfinished_roadmap_items_include_operator_planning_detail() -> None:
    """Every open action states implementation scope, benefit, and effort."""

    lines = (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8").splitlines()
    open_items = [index for index, line in enumerate(lines) if line.startswith("- [ ] ")]
    assert open_items

    for position, start in enumerate(open_items):
        end = open_items[position + 1] if position + 1 < len(open_items) else len(lines)
        block = "\n".join(lines[start:end])
        assert "  - **Remaining work:**" in block, lines[start]
        assert "  - **Operational benefit:**" in block, lines[start]
        assert "  - **Estimated effort:**" in block, lines[start]


def test_runtime_flow_diagrams_track_source_boundaries() -> None:
    """Keep all three source-maintained diagrams tied to live entry points."""

    from lldp_runner import claims, outputs, topology_graph, worker
    from lldp_runner.coordinator import Coordinator
    from lldp_runner.state import StateStore

    path = ROOT / "docs" / "dev" / "FLOW-DIAGRAMS.md"
    text = path.read_text(encoding="utf-8")

    assert text.count("```mermaid\nflowchart TD") >= 3
    for heading in (
        "## Collection flow",
        "## Resolver flow",
        "## Graph rematerialization flow",
    ):
        assert heading in text

    anchors = (
        "Coordinator.initialize",
        "Coordinator.run",
        "StateStore.claim_batch",
        "worker_main",
        "process_batch",
        "StateStore.apply_device_result",
        "Coordinator._process_neighbor",
        "candidate_claims",
        "StateStore.upsert_candidate",
        "_record_observation_uncommitted",
        "_record_claims_uncommitted",
        "_record_resolution_decision_uncommitted",
        "outputs._build_discovery_document",
        "StateStore.materialize_topology_graph",
        "topology_graph.build_topology_graph",
        "_record_graph_component_decision_uncommitted",
        "graph_projection",
        "projection_fingerprint",
    )
    for anchor in anchors:
        assert anchor in text

    for method in (
        "initialize",
        "run",
        "_process_neighbor",
        "_dispatch",
    ):
        assert callable(getattr(Coordinator, method))
    for method in (
        "claim_batch",
        "apply_device_result",
        "upsert_candidate",
        "_record_observation_uncommitted",
        "_record_claims_uncommitted",
        "_record_resolution_decision_uncommitted",
        "materialize_topology_graph",
        "_record_graph_component_decision_uncommitted",
    ):
        assert callable(getattr(StateStore, method))
    assert callable(worker.worker_main)
    assert callable(worker.process_batch)
    assert callable(claims.candidate_claims)
    assert callable(outputs._build_discovery_document)
    assert callable(outputs.write_outputs)
    assert callable(topology_graph.build_topology_graph)

    assert "dev/FLOW-DIAGRAMS.md" in (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "FLOW-DIAGRAMS.md" in (ROOT / "docs" / "DEV.md").read_text(encoding="utf-8")
    assert "FLOW-DIAGRAMS.md" in (ROOT / "docs" / "dev" / "ARCHITECTURE.md").read_text(
        encoding="utf-8"
    )
    roadmap = (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8")
    assert "- [x] Add source-maintained diagrams" in roadmap


def test_license_metadata_and_unlicense_text() -> None:
    """Keep package metadata and the shipped Unlicense synchronized."""

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["license"] == {"file": "LICENSE.md"}

    text = (ROOT / "LICENSE.md").read_text(encoding="utf-8")
    assert text.startswith(
        "This is free and unencumbered software released into the public domain.\n"
    )
    assert "dedicate any and all copyright interest" in text
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in text
    assert "https://unlicense.org" in text
    assert "Apache License" not in text


def test_readme_links_to_reference_documents() -> None:
    """Make the short README an index into the deeper operator references."""

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for relative in (
        "docs/INSTALL.md",
        "docs/CLI.md",
        "docs/ENVIRONMENT.md",
        "docs/SNMP.md",
        "docs/ERRORS.md",
        "docs/ARCHITECTURE.md",
        "docs/ABOUT.md",
        "docs/PRECEDENCE.md",
        "docs/CREDS.md",
        "docs/PLAN.md",
        "docs/CUSTOM-CSV.md",
        "docs/CSV-INPUT.md",
        "docs/RUN.md",
        "docs/DNS.md",
        "docs/CLAIMS.md",
        "docs/PRIMER.md",
        "docs/ROADMAP.md",
        "docs/NAMES.md",
        "docs/DIFF.md",
        "docs/dev/FLOW-DIAGRAMS.md",
        "docs/dev/SCHEMA.md",
        "CHANGELOG.md",
        "LICENSE.md",
    ):
        assert relative in text


def test_snmp_algorithm_documentation_matches_backend_capabilities() -> None:
    """Keep PySNMP-only SHA-256/AES-256 names explicit in operator docs."""

    from lldp_runner.snmp.selection import snmp_backend_credential_capabilities

    gufo = snmp_backend_credential_capabilities("gufo")
    pysnmp = snmp_backend_credential_capabilities("pysnmp")
    assert gufo.auth_protocols == ("sha1", "md5")
    assert gufo.priv_protocols == ("aes128", "des")
    assert pysnmp.auth_protocols == ("sha1", "md5", "sha256")
    assert pysnmp.priv_protocols == (
        "aes128",
        "aes256",
        "aes256-blumenthal",
        "des",
    )

    snmp_text = (ROOT / "docs" / "SNMP.md").read_text(encoding="utf-8")
    for token in (
        "USM_AUTH_HMAC192_SHA256",
        "USM_PRIV_CFB256_AES",
        "USM_PRIV_CFB256_AES_BLUMENTHAL",
        "AES-256-Cisco",
        "does not accept `aes256-reeder`",
    ):
        assert token in snmp_text
    assert "Gufo remains" in snmp_text
    assert "limited to SHA-1/MD5 authentication" in snmp_text


def test_pysnmp_default_and_gufo_resume_migration_are_documented() -> None:
    """Keep the 0.37 default change and safe Gufo-resume guidance prominent."""

    from lldp_runner.defaults import DEFAULT_SNMP_BACKEND

    assert DEFAULT_SNMP_BACKEND == "pysnmp"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    snmp = (ROOT / "docs" / "SNMP.md").read_text(encoding="utf-8")
    run = (ROOT / "docs" / "RUN.md").read_text(encoding="utf-8")
    install = (ROOT / "docs" / "INSTALL.md").read_text(encoding="utf-8")
    cli = (ROOT / "docs" / "CLI.md").read_text(encoding="utf-8")

    assert "PySNMP the built-in default" in readme
    assert "`pysnmp`, the default" in snmp
    assert "A run started with Gufo remains a Gufo run" in run
    assert 'explicit `snmp.backend = "gufo"`' in install
    assert "an omitted backend now resolves to `pysnmp`" in " ".join(cli.split())


def test_schema_quick_reference_matches_implementation_constants() -> None:
    """Keep the compact developer schema index synchronized with writers."""

    from lldp_runner import __version__
    from lldp_runner.discovery_diff import DIFF_JSON_SCHEMA_VERSION
    from lldp_runner.outputs import DISCOVERY_JSON_SCHEMA_VERSION
    from lldp_runner.run_manifest import RUN_JSON_SCHEMA_VERSION
    from lldp_runner.scoreboard import SCOREBOARD_SCHEMA
    from lldp_runner.topology_graph import TOPOLOGY_GRAPH_SCHEMA_VERSION

    text = (ROOT / "docs" / "dev" / "SCHEMA.md").read_text(encoding="utf-8")
    assert f"LLDP-Runner {__version__}" in text
    expected_rows = (
        f"| `discovery.json` | `schema_version` | {DISCOVERY_JSON_SCHEMA_VERSION} |",
        "| Embedded topology graph | `topology_graph.schema_version` | "
        f"{TOPOLOGY_GRAPH_SCHEMA_VERSION} |",
        f"| Diff JSON | `schema_version` | {DIFF_JSON_SCHEMA_VERSION} |",
        f"| `run.json` | `schema_version` | {RUN_JSON_SCHEMA_VERSION} |",
        f"| Active-run `scoreboard.json` | `scoreboard_schema` | {SCOREBOARD_SCHEMA} |",
    )
    for row in expected_rows:
        assert row in text


def test_release_guide_keeps_changelog_entries_delta_focused() -> None:
    """Preserve the policy that avoids repeating unchanged schema inventories."""

    text = (ROOT / "docs" / "dev" / "RELEASES.md").read_text(encoding="utf-8")
    assert "Mention a\nschema number only when that schema changes" in text
    assert "Do not pad a new entry by restating an\nestablished feature" in text
    assert "current-version inventory\nbelongs in [`SCHEMA.md`](SCHEMA.md)" in text


def test_plan_example_configuration_is_loadable(tmp_path: Path) -> None:
    """Keep the enterprise planning example synchronized with config syntax."""

    from lldp_runner.config import CredentialMode, load_config

    text = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")
    block = text.split("```toml", 1)[1].split("```", 1)[0].strip() + "\n"
    path = tmp_path / "config.toml"
    path.write_text(block, encoding="utf-8")

    config = load_config(
        path,
        env={},
        credential_mode=CredentialMode.OPTIONAL,
        resolve_paths=False,
    )
    assert config.credential_rules.default_profile == "default"
    assert config.query_policy.default_action == "deny"
    assert len(config.tagging.rules) >= 5

    from lldp_runner.seed_credentials import load_seed_credential_files

    overlay = text.split("```json", 1)[1].split("```", 1)[0].strip() + "\n"
    overlay_path = tmp_path / "seed-credentials.json"
    overlay_path.write_text(overlay, encoding="utf-8")
    overlay_path.chmod(0o600)
    loaded = load_seed_credential_files([overlay_path], config)
    assert len(loaded.records) == 2
    assert {item.credential_profile for item in loaded.records} == {"exception"}


def test_terminal_color_fragment_is_parseable_and_documents_defaults() -> None:
    """Keep the shipped conf.d terminal-color example synchronized with defaults."""

    path = ROOT / "configs" / "conf.d" / "terminal-colors.toml.example"
    parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    assert parsed["terminal"] == {
        "color": "auto",
        "palette": "dark",
        "heading_color": "cyan",
        "success_color": "green",
        "warning_color": "yellow",
        "error_color": "red",
        "learned_color": "cyan",
        "observed_by_color": "magenta",
        "inspection_neighbor_color": "magenta",
        "metric_color": "green",
    }


def test_shared_paths_fragment_is_parseable_and_explicit() -> None:
    """Keep the multi-user path example explicit and machine-parseable."""

    path = ROOT / "configs" / "conf.d" / "shared-paths.toml.example"
    parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    assert parsed["paths"] == {
        "persistent_root": "/var/lib/lldp-runner",
        "scratch_root": "/var/tmp/lldp-runner",
    }


def test_hidden_watch_overlay_stays_out_of_operator_documentation() -> None:
    """Keep the optional watch Easter egg out of shipped Markdown references."""

    forbidden = (
        "a america",
        "America overlay",
        "America screen",
        "United States of America",
        "1776-2026",
        "best has yet to come",
    )
    for path in DOCUMENTATION_FILES:
        text = path.read_text(encoding="utf-8")
        for phrase in forbidden:
            assert phrase not in text, f"{path} documents hidden watch feature: {phrase}"


def test_names_document_covers_identity_collision_guidance() -> None:
    """Keep name identity guidance explicit as the correlation model evolves."""

    text = (ROOT / "docs" / "NAMES.md").read_text(encoding="utf-8")
    for phrase in (
        "`preferred_name` is an operator-facing presentation value",
        "not guaranteed to be unique",
        "same name can be",
        "Use unique device names throughout the network",
        "same normalized local and remote interfaces",
        "preserves the raw advertisement and parses a plausible final",
        "shared normalized name and at least one shared management address",
        "Cisco Nexus VDC example",
        "VMware ESXi CDP sentinel example",
        "255.255.255.255",
        "`cdp.entry_addresses`",
        "json.host.id",
    ):
        assert phrase in text


def test_output_docs_cover_unknown_csv_and_mac_name_fallback() -> None:
    """Keep the changed fixed schema and guarded presentation rule explicit."""

    names = (ROOT / "docs" / "NAMES.md").read_text(encoding="utf-8")
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    custom = (ROOT / "docs" / "CUSTOM-CSV.md").read_text(encoding="utf-8")

    assert "one unambiguous\n   MAC-address-typed chassis value" in names
    assert "A nonblank\n   observed name or description prevents this substitution" in names
    assert "preferred_name,ipv4,ipv6,last_seen,protocols,observed_names" in (architecture)
    assert "consistently blank `manufacturer` and `model`" in architecture
    assert "are not supported and fail configuration validation" in custom
    assert "`unknown-devices.manufacturer`" in custom
    assert "`unknown-devices.model`" in custom
    assert "`json.host.system.manufacturer`" in custom
    assert "`json.host.system.model`" in custom


def test_diff_document_covers_comparison_contract() -> None:
    """Keep the run-comparison identity and source contract documented."""

    text = (ROOT / "docs" / "DIFF.md").read_text(encoding="utf-8")
    for phrase in (
        "A = latest; B = previous",
        "There is intentionally no `--last`",
        "timezone-aware completed timestamp",
        "Physical | serial, SNMP engine ID, chassis ID",
        "`preferred_name` also cannot be treated as a unique cross-run key",
        "Sentinel/group values such as `0.0.0.0`, `::`, `255.255.255.255`",
        "shared-serial Nexus VDCs are paired by logical name plus",
        "Macro topology comparison therefore uses only `learned_neighbors`",
        "`possible reboot` difference",
        "`run.json`",
        "`--changes-only`",
        "`--json`",
        "`change_dimensions`",
        "`member_protocol_changes`",
        "`graph_member_keys`",
    ):
        assert phrase in text


def test_csv_input_document_covers_shared_reader_contract() -> None:
    """Keep flexible CSV input behavior explicit for operators and maintainers."""

    text = (ROOT / "docs" / "CSV-INPUT.md").read_text(encoding="utf-8")
    for phrase in (
        "standard-library `csv` module",
        "case-insensitive by default",
        "Multiline quoted fields are not supported",
        "65,535",
        "Extra data columns are silently discarded by default",
        "fields may appear in any order",
    ):
        assert phrase in text


def test_run_document_covers_startup_lifecycle_and_progress() -> None:
    """Keep long startup phases and run-mode vocabulary operator-visible."""

    text = (ROOT / "docs" / "RUN.md").read_text(encoding="utf-8")
    for phrase in (
        "Run started",
        "Seed resolution started",
        "every 30 seconds",
        "recursive discovery",
        "seed-only discovery",
        "raw seeds",
        "queryable",
        "Run initialization failed",
        "activity.log",
    ):
        assert phrase in text


def test_dns_document_covers_seed_modes_and_caching_guidance() -> None:
    """Keep seed DNS fast-path eligibility and resolver guidance explicit."""

    text = (ROOT / "docs" / "DNS.md").read_text(encoding="utf-8")
    for phrase in (
        'seed_dns_mode = "resolve"',
        'seed_dns_mode = "skip-addressed"',
        "non-IP logical seed/preferred name",
        "valid `queried_as` IPv4 or IPv6 address",
        "local caching stub resolver",
        "Future consideration: LLDP-Runner DNS cache",
        "does not disable learned managed-neighbor DNS enrichment",
    ):
        assert phrase in text


def test_local_markdown_page_links_resolve() -> None:
    """Keep source navigation valid so the HTML publisher can rewrite links."""

    import re

    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+\.md(?:#[^)]*)?)\)")
    for path in DOCUMENTATION_FILES:
        text = path.read_text(encoding="utf-8")
        for target in link_pattern.findall(text):
            relative = target.split("#", 1)[0]
            destination = (path.parent / relative).resolve()
            assert destination.is_file(), f"{path}: broken Markdown link {target}"
            assert destination.suffix.lower() == ".md"


def test_markdown_page_references_are_links_not_inline_code() -> None:
    """Prevent navigational page references from becoming plain HTML text."""

    import re

    # Remove proper links before looking for filename-shaped inline-code spans.
    link_pattern = re.compile(r"\[[^\]]+\]\([^)]+\.md(?:#[^)]*)?\)")
    code_pattern = re.compile(r"`([^`]*\.md)`")
    allowed_literals = {
        (ROOT / "README.md", "docs/CLI.md"),
        (ROOT / "CHANGELOG.md", "docs/CLI.md"),
    }

    for path in DOCUMENTATION_FILES:
        unlinked_text = link_pattern.sub("", path.read_text(encoding="utf-8"))
        for reference in code_pattern.findall(unlinked_text):
            if (path, reference) in allowed_literals:
                continue
            raise AssertionError(f"{path}: unlinked Markdown page reference {reference}")
