"""Operator-friendly TOML generation for LLDP-Runner built-in defaults.

The generator intentionally favors readable, hand-editable TOML over the most
compact representation. Generated files are an operator starting point, so
comments and long lists are wrapped to approximately 80 columns.
"""

from __future__ import annotations

import json
import os
import textwrap
from collections.abc import Mapping
from typing import Any

from lldp_runner.defaults import DEFAULT_SNMP_BACKEND

# Comments are keyed by dotted configuration path and deliberately describe the
# operational consequence, not merely restate the option name. The same renderer
# is used for ``generate-config`` and guides the shipped example configuration.
ARRAY_TABLE_PATHS = {
    "credential_rules.address",
    "credential_rules.name",
    "query_policy.address_rules",
    "query_policy.name_rules",
    "classification.address_rules",
    "classification.name_rules",
    "classification.evidence_rules",
    "tagging.rules",
}

# Generated configuration is meant to be comfortable in an 80-column terminal.
# A single indivisible value can occasionally exceed this width, but comments and
# list formatting should not create unnecessarily long lines.
GENERATED_LINE_WIDTH = 80


COMMENTS: dict[str, tuple[str, ...]] = {
    "paths": (
        "Persistent state/output and temporary runtime storage.",
        "'auto' places data with the installation this file belongs to, so",
        "keep it unless the site needs a different location.",
    ),
    "paths.persistent_root": (
        "When set to auto, follow this file's directory: <dir>/var for",
        "<dir>/config.toml (for example /opt/lldp-runner/var or ~/lldp-runner/var),",
        "or /var/lib/lldp-runner for /etc/lldp-runner/config.toml.",
        "A shared or system root must already exist; a per-user one is created.",
    ),
    "paths.scratch_root": (
        "When set to auto: /dev/shm/lldp-runner for a shared install,",
        "/run/lldp-runner then /dev/shm/lldp-runner for /etc/lldp-runner, or",
        "$XDG_RUNTIME_DIR/lldp-runner below the home directory; otherwise",
        "<persistent_root>/tmp.",
    ),
    "paths.runs_dirname": (
        "Durable SQLite/checkpoint state is stored below "
        "<persistent_root>/<runs_dirname>/<runid>/.",
    ),
    "paths.output_dirname": (
        "Finalized operator output is stored below <persistent_root>/<output_dirname>/<runid>/.",
        "The project default is the plural directory name 'outputs'.",
    ),
    "paths.clean_scratch_when_completed": (
        "Remove <scratch_root>/<runid>/ and its matching current symlink after "
        "a successful run has closed and archived durable files/scoreboards.",
        "The shared <scratch_root>/scoreboard/ publication remains available.",
        "Set false to retain per-run drafts and another final scoreboard copy.",
    ),
    "paths.run_id_format": (
        "Run directory identifier format: supported strftime directives plus "
        "optional {counter}; the default preserves the historical timezone suffix.",
        "{counter} is stateless, zero-padded 00..99, and fails on exhaustion; "
        "%f is available when a higher-precision timestamp is preferable.",
    ),
    "time": (
        "Project-wide wall-clock policy for logs, summaries, persisted timestamps, "
        "and run-ID strftime expansion.",
    ),
    "time.timezone": (
        "Default eastern preserves historical behavior. Also accepts utc, local, "
        "or an IANA timezone such as America/Denver.",
    ),
    "discovery": (
        "Discovery guardrails and worker/cohort behavior.",
        "The built-in boundary is intentionally unlimited; production sites "
        "should normally narrow it.",
    ),
    "discovery.boundaries": (
        "CIDRs that LLDP-Runner may recursively query. The built-in default "
        "allows all IPv4 and IPv6 addresses.",
    ),
    "discovery.seed_dirs": (
        "Eligible files below each directory are read recursively; "
        "/opt/lldp-runner/seeds.d is a common site path.",
    ),
    "discovery.seed_order": (
        "Seed scheduling after consolidation/de-duplication: input (default), "
        "sorted (lexical), or random.",
        "Random ordering is especially useful with max_devices='auto' for "
        "topology sampling without recursive polling.",
    ),
    "discovery.seed_dns_mode": (
        "Seed DNS policy: resolve (default) performs normal resolver work; "
        "skip-addressed can reuse a confirmed name + queried_as address.",
        "The skip-addressed fast path is conservative and does not change "
        "learned-neighbor DNS enrichment.",
    ),
    "discovery.shuffle_key": (
        "Optional reproducibility key for seed_order='random'. Empty generates "
        "and persists a fresh key per new run.",
    ),
    "discovery.limit_behavior": (
        "pause leaves LIMIT_REACHED resumable; complete finalizes intentional "
        "bounded/sampling runs as COMPLETED_LIMIT.",
    ),
    "discovery.workers": ("Set to auto to resolve at runtime to (os.cpu_count() or 1) * 4.",),
    "discovery.batch_size": (
        "Cohort size assigned to one worker. Smaller cohorts reduce slow-device straggler delay.",
    ),
    "discovery.max_devices": (
        "Positive integer = finite recursive managed-device limit; 0 = "
        "unlimited recursive discovery.",
        "Set to 'auto' for seed-only discovery: all unique seeds are queried "
        "and their neighbors are recorded/output, but discovered non-seed "
        "neighbors are never scheduled for SNMP.",
        "A finite limit smaller than the unique seed count fails before workers "
        "start instead of silently querying only part of the seed inventory.",
    ),
    "discovery.max_hosts": (
        "Host guardrail; 0 disables this guardrail. Recursive mode counts every "
        "identity, preserving historical behavior.",
        "With max_devices='auto', explicit seeds are sampling points and only "
        "discovered non-seed identities count toward max_hosts.",
        "Concurrent batches can overshoot a threshold; use "
        "limit_behavior='complete' when reaching it is intentional.",
    ),
    "discovery.late_address_recovery_attempts": (
        "Bounded re-admission count for a FAILED recursively learned host when "
        "later protocol evidence supplies a genuinely new permitted address.",
        "Default 1; set 0 to disable. Accepted range is 0 through 3.",
    ),
    "snmp": (
        "SNMP transport/default credential preference. Explicit credential "
        "rules remain authoritative.",
    ),
    "snmp.backend": (
        f"Select exactly one discovery backend: {DEFAULT_SNMP_BACKEND} (default) or gufo.",
        "The selected backend is fixed for the complete run and every resume; "
        "there is no automatic fallback or mixed-backend operation.",
        "PySNMP SNMPv3 authPriv requires cryptography>=50.0. Before discovery, "
        "LLDP-Runner constructively verifies each reachable "
        "AES-128/AES-256/DES cipher; "
        "SNMPv2c and Gufo do not run this crypto probe.",
    ),
    "snmp.version": (
        "Preferred runtime default when both v2c and v3 credentials exist: '2c' or '3'.",
        "SNMPv3 authPriv is the best-practice default; v2c becomes fallback "
        "when both are available.",
    ),
    "snmp.timeout_seconds": (
        "Timeout for each individual SNMP request, not the complete device/table collection.",
    ),
    "snmp.max_repetitions": (
        "GETBULK max-repetitions value; larger values reduce round trips but "
        "increase response size/work.",
    ),
    "snmp.retry_per_operation": (
        "Retries allowed for each logical scalar, batch, or table operation.",
    ),
    "snmp.retry_per_collector": (
        "Normal adaptive retries allowed for one collector family on a target.",
        "LLDP and LLDPv2 share the LLDP family; CDP has its own family.",
    ),
    "snmp.retry_total_cap": (
        "Maximum shared adaptive retries across one target and credential route.",
        "Neighbor collectors have a separate protected reserve below.",
    ),
    "snmp.retry_neighbor_reserve": (
        "Protected adaptive retries for LLDP-family and CDP collectors.",
        "Earlier SYSTEM-MIB, ENTITY-MIB, and IF-MIB retries cannot consume it.",
    ),
    "snmp.structural_table_retry": (
        "Full-table restarts allowed after structural CDP/LLDP validation fails.",
        "They consume either the neighbor reserve or shared target cap.",
    ),
    "snmp.retry_timeout_multiplier": (
        "Multiply the active request timeout after the first retry-eligible failure.",
    ),
    "snmp.retry_max_repetitions_multiplier": (
        "Multiply GETBULK max-repetitions and GET-MANY batch size after slowdown.",
        "A value of 0.5 halves agent work; odd counts round upward.",
    ),
    "snmp.retry_min_max_repetitions": ("Lower bound for adaptive GETBULK max-repetitions.",),
    "snmp.retry_inter_pdu_delay_ms": (
        "Additional per-PDU pacing applied to a target after adaptive slowdown.",
        "The degraded profile remains active for later tables on that target only.",
    ),
    "snmp.neighbor_stability_retry": (
        "After normal repair is exhausted, retry each failed LLDP-family/CDP collector once.",
        "Only timeout and structurally invalid outcomes are eligible.",
    ),
    "snmp.neighbor_stability_retry_delay_seconds": (
        "One shared quiet-period delay before delayed neighbor stability retries.",
        "Use 0 for an immediate final pass or disable neighbor_stability_retry.",
    ),
    "snmp.per_device_rps": (
        "Maximum request rate for one healthy target before adaptive slowdown.",
    ),
    "snmp.max_outstanding_devices_per_worker": (
        "Maximum concurrently active device operations inside each worker process.",
    ),
    "snmp.collect_entity_mib": (
        "Master switch for ENTITY-MIB chassis identity enrichment. false skips "
        "ENTITY-MIB regardless of entity_mib_mode.",
    ),
    "snmp.entity_mib_mode": (
        "ENTITY-MIB query scope: full preserves the complete historical table "
        "walk; auto selects high-value fields by device identity; brief requests "
        "only common manufacturer/model/serial fields.",
        "auto and brief discover the agent-assigned chassis/stack/module index "
        "before targeted GETs; they never assume entPhysicalIndex=1.",
    ),
    "snmp.report_metrics": (
        "When true, full discovery stores per-device SNMP object counts and "
        "collector elapsed milliseconds in discovery.json.",
        "Disabled by default to keep normal discovery output concise; "
        "get-neighbors always reports these lightweight metrics.",
    ),
    "icmp": ("Two ICMP wake-up probes precede the first SNMP attempt for each candidate address.",),
    "icmp.backend": (
        "auto tries raw ICMP first and can fall back to the system ping utility "
        "when raw sockets are unavailable.",
    ),
    "output": (
        "Draft/final output cadence plus fixed and optional custom CSV views.",
        "discovery.json is always written and is the complete structured result.",
    ),
    "output.run_json_config_log": (
        "Record resolved primary/include/conf.d configuration pathnames in run.json.",
        "Set false when output artifacts should not reveal deployment config paths.",
    ),
    "output.purge_keep": (
        "Default number of additional finalized output directories retained by purge",
        "beyond latest. Zero keeps latest only unless --keep overrides it.",
    ),
    "output.neighbor_local_width": (
        "Baseline Local column width for get-neighbors/show-neighbors tables; "
        "the renderer expands it when longer values fit the terminal.",
    ),
    "output.neighbor_remote_port_width": (
        "Baseline Remote Port column width for get-neighbors/show-neighbors "
        "tables; the renderer expands it when longer values fit.",
    ),
    "output.relationship_view": (
        "Graph-aware show-neighbors layout. sectioned groups ordinary, shared-",
        "chassis, overlay, and multi-neighbor observations; combined labels rows.",
    ),
    "output.chassis_id_name_fallback": (
        "disabled preserves names; name_like permits hostname-like chassis IDs; "
        "any accepts any nonblank chassis ID.",
    ),
    "output.write_hosts_csv": (
        "Write fixed-schema hosts.csv. Set false to suppress this convenience view.",
    ),
    "output.write_stack_members_csv": (
        "Write fixed-schema stack-members.csv when physical switch-stack members ",
        "are discovered. Enabled by default.",
    ),
    "output.write_seeds_csv": (
        "Write fixed-schema reusable seeds.csv. Set false only when not needed.",
    ),
    "output.write_unknown_devices_csv": (
        "Write fixed-schema unknown-devices.csv for unresolved/unknown identities.",
    ),
    "output.write_errors_csv": (
        "Write fixed-schema errors.csv. Errors remain present in discovery.json.",
    ),
    "output.write_empty_csv": (
        "When false (default), omit any enabled fixed-schema CSV that has zero ",
        "data rows instead of writing a header-only file.",
    ),
    "output.log_alert_on_empty_csv": (
        "When true, terminal output logs one INFO message listing enabled CSVs ",
        "omitted because they contained no records.",
    ),
    "output.custom_csv": (
        "Optional named custom CSV reports rendered from discovery.json. See ",
        "docs/CUSTOM-CSV.md for row sources, fields, transforms, and examples.",
    ),
    "diff": (
        "Cross-run comparison semantics and human-readable report detail.",
        "These options never change discovery collection or retry behavior.",
    ),
    "diff.include_collection_timing": (
        "Compare collector duration_ms values. Disabled by default because exact ",
        "timings remain in discovery.json but ordinary elapsed-time jitter is not ",
        "a semantic topology or coverage change.",
    ),
    "diff.summary_only": (
        "Render only source/result warnings, summaries, and collection incidents ",
        "for human output. Machine-readable JSON always retains full detail.",
    ),
    "diff.expand_collection_incidents": (
        "Show every derivative coverage-uncertain graph and compatibility row in ",
        "human output. Disabled collapses them beneath the originating incident; ",
        "JSON always retains every structured row.",
    ),
    "terminal": (
        "Terminal styling policy for get-neighbors, show-neighbors, and watch.",
        "Colors never affect CSV/JSON and NO_COLOR remains authoritative.",
    ),
    "terminal.color": (
        "auto uses styling only on color-capable interactive terminals; never ",
        "disables terminal color/styling from configuration.",
    ),
    "terminal.palette": (
        "Built-in watch dashboard theme: dark (default) or light. The explicit ",
        "semantic color settings below continue to control neighbor renderers.",
    ),
    "terminal.heading_color": ("Headings and major detail-section titles.",),
    "terminal.success_color": ("Successful/complete state emphasis.",),
    "terminal.warning_color": ("Partial, warning, diagnostic, and non-complete state emphasis.",),
    "terminal.error_color": ("Failed get-neighbors state emphasis.",),
    "terminal.learned_color": ("Learned-neighbor labels and protocol emphasis in show-neighbors.",),
    "terminal.observed_by_color": ("Observed_by labels and protocol emphasis in show-neighbors.",),
    "terminal.inspection_neighbor_color": ("Neighbor protocol emphasis in get-neighbors tables.",),
    "terminal.metric_color": ("Numeric ping/timing/SNMP metric emphasis in get-neighbors.",),
    "resume": (
        "Incomplete RUNNING/PAUSED/INTERRUPTED/LIMIT_REACHED runs may be resumed by default.",
    ),
    "credential_rules": (
        "Runtime SNMPCOMM or SNMPUSER/SNMPAUTH/SNMPPRIV credentials synthesize "
        "profile 'runtime-default'.",
        "Explicit [credentials.*] / [credential_profiles.*] suppress those "
        "lowest-priority runtime credentials.",
    ),
    "query_policy": (
        "Query policy is independent of classification. Address rules use "
        "most-specific CIDR; name rules are first-match-wins.",
        "Single-device inspection may target outside discovery.boundaries, but "
        "explicit query-policy deny rules still apply.",
    ),
    "classification": (
        "Classification rule ordering: explicit address/name/evidence rules "
        "precede built-in heuristic patterns.",
    ),
    "tagging": (
        "Tagging is independent of classification; every matching rule "
        "contributes de-duplicated tags.",
    ),
    "neighbors": (
        "Select which neighbor protocols are collected. CDP is normally limited "
        "to manufacturers expected to support it.",
    ),
    "logging": ("INFO is recommended for normal operation; DEBUG is useful for troubleshooting.",),
    "logging.console": (
        "Write log records to the console. Console and file logging are independent.",
    ),
    "logging.file": ("Append log records to logging.filename. Enabled by default.",),
    "logging.filename": (
        "Relative paths are rooted beneath runs/<run-id>/; absolute or ~-expanded ",
        "paths may be used for centralized logs such as /var/log/lldprunner.log. ",
        "Existing files are appended and append-open failures stop startup.",
    ),
}


def _literal(value: Any) -> str:
    """Render scalar/inline TOML values used by LLDP-Runner configuration."""

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, Mapping):
        return "{ " + ", ".join(f"{key} = {_literal(item)}" for key, item in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(_literal(item) for item in value) + "]"
    raise TypeError(f"cannot render TOML value of type {type(value).__name__}")


def _wrap_comment(text: str) -> list[str]:
    """Wrap one explanatory comment to the generated file's target width."""

    wrapped = textwrap.wrap(
        text,
        width=GENERATED_LINE_WIDTH - 2,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]
    return [f"# {line}" if line else "#" for line in wrapped]


def _comment_lines(path: str) -> list[str]:
    """Return wrapped comments associated with a dotted configuration path."""

    lines: list[str] = []
    for comment in COMMENTS.get(path, ()):
        lines.extend(_wrap_comment(comment))
    return lines


def _assignment_lines(key: str, value: Any) -> list[str]:
    """Render an assignment, expanding long lists one element per line.

    One-item-per-line lists make regular expressions and policy values easy to
    review and edit. Compact lists remain on one line when the whole assignment
    fits within the approximate 80-column target.
    """

    compact = f"{key} = {_literal(value)}"
    if not isinstance(value, list) or not value or len(compact) <= GENERATED_LINE_WIDTH:
        return [compact]

    lines = [f"{key} = ["]
    lines.extend(f"  {_literal(item)}," for item in value)
    lines.append("]")
    return lines


def _emit_table(lines: list[str], path: tuple[str, ...], table: Mapping[str, Any]) -> None:
    """Append one TOML table and recursively append deferred child tables."""

    dotted = ".".join(path)
    if path:
        if lines and lines[-1] != "":
            lines.append("")
        lines.extend(_comment_lines(dotted))
        lines.append(f"[{dotted}]")

    deferred: list[tuple[str, Any]] = []
    for key, value in table.items():
        item_path = ".".join((*path, key))
        if isinstance(value, Mapping) or (
            isinstance(value, list) and value and all(isinstance(item, Mapping) for item in value)
        ):
            deferred.append((key, value))
            continue
        # Empty rule arrays are omitted so operators can later add
        # [[array.of.tables]] entries without conflicting with a defined key.
        if item_path in ARRAY_TABLE_PATHS and value == []:
            continue
        lines.extend(_comment_lines(item_path))
        lines.extend(_assignment_lines(key, value))

    for key, value in deferred:
        if isinstance(value, Mapping):
            _emit_table(lines, (*path, key), value)
            continue
        for item in value:
            if lines and lines[-1] != "":
                lines.append("")
            item_path = ".".join((*path, key))
            lines.extend(_comment_lines(item_path))
            lines.append(f"[[{item_path}]]")
            # Array-table entries are flat in the current LLDP-Runner schema.
            for item_key, item_value in item.items():
                lines.extend(_assignment_lines(item_key, item_value))


def _append_comment_block(lines: list[str], comments: list[str]) -> None:
    """Append wrapped prose/example comments while preserving '#' separators."""

    for text in comments:
        if text == "#":
            lines.append("#")
        elif text.startswith("# "):
            # Example TOML is already intentionally formatted; preserve it.
            lines.append(text)
        else:
            lines.extend(_wrap_comment(text))


def render_generated_config(data: Mapping[str, Any]) -> str:
    """Return a complete, commented, hand-editable TOML configuration."""

    lines: list[str] = []
    _append_comment_block(
        lines,
        [
            "LLDP-Runner configuration generated from the package's built-in defaults.",
            "#",
            "Runtime precedence (lowest to highest):",
            "#   defaults.py -> config/@include/conf.d -> LLDP_RUNNER_* env -> --set",
            "#   -> dedicated CLI options",
            "#",
            (
                'On this host, workers = "auto" currently resolves to '
                f"{(os.cpu_count() or 1) * 4} workers."
            ),
            "#",
            "If --config is omitted, LLDP-Runner searches:",
            "#   ~/lldp-runner-config.toml",
            "#   ~/lldp-runner/config.toml",
            "#   /opt/lldp-runner/config.toml",
            "#   /etc/lldp-runner/config.toml",
            "and otherwise runs from built-in defaults.",
            "#",
            "Default SNMP credentials may be supplied without credential tables:",
            "#   SNMPCOMM                        (SNMPv2c)",
            "#   SNMPUSER + SNMPAUTH + SNMPPRIV (SNMPv3 authPriv; all three required)",
            (
                "Dedicated --community/--snmp.* CLI credentials use the same "
                "lowest-priority runtime profile."
            ),
            (
                "Prefer environment-variable names on the CLI rather than literal "
                "secrets to avoid shell history/process exposure."
            ),
        ],
    )

    for section, value in data.items():
        if not isinstance(value, Mapping):
            raise TypeError(f"top-level configuration value {section!r} must be a table")
        _emit_table(lines, (section,), value)

    lines.extend(["", "# Explicit credential example (uncomment and tailor for larger sites):"])
    lines.extend(
        [
            "# [credentials.site-v3]",
            '# version = "v3"',
            '# username_env = "LLDP_RUNNER_SITE_V3_USER"',
            '# auth_password_env = "LLDP_RUNNER_SITE_V3_AUTH_PASSWORD"',
            '# priv_password_env = "LLDP_RUNNER_SITE_V3_PRIV_PASSWORD"',
            "# Gufo supports sha1/md5 with aes128/des. PySNMP additionally",
            "# supports sha256 with aes256 (Reeder/Cisco) or",
            "# aes256-blumenthal.",
            '# auth_protocol = "sha1"',
            '# priv_protocol = "aes128"',
            "#",
            "# [credential_profiles.site]",
            '# primary = "site-v3"',
            "# primary_attempts = 2",
            "#",
        ]
    )
    lines.extend(
        _wrap_comment(
            "Change credential_rules.default_profile above to 'site' when this "
            "explicit profile should be the default."
        )
    )
    lines.extend(
        [
            "#",
            "# Example most-specific credential address rule:",
            "# [[credential_rules.address]]",
            '# networks = ["192.0.2.0/24"]',
            '# profile = "site"',
            "#",
            "# Example query exclusion:",
            "# [[query_policy.name_rules]]",
            '# patterns = ["(?i)^printer-", "(?i)\\.unmanaged\\.example$"]',
            '# action = "deny"',
            "#",
            "# Example explicit classification rule:",
            "# [[classification.name_rules]]",
            '# patterns = ["(?i)^managed-fw-"]',
            '# category = "managed_device"',
            "#",
            "# Example tagging rule for managed infrastructure:",
            "# [[tagging.rules]]",
            '# label = "infrastructure-role"',
            '# category = "managed_device"',
            '# name_patterns = ["(?i)^(core|dist)-"]',
            '# tags = ["role:infrastructure"]',
            "#",
            "# Example tagging rule for managed voice endpoints:",
            "# [[tagging.rules]]",
            '# label = "voice-endpoints"',
            '# category = "managed_endpoint"',
            '# name_patterns = ["(?i)^SEP[0-9A-F]{12}$"]',
            '# tags = ["service:voice"]',
            "#",
        ]
    )
    lines.extend(
        _wrap_comment(
            "@include directives remain supported in real config files and may "
            "use relative or absolute paths."
        )
    )
    lines.extend(
        _wrap_comment(
            "Automatic sibling conf.d/**/*.toml fragments are loaded once in "
            "lexical relative-path order."
        )
    )
    lines.append("")
    return "\n".join(lines)
