"""Built-in LLDP-Runner defaults and operator-facing configuration guidance.

This module is intentionally ordinary package source rather than hidden generated
metadata. Distribution maintainers and site-local support teams may modify these
values when building or maintaining LLDP-Runner for their environment, just as
they may patch any other Python source file in the package.

Runtime precedence is intentionally higher than these values:

    defaults.py
      -> discovered/explicit TOML configuration (+ @include/conf.d)
      -> LLDP_RUNNER_* environment overrides
      -> repeatable --set overrides
      -> dedicated command-line options

The ``auto`` values are resolved by :mod:`lldp_runner.config` on the host that is
actually running LLDP-Runner. Keep comments here concise but operationally useful;
``generate-config`` and ``configs/example.toml`` provide the longer operator guide.
"""

from __future__ import annotations

from typing import Any, Final

TERMINAL_COLOR_NAMES = frozenset(
    {
        "black",
        "red",
        "green",
        "yellow",
        "blue",
        "magenta",
        "cyan",
        "white",
        "default",
        "none",
    }
)

# Configuration filenames searched when the operator does not supply --config
# (and LLDP_RUNNER_CONFIG is unset). Paths beginning with ``~`` are expanded for
# the invoking user. The first existing file wins.
CONFIG_SEARCH_PATHS: tuple[str, ...] = (
    "~/lldp-runner-config.toml",
    "~/lldp-runner/config.toml",
    "/opt/lldp-runner/config.toml",
    "/etc/lldp-runner/config.toml",
)

# Install layouts used when ``paths.persistent_root`` or ``paths.scratch_root``
# is ``auto``. The layout follows the directory of the selected primary config
# file as it was named (symlinks are not resolved), so runtime data always
# belongs to the installation that defined it (see lldp_runner.layout):
#
#   shared  <dir>/config.toml outside the home directory, such as
#           /opt/lldp-runner: persistent <dir>/var, scratch /dev/shm/lldp-runner
#   system  /etc/lldp-runner/config.toml: persistent /var/lib/lldp-runner,
#           scratch /run/lldp-runner
#   user    a config below the home directory, or no config at all:
#           persistent <dir>/var (~/lldp-runner/var for a file directly in the
#           home directory or no file), scratch $XDG_RUNTIME_DIR/lldp-runner
#
# A shared installation other than /opt/lldp-runner, or a user installation
# other than ~/lldp-runner, gets its own scratch name such as
# /dev/shm/lldp-runner-srv-lab. Every layout falls back to <persistent_root>/tmp
# for scratch. Distribution packagers can change these constants instead of
# patching resolver code.
SYSTEM_CONFIG_DIR: Final[str] = "/etc/lldp-runner"
SYSTEM_PERSISTENT_ROOT: Final[str] = "/var/lib/lldp-runner"
SYSTEM_SCRATCH_ROOTS: tuple[str, ...] = ("/run/lldp-runner",)
SHARED_DEFAULT_INSTANCE_DIR: Final[str] = "/opt/lldp-runner"
SHARED_SCRATCH_BASES: tuple[str, ...] = ("/dev/shm",)
USER_INSTANCE_DIR: Final[str] = "~/lldp-runner"
INSTANCE_DATA_DIRNAME: Final[str] = "var"
SCRATCH_FALLBACK_DIRNAME: Final[str] = "tmp"

# PySNMP became the built-in default in 0.37.0 after repeated production
# discovery runs demonstrated complete collection, stable topology, correct
# SNMPv3/IPv6 behavior, and lower elapsed time. Explicit Gufo selection remains
# supported, and a run's selected backend is still immutable across every resume.
DEFAULT_SNMP_BACKEND: Final[str] = "pysnmp"

# Direct environment-variable credentials are deliberately generic and lowest
# priority. Explicit credential tables/profiles in TOML take precedence and
# suppress synthesis of this runtime default profile.
DEFAULT_SNMP_ENV = {
    "community": "SNMPCOMM",
    "username": "SNMPUSER",
    "auth_password": "SNMPAUTH",
    "priv_password": "SNMPPRIV",
}

# Complete built-in configuration. Lists here are copied before use so runtime
# code never mutates this module-level object. A partial config.toml only needs to
# specify values that differ from these defaults.
DEFAULTS: dict[str, Any] = {
    "paths": {
        # Resolve at runtime from the install layout described above.
        "persistent_root": "auto",
        "scratch_root": "auto",
        "runs_dirname": "runs",
        "output_dirname": "outputs",
        # Completed runs normally leave no transient snapshots or scoreboard
        # files behind. Disable only when operators intentionally retain scratch
        # artifacts for post-run diagnostics.
        "clean_scratch_when_completed": True,
        # strftime directives plus optional {counter}; preserve the historical
        # timestamp-and-timezone naming scheme unless an operator overrides it.
        "run_id_format": "%Y%m%d-%H%M%S-%Z",
    },
    "time": {
        # eastern preserves historical LLDP-Runner behavior. Also accepted:
        # utc, local, or any IANA timezone available through zoneinfo.
        "timezone": "eastern",
    },
    "discovery": {
        # Unlimited scope by default. Complex/production engagements should set
        # explicit boundaries even though max_devices/max_hosts remain guardrails.
        "boundaries": ["0.0.0.0/0", "::/0"],
        "seeds": [],
        "seed_files": [],
        "seed_dirs": [],
        # Seed scheduling policy after all input sources have been consolidated and
        # DNS/alias identity correlation has de-duplicated the authoritative seeds:
        #   input  -> preserve first-seen consolidated seed order;
        #   sorted -> case-insensitive lexical order of the resolved preferred name;
        #   random -> deterministic hash shuffle using shuffle_key.  When the key is
        #             empty, a fresh key is generated for a new run and persisted so
        #             pause/resume retains the same order.
        "seed_order": "input",
        # Seed DNS policy:
        #   resolve         -> always perform normal seed resolver work;
        #   skip-addressed  -> reuse a supplied name + queried_as address when
        #                      prior state is successful/complete (or absent).
        # Learned-neighbor DNS enrichment is controlled separately below.
        "seed_dns_mode": "resolve",
        "shuffle_key": "",
        # What reaching a finite runtime guardrail means:
        #   pause    -> guardrail stop, status LIMIT_REACHED, resumable by default;
        #   complete -> intentional endpoint, finalize outputs as COMPLETED_LIMIT and
        #               do not advertise the run as resumable.
        "limit_behavior": "pause",
        # Resolved to (os.cpu_count() or 1) * 4 on the running host.
        "workers": "auto",
        # Cohort size: number of device tasks assigned together to a worker.
        "batch_size": 9,
        # Managed-device query guardrail. Supported operator values are:
        #   positive integer -> recursive discovery up to that managed-device limit;
        #   0                -> unlimited managed-device recursive discovery;
        #   "auto"           -> seed-only mode: query every unique seed but record,
        #                       classify, and output discovered neighbors without
        #                       scheduling those non-seed neighbors for SNMP.
        # The conservative built-in integer protects accidental broad discovery.
        "max_devices": 10,
        # Host-identification guardrail. Recursive discovery counts all identities.
        # In max_devices="auto" seed-only sampling, explicit seeds are sampling
        # points and only discovered non-seed identities consume this threshold.
        # A value of 0 disables the host-count guardrail.
        "max_hosts": 1000,
        # One failed recursively discovered host may be re-admitted only when
        # later protocol evidence adds a genuinely new permitted address.
        "late_address_recovery_attempts": 1,
        "address_preference": ["ipv4", "ipv6"],
        "work_stealing": True,
        "dns_suffixes": [],
        "resolve_discovered_managed_names": True,
    },
    "snmp": {
        "backend": DEFAULT_SNMP_BACKEND,
        "port": 161,
        # Default credential preference when both v2c and v3 runtime credentials
        # are available. SNMPv3 authPriv is preferred as the best-practice default.
        "version": "3",
        "timeout_seconds": 3.0,
        "max_repetitions": 20,
        # Each logical operation and collector family has a bounded allowance.
        # General retries use the shared target cap. LLDP-family and CDP
        # collectors also have a protected reserve so earlier SYSTEM-MIB,
        # ENTITY-MIB, or IF-MIB failures cannot consume every topology repair.
        "retry_per_operation": 1,
        "retry_per_collector": 1,
        "retry_total_cap": 3,
        "retry_neighbor_reserve": 2,
        "structural_table_retry": 1,
        "retry_timeout_multiplier": 1.5,
        "retry_max_repetitions_multiplier": 0.5,
        "retry_min_max_repetitions": 1,
        "retry_inter_pdu_delay_ms": 100.0,
        # After normal adaptive repair is exhausted, one optional delayed
        # full-protocol retry may be issued for each failed LLDP-family or CDP
        # collector. All failed protocols on a target share one delay window.
        "neighbor_stability_retry": True,
        "neighbor_stability_retry_delay_seconds": 2.0,
        "per_device_rps": 5.0,
        "max_outstanding_devices_per_worker": 24,
        "inter_wave_delay_seconds": 0.15,
        "collect_entity_mib": True,
        # Query scope for ENTITY-MIB enrichment. full preserves the historical
        # entPhysicalEntry walk; auto/brief use index-aware selective queries.
        "entity_mib_mode": "full",
        # Full discovery does not persist per-collector SNMP telemetry unless
        # explicitly requested. Single-device inspection always collects these
        # lightweight object-count and elapsed-time metrics for interactive diagnostics.
        "report_metrics": False,
    },
    "icmp": {
        "enabled": True,
        # Current discovery policy intentionally sends exactly two wake-up probes.
        "probes": 2,
        "timeout_seconds": 1.0,
        "inter_probe_delay_seconds": 0.15,
        "backend": "auto",
    },
    "output": {
        "draft_in_scratch": True,
        "snapshot_interval_seconds": 30.0,
        "scoreboard_interval_seconds": 3.0,
        "pretty_json_indent": 2,
        # run.json records sanitized launch provenance for completed runs. Config
        # file paths are useful operational provenance but may be suppressed by
        # sites that do not want deployment layout details in output artifacts.
        "run_json_config_log": True,
        # purge keeps latest plus this many additional timestamp-ranked output
        # directories when --keep is not supplied. Zero means latest only.
        "purge_keep": 0,
        # Baseline widths for the shared get-neighbors/show-neighbors table.
        # Renderers may expand these columns when longer interface values fit.
        "neighbor_local_width": 18,
        "neighbor_remote_port_width": 18,
        # sectioned groups ordinary adjacency observations separately from shared-
        # chassis, overlay, and multi-neighbor discrepancies. combined emits one
        # table with compact relationship labels and a legend.
        "relationship_view": "sectioned",
        "chassis_id_name_fallback": "disabled",
        # The five standard CSVs are fixed-schema convenience views. Operators
        # may suppress an unneeded view, but fields/labels stay version-controlled.
        # discovery.json remains the complete structured result for later exporters.
        "write_hosts_csv": True,
        "write_stack_members_csv": True,
        "write_seeds_csv": True,
        "write_unknown_devices_csv": True,
        "write_errors_csv": True,
        # Header-only CSVs add little operational value and can look like populated
        # reports to simplistic automation. This one global policy applies to all
        # five fixed-schema CSVs while preserving each report's enable switch.
        "write_empty_csv": False,
        # Optional informational logging for terminal snapshots when one or more
        # enabled CSVs are suppressed solely because they contain no records.
        "log_alert_on_empty_csv": False,
        # Named operator-defined CSV reports. Each report declares one row source
        # and an ordered list of registered fixed/JSON fields. Empty by default.
        "custom_csv": {},
    },
    "diff": {
        # Collection timings are useful diagnostics inside each discovery, but
        # ordinary elapsed-time jitter is not a semantic cross-run change.
        "include_collection_timing": False,
        # Keep the default report useful for interactive investigations while
        # permitting an intentionally compact health/summary-only form.
        "summary_only": False,
        # Coverage incidents can obscure hundreds of downstream observations.
        # The default terminal report collapses those derivative rows under the
        # originating incident; JSON always retains every structured detail.
        "expand_collection_incidents": False,
    },
    "terminal": {
        # Terminal color policy. ``palette`` selects the built-in watch dashboard
        # theme; the semantic named colors below remain direct overrides for the
        # neighbor-oriented renderers. ``color=never`` disables terminal styling.
        "color": "auto",
        "palette": "dark",
        # Semantic terminal colors shared by get-neighbors and show-neighbors.
        # Values are validated named colors rather than raw ANSI escape strings.
        "heading_color": "cyan",
        "success_color": "green",
        "warning_color": "yellow",
        "error_color": "red",
        "learned_color": "cyan",
        "observed_by_color": "magenta",
        "inspection_neighbor_color": "magenta",
        "metric_color": "green",
    },
    "resume": {
        "default_resume": True,
        "lease_seconds": 300,
        "pause_indicator": "pause.request",
    },
    "credentials": {},
    "credential_profiles": {},
    "credential_rules": {
        # When runtime default credentials are synthesized from SNMPCOMM or the
        # SNMPUSER/SNMPAUTH/SNMPPRIV trio, this is the profile name they use.
        "default_profile": "runtime-default",
        "address": [],
        "name": [],
    },
    "query_policy": {
        "default_action": "allow",
        "address_rules": [],
        "name_rules": [],
    },
    "classification": {
        "address_rules": [],
        "name_rules": [],
        "evidence_rules": [],
        "managed_manufacturers": ["Cisco", "Juniper", "Arista", "Aruba", "HPE"],
        "managed_endpoint_patterns": [
            r"(?i)\bCisco\s+(IP\s+)?Phone\b",
            r"(?i)\bSEP[0-9A-F]{12}\b",
            r"(?i)\bAIR-[A-Z0-9-]+\b",
            r"(?i)\b(Cisco|Juniper|Mist).*\bAP\b",
            r"(?i)\bvIPer\b",
        ],
        "unmanaged_patterns": [
            r"(?i)\bprinter\b",
            r"(?i)\bTACLANE\b",
            r"(?i)\bworkstation\b",
        ],
    },
    "tagging": {"rules": []},
    "neighbors": {
        "enable_lldp": True,
        "enable_lldpv2": True,
        "cdp_for_cisco": True,
        "cdp_manufacturers": ["Cisco"],
    },
    "logging": {
        "level": "INFO",
        "console": True,
        # Console and file destinations are independent. A relative filename is
        # resolved beneath runs/<run-id>/; an absolute path supports centralized
        # logging such as /var/log/lldprunner.log.
        "file": True,
        "filename": "activity.log",
    },
}

# Defaults for optional fields inside explicit credential/profile tables. They are
# separate from DEFAULTS because credential names are site-defined dynamic keys.
CREDENTIAL_AUTH_PROTOCOL_DEFAULT = "sha1"
CREDENTIAL_PRIV_PROTOCOL_DEFAULT = "aes128"
CREDENTIAL_PRIMARY_ATTEMPTS_DEFAULT = 1
CREDENTIAL_FALLBACK_ATTEMPTS_DEFAULT = 1
