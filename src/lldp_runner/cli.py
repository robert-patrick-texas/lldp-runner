"""LLDP-Runner command line interface."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from lldp_runner import __version__
from lldp_runner.cleanup import clean_run_history
from lldp_runner.config import (
    ConfigError,
    CredentialMode,
    defaults_with_set_overrides,
    discover_config_path,
    load_config,
    resolve_existing_persistent_root,
    resolve_readonly_scratch_root,
)
from lldp_runner.configgen import render_generated_config
from lldp_runner.coordinator import Coordinator, DiscoveryOutcome, explain_target
from lldp_runner.defaults import DEFAULT_SNMP_BACKEND
from lldp_runner.discovery_diff import (
    DiffOutcome,
    DiffSourceSpec,
    DiscoveryDiffError,
    DiscoveryDiffUnavailable,
    host_diff,
    macro_diff,
    resolve_diff_sources,
)
from lldp_runner.discovery_diff_output import render_diff
from lldp_runner.discovery_query import (
    DiscoveryQueryError,
    build_query_criteria,
    load_discovery_document,
    select_hosts,
)
from lldp_runner.discovery_view_output import (
    render_ambiguous_matches,
    render_selected_host,
)
from lldp_runner.identity import resolve_seed_input
from lldp_runner.inspection import inspect_target_sync
from lldp_runner.inspection_output import render_inspection
from lldp_runner.models import SeedInput
from lldp_runner.purge import purge_output_history
from lldp_runner.run_manifest import build_invocation_provenance
from lldp_runner.runtime import find_resumable_run, make_run_paths
from lldp_runner.scoreboard import current_scoreboard_path
from lldp_runner.seed_credentials import load_seed_credential_files
from lldp_runner.seeds import (
    merge_seed_inputs as _merge_seed_inputs,
)
from lldp_runner.seeds import (
    parse_text_seed_line,
    seed_directories_from_environment,
)
from lldp_runner.seeds import (
    read_seed_directory as _read_seed_directory,
)
from lldp_runner.seeds import (
    read_seed_file as _read_seed_file,
)
from lldp_runner.snmp import preflight_snmp_backend
from lldp_runner.snmp.base import SnmpBackendCapabilityError
from lldp_runner.snmp.trace import SnmpTrace
from lldp_runner.watch import WORKER_VIEWS, WatchError, run_watch


class _LldpArgumentParser(argparse.ArgumentParser):
    """Argument parser with project-specific operator-facing diagnostics.

    ``lldp-runner diff`` promises a stable ``Result:`` line for scriptable human
    output, including parser-level usage failures that occur before command
    dispatch. Other subcommands retain argparse's established diagnostics.
    """

    def error(self, message: str) -> None:
        if "argument --tracefile" in message and "expected one argument" in message:
            message = "--tracefile requires a filename to be identified for output"
        if self.prog == "lldp-runner diff":
            print(f"Result: Error - {message}")
        super().error(message)


def _worker_count(value: str) -> int | str:
    """Argparse converter accepting either a positive integer or ``auto``."""

    if value.lower() == "auto":
        return "auto"
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("workers must be a positive integer or 'auto'") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("workers must be >= 1 or 'auto'")
    return parsed


def _positive_float(value: str) -> float:
    """Argparse converter accepting a strictly positive floating-point value."""

    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a number greater than zero") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _non_negative_int(value: str) -> int:
    """Argparse converter accepting a non-negative integer."""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be >= 0")
    return parsed


def _max_devices(value: str) -> int | str:
    """Parse ``--max-devices`` including zero/unlimited and seed-only ``auto``.

    ``auto`` cannot be resolved by argparse because the effective count depends on
    seed identity de-duplication performed by the coordinator at run initialization.
    """

    if value.lower() == "auto":
        return "auto"
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "max-devices must be a non-negative integer or 'auto'"
        ) from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("max-devices must be >= 0 or 'auto'")
    return parsed


def _collect_seeds(
    args: argparse.Namespace,
    config: object,
    *,
    stdin_capture: list[str] | None = None,
    raw_count_capture: list[int] | None = None,
) -> list[SeedInput]:
    """Collect additive seeds from config, CLI, environment, directories, and stdin."""

    seeds: list[SeedInput] = []
    discovery = getattr(config, "discovery")  # noqa: B009 - ty: config is typed as object
    seeds.extend(SeedInput(seed=value, source="config") for value in discovery.seeds)
    for path in discovery.seed_files:
        seeds.extend(_read_seed_file(Path(path)))
    for path in discovery.seed_dirs:
        seeds.extend(_read_seed_directory(Path(path)))

    seeds.extend(SeedInput(seed=value, source="cli") for value in (args.seed or []))
    for path in args.seed_file or []:
        seeds.extend(_read_seed_file(Path(path)))
    for path in args.seed_dir or []:
        seeds.extend(_read_seed_directory(Path(path)))

    env_seeds = os.environ.get("LLDP_RUNNER_SEEDS", "")
    if env_seeds:
        for part in env_seeds.replace(",", "\n").splitlines():
            if part.strip():
                seeds.append(SeedInput(seed=part.strip(), source="LLDP_RUNNER_SEEDS"))

    env_files = os.environ.get("LLDP_RUNNER_SEED_FILES", "")
    if env_files:
        for part in env_files.split(os.pathsep):
            if part:
                seeds.extend(_read_seed_file(Path(part)))

    env_dirs = os.environ.get("LLDP_RUNNER_SEED_DIRS", "")
    if env_dirs:
        for path in seed_directories_from_environment(env_dirs):
            seeds.extend(_read_seed_directory(path))

    if args.stdin:
        for line in sys.stdin:
            seed = parse_text_seed_line(line)
            if seed:
                seeds.append(SeedInput(seed=seed, source="stdin"))
                if stdin_capture is not None:
                    stdin_capture.append(seed)
    if raw_count_capture is not None:
        raw_count_capture.append(len(seeds))
    return _merge_seed_inputs(seeds)


def _add_inspect_format_options(parser: argparse.ArgumentParser) -> None:
    """Add inspect render modes plus dry-run/system-only behavior switches."""

    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--format",
        dest="inspect_format",
        choices=("table", "detail", "csv", "json"),
        default="table",
        help="inspection output format (default: table)",
    )
    output.add_argument(
        "--detail",
        dest="inspect_format",
        action="store_const",
        const="detail",
        help="scrolling semi-structured neighbor detail",
    )
    output.add_argument(
        "--csv",
        dest="inspect_format",
        action="store_const",
        const="csv",
        help="compact parser-friendly neighbor CSV",
    )
    output.add_argument(
        "--json",
        dest="inspect_format",
        action="store_const",
        const="json",
        help="rich discovery.json-aligned JSON",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve DNS and show policy/credential selection without ICMP or SNMP",
    )
    parser.add_argument(
        "--system-only",
        "--no-neighbors",
        dest="system_only",
        action="store_true",
        help=(
            "collect only the initial SYSTEM-MIB probe; skip ENTITY-MIB, IF-MIB, "
            "LLDP, LLDPv2, and CDP"
        ),
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="write operator-readable resolver/ICMP/SNMP network trace to stderr",
    )
    parser.add_argument(
        "--tracefile",
        metavar="FILENAME",
        help=(
            "write network trace to FILENAME; relative names use the current working "
            "directory and this option implies tracing"
        ),
    )


def _add_inspect_runtime_options(
    parser: argparse.ArgumentParser,
    *,
    suppress_defaults: bool,
) -> None:
    """Add config/credential/query knobs that logically apply to one target.

    Discovery controls such as workers, cohorts, max-devices, max-hosts, seed
    ordering, persistence roots, and resume behavior are intentionally absent.
    ``suppress_defaults`` lets the ``lldp-runner get-neighbors`` subparser
    accept options after the subcommand without overwriting equivalent global
    options supplied before the subcommand.
    """

    default = argparse.SUPPRESS if suppress_defaults else None
    set_default: object = argparse.SUPPRESS if suppress_defaults else []
    parser.add_argument("--config", default=default, help="primary TOML configuration")
    parser.add_argument(
        "--set",
        dest="inspect_set" if suppress_defaults else "set",
        action="append",
        default=set_default,
        metavar="OPTION=VALUE",
        help="override any applicable config value using TOML syntax; repeatable",
    )
    parser.add_argument(
        "--snmp.community",
        "--community",
        dest="snmp_community",
        default=default,
        metavar="SNMPCOMM",
        help="default SNMPv2c community; env-var name first, literal second",
    )
    parser.add_argument(
        "--snmp.user",
        "--snmp-user",
        dest="snmp_user",
        default=default,
        metavar="SNMPUSER",
        help="default SNMPv3 authPriv username; env-var name first, literal second",
    )
    parser.add_argument(
        "--snmp.auth",
        "--snmp-auth",
        dest="snmp_auth",
        default=default,
        metavar="SNMPAUTH",
        help="default SNMPv3 auth password; env-var name first, literal second",
    )
    parser.add_argument(
        "--snmp.priv",
        "--snmp-priv",
        dest="snmp_priv",
        default=default,
        metavar="SNMPPRIV",
        help="default SNMPv3 privacy password; env-var name first, literal second",
    )
    parser.add_argument(
        "--snmp.backend",
        "--snmp-backend",
        dest="snmp_backend",
        choices=("gufo", "pysnmp"),
        default=default,
        help=(f"SNMP transport backend for this invocation (default: {DEFAULT_SNMP_BACKEND})"),
    )
    parser.add_argument(
        "--snmp.version",
        "--snmp-version",
        dest="snmp_version",
        choices=("2c", "3"),
        default=default,
        help="preferred runtime SNMP version when both v2c and v3 credentials exist",
    )
    parser.add_argument(
        "--snmp-timeout", type=float, default=default, help="override SNMP request timeout seconds"
    )
    parser.add_argument(
        "--per-device-rps",
        type=float,
        default=default,
        help="override per-device SNMP request rate",
    )
    parser.add_argument("--log-level", default=default, help="override logging level")


def _get_neighbors_parser() -> argparse.ArgumentParser:
    """Build the standalone get-neighbors parser where options may surround TARGET."""

    parser = _LldpArgumentParser(
        prog="get-neighbors",
        description="Inspect one device with LLDP-Runner collectors; never recurse",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__} (LLDP-Runner {__version__})",
    )
    _add_inspect_runtime_options(parser, suppress_defaults=False)
    _add_inspect_format_options(parser)
    parser.add_argument("target", metavar="SEED", help="hostname, IPv4 address, or IPv6 address")
    return parser


class _DiffSourceAction(argparse.Action):
    """Record repeatable diff source selectors in exact command-line order."""

    def __init__(self, option_strings, dest, **kwargs):
        self.source_kind = kwargs.pop("source_kind")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        items = list(getattr(namespace, self.dest, None) or [])
        value = None if self.nargs == 0 else str(values)
        items.append(DiffSourceSpec(self.source_kind, value))
        setattr(namespace, self.dest, items)


def _add_host_selection_options(parser: argparse.ArgumentParser) -> None:
    """Add the host selector contract shared by show-neighbors and diff."""

    parser.add_argument(
        "pattern",
        nargs="?",
        metavar="PATTERN",
        help=(
            "case-insensitive Python regex matched from the start of preferred_name; "
            "equivalent to --name"
        ),
    )
    parser.add_argument(
        "--name",
        metavar="PATTERN",
        help="preferred_name Python regex; matched case-insensitively from the left",
    )
    parser.add_argument(
        "--id",
        dest="host_id",
        type=int,
        metavar="NUM",
        help="select one exact discovery host id; mutually exclusive with all filters",
    )
    parser.add_argument(
        "--key",
        action="append",
        default=[],
        metavar="KEY:PATTERN",
        help=(
            "require a top-level/dotted host key to match a case-insensitive Python "
            "regex; repeatable and AND-combined"
        ),
    )
    parser.add_argument(
        "--ipv4",
        action="append",
        default=[],
        metavar="PREFIX|CIDR",
        help="require an IPv4 literal prefix or CIDR membership match; repeatable",
    )
    parser.add_argument(
        "--ipv6",
        action="append",
        default=[],
        metavar="PREFIX|CIDR",
        help="require an IPv6 literal prefix or CIDR membership match; repeatable",
    )


def _add_show_selection_options(parser: argparse.ArgumentParser) -> None:
    """Add stored-discovery selectors and output controls to a parser.

    Args:
        parser: Main-CLI or standalone ``show-neighbors`` parser receiving the
            common query/output contract.

    Returns:
        ``None`` after mutating ``parser``. Exact ID selection is validated at
        execution time because argparse groups cannot express its exclusivity
        with a repeatable combination of name/key/address criteria.
    """

    _add_host_selection_options(parser)

    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--detail",
        dest="show_format",
        action="store_const",
        const="detail",
        help="scrolling detailed terminal view",
    )
    output.add_argument(
        "--csv",
        dest="show_format",
        action="store_const",
        const="csv",
        help="two metadata comments plus neighbor CSV records",
    )
    output.add_argument(
        "--json",
        dest="show_format",
        action="store_const",
        const="json",
        help="standalone JSON host record preserving its discovery id",
    )
    parser.set_defaults(show_format="table")
    parser.add_argument(
        "--system-only",
        "--no-neighbors",
        dest="system_only",
        action="store_true",
        help="display only the selected host/system record and suppress neighbors",
    )
    parser.add_argument(
        "--neighbors",
        nargs="?",
        const="both",
        choices=("both", "learned", "observed_by"),
        help=(
            "neighbor direction: omitted uses learned then observed_by fallback; "
            "bare --neighbors means both"
        ),
    )
    parser.add_argument(
        "--relationship-view",
        choices=("sectioned", "combined"),
        help=(
            "terminal relationship layout; sectioned is the configured default, "
            "combined uses compact relationship labels and a legend"
        ),
    )


def _add_show_source_options(
    parser: argparse.ArgumentParser,
    *,
    suppress_defaults: bool,
) -> None:
    """Add read-only configuration/source options for stored discovery viewing.

    Args:
        parser: Parser receiving ``--config``, ``--set``, and persistent-root
            override options.
        suppress_defaults: Use ``argparse.SUPPRESS`` for the
            ``lldp-runner show-neighbors`` subparser so options after the
            subcommand do not overwrite global options supplied before it.

    Returns:
        ``None`` after extending ``parser``.
    """

    default = argparse.SUPPRESS if suppress_defaults else None
    set_default: object = argparse.SUPPRESS if suppress_defaults else []
    parser.add_argument(
        "--config",
        dest="show_config" if suppress_defaults else "config",
        default=default,
        help="primary TOML configuration used to locate persistent output",
    )
    parser.add_argument(
        "--set",
        dest="show_set" if suppress_defaults else "set",
        action="append",
        default=set_default,
        metavar="OPTION=VALUE",
        help="override an applicable config value using TOML syntax; repeatable",
    )
    parser.add_argument(
        "--persistent-root",
        dest="show_persistent_root" if suppress_defaults else "persistent_root",
        default=default,
        help="read finalized discovery output beneath this persistent root",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--runid",
        dest="show_runid" if suppress_defaults else "runid",
        default=default,
        metavar="RUNID",
        help="read outputs/<RUNID>/discovery.json instead of outputs/latest",
    )
    source.add_argument(
        "--file",
        dest="show_file" if suppress_defaults else "file",
        default=default,
        metavar="FILENAME",
        help=(
            "read an alternate discovery.json; relative paths start at the "
            "current working directory"
        ),
    )


def _add_diff_options(
    parser: argparse.ArgumentParser,
    *,
    suppress_defaults: bool,
) -> None:
    """Add read-only source, host-selector, and output options for ``diff``."""

    default = argparse.SUPPRESS if suppress_defaults else None
    set_default: object = argparse.SUPPRESS if suppress_defaults else []
    parser.add_argument(
        "--config",
        dest="diff_config" if suppress_defaults else "config",
        default=default,
        help="primary TOML configuration used to locate persistent output",
    )
    parser.add_argument(
        "--set",
        dest="diff_set" if suppress_defaults else "set",
        action="append",
        default=set_default,
        metavar="OPTION=VALUE",
        help="override an applicable config value using TOML syntax; repeatable",
    )
    parser.add_argument(
        "--persistent-root",
        dest="diff_persistent_root" if suppress_defaults else "persistent_root",
        default=default,
        help="read finalized discovery output beneath this persistent root",
    )
    parser.set_defaults(diff_sources=[])
    parser.add_argument(
        "--latest",
        dest="diff_sources",
        action=_DiffSourceAction,
        source_kind="latest",
        nargs=0,
        help="use the most recently completed finalized run as one data set",
    )
    parser.add_argument(
        "--previous",
        "--prior",
        dest="diff_sources",
        action=_DiffSourceAction,
        source_kind="previous",
        nargs=0,
        help="use the finalized run immediately preceding the latest run",
    )
    parser.add_argument(
        "--oldest",
        dest="diff_sources",
        action=_DiffSourceAction,
        source_kind="oldest",
        nargs=0,
        help="use the oldest finalized run with an orderable completed timestamp",
    )
    parser.add_argument(
        "--runid",
        dest="diff_sources",
        action=_DiffSourceAction,
        source_kind="runid",
        metavar="RUNID",
        help="use outputs/<RUNID>/discovery.json; may be supplied twice",
    )
    parser.add_argument(
        "--file",
        dest="diff_sources",
        action=_DiffSourceAction,
        source_kind="file",
        metavar="FILENAME",
        help=(
            "use an alternate discovery JSON; relative paths start at the current "
            "working directory; may be supplied twice"
        ),
    )
    _add_host_selection_options(parser)
    parser.add_argument(
        "--json",
        dest="diff_json",
        action="store_true",
        help="emit machine-readable comparison JSON instead of terminal tables",
    )
    parser.add_argument(
        "--changes-only",
        action="store_true",
        help="suppress unchanged host/neighbor rows from comparison detail",
    )
    parser.add_argument(
        "--include-collection-timing",
        action=argparse.BooleanOptionalAction,
        default=default,
        help=(
            "compare collector duration_ms telemetry; by default timing jitter "
            "is retained in discovery.json but ignored by diff"
        ),
    )
    parser.add_argument(
        "--summary-only",
        action=argparse.BooleanOptionalAction,
        default=default,
        help="emit comparison summaries and collection incidents without row detail",
    )
    parser.add_argument(
        "--expand-collection-incidents",
        action=argparse.BooleanOptionalAction,
        default=default,
        help=(
            "show derivative coverage-uncertain rows in terminal output instead "
            "of collapsing them under their originating incident"
        ),
    )


def _show_neighbors_parser() -> argparse.ArgumentParser:
    """Build the standalone read-only ``show-neighbors`` parser."""

    parser = argparse.ArgumentParser(
        prog="show-neighbors",
        description="Search and display finalized LLDP-Runner discovery JSON",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__} (LLDP-Runner {__version__})",
    )
    _add_show_source_options(parser, suppress_defaults=False)
    _add_show_selection_options(parser)
    return parser


def _parser() -> argparse.ArgumentParser:
    """Build and return the complete ``lldp-runner`` argument parser.

    Returns:
        Configured parser for global options and every supported subcommand.
    """

    parser = _LldpArgumentParser(
        prog="lldp-runner",
        description="Recursive SNMP CDP/LLDP network discovery",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show LLDP-Runner version and exit",
    )
    parser.add_argument(
        "--config",
        help=(
            "primary TOML configuration; when omitted search ~/lldp-runner-config.toml, "
            "~/lldp-runner/config.toml, /opt/lldp-runner/config.toml, then "
            "/etc/lldp-runner/config.toml before using built-in defaults"
        ),
    )
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="OPTION=VALUE",
        help=(
            "override any config value using TOML syntax; repeatable, for example "
            "--set 'snmp.max_repetitions=20'"
        ),
    )
    parser.add_argument(
        "--snmp.community",
        "--community",
        dest="snmp_community",
        metavar="SNMPCOMM",
        help="lowest-priority default SNMPv2c community; env-var name first, literal second",
    )
    parser.add_argument(
        "--snmp.user",
        "--snmp-user",
        dest="snmp_user",
        metavar="SNMPUSER",
        help="lowest-priority default SNMPv3 authPriv username; env-var name first, literal second",
    )
    parser.add_argument(
        "--snmp.auth",
        "--snmp-auth",
        dest="snmp_auth",
        metavar="SNMPAUTH",
        help="lowest-priority default SNMPv3 auth password; env-var name first, literal second",
    )
    parser.add_argument(
        "--snmp.priv",
        "--snmp-priv",
        dest="snmp_priv",
        metavar="SNMPPRIV",
        help="lowest-priority default SNMPv3 privacy password; env-var name first, literal second",
    )
    parser.add_argument(
        "--snmp.backend",
        "--snmp-backend",
        dest="snmp_backend",
        choices=("gufo", "pysnmp"),
        help=(f"SNMP transport backend for this invocation (default: {DEFAULT_SNMP_BACKEND})"),
    )
    parser.add_argument(
        "--snmp.version",
        "--snmp-version",
        dest="snmp_version",
        choices=("2c", "3"),
        help="preferred default SNMP version when both runtime v2c and v3 credentials exist",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "version",
        help="show the installed LLDP-Runner version",
    )

    clean = sub.add_parser(
        "clean",
        help="remove historical run state while preserving current/latest/newest",
    )
    clean.add_argument(
        "--all",
        action="store_true",
        help=(
            "clean persistent and scratch run history (also the default; overrides "
            "--scratch when both are supplied)"
        ),
    )
    clean.add_argument(
        "--scratch",
        action="store_true",
        help="clean only scratch run history; leave persistent run state unchanged",
    )
    clean.add_argument(
        "--dry-run",
        action="store_true",
        help="show LLDP-Runner artifacts that would be removed without deleting them",
    )

    purge = sub.add_parser(
        "purge",
        help="remove historical finalized output directories while preserving latest",
    )
    purge.add_argument(
        "--keep",
        type=_non_negative_int,
        metavar="NUMBER",
        help=(
            "keep latest plus NUMBER additional recent output directories; "
            "default: output.purge_keep"
        ),
    )
    purge.add_argument(
        "--dry-run",
        action="store_true",
        help="show output directories that would be removed without deleting them",
    )

    run = sub.add_parser("run", help="run or resume recursive discovery")
    run.add_argument("--seed", action="append", help="seed host/address; repeatable")
    run.add_argument(
        "--seed-file",
        action="append",
        help="seed file; *.csv uses the current LLDP-Runner seed field set",
    )
    run.add_argument(
        "--seed-dir",
        action="append",
        help="recursively read eligible seed files from this directory; repeatable",
    )
    run.add_argument(
        "--seed-credential-file",
        action="append",
        metavar="FILENAME",
        help=(
            "CSV or JSON per-seed SNMP credential overlay; repeatable; records "
            "never create discovery seeds"
        ),
    )
    run.add_argument(
        "--stdin", action="store_true", help="read additional seeds from standard input"
    )
    run.add_argument("--new-run", action="store_true", help="always start a new run")
    run.add_argument("--no-resume", action="store_true", help="do not resume an incomplete run")
    run.add_argument(
        "--dry-run", action="store_true", help="resolve seeds and explain policy; send no ICMP/SNMP"
    )
    run.add_argument("--workers", type=_worker_count, help="worker count or 'auto'")
    run.add_argument("--batch-size", type=int, help="override cohort batch size")
    run.add_argument(
        "--seed-order",
        choices=("input", "sorted", "random"),
        help="schedule consolidated unique seeds in input, lexical sorted, or randomized order",
    )
    run.add_argument(
        "--seed-dns-mode",
        choices=("resolve", "skip-addressed"),
        help=(
            "seed resolver policy: resolve every seed (default) or reuse eligible "
            "preferred_name + queried_as input without DNS"
        ),
    )
    run.add_argument(
        "--shuffle-key",
        help=(
            "reproducible key for --seed-order random; when omitted a new key is "
            "generated for a new run and persisted for resume"
        ),
    )
    run.add_argument(
        "--limit-behavior",
        choices=("pause", "complete"),
        help=(
            "pause leaves a LIMIT_REACHED run resumable; complete treats a reached "
            "guardrail as an intentional successful endpoint and finalizes outputs"
        ),
    )
    run.add_argument("--persistent-root", help="override persistent root; 'auto' is accepted")
    run.add_argument("--scratch-root", help="override scratch/scoreboard root; 'auto' is accepted")
    run.add_argument(
        "--boundary",
        action="append",
        help="replace configured discovery boundaries with these CIDRs; repeatable",
    )
    run.add_argument(
        "--max-devices",
        type=_max_devices,
        help=(
            "managed-device guardrail: positive integer for recursive limit, 0 for "
            "unlimited, or 'auto' to query seeds only and never recurse into neighbors"
        ),
    )
    run.add_argument(
        "--max-hosts",
        type=int,
        help=(
            "host guardrail; 0 disables it; max-devices=auto counts discovered "
            "non-seed identities rather than the seed inventory"
        ),
    )
    run.add_argument(
        "--snmp-backend",
        choices=("gufo", "pysnmp"),
        default=argparse.SUPPRESS,
        help="select Gufo or PySNMP for the complete run/resume invocation",
    )
    run.add_argument("--snmp-timeout", type=float, help="override SNMP request timeout seconds")
    run.add_argument("--per-device-rps", type=float, help="override per-device SNMP request rate")
    run.add_argument(
        "--max-outstanding",
        type=int,
        help="override max concurrently active device operations per worker",
    )
    run.add_argument("--log-level", help="override logging level")

    inspect = sub.add_parser(
        "get-neighbors", help="probe one device and print CDP/LLDP information"
    )
    inspect.add_argument("target", metavar="SEED", help="hostname, IPv4 address, or IPv6 address")
    _add_inspect_runtime_options(inspect, suppress_defaults=True)
    _add_inspect_format_options(inspect)

    show = sub.add_parser(
        "show-neighbors",
        help="search and display one host from the latest finalized discovery.json",
    )
    _add_show_source_options(show, suppress_defaults=True)
    _add_show_selection_options(show)

    diff = sub.add_parser(
        "diff",
        help="compare finalized discovery results across two runs",
    )
    _add_diff_options(diff, suppress_defaults=True)

    sub.add_parser("validate-config", help="validate effective configuration and credentials")

    generate = sub.add_parser(
        "generate-config",
        help="write a commented configuration starting from built-in defaults",
    )
    generate.add_argument(
        "filename",
        nargs="?",
        help=(
            "output filename; when omitted use ./config.toml in standard "
            "LLDP-Runner directories if absent, otherwise ./lldp-runner-config.toml"
        ),
    )

    explain = sub.add_parser(
        "explain-target", help="explain scope, no-query, and credential policy"
    )
    explain.add_argument("target")

    status = sub.add_parser("status", help="show the current scratch-root scoreboard")
    status.add_argument("--json", action="store_true", help="print machine-readable scoreboard")

    watch = sub.add_parser("watch", help="interactively monitor the current scoreboard")
    watch.add_argument(
        "--interval",
        type=_positive_float,
        default=1.0,
        metavar="SECONDS",
        help="terminal refresh interval in seconds (default: 1)",
    )
    watch.add_argument(
        "--worker-view",
        choices=WORKER_VIEWS,
        default="auto",
        help="worker layout: auto, full, compact, heatmap, or summary (default: auto)",
    )
    watch.add_argument(
        "--palette",
        choices=("dark", "light"),
        help="override terminal.palette for this watch session",
    )
    watch.add_argument(
        "--no-color",
        action="store_true",
        help="disable all watch color/styling for this session",
    )

    sub.add_parser("pause", help="request a controlled pause of the current run")
    return parser


def _load_app(
    args: argparse.Namespace,
    *,
    credential_mode: CredentialMode = CredentialMode.REQUIRED,
    resolve_paths: bool = True,
):
    """Resolve config and apply runtime precedence for one command.

    Args:
        args: Parsed command-line namespace containing global/runtime overrides.
        credential_mode: Determines whether runtime credentials are required,
            merely policy-aware, or completely disabled for stored-data commands.
        resolve_paths: Resolve and probe writable runtime paths when ``True``.

    Returns:
        Effective :class:`~lldp_runner.config.AppConfig` for command execution.
    """

    config_path = discover_config_path(args.config)
    overrides = {
        "workers": getattr(args, "workers", None),
        "batch_size": getattr(args, "batch_size", None),
        "seed_order": getattr(args, "seed_order", None),
        "seed_dns_mode": getattr(args, "seed_dns_mode", None),
        "shuffle_key": getattr(args, "shuffle_key", None),
        "limit_behavior": getattr(args, "limit_behavior", None),
        "persistent_root": getattr(args, "persistent_root", None),
        "scratch_root": getattr(args, "scratch_root", None),
        "boundaries": getattr(args, "boundary", None),
        "max_devices": getattr(args, "max_devices", None),
        "max_hosts": getattr(args, "max_hosts", None),
        "snmp_backend": getattr(args, "snmp_backend", None),
        "snmp_timeout": getattr(args, "snmp_timeout", None),
        "per_device_rps": getattr(args, "per_device_rps", None),
        "max_outstanding": getattr(args, "max_outstanding", None),
        "log_level": getattr(args, "log_level", None),
        "snmp_version": args.snmp_version,
    }
    credentials: dict[str, str | None] = {}
    if credential_mode is not CredentialMode.DISABLED:
        credentials = {
            "community": args.snmp_community,
            "username": args.snmp_user,
            "auth_password": args.snmp_auth,
            "priv_password": args.snmp_priv,
        }
    return load_config(
        config_path,
        overrides=overrides,
        set_expressions=args.set,
        credential_overrides=credentials,
        credential_mode=credential_mode,
        resolve_paths=resolve_paths,
    )


def _default_generated_config_path(
    *,
    cwd: Path | None = None,
    home: Path | None = None,
) -> Path:
    """Choose the no-argument ``generate-config`` destination.

    LLDP-Runner's standard installation/configuration directories conventionally
    use ``config.toml`` as the primary file. When the operator is already inside
    one of those directories and no primary file exists, generating ``config.toml``
    avoids creating a second filename that config discovery would rank differently.

    If ``config.toml`` already exists, fall back to the historical
    ``lldp-runner-config.toml`` name rather than risking an overwrite. Explicit
    filenames always bypass this helper.
    """

    current = (cwd or Path.cwd()).expanduser().resolve()
    home_dir = (home or Path.home()).expanduser().resolve()
    standard_directories = {
        (home_dir / "lldp-runner").resolve(),
        Path("/opt/lldp-runner").resolve(),
        Path("/etc/lldp-runner").resolve(),
    }
    if current in standard_directories and not (current / "config.toml").exists():
        return current / "config.toml"
    return current / "lldp-runner-config.toml"


def _generate_config(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Write a safe, commented configuration without requiring runtime credentials."""

    try:
        data = defaults_with_set_overrides(args.set)
    except (ConfigError, ValueError) as exc:
        parser.error(str(exc))
        return
    if getattr(args, "snmp_backend", None) is not None:
        data["snmp"]["backend"] = args.snmp_backend
    if args.snmp_version is not None:
        data["snmp"]["version"] = args.snmp_version

    destination = (
        Path(args.filename).expanduser() if args.filename else _default_generated_config_path()
    )
    if destination.exists():
        parser.error(f"refusing to overwrite existing configuration file: {destination}")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(render_generated_config(data), encoding="utf-8")
    except OSError as exc:
        parser.error(f"unable to write configuration file {destination}: {exc}")
        return
    print(f"Generated configuration: {destination.resolve()}")


def _execute_inspect(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Load inspect-effective config, run one target, and write only the result to stdout."""

    # lldp-runner accepts global --set before the subcommand and inspect-local
    # --set after it. Keep both in command-line order groups instead of letting
    # argparse's subparser namespace replace the global repeatable list.
    if hasattr(args, "inspect_set"):
        args.set = [*getattr(args, "set", []), *args.inspect_set]

    try:
        config = _load_app(
            args,
            credential_mode=(CredentialMode.OPTIONAL if args.dry_run else CredentialMode.REQUIRED),
            resolve_paths=False,
        )
        # Inspection has no activity.log, so applicable logging is a simple stderr
        # stream. Machine-readable stdout remains pure for redirection/parsing.
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.setLevel(config.logging.level.upper())
        if config.logging.console:
            handler = logging.StreamHandler(sys.stderr)
            handler.setLevel(config.logging.level.upper())
            handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
            root_logger.addHandler(handler)
        if not args.dry_run:
            # Single-device inspection bypasses the coordinator, so perform the
            # same local PySNMP authPriv capability check explicitly before DNS,
            # ICMP, trace-file creation, or SNMP work.
            preflight_snmp_backend(config)
        trace_file = None
        trace = None
        try:
            trace_streams = []
            if getattr(args, "trace", False):
                trace_streams.append(sys.stderr)
            if getattr(args, "tracefile", None) is not None:
                if args.tracefile == "":
                    raise ValueError("--tracefile requires a filename to be identified for output")
                trace_path = Path(args.tracefile).expanduser()
                try:
                    # Open before DNS/ICMP/SNMP work so an invalid trace
                    # destination cannot fail after the device was contacted.
                    trace_file = trace_path.open("w", encoding="utf-8", newline="\n")
                except OSError as exc:
                    raise OSError(f"unable to open trace file {trace_path}: {exc}") from exc
                trace_streams.append(trace_file)
            if trace_streams:
                trace = SnmpTrace(trace_streams, input_target=args.target)

            result = inspect_target_sync(
                config,
                args.target,
                dry_run=args.dry_run,
                system_only=args.system_only,
                trace=trace,
            )
            rendered = render_inspection(config, result, args.inspect_format, stream=sys.stdout)
        finally:
            if trace is not None:
                trace.finish()
            if trace_file is not None:
                trace_file.close()
    except (
        ConfigError,
        OSError,
        SnmpBackendCapabilityError,
        UnicodeError,
        ValueError,
    ) as exc:
        parser.error(str(exc))
        return 2
    except KeyboardInterrupt:
        return 130
    sys.stdout.write(rendered)
    sys.stdout.write("\n")
    return result.exit_code


def get_neighbors_main(argv: list[str] | None = None) -> None:
    """Console entry point for the compact single-device ``get-neighbors`` command."""

    parser = _get_neighbors_parser()
    args = parser.parse_args(argv)
    status = _execute_inspect(args, parser)
    if status:
        raise SystemExit(status)


def _execute_show(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Search finalized discovery JSON and render exactly one selected host.

    Args:
        args: Parsed ``show-neighbors`` arguments.
        parser: Active parser used to report invalid syntax/configuration on
            standard error with argparse's conventional exit status 2.

    Returns:
        ``0`` for one successful match, ``1`` for no match, or ``3`` for an
        ambiguous multiple-match result. Invalid filters/configuration call
        ``parser.error`` and therefore exit with status 2.
    """

    if getattr(args, "pattern", None) is not None and getattr(args, "name", None) is not None:
        parser.error("PATTERN and --name are alternate forms; provide only one")
    if args.system_only and args.neighbors is not None:
        parser.error("--system-only/--no-neighbors cannot be combined with --neighbors")

    if hasattr(args, "show_config") and args.show_config is not None:
        args.config = args.show_config
    if hasattr(args, "show_set"):
        args.set = [*getattr(args, "set", []), *args.show_set]
    if hasattr(args, "show_persistent_root") and args.show_persistent_root is not None:
        args.persistent_root = args.show_persistent_root
    if hasattr(args, "show_runid") and args.show_runid is not None:
        args.runid = args.show_runid
    if hasattr(args, "show_file") and args.show_file is not None:
        args.file = args.show_file

    name_pattern = args.name if args.name is not None else args.pattern
    try:
        config_path = discover_config_path(getattr(args, "config", None))
        config = load_config(
            config_path,
            overrides={"persistent_root": getattr(args, "persistent_root", None)},
            set_expressions=getattr(args, "set", []),
            credential_overrides={},
            credential_mode=CredentialMode.DISABLED,
            resolve_paths=False,
        )
        criteria = build_query_criteria(
            host_id=args.host_id,
            name=name_pattern,
            key_expressions=args.key,
            ipv4_values=args.ipv4,
            ipv6_values=args.ipv6,
        )
        document = load_discovery_document(
            config,
            run_id=getattr(args, "runid", None),
            filename=getattr(args, "file", None),
        )
        matches = select_hosts(document, criteria)
    except (ConfigError, DiscoveryQueryError, OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
        return 2

    if not matches:
        print("No discovery records matched.")
        return 1
    if len(matches) > 1:
        print(render_ambiguous_matches(matches))
        return 3

    rendered = render_selected_host(
        config,
        document,
        matches[0],
        output_format=args.show_format,
        neighbor_mode=args.neighbors,
        relationship_view=(args.relationship_view or config.output.relationship_view),
        system_only=args.system_only,
        json_indent=config.output.pretty_json_indent,
        stream=sys.stdout,
    )
    sys.stdout.write(rendered)
    sys.stdout.write("\n")
    return 0


def _diff_selector_present(args: argparse.Namespace) -> bool:
    """Return whether any show-neighbors-compatible host selector was supplied."""

    return bool(
        getattr(args, "pattern", None) is not None
        or getattr(args, "name", None) is not None
        or getattr(args, "host_id", None) is not None
        or getattr(args, "key", [])
        or getattr(args, "ipv4", [])
        or getattr(args, "ipv6", [])
    )


def _execute_diff(args: argparse.Namespace) -> int:
    """Resolve two stored data sets and perform macro or one-host comparison."""

    if getattr(args, "pattern", None) is not None and getattr(args, "name", None) is not None:
        print("Result: Error - PATTERN and --name are alternate forms; provide only one")
        return 2

    if hasattr(args, "diff_config") and args.diff_config is not None:
        args.config = args.diff_config
    if hasattr(args, "diff_set"):
        args.set = [*getattr(args, "set", []), *args.diff_set]
    if hasattr(args, "diff_persistent_root") and args.diff_persistent_root is not None:
        args.persistent_root = args.diff_persistent_root

    config = None
    json_output = bool(getattr(args, "diff_json", False))
    try:
        config_path = discover_config_path(getattr(args, "config", None))
        config = load_config(
            config_path,
            overrides={"persistent_root": getattr(args, "persistent_root", None)},
            set_expressions=getattr(args, "set", []),
            credential_overrides={},
            credential_mode=CredentialMode.DISABLED,
            resolve_paths=False,
        )
        source_a, source_b = resolve_diff_sources(config, getattr(args, "diff_sources", []))
        criteria = None
        if _diff_selector_present(args):
            name_pattern = args.name if args.name is not None else args.pattern
            criteria = build_query_criteria(
                host_id=args.host_id,
                name=name_pattern,
                key_expressions=args.key,
                ipv4_values=args.ipv4,
                ipv6_values=args.ipv6,
            )
        if criteria is None:
            include_collection_timing = getattr(
                args,
                "include_collection_timing",
                config.diff.include_collection_timing,
            )
            outcome = macro_diff(
                config,
                source_a,
                source_b,
                changes_only=bool(args.changes_only),
                include_collection_timing=bool(include_collection_timing),
            )
        else:
            include_collection_timing = getattr(
                args,
                "include_collection_timing",
                config.diff.include_collection_timing,
            )
            outcome = host_diff(
                config,
                source_a,
                source_b,
                criteria,
                changes_only=bool(args.changes_only),
                include_collection_timing=bool(include_collection_timing),
            )
    except DiscoveryDiffUnavailable as exc:
        outcome = DiffOutcome(
            status="comparison_unavailable",
            message=str(exc),
            exit_code=4,
            mode="host" if _diff_selector_present(args) else "macro",
        )
    except (
        ConfigError,
        DiscoveryDiffError,
        DiscoveryQueryError,
        OSError,
        UnicodeError,
        ValueError,
    ) as exc:
        outcome = DiffOutcome(
            status="error",
            message=f"Error - {exc}",
            exit_code=2,
            mode="host" if _diff_selector_present(args) else "macro",
        )

    if config is None:
        if json_output:
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "result": {
                            "status": outcome.status,
                            "message": outcome.message,
                            "exit_code": outcome.exit_code,
                        },
                    },
                    indent=2,
                )
            )
        else:
            print(f"Result: {outcome.message}")
        return outcome.exit_code

    rendered = render_diff(
        config,
        outcome,
        json_output=json_output,
        json_indent=config.output.pretty_json_indent,
        summary_only=bool(getattr(args, "summary_only", config.diff.summary_only)),
        expand_collection_incidents=bool(
            getattr(
                args,
                "expand_collection_incidents",
                config.diff.expand_collection_incidents,
            )
        ),
        stream=sys.stdout,
    )
    sys.stdout.write(rendered)
    sys.stdout.write("\n")
    return outcome.exit_code


def show_neighbors_main(argv: list[str] | None = None) -> None:
    """Console entry point for read-only searches of finalized discovery output."""

    parser = _show_neighbors_parser()
    args = parser.parse_args(argv)
    status = _execute_show(args, parser)
    if status:
        raise SystemExit(status)


def _print_discovery_outcome(outcome: DiscoveryOutcome) -> None:
    """Print the stable terminal summary for a completed run invocation.

    Args:
        outcome: Coordinator result containing status, runtime, and artifact paths.

    Returns:
        ``None``. Human-readable lines are written to standard output. The Runtime
        line intentionally follows Status so scripts/operators see terminal state
        and execution timing together.
    """

    print(f"Run: {outcome.run_id}")
    print(f"Status: {outcome.status}")
    print(
        "Runtime: "
        f"{outcome.started_timestamp} to {outcome.ended_timestamp} "
        f"(duration: {outcome.duration_seconds}s)"
    )
    print(f"State: {outcome.state_path}")
    print(
        f"Activity log: {outcome.activity_log}"
        if outcome.activity_log is not None
        else "Activity log: disabled"
    )
    if outcome.output_directory:
        print(f"Output: {outcome.output_directory}")


def main(argv: list[str] | None = None) -> None:
    """Execute the LLDP-Runner command-line interface.

    Args:
        argv: Optional arguments without the program name. ``None`` delegates to
            argparse's normal ``sys.argv`` processing for the console entry point.

    Results:
        Prints command results/status and exits through argparse/SystemExit for
        requested help/version output or terminal command errors.
    """

    parser = _parser()
    raw_argv = list(argv) if argv is not None else list(sys.argv[1:])
    args = parser.parse_args(raw_argv)

    if args.command == "version":
        print(f"{parser.prog} {__version__}")
        return

    if args.command == "generate-config":
        _generate_config(args, parser)
        return

    if args.command == "get-neighbors":
        status = _execute_inspect(args, parser)
        if status:
            raise SystemExit(status)
        return

    if args.command == "show-neighbors":
        status = _execute_show(args, parser)
        if status:
            raise SystemExit(status)
        return

    if args.command == "diff":
        status = _execute_diff(args)
        if status:
            raise SystemExit(status)
        return

    try:
        credential_mode = CredentialMode.REQUIRED
        if args.command in {"status", "watch", "clean", "purge"}:
            credential_mode = CredentialMode.DISABLED
        elif args.command in {"pause", "explain-target"}:
            # explain-target evaluates credential-profile policy but never needs
            # secret material or writable runtime paths. OPTIONAL retains the
            # profile/rule model while allowing unavailable secrets.
            credential_mode = CredentialMode.OPTIONAL
        config = _load_app(
            args,
            credential_mode=credential_mode,
            resolve_paths=(
                args.command not in {"status", "watch", "clean", "purge", "explain-target"}
            ),
        )
        if args.command in {"status", "watch", "clean", "purge"}:
            config.paths.scratch_root = resolve_readonly_scratch_root(
                config.paths.scratch_root,
                persistent_root=config.paths.persistent_root,
            )
    except (ConfigError, OSError, ValueError) as exc:
        parser.error(str(exc))
        return

    if args.command == "clean":
        # ``--all`` intentionally wins over ``--scratch`` so ``clean --scratch
        # --all`` has the same all-area semantics as ``clean --all``. With no
        # flags the command also cleans both areas, matching the operator-facing
        # default requested for routine retention maintenance.
        scratch_only = bool(args.scratch and not args.all)
        persistent_root = None
        try:
            persistent_root = resolve_existing_persistent_root(config.paths.persistent_root)
        except (ConfigError, OSError, ValueError) as exc:
            # Scratch-only cleanup must not become dependent on persistent
            # storage availability. When resolvable, however, its latest alias
            # provides one extra run ID that scratch cleanup should preserve.
            if not scratch_only:
                parser.error(str(exc))
                return
        try:
            result = clean_run_history(
                config,
                persistent_root=persistent_root,
                scratch_root=Path(config.paths.scratch_root),
                scratch_only=scratch_only,
                dry_run=args.dry_run,
            )
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
            return
        action = "would remove" if args.dry_run else "removed"
        for area in result.areas:
            kept = ", ".join(area.preserved) if area.preserved else "none"
            print(
                f"{area.label.capitalize()}: {action} {len(area.removed)}; "
                f"preserved {kept}; root={area.root}"
            )
        prefix = "Clean dry-run" if args.dry_run else "Clean complete"
        print(f"{prefix}: {action} {result.removed_count} LLDP-Runner artifact(s)")
        return

    if args.command == "purge":
        try:
            persistent_root = resolve_existing_persistent_root(config.paths.persistent_root)
            keep = config.output.purge_keep if args.keep is None else args.keep
            result = purge_output_history(
                config,
                persistent_root=persistent_root,
                scratch_root=Path(config.paths.scratch_root),
                keep=keep,
                dry_run=args.dry_run,
            )
        except (ConfigError, OSError, ValueError) as exc:
            parser.error(str(exc))
            return
        verb = "would remove" if args.dry_run else "removed"
        for item in result.removed:
            print(f"Purge: {verb} {item.run_id} (timestamp={item.timestamp_source})")
        kept = ", ".join(item.run_id for item in result.preserved) or "none"
        prefix = "Purge dry-run" if args.dry_run else "Purge complete"
        print(
            f"{prefix}: {verb} {len(result.removed)} output "
            f"{'directory' if len(result.removed) == 1 else 'directories'}; "
            f"preserved {kept}; keep={keep}; root={result.root}"
        )
        return

    if args.command == "watch":
        try:
            run_watch(
                config,
                interval=args.interval,
                worker_view=args.worker_view,
                palette=args.palette,
                no_color=args.no_color,
            )
        except WatchError as exc:
            parser.error(str(exc))
        return

    if args.command in {"status", "pause"}:
        # Operational commands use the complete include-aware/default-aware path
        # resolver. ``status`` disables the credential subsystem entirely; pause
        # remains credential-optional because it mutates current run control state.
        scratch_root = config.paths.scratch_root
        pause_indicator = config.resume.pause_indicator
        if args.command == "pause":
            current = scratch_root / "current"
            if not current.exists():
                parser.error(f"no current run under {scratch_root}")
            indicator = current / pause_indicator
            indicator.touch(exist_ok=True)
            print(f"Pause requested: {indicator}")
            return
        scoreboard = current_scoreboard_path(scratch_root, json_output=args.json)
        if not scoreboard.exists():
            parser.error(f"scoreboard not found: {scoreboard}")
        sys.stdout.write(scoreboard.read_text(encoding="utf-8"))
        return

    if args.command == "validate-config":
        source = str(config.config_path) if config.config_path is not None else "built-in defaults"
        print(f"Configuration valid: {source}")
        return

    if args.command == "explain-target":
        print(json.dumps(explain_target(config, args.target), indent=2))
        return

    if args.command == "run":
        stdin_seeds: list[str] = []
        raw_seed_counts: list[int] = []
        try:
            seeds = _collect_seeds(
                args,
                config,
                stdin_capture=stdin_seeds,
                raw_count_capture=raw_seed_counts,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            parser.error(str(exc))
            return
        if args.dry_run:
            if not seeds:
                parser.error("dry-run requires at least one seed")
            payload = []
            for seed in seeds:
                resolved, _dns_action = resolve_seed_input(
                    seed,
                    config.discovery.dns_suffixes,
                    mode=config.discovery.seed_dns_mode,
                )
                payload.append(
                    explain_target(
                        config,
                        seed.seed,
                        resolved_identity=resolved,
                    )
                )
            print(json.dumps(payload, indent=2))
            return

        try:
            seed_credential_load = load_seed_credential_files(
                [Path(value) for value in (args.seed_credential_file or [])],
                config,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            parser.error(str(exc))
            return

        resume_id: str | None = None
        resume_enabled = config.resume.default_resume and not args.no_resume and not args.new_run
        if resume_enabled:
            resume_id = find_resumable_run(config)
        invocation_provenance = build_invocation_provenance(
            config,
            argv=raw_argv,
            arguments=vars(args),
            seeds=seeds,
            stdin_seeds=stdin_seeds,
        )
        try:
            paths = make_run_paths(config, resume_id)
            coordinator = Coordinator(
                config,
                paths,
                resume=resume_id is not None,
                invocation_provenance=invocation_provenance,
                seed_credential_load=seed_credential_load,
            )
        except (OSError, SnmpBackendCapabilityError, ValueError) as exc:
            # Run-ID allocation, storage preflight, and logging setup all happen
            # before initialize() can schedule discovery work. Report storage,
            # backend capability, and collision failures without a traceback.
            parser.error(str(exc))
            return
        try:
            coordinator.initialize(
                seeds,
                raw_seed_count=raw_seed_counts[0] if raw_seed_counts else len(seeds),
            )
        except (OSError, ValueError) as exc:
            # initialize() can fail before run() owns the normal finally/cleanup
            # path, notably for the finite max_devices seed-count fail-fast check.
            # Close the provenance invocation as well so run.json history never
            # leaves a failed launch looking as though its process were still active.
            try:
                coordinator.log_initialization_failure(exc)
                coordinator.record_initialization_failure()
            finally:
                coordinator.close()
            parser.error(str(exc))
            return
        try:
            outcome = coordinator.run()
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
            return
        _print_discovery_outcome(outcome)
        return

    parser.error(f"unknown command {args.command}")


if __name__ == "__main__":
    main()
