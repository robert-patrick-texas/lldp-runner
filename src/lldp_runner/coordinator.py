"""Single-owner discovery coordinator and multiprocessing scheduler."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import math
import multiprocessing as mp
import queue
import secrets
import signal
import threading
import time
from dataclasses import dataclass
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Any, cast

from lldp_runner.classify import Classifier
from lldp_runner.config import AppConfig
from lldp_runner.identity import (
    ResolvedIdentity,
    resolve_discovered_name,
    resolve_seed,
    resolve_seed_input,
)
from lldp_runner.logging_setup import start_log_listener
from lldp_runner.models import (
    Candidate,
    DeviceResult,
    DeviceTask,
    NeighborObservation,
    SeedInput,
    TargetAttempt,
)
from lldp_runner.outputs import OUTPUT_NAMES, finalize_to_persistent, write_outputs
from lldp_runner.policy import PolicyEngine
from lldp_runner.run_manifest import (
    RUN_JSON_NAME,
    InvocationProvenance,
    begin_run_manifest,
    publish_run_manifest,
    update_run_manifest,
)
from lldp_runner.runtime import (
    RunPaths,
    canonical_operator_path,
    clean_completed_scratch,
    ensure_run_directories,
    publish_latest_symlink,
)
from lldp_runner.scoreboard import ScoreboardSnapshot, archive_scoreboard, write_scoreboard
from lldp_runner.seed_credentials import (
    SeedCredentialLoad,
    SeedCredentialRecord,
    normalize_seed_key,
)
from lldp_runner.snmp import preflight_snmp_backend, snmp_backend_selection
from lldp_runner.state import StateStore
from lldp_runner.timeutil import human_now, iso_now
from lldp_runner.worker import worker_main

LOG = logging.getLogger(__name__)

SEED_RESOLUTION_PROGRESS_SECONDS = 30.0


def _operator_duration(seconds: float) -> str:
    """Return a compact operator-facing elapsed duration."""

    total = max(0, round(seconds))
    minutes, remaining = divmod(total, 60)
    if minutes:
        return f"{minutes}m {remaining:02d}s"
    return f"{remaining}s"


class _SeedResolutionProgress:
    """Emit low-noise progress while synchronous seed DNS resolution runs.

    Resolver calls are intentionally synchronous in coordinator initialization.
    A lightweight timer thread lets the console reassure operators every 30
    seconds even if the main thread is blocked inside one slow resolver call.
    It never touches SQLite; the main thread only publishes simple counters.
    """

    def __init__(self, *, total: int, raw: int, started: float) -> None:
        self.total = total
        self.raw = raw
        self.started = started
        self.processed = 0
        self.dns_resolved = 0
        self.dns_skipped = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="seed-resolution-progress",
            daemon=True,
        )

    def start(self) -> None:
        """Start the background heartbeat timer."""

        self._thread.start()

    def update(self, dns_action: str) -> None:
        """Record one completed input identity and its resolver action."""

        with self._lock:
            self.processed += 1
            if dns_action == "skipped":
                self.dns_skipped += 1
            else:
                self.dns_resolved += 1

    def stop(self) -> None:
        """Stop the heartbeat thread without delaying initialization."""

        self._stop.set()
        self._thread.join(timeout=1.0)

    def snapshot(self) -> tuple[int, int, int]:
        """Return processed, resolver-used, resolver-skipped counters."""

        with self._lock:
            return self.processed, self.dns_resolved, self.dns_skipped

    def _run(self) -> None:
        """Publish console and activity-only progress at the fixed cadence."""

        while not self._stop.wait(SEED_RESOLUTION_PROGRESS_SECONDS):
            processed, dns_resolved, dns_skipped = self.snapshot()
            elapsed = time.monotonic() - self.started
            LOG.info(
                "Seed resolution in progress: %d/%d input identities processed (%s)",
                processed,
                self.total,
                _operator_duration(elapsed),
            )
            LOG.info(
                "seed resolution progress: processed=%d total=%d raw=%d "
                "dns_resolved=%d dns_skipped=%d elapsed=%.1fs",
                processed,
                self.total,
                self.raw,
                dns_resolved,
                dns_skipped,
                elapsed,
                extra={"activity_only": True},
            )


@dataclass(slots=True)
class DiscoveryOutcome:
    """Terminal information returned to the CLI after one run invocation.

    ``started_timestamp`` and ``ended_timestamp`` describe this invocation, not
    the lifetime of a resumable run ID. That keeps the displayed duration equal to
    actual execution time even when an operator resumes a run hours or days later.
    """

    run_id: str
    status: str
    started_timestamp: str
    ended_timestamp: str
    duration_seconds: int
    output_directory: Path | None
    state_path: Path
    activity_log: Path | None


@dataclass(slots=True)
class _SeedCredentialBinding:
    """Ephemeral ordered credentials attached to one explicit seed host."""

    strategy: str
    records: list[SeedCredentialRecord]
    source_keys: list[str]


class Coordinator:
    """Own discovery state, scheduling, workers, and run-level output lifecycle.

    The coordinator is the only process that mutates authoritative topology state.
    Workers receive immutable device batches and return observations through queues.
    Seed-only runs may use a smaller runtime execution plan than the configured
    worker/batch ceilings when the complete query workload is known up front.
    """

    def __init__(
        self,
        config: AppConfig,
        paths: RunPaths,
        *,
        resume: bool,
        invocation_provenance: InvocationProvenance | None = None,
        seed_credential_load: SeedCredentialLoad | None = None,
    ) -> None:
        """Create the single state-owning coordinator for one CLI invocation.

        Args:
            config: Fully assembled and validated runtime configuration.
            paths: Scratch/state/output paths selected for the logical run.
            resume: Whether this invocation is resuming an existing run state.
            invocation_provenance: Sanitized launch provenance recorded for CLI runs.
                Focused tests/embedders may omit it.
            seed_credential_load: Parsed per-seed credential overlay. Secrets remain
                process-local and are never written to coordinator state.

        Results:
            Opens state, prepares policy helpers, multiprocessing primitives, and
            logging resources. Call ``close`` if setup fails before ``run``.
        """

        self.config = config
        self.paths = paths
        self.resume = resume
        self.seed_credential_load = seed_credential_load or SeedCredentialLoad()
        self.seed_credential_bindings: dict[int, _SeedCredentialBinding] = {}
        ensure_run_directories(paths)
        self.state = StateStore(paths.state_path)
        try:
            self.snmp_backend = snmp_backend_selection(config)
            self._bind_snmp_backend_to_run()
            # Direct seed credentials exist only in memory, so the coordinator
            # supplies their non-secret protocol metadata to the local backend
            # capability check before creating a manifest or starting workers.
            direct_credentials = tuple(
                record.direct_credential
                for record in self.seed_credential_load.records
                if record.direct_credential is not None
            )
            self.snmp_preflight_protocols = preflight_snmp_backend(
                config,
                direct_credentials=direct_credentials,
            )
        except Exception:
            # Backend mismatch and local capability failures are pre-discovery,
            # pre-manifest initialization errors. Close SQLite immediately so
            # the caller can safely correct the environment and retry.
            self.state.close()
            raise
        self.policy = PolicyEngine(config)
        self.classifier = Classifier(config)
        self.pause_requested = False
        self.limit_reached = False
        self.limit_reason: str | None = None
        # ``max_devices='auto'`` is a scheduling mode, not merely a numeric limit.
        # It is resolved only after seed identity de-duplication in initialize().
        self.seed_only = isinstance(config.discovery.max_devices, str) and (
            config.discovery.max_devices.lower() == "auto"
        )
        self.effective_max_devices: int | None = None
        # Keep configured scheduler ceilings immutable and derive separate runtime
        # values. This lets scoreboards/logs explain why a seed-only run may spawn
        # fewer processes or claim smaller batches without changing site policy.
        self.configured_workers = int(config.discovery.workers)
        self.effective_workers = self.configured_workers
        self.configured_batch_size = int(config.discovery.batch_size)
        self.effective_batch_size = self.configured_batch_size
        self.execution_plan_ready_seeds: int | None = None
        self.execution_plan_per_worker_capacity = min(
            self.configured_batch_size,
            int(config.snmp.max_outstanding_devices_per_worker),
        )
        # Track this execution attempt separately from the persisted logical run
        # start. A resumed run keeps its original state metadata, while the CLI's
        # Runtime line reports how long the current invocation actually executed.
        self.invocation_started_iso = iso_now()
        self.invocation_started_text = human_now()
        self.started_monotonic = time.monotonic()
        self.started_text = self.state.get_meta("started") or self.invocation_started_iso
        self.run_manifest_path = self.paths.run_dir / "run.json.draft"
        self.run_manifest_sequence: int | None = None
        if invocation_provenance is not None:
            try:
                self.run_manifest_sequence = begin_run_manifest(
                    self.run_manifest_path,
                    run_id=self.paths.run_id,
                    started=self.started_text,
                    status="RUNNING",
                    invocation=invocation_provenance,
                    indent=self.config.output.pretty_json_indent,
                    resuming_existing=self.resume,
                )
            except Exception:
                self.state.close()
                raise
        self.ctx = mp.get_context("spawn")
        self.pause_event = self.ctx.Event()
        self.result_queue: mp.Queue = self.ctx.Queue()  # type: ignore[type-arg]
        self.log_queue: mp.Queue = self.ctx.Queue()  # type: ignore[type-arg]
        self.work_queues: list[mp.Queue] = []  # type: ignore[type-arg]
        self.workers: list[BaseProcess] = []
        self.worker_status: dict[int, dict[str, Any]] = {}
        self.batch_hosts: dict[str, list[int]] = {}
        # A host task can contain several credential attempts for one or more
        # management addresses. Reserve every normalized target while its batch is
        # in flight so two workers never poll the same target concurrently merely
        # because recursive discovery created two compatibility projections.
        self.batch_target_keys: dict[str, frozenset[str]] = {}
        self.target_waiting_hosts: dict[int, frozenset[str]] = {}
        self.batch_counter = 0
        self.log_listener = start_log_listener(
            self.log_queue,
            paths.activity_log,
            config.logging.level,
            console=config.logging.console,
        )
        self._old_signals: dict[int, Any] = {}
        self._closed = False
        LOG.info(
            "SNMP backend selected: %s %s",
            self.snmp_backend.name,
            self.snmp_backend.version,
        )
        LOG.info(
            "snmp backend selected: name=%s version=%s fixed_for_run=true",
            self.snmp_backend.name,
            self.snmp_backend.version,
            extra={"activity_only": True},
        )

    def _bind_snmp_backend_to_run(self) -> None:
        """Persist and validate the backend identity before any discovery work.

        A real resume is identifiable by its existing ``run_id`` metadata. Such
        a run must already carry 0.36 backend metadata; guessing a backend for an
        older checkpoint could silently mix evidence and is therefore rejected.
        Empty-state test/embedding resumes are treated as a new binding because
        they have no logical run identity yet.
        """

        persisted_name = self.state.get_meta("snmp_backend")
        persisted_run_id = self.state.get_meta("run_id")
        if self.resume and persisted_run_id is not None and persisted_name is None:
            raise ValueError(
                "cannot resume run without persisted SNMP backend metadata; "
                "start a new current-version run"
            )
        if persisted_name is not None and persisted_name != self.snmp_backend.name:
            raise ValueError(
                "cannot resume with a different SNMP backend: "
                f"run uses {persisted_name!r}, requested "
                f"{self.snmp_backend.name!r}"
            )
        self.state.set_meta("snmp_backend", self.snmp_backend.name)
        self.state.set_meta("snmp_backend_version", self.snmp_backend.version)

    def close(self) -> None:
        """Release coordinator-owned state/logging resources exactly once.

        Normal discovery closes these resources from ``run()``. Initialization can
        also fail before ``run()`` starts (for example, when seed count exceeds a
        finite max_devices), so the CLI uses this idempotent helper on that path.

        Multiprocessing queues own background feeder threads in their creating
        process.  Closing the database and log listener alone can leave Python's
        interpreter waiting for one of those threads after an otherwise completed
        run.  At this boundary every worker and queue consumer has already stopped,
        so pending queue buffers are no longer operational state and must not delay
        process exit.
        """

        if self._closed:
            return
        self._closed = True
        self.state.close()
        self.log_listener.stop()
        for queue_object in [
            *getattr(self, "work_queues", []),
            getattr(self, "result_queue", None),
            getattr(self, "log_queue", None),
        ]:
            if queue_object is None:
                continue
            close = getattr(queue_object, "close", None)
            if callable(close):
                close()
            # Queue data has no meaning after all workers/listeners have stopped.
            # Avoid interpreter-shutdown waits if a feeder thread still has an
            # unconsumed sentinel or diagnostic record in its local buffer.
            cancel_join_thread = getattr(queue_object, "cancel_join_thread", None)
            if callable(cancel_join_thread):
                cancel_join_thread()

    def initialize(
        self,
        seeds: list[SeedInput],
        *,
        raw_seed_count: int | None = None,
    ) -> None:
        """Initialize seed state and resolve the runtime managed-device guardrail.

        Numeric ``max_devices`` values are validated *after* seed resolution and
        identity de-duplication but *before* workers start.  This gives operators a
        deterministic fail-fast error when explicit seeds already exceed a finite
        recursive-discovery guardrail.

        ``max_devices='auto'`` means seed-only discovery: its effective numeric
        value is the number of unique managed seed identities in state, while the
        scheduler independently prevents non-seed neighbors from becoming work.
        That separation is important because discovered managed neighbors still
        count as hosts and must remain visible in topology/output data.
        """

        raw_count = len(seeds) if raw_seed_count is None else raw_seed_count
        self._announce_initialization_start(seeds, raw_count=raw_count)
        self.state.set_meta("run_id", self.paths.run_id)
        self.state.set_meta("started", self.started_text)
        self.state.set_meta("status", "RUNNING")
        # A resumed LIMIT_REACHED run may now have larger limits. Clear the prior
        # stop/completion markers so later snapshots describe the current attempt.
        # seed_shuffle_key is intentionally retained for reproducible random order.
        self.state.delete_meta("completed", "completion_reason", "limit_reason")
        self.paths.scratch_dir.joinpath(self.config.resume.pause_indicator).unlink(missing_ok=True)
        if self.resume:
            reset = self.state.reset_active_claims()
            self.state.normalize_cohorts(cast(int, self.config.discovery.workers))
            self.state.ensure_missing_seed_ranks()
            first_rank = self.state.next_seed_rank()
            self._resolve_seed_inputs(
                seeds,
                raw_count=raw_count,
                first_rank=first_rank,
            )
            self._bind_seed_credentials()
            self._apply_seed_order()
            self._resolve_seed_device_limit()
            self._resolve_seed_only_execution_plan()
            LOG.info(
                "resuming run %s; reset %d active claims; added %d seeds",
                self.paths.run_id,
                reset,
                len(seeds),
            )
            return
        if not seeds:
            raise ValueError("at least one seed is required for a new run")
        self._resolve_seed_inputs(seeds, raw_count=raw_count, first_rank=0)
        self._bind_seed_credentials()
        self._apply_seed_order()
        self._resolve_seed_device_limit()
        self._resolve_seed_only_execution_plan()

    def _run_mode_text(self) -> str:
        """Return the concise operator-facing discovery mode description."""

        if self.seed_only:
            return "seed-only discovery (max_devices=auto)"
        return "recursive discovery"

    def _announce_initialization_start(
        self,
        seeds: list[SeedInput],
        *,
        raw_count: int,
    ) -> None:
        """Announce run/config/seed loading before potentially slow DNS work."""

        action = "resuming" if self.resume else "started"
        LOG.info(
            "LLDP-Runner run %s %s: %s",
            self.paths.run_id,
            action,
            self._run_mode_text(),
        )
        LOG.info(
            "run initialization: run_id=%s action=%s mode=%s",
            self.paths.run_id,
            action,
            "seed_only" if self.seed_only else "recursive",
            extra={"activity_only": True},
        )

        primary = str(self.config.config_path) if self.config.config_path else "built-in defaults"
        LOG.info("Configuration loaded: %s", primary)
        LOG.info(
            "configuration loaded: primary=%s sources=%d",
            primary,
            len(self.config.config_files),
            extra={"activity_only": True},
        )
        if self.config.config_files:
            LOG.info(
                "configuration sources: %s",
                ";".join(str(path) for path in self.config.config_files),
                extra={"activity_only": True},
            )

        LOG.info("Seeds loaded: %d raw seeds", raw_count)
        LOG.info(
            "seed input loaded: raw=%d input_identities=%d",
            raw_count,
            len(seeds),
            extra={"activity_only": True},
        )

    def _resolve_seed_inputs(
        self,
        seeds: list[SeedInput],
        *,
        raw_count: int,
        first_rank: int,
    ) -> None:
        """Resolve all seed identities with progress and final count reporting."""

        started = time.monotonic()
        dns_mode = self.config.discovery.seed_dns_mode
        if dns_mode == "skip-addressed":
            LOG.info(
                "Seed resolution started: resolving identities; DNS may be skipped "
                "for eligible addressed seeds"
            )
        else:
            LOG.info(
                "Seed resolution started: resolving names, addresses, and duplicate identities"
            )
        LOG.info(
            "seed resolution started: raw=%d input_identities=%d dns_mode=%s",
            raw_count,
            len(seeds),
            dns_mode,
            extra={"activity_only": True},
        )

        progress = _SeedResolutionProgress(
            total=len(seeds),
            raw=raw_count,
            started=started,
        )
        progress.start()
        try:
            for offset, seed in enumerate(seeds):
                dns_action = self._add_seed(seed, seed_rank=first_rank + offset)
                progress.update(dns_action)
        finally:
            progress.stop()

        elapsed = time.monotonic() - started
        processed, dns_resolved, dns_skipped = progress.snapshot()
        counts = self.state.seed_resolution_counts()
        self.seed_resolution_summary = counts
        LOG.info(
            "Seed resolution complete: %d raw seeds -> %d unique seeds; "
            "%d queryable, %d unresolved (%s)",
            raw_count,
            counts["unique"],
            counts["queryable"],
            counts["unresolved"],
            _operator_duration(elapsed),
        )
        LOG.info(
            "seed resolution completed: raw=%d input_identities=%d processed=%d "
            "unique=%d queryable=%d unresolved=%d no_query=%d out_of_scope=%d "
            "complete=%d failed=%d dns_resolved=%d dns_skipped=%d elapsed=%.1fs",
            raw_count,
            len(seeds),
            processed,
            counts["unique"],
            counts["queryable"],
            counts["unresolved"],
            counts["no_query"],
            counts["out_of_scope"],
            counts["complete"],
            counts["failed"],
            dns_resolved,
            dns_skipped,
            elapsed,
            extra={"activity_only": True},
        )

    def log_initialization_failure(self, exc: BaseException) -> None:
        """Emit concise console plus detailed activity-log initialization failure."""

        LOG.error("Run initialization failed: %s", exc)
        LOG.error(
            "run initialization failed: run_id=%s mode=%s error_type=%s reason=%s",
            self.paths.run_id,
            "seed_only" if self.seed_only else "recursive",
            exc.__class__.__name__,
            exc,
            extra={"activity_only": True},
        )

    def _bind_seed_credentials(self) -> None:
        """Match credential overlay records to the already-established seed set.

        Credential files are intentionally not seed sources. Matching uses only
        identities that the normal seed path has already placed in state. Unmatched
        records are activity-log warnings, never stderr warnings, and never trigger
        DNS resolution or network scheduling on their own.
        """

        seed_credential_load = getattr(self, "seed_credential_load", SeedCredentialLoad())
        if not hasattr(self, "seed_credential_bindings"):
            self.seed_credential_bindings = {}
        for message in seed_credential_load.warnings:
            LOG.warning(message, extra={"activity_only": True})

        alias_to_hosts: dict[str, set[int]] = {}
        for row in self.state.seed_hosts():
            host_id = int(row["id"])
            names, addresses, _chassis = self.state.aliases_for_host(host_id)
            values = [str(row["preferred_name"]), *names, *addresses]
            for value in values:
                if not value.strip():
                    continue
                key = normalize_seed_key(value)
                alias_to_hosts.setdefault(key, set()).add(host_id)

        grouped: dict[int, list[SeedCredentialRecord]] = {}
        matched = 0
        unmatched = 0
        for record in seed_credential_load.records:
            key = normalize_seed_key(record.seed)
            host_ids = alias_to_hosts.get(key, set())
            if not host_ids:
                unmatched += 1
                location = (
                    f"{record.source}:{record.source_line}"
                    if record.source_line is not None
                    else str(record.source)
                )
                LOG.warning(
                    "seed credential record unmatched: seed=%r source=%s",
                    record.seed,
                    location,
                    extra={"activity_only": True},
                )
                continue
            if len(host_ids) != 1:
                raise ValueError(
                    f"seed credential {record.seed!r} matches multiple consolidated seeds"
                )
            host_id = next(iter(host_ids))
            grouped.setdefault(host_id, []).append(record)
            matched += 1

        bindings: dict[int, _SeedCredentialBinding] = {}
        for host_id, records in grouped.items():
            records.sort(key=lambda item: item.order)
            source_keys = list(dict.fromkeys(normalize_seed_key(item.seed) for item in records))
            if len(source_keys) > 1 and any(item.strategy == "exclusive" for item in records):
                row = self.state.host_row(host_id)
                raise ValueError(
                    "multiple explicit seed aliases converged on "
                    f"{row['preferred_name']!r} with an exclusive seed credential policy"
                )
            strategies = {item.strategy for item in records}
            if len(strategies) > 1:
                row = self.state.host_row(host_id)
                raise ValueError(
                    f"seed credential strategies conflict after identity merge for "
                    f"{row['preferred_name']!r}"
                )
            strategy = next(iter(strategies))
            binding = _SeedCredentialBinding(strategy, records, source_keys)
            bindings[host_id] = binding

        existing = self.state.seed_credential_requirements()
        for host_id, required_strategy in existing.items():
            binding = bindings.get(host_id)
            if binding is None:
                row = self.state.host_row(host_id)
                raise ValueError(
                    "resumed run requires seed credential input for "
                    f"{row['preferred_name']!r}; provide the seed credential file again"
                )
            if binding.strategy != required_strategy:
                row = self.state.host_row(host_id)
                raise ValueError(
                    f"resumed seed {row['preferred_name']!r} requires credential strategy "
                    f"{required_strategy!r}, got {binding.strategy!r}"
                )

        for host_id, binding in bindings.items():
            self.state.set_seed_credential_requirement(
                host_id,
                binding.strategy,
                binding.source_keys,
                [record.credential_label or "" for record in binding.records],
            )
        self.seed_credential_bindings = bindings

        if seed_credential_load.files:
            LOG.info(
                "seed credential bindings: %d matched, %d unmatched",
                matched,
                unmatched,
                extra={"activity_only": True},
            )

    def _apply_seed_order(self) -> None:
        """Persist configured order for the de-duplicated seed identities.

        ``input`` retains the earliest seed rank through identity merges. ``sorted``
        compares the resolved preferred presentation name case-insensitively.
        ``random`` sorts by a BLAKE2 digest of shuffle key + identity, which makes
        explicit keys reproducible without depending on Python PRNG internals. An
        omitted key is generated once and stored so pause/resume keeps the order.
        """

        rows = list(self.state.seed_order_rows())
        mode = self.config.discovery.seed_order
        if mode == "input":
            rows.sort(
                key=lambda row: (
                    int(row["seed_rank"]) if row["seed_rank"] is not None else 2**63,
                    int(row["id"]),
                )
            )
            self.state.set_meta("seed_order", "input")
            self.state.apply_seed_order([int(row["id"]) for row in rows])
            return

        if mode == "sorted":
            rows.sort(
                key=lambda row: (
                    str(row["preferred_name"]).casefold(),
                    str(row["preferred_name"]),
                    int(row["id"]),
                )
            )
            self.state.set_meta("seed_order", "sorted")
            self.state.apply_seed_order([int(row["id"]) for row in rows])
            return

        configured_key = str(self.config.discovery.shuffle_key).strip()
        shuffle_key = configured_key
        if not shuffle_key and self.resume:
            shuffle_key = self.state.get_meta("seed_shuffle_key", "") or ""
        if not shuffle_key:
            shuffle_key = secrets.token_hex(16)
        self.state.set_meta("seed_order", "random")
        self.state.set_meta("seed_shuffle_key", shuffle_key)

        def random_key(row: Any) -> tuple[bytes, str, int]:
            """Return a reproducible digest/name/id ordering key for one seed."""

            identity = str(row["preferred_name"]).casefold()
            digest = hashlib.blake2b(
                f"{shuffle_key}\0{identity}".encode(),
                digest_size=16,
            ).digest()
            return digest, identity, int(row["id"])

        rows.sort(key=random_key)
        self.state.apply_seed_order([int(row["id"]) for row in rows])
        LOG.info(
            "seed_order=random: ordered %d unique seeds with shuffle_key=%s",
            len(rows),
            shuffle_key,
        )

    def _resolve_seed_device_limit(self) -> None:
        """Resolve max-device semantics after unique seed identities are known.

        * positive integer: finite recursive guardrail; too many seeds is an
          operator/configuration error and discovery never starts;
        * zero: unlimited recursive managed-device discovery;
        * ``auto``: query all unique seeds, retain their neighbors, but do not
          recursively query non-seed neighbors.
        """

        seed_devices = self.state.seed_device_count()
        configured = self.config.discovery.max_devices
        if self.seed_only:
            self.effective_max_devices = seed_devices
            suppressed = self.state.suppress_nonseed_pending_queries()
            self.state.set_meta("discovery_mode", "seed_only")
            self.state.set_meta("effective_max_devices", str(seed_devices))
            LOG.info(
                "max_devices=auto: seed-only discovery enabled for %d unique seed devices; "
                "suppressed %d pending non-seed queries",
                seed_devices,
                suppressed,
            )
            return

        limit = int(configured)
        self.effective_max_devices = None if limit == 0 else limit
        self.state.set_meta("discovery_mode", "recursive")
        self.state.set_meta("effective_max_devices", "unlimited" if limit == 0 else str(limit))
        if limit > 0 and seed_devices > limit:
            message = (
                f"{seed_devices} unique managed seed devices were supplied, but "
                f"discovery.max_devices is {limit}. No discovery queries were started. "
                f"Increase --max-devices to at least {seed_devices}, set "
                "--max-devices 0 for unlimited recursive discovery, or use "
                "--max-devices auto to query only the supplied seeds without recursion."
            )
            # Do not leave a deliberately rejected initialization looking resumable.
            # DNS/identity processing may already have created state, but workers have
            # not started and no ICMP/SNMP discovery query has been dispatched.
            self.state.set_meta("status", "SEED_LIMIT_EXCEEDED")
            self.state.add_error(
                None,
                "seed_validation",
                "seed_count_exceeds_max_devices",
                message,
                recoverable=False,
                final_device_status="SEED_LIMIT_EXCEEDED",
            )
            raise ValueError(message)

    def _resolve_seed_only_execution_plan(self) -> None:
        """Right-size process and batch ceilings for a known seed-only workload.

        ``max_devices="auto"`` guarantees that READY seeds are the complete SNMP
        query population: learned non-seed devices are retained as topology data but
        never scheduled. A worker processes one claimed batch asynchronously, so the
        useful per-worker first-wave capacity is the smaller of ``batch_size`` and
        ``snmp.max_outstanding_devices_per_worker``. The plan therefore launches the
        minimum configured number of workers needed to cover that first wave and
        balances a small seed population across those workers by reducing batch size.

        Results:
            Updates ``effective_workers`` and ``effective_batch_size`` for this run,
            persists configured/effective values in run metadata, and emits one INFO
            record suitable for both console and activity.log handlers. Recursive
            discovery retains the configured scheduler values unchanged.
        """

        # Reinitialize from immutable configuration so repeated calls (including a
        # resume initialization) never compound a prior runtime reduction.
        self.configured_workers = int(self.config.discovery.workers)
        self.effective_workers = self.configured_workers
        self.configured_batch_size = int(self.config.discovery.batch_size)
        self.effective_batch_size = self.configured_batch_size
        self.execution_plan_ready_seeds = None
        self.execution_plan_per_worker_capacity = min(
            self.configured_batch_size,
            int(self.config.snmp.max_outstanding_devices_per_worker),
        )

        if not self.seed_only:
            return

        # _resolve_seed_device_limit() has already suppressed pending non-seed work,
        # so READY is exactly the currently queryable seed workload, including on
        # resume after active claims have been reset.
        ready_seeds = self.state.ready_count()
        capacity = self.execution_plan_per_worker_capacity
        needed_workers = max(1, math.ceil(ready_seeds / capacity))
        self.effective_workers = min(self.configured_workers, needed_workers)

        balanced_batch = max(1, math.ceil(ready_seeds / self.effective_workers))
        self.effective_batch_size = min(
            self.configured_batch_size,
            capacity,
            balanced_batch,
        )
        self.execution_plan_ready_seeds = ready_seeds

        metadata = {
            "configured_workers": self.configured_workers,
            "effective_workers": self.effective_workers,
            "configured_batch_size": self.configured_batch_size,
            "effective_batch_size": self.effective_batch_size,
            "execution_plan_ready_seeds": ready_seeds,
            "execution_plan_per_worker_capacity": capacity,
        }
        for key, value in metadata.items():
            self.state.set_meta(key, str(value))

        LOG.info(
            "seed-only execution plan: %d READY seeds; workers %d -> %d; "
            "batch_size %d -> %d; max_outstanding_devices_per_worker=%d",
            ready_seeds,
            self.configured_workers,
            self.effective_workers,
            self.configured_batch_size,
            self.effective_batch_size,
            self.config.snmp.max_outstanding_devices_per_worker,
        )

    def _execution_plan_for_scoreboard(self) -> dict[str, Any]:
        """Return configured/effective scheduler values for scoreboard rendering.

        Returns:
            A JSON-serializable mapping containing discovery mode, configured and
            effective worker/batch limits, per-worker asynchronous capacity, and the
            READY seed count when a seed-only plan was calculated. Defensive defaults
            support focused tests/embedders that construct ``Coordinator`` manually.
        """

        configured_workers = int(getattr(self, "configured_workers", self.config.discovery.workers))
        configured_batch = int(
            getattr(self, "configured_batch_size", self.config.discovery.batch_size)
        )
        capacity = int(
            getattr(
                self,
                "execution_plan_per_worker_capacity",
                min(
                    configured_batch,
                    int(self.config.snmp.max_outstanding_devices_per_worker),
                ),
            )
        )
        payload: dict[str, Any] = {
            "mode": "seed_only" if self.seed_only else "recursive",
            "configured_workers": configured_workers,
            "effective_workers": int(getattr(self, "effective_workers", configured_workers)),
            "configured_batch_size": configured_batch,
            "effective_batch_size": int(getattr(self, "effective_batch_size", configured_batch)),
            "max_outstanding_devices_per_worker": int(
                self.config.snmp.max_outstanding_devices_per_worker
            ),
            "per_worker_first_wave_capacity": capacity,
        }
        ready_seeds = getattr(self, "execution_plan_ready_seeds", None)
        if ready_seeds is not None:
            payload["ready_seeds"] = int(ready_seeds)
        return payload

    def _add_seed(self, seed: SeedInput, *, seed_rank: int | None = None) -> str:
        """Resolve one seed while preserving address hints from reusable seeds.csv.

        A previous run may know a working management address even when DNS is
        unavailable during the current run.  Those CSV address hints are merged
        with fresh resolver results before policy checks and scheduling.
        """

        if seed_rank is None:
            # Direct/internal callers that are not running the initialize() loop still
            # receive a deterministic append rank. initialize() supplies explicit
            # ranks so input ordering remains tied to the consolidated seed stream.
            seed_rank = self.state.next_seed_rank()

        try:
            resolved, dns_action = resolve_seed_input(
                seed,
                self.config.discovery.dns_suffixes,
                mode=self.config.discovery.seed_dns_mode,
            )
        except Exception as exc:
            LOG.error("seed %r could not be parsed: %s", seed.seed, exc)
            self.state.add_error(
                None,
                "seed",
                "invalid_seed",
                f"{seed.seed}: {exc}",
                recoverable=False,
            )
            return dns_action

        candidate = Candidate(
            names=resolved.names,
            addresses=resolved.addresses,
            category="managed_device",
            reason=["initial seed list"],
        )
        candidate.tags = self.classifier.tags_for_candidate(candidate)
        host_id = self.state.upsert_candidate(
            candidate,
            preferred_name=resolved.preferred_name,
            is_seed=True,
            seed_rank=seed_rank,
        )
        for error in seed.parse_errors:
            self.state.add_error(
                host_id,
                "seed_inventory",
                "invalid_seed_metadata",
                f"{seed.source or 'seed input'}: {error}",
            )
        for error in resolved.errors:
            self.state.add_error(host_id, "dns", "resolution", error)
        self._schedule_if_queryable(host_id)
        return dns_action

    def _cohort(self, identity: str) -> int:
        """Map a stable host identity to one configured worker cohort.

        Args:
            identity: Preferred logical identity used for deterministic hashing.

        Returns:
            Zero-based worker cohort number.
        """

        digest = hashlib.blake2b(identity.casefold().encode(), digest_size=8).digest()
        return int.from_bytes(digest, "big") % cast(int, self.config.discovery.workers)

    def _ordered_addresses(self, addresses: list[str]) -> list[str]:
        """De-duplicate and sort management addresses by configured family order.

        Args:
            addresses: Valid textual IP addresses associated with one host.

        Returns:
            Addresses ordered by ``discovery.address_preference`` then numerically.
        """

        preference = {
            name: index for index, name in enumerate(self.config.discovery.address_preference)
        }

        def key(value: str) -> tuple[int, int]:
            """Return configured family priority plus numeric IP sort value."""

            ip = ipaddress.ip_address(value)
            family = "ipv4" if ip.version == 4 else "ipv6"
            return preference.get(family, 99), int(ip)

        return sorted(dict.fromkeys(addresses), key=key)

    def _build_task(self, host_id: int) -> DeviceTask | None:
        """Build a policy-filtered worker task for one managed host.

        Args:
            host_id: Internal state identifier of the candidate host.

        Returns:
            A ``DeviceTask`` when an address is queryable, otherwise ``None`` after
            recording the applicable NO_QUERY/OUT_OF_SCOPE state.
        """

        row = self.state.host_row(host_id)
        if row["classification"] != "managed_device":
            self.state.set_host_no_query(host_id)
            return None
        names, addresses, _chassis = self.state.aliases_for_host(host_id)
        recovery_addresses = (
            self.state.pending_late_recovery_addresses(host_id)
            if int(row["late_recovery_used"] or 0) > 0
            else []
        )
        route_addresses = recovery_addresses or addresses
        attempts: list[TargetAttempt] = []
        boundary_seen = False
        denied_seen = False
        for address in self._ordered_addresses(route_addresses):
            boundary = self.policy.in_boundary(address)
            if not boundary.allowed:
                continue
            boundary_seen = True
            query = self.policy.query_policy(names, address)
            if not query.allowed:
                denied_seen = True
                continue
            binding = self.seed_credential_bindings.get(host_id)
            if binding is not None:
                for record in binding.records:
                    if record.direct_credential is not None:
                        attempts.append(
                            TargetAttempt(
                                address=address,
                                direct_credential=record.direct_credential,
                                credential_source="seed-direct",
                                credential_label=record.credential_label,
                            )
                        )
                    else:
                        attempts.append(
                            TargetAttempt(
                                address=address,
                                credential_profile=record.credential_profile,
                                credential_source="seed-profile",
                                credential_label=record.credential_label,
                            )
                        )
                if binding.strategy == "exclusive":
                    continue
            cred = self.policy.credential_profile(names, address)
            attempts.append(
                TargetAttempt(
                    address=address,
                    credential_profile=cred.profile.name,
                    credential_source="policy-profile",
                )
            )
        if not attempts:
            if recovery_addresses:
                self.state.set_host_no_query(host_id, "FAILED")
                self.state.add_error(
                    host_id,
                    "late_address_recovery",
                    "route_unavailable",
                    "late-recovery address no longer has a permitted credential route",
                    final_device_status="FAILED",
                )
            elif not addresses:
                self.state.set_host_no_query(host_id)
                self.state.add_error(
                    host_id,
                    "target_resolution",
                    "no_address",
                    "managed device has no resolvable or discovered management address",
                )
            elif not boundary_seen:
                self.state.set_host_no_query(host_id, "OUT_OF_SCOPE")
            elif denied_seen:
                self.state.set_host_no_query(host_id, "NO_QUERY")
            else:
                self.state.set_host_no_query(host_id, "NO_QUERY")
            return None
        return DeviceTask(
            host_id=host_id,
            preferred_name=str(row["preferred_name"]),
            names=names,
            addresses=addresses,
            attempts=attempts,
            cohort=int(row["cohort"]),
        )

    def _schedule_if_queryable(
        self,
        host_id: int,
        *,
        evidence_source: str | None = None,
    ) -> None:
        """Admit a managed host, including one bounded late-address recovery.

        Ordinary admission applies to newly discovered or previously policy-held
        hosts.  A ``FAILED`` host remains terminal unless a later protocol
        observation supplies a direct, host-eligible, in-boundary, query-allowed
        address absent from durable route history.  StateStore atomically enforces
        the per-host allowance and records the scheduler decision for resume.
        """

        row = self.state.host_row(host_id)
        state_name = str(row["state"])
        if self.seed_only and not bool(row["is_seed"]):
            if state_name not in {
                "COMPLETE",
                "FAILED",
                "NO_QUERY",
                "OUT_OF_SCOPE",
            }:
                self.state.set_host_no_query(host_id, "NO_QUERY")
            return

        if state_name == "FAILED":
            if evidence_source is None or row["classification"] != "managed_device":
                return
            allowance = self.config.discovery.late_address_recovery_attempts
            if allowance <= 0:
                return
            names, _all_addresses, _ = self.state.aliases_for_host(host_id)
            attempted = self.state.attempted_addresses(host_id)
            permitted_new: list[str] = []
            for address in self._ordered_addresses(self.state.identity_addresses_for_host(host_id)):
                if address in attempted:
                    continue
                if not self.policy.in_boundary(address).allowed:
                    continue
                if not self.policy.query_policy(names, address).allowed:
                    continue
                permitted_new.append(address)
            admitted = self.state.admit_late_address_recovery(
                host_id,
                new_addresses=permitted_new,
                evidence_source=evidence_source,
                allowance=allowance,
            )
            if admitted:
                LOG.info(
                    "late-address recovery admitted host_id=%d prior_state=FAILED "
                    "new_addresses=%s evidence_source=%s remaining=%d",
                    host_id,
                    ",".join(admitted),
                    evidence_source,
                    max(
                        0,
                        allowance - int(self.state.host_row(host_id)["late_recovery_used"] or 0),
                    ),
                    extra={"activity_only": True},
                )
            return

        if state_name in {
            "READY",
            "CLAIMED",
            "PINGING",
            "SNMP_BASIC",
            "SNMP_DETAIL",
            "NEIGHBOR_DISCOVERY",
            "COMPLETE",
        }:
            return
        if row["classification"] != "managed_device":
            self.state.set_host_no_query(host_id)
            return
        names, addresses, _ = self.state.aliases_for_host(host_id)
        if not addresses:
            self.state.set_host_no_query(host_id)
            self.state.add_error(
                host_id,
                "target_resolution",
                "no_address",
                "managed device has no resolvable or discovered management address",
            )
            return
        permitted = False
        in_scope = False
        for address in addresses:
            if self.policy.in_boundary(address).allowed:
                in_scope = True
                if self.policy.query_policy(names, address).allowed:
                    permitted = True
                    break
        if not in_scope:
            self.state.set_host_no_query(host_id, "OUT_OF_SCOPE")
            return
        if not permitted:
            self.state.set_host_no_query(host_id, "NO_QUERY")
            return
        self.state.set_host_ready(host_id, self._cohort(str(row["preferred_name"])))

    def _classify_and_enrich_neighbor(self, candidate: Candidate, remote_name: str | None) -> None:
        """Classify a neighbor, resolve provisional managed names, then classify again.

        DNS enrichment can reveal an FQDN or management address covered by an
        explicit ownership rule. The second classification therefore occurs before
        state insertion and scheduling.
        """
        decision = self.classifier.classify_candidate(candidate)
        candidate.category = decision.category
        candidate.reason = decision.reasons

        if (
            candidate.category == "managed_device"
            and remote_name
            and self.config.discovery.resolve_discovered_managed_names
        ):
            try:
                resolved = resolve_discovered_name(remote_name, self.config.discovery.dns_suffixes)
                candidate.names = list(dict.fromkeys([*candidate.names, *resolved.names]))
                candidate.addresses = list(
                    dict.fromkeys([*candidate.addresses, *resolved.addresses])
                )
                decision = self.classifier.classify_candidate(candidate)
                candidate.category = decision.category
                candidate.reason = decision.reasons
            except Exception as exc:
                LOG.debug("neighbor DNS resolution failed name=%s: %s", remote_name, exc)

    def _process_neighbor(self, source_host_id: int, obs: NeighborObservation) -> None:
        """Merge one CDP/LLDP observation into topology state and scheduling.

        Args:
            source_host_id: Internal ID of the device that reported the neighbor.
            obs: Normalized neighbor observation returned by a worker collector.

        Results:
            Classifies/enriches the remote host, upserts its edge/state, and schedules
            it when policy and recursion mode permit.
        """

        candidate = Candidate(
            names=[obs.remote_name] if obs.remote_name else [],
            identity_names=[obs.remote_name] if obs.remote_name else [],
            addresses=list(obs.remote_addresses),
            identity_addresses=list(obs.remote_addresses),
            category="unknown_device",
            source_host_id=source_host_id,
            protocol=obs.protocol,
            local_interface=obs.local_interface,
            local_interface_raw=obs.local_interface_raw,
            remote_interface=obs.remote_interface,
            remote_interface_raw=obs.remote_interface_raw,
            remote_description=obs.remote_description,
            remote_platform=obs.remote_platform,
            capabilities=list(obs.capabilities),
            chassis_id=obs.chassis_id,
            chassis_id_subtype=obs.chassis_id_subtype,
            chassis_id_subtype_id=obs.chassis_id_subtype_id,
            protocols=list(dict.fromkeys([obs.protocol, *obs.details.get("protocols", [])])),
            details=dict(obs.details),
        )
        # DNS is most useful for potential recursive targets. Preserve discovered FQDNs exactly,
        # then reclassify before state insertion/scheduling so enriched ownership evidence applies.
        self._classify_and_enrich_neighbor(candidate, obs.remote_name)
        decision_category = candidate.category
        decision_reasons = list(candidate.reason)

        candidate.tags = self.classifier.tags_for_candidate(candidate)

        synthetic = (
            f"edge:{source_host_id}:{obs.protocol}:{obs.local_interface or ''}:"
            f"{obs.remote_interface or ''}:{obs.chassis_id or ''}"
        )
        direct_names = candidate.identity_names or []
        preferred = next((x for x in direct_names if "." in x), None)
        if preferred is None:
            preferred = direct_names[0] if direct_names else None
        if preferred is None:
            preferred = next((x for x in candidate.names if "." in x), None)
        if preferred is None:
            preferred = candidate.names[0] if candidate.names else None
        if preferred is None and candidate.addresses:
            preferred = candidate.addresses[0]
        remote_host_id = self.state.upsert_candidate(
            candidate,
            preferred_name=preferred,
            synthetic_alias=synthetic,
        )
        self.state.add_neighbor(source_host_id, remote_host_id, obs)
        self.state.update_classification(remote_host_id, decision_category, decision_reasons)
        self._schedule_if_queryable(
            remote_host_id,
            evidence_source=f"{obs.protocol}:source_host={source_host_id}",
        )

    def _process_result(self, result: DeviceResult) -> None:
        """Persist one worker result and process neighbors from successful queries.

        Args:
            result: Completed, failed, or deferred result for a scheduled host.

        Results:
            Updates authoritative state and can add/schedule learned neighbors.
        """

        self.state.apply_device_result(result)
        if result.status != "success":
            return
        for obs in result.neighbors:
            self._process_neighbor(result.host_id, obs)

    def _start_workers(self) -> None:
        """Spawn effective worker processes and create their work queues.

        Results:
            Populates worker, queue, and initial worker-status bookkeeping.
        """

        for worker_id in range(
            int(getattr(self, "effective_workers", self.config.discovery.workers))
        ):
            work_queue = self.ctx.Queue()
            process = self.ctx.Process(
                target=worker_main,
                name=f"lldp-worker-{worker_id}",
                args=(
                    worker_id,
                    self.config,
                    work_queue,
                    self.result_queue,
                    self.log_queue,
                    self.pause_event,
                ),
            )
            process.start()
            self.work_queues.append(work_queue)
            self.workers.append(process)
            self.worker_status[worker_id] = {"status": "IDLE", "batch": "-", "size": 0}

    @staticmethod
    def _task_target_keys(task: DeviceTask) -> frozenset[str]:
        """Return normalized management targets that one worker task may poll.

        Credential fallbacks for one address are intentionally represented by one
        target key. A task already owns the ordered credential route, so allowing a
        second worker to query the same address at the same time provides no useful
        concurrency and can create duplicate complete projections.
        """

        keys: set[str] = set()
        for attempt in task.attempts:
            try:
                keys.add(ipaddress.ip_address(attempt.address).compressed.casefold())
            except ValueError:
                keys.add(str(attempt.address).strip().casefold())
        return frozenset(value for value in keys if value)

    def _inflight_target_keys(self) -> set[str]:
        """Return all targets currently owned by dispatched worker batches."""

        batches = getattr(self, "batch_target_keys", {})
        return {target for targets in batches.values() for target in targets}

    def _refresh_target_waiters(self) -> set[int]:
        """Return host IDs still blocked by an in-flight target reservation."""

        inflight = self._inflight_target_keys()
        waiters = getattr(self, "target_waiting_hosts", {})
        released = [
            host_id for host_id, targets in waiters.items() if not (set(targets) & inflight)
        ]
        for host_id in released:
            waiters.pop(host_id, None)
        self.target_waiting_hosts = waiters
        return set(waiters)

    def _release_batch_targets(self, batch_id: str) -> None:
        """Release target reservations after a worker batch terminates."""

        getattr(self, "batch_target_keys", {}).pop(batch_id, None)
        self._refresh_target_waiters()

    def _dispatch(self) -> None:
        """Claim READY hosts and send policy-valid batches to idle workers.

        Results:
            Mutates host claim state and worker/batch bookkeeping. No work is sent
            while a controlled pause or guardrail stop is active.
        """

        if self.pause_event.is_set():
            return
        if not hasattr(self, "batch_target_keys"):
            self.batch_target_keys = {}
        if not hasattr(self, "target_waiting_hosts"):
            self.target_waiting_hosts = {}
        blocked_host_ids = self._refresh_target_waiters()
        reserved_targets = self._inflight_target_keys()
        for worker_id, process in enumerate(self.workers):
            if not process.is_alive():
                continue
            if self.worker_status[worker_id]["status"] != "IDLE":
                continue
            ids = self.state.claim_batch(
                worker_id,
                int(
                    getattr(
                        self,
                        "effective_batch_size",
                        self.config.discovery.batch_size,
                    )
                ),
                self.config.resume.lease_seconds,
                allow_steal=self.config.discovery.work_stealing,
                exclude_host_ids=blocked_host_ids,
            )
            if not ids:
                continue
            tasks: list[DeviceTask] = []
            batch_targets: set[str] = set()
            for host_id in ids:
                task = self._build_task(host_id)
                if task is None:
                    continue
                target_keys = set(self._task_target_keys(task))
                if target_keys & reserved_targets:
                    # Keep the shadow READY and exclude it from later claims until
                    # the owning batch finishes. Pre-claim reconciliation can then
                    # absorb it safely if the completed logical identity agrees.
                    self.state.defer_host(host_id)
                    self.target_waiting_hosts[host_id] = frozenset(target_keys)
                    blocked_host_ids.add(host_id)
                    LOG.info(
                        "deferred duplicate in-flight query target: host_id=%d targets=%s",
                        host_id,
                        ",".join(sorted(target_keys)),
                        extra={"activity_only": True},
                    )
                    continue
                tasks.append(task)
                batch_targets.update(target_keys)
                reserved_targets.update(target_keys)
            if not tasks:
                continue
            self.batch_counter += 1
            batch_id = f"{worker_id}-{self.batch_counter}"
            self.batch_hosts[batch_id] = [task.host_id for task in tasks]
            self.batch_target_keys[batch_id] = frozenset(batch_targets)
            self.worker_status[worker_id] = {
                "status": "BUSY",
                "batch": batch_id,
                "size": len(tasks),
            }
            self.work_queues[worker_id].put((batch_id, tasks))

    def _handle_result_message(self, message: tuple[Any, ...]) -> None:
        """Consume one worker IPC result tuple and return its worker to idle state.

        Args:
            message: ``(worker_id, batch_id, results, worker_error)`` emitted by a
                worker process through the coordinator result queue.

        Results:
            Applies successful device results or defers the batch and records errors
            when the worker reports a batch-level failure.
        """

        worker_id, batch_id, results, worker_error = message
        self.worker_status[int(worker_id)] = {"status": "IDLE", "batch": "-", "size": 0}
        host_ids = self.batch_hosts.pop(str(batch_id), [])
        self._release_batch_targets(str(batch_id))
        if worker_error:
            LOG.error("worker %s batch %s failed: %s", worker_id, batch_id, worker_error)
            for host_id in host_ids:
                self.state.defer_host(host_id)
                self.state.add_error(
                    host_id,
                    "worker",
                    "worker_failure",
                    str(worker_error),
                    recoverable=True,
                )
            return
        for result in results:
            self._process_result(result)

    def _check_worker_health(self) -> None:
        """Detect unexpected worker exits and defer their in-flight hosts.

        Results:
            Marks dead workers, records recoverable errors, and requests a controlled
            pause so partially claimed state is not silently abandoned.
        """

        for worker_id, process in enumerate(self.workers):
            if process.is_alive() or self.worker_status[worker_id]["status"] == "DEAD":
                continue
            status = self.worker_status[worker_id]
            batch_id = str(status.get("batch", "-"))
            if batch_id in self.batch_hosts:
                for host_id in self.batch_hosts.pop(batch_id):
                    self.state.defer_host(host_id)
                    self.state.add_error(
                        host_id,
                        "worker",
                        "worker_exit",
                        f"worker {worker_id} exited unexpectedly",
                    )
            self._release_batch_targets(batch_id)
            self.worker_status[worker_id] = {"status": "DEAD", "batch": "-", "size": 0}
            LOG.error("worker %d exited unexpectedly with code %s", worker_id, process.exitcode)
            self.pause_event.set()
            self.pause_requested = True

    def _check_pause_indicator(self) -> None:
        """Translate the configured pause-indicator file into a controlled pause.

        Results:
            Sets shared/local pause flags once the indicator exists.
        """

        indicator = self.paths.scratch_dir / self.config.resume.pause_indicator
        if indicator.exists() and not self.pause_event.is_set():
            LOG.warning("pause indicator detected: %s", indicator)
            self.pause_event.set()
            self.pause_requested = True

    def _check_limits(self) -> None:
        """Apply runtime discovery guardrails without confusing identification with polling.

        Zero disables the corresponding guardrail.  In seed-only ``auto`` mode,
        managed neighbors may legitimately make ``managed_devices`` larger than the
        effective seed count, so recursion is controlled by scheduler admission
        rather than by comparing the total identified managed-device population.
        """

        counts = self.state.counts()
        max_hosts = self.config.discovery.max_hosts
        host_population = self.state.host_guardrail_count(seed_only=self.seed_only)
        # In seed-only sampling, reaching N discovered non-seeds is the intended
        # threshold. Recursive mode preserves the historical > comparison so N
        # preloaded seed identities do not prevent those N seeds from being polled.
        host_limit_hit = max_hosts > 0 and (
            host_population >= max_hosts if self.seed_only else host_population > max_hosts
        )
        if host_limit_hit:
            LOG.warning(
                "maximum host guardrail reached: population=%d limit=%d mode=%s",
                host_population,
                max_hosts,
                "seed_only_nonseed" if self.seed_only else "all_hosts",
            )
            self.limit_reached = True
            self.limit_reason = self.limit_reason or "max_hosts"

        if not self.seed_only:
            max_devices = int(self.config.discovery.max_devices)
            if max_devices > 0 and counts["managed_devices"] > max_devices:
                LOG.warning("maximum managed-device guardrail reached")
                self.limit_reached = True
                self.limit_reason = self.limit_reason or "max_devices"
        if self.limit_reached:
            if self.limit_reason:
                self.state.set_meta("limit_reason", self.limit_reason)
            self.pause_event.set()

    def _limit_stop_status(self) -> str:
        """Select resumable guardrail stop or intentional completed-limit status."""

        return (
            "COMPLETED_LIMIT"
            if self.config.discovery.limit_behavior == "complete"
            else "LIMIT_REACHED"
        )

    def _all_workers_idle(self) -> bool:
        """Return whether every worker is idle or already known dead."""

        return all(info["status"] in {"IDLE", "DEAD"} for info in self.worker_status.values())

    def _register_signals(self) -> None:
        """Install SIGINT/SIGTERM/SIGUSR1 handlers for controlled pause behavior."""

        def handler(signum: int, _frame: Any) -> None:
            """Convert one process signal into the coordinator pause request."""

            LOG.warning("signal %s requested controlled pause", signum)
            self.pause_requested = True
            self.pause_event.set()

        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGUSR1):
            self._old_signals[signum] = signal.getsignal(signum)
            signal.signal(signum, handler)

    def _restore_signals(self) -> None:
        """Restore process signal handlers saved by ``_register_signals``."""

        for signum, old in self._old_signals.items():
            signal.signal(signum, old)

    def _stop_workers(self) -> None:
        """Request worker shutdown, then terminate processes that do not exit.

        Results:
            Sends sentinel work items, waits for graceful exit, and force-terminates
            remaining processes so coordinator cleanup can continue.
        """

        for work_queue in self.work_queues:
            try:
                work_queue.put_nowait(None)
            except Exception:
                pass
        for process in self.workers:
            process.join(timeout=5.0)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2.0)

    def _update_run_provenance(
        self,
        *,
        status: str,
        invocation_ended: str | None = None,
        phase_metrics: dict[str, float] | None = None,
    ) -> None:
        """Refresh durable run.json provenance when this CLI invocation records it."""

        sequence = getattr(self, "run_manifest_sequence", None)
        if sequence is None:
            return
        update_run_manifest(
            self.run_manifest_path,
            sequence=sequence,
            status=status,
            started=self.state.get_meta("started") or self.started_text,
            completed=self.state.get_meta("completed"),
            invocation_ended=invocation_ended,
            indent=self.config.output.pretty_json_indent,
            phase_metrics=phase_metrics,
        )

    def _publish_run_provenance(self, directory: Path, *, draft: bool) -> Path | None:
        """Publish run provenance beside discovery output when CLI metadata exists."""

        if getattr(self, "run_manifest_sequence", None) is None:
            return None
        return publish_run_manifest(
            self.run_manifest_path,
            directory,
            draft=draft,
            indent=self.config.output.pretty_json_indent,
        )

    def _archive_completed_scoreboard(self, snapshot: ScoreboardSnapshot) -> None:
        """Retain the exact terminal scoreboard in completed-run state.

        The live scoreboard is shared at ``<scratch_root>/scoreboard`` and may be
        replaced by a subsequent run at any moment. Archiving the in-memory
        terminal snapshot avoids rereading that shared location after completion.
        Durable run state always receives a copy. Retained per-run scratch state
        receives one only when automatic scratch cleanup is disabled.
        """

        archive_scoreboard(snapshot, self.paths.run_dir)
        if not self.config.paths.clean_scratch_when_completed:
            archive_scoreboard(snapshot, self.paths.scratch_dir)

    def _remove_completed_run_manifest_draft(self) -> None:
        """Remove durable ``run.json.draft`` after final run.json publication."""

        manifest_path = getattr(self, "run_manifest_path", None)
        if manifest_path is not None:
            Path(manifest_path).unlink(missing_ok=True)

    def record_initialization_failure(self) -> None:
        """Close the current provenance invocation after pre-run initialization fails."""

        status = self.state.get_meta("status") or "INITIALIZATION_FAILED"
        self._update_run_provenance(status=status, invocation_ended=iso_now())

    def run(self) -> DiscoveryOutcome:
        """Run scheduling, worker collection, snapshots, and terminal finalization.

        Returns:
            ``DiscoveryOutcome`` with terminal status, invocation start/end, elapsed
            whole seconds, and state/output locations.

        Raises:
            BaseException: Re-raises unexpected failures after checkpointing
            interrupted state and attempting diagnostic draft output.

        Runtime timestamps describe this invocation. Persisted run metadata retains
        the original logical start across pause/resume boundaries.
        """

        # Normal CLI construction records the invocation wall clock in __init__.
        # Retain a defensive fallback for focused tests/embedders that intentionally
        # construct Coordinator via __new__ and provide only execution primitives.
        if not hasattr(self, "invocation_started_iso"):
            self.invocation_started_iso = iso_now()
        if not hasattr(self, "invocation_started_text"):
            self.invocation_started_text = human_now()

        self._register_signals()
        counts = getattr(self, "seed_resolution_summary", None)
        unique_seeds = (
            int(counts["unique"])
            if isinstance(counts, dict) and "unique" in counts
            else self.state.seed_device_count()
        )
        LOG.info(
            "%s starting: proceeding with %d unique seeds",
            "Seed-only discovery" if self.seed_only else "Discovery",
            unique_seeds,
        )
        LOG.info(
            "discovery scheduling started: mode=%s seeds=%d ready=%d workers=%d batch_size=%d",
            "seed_only" if self.seed_only else "recursive",
            unique_seeds,
            self.state.ready_count(),
            getattr(self, "effective_workers", int(self.config.discovery.workers)),
            getattr(self, "effective_batch_size", int(self.config.discovery.batch_size)),
            extra={"activity_only": True},
        )
        self._start_workers()
        last_scoreboard = 0.0
        last_snapshot = 0.0
        draft_dir = (
            self.paths.scratch_dir if self.config.output.draft_in_scratch else self.paths.run_dir
        )
        final_staging = draft_dir
        final_status = "INTERRUPTED"
        output_directory: Path | None = None
        outcome: DiscoveryOutcome | None = None
        discovery_finished_monotonic: float | None = None
        output_publication_duration = 0.0
        output_phase_metrics: dict[str, float] = {}
        final_scoreboard_snapshot: ScoreboardSnapshot | None = None
        try:
            while True:
                self._check_pause_indicator()
                self._check_worker_health()
                self._check_limits()
                self._dispatch()

                try:
                    message = self.result_queue.get(timeout=0.2)
                    self._handle_result_message(message)
                except queue.Empty:
                    pass

                now = time.monotonic()
                if now - last_scoreboard >= self.config.output.scoreboard_interval_seconds:
                    status = "PAUSING" if self.pause_event.is_set() else "RUNNING"
                    write_scoreboard(
                        self.state,
                        self.paths.scoreboard_dir,
                        run_id=self.paths.run_id,
                        started=self.started_text,
                        status=status,
                        elapsed_seconds=now - self.started_monotonic,
                        worker_status=self.worker_status,
                        execution_plan=self._execution_plan_for_scoreboard(),
                    )
                    last_scoreboard = now
                if now - last_snapshot >= self.config.output.snapshot_interval_seconds:
                    self._update_run_provenance(status="RUNNING")
                    write_outputs(
                        self.state,
                        self.config,
                        draft_dir,
                        run_id=self.paths.run_id,
                        status="RUNNING",
                        draft=True,
                    )
                    self._publish_run_provenance(draft_dir, draft=True)
                    last_snapshot = now

                if self.pause_event.is_set() and self._all_workers_idle():
                    final_status = self._limit_stop_status() if self.limit_reached else "PAUSED"
                    break
                if (
                    not self.pause_event.is_set()
                    and self.state.ready_count() == 0
                    and self.state.active_count() == 0
                    and self._all_workers_idle()
                ):
                    final_status = "COMPLETED"
                    break

            self._stop_workers()
            absorbed_projections = self.state.reconcile_duplicate_query_projections()
            if absorbed_projections:
                LOG.info(
                    "reconciled %d duplicate managed-host projection(s) before output",
                    len(absorbed_projections),
                )
            discovery_finished_monotonic = time.monotonic()
            if final_status in {"COMPLETED", "COMPLETED_LIMIT"}:
                completed = iso_now()
                self.state.set_meta("completed", completed)
                self.state.set_meta("status", final_status)
                if final_status == "COMPLETED_LIMIT":
                    self.state.set_meta(
                        "completion_reason", self.limit_reason or "configured_limit"
                    )
                    self.state.set_meta(
                        "configured_max_hosts", str(self.config.discovery.max_hosts)
                    )
                    self.state.set_meta(
                        "configured_max_devices", str(self.config.discovery.max_devices)
                    )
                # ``completed`` and the legacy top-level ``duration`` retain the
                # discovery-complete boundary. Final graph/output work is measured
                # independently below and published as schema-3 phase telemetry.
                self._update_run_provenance(status=final_status)
                final_outputs = write_outputs(
                    self.state,
                    self.config,
                    final_staging,
                    run_id=self.paths.run_id,
                    status=final_status,
                    draft=False,
                )
                output_phase_metrics = dict(getattr(final_outputs, "phase_metrics", {}))
                run_manifest_output = self._publish_run_provenance(final_staging, draft=False)
                if run_manifest_output is not None:
                    final_outputs.append(run_manifest_output)
                custom_output_names = [
                    item.filename for item in self.config.output.custom_csv.values()
                ]
                publication_started = time.monotonic()
                finalize_to_persistent(
                    final_staging,
                    self.paths.output_run_dir,
                    self.paths.latest_link,
                    output_names=[path.name for path in final_outputs],
                    known_output_names=[RUN_JSON_NAME, *OUTPUT_NAMES, *custom_output_names],
                )
                output_publication_duration = max(0.0, time.monotonic() - publication_started)
                # Resolve a retained legacy symlink such as ``output -> outputs``
                # before presenting the path to operators or downstream scripts.
                output_directory = canonical_operator_path(self.paths.output_run_dir)
            else:
                self.state.set_meta("status", final_status)
                invocation_ended = iso_now()
                self._update_run_provenance(status=final_status, invocation_ended=invocation_ended)
                write_outputs(
                    self.state,
                    self.config,
                    draft_dir,
                    run_id=self.paths.run_id,
                    status=final_status,
                    draft=True,
                )
                self._publish_run_provenance(draft_dir, draft=True)
                LOG.warning("run %s stopped with status %s", self.paths.run_id, final_status)
            self.state.checkpoint()
            final_scoreboard_snapshot = write_scoreboard(
                self.state,
                self.paths.scoreboard_dir,
                run_id=self.paths.run_id,
                started=self.started_text,
                status=final_status,
                elapsed_seconds=time.monotonic() - self.started_monotonic,
                worker_status=self.worker_status,
                execution_plan=self._execution_plan_for_scoreboard(),
            )
            if (
                final_status in {"COMPLETED", "COMPLETED_LIMIT"}
                and output_directory is not None
                and discovery_finished_monotonic is not None
            ):
                timing_boundary = time.monotonic()
                discovery_duration = max(0.0, discovery_finished_monotonic - self.started_monotonic)
                finalization_duration = max(0.0, timing_boundary - discovery_finished_monotonic)
                phase_metrics = {
                    "discovery_duration": discovery_duration,
                    "graph_resolution_duration": output_phase_metrics.get(
                        "graph_resolution_duration", 0.0
                    ),
                    "graph_serialization_duration": output_phase_metrics.get(
                        "graph_serialization_duration", 0.0
                    ),
                    "output_publication_duration": output_publication_duration,
                    "finalization_duration": finalization_duration,
                    "total_wall_clock_duration": max(0.0, timing_boundary - self.started_monotonic),
                }
                invocation_ended = iso_now()
                self._update_run_provenance(
                    status=final_status,
                    invocation_ended=invocation_ended,
                    phase_metrics=phase_metrics,
                )
                # The preliminary manifest was copied with the output set so a
                # crash never leaves discovery.json without provenance. Replace
                # it atomically now that final phase timing is known.
                self._publish_run_provenance(output_directory, draft=False)
                LOG.info(
                    "run %s completed with status %s; output=%s",
                    self.paths.run_id,
                    final_status,
                    output_directory,
                )
            ended_timestamp = human_now()
            duration_seconds = int(max(0.0, time.monotonic() - self.started_monotonic))
            outcome = DiscoveryOutcome(
                run_id=self.paths.run_id,
                status=final_status,
                started_timestamp=self.invocation_started_text,
                ended_timestamp=ended_timestamp,
                duration_seconds=duration_seconds,
                output_directory=output_directory,
                state_path=self.paths.state_path,
                activity_log=self.paths.activity_log,
            )
        except BaseException:
            self.pause_event.set()
            self._stop_workers()
            self.state.set_meta("status", "INTERRUPTED")
            self.state.checkpoint()
            try:
                self._update_run_provenance(status="INTERRUPTED", invocation_ended=iso_now())
                write_outputs(
                    self.state,
                    self.config,
                    draft_dir,
                    run_id=self.paths.run_id,
                    status="INTERRUPTED",
                    draft=True,
                )
                self._publish_run_provenance(draft_dir, draft=True)
                write_scoreboard(
                    self.state,
                    self.paths.scoreboard_dir,
                    run_id=self.paths.run_id,
                    started=self.started_text,
                    status="INTERRUPTED",
                    elapsed_seconds=time.monotonic() - self.started_monotonic,
                    worker_status=self.worker_status,
                    execution_plan=self._execution_plan_for_scoreboard(),
                )
            except Exception:
                LOG.exception("unable to write interrupted-run draft outputs")
            LOG.exception("run %s interrupted", self.paths.run_id)
            raise
        finally:
            self._restore_signals()
            self.close()

        if outcome is None:  # pragma: no cover - defensive control-flow guard
            raise RuntimeError("discovery completed without producing an outcome")
        if outcome.status in {"COMPLETED", "COMPLETED_LIMIT"}:
            try:
                if final_scoreboard_snapshot is None:
                    raise OSError("completed run has no terminal scoreboard snapshot")
                self._archive_completed_scoreboard(final_scoreboard_snapshot)
                self._remove_completed_run_manifest_draft()
                # Persistent run state and its activity log must be closed before
                # this alias advertises the fully archived directory as newest.
                publish_latest_symlink(
                    self.paths.run_latest_link,
                    self.paths.run_dir,
                )
                if self.config.paths.clean_scratch_when_completed:
                    clean_completed_scratch(self.paths)
            except OSError as exc:
                raise OSError(
                    f"run {self.paths.run_id} completed successfully, but "
                    f"post-completion storage finalization failed: {exc}"
                ) from exc
        return outcome


def explain_target(
    config: AppConfig,
    target: str,
    *,
    resolved_identity: ResolvedIdentity | None = None,
) -> dict[str, Any]:
    """Explain boundary/query/credential policy for each resolved target address.

    Args:
        config: Effective validated configuration whose policy should be evaluated.
        target: Seed hostname, IPv4 address, or IPv6 address to resolve and explain.
        resolved_identity: Optional already-resolved seed identity. ``run --dry-run``
            uses this to honor the same seed DNS policy as real initialization;
            standalone explain-target behavior omits it and performs fresh DNS.

    Returns:
        Target identity, DNS errors, per-address decisions, selected credential
        profiles, and an overall query-allowed action string.
    """

    policy = PolicyEngine(config)
    if resolved_identity is None:
        resolved = resolve_seed(target, config.discovery.dns_suffixes)
    else:
        resolved = resolved_identity
    addresses = []
    for address in resolved.addresses:
        boundary = policy.in_boundary(address)
        query = policy.query_policy(resolved.names, address)
        credential = policy.credential_profile(resolved.names, address)
        addresses.append(
            {
                "address": address,
                "boundary_allowed": boundary.allowed,
                "boundary_reason": boundary.reason,
                "query_allowed": query.allowed,
                "query_reason": query.reason,
                "credential_profile": credential.profile.name,
                "credential_reason": credential.reason,
                "primary_credential": credential.profile.primary,
                "fallback_credential": credential.profile.fallback,
            }
        )
    return {
        "target": target,
        "preferred_name": resolved.preferred_name,
        "names": resolved.names,
        "addresses": addresses,
        "dns_errors": resolved.errors,
        "action": "SNMP QUERY ALLOWED"
        if any(x["boundary_allowed"] and x["query_allowed"] for x in addresses)
        else "SNMP QUERY NOT ALLOWED",
    }
