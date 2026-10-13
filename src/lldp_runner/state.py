"""Durable coordinator-owned SQLite state and identity registry."""

from __future__ import annotations

import json
import sqlite3
import zlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from lldp_runner.claims import (
    IdentityClaim,
    candidate_claims,
    candidate_observation_payload,
    device_result_claims,
    device_result_observation_payload,
    neighbor_observation_claims,
    stable_fingerprint,
    stable_json,
)
from lldp_runner.identity import (
    alias_tuples,
    anonymous_endpoint_port_mac,
    cisco_ap_mac,
    cisco_sep_mac,
    normalize_host_address,
    normalize_identity_name,
    normalized_advertised_name,
)
from lldp_runner.models import Candidate, DeviceResult, NeighborObservation
from lldp_runner.timeutil import iso_after, iso_now
from lldp_runner.topology_graph import (
    GraphBuildResult,
    build_topology_graph,
    canonical_raw_advertisements,
    observation_from_payload,
)

ACTIVE_STATES = ("CLAIMED", "PINGING", "SNMP_BASIC", "SNMP_DETAIL", "NEIGHBOR_DISCOVERY")
TERMINAL_STATES = ("COMPLETE", "FAILED", "NO_QUERY", "OUT_OF_SCOPE")


def _identity_name_sets_compatible(left: set[str], right: set[str]) -> bool:
    """Return whether two direct-name sets can describe one logical host.

    Exact normalized names are compatible.  One single-label short name may also
    match the identical left-most component of one FQDN when other evidence (for
    example a shared address) is present.  Two FQDNs are never equated merely by
    suffix removal, and two unrelated names sharing an address remain conflicting.
    """

    left_bases = {
        normalize_identity_name(parsed.base_name) or name
        for name in left
        if (parsed := normalized_advertised_name(name)) is not None
    }
    right_bases = {
        normalize_identity_name(parsed.base_name) or name
        for name in right
        if (parsed := normalized_advertised_name(name)) is not None
    }
    if left_bases & right_bases:
        return True
    for left_name in left_bases:
        for right_name in right_bases:
            left_short = "." not in left_name
            right_short = "." not in right_name
            if left_short == right_short:
                continue
            if left_short and right_name.startswith(left_name + "."):
                return True
            if right_short and left_name.startswith(right_name + "."):
                return True
    return False


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        # WAL + NORMAL avoids an fsync per small topology-state commit while
        # retaining committed WAL records for normal process-crash recovery.
        # checkpoint() performs an explicit FULL WAL checkpoint at controlled
        # pause/finalization boundaries.
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self._create_schema()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def checkpoint(self) -> None:
        self.conn.commit()
        self.conn.execute("PRAGMA wal_checkpoint(FULL)")

    def _create_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                observation_type TEXT NOT NULL,
                source_host_id INTEGER,
                protocol TEXT,
                observed_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS observations_source_idx
                ON observations(source_host_id, protocol, id);

            CREATE TABLE IF NOT EXISTS claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                observation_id INTEGER NOT NULL
                    REFERENCES observations(id) ON DELETE RESTRICT,
                fingerprint TEXT NOT NULL UNIQUE,
                claim_type TEXT NOT NULL,
                claim_subtype TEXT,
                raw_value_json TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                provenance TEXT NOT NULL,
                scope TEXT NOT NULL,
                strength TEXT NOT NULL,
                identity_eligible INTEGER NOT NULL DEFAULT 0,
                context_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS claims_observation_idx
                ON claims(observation_id, id);
            CREATE INDEX IF NOT EXISTS claims_lookup_idx
                ON claims(claim_type, claim_subtype, normalized_value, scope, strength);

            CREATE TABLE IF NOT EXISTS resolution_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                observation_id INTEGER NOT NULL
                    REFERENCES observations(id) ON DELETE RESTRICT,
                sequence INTEGER NOT NULL,
                supersedes_decision_id INTEGER
                    REFERENCES resolution_decisions(id) ON DELETE RESTRICT,
                decision_fingerprint TEXT NOT NULL UNIQUE,
                decision_type TEXT NOT NULL,
                projected_host_id INTEGER,
                candidate_host_ids_json TEXT NOT NULL DEFAULT '[]',
                confidence TEXT NOT NULL,
                rationale_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                UNIQUE(observation_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS resolution_decisions_observation_idx
                ON resolution_decisions(observation_id, sequence);

            CREATE TABLE IF NOT EXISTS decision_claims (
                decision_id INTEGER NOT NULL
                    REFERENCES resolution_decisions(id) ON DELETE RESTRICT,
                claim_id INTEGER NOT NULL REFERENCES claims(id) ON DELETE RESTRICT,
                role TEXT NOT NULL,
                PRIMARY KEY(decision_id, claim_id, role)
            );

            CREATE TABLE IF NOT EXISTS protocol_advertisements (
                observation_id INTEGER PRIMARY KEY
                    REFERENCES observations(id) ON DELETE RESTRICT,
                occurrence_fingerprint TEXT NOT NULL UNIQUE,
                content_fingerprint TEXT NOT NULL,
                source_host_id INTEGER NOT NULL,
                source_observation_id INTEGER
                    REFERENCES observations(id) ON DELETE RESTRICT,
                protocol TEXT NOT NULL,
                duplicate_ordinal INTEGER NOT NULL DEFAULT 0,
                local_interface TEXT,
                local_interface_namespace TEXT NOT NULL,
                source_context_json TEXT NOT NULL DEFAULT '{}',
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS protocol_advertisements_source_idx
                ON protocol_advertisements(source_host_id, protocol, observation_id);

            CREATE TABLE IF NOT EXISTS graph_projection (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                projection_fingerprint TEXT NOT NULL,
                materialized_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_codec TEXT,
                payload_blob BLOB,
                summary_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS graph_component_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component_key TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                supersedes_decision_id INTEGER
                    REFERENCES graph_component_decisions(id) ON DELETE RESTRICT,
                decision_fingerprint TEXT NOT NULL UNIQUE,
                decision_type TEXT NOT NULL,
                outcome_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                UNIQUE(component_key, sequence)
            );
            CREATE INDEX IF NOT EXISTS graph_component_decisions_component_idx
                ON graph_component_decisions(component_key, sequence);

            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                preferred_name TEXT NOT NULL,
                snmp_sysname TEXT,
                classification TEXT NOT NULL DEFAULT 'unknown_device',
                classification_reason_json TEXT NOT NULL DEFAULT '[]',
                state TEXT NOT NULL DEFAULT 'DISCOVERED',
                cohort INTEGER NOT NULL DEFAULT 0,
                worker_id INTEGER,
                lease_until TEXT,
                query_target TEXT,
                credential_profile TEXT,
                credential_source TEXT,
                credential_label TEXT,
                credential_result TEXT,
                is_seed INTEGER NOT NULL DEFAULT 0,
                seed_rank INTEGER,
                first_seen TEXT NOT NULL,
                last_seen TEXT,
                last_seen_source TEXT,
                ping_json TEXT NOT NULL DEFAULT '[]',
                system_json TEXT NOT NULL DEFAULT '{}',
                metrics_json TEXT NOT NULL DEFAULT '{}',
                snmp_sessions_json TEXT NOT NULL DEFAULT '[]',
                interface_groups_json TEXT NOT NULL DEFAULT '[]',
                collection_coverage_json TEXT NOT NULL DEFAULT '{}',
                late_recovery_used INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS aliases (
                alias_type TEXT NOT NULL,
                value TEXT NOT NULL,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                PRIMARY KEY(alias_type, value)
            );
            CREATE INDEX IF NOT EXISTS aliases_host_idx ON aliases(host_id);

            CREATE TABLE IF NOT EXISTS host_addresses (
                address_type TEXT NOT NULL,
                value TEXT NOT NULL,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                identity_eligible INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(address_type, value, host_id)
            );
            CREATE INDEX IF NOT EXISTS host_addresses_value_idx
                ON host_addresses(address_type, value);
            CREATE INDEX IF NOT EXISTS host_addresses_host_idx
                ON host_addresses(host_id, address_type, value);

            CREATE TABLE IF NOT EXISTS host_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                tag TEXT NOT NULL,
                UNIQUE(host_id, tag)
            );
            CREATE INDEX IF NOT EXISTS host_tags_host_idx ON host_tags(host_id, id);

            CREATE TABLE IF NOT EXISTS neighbors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                remote_host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                protocols TEXT NOT NULL,
                local_interface TEXT NOT NULL DEFAULT '',
                local_interface_raw TEXT,
                remote_interface TEXT NOT NULL DEFAULT '',
                remote_interface_raw TEXT,
                observed_name TEXT,
                observed_addresses_json TEXT NOT NULL DEFAULT '[]',
                details_json TEXT NOT NULL DEFAULT '{}',
                last_seen TEXT NOT NULL,
                UNIQUE(source_host_id, remote_host_id, local_interface, remote_interface)
            );
            CREATE INDEX IF NOT EXISTS neighbors_remote_idx ON neighbors(remote_host_id);

            CREATE TABLE IF NOT EXISTS errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
                timestamp TEXT NOT NULL,
                operation TEXT NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                attempted_target TEXT,
                address_family TEXT,
                phase TEXT,
                exception_type TEXT,
                exception_errno INTEGER,
                exception_strerror TEXT,
                exception_args_json TEXT NOT NULL DEFAULT '[]',
                credential_profile TEXT,
                credential_stage TEXT,
                credential_source TEXT,
                credential_label TEXT,
                attempt INTEGER,
                collector TEXT,
                recoverable INTEGER NOT NULL DEFAULT 1,
                final_device_status TEXT
            );
            CREATE INDEX IF NOT EXISTS errors_host_idx ON errors(host_id);

            CREATE TABLE IF NOT EXISTS route_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                attempted_target TEXT NOT NULL,
                address_family TEXT NOT NULL,
                credential_profile TEXT,
                credential_stage TEXT,
                credential_source TEXT,
                credential_label TEXT,
                attempt INTEGER,
                outcome TEXT NOT NULL,
                category TEXT,
                recorded_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS route_attempts_host_idx
                ON route_attempts(host_id, attempted_target, id);
            CREATE UNIQUE INDEX IF NOT EXISTS route_attempts_identity_idx
                ON route_attempts(
                    host_id,
                    attempted_target,
                    COALESCE(credential_profile, ''),
                    COALESCE(credential_stage, ''),
                    COALESCE(credential_source, ''),
                    COALESCE(credential_label, ''),
                    COALESCE(attempt, -1),
                    outcome
                );

            CREATE TABLE IF NOT EXISTS scheduler_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS scheduler_events_host_idx
                ON scheduler_events(host_id, id);

            CREATE TABLE IF NOT EXISTS seed_credential_requirements (
                host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
                strategy TEXT NOT NULL,
                source_keys_json TEXT NOT NULL DEFAULT '[]',
                labels_json TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TRIGGER IF NOT EXISTS observations_immutable_update
            BEFORE UPDATE ON observations
            BEGIN
                SELECT RAISE(ABORT, 'observations are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS observations_immutable_delete
            BEFORE DELETE ON observations
            BEGIN
                SELECT RAISE(ABORT, 'observations are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS claims_immutable_update
            BEFORE UPDATE ON claims
            BEGIN
                SELECT RAISE(ABORT, 'claims are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS claims_immutable_delete
            BEFORE DELETE ON claims
            BEGIN
                SELECT RAISE(ABORT, 'claims are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS resolution_decisions_immutable_update
            BEFORE UPDATE ON resolution_decisions
            BEGIN
                SELECT RAISE(ABORT, 'resolution decisions are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS resolution_decisions_immutable_delete
            BEFORE DELETE ON resolution_decisions
            BEGIN
                SELECT RAISE(ABORT, 'resolution decisions are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS decision_claims_immutable_update
            BEFORE UPDATE ON decision_claims
            BEGIN
                SELECT RAISE(ABORT, 'decision claim links are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS decision_claims_immutable_delete
            BEFORE DELETE ON decision_claims
            BEGIN
                SELECT RAISE(ABORT, 'decision claim links are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS protocol_advertisements_immutable_update
            BEFORE UPDATE ON protocol_advertisements
            BEGIN
                SELECT RAISE(ABORT, 'protocol advertisements are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS protocol_advertisements_immutable_delete
            BEFORE DELETE ON protocol_advertisements
            BEGIN
                SELECT RAISE(ABORT, 'protocol advertisements are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS graph_component_decisions_immutable_update
            BEFORE UPDATE ON graph_component_decisions
            BEGIN
                SELECT RAISE(ABORT, 'graph component decisions are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS graph_component_decisions_immutable_delete
            BEFORE DELETE ON graph_component_decisions
            BEGIN
                SELECT RAISE(ABORT, 'graph component decisions are immutable');
            END;
            """
        )
        # CREATE TABLE IF NOT EXISTS does not add columns to an existing run DB.
        # seed_rank is internal checkpoint state, not an external input format, so
        # migrate v0.9.x state in place before creating its scheduling index.
        host_columns = {
            str(row[1]) for row in self.conn.execute("PRAGMA table_info(hosts)").fetchall()
        }
        if "seed_rank" not in host_columns:
            self.conn.execute("ALTER TABLE hosts ADD COLUMN seed_rank INTEGER")
        # v0.13 adds optional per-device collection telemetry.  Older run DBs
        # remain resumable; an empty object simply means metrics were not
        # requested (or the host has not yet been queried with metrics enabled).
        if "metrics_json" not in host_columns:
            self.conn.execute(
                "ALTER TABLE hosts ADD COLUMN metrics_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "snmp_sessions_json" not in host_columns:
            self.conn.execute(
                "ALTER TABLE hosts ADD COLUMN snmp_sessions_json "
                "TEXT NOT NULL DEFAULT '[]'"
            )
        if "interface_groups_json" not in host_columns:
            self.conn.execute(
                "ALTER TABLE hosts ADD COLUMN interface_groups_json "
                "TEXT NOT NULL DEFAULT '[]'"
            )
        if "collection_coverage_json" not in host_columns:
            self.conn.execute(
                "ALTER TABLE hosts ADD COLUMN collection_coverage_json "
                "TEXT NOT NULL DEFAULT '{}'"
            )
        if "late_recovery_used" not in host_columns:
            self.conn.execute(
                "ALTER TABLE hosts ADD COLUMN late_recovery_used "
                "INTEGER NOT NULL DEFAULT 0"
            )
        if "credential_source" not in host_columns:
            self.conn.execute("ALTER TABLE hosts ADD COLUMN credential_source TEXT")
        if "credential_label" not in host_columns:
            self.conn.execute("ALTER TABLE hosts ADD COLUMN credential_label TEXT")
        if "preferred_name" in host_columns:
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS hosts_preferred_name_nocase_idx "
                "ON hosts(preferred_name COLLATE NOCASE)"
            )
        error_columns = {
            str(row[1]) for row in self.conn.execute("PRAGMA table_info(errors)").fetchall()
        }
        if "credential_source" not in error_columns:
            self.conn.execute("ALTER TABLE errors ADD COLUMN credential_source TEXT")
        if "credential_label" not in error_columns:
            self.conn.execute("ALTER TABLE errors ADD COLUMN credential_label TEXT")
        for column, definition in (
            ("attempted_target", "TEXT"),
            ("address_family", "TEXT"),
            ("phase", "TEXT"),
            ("exception_type", "TEXT"),
            ("exception_errno", "INTEGER"),
            ("exception_strerror", "TEXT"),
            ("exception_args_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("collector", "TEXT"),
        ):
            if column not in error_columns:
                self.conn.execute(
                    f"ALTER TABLE errors ADD COLUMN {column} {definition}"
                )

        address_columns = {
            str(row[1])
            for row in self.conn.execute("PRAGMA table_info(host_addresses)").fetchall()
        }
        if "identity_eligible" not in address_columns:
            self.conn.execute(
                "ALTER TABLE host_addresses ADD COLUMN "
                "identity_eligible INTEGER NOT NULL DEFAULT 1"
            )

        advertisement_columns = {
            str(row[1])
            for row in self.conn.execute(
                "PRAGMA table_info(protocol_advertisements)"
            ).fetchall()
        }
        if "source_context_json" not in advertisement_columns:
            self.conn.execute(
                "ALTER TABLE protocol_advertisements ADD COLUMN "
                "source_context_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "source_observation_id" not in advertisement_columns:
            self.conn.execute(
                "ALTER TABLE protocol_advertisements ADD COLUMN "
                "source_observation_id INTEGER REFERENCES observations(id) "
                "ON DELETE RESTRICT"
            )

        projection_columns = {
            str(row[1])
            for row in self.conn.execute("PRAGMA table_info(graph_projection)").fetchall()
        }
        if "payload_codec" not in projection_columns:
            self.conn.execute("ALTER TABLE graph_projection ADD COLUMN payload_codec TEXT")
        if "payload_blob" not in projection_columns:
            self.conn.execute("ALTER TABLE graph_projection ADD COLUMN payload_blob BLOB")
        if "summary_json" not in projection_columns:
            self.conn.execute(
                "ALTER TABLE graph_projection ADD COLUMN "
                "summary_json TEXT NOT NULL DEFAULT '{}'"
            )

        # Releases through 0.31.3 stored addresses in the one-owner alias table.
        # Address observations are not globally unique in real networks: default
        # management addresses, overlapping private space, anycast services, and
        # vendor bugs can legitimately produce the same value on distinct hosts.
        # Migrate those rows into a many-to-many claim table before identity lookup.
        self.conn.execute(
            "INSERT OR IGNORE INTO host_addresses("
            "address_type, value, host_id, identity_eligible"
            ") SELECT alias_type, value, host_id, 1 FROM aliases "
            "WHERE alias_type IN ('ipv4', 'ipv6')"
        )
        self.conn.execute("DELETE FROM aliases WHERE alias_type IN ('ipv4', 'ipv6')")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS hosts_ready_seed_rank_idx "
            "ON hosts(state, is_seed, seed_rank, cohort, id)"
        )
        self._backfill_legacy_gufo_ipv6_constructor_errors()
        self.conn.commit()

    def _backfill_legacy_gufo_ipv6_constructor_errors(self) -> None:
        """Recover exact 0.32.4 Gufo IPv6 routes from persisted telemetry.

        Releases before 0.32.5 stored one adaptive-session record per address and
        credential route but omitted the address from the corresponding error
        row. The confirmed Gufo signature is uniquely identifiable: an
        ``OSError: invalid address`` basic failure on a FAILED host paired with
        IPv6 session telemetry whose profile/source/stage matches the error.

        A single matching destination is sufficient. When one host tried more
        than one IPv6 address under the same credential stage, 0.32.4 preserved
        both the error rows and session records in attempt order; ordinal pairing
        is used only when those group sizes match exactly. A one-error/two-route
        or otherwise incomplete group remains unresolved rather than borrowing
        the host-level query target.
        """

        hosts = self.conn.execute(
            """
            SELECT DISTINCT h.id, h.snmp_sessions_json
            FROM hosts h JOIN errors e ON e.host_id=h.id
            WHERE h.state='FAILED'
              AND e.attempted_target IS NULL
              AND e.operation='snmp_basic'
              AND e.message IN ('OSError: invalid address',
                                'builtins.OSError: invalid address')
            """
        ).fetchall()
        for host in hosts:
            try:
                sessions = json.loads(str(host["snmp_sessions_json"] or "[]"))
            except json.JSONDecodeError:
                continue
            if not isinstance(sessions, list):
                continue

            session_groups: dict[
                tuple[str | None, str | None, str | None], list[str]
            ] = {}
            for session in sessions:
                if not isinstance(session, dict):
                    continue
                target = str(session.get("target") or "")
                normalized = self._normalized_route_target(target)
                if normalized is None or normalized[1] != "ipv6":
                    continue
                route = str(session.get("credential_route") or "")
                parts = route.split("|", 3)
                source = parts[1] if len(parts) >= 2 else None
                stage = parts[2] if len(parts) >= 3 else None
                key = (
                    str(session.get("credential_profile"))
                    if session.get("credential_profile") is not None
                    else None,
                    stage,
                    source,
                )
                session_groups.setdefault(key, []).append(normalized[0])

            errors = self.conn.execute(
                """
                SELECT * FROM errors
                WHERE host_id=? AND attempted_target IS NULL
                  AND operation='snmp_basic'
                  AND message IN ('OSError: invalid address',
                                  'builtins.OSError: invalid address')
                ORDER BY id
                """,
                (int(host["id"]),),
            ).fetchall()
            error_groups: dict[
                tuple[str | None, str | None, str | None], list[sqlite3.Row]
            ] = {}
            for error in errors:
                key = (
                    str(error["credential_profile"])
                    if error["credential_profile"] is not None
                    else None,
                    str(error["credential_stage"])
                    if error["credential_stage"] is not None
                    else None,
                    str(error["credential_source"])
                    if error["credential_source"] is not None
                    else None,
                )
                error_groups.setdefault(key, []).append(error)

            for key, grouped_errors in error_groups.items():
                candidates = session_groups.get(key, [])
                unique = list(dict.fromkeys(candidates))
                assignments: list[str]
                if len(unique) == 1:
                    assignments = [unique[0]] * len(grouped_errors)
                elif len(candidates) == len(grouped_errors):
                    assignments = list(candidates)
                else:
                    continue
                for error, target in zip(
                    grouped_errors, assignments, strict=True
                ):
                    self.conn.execute(
                        """
                        UPDATE errors SET attempted_target=?,
                            address_family='ipv6',
                            phase='session_construct',
                            exception_type='builtins.OSError',
                            exception_args_json=?, collector='system',
                            category='snmp_session_address_error'
                        WHERE id=?
                        """,
                        (
                            target,
                            json.dumps([repr("invalid address")]),
                            int(error["id"]),
                        ),
                    )
                    self._record_route_attempt_uncommitted(
                        host_id=int(host["id"]),
                        attempted_target=target,
                        credential_profile=error["credential_profile"],
                        credential_stage=error["credential_stage"],
                        credential_source=error["credential_source"],
                        credential_label=error["credential_label"],
                        attempt=error["attempt"],
                        outcome="failed",
                        category="snmp_session_address_error",
                        recorded_at=str(error["timestamp"]),
                    )

    def _record_observation_uncommitted(
        self,
        payload: dict[str, Any],
        *,
        source_host_id: int | None,
        protocol: str | None,
        observed_at: str,
    ) -> tuple[int, str]:
        """Insert one immutable observation, or return its existing row.

        The fingerprint excludes collection time.  Replaying the exact same
        normalized input therefore remains idempotent while a materially changed
        observation receives a new row and can trigger a new resolver decision.
        """

        fingerprint = stable_fingerprint(payload)
        observation_type = str(payload.get("kind") or "observation")
        self.conn.execute(
            "INSERT OR IGNORE INTO observations("
            "fingerprint, observation_type, source_host_id, protocol, observed_at, "
            "payload_json) VALUES(?, ?, ?, ?, ?, ?)",
            (
                fingerprint,
                observation_type,
                source_host_id,
                protocol,
                observed_at,
                stable_json(payload),
            ),
        )
        row = self.conn.execute(
            "SELECT id FROM observations WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        if row is None:
            raise RuntimeError("observation insert did not produce a durable row")
        return int(row["id"]), fingerprint

    def _record_claims_uncommitted(
        self,
        observation_id: int,
        observation_fingerprint: str,
        claims: Iterable[IdentityClaim],
    ) -> list[int]:
        """Insert immutable typed claims and return their durable identifiers."""

        claim_ids: list[int] = []
        for claim in claims:
            fingerprint = claim.fingerprint(observation_fingerprint)
            self.conn.execute(
                "INSERT OR IGNORE INTO claims("
                "observation_id, fingerprint, claim_type, claim_subtype, "
                "raw_value_json, normalized_value, provenance, scope, strength, "
                "identity_eligible, context_json"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    observation_id,
                    fingerprint,
                    claim.claim_type,
                    claim.claim_subtype,
                    stable_json(claim.raw_value),
                    claim.normalized_value,
                    claim.provenance,
                    claim.scope,
                    claim.strength,
                    1 if claim.identity_eligible else 0,
                    stable_json(claim.context),
                ),
            )
            row = self.conn.execute(
                "SELECT id FROM claims WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if row is None:
                raise RuntimeError("claim insert did not produce a durable row")
            claim_ids.append(int(row["id"]))
        return list(dict.fromkeys(claim_ids))

    def _protocol_source_context_uncommitted(
        self, result: DeviceResult
    ) -> dict[str, Any]:
        """Return compact source metadata not present in the SNMP result fact.

        Each protocol row references the immutable ``snmp_device_result``
        observation that produced it.  The small inline context preserves the
        operator-facing provisional name and classification without repeating
        full SYSTEM-MIB and collection-coverage payloads for every neighbor row.
        No credential secret is stored here.
        """

        row = self.conn.execute(
            "SELECT preferred_name, classification FROM hosts WHERE id=?",
            (result.host_id,),
        ).fetchone()
        return {
            "schema_version": 2,
            "source_host_id": result.host_id,
            "preferred_name": (
                str(row["preferred_name"])
                if row is not None and row["preferred_name"] not in {None, ""}
                else result.query_target or "unknown"
            ),
            "classification": (
                str(row["classification"])
                if row is not None and row["classification"] not in {None, ""}
                else "managed_device"
            ),
        }

    def _record_protocol_advertisements_uncommitted(
        self,
        result: DeviceResult,
        observed_at: str,
        *,
        source_observation_id: int,
    ) -> int:
        """Persist raw CDP/LLDP rows before any compatibility merge.

        The immutable row and its typed claims are the factual resolver input.
        ``neighbors`` remains a compatibility projection and may be rebuilt when
        later evidence supersedes an earlier clustering decision.
        """

        observations = result.raw_neighbors or result.neighbors
        source_context = self._protocol_source_context_uncommitted(result)
        inserted = 0
        for record in canonical_raw_advertisements(result.host_id, observations):
            observation_id, fingerprint = self._record_observation_uncommitted(
                record,
                source_host_id=result.host_id,
                protocol=str(record.get("protocol") or ""),
                observed_at=observed_at,
            )
            payload = record.get("observation")
            if not isinstance(payload, dict):
                continue
            observation = observation_from_payload(payload)
            claims = neighbor_observation_claims(result.host_id, observation)
            claim_ids = self._record_claims_uncommitted(
                observation_id, fingerprint, claims
            )
            details = observation.details if isinstance(observation.details, dict) else {}
            namespace = str(details.get("local_interface_namespace") or "")
            if not namespace:
                local_value = observation.local_interface or observation.local_interface_raw or ""
                namespace = "typed" if ":" in local_value else "resolved"
            cursor = self.conn.execute(
                "INSERT OR IGNORE INTO protocol_advertisements("
                "observation_id, occurrence_fingerprint, content_fingerprint, "
                "source_host_id, source_observation_id, protocol, duplicate_ordinal, "
                "local_interface, local_interface_namespace, source_context_json, "
                "payload_json"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    observation_id,
                    str(record["occurrence_fingerprint"]),
                    str(record["content_fingerprint"]),
                    result.host_id,
                    source_observation_id,
                    observation.protocol,
                    int(record.get("duplicate_ordinal") or 0),
                    observation.local_interface or observation.local_interface_raw,
                    namespace,
                    stable_json(source_context),
                    stable_json(record),
                ),
            )
            inserted += max(0, int(cursor.rowcount))
            self._record_resolution_decision_uncommitted(
                observation_id,
                decision_type="raw_protocol_advertisement_retained",
                projected_host_id=None,
                candidate_host_ids=[],
                confidence=self._claim_confidence(claims),
                rationale=[
                    "raw protocol advertisement retained before cross-protocol reasoning"
                ],
                supporting_claim_ids=claim_ids,
                coalesce_same_outcome=True,
            )
        return inserted

    @staticmethod
    def _claim_confidence(claims: Iterable[IdentityClaim]) -> str:
        """Return an explainable engineering category for projection evidence."""

        values = list(claims)
        if any(
            claim.identity_eligible
            and claim.strength == "strong"
            and claim.scope in {"global", "physical_container", "snmp_agent"}
            for claim in values
        ):
            return "verified"
        if any(
            claim.identity_eligible
            and (
                claim.strength == "moderate"
                or (claim.strength == "strong" and claim.scope == "edge")
            )
            for claim in values
        ):
            return "high"
        if any(claim.identity_eligible and claim.strength == "weak" for claim in values):
            return "medium"
        return "low"

    def _record_resolution_decision_uncommitted(
        self,
        observation_id: int,
        *,
        decision_type: str,
        projected_host_id: int | None,
        candidate_host_ids: Iterable[int],
        confidence: str,
        rationale: Iterable[str],
        supporting_claim_ids: Iterable[int] = (),
        conflicting_claim_ids: Iterable[int] = (),
        coalesce_same_outcome: bool = False,
    ) -> int:
        """Append a decision that supersedes the prior conclusion when needed.

        Decisions are never updated.  Repeating the same decision is idempotent;
        a materially different result appends a row whose
        ``supersedes_decision_id`` points at the prior conclusion.
        """

        candidates = sorted(dict.fromkeys(int(value) for value in candidate_host_ids))
        reasons = list(dict.fromkeys(str(value) for value in rationale if str(value)))
        semantic = {
            "decision_type": decision_type,
            "projected_host_id": projected_host_id,
            "candidate_host_ids": candidates,
            "confidence": confidence,
            "rationale": reasons,
        }
        latest = self.conn.execute(
            "SELECT * FROM resolution_decisions WHERE observation_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (observation_id,),
        ).fetchone()
        if latest is not None:
            latest_semantic = {
                "decision_type": str(latest["decision_type"]),
                "projected_host_id": (
                    int(latest["projected_host_id"])
                    if latest["projected_host_id"] is not None
                    else None
                ),
                "candidate_host_ids": json.loads(
                    str(latest["candidate_host_ids_json"] or "[]")
                ),
                "confidence": str(latest["confidence"]),
                "rationale": json.loads(str(latest["rationale_json"] or "[]")),
            }
            if latest_semantic == semantic:
                return int(latest["id"])
            # Ingestion replay can encounter the compatibility host created by
            # the first pass and therefore produce different incidental candidate
            # or rationale lists.  Coalesce that replay only while its outcome is
            # unchanged.  Explicit later cluster-analysis decisions use the full
            # semantic comparison above, so changed evidence/rationale can append
            # a superseding decision even when the projected host remains equal.
            if coalesce_same_outcome and (
                latest_semantic["decision_type"] == semantic["decision_type"]
                and latest_semantic["projected_host_id"]
                == semantic["projected_host_id"]
                and latest_semantic["confidence"] == semantic["confidence"]
            ):
                return int(latest["id"])
            sequence = int(latest["sequence"]) + 1
            supersedes = int(latest["id"])
        else:
            sequence = 1
            supersedes = None

        decision_fingerprint = stable_fingerprint(
            {
                "observation_id": observation_id,
                "sequence": sequence,
                "supersedes": supersedes,
                **semantic,
            }
        )
        self.conn.execute(
            "INSERT INTO resolution_decisions("
            "observation_id, sequence, supersedes_decision_id, "
            "decision_fingerprint, decision_type, projected_host_id, "
            "candidate_host_ids_json, confidence, rationale_json, created_at"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                observation_id,
                sequence,
                supersedes,
                decision_fingerprint,
                decision_type,
                projected_host_id,
                stable_json(candidates),
                confidence,
                stable_json(reasons),
                iso_now(),
            ),
        )
        decision_id = int(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        for claim_id in dict.fromkeys(int(value) for value in supporting_claim_ids):
            self.conn.execute(
                "INSERT OR IGNORE INTO decision_claims(decision_id, claim_id, role) "
                "VALUES(?, ?, 'supporting')",
                (decision_id, claim_id),
            )
        for claim_id in dict.fromkeys(int(value) for value in conflicting_claim_ids):
            self.conn.execute(
                "INSERT OR IGNORE INTO decision_claims(decision_id, claim_id, role) "
                "VALUES(?, ?, 'conflicting')",
                (decision_id, claim_id),
            )
        return decision_id

    def record_resolution_decision(
        self,
        observation_id: int,
        *,
        decision_type: str,
        projected_host_id: int | None,
        candidate_host_ids: Iterable[int] = (),
        confidence: str = "low",
        rationale: Iterable[str] = (),
        supporting_claim_ids: Iterable[int] = (),
        conflicting_claim_ids: Iterable[int] = (),
    ) -> int:
        """Public append-only decision API for later cluster-analysis passes."""

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            decision_id = self._record_resolution_decision_uncommitted(
                observation_id,
                decision_type=decision_type,
                projected_host_id=projected_host_id,
                candidate_host_ids=candidate_host_ids,
                confidence=confidence,
                rationale=rationale,
                supporting_claim_ids=supporting_claim_ids,
                conflicting_claim_ids=conflicting_claim_ids,
            )
            self.conn.commit()
            return decision_id
        except Exception:
            self.conn.rollback()
            raise

    def observations(self) -> list[sqlite3.Row]:
        """Return immutable observations in ingestion order for audit/replay."""

        return self.conn.execute("SELECT * FROM observations ORDER BY id").fetchall()

    def claims_for_observation(self, observation_id: int) -> list[sqlite3.Row]:
        """Return typed claims derived from one immutable observation."""

        return self.conn.execute(
            "SELECT * FROM claims WHERE observation_id=? ORDER BY id",
            (observation_id,),
        ).fetchall()

    def resolution_decisions_for_observation(
        self, observation_id: int
    ) -> list[sqlite3.Row]:
        """Return the complete, supersedable decision history for an observation."""

        return self.conn.execute(
            "SELECT * FROM resolution_decisions WHERE observation_id=? "
            "ORDER BY sequence",
            (observation_id,),
        ).fetchall()

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row else default

    def delete_meta(self, *keys: str) -> None:
        """Remove transient run metadata before a paused/limited run resumes."""

        if not keys:
            return
        placeholders = ",".join("?" for _ in keys)
        self.conn.execute(f"DELETE FROM meta WHERE key IN ({placeholders})", keys)
        self.conn.commit()

    def _host_ids_for_aliases(self, aliases: list[tuple[str, str]]) -> list[int]:
        if not aliases:
            return []
        found: set[int] = set()
        for alias_type, value in aliases:
            if alias_type in {"ipv4", "ipv6"}:
                rows = self.conn.execute(
                    "SELECT host_id FROM host_addresses "
                    "WHERE address_type=? AND value=? AND identity_eligible=1 "
                    "ORDER BY host_id",
                    (alias_type, value),
                ).fetchall()
                # A repeated address is contested evidence.  Do not let it select
                # or merge every claimant; another unique name/MAC/chassis token
                # must identify the intended host.  A single-owner address retains
                # the historical useful behavior for seeds and ordinary devices.
                if len(rows) == 1:
                    found.add(int(rows[0][0]))
                continue
            row = self.conn.execute(
                "SELECT host_id FROM aliases WHERE alias_type=? AND value=?",
                (alias_type, value),
            ).fetchone()
            if row:
                found.add(int(row[0]))
        return sorted(found)

    def _identity_aliases_for_host(self, host_id: int) -> set[tuple[str, str]]:
        """Return all durable identity evidence known for one host.

        The global alias table can store only one owner for a normalized name or
        typed chassis identity. Addresses are retained separately as many-to-many
        observation claims because defaults, overlapping private space, and anycast
        values are not globally unique. During discovery, contradictory early
        observations can still create a temporary split host whose duplicate name
        is visible only in ``hosts.preferred_name`` or inbound neighbor evidence.
        Include all of those values here so a later bridge observation can safely
        reconcile the split when *both* logical name and management address agree.
        """

        rows = self.conn.execute(
            "SELECT alias_type, value FROM aliases "
            "WHERE host_id=? AND alias_type IN ('name', 'mac', 'chassis_id')",
            (host_id,),
        ).fetchall()
        evidence = {(str(row["alias_type"]), str(row["value"])) for row in rows}
        rows = self.conn.execute(
            "SELECT address_type, value FROM host_addresses "
            "WHERE host_id=? AND identity_eligible=1",
            (host_id,),
        ).fetchall()
        evidence.update(
            (str(row["address_type"]), str(row["value"])) for row in rows
        )

        host = self.conn.execute(
            "SELECT preferred_name FROM hosts WHERE id=?", (host_id,)
        ).fetchone()
        if host is not None and host["preferred_name"]:
            preferred_name = str(host["preferred_name"])
            name = normalize_identity_name(preferred_name)
            if name is not None:
                evidence.add(("name", name))
            sep_mac = cisco_sep_mac(preferred_name)
            if sep_mac is not None:
                evidence.add(("mac", sep_mac))
            ap_mac = cisco_ap_mac(preferred_name)
            if ap_mac is not None:
                evidence.add(("mac", ap_mac))

        # Preserve identity evidence that could not own a globally unique alias.
        # This is especially important for Nexus logical hosts that advertise the
        # same logical name through several link-specific chassis identities.
        rows = self.conn.execute(
            "SELECT observed_addresses_json FROM neighbors WHERE remote_host_id=?",
            (host_id,),
        ).fetchall()
        for row in rows:
            try:
                values = json.loads(str(row["observed_addresses_json"] or "[]"))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(values, list):
                continue
            for value in values:
                try:
                    address = normalize_host_address(str(value))
                except ValueError:
                    continue
                evidence.add(("ipv6" if ":" in address else "ipv4", address))
        return evidence

    def _logical_reconciliation_host_ids(
        self, candidate_aliases: list[tuple[str, str]]
    ) -> list[int]:
        """Find split hosts corroborated by candidate name *and* address evidence.

        This is intentionally narrower than ordinary alias lookup.  A duplicate
        preferred name by itself is never enough to pull another host into a merge;
        the candidate must also share a management address with evidence already
        observed for that host.  The rule lets a later bridge observation repair an
        order-dependent split without weakening duplicate-name safeguards.
        """

        candidate = set(candidate_aliases)
        names = {value for kind, value in candidate if kind == "name"}
        addresses = {
            (kind, value) for kind, value in candidate if kind in {"ipv4", "ipv6"}
        }
        if not names or not addresses:
            return []
        found: set[int] = set()
        for name in names:
            rows = self.conn.execute(
                "SELECT id FROM hosts WHERE preferred_name=? COLLATE NOCASE", (name,)
            ).fetchall()
            for row in rows:
                host_id = int(row["id"])
                existing = self._identity_aliases_for_host(host_id)
                existing_names = {value for kind, value in existing if kind == "name"}
                existing_addresses = {
                    (kind, value)
                    for kind, value in existing
                    if kind in {"ipv4", "ipv6"}
                }
                if names & existing_names and addresses & existing_addresses:
                    found.add(host_id)
        return sorted(found)

    def _identity_conflicts(
        self, host_id: int, candidate_aliases: list[tuple[str, str]]
    ) -> bool:
        """Return whether candidate evidence contradicts an established host.

        Strict Cisco ``SEP<12-hex>`` names contribute canonical ``mac`` aliases.
        When both sides have that hardware identity and the MAC sets are disjoint,
        the observations must remain separate even if they advertise the same IP
        address or network-address chassis ID. Some endpoint software reports a
        shared/default address across physically unrelated phones, so address
        agreement cannot override contradictory SEP hardware identity.

        Different trusted chassis identities are normally contradictory. Cisco
        Nexus VDCs are the main exception when exact normalized name plus address
        evidence agrees. Strict Cisco ``SEP<12-hex>`` names provide a second,
        narrower exception because both protocol observations independently encode
        the same endpoint MAC even if DNS suffix or network-address chassis data
        changes. A shared address by itself is no longer allowed to merge two
        incompatible direct names; repeated private/default addresses and DNS
        frontends are common enough that such a merge is more dangerous than a
        conservative split. A chassis-only match is still rejected when stronger
        corroborating evidence is absent.
        """

        existing = self._identity_aliases_for_host(host_id)
        candidate = set(candidate_aliases)
        shared = existing & candidate
        shared_names = {item for item in shared if item[0] == "name"}
        shared_addresses = {
            item for item in shared if item[0] in {"ipv4", "ipv6"}
        }
        shared_macs = {item for item in shared if item[0] == "mac"}
        existing_macs = {value for kind, value in existing if kind == "mac"}
        candidate_macs = {value for kind, value in candidate if kind == "mac"}
        existing_names = {value for kind, value in existing if kind == "name"}
        candidate_names = {value for kind, value in candidate if kind == "name"}

        # A strict SEP-derived MAC is stronger evidence than a shared address.
        # Check this before the generic shared-non-chassis fast path below;
        # otherwise one repeated/default phone address can transitively collapse
        # many distinct SEP endpoints into whichever host was observed first.
        if (
            existing_macs
            and candidate_macs
            and existing_macs.isdisjoint(candidate_macs)
        ):
            return True

        # Address equality is weak when both observations also carry direct names
        # that cannot describe the same logical host.  This prevents unrelated
        # devices behind a common DNS/load-balancer address, overlapping private
        # space, or a vendor default address from becoming one state host.  Exact
        # SEP/MAC or MAC-address chassis evidence can still override a name change.
        shared_mac_chassis = {
            value
            for kind, value in shared
            if kind == "chassis_id" and value.startswith("4:")
        }
        if (
            shared_addresses
            and existing_names
            and candidate_names
            and not _identity_name_sets_compatible(existing_names, candidate_names)
            and not shared_macs
            and not shared_mac_chassis
        ):
            return True

        existing_chassis = {value for kind, value in existing if kind == "chassis_id"}
        candidate_chassis = {value for kind, value in candidate if kind == "chassis_id"}
        if existing_chassis and candidate_chassis and existing_chassis.isdisjoint(
            candidate_chassis
        ):
            # Name *and* address agreement is deliberately stronger than a
            # per-link chassis disagreement.  Requiring both keeps duplicate-name
            # devices with different addresses separate, preserving the 0.30.3
            # false-consolidation safeguard.
            if not shared_macs and not (shared_names and shared_addresses):
                return True

        shared_non_chassis = {item for item in shared if item[0] != "chassis_id"}
        shared_chassis = {item for item in shared if item[0] == "chassis_id"}
        if not shared_chassis or shared_non_chassis:
            return False

        existing_addresses = {
            value for kind, value in existing if kind in {"ipv4", "ipv6"}
        }
        candidate_addresses = {
            value for kind, value in candidate if kind in {"ipv4", "ipv6"}
        }
        names_conflict = (
            bool(existing_names)
            and bool(candidate_names)
            and not _identity_name_sets_compatible(existing_names, candidate_names)
        )
        addresses_conflict = (
            bool(existing_addresses)
            and bool(candidate_addresses)
            and existing_addresses.isdisjoint(candidate_addresses)
        )
        return names_conflict and addresses_conflict

    @staticmethod
    def _query_projection_logical_names(row: sqlite3.Row) -> set[str]:
        """Return direct normalized system names for one managed projection.

        Duplicate-query prevention uses only the device's own SNMP name and the
        row's selected compatibility presentation. It does not compare the full
        alias set: DNS enrichment and neighbor-advertised aliases remain useful
        evidence, but they are too broad for a destructive within-run merge.

        Retaining both short and fully qualified direct forms lets one completed
        ``sysName`` projection absorb a still-ready FQDN projection before the
        latter performs redundant SNMP work. Two FQDNs are not equated merely by
        removing their suffixes; ``_identity_name_sets_compatible`` preserves that
        strict boundary.
        """

        try:
            system = json.loads(str(row["system_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            system = {}
        values = (
            system.get("sys_name") if isinstance(system, dict) else None,
            row["snmp_sysname"],
            row["preferred_name"],
        )
        return {
            normalized
            for value in values
            if (normalized := normalize_identity_name(str(value or ""))) is not None
        }

    @staticmethod
    def _system_identity_values(row: sqlite3.Row) -> tuple[str | None, str | None]:
        """Return normalized serial and SNMP-engine values from one host row.

        Duplicate query projections can be created while one worker owns the
        first projection and a later neighbor observation cannot safely merge it.
        A final reconciliation may repair that split, but it must retain the same
        hard identity boundary used by cross-run comparison: conflicting serials
        or SNMP engine IDs are never merged merely because a name and address were
        reused.
        """

        try:
            system = json.loads(str(row["system_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None, None
        if not isinstance(system, dict):
            return None, None

        def normalized(value: object) -> str | None:
            text = str(value or "").strip().casefold()
            return text or None

        return normalized(system.get("serial_number")), normalized(
            system.get("snmp_engine_id")
        )

    def _query_projection_identity_conflicts(
        self, left: sqlite3.Row, right: sqlite3.Row
    ) -> bool:
        """Return whether direct managed-projection evidence is contradictory.

        This check intentionally differs from the general candidate resolver's
        alias conflict gate.  A temporary duplicate query projection can carry a
        shadow preferred name and one link-specific chassis MAC while its SNMP
        ``sysName`` identifies the same logical Nexus VDC as another row.  Full
        neighbor/DNS alias sets are therefore too broad for this final repair.

        Direct logical names plus a shared identity-eligible address may tolerate
        different per-link chassis IDs.  Conflicting strict endpoint MACs, system
        serials, or SNMP engine IDs remain hard conflicts.  For transitive
        components, disjoint chassis IDs are tolerated only when the two rows
        themselves also share an address; a sparse bridge may not collapse two
        otherwise unrelated VDCs.
        """

        left_evidence = self._identity_aliases_for_host(int(left["id"]))
        right_evidence = self._identity_aliases_for_host(int(right["id"]))
        left_names = self._query_projection_logical_names(left)
        right_names = self._query_projection_logical_names(right)
        left_addresses = {
            (kind, value)
            for kind, value in left_evidence
            if kind in {"ipv4", "ipv6"}
        }
        right_addresses = {
            (kind, value)
            for kind, value in right_evidence
            if kind in {"ipv4", "ipv6"}
        }

        left_macs = {value for kind, value in left_evidence if kind == "mac"}
        right_macs = {value for kind, value in right_evidence if kind == "mac"}
        if left_macs and right_macs and left_macs.isdisjoint(right_macs):
            return True

        left_serial, left_engine = self._system_identity_values(left)
        right_serial, right_engine = self._system_identity_values(right)
        if left_serial and right_serial and left_serial != right_serial:
            return True
        if left_engine and right_engine and left_engine != right_engine:
            return True

        left_chassis = {
            value for kind, value in left_evidence if kind == "chassis_id"
        }
        right_chassis = {
            value for kind, value in right_evidence if kind == "chassis_id"
        }
        if left_chassis and right_chassis and left_chassis.isdisjoint(right_chassis):
            logical_corroboration = (
                _identity_name_sets_compatible(left_names, right_names)
                and bool(left_addresses & right_addresses)
            )
            if not logical_corroboration:
                return True
        return False

    def _query_projection_pair_is_equivalent(
        self, left: sqlite3.Row, right: sqlite3.Row
    ) -> bool:
        """Return whether two managed rows are duplicate query projections.

        Reconciliation requires compatible direct names and at least one shared
        identity-eligible host address.  Shared physical serial evidence alone is
        deliberately insufficient because separate Nexus VDC logical systems can
        reside in one chassis.  Conversely, per-link chassis IDs may differ when
        exact logical name and management-address evidence identify one VDC.
        """

        if str(left["classification"]) != "managed_device" or str(
            right["classification"]
        ) != "managed_device":
            return False

        left_names = self._query_projection_logical_names(left)
        right_names = self._query_projection_logical_names(right)
        if not left_names or not right_names:
            return False
        if not _identity_name_sets_compatible(left_names, right_names):
            return False

        left_evidence = self._identity_aliases_for_host(int(left["id"]))
        right_evidence = self._identity_aliases_for_host(int(right["id"]))
        left_addresses = {
            (kind, value)
            for kind, value in left_evidence
            if kind in {"ipv4", "ipv6"}
        }
        right_addresses = {
            (kind, value)
            for kind, value in right_evidence
            if kind in {"ipv4", "ipv6"}
        }
        if not (left_addresses & right_addresses):
            return False
        return not self._query_projection_identity_conflicts(left, right)

    @staticmethod
    def _query_projection_winner(rows: list[sqlite3.Row]) -> int:
        """Select the operationally strongest stable merge winner.

        Seed status and rank survive :meth:`_merge_hosts` even when the seed row
        is absorbed, so they must not outrank a successfully completed query.
        Likewise, a READY alternate must remain queryable when its equivalent
        projection failed.  Choosing FAILED ahead of READY would silently discard
        a still-usable route before the worker had a chance to try it.
        """

        state_priority = {
            "COMPLETE": 0,
            "READY": 1,
            "DISCOVERED": 2,
            "FAILED": 3,
            "NO_QUERY": 4,
            "OUT_OF_SCOPE": 5,
        }
        return int(
            min(
                rows,
                key=lambda row: (
                    state_priority.get(str(row["state"]), 99),
                    0 if int(row["is_seed"]) else 1,
                    int(row["seed_rank"])
                    if row["seed_rank"] is not None
                    else 2**31,
                    int(row["id"]),
                ),
            )["id"]
        )

    def _reconcile_duplicate_query_projections_uncommitted(self) -> dict[int, int]:
        """Merge inactive duplicate managed-host projections conservatively.

        The coordinator owns host IDs while workers are active, so no component
        containing an active row is modified here. Completed projections may be
        absorbed after workers stop: immutable protocol advertisements retain
        their original source host IDs and embedded source context, allowing graph
        materialization to recreate factual source agents after the compatibility
        row is retired.

        ``claim_batch`` invokes this pass before selecting new work, and
        finalization invokes it again after workers stop. The returned mapping
        records each absorbed ID for telemetry and focused tests.
        """

        rows = self.conn.execute(
            "SELECT * FROM hosts WHERE classification='managed_device' ORDER BY id"
        ).fetchall()
        by_id = {int(row["id"]): row for row in rows}
        address_rows = self.conn.execute(
            "SELECT address_type, value, host_id FROM host_addresses "
            "WHERE identity_eligible=1 ORDER BY address_type, value, host_id"
        ).fetchall()
        owners: dict[tuple[str, str], list[int]] = {}
        for row in address_rows:
            host_id = int(row["host_id"])
            if host_id not in by_id:
                continue
            owners.setdefault((str(row["address_type"]), str(row["value"])), []).append(
                host_id
            )

        parent = {host_id: host_id for host_id in by_id}

        def find(value: int) -> int:
            while parent[value] != value:
                parent[value] = parent[parent[value]]
                value = parent[value]
            return value

        def union(left_id: int, right_id: int) -> None:
            left_root = find(left_id)
            right_root = find(right_id)
            if left_root != right_root:
                parent[max(left_root, right_root)] = min(left_root, right_root)

        checked: set[tuple[int, int]] = set()
        for host_ids in owners.values():
            unique = sorted(set(host_ids))
            for index, left_id in enumerate(unique):
                for right_id in unique[index + 1 :]:
                    pair = (left_id, right_id)
                    if pair in checked:
                        continue
                    checked.add(pair)
                    if self._query_projection_pair_is_equivalent(
                        by_id[left_id], by_id[right_id]
                    ):
                        union(left_id, right_id)

        components: dict[int, list[int]] = {}
        for host_id in by_id:
            components.setdefault(find(host_id), []).append(host_id)

        absorbed: dict[int, int] = {}
        for host_ids in sorted(components.values(), key=lambda values: min(values)):
            if len(host_ids) < 2:
                continue
            component_rows = [by_id[host_id] for host_id in host_ids]
            if any(str(row["state"]) in ACTIVE_STATES for row in component_rows):
                continue

            # A sparse projection can bridge two rows that do not directly share
            # an address.  That bridge is useful only when the complete component
            # has one compatible logical identity.  Conflicting names, strict
            # MAC/chassis evidence, serials, or SNMP engine IDs make the component
            # ambiguous, so retain every row instead of allowing union-find
            # transitivity to collapse contradictory devices.
            component_conflict = False
            for index, left in enumerate(component_rows):
                left_names = self._query_projection_logical_names(left)
                for right in component_rows[index + 1 :]:
                    right_names = self._query_projection_logical_names(right)
                    if (
                        not _identity_name_sets_compatible(left_names, right_names)
                        or self._query_projection_identity_conflicts(left, right)
                    ):
                        component_conflict = True
                        break
                if component_conflict:
                    break
            if component_conflict:
                continue

            winner = self._query_projection_winner(component_rows)
            for loser in sorted(host_ids):
                if loser == winner:
                    continue
                self._merge_hosts(winner, loser)
                absorbed[loser] = winner
        return absorbed

    def reconcile_duplicate_query_projections(self) -> dict[int, int]:
        """Run the conservative duplicate-projection repair as one transaction."""

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            absorbed = self._reconcile_duplicate_query_projections_uncommitted()
            self.conn.commit()
            return absorbed
        except Exception:
            self.conn.rollback()
            raise

    def _has_active_equivalent_projection_uncommitted(self, host_id: int) -> bool:
        """Return whether an active worker already owns an equivalent projection."""

        row = self.conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
        if row is None:
            return False
        candidates = self.conn.execute(
            "SELECT DISTINCT h.* FROM hosts h "
            "JOIN host_addresses candidate ON candidate.host_id=? "
            "JOIN host_addresses active ON active.address_type=candidate.address_type "
            "AND active.value=candidate.value AND active.identity_eligible=1 "
            "WHERE candidate.identity_eligible=1 AND h.id=active.host_id "
            "AND h.id<>? AND h.state IN ('CLAIMED','PINGING','SNMP_BASIC',"
            "'SNMP_DETAIL','NEIGHBOR_DISCOVERY') ORDER BY h.id",
            (host_id, host_id),
        ).fetchall()
        return any(self._query_projection_pair_is_equivalent(row, item) for item in candidates)

    def upsert_candidate(
        self,
        candidate: Candidate,
        *,
        preferred_name: str | None = None,
        is_seed: bool = False,
        seed_rank: int | None = None,
        synthetic_alias: str | None = None,
    ) -> int:
        identity_addresses = (
            candidate.identity_addresses
            if candidate.identity_addresses is not None
            else candidate.addresses
        )
        aliases = alias_tuples(
            candidate.identity_names
            if candidate.identity_names is not None
            else candidate.names,
            identity_addresses,
            candidate.chassis_id,
            candidate.chassis_id_subtype,
            candidate.chassis_id_subtype_id,
        )
        # LLDP subtype 7 is locally assigned and cannot safely identify a host
        # across the network.  For an otherwise anonymous endpoint, an explicitly
        # typed MAC-address Port ID is the bounded identity used by the topology
        # graph as well.  Named/addressed devices never take this fallback.
        if not aliases:
            endpoint_mac = anonymous_endpoint_port_mac(
                names=(
                    candidate.identity_names
                    if candidate.identity_names is not None
                    else candidate.names
                ),
                addresses=identity_addresses,
                chassis_id=candidate.chassis_id,
                chassis_id_subtype=candidate.chassis_id_subtype,
                chassis_id_subtype_id=candidate.chassis_id_subtype_id,
                details=candidate.details,
            )
            if endpoint_mac is not None:
                aliases = [("mac", endpoint_mac)]
        identity_address_claims = {
            item for item in aliases if item[0] in {"ipv4", "ipv6"}
        }
        all_address_claims = {
            item
            for item in alias_tuples([], candidate.addresses)
            if item[0] in {"ipv4", "ipv6"}
        }
        # Only direct management addresses enter the compatibility projection.
        # LLDP network-address chassis values remain immutable edge-scoped
        # claims and raw protocol evidence, but are not host address aliases.
        all_address_claims.update(identity_address_claims)
        if not aliases and synthetic_alias:
            aliases = [("observation", synthetic_alias)]
        if not aliases:
            raise ValueError("candidate has no usable identity")
        evidence_claims = candidate_claims(candidate, is_seed=is_seed)
        observation_payload = candidate_observation_payload(
            candidate,
            preferred_name=preferred_name,
            synthetic_alias=synthetic_alias,
            is_seed=is_seed,
        )
        now = iso_now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            observation_id, observation_fingerprint = (
                self._record_observation_uncommitted(
                    observation_payload,
                    source_host_id=candidate.source_host_id,
                    protocol=candidate.protocol,
                    observed_at=now,
                )
            )
            claim_ids = self._record_claims_uncommitted(
                observation_id, observation_fingerprint, evidence_claims
            )
            matched_host_ids = sorted(
                set(self._host_ids_for_aliases(aliases))
                | set(self._logical_reconciliation_host_ids(aliases))
            )
            host_ids = list(matched_host_ids)
            if not host_ids and synthetic_alias and aliases:
                # A contested address intentionally has more than one claimant,
                # so ordinary address lookup cannot select either host.  An
                # edge-specific observation alias may recover the same prior
                # candidate, but only when the current candidate still shares
                # some normal identity evidence with that host.  This keeps a
                # temporarily missing name from creating a fresh host on every
                # observation without allowing an old edge key to merge a true
                # endpoint replacement whose identity evidence is disjoint.
                observation_row = self.conn.execute(
                    "SELECT host_id FROM aliases "
                    "WHERE alias_type='observation' AND value=?",
                    (synthetic_alias,),
                ).fetchone()
                if observation_row is not None:
                    observation_host_id = int(observation_row["host_id"])
                    existing = self._identity_aliases_for_host(observation_host_id)
                    if set(aliases) & existing:
                        host_ids = [observation_host_id]
            rejected_identity_match = False
            rejected_host_ids: list[int] = []
            if host_ids:
                compatible_ids = [
                    host_id
                    for host_id in host_ids
                    if not self._identity_conflicts(host_id, aliases)
                ]
                rejected_host_ids = [
                    host_id for host_id in host_ids if host_id not in compatible_ids
                ]
                rejected_identity_match = bool(host_ids and not compatible_ids)
                host_ids = compatible_ids
            merged_host_ids: list[int] = []
            created_projection = False
            if host_ids:
                # Never collapse an identity row that may currently be owned by a
                # worker. A later observation can reconcile the rows after the
                # active claim completes. This avoids invalidating in-flight host IDs.
                state_rows = {
                    host_id: self.conn.execute(
                        "SELECT state FROM hosts WHERE id=?", (host_id,)
                    ).fetchone()
                    for host_id in host_ids
                }
                active_ids = [
                    host_id
                    for host_id, state_row in state_rows.items()
                    if state_row is not None and str(state_row["state"]) in ACTIVE_STATES
                ]
                if active_ids:
                    host_id = active_ids[0]
                else:
                    priority = {
                        "COMPLETE": 0,
                        "FAILED": 1,
                        "READY": 2,
                        "NO_QUERY": 3,
                        "OUT_OF_SCOPE": 4,
                        "DISCOVERED": 5,
                    }
                    host_id = min(
                        host_ids,
                        key=lambda value: (
                            priority.get(str(state_rows[value]["state"]), 99)
                            if state_rows[value] is not None
                            else 99,
                            value,
                        ),
                    )
                    for loser in host_ids:
                        if loser != host_id:
                            merged_host_ids.append(loser)
                            self._merge_hosts(host_id, loser)
            else:
                created_projection = True
                presentation = preferred_name or self._best_name(candidate.names, candidate.addresses)
                self.conn.execute(
                    """
                    INSERT INTO hosts(
                        preferred_name, classification, classification_reason_json,
                        state, is_seed, seed_rank, first_seen, last_seen, last_seen_source, updated_at
                    ) VALUES(?, ?, ?, 'DISCOVERED', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        presentation,
                        candidate.category,
                        json.dumps(candidate.reason),
                        1 if is_seed else 0,
                        seed_rank if is_seed else None,
                        now,
                        now if candidate.source_host_id is not None else None,
                        candidate.protocol if candidate.source_host_id is not None else None,
                        now,
                    ),
                )
                host_id = int(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])
                # If otherwise matching aliases were rejected as contradictory,
                # retain an observation-specific alias when available.  Duplicate
                # name/chassis aliases remain owned by the established host, while
                # the new record still has a durable identity for this run.
                if rejected_identity_match and synthetic_alias:
                    aliases = [*aliases, ("observation", synthetic_alias)]

            for alias_type, value in aliases:
                if alias_type in {"ipv4", "ipv6"}:
                    continue
                self.conn.execute(
                    "INSERT OR IGNORE INTO aliases(alias_type, value, host_id) "
                    "VALUES(?, ?, ?)",
                    (alias_type, value, host_id),
                )
            for address_type, value in sorted(all_address_claims):
                eligible = 1 if (address_type, value) in identity_address_claims else 0
                self.conn.execute(
                    "INSERT INTO host_addresses("
                    "address_type, value, host_id, identity_eligible"
                    ") VALUES(?, ?, ?, ?) "
                    "ON CONFLICT(address_type, value, host_id) DO UPDATE SET "
                    "identity_eligible=MAX(host_addresses.identity_eligible, "
                    "excluded.identity_eligible)",
                    (address_type, value, host_id, eligible),
                )
            # Keep a case-preserving display copy only when this host actually owns
            # the accepted chassis identity alias.  Malformed values, and a reused
            # chassis alias rejected because other evidence conflicts, remain only
            # in neighbor observation details.
            chassis_aliases = [
                value for alias_type, value in aliases if alias_type == "chassis_id"
            ]
            owns_chassis_alias = any(
                self.conn.execute(
                    "SELECT 1 FROM aliases WHERE alias_type='chassis_id' "
                    "AND value=? AND host_id=?",
                    (value, host_id),
                ).fetchone()
                is not None
                for value in chassis_aliases
            )
            if owns_chassis_alias and candidate.chassis_id is not None:
                self.conn.execute(
                    "INSERT OR IGNORE INTO aliases(alias_type, value, host_id) "
                    "VALUES('chassis_display', ?, ?)",
                    (candidate.chassis_id.strip(), host_id),
                )
            self._add_tags_uncommitted(host_id, candidate.tags)

            row = self.conn.execute(
                "SELECT classification, classification_reason_json, preferred_name, is_seed, seed_rank FROM hosts WHERE id=?",
                (host_id,),
            ).fetchone()
            assert row is not None
            existing_category = str(row["classification"])
            category = self._merge_category(
                existing_category,
                candidate.category,
                is_seed,
                explicit=any(reason.startswith("explicit ") for reason in candidate.reason),
            )
            reasons = list(json.loads(row["classification_reason_json"] or "[]"))
            for reason in candidate.reason:
                if reason not in reasons:
                    reasons.append(reason)
            presentation = self._prefer_presentation(
                str(row["preferred_name"]),
                preferred_name or self._best_name(candidate.names, candidate.addresses),
            )
            existing_seed_rank = row["seed_rank"]
            merged_seed_rank = existing_seed_rank
            if is_seed and seed_rank is not None:
                merged_seed_rank = (
                    seed_rank
                    if existing_seed_rank is None
                    else min(int(existing_seed_rank), seed_rank)
                )
            self.conn.execute(
                """
                UPDATE hosts SET preferred_name=?, classification=?,
                    classification_reason_json=?, is_seed=?, seed_rank=?,
                    last_seen=CASE WHEN ? IS NOT NULL THEN ? ELSE last_seen END,
                    last_seen_source=CASE WHEN ? IS NOT NULL THEN ? ELSE last_seen_source END,
                    updated_at=? WHERE id=?
                """,
                (
                    presentation,
                    category,
                    json.dumps(reasons),
                    1 if (is_seed or int(row["is_seed"])) else 0,
                    merged_seed_rank,
                    candidate.source_host_id,
                    now,
                    candidate.source_host_id,
                    candidate.protocol,
                    now,
                    host_id,
                ),
            )

            decision_rationale = ["candidate evidence projected to one host"]
            if created_projection:
                decision_rationale.append("no compatible existing projection was selected")
            if merged_host_ids:
                decision_rationale.append(
                    "compatible inactive host projections were consolidated"
                )
            if rejected_host_ids:
                decision_rationale.append(
                    "contradictory strong or scoped evidence rejected one or more candidates"
                )
            conflicting_claim_ids = [
                claim_id
                for claim, claim_id in zip(evidence_claims, claim_ids, strict=True)
                if rejected_host_ids and claim.strength == "strong"
            ]
            self._record_resolution_decision_uncommitted(
                observation_id,
                decision_type=(
                    "projected_host_with_conflict"
                    if rejected_host_ids
                    else "projected_host"
                ),
                projected_host_id=host_id,
                candidate_host_ids=[
                    host_id,
                    *matched_host_ids,
                    *rejected_host_ids,
                    *merged_host_ids,
                ],
                confidence=self._claim_confidence(evidence_claims),
                rationale=decision_rationale,
                supporting_claim_ids=claim_ids,
                conflicting_claim_ids=conflicting_claim_ids,
                coalesce_same_outcome=True,
            )
            self.conn.commit()
            return host_id
        except Exception:
            self.conn.rollback()
            raise

    @staticmethod
    def _best_name(names: list[str], addresses: list[str]) -> str:
        if names:
            return next((x for x in names if "." in x), names[0])
        if addresses:
            return addresses[0]
        return "unknown"

    @staticmethod
    def _prefer_presentation(existing: str, candidate: str) -> str:
        if "." in candidate and not "." in existing and ":" not in candidate:
            return candidate
        if existing in {"unknown", ""}:
            return candidate
        return existing

    @staticmethod
    def _merge_category(
        existing: str, candidate: str, is_seed: bool, *, explicit: bool = False
    ) -> str:
        if is_seed:
            return "managed_device"
        if explicit:
            return candidate
        if existing == "unknown_device" and candidate != "unknown_device":
            return candidate
        return existing

    def _merge_hosts(self, winner: int, loser: int) -> None:
        if winner == loser:
            return
        loser_row = self.conn.execute("SELECT * FROM hosts WHERE id=?", (loser,)).fetchone()
        winner_row = self.conn.execute("SELECT * FROM hosts WHERE id=?", (winner,)).fetchone()
        if loser_row is None or winner_row is None:
            return
        rows = self.conn.execute(
            "SELECT * FROM neighbors WHERE source_host_id=? OR remote_host_id=?", (loser, loser)
        ).fetchall()
        for row in rows:
            source = winner if int(row["source_host_id"]) == loser else int(row["source_host_id"])
            remote = winner if int(row["remote_host_id"]) == loser else int(row["remote_host_id"])
            if source == remote:
                continue
            self.conn.execute(
                """
                INSERT OR IGNORE INTO neighbors(
                    source_host_id, remote_host_id, protocols, local_interface,
                    local_interface_raw, remote_interface, remote_interface_raw,
                    observed_name, observed_addresses_json, details_json, last_seen
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source,
                    remote,
                    row["protocols"],
                    row["local_interface"],
                    row["local_interface_raw"],
                    row["remote_interface"],
                    row["remote_interface_raw"],
                    row["observed_name"],
                    row["observed_addresses_json"],
                    row["details_json"],
                    row["last_seen"],
                ),
            )
        self.conn.execute("DELETE FROM neighbors WHERE source_host_id=? OR remote_host_id=?", (loser, loser))
        # A duplicate projection may carry an alias already owned by the winner.
        # Copy with conflict suppression before deleting the loser instead of a
        # direct UPDATE that could violate the aliases primary key.
        self.conn.execute(
            "INSERT OR IGNORE INTO aliases(alias_type, value, host_id) "
            "SELECT alias_type, value, ? FROM aliases WHERE host_id=?",
            (winner, loser),
        )
        self.conn.execute("DELETE FROM aliases WHERE host_id=?", (loser,))
        self.conn.execute(
            "INSERT INTO host_addresses("
            "address_type, value, host_id, identity_eligible"
            ") SELECT address_type, value, ?, identity_eligible "
            "FROM host_addresses WHERE host_id=? "
            "ON CONFLICT(address_type, value, host_id) DO UPDATE SET "
            "identity_eligible=MAX(host_addresses.identity_eligible, "
            "excluded.identity_eligible)",
            (winner, loser),
        )
        self.conn.execute("DELETE FROM host_addresses WHERE host_id=?", (loser,))
        loser_tags = self.conn.execute(
            "SELECT tag FROM host_tags WHERE host_id=? ORDER BY id", (loser,)
        ).fetchall()
        self._add_tags_uncommitted(winner, [str(row["tag"]) for row in loser_tags])
        self.conn.execute("DELETE FROM host_tags WHERE host_id=?", (loser,))
        self.conn.execute("UPDATE errors SET host_id=? WHERE host_id=?", (winner, loser))
        # Route history must survive identity reconciliation without multiplying
        # an address/credential attempt.  Reinsert through the canonical unique
        # index before deleting the losing projection.
        loser_routes = self.conn.execute(
            "SELECT * FROM route_attempts WHERE host_id=? ORDER BY id", (loser,)
        ).fetchall()
        for route in loser_routes:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO route_attempts(
                    host_id, attempted_target, address_family,
                    credential_profile, credential_stage, credential_source,
                    credential_label, attempt, outcome, category, recorded_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    winner,
                    route["attempted_target"],
                    route["address_family"],
                    route["credential_profile"],
                    route["credential_stage"],
                    route["credential_source"],
                    route["credential_label"],
                    route["attempt"],
                    route["outcome"],
                    route["category"],
                    route["recorded_at"],
                ),
            )
        self.conn.execute("DELETE FROM route_attempts WHERE host_id=?", (loser,))
        self.conn.execute(
            "UPDATE scheduler_events SET host_id=? WHERE host_id=?", (winner, loser)
        )
        merged_category = self._merge_category(
            str(winner_row["classification"]),
            str(loser_row["classification"]),
            bool(loser_row["is_seed"]),
        )

        # Identity correlation can merge records that learned complementary pieces
        # of the same device.  Preserve successful query metadata instead of losing
        # it merely because the presentation/alias record selected as the winner was
        # created first.  A COMPLETE winner only accepts a query target from another
        # COMPLETE record; copying a failed attempt would falsely claim that address
        # was the successful target.
        winner_state = str(winner_row["state"])
        loser_state = str(loser_row["state"])
        can_copy_query_result = winner_state != "COMPLETE" or loser_state == "COMPLETE"
        query_target = winner_row["query_target"]
        credential_profile = winner_row["credential_profile"]
        credential_source = winner_row["credential_source"]
        credential_label = winner_row["credential_label"]
        credential_result = winner_row["credential_result"]
        if can_copy_query_result:
            query_target = query_target or loser_row["query_target"]
            credential_profile = credential_profile or loser_row["credential_profile"]
            credential_source = credential_source or loser_row["credential_source"]
            credential_label = credential_label or loser_row["credential_label"]
            credential_result = credential_result or loser_row["credential_result"]

        copy_complete_result = winner_state != "COMPLETE" and loser_state == "COMPLETE"
        merged_state = "COMPLETE" if copy_complete_result else winner_state
        snmp_sysname = winner_row["snmp_sysname"] or loser_row["snmp_sysname"]
        winner_ping = str(winner_row["ping_json"] or "[]")
        loser_ping = str(loser_row["ping_json"] or "[]")
        ping_json = (
            loser_ping
            if copy_complete_result or (winner_ping == "[]" and loser_ping != "[]")
            else winner_ping
        )
        winner_system = str(winner_row["system_json"] or "{}")
        loser_system = str(loser_row["system_json"] or "{}")
        system_json = (
            loser_system
            if copy_complete_result or (winner_system == "{}" and loser_system != "{}")
            else winner_system
        )
        winner_metrics = str(winner_row["metrics_json"] or "{}")
        loser_metrics = str(loser_row["metrics_json"] or "{}")
        metrics_json = (
            loser_metrics
            if copy_complete_result or (winner_metrics == "{}" and loser_metrics != "{}")
            else winner_metrics
        )
        winner_sessions = str(winner_row["snmp_sessions_json"] or "[]")
        loser_sessions = str(loser_row["snmp_sessions_json"] or "[]")
        snmp_sessions_json = (
            loser_sessions
            if copy_complete_result
            or (winner_sessions == "[]" and loser_sessions != "[]")
            else winner_sessions
        )
        winner_interfaces = str(winner_row["interface_groups_json"] or "[]")
        loser_interfaces = str(loser_row["interface_groups_json"] or "[]")
        interface_groups_json = (
            loser_interfaces
            if copy_complete_result
            or (winner_interfaces == "[]" and loser_interfaces != "[]")
            else winner_interfaces
        )
        winner_coverage = str(winner_row["collection_coverage_json"] or "{}")
        loser_coverage = str(loser_row["collection_coverage_json"] or "{}")
        collection_coverage_json = (
            loser_coverage
            if copy_complete_result
            or (winner_coverage == "{}" and loser_coverage != "{}")
            else winner_coverage
        )
        seed_ranks = [
            int(value)
            for value in (winner_row["seed_rank"], loser_row["seed_rank"])
            if value is not None
        ]
        seed_rank = min(seed_ranks) if seed_ranks else None
        late_recovery_used = max(
            int(winner_row["late_recovery_used"] or 0),
            int(loser_row["late_recovery_used"] or 0),
        )
        self.conn.execute(
            """
            UPDATE hosts SET state=?, worker_id=NULL, lease_until=NULL,
                classification=?, is_seed=?, seed_rank=?, query_target=?,
                credential_profile=?, credential_source=?, credential_label=?,
                credential_result=?, snmp_sysname=?,
                ping_json=?, system_json=?, metrics_json=?, snmp_sessions_json=?,
                interface_groups_json=?, collection_coverage_json=?,
                late_recovery_used=?, last_seen=COALESCE(last_seen, ?),
                last_seen_source=COALESCE(last_seen_source, ?), updated_at=?
            WHERE id=?
            """,
            (
                merged_state,
                merged_category,
                1 if int(winner_row["is_seed"]) or int(loser_row["is_seed"]) else 0,
                seed_rank,
                query_target,
                credential_profile,
                credential_source,
                credential_label,
                credential_result,
                snmp_sysname,
                ping_json,
                system_json,
                metrics_json,
                snmp_sessions_json,
                interface_groups_json,
                collection_coverage_json,
                late_recovery_used,
                loser_row["last_seen"],
                loser_row["last_seen_source"],
                iso_now(),
                winner,
            ),
        )
        winner_req = self.conn.execute(
            "SELECT 1 FROM seed_credential_requirements WHERE host_id=?", (winner,)
        ).fetchone()
        if winner_req is None:
            self.conn.execute(
                "UPDATE seed_credential_requirements SET host_id=? WHERE host_id=?",
                (winner, loser),
            )
        else:
            self.conn.execute(
                "DELETE FROM seed_credential_requirements WHERE host_id=?", (loser,)
            )
        self.conn.execute("DELETE FROM hosts WHERE id=?", (loser,))

    def _add_tags_uncommitted(self, host_id: int, tags: Iterable[str]) -> None:
        for tag in tags:
            value = str(tag).strip()
            if not value:
                continue
            self.conn.execute(
                "INSERT OR IGNORE INTO host_tags(host_id, tag) VALUES(?, ?)",
                (host_id, value),
            )

    def add_tags(self, host_id: int, tags: Iterable[str]) -> None:
        self._add_tags_uncommitted(host_id, tags)
        self.conn.commit()

    def tags_for_host(self, host_id: int) -> list[str]:
        rows = self.conn.execute(
            "SELECT tag FROM host_tags WHERE host_id=? ORDER BY id", (host_id,)
        ).fetchall()
        return [str(row["tag"]) for row in rows]

    def aliases_for_host(self, host_id: int) -> tuple[list[str], list[str], str | None]:
        rows = self.conn.execute(
            "SELECT alias_type, value FROM aliases WHERE host_id=? ORDER BY alias_type, value", (host_id,)
        ).fetchall()
        names: list[str] = []
        addresses: list[str] = []
        chassis: str | None = None
        chassis_display: str | None = None
        for row in rows:
            alias_type, value = str(row["alias_type"]), str(row["value"])
            if alias_type == "name":
                names.append(value)
            elif alias_type in {"ipv4", "ipv6"}:
                addresses.append(value)
            elif alias_type == "chassis_id":
                chassis = value
            elif alias_type == "chassis_display":
                chassis_display = value
        address_rows = self.conn.execute(
            "SELECT address_type, value FROM host_addresses "
            "WHERE host_id=? ORDER BY address_type, value",
            (host_id,),
        ).fetchall()
        addresses.extend(str(row["value"]) for row in address_rows)
        return names, addresses, chassis_display or chassis

    def identity_addresses_for_host(self, host_id: int) -> list[str]:
        """Return direct host-eligible management evidence only."""

        rows = self.conn.execute(
            "SELECT value FROM host_addresses WHERE host_id=? "
            "AND identity_eligible=1 ORDER BY address_type, value",
            (host_id,),
        ).fetchall()
        return [str(row["value"]) for row in rows]

    def pending_late_recovery_addresses(self, host_id: int) -> list[str]:
        """Return addresses from the latest durable late-recovery admission."""

        row = self.conn.execute(
            "SELECT payload_json FROM scheduler_events WHERE host_id=? "
            "AND event_type='late_address_recovery_admitted' "
            "ORDER BY id DESC LIMIT 1",
            (host_id,),
        ).fetchone()
        if row is None:
            return []
        try:
            payload = json.loads(str(row["payload_json"] or "{}"))
        except json.JSONDecodeError:
            return []
        values = payload.get("new_addresses") if isinstance(payload, dict) else None
        if not isinstance(values, list):
            return []
        result: list[str] = []
        for value in values:
            normalized = self._normalized_route_target(str(value))
            if normalized is not None and normalized[0] not in result:
                result.append(normalized[0])
        return result

    def host_row(self, host_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
        if row is None:
            raise KeyError(host_id)
        return row

    def set_host_ready(self, host_id: int, cohort: int) -> None:
        row = self.host_row(host_id)
        state = str(row["state"])
        if state == "READY" or state in ACTIVE_STATES:
            return
        if state in TERMINAL_STATES and state not in {"NO_QUERY", "OUT_OF_SCOPE"}:
            return
        self.conn.execute(
            "UPDATE hosts SET state='READY', cohort=?, worker_id=NULL, lease_until=NULL, updated_at=? WHERE id=?",
            (cohort, iso_now(), host_id),
        )
        self.conn.commit()

    def set_host_no_query(self, host_id: int, state: str = "NO_QUERY") -> None:
        self.conn.execute(
            "UPDATE hosts SET state=?, worker_id=NULL, lease_until=NULL, updated_at=? WHERE id=?",
            (state, iso_now(), host_id),
        )
        self.conn.commit()

    def claim_batch(
        self,
        worker_id: int,
        batch_size: int,
        lease_seconds: int,
        *,
        allow_steal: bool,
        exclude_host_ids: Iterable[int] = (),
    ) -> list[int]:
        lease_until = iso_after(lease_seconds)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            # Repair inactive split projections before they can become parallel
            # work. A row equivalent to an already active projection is retained
            # for that worker to finish, but is not claimed by another worker.
            self._reconcile_duplicate_query_projections_uncommitted()
            # Seed order is global rather than per cohort. Otherwise each worker
            # would consume a different hash cohort and requested sorted/random
            # sampling would not actually begin from the consolidated sequence.
            # After all READY seeds are claimed, normal recursive work returns to
            # deterministic cohort assignment with optional stealing.
            rows = self.conn.execute(
                "SELECT id FROM hosts WHERE state='READY' AND is_seed=1 "
                "ORDER BY seed_rank, id",
            ).fetchall()
            if not rows:
                rows = self.conn.execute(
                    "SELECT id FROM hosts WHERE state='READY' AND is_seed=0 "
                    "AND cohort=? ORDER BY id",
                    (worker_id,),
                ).fetchall()
            if not rows and allow_steal:
                rows = self.conn.execute(
                    "SELECT id FROM hosts WHERE state='READY' AND is_seed=0 "
                    "ORDER BY id",
                ).fetchall()
            excluded = {int(value) for value in exclude_host_ids}
            ids: list[int] = []
            for row in rows:
                host_id = int(row[0])
                if host_id in excluded:
                    continue
                if self._has_active_equivalent_projection_uncommitted(host_id):
                    continue
                ids.append(host_id)
                if len(ids) >= batch_size:
                    break
            if ids:
                placeholders = ",".join("?" for _ in ids)
                self.conn.execute(
                    f"UPDATE hosts SET state='CLAIMED', worker_id=?, lease_until=?, updated_at=? "
                    f"WHERE id IN ({placeholders}) AND state='READY'",
                    (worker_id, lease_until, iso_now(), *ids),
                )
            self.conn.commit()
            return ids
        except Exception:
            self.conn.rollback()
            raise

    def defer_host(self, host_id: int) -> None:
        self.conn.execute(
            "UPDATE hosts SET state='READY', worker_id=NULL, lease_until=NULL, updated_at=? WHERE id=?",
            (iso_now(), host_id),
        )
        self.conn.commit()

    def normalize_cohorts(self, workers: int) -> None:
        if workers < 1:
            raise ValueError("workers must be >= 1")
        self.conn.execute("UPDATE hosts SET cohort = cohort % ?", (workers,))
        self.conn.commit()

    def reset_active_claims(self) -> int:
        placeholders = ",".join("?" for _ in ACTIVE_STATES)
        cur = self.conn.execute(
            f"UPDATE hosts SET state='READY', worker_id=NULL, lease_until=NULL, updated_at=? "
            f"WHERE state IN ({placeholders})",
            (iso_now(), *ACTIVE_STATES),
        )
        self.conn.commit()
        return int(cur.rowcount)

    def add_neighbor(self, source_host_id: int, remote_host_id: int, obs: NeighborObservation) -> None:
        protocols = obs.details.get("protocols", [obs.protocol])
        edge_details = dict(obs.details)
        if obs.remote_description:
            edge_details["remote_description"] = obs.remote_description
        if obs.remote_platform:
            edge_details["remote_platform"] = obs.remote_platform
        if obs.capabilities:
            edge_details["capabilities"] = list(obs.capabilities)
        if obs.chassis_id:
            edge_details["chassis_id"] = obs.chassis_id
        if obs.chassis_id_subtype:
            edge_details["chassis_id_subtype"] = obs.chassis_id_subtype
        if obs.chassis_id_subtype_id is not None:
            edge_details["chassis_id_subtype_id"] = obs.chassis_id_subtype_id
        now = iso_now()
        self.conn.execute(
            """
            INSERT INTO neighbors(
                source_host_id, remote_host_id, protocols, local_interface,
                local_interface_raw, remote_interface, remote_interface_raw,
                observed_name, observed_addresses_json, details_json, last_seen
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_host_id, remote_host_id, local_interface, remote_interface)
            DO UPDATE SET
                protocols=excluded.protocols,
                local_interface_raw=COALESCE(excluded.local_interface_raw, neighbors.local_interface_raw),
                remote_interface_raw=COALESCE(excluded.remote_interface_raw, neighbors.remote_interface_raw),
                observed_name=COALESCE(excluded.observed_name, neighbors.observed_name),
                observed_addresses_json=excluded.observed_addresses_json,
                details_json=excluded.details_json,
                last_seen=excluded.last_seen
            """,
            (
                source_host_id,
                remote_host_id,
                ",".join(protocols),
                obs.local_interface or "",
                obs.local_interface_raw,
                obs.remote_interface or "",
                obs.remote_interface_raw,
                obs.remote_name,
                json.dumps(obs.remote_addresses),
                json.dumps(edge_details, default=str),
                now,
            ),
        )
        self.conn.execute(
            "UPDATE hosts SET last_seen=?, last_seen_source=?, updated_at=? WHERE id=?",
            (now, obs.protocol, now, remote_host_id),
        )
        self.conn.commit()

    @staticmethod
    def _normalized_route_target(value: str) -> tuple[str, str] | None:
        """Return a canonical host-eligible target and stable family label."""

        try:
            normalized = normalize_host_address(value)
        except ValueError:
            return None
        family = "ipv6" if ":" in normalized else "ipv4"
        return normalized, family

    def _record_route_attempt_uncommitted(
        self,
        *,
        host_id: int,
        attempted_target: str,
        credential_profile: str | None,
        credential_stage: str | None,
        credential_source: str | None,
        credential_label: str | None,
        attempt: int | None,
        outcome: str,
        category: str | None,
        recorded_at: str,
    ) -> None:
        """Persist one non-secret address/credential route outcome once."""

        normalized = self._normalized_route_target(attempted_target)
        if normalized is None:
            return
        target, family = normalized
        self.conn.execute(
            """
            INSERT OR IGNORE INTO route_attempts(
                host_id, attempted_target, address_family,
                credential_profile, credential_stage, credential_source,
                credential_label, attempt, outcome, category, recorded_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                host_id,
                target,
                family,
                credential_profile,
                credential_stage,
                credential_source,
                credential_label,
                attempt,
                outcome,
                category,
                recorded_at,
            ),
        )

    def record_route_attempt(
        self,
        *,
        host_id: int,
        attempted_target: str,
        credential_profile: str | None = None,
        credential_stage: str | None = None,
        credential_source: str | None = None,
        credential_label: str | None = None,
        attempt: int | None = None,
        outcome: str,
        category: str | None = None,
        recorded_at: str | None = None,
    ) -> None:
        """Persist one route result outside a device-result transaction."""

        self._record_route_attempt_uncommitted(
            host_id=host_id,
            attempted_target=attempted_target,
            credential_profile=credential_profile,
            credential_stage=credential_stage,
            credential_source=credential_source,
            credential_label=credential_label,
            attempt=attempt,
            outcome=outcome,
            category=category,
            recorded_at=recorded_at or iso_now(),
        )
        self.conn.commit()

    def route_attempts_for_host(self, host_id: int) -> list[sqlite3.Row]:
        """Return persisted collection routes in original attempt order."""

        return self.conn.execute(
            "SELECT * FROM route_attempts WHERE host_id=? ORDER BY id",
            (host_id,),
        ).fetchall()

    def attempted_addresses(self, host_id: int) -> set[str]:
        """Return canonical addresses already sent to a worker backend."""

        rows = self.conn.execute(
            "SELECT DISTINCT attempted_target FROM route_attempts WHERE host_id=?",
            (host_id,),
        ).fetchall()
        return {str(row["attempted_target"]) for row in rows}

    def scheduler_events_for_host(self, host_id: int) -> list[dict[str, Any]]:
        """Return durable scheduler decisions with decoded payloads."""

        rows = self.conn.execute(
            "SELECT * FROM scheduler_events WHERE host_id=? ORDER BY id",
            (host_id,),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"] or "{}"))
            except json.JSONDecodeError:
                payload = {}
            result.append(
                {
                    "id": int(row["id"]),
                    "host_id": int(row["host_id"]),
                    "timestamp": str(row["timestamp"]),
                    "event_type": str(row["event_type"]),
                    "payload": payload,
                }
            )
        return result

    def admit_late_address_recovery(
        self,
        host_id: int,
        *,
        new_addresses: Iterable[str],
        evidence_source: str,
        allowance: int,
    ) -> list[str]:
        """Atomically re-admit one FAILED host for genuinely new routes.

        Policy/boundary checks remain coordinator responsibilities.  This state
        boundary enforces terminal-state, persisted-route, and per-host cap
        invariants so duplicate advertisements and pause/resume cannot multiply
        work.
        """

        candidates: list[str] = []
        for value in new_addresses:
            normalized = self._normalized_route_target(str(value))
            if normalized is not None and normalized[0] not in candidates:
                candidates.append(normalized[0])
        if not candidates or allowance <= 0:
            return []

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT state, late_recovery_used FROM hosts WHERE id=?",
                (host_id,),
            ).fetchone()
            if row is None or str(row["state"]) != "FAILED":
                self.conn.rollback()
                return []
            used = int(row["late_recovery_used"] or 0)
            if used >= allowance:
                self.conn.rollback()
                return []
            attempted = self.attempted_addresses(host_id)
            admitted = [value for value in candidates if value not in attempted]
            if not admitted:
                self.conn.rollback()
                return []
            now = iso_now()
            self.conn.execute(
                "UPDATE hosts SET state='READY', worker_id=NULL, lease_until=NULL, "
                "late_recovery_used=?, updated_at=? WHERE id=? AND state='FAILED'",
                (used + 1, now, host_id),
            )
            payload = {
                "new_addresses": admitted,
                "evidence_source": evidence_source,
                "prior_state": "FAILED",
                "allowance": allowance,
                "used_before": used,
                "used_after": used + 1,
                "remaining": max(0, allowance - used - 1),
            }
            self.conn.execute(
                "INSERT INTO scheduler_events(host_id, timestamp, event_type, payload_json) "
                "VALUES(?, ?, 'late_address_recovery_admitted', ?)",
                (host_id, now, json.dumps(payload, sort_keys=True)),
            )
            self.conn.commit()
            return admitted
        except Exception:
            self.conn.rollback()
            raise

    def apply_device_result(self, result: DeviceResult) -> None:
        if result.status == "deferred":
            self.defer_host(result.host_id)
            return
        now = iso_now()
        result_observation_payload = device_result_observation_payload(result)
        result_observation_id, result_observation_fingerprint = (
            self._record_observation_uncommitted(
                result_observation_payload,
                source_host_id=result.host_id,
                protocol="snmp",
                observed_at=now,
            )
        )
        result_evidence_claims = device_result_claims(result)
        result_claim_ids = self._record_claims_uncommitted(
            result_observation_id,
            result_observation_fingerprint,
            result_evidence_claims,
        )
        self._record_protocol_advertisements_uncommitted(
            result,
            now,
            source_observation_id=result_observation_id,
        )
        result_dict = result.to_dict()
        system_dict = result_dict.get("system") or {}
        metrics_dict = result_dict.get("collection_metrics") or {}
        snmp_sessions = result_dict.get("snmp_sessions") or []
        interface_groups = result_dict.get("interface_observation_groups") or []
        collection_coverage = result_dict.get("collection_coverage") or {}
        snmp_sysname = system_dict.get("sys_name") if isinstance(system_dict, dict) else None
        final_state = "COMPLETE" if result.status == "success" else "FAILED"
        self.conn.execute(
            """
            UPDATE hosts SET state=?, worker_id=NULL, lease_until=NULL,
                query_target=COALESCE(?, query_target), credential_profile=?,
                credential_source=?, credential_label=?, credential_result=?,
                snmp_sysname=COALESCE(?, snmp_sysname), ping_json=?, system_json=?,
                metrics_json=?, snmp_sessions_json=?, interface_groups_json=?,
                collection_coverage_json=?, last_seen=COALESCE(?, last_seen),
                last_seen_source=COALESCE(?, last_seen_source), updated_at=? WHERE id=?
            """,
            (
                final_state,
                result.query_target,
                result.credential_profile,
                result.credential_source,
                result.credential_label,
                result.credential_result,
                snmp_sysname,
                json.dumps([p.__dict__ if hasattr(p, "__dict__") else {
                    "status": p.status,
                    "timestamp": p.timestamp,
                    "address": p.address,
                    "rtt_ms": p.rtt_ms,
                    "error": p.error,
                } for p in result.ping_probes]),
                json.dumps(system_dict, default=str),
                json.dumps(metrics_dict, default=str),
                json.dumps(snmp_sessions, default=str),
                json.dumps(interface_groups, default=str),
                json.dumps(collection_coverage, default=str),
                result.last_seen,
                result.last_seen_source,
                now,
                result.host_id,
            ),
        )
        normalized_sysname = (
            normalize_identity_name(str(snmp_sysname)) if snmp_sysname else None
        )
        if normalized_sysname:
            self.conn.execute(
                "INSERT OR IGNORE INTO aliases(alias_type, value, host_id) VALUES('name', ?, ?)",
                (normalized_sysname, result.host_id),
            )
        if result.status == "success" and result.query_target:
            try:
                query_address = normalize_host_address(result.query_target)
            except ValueError:
                query_address = None
            if query_address is not None:
                address_type = "ipv6" if ":" in query_address else "ipv4"
                # A successful SNMP response is direct evidence that this host
                # was reachable at the selected address. Upgrade a DNS-only
                # query claim without assuming the value is globally unique.
                self.conn.execute(
                    "INSERT INTO host_addresses("
                    "address_type, value, host_id, identity_eligible"
                    ") VALUES(?, ?, ?, 1) "
                    "ON CONFLICT(address_type, value, host_id) DO UPDATE SET "
                    "identity_eligible=1",
                    (address_type, query_address, result.host_id),
                )
        for error in result.errors:
            self.conn.execute(
                """
                INSERT INTO errors(
                    host_id, timestamp, operation, category, message,
                    attempted_target, address_family, phase, exception_type,
                    exception_errno, exception_strerror, exception_args_json,
                    credential_profile, credential_stage, credential_source,
                    credential_label, attempt, collector, recoverable,
                    final_device_status
                ) VALUES(
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    result.host_id,
                    error.timestamp,
                    error.operation,
                    error.category,
                    error.message,
                    error.attempted_target,
                    error.address_family,
                    error.phase,
                    error.exception_type,
                    error.exception_errno,
                    error.exception_strerror,
                    json.dumps(error.exception_args),
                    error.credential_profile,
                    error.credential_stage,
                    error.credential_source,
                    error.credential_label,
                    error.attempt,
                    error.collector,
                    1 if error.recoverable else 0,
                    final_state,
                ),
            )
            if error.attempted_target:
                self._record_route_attempt_uncommitted(
                    host_id=result.host_id,
                    attempted_target=error.attempted_target,
                    credential_profile=error.credential_profile,
                    credential_stage=error.credential_stage,
                    credential_source=error.credential_source,
                    credential_label=error.credential_label,
                    attempt=error.attempt,
                    outcome="failed",
                    category=error.category,
                    recorded_at=error.timestamp,
                )
        if result.status == "success" and result.query_target:
            self._record_route_attempt_uncommitted(
                host_id=result.host_id,
                attempted_target=result.query_target,
                credential_profile=result.credential_profile,
                credential_stage=result.credential_result,
                credential_source=result.credential_source,
                credential_label=result.credential_label,
                attempt=None,
                outcome="succeeded",
                category=None,
                recorded_at=result.last_seen or now,
            )
        self._record_resolution_decision_uncommitted(
            result_observation_id,
            decision_type="snmp_result_projected",
            projected_host_id=result.host_id,
            candidate_host_ids=[result.host_id],
            confidence=self._claim_confidence(result_evidence_claims),
            rationale=[
                "SNMP result retained as self-observed evidence for the existing host projection"
            ],
            supporting_claim_ids=result_claim_ids,
            coalesce_same_outcome=True,
        )
        self.conn.commit()

    def add_error(
        self,
        host_id: int | None,
        operation: str,
        category: str,
        message: str,
        *,
        recoverable: bool = True,
        final_device_status: str | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO errors(host_id, timestamp, operation, category, message, recoverable, final_device_status)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                host_id,
                iso_now(),
                operation,
                category,
                message,
                1 if recoverable else 0,
                final_device_status,
            ),
        )
        self.conn.commit()

    def ensure_error(
        self,
        host_id: int | None,
        operation: str,
        category: str,
        message: str,
        *,
        recoverable: bool = True,
        final_device_status: str | None = None,
    ) -> None:
        """Insert an error once, even when periodic draft snapshots repeat checks.

        Output integrity validation runs every snapshot.  Without this idempotent
        helper, a four-hour discovery could append the same missing-query-target
        warning hundreds of times to ``errors.csv``.
        """

        if host_id is None:
            row = self.conn.execute(
                """
                SELECT 1 FROM errors
                WHERE host_id IS NULL AND operation=? AND category=? AND message=?
                LIMIT 1
                """,
                (operation, category, message),
            ).fetchone()
        else:
            row = self.conn.execute(
                """
                SELECT 1 FROM errors
                WHERE host_id=? AND operation=? AND category=? AND message=?
                LIMIT 1
                """,
                (host_id, operation, category, message),
            ).fetchone()
        if row is not None:
            return
        self.add_error(
            host_id,
            operation,
            category,
            message,
            recoverable=recoverable,
            final_device_status=final_device_status,
        )

    def clear_errors(
        self, host_ids: Iterable[int], operation: str, category: str
    ) -> int:
        """Delete stale errors for many hosts with one batched commit.

        Output-time integrity checks may describe a condition that is only
        temporarily true.  For example, a CLAIMED managed device is expected to
        have no ``query_target`` until one candidate address successfully answers
        SNMP.  An older snapshot may have persisted that transient condition as an
        error.  Later snapshots need to remove those stale rows without performing
        one SQLite commit per managed device, which would be unnecessarily costly on
        large discovery runs.
        """

        ids = list(dict.fromkeys(int(host_id) for host_id in host_ids))
        if not ids:
            return 0

        deleted = 0
        # Keep each IN clause comfortably below SQLite's common host-parameter
        # limits.  All chunks share one final commit so periodic snapshots remain
        # lightweight even when thousands of managed devices are present.
        for offset in range(0, len(ids), 500):
            chunk = ids[offset : offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            cursor = self.conn.execute(
                f"DELETE FROM errors WHERE operation=? AND category=? "
                f"AND host_id IN ({placeholders})",
                (operation, category, *chunk),
            )
            deleted += int(cursor.rowcount)
        self.conn.commit()
        return deleted

    def errors_for_host(self, host_id: int) -> list[sqlite3.Row]:
        """Return recorded errors for one host in discovery order."""

        return self.conn.execute(
            "SELECT * FROM errors WHERE host_id=? ORDER BY id",
            (host_id,),
        ).fetchall()

    def update_preferred_name(self, host_id: int, candidate: str) -> None:
        row = self.host_row(host_id)
        preferred = self._prefer_presentation(str(row["preferred_name"]), candidate)
        self.conn.execute(
            "UPDATE hosts SET preferred_name=?, updated_at=? WHERE id=?",
            (preferred, iso_now(), host_id),
        )
        self.conn.commit()

    def update_classification(self, host_id: int, category: str, reasons: Iterable[str]) -> None:
        row = self.host_row(host_id)
        current = str(row["classification"])
        merged = self._merge_category(
            current,
            category,
            bool(row["is_seed"]),
            explicit=any(str(reason).startswith("explicit ") for reason in reasons),
        )
        current_reasons = list(json.loads(row["classification_reason_json"] or "[]"))
        for reason in reasons:
            if reason not in current_reasons:
                current_reasons.append(reason)
        self.conn.execute(
            "UPDATE hosts SET classification=?, classification_reason_json=?, updated_at=? WHERE id=?",
            (merged, json.dumps(current_reasons), iso_now(), host_id),
        )
        self.conn.commit()

    def host_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0])

    def managed_device_count(self) -> int:
        return int(
            self.conn.execute(
                "SELECT COUNT(*) FROM hosts WHERE classification='managed_device'"
            ).fetchone()[0]
        )

    def seed_order_rows(self) -> list[sqlite3.Row]:
        """Return authoritative de-duplicated managed seeds for rank calculation."""

        return self.conn.execute(
            "SELECT id, preferred_name, seed_rank FROM hosts "
            "WHERE is_seed=1 AND classification='managed_device' "
            "ORDER BY COALESCE(seed_rank, id), id"
        ).fetchall()

    def ensure_missing_seed_ranks(self) -> None:
        """Assign input-order ranks to seed rows resumed from pre-v0.10 state.

        This migrates internal SQLite checkpoint state only. It does not add support
        for any previous external seed-input format. Historical host-ID order is the
        only ordering evidence available to a v0.9.x run that predates seed ranks.
        """

        rows = self.conn.execute(
            "SELECT id FROM hosts WHERE is_seed=1 AND seed_rank IS NULL ORDER BY id"
        ).fetchall()
        next_rank = self.next_seed_rank()
        for row in rows:
            self.conn.execute(
                "UPDATE hosts SET seed_rank=?, updated_at=? WHERE id=?",
                (next_rank, iso_now(), int(row["id"])),
            )
            next_rank += 1
        self.conn.commit()

    def next_seed_rank(self) -> int:
        """Return the next rank after all currently ranked seed identities."""

        row = self.conn.execute(
            "SELECT MAX(seed_rank) FROM hosts WHERE is_seed=1 AND seed_rank IS NOT NULL"
        ).fetchone()
        return 0 if row is None or row[0] is None else int(row[0]) + 1

    def apply_seed_order(self, ordered_host_ids: list[int]) -> None:
        """Persist one complete contiguous seed scheduling order."""

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            now = iso_now()
            for rank, host_id in enumerate(ordered_host_ids):
                self.conn.execute(
                    "UPDATE hosts SET seed_rank=?, updated_at=? "
                    "WHERE id=? AND is_seed=1",
                    (rank, now, host_id),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def host_guardrail_count(self, *, seed_only: bool) -> int:
        """Return the host population relevant to ``max_hosts`` in this mode.

        Recursive discovery preserves the historical all-host count. Seed-only
        sampling treats the explicit seed inventory as sampling points, so only
        non-seed identities consume max_hosts; otherwise a large switch inventory
        could exhaust the sample threshold before any switch was queried.
        """

        if seed_only:
            return int(
                self.conn.execute("SELECT COUNT(*) FROM hosts WHERE is_seed=0").fetchone()[0]
            )
        return self.host_count()

    def seed_device_count(self) -> int:
        """Return the de-duplicated managed seed identities in this run.

        Seed inputs may repeat the same hostname/address through multiple files or
        may merge after DNS/alias correlation.  Guardrail decisions therefore use
        authoritative state identities rather than the raw number of input lines.
        """

        return int(
            self.conn.execute(
                "SELECT COUNT(*) FROM hosts "
                "WHERE is_seed=1 AND classification='managed_device'"
            ).fetchone()[0]
        )

    def seed_resolution_counts(self) -> dict[str, int]:
        """Return operator-facing counts after seed identity resolution.

        ``unique`` counts authoritative managed seed hosts after alias/DNS
        consolidation. ``queryable`` counts seeds currently READY for worker
        scheduling. ``unresolved`` counts managed seeds with no IPv4/IPv6 alias;
        policy-denied and out-of-boundary seeds remain resolved identities and are
        therefore reported separately in the activity log rather than being
        mislabeled as DNS failures.
        """

        rows = self.conn.execute(
            "SELECT state, COUNT(*) AS n FROM hosts "
            "WHERE is_seed=1 AND classification='managed_device' GROUP BY state"
        ).fetchall()
        by_state = {str(row["state"]): int(row["n"]) for row in rows}
        unresolved = int(
            self.conn.execute(
                """
                SELECT COUNT(*)
                FROM hosts h
                WHERE h.is_seed=1
                  AND h.classification='managed_device'
                  AND NOT EXISTS (
                    SELECT 1 FROM host_addresses a
                    WHERE a.host_id=h.id
                  )
                """
            ).fetchone()[0]
        )
        return {
            "unique": sum(by_state.values()),
            "queryable": by_state.get("READY", 0),
            "unresolved": unresolved,
            "no_query": by_state.get("NO_QUERY", 0),
            "out_of_scope": by_state.get("OUT_OF_SCOPE", 0),
            "complete": by_state.get("COMPLETE", 0),
            "failed": by_state.get("FAILED", 0),
        }

    def suppress_nonseed_pending_queries(self) -> int:
        """Mark pending non-seed managed devices NO_QUERY for seed-only mode.

        ``max_devices='auto'`` intentionally records discovered neighbors without
        recursively polling them.  New neighbors are suppressed by the coordinator,
        but this bulk transition also protects resume scenarios where a prior
        recursive run left non-seed hosts in DISCOVERED or READY state.
        """

        cursor = self.conn.execute(
            """
            UPDATE hosts
            SET state='NO_QUERY', worker_id=NULL, lease_until=NULL, updated_at=?
            WHERE is_seed=0
              AND classification='managed_device'
              AND state IN ('DISCOVERED', 'READY')
            """,
            (iso_now(),),
        )
        self.conn.commit()
        return int(cursor.rowcount)

    def ready_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM hosts WHERE state='READY'").fetchone()[0])

    def active_count(self) -> int:
        placeholders = ",".join("?" for _ in ACTIVE_STATES)
        return int(
            self.conn.execute(
                f"SELECT COUNT(*) FROM hosts WHERE state IN ({placeholders})", ACTIVE_STATES
            ).fetchone()[0]
        )

    def counts(self) -> dict[str, Any]:
        counts: dict[str, Any] = {
            "hosts_discovered": self.host_count(),
            "managed_devices": 0,
            "managed_endpoints": 0,
            "unmanaged_devices": 0,
            "unknown_devices": 0,
            "ready": self.ready_count(),
            "active": self.active_count(),
            "complete": 0,
            "failed": 0,
            "primary_successes": 0,
            "fallback_successes": 0,
            "direct_successes": 0,
            "errors": int(self.conn.execute("SELECT COUNT(*) FROM errors").fetchone()[0]),
        }
        category_key = {
            "managed_device": "managed_devices",
            "managed_endpoint": "managed_endpoints",
            "unmanaged_device": "unmanaged_devices",
            "unknown_device": "unknown_devices",
        }
        for row in self.conn.execute("SELECT classification, COUNT(*) n FROM hosts GROUP BY classification"):
            if str(row["classification"]) in category_key:
                counts[category_key[str(row["classification"])]] = int(row["n"])
        for row in self.conn.execute("SELECT state, COUNT(*) n FROM hosts GROUP BY state"):
            state = str(row["state"])
            if state == "COMPLETE":
                counts["complete"] = int(row["n"])
            elif state == "FAILED":
                counts["failed"] = int(row["n"])
        for row in self.conn.execute(
            "SELECT credential_result, COUNT(*) n FROM hosts GROUP BY credential_result"
        ):
            if row["credential_result"] == "primary":
                counts["primary_successes"] = int(row["n"])
            elif row["credential_result"] == "fallback":
                counts["fallback_successes"] = int(row["n"])
            elif row["credential_result"] == "direct":
                counts["direct_successes"] = int(row["n"])
        return counts

    def _compatibility_advertisements(self) -> list[dict[str, Any]]:
        """Return migration evidence for hosts without retained raw rows.

        State created before schema 7 contains only merged ``neighbors`` rows.
        These records cannot recover every original protocol row, but they allow
        a resumed database to materialize a conservative graph while clearly
        marking the evidence as a compatibility projection.
        """

        rows = self.conn.execute("SELECT * FROM neighbors ORDER BY id").fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            details = json.loads(str(row["details_json"] or "{}"))
            if not isinstance(details, dict):
                details = {}
            protocols = [
                value for value in str(row["protocols"] or "").split(",") if value
            ]
            protocol = protocols[0] if protocols else "unknown"
            details.setdefault("protocols", protocols or [protocol])
            observation = NeighborObservation(
                protocol=protocol,
                local_interface=str(row["local_interface"] or "") or None,
                local_interface_raw=row["local_interface_raw"],
                remote_name=row["observed_name"],
                remote_interface=str(row["remote_interface"] or "") or None,
                remote_interface_raw=row["remote_interface_raw"],
                remote_addresses=list(
                    json.loads(str(row["observed_addresses_json"] or "[]"))
                ),
                remote_description=details.get("remote_description"),
                remote_platform=details.get("remote_platform"),
                capabilities=list(details.get("capabilities") or []),
                chassis_id=details.get("chassis_id"),
                chassis_id_subtype=details.get("chassis_id_subtype"),
                chassis_id_subtype_id=details.get("chassis_id_subtype_id"),
                details=details,
            )
            record = canonical_raw_advertisements(
                int(row["source_host_id"]), [observation]
            )[0]
            record["remote_host_id"] = int(row["remote_host_id"])
            record["migration_source"] = "merged_neighbor_projection"
            record["occurrence_fingerprint"] = stable_fingerprint(
                {
                    "compatibility_record": record,
                    "neighbor_row_id": int(row["id"]),
                }
            )
            records.append(record)
        return records

    def _record_graph_component_decision_uncommitted(
        self, decision: dict[str, Any]
    ) -> int:
        """Append one graph conclusion when its semantic outcome changed."""

        component_key = str(decision["component_key"])
        decision_type = str(decision["decision_type"])
        outcome = decision.get("outcome", {})
        evidence = sorted(
            dict.fromkeys(str(value) for value in decision.get("evidence", []))
        )
        semantic = {
            "decision_type": decision_type,
            "outcome": outcome,
            "evidence": evidence,
        }
        latest = self.conn.execute(
            "SELECT * FROM graph_component_decisions WHERE component_key=? "
            "ORDER BY sequence DESC LIMIT 1",
            (component_key,),
        ).fetchone()
        if latest is not None:
            latest_semantic = {
                "decision_type": str(latest["decision_type"]),
                "outcome": json.loads(str(latest["outcome_json"])),
                "evidence": json.loads(str(latest["evidence_json"])),
            }
            if latest_semantic == semantic:
                return int(latest["id"])
            sequence = int(latest["sequence"]) + 1
            supersedes = int(latest["id"])
        else:
            sequence = 1
            supersedes = None
        fingerprint = stable_fingerprint(
            {
                "component_key": component_key,
                "sequence": sequence,
                "supersedes_decision_id": supersedes,
                **semantic,
            }
        )
        self.conn.execute(
            "INSERT INTO graph_component_decisions("
            "component_key, sequence, supersedes_decision_id, decision_fingerprint, "
            "decision_type, outcome_json, evidence_json, created_at"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (
                component_key,
                sequence,
                supersedes,
                fingerprint,
                decision_type,
                stable_json(outcome),
                stable_json(evidence),
                iso_now(),
            ),
        )
        return int(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    def materialize_topology_graph(self) -> GraphBuildResult:
        """Rebuild and transactionally publish the graph from durable evidence.

        Materialization is deterministic and may be repeated.  Unchanged
        components reuse their latest decision.  Changed components append a
        superseding decision before the current projection is replaced, so the
        complete reasoning history remains auditable.
        """

        host_rows = [dict(row) for row in self.conn.execute("SELECT * FROM hosts")]
        names_by_host: dict[int, list[str]] = {}
        for row in self.conn.execute(
            "SELECT host_id, value FROM aliases WHERE alias_type='name' "
            "ORDER BY host_id, value"
        ):
            names_by_host.setdefault(int(row["host_id"]), []).append(str(row["value"]))
        addresses_by_host: dict[int, list[str]] = {}
        for row in self.conn.execute(
            "SELECT host_id, value FROM host_addresses ORDER BY host_id, value"
        ):
            addresses_by_host.setdefault(int(row["host_id"]), []).append(
                str(row["value"])
            )
        coverage_by_host: dict[int, dict[str, Any]] = {}
        for row in host_rows:
            try:
                value = json.loads(str(row.get("collection_coverage_json") or "{}"))
            except json.JSONDecodeError:
                value = {}
            coverage_by_host[int(row["id"])] = value if isinstance(value, dict) else {}

        # Every new protocol row references the immutable SNMP result that
        # produced it.  A per-host latest-result index also recovers schema-7
        # rows created before that reference existed.  Both survive compatibility
        # host absorption and let graph materialization rebuild source agents
        # directly from factual collection records.
        source_context_by_host: dict[int, dict[str, Any]] = {}
        source_context_by_observation: dict[int, dict[str, Any]] = {}
        for row in self.conn.execute(
            "SELECT id, source_host_id, payload_json FROM observations "
            "WHERE observation_type='snmp_device_result' "
            "ORDER BY id"
        ):
            if row["source_host_id"] is None:
                continue
            try:
                payload = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            system = payload.get("system")
            if not isinstance(system, dict):
                system = {}
            host_id = int(row["source_host_id"])
            query_target = payload.get("query_target")
            sys_name = system.get("sys_name")
            context = {
                "schema_version": 2,
                "source_host_id": host_id,
                "preferred_name": sys_name or query_target or "unknown",
                "snmp_sysname": sys_name,
                "classification": "managed_device",
                "state": (
                    "COMPLETE" if payload.get("status") == "success" else "FAILED"
                ),
                "query_target": query_target,
                "names": [sys_name] if sys_name else [],
                "addresses": [query_target] if query_target else [],
                "system": system,
                "collection_coverage": (
                    payload.get("collection_coverage")
                    if isinstance(payload.get("collection_coverage"), dict)
                    else {}
                ),
                "credential_route": {
                    "profile": payload.get("credential_profile"),
                    "source": payload.get("credential_source"),
                    "label": payload.get("credential_label"),
                    "result": payload.get("credential_result"),
                },
            }
            source_context_by_observation[int(row["id"])] = context
            source_context_by_host[host_id] = context

        raw_records: list[dict[str, Any]] = []
        for row in self.conn.execute(
            "SELECT source_host_id, source_observation_id, source_context_json, "
            "payload_json FROM protocol_advertisements "
            "ORDER BY source_host_id, occurrence_fingerprint"
        ):
            try:
                value = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError:
                continue
            if not isinstance(value, dict):
                continue
            try:
                context = json.loads(str(row["source_context_json"] or "{}"))
            except json.JSONDecodeError:
                context = {}
            source_host_id = int(row["source_host_id"])
            source_observation_id = row["source_observation_id"]
            factual_context = (
                source_context_by_observation.get(int(source_observation_id), {})
                if source_observation_id is not None
                else source_context_by_host.get(source_host_id, {})
            )
            if not isinstance(context, dict):
                context = {}
            context = {**factual_context, **context}
            if context:
                value["source_context"] = context
                source_context_by_host[source_host_id] = context
            raw_records.append(value)

        host_row_by_id = {int(row["id"]): row for row in host_rows}
        for host_id, context in sorted(source_context_by_host.items()):
            names = context.get("names")
            if isinstance(names, list):
                names_by_host.setdefault(host_id, []).extend(
                    str(value) for value in names if value not in {None, ""}
                )
            addresses = context.get("addresses")
            if isinstance(addresses, list):
                addresses_by_host.setdefault(host_id, []).extend(
                    str(value) for value in addresses if value not in {None, ""}
                )
            coverage = context.get("collection_coverage")
            if isinstance(coverage, dict) and coverage:
                coverage_by_host.setdefault(host_id, coverage)
            if host_id in host_row_by_id:
                continue
            system = context.get("system")
            if not isinstance(system, dict):
                system = {}
            synthetic = {
                "id": host_id,
                "preferred_name": str(
                    context.get("preferred_name")
                    or context.get("snmp_sysname")
                    or context.get("query_target")
                    or "unknown"
                ),
                "snmp_sysname": context.get("snmp_sysname"),
                "classification": str(
                    context.get("classification") or "managed_device"
                ),
                "query_target": context.get("query_target"),
                "system_json": stable_json(system),
                "state": str(context.get("state") or "COMPLETE"),
                "collection_coverage_json": stable_json(
                    coverage if isinstance(coverage, dict) else {}
                ),
            }
            host_rows.append(synthetic)
            host_row_by_id[host_id] = synthetic

        for host_id in names_by_host:
            names_by_host[host_id] = sorted(
                dict.fromkeys(names_by_host[host_id]), key=str.casefold
            )
        for host_id in addresses_by_host:
            addresses_by_host[host_id] = sorted(
                dict.fromkeys(addresses_by_host[host_id])
            )

        raw_sources = {
            int(record["source_host_id"])
            for record in raw_records
            if record.get("source_host_id") is not None
        }
        compatibility_projection = self._compatibility_advertisements()
        compatibility = [
            record
            for record in compatibility_projection
            if int(record["source_host_id"]) not in raw_sources
        ]
        result = build_topology_graph(
            hosts=host_rows,
            names_by_host=names_by_host,
            addresses_by_host=addresses_by_host,
            raw_advertisements=[*raw_records, *compatibility],
            compatibility_projection_advertisements=compatibility_projection,
            coverage_by_host=coverage_by_host,
        )

        self.conn.commit()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            for decision in result.decisions:
                self._record_graph_component_decision_uncommitted(decision)
            # Component keys can legitimately change after a split or merge.  A
            # stable projection-level lineage ensures that every published graph
            # still has an explicit predecessor even when no individual component
            # retains its former key.
            self._record_graph_component_decision_uncommitted(
                {
                    "component_key": "graph:observation_projection",
                    "decision_type": "graph_materialized",
                    "outcome": {
                        "schema_version": result.document.get("schema_version"),
                        "projection_fingerprint": result.document.get(
                            "projection_fingerprint"
                        ),
                        "summary": result.document.get("summary", {}),
                    },
                    "evidence": [
                        f"projection:{result.document.get('projection_fingerprint')}"
                    ],
                }
            )
            graph_json = stable_json(result.document)
            graph_blob = zlib.compress(graph_json.encode("utf-8"), level=9)
            self.conn.execute(
                "INSERT INTO graph_projection("
                "singleton, projection_fingerprint, materialized_at, payload_json, "
                "payload_codec, payload_blob, summary_json"
                ") VALUES(1, ?, ?, '{}', 'zlib-json', ?, ?) "
                "ON CONFLICT(singleton) DO UPDATE SET "
                "projection_fingerprint=excluded.projection_fingerprint, "
                "materialized_at=excluded.materialized_at, "
                "payload_json=excluded.payload_json, "
                "payload_codec=excluded.payload_codec, "
                "payload_blob=excluded.payload_blob, "
                "summary_json=excluded.summary_json",
                (
                    str(result.document["projection_fingerprint"]),
                    iso_now(),
                    graph_blob,
                    stable_json(result.document.get("summary", {})),
                ),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return result

    def current_topology_graph(self) -> dict[str, Any] | None:
        """Return the latest materialized graph, if one has been published."""

        row = self.conn.execute(
            "SELECT payload_json, payload_codec, payload_blob "
            "FROM graph_projection WHERE singleton=1"
        ).fetchone()
        if row is None:
            return None
        try:
            if row["payload_codec"] == "zlib-json" and row["payload_blob"] is not None:
                text = zlib.decompress(bytes(row["payload_blob"])).decode("utf-8")
            else:
                text = str(row["payload_json"])
            value = json.loads(text)
        except (UnicodeError, ValueError, zlib.error, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def graph_decision_history(self) -> list[dict[str, Any]]:
        """Return append-only graph decisions for audit and regression tests."""

        records: list[dict[str, Any]] = []
        for row in self.conn.execute(
            "SELECT * FROM graph_component_decisions ORDER BY component_key, sequence"
        ):
            records.append(
                {
                    "id": int(row["id"]),
                    "component_key": str(row["component_key"]),
                    "sequence": int(row["sequence"]),
                    "supersedes_decision_id": (
                        int(row["supersedes_decision_id"])
                        if row["supersedes_decision_id"] is not None
                        else None
                    ),
                    "decision_fingerprint": str(row["decision_fingerprint"]),
                    "decision_type": str(row["decision_type"]),
                    "outcome": json.loads(str(row["outcome_json"])),
                    "evidence": json.loads(str(row["evidence_json"])),
                    "created_at": str(row["created_at"]),
                }
            )
        return records

    def seed_hosts(self) -> list[sqlite3.Row]:
        """Return explicit seed hosts for credential-overlay matching."""

        return self.conn.execute(
            "SELECT * FROM hosts WHERE is_seed=1 ORDER BY seed_rank, id"
        ).fetchall()

    def seed_credential_requirements(self) -> dict[int, str]:
        """Return persisted seed-credential strategy requirements by host ID."""

        rows = self.conn.execute(
            "SELECT host_id, strategy FROM seed_credential_requirements"
        ).fetchall()
        return {int(row["host_id"]): str(row["strategy"]) for row in rows}

    def set_seed_credential_requirement(
        self, host_id: int, strategy: str, source_keys: list[str], labels: list[str]
    ) -> None:
        """Persist only non-secret metadata needed to validate resumed overlays."""

        self.conn.execute(
            """
            INSERT INTO seed_credential_requirements(
                host_id, strategy, source_keys_json, labels_json
            ) VALUES(?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET
                strategy=excluded.strategy,
                source_keys_json=excluded.source_keys_json,
                labels_json=excluded.labels_json
            """,
            (host_id, strategy, json.dumps(source_keys), json.dumps(labels)),
        )
        self.conn.commit()

    def all_hosts(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM hosts ORDER BY preferred_name, id").fetchall()

    def neighbors_from(self, host_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT n.*, h.preferred_name remote_preferred_name, h.classification remote_classification
            FROM neighbors n JOIN hosts h ON h.id=n.remote_host_id
            WHERE n.source_host_id=? ORDER BY n.local_interface, h.preferred_name
            """,
            (host_id,),
        ).fetchall()

    def neighbors_to(self, host_id: int) -> list[sqlite3.Row]:
        """Return topology edges where another host observed `host_id` as a neighbor.

        The source host's presentation fields are joined here because output writers
        need to describe reciprocal/inbound topology evidence without issuing extra
        per-edge lookups.  Keeping this query directional also makes it clear that the
        evidence originated from the source device's CDP/LLDP tables.
        """

        return self.conn.execute(
            """
            SELECT n.*, h.preferred_name source_preferred_name,
                h.classification source_classification
            FROM neighbors n JOIN hosts h ON h.id=n.source_host_id
            WHERE n.remote_host_id=? ORDER BY h.preferred_name, n.local_interface
            """,
            (host_id,),
        ).fetchall()

    def all_errors(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT e.*, h.preferred_name, h.query_target,
                h.state AS current_host_state
            FROM errors e LEFT JOIN hosts h ON h.id=e.host_id
            ORDER BY e.id
            """
        ).fetchall()
