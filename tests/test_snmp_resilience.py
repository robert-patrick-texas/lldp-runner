"""Adaptive SNMP retry, pacing, and access-restriction regression coverage."""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from types import TracebackType

import pytest

from lldp_runner.snmp.resilience import (
    AdaptiveSnmpClient,
    AdaptiveSnmpState,
    SnmpAccessRestrictedError,
    SnmpTransportProfile,
    is_snmp_timeout,
    snmp_access_restriction_detail,
)
from lldp_runner.worker import _error_category


class _ScriptedClient:
    """Minimal project SNMP client whose operations consume scripted outcomes."""

    def __init__(
        self,
        outcomes: dict[str, deque[object]],
        *,
        entered: list[SnmpTransportProfile],
        exited: list[SnmpTransportProfile],
        profile: SnmpTransportProfile,
        get_many_requests: list[list[str]],
        open_outcome: object | None,
    ) -> None:
        self.outcomes = outcomes
        self.entered = entered
        self.exited = exited
        self.profile = profile
        self.get_many_requests = get_many_requests
        self.open_outcome = open_outcome

    async def __aenter__(self) -> _ScriptedClient:
        self.entered.append(self.profile)
        if isinstance(self.open_outcome, BaseException):
            raise self.open_outcome
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.exited.append(self.profile)

    def _next(self, operation: str) -> object:
        value = self.outcomes[operation].popleft()
        if isinstance(value, BaseException):
            raise value
        return value

    async def get(self, oid: str) -> object:
        return self._next("get")

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        self.get_many_requests.append(list(oids))
        value = self._next("get_many")
        assert isinstance(value, dict)
        return value

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        value = self._next("walk")
        assert isinstance(value, list)
        return value

    def engine_id_hex(self) -> str | None:
        return "800000090300001122334455"


class _Factory:
    """Create scripted sessions while recording every effective transport profile."""

    def __init__(
        self,
        *,
        open_outcomes: list[object] | None = None,
        **outcomes: list[object],
    ) -> None:
        self.outcomes = {
            operation: deque(values)
            for operation, values in {
                "get": [],
                "get_many": [],
                "walk": [],
                **outcomes,
            }.items()
        }
        self.open_outcomes = deque(open_outcomes or [])
        self.profiles: list[SnmpTransportProfile] = []
        self.entered: list[SnmpTransportProfile] = []
        self.exited: list[SnmpTransportProfile] = []
        self.get_many_requests: list[list[str]] = []

    def __call__(self, profile: SnmpTransportProfile) -> _ScriptedClient:
        self.profiles.append(profile)
        open_outcome = self.open_outcomes.popleft() if self.open_outcomes else None
        return _ScriptedClient(
            self.outcomes,
            entered=self.entered,
            exited=self.exited,
            profile=profile,
            get_many_requests=self.get_many_requests,
            open_outcome=open_outcome,
        )


def _state(
    target: str,
    *,
    timeout: float = 2.0,
    max_repetitions: int = 25,
    retry_per_operation: int = 1,
    retry_per_collector: int = 1,
    retry_total_cap: int = 3,
    retry_neighbor_reserve: int = 2,
    structural_table_retry: int = 1,
    retry_delay_ms: float = 100.0,
) -> AdaptiveSnmpState:
    """Return the production-shaped adaptive policy used by unit tests."""

    return AdaptiveSnmpState(
        target=target,
        timeout_seconds=timeout,
        max_repetitions=max_repetitions,
        per_device_rps=5.0,
        retry_per_operation=retry_per_operation,
        retry_per_collector=retry_per_collector,
        retry_total_cap=retry_total_cap,
        retry_neighbor_reserve=retry_neighbor_reserve,
        structural_table_retry=structural_table_retry,
        timeout_multiplier=1.5,
        max_repetitions_multiplier=0.5,
        min_max_repetitions=1,
        retry_inter_pdu_delay_ms=retry_delay_ms,
    )


def test_get_timeout_applies_complete_degraded_target_profile(caplog) -> None:
    """A timeout raises time allowance while reducing request size and rate."""

    factory = _Factory(get=[TimeoutError("request timed out"), "switch1"])
    state = _state("198.18.0.10")

    async def exercise() -> object:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            return await client.get("1.3.6.1.2.1.1.5.0")

    with caplog.at_level(logging.INFO):
        result = asyncio.run(exercise())

    assert result == "switch1"
    assert [profile.timeout_seconds for profile in factory.profiles] == [2.0, 3.0]
    assert [profile.max_repetitions for profile in factory.profiles] == [25, 13]
    assert state.max_repetitions == 13
    assert state.inter_pdu_delay_ms == 100.0
    assert state.per_device_rps == pytest.approx(10 / 3)
    assert state.events[0].final_outcome == "succeeded"
    assert "SNMP target=198.18.0.10 adaptive retry" in caplog.text
    assert "SNMP target=198.18.0.10" in caplog.text
    assert "timeout=2.000->3.000" in caplog.text
    assert "max_repetitions=25->13" in caplog.text
    assert "inter_pdu_delay_ms=0.000->100.000" in caplog.text


def test_mid_walk_timeout_discards_partial_attempt_and_restarts_table() -> None:
    """A timed-out table restarts at its root with the degraded profile."""

    complete = [
        ("1.3.6.1.2.1.2.2.1.2.1", "Gi1/0/1"),
        ("1.3.6.1.2.1.2.2.1.2.2", "Gi1/0/2"),
    ]
    factory = _Factory(walk=[TimeoutError("GETBULK timed out mid-table"), complete])
    state = _state("198.18.0.20", timeout=4.0)

    async def exercise() -> list[tuple[str, object]]:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            return await client.walk("1.3.6.1.2.1.2.2.1.2")

    assert asyncio.run(exercise()) == complete
    assert [profile.timeout_seconds for profile in factory.profiles] == [4.0, 6.0]
    assert state.events[0].partial_rows_discarded is True
    assert not factory.outcomes["walk"]


def test_later_operation_keeps_its_retry_after_early_timeout() -> None:
    """A recovered walk does not consume a later GET-MANY repair allowance."""

    factory = _Factory(
        walk=[TimeoutError("walk timeout"), []],
        get_many=[TimeoutError("later timeout"), {"1.0": "ok"}],
    )
    state = _state("198.18.0.30")

    async def exercise() -> dict[str, object]:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            assert await client.walk("1.1") == []
            return await client.get_many(["1.0"])

    assert asyncio.run(exercise()) == {"1.0": "ok"}
    assert [profile.timeout_seconds for profile in factory.profiles] == [2.0, 3.0, 3.0]
    assert state.total_retries_used == 2
    assert len(state.events) == 2
    assert all(event.per_operation_retry_count == 1 for event in state.events)


def test_recovered_get_many_does_not_block_later_lldp_structural_restart() -> None:
    """The production failure sequence retains a separate LLDP repair attempt."""

    factory = _Factory(
        get_many=[TimeoutError("early batch timeout"), {"1.0": "ok"}],
    )
    state = _state("198.18.0.31", retry_delay_ms=0.0)

    async def exercise() -> tuple[dict[str, object], bool]:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            batch = await client.get_many(["1.0"])
            with client.collection_context(
                collector="lldp",
                table_name="lldp",
                collection_phase="detail",
                root_oid="1.0.8802.1.1.2.1.4.1.1",
            ):
                repaired = await client.prepare_collection_retry(
                    operation="LLDP",
                    category="incomplete_table",
                    root_oid="1.0.8802.1.1.2.1.4.1.1",
                )
            return batch, repaired

    batch, repaired = asyncio.run(exercise())
    assert batch == {"1.0": "ok"}
    assert repaired is True
    assert state.total_retries_used == 2
    assert [event.category for event in state.events] == [
        "timeout",
        "incomplete_table",
    ]
    assert state.events[1].collector == "lldp"
    assert state.events[1].root_oid == "1.0.8802.1.1.2.1.4.1.1"


def test_second_timeout_is_propagated_without_unbounded_retry() -> None:
    """The retried operation stops when the fresh degraded session also times out."""

    factory = _Factory(get=[TimeoutError("first timeout"), TimeoutError("second timeout")])
    state = _state("198.18.0.40")

    async def exercise() -> None:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            await client.get("1.0")

    with pytest.raises(TimeoutError, match="second timeout"):
        asyncio.run(exercise())
    assert [profile.timeout_seconds for profile in factory.profiles] == [2.0, 3.0]
    assert state.events[0].final_outcome == "failed"
    assert state.events[0].outcome_type == "TimeoutError"


def test_degraded_get_many_uses_half_sized_oid_batches() -> None:
    """GET-MANY uses the same 50-percent work reduction as GETBULK."""

    factory = _Factory(
        get=[TimeoutError("initial timeout"), "ok"],
        get_many=[{"1": 1, "2": 2, "3": 3}, {"4": 4, "5": 5}],
    )
    state = _state("198.18.0.41", retry_delay_ms=0.0)

    async def exercise() -> dict[str, object]:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            assert await client.get("0") == "ok"
            return await client.get_many(["1", "2", "3", "4", "5"])

    assert asyncio.run(exercise()) == {"1": 1, "2": 2, "3": 3, "4": 4, "5": 5}
    assert factory.get_many_requests == [["1", "2", "3"], ["4", "5"]]


def test_degraded_profile_survives_reopen_between_basic_and_detail_sessions() -> None:
    """The successful address keeps its slowdown settings for later collectors."""

    factory = _Factory(get=[TimeoutError("basic timeout"), "system", "detail"])
    state = _state("198.18.0.42", retry_delay_ms=0.0)

    async def exercise() -> tuple[object, object]:
        async with AdaptiveSnmpClient(factory, state=state) as basic:
            first = await basic.get("1.0")
        async with AdaptiveSnmpClient(factory, state=state) as detail:
            second = await detail.get("1.1")
        return first, second

    assert asyncio.run(exercise()) == ("system", "detail")
    assert [profile.timeout_seconds for profile in factory.profiles] == [2.0, 3.0, 3.0]
    assert [profile.max_repetitions for profile in factory.profiles] == [25, 13, 13]


def test_structural_collection_restart_uses_independent_allowance() -> None:
    """A structural restart consumes the cap but leaves later operations eligible."""

    factory = _Factory()
    state = _state("198.18.0.43", retry_delay_ms=0.0)

    async def exercise() -> bool:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            return await client.prepare_collection_retry(
                operation="LLDP", category="incomplete_table"
            )

    assert asyncio.run(exercise()) is True
    assert [profile.timeout_seconds for profile in factory.profiles] == [2.0, 3.0]
    assert [profile.max_repetitions for profile in factory.profiles] == [25, 13]
    assert state.events[0].partial_rows_discarded is True
    assert state.total_retries_used == 1
    assert state.retry_available("later-operation", retry_kind="transport") is True


def test_total_target_retry_cap_bounds_independent_operations() -> None:
    """Independent operation allowances still stop at the target-wide cap."""

    factory = _Factory(
        get=[
            TimeoutError("one"),
            "one-ok",
            TimeoutError("two"),
            "two-ok",
            TimeoutError("three"),
            "three-ok",
            TimeoutError("four"),
        ]
    )
    state = _state(
        "198.18.0.44",
        retry_total_cap=3,
        retry_neighbor_reserve=0,
        retry_delay_ms=0.0,
    )

    async def exercise() -> None:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            assert await client.get("1") == "one-ok"
            assert await client.get("2") == "two-ok"
            assert await client.get("3") == "three-ok"
            await client.get("4")

    with pytest.raises(TimeoutError, match="four"):
        asyncio.run(exercise())
    assert state.total_retries_used == 3
    assert len(state.events) == 4
    exhaustion = state.events[-1]
    assert exhaustion.retry_allowed is False
    assert exhaustion.retry_kind == "transport"
    assert exhaustion.final_outcome == "unavailable"
    assert exhaustion.outcome_type == "shared_retry_cap"
    assert exhaustion.total_target_retry_count == 3
    assert exhaustion.timeout_before_seconds == exhaustion.timeout_after_seconds
    assert [profile.timeout_seconds for profile in factory.profiles] == [
        2.0,
        3.0,
        3.0,
        3.0,
    ]


class AuthorizationError(Exception):
    """Test double matching an SNMP authorizationError response."""


def test_nested_backend_timeout_and_access_causes_are_detected() -> None:
    """Backend wrappers cannot hide the transport or VACM failure category."""

    try:
        raise TimeoutError("request timed out")
    except TimeoutError as timeout:
        wrapped_timeout = RuntimeError("backend request failed")
        wrapped_timeout.__cause__ = timeout

    try:
        raise AuthorizationError("authorizationError from VACM")
    except AuthorizationError as denied:
        wrapped_access = RuntimeError("collector failed")
        wrapped_access.__cause__ = denied

    assert is_snmp_timeout(wrapped_timeout) is True
    access_detail = snmp_access_restriction_detail(wrapped_access)
    assert access_detail is not None
    assert "authorizationerror" in access_detail.casefold()


def test_ordinary_text_containing_access_word_is_not_an_snmp_error() -> None:
    """A hostname or description must not be mistaken for a VACM status."""

    assert snmp_access_restriction_detail("noaccess-switch.example.com") is None
    assert snmp_access_restriction_detail("Access denied banner test appliance") is None
    assert snmp_access_restriction_detail("noAccess") == "noAccess"


def test_degraded_profile_paces_retry_and_later_operations(monkeypatch) -> None:
    """The configured delay remains active after a target demonstrates slowness."""

    factory = _Factory(get=[TimeoutError("initial timeout"), "retry-ok", "later-ok"])
    state = _state("198.18.0.44", retry_delay_ms=100.0)
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr("lldp_runner.snmp.resilience.asyncio.sleep", fake_sleep)

    async def exercise() -> tuple[object, object]:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            retry_result = await client.get("1.0")
            later_result = await client.get("1.1")
        return retry_result, later_result

    assert asyncio.run(exercise()) == ("retry-ok", "later-ok")
    assert sleeps == [0.1, 0.1]


def test_explicit_access_exception_is_reported_logged_and_not_retried(caplog) -> None:
    """Authenticated VACM or ACL denial has a distinct operator category."""

    factory = _Factory(get=[AuthorizationError("authorizationError from VACM")])
    state = _state("198.18.0.50")

    async def exercise() -> None:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            await client.get("1.3.6.1.2.1.47")

    with caplog.at_level(logging.ERROR):
        with pytest.raises(SnmpAccessRestrictedError) as exc_info:
            asyncio.run(exercise())

    assert exc_info.value.operation == "GET"
    assert exc_info.value.oids == ("1.3.6.1.2.1.47",)
    assert _error_category(exc_info.value) == "snmp_access_restricted"
    assert len(factory.profiles) == 1
    assert state.total_retries_used == 0
    assert "SNMP target=198.18.0.50 access restriction" in caplog.text
    assert "SNMP target=198.18.0.50" in caplog.text


def test_access_marker_in_returned_varbind_is_promoted_to_error(caplog) -> None:
    """An explicit noAccess result cannot masquerade as ordinary table data."""

    factory = _Factory(get_many=[{"1.3.6.1.2.1.47": "noAccess"}])
    state = _state("198.18.0.60")

    async def exercise() -> None:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            await client.get_many(["1.3.6.1.2.1.47"])

    with caplog.at_level(logging.ERROR):
        with pytest.raises(SnmpAccessRestrictedError, match="noAccess"):
            asyncio.run(exercise())
    assert len(factory.profiles) == 1
    assert "SNMP target=198.18.0.60" in caplog.text


def test_retry_reopen_access_denial_is_classified_and_recorded(caplog) -> None:
    """A VACM denial while opening the retry session remains an access error."""

    factory = _Factory(
        open_outcomes=[None, AuthorizationError("authorizationError from VACM")],
        get=[TimeoutError("request timed out")],
    )
    state = _state("198.18.0.65")

    async def exercise() -> None:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            await client.get("1.3.6.1.2.1.47")

    with caplog.at_level(logging.ERROR):
        with pytest.raises(SnmpAccessRestrictedError):
            asyncio.run(exercise())

    assert state.events[0].final_outcome == "failed"
    assert state.events[0].outcome_type == "AuthorizationError"
    assert "SNMP target=198.18.0.65 access restriction" in caplog.text


def test_session_open_timeout_uses_the_same_adaptive_profile() -> None:
    """SNMPv3 discovery/session setup shares the target retry budget."""

    factory = _Factory(
        open_outcomes=[TimeoutError("engine discovery timed out"), None],
        get=["ok"],
    )
    state = _state("198.18.0.70")

    async def exercise() -> tuple[object, float]:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            return await client.get("1.0"), client.timeout_seconds

    assert asyncio.run(exercise()) == ("ok", 3.0)
    assert [profile.timeout_seconds for profile in factory.profiles] == [2.0, 3.0]
    assert [profile.max_repetitions for profile in factory.profiles] == [25, 13]


def test_access_restriction_survives_collector_wrapping() -> None:
    """Nested collection errors retain the SNMP access-restriction category."""

    from lldp_runner.collectors.interfaces import InterfaceCollectionError

    access = SnmpAccessRestrictedError("WALK", ("1.3.6.1.2.1.31",), "noAccess")
    try:
        raise InterfaceCollectionError("interface collection failed") from access
    except InterfaceCollectionError as wrapped:
        assert _error_category(wrapped) == "snmp_access_restricted"


def test_neighbor_retry_reserve_survives_shared_pool_exhaustion() -> None:
    """Earlier identity/interface retries must not starve LLDP or CDP repair."""

    state = _state(
        "198.18.0.80",
        retry_per_collector=1,
        retry_total_cap=3,
        retry_neighbor_reserve=2,
    )

    def consume(collector: str) -> object | None:
        return state.consume_retry(
            operation_key=f"transport:{collector}",
            retry_kind="transport",
            collector=collector,
            logical_operation="GET",
            table_name=collector,
            root_oid=None,
            collection_phase="detail",
            category="timeout",
            partial_rows_discarded=False,
        )

    shared_events = [
        consume("system"),
        consume("entity"),
        consume("interfaces"),
    ]
    assert [event.retry_pool for event in shared_events if event is not None] == [
        "shared",
        "shared",
        "shared",
    ]
    assert consume("stack") is None

    lldp_event = consume("lldp")
    cdp_event = consume("cdp")
    assert lldp_event is not None
    assert cdp_event is not None
    assert lldp_event.retry_pool == "neighbor_reserve"
    assert cdp_event.retry_pool == "neighbor_reserve"
    assert lldp_event.collector_family == "lldp"
    assert cdp_event.collector_family == "cdp"

    # Original LLDP and LLDPv2 share one fair-share collector allowance.
    assert consume("lldpv2") is None
    telemetry = state.telemetry()
    assert telemetry.shared_retries_used == 3
    assert telemetry.neighbor_reserve_used == 2
    assert telemetry.total_retries_used == 5
    assert telemetry.collector_retry_counts["lldp"] == 1
    assert telemetry.collector_retry_counts["cdp"] == 1


def test_stability_retry_is_separate_and_bounded_per_protocol() -> None:
    state = _state("198.18.0.81")

    def consume(collector: str, attempt: int) -> object | None:
        return state.consume_stability_retry(
            collector=collector,
            logical_operation=collector.upper(),
            table_name=collector,
            root_oid="1.3.6.1",
            collection_phase="detail",
            category="timeout",
            attempt=attempt,
            delay_seconds=2.0,
        )

    lldp_event = consume("lldp", 3)
    assert lldp_event is not None
    assert lldp_event.retry_kind == "stability"
    assert lldp_event.retry_pool == "stability"
    assert lldp_event.attempt == 3
    assert lldp_event.delay_before_retry_seconds == 2.0
    assert consume("lldp", 4) is None

    # LLDPv2 is a distinct protocol pass even though normal retries share the
    # LLDP family. Each failed protocol receives at most one stability attempt.
    assert consume("lldpv2", 2) is not None
    assert consume("cdp", 2) is not None
    telemetry = state.telemetry()
    assert telemetry.stability_retries_used == 3
    assert telemetry.stability_retry_counts == {
        "cdp": 1,
        "lldp": 1,
        "lldpv2": 1,
    }


def test_stability_attempt_suppresses_nested_transport_retry() -> None:
    factory = _Factory(get=[TimeoutError("final timeout")])
    state = _state("198.18.0.82", retry_delay_ms=0.0)

    async def exercise() -> None:
        async with AdaptiveSnmpClient(factory, state=state) as client:
            with client.collection_context(
                collector="lldp",
                table_name="lldp",
                collection_phase="detail",
                root_oid="1.0",
            ):
                assert await client.prepare_stability_retry(
                    operation="LLDP",
                    category="timeout",
                    attempt=2,
                    delay_seconds=2.0,
                    root_oid="1.0",
                )
                with client.suppress_normal_retries():
                    await client.get("1.0")

    with pytest.raises(TimeoutError, match="final timeout"):
        asyncio.run(exercise())

    assert len(state.events) == 1
    assert state.events[0].retry_kind == "stability"
    assert len(factory.profiles) == 2
    assert state.shared_retries_used == 0
    assert state.neighbor_reserve_used == 0
    assert state.stability_retries_used == 1
