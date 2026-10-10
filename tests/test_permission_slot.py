"""Actual local controls under explicitly admitted fixture authority and observer.

Secure Hash Algorithm 256-bit (SHA-256). Fixture admission is selected test policy,
not production provenance, authentication or complete Corrigibility qualification.
No providers, models, networks, subprocesses or outside effects are exercised.
"""
from __future__ import annotations

from asyncio import CancelledError
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from os import getpid
from threading import Event as ThreadEvent, Thread
from typing import Callable

import pytest

from verifier.runtime.permission_slot import (
    BoundaryResult, Census, DrainObservation, EntryObservation, Grant,
    GrantDecision, Outcome, PermissionSlot, Selection, Ticket, check_trace,
    trace_commitment,
)


def commitment(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def selection(generation: int = 1) -> Selection:
    return Selection(*(commitment(f"{field}:{generation}") for field in
                       ("artifact", "instruction", "policy", "context")),
                     f"fixture-session:{generation}", str(getpid()), generation)


def grant_for(selected: Selection, purpose: str = "initial", authority: str = "fixture:parent") -> Grant:
    return Grant(selected, authority, commitment(f"permission:{selected.generation}"),
                 commitment(f"fresh-view:{selected.generation}"), commitment(f"grant:{selected.generation}"),
                 f"fixture-nonce:{selected.generation}", purpose)


class FixtureAuthority:
    """An explicitly selected local authority fixture; performs no production admission."""

    def __init__(self) -> None:
        self.status = Outcome.PASS
        self.outage = False
        self.calls: list[tuple[Grant, Selection, Selection | None, int]] = []
        self.before_return: Callable[[], None] | None = None

    def verify(self, grant: Grant, *, expected: Selection,
               revoked: Selection | None, epoch: int) -> GrantDecision:
        self.calls.append((grant, expected, revoked, epoch))
        if self.outage:
            raise OSError("fixture authority unavailable")
        if self.before_return is not None:
            self.before_return()
        return GrantDecision(self.status, grant, epoch)


class FixtureObserver:
    """Wrap actual callback entry and exit; do not infer them from returned booleans."""

    def __init__(self) -> None:
        self.observer_id = "fixture:independently-selected-observer"
        self.attempts: list[Ticket] = []
        self.entries: list[Ticket] = []
        self.exits: list[Ticket] = []
        self.censuses: list[Census] = []
        self.before_boundary: Callable[[], None] | None = None
        self.outage = False
        self.omit = False
        self.duplicate = False
        self.contradict = False
        self.drain_missing = False
        self.drain_contradict = False

    def invoke(self, ticket: Ticket,
               boundary: Callable[[Callable[[], None]], BoundaryResult],
               effect: Callable[[], None]) -> EntryObservation:
        if self.outage:
            raise OSError("fixture observer unavailable")
        if self.before_boundary is not None:
            self.before_boundary()
        attempts = entries = exits = 0

        def observed_effect() -> None:
            nonlocal entries, exits
            self.entries.append(ticket)
            entries += 1
            try:
                effect()
            finally:
                exits += 1
                self.exits.append(ticket)

        result = BoundaryResult(Outcome.PASS, False, "fixture omitted the actual attempt")
        if not self.omit:
            self.attempts.append(ticket)
            attempts += 1
            result = boundary(observed_effect)
            if self.duplicate:
                self.attempts.append(ticket)
                attempts += 1
                result = boundary(observed_effect)
        return EntryObservation(self.observer_id, ticket, attempts,
                                entries + int(self.contradict), exits, result.status)

    def drain(self, read_census: Callable[[], Census]) -> DrainObservation | None:
        if self.outage:
            raise OSError("fixture observer unavailable")
        if self.drain_missing:
            return None
        actual = read_census()
        self.censuses.append(actual)
        if self.drain_contradict:
            actual = replace(actual, epoch=actual.epoch + 1)
        return DrainObservation(self.observer_id, actual, Outcome.PASS)


def host(**overrides: object) -> tuple[PermissionSlot, FixtureAuthority, FixtureObserver]:
    authority, observer = FixtureAuthority(), FixtureObserver()
    configuration = {"authorities": ("fixture:parent", "fixture:external-successor"),
                     "verifier": authority, "observer": observer, "observer_id": observer.observer_id}
    configuration.update(overrides)
    return PermissionSlot(selection(), **configuration), authority, observer


def active_host(**overrides: object) -> tuple[PermissionSlot, FixtureAuthority, FixtureObserver]:
    slot, authority, observer = host(**overrides)
    assert slot.grant(grant_for(selection())).status == Outcome.PASS
    return slot, authority, observer


def queued(slot: PermissionSlot, selected: Selection, invocation_id: str) -> Ticket:
    result = slot.queue(selected, invocation_id)
    assert result.status == Outcome.PASS and result.ticket is not None
    return result.ticket


def ready_successor(slot: PermissionSlot) -> None:
    assert slot.revoke(selection()).status == Outcome.PASS
    assert slot.drain().status == Outcome.PASS
    slot.select_successor(selection(2))


def test_actual_revoke_drain_stale_refusal_and_successor_entry() -> None:
    slot, authority, observer = active_host()
    old = queued(slot, selection(), "old-queued")
    unrelated_canary = {"value": "unchanged"}
    actual_effects: list[str] = []
    ready_successor(slot)
    intent = slot.select_successor(selection(2))
    assert slot.reconcile(intent).status == Outcome.UNKNOWN
    assert not slot.census().active
    successor_grant = grant_for(selection(2), "successor", "fixture:external-successor")
    assert slot.grant(successor_grant).status == Outcome.PASS
    assert authority.calls[-1][1:3] == (selection(2), selection())
    assert slot.reconcile(intent).status == Outcome.PASS
    assert slot.invoke(old, lambda: actual_effects.append("forbidden-old")).status == Outcome.PASS
    new = queued(slot, selection(2), "new-work")
    assert slot.invoke(new, lambda: actual_effects.append("successor")).status == Outcome.PASS
    assert actual_effects == ["successor"]
    assert observer.attempts == [old, new]
    assert observer.entries == observer.exits == [new]
    assert unrelated_canary == {"value": "unchanged"}
    assert slot.assessment().status == Outcome.PASS
    actions = [event.action for event in slot.trace()]
    assert actions.index("revoked") < actions.index("drained") < actions.index("successor_grant")
    assert actions.index("successor_grant") < actions.index("callback_refused") < actions.index("callback_entry")
    stale_events = [event for event in slot.trace() if event.invocation_id == old.invocation_id]
    assert all(event.selection == old.selection and event.ticket == old for event in stale_events)


def test_revoke_during_callback_preparation_counts_work_until_observed_exit() -> None:
    slot, _, observer = active_host()
    first = queued(slot, selection(), "old-preparing")
    stale = queued(slot, selection(), "old-stale")
    preparing, release = ThreadEvent(), ThreadEvent()
    effects: list[str] = []
    results: list[Outcome] = []

    def prepare() -> None:
        preparing.set()
        if not release.wait(3):
            raise TimeoutError("fixture preparation not released")

    def worker() -> None:
        results.append(slot.invoke(first, lambda: effects.append("old"), prepare=prepare).status)

    thread = Thread(target=worker)
    thread.start()
    try:
        assert preparing.wait(3)
        assert slot.census().inflight == (first,)
        assert slot.revoke(selection()).status == Outcome.PASS
        assert slot.census().queued == () and slot.census().inflight == (first,)
        assert slot.drain().status == Outcome.UNKNOWN
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and results == [Outcome.PASS]
    assert effects == [] and observer.entries == []
    assert slot.drain().status == Outcome.PASS
    slot.select_successor(selection(2))
    assert slot.grant(grant_for(selection(2), "successor", "fixture:external-successor")).status == Outcome.PASS
    assert slot.invoke(stale, lambda: effects.append("stale")).status == Outcome.PASS
    new = queued(slot, selection(2), "successor")
    assert slot.invoke(new, lambda: effects.append("new")).status == Outcome.PASS
    assert effects == ["new"] and slot.assessment().status == Outcome.PASS


def test_already_entered_callback_is_not_claimed_preempted() -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "already-entered")
    events: list[str] = []

    def effect() -> None:
        events.append("entered")
        assert slot.revoke(selection()).status == Outcome.PASS
        assert slot.drain().status == Outcome.UNKNOWN
        events.append("finished")

    assert slot.invoke(ticket, effect).status == Outcome.PASS
    assert events == ["entered", "finished"] and observer.entries == observer.exits == [ticket]
    assert slot.drain().status == Outcome.PASS


@pytest.mark.parametrize("during", ["verification", "preparation"])
def test_atomic_successor_grant_rechecks_epoch_after_user_callbacks(during: str) -> None:
    slot, authority, _ = active_host()
    ready_successor(slot)
    before = slot.census()
    cutoff = lambda: slot.revoke(selection())
    if during == "verification":
        authority.before_return = cutoff
    result = slot.grant(grant_for(selection(2), "successor", "fixture:external-successor"),
                        prepare=cutoff if during == "preparation" else None)
    assert result.status == Outcome.UNKNOWN
    assert not result.census.active and result.census.selection == before.selection
    assert result.census.epoch > before.epoch
    assert all(event.action != "successor_grant" for event in slot.trace())


def test_observer_setup_revocation_denies_before_actual_entry() -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "observer-race")
    effects: list[str] = []
    observer.before_boundary = lambda: slot.revoke(selection())
    assert slot.invoke(ticket, lambda: effects.append("forbidden")).status == Outcome.PASS
    assert observer.attempts == [ticket] and observer.entries == [] and effects == []


def test_revoked_parent_cannot_authorize_its_successor() -> None:
    slot, authority, observer = active_host()
    ready_successor(slot)
    call_count = len(authority.calls)
    result = slot.grant(grant_for(selection(2), "successor", "fixture:parent"))
    assert result.status == Outcome.FAIL and not result.census.active
    assert len(authority.calls) == call_count and observer.entries == []


@pytest.mark.parametrize("dependency", ["authorities", "verifier", "observer", "observer_id"])
def test_unavailable_independent_dependencies_leave_slot_inactive(dependency: str) -> None:
    slot, _, _ = host(**{dependency: () if dependency == "authorities" else None})
    result = slot.grant(grant_for(selection()))
    assert result.status == Outcome.UNKNOWN and not result.census.active
    assert slot.assessment().status == Outcome.UNKNOWN


@pytest.mark.parametrize("field", ["artifact_digest", "instruction_digest", "policy_digest", "context_digest",
                                  "session_id", "process_id", "generation"])
def test_grant_exact_tuple_substitution_refused(field: str) -> None:
    slot, authority, observer = host()
    value: str | int = 2 if field == "generation" else "other" if field.endswith("_id") else commitment("substitute")
    altered = replace(selection(), **{field: value})
    assert slot.grant(grant_for(altered)).status == Outcome.FAIL
    assert not slot.census().active and authority.calls == [] and observer.entries == []


@pytest.mark.parametrize("field", ["artifact_digest", "instruction_digest", "policy_digest", "context_digest",
                                  "session_id", "process_id", "generation", "permission_digest", "epoch"])
def test_ticket_substitution_denied_before_any_callback(field: str) -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "exact-ticket")
    if field in ("permission_digest", "epoch"):
        altered = replace(ticket, **{field: ticket.epoch + 1 if field == "epoch" else commitment("other-permission")})
    else:
        value: str | int = 2 if field == "generation" else "other" if field.endswith("_id") else commitment("substitute")
        altered = replace(ticket, selection=replace(ticket.selection, **{field: value}))
    effects: list[str] = []
    assert slot.invoke(altered, lambda: effects.append("forbidden")).status == Outcome.FAIL
    assert observer.entries == observer.attempts == [] and effects == []


def test_duplicate_activation_and_invocation_are_not_repeated() -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "once")
    effects: list[str] = []
    assert slot.invoke(ticket, lambda: effects.append("one")).status == Outcome.PASS
    assert slot.invoke(ticket, lambda: effects.append("two")).status == Outcome.FAIL
    assert slot.grant(grant_for(selection())).status == Outcome.FAIL
    assert effects == ["one"] and observer.entries == [ticket]


def test_successor_cannot_be_activated_twice_after_second_revocation() -> None:
    slot, _, _ = active_host()
    ready_successor(slot)
    grant = grant_for(selection(2), "successor", "fixture:external-successor")
    assert slot.grant(grant).status == Outcome.PASS
    assert slot.revoke(selection(2)).status == Outcome.PASS
    assert slot.drain().status == Outcome.PASS
    assert slot.grant(replace(grant, nonce="another-nonce")).status == Outcome.FAIL
    assert not slot.census().active


def test_observer_duplicate_boundary_enters_real_callback_only_once_and_fails() -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "duplicate-boundary")
    observer.duplicate = True
    effects: list[str] = []
    assert slot.invoke(ticket, lambda: effects.append("one")).status == Outcome.FAIL
    assert effects == ["one"] and observer.entries == [ticket]
    assert slot.assessment().status == Outcome.FAIL


def test_producer_false_without_an_actual_observed_attempt_is_unknown() -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "omitted-attempt")
    ready_successor(slot)
    observer.omit = True
    effects: list[str] = []
    assert slot.invoke(ticket, lambda: effects.append("old")).status == Outcome.UNKNOWN
    assert observer.attempts == observer.entries == [] and effects == []
    assert slot.assessment().status == Outcome.UNKNOWN


def test_contradictory_actual_entry_observation_is_fail() -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "contradiction")
    ready_successor(slot)
    observer.contradict = True
    effects: list[str] = []
    assert slot.invoke(ticket, lambda: effects.append("old")).status == Outcome.FAIL
    assert effects == [] and slot.assessment().status == Outcome.FAIL


@pytest.mark.parametrize("problem", ["missing", "contradictory", "outage"])
def test_drain_requires_actual_matching_observer_census(problem: str) -> None:
    slot, _, observer = active_host()
    slot.revoke(selection())
    observer.drain_missing = problem == "missing"
    observer.drain_contradict = problem == "contradictory"
    observer.outage = problem == "outage"
    result = slot.drain()
    assert result.status == (Outcome.FAIL if problem == "contradictory" else Outcome.UNKNOWN)
    slot.select_successor(selection(2))
    assert slot.grant(grant_for(selection(2), "successor", "fixture:external-successor")).status != Outcome.PASS
    assert not slot.census().active


def test_missing_stale_attempt_keeps_lifecycle_unknown_despite_new_entry() -> None:
    slot, _, observer = active_host()
    ready_successor(slot)
    assert slot.grant(grant_for(selection(2), "successor", "fixture:external-successor")).status == Outcome.PASS
    ticket = queued(slot, selection(2), "only-successor")
    assert slot.invoke(ticket, lambda: None).status == Outcome.PASS
    assert observer.entries == [ticket] and slot.assessment().status == Outcome.UNKNOWN


def test_restart_intent_cannot_reconstruct_activation_in_a_fresh_host() -> None:
    slot, _, _ = active_host()
    ready_successor(slot)
    intent = slot.select_successor(selection(2))
    fresh, _, _ = host()
    assert not fresh.census().active
    assert fresh.reconcile(intent).status == Outcome.UNKNOWN
    assert slot.reconcile(intent).status == Outcome.UNKNOWN and not slot.census().active


def test_cancellation_and_outage_preserve_prior_known_failure() -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "original")
    first = slot.queue(selection(), "original")
    assert first.status == Outcome.FAIL
    assert slot.cancel(ticket).status == Outcome.FAIL
    observer.outage = True
    assert slot.invoke(ticket, lambda: pytest.fail("forbidden callback")).status == Outcome.FAIL
    assert slot.assessment().status == Outcome.FAIL
    assert slot.assessment().reason == first.reason


def test_known_authority_failure_prevents_later_preparation_cancellation() -> None:
    slot, authority, _ = host()
    authority.status = Outcome.FAIL
    called: list[str] = []

    def prepare() -> None:
        called.append("prepare")
        raise OSError("cancelled")

    assert slot.grant(grant_for(selection()), prepare=prepare).status == Outcome.FAIL
    assert called == [] and slot.assessment().status == Outcome.FAIL


def test_event_and_queue_bounds_deny_work_without_erasing_known_state() -> None:
    slot, _, _ = active_host(max_events=1)
    result = slot.queue(selection(), "exhausted")
    assert result.status == Outcome.UNKNOWN and result.ticket is None and not result.census.active
    assert len(slot.trace()) == 1
    bounded, _, _ = active_host(max_queue=1)
    original = queued(bounded, selection(), "first")
    assert bounded.queue(selection(), "overflow").status == Outcome.UNKNOWN
    assert bounded.census().queued == (original,)


def test_anchored_trace_omission_substitution_and_missing_anchor() -> None:
    slot, _, _ = active_host()
    queued(slot, selection(), "anchored")
    events = slot.trace()
    fixture_anchor = trace_commitment(events)
    assert check_trace(events, expected_digest=fixture_anchor, expected_sequence=len(events)).status == Outcome.PASS
    assert check_trace(events[:-1], expected_digest=fixture_anchor, expected_sequence=len(events)).status == Outcome.FAIL
    substituted = (replace(events[0], action="substituted"), *events[1:])
    assert check_trace(substituted, expected_digest=fixture_anchor, expected_sequence=len(events)).status == Outcome.FAIL
    assert check_trace(events, expected_digest=None, expected_sequence=None).status == Outcome.UNKNOWN


def test_frozen_records_and_actual_host_process_are_required() -> None:
    selected = selection()
    with pytest.raises(FrozenInstanceError):
        selected.generation = 2
    with pytest.raises(ValueError, match="actual local host process"):
        PermissionSlot(replace(selected, process_id="other-process"))
    with pytest.raises(ValueError):
        replace(selected, generation=True)
    slot, _, _ = active_host()
    with pytest.raises(ValueError):
        slot.select_successor(replace(selection(2), process_id="other-process"))


def test_cancelled_queued_callback_does_not_enter_preparation_or_effect() -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "cancel-before-entry")
    assert slot.cancel(ticket).status == Outcome.PASS
    effects: list[str] = []

    def prepare() -> None:
        pytest.fail("cancelled work entered preparation")

    assert slot.invoke(ticket, lambda: effects.append("forbidden"), prepare=prepare).status == Outcome.PASS
    assert observer.attempts == [ticket] and observer.entries == [] and effects == []


@pytest.mark.parametrize("problem", ["unknown", "outage"])
def test_external_authority_unknown_or_outage_does_not_activate(problem: str) -> None:
    slot, authority, observer = host()
    authority.status = Outcome.UNKNOWN if problem == "unknown" else Outcome.PASS
    authority.outage = problem == "outage"
    assert slot.grant(grant_for(selection())).status == Outcome.UNKNOWN
    assert not slot.census().active and observer.entries == []


def test_effect_cannot_bypass_its_actual_instrumented_boundary() -> None:
    class BypassObserver(FixtureObserver):
        def invoke(self, ticket: Ticket,
                   boundary: Callable[[Callable[[], None]], BoundaryResult],
                   effect: Callable[[], None]) -> EntryObservation:
            effect()
            return EntryObservation(self.observer_id, ticket, 0, 1, 1, Outcome.PASS)

    observer = BypassObserver()
    slot, _, _ = active_host(observer=observer, observer_id=observer.observer_id)
    ticket = queued(slot, selection(), "bypass")
    effects: list[str] = []
    assert slot.invoke(ticket, lambda: effects.append("forbidden")).status == Outcome.FAIL
    assert effects == [] and slot.assessment().status == Outcome.FAIL


def test_observer_cannot_move_callback_entry_to_an_unselected_thread() -> None:
    class ThreadedObserver(FixtureObserver):
        def invoke(self, ticket: Ticket,
                   boundary: Callable[[Callable[[], None]], BoundaryResult],
                   effect: Callable[[], None]) -> EntryObservation:
            receipts: list[EntryObservation] = []

            def worker() -> None:
                receipts.append(super(ThreadedObserver, self).invoke(ticket, boundary, effect))

            thread = Thread(target=worker)
            thread.start()
            thread.join(3)
            if thread.is_alive() or not receipts:
                raise TimeoutError("fixture observer did not complete")
            return receipts[0]

    observer = ThreadedObserver()
    slot, _, _ = active_host(observer=observer, observer_id=observer.observer_id)
    ticket = queued(slot, selection(), "foreign-thread")
    effects: list[str] = []
    assert slot.invoke(ticket, lambda: effects.append("forbidden")).status == Outcome.FAIL
    assert observer.entries == [] and effects == []


def test_inflight_bound_is_checked_before_a_second_preparation() -> None:
    slot, _, observer = active_host(max_inflight=1)
    first = queued(slot, selection(), "first-inflight")
    second = queued(slot, selection(), "second-inflight")
    started, release = ThreadEvent(), ThreadEvent()
    effects: list[str] = []

    def prepare() -> None:
        started.set()
        if not release.wait(3):
            raise TimeoutError("fixture preparation not released")

    thread = Thread(target=lambda: slot.invoke(first, lambda: effects.append("first"), prepare=prepare))
    thread.start()
    try:
        assert started.wait(3)
        result = slot.invoke(second, lambda: effects.append("second"),
                             prepare=lambda: pytest.fail("inflight bound bypassed"))
        assert result.status == Outcome.UNKNOWN and slot.census().inflight == (first,)
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and effects == ["first"] and observer.entries == [first]


def test_read_only_capture_preserves_actual_observations_and_claim_limits() -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "capture")
    effects: list[str] = []
    assert slot.invoke(ticket, lambda: effects.append("once")).status == Outcome.PASS
    before = slot.trace()
    first, second = slot.capture(), slot.capture()
    assert first == second and slot.trace() == before
    assert effects == ["once"] and observer.entries == observer.exits == [ticket]
    record = json.loads(first)
    assert record["schema_version"] == "verifier-local-permission-slot-observation-1"
    assert record["result"]["scope"] == "finite-local-permission-slot-controls"
    assert record["result"]["native_corrigibility_conformance"] == "NOT_ESTABLISHED"
    assert record["result"]["authority_admission"] == record["result"]["observer_admission"] == "EXTERNAL_DEPENDENCY"
    assert record["terminal_sequence"] == len(before)
    assert record["trace_digest"] == trace_commitment(before)
    entry = [item for item in record["observations"] if item["kind"] == "EntryObservation"]
    assert len(entry) == 1 and entry[0]["record"]["entries"] == entry[0]["record"]["exits"] == 1


@pytest.mark.parametrize("dependency", ["verifier", "observer"])
@pytest.mark.parametrize("contradiction", ["tuple", "purpose", "authority"])
def test_known_grant_contradictions_precede_missing_dependencies(dependency: str, contradiction: str) -> None:
    slot, authority, observer = host(**{dependency: None})
    grant = grant_for(selection())
    if contradiction == "tuple":
        grant = replace(grant, selection=replace(selection(), artifact_digest=commitment("wrong-artifact")))
    elif contradiction == "purpose":
        grant = replace(grant, purpose="successor")
    else:
        grant = replace(grant, authority="fixture:not-admitted")
    result = slot.grant(grant)
    assert result.status == Outcome.FAIL and not result.census.active
    assert authority.calls == [] and observer.attempts == observer.entries == []
    assert slot.assessment().status == Outcome.FAIL


@pytest.mark.parametrize("dependency", ["verifier", "observer"])
def test_actual_revoked_initial_grant_is_refuted_despite_missing_dependency(
        dependency: str, monkeypatch: pytest.MonkeyPatch) -> None:
    slot, authority, observer = active_host()
    assert slot.revoke(selection()).status == Outcome.PASS
    cutoff = slot.census()
    # Fault injection removes one fixture dependency after actual old admission/revocation.
    monkeypatch.setattr(slot, "_" + dependency, None)
    grant = replace(grant_for(selection()), nonce="fresh-nonce-for-revoked-initial")
    result = slot.grant(grant)
    assert result.status == Outcome.FAIL
    assert result.reason == "revoked initial permission cannot be reactivated"
    assert result.census == cutoff and not result.census.active
    assert len(authority.calls) == 1 and observer.entries == []


@pytest.mark.parametrize("dependency", ["verifier", "observer"])
def test_actual_revoked_authority_is_refuted_despite_missing_dependency(
        dependency: str, monkeypatch: pytest.MonkeyPatch) -> None:
    slot, authority, observer = active_host()
    ready_successor(slot)
    cutoff = slot.census()
    monkeypatch.setattr(slot, "_" + dependency, None)
    result = slot.grant(grant_for(selection(2), "successor", "fixture:parent"))
    assert result.status == Outcome.FAIL
    assert result.reason == "unadmitted or revoked authority cannot grant permission"
    assert result.census == cutoff and not result.census.active
    assert len(authority.calls) == 1 and observer.entries == []


def test_empty_default_authority_admission_is_unknown_for_a_neutral_grant() -> None:
    slot = PermissionSlot(selection())
    result = slot.grant(grant_for(selection()))
    assert result.status == Outcome.UNKNOWN and not result.census.active
    assert slot.assessment().status == Outcome.UNKNOWN


@pytest.mark.parametrize("phase", ["prepare", "observer", "effect"])
def test_actual_cooperative_cancellation_releases_full_inflight_lifetime(
        phase: str, monkeypatch: pytest.MonkeyPatch) -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "actually-cancelled")
    effects: list[str] = []

    def cancel() -> None:
        raise CancelledError("actual fixture cooperative cancellation")

    def cancelled_observation(*args: object) -> EntryObservation:
        raise CancelledError("actual fixture observer cancellation")

    def effect() -> None:
        effects.append("entered")
        if phase == "effect":
            cancel()

    if phase == "observer":
        monkeypatch.setattr(observer, "invoke", cancelled_observation)
    result = slot.invoke(ticket, effect, prepare=cancel if phase == "prepare" else None)
    assert result.status == Outcome.UNKNOWN and "cancelled" in result.reason
    assert result.census.inflight == slot.census().inflight == ()
    assert effects == (["entered"] if phase == "effect" else [])
    assert observer.entries == observer.exits == ([ticket] if phase == "effect" else [])
    assert slot.revoke(selection()).status == Outcome.PASS
    assert slot.drain().status == Outcome.PASS
    assert slot.assessment().status == Outcome.UNKNOWN


@pytest.mark.parametrize("phase", ["verification", "preparation"])
@pytest.mark.parametrize("known_failure", [False, True])
def test_actual_grant_cancellation_never_activates_or_softens_known_failure(
        phase: str, known_failure: bool) -> None:
    slot, authority, observer = host()
    reasons: list[str] = []

    def cancel() -> None:
        if known_failure:
            result = slot.queue(replace(selection(), artifact_digest=commitment("wrong-before-cancel")), "bad-before-cancel")
            assert result.status == Outcome.FAIL
            reasons.append(result.reason)
        raise CancelledError("actual fixture grant cancellation")

    if phase == "verification":
        authority.before_return = cancel
    result = slot.grant(grant_for(selection()), prepare=cancel if phase == "preparation" else None)
    assert result.status == (Outcome.FAIL if known_failure else Outcome.UNKNOWN)
    assert not result.census.active and result.census.inflight == () and observer.entries == []
    if known_failure:
        assert result.reason == reasons[0] and slot.assessment().status == Outcome.FAIL
    else:
        assert "cancelled" in result.reason and slot.assessment().status == Outcome.UNKNOWN


def test_actual_drain_cancellation_does_not_declare_drain_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    slot, _, observer = active_host()
    assert slot.revoke(selection()).status == Outcome.PASS

    def cancelled_drain(read_census: Callable[[], Census]) -> DrainObservation:
        raise CancelledError("actual fixture drain cancellation")

    monkeypatch.setattr(observer, "drain", cancelled_drain)
    result = slot.drain()
    assert result.status == Outcome.UNKNOWN and "cancelled" in result.reason
    slot.select_successor(selection(2))
    assert slot.grant(grant_for(selection(2), "successor", "fixture:external-successor")).status == Outcome.UNKNOWN
    assert not slot.census().active


def test_actual_observer_cancellation_preserves_known_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "known-failure-before-cancel")
    first = slot.queue(selection(), ticket.invocation_id)
    assert first.status == Outcome.FAIL

    def cancelled_observation(*args: object) -> EntryObservation:
        raise CancelledError("actual fixture observer cancellation")

    monkeypatch.setattr(observer, "invoke", cancelled_observation)
    result = slot.invoke(ticket, lambda: pytest.fail("known failure permitted effect"))
    assert result.status == Outcome.FAIL and result.reason == first.reason
    assert result.census.inflight == slot.census().inflight == ()
    assert slot.assessment().status == Outcome.FAIL and observer.entries == []


def test_other_baseexception_also_cleans_registered_inflight_lifetime() -> None:
    class FixtureAbort(BaseException):
        pass

    slot, _, observer = active_host()
    ticket = queued(slot, selection(), "aborted-preparation")

    def prepare() -> None:
        raise FixtureAbort("fixture abrupt abort")

    with pytest.raises(FixtureAbort):
        slot.invoke(ticket, lambda: pytest.fail("aborted preparation entered effect"), prepare=prepare)
    assert slot.census().inflight == () and observer.entries == []
    assert slot.revoke(selection()).status == Outcome.PASS
    assert slot.drain().status == Outcome.PASS


def test_authority_element_validation_precedes_foreign_hash_callbacks() -> None:
    hash_calls: list[str] = []

    class ForeignAuthority:
        def __hash__(self) -> int:
            hash_calls.append("called")
            raise AssertionError("foreign authority hash was invoked")

    with pytest.raises(ValueError, match="bounded nonempty identifier"):
        PermissionSlot(selection(), authorities=(ForeignAuthority(),))
    assert hash_calls == []


def test_authority_identifier_length_is_bounded_before_admission() -> None:
    accepted = PermissionSlot(selection(), authorities=("a" * 256,))
    assert not accepted.census().active
    with pytest.raises(ValueError, match="bounded nonempty identifier"):
        PermissionSlot(selection(), authorities=("a" * 257,))
