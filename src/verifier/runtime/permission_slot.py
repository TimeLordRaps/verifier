"""Bounded local permission revocation and one separately admitted successor.

application programming interface (API); Secure Hash Algorithm 256-bit (SHA-256).
This host control does not register a native objective, issue a certificate, prove
observer independence, or discharge a Verifier Standard numbered-profile rung.
All work in the selected local boundary must enter through this slot. Admission
of its external grant verifier, authority roots and callback observer is a caller
dependency. A test fixture supplies no production authority. Counts are finite
dimensionless values; no elapsed-time, availability or erasure claim is made.
"""
from __future__ import annotations

from asyncio import CancelledError
from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from os import getpid
import re
from threading import RLock, get_ident
from typing import Callable, Protocol


class Outcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


def _identifier(value: str) -> None:
    if type(value) is not str or len(value) > 256 or not value.strip():
        raise ValueError("bounded nonempty identifier required")


def _digest(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("canonical SHA-256 commitment required")


def _bound(value: int, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("finite plain-integer bound required")


def _counter(value: int, maximum: int = 2**63 - 1) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("bounded plain-integer counter required")


def _outcome(value: Outcome) -> None:
    if type(value) is not Outcome:
        raise ValueError("plain outcome enumeration required")


@dataclass(frozen=True)
class Selection:
    artifact_digest: str
    instruction_digest: str
    policy_digest: str
    context_digest: str
    session_id: str
    process_id: str
    generation: int

    def __post_init__(self) -> None:
        for value in (self.artifact_digest, self.instruction_digest,
                      self.policy_digest, self.context_digest):
            _digest(value)
        _identifier(self.session_id)
        _identifier(self.process_id)
        _bound(self.generation, 2**63 - 1)


@dataclass(frozen=True)
class Grant:
    selection: Selection
    authority: str
    permission_digest: str
    revocation_view_digest: str
    evidence_digest: str
    nonce: str
    purpose: str

    def __post_init__(self) -> None:
        if (type(self.selection) is not Selection or type(self.purpose) is not str
                or self.purpose not in ("initial", "successor")):
            raise ValueError("exact selection and grant purpose required")
        _identifier(self.authority)
        _identifier(self.nonce)
        for value in (self.permission_digest, self.revocation_view_digest, self.evidence_digest):
            _digest(value)


@dataclass(frozen=True)
class Ticket:
    invocation_id: str
    selection: Selection
    permission_digest: str
    epoch: int

    def __post_init__(self) -> None:
        _identifier(self.invocation_id)
        _digest(self.permission_digest)
        _bound(self.epoch, 2**63 - 1)
        if type(self.selection) is not Selection:
            raise ValueError("exact immutable ticket selection required")


@dataclass(frozen=True)
class RestartIntent:
    old: Selection
    successor: Selection
    epoch: int

    def __post_init__(self) -> None:
        if type(self.old) is not Selection or type(self.successor) is not Selection:
            raise ValueError("exact immutable intent selections required")
        _counter(self.epoch)


@dataclass(frozen=True)
class Census:
    selection: Selection
    epoch: int
    active: bool
    queued: tuple[Ticket, ...]
    inflight: tuple[Ticket, ...]
    permission_digest: str | None = None
    authority: str | None = None

    def __post_init__(self) -> None:
        if type(self.selection) is not Selection or type(self.active) is not bool:
            raise ValueError("exact immutable census fields required")
        _counter(self.epoch)
        for tickets in (self.queued, self.inflight):
            if type(tickets) is not tuple or len(tickets) > 4096 or any(type(item) is not Ticket for item in tickets):
                raise ValueError("finite immutable ticket census required")
        if self.permission_digest is not None:
            _digest(self.permission_digest)
        if self.authority is not None:
            _identifier(self.authority)


@dataclass(frozen=True)
class Event:
    sequence: int
    action: str
    selection: Selection
    epoch: int
    invocation_id: str = ""
    ticket: Ticket | None = None

    def __post_init__(self) -> None:
        _bound(self.sequence, 16384)
        _counter(self.epoch)
        _identifier(self.action)
        if type(self.selection) is not Selection or type(self.invocation_id) is not str:
            raise ValueError("exact immutable event fields required")
        if self.ticket is not None and (type(self.ticket) is not Ticket
                or self.ticket.selection != self.selection or self.ticket.invocation_id != self.invocation_id):
            raise ValueError("event ticket binding differs")


@dataclass(frozen=True)
class Result:
    status: Outcome
    reason: str
    census: Census
    ticket: Ticket | None = None
    scope: str = "finite-local-permission-slot-controls"
    native_corrigibility_conformance: str = "NOT_ESTABLISHED"
    authority_admission: str = "EXTERNAL_DEPENDENCY"
    observer_admission: str = "EXTERNAL_DEPENDENCY"

    def __post_init__(self) -> None:
        _outcome(self.status)
        _identifier(self.reason)
        if type(self.census) is not Census or (self.ticket is not None and type(self.ticket) is not Ticket):
            raise ValueError("exact immutable result required")


@dataclass(frozen=True)
class GrantDecision:
    status: Outcome
    grant: Grant
    epoch: int

    def __post_init__(self) -> None:
        _outcome(self.status)
        _counter(self.epoch)
        if type(self.grant) is not Grant:
            raise ValueError("exact verified grant required")


@dataclass(frozen=True)
class BoundaryResult:
    status: Outcome
    entered: bool
    reason: str

    def __post_init__(self) -> None:
        _outcome(self.status)
        _identifier(self.reason)
        if type(self.entered) is not bool:
            raise ValueError("plain entry indicator required")


@dataclass(frozen=True)
class EntryObservation:
    observer_id: str
    ticket: Ticket
    attempts: int
    entries: int
    exits: int
    status: Outcome

    def __post_init__(self) -> None:
        _outcome(self.status)
        _identifier(self.observer_id)
        if type(self.ticket) is not Ticket:
            raise ValueError("exact observed ticket required")
        for value in (self.attempts, self.entries, self.exits):
            _counter(value, 4096)


@dataclass(frozen=True)
class DrainObservation:
    observer_id: str
    census: Census
    status: Outcome

    def __post_init__(self) -> None:
        _outcome(self.status)
        _identifier(self.observer_id)
        if type(self.census) is not Census:
            raise ValueError("exact observed census required")


@dataclass(frozen=True)
class TraceCheck:
    status: Outcome
    reason: str

    def __post_init__(self) -> None:
        _outcome(self.status)
        _identifier(self.reason)


def trace_commitment(events: tuple[Event, ...]) -> str:
    """Commit local trace bytes; a producer-selected anchor supplies no admission."""
    if type(events) is not tuple or len(events) > 16384 or any(type(item) is not Event for item in events):
        raise ValueError("bounded immutable event tuple required")
    encoded = json.dumps([asdict(item) for item in events], sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def check_trace(events: tuple[Event, ...], *, expected_digest: str | None,
                expected_sequence: int | None) -> TraceCheck:
    """Check exact external anchoring only; this never replays lifecycle effects."""
    if expected_digest is None or expected_sequence is None:
        return TraceCheck(Outcome.UNKNOWN, "independently selected terminal trace anchor missing")
    _digest(expected_digest)
    _bound(expected_sequence, 16384)
    try:
        actual = trace_commitment(events)
    except (ValueError, TypeError):
        return TraceCheck(Outcome.FAIL, "trace structure differs")
    if (len(events) != expected_sequence or actual != expected_digest
            or tuple(item.sequence for item in events) != tuple(range(1, expected_sequence + 1))):
        return TraceCheck(Outcome.FAIL, "trace differs from exact independently selected terminal anchor")
    return TraceCheck(Outcome.PASS, "exact anchored trace bytes and event sequence reproduced")


class GrantVerifier(Protocol):
    def verify(self, grant: Grant, *, expected: Selection,
               revoked: Selection | None, epoch: int) -> GrantDecision: ...


class EntryObserver(Protocol):
    def invoke(self, ticket: Ticket,
               boundary: Callable[[Callable[[], None]], BoundaryResult],
               effect: Callable[[], None]) -> EntryObservation: ...

    def drain(self, read_census: Callable[[], Census]) -> DrainObservation: ...


class _Refused(Exception):
    pass


class PermissionSlot:
    """One process-local boundary; construction creates an inactive selected slot.

    External dependencies are explicitly supplied and admitted by the caller.
    Observer invocation must be synchronous on the caller thread and instrument
    actual entry/exit of the supplied effect through the supplied boundary.
    User preparation, grant verification and observer setup precede final checks.
    A callback already entered before revocation may finish; it is not preempted.
    """

    def __init__(self, initial: Selection, *, authorities: tuple[str, ...] = (),
                 verifier: GrantVerifier | None = None,
                 observer: EntryObserver | None = None, observer_id: str | None = None,
                 max_queue: int = 32, max_inflight: int = 8,
                 max_invocations: int = 128, max_events: int = 512) -> None:
        if type(initial) is not Selection or type(authorities) is not tuple:
            raise ValueError("immutable selection and authority tuple required")
        self._host_process = str(getpid())
        if initial.process_id != self._host_process:
            raise ValueError("selected process must be the actual local host process")
        if len(authorities) > 16:
            raise ValueError("at most sixteen distinct admitted authority identifiers")
        for authority in authorities:
            _identifier(authority)
        if len(set(authorities)) != len(authorities):
            raise ValueError("at most sixteen distinct admitted authority identifiers")
        if observer_id is not None:
            _identifier(observer_id)
        for value in (max_queue, max_inflight, max_invocations):
            _bound(value, 4096)
        _bound(max_events, 16384)
        self._lock = RLock()
        self._initial = self._selected = initial
        self._authorities, self._verifier = authorities, verifier
        self._observer, self._observer_id = observer, observer_id
        self._max_queue, self._max_inflight = max_queue, max_inflight
        self._max_invocations, self._max_events = max_invocations, max_events
        self._epoch, self._active, self._halted = 0, False, False
        self._permission: str | None = None
        self._authority: str | None = None
        self._revoked, self._drained = False, False
        self._revoked_authorities: set[str] = set()
        self._grant_nonces: set[str] = set()
        self._intent: RestartIntent | None = None
        self._tickets: dict[str, Ticket] = {}
        self._states: dict[str, str] = {}
        self._queue: set[str] = set()
        self._inflight: set[str] = set()
        self._cancelled: set[str] = set()
        self._events: list[Event] = []
        self._observations: list[GrantDecision | EntryObservation | DrainObservation] = []
        self._failure: str | None = None
        self._unknown: str | None = None
        self._attempt_count = 0
        self._successor_committed = self._stale_observed = self._successor_observed = False
        self._initial_admitted = False

    def census(self) -> Census:
        with self._lock:
            return Census(self._selected, self._epoch, self._active,
                          tuple(self._tickets[key] for key in sorted(self._queue)),
                          tuple(self._tickets[key] for key in sorted(self._inflight)),
                          self._permission, self._authority)

    def trace(self) -> tuple[Event, ...]:
        with self._lock:
            return tuple(self._events)

    def observations(self) -> tuple[GrantDecision | EntryObservation | DrainObservation, ...]:
        with self._lock:
            return tuple(self._observations)

    def capture(self) -> bytes:
        """Read immutable bounded observation bytes; do not repeat any callback.

        This local observation envelope is neither a native certificate nor an
        admission proof. Independently selected roots and signature verification
        belong to the separate native consumer, not to these serialized labels.
        """
        with self._lock:
            value = {
                "schema_version": "verifier-local-permission-slot-observation-1",
                "initial": asdict(self._initial),
                "intent": asdict(self._intent) if self._intent else None,
                "result": asdict(self.assessment()),
                "terminal_sequence": len(self._events),
                "trace_digest": trace_commitment(tuple(self._events)),
                "events": [asdict(item) for item in self._events],
                "observations": [{"kind": type(item).__name__, "record": asdict(item)}
                                 for item in self._observations],
            }
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True, allow_nan=False).encode("utf-8")
            if len(encoded) > 16 * 1024 * 1024:
                raise ValueError("finite sixteen-mebibyte capture bound exceeded")
            return encoded

    def _result(self, status: Outcome, reason: str, ticket: Ticket | None = None) -> Result:
        return Result(Outcome.FAIL if self._failure else status,
                      self._failure or reason, self.census(), ticket)

    def _fail(self, reason: str) -> Result:
        self._failure = self._failure or reason
        return self._result(Outcome.FAIL, reason)

    def _unavailable(self, reason: str) -> Result:
        self._unknown = self._unknown or reason
        return self._result(Outcome.UNKNOWN, reason)

    def _record(self, action: str, invocation_id: str = "", ticket: Ticket | None = None) -> bool:
        if len(self._events) >= self._max_events:
            self._halted, self._active = True, False
            self._epoch += 1
            self._cancelled.update(self._queue)
            self._queue.clear()
            self._unknown = self._unknown or "finite event bound exhausted"
            return False
        ticket = ticket or self._tickets.get(invocation_id)
        selection = ticket.selection if ticket else self._selected
        self._events.append(Event(len(self._events) + 1, action, selection,
                                  self._epoch, invocation_id, ticket))
        return True

    def _observe(self, observation: GrantDecision | EntryObservation | DrainObservation) -> bool:
        if len(self._observations) >= self._max_events:
            self._halted, self._active = True, False
            self._epoch += 1
            self._cancelled.update(self._queue)
            self._queue.clear()
            self._unknown = self._unknown or "finite observation bound exhausted"
            return False
        self._observations.append(observation)
        return True

    def grant(self, grant: Grant, *, prepare: Callable[[], None] | None = None) -> Result:
        with self._lock:
            if type(grant) is not Grant:
                return self._fail("grant record differs")
            if grant.nonce in self._grant_nonces or self._active:
                return self._fail("duplicate or competing activation")
            if self._successor_committed:
                return self._fail("one successor activation was already committed")
            successor = self._intent is not None
            expected = self._intent.successor if self._intent else self._initial
            # Refute known contradictions before considering unavailable dependencies.
            if grant.selection != expected or grant.purpose != ("successor" if successor else "initial"):
                return self._fail("grant differs from independently selected tuple or purpose")
            if not successor and self._revoked:
                return self._fail("revoked initial permission cannot be reactivated")
            if self._authorities and (grant.authority not in self._authorities
                                     or grant.authority in self._revoked_authorities):
                return self._fail("unadmitted or revoked authority cannot grant permission")
            if self._halted or self._failure:
                return self._result(Outcome.UNKNOWN, "host is halted")
            if not self._authorities or self._verifier is None or self._observer is None or self._observer_id is None:
                return self._unavailable("grant authority, verifier or admitted observer unavailable")
            if successor and (not self._initial_admitted or not self._revoked or not self._drained or self._queue or self._inflight):
                return self._unavailable("revocation and observed drain are not complete")
            epoch, previous, intent = self._epoch, self._selected, self._intent
        try:
            decision = self._verifier.verify(grant, expected=expected,
                                             revoked=self._initial if successor else None, epoch=epoch)
        except CancelledError:
            with self._lock:
                return self._unavailable("external grant verification cancelled")
        except Exception:
            with self._lock:
                return self._unavailable("external grant verification unavailable")
        with self._lock:
            if type(decision) is not GrantDecision:
                return self._unavailable("external grant decision missing")
            if decision.grant != grant or type(decision.epoch) is not int or decision.epoch != epoch:
                return self._fail("external grant decision binding contradicts selection")
            if decision.status != Outcome.PASS:
                if decision.status == Outcome.FAIL:
                    self._fail("external grant rejected")
                self._observe(decision)
                return self._result(Outcome.FAIL, "external grant rejected") if decision.status == Outcome.FAIL else self._unavailable("external grant authority unknown")
            if not self._observe(decision):
                return self._result(Outcome.UNKNOWN, "grant observation capacity unavailable")
            if self._failure:
                return self._result(Outcome.FAIL, "prior failure prevents grant preparation")
        try:
            if prepare is not None:
                prepare()
        except CancelledError:
            with self._lock:
                return self._unavailable("grant preparation cancelled")
        except Exception:
            with self._lock:
                return self._unavailable("external verification or preparation unavailable")
        with self._lock:
            # This is the authority/generation commit, after every external callback.
            if (self._epoch != epoch or self._selected != previous or self._intent != intent
                    or self._active or self._halted or self._failure or self._inflight or self._queue
                    or grant.authority in self._revoked_authorities):
                return self._result(Outcome.UNKNOWN, "slot changed before atomic grant commit")
            self._epoch += 1
            self._selected, self._permission, self._authority = expected, grant.permission_digest, grant.authority
            if not self._record("successor_grant" if successor else "initial_grant"):
                return self._result(Outcome.UNKNOWN, "grant trace unavailable")
            self._active = True
            self._grant_nonces.add(grant.nonce)
            self._successor_committed = successor
            self._initial_admitted = self._initial_admitted or not successor
            return self._result(Outcome.PASS, "exact selected grant committed")

    def queue(self, selection: Selection, invocation_id: str) -> Result:
        _identifier(invocation_id)
        with self._lock:
            if type(selection) is not Selection or selection != self._selected:
                return self._fail("queued tuple differs from active selection")
            if invocation_id in self._tickets:
                return self._fail("duplicate invocation identifier")
            if not self._active or self._halted or self._failure:
                return self._result(Outcome.UNKNOWN, "permission is inactive")
            if len(self._queue) >= self._max_queue or len(self._tickets) >= self._max_invocations:
                return self._unavailable("finite queue or invocation bound exhausted")
            ticket = Ticket(invocation_id, selection, self._permission, self._epoch)
            if not self._record("queued", invocation_id, ticket):
                return self._result(Outcome.UNKNOWN, "queue trace unavailable")
            self._tickets[invocation_id], self._states[invocation_id] = ticket, "queued"
            self._queue.add(invocation_id)
            return self._result(Outcome.PASS, "invocation registered", ticket)

    def revoke(self, expected: Selection) -> Result:
        with self._lock:
            if expected != self._selected:
                return self._fail("revocation tuple differs from actual slot")
            if self._halted:
                return self._result(Outcome.UNKNOWN, "host is halted")
            if not self._active:
                self._epoch += 1
                self._revoked, self._drained = True, False
                self._record("revocation_cutoff_refreshed")
                return self._result(Outcome.PASS if self._initial_admitted else Outcome.UNKNOWN,
                                    "fresh revocation cutoff invalidates pending grant preparations")
            self._epoch += 1
            self._active, self._revoked, self._drained = False, True, False
            self._revoked_authorities.add(self._authority)
            self._cancelled.update(self._queue)
            for key in self._queue:
                self._states[key] = "revoked"
            self._queue.clear()
            if not self._record("revoked"):
                return self._result(Outcome.UNKNOWN, "revocation applied; trace unavailable")
            return self._result(Outcome.PASS, "old admissions revoked; admitted inflight work remains counted")

    def drain(self) -> Result:
        with self._lock:
            if self._halted:
                return self._result(Outcome.UNKNOWN, "host is halted")
            expected = self.census()
            if not self._revoked or expected.active or expected.queued or expected.inflight:
                return self._result(Outcome.UNKNOWN, "finite local work is not drained")
            if self._observer is None or self._observer_id is None:
                return self._unavailable("admitted drain observer unavailable")
        try:
            observed = self._observer.drain(self.census)
        except CancelledError:
            with self._lock:
                return self._unavailable("drain observation cancelled")
        except Exception:
            with self._lock:
                return self._unavailable("drain observer unavailable")
        with self._lock:
            if type(observed) is not DrainObservation:
                return self._unavailable("drain observation missing")
            if observed.observer_id != self._observer_id or observed.census != expected:
                return self._fail("drain observation contradicts actual finite census")
            if observed.status != Outcome.PASS:
                return self._fail("drain observer reported failure") if observed.status == Outcome.FAIL else self._unavailable("drain observation unknown")
            if self.census() != expected or self._halted:
                return self._result(Outcome.UNKNOWN, "actual slot changed during drain observation")
            if not self._observe(observed):
                return self._result(Outcome.UNKNOWN, "drain observation capacity unavailable")
            if not self._record("drained"):
                return self._result(Outcome.UNKNOWN, "drain trace unavailable")
            self._drained = True
            return self._result(Outcome.PASS, "selected observer read an empty actual local census")

    def select_successor(self, successor: Selection) -> RestartIntent:
        with self._lock:
            if (type(successor) is not Selection or successor.generation != self._initial.generation + 1
                    or successor.process_id != self._host_process or self._halted):
                raise ValueError("exact independently selected next generation required")
            intent = RestartIntent(self._initial, successor, self._epoch)
            if self._intent is not None and self._intent.successor != successor:
                raise ValueError("successor selection is already frozen")
            if self._intent is None:
                self._intent = intent
                self._record("restart_intent")
            return self._intent

    def reconcile(self, intent: RestartIntent) -> Result:
        with self._lock:
            if type(intent) is not RestartIntent:
                return self._fail("restart intent differs from frozen selection")
            if self._intent is None:
                if (intent.old != self._initial or intent.successor.generation != self._initial.generation + 1
                        or intent.successor.process_id != self._host_process):
                    return self._fail("restart intent tuple contradicts actual host selection")
                return self._result(Outcome.UNKNOWN, "recorded intent has no actual committed successor state")
            if intent != self._intent:
                return self._fail("restart intent differs from frozen selection")
            if self._successor_committed and self._selected == intent.successor and self._active:
                return self._result(Outcome.PASS, "actual in-memory slot contains committed successor")
            return self._result(Outcome.UNKNOWN, "restart intent is not an active committed slot")

    def cancel(self, ticket: Ticket) -> Result:
        with self._lock:
            if type(ticket) is not Ticket or self._tickets.get(ticket.invocation_id) != ticket:
                return self._fail("cancelled ticket differs from registered work")
            if self._halted:
                return self._result(Outcome.UNKNOWN, "host is halted")
            self._cancelled.add(ticket.invocation_id)
            self._queue.discard(ticket.invocation_id)
            self._record("cancel_requested", ticket.invocation_id)
            return self._result(Outcome.UNKNOWN if ticket.invocation_id in self._inflight else Outcome.PASS,
                                "cancellation requested; entered callback is not preempted", ticket)

    def invoke(self, ticket: Ticket, effect: Callable[[], None], *,
               prepare: Callable[[], None] | None = None) -> Result:
        with self._lock:
            if type(ticket) is not Ticket or self._tickets.get(ticket.invocation_id) != ticket:
                return self._fail("invocation ticket differs from registered exact tuple")
            key = ticket.invocation_id
            if key in self._inflight or self._states[key] in ("entered", "finished", "attempted"):
                return self._fail("duplicate callback invocation")
            if self._observer is None or self._observer_id is None:
                return self._unavailable("admitted callback-entry observer unavailable")
            if self._attempt_count >= self._max_invocations or self._halted:
                return self._unavailable("finite attempt or event bound exhausted")
            admitted = (self._active and not self._failure and key not in self._cancelled
                        and ticket.selection == self._selected and ticket.epoch == self._epoch)
            if admitted and len(self._inflight) >= self._max_inflight:
                return self._unavailable("finite inflight bound exhausted")
            self._attempt_count += 1
            self._queue.discard(key)
            self._states[key] = "attempted"
            if admitted:
                self._inflight.add(key)
            if not self._record("callback_attempt", key):
                self._inflight.discard(key)
                return self._result(Outcome.UNKNOWN, "attempt trace unavailable")
        result: Result | None = None
        unavailable_reason: str | None = None
        try:
            if admitted and prepare is not None:
                prepare()
            result = self._invoke_observed(ticket, effect)
        except CancelledError:
            unavailable_reason = "callback preparation or observation cancelled"
        except Exception:
            unavailable_reason = "callback preparation or observation unavailable"
        finally:
            # Every BaseException path releases the complete admitted lifetime.
            with self._lock:
                self._inflight.discard(key)
        with self._lock:
            if unavailable_reason is not None:
                return self._unavailable(unavailable_reason)
            if result is None:
                return self._unavailable("callback result missing")
            return self._result(result.status, result.reason, result.ticket)

    def _invoke_observed(self, ticket: Ticket, effect: Callable[[], None]) -> Result:
        key = ticket.invocation_id
        owner, attempts, entries, exits = get_ident(), 0, 0, 0
        boundary_open = False
        refused = False

        def actual_effect() -> None:
            nonlocal entries, exits
            with self._lock:
                if not boundary_open or get_ident() != owner or entries:
                    self._fail("effect bypassed or duplicated its instrumented boundary")
                    raise _Refused()
                if str(getpid()) != ticket.selection.process_id:
                    self._fail("actual host process differs from selected callback process")
                    raise _Refused()
                # The observer may run setup before this call: recheck AFTER it.
                if (not self._active or self._halted or self._failure or key in self._cancelled
                        or self._selected != ticket.selection or self._permission != ticket.permission_digest
                        or self._epoch != ticket.epoch):
                    raise _Refused()
                if not self._record("callback_entry", key):
                    raise _Refused()
                entries += 1
                self._states[key] = "entered"
                try:
                    effect()
                finally:
                    exits += 1
                    self._record("callback_exit", key)

        def boundary(observed_effect: Callable[[], None]) -> BoundaryResult:
            nonlocal attempts, boundary_open, refused
            with self._lock:
                attempts += 1
                if attempts != 1 or get_ident() != owner:
                    self._fail("observer duplicated or moved the selected callback boundary")
                    return BoundaryResult(Outcome.FAIL, False, "invalid observer boundary")
                if (not self._active or self._halted or self._failure or key in self._cancelled
                        or self._selected != ticket.selection or self._permission != ticket.permission_digest
                        or self._epoch != ticket.epoch):
                    refused = True
                    return BoundaryResult(Outcome.PASS, False, "stale or revoked callback refused before entry")
                boundary_open = True
                try:
                    observed_effect()
                except _Refused:
                    refused = True
                    return BoundaryResult(Outcome.FAIL if self._failure else Outcome.PASS, False, "permission refused at final callback entry")
                except Exception:
                    self._unknown = self._unknown or "entered callback did not complete normally"
                    return BoundaryResult(Outcome.UNKNOWN, bool(entries), "callback unavailable")
                finally:
                    boundary_open = False
                return BoundaryResult(Outcome.PASS if entries == 1 else Outcome.UNKNOWN,
                                      entries == 1, "instrumented callback boundary completed")

        observed = self._observer.invoke(ticket, boundary, actual_effect)
        with self._lock:
            if type(observed) is not EntryObservation:
                return self._unavailable("actual callback observation missing")
            if (observed.observer_id != self._observer_id or observed.ticket != ticket
                    or type(observed.attempts) is not int or type(observed.entries) is not int
                    or type(observed.exits) is not int
                    or (observed.attempts, observed.entries, observed.exits) != (attempts, entries, exits)):
                return self._fail("trusted callback observation contradicts actual boundary")
            if observed.status == Outcome.FAIL:
                return self._fail("trusted callback observer reported failure")
            if observed.status != Outcome.PASS or attempts != 1:
                return self._unavailable("trusted callback observation incomplete or unknown")
            if not self._observe(observed):
                return self._result(Outcome.UNKNOWN, "callback observation capacity unavailable")
            if refused and entries == 0:
                if self._drained and ticket.selection == self._initial and self._revoked:
                    self._stale_observed = True
                if not self._record("callback_refused", key):
                    return self._result(Outcome.UNKNOWN, "refusal trace unavailable", ticket)
                return self._result(Outcome.PASS, "observed actual attempt refused before callback entry", ticket)
            if entries != 1 or exits != 1:
                return self._unavailable("observer did not instrument actual callback entry and exit")
            self._states[key] = "finished"
            if self._successor_committed and ticket.selection == self._selected:
                self._successor_observed = True
            return self._result(Outcome.UNKNOWN if self._unknown else Outcome.PASS,
                                self._unknown or "observed actual callback completed", ticket)

    def assessment(self) -> Result:
        with self._lock:
            complete = (self._revoked and self._drained and self._successor_committed
                        and self._stale_observed and self._successor_observed)
            if self._unknown or self._halted or not complete:
                return self._result(Outcome.UNKNOWN, self._unknown or "selected lifecycle observations incomplete")
            return self._result(Outcome.PASS, "finite selected local replacement lifecycle observed")
