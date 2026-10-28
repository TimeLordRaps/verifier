"""Cooperative in-process stop gate around controlled certificate emission.

The gate recomputes the existing consent, governance, privacy, transparency, and
computational checks for each attempted emission. A trusted host must supply
current policies, status records, time, and observer identity; the candidate
certificate cannot choose its own authority. Only a returned PASS admits a
callback. Stop is permanent for this session, and quiescence means that every
locally tracked invocation has returned. It does not prove remote publication,
process termination, or the absence of effects outside this cooperating gate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
import secrets
from threading import Condition
from time import monotonic, time
from typing import Any, Callable

from verifier.controlled_emission import evaluate_controlled_emission
from .operator_stop import OperatorStopPolicy, evaluate_stop_request


_MAX_SPENT_INVOCATIONS = 4096  # Finite local memory; exhausted sessions refuse further effects.


@dataclass(frozen=True)
class StopObservation:
    """Local state at a stop request; active counts are dimensionless."""

    state: str
    active_invocations: int
    authorization: str = "NOT_REQUIRED"
    request_digest: str | None = field(default=None, repr=False)
    stop_latched: bool = False


@dataclass(frozen=True)
class ControlledInvocation:
    """One local attempt; the private gate receipt must be disclosure-reviewed."""

    control_status: str
    admission: str
    effect_called: bool
    gate_receipt: dict[str, Any] | None = field(default=None, repr=False)
    value: Any = field(default=None, repr=False)


class ControlledEmissionSession:
    """Latch an operator stop and account for cooperating local invocations.

    An invocation is marked active before checking the underlying admission
    gates. A callback becomes locally admitted while holding the same lock that
    latches stop. A stop racing after that point reports STOP_REQUESTED until
    the callback returns; it never claims to preempt an in-flight callback.
    """

    def __init__(self, *, stop_authority: OperatorStopPolicy | None = None) -> None:
        if stop_authority is not None and type(stop_authority) is not OperatorStopPolicy:
            raise TypeError("stop_authority must be a trusted OperatorStopPolicy")
        self._condition = Condition()
        self._stop_requested = False
        self._active_invocations = 0
        self._spent_invocations: set[str] = set()
        self._stop_authority = stop_authority
        self._session_id = secrets.token_hex(16)
        self._process_id = os.getpid()

    @property
    def session_id(self) -> str:
        """Random local session coordinate; it carries no authority by itself."""
        return self._session_id

    @property
    def process_id(self) -> int:
        """Operating-system process identifier captured when this session began."""
        return self._process_id

    @property
    def stop_requested(self) -> bool:
        """Read the local latch; in protected sessions only an admitted STOP sets it.

        This thread-safe observation does not assert cancellation of work that
        was admitted before the latch. A callback must cooperate to exit.
        """
        with self._condition:
            return self._stop_requested

    def request_stop(self, request: dict[str, Any] | None = None) -> StopObservation:
        """Latch stop only after configured-key authentication when required.

        A protected session refuses an absent, forged or stale request without
        latching. Authentication finishes before the stop is acknowledged;
        effects admitted earlier may still be active.
        """
        authorization, request_digest = "NOT_REQUIRED", None
        if self._stop_authority is None:
            if request is not None:
                with self._condition:
                    return StopObservation("AUTHORIZATION_REFUSED", self._active_invocations,
                                           "REJECTED", stop_latched=self._stop_requested)
        else:
            if os.getpid() != self.process_id:
                with self._condition:
                    return StopObservation("AUTHORIZATION_UNKNOWN", self._active_invocations,
                                           "UNKNOWN", stop_latched=self._stop_requested)
            authorization, request_digest = evaluate_stop_request(
                self._stop_authority, self.session_id, self.process_id, request, int(time()))
            if authorization != "PASS":
                with self._condition:
                    state = "AUTHORIZATION_UNKNOWN" if authorization == "UNKNOWN" else "AUTHORIZATION_REFUSED"
                    return StopObservation(state, self._active_invocations, authorization,
                                           stop_latched=self._stop_requested)
        with self._condition:
            self._stop_requested = True
            state = "QUIESCENT" if self._active_invocations == 0 else "STOP_REQUESTED"
            self._condition.notify_all()
            return StopObservation(state, self._active_invocations, authorization,
                                   request_digest, stop_latched=True)

    def wait_for_quiescence(self, timeout_seconds: float) -> bool:
        """Observe local quiescence by a monotonic deadline; seconds are real time.

        False covers both a missing stop request and an in-flight or timed-out
        invocation. It must not be interpreted as physical shutdown evidence.
        """
        if type(timeout_seconds) not in (float, int) or not 0 <= timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be a finite value in [0, 3600]")
        deadline = monotonic() + timeout_seconds
        with self._condition:
            while not (self._stop_requested and self._active_invocations == 0):
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def wait_for_stop(self, timeout_seconds: float) -> bool:
        """Wait for the local stop latch by a monotonic deadline in seconds.

        A cooperating callback can use this to exit early after authenticated
        STOP. False means the deadline elapsed without a latched stop. The
        method does not interrupt code or observe external effects.
        """
        if type(timeout_seconds) not in (float, int) or not 0 <= timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be a finite value in [0, 3600]")
        deadline = monotonic() + timeout_seconds
        with self._condition:
            while not self._stop_requested:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def invoke(self, admission_inputs: dict[str, Any],
               effect: Callable[[dict[str, Any]], Any]) -> ControlledInvocation:
        """Check one emission and call an effect only after current admission.

        The host owns the effect and must route every relevant operation through
        this session. The callback receives the admitted certificate, not the
        private authority receipt. An exception propagates after local activity
        accounting is released; no external effect is inferred from its return.
        """
        if type(admission_inputs) is not dict or not callable(effect):
            raise TypeError("invoke requires plain admission inputs and a callable effect")
        with self._condition:
            if self._stop_authority is not None and os.getpid() != self.process_id:
                return ControlledInvocation("PROCESS_CHANGED", "UNKNOWN", False)
            if self._stop_requested:
                return ControlledInvocation("STOP_REQUESTED", "UNKNOWN", False)
            self._active_invocations += 1
        try:
            gate = evaluate_controlled_emission(**admission_inputs)
            if type(gate) is not dict:
                return ControlledInvocation("GATE_RESULT_INVALID", "UNKNOWN", False)
            admission = gate.get("admission")
            receipt = gate.get("receipt")
            if admission not in ("PASS", "REJECTED", "UNKNOWN"):
                return ControlledInvocation("GATE_RESULT_INVALID", "UNKNOWN", False)
            with self._condition:
                if self._stop_requested:
                    return ControlledInvocation("STOP_REQUESTED", admission, False, receipt)
                certificate = gate.get("emitted_certificate")
                if admission != "PASS":
                    return ControlledInvocation("ADMISSION_REFUSED", admission, False, receipt)
                if type(certificate) is not dict:
                    return ControlledInvocation("GATE_RESULT_INVALID", "UNKNOWN", False, receipt)
                action = receipt.get("action") if type(receipt) is dict else None
                invocation_id = action.get("invocation_id") if type(action) is dict else None
                if type(invocation_id) is not str or not 0 < len(invocation_id) <= 512:
                    return ControlledInvocation("GATE_RESULT_INVALID", "UNKNOWN", False, receipt)
                if invocation_id in self._spent_invocations:
                    return ControlledInvocation("LOCAL_REPLAY_REFUSED", "REJECTED", False, receipt)
                if len(self._spent_invocations) >= _MAX_SPENT_INVOCATIONS:
                    return ControlledInvocation("LOCAL_CAPACITY_EXHAUSTED", "UNKNOWN", False, receipt)
                self._spent_invocations.add(invocation_id)
                # This lock orders local callback admission before any stop latch.
                # The callback itself runs outside the lock and may remain active.
            value = effect(certificate)
            return ControlledInvocation("CALLBACK_RETURNED", "PASS", True, receipt, value)
        finally:
            with self._condition:
                self._active_invocations -= 1
                self._condition.notify_all()
