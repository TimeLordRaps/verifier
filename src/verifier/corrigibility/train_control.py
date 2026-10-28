"""Local mediation for the explicitly selected TRAIN control application profile.

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
JavaScript Object Notation (JSON) records retain exact EVENT, TIME, TOKEN,
environment (ENV), HARDWARE and SPACE bindings. This trusted-host gate does not
sandbox MODEL code, preempt callbacks, authenticate a human or survive restart.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from threading import RLock
from typing import Any, Callable
from uuid import uuid4

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.core.evidence import BoundProposition, MechanismDecision, MechanismOutcome
from verifier.core.signature_keys import admit_ed25519_public_key
from verifier.domains import token as native_token
from verifier.domains.common import Budget, Refuted, Unavailable, digest
from .operator_stop import OperatorStopPolicy, evaluate_stop_request
from .train_profile import Assessment, EFFECTS, PROFILE, TrainControlPlan, assess_train_control, bounded_name

_FIELDS = {"schema", "session_id", "plan_digest", "request_id", "actor_id", "origin_id",
           "train_id", "target_id", "target_digest", "action", "change_digest"}
_MAX_EVENTS = 4096


def _plain(value: Any) -> Any:
    count = 0
    charged = 0
    def visit(item: Any, depth: int = 0) -> Any:
        nonlocal count, charged
        count += 1
        charged += 32
        if charged > 1024 * 1024:
            raise Unavailable("plain capture byte bound exhausted")
        if count > 16384 or depth > 32:
            raise Unavailable("plain evidence traversal bound exhausted")
        if type(item) is dict:
            if len(item) > 256:
                raise Unavailable("plain evidence item bound exhausted")
            if any(type(key) is not str or len(key) > 128 for key in item):
                raise ValueError("plain bounded object required")
            charged += sum(4 * len(key) for key in item)
            captured = item.copy()
            return {key: visit(child, depth + 1) for key, child in captured.items()}
        if type(item) is list:
            if len(item) > 256:
                raise Unavailable("plain evidence item bound exhausted")
            return [visit(child, depth + 1) for child in item]
        if type(item) not in (str, int, bool, type(None)):
            raise ValueError("plain scalar required")
        if type(item) is str and len(item) > 4096:
            raise Unavailable("plain text bound exhausted")
        if type(item) is str:
            charged += len(item.encode("utf-8"))
            if charged > 1024 * 1024:
                raise Unavailable("plain capture byte bound exhausted")
        if type(item) is int and not -(2**53) < item < 2**53:
            raise Unavailable("plain integer bound exhausted")
        return item
    captured = visit(value)
    if len(canonical_bytes(captured)) > 1024 * 1024:
        raise Unavailable("plain evidence byte bound exhausted")
    return captured


def operation_signing_bytes(body: dict[str, Any]) -> bytes:
    """Exact session/plan/action/target/attribution signing contract."""
    body = _plain(body)
    if type(body) is not dict or set(body) != _FIELDS:
        raise ValueError("operation body must have exact fields")
    for value in body.values():
        bounded_name(value)
    if body["schema"] != "verifier-train-operation-1" or body["action"] not in EFFECTS:
        raise ValueError("unsupported operation wire or action")
    return b"verifier-train-operation-ed25519-1\0" + canonical_bytes(body)


def operation_scope(body: dict[str, Any]) -> str:
    """Native TOKEN purpose binds the entire operation except its one-use identifier."""
    operation_signing_bytes(body)
    return PROFILE + "|" + digest({key: value for key, value in body.items() if key != "request_id"})


@dataclass(frozen=True)
class TrainControlPolicy:
    """Externally configured root and executor authority, never candidate payload."""

    policy_id: str
    root_birth_id: str
    root_key_id: str
    witness_keys: tuple[tuple[str, str], ...]
    principals: tuple[tuple[str, str, str], ...]
    root_scopes: tuple[str, ...]
    audience: str
    clock: str
    stop_policy: OperatorStopPolicy
    max_status_age_seconds: int = 60

    def __post_init__(self) -> None:
        for value in (self.policy_id, self.root_birth_id, self.root_key_id, self.audience, self.clock):
            bounded_name(value)
        for value, width in ((self.witness_keys, 2), (self.principals, 3)):
            if type(value) is not tuple or not 0 < len(value) <= 32:
                raise ValueError("bounded immutable authority configuration required")
            for row in value:
                if type(row) is not tuple or len(row) != width:
                    raise ValueError("exact authority row required")
                for item in row:
                    bounded_name(item)
        keys = dict(self.witness_keys)
        if len(keys) != len(self.witness_keys) or self.root_key_id not in keys:
            raise ValueError("exact distinct configured root keys required")
        for key_id, public in keys.items():
            admit_ed25519_public_key(bytes.fromhex(public))
            if key_id != digest(public):
                raise ValueError("key identifier differs from native TOKEN key digest")
        if (len({row[0] for row in self.principals}) != len(self.principals)
                or any(key not in keys or role not in {"ROOT", "EXECUTOR"}
                       for _, key, role in self.principals)):
            raise ValueError("configured principal/key/role mapping required")
        if (type(self.root_scopes) is not tuple or not self.root_scopes
                or len(self.root_scopes) > 256
                or len(set(self.root_scopes)) != len(self.root_scopes)
                or type(self.stop_policy) is not OperatorStopPolicy):
            raise ValueError("configured scopes and authenticated stop policy required")
        for scope in self.root_scopes:
            bounded_name(scope)
        if type(self.max_status_age_seconds) is not int or not 1 <= self.max_status_age_seconds <= 3600:
            raise ValueError("finite trusted status freshness bound required")

    @property
    def digest(self) -> str:
        return digest({"schema": "verifier-train-control-policy-1", "policy_id": self.policy_id,
                       "root_birth_id": self.root_birth_id, "root_key_id": self.root_key_id,
                       "witness_keys": [list(row) for row in self.witness_keys],
                       "principals": [list(row) for row in self.principals],
                       "root_scopes": list(self.root_scopes), "audience": self.audience,
                       "clock": self.clock, "stop_policy_digest": self.stop_policy.digest,
                       "max_status_age_seconds": self.max_status_age_seconds})


@dataclass(frozen=True)
class AuthoritySnapshot:
    """Current trusted-host view; unsigned native status rows require this trust root."""

    generation: int
    artifact: dict[str, Any]
    inputs: dict[str, Any]


@dataclass(frozen=True)
class MediatedResult:
    outcome: str
    reason: str
    effect_called: bool
    event: NamespaceObject | None
    value: Any = None


@dataclass(frozen=True)
class _CheckedAuthority:
    ancestors: tuple[str, ...]
    ceilings: tuple[tuple[str, int], ...]
    generation: int
    view_digest: str
    observed_at: int


class TrainControlSession:
    """One process/session: model-origin proposals cannot invoke protected effects.

    The host alone supplies attribution, keys, current authority views, clock and
    trusted executor callbacks. All effects in scope must traverse this instance.
    A MODEL must not receive this Python object, root keys or callback internals.
    """

    def __init__(self, plan: TrainControlPlan, policy: TrainControlPolicy, *,
                 authority: Callable[[], AuthoritySnapshot | None], clock: Callable[[], int],
                 session_id: str | None = None):
        if type(plan) is not TrainControlPlan or type(policy) is not TrainControlPolicy:
            raise ValueError("explicit native plan and host policy required")
        self._plan, self._policy = plan, policy
        self.preflight = assess_train_control(plan)
        self.session_id = bounded_name(session_id) if session_id is not None else uuid4().hex
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.session_id) is None:
            raise ValueError("event-safe fresh session identifier required")
        self.process_id = os.getpid()
        self._authority, self._clock = authority, clock
        self._lock = RLock()
        self._events: list[NamespaceObject] = []
        self._spent: set[str] = set()
        self._uses: dict[str, int] = {}
        self._revoked: set[str] = set()
        self._generation = -1
        self._view_digest: str | None = None
        self._stopped = False
        self._active = 0
        self._last_clock_observation: int | None = None

    @property
    def plan(self) -> TrainControlPlan:
        return self._plan

    @property
    def policy(self) -> TrainControlPolicy:
        return self._policy

    @property
    def events(self) -> tuple[NamespaceObject, ...]:
        with self._lock:
            return tuple(self._events)

    @property
    def quiescent(self) -> bool:
        with self._lock:
            return self._stopped and self._active == 0

    def request_stop(self, request: Any) -> str:
        """Authenticated permanent admission stop; in-flight effects may continue."""
        if os.getpid() != self.process_id:
            return "UNKNOWN"
        try:
            now = self._now()
        except (Exception, asyncio.CancelledError):
            return "UNKNOWN"
        outcome, request_digest = evaluate_stop_request(
            self.policy.stop_policy, self.session_id, self.process_id, request, now)
        with self._lock:
            if outcome == "PASS":
                self._stopped = True
                if len(self._events) + self._active < _MAX_EVENTS:
                    self._record({"action": "STOP", "request_digest": request_digest}, "PASS", "stop latched", False, observed_at=now)
        return outcome

    def _now(self) -> int:
        self._last_clock_observation = None
        now = self._clock()
        if type(now) is not int or not 0 <= now < 2**53:
            raise Unavailable("trusted clock unavailable or invalid")
        self._last_clock_observation = now
        return now

    def scope(self, body: dict[str, Any]) -> str:
        return operation_scope(body)

    def _record(self, operation: dict[str, Any], outcome: str, reason: str,
                called: bool, authority_digest: str | None = None, *, observed_at: int | None = None) -> NamespaceObject | None:
        if len(self._events) >= _MAX_EVENTS:
            return None
        try:
            context = {self.plan.resolve(identifier).kind.value: self.plan.resolve(identifier)
                       for identifier in self.plan.context}
            if set(context) != {"TIME", "TOKEN", "ENV", "HARDWARE", "SPACE"}:
                return None
        except (ValueError, LookupError):
            return None
        train_ids = [o.object_id for o in self.plan.objects if o.kind.value == "TRAIN"]
        if not train_ids:
            return None
        meaning = train_ids[0]
        if "train_id" in operation:
            try:
                selected_train = self.plan.resolve(operation["train_id"])
                if selected_train.kind.value == "TRAIN":
                    meaning = selected_train.object_id
            except (ValueError, LookupError):
                pass
        payload = {"profile": PROFILE, "scope": "retained-local-train-mediation",
                   "plan_digest": self.plan.digest, "policy_digest": self.policy.digest,
                   "session_id": self.session_id, "process_id": self.process_id,
                   "index": len(self._events), "previous": self._events[-1].digest if self._events else None,
                   "operation": operation, "outcome": outcome, "reason": reason[:256],
                   "effect_called": called, "authority_digest": authority_digest,
                   "clock": self.policy.clock, "observed_at": observed_at,
                   "context": {kind: obj.digest for kind, obj in context.items()}}
        event = NamespaceObject.create("train-control-event-" + self.session_id + "-" + str(len(self._events)),
                                       "EVENT", payload, {"time": [context["TIME"].object_id],
                                                          "space": [context["SPACE"].object_id],
                                                          "meaning": [meaning]})
        self._events.append(event)
        return event

    def _decision(self, body: dict[str, Any]) -> Assessment:
        if self.preflight.outcome == "FAIL":
            return self.preflight
        if body["plan_digest"] != self.plan.digest or body["session_id"] != self.session_id:
            return Assessment("FAIL", ("exact session or plan binding differs",))
        attribution: dict[str, NamespaceObject] = {}
        for key in ("origin_id", "actor_id"):
            try:
                attribution[key] = self.plan.resolve(body[key])
            except LookupError:
                continue
            except ValueError as exc:
                return Assessment("FAIL", (str(exc),))
        if any(obj.kind.value == "MODEL" for obj in attribution.values()):
            return Assessment("FAIL", ("MODEL-origin effect has no training or descendant authority",))
        actor = attribution.get("actor_id")
        role = next((role for identifier, _, role in self.policy.principals
                     if actor is not None and identifier == actor.object_id), None)
        if actor is not None and ((body["action"] == "write_checkpoint" and role != "EXECUTOR")
                                   or (body["action"] != "write_checkpoint" and role != "ROOT")):
            return Assessment("FAIL", ("actor lacks the selected executor or root role",))
        if len(attribution) == 2 and attribution["origin_id"].object_id != actor.object_id:
            return Assessment("FAIL", ("executor cannot replace a proposal's origin",))
        if body["action"] == "fork_train" and body["change_digest"] in {self.plan.digest, "none"}:
            return Assessment("FAIL", ("fork must select an exact new plan revision",))
        if body["action"] == "write_checkpoint" and body["change_digest"] == "none":
            return Assessment("FAIL", ("checkpoint write must bind exact new content",))
        selected: dict[str, NamespaceObject] = {}
        for key in ("target_id", "train_id"):
            try:
                selected[key] = self.plan.resolve(body[key])
            except LookupError:
                continue
            except ValueError as exc:
                return Assessment("FAIL", (str(exc),))
        if (("target_id" in selected and body["target_digest"] != selected["target_id"].digest)
                or ("train_id" in selected and selected["train_id"].kind.value != "TRAIN")):
            return Assessment("FAIL", ("exact revision or TRAIN binding differs",))
        if len(attribution) != 2 or len(selected) != 2:
            return Assessment("UNKNOWN", ("proposal attribution or selected endpoint unresolved",))
        try:
            origin, actor = attribution["origin_id"], attribution["actor_id"]
            target, train = selected["target_id"], selected["train_id"]
            if body["action"] == "write_checkpoint":
                checkpoint_targets = {(self.plan.resolve(owner).object_id, self.plan.resolve(checkpoint).object_id)
                                      for owner, checkpoint in self.plan.checkpoints}
                if role != "EXECUTOR" or (train.object_id, target.object_id) not in checkpoint_targets:
                    return Assessment("FAIL", ("checkpoint write is not a declared executor target",))
        except LookupError as exc:
            return Assessment("UNKNOWN", (str(exc),))
        except ValueError as exc:
            return Assessment("FAIL", (str(exc),))
        return self.preflight

    def _check_authority(self, body: dict[str, Any], envelope: dict[str, Any], token_id: str,
                         now: int) -> _CheckedAuthority:
        snapshot = self._authority()
        if type(snapshot) is not AuthoritySnapshot:
            raise Unavailable("current trusted authority view unavailable")
        if type(snapshot.generation) is not int or snapshot.generation < 0:
            raise Refuted("invalid current authority generation")
        artifact, inputs = _plain(snapshot.artifact), _plain(snapshot.inputs)
        view_digest = digest({"generation": snapshot.generation, "artifact": artifact, "inputs": inputs})
        if (snapshot.generation < self._generation or
                snapshot.generation == self._generation and view_digest != self._view_digest):
            raise Refuted("authority view rollback or equivocation")
        self._generation, self._view_digest = snapshot.generation, view_digest
        if artifact.get("clock") != self.policy.clock:
            raise Refuted("authority snapshot clock differs from selected clock")
        artifact.update(root_scopes=list(self.policy.root_scopes), audience=[self.policy.audience],
                        clock=self.policy.clock, observed_at=now, clock_skew=0,
                        status_schedule=self.policy.max_status_age_seconds,
                        period={"start": now, "end": now + 1})
        budget = Budget(200000, max_items=256)
        held = {token["token_id"]: token for token in inputs.get("tokens", [])}
        birth = held.get(self.policy.root_birth_id)
        if not birth or birth["kind"] != "birth" or birth["issuing_key_id"] != self.policy.root_key_id:
            raise Refuted("holding does not use the configured root")
        selected = held.get(token_id)
        if not selected or selected["kind"] != "lifetime":
            raise Refuted("selected capability is not a lifetime grant")
        principal = next((row for row in self.policy.principals if row[0] == self.plan.resolve(body["actor_id"]).object_id), None)
        if (principal is None or selected["delegate_key_id"] != principal[1]
                or selected["confirmation_key_id"] != principal[1]
                or self.policy.audience not in selected["audience"]
                or self.scope(body) not in selected["permitted_scopes"]):
            raise Refuted("grant does not bind the selected principal, audience and exact operation")
        if principal[2] == "ROOT" and selected["parent_grant_id"] != self.policy.root_birth_id:
            raise Refuted("root operation requires a newly selected direct root grant")
        current = selected
        selected_path = {self.policy.root_birth_id}
        seen_path: set[str] = set()
        while current["kind"] != "birth":
            if current["token_id"] in seen_path:
                raise Refuted("selected delegation path cycles")
            seen_path.add(current["token_id"])
            if current["kind"] != "lifetime":
                raise Refuted("selected delegation names a non-grant parent")
            selected_path.add(current["token_id"])
            parent = held.get(current["parent_grant_id"])
            if parent is None:
                raise Refuted("selected delegation parent unresolved")
            grantor = parent["issuing_key_id"] if parent["kind"] == "birth" else parent["delegate_key_id"]
            if current["issuing_key_id"] != grantor:
                raise Refuted("delegation issuer differs from exact parent authority")
            current = parent
        now = self._now()
        artifact.update(observed_at=now, period={"start": now, "end": now + 1})
        for identifier in seen_path:
            grant = held[identifier]
            if (type(grant["not_before"]) is not int or type(grant["not_after"]) is not int
                    or not grant["not_before"] <= now < grant["not_after"]):
                raise Refuted("selected grant or ancestor is outside its finite current window")
        if digest(inputs.get("statuses")) != artifact.get("statuses_digest"):
            raise Refuted("retained statuses differ from bound digest")
        latest = {}
        for status in inputs.get("statuses", []):
            if (type(status) is dict and set(status) == {"token_id", "published_at", "verdict"}
                    and type(status["published_at"]) is int and status["published_at"] <= now):
                identifier = status["token_id"]
                if identifier not in latest or status["published_at"] > latest[identifier]["published_at"]:
                    latest[identifier] = status
        for identifier in selected_path:
            if identifier in self._revoked:
                raise Refuted("selected grant or ancestor previously revoked")
            status = latest.get(identifier)
            if (status is not None and now - status["published_at"] <= self.policy.max_status_age_seconds
                    and status["verdict"] in {"REVOKED", "SUSPENDED"}):
                if status["verdict"] == "REVOKED":
                    self._revoked.add(identifier)
                raise Refuted("current selected grant or ancestor revoked or suspended")
        native_token.evaluate("leases", artifact, inputs, budget, witness_keys=dict(self.policy.witness_keys))
        for check in ("closure", "tenure"):
            result = native_token.evaluate(check, artifact, inputs, budget,
                                           witness_keys=dict(self.policy.witness_keys))
            if check == "closure":
                self._revoked.update(result["revoked"])
                if token_id not in result["open"]:
                    raise Refuted("selected grant is not currently open")
                blocked = set(result["revoked"]) | set(result["suspended"])
            if check == "tenure" and result["revoked_at"] is not None:
                raise Refuted("root tenure is revoked")
        ancestors: list[str] = []
        current = selected
        while current["kind"] != "birth":
            identifier = current["token_id"]
            ancestors.append(identifier)
            if identifier in blocked | self._revoked:
                raise Refuted("selected grant or ancestor revoked or suspended")
            if current["caveats"]:
                raise Unavailable("capability caveat enforcement unsupported")
            if (current["not_after"] is None or not current["not_before"] <= now < current["not_after"]
                    or current["max_invocations"] is None):
                raise Refuted("finite current grant interval and invocation budget required")
            if self._uses.get(identifier, 0) >= current["max_invocations"]:
                raise Refuted("selected grant or shared ancestor invocation budget spent")
            parent = held[current["parent_grant_id"]]
            grantor = parent["issuing_key_id"] if parent["kind"] == "birth" else parent["delegate_key_id"]
            if current["issuing_key_id"] != grantor:
                raise Refuted("delegation issuer differs from exact parent authority")
            current = parent
        if current["token_id"] in blocked | self._revoked:
            raise Refuted("root grant revoked or suspended")
        native_token.evaluate("signatures", artifact, inputs, budget, witness_keys=dict(self.policy.witness_keys))
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError as exc:
            raise Unavailable("operation signature backend unavailable") from exc
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(dict(self.policy.witness_keys)[principal[1]])).verify(
                bytes.fromhex(envelope["signature"]), operation_signing_bytes(body))
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise Refuted("operation proof of possession does not verify") from exc
        final_now = self._now()
        if final_now < now:
            raise Unavailable("clock moved backward during admission")
        for identifier in ancestors:
            grant = held[identifier]
            if not grant["not_before"] <= final_now < grant["not_after"]:
                raise Refuted("selected grant or ancestor expired at final effect boundary")
        artifact.update(observed_at=final_now, period={"start": final_now, "end": final_now + 1})
        native_token.evaluate("closure", artifact, inputs, budget, witness_keys=dict(self.policy.witness_keys))
        return _CheckedAuthority(tuple(ancestors), tuple((identifier, held[identifier]["max_invocations"])
                                                        for identifier in ancestors),
                                 snapshot.generation, view_digest, final_now)

    def mediate(self, envelope: Any, token_id: str, effect: Callable[[bytes | None], Any], *,
                artifact_bytes: bytes | None = None, fork_plan: TrainControlPlan | None = None) -> MediatedResult:
        """Invoke a host callback once only after exact live authorization checks."""
        envelope = _plain(envelope)
        if type(envelope) is not dict or set(envelope) != {"body", "signature"}:
            raise ValueError("operation envelope must have exact fields")
        body = envelope["body"]
        operation_signing_bytes(body)
        bounded_name(token_id)
        with self._lock:
            # Reserve completion capacity before any effect. A full gate refuses
            # without an EVENT rather than falsely recording an unretained pass.
            if len(self._events) + self._active >= _MAX_EVENTS:
                raise Unavailable("retained EVENT bound exhausted")
            decision = self._decision(body)
            reason = "; ".join(decision.reasons)
            authority_digest = None
            if decision.outcome == "PASS" and body["action"] == "fork_train":
                if (type(fork_plan) is not TrainControlPlan or fork_plan.digest != body["change_digest"]
                        or fork_plan.digest == self.plan.digest):
                    decision, reason = Assessment("FAIL"), "fork must supply the exact new finite plan"
                else:
                    fork_assessment = assess_train_control(fork_plan)
                    if fork_assessment.outcome != "PASS":
                        decision, reason = fork_assessment, "; ".join(fork_assessment.reasons)
            if decision.outcome == "PASS" and body["action"] == "write_checkpoint":
                if type(artifact_bytes) is bytes and len(artifact_bytes) > 1024 * 1024:
                    decision, reason = Assessment("UNKNOWN"), "checkpoint content byte bound exhausted"
                elif (type(artifact_bytes) is not bytes
                      or "sha256:" + hashlib.sha256(artifact_bytes).hexdigest() != body["change_digest"]):
                    decision, reason = Assessment("FAIL"), "exact checkpoint content differs"
            now = None
            try:
                now = self._now()
            except (Exception, asyncio.CancelledError):
                if decision.outcome == "PASS":
                    decision, reason = Assessment("UNKNOWN"), "trusted clock unavailable"
            if os.getpid() != self.process_id and decision.outcome != "FAIL":
                decision, reason = Assessment("UNKNOWN"), "process changed; a new root-authorized session is required"
            elif self._stopped:
                decision, reason = Assessment("FAIL"), "authorized stop already latched"
            elif body["request_id"] in self._spent:
                decision, reason = Assessment("FAIL"), "invocation identifier already spent"
            if decision.outcome == "PASS":
                try:
                    checked = self._check_authority(body, envelope, token_id, now)
                    ancestors, authority_digest, now = checked.ancestors, checked.view_digest, checked.observed_at
                except Refuted as exc:
                    decision, reason = Assessment("FAIL"), str(exc)
                except (Exception, asyncio.CancelledError) as exc:
                    decision, reason = Assessment("UNKNOWN"), "authority evaluation unavailable: " + type(exc).__name__
                now = self._last_clock_observation
            # Host providers may synchronously invoke STOP or another admission.
            # Recheck the live session atomically after all host/native callbacks.
            if decision.outcome == "PASS":
                if self._stopped or body["request_id"] in self._spent:
                    decision, reason = Assessment("FAIL"), "stop or invocation consumption changed during admission"
                elif (self._generation != checked.generation or self._view_digest != checked.view_digest
                      or self._revoked.intersection((*ancestors, self.policy.root_birth_id))):
                    decision, reason = Assessment("FAIL"), "selected authority view or revocation changed during admission"
                elif any(self._uses.get(identifier, 0) >= ceiling for identifier, ceiling in checked.ceilings):
                    decision, reason = Assessment("FAIL"), "shared ancestor invocation budget spent during admission"
                elif os.getpid() != self.process_id or len(self._events) + self._active >= _MAX_EVENTS:
                    decision, reason = Assessment("UNKNOWN"), "process or retention capacity changed during admission"
            if decision.outcome != "PASS":
                event = self._record(body, decision.outcome, reason, False, authority_digest, observed_at=now)
                return MediatedResult(decision.outcome, reason, False, event)
            self._spent.add(body["request_id"])
            for ancestor in ancestors:
                self._uses[ancestor] = self._uses.get(ancestor, 0) + 1
            self._active += 1
        outcome, reason, value = "PASS", "host callback completed", None
        interrupted: BaseException | None = None
        try:
            value = effect(artifact_bytes)
        except (Exception, asyncio.CancelledError) as exc:
            outcome, reason = "UNKNOWN", "callback did not complete: " + type(exc).__name__
        except BaseException as exc:
            outcome, reason, interrupted = "UNKNOWN", "callback interrupted: " + type(exc).__name__, exc
        finally:
            with self._lock:
                self._active -= 1
                event = self._record(body, outcome, reason, True, authority_digest, observed_at=now)
        if interrupted is not None:
            raise interrupted
        return MediatedResult(outcome, reason, True, event, value)


def recheck_denial_trace(plan: TrainControlPlan, events: tuple[NamespaceObject, ...], *,
                         expected_digest: str, subject_id: str | None = None) -> Assessment:
    """Pure historical integrity/denial replay; never authority or trace completeness."""
    if type(events) is not tuple or not events or len(events) > _MAX_EVENTS:
        return Assessment("UNKNOWN", ("bounded retained EVENTs required",))
    if any(type(event) is not NamespaceObject for event in events):
        return Assessment("FAIL", ("native EVENT records required",))
    if digest([event.to_dict() for event in events]) != expected_digest:
        return Assessment("FAIL", ("exact independently selected trace commitment differs",))
    context_objects = {plan.resolve(identifier).kind.value: plan.resolve(identifier) for identifier in plan.context}
    context = {kind: obj.digest for kind, obj in context_objects.items()}
    if set(context) != {"TIME", "TOKEN", "ENV", "HARDWARE", "SPACE"}:
        return Assessment("UNKNOWN", ("complete context required for denial replay",))
    default_train = next(o.object_id for o in plan.objects if o.kind.value == "TRAIN")
    denied = 0
    gaps = []
    previous = None
    session = None
    for index, event in enumerate(events):
        payload = event.payload
        body = payload.get("operation", {})
        selected_train = None
        try:
            if "train_id" in body:
                obj = plan.resolve(body["train_id"])
                if obj.kind.value == "TRAIN":
                    selected_train = obj.object_id
        except (ValueError, LookupError):
            pass
        expected_operands = {"time": (context_objects["TIME"].object_id,),
                             "space": (context_objects["SPACE"].object_id,),
                             "meaning": (selected_train or default_train,)}
        if (event.kind.value != "EVENT" or dict(event.operands) != expected_operands or payload.get("profile") != PROFILE
                or payload.get("plan_digest") != plan.digest or payload.get("context") != context
                or payload.get("index") != index or payload.get("previous") != previous
                or (session is not None and payload.get("session_id") != session)):
            return Assessment("FAIL", ("EVENT chain, context or revision binding differs",))
        previous, session = event.digest, payload["session_id"]
        if (type(payload.get("observed_at")) is not int or not 0 <= payload["observed_at"] < 2**53
                or type(payload.get("clock")) is not str or not payload["clock"]):
            gaps.append("retained current clock observation missing")
        if body.get("action") == "STOP":
            continue
        try:
            operation_signing_bytes(body)
        except (ValueError, KeyError):
            return Assessment("FAIL", ("malformed retained operation",))
        resolved = []
        for key in ("origin_id", "actor_id"):
            try:
                resolved.append(plan.resolve(body[key]))
            except LookupError:
                continue
            except ValueError:
                return Assessment("FAIL", ("retained alias cycle",))
        model_origin = any(obj.kind.value == "MODEL" for obj in resolved)
        if not model_origin and len(resolved) != 2:
            gaps.append("retained attribution unresolved")
        if model_origin:
            if subject_id is None or selected_train == subject_id:
                denied += 1
            if payload.get("effect_called") is not False or payload.get("outcome") != "FAIL":
                return Assessment("FAIL", ("retained MODEL-origin effect was not denied",))
    if not denied:
        gaps.append("no retained MODEL-origin denial")
    return Assessment("UNKNOWN", tuple(sorted(set(gaps)))) if gaps else Assessment("PASS")


class TrainDenialTraceMechanism:
    """Native retained denial replay under a separately selected host commitment.

    PASS establishes this trace predicate only. The host commitment does not prove
    complete instrumentation, physical effects, operator authority or corrigibility.
    """

    mechanism_id = "verifier.train-control.retained-denial-trace.1"

    def __init__(self, plan: TrainControlPlan, *, expected_trace_digest: str, policy_digest: str):
        self.plan = plan
        self.expected_trace_digest = expected_trace_digest
        self.policy_digest = policy_digest
        self.mechanism_digest = digest({name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                       for name in ("train_control.py", "train_profile.py")})

    def evaluate(self, binding: BoundProposition, evidence: tuple[bytes, ...]) -> MechanismDecision:
        if (binding.predicate != "retained-model-origin-effects-denied-1"
                or binding.subject_id not in {o.object_id for o in self.plan.objects if o.kind.value == "TRAIN"}
                or binding.expected is not True
                or dict(binding.parameters) != {"plan_digest": self.plan.digest,
                                                "trace_digest": self.expected_trace_digest,
                                                "policy_digest": self.policy_digest}
                or binding.trust_roots != ("train-control-host:" + self.policy_digest,)):
            return MechanismDecision(MechanismOutcome.FAIL, "exact host-selected denial binding differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one bounded retained trace required")
        if len(evidence[0]) > 1024 * 1024:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "native trace byte bound exhausted")
        try:
            rows = _plain(json.loads(evidence[0]))
            if canonical_bytes(rows) != evidence[0]:
                raise ValueError("retained trace must be exact canonical bytes")
            if type(rows) is not list:
                raise ValueError("retained trace must be an array")
            events = []
            for row in rows:
                if type(row) is not dict or set(row) != {"object_id", "kind", "payload", "operands"}:
                    raise ValueError("exact native EVENT shape required")
                event = NamespaceObject.create(row["object_id"], row["kind"], row["payload"], row["operands"])
                if event.payload.get("policy_digest") != self.policy_digest:
                    raise ValueError("selected policy binding differs")
                events.append(event)
            result = recheck_denial_trace(self.plan, tuple(events), expected_digest=self.expected_trace_digest,
                                         subject_id=binding.subject_id)
        except Unavailable as exc:
            return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
        except (ValueError, TypeError, KeyError, LookupError) as exc:
            return MechanismDecision(MechanismOutcome.FAIL, str(exc))
        return MechanismDecision(MechanismOutcome(result.outcome), "; ".join(result.reasons),
                                 {"retained_events": len(events), "trace_digest": self.expected_trace_digest,
                                  "whole_corrigibility": "UNKNOWN"})
