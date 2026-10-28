"""Bounded selected digest validation loops for Verifier Standard (VSTD).

Secure Hash Algorithm 256-bit (SHA-256) equality checks only supplied bytes.
This experimental direct module discharges no VSTD-4 rung. Ordered targets are
host-declared, not inferred obligations. Target exhaustion is not geometry
closure. Reservations count declared input ceilings, not actual work or verified
bytes; they provide no time, sandbox, transport-memory, or authority-freshness
guarantee. The local host interpreter and built-in registration remain trusted.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from verifier.core.evidence import BytesDigestMechanism, EvidenceBindingError, EvidenceBounds, EvidenceStore
from verifier.core.geometry import VerificationGeometry
from verifier.core.geometry_io import load_verification_geometry
from .catalog import InteroperabilityComponentRegistry
from .control_surface import ControlSurfaceContext, analyze_verification_surface, plan_validation
from .selected_execution import (
    DigestHostPolicy, SelectedExecutionError, _canonical, _digest, _object,
    execute_selected_validation, prepare_digest_validation,
)
from .storage import StoredComponentPackage


_REQUEST_FORMAT = "verifier-digest-loop-request-1"
_RECORD_FORMAT = "verifier-digest-loop-execution-1"
_REQUEST_KEYS = {"schema_version", "geometry", "registry", "context", "targets", "bounds", "mechanism_id", "mechanism_digest"}
_RECORD_KEYS = {"schema_version", "request", "steps", "attempted_steps", "reserved_evidence_bytes", "stop_reason", "unattempted_targets", "final_geometry", "final_analysis", "final_plan"}
_STEP_RECORD_KEYS = {"schema_version", "request", "evidence", "evaluation", "evidence_id", "original_analysis", "updated_geometry", "updated_analysis"}


class DigestLoopError(SelectedExecutionError):
    """The bounded loop contract or its replay is not established."""


def _integer(value: Any, name: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise DigestLoopError(f"{name} must be a bounded nonnegative integer")
    return value


@dataclass(frozen=True)
class DigestValidationTarget:
    """One predeclared exact coordinate and independently pinned expectation."""

    coordinate_id: str
    expected_digest: str
    evidence_ref: str
    max_evidence_bytes: int

    def __post_init__(self) -> None:
        if type(self.coordinate_id) is not str or not self.coordinate_id or self.coordinate_id.strip() != self.coordinate_id:
            raise DigestLoopError("coordinate_id must be a nonempty canonical string")
        _digest(self.expected_digest)
        _digest(self.evidence_ref)
        _integer(self.max_evidence_bytes, "max_evidence_bytes")

    def to_dict(self) -> dict[str, Any]:
        return {"coordinate_id": self.coordinate_id, "expected_digest": self.expected_digest,
            "evidence_ref": self.evidence_ref, "max_evidence_bytes": self.max_evidence_bytes}


@dataclass(frozen=True)
class DigestLoopBounds:
    """Step count and cumulative declared-byte reservations, with no refunds."""

    max_steps: int
    max_reserved_evidence_bytes: int

    def __post_init__(self) -> None:
        _integer(self.max_steps, "max_steps", 256)
        _integer(self.max_reserved_evidence_bytes, "max_reserved_evidence_bytes")

    def to_dict(self) -> dict[str, int]:
        return {"max_steps": self.max_steps, "max_reserved_evidence_bytes": self.max_reserved_evidence_bytes}


def _child(geometry: VerificationGeometry, registry: InteroperabilityComponentRegistry,
           context: ControlSurfaceContext, target: DigestValidationTarget,
           package: StoredComponentPackage | None) -> dict[str, Any]:
    analysis = analyze_verification_surface(geometry, context)
    plan = plan_validation(analysis, registry, package=package)
    return prepare_digest_validation(geometry, registry, plan,
        coordinate_id=target.coordinate_id, expected_digest=target.expected_digest,
        evidence_ref=target.evidence_ref, bounds=EvidenceBounds(1, target.max_evidence_bytes),
        package=package)


def _validate(request: Any) -> tuple[VerificationGeometry, InteroperabilityComponentRegistry,
        ControlSurfaceContext, tuple[DigestValidationTarget, ...], DigestLoopBounds, StoredComponentPackage | None]:
    if type(request) is not dict:
        raise DigestLoopError("loop request must be a plain record")
    raw = _object(request, _REQUEST_KEYS | ({"package"} if "package" in request else set()), "loop request")
    _canonical(raw)
    if raw["schema_version"] != _REQUEST_FORMAT:
        raise DigestLoopError("unsupported loop request format")
    if raw["mechanism_id"] != BytesDigestMechanism.mechanism_id or _digest(raw["mechanism_digest"]) != BytesDigestMechanism.mechanism_digest:
        raise DigestLoopError("loop mechanism coordinate differs from the host builtin")
    geometry = load_verification_geometry(raw["geometry"])
    registry = InteroperabilityComponentRegistry.from_dict(raw["registry"])
    context = ControlSurfaceContext(**_object(raw["context"], set(ControlSurfaceContext().to_dict()), "context"))
    for name, value in (("geometry", geometry), ("registry", registry), ("context", context)):
        if _canonical(value.to_dict()) != _canonical(raw[name]):
            raise DigestLoopError(f"{name} must be complete and canonical")
    targets_raw = raw["targets"]
    if type(targets_raw) is not list or not 1 <= len(targets_raw) <= 256:
        raise DigestLoopError("loop requires between 1 and 256 ordered targets")
    targets = tuple(DigestValidationTarget(**_object(item,
        {"coordinate_id", "expected_digest", "evidence_ref", "max_evidence_bytes"}, "target")) for item in targets_raw)
    if len({item.coordinate_id for item in targets}) != len(targets):
        raise DigestLoopError("duplicate target coordinates are forbidden")
    bounds = DigestLoopBounds(**_object(raw["bounds"], {"max_steps", "max_reserved_evidence_bytes"}, "loop bounds"))
    package = None
    if "package" in raw:
        if type(raw["package"]) is not dict:
            raise DigestLoopError("package must be a complete record")
        package = StoredComponentPackage.from_dict(raw["package"])
        if _canonical(package.to_dict()) != _canonical(raw["package"]):
            raise DigestLoopError("package must be canonical")
    # Eligibility is checked against the complete original geometry, never a
    # synthetic surface containing only the selected holes.
    coordinate_ids = {item.coordinate_id for item in geometry.coordinates}
    for target in targets:
        if target.coordinate_id not in coordinate_ids:
            raise DigestLoopError("target coordinate is absent from the geometry")
        _child(geometry, registry, context, target, package)
    return geometry, registry, context, targets, bounds, package


def prepare_digest_validation_loop(geometry: VerificationGeometry,
        registry: InteroperabilityComponentRegistry, targets: tuple[DigestValidationTarget, ...],
        *, bounds: DigestLoopBounds, context: ControlSurfaceContext | None = None,
        package: StoredComponentPackage | None = None) -> dict[str, Any]:
    """Bind the whole ordered loop without reading evidence or granting permission."""
    if type(targets) is not tuple or any(type(item) is not DigestValidationTarget for item in targets):
        raise DigestLoopError("targets must be an explicit tuple of typed targets")
    if type(bounds) is not DigestLoopBounds:
        raise DigestLoopError("bounds must be DigestLoopBounds")
    context = ControlSurfaceContext() if context is None else context
    if type(context) is not ControlSurfaceContext:
        raise DigestLoopError("context must be ControlSurfaceContext")
    request = {"schema_version": _REQUEST_FORMAT, "geometry": geometry.to_dict(),
        "registry": registry.to_dict(), "context": context.to_dict(),
        "targets": [item.to_dict() for item in targets], "bounds": bounds.to_dict(),
        "mechanism_id": BytesDigestMechanism.mechanism_id,
        "mechanism_digest": BytesDigestMechanism.mechanism_digest}
    if package is not None:
        if type(package) is not StoredComponentPackage:
            raise DigestLoopError("package must be StoredComponentPackage")
        request["package"] = package.to_dict()
    _validate(request)
    return request


@dataclass(frozen=True, init=False)
class DigestLoopPolicy:
    """Reusable host-owned approval of exact complete loop bytes, default deny.

    The host configures this outside untrusted request handling. No request or
    carried child record grants permission. No expiry, revocation, freshness,
    one-time-use enforcement, or protection against hostile host code is supplied.
    """

    approved_requests: tuple[bytes, ...]
    mechanism: BytesDigestMechanism | None

    def __init__(self, approved_requests: tuple[dict[str, Any], ...] = (), *, mechanism: BytesDigestMechanism | None = None) -> None:
        if type(approved_requests) is not tuple:
            raise DigestLoopError("host approvals must be an explicit tuple")
        DigestHostPolicy(mechanism=mechanism)  # Same exact built-in instance boundary.
        snapshots = tuple(_canonical(item) for item in approved_requests)
        for snapshot in snapshots:
            _validate(json.loads(snapshot))
        object.__setattr__(self, "approved_requests", snapshots)
        object.__setattr__(self, "mechanism", mechanism)


def _authorize(request: dict[str, Any], policy: DigestLoopPolicy | None) -> None:
    if type(policy) is not DigestLoopPolicy or _canonical(request) not in policy.approved_requests:
        raise DigestLoopError("loop host authorization denied")
    DigestHostPolicy(mechanism=policy.mechanism)


def _admit(store: EvidenceStore, target: DigestValidationTarget) -> EvidenceStore:
    admitted = EvidenceStore()
    try:
        payload = store.resolve(target.evidence_ref)
    except EvidenceBindingError:
        return admitted
    if type(payload) is bytes and len(payload) <= target.max_evidence_bytes:
        admitted.add(payload)
    # No cause or size is asserted for unadmitted input. Oversized bytes are not
    # passed to the single-step executor and therefore cannot enter its record.
    return admitted


def _run(request: dict[str, Any], evidence: EvidenceStore | tuple[EvidenceStore, ...],
         policy: DigestLoopPolicy | None) -> dict[str, Any]:
    request = json.loads(_canonical(request))
    geometry, registry, context, targets, bounds, package = _validate(request)
    _authorize(request, policy)
    steps: list[dict[str, Any]] = []
    reserved = 0
    analysis = analyze_verification_surface(geometry, context)
    plan = plan_validation(analysis, registry, package=package)
    while True:
        # Deterministic precedence: exhaustion, step cap, reservation cap, then
        # attempt. Every attempt is charged in full, including FAIL and UNKNOWN.
        index = len(steps)
        if index == len(targets):
            reason = "TARGETS_EXHAUSTED"
            break
        if index >= bounds.max_steps:
            reason = "STEP_BUDGET_EXHAUSTED"
            break
        target = targets[index]
        if reserved + target.max_evidence_bytes > bounds.max_reserved_evidence_bytes:
            reason = "EVIDENCE_BUDGET_EXHAUSTED"
            break
        reserved += target.max_evidence_bytes
        child_request = _child(geometry, registry, context, target, package)
        if child_request["proposition"]["mechanism_digest"] != request["mechanism_digest"]:
            raise DigestLoopError("mechanism coordinate changed during the loop")
        source = evidence if type(evidence) is EvidenceStore else (evidence[index] if index < len(evidence) else EvidenceStore())
        admitted = _admit(source, target)
        # Only this approved loop derives child permission from its own exact
        # current geometry, target, registry and plan, not a serialized child.
        child_policy = DigestHostPolicy((child_request,), mechanism=policy.mechanism)
        execution = execute_selected_validation(child_request, admitted, policy=child_policy)
        steps.append({"target_index": index, "execution": execution})
        geometry = load_verification_geometry(execution["updated_geometry"])
        analysis = analyze_verification_surface(geometry, context)
        plan = plan_validation(analysis, registry, package=package)
        outcome = execution["evaluation"]["outcome"]
        if outcome in ("FAIL", "UNKNOWN"):
            reason = "FAILED" if outcome == "FAIL" else "UNKNOWN"
            break
    return {"schema_version": _RECORD_FORMAT, "request": request, "steps": steps,
        "attempted_steps": len(steps), "reserved_evidence_bytes": reserved,
        "stop_reason": reason, "unattempted_targets": [item.to_dict() for item in targets[len(steps):]],
        "final_geometry": geometry.to_dict(), "final_analysis": analysis.to_dict(), "final_plan": plan.to_dict()}


def execute_digest_validation_loop(request: dict[str, Any], evidence: EvidenceStore,
        *, policy: DigestLoopPolicy | None = None) -> dict[str, Any]:
    """Execute declared targets within reservations; do not imply surface closure."""
    if type(evidence) is not EvidenceStore:
        raise DigestLoopError("evidence must be EvidenceStore")
    return _run(request, evidence, policy)


def replay_digest_validation_loop(record: dict[str, Any], *, policy: DigestLoopPolicy | None = None) -> dict[str, Any]:
    """Rebuild every child request and decision under separately supplied approval.

    Retained admission snapshots are step-local, never merged into one store.
    Strict duplicate-key-refusing parsing is required before passing parsed data.
    A canonical entry snapshot prevents later caller-record mutation from changing
    the comparison target; it does not protect against a hostile host process.
    """
    raw = _object(json.loads(_canonical(record)), _RECORD_KEYS, "loop execution record")
    if raw["schema_version"] != _RECORD_FORMAT:
        raise DigestLoopError("unsupported loop execution format")
    _, _, _, targets, bounds, package = _validate(raw["request"])
    _authorize(raw["request"], policy)
    steps = raw["steps"]
    if type(steps) is not list or len(steps) > min(len(targets), bounds.max_steps):
        raise DigestLoopError("record exceeds the declared step bound")
    if sum(item.max_evidence_bytes for item in targets[:len(steps)]) > bounds.max_reserved_evidence_bytes:
        raise DigestLoopError("record exceeds declared evidence reservations")
    stores: list[EvidenceStore] = []
    version = "verifier-selected-digest-execution-1" if package is None else "verifier-selected-digest-execution-2"
    for index, step in enumerate(steps):
        _object(step, {"target_index", "execution"}, "loop step")
        if type(step["target_index"]) is not int or step["target_index"] != index:
            raise DigestLoopError("step order does not match declared targets")
        execution = _object(step["execution"], _STEP_RECORD_KEYS, "child execution")
        if execution["schema_version"] != version:
            raise DigestLoopError("child record format differs from the loop package binding")
        carried = execution["evidence"]
        target = targets[index]
        if type(carried) is not dict or not set(carried).issubset({target.evidence_ref}):
            raise DigestLoopError("step evidence does not bind its declared target")
        store = EvidenceStore()
        for reference, encoded in carried.items():
            if type(encoded) is not str or len(encoded) > 4 * ((target.max_evidence_bytes + 2) // 3):
                raise DigestLoopError("retained evidence exceeds the target admission bound")
            try:
                payload = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise DigestLoopError("retained evidence is not canonical base64") from exc
            if len(payload) > target.max_evidence_bytes or base64.b64encode(payload).decode("ascii") != encoded:
                raise DigestLoopError("retained evidence is oversized or noncanonical")
            if "sha256:" + hashlib.sha256(payload).hexdigest() != reference:
                raise DigestLoopError("retained evidence bytes do not match their target")
            store.add(payload)
        stores.append(store)
    reproduced = _run(raw["request"], tuple(stores), policy)
    if _canonical(reproduced) != _canonical(raw):
        raise DigestLoopError("loop execution record did not reproduce exactly")
    return reproduced
