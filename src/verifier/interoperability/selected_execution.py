"""Experimental selected digest execution for Verifier Standard (VSTD).

Secure Hash Algorithm 256-bit (SHA-256) checks byte identity, not arbitrary
correctness. This direct module discharges no VSTD-4 rung. It changes one exact
digest coordinate and reassesses the entire original modeled geometry. Host
policy is an in-process trust boundary, not a portable authorization claim or a
sandbox against hostile Python code. Evidence bounds limit counts and bytes,
not execution time. No package, plugin, network, or filesystem input is executed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import hashlib
import re
from typing import Any

from verifier.core.certificate import canonical_digest
from verifier.core.evidence import (
    BoundProposition, BytesDigestMechanism, EvidenceBindingError, EvidenceBounds,
    EvidenceStore, MechanismOutcome, VerificationSession,
)
from verifier.core.geometry import CoordinateStatus, VerificationGeometry
from verifier.core.geometry_io import load_verification_geometry
from .catalog import InteroperabilityComponentRegistry
from .control_surface import (
    CandidateStatus, ControlSurfaceContext, ValidationPlan,
    analyze_verification_surface, plan_validation,
)
from .storage import StoredComponentPackage


DIGEST_FACET_DESCRIPTION = "SHA-256 of the exact supplied bytes equals the pinned expected digest; no other property is checked."
_FORMAT = "verifier-selected-digest-execution-1"
_PACKAGE_FORMAT = "verifier-selected-digest-execution-2"
_REQUEST_KEYS = {"geometry", "registry", "plan", "candidate_id", "coordinate_id", "proposition"}
_IMPLEMENTATION = "verifier.core.evidence:BytesDigestMechanism"
_PRIMARY_SOURCE = "src/verifier/core/evidence.py"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class SelectedExecutionError(ValueError):
    """Selection, authorization, or replay is not established."""


def _canonical(value: Any) -> bytes:
    def check(item: Any) -> None:
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is list:
            for child in item:
                check(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                check(child)
            return
        raise SelectedExecutionError("only strict canonical data types are accepted")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _object(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise SelectedExecutionError(f"{name} has unexpected or missing fields")
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise SelectedExecutionError("digest must have canonical sha256: lowercase form")
    return value


def _request_format(request: Any) -> str:
    if type(request) is not dict:
        raise SelectedExecutionError("request must be a plain record")
    if set(request) == _REQUEST_KEYS:
        return _FORMAT
    if set(request) == _REQUEST_KEYS | {"package"} and type(request["package"]) is dict:
        return _PACKAGE_FORMAT
    raise SelectedExecutionError("request has unexpected fields or a non-record package")


def _binding(value: Any) -> BoundProposition:
    raw = _object(value, {"subject_id", "predicate", "expected", "mechanism_id", "mechanism_digest", "evidence_refs", "trust_roots", "bounds", "parameters"}, "proposition")
    for name in ("subject_id", "predicate", "mechanism_id"):
        if type(raw[name]) is not str or not raw[name]:
            raise SelectedExecutionError(f"{name} must be a nonempty string")
    _digest(raw["expected"])
    _digest(raw["mechanism_digest"])
    for name in ("evidence_refs", "trust_roots"):
        if type(raw[name]) is not list or not raw[name] or any(type(item) is not str or not item for item in raw[name]):
            raise SelectedExecutionError(f"{name} must be a nonempty string array")
    for reference in raw["evidence_refs"]:
        _digest(reference)
    limits = _object(raw["bounds"], {"max_evidence_items", "max_evidence_bytes"}, "bounds")
    if any(type(number) is not int or number < 0 for number in limits.values()):
        raise SelectedExecutionError("bounds must be nonnegative integers, not coerced values")
    parameters = _object(raw["parameters"], {"coordinate_id", "locus_id", "address"}, "parameters")
    if any(type(item) is not str or not item for item in parameters.values()):
        raise SelectedExecutionError("mapping parameters must be nonempty strings")
    result = BoundProposition(
        raw["subject_id"], raw["predicate"], raw["expected"], raw["mechanism_id"],
        raw["mechanism_digest"], tuple(raw["evidence_refs"]), tuple(raw["trust_roots"]),
        EvidenceBounds(**limits), parameters,
    )
    if _canonical(result.to_dict()) != _canonical(raw):
        raise SelectedExecutionError("proposition is not canonical")
    return result


def _validate(request: Any) -> tuple[VerificationGeometry, ControlSurfaceContext, BoundProposition]:
    format_id = _request_format(request)
    raw = request
    _canonical(raw)
    geometry = load_verification_geometry(raw["geometry"])
    registry = InteroperabilityComponentRegistry.from_dict(raw["registry"])
    if _canonical(geometry.to_dict()) != _canonical(raw["geometry"]) or _canonical(registry.to_dict()) != _canonical(raw["registry"]):
        raise SelectedExecutionError("geometry and registry must be complete canonical records")
    supplied_plan = raw["plan"]
    if type(supplied_plan) is not dict or type(supplied_plan.get("context")) is not dict:
        raise SelectedExecutionError("plan must carry its full context")
    context = ControlSurfaceContext(**supplied_plan["context"])
    if _canonical(context.to_dict()) != _canonical(supplied_plan["context"]):
        raise SelectedExecutionError("context is not canonical")
    analysis = analyze_verification_surface(geometry, context)
    package = None
    if format_id == _PACKAGE_FORMAT:
        package = StoredComponentPackage.from_dict(raw["package"])
        if _canonical(package.to_dict()) != _canonical(raw["package"]):
            raise SelectedExecutionError("package must be a complete canonical record")
    plan = plan_validation(analysis, registry, package=package)
    if _canonical(plan.to_dict()) != _canonical(supplied_plan):
        raise SelectedExecutionError("stale or substituted geometry, registry, context, or plan")
    binding = _binding(raw["proposition"])
    if binding.predicate != "bytes.sha256" or binding.mechanism_id != BytesDigestMechanism.mechanism_id or len(binding.evidence_refs) != 1:
        raise SelectedExecutionError("only one exact builtin bytes.sha256 proposition is supported")
    selected = next((item for item in plan.candidates if item.candidate_id == raw["candidate_id"]), None)
    if selected is None or selected.status is not CandidateStatus.CANDIDATE or selected.mechanism_id != binding.mechanism_id or selected.relation_id is not None:
        raise SelectedExecutionError("selection is not an executable exact digest candidate")
    hole = next(item for item in analysis.holes if item.hole_id == selected.hole_id)
    if hole.source_kind != "COORDINATE" or hole.source_id != raw["coordinate_id"]:
        raise SelectedExecutionError("candidate is not for the exact selected coordinate")
    component = registry.get(selected.component_id)
    if package is not None:
        implementation = next(item for item in package.implementations if item.component_id == selected.component_id)
        if implementation.dependency_ids:
            raise SelectedExecutionError("selected package dependencies remain unresolved")
        if _PRIMARY_SOURCE not in implementation.artifact_paths:
            raise SelectedExecutionError("selected implementation does not bind the builtin primary source")
        source = next(item for item in package.artifacts if item.path == _PRIMARY_SOURCE)
        source_digest = "sha256:" + hashlib.sha256(source.content).hexdigest()
        if source_digest != BytesDigestMechanism.mechanism_digest or source_digest != binding.mechanism_digest:
            raise SelectedExecutionError("retained source does not match the exact host builtin and proposition")
    if component.implementation_ref != _IMPLEMENTATION or component.optional_dependencies or component.execution_prerequisites or context.authority_requirements:
        raise SelectedExecutionError("unsupported implementation or unresolved external prerequisites")
    if set(binding.trust_roots) != set(component.trust_roots) or not component.trust_roots:
        raise SelectedExecutionError("proposition must retain the exact descriptor trust roots")
    coordinate = next(item for item in geometry.coordinates if item.coordinate_id == raw["coordinate_id"])
    locus = next(item for item in geometry.loci if item.locus_id == coordinate.locus_id)
    facet = next(item for item in geometry.facets if item.facet_id == coordinate.facet_id)
    if facet.facet_id != "bytes.sha256" or facet.label != "Byte digest equality" or facet.description != DIGEST_FACET_DESCRIPTION:
        raise SelectedExecutionError("an arbitrary facet cannot inherit byte-digest verification")
    if binding.subject_id != locus.subject_id or dict(binding.parameters) != {"coordinate_id": coordinate.coordinate_id, "locus_id": locus.locus_id, "address": locus.address}:
        raise SelectedExecutionError("proposition does not bind the exact subject, locus, address, and coordinate")
    judgment = next((item for item in geometry.judgments if item.coordinate_id == coordinate.coordinate_id), None)
    if judgment is None or judgment.status is not CoordinateStatus.INDETERMINATE or judgment.mechanism_ids != (binding.mechanism_id,):
        raise SelectedExecutionError("unsupported, negative, stale, or differently bound judgment is not replaceable")
    return geometry, context, binding


def prepare_digest_validation(
    geometry: VerificationGeometry,
    registry: InteroperabilityComponentRegistry,
    plan: ValidationPlan,
    *, coordinate_id: str, expected_digest: str, evidence_ref: str, bounds: EvidenceBounds,
    package: StoredComponentPackage | None = None,
) -> dict[str, Any]:
    """Prepare without inspecting bytes; expectation must come from the host claim.

    Passing a digest calculated from the tested bytes as the expectation would
    test a tautology. This function cannot establish an expectation's provenance.
    Optional retained package source must correspond to the host builtin; it is
    never loaded or executed. Correspondence does not establish dependency
    completeness, package correctness, runtime qualification, or attestation.
    """
    coordinate = next(item for item in geometry.coordinates if item.coordinate_id == coordinate_id)
    locus = next(item for item in geometry.loci if item.locus_id == coordinate.locus_id)
    analysis = analyze_verification_surface(geometry, plan.context)
    hole_ids = {item.hole_id for item in analysis.holes if item.source_kind == "COORDINATE" and item.source_id == coordinate_id}
    candidates = [item for item in plan.candidates if item.hole_id in hole_ids and item.status is CandidateStatus.CANDIDATE and item.mechanism_id == BytesDigestMechanism.mechanism_id and item.relation_id is None]
    if len(candidates) != 1:
        raise SelectedExecutionError("exactly one digest candidate must be selected")
    selected = candidates[0]
    binding = BoundProposition(locus.subject_id, "bytes.sha256", expected_digest,
        BytesDigestMechanism.mechanism_id, BytesDigestMechanism.mechanism_digest,
        (evidence_ref,), registry.get(selected.component_id).trust_roots, bounds,
        {"coordinate_id": coordinate_id, "locus_id": locus.locus_id, "address": locus.address})
    request = {"geometry": geometry.to_dict(), "registry": registry.to_dict(), "plan": plan.to_dict(),
        "candidate_id": selected.candidate_id, "coordinate_id": coordinate_id, "proposition": binding.to_dict()}
    if package is not None:
        if type(package) is not StoredComponentPackage:
            raise SelectedExecutionError("package must be a StoredComponentPackage, not a digest")
        request["package"] = package.to_dict()
    # Validate original argument types before existing constructors can coerce them.
    _digest(expected_digest)
    _digest(evidence_ref)
    if type(bounds) is not EvidenceBounds:
        raise SelectedExecutionError("bounds must be an EvidenceBounds record")
    _validate(request)
    return request


@dataclass(frozen=True, init=False)
class DigestHostPolicy:
    """Host-owned exact-request allowlist; never reconstruct this from a record.

    The host must configure this outside untrusted request handling. Possession
    of a request digest or serialized AUTHORIZED text does not grant permission.
    A caller controlling host Python code can replace this policy: this is not
    isolation, identity authentication, or a privilege boundary inside Python.
    """

    approved_requests: tuple[bytes, ...]
    mechanism: BytesDigestMechanism | None

    def __init__(self, approved_requests: tuple[dict[str, Any], ...] = (), *, mechanism: BytesDigestMechanism | None = None) -> None:
        if type(approved_requests) is not tuple:
            raise SelectedExecutionError("host approvals must be an explicit tuple")
        for request in approved_requests:
            _validate(request)
        if mechanism is not None and (type(mechanism) is not BytesDigestMechanism or vars(mechanism)):
            raise SelectedExecutionError("only an unmodified explicit builtin instance can be registered")
        object.__setattr__(self, "approved_requests", tuple(_canonical(item) for item in approved_requests))
        object.__setattr__(self, "mechanism", mechanism)


def execute_selected_validation(request: dict[str, Any], evidence: EvidenceStore, *, policy: DigestHostPolicy | None = None) -> dict[str, Any]:
    """Invoke only after exact host approval, then reassess the complete geometry."""
    # Snapshot caller-owned mutable records before checking policy or executing.
    request = json.loads(_canonical(request))
    geometry, context, binding = _validate(request)
    if type(policy) is not DigestHostPolicy or _canonical(request) not in policy.approved_requests:
        raise SelectedExecutionError("host authorization denied; no mechanism invoked")
    if type(evidence) is not EvidenceStore:
        raise SelectedExecutionError("evidence must be an EvidenceStore")
    # One byte snapshot feeds both evaluation and retention. Mutation of the
    # caller's store during the run cannot leave a passing record without the
    # bytes that actually passed. Unresolvable input remains unavailable.
    snapshot = EvidenceStore()
    for reference in binding.evidence_refs:
        try:
            snapshot.add(evidence.resolve(reference))
        except EvidenceBindingError:
            pass
    session = VerificationSession(snapshot)
    if policy.mechanism is not None:
        if type(policy.mechanism) is not BytesDigestMechanism or vars(policy.mechanism):
            raise SelectedExecutionError("host mechanism registration was substituted")
        session.register(policy.mechanism)
    result = session.evaluate(binding)
    evidence_id = "selected-execution:" + canonical_digest({"request": request, "evaluation": result.to_dict()})
    updated = load_verification_geometry(geometry.to_dict())
    status = {MechanismOutcome.PASS: CoordinateStatus.VERIFIED, MechanismOutcome.FAIL: CoordinateStatus.FALSIFIED, MechanismOutcome.UNKNOWN: CoordinateStatus.INDETERMINATE}[result.outcome]
    updated.judgments = [replace(item, status=status, evidence_ids=(*item.evidence_ids, evidence_id)) if item.coordinate_id == request["coordinate_id"] else item for item in updated.judgments]
    retained: dict[str, str] = {}
    for reference in binding.evidence_refs:
        try:
            retained.update(snapshot.export_base64((reference,)))
        except EvidenceBindingError:
            pass  # Missing/corrupt bytes remain UNKNOWN; replay cannot manufacture them.
    return {"schema_version": _request_format(request), "request": request, "evidence": retained,
        "evaluation": result.to_dict(), "evidence_id": evidence_id,
        "original_analysis": analyze_verification_surface(geometry, context).to_dict(),
        "updated_geometry": updated.to_dict(),
        "updated_analysis": analyze_verification_surface(updated, context).to_dict()}


def replay_selected_validation(record: dict[str, Any], *, policy: DigestHostPolicy | None = None) -> dict[str, Any]:
    """Rerun and compare the entire record; equality is not independent authority.

    The host supplies approval separately, never from historical record fields.
    Policies are reusable: freshness, expiry, revocation, and one-time use are
    not enforced here. Callers parsing text must use a strict
    duplicate-key-refusing reader.
    Missing or corrupt input bytes are absent from the execution snapshot and
    therefore remain unavailable during both original evaluation and replay.
    Canonical entry bytes fix the comparison target before mechanism invocation;
    later caller mutation cannot repair or invalidate that retained target. This
    is input snapshotting, not protection against a hostile host process.
    """
    entry_bytes = _canonical(record)
    raw = _object(json.loads(entry_bytes), {"schema_version", "request", "evidence", "evaluation", "evidence_id", "original_analysis", "updated_geometry", "updated_analysis"}, "execution record")
    if raw["schema_version"] != _request_format(raw["request"]) or type(raw["evidence"]) is not dict:
        raise SelectedExecutionError("unsupported execution record")
    _, _, binding = _validate(raw["request"])
    if not set(raw["evidence"]).issubset(set(binding.evidence_refs)) or any(type(value) is not str for value in raw["evidence"].values()):
        raise SelectedExecutionError("record carries unexpected evidence")
    store = EvidenceStore()
    store.import_base64(raw["evidence"])
    reproduced = execute_selected_validation(raw["request"], store, policy=policy)
    if _canonical(reproduced) != entry_bytes:
        raise SelectedExecutionError("execution record did not reproduce exactly")
    return reproduced
