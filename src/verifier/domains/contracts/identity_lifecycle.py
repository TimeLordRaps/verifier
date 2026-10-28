"""Current finite declared identity lifecycle certificate.

IDENTITY-2.1 replays one externally selected IDENTITY-3.1 child and one exact
single-binding retained event/presentation history. Valid terminal histories may
PASS consistency. This does not grant current occupancy, real authority, clock
truth, actual SIM occurrence, paired-recipient enrollment or identity closure.
Verifier Standard (VSTD); simulation (SIM); JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

from asyncio import CancelledError
import hashlib
from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.receipt import strict_json_loads
from verifier.core.namespace import NamespaceObject
from verifier.domains import common as common_module
from verifier.domains.common import Unavailable
from verifier.domains.contracts import identity_scope, identity_lifecycle_replay

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "IDENTITY-2.1"
REQUEST_VERSION = "verifier-current-identity-lifecycle-request-1"
POLICY_VERSION = "verifier-current-identity-lifecycle-policy-1"
EVIDENCE_VERSION = "verifier-current-identity-declared-lifecycle-evidence-1"
CERTIFICATE_VERSION = "verifier-current-identity-lifecycle-certificate-1"
MECHANISM_ID = "verifier.current-object.identity-declared-lifecycle.1"
SCOPE = "finite_selected_declared_identity_lifecycle_consistency"
PROTOCOL_ID = "identity-lifecycle-protocol-1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_events": 1024, "max_presentations": 1024,
             "max_steps": 100000, "max_evidence_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
PROPOSITION = {
    "schema_version": "verifier-current-object-proposition-1",
    "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
    "subject_kind": "IDENTITY", "scope": SCOPE,
    "proposition": "The exact externally selected current identity role/scope child reproduces PASS and binds this immutable lifecycle relation. The complete selected single-binding retained event/presentation inventory matches its external initial anchor, final head and event count and obeys the finite declared lifecycle protocol, including half-open validity, active-only renewal, prospective terminal events and termination-first presentation ties. Consistent terminal history does not assert live eligibility.",
    "prerequisites": ["exact selected subject, collection, child request/policy/certificate bytes",
                      "exact selected binding, event/presentation inventories, initial anchor/head/count",
                      "declared clock domain, renewal ceiling, installed mechanism and finite limits"],
    "exclusions": ["actual personhood or human authentication", "real issuer/role authority or consent",
                   "observed clock, log completeness beyond selected finite inventory or current nonrevocation",
                   "actual SIM end/containment or paired recipient enrollment",
                   "unilateral exit enforcement, assurance or attribute source admission",
                   "privacy, public checkability, full identity closure, whole dynamics tier or object polish"],
}
PROPOSITION_DIGEST = "sha256:" + canonical_digest(PROPOSITION)
ROUTE_DESCRIPTOR = {"coordinate": COORDINATE, "fixed_kind": "IDENTITY", "scope": SCOPE,
    "module": __name__, "policy_builder": "identity_lifecycle_policy",
    "request_builder": "identity_lifecycle_request", "builder": "build_identity_lifecycle_certificate",
    "rechecker": "recheck_identity_lifecycle_certificate"}


class IdentityLifecycleError(ValueError):
    """Malformed external selection or substituted native certificate."""


class IdentityLifecycleUnavailable(OSError):
    """Retained checking capacity is unavailable; no semantic refusal."""


def _capture(value: Any) -> Any:
    """Own bounded plain selections before installed source or child callbacks."""
    nodes = 0
    text_bytes = 0
    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, text_bytes
        nodes += 1
        if nodes > 100000 or depth > 64:
            raise IdentityLifecycleError("external selection capture bound exhausted")
        if type(item) is dict:
            if len(item) > 4096:
                raise IdentityLifecycleError("external map bound exhausted")
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise IdentityLifecycleError("plain text keys required")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        if type(item) is list:
            if len(item) > 4096:
                raise IdentityLifecycleError("external array bound exhausted")
            return [visit(child, depth + 1) for child in item]
        if type(item) is str:
            size = len(item.encode("utf-8"))
            text_bytes += size
            if size > 4 * 1024 * 1024 or text_bytes > 8 * 1024 * 1024:
                raise IdentityLifecycleError("external text bound exhausted")
            return item
        if type(item) is int and item.bit_length() <= 256:
            return item
        if item is None or type(item) is bool:
            return item
        raise IdentityLifecycleError("plain bounded JSON selection required")
    try:
        return visit(value, 0)
    except (RuntimeError, UnicodeError) as exc:
        raise IdentityLifecycleError("external selection changed or invalid during capture") from exc


def _retained_preflight(data: bytes, maximum: int) -> None:
    """Fence bytes and JSON structure before recursive decode or canonical hash.

    This scanner grants no JSON validity: the strict decoder still rejects bad
    syntax, duplicate keys and nonfinite values. Strings shield punctuation.
    """
    if type(data) is not bytes:
        raise IdentityLifecycleError("immutable retained bytes required")
    if len(data) > maximum:
        raise IdentityLifecycleUnavailable("retained byte bound exhausted")
    stack: list[int] = []
    quoted = escaped = atom = False
    nodes = token_bytes = 0
    for unit in data:
        if quoted:
            if escaped:
                escaped = False
            elif unit == 92:
                escaped = True
            elif unit == 34:
                quoted = False
            continue
        if unit == 34:
            quoted, atom = True, False
            nodes += 1
        elif unit in (91, 123):
            stack.append(0)
            nodes += 1
            atom = False
            if len(stack) > 64:
                raise IdentityLifecycleUnavailable("retained JSON depth bound exhausted")
        elif unit in (93, 125):
            if stack:
                stack.pop()
            atom = False
        elif unit == 44:
            if stack:
                stack[-1] += 1
                if stack[-1] >= 4096:
                    raise IdentityLifecycleUnavailable("retained JSON container bound exhausted")
            atom = False
        elif unit in (9, 10, 13, 32, 58):
            atom = False
        else:
            if not atom:
                nodes += 1
                token_bytes = 0
                atom = True
            token_bytes += 1
            if token_bytes > 256:
                raise IdentityLifecycleUnavailable("retained JSON atom bound exhausted")
        if nodes > 100000:
            raise IdentityLifecycleUnavailable("retained JSON node bound exhausted")


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value) or set(value) != fields:
        raise IdentityLifecycleError(label + " fields differ")
    return dict(value)


def registration() -> dict[str, Any]:
    """Return an owned registration proposition; grant no installation credit."""
    return _capture(PROPOSITION)


def _hash(value: Any, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise IdentityLifecycleError("canonical SHA-256 commitment required")
    return value


def _text(value: Any) -> bool:
    return type(value) is str and 0 < len(value) <= 256 and bool(value.strip())


def _time(value: Any, *, optional: bool = False) -> bool:
    return (optional and value is None) or (type(value) is int and 0 <= value <= (1 << 63) - 1)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module, identity_lifecycle_replay)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["CURRENT_IDENTITY_LIFECYCLE.md"] = Path(__file__).parents[2] / "standard" / "CURRENT_IDENTITY_LIFECYCLE.md"
    paths["identity_lifecycle_evidence.json"] = Path(__file__).parents[2] / "schemas" / "identity_lifecycle_evidence.json"
    pins = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())}
    # Child mechanism recursively pins its actual composition/occupancy/core/spec dependencies.
    pins["identity_scope_dependency_closure"] = identity_scope.mechanism_digest()
    return "sha256:" + canonical_digest(pins)


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(_capture(value), {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "identity_scope_policy", "max_certificate_bytes"}, "policy")
    if policy["schema_version"] != POLICY_VERSION or policy["mechanism_id"] != MECHANISM_ID:
        raise IdentityLifecycleError("selected lifecycle mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise IdentityLifecycleError("policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(not _text(root) for root in roots) or roots != sorted(set(roots))):
        raise IdentityLifecycleError("bounded sorted unique trust-root labels required")
    if type(policy["max_certificate_bytes"]) is not int or not 1 <= policy["max_certificate_bytes"] <= _MAX_CERTIFICATE_BYTES:
        raise IdentityLifecycleError("unsupported certificate bound")
    child_policy = _record(policy["identity_scope_policy"],
        {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "child policy")
    rebuilt = identity_scope.identity_scope_policy(trust_roots=child_policy["trust_roots"],
        max_certificate_bytes=child_policy["max_certificate_bytes"])
    if canonical_bytes(rebuilt) != canonical_bytes(child_policy):
        raise IdentityLifecycleError("child policy differs from installed selection")
    policy["trust_roots"] = list(roots)
    policy["identity_scope_policy"] = rebuilt
    return policy


def identity_lifecycle_policy(*, trust_roots: list[str], identity_scope_policy: dict[str, Any],
                              max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    owned = _capture({"trust_roots": trust_roots, "identity_scope_policy": identity_scope_policy,
                      "max_certificate_bytes": max_certificate_bytes})
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), **owned})


_REQUEST_FIELDS = {"schema_version", "semantic_version", "coordinate", "proposition_digest",
    "object_kind", "subject_id", "object_digest", "collection_digest", "protocol_id",
    "identity_scope_request", "identity_scope_certificate_ref", "binding_digest", "events_digest",
    "presentation_inventory_digest", "initial_event_anchor", "selected_head_digest", "selected_event_count",
    "clock_id", "evaluation_at", "renewal_ceiling", "evidence_ref", "policy_digest", "limits"}
_CHILD_REQUEST_FIELDS = {"schema_version", "semantic_version", "coordinate", "proposition_digest",
    "object_kind", "subject_id", "object_digest", "collective_id", "declaration_digest",
    "collection_digest", "evidence_ref", "policy_digest", "limits"}


def _request(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    request = _record(_capture(value), _REQUEST_FIELDS, "request")
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE), ("object_kind", "IDENTITY"), ("protocol_id", PROTOCOL_ID)):
        if type(request[field]) is not str or request[field] != expected:
            raise IdentityLifecycleError("selected lifecycle objective/protocol differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "binding_digest", "events_digest",
                  "presentation_inventory_digest", "evidence_ref", "policy_digest", "identity_scope_certificate_ref"):
        _hash(request[field])
    for field in ("initial_event_anchor", "selected_head_digest"):
        _hash(request[field], optional=True)
    if request["proposition_digest"] != PROPOSITION_DIGEST or request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise IdentityLifecycleError("selected proposition/policy differs")
    if not _text(request["subject_id"]) or not (request["clock_id"] is None or _text(request["clock_id"])):
        raise IdentityLifecycleError("bounded subject/clock selection required")
    count = request["selected_event_count"]
    if count is not None and not (type(count) is int and 0 <= count <= 1024):
        raise IdentityLifecycleError("unsupported selected event count")
    if not _time(request["evaluation_at"], optional=True) or not _time(request["renewal_ceiling"]):
        raise IdentityLifecycleError("bounded microsecond selections required")
    limits = _record(request["limits"], set(_CEILINGS), "limits")
    if any(type(limits[k]) is not int or not 1 <= limits[k] <= ceiling for k, ceiling in _CEILINGS.items()):
        raise IdentityLifecycleError("unsupported selected bounds")
    request["limits"] = limits
    child = _record(request["identity_scope_request"], _CHILD_REQUEST_FIELDS, "external child request")
    rebuilt = identity_scope.identity_scope_request(subject_id=child["subject_id"], object_digest=child["object_digest"],
        collective_id=child["collective_id"], declaration_digest=child["declaration_digest"],
        collection_digest=child["collection_digest"], evidence_ref=child["evidence_ref"],
        policy=policy["identity_scope_policy"], limits=child["limits"])
    if canonical_bytes(rebuilt) != canonical_bytes(child):
        raise IdentityLifecycleError("external child request differs from installed selection")
    if any(rebuilt[field] != request[field] for field in ("subject_id", "object_digest", "collection_digest")):
        raise IdentityLifecycleError("foreign child subject or collection")
    request["identity_scope_request"] = rebuilt
    return request


def identity_lifecycle_request(*, identity_scope_request: dict[str, Any], identity_scope_certificate_ref: str,
    binding_digest: str, events_digest: str, presentation_inventory_digest: str,
    initial_event_anchor: str | None, selected_head_digest: str | None, selected_event_count: int | None,
    clock_id: str | None, evaluation_at: int | None, renewal_ceiling: int, evidence_ref: str,
    policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    owned = _capture({"identity_scope_request": identity_scope_request,
        "identity_scope_certificate_ref": identity_scope_certificate_ref,
        "binding_digest": binding_digest, "events_digest": events_digest,
        "presentation_inventory_digest": presentation_inventory_digest,
        "initial_event_anchor": initial_event_anchor, "selected_head_digest": selected_head_digest,
        "selected_event_count": selected_event_count, "clock_id": clock_id,
        "evaluation_at": evaluation_at, "renewal_ceiling": renewal_ceiling,
        "evidence_ref": evidence_ref, "policy": policy, "limits": limits})
    admitted = _policy(owned.pop("policy"))
    limits = owned.pop("limits")
    if limits is not None and (type(limits) is not dict or set(limits) - set(_CEILINGS)):
        raise IdentityLifecycleError("unsupported selected limit override")
    child = _record(owned["identity_scope_request"], _CHILD_REQUEST_FIELDS, "external child request")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST, "object_kind": "IDENTITY",
        "subject_id": child["subject_id"], "object_digest": child["object_digest"],
        "collection_digest": child["collection_digest"], "protocol_id": PROTOCOL_ID,
        **owned,
        "policy_digest": "sha256:" + canonical_digest(admitted), "limits": {**_CEILINGS, **(limits or {})}}, admitted)


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    statuses: list[str] = []
    observations: dict[str, Any] = {}
    try:
        _retained_preflight(data, request["limits"]["max_evidence_bytes"])
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "binding", "events", "presentations", "identity_scope_certificate"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            return MechanismDecision(MechanismOutcome.FAIL, "retained lifecycle canonical version differs")
        binding, events, rows = value["binding"], value["events"], value["presentations"]
        # Independent commitment refutations precede missing head/child support.
        for item, field in ((binding, "binding_digest"), (events, "events_digest"), (rows, "presentation_inventory_digest")):
            if item is not None and "sha256:" + canonical_digest(item) != request[field]:
                return MechanismDecision(MechanismOutcome.FAIL, "retained selection commitment differs: " + field)
        child_value = value["identity_scope_certificate"]
        child_result = None
        if child_value is not None:
            child_bytes = canonical_bytes(child_value)
            if "sha256:" + hashlib.sha256(child_bytes).hexdigest() != request["identity_scope_certificate_ref"]:
                return MechanismDecision(MechanismOutcome.FAIL, "child byte commitment substitution")
        if type(binding) is dict:
            if binding.get("identity_id") != request["subject_id"] or binding.get("identity_record_digest") != request["object_digest"][7:]:
                statuses.append("FAIL")
                observations["binding_failure"] = "lifecycle subject/record differs from exact child selection"
            if request["clock_id"] is not None and binding.get("clock_id") != request["clock_id"]:
                statuses.append("FAIL")
                observations["clock_failure"] = "lifecycle clock differs from external selection"
        missing_head = [field for field in ("initial_event_anchor", "selected_head_digest", "selected_event_count", "clock_id")
                        if request[field] is None]
        if missing_head:
            statuses.append("UNKNOWN")
            observations["missing_external_selections"] = missing_head
        if type(events) is list:
            if len(events) > request["limits"]["max_events"]:
                statuses.append("UNKNOWN")
                observations["event_bound"] = "selected event bound exhausted; replay unrun"
            else:
                if request["selected_event_count"] is not None and len(events) != request["selected_event_count"]:
                    statuses.append("FAIL")
                    observations["head_count_failure"] = "retained event count differs from external selection"
                if events and request["selected_head_digest"] is not None and "sha256:" + canonical_digest(events[-1]) != request["selected_head_digest"]:
                    statuses.append("FAIL")
                    observations["head_count_failure"] = "retained final head differs from external selection"
        # All present independent grammar and local selections precede child
        # callbacks. Missing companions/anchor block dependent completion only.
        lifecycle = identity_lifecycle_replay.replay_declared_identity_lifecycle(binding, events, rows,
            expected_binding_digest=request["binding_digest"][7:], expected_events_digest=request["events_digest"][7:],
            expected_presentations_digest=request["presentation_inventory_digest"][7:],
            initial_event_anchor=None if request["initial_event_anchor"] is None else request["initial_event_anchor"][7:],
            evaluation_at=request["evaluation_at"], renewal_ceiling=request["renewal_ceiling"],
            max_events=request["limits"]["max_events"], max_presentations=request["limits"]["max_presentations"],
            max_steps=request["limits"]["max_steps"])
        statuses.append(lifecycle["consistency_status"])
        observations["declared_lifecycle"] = lifecycle
        if lifecycle.get("checking_unavailable"):
            observations["unavailable_execution"] = "declared replay resource unavailable"
        if child_value is None:
            statuses.append("UNKNOWN")
            observations["identity_scope"] = {"status": "UNKNOWN", "reason": "selected child certificate absent"}
        else:
            try:
                child_result = identity_scope.recheck_identity_scope_certificate(child_bytes,
                    expected_request=request["identity_scope_request"], policy=policy["identity_scope_policy"])
                statuses.append(child_result["status"])
                observations["identity_scope"] = child_result
            except (Unavailable, OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
                statuses.append("UNKNOWN")
                observations["identity_scope"] = {"status": "UNKNOWN", "reason": "native child checking unavailable: " + type(exc).__name__}
                observations["unavailable_execution"] = "native child checking unavailable"
        if type(binding) is dict and child_result is not None and child_result["status"] == "PASS":
            facts = child_result["evaluation"]["observations"]["identity_assessment"]
            mapping = {"actor_id": "actor_id", "role_id": "role_id", "collective_id": "collective_id",
                "representation_id": "representation_id", "represented_kind": "actor_kind",
                "root_human_id": "root_human_id", "scope": "declared_scope"}
            if any(binding.get(field) != facts[fact] for field, fact in mapping.items()):
                statuses.append("FAIL")
                observations["binding_failure"] = "lifecycle relation differs from reproduced3.1 facts"
            if binding.get("represented_kind") == "BOT":
                child_store = EvidenceStore()
                child_store.import_base64(child_value["evidence_payloads"])
                child_data = child_store.resolve(request["identity_scope_request"]["evidence_ref"])
                _retained_preflight(child_data, request["identity_scope_request"]["limits"]["max_evidence_bytes"])
                child_evidence = strict_json_loads(child_data.decode("utf-8"))
                sims = [NamespaceObject.create(**record) for record in child_evidence["objects"]
                        if record["object_id"] == binding.get("simulation_id") and record["kind"] == "SIM"]
                if len(sims) != 1 or sims[0].digest[7:] != binding.get("simulation_record_digest"):
                    statuses.append("FAIL")
                    observations["binding_failure"] = "lifecycle SIM record differs from exact selected collection"
        outcome = "FAIL" if "FAIL" in statuses else ("UNKNOWN" if "UNKNOWN" in statuses else "PASS")
        return MechanismDecision(MechanismOutcome(outcome), "selected declared identity lifecycle replay", observations)
    except (Unavailable, OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        observations["unavailable_execution"] = "retained checking unavailable: " + type(exc).__name__
        outcome = MechanismOutcome.FAIL if "FAIL" in statuses else MechanismOutcome.UNKNOWN
        return MechanismDecision(outcome, "retained lifecycle checking unavailable", observations)
    except (ValueError, TypeError, KeyError, UnicodeError):
        observations["semantic_refutation"] = "malformed or substituted retained lifecycle/native child"
        return MechanismDecision(MechanismOutcome.FAIL, "malformed or substituted retained lifecycle/native child", observations)


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request), "proposition_digest": PROPOSITION_DIGEST}


class _IdentityLifecycleMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound lifecycle proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained lifecycle evidence bundle required")
        return _evaluate(evidence[0], self.request, self.policy)


def _binding(request: dict[str, Any], policy: dict[str, Any]) -> BoundProposition:
    return BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))


def _retained_claims(value: dict[str, Any], request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> None:
    """Refuse independently false carried claims before unavailable replay."""
    for field, expected in (("policy_digest", request["policy_digest"]),
                            ("mechanism_digest", policy["mechanism_digest"]),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("evidence_refs", [request["evidence_ref"]])):
        if value[field] != expected:
            raise IdentityLifecycleError("retained envelope selection differs: " + field)
    result = _record(value["result"], {"status", "semantic_version", "coordinate", "object_kind", "scope",
        "authority", "occupancy_liveness", "actual_log_completeness", "public_checkability",
        "whole_identity_closure", "object_profile_conformance", "evaluation"}, "retained result")
    for field, expected in (("semantic_version", SEMANTIC_VERSION), ("coordinate", COORDINATE),
                            ("object_kind", "IDENTITY"), ("scope", SCOPE),
                            *((field, "NOT_ESTABLISHED") for field in ("authority", "occupancy_liveness",
                                "actual_log_completeness", "public_checkability", "whole_identity_closure",
                                "object_profile_conformance"))):
        if type(result[field]) is not str or result[field] != expected:
            raise IdentityLifecycleError("retained result claim boundary differs: " + field)
    if type(result["status"]) is not str or result["status"] not in ("PASS", "FAIL", "UNKNOWN"):
        raise IdentityLifecycleError("retained result status differs")
    evaluation = _record(result["evaluation"], {"binding_digest", "outcome", "mechanism_id", "mechanism_digest",
        "evidence_refs", "trust_roots", "observed_evidence_bytes", "details", "observations"}, "retained evaluation")
    for field, expected in (("binding_digest", _binding(request, policy).digest()), ("outcome", result["status"]),
                            ("mechanism_id", MECHANISM_ID), ("mechanism_digest", policy["mechanism_digest"]),
                            ("evidence_refs", [request["evidence_ref"]]), ("trust_roots", policy["trust_roots"])):
        if evaluation[field] != expected:
            raise IdentityLifecycleError("retained evaluation selection differs: " + field)
    expected_size = len(store.resolve(request["evidence_ref"])) if request["evidence_ref"] in store else 0
    if (type(evaluation["observed_evidence_bytes"]) is not int or evaluation["observed_evidence_bytes"] != expected_size
            or type(evaluation["details"]) is not str or type(evaluation["observations"]) is not dict):
        raise IdentityLifecycleError("retained evaluation shape differs")
    if _hash(value["digest"]) != "sha256:" + canonical_digest({k: v for k, v in value.items() if k != "digest"}):
        raise IdentityLifecycleError("retained certificate digest differs")


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    binding = _binding(request, policy)
    session = VerificationSession(store)
    session.register(_IdentityLifecycleMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "IDENTITY", "scope": SCOPE,
        "authority": "NOT_ESTABLISHED", "occupancy_liveness": "NOT_ESTABLISHED",
        "actual_log_completeness": "NOT_ESTABLISHED", "public_checkability": "NOT_ESTABLISHED",
        "whole_identity_closure": "NOT_ESTABLISHED", "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"], "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]], "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise IdentityLifecycleUnavailable("certificate byte bound exhausted")
    return encoded


def build_identity_lifecycle_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    owned = _capture({"request": request, "policy": policy})
    admitted = _policy(owned["policy"])
    selected = _request(owned["request"], admitted)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise IdentityLifecycleError("bounded immutable lifecycle evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise IdentityLifecycleError("evidence differs from externally selected bytes")
    try:
        return _build(selected, admitted, store)
    except (Unavailable, OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        raise IdentityLifecycleUnavailable("retained certificate construction capacity unavailable") from exc


def recheck_identity_lifecycle_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    owned = _capture({"request": expected_request, "policy": policy})
    admitted = _policy(owned["policy"])
    selected = _request(owned["request"], admitted)
    if type(certificate_bytes) is not bytes:
        raise IdentityLifecycleError("immutable certificate required")
    if len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise IdentityLifecycleUnavailable("selected certificate byte checking bound exhausted")
    try:
        _retained_preflight(certificate_bytes, admitted["max_certificate_bytes"])
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest",
            "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if value["schema_version"] != CERTIFICATE_VERSION or canonical_bytes(value) != certificate_bytes or value["request"] != selected:
            raise IdentityLifecycleError("canonical certificate or external selection differs")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or set(payloads) - {selected["evidence_ref"]} or any(type(v) is not str for v in payloads.values()):
            raise IdentityLifecycleError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        _retained_claims(value, selected, admitted, store)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            reproduced = strict_json_loads(rebuilt.decode("utf-8"))["result"]
            fresh = reproduced["evaluation"]["observations"]
            if (fresh.get("unavailable_execution") and not fresh.get("semantic_refutation")
                    and (reproduced["status"] == "UNKNOWN"
                         or reproduced["status"] == value["result"]["status"] == "FAIL")):
                raise IdentityLifecycleUnavailable("native recheck unavailable; evaluated " + reproduced["status"]
                    + " retained, exact certificate reproduction unestablished")
            raise IdentityLifecycleError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (Unavailable, OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        if isinstance(exc, IdentityLifecycleUnavailable):
            raise
        raise IdentityLifecycleUnavailable("retained certificate checking capacity unavailable") from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, IdentityLifecycleError):
            raise
        raise IdentityLifecycleError("invalid lifecycle certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "PROPOSITION", "PROPOSITION_DIGEST", "SCOPE",
           "REQUEST_VERSION", "POLICY_VERSION", "EVIDENCE_VERSION", "CERTIFICATE_VERSION",
           "IdentityLifecycleError", "IdentityLifecycleUnavailable", "ROUTE_DESCRIPTOR", "registration",
           "identity_lifecycle_policy", "identity_lifecycle_request",
           "build_identity_lifecycle_certificate", "recheck_identity_lifecycle_certificate"]
