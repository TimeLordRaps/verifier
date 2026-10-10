"""Versioned current HUMAN no-composition certificate over declared arrangements.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Route depth counts declared arrangement hops and is
dimensionless; object and arrangement counts are dimensionless; byte ceilings
count encoded bytes.

The check reads a finite typed namespace collection plus retained DECLARED
arrangement records. It never establishes that anyone is a person, and kind is
read from typed namespace records only, never from an identifier or label such
as ``human:``.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
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
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "HUMAN-3.6"
REQUEST_VERSION = "verifier-current-human-no-composition-request-1"
POLICY_VERSION = "verifier-current-human-no-composition-policy-1"
CERTIFICATE_VERSION = "verifier-current-human-no-composition-certificate-1"
EVIDENCE_VERSION = "verifier-current-human-no-composition-evidence-1"
MECHANISM_ID = "verifier.current-human.no-composition.1"
SCOPE = "finite_typed_collection_and_retained_declared_arrangements"

#: The exact HUMAN-3.6 requirement text of DOMAIN_OBLIGATIONS.md.
ROW = ("No arrangement of models, agents, bots, simulations or collectives produces "
       "a human, at any strength, by any route. This is the one statics row no "
       "composition can reach.")
#: The exact requirement text of the prerequisite row the proposition also selects.
PREREQUISITE_ROWS = {
    "HUMAN-3.1": ("A human is singular and non-copyable and cannot be manufactured on "
                  "demand. This is what makes Sybil resistance mean anything, and no "
                  "declaration or adaptation changes it."),
}
#: The row's "models, agents, bots, simulations or collectives", as typed kinds.
ARRANGING_KINDS = frozenset({"MODEL", "AGENT", "BOT", "SIM", "COLLECTIVE"})
_EXCLUDED_FIELDS = (
    "personhood", "liveness", "biometric_accuracy", "presentation_attack_resistance",
    "injection_attack_resistance", "uniqueness_claim", "death", "authority",
    "consent", "privacy",
)
_ARRANGEMENT_FIELDS = frozenset({
    "arrangement_id", "arranged", "output", "declared_output_kind", "strength",
})
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_arrangements": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class HumanNoCompositionError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "HUMAN",
        "scope": SCOPE,
        "obligation_row": ROW,
        "prerequisite_rows": dict(PREREQUISITE_ROWS),
        "proposition": (
            "The externally selected exact HUMAN namespace record occurs, by typed "
            "kind, in the selected finite typed collection, which passes namespace "
            "composition, so every HUMAN record is a primitive leaf with no operands; "
            "the externally selected retained declared arrangement records rehash "
            "exactly and every reference resolves in the collection; no HUMAN record, "
            "by typed kind, is the output of an arrangement reachable at any route "
            "depth from a MODEL, AGENT, BOT, SIM or COLLECTIVE record, through declared "
            "arrangements or namespace operands, and no such arrangement declares HUMAN "
            "as its output kind, whatever strength it declares; and no retained "
            "arrangement at all outputs a HUMAN record or declares HUMAN as its output kind."
        ),
        "prerequisites": [
            "independently selected exact HUMAN record, collection, retained declared "
            "arrangement bytes, installed policy and finite checker limits"
        ],
        "exclusions": [
            "personhood, liveness, biometric accuracy, or that any declared arrangement ran",
            "arrangements absent from the retained records or undeclared derivations",
            "HUMAN-3.1 singularity, non-copyability and Sybil resistance beyond declared arrangements",
            "presentation or injection attack resistance, uniqueness and death as a fact",
            "whole HUMAN statics tier or object-profile conformance",
            "authority, consent, privacy, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class HumanNoCompositionDescriptor:
    """Native public route metadata for one declared no-composition proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != set(fields)):
        raise HumanNoCompositionError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise HumanNoCompositionError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_HUMAN_NO_COMPOSITION.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {
        "schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes",
    }, "policy")
    if (type(policy["schema_version"]) is not str
            or type(policy["mechanism_id"]) is not str
            or policy["schema_version"] != POLICY_VERSION
            or policy["mechanism_id"] != MECHANISM_ID):
        raise HumanNoCompositionError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise HumanNoCompositionError("policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise HumanNoCompositionError("bounded sorted unique trust-root labels required")
    size = policy["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise HumanNoCompositionError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def human_no_composition_policy(*, trust_roots: list[str],
                                max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling
           for key, ceiling in _CEILINGS.items()):
        raise HumanNoCompositionError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "arrangements_digest", "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "HUMAN"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise HumanNoCompositionError("selected no-composition objective differs")
    for field in ("object_digest", "collection_digest", "arrangements_digest",
                  "evidence_ref", "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise HumanNoCompositionError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def human_no_composition_request(*, subject_id: str, object_digest: str,
                                 collection_digest: str, arrangements_digest: str,
                                 evidence_ref: str, policy: dict[str, Any],
                                 limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise HumanNoCompositionError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "HUMAN", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "arrangements_digest": arrangements_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def _arrangements(inputs: Any, objects: list[NamespaceObject], request: dict[str, Any],
                  budget: common_module.Budget) -> dict[str, Any]:
    retained = _record(inputs, {"arrangements"}, "arrangement inputs")
    rows = retained["arrangements"]
    if type(rows) is not list:
        raise Refuted("retained arrangements must be an array")
    if len(rows) > request["limits"]["max_arrangements"]:
        raise Unavailable("selected arrangement bound exhausted")
    arrangements_digest = "sha256:" + canonical_digest(rows)
    if arrangements_digest != request["arrangements_digest"]:
        raise Refuted("retained arrangements differ from external selection")
    kinds = {item.object_id: item.kind.value for item in objects}
    admitted_kinds = {kind.value for kind in ObjectKind}
    parsed: list[dict[str, Any]] = []
    previous: str | None = None
    for row in rows:
        budget.tick()
        arrangement = _record(row, _ARRANGEMENT_FIELDS, "arrangement")
        name, arranged = arrangement["arrangement_id"], arrangement["arranged"]
        if not _text(name):
            raise Refuted("bounded arrangement identifier required")
        if previous is not None and name <= previous:
            raise Refuted("arrangement identifiers must be sorted and unique")
        previous = name
        if (type(arranged) is not list or not arranged
                or any(type(ref) is not str for ref in arranged)
                or arranged != sorted(set(arranged))):
            raise Refuted("arranged references must be a nonempty sorted unique array")
        budget.tick(len(arranged))
        output = arrangement["output"]
        if type(output) is not str or output not in kinds or any(ref not in kinds for ref in arranged):
            raise Refuted(f"arrangement {name} refers to an object outside the selected collection")
        if output in arranged:
            raise Refuted(f"arrangement {name} lists its output among its constituents")
        if arrangement["declared_output_kind"] not in admitted_kinds:
            raise Refuted(f"arrangement {name} declares an unadmitted output kind")
        if not _text(arrangement["strength"]):
            raise Refuted(f"arrangement {name} declares no bounded strength label")
        parsed.append(arrangement)
    # Least route depth from an arranging kind: namespace operands carry depth
    # unchanged from operand to composite; each declared arrangement adds one hop.
    composites: dict[str, list[str]] = {name: [] for name in kinds}
    for item in objects:
        for _, targets in item.operands:
            for target in targets:
                composites[target].append(item.object_id)
                budget.tick()
    produces: dict[str, list[int]] = {name: [] for name in kinds}
    for index, arrangement in enumerate(parsed):
        for ref in arrangement["arranged"]:
            produces[ref].append(index)
    depth: dict[str, int] = {}
    pending: deque[tuple[int, str]] = deque()
    for name in sorted(kinds):
        if kinds[name] in ARRANGING_KINDS:
            depth[name] = 0
            pending.append((0, name))
    while pending:
        level, name = pending.popleft()
        budget.tick()
        if depth[name] != level:
            continue
        for parent in composites[name]:
            if level < depth.get(parent, level + 1):
                depth[parent] = level
                pending.appendleft((level, parent))
        for index in produces[name]:
            output = parsed[index]["output"]
            if level + 1 < depth.get(output, level + 2):
                depth[output] = level + 1
                pending.append((level + 1, output))
    routed: list[tuple[int, str, str]] = []
    for arrangement in parsed:
        budget.tick()
        reached = [depth[ref] for ref in arrangement["arranged"] if ref in depth]
        yields_human = (kinds[arrangement["output"]] == "HUMAN"
                        or arrangement["declared_output_kind"] == "HUMAN")
        if yields_human and reached:
            routed.append((min(reached) + 1, arrangement["arrangement_id"], arrangement["output"]))
    if routed:
        hops, name, output = min(routed)
        raise Refuted(
            f"arrangement {name} yields HUMAN {output} from a MODEL, AGENT, BOT, SIM or "
            f"COLLECTIVE record at route depth {hops}")
    for arrangement in parsed:
        if kinds[arrangement["output"]] == "HUMAN" or arrangement["declared_output_kind"] == "HUMAN":
            raise Refuted(
                f"arrangement {arrangement['arrangement_id']} manufactures HUMAN "
                f"{arrangement['output']}, which HUMAN-3.1 excludes")
    for arrangement in parsed:
        if arrangement["declared_output_kind"] != kinds[arrangement["output"]]:
            raise Refuted(
                f"arrangement {arrangement['arrangement_id']} declares an output kind that "
                "differs from the typed output record")
    return {
        "arrangements_digest": arrangements_digest, "arrangement_count": len(parsed),
        "human_records": sorted(name for name, kind in kinds.items() if kind == "HUMAN"),
        "arranging_records": sorted(name for name, kind in kinds.items() if kind in ARRANGING_KINDS),
        "records_reached_from_arranging_kinds": len(depth),
    }


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        raw = strict_json_loads(data.decode("utf-8"))
        if type(raw) is dict and set(raw) == {"schema_version", "objects"}:
            if raw["schema_version"] != EVIDENCE_VERSION or canonical_bytes(raw) != data:
                raise Refuted("retained evidence version or canonical bytes differ")
            raise Unavailable("retained arrangement records absent")
        value = _record(raw, {"schema_version", "objects", "inputs"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            selected = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "HUMAN"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained typed HUMAN subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        if value["inputs"] is None:
            raise Unavailable("retained arrangement records absent")
        result = _arrangements(value["inputs"], objects, request, budget)
        return MechanismDecision(
            MechanismOutcome.PASS,
            "no selected declared arrangement yields a typed HUMAN record",
            {"arrangements": result, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **{key: request[key] for key in (
            "semantic_version", "proposition_digest", "object_kind",
            "object_digest", "collection_digest", "arrangements_digest", "policy_digest",
        )},
        "limits_digest": "sha256:" + canonical_digest(request["limits"]),
    }


class _HumanNoCompositionMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound no-composition proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained arrangement evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise HumanNoCompositionError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_HumanNoCompositionMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "HUMAN", "scope": SCOPE,
        "no_composition_yields_human": "PASS" if evaluation.outcome is MechanismOutcome.PASS
        else "NOT_ESTABLISHED",
        **{field: "NOT_ESTABLISHED" for field in _EXCLUDED_FIELDS},
        "human_singularity": "NOT_ESTABLISHED",
        "human_statics_tier_conformance": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise HumanNoCompositionError("certificate byte bound exhausted")
    return encoded


def build_human_no_composition_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                           *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise HumanNoCompositionError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise HumanNoCompositionError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_human_no_composition_certificate(certificate_bytes: bytes, *,
                                             expected_request: dict[str, Any],
                                             policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise HumanNoCompositionError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise HumanNoCompositionError("canonical certificate version differs")
        if value["request"] != selected:
            raise HumanNoCompositionError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise HumanNoCompositionError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise HumanNoCompositionError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, HumanNoCompositionError):
            raise
        raise HumanNoCompositionError("invalid retained no-composition certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "ROW", "PREREQUISITE_ROWS", "ARRANGING_KINDS",
    "HumanNoCompositionDescriptor", "HumanNoCompositionError", "registration",
    "human_no_composition_policy", "human_no_composition_request",
    "build_human_no_composition_certificate", "recheck_human_no_composition_certificate",
]
