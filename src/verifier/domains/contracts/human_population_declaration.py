"""Versioned current HUMAN population-declaration certificate over typed assertions.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). False-match and false-non-match rates are
dimensionless proportions in [0, 1], retained as exact decimal strings and
decided as exact rationals, never as binary floating point. Counts are
dimensionless; byte ceilings count encoded bytes.

The check reads DECLARED humanness-assertion records in a finite typed
collection. It never establishes that anyone is a person or that any claimed
uniqueness holds, and kind is read from typed namespace records only, never
from an identifier or label such as ``human:``. The verdict follows HUMAN-4.3
and its listed dependencies HUMAN-4.1 and HUMAN-4.2 only. A declared
deduplication mechanism and both error rates declared zero are retained
observations that never decide it; HUMAN-3.2 and HUMAN-3.5 are not decided.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
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
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "HUMAN-4.3"
REQUEST_VERSION = "verifier-current-human-population-declaration-request-1"
POLICY_VERSION = "verifier-current-human-population-declaration-policy-1"
CERTIFICATE_VERSION = "verifier-current-human-population-declaration-certificate-1"
EVIDENCE_VERSION = "verifier-current-human-population-declaration-evidence-1"
MECHANISM_ID = "verifier.current-human.population-declaration.1"
SCOPE = "finite_typed_collection_of_declared_humanness_assertions"

#: The exact HUMAN-4.3 requirement text of DOMAIN_OBLIGATIONS.md.
ROW = ("Every assertion declares the exact enrollment population its uniqueness is "
       "relative to, and an undeclared population makes the uniqueness claim unestablished.")
#: The exact requirement text of the prerequisite rows the proposition also selects.
PREREQUISITE_ROWS = {
    "HUMAN-4.1": "Every humanness assertion declares the evidence class it rests on.",
    "HUMAN-4.2": ("Every assertion declares the error rates of that evidence class at "
                  "the operating point actually used."),
}
#: The exact text of two statics rows outside HUMAN-4.3's dependency column. They are
#: quoted for context and corroboration only; neither decides the verdict, and both
#: are NOT_ESTABLISHED in every result.
CITED_ROWS = {
    "HUMAN-3.2": ("False-match and false-non-match rates are decision-theoretic facts of "
                  "the operating point rather than implementation defects, and no "
                  "operating point has both at zero."),
    "HUMAN-3.5": ("Uniqueness holds only relative to an enrollment population and a "
                  "deduplication mechanism. No protocol establishes global uniqueness of "
                  "a person, and an assertion claiming it is malformed."),
}
#: HUMAN-1.2 names exactly these four evidence classes.
EVIDENCE_CLASSES = ("biometric", "hardware-attested", "in-person", "social-graph")
#: Population declarations that name no exact enrollment population, compared after
#: strip and casefold. HUMAN-4.3 asks for the exact population; HUMAN-3.5 corroborates.
GLOBAL_POPULATIONS = frozenset({"global", "worldwide", "all-humans", "all humans"})
_RATE = re.compile(r"[01](\.[0-9]{1,64})?\Z")
_RATE_FIELDS = (("false_match_rate", "false-match rate"),
                ("false_non_match_rate", "false-non-match rate"))
_EXCLUDED_FIELDS = (
    "personhood", "liveness", "biometric_accuracy", "presentation_attack_resistance",
    "injection_attack_resistance", "uniqueness_claim", "death", "authority",
    "consent", "privacy",
)
#: Rows outside the dependency column; reported, never decided here.
_NOT_DECIDED_ROWS = ("human_3_2", "human_3_5")
#: Retained observations that never decide the verdict.
_OBSERVATIONS = ("deduplication_mechanism_declared", "both_rates_zero_declared")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class HumanPopulationDeclarationError(ValueError):
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
        "cited_rows": dict(CITED_ROWS),
        "proposition": (
            "The externally selected exact HUMAN namespace record occurs, by typed "
            "kind, in the selected finite typed collection, which passes namespace "
            "composition; and every record typed HUMAN in that collection declares, "
            "in its payload, an evidence class that is one of the four HUMAN-1.2 "
            "classes and is admitted by the installed policy (HUMAN-4.1); a nonempty "
            "operating point, and a false-match rate and a false-non-match rate that "
            "are exact decimal strings in [0, 1] (HUMAN-4.2); and a nonempty exact "
            "enrollment population, which a global, worldwide or all-humans "
            "population is not (HUMAN-4.3)."
        ),
        "prerequisites": [
            "independently selected exact HUMAN record, collection, installed policy "
            "with its admitted evidence classes, and finite checker limits"
        ],
        "exclusions": [
            "personhood, liveness, biometric accuracy, or that any declared rate, population or mechanism is true",
            "uniqueness itself, relative or global, and HUMAN-4.4 accountability termination",
            "HUMAN-3.2 and HUMAN-3.5: a declared deduplication mechanism and both error rates "
            "declared zero are retained observations that never decide the verdict",
            "HUMAN-4.5 occupancy and the HUMAN-4.6 closure result, which never PASS here",
            "presentation or injection attack resistance and death as a fact",
            "whole HUMAN closure tier or object-profile conformance",
            "authority, consent, privacy, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class HumanPopulationDeclarationDescriptor:
    """Native public route metadata for one declared population proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != set(fields)):
        raise HumanPopulationDeclarationError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise HumanPopulationDeclarationError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_HUMAN_POPULATION_DECLARATION.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {
        "schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "admitted_evidence_classes", "max_certificate_bytes",
    }, "policy")
    if (type(policy["schema_version"]) is not str
            or type(policy["mechanism_id"]) is not str
            or policy["schema_version"] != POLICY_VERSION
            or policy["mechanism_id"] != MECHANISM_ID):
        raise HumanPopulationDeclarationError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise HumanPopulationDeclarationError("policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise HumanPopulationDeclarationError("bounded sorted unique trust-root labels required")
    classes = policy["admitted_evidence_classes"]
    if (type(classes) is not list or not classes
            or any(type(name) is not str or name not in EVIDENCE_CLASSES for name in classes)
            or classes != sorted(set(classes))):
        raise HumanPopulationDeclarationError(
            "admitted evidence classes must be a nonempty sorted unique subset of the HUMAN-1.2 classes")
    size = policy["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise HumanPopulationDeclarationError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    policy["admitted_evidence_classes"] = list(classes)
    return policy


def human_population_declaration_policy(
        *, trust_roots: list[str], admitted_evidence_classes: list[str] | None = None,
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "admitted_evidence_classes": (sorted(EVIDENCE_CLASSES)
                                      if admitted_evidence_classes is None
                                      else admitted_evidence_classes),
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling
           for key, ceiling in _CEILINGS.items()):
        raise HumanPopulationDeclarationError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "HUMAN"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise HumanPopulationDeclarationError("selected population-declaration objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise HumanPopulationDeclarationError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def human_population_declaration_request(
        *, subject_id: str, object_digest: str, collection_digest: str,
        evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise HumanPopulationDeclarationError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "HUMAN", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def _assertion(item: NamespaceObject, admitted: Sequence[str],
               budget: common_module.Budget) -> dict[str, bool]:
    """Decide HUMAN-4.1, 4.2 and 4.3 for one assertion; return its non-deciding observations."""
    name = item.object_id
    payload = item.payload
    budget.tick()
    if type(payload) is not dict:
        raise Refuted(f"HUMAN assertion {name} declares no assertion record")
    evidence_class = payload.get("evidence_class")
    if evidence_class is None:
        raise Refuted(f"HUMAN assertion {name} does not declare its evidence class (HUMAN-4.1)")
    if type(evidence_class) is not str or evidence_class not in EVIDENCE_CLASSES:
        raise Refuted(f"HUMAN assertion {name} declares an evidence class outside HUMAN-1.2 (HUMAN-4.1)")
    if evidence_class not in admitted:
        raise Refuted(
            f"HUMAN assertion {name} declares evidence class {evidence_class}, which the "
            "selected policy does not admit (HUMAN-4.1)")
    operating_point = payload.get("operating_point")
    if operating_point is None:
        raise Refuted(f"HUMAN assertion {name} does not declare its operating point (HUMAN-4.2)")
    if not _text(operating_point):
        raise Refuted(f"HUMAN assertion {name} declares no bounded operating point (HUMAN-4.2)")
    rates = []
    for field, label in _RATE_FIELDS:
        budget.tick()
        text = payload.get(field)
        if text is None:
            raise Refuted(f"HUMAN assertion {name} does not declare its {label} (HUMAN-4.2)")
        if type(text) is not str or _RATE.fullmatch(text) is None:
            raise Refuted(
                f"HUMAN assertion {name} declares its {label} other than as an exact decimal string (HUMAN-4.2)")
        rate = Fraction(text)
        if not Fraction(0) <= rate <= Fraction(1):
            raise Refuted(f"HUMAN assertion {name} declares its {label} outside [0, 1] (HUMAN-4.2)")
        rates.append(rate)
    population = payload.get("enrollment_population")
    if population is None or not _text(population):
        raise Refuted(f"HUMAN assertion {name} does not declare its enrollment population (HUMAN-4.3)")
    if population.strip().casefold() in GLOBAL_POPULATIONS:
        raise Refuted(
            f"HUMAN assertion {name} declares a global population, which is not an exact "
            "enrollment population (HUMAN-4.3); HUMAN-3.5 corroborates that a global "
            "uniqueness claim is malformed")
    # Retained observations only: neither HUMAN-3.2 nor HUMAN-3.5 is in this row's
    # dependency column, so neither value decides the verdict.
    return {
        "deduplication_mechanism_declared": _text(payload.get("deduplication_mechanism")),
        "both_rates_zero_declared": rates[0] == 0 and rates[1] == 0,
    }


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "objects"}, "evidence")
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
        assertions = sorted((item for item in objects if item.kind.value == "HUMAN"),
                            key=lambda item: item.object_id)
        observed = {field: [] for field in _OBSERVATIONS}
        for item in assertions:
            flags = _assertion(item, policy["admitted_evidence_classes"], budget)
            for field in _OBSERVATIONS:
                if flags[field]:
                    observed[field].append(item.object_id)
        return MechanismDecision(
            MechanismOutcome.PASS,
            "every typed HUMAN assertion declares its evidence, error rates and enrollment population",
            {"assertions": {
                "assertion_ids": [item.object_id for item in assertions],
                "assertion_count": len(assertions),
                "admitted_evidence_classes": list(policy["admitted_evidence_classes"]),
                **observed,
            }, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError,
            ZeroDivisionError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **{key: request[key] for key in (
            "semantic_version", "proposition_digest", "object_kind",
            "object_digest", "collection_digest", "policy_digest",
        )},
        "limits_digest": "sha256:" + canonical_digest(request["limits"]),
    }


class _HumanPopulationDeclarationMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound population-declaration proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained assertion evidence bundle is required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise HumanPopulationDeclarationError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_HumanPopulationDeclarationMechanism(request, policy))
    evaluation = session.evaluate(binding)
    passed = evaluation.outcome is MechanismOutcome.PASS
    assertions = evaluation.observations.get("assertions", {}) if passed else {}
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "HUMAN", "scope": SCOPE,
        "population_declaration": "PASS" if passed else "NOT_ESTABLISHED",
        **{field: list(assertions[field]) if passed else "NOT_OBSERVED"
           for field in _OBSERVATIONS},
        **{field: "NOT_ESTABLISHED" for field in _NOT_DECIDED_ROWS},
        **{field: "NOT_ESTABLISHED" for field in _EXCLUDED_FIELDS},
        "accountability_termination": "NOT_ESTABLISHED",
        "occupancy_termination": "NOT_ESTABLISHED",
        "closure_result": "NOT_ESTABLISHED",
        "human_closure_tier_conformance": "NOT_ESTABLISHED",
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
        raise HumanPopulationDeclarationError("certificate byte bound exhausted")
    return encoded


def build_human_population_declaration_certificate(
        request: dict[str, Any], evidence_bytes: bytes | None,
        *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise HumanPopulationDeclarationError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise HumanPopulationDeclarationError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_human_population_declaration_certificate(
        certificate_bytes: bytes, *, expected_request: dict[str, Any],
        policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise HumanPopulationDeclarationError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise HumanPopulationDeclarationError("canonical certificate version differs")
        if value["request"] != selected:
            raise HumanPopulationDeclarationError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise HumanPopulationDeclarationError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise HumanPopulationDeclarationError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, HumanPopulationDeclarationError):
            raise
        raise HumanPopulationDeclarationError("invalid retained population-declaration certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "ROW", "PREREQUISITE_ROWS", "CITED_ROWS", "EVIDENCE_CLASSES",
    "GLOBAL_POPULATIONS", "HumanPopulationDeclarationDescriptor",
    "HumanPopulationDeclarationError", "registration",
    "human_population_declaration_policy", "human_population_declaration_request",
    "build_human_population_declaration_certificate",
    "recheck_human_population_declaration_certificate",
]
