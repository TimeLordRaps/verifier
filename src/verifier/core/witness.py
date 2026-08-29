"""Terminology: identifier (ID); Request for Comments (RFC); Secure Hash Algorithm
256-bit (SHA-256); Verifier Standard (VSTD).

Evidence-bound VSTD-5 Witness Corroboration reference mechanism.

Witness identifiers are coordinates, not trust.  Every required separation
dimension is an exact proposition rerun by a named mechanism, and every
corroboration reruns a mechanism over content-addressed observations.  Matching
names, repeated evidence, cryptographic identity, or majority count cannot
manufacture independence or corroboration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import re
from typing import Any, Mapping

from .depth import EvidenceBoundDepthResult, require_vstd5_entry
from .evidence import (
    BoundProposition,
    EvidenceStore,
    EvaluatedProposition,
    MechanismOutcome,
    VerificationSession,
    VerificationMechanism,
)
from .certificate import canonical_digest


class IndependenceDimension(str, Enum):
    CONTROL = "control"
    VERDICT_CODE = "verdict_code"
    TRUST_ROOT = "trust_root"
    EVIDENCE_SOURCE = "evidence_source"
    INFRASTRUCTURE = "infrastructure"
    FINANCIAL_DEPENDENCE = "financial_dependence"
    JURISDICTIONAL_DEPENDENCE = "jurisdictional_dependence"


class RelationshipState(str, Enum):
    SHARED = "SHARED"
    SEPARATE = "SEPARATE"
    UNKNOWN = "UNKNOWN"


class CorroborationOutcome(str, Enum):
    CORROBORATED = "CORROBORATED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"


class WitnessResultStatus(str, Enum):
    CORROBORATED = "CORROBORATED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"
    CONFLICTED = "CONFLICTED"


@dataclass(frozen=True)
class WitnessIdentity:
    witness_id: str
    identity_evidence_ref: str

    def to_dict(self) -> dict[str, str]:
        return {
            "witness_id": self.witness_id,
            "identity_evidence_ref": self.identity_evidence_ref,
        }


@dataclass(frozen=True)
class IndependenceAssertion:
    witness_id: str
    relationships: Mapping[IndependenceDimension, RelationshipState]
    evidence: Mapping[IndependenceDimension, BoundProposition]

    def to_dict(self) -> dict[str, Any]:
        return {
            "witness_id": self.witness_id,
            "dimensions": {
                dimension.value: {
                    "state": self.relationships.get(
                        dimension, RelationshipState.UNKNOWN
                    ).value,
                    "binding": (
                        None
                        if self.evidence.get(dimension) is None
                        else self.evidence[dimension].to_dict()
                    ),
                }
                for dimension in IndependenceDimension
            },
        }


@dataclass(frozen=True)
class CorroborationRecord:
    corroboration_id: str
    witness_id: str
    claim_binding_digest: str
    vstd4_certificate_digest: str
    checker_descriptor_digest: str
    observed_evidence_refs: tuple[str, ...]
    result: CorroborationOutcome
    observed_at: str
    verification: BoundProposition
    corroboration_class: str = "GENERAL_COMPUTATIONAL_CHECK"

    def to_dict(self) -> dict[str, Any]:
        return {
            "corroboration_id": self.corroboration_id,
            "witness_id": self.witness_id,
            "claim_binding_digest": self.claim_binding_digest,
            "vstd4_certificate_digest": self.vstd4_certificate_digest,
            "checker_descriptor_digest": self.checker_descriptor_digest,
            "observed_evidence_refs": list(self.observed_evidence_refs),
            "result": self.result.value,
            "observed_at": self.observed_at,
            "verification": self.verification.to_dict(),
            "corroboration_class": self.corroboration_class,
        }


@dataclass(frozen=True)
class WitnessBundle:
    """Claim-bound identities, ordered separation assertions, and corroborations."""

    claim_id: str
    declarant_id: str
    claim_binding_digest: str
    witnesses: tuple[WitnessIdentity, ...]
    independence: tuple[IndependenceAssertion, ...]
    corroborations: tuple[CorroborationRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "declarant_id": self.declarant_id,
            "claim_binding_digest": self.claim_binding_digest,
            "witnesses": [witness.to_dict() for witness in self.witnesses],
            "independence_assertions": [
                item.to_dict() for item in self.independence
            ],
            "corroborations": [item.to_dict() for item in self.corroborations],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WitnessBundle":
        witnesses: list[WitnessIdentity] = []
        assertions: list[IndependenceAssertion] = []
        for item in data.get("witnesses", ()):
            witness = WitnessIdentity(
                str(item["witness_id"]), str(item["identity_evidence_ref"])
            )
            witnesses.append(witness)
        for item in data.get("independence_assertions", ()):
            dimensions = item.get("dimensions")
            if not isinstance(dimensions, Mapping):
                continue
            relationships: dict[IndependenceDimension, RelationshipState] = {}
            evidence: dict[IndependenceDimension, BoundProposition] = {}
            for dimension in IndependenceDimension:
                value = dimensions.get(dimension.value, {})
                if not isinstance(value, Mapping):
                    continue
                relationships[dimension] = RelationshipState(
                    value.get("state", RelationshipState.UNKNOWN.value)
                )
                binding = value.get("binding")
                if isinstance(binding, Mapping):
                    evidence[dimension] = BoundProposition.from_dict(binding)
            assertions.append(
                IndependenceAssertion(str(item["witness_id"]), relationships, evidence)
            )
        corroborations = tuple(
            CorroborationRecord(
                str(item["corroboration_id"]),
                str(item["witness_id"]),
                str(item["claim_binding_digest"]),
                str(item["vstd4_certificate_digest"]),
                str(item["checker_descriptor_digest"]),
                tuple(str(ref) for ref in item["observed_evidence_refs"]),
                CorroborationOutcome(item["result"]),
                str(item["observed_at"]),
                BoundProposition.from_dict(item["verification"]),
                str(item.get("corroboration_class", "GENERAL_COMPUTATIONAL_CHECK")),
            )
            for item in data.get("corroborations", ())
        )
        return cls(
            str(data["claim_id"]),
            str(data["declarant_id"]),
            str(data["claim_binding_digest"]),
            tuple(witnesses),
            tuple(assertions),
            corroborations,
        )


@dataclass(frozen=True)
class WitnessCorroborationResult:
    claim_id: str
    status: WitnessResultStatus
    conformance_status: str
    computed_independence: str
    independence_evaluations: tuple[
        tuple[str, str, EvaluatedProposition], ...
    ]
    corroboration_evaluations: tuple[tuple[str, EvaluatedProposition], ...]
    disagreements: tuple[tuple[str, ...], ...]
    binding_errors: tuple[str, ...]
    identity_errors: tuple[str, ...]
    separation_errors: tuple[str, ...]
    corroboration_errors: tuple[str, ...]
    limitations: tuple[str, ...] = field(default_factory=tuple)

    @property
    def established(self) -> bool:
        return self.conformance_status == "ESTABLISHED"

    @property
    def errors(self) -> tuple[str, ...]:
        """Return all errors without using message text as decision input."""
        return (
            *self.binding_errors,
            *self.identity_errors,
            *self.separation_errors,
            *self.corroboration_errors,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "status": self.status.value,
            "conformance_status": self.conformance_status,
            "computed_independence": self.computed_independence,
            "independence_evaluations": [
                {
                    "witness_id": witness_id,
                    "dimension": dimension,
                    "evaluation": evaluation.to_dict(),
                }
                for witness_id, dimension, evaluation in self.independence_evaluations
            ],
            "corroboration_evaluations": [
                {
                    "corroboration_id": record_id,
                    "evaluation": evaluation.to_dict(),
                }
                for record_id, evaluation in self.corroboration_evaluations
            ],
            "disagreements": [list(group) for group in self.disagreements],
            "binding_errors": list(self.binding_errors),
            "identity_errors": list(self.identity_errors),
            "separation_errors": list(self.separation_errors),
            "corroboration_errors": list(self.corroboration_errors),
            "errors": list(self.errors),
            "limitations": list(self.limitations),
        }


_RECEIPT_ID = re.compile(r"^VFY-5-[A-Za-z0-9._:-]+$")
_RAW_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_REF = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_PREFIXED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _shape_error(path: str, message: str) -> None:
    raise ValueError(f"invalid VSTD-5 receipt shape at {path}: {message}")


def _object(value: Any, path: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _shape_error(path, f"must be an object with exactly {sorted(keys)}")
    return value


def _array(value: Any, path: str, minimum: int = 0) -> list[Any]:
    if not isinstance(value, list) or len(value) < minimum:
        _shape_error(path, f"must be an array with at least {minimum} item(s)")
    return value


def _text(value: Any, path: str, nonempty: bool = False) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        _shape_error(path, "must be a nonempty string" if nonempty else "must be a string")
    return value


def _sha(value: Any, path: str, form: str = "raw") -> str:
    value = _text(value, path)
    pattern = {"raw": _RAW_DIGEST, "ref": _DIGEST_REF, "prefixed": _PREFIXED_DIGEST}[form]
    if pattern.fullmatch(value) is None:
        _shape_error(path, f"must be a {form} SHA-256 digest")
    return value


def _strings(
    value: Any,
    path: str,
    minimum: int = 0,
    *,
    unique: bool = False,
    nonempty: bool = False,
) -> list[str]:
    values = _array(value, path, minimum)
    for index, item in enumerate(values):
        _text(item, f"{path}[{index}]", nonempty)
    if unique and len(set(values)) != len(values):
        _shape_error(path, "must not contain duplicates")
    return values


def _evidence_refs(
    value: Any,
    path: str,
    required_payloads: set[str],
    minimum: int = 0,
    *,
    prefixed: bool = False,
) -> list[str]:
    references = _array(value, path, minimum)
    normalized: list[str] = []
    for index, reference in enumerate(references):
        reference = _sha(reference, f"{path}[{index}]", "prefixed" if prefixed else "ref")
        normalized.append("sha256:" + reference.removeprefix("sha256:"))
    if len(set(normalized)) != len(normalized):
        _shape_error(path, "must not contain duplicates")
    required_payloads.update(normalized)
    return normalized


def _binding_shape(value: Any, path: str, required_payloads: set[str]) -> None:
    binding = _object(
        value,
        path,
        {
            "subject_id", "predicate", "expected", "mechanism_id", "mechanism_digest",
            "evidence_refs", "trust_roots", "bounds", "parameters",
        },
    )
    for field_name in ("subject_id", "predicate", "mechanism_id"):
        _text(binding[field_name], f"{path}.{field_name}", True)
    _sha(binding["mechanism_digest"], f"{path}.mechanism_digest", "prefixed")
    _evidence_refs(binding["evidence_refs"], f"{path}.evidence_refs", required_payloads, 1, prefixed=True)
    _strings(binding["trust_roots"], f"{path}.trust_roots", 1, unique=True, nonempty=True)
    bounds = _object(
        binding["bounds"], f"{path}.bounds", {"max_evidence_items", "max_evidence_bytes"}
    )
    if any(type(bounds[name]) is not int or bounds[name] < 0 for name in bounds):
        _shape_error(f"{path}.bounds", "values must be nonnegative integers")
    parameters = binding["parameters"]
    if not isinstance(parameters, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in parameters.items()
    ):
        _shape_error(f"{path}.parameters", "must map strings to strings")


def _evaluation_shape(value: Any, path: str) -> None:
    evaluation = _object(
        value,
        path,
        {
            "binding_digest", "outcome", "mechanism_id", "mechanism_digest",
            "evidence_refs", "trust_roots", "observed_evidence_bytes", "details",
            "observations",
        },
    )
    _sha(evaluation["binding_digest"], f"{path}.binding_digest")
    if evaluation["outcome"] not in {item.value for item in MechanismOutcome}:
        _shape_error(f"{path}.outcome", "is not a mechanism outcome")
    _text(evaluation["mechanism_id"], f"{path}.mechanism_id", True)
    _sha(evaluation["mechanism_digest"], f"{path}.mechanism_digest", "ref")
    references: set[str] = set()
    _evidence_refs(evaluation["evidence_refs"], f"{path}.evidence_refs", references)
    _strings(evaluation["trust_roots"], f"{path}.trust_roots", 1, unique=True, nonempty=True)
    if type(evaluation["observed_evidence_bytes"]) is not int or evaluation["observed_evidence_bytes"] < 0:
        _shape_error(f"{path}.observed_evidence_bytes", "must be a nonnegative integer")
    _text(evaluation["details"], f"{path}.details")
    if not isinstance(evaluation["observations"], Mapping):
        _shape_error(f"{path}.observations", "must be an object")


def _result_shape(value: Any, path: str) -> None:
    result = _object(
        value,
        path,
        {
            "claim_id", "status", "conformance_status", "computed_independence",
            "independence_evaluations", "corroboration_evaluations", "disagreements",
            "binding_errors", "identity_errors", "separation_errors",
            "corroboration_errors", "errors", "limitations",
        },
    )
    _text(result["claim_id"], f"{path}.claim_id", True)
    if result["status"] not in {item.value for item in WitnessResultStatus}:
        _shape_error(f"{path}.status", "is not a witness result")
    if result["conformance_status"] not in {"ESTABLISHED", "NOT_ESTABLISHED"}:
        _shape_error(f"{path}.conformance_status", "is not a conformance status")
    if result["computed_independence"] not in {"INDEPENDENT", "UNKNOWN"}:
        _shape_error(f"{path}.computed_independence", "is not an independence result")
    for field_name, id_name in (
        ("independence_evaluations", "witness_id"),
        ("corroboration_evaluations", "corroboration_id"),
    ):
        for index, item in enumerate(_array(result[field_name], f"{path}.{field_name}")):
            keys = {id_name, "evaluation"}
            if field_name == "independence_evaluations":
                keys.add("dimension")
            item = _object(item, f"{path}.{field_name}[{index}]", keys)
            _text(item[id_name], f"{path}.{field_name}[{index}].{id_name}")
            if "dimension" in item:
                _text(item["dimension"], f"{path}.{field_name}[{index}].dimension")
            _evaluation_shape(item["evaluation"], f"{path}.{field_name}[{index}].evaluation")
    for index, group in enumerate(_array(result["disagreements"], f"{path}.disagreements")):
        _strings(group, f"{path}.disagreements[{index}]", 2, unique=True)
    error_fields = (
        "binding_errors", "identity_errors", "separation_errors",
        "corroboration_errors", "errors", "limitations",
    )
    errors = {name: _strings(result[name], f"{path}.{name}") for name in error_fields}
    if result["status"] == "CORROBORATED" and (
        result["conformance_status"] != "ESTABLISHED"
        or result["computed_independence"] != "INDEPENDENT"
    ):
        _shape_error(path, "CORROBORATED requires established independent evidence")
    if result["computed_independence"] == "INDEPENDENT" and any(
        errors[name] for name in error_fields[:3]
    ):
        _shape_error(path, "INDEPENDENT cannot retain binding, identity, or separation errors")
    if result["conformance_status"] == "ESTABLISHED" and (
        result["computed_independence"] != "INDEPENDENT"
        or any(errors[name] for name in error_fields[:-1])
    ):
        _shape_error(path, "ESTABLISHED cannot retain conformance errors")


def _validate_vstd5_receipt_shape(receipt: Mapping[str, Any]) -> None:
    """Enforce the published receipt profile without adding a schema dependency."""

    receipt = _object(
        receipt,
        "$",
        {"schema_version", "receipt_id", "entry_vstd4", "bundle", "evidence_payloads", "result"},
    )
    if receipt["schema_version"] != "VSTD-5":
        _shape_error("$.schema_version", "must equal VSTD-5")
    if _RECEIPT_ID.fullmatch(_text(receipt["receipt_id"], "$.receipt_id")) is None:
        _shape_error("$.receipt_id", "must match the VFY-5 identifier grammar")
    entry = _object(
        receipt["entry_vstd4"],
        "$.entry_vstd4",
        {"result_digest", "depth", "conformance_status", "witness_digest"},
    )
    _sha(entry["result_digest"], "$.entry_vstd4.result_digest")
    _sha(entry["witness_digest"], "$.entry_vstd4.witness_digest")
    if entry["depth"] != 14 or entry["conformance_status"] != "ESTABLISHED":
        _shape_error("$.entry_vstd4", "must identify an established depth-14 VSTD-4 result")
    bundle = _object(
        receipt["bundle"],
        "$.bundle",
        {"claim_id", "declarant_id", "claim_binding_digest", "witnesses", "independence_assertions", "corroborations"},
    )
    _text(bundle["claim_id"], "$.bundle.claim_id", True)
    _text(bundle["declarant_id"], "$.bundle.declarant_id", True)
    _sha(bundle["claim_binding_digest"], "$.bundle.claim_binding_digest")
    required_payloads: set[str] = set()
    for index, item in enumerate(_array(bundle["witnesses"], "$.bundle.witnesses", 1)):
        witness = _object(item, f"$.bundle.witnesses[{index}]", {"witness_id", "identity_evidence_ref"})
        _text(witness["witness_id"], f"$.bundle.witnesses[{index}].witness_id", True)
        _evidence_refs([witness["identity_evidence_ref"]], f"$.bundle.witnesses[{index}].identity_evidence_ref", required_payloads, 1)
    dimensions = {item.value for item in IndependenceDimension}
    for index, item in enumerate(_array(bundle["independence_assertions"], "$.bundle.independence_assertions")):
        path = f"$.bundle.independence_assertions[{index}]"
        assertion = _object(item, path, {"witness_id", "dimensions"})
        _text(assertion["witness_id"], f"{path}.witness_id", True)
        records = _object(assertion["dimensions"], f"{path}.dimensions", dimensions)
        for dimension, value in records.items():
            coordinate = f"{path}.dimensions.{dimension}"
            record = _object(value, coordinate, {"state", "binding"})
            if record["state"] not in {item.value for item in RelationshipState}:
                _shape_error(f"{coordinate}.state", "is not a relationship state")
            if record["binding"] is not None:
                _binding_shape(record["binding"], f"{coordinate}.binding", required_payloads)
    for index, item in enumerate(_array(bundle["corroborations"], "$.bundle.corroborations", 1)):
        path = f"$.bundle.corroborations[{index}]"
        record = _object(
            item,
            path,
            {
                "corroboration_id", "witness_id", "claim_binding_digest",
                "vstd4_certificate_digest", "checker_descriptor_digest",
                "observed_evidence_refs", "result", "observed_at", "verification",
                "corroboration_class",
            },
        )
        for name in ("corroboration_id", "witness_id", "corroboration_class"):
            _text(record[name], f"{path}.{name}", True)
        _sha(record["claim_binding_digest"], f"{path}.claim_binding_digest")
        _sha(record["vstd4_certificate_digest"], f"{path}.vstd4_certificate_digest", "ref")
        _sha(record["checker_descriptor_digest"], f"{path}.checker_descriptor_digest", "ref")
        _evidence_refs(record["observed_evidence_refs"], f"{path}.observed_evidence_refs", required_payloads, 1)
        if record["result"] not in {item.value for item in CorroborationOutcome}:
            _shape_error(f"{path}.result", "is not a corroboration outcome")
        observed_at = _text(record["observed_at"], f"{path}.observed_at")
        try:
            if _DATE_TIME.fullmatch(observed_at) is None:
                raise ValueError
            datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError:
            _shape_error(f"{path}.observed_at", "must be an RFC 3339 date-time")
        _binding_shape(record["verification"], f"{path}.verification", required_payloads)
    payloads = receipt["evidence_payloads"]
    if not isinstance(payloads, Mapping):
        _shape_error("$.evidence_payloads", "must be an object")
    for reference, encoded in payloads.items():
        _sha(reference, "$.evidence_payloads key", "prefixed")
        _text(encoded, f"$.evidence_payloads.{reference}")
    missing = sorted(required_payloads - set(payloads))
    if missing:
        _shape_error("$.evidence_payloads", f"is missing verdict-material bytes for {missing}")
    _result_shape(receipt["result"], "$.result")

def assess_witness_corroboration(
    entry: EvidenceBoundDepthResult,
    bundle: WitnessBundle,
    *,
    session: VerificationSession,
) -> WitnessCorroborationResult:
    """Recheck VSTD-5 entry, separation evidence, and corroboration evidence."""

    require_vstd5_entry(entry)
    binding_errors: list[str] = []
    identity_errors: list[str] = []
    separation_errors: list[str] = []
    corroboration_errors: list[str] = []
    independence_results: list[tuple[str, str, EvaluatedProposition]] = []
    corroboration_results: list[tuple[str, EvaluatedProposition]] = []

    if bundle.claim_id == "":
        binding_errors.append("claim_id must not be empty")
    if bundle.declarant_id == "":
        identity_errors.append("declarant_id must not be empty")
    if bundle.claim_binding_digest != entry.witness.header.binding:  # type: ignore[union-attr]
        binding_errors.append(
            "witness bundle does not bind the admitted VSTD-4 commitment"
        )

    identities: dict[str, WitnessIdentity] = {}
    identity_refs: set[str] = set()
    for witness in bundle.witnesses:
        if not witness.witness_id:
            identity_errors.append("witness_id must not be empty")
            continue
        if witness.witness_id == bundle.declarant_id:
            identity_errors.append(f"witness {witness.witness_id} is the declarant")
        if witness.witness_id in identities:
            identity_errors.append(
                f"duplicate witness identifier: {witness.witness_id}"
            )
        identities[witness.witness_id] = witness
        try:
            identity_ref = session.evidence.add(
                session.evidence.resolve(witness.identity_evidence_ref)
            )
        except Exception as exc:
            identity_errors.append(
                f"witness {witness.witness_id} identity evidence unavailable: {exc}"
            )
            continue
        if identity_ref in identity_refs:
            identity_errors.append(
                f"witness {witness.witness_id} repeats another witness identity evidence"
            )
        identity_refs.add(identity_ref)

    assertions: dict[str, IndependenceAssertion] = {}
    for assertion in bundle.independence:
        if assertion.witness_id in assertions:
            separation_errors.append(
                f"duplicate independence assertion: {assertion.witness_id}"
            )
            continue
        assertions[assertion.witness_id] = assertion
        if assertion.witness_id not in identities:
            separation_errors.append(
                f"independence assertion references missing witness {assertion.witness_id}"
            )
            continue
        for dimension in IndependenceDimension:
            state = assertion.relationships.get(dimension, RelationshipState.UNKNOWN)
            if state is RelationshipState.SHARED:
                separation_errors.append(
                    f"witness {assertion.witness_id} shares {dimension.value} with declarant"
                )
                continue
            if state is RelationshipState.UNKNOWN:
                separation_errors.append(
                    f"witness {assertion.witness_id} has UNKNOWN {dimension.value} separation"
                )
                continue
            proposition = assertion.evidence.get(dimension)
            if proposition is None:
                separation_errors.append(
                    f"witness {assertion.witness_id} has no evidence for {dimension.value}"
                )
                continue
            relation_subject = f"{bundle.declarant_id}->{assertion.witness_id}"
            expected_predicate = f"vstd5.shared.{dimension.value}"
            if (
                proposition.subject_id != relation_subject
                or proposition.predicate != expected_predicate
                or proposition.expected is not False
                or proposition.parameters.get("claim_binding_digest")
                != bundle.claim_binding_digest
            ):
                separation_errors.append(
                    f"witness {assertion.witness_id} {dimension.value} evidence is not "
                    "bound to the exact negative separation proposition"
                )
                continue
            result = session.evaluate(proposition)
            independence_results.append(
                (assertion.witness_id, dimension.value, result)
            )
            if not result.passed:
                separation_errors.append(
                    f"witness {assertion.witness_id} {dimension.value} separation "
                    f"was not established: {result.outcome.value}"
                )

    for witness_id in identities:
        if witness_id not in assertions:
            separation_errors.append(
                f"witness {witness_id} has no independence assertion"
            )

    seen_records: set[str] = set()
    observed_sets: set[tuple[str, ...]] = set()
    accepted_outcomes: list[tuple[str, CorroborationOutcome]] = []
    for record in bundle.corroborations:
        if record.corroboration_id in seen_records:
            corroboration_errors.append(
                f"duplicate corroboration identifier: {record.corroboration_id}"
            )
            continue
        seen_records.add(record.corroboration_id)
        if record.witness_id not in identities:
            corroboration_errors.append(
                f"corroboration {record.corroboration_id} references missing witness"
            )
            continue
        if record.claim_binding_digest != bundle.claim_binding_digest:
            corroboration_errors.append(
                f"corroboration {record.corroboration_id} binds a neighboring claim"
            )
            continue
        if record.vstd4_certificate_digest.removeprefix("sha256:") != entry.witness.digest():  # type: ignore[union-attr]
            corroboration_errors.append(
                f"corroboration {record.corroboration_id} binds a different VSTD-4 certificate"
            )
            continue
        unique_observations = tuple(sorted(set(record.observed_evidence_refs)))
        if len(unique_observations) != len(record.observed_evidence_refs):
            corroboration_errors.append(
                f"corroboration {record.corroboration_id} repeats evidence references"
            )
            continue
        if unique_observations in observed_sets:
            corroboration_errors.append(
                f"corroboration {record.corroboration_id} duplicates another evidence set"
            )
            continue
        observed_sets.add(unique_observations)
        expected = {
            "claim_binding_digest": bundle.claim_binding_digest,
            "vstd4_certificate_digest": record.vstd4_certificate_digest,
            "checker_descriptor_digest": record.checker_descriptor_digest,
            "result": record.result.value,
        }
        proposition = record.verification
        if (
            proposition.subject_id != bundle.claim_id
            or proposition.predicate != "vstd5.corroboration"
            or proposition.expected != expected
            or tuple(sorted(proposition.evidence_refs)) != unique_observations
            or proposition.parameters.get("witness_id") != record.witness_id
            or proposition.parameters.get("observed_at") != record.observed_at
        ):
            corroboration_errors.append(
                f"corroboration {record.corroboration_id} is not exactly bound"
            )
            continue
        result = session.evaluate(proposition)
        corroboration_results.append((record.corroboration_id, result))
        if result.outcome is MechanismOutcome.PASS:
            accepted_outcomes.append((record.corroboration_id, record.result))
        else:
            corroboration_errors.append(
                f"corroboration {record.corroboration_id} mechanism did not pass: "
                f"{result.outcome.value}"
            )

    if not bundle.witnesses:
        identity_errors.append("at least one witness is required")
    if not bundle.corroborations:
        corroboration_errors.append("at least one corroboration is required")
    corroborating_witnesses = {record.witness_id for record in bundle.corroborations}
    for witness_id in identities:
        if witness_id not in corroborating_witnesses:
            corroboration_errors.append(
                f"witness {witness_id} has no corroboration record"
            )

    outcome_groups = {
        outcome: tuple(record_id for record_id, item in accepted_outcomes if item is outcome)
        for outcome in CorroborationOutcome
    }
    nonempty = [outcome for outcome, ids in outcome_groups.items() if ids]
    disagreements: tuple[tuple[str, ...], ...] = ()
    if len(nonempty) > 1:
        status = WitnessResultStatus.CONFLICTED
        disagreements = (tuple(sorted(record_id for record_id, _ in accepted_outcomes)),)
    elif nonempty == [CorroborationOutcome.CORROBORATED]:
        status = WitnessResultStatus.CORROBORATED
    elif nonempty == [CorroborationOutcome.REFUTED]:
        status = WitnessResultStatus.REFUTED
    else:
        status = WitnessResultStatus.UNKNOWN

    expected_independence_checks = len(identities) * len(IndependenceDimension)
    independence_established = (
        bool(identities)
        and len(bundle.witnesses) == len(identities)
        and len(assertions) == len(identities)
        and len(independence_results) == expected_independence_checks
        and all(result.passed for _, _, result in independence_results)
        and not binding_errors
        and not identity_errors
        and not separation_errors
    )
    computed_independence = "INDEPENDENT" if independence_established else "UNKNOWN"
    conformance = (
        "ESTABLISHED"
        if (
            independence_established
            and not corroboration_errors
            and len(corroboration_results) > 0
        )
        else "NOT_ESTABLISHED"
    )
    if status is WitnessResultStatus.CORROBORATED and conformance != "ESTABLISHED":
        status = WitnessResultStatus.UNKNOWN
    return WitnessCorroborationResult(
        bundle.claim_id,
        status,
        conformance,
        computed_independence,
        tuple(independence_results),
        tuple(corroboration_results),
        disagreements,
        tuple(binding_errors),
        tuple(identity_errors),
        tuple(separation_errors),
        tuple(corroboration_errors),
        (
            "Identity evidence identifies the witness coordinate; it does not confer trust.",
            "The result is bounded to the registered mechanisms, trust roots, evidence, and bounds.",
        ),
    )


def build_vstd5_receipt(
    entry: EvidenceBoundDepthResult,
    bundle: WitnessBundle,
    result: WitnessCorroborationResult,
    *,
    receipt_id: str,
    session: VerificationSession,
) -> dict[str, Any]:
    """Serialize a replayable VSTD-5 receipt without treating names as trust."""
    require_vstd5_entry(entry)
    recomputed = assess_witness_corroboration(entry, bundle, session=session)
    if canonical_digest(recomputed.to_dict()) != canonical_digest(result.to_dict()):
        raise ValueError("VSTD-5 result does not match the supplied replay inputs")
    references = {
        witness.identity_evidence_ref for witness in bundle.witnesses
    }
    for assertion in bundle.independence:
        for proposition in assertion.evidence.values():
            references.update(proposition.evidence_refs)
    for record in bundle.corroborations:
        references.update(record.observed_evidence_refs)
        references.update(record.verification.evidence_refs)
    receipt = {
        "schema_version": "VSTD-5",
        "receipt_id": receipt_id,
        "entry_vstd4": {
            "result_digest": canonical_digest(entry.to_dict()),
            "depth": entry.depth,
            "conformance_status": entry.conformance_status,
            "witness_digest": entry.witness.digest(),  # type: ignore[union-attr]
        },
        "bundle": bundle.to_dict(),
        "evidence_payloads": session.evidence.export_base64(tuple(sorted(references))),
        "result": result.to_dict(),
    }
    _validate_vstd5_receipt_shape(receipt)
    return receipt


def recheck_vstd5_receipt(
    entry: EvidenceBoundDepthResult,
    receipt: Mapping[str, Any],
    *,
    mechanisms: tuple[VerificationMechanism, ...],
) -> WitnessCorroborationResult:
    """Import exact bytes, rerun all witness mechanisms, and compare the result."""
    require_vstd5_entry(entry)
    _validate_vstd5_receipt_shape(receipt)
    entry_record = receipt.get("entry_vstd4")
    bundle_data = receipt.get("bundle")
    payloads = receipt.get("evidence_payloads")
    if not isinstance(entry_record, Mapping) or not isinstance(bundle_data, Mapping) or not isinstance(payloads, Mapping):
        raise ValueError("VSTD-5 receipt is missing replay inputs")
    if entry_record.get("result_digest") != canonical_digest(entry.to_dict()):
        raise ValueError("VSTD-5 receipt references a different VSTD-4 result")
    store = EvidenceStore()
    store.import_base64({str(key): str(value) for key, value in payloads.items()})
    session = VerificationSession(store)
    for mechanism in mechanisms:
        session.register(mechanism)
    result = assess_witness_corroboration(
        entry, WitnessBundle.from_dict(bundle_data), session=session
    )
    if canonical_digest(result.to_dict()) != canonical_digest(receipt.get("result")):
        raise ValueError("recomputed VSTD-5 result does not match receipt")
    return result


__all__ = [
    "CorroborationOutcome",
    "CorroborationRecord",
    "IndependenceAssertion",
    "IndependenceDimension",
    "RelationshipState",
    "WitnessBundle",
    "WitnessCorroborationResult",
    "WitnessIdentity",
    "WitnessResultStatus",
    "assess_witness_corroboration",
    "build_vstd5_receipt",
    "recheck_vstd5_receipt",
]
