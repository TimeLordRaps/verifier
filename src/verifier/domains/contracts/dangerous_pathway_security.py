"""Bounded dangerous-pathway security interoperability, version 1.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); identifier (ID). This module mechanically binds
and replays selected pathway records. It does not select a host threat catalog,
classify an object by itself, establish reviewer identity, authorize
publication, or execute a producer-selected checker, path, callback, or
command.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import ObjectKind
from verifier.core.receipt import strict_json_loads


REQUEST_VERSION = "verifier-dangerous-pathway-request-1"
CERTIFICATE_VERSION = "verifier-dangerous-pathway-certificate-1"
ASSESSMENT_VERSION = "claim-garden-dangerous-pathway-assessment-1"
ASSESSMENT_V2_VERSION = "claim-garden-dangerous-pathway-assessment-2"
EVIDENCE_REFERENCE_VERSION = "verifier-dangerous-pathway-evidence-reference-1"
OBSERVATION_VERSION = "verifier-dangerous-pathway-observation-1"
CATALOG_VERSION = "verifier-dangerous-pathway-catalog-1"
MECHANISM_ID = "verifier.dangerous-pathway-security.1"

DESIGN_PROVENANCE_SHA256 = (
    "sha256:91cfed1c45a9fda70bc9e9d8cfa19f76afe6396496652f13593bb3e89df9acda"
)
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
MAX_ASSESSMENT_BYTES = 32 * 1024 * 1024
MAX_ROWS = 4096
MAX_DEPTH = 48
MAX_NODES = 100_000
MAX_STRING_BYTES = 1024 * 1024
MAX_INTEGER_BITS = 4096
MAX_PREDECESSOR_DEPTH = 16

APPLICABILITY = {"APPLICABLE", "PROVED_NOT_APPLICABLE", "UNKNOWN"}
VERDICTS = {
    "REFUTED_WITHIN_ENVELOPE", "CAPABILITY_REMOVED",
    "CONTAINED_NOT_REFUTED", "PRESENT", "UNKNOWN",
}
STATUSES = {"PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED"}
RISK_CLASSES = {"R2_PENDING", "R2", "R3"}
ASSURANCE_LEVELS = {
    "SEC0_UNASSESSED", "SEC1_INVENTORY_BOUND", "SEC2_PATHWAYS_REPLAYED",
    "SEC3_INDEPENDENTLY_REFUTED", "SEC4_CONTINUOUSLY_GOVERNED",
}
SECURITY_OUTCOMES = {"ESTABLISHED", "FAIL", "UNKNOWN", "NOT_ESTABLISHED"}
SECURITY_ELIGIBILITY_STATES = {
    "DENY", "ELIGIBLE_FOR_SEPARATE_PUBLICATION_AUTHORIZATION",
}
RELEASE_SCOPES = {"DENY", "RECEIPT_ONLY", "METADATA_ONLY", "BOUNDED_INTERFACE"}
GENERALIZABLE_TOOLING_STATES = {"PRESENT", "ABSENT", "UNKNOWN"}
POLISH_TIER_NAMES = {
    1: "FACETS", 2: "DYNAMICS", 3: "STATICS", 4: "CLOSURE", 5: "INDEPENDENCE",
}
CHECK_PURPOSES = {
    "APPLICABILITY", "TRIGGER", "REFUTATION", "CAPABILITY_REMOVAL",
    "COUNTEREXAMPLE", "CONTAINMENT",
}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

CLAIM_BOUNDARY = (
    "Exact bounded host-selected dangerous-pathway inputs and retained mechanical "
    "results over one pinned catalog version and search scope only. No unknown- or "
    "future-pathway absence, real-world safety, reviewer identity, confidential proof, "
    "payment-derived authority, publication authority or distribution action is established."
)
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REQUEST_FIELDS = {
    "schema_version", "mechanism_digest", "artifact_digest",
    "derived_surface_digest", "source_coordinate_digest",
    "dependency_inventory_digest", "object_kind", "risk_policy_digest",
    "threat_catalog_digest", "threat_catalog_version", "pathway_search_scope_digest",
    "operating_envelope_digest",
    "capability_inventory_digest", "pathway_id", "catalog_entry_digest",
    "severity", "required_checks", "reviewer_policy_digest",
    "invalidator_policy_digest", "limits", "request_digest",
}
_CHECK_SELECTION_FIELDS = {
    "check_id", "purpose", "mechanism_digest", "request_digest",
    "policy_digest", "confidential",
}
_CHECK_RESULT_FIELDS = {
    "check_id", "mechanism_digest", "request_digest", "policy_digest",
    "certificate_digest", "replay_digest", "status",
}
_REVIEW_FIELDS = {
    "reviewer_id_digest", "role_digest", "conflict_check_digest",
    "mechanism_digest", "review_digest", "review_status", "conflict_status",
}
_OBSERVATION_FIELDS = {
    "schema_version", "applicability", "applicability_evidence_digest",
    "verdict", "trigger_witness_digest", "check_results",
    "counterexample_search_digest", "mitigation_digests",
    "residual_risk_digest", "residual_risk_status", "review", "invalidators",
}
_CERTIFICATE_FIELDS = {
    "schema_version", "request", "request_digest", "artifact_digest",
    "derived_surface_digest", "source_coordinate_digest",
    "dependency_inventory_digest", "object_kind", "risk_policy_digest",
    "threat_catalog_digest", "threat_catalog_version", "pathway_search_scope_digest",
    "operating_envelope_digest",
    "capability_inventory_digest", "reviewer_policy_digest", "invalidator_policy_digest",
    "pathway_id", "catalog_entry_digest",
    "severity", "applicability", "applicability_evidence_digest", "verdict",
    "trigger_witness_digest", "required_check_results",
    "counterexample_search_digest", "mitigation_digests",
    "residual_risk_digest", "residual_risk_status", "review", "invalidators", "status",
    "security_outcome", "claim_boundary", "certificate_digest",
}
_ASSESSMENT_FIELDS = {
    "schema_version", "artifact_digest", "derived_surface_digest",
    "source_coordinate_digest", "dependency_inventory_digest", "object_kind",
    "namespace_digest", "polish_receipt_digest", "ordinary_polish", "risk_policy_digest",
    "threat_catalog_digest", "threat_catalog_version", "pathway_search_scope_digest",
    "operating_envelope_digest", "reviewer_policy_digest", "invalidator_policy_digest",
    "capability_inventory_digest", "catalog_entry_digests", "pathways",
    "components", "interactions", "predecessor", "r2_evidence", "aggregate", "review",
    "invalidators", "status", "claim_boundary", "assessment_digest",
}
_ASSESSMENT_V2_FIELDS = {
    "schema_version", "mechanism_digest", "artifact_digest", "derived_surface_digest",
    "source_coordinate_digest", "dependency_inventory_digest",
    "source_inventory_digest", "package_inventory_digest", "object_kind",
    "namespace_digest", "assessment_scope_digest", "polish_receipt_digest",
    "ordinary_polish", "risk_policy_digest", "threat_catalog_digest",
    "threat_catalog_version", "pathway_search_scope_digest",
    "operating_envelope_digest", "reviewer_policy_digest",
    "invalidator_policy_digest", "capability_inventory_digest",
    "catalog_manifest", "pathways", "components", "interactions",
    "predecessor_assessment", "predecessor_assessment_digest",
    "predecessor_replay_digest", "r2_evidence", "evidence_artifact_manifest",
    "aggregate", "review",
    "invalidators", "status", "claim_boundary", "assessment_digest",
}
_CATALOG_MANIFEST_ENTRY_FIELDS = {
    "pathway_id", "catalog_entry_digest", "severity",
}
_POLISH_ROW_FIELDS = {"tier", "tier_name", "status", "receipt_digest"}
_CAPABILITY_OBSERVATION_FIELDS = {
    "inventory_digest", "observer_mechanism_digest", "observer_certificate_digest",
    "observer_replay_digest", "status", "generalizable_tooling", "risk_floor",
}
_CATALOG_COVERAGE_FIELDS = {
    "catalog_digest", "catalog_version", "search_scope_digest",
    "entry_inventory_digest", "entry_count", "coverage_evidence_digest", "status",
    "scope_claim",
}
_ENVELOPE_COVERAGE_FIELDS = {
    "envelope_digest", "replay_digest", "status",
}
_INVALIDATOR_COVERAGE_FIELDS = {
    "policy_digest", "inventory_digest", "coverage_evidence_digest", "status",
}
_COMPOSITION_COVERAGE_FIELDS = {
    "component_inventory_digest", "interaction_inventory_digest",
    "coverage_evidence_digest", "status",
}
_R2_EVIDENCE_FIELDS = {
    "capability_observation", "catalog_coverage", "operating_envelope",
    "invalidator_coverage", "composition_coverage",
}
_EVIDENCE_ARTIFACT_REFERENCE_FIELDS = {
    "schema_version", "contributor_id", "contributor_kind", "artifact_id",
    "artifact_digest", "replayer_id",
}
_EVIDENCE_CONTRIBUTOR_KINDS = {
    "SOURCE_INVENTORY", "PACKAGE_INVENTORY", "PATHWAY_APPLICABILITY",
    "PATHWAY_VERDICT", "CHECK_RESULT", "COUNTEREXAMPLE_SEARCH",
    "RESIDUAL_RISK", "POLISH_TIER", "REVIEWER_IDENTITY",
    "REVIEWER_CONFLICT", "REVIEW_RESULT", "CAPABILITY_OBSERVATION",
    "CATALOG_COVERAGE", "OPERATING_ENVELOPE", "INTERACTION",
    "COMPOSITION_COVERAGE", "INVALIDATOR", "INVALIDATOR_COVERAGE",
}


class DangerousPathwaySecurityError(ValueError):
    """The external selection or retained security record is contradictory."""


class DangerousPathwaySecurityUnavailable(DangerousPathwaySecurityError):
    """A finite input exceeded this version's supported checking capacity."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise DangerousPathwaySecurityError(label + " must be a plain object")
    if set(value) != fields:
        raise DangerousPathwaySecurityError(label + " fields differ")
    return dict(value)


def _hash(value: Any, label: str = "digest") -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise DangerousPathwaySecurityError(label + " must be a canonical SHA-256 digest")
    return value


def _nullable_hash(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _hash(value, label)


def _text(value: Any, label: str, maximum: int = 256) -> str:
    if (type(value) is not str or not value.strip() or len(value.encode("utf-8")) > maximum
            or any(ord(char) < 32 for char in value)):
        raise DangerousPathwaySecurityError(label + " must be bounded non-control text")
    return value


def _plain(value: Any, *, depth: int = 0, state: list[int] | None = None) -> None:
    """Refuse foreign containers and preflight finite canonicalization bounds."""
    if state is None:
        state = [0]
    state[0] += 1
    if state[0] > MAX_NODES or depth > MAX_DEPTH:
        raise DangerousPathwaySecurityUnavailable("plain input structure exceeds capacity")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if value.bit_length() > MAX_INTEGER_BITS:
            raise DangerousPathwaySecurityUnavailable("integer exceeds capacity")
        return
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise DangerousPathwaySecurityUnavailable("string exceeds capacity")
        return
    if type(value) is list:
        if len(value) > MAX_ROWS:
            raise DangerousPathwaySecurityUnavailable("row inventory exceeds capacity")
        for item in value:
            _plain(item, depth=depth + 1, state=state)
        return
    if type(value) is dict:
        if len(value) > MAX_ROWS or any(type(key) is not str for key in value):
            raise DangerousPathwaySecurityUnavailable("object exceeds capacity")
        for key, item in value.items():
            _plain(key, depth=depth + 1, state=state)
            _plain(item, depth=depth + 1, state=state)
        return
    raise DangerousPathwaySecurityError("only plain JSON values are admitted")


def _digest_value(value: Any) -> str:
    _plain(value)
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _digest_without(value: Mapping[str, Any], field: str) -> str:
    return _digest_value({key: item for key, item in value.items() if key != field})


def _decode(raw: bytes, maximum: int, label: str) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise DangerousPathwaySecurityError(label + " requires exact bytes")
    if len(raw) > maximum:
        raise DangerousPathwaySecurityUnavailable(label + " exceeds byte capacity")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise DangerousPathwaySecurityError(label + " is not strict JSON") from exc
    _plain(value)
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise DangerousPathwaySecurityError(label + " must be a canonical JSON object")
    return value


def mechanism_digest() -> str:
    root = Path(__file__).resolve().parents[2]
    paths = (
        Path(__file__),
        root / "standard" / "DANGEROUS_PATHWAY_SECURITY.md",
        root / "schemas" / "verifier-dangerous-pathway-request-1.schema.json",
        root / "schemas" / "verifier-dangerous-pathway-certificate-1.schema.json",
        root / "schemas" / "claim-garden-dangerous-pathway-assessment-1.schema.json",
        root / "schemas" / "claim-garden-dangerous-pathway-assessment-2.schema.json",
    )
    rows = {
        path.name: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }
    return _digest_value({"schema_version": "verifier-dangerous-pathway-mechanism-1",
                          "sources": rows})


def _limits(value: Any) -> dict[str, int]:
    row = _record(value, {"max_checks", "max_reviewers", "max_invalidators"}, "limits")
    ceilings = {"max_checks": 256, "max_reviewers": 64, "max_invalidators": 256}
    for name, ceiling in ceilings.items():
        if type(row[name]) is not int or not 1 <= row[name] <= ceiling:
            raise DangerousPathwaySecurityError(name + " limit is unsupported")
    return row


def _check_selections(value: Any, limits: dict[str, int]) -> list[dict[str, Any]]:
    if type(value) is not list or not value or len(value) > limits["max_checks"]:
        raise DangerousPathwaySecurityError("bounded nonempty required-check selection needed")
    rows = []
    for item in value:
        row = _record(item, _CHECK_SELECTION_FIELDS, "required check")
        _text(row["check_id"], "check identifier")
        if row["purpose"] not in CHECK_PURPOSES:
            raise DangerousPathwaySecurityError("unsupported check purpose")
        for field in ("mechanism_digest", "request_digest", "policy_digest"):
            _hash(row[field], field)
        if type(row["confidential"]) is not bool:
            raise DangerousPathwaySecurityError("confidential marker must be boolean")
        rows.append(row)
    identifiers = [row["check_id"] for row in rows]
    if identifiers != sorted(set(identifiers)):
        raise DangerousPathwaySecurityError("required checks must be sorted and unique")
    return rows


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, _REQUEST_FIELDS, "request")
    if request["schema_version"] != REQUEST_VERSION:
        raise DangerousPathwaySecurityError("request version differs")
    if request["mechanism_digest"] != mechanism_digest():
        raise DangerousPathwaySecurityError("request mechanism differs from installed source")
    for field in (
        "mechanism_digest", "artifact_digest", "derived_surface_digest",
        "source_coordinate_digest", "dependency_inventory_digest",
        "risk_policy_digest", "threat_catalog_digest", "operating_envelope_digest",
        "capability_inventory_digest", "catalog_entry_digest", "pathway_search_scope_digest",
        "reviewer_policy_digest", "invalidator_policy_digest",
    ):
        _hash(request[field], field)
    try:
        request["object_kind"] = ObjectKind(request["object_kind"]).value
    except (TypeError, ValueError) as exc:
        raise DangerousPathwaySecurityError("object kind is not admitted") from exc
    _text(request["threat_catalog_version"], "threat catalog version")
    _text(request["pathway_id"], "pathway identifier")
    if request["severity"] not in SEVERITIES:
        raise DangerousPathwaySecurityError("unsupported pathway severity")
    request["limits"] = _limits(request["limits"])
    request["required_checks"] = _check_selections(request["required_checks"], request["limits"])
    if request["request_digest"] != _digest_without(request, "request_digest"):
        raise DangerousPathwaySecurityError("request digest differs")
    return request


def dangerous_pathway_request(*, artifact_digest: str, derived_surface_digest: str,
        source_coordinate_digest: str, dependency_inventory_digest: str,
        object_kind: str, risk_policy_digest: str, threat_catalog_digest: str,
        threat_catalog_version: str, pathway_search_scope_digest: str,
        operating_envelope_digest: str, capability_inventory_digest: str,
        pathway_id: str, catalog_entry_digest: str, severity: str,
        required_checks: Sequence[Mapping[str, Any]], reviewer_policy_digest: str,
        invalidator_policy_digest: str, limits: Mapping[str, int] | None = None) -> dict[str, Any]:
    """Capture one exact host-selected pathway request; perform no native dispatch."""
    selected = {
        "schema_version": REQUEST_VERSION,
        "mechanism_digest": mechanism_digest(),
        "artifact_digest": artifact_digest,
        "derived_surface_digest": derived_surface_digest,
        "source_coordinate_digest": source_coordinate_digest,
        "dependency_inventory_digest": dependency_inventory_digest,
        "object_kind": object_kind,
        "risk_policy_digest": risk_policy_digest,
        "threat_catalog_digest": threat_catalog_digest,
        "threat_catalog_version": threat_catalog_version,
        "pathway_search_scope_digest": pathway_search_scope_digest,
        "operating_envelope_digest": operating_envelope_digest,
        "capability_inventory_digest": capability_inventory_digest,
        "pathway_id": pathway_id,
        "catalog_entry_digest": catalog_entry_digest,
        "severity": severity,
        "required_checks": [dict(row) for row in required_checks],
        "reviewer_policy_digest": reviewer_policy_digest,
        "invalidator_policy_digest": invalidator_policy_digest,
        "limits": dict(limits or {"max_checks": 256, "max_reviewers": 64,
                                  "max_invalidators": 256}),
        "request_digest": "",
    }
    selected["request_digest"] = _digest_without(selected, "request_digest")
    return _request(selected)


def _check_results(value: Any, request: dict[str, Any]) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) != len(request["required_checks"]):
        raise DangerousPathwaySecurityError("every selected check requires one result")
    selected = {row["check_id"]: row for row in request["required_checks"]}
    rows = []
    for item in value:
        row = _record(item, _CHECK_RESULT_FIELDS, "check result")
        check_id = _text(row["check_id"], "check result identifier")
        expected = selected.get(check_id)
        if expected is None:
            raise DangerousPathwaySecurityError("unselected check result")
        for field in ("mechanism_digest", "request_digest", "policy_digest"):
            if _hash(row[field], field) != expected[field]:
                raise DangerousPathwaySecurityError("check selection binding differs")
        for field in ("certificate_digest", "replay_digest"):
            _hash(row[field], field)
        if row["status"] not in STATUSES:
            raise DangerousPathwaySecurityError("unsupported check status")
        if expected["confidential"] and row["status"] == "PASS":
            raise DangerousPathwaySecurityError(
                "confidential digest-only evidence cannot establish PASS")
        rows.append(row)
    identifiers = [row["check_id"] for row in rows]
    if identifiers != sorted(selected):
        raise DangerousPathwaySecurityError("check result inventory differs")
    return rows


def _reviews(value: Any, maximum: int) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > maximum:
        raise DangerousPathwaySecurityError("review inventory exceeds bounds")
    rows = []
    for item in value:
        row = _record(item, _REVIEW_FIELDS, "review")
        for field in _REVIEW_FIELDS - {"review_status", "conflict_status"}:
            _hash(row[field], field)
        if row["review_status"] not in STATUSES or row["conflict_status"] not in STATUSES:
            raise DangerousPathwaySecurityError("review status differs")
        rows.append(row)
    keys = [(row["reviewer_id_digest"], row["review_digest"]) for row in rows]
    if keys != sorted(set(keys)):
        raise DangerousPathwaySecurityError("reviews must be sorted and unique")
    return rows


def _digest_list(value: Any, label: str, maximum: int, *, allow_empty: bool = True) -> list[str]:
    if type(value) is not list or len(value) > maximum or (not allow_empty and not value):
        raise DangerousPathwaySecurityError(label + " inventory exceeds bounds")
    rows = [_hash(item, label) for item in value]
    if rows != sorted(set(rows)):
        raise DangerousPathwaySecurityError(label + " inventory must be sorted and unique")
    return rows


def _status(checks: Sequence[Mapping[str, Any]], invalidators: Sequence[str]) -> str:
    values = [row["status"] for row in checks]
    if "FAIL" in values:
        return "FAIL"
    if invalidators or any(value in {"UNKNOWN", "NOT_ESTABLISHED"} for value in values):
        return "UNKNOWN"
    return "PASS"


def _observation(value: Any, request: dict[str, Any]) -> dict[str, Any]:
    row = _record(value, _OBSERVATION_FIELDS, "observation")
    if row["schema_version"] != OBSERVATION_VERSION:
        raise DangerousPathwaySecurityError("observation version differs")
    if row["applicability"] not in APPLICABILITY or row["verdict"] not in VERDICTS:
        raise DangerousPathwaySecurityError("applicability or verdict differs")
    row["applicability_evidence_digest"] = _nullable_hash(
        row["applicability_evidence_digest"], "applicability evidence")
    row["trigger_witness_digest"] = _nullable_hash(
        row["trigger_witness_digest"], "trigger witness")
    row["counterexample_search_digest"] = _nullable_hash(
        row["counterexample_search_digest"], "counterexample search")
    _hash(row["residual_risk_digest"], "residual risk")
    if row["residual_risk_status"] not in STATUSES:
        raise DangerousPathwaySecurityError("residual risk status differs")
    row["check_results"] = _check_results(row["check_results"], request)
    row["mitigation_digests"] = _digest_list(
        row["mitigation_digests"], "mitigation", request["limits"]["max_checks"])
    row["invalidators"] = _digest_list(
        row["invalidators"], "invalidator", request["limits"]["max_invalidators"])
    row["review"] = _reviews(row["review"], request["limits"]["max_reviewers"])
    purposes = {selected["purpose"]: result["status"]
                for selected, result in zip(request["required_checks"], row["check_results"])}
    if row["applicability"] == "UNKNOWN":
        if row["applicability_evidence_digest"] is not None or row["verdict"] != "UNKNOWN":
            raise DangerousPathwaySecurityError("unknown applicability cannot claim evidence or verdict")
    elif row["applicability"] == "PROVED_NOT_APPLICABLE":
        if (row["applicability_evidence_digest"] is None
                or purposes.get("APPLICABILITY") != "PASS"
                or row["verdict"] != "UNKNOWN"):
            raise DangerousPathwaySecurityError(
                "proved inapplicability requires a passing selected mechanism")
    elif row["verdict"] == "PRESENT":
        if row["trigger_witness_digest"] is None or purposes.get("TRIGGER") != "PASS":
            raise DangerousPathwaySecurityError("present pathway requires a replayed trigger")
    elif row["verdict"] == "REFUTED_WITHIN_ENVELOPE":
        if (row["counterexample_search_digest"] is None
                or purposes.get("REFUTATION") != "PASS"
                or purposes.get("COUNTEREXAMPLE") != "PASS"):
            raise DangerousPathwaySecurityError(
                "refutation requires replay and adversarial counterexample search")
    elif row["verdict"] == "CAPABILITY_REMOVED":
        if (request["artifact_digest"] == request["derived_surface_digest"]
                or purposes.get("CAPABILITY_REMOVAL") != "PASS"):
            raise DangerousPathwaySecurityError(
                "capability removal requires a separately digested derived surface")
    elif row["verdict"] == "CONTAINED_NOT_REFUTED":
        if not row["mitigation_digests"] or purposes.get("CONTAINMENT") != "PASS":
            raise DangerousPathwaySecurityError("containment requires retained mitigation replay")
    elif row["verdict"] != "UNKNOWN":
        raise DangerousPathwaySecurityError("pathway verdict is unsupported")
    return row


def _certificate_from(request: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
    status = _status(observation["check_results"], observation["invalidators"])
    if (observation["applicability"] == "UNKNOWN"
            or (observation["verdict"] == "UNKNOWN"
                and observation["applicability"] != "PROVED_NOT_APPLICABLE")):
        status = "UNKNOWN" if status == "PASS" else status
    if status == "FAIL":
        security = "NOT_ESTABLISHED"
    elif (observation["verdict"] == "PRESENT"
          or observation["residual_risk_status"] == "FAIL") and status == "PASS":
        security = "FAIL"
    elif observation["residual_risk_status"] != "PASS":
        security = "UNKNOWN"
    elif status != "PASS":
        security = "UNKNOWN"
    elif (observation["applicability"] == "PROVED_NOT_APPLICABLE"
          or observation["verdict"] in {"REFUTED_WITHIN_ENVELOPE", "CAPABILITY_REMOVED"}):
        security = "ESTABLISHED"
    else:
        security = "UNKNOWN"
    certificate = {
        "schema_version": CERTIFICATE_VERSION,
        "request": request,
        "request_digest": request["request_digest"],
        **{field: request[field] for field in (
            "artifact_digest", "derived_surface_digest", "source_coordinate_digest",
            "dependency_inventory_digest", "object_kind", "risk_policy_digest",
            "threat_catalog_digest", "threat_catalog_version",
            "pathway_search_scope_digest", "operating_envelope_digest",
            "capability_inventory_digest", "reviewer_policy_digest",
            "invalidator_policy_digest", "pathway_id", "catalog_entry_digest", "severity")},
        "applicability": observation["applicability"],
        "applicability_evidence_digest": observation["applicability_evidence_digest"],
        "verdict": observation["verdict"],
        "trigger_witness_digest": observation["trigger_witness_digest"],
        "required_check_results": observation["check_results"],
        "counterexample_search_digest": observation["counterexample_search_digest"],
        "mitigation_digests": observation["mitigation_digests"],
        "residual_risk_digest": observation["residual_risk_digest"],
        "residual_risk_status": observation["residual_risk_status"],
        "review": observation["review"],
        "invalidators": observation["invalidators"],
        "status": status,
        "security_outcome": security,
        "claim_boundary": CLAIM_BOUNDARY,
        "certificate_digest": "",
    }
    certificate["certificate_digest"] = _digest_without(certificate, "certificate_digest")
    return certificate


def build_dangerous_pathway_certificate(request: Mapping[str, Any],
        observation: Mapping[str, Any]) -> bytes:
    """Build a canonical retained result from already-run host-selected checks."""
    selected = _request(dict(request))
    observed = _observation(dict(observation), selected)
    return canonical_bytes(_certificate_from(selected, observed))


def _certificate(value: Any, request: dict[str, Any]) -> dict[str, Any]:
    carried = _record(value, _CERTIFICATE_FIELDS, "certificate")
    observation = {
        "schema_version": OBSERVATION_VERSION,
        "applicability": carried["applicability"],
        "applicability_evidence_digest": carried["applicability_evidence_digest"],
        "verdict": carried["verdict"],
        "trigger_witness_digest": carried["trigger_witness_digest"],
        "check_results": carried["required_check_results"],
        "counterexample_search_digest": carried["counterexample_search_digest"],
        "mitigation_digests": carried["mitigation_digests"],
        "residual_risk_digest": carried["residual_risk_digest"],
        "residual_risk_status": carried["residual_risk_status"],
        "review": carried["review"],
        "invalidators": carried["invalidators"],
    }
    rebuilt = _certificate_from(request, _observation(observation, request))
    if canonical_bytes(carried) != canonical_bytes(rebuilt):
        raise DangerousPathwaySecurityError("certificate result or digest differs")
    return carried


def recheck_dangerous_pathway_certificate(certificate_bytes: bytes, *,
        request_bytes: bytes) -> dict[str, Any]:
    """Recheck legacy record bytes without qualifying selected check semantics.

    Version 1 certificate/check digests are retained record bindings, not an
    installed semantic replay protocol. Reconstructing the record therefore
    cannot make its carried outcome effective security evidence.
    """
    request = _request(_decode(request_bytes, MAX_REQUEST_BYTES, "request"))
    certificate = _certificate(
        _decode(certificate_bytes, MAX_CERTIFICATE_BYTES, "certificate"), request)
    recorded_security = certificate["security_outcome"]
    effective_security = (
        "UNKNOWN" if recorded_security == "UNKNOWN" else "NOT_ESTABLISHED")
    return {
        "schema_version": "verifier-dangerous-pathway-replay-1",
        "replay_status": "REPRODUCED",
        "status": certificate["status"],
        "security_outcome": effective_security,
        "recorded_security_outcome": recorded_security,
        "security_eligibility": "DENY",
        "qualification_status": "LEGACY_UNQUALIFIED",
        "revocation_reason": "SELECTED_CHECK_SEMANTIC_REPLAY_NOT_ESTABLISHED",
        "certificate_digest": certificate["certificate_digest"],
        "publication_authority": "NOT_ESTABLISHED",
        "claim_boundary": CLAIM_BOUNDARY,
    }


def _component_rows(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > MAX_ROWS:
        raise DangerousPathwaySecurityError("component inventory exceeds bounds")
    rows = []
    for item in value:
        row = _record(item, {"component_id", "digest", "risk_class"}, "component")
        _text(row["component_id"], "component identifier")
        _hash(row["digest"], "component digest")
        if row["risk_class"] not in RISK_CLASSES:
            raise DangerousPathwaySecurityError("component risk class differs")
        rows.append(row)
    identifiers = [row["component_id"] for row in rows]
    if identifiers != sorted(set(identifiers)):
        raise DangerousPathwaySecurityError("components must be sorted and unique")
    return rows


def _interaction_rows(value: Any, components: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > MAX_ROWS:
        raise DangerousPathwaySecurityError("interaction inventory exceeds bounds")
    available = {row["component_id"] for row in components}
    rows = []
    fields = {"interaction_id", "component_ids", "amplification_status",
              "counterexample_search_digest"}
    for item in value:
        row = _record(item, fields, "interaction")
        _text(row["interaction_id"], "interaction identifier")
        if (type(row["component_ids"]) is not list or len(row["component_ids"]) < 2
                or row["component_ids"] != sorted(set(row["component_ids"]))
                or not set(row["component_ids"]) <= available):
            raise DangerousPathwaySecurityError("interaction component selection differs")
        if row["amplification_status"] not in STATUSES:
            raise DangerousPathwaySecurityError("interaction status differs")
        row["counterexample_search_digest"] = _nullable_hash(
            row["counterexample_search_digest"], "interaction counterexample search")
        if (row["amplification_status"] in {"PASS", "FAIL"}
                and row["counterexample_search_digest"] is None):
            raise DangerousPathwaySecurityError("observed interaction needs search evidence")
        rows.append(row)
    identifiers = [row["interaction_id"] for row in rows]
    if identifiers != sorted(set(identifiers)):
        raise DangerousPathwaySecurityError("interactions must be sorted and unique")
    return rows


def _has_full_composition_interaction(components: Sequence[Mapping[str, Any]],
        interactions: Sequence[Mapping[str, Any]]) -> bool:
    """Require an explicit higher-order check over the complete composition."""
    if len(components) < 2:
        return True
    complete = [row["component_id"] for row in components]
    return any(row["component_ids"] == complete for row in interactions)


def _predecessor(value: Any) -> dict[str, Any]:
    row = _record(value, {"artifact_digest", "derived_surface_digest",
                          "assessment_digest", "risk_class"}, "predecessor")
    if all(item is None for item in row.values()):
        return row
    for field in ("artifact_digest", "derived_surface_digest", "assessment_digest"):
        _hash(row[field], "predecessor " + field)
    if row["risk_class"] not in RISK_CLASSES:
        raise DangerousPathwaySecurityError("predecessor risk class differs")
    return row


def _invalidator_rows(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > MAX_ROWS:
        raise DangerousPathwaySecurityError("invalidator inventory exceeds bounds")
    rows = []
    for item in value:
        row = _record(item, {"invalidator_id", "digest", "status"}, "invalidator")
        _text(row["invalidator_id"], "invalidator identifier")
        _hash(row["digest"], "invalidator digest")
        if row["status"] not in {"ACTIVE", "CLEARED", "UNKNOWN"}:
            raise DangerousPathwaySecurityError("invalidator status differs")
        rows.append(row)
    identifiers = [row["invalidator_id"] for row in rows]
    if identifiers != sorted(set(identifiers)):
        raise DangerousPathwaySecurityError("invalidators must be sorted and unique")
    return rows


def _independent_review(rows: Sequence[Mapping[str, Any]]) -> bool:
    passed = [row for row in rows
              if row["review_status"] == "PASS" and row["conflict_status"] == "PASS"]
    return (len({row["reviewer_id_digest"] for row in passed}) >= 2
            and len({row["mechanism_digest"] for row in passed}) >= 2)


def _ordinary_polish(value: Any, polish_receipt_digest: str) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) != len(POLISH_TIER_NAMES):
        raise DangerousPathwaySecurityError("ordinary polish tiers 1 through 5 are required")
    rows = []
    for item in value:
        row = _record(item, _POLISH_ROW_FIELDS, "ordinary polish tier")
        if (type(row["tier"]) is not int
                or POLISH_TIER_NAMES.get(row["tier"]) != row["tier_name"]
                or row["status"] not in STATUSES):
            raise DangerousPathwaySecurityError("ordinary polish tier semantics differ")
        _hash(row["receipt_digest"], "ordinary polish receipt")
        rows.append(row)
    if [row["tier"] for row in rows] != list(POLISH_TIER_NAMES):
        raise DangerousPathwaySecurityError("ordinary polish tier inventory differs")
    if _digest_value(rows) != polish_receipt_digest:
        raise DangerousPathwaySecurityError("ordinary polish receipt binding differs")
    return rows


def _coverage_status(value: Any, label: str) -> str:
    if value not in STATUSES:
        raise DangerousPathwaySecurityError(label + " status differs")
    return value


def _r2_evidence(value: Any, assessment: Mapping[str, Any]) -> dict[str, Any]:
    evidence = _record(value, _R2_EVIDENCE_FIELDS, "R2 evidence")

    capability = _record(
        evidence["capability_observation"], _CAPABILITY_OBSERVATION_FIELDS,
        "capability observation")
    for field in (
        "inventory_digest", "observer_mechanism_digest", "observer_certificate_digest",
        "observer_replay_digest",
    ):
        _hash(capability[field], "capability " + field)
    if capability["inventory_digest"] != assessment["capability_inventory_digest"]:
        raise DangerousPathwaySecurityError("capability inventory binding differs")
    _coverage_status(capability["status"], "capability observation")
    if capability["generalizable_tooling"] not in GENERALIZABLE_TOOLING_STATES:
        raise DangerousPathwaySecurityError("generalizable tooling state differs")
    if capability["risk_floor"] not in RISK_CLASSES:
        raise DangerousPathwaySecurityError("capability risk floor differs")
    if (capability["generalizable_tooling"] == "PRESENT"
            and capability["risk_floor"] == "R2_PENDING"):
        raise DangerousPathwaySecurityError(
            "observed generalizable tooling requires at least R2")

    catalog = _record(
        evidence["catalog_coverage"], _CATALOG_COVERAGE_FIELDS, "catalog coverage")
    for field in (
        "catalog_digest", "search_scope_digest", "entry_inventory_digest",
        "coverage_evidence_digest",
    ):
        _hash(catalog[field], "catalog " + field)
    _text(catalog["catalog_version"], "catalog version")
    if (catalog["catalog_digest"] != assessment["threat_catalog_digest"]
            or catalog["catalog_version"] != assessment["threat_catalog_version"]
            or catalog["search_scope_digest"] != assessment["pathway_search_scope_digest"]
            or catalog["entry_inventory_digest"]
                != _digest_value(assessment["catalog_entry_digests"])
            or type(catalog["entry_count"]) is not int
            or catalog["entry_count"] != len(assessment["catalog_entry_digests"])):
        raise DangerousPathwaySecurityError("catalog coverage binding differs")
    if catalog["scope_claim"] != "PINNED_CATALOG_ONLY":
        raise DangerousPathwaySecurityError("catalog scope must preserve unknown pathways")
    _coverage_status(catalog["status"], "catalog coverage")

    envelope = _record(
        evidence["operating_envelope"], _ENVELOPE_COVERAGE_FIELDS,
        "operating envelope coverage")
    _hash(envelope["envelope_digest"], "operating envelope")
    _hash(envelope["replay_digest"], "operating envelope replay")
    if envelope["envelope_digest"] != assessment["operating_envelope_digest"]:
        raise DangerousPathwaySecurityError("operating envelope binding differs")
    _coverage_status(envelope["status"], "operating envelope")

    invalidators = _record(
        evidence["invalidator_coverage"], _INVALIDATOR_COVERAGE_FIELDS,
        "invalidator coverage")
    for field in ("policy_digest", "inventory_digest", "coverage_evidence_digest"):
        _hash(invalidators[field], "invalidator " + field)
    if (invalidators["policy_digest"] != assessment["invalidator_policy_digest"]
            or invalidators["inventory_digest"]
                != _digest_value(assessment["invalidators"])):
        raise DangerousPathwaySecurityError("invalidator coverage binding differs")
    _coverage_status(invalidators["status"], "invalidator coverage")

    composition = _record(
        evidence["composition_coverage"], _COMPOSITION_COVERAGE_FIELDS,
        "composition coverage")
    for field in (
        "component_inventory_digest", "interaction_inventory_digest",
        "coverage_evidence_digest",
    ):
        _hash(composition[field], "composition " + field)
    if (composition["component_inventory_digest"]
            != _digest_value(assessment["components"])
            or composition["interaction_inventory_digest"]
                != _digest_value(assessment["interactions"])):
        raise DangerousPathwaySecurityError("composition coverage binding differs")
    _coverage_status(composition["status"], "composition coverage")
    return evidence


def _evidence_contributor_id(kind: str, key: Any) -> str:
    return kind + ":" + _digest_value(key).removeprefix("sha256:")


def _required_evidence_replayer_id(kind: str) -> str:
    return "verifier.dangerous-pathway-evidence." + kind.lower().replace("_", "-") + ".1"


def _evidence_contributors(
        assessment: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Derive every exact artifact needed before v2 eligibility can be established."""
    contributors: dict[str, dict[str, Any]] = {}

    def add(kind: str, key: Any, payload: Mapping[str, Any] | None, *,
            expected_digest: str | None = None) -> None:
        contributor_id = _evidence_contributor_id(kind, key)
        if contributor_id in contributors:
            raise DangerousPathwaySecurityError(
                "evidence contributor identifier collides")
        expected_bytes = None if payload is None else canonical_bytes(dict(payload))
        contributors[contributor_id] = {
            "kind": kind,
            "replayer_id": _required_evidence_replayer_id(kind),
            "expected_bytes": expected_bytes,
            "expected_digest": expected_digest,
        }
        if len(contributors) > MAX_ROWS:
            raise DangerousPathwaySecurityUnavailable(
                "evidence contributor inventory exceeds capacity")

    add("SOURCE_INVENTORY", {"singleton": "source_inventory"}, None,
        expected_digest=assessment["source_inventory_digest"])
    add("PACKAGE_INVENTORY", {"singleton": "package_inventory"}, None,
        expected_digest=assessment["package_inventory_digest"])
    for row in assessment["ordinary_polish"]:
        add("POLISH_TIER", {"tier": row["tier"]}, row)
    for pathway in assessment["pathways"]:
        pathway_id = pathway["pathway_id"]
        request = pathway["request"]
        add("PATHWAY_APPLICABILITY", {"pathway_id": pathway_id}, {
            "pathway_id": pathway_id,
            "request_digest": pathway["request_digest"],
            "applicability": pathway["applicability"],
            "applicability_evidence_digest": pathway[
                "applicability_evidence_digest"],
        })
        add("PATHWAY_VERDICT", {"pathway_id": pathway_id}, {
            "pathway_id": pathway_id,
            "request_digest": pathway["request_digest"],
            "operating_envelope_digest": pathway["operating_envelope_digest"],
            "verdict": pathway["verdict"],
            "trigger_witness_digest": pathway["trigger_witness_digest"],
        })
        selections = {item["check_id"]: item for item in request["required_checks"]}
        for result in pathway["required_check_results"]:
            add("CHECK_RESULT", {
                "pathway_id": pathway_id, "check_id": result["check_id"],
            }, {
                "pathway_id": pathway_id,
                "selection": selections[result["check_id"]],
                "result": result,
            })
        add("COUNTEREXAMPLE_SEARCH", {"pathway_id": pathway_id}, {
            "pathway_id": pathway_id,
            "request_digest": pathway["request_digest"],
            "counterexample_search_digest": pathway[
                "counterexample_search_digest"],
        })
        add("RESIDUAL_RISK", {"pathway_id": pathway_id}, {
            "pathway_id": pathway_id,
            "request_digest": pathway["request_digest"],
            "residual_risk_digest": pathway["residual_risk_digest"],
            "residual_risk_status": pathway["residual_risk_status"],
        })
    for row in assessment["review"]:
        key = {
            "reviewer_id_digest": row["reviewer_id_digest"],
            "review_digest": row["review_digest"],
        }
        add("REVIEWER_IDENTITY", key, {
            "reviewer_id_digest": row["reviewer_id_digest"],
            "role_digest": row["role_digest"],
        })
        add("REVIEWER_CONFLICT", key, {
            "reviewer_id_digest": row["reviewer_id_digest"],
            "role_digest": row["role_digest"],
            "mechanism_digest": row["mechanism_digest"],
            "conflict_check_digest": row["conflict_check_digest"],
            "conflict_status": row["conflict_status"],
        })
        add("REVIEW_RESULT", key, row)
    evidence = assessment["r2_evidence"]
    add("CAPABILITY_OBSERVATION", {"singleton": "capability"}, {
        "capability_inventory_digest": assessment["capability_inventory_digest"],
        "observation": evidence["capability_observation"],
    })
    add("CATALOG_COVERAGE", {"singleton": "catalog"}, {
        "catalog_manifest": assessment["catalog_manifest"],
        "coverage": evidence["catalog_coverage"],
    })
    add("OPERATING_ENVELOPE", {"singleton": "operating_envelope"}, {
        "operating_envelope_digest": assessment["operating_envelope_digest"],
        "coverage": evidence["operating_envelope"],
    })
    for row in assessment["interactions"]:
        add("INTERACTION", {"interaction_id": row["interaction_id"]}, row)
    add("COMPOSITION_COVERAGE", {"singleton": "composition"}, {
        "components": assessment["components"],
        "interactions": assessment["interactions"],
        "coverage": evidence["composition_coverage"],
    })
    for row in assessment["invalidators"]:
        add("INVALIDATOR", {"invalidator_id": row["invalidator_id"]}, row)
    add("INVALIDATOR_COVERAGE", {"singleton": "invalidators"}, {
        "invalidators": assessment["invalidators"],
        "coverage": evidence["invalidator_coverage"],
    })
    return contributors


# No eligibility-contributing external evidence dialect is installed yet. A
# fixed slot exists for every kind above, but absence is replayed as UNKNOWN;
# producer-authored status strings are never an oracle.
_INSTALLED_EVIDENCE_REPLAYER_IDS: frozenset[str] = frozenset()


def _replay_evidence_artifact(replayer_id: str, artifact_bytes: bytes) -> str:
    if replayer_id not in _INSTALLED_EVIDENCE_REPLAYER_IDS:
        return "UNKNOWN"
    # A future installed ID must add a fixed branch here; artifact bytes never
    # select code and a manifest cannot extend this closed set.
    raise DangerousPathwaySecurityError(
        "installed evidence replayer has no fixed implementation")


def _evidence_artifact_manifest(value: Any, *,
        assessment: Mapping[str, Any],
        evidence_artifacts: Mapping[str, bytes] | None) -> tuple[
            list[dict[str, Any]], bool]:
    if type(value) is not list or len(value) > MAX_ROWS:
        raise DangerousPathwaySecurityUnavailable(
            "evidence artifact manifest exceeds capacity")
    if evidence_artifacts is None:
        artifacts: dict[str, bytes] = {}
    elif (type(evidence_artifacts) is not dict
          or any(type(key) is not str or type(raw) is not bytes
                 for key, raw in evidence_artifacts.items())
          or len(evidence_artifacts) > MAX_ROWS):
        raise DangerousPathwaySecurityError(
            "evidence artifacts must be a bounded exact-byte mapping")
    else:
        artifacts = dict(evidence_artifacts)

    contributors = _evidence_contributors(assessment)
    rows = []
    replay_statuses: dict[str, str] = {}
    total_bytes = 0
    for item in value:
        row = _record(
            item, _EVIDENCE_ARTIFACT_REFERENCE_FIELDS,
            "evidence artifact reference")
        if row["schema_version"] != EVIDENCE_REFERENCE_VERSION:
            raise DangerousPathwaySecurityError(
                "evidence artifact reference version differs")
        contributor_id = _text(
            row["contributor_id"], "evidence contributor identifier")
        if row["contributor_kind"] not in _EVIDENCE_CONTRIBUTOR_KINDS:
            raise DangerousPathwaySecurityError(
                "evidence contributor kind differs")
        expected = contributors.get(contributor_id)
        if (expected is None
                or row["contributor_kind"] != expected["kind"]
                or row["replayer_id"] != expected["replayer_id"]):
            raise DangerousPathwaySecurityError(
                "evidence contributor or fixed replayer is unresolved")
        _text(row["replayer_id"], "evidence replayer identifier")
        artifact_digest = _hash(
            row["artifact_digest"], "evidence artifact digest")
        expected_artifact_id = "urn:sha256:" + artifact_digest.removeprefix(
            "sha256:")
        if row["artifact_id"] != expected_artifact_id:
            raise DangerousPathwaySecurityError(
                "evidence artifact immutable identifier differs")
        expected_bytes = expected["expected_bytes"]
        expected_digest = expected["expected_digest"]
        if expected_bytes is not None:
            expected_digest = "sha256:" + hashlib.sha256(expected_bytes).hexdigest()
        if expected_digest is not None and artifact_digest != expected_digest:
            raise DangerousPathwaySecurityError(
                "evidence artifact digest differs from contributor")
        raw = artifacts.get(row["artifact_id"])
        if raw is None:
            replay_statuses[contributor_id] = "UNKNOWN"
        else:
            total_bytes += len(raw)
            if len(raw) > MAX_ASSESSMENT_BYTES or total_bytes > MAX_ASSESSMENT_BYTES:
                raise DangerousPathwaySecurityUnavailable(
                    "evidence artifact bytes exceed capacity")
            actual_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            if actual_digest != artifact_digest:
                raise DangerousPathwaySecurityError(
                    "evidence artifact bytes differ from digest")
            if expected_bytes is not None:
                if raw != expected_bytes:
                    raise DangerousPathwaySecurityError(
                        "evidence artifact bytes differ from contributor")
            else:
                _decode(raw, MAX_ASSESSMENT_BYTES, "evidence artifact")
            replay_statuses[contributor_id] = _replay_evidence_artifact(
                row["replayer_id"], raw)
        rows.append(row)

    identifiers = [row["contributor_id"] for row in rows]
    if identifiers != sorted(set(identifiers)):
        raise DangerousPathwaySecurityError(
            "evidence artifact references must be sorted and unique")
    referenced_artifact_ids = {row["artifact_id"] for row in rows}
    if not set(artifacts) <= referenced_artifact_ids:
        raise DangerousPathwaySecurityError(
            "unreferenced evidence artifact bytes are not admitted")
    complete = (
        set(identifiers) == set(contributors)
        and all(replay_statuses.get(identifier) == "PASS"
                for identifier in contributors)
    )
    return rows, complete


def _assessment(value: Any) -> dict[str, Any]:
    assessment = _record(value, _ASSESSMENT_FIELDS, "assessment")
    if assessment["schema_version"] != ASSESSMENT_VERSION:
        raise DangerousPathwaySecurityError("assessment version differs")
    for field in (
        "artifact_digest", "derived_surface_digest", "source_coordinate_digest",
        "dependency_inventory_digest", "namespace_digest", "polish_receipt_digest",
        "risk_policy_digest", "threat_catalog_digest", "operating_envelope_digest",
        "capability_inventory_digest", "pathway_search_scope_digest",
        "reviewer_policy_digest", "invalidator_policy_digest",
    ):
        _hash(assessment[field], field)
    _text(assessment["threat_catalog_version"], "threat catalog version")
    assessment["ordinary_polish"] = _ordinary_polish(
        assessment["ordinary_polish"], assessment["polish_receipt_digest"])
    try:
        assessment["object_kind"] = ObjectKind(assessment["object_kind"]).value
    except (TypeError, ValueError) as exc:
        raise DangerousPathwaySecurityError("assessment object kind is not admitted") from exc
    assessment["catalog_entry_digests"] = _digest_list(
        assessment["catalog_entry_digests"], "catalog entry", MAX_ROWS, allow_empty=False)
    if type(assessment["pathways"]) is not list or len(assessment["pathways"]) > MAX_ROWS:
        raise DangerousPathwaySecurityError("pathway inventory exceeds bounds")
    pathways = []
    for value in assessment["pathways"]:
        row = _record(value, _CERTIFICATE_FIELDS, "pathway certificate")
        if row["schema_version"] != CERTIFICATE_VERSION:
            raise DangerousPathwaySecurityError("pathway certificate version differs")
        selected_request = _request(row["request"])
        row = _certificate(row, selected_request)
        for field in (
            "artifact_digest", "derived_surface_digest", "source_coordinate_digest",
            "dependency_inventory_digest", "object_kind", "risk_policy_digest",
            "threat_catalog_digest", "threat_catalog_version",
            "pathway_search_scope_digest", "operating_envelope_digest",
            "capability_inventory_digest", "reviewer_policy_digest",
            "invalidator_policy_digest",
        ):
            expected = assessment[field]
            if row[field] != expected:
                raise DangerousPathwaySecurityError("pathway assessment binding differs")
        if (row["status"] not in {"PASS", "FAIL", "UNKNOWN"}
                or row["security_outcome"] not in SECURITY_OUTCOMES
                or row["applicability"] not in APPLICABILITY or row["verdict"] not in VERDICTS
                or row["claim_boundary"] != CLAIM_BOUNDARY):
            raise DangerousPathwaySecurityError("pathway result semantics differ")
        pathways.append(row)
    catalog = [row["catalog_entry_digest"] for row in pathways]
    if catalog != assessment["catalog_entry_digests"]:
        raise DangerousPathwaySecurityError("pathway catalog coverage differs")
    assessment["pathways"] = pathways
    assessment["components"] = _component_rows(assessment["components"])
    assessment["interactions"] = _interaction_rows(
        assessment["interactions"], assessment["components"])
    assessment["predecessor"] = _predecessor(assessment["predecessor"])
    assessment["review"] = _reviews(assessment["review"], 64)
    assessment["invalidators"] = _invalidator_rows(assessment["invalidators"])
    assessment["r2_evidence"] = _r2_evidence(assessment["r2_evidence"], assessment)
    aggregate = _record(assessment["aggregate"], {
        "risk_class", "assurance_level", "security_outcome",
        "maximum_release_scope", "publication_authority", "security_tier",
        "security_tier_name", "security_tier_status",
    }, "aggregate")
    if (aggregate["risk_class"] not in RISK_CLASSES
            or aggregate["assurance_level"] not in ASSURANCE_LEVELS
            or aggregate["security_outcome"] not in SECURITY_OUTCOMES
            or aggregate["maximum_release_scope"] not in RELEASE_SCOPES
            or aggregate["security_tier"] != 9
            or aggregate["security_tier_name"] != "SECURITY"
            or aggregate["security_tier_status"] not in {"PASS", "FAIL", "UNKNOWN"}
            or aggregate["publication_authority"] != "NOT_ESTABLISHED"):
        raise DangerousPathwaySecurityError("aggregate semantics differ")

    mechanics = "PASS"
    if any(row["status"] == "FAIL" for row in pathways):
        mechanics = "FAIL"
    elif (any(row["status"] != "PASS" for row in pathways)
          or any(row["amplification_status"] in {"UNKNOWN", "NOT_ESTABLISHED"}
                 for row in assessment["interactions"])
          or any(row["status"] != "CLEARED" for row in assessment["invalidators"])
          or not _has_full_composition_interaction(
              assessment["components"], assessment["interactions"])):
        mechanics = "UNKNOWN"

    present = (any(row["verdict"] == "PRESENT"
                   or row["security_outcome"] == "FAIL" for row in pathways)
               or any(row["amplification_status"] == "FAIL"
                      for row in assessment["interactions"]))
    if present and (aggregate["risk_class"] != "R3"
                    or aggregate["maximum_release_scope"] != "DENY"
                    or aggregate["security_outcome"] != "FAIL"):
        raise DangerousPathwaySecurityError("present pathway requires R3 denial")
    predecessor = assessment["predecessor"]
    same_r3 = (predecessor["risk_class"] == "R3"
               and (predecessor["artifact_digest"] == assessment["artifact_digest"]
                    or predecessor["derived_surface_digest"] == assessment["derived_surface_digest"]))
    if same_r3 and (aggregate["risk_class"] != "R3"
                    or aggregate["maximum_release_scope"] != "DENY"):
        raise DangerousPathwaySecurityError("R3 cannot be downgraded in place")
    order = {"R2_PENDING": 0, "R2": 1, "R3": 2}
    component_floor = max((order[row["risk_class"]] for row in assessment["components"]), default=0)
    if order[aggregate["risk_class"]] < component_floor:
        raise DangerousPathwaySecurityError("composition cannot lower component risk")
    capability = assessment["r2_evidence"]["capability_observation"]
    if order[aggregate["risk_class"]] < order[capability["risk_floor"]]:
        raise DangerousPathwaySecurityError(
            "risk class is below observed capability and tooling floor")

    cleared = all(
        row["security_outcome"] == "ESTABLISHED"
        and row["residual_risk_status"] == "PASS"
        and (row["applicability"] == "PROVED_NOT_APPLICABLE"
             or row["verdict"] in {"REFUTED_WITHIN_ENVELOPE", "CAPABILITY_REMOVED"})
        for row in pathways
    )
    sec3 = (aggregate["assurance_level"] in {
        "SEC3_INDEPENDENTLY_REFUTED", "SEC4_CONTINUOUSLY_GOVERNED"}
        and _independent_review(assessment["review"]))
    evidence = assessment["r2_evidence"]
    exact_r2_evidence = (
        all(row["status"] == "PASS" for row in assessment["ordinary_polish"])
        and capability["status"] == "PASS"
        and capability["generalizable_tooling"] != "UNKNOWN"
        and evidence["catalog_coverage"]["status"] == "PASS"
        and evidence["operating_envelope"]["status"] == "PASS"
        and evidence["invalidator_coverage"]["status"] == "PASS"
        and evidence["composition_coverage"]["status"] == "PASS")
    if aggregate["risk_class"] == "R2":
        if not (mechanics == "PASS" and cleared and sec3
                and exact_r2_evidence and not present):
            raise DangerousPathwaySecurityError("R2 requires independent bounded refutation")
        expected_security = "ESTABLISHED"
        expected_tier_status = "PASS"
    elif aggregate["risk_class"] == "R3":
        expected_security = "FAIL" if present or same_r3 else "NOT_ESTABLISHED"
        expected_tier_status = "FAIL" if expected_security == "FAIL" else "UNKNOWN"
        if aggregate["maximum_release_scope"] != "DENY":
            raise DangerousPathwaySecurityError("R3 is never releasable")
    else:
        expected_security = "UNKNOWN"
        expected_tier_status = "UNKNOWN"
        if aggregate["maximum_release_scope"] != "DENY":
            raise DangerousPathwaySecurityError("pending risk is denied")
    if aggregate["security_outcome"] != expected_security:
        raise DangerousPathwaySecurityError("aggregate security outcome differs")
    if aggregate["security_tier_status"] != expected_tier_status:
        raise DangerousPathwaySecurityError("security tier status differs")
    if assessment["status"] != mechanics:
        raise DangerousPathwaySecurityError("assessment mechanical status differs")
    if assessment["claim_boundary"] != CLAIM_BOUNDARY:
        raise DangerousPathwaySecurityError("assessment claim boundary differs")
    if assessment["assessment_digest"] != _digest_without(assessment, "assessment_digest"):
        raise DangerousPathwaySecurityError("assessment digest differs")
    return assessment


def _aggregate_legacy_dangerous_pathway_assessment_record(*, artifact_digest: str,
        derived_surface_digest: str, source_coordinate_digest: str,
        dependency_inventory_digest: str, object_kind: str, namespace_digest: str,
        polish_receipt_digest: str, ordinary_polish: Sequence[Mapping[str, Any]],
        risk_policy_digest: str, threat_catalog_digest: str,
        threat_catalog_version: str, pathway_search_scope_digest: str,
        operating_envelope_digest: str, reviewer_policy_digest: str,
        invalidator_policy_digest: str,
        capability_inventory_digest: str, pathways: Sequence[Mapping[str, Any]],
        components: Sequence[Mapping[str, Any]], interactions: Sequence[Mapping[str, Any]],
        predecessor: Mapping[str, Any], r2_evidence: Mapping[str, Any],
        risk_class: str, assurance_level: str,
        maximum_release_scope: str, review: Sequence[Mapping[str, Any]],
        invalidators: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Build the retained v1 record used only for exact legacy replay."""
    selected_pathways = [dict(row) for row in pathways]
    mechanics = "PASS"
    if any(row.get("status") == "FAIL" for row in selected_pathways):
        mechanics = "FAIL"
    elif (any(row.get("status") != "PASS" for row in selected_pathways)
          or any(row.get("amplification_status") in {"UNKNOWN", "NOT_ESTABLISHED"}
                 for row in interactions)
          or any(row.get("status") != "CLEARED" for row in invalidators)
          or not _has_full_composition_interaction(components, interactions)):
        mechanics = "UNKNOWN"
    present = (any(row.get("verdict") == "PRESENT"
                   or row.get("security_outcome") == "FAIL" for row in selected_pathways)
               or any(row.get("amplification_status") == "FAIL" for row in interactions))
    predecessor_row = dict(predecessor)
    same_r3 = (predecessor_row.get("risk_class") == "R3"
               and (predecessor_row.get("artifact_digest") == artifact_digest
                    or predecessor_row.get("derived_surface_digest") == derived_surface_digest))
    if risk_class == "R2":
        security = "ESTABLISHED"
        tier_status = "PASS"
    elif risk_class == "R3":
        security = "FAIL" if present or same_r3 else "NOT_ESTABLISHED"
        tier_status = "FAIL" if security == "FAIL" else "UNKNOWN"
    else:
        security = "UNKNOWN"
        tier_status = "UNKNOWN"
    assessment = {
        "schema_version": ASSESSMENT_VERSION,
        "artifact_digest": artifact_digest,
        "derived_surface_digest": derived_surface_digest,
        "source_coordinate_digest": source_coordinate_digest,
        "dependency_inventory_digest": dependency_inventory_digest,
        "object_kind": object_kind,
        "namespace_digest": namespace_digest,
        "polish_receipt_digest": polish_receipt_digest,
        "ordinary_polish": [dict(row) for row in ordinary_polish],
        "risk_policy_digest": risk_policy_digest,
        "threat_catalog_digest": threat_catalog_digest,
        "threat_catalog_version": threat_catalog_version,
        "pathway_search_scope_digest": pathway_search_scope_digest,
        "operating_envelope_digest": operating_envelope_digest,
        "reviewer_policy_digest": reviewer_policy_digest,
        "invalidator_policy_digest": invalidator_policy_digest,
        "capability_inventory_digest": capability_inventory_digest,
        "catalog_entry_digests": [row["catalog_entry_digest"] for row in selected_pathways],
        "pathways": selected_pathways,
        "components": [dict(row) for row in components],
        "interactions": [dict(row) for row in interactions],
        "predecessor": predecessor_row,
        "r2_evidence": dict(r2_evidence),
        "aggregate": {"risk_class": risk_class, "assurance_level": assurance_level,
                      "security_outcome": security,
                      "maximum_release_scope": maximum_release_scope,
                      "security_tier": 9, "security_tier_name": "SECURITY",
                      "security_tier_status": tier_status,
                      "publication_authority": "NOT_ESTABLISHED"},
        "review": [dict(row) for row in review],
        "invalidators": [dict(row) for row in invalidators],
        "status": mechanics,
        "claim_boundary": CLAIM_BOUNDARY,
        "assessment_digest": "",
    }
    assessment["assessment_digest"] = _digest_without(assessment, "assessment_digest")
    return _assessment(assessment)


def aggregate_dangerous_pathway_assessment(**kwargs: Any) -> dict[str, Any]:
    """Return an explicit DENY decision for the retired v1 aggregate dialect.

    The former constructor could mint a fresh record whose internal aggregate said
    ``ESTABLISHED``.  V1 has no exact predecessor replay and is no longer a
    qualification surface, so the exported boundary returns only its replayed
    legacy-unqualified decision.  The private record constructor remains solely so
    retained v1 bytes can be exercised by compatibility tests.
    """
    record = _aggregate_legacy_dangerous_pathway_assessment_record(**kwargs)
    return recheck_dangerous_pathway_assessment(canonical_bytes(record))


def _catalog_manifest(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list or not value or len(value) > MAX_ROWS:
        raise DangerousPathwaySecurityError(
            "catalog manifest must be a bounded nonempty inventory")
    rows = []
    for item in value:
        row = _record(item, _CATALOG_MANIFEST_ENTRY_FIELDS, "catalog manifest entry")
        _text(row["pathway_id"], "catalog pathway identifier")
        _hash(row["catalog_entry_digest"], "catalog entry digest")
        if row["severity"] not in SEVERITIES:
            raise DangerousPathwaySecurityError("catalog manifest severity differs")
        rows.append(row)
    keys = [(row["pathway_id"], row["catalog_entry_digest"], row["severity"])
            for row in rows]
    if keys != sorted(keys):
        raise DangerousPathwaySecurityError("catalog manifest must be sorted")
    identifiers = [row["pathway_id"] for row in rows]
    digests = [row["catalog_entry_digest"] for row in rows]
    if len(set(identifiers)) != len(rows) or len(set(digests)) != len(rows):
        raise DangerousPathwaySecurityError(
            "catalog manifest identifiers and digests must be unique")
    return rows


def _assessment_scope_payload(assessment: Mapping[str, Any]) -> dict[str, Any]:
    """Return the static subject, catalog, and composition selection for v2.

    Results, reviewers, invalidators, assurance, risk classification, and evidence
    receipts are intentionally excluded. A change to subject identity, selected
    catalog, or composition topology starts a new assessment scope.
    """
    fields = (
        "mechanism_digest", "artifact_digest", "derived_surface_digest",
        "source_coordinate_digest", "dependency_inventory_digest",
        "source_inventory_digest", "package_inventory_digest",
        "object_kind", "namespace_digest",
        "risk_policy_digest", "threat_catalog_digest", "threat_catalog_version",
        "pathway_search_scope_digest", "operating_envelope_digest",
        "reviewer_policy_digest", "invalidator_policy_digest",
        "capability_inventory_digest",
    )
    return {
        "schema_version": "claim-garden-dangerous-pathway-assessment-scope-1",
        **{field: assessment[field] for field in fields},
        "catalog_manifest": [dict(row) for row in assessment["catalog_manifest"]],
        "components": [
            {"component_id": row["component_id"], "digest": row["digest"]}
            for row in assessment["components"]
        ],
        "interaction_topology": [
            {"interaction_id": row["interaction_id"],
             "component_ids": list(row["component_ids"])}
            for row in assessment["interactions"]
        ],
    }


def assessment_scope_digest(assessment: Mapping[str, Any]) -> str:
    """Derive the v2 static scope; never accept a caller-declared scope digest."""
    return _digest_value(_assessment_scope_payload(assessment))


def _predecessor_replay_digests(
        predecessor: Mapping[str, Any] | None) -> tuple[str | None, str | None]:
    if predecessor is None:
        return None, None
    assessment_digest = _hash(
        predecessor.get("assessment_digest"), "predecessor assessment digest")
    exact_bytes_digest = "sha256:" + hashlib.sha256(
        canonical_bytes(predecessor)).hexdigest()
    replay_digest = _digest_value({
        "schema_version": "claim-garden-dangerous-pathway-predecessor-replay-1",
        "predecessor_assessment_digest": assessment_digest,
        "predecessor_exact_bytes_digest": exact_bytes_digest,
        "replay_status": "REPRODUCED",
    })
    return assessment_digest, replay_digest


def _assessment_v2(value: Any, *, predecessor_depth: int = 0,
        evidence_artifacts: Mapping[str, bytes] | None = None) -> dict[str, Any]:
    if predecessor_depth > MAX_PREDECESSOR_DEPTH:
        raise DangerousPathwaySecurityUnavailable(
            "predecessor assessment chain exceeds capacity")
    assessment = _record(value, _ASSESSMENT_V2_FIELDS, "assessment v2")
    if assessment["schema_version"] != ASSESSMENT_V2_VERSION:
        raise DangerousPathwaySecurityError("assessment v2 version differs")
    for field in (
        "mechanism_digest", "artifact_digest", "derived_surface_digest",
        "source_coordinate_digest",
        "dependency_inventory_digest", "source_inventory_digest",
        "package_inventory_digest", "namespace_digest", "assessment_scope_digest",
        "polish_receipt_digest", "risk_policy_digest", "threat_catalog_digest",
        "pathway_search_scope_digest", "operating_envelope_digest",
        "capability_inventory_digest", "reviewer_policy_digest",
        "invalidator_policy_digest",
    ):
        _hash(assessment[field], field)
    if assessment["mechanism_digest"] != mechanism_digest():
        raise DangerousPathwaySecurityError(
            "assessment v2 mechanism differs from installed source")
    _text(assessment["threat_catalog_version"], "threat catalog version")
    try:
        assessment["object_kind"] = ObjectKind(assessment["object_kind"]).value
    except (TypeError, ValueError) as exc:
        raise DangerousPathwaySecurityError(
            "assessment v2 object kind is not admitted") from exc
    assessment["ordinary_polish"] = _ordinary_polish(
        assessment["ordinary_polish"], assessment["polish_receipt_digest"])
    assessment["catalog_manifest"] = _catalog_manifest(assessment["catalog_manifest"])
    if assessment["threat_catalog_digest"] != _digest_value(
            assessment["catalog_manifest"]):
        raise DangerousPathwaySecurityError(
            "threat catalog digest differs from exact catalog manifest")

    if type(assessment["pathways"]) is not list or len(assessment["pathways"]) > MAX_ROWS:
        raise DangerousPathwaySecurityError("pathway inventory exceeds bounds")
    manifest = {row["pathway_id"]: row for row in assessment["catalog_manifest"]}
    pathways = []
    for value in assessment["pathways"]:
        row = _record(value, _CERTIFICATE_FIELDS, "pathway certificate")
        if row["schema_version"] != CERTIFICATE_VERSION:
            raise DangerousPathwaySecurityError("pathway certificate version differs")
        selected_request = _request(row["request"])
        row = _certificate(row, selected_request)
        for field in (
            "artifact_digest", "derived_surface_digest", "source_coordinate_digest",
            "dependency_inventory_digest", "object_kind", "risk_policy_digest",
            "threat_catalog_digest", "threat_catalog_version",
            "pathway_search_scope_digest", "operating_envelope_digest",
            "capability_inventory_digest", "reviewer_policy_digest",
            "invalidator_policy_digest",
        ):
            if row[field] != assessment[field]:
                raise DangerousPathwaySecurityError("pathway assessment binding differs")
        expected = manifest.get(row["pathway_id"])
        if (expected is None
                or row["catalog_entry_digest"] != expected["catalog_entry_digest"]
                or row["severity"] != expected["severity"]):
            raise DangerousPathwaySecurityError(
                "pathway certificate differs from exact catalog manifest")
        pathways.append(row)
    pathway_ids = [row["pathway_id"] for row in pathways]
    if pathway_ids != sorted(set(pathway_ids)):
        raise DangerousPathwaySecurityError(
            "pathway certificates must be sorted and unique")
    required = {row["pathway_id"] for row in assessment["catalog_manifest"]
                if row["severity"] in {"HIGH", "CRITICAL"}}
    if not required <= set(pathway_ids):
        raise DangerousPathwaySecurityError(
            "every HIGH or CRITICAL catalog entry requires a matching certificate")
    assessment["pathways"] = pathways
    assessment["components"] = _component_rows(assessment["components"])
    assessment["interactions"] = _interaction_rows(
        assessment["interactions"], assessment["components"])
    derived_scope = assessment_scope_digest(assessment)
    if assessment["assessment_scope_digest"] != derived_scope:
        raise DangerousPathwaySecurityError("assessment scope digest differs")

    predecessor_value = assessment["predecessor_assessment"]
    if predecessor_value is None:
        predecessor = None
    else:
        predecessor = _assessment_v2(
            predecessor_value, predecessor_depth=predecessor_depth + 1)
        if canonical_bytes(predecessor) != canonical_bytes(predecessor_value):
            raise DangerousPathwaySecurityError(
                "predecessor assessment canonical replay differs")
    assessment["predecessor_assessment"] = predecessor
    predecessor_assessment_digest = _nullable_hash(
        assessment["predecessor_assessment_digest"],
        "predecessor assessment digest")
    predecessor_replay_digest = _nullable_hash(
        assessment["predecessor_replay_digest"], "predecessor replay digest")
    expected_assessment_digest, expected_replay_digest = _predecessor_replay_digests(
        predecessor)
    if (predecessor_assessment_digest != expected_assessment_digest
            or predecessor_replay_digest != expected_replay_digest):
        raise DangerousPathwaySecurityError(
            "predecessor replay digest binding differs")
    assessment["review"] = _reviews(assessment["review"], 64)
    assessment["invalidators"] = _invalidator_rows(assessment["invalidators"])
    catalog_digests = [row["catalog_entry_digest"]
                       for row in assessment["catalog_manifest"]]
    evidence_subject = dict(assessment)
    evidence_subject["catalog_entry_digests"] = catalog_digests
    assessment["r2_evidence"] = _r2_evidence(
        assessment["r2_evidence"], evidence_subject)
    assessment["evidence_artifact_manifest"], _native_evidence_complete = (
        _evidence_artifact_manifest(
            assessment["evidence_artifact_manifest"],
            assessment=assessment,
            evidence_artifacts=evidence_artifacts,
        )
    )

    aggregate = _record(assessment["aggregate"], {
        "risk_class", "assurance_level", "security_outcome",
        "security_eligibility",
        "maximum_release_scope", "publication_authority", "catalog_authority",
        "assessment_time_authority", "reviewer_authority", "security_tier",
        "security_tier_name", "security_tier_status",
    }, "aggregate v2")
    if (aggregate["risk_class"] not in RISK_CLASSES
            or aggregate["assurance_level"] not in ASSURANCE_LEVELS
            or aggregate["security_outcome"] not in SECURITY_OUTCOMES
            or aggregate["security_eligibility"] not in SECURITY_ELIGIBILITY_STATES
            or aggregate["maximum_release_scope"] not in RELEASE_SCOPES
            or aggregate["security_tier"] != 9
            or aggregate["security_tier_name"] != "SECURITY"
            or aggregate["security_tier_status"] not in {"PASS", "FAIL", "UNKNOWN"}
            or aggregate["publication_authority"] != "NOT_ESTABLISHED"
            or aggregate["catalog_authority"] != "UNKNOWN"
            or aggregate["assessment_time_authority"] != "UNKNOWN"
            or aggregate["reviewer_authority"] != "NOT_ESTABLISHED"):
        raise DangerousPathwaySecurityError("aggregate v2 semantics differ")

    mechanics = "PASS"
    if any(row["status"] == "FAIL" for row in pathways):
        mechanics = "FAIL"
    elif (any(row["status"] != "PASS" for row in pathways)
          or any(row["amplification_status"] in {"UNKNOWN", "NOT_ESTABLISHED"}
                 for row in assessment["interactions"])
          or any(row["status"] != "CLEARED" for row in assessment["invalidators"])
          or not _has_full_composition_interaction(
              assessment["components"], assessment["interactions"])):
        mechanics = "UNKNOWN"
    present = (any(row["verdict"] == "PRESENT"
                   or row["security_outcome"] == "FAIL" for row in pathways)
               or any(row["amplification_status"] == "FAIL"
                      for row in assessment["interactions"]))

    current_risk = aggregate["risk_class"]
    if predecessor is None:
        if current_risk != "R2_PENDING":
            raise DangerousPathwaySecurityError(
                "initial assessment must be R2_PENDING")
    elif predecessor["assessment_scope_digest"] != derived_scope:
        if current_risk != "R2_PENDING":
            raise DangerousPathwaySecurityError(
                "scope change must restart at R2_PENDING")
    else:
        previous_risk = predecessor["aggregate"]["risk_class"]
        transitions = {
            "R2_PENDING": {"R2_PENDING", "R2", "R3"},
            "R2": {"R2", "R3"},
            "R3": {"R3"},
        }
        if current_risk not in transitions[previous_risk]:
            raise DangerousPathwaySecurityError(
                "same-scope risk transition is not monotone")

    order = {"R2_PENDING": 0, "R2": 1, "R3": 2}
    capability = assessment["r2_evidence"]["capability_observation"]
    component_floor = max(
        (order[row["risk_class"]] for row in assessment["components"]), default=0)
    if current_risk != "R2_PENDING" and order[current_risk] < component_floor:
        raise DangerousPathwaySecurityError("composition cannot lower component risk")
    if (current_risk != "R2_PENDING"
            and order[current_risk] < order[capability["risk_floor"]]):
        raise DangerousPathwaySecurityError(
            "risk class is below observed capability and tooling floor")

    if current_risk == "R2":
        if present or mechanics == "FAIL":
            raise DangerousPathwaySecurityError(
                "R2 requires independent bounded refutation")
        expected_security = "UNKNOWN"
        expected_tier_status = "UNKNOWN"
        if aggregate["maximum_release_scope"] != "DENY":
            raise DangerousPathwaySecurityError(
                "unreplayed R2 evidence is denied")
    elif current_risk == "R3":
        expected_security = "FAIL" if present else "NOT_ESTABLISHED"
        expected_tier_status = "FAIL" if expected_security == "FAIL" else "UNKNOWN"
        if aggregate["maximum_release_scope"] != "DENY":
            raise DangerousPathwaySecurityError("R3 is never releasable")
    else:
        expected_security = "UNKNOWN"
        expected_tier_status = "UNKNOWN"
        if aggregate["maximum_release_scope"] != "DENY":
            raise DangerousPathwaySecurityError("pending risk is denied")
    if aggregate["security_outcome"] != expected_security:
        raise DangerousPathwaySecurityError("aggregate v2 security outcome differs")
    expected_eligibility = (
        "ELIGIBLE_FOR_SEPARATE_PUBLICATION_AUTHORIZATION"
        if current_risk == "R2" and expected_security == "ESTABLISHED"
        else "DENY")
    if aggregate["security_eligibility"] != expected_eligibility:
        raise DangerousPathwaySecurityError("aggregate v2 security eligibility differs")
    if aggregate["security_tier_status"] != expected_tier_status:
        raise DangerousPathwaySecurityError("aggregate v2 security tier status differs")
    if assessment["status"] != mechanics:
        raise DangerousPathwaySecurityError("assessment v2 mechanical status differs")
    if assessment["claim_boundary"] != CLAIM_BOUNDARY:
        raise DangerousPathwaySecurityError("assessment v2 claim boundary differs")
    if assessment["assessment_digest"] != _digest_without(
            assessment, "assessment_digest"):
        raise DangerousPathwaySecurityError("assessment v2 digest differs")
    return assessment


def aggregate_dangerous_pathway_assessment_v2(*, artifact_digest: str,
        derived_surface_digest: str, source_coordinate_digest: str,
        dependency_inventory_digest: str, source_inventory_digest: str,
        package_inventory_digest: str, object_kind: str, namespace_digest: str,
        polish_receipt_digest: str, ordinary_polish: Sequence[Mapping[str, Any]],
        risk_policy_digest: str, threat_catalog_digest: str,
        threat_catalog_version: str, pathway_search_scope_digest: str,
        operating_envelope_digest: str, reviewer_policy_digest: str,
        invalidator_policy_digest: str, capability_inventory_digest: str,
        catalog_manifest: Sequence[Mapping[str, Any]],
        pathways: Sequence[Mapping[str, Any]], components: Sequence[Mapping[str, Any]],
        interactions: Sequence[Mapping[str, Any]],
        predecessor_assessment_bytes: bytes | None,
        r2_evidence: Mapping[str, Any], risk_class: str, assurance_level: str,
        maximum_release_scope: str, review: Sequence[Mapping[str, Any]],
        invalidators: Sequence[Mapping[str, Any]],
        evidence_artifact_manifest: Sequence[Mapping[str, Any]] = (),
        evidence_artifacts: Mapping[str, bytes] | None = None) -> dict[str, Any]:
    """Build v2 from an exact prior assessment, never a claimed prior digest/status."""
    predecessor = None
    if predecessor_assessment_bytes is not None:
        predecessor = _assessment_v2(_decode(
            predecessor_assessment_bytes, MAX_ASSESSMENT_BYTES,
            "predecessor assessment"))
    predecessor_assessment_digest, predecessor_replay_digest = (
        _predecessor_replay_digests(predecessor))
    selected_pathways = [dict(row) for row in pathways]
    selected_components = [dict(row) for row in components]
    selected_interactions = [dict(row) for row in interactions]
    selected_invalidators = [dict(row) for row in invalidators]
    mechanics = "PASS"
    if any(row.get("status") == "FAIL" for row in selected_pathways):
        mechanics = "FAIL"
    elif (any(row.get("status") != "PASS" for row in selected_pathways)
          or any(row.get("amplification_status") in {"UNKNOWN", "NOT_ESTABLISHED"}
                 for row in selected_interactions)
          or any(row.get("status") != "CLEARED" for row in selected_invalidators)
          or not _has_full_composition_interaction(
              selected_components, selected_interactions)):
        mechanics = "UNKNOWN"
    present = (any(row.get("verdict") == "PRESENT"
                   or row.get("security_outcome") == "FAIL"
                   for row in selected_pathways)
               or any(row.get("amplification_status") == "FAIL"
                      for row in selected_interactions))
    if risk_class == "R2":
        security = "UNKNOWN"
        tier_status = "UNKNOWN"
    elif risk_class == "R3":
        security = "FAIL" if present else "NOT_ESTABLISHED"
        tier_status = "FAIL" if security == "FAIL" else "UNKNOWN"
    else:
        security = "UNKNOWN"
        tier_status = "UNKNOWN"
    assessment: dict[str, Any] = {
        "schema_version": ASSESSMENT_V2_VERSION,
        "mechanism_digest": mechanism_digest(),
        "artifact_digest": artifact_digest,
        "derived_surface_digest": derived_surface_digest,
        "source_coordinate_digest": source_coordinate_digest,
        "dependency_inventory_digest": dependency_inventory_digest,
        "source_inventory_digest": source_inventory_digest,
        "package_inventory_digest": package_inventory_digest,
        "object_kind": object_kind,
        "namespace_digest": namespace_digest,
        "assessment_scope_digest": "",
        "polish_receipt_digest": polish_receipt_digest,
        "ordinary_polish": [dict(row) for row in ordinary_polish],
        "risk_policy_digest": risk_policy_digest,
        "threat_catalog_digest": threat_catalog_digest,
        "threat_catalog_version": threat_catalog_version,
        "pathway_search_scope_digest": pathway_search_scope_digest,
        "operating_envelope_digest": operating_envelope_digest,
        "reviewer_policy_digest": reviewer_policy_digest,
        "invalidator_policy_digest": invalidator_policy_digest,
        "capability_inventory_digest": capability_inventory_digest,
        "catalog_manifest": [dict(row) for row in catalog_manifest],
        "pathways": selected_pathways,
        "components": selected_components,
        "interactions": selected_interactions,
        "predecessor_assessment": predecessor,
        "predecessor_assessment_digest": predecessor_assessment_digest,
        "predecessor_replay_digest": predecessor_replay_digest,
        "r2_evidence": dict(r2_evidence),
        "evidence_artifact_manifest": [
            dict(row) for row in evidence_artifact_manifest],
        "aggregate": {
            "risk_class": risk_class,
            "assurance_level": assurance_level,
            "security_outcome": security,
            "security_eligibility": (
                "ELIGIBLE_FOR_SEPARATE_PUBLICATION_AUTHORIZATION"
                if risk_class == "R2" and security == "ESTABLISHED" else "DENY"),
            "maximum_release_scope": maximum_release_scope,
            "security_tier": 9,
            "security_tier_name": "SECURITY",
            "security_tier_status": tier_status,
            "publication_authority": "NOT_ESTABLISHED",
            "catalog_authority": "UNKNOWN",
            "assessment_time_authority": "UNKNOWN",
            "reviewer_authority": "NOT_ESTABLISHED",
        },
        "review": [dict(row) for row in review],
        "invalidators": selected_invalidators,
        "status": mechanics,
        "claim_boundary": CLAIM_BOUNDARY,
        "assessment_digest": "",
    }
    assessment["assessment_scope_digest"] = assessment_scope_digest(assessment)
    assessment["assessment_digest"] = _digest_without(assessment, "assessment_digest")
    return _assessment_v2(assessment, evidence_artifacts=evidence_artifacts)


def recheck_dangerous_pathway_assessment_v2(assessment_bytes: bytes, *,
        predecessor_assessment_bytes: bytes | None = None,
        evidence_artifacts: Mapping[str, bytes] | None = None) -> dict[str, Any]:
    """Replay exact canonical v2 bytes and optionally bind the expected predecessor."""
    assessment = _assessment_v2(
        _decode(assessment_bytes, MAX_ASSESSMENT_BYTES, "assessment v2"),
        evidence_artifacts=evidence_artifacts)
    embedded = assessment["predecessor_assessment"]
    if predecessor_assessment_bytes is not None:
        expected = _assessment_v2(_decode(
            predecessor_assessment_bytes, MAX_ASSESSMENT_BYTES,
            "expected predecessor assessment"))
        if embedded is None or canonical_bytes(embedded) != canonical_bytes(expected):
            raise DangerousPathwaySecurityError(
                "expected predecessor assessment differs from embedded predecessor")
    return {
        "schema_version": "claim-garden-dangerous-pathway-assessment-replay-2",
        "replay_status": "REPRODUCED",
        "status": assessment["status"],
        "security_outcome": assessment["aggregate"]["security_outcome"],
        "security_eligibility": assessment["aggregate"]["security_eligibility"],
        "risk_class": assessment["aggregate"]["risk_class"],
        "assurance_level": assessment["aggregate"]["assurance_level"],
        "security_tier": assessment["aggregate"]["security_tier"],
        "security_tier_name": assessment["aggregate"]["security_tier_name"],
        "security_tier_status": assessment["aggregate"]["security_tier_status"],
        "maximum_release_scope": assessment["aggregate"]["maximum_release_scope"],
        "publication_authority": "NOT_ESTABLISHED",
        "catalog_authority": "UNKNOWN",
        "assessment_time_authority": "UNKNOWN",
        "reviewer_authority": "NOT_ESTABLISHED",
        "assessment_scope_digest": assessment["assessment_scope_digest"],
        "mechanism_digest": assessment["mechanism_digest"],
        "source_inventory_digest": assessment["source_inventory_digest"],
        "package_inventory_digest": assessment["package_inventory_digest"],
        "threat_catalog_digest": assessment["threat_catalog_digest"],
        "predecessor_assessment_digest": assessment[
            "predecessor_assessment_digest"],
        "predecessor_replay_digest": assessment["predecessor_replay_digest"],
        "evidence_artifact_reference_count": len(
            assessment["evidence_artifact_manifest"]),
        "eligibility_replayer_status": (
            "INSTALLED" if _INSTALLED_EVIDENCE_REPLAYER_IDS else "NOT_INSTALLED"),
        "assessment_digest": assessment["assessment_digest"],
        "claim_boundary": CLAIM_BOUNDARY,
    }


def recheck_dangerous_pathway_assessment(assessment_bytes: bytes, *,
        evidence_artifacts: Mapping[str, bytes] | None = None) -> dict[str, Any]:
    decoded = _decode(assessment_bytes, MAX_ASSESSMENT_BYTES, "assessment")
    if decoded.get("schema_version") == ASSESSMENT_V2_VERSION:
        return recheck_dangerous_pathway_assessment_v2(
            assessment_bytes, evidence_artifacts=evidence_artifacts)
    assessment = _assessment(decoded)
    return {
        "schema_version": "claim-garden-dangerous-pathway-assessment-replay-1",
        "replay_status": "REPRODUCED",
        "status": assessment["status"],
        "security_outcome": "NOT_ESTABLISHED",
        "recorded_security_outcome": assessment["aggregate"]["security_outcome"],
        "security_eligibility": "DENY",
        "qualification_status": "LEGACY_UNQUALIFIED",
        "revocation_reason": "R2_PREDECESSOR_REPLAY_NOT_ESTABLISHED",
        "risk_class": assessment["aggregate"]["risk_class"],
        "assurance_level": assessment["aggregate"]["assurance_level"],
        "security_tier": assessment["aggregate"]["security_tier"],
        "security_tier_name": assessment["aggregate"]["security_tier_name"],
        "security_tier_status": assessment["aggregate"]["security_tier_status"],
        "maximum_release_scope": assessment["aggregate"]["maximum_release_scope"],
        "publication_authority": "NOT_ESTABLISHED",
        "assessment_digest": assessment["assessment_digest"],
        "claim_boundary": CLAIM_BOUNDARY,
    }


def dangerous_pathway_catalog() -> dict[str, Any]:
    """Describe the installed mechanical dialect; select no host policy."""
    return {
        "schema_version": CATALOG_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "request_schema_version": REQUEST_VERSION,
        "certificate_schema_version": CERTIFICATE_VERSION,
        "assessment_schema_version": ASSESSMENT_V2_VERSION,
        "legacy_assessment_schema_version": ASSESSMENT_VERSION,
        "assessment_schema_versions": [ASSESSMENT_VERSION, ASSESSMENT_V2_VERSION],
        "legacy_assessment_security_eligibility": "DENY",
        "legacy_assessment_revocation_reason": (
            "R2_PREDECESSOR_REPLAY_NOT_ESTABLISHED"),
        "legacy_certificate_security_eligibility": "DENY",
        "legacy_certificate_revocation_reason": (
            "SELECTED_CHECK_SEMANTIC_REPLAY_NOT_ESTABLISHED"),
        "evidence_artifact_reference_version": EVIDENCE_REFERENCE_VERSION,
        "installed_eligibility_replayer_count": len(
            _INSTALLED_EVIDENCE_REPLAYER_IDS),
        "current_v2_security_eligibility": "DENY",
        "object_kinds": sorted(kind.value for kind in ObjectKind),
        "applicability": sorted(APPLICABILITY),
        "verdicts": sorted(VERDICTS),
        "risk_classes": ["R2_PENDING", "R2", "R3"],
        "risk_basis": "OBSERVED_CAPABILITY_AND_GENERALIZABLE_TOOLING_NOT_OBJECT_KIND",
        "known_pathway_scope": "PINNED_CATALOG_ONLY",
        "ordinary_polish_security_effect": "NECESSARY_FOR_R2_NOT_SECURITY_CLEARANCE",
        "commercial_priority_security_effect": "NONE",
        "publication_authority": "NOT_ESTABLISHED",
        "design_provenance_digest": DESIGN_PROVENANCE_SHA256,
        "design_provenance_authority": "DESIGN_ONLY",
        "claim_boundary": CLAIM_BOUNDARY,
    }


__all__ = [
    "ASSESSMENT_VERSION", "ASSESSMENT_V2_VERSION", "CATALOG_VERSION",
    "CERTIFICATE_VERSION",
    "DESIGN_PROVENANCE_SHA256", "DangerousPathwaySecurityError",
    "DangerousPathwaySecurityUnavailable", "MAX_ASSESSMENT_BYTES",
    "EVIDENCE_REFERENCE_VERSION", "MAX_CERTIFICATE_BYTES", "MAX_REQUEST_BYTES",
    "OBSERVATION_VERSION",
    "REQUEST_VERSION", "aggregate_dangerous_pathway_assessment",
    "aggregate_dangerous_pathway_assessment_v2", "assessment_scope_digest",
    "build_dangerous_pathway_certificate", "dangerous_pathway_catalog",
    "dangerous_pathway_request", "mechanism_digest",
    "recheck_dangerous_pathway_assessment",
    "recheck_dangerous_pathway_assessment_v2",
    "recheck_dangerous_pathway_certificate",
]
