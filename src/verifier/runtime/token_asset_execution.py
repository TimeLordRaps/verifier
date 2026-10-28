"""Finite source-bound ASSET checks for retained capability-token mechanics.

The selected implementation is the existing TOKEN checker, exercised in a
closed worker and rechecked by the parent.  These propositions establish only
finite retained-record behavior.  They never promote a recorded capability to
issuer authority, physical custody, financial backing or actual enforcement.
"""
from __future__ import annotations

import base64
from typing import Any

from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


ADAPTER = "verifier-token-asset-1"
SEMANTIC_VERSION = "verifier-token-asset-obligations-1"
IMPLEMENTATION = "src/verifier/domains/contracts/token_checks.py"
WORKER = "token_asset_worker.py"
REQUEST_SCHEMA = "verifier-token-asset-request-1"
OBSERVATION_SCHEMA = "verifier-token-asset-observations-1"
BOUNDARY = (
    "Fresh bounded replay of the exact owned retained capability-token checker. "
    "The replay covers typed record identity, declared integer units, retained "
    "lifecycle folds, delegation restrictions and reconciliation of the selected "
    "finite inventory. It does not establish issuer authority, signature validity, "
    "real custody, holding completeness, redemption, application enforcement, "
    "supply conservation, backing, complete ASSET conformance or package polish."
)
CLAIM_BOUNDARY = {
    "issuer_authority": "NOT_ESTABLISHED",
    "signature_validity": "NOT_ESTABLISHED",
    "real_custody": "NOT_ESTABLISHED",
    "holding_completeness": "NOT_ESTABLISHED",
    "redemption": "NOT_ESTABLISHED",
    "application_enforcement": "NOT_ESTABLISHED",
    "supply_conservation": "NOT_ESTABLISHED",
    "backing": "NOT_ESTABLISHED",
}
_CONTRACTS = (
    (
        "ASSET-1.1",
        "capability-identity-units-and-precision",
        1,
        "An asset record cannot support a quantity or capability claim unless its exact identity, declared unit and numeric precision are bound and type checked.",
        "The selected retained TOKEN subject reconstructs exactly with a declared microsecond clock and dimensionless integer counts; cross-objective, non-integer and unadmitted-unit variants do not PASS.",
    ),
    (
        "ASSET-2.1",
        "issuance-lifecycle-and-redemption-boundary",
        2,
        "Issuance, suspension, revocation and redemption have different consequences; a retained lifecycle must not imply an authority or redemption event that was not observed.",
        "One declared birth and its contiguous retained epoch fold reproduce exactly, suspension halts accrual and revocation is irreversible; redemption and actual application remain explicitly NOT_ESTABLISHED.",
    ),
    (
        "ASSET-3.1",
        "capability-encumbrance-and-reconciliation",
        3,
        "Custody and encumbrance claims require reconciliation of the selected inventory and must not allow delegated scope, time, quota, caveats or soulbound restrictions to widen.",
        "The finite selected delegation inventory resolves through acyclic parent paths and reconciles narrowing scopes, windows, quotas, caveats and soulbound restrictions; real custody, completeness, supply conservation and backing remain NOT_ESTABLISHED.",
    ),
)
_RESULT_BOUNDARY = {
    "object_profile_conformance": "NOT_ESTABLISHED",
    "authority": "NOT_ESTABLISHED",
    "signature_validity": "NOT_ESTABLISHED",
    "physical_clock": "NOT_ESTABLISHED",
    "holding_completeness": "NOT_ESTABLISHED",
    "actual_execution": "NOT_ESTABLISHED",
}
_DECLARATION = {
    "record_model": "retained-capability-token-records",
    "window_unit": "declared-microsecond-integer",
    "quantity_unit": "dimensionless-integer",
    "precision": "exact-integer-replay",
}


def catalog() -> list[dict[str, Any]]:
    """Name the finite ASSET propositions; none is a whole-kind waiver."""
    return [
        {
            "coordinate": coordinate,
            "obligation_id": coordinate + "-" + slug,
            "obligation_name": slug.replace("-", " ").capitalize(),
            "object_kind": "ASSET",
            "tier": tier,
            "reason": reason,
            "exact_claim": claim,
            "semantic_version": SEMANTIC_VERSION,
            "proposition_digest": value_digest(
                {"coordinate": coordinate, "claim": claim, "boundary": BOUNDARY}
            ),
            "checking_mechanism": "verifier.runtime.token_asset_execution.evaluate",
            "scope": "retained_token_asset_" + slug.replace("-", "_"),
            "adapter": ADAPTER,
        }
        for coordinate, slug, tier, reason, claim in _CONTRACTS
    ]


def _equal(left: Any, right: Any) -> bool:
    """Keep booleans distinct from integers at the parent evidence boundary."""
    return canonical_bytes(left) == canonical_bytes(right)


def _certificate(row: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Recheck worker bytes and return the reproduced result and evidence."""
    from verifier.domains.contracts import token_checks

    if type(row) is not dict or set(row) != {
        "check", "request", "policy", "certificate", "reported_result"
    }:
        raise ValueError("TOKEN_ASSET_OBSERVATION_FIELDS_DIFFER")
    if type(row["certificate"]) is not str or len(row["certificate"]) > 12 * 1024 * 1024:
        raise ValueError("TOKEN_ASSET_CERTIFICATE_BOUND_DIFFERS")
    try:
        certificate = base64.b64decode(row["certificate"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("TOKEN_ASSET_CERTIFICATE_ENCODING_DIFFERS") from exc
    result = token_checks.recheck_token_checks_certificate(
        certificate, expected_request=row["request"], policy=row["policy"]
    )
    if not _equal(result, row["reported_result"]):
        raise ValueError("TOKEN_ASSET_REPORTED_RESULT_DIFFERS")
    if row["check"] not in token_checks.CHECKS:
        raise ValueError("TOKEN_ASSET_CHECK_DIFFERS")
    if row["request"].get("check") != row["check"]:
        raise ValueError("TOKEN_ASSET_REQUEST_CHECK_DIFFERS")
    envelope = strict_json_loads(certificate.decode("utf-8"))
    payloads = envelope["evidence_payloads"]
    if type(payloads) is not dict or set(payloads) != {row["request"]["evidence_ref"]}:
        raise ValueError("TOKEN_ASSET_EVIDENCE_SELECTION_DIFFERS")
    evidence = strict_json_loads(
        base64.b64decode(payloads[row["request"]["evidence_ref"]], validate=True).decode("utf-8")
    )
    return result, evidence


def _verified(observed: dict[str, Any]) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    if type(observed) is not dict or set(observed) != {
        "boundary", "declaration", "checks", "controls"
    }:
        raise ValueError("TOKEN_ASSET_OBSERVATION_SHAPE_DIFFERS")
    if not _equal(observed["boundary"], CLAIM_BOUNDARY):
        raise ValueError("TOKEN_ASSET_CLAIM_BOUNDARY_DIFFERS")
    if not _equal(observed["declaration"], _DECLARATION):
        raise ValueError("TOKEN_ASSET_DECLARED_UNIT_DIFFERS")
    checks = observed["checks"]
    if type(checks) is not dict or set(checks) != {"tenure", "windows", "delegation"}:
        raise ValueError("TOKEN_ASSET_CHECK_COVERAGE_DIFFERS")
    verified = {name: _certificate(row) for name, row in checks.items()}
    requests = [checks[name]["request"] for name in sorted(checks)]
    for field in ("subject_id", "object_digest", "collection_digest", "evidence_ref"):
        if len({request[field] for request in requests}) != 1:
            raise ValueError("TOKEN_ASSET_SELECTED_IDENTITY_DIFFERS")
    for result, evidence in verified.values():
        if result["status"] != "PASS" or any(
            result[field] != value for field, value in _RESULT_BOUNDARY.items()
        ):
            raise ValueError("TOKEN_ASSET_BASE_REPLAY_DIFFERS")
        if (
            type(evidence) is not dict
            or set(evidence) != {"schema_version", "objects", "inputs"}
            or type(evidence["objects"]) is not list
            or len(evidence["objects"]) != 1
        ):
            raise ValueError("TOKEN_ASSET_EVIDENCE_SHAPE_DIFFERS")
        subject = evidence["objects"][0]
        payload = subject.get("payload", {})
        if (
            subject.get("kind") != "TOKEN"
            or payload.get("scope") != _DECLARATION["record_model"]
            or payload.get("clock_unit") != "microsecond"
        ):
            raise ValueError("TOKEN_ASSET_SUBJECT_MAPPING_DIFFERS")
    return verified


def _control(observed: dict[str, Any], name: str, status: str) -> dict[str, Any]:
    controls = observed["controls"]
    if type(controls) is not dict or set(controls) != {
        "boolean_integer", "unadmitted_unit", "revival", "widened_scope", "unsupported_asset"
    }:
        raise ValueError("TOKEN_ASSET_CONTROL_COVERAGE_DIFFERS")
    result, _ = _certificate(controls[name])
    if result["status"] != status or any(
        result[field] != value for field, value in _RESULT_BOUNDARY.items()
    ):
        raise ValueError("TOKEN_ASSET_CONTROL_OUTCOME_DIFFERS")
    return result


def check_observations(coordinate: str, observed: dict[str, Any]) -> bool:
    """Recompute certificates and inspect semantic effects, never worker verdicts."""
    verified = _verified(observed)
    tenure = verified["tenure"][0]["evaluation"]["observations"]["token"]
    windows = verified["windows"][0]["evaluation"]["observations"]["token"]
    delegation = verified["delegation"][0]["evaluation"]["observations"]["token"]
    if coordinate == "ASSET-1.1":
        return (
            _equal(windows, {"leases": 2, "narrowest": 600, "skew": 30,
                             "unbounded_windows": [], "windows": 2})
            and _control(observed, "boolean_integer", "FAIL")["status"] == "FAIL"
            and _control(observed, "unadmitted_unit", "UNKNOWN")["status"] == "UNKNOWN"
        )
    if coordinate == "ASSET-2.1":
        return (
            _equal(tenure, {"active_epochs": 2, "aging_tokens": 1, "birth_epoch": 4,
                "head": "sha256:8ee9c8c60da94dc0986cd5c4ea4b8d6278f71f5ffa372d9e1e0c72565341eb2e",
                "last_epoch": 8, "revoked_at": 8, "suspended_epochs": [6]})
            and _control(observed, "revival", "FAIL")["status"] == "FAIL"
            and _control(observed, "unsupported_asset", "UNKNOWN")["status"] == "UNKNOWN"
        )
    if coordinate == "ASSET-3.1":
        return (
            _equal(delegation, {"delegation_depth": 2, "leases": 2,
                "root_leases": 1, "scopes_conveyed": ["read", "write"], "soulbound": []})
            and windows["windows"] == 2
            and _control(observed, "widened_scope", "FAIL")["status"] == "FAIL"
        )
    raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")


def _execute(snapshot: Any, item: NamespaceObject, selection: dict[str, Any]) -> dict[str, Any]:
    from verifier.runtime.package_execution import execute_bound

    return execute_bound(snapshot, item, selection)


def evaluate(snapshot: Any, item: NamespaceObject, route: dict[str, Any]) -> dict[str, Any] | None:
    from verifier.runtime.package_execution import evaluate_selected

    return evaluate_selected(snapshot, item, route)

