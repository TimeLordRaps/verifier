"""Source-review counterexamples; execute only under the integrator's supervisor.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Time is integer Coordinated Universal Time (UTC)
Unix seconds; counts are dimensionless. No test here was run by its author.
"""
from __future__ import annotations

import builtins
import json
from typing import Any

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import object_governance as governance
from verifier.runtime import polish
from test_current_kind_governance import digest, encoded, specimen


def test_original_object_governance_polish_binding_does_not_raise_missing_import() -> None:
    item = NamespaceObject.create("original-object", "OBJECT", {"value": "retained"})
    selection = {
        "coordinate": "OBJECT-8.1", "semantic_version": "verifier-current-object-obligations-1",
        "certificate_digest": "sha256:" + "0" * 64,
        "request": {"object_id": item.object_id, "record_digest": item.digest},
    }
    # Missing evidence has an existing explicit UNKNOWN path. A NameError
    # before that branch is a regression, not an evidence-unavailable result.
    result = polish._objective(selection, item, {}, "sha256:" + "1" * 64)
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "PUBLIC_REPLAY_EVIDENCE_MISSING"


@pytest.mark.parametrize("kind", ["OBJECT", "HUMAN"])
@pytest.mark.parametrize("backend_missing", [False, True])
@pytest.mark.parametrize("field", ["request-time", "result-revision", "evaluation-size", "observation-control"])
def test_nonexact_carried_numeric_fields_reject_even_when_signature_backend_is_unavailable(
        kind: str, backend_missing: bool, field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = specimen(kind)
    certificate = governance.build_governance_certificate(request, evidence, policy=policy)
    changed = json.loads(certificate)
    if field == "request-time":
        changed["request"]["evaluation_time"] = float(request["evaluation_time"])
    elif field == "result-revision":
        changed["result"]["policy_revision"] = float(policy["revision"])
    elif field == "evaluation-size":
        evaluation = changed["result"]["evaluation"]
        evaluation["observed_evidence_bytes"] = float(evaluation["observed_evidence_bytes"])
    else:
        changed["result"]["evaluation"]["observations"]["quorum"] = float(policy["quorum"])
    changed["certificate_digest"] = digest({key: value for key, value in changed.items()
                                            if key != "certificate_digest"})
    if backend_missing:
        original_import = builtins.__import__

        def unavailable(name: str, *args: Any, **kwargs: Any) -> Any:
            if name.startswith("cryptography"):
                raise ImportError("test-only signature backend removal after certificate construction")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", unavailable)
    # This is an exact-selection refusal, not a demand for a cryptographic
    # verdict when the backend is unavailable. The external request/policy
    # still contain integers; only carried certificate fields were changed.
    with pytest.raises(governance.ObjectGovernanceError):
        governance.recheck_governance_certificate(
            encoded(changed), expected_request=request, policy=policy)


def test_original_object_registration_and_declared_wire_defaults_are_literal_compatible() -> None:
    expected = {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": "verifier-current-object-obligations-1",
        "coordinate": "OBJECT-8.1", "subject_kind": "OBJECT",
        "scope": "selected_signed_namespace_admission_quorum",
        "proposition": (
            "Under the independently selected revisioned public-key policy "
            "and evaluation time, the exact retained OBJECT namespace record "
            "has a configured quorum of distinct signed approvals for its "
            "selected namespace admission action, no selected veto or revoked "
            "decision, and a separately signed fresh revocation view."),
        "prerequisites": [
            "externally selected exact OBJECT record digest, namespace, "
            "policy, trusted evaluation time and retained signed evidence"],
        "exclusions": [
            "policy issuer authenticity, clock source authenticity, human consent",
            "legal or moral compliance, actual namespace admission or enforcement",
            "registry completeness, operand target truth, whole governance tier",
            "OBJECT profile, privacy and security conclusions"],
    }
    assert governance.registration() == expected
    assert governance.PROPOSITION_DIGEST == digest(expected)
    assert governance.GovernanceDescriptor.PROPOSITION_DIGEST == digest(expected)
    assert governance.GovernanceDescriptor.CERTIFICATE_VERSION == "verifier-current-object-governance-certificate-1"
    assert governance.REQUEST_VERSION == "verifier-current-object-governance-request-1"
    assert governance.POLICY_VERSION == "verifier-current-object-governance-policy-1"
    assert governance.MECHANISM_ID == "verifier.current-object.namespace-governance.1"


def test_governance_inventory_status_does_not_claim_whole_tier_closure() -> None:
    from verifier.domains.inventory import slot_inventory

    rows = [row for row in slot_inventory() if row["tier"] == 8]
    assert len(rows) == 26
    for row in rows:
        assert row["status"] == "REPLAYABLE"
        assert row["coordinate_role"] == "PRIMARY_REGISTERED_OBJECTIVE"
        assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"
        assert row["rationale_status"] == "PLANNING_CONTEXT_NOT_NUMBERED_REQUIREMENTS"
        assert row["mechanized_route"]["exact_claim"] == governance.registration(row["object_kind"])["proposition"]
        assert "whole governance tier" in row["mechanized_route"]["assumptions_and_exclusions"]
