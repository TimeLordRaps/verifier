"""Retained subject-security certificates cannot become redacted certificates.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
These local tests exercise native certificate replay and the disclosure engine;
they establish neither observer authentication nor authority to transmit data.
The existing fixture creates independently encoded receipt-chain messages; this
module supplies separate emission oracles and never substitutes native verdicts.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from test_current_subject_security import fixture
from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import subject_security
from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
from verifier.privacy.models import (
    DisclosureBound, DisclosureSurface, EmissionContext, ObserverParty,
)


def _certificate(kind: str, status: str) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    request, policy, evidence, _ = fixture(kind, child_status=status)
    certificate = subject_security.build_subject_security_certificate(
        request, evidence, policy=policy,
    )
    result = subject_security.recheck_subject_security_certificate(
        certificate, expected_request=request, policy=policy,
    )
    assert result["status"] == status
    assert result["public_disclosure_authority"] == "NOT_ESTABLISHED"
    return certificate, request, policy


def _selection(value: dict[str, Any], omitted: tuple[str, ...] = ()) -> tuple[
    DisclosureSurface, tuple[DisclosureBound, ...], EmissionContext
]:
    fields = tuple(key for key in value if key not in omitted)
    return (
        DisclosureSurface(value["request"]["object_kind"], fields, omitted),
        tuple(DisclosureBound(key, key, admitted_observers=("local-reader",))
              for key in fields),
        EmissionContext(ObserverParty("local-reader", "auditor", "local-inspection"),
                        "2026-09-30T00:00:00Z"),
    )


@pytest.mark.parametrize("kind", ["MODEL", "HUMAN", "RECEIPT"])
@pytest.mark.parametrize("status", ["PASS", "FAIL", "UNKNOWN"])
def test_full_native_subject_security_certificate_preserves_exact_bytes(
    kind: str, status: str,
) -> None:
    certificate, request, policy = _certificate(kind, status)
    value = json.loads(certificate)
    output = EmissionEvaluator().evaluate_emission(value, *_selection(value))
    assert canonical_bytes(output.emitted_certificate) == certificate
    assert output.redacted_fields == ()
    assert output.receipt["certificate_validation"] == "NOT_CHECKED"
    assert output.receipt["observer_authentication"] == "NOT_CHECKED"
    assert output.receipt["level_6_conformance"] == "UNKNOWN"
    replay = subject_security.recheck_subject_security_certificate(
        canonical_bytes(output.emitted_certificate), expected_request=request,
        policy=policy,
    )
    assert replay["status"] == status
    assert replay["public_disclosure_authority"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("kind", ["MODEL", "HUMAN", "RECEIPT"])
@pytest.mark.parametrize("status", ["PASS", "FAIL", "UNKNOWN"])
def test_retained_subject_chain_witness_cannot_be_withheld(
    kind: str, status: str,
) -> None:
    certificate, _, _ = _certificate(kind, status)
    value = json.loads(certificate)
    assert value["evidence_payloads"]
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(
            value, *_selection(value, ("evidence_payloads",)),
        )


@pytest.mark.parametrize("field", [
    "schema_version", "request", "policy_digest", "mechanism_digest",
    "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest",
])
def test_each_canonical_subject_security_field_requires_complete_disclosure(
    field: str,
) -> None:
    certificate, _, _ = _certificate("MODEL", "PASS")
    value = json.loads(certificate)
    assert field in value
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, *_selection(value, (field,)))
