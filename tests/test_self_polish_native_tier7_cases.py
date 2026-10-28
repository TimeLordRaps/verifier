"""Source-bound Tier-7 consent native specimen extension tests."""
from __future__ import annotations

import base64

import pytest

from scripts import build_self_polish_native_tier7_cases as tier7_builder
from verifier.domains.contracts import consent_checks
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import self_polish_native_adapters as adapters
from verifier.runtime import self_polish_native_tier7_cases as tier7_cases


def _memberships() -> dict[str, dict]:
    inventory = core_tier_progression.installed_core_route_inventory()
    return {
        f"{cell['object_kind']}:{route['coordinate']}": {
            "object_kind": cell["object_kind"],
            **route,
        }
        for cell in inventory["family_cells"]
        if cell["tier"] == 7
        for route in cell["registered_route_memberships"]
    }


def test_tier7_extension_is_exact_and_source_bound() -> None:
    selected = tier7_cases.installed_case_inputs()
    memberships = _memberships()

    assert tier7_cases.CASE_REGISTRY_ENTRY_COUNT == 156
    assert set(selected) == set(memberships)
    assert core_obligation_union.value_digest(selected) \
        == tier7_cases.CASE_REGISTRY_DIGEST
    for identifier, case in selected.items():
        route = memberships[identifier]
        request = case["request"]
        assert case["checking_mechanism"] == route["checking_mechanism"]
        assert request["object_kind"] == route["object_kind"]
        assert request["coordinate"] == route["coordinate"]
        assert request["semantic_version"] == route["semantic_version"]
        assert request["proposition_digest"] == route["proposition_digest"]
        assert request["policy_digest"] \
            == core_obligation_union.value_digest(case["policy"])
        assert case["builder_adapter"] == "BOUNDED_EVIDENCE_BYTES"
        assert case["negative_adapter"] == "MALFORMED_EVIDENCE_REBIND"
        assert case["unknown_adapter"] == "ABSENT_EVIDENCE"


def test_tier7_extension_rejects_payload_drift(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tier7_cases, "_PAYLOAD_B85", b"not-the-payload")

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier7_cases.installed_case_inputs()


def test_tier7_generator_reproduces_embedded_payload() -> None:
    raw, encoded = tier7_builder.build_payload()
    second_raw, second_encoded = tier7_builder.build_payload()

    assert (second_raw, second_encoded) == (raw, encoded)
    assert encoded == tier7_cases._PAYLOAD_B85
    assert core_obligation_union.bytes_digest(raw) \
        == tier7_cases.CASE_REGISTRY_DIGEST


def test_tier7_extension_reproduces_native_triads() -> None:
    selected = tier7_cases.installed_case_inputs()
    observed = {}
    for identifier, case in selected.items():
        assert case["checking_mechanism"] == (
            "verifier.domains.contracts.consent_checks."
            "recheck_consent_checks_certificate"
        )
        rechecker = consent_checks.recheck_consent_checks_certificate
        builder = consent_checks.build_consent_checks_certificate
        request = case["request"]
        policy = case["policy"]
        evidence = base64.b64decode(case["evidence_base64"], validate=True)
        negative_request, negative_evidence = adapters.negative_case(
            case["negative_adapter"], request, evidence
        )
        built = {
            "POSITIVE": (
                adapters.build_certificate(
                    case["builder_adapter"], "POSITIVE", builder,
                    request, evidence, policy,
                ),
                request,
            ),
            "NEGATIVE": (
                adapters.build_certificate(
                    case["builder_adapter"], "NEGATIVE", builder,
                    negative_request, negative_evidence, policy,
                ),
                negative_request,
            ),
            "UNKNOWN": (
                adapters.build_certificate(
                    case["builder_adapter"], case["unknown_adapter"],
                    builder, request, evidence, policy,
                ),
                request,
            ),
        }
        observed[identifier] = {
            kind: rechecker(
                certificate,
                expected_request=expected_request,
                policy=policy,
            )["status"]
            for kind, (certificate, expected_request) in built.items()
        }

    assert len(observed) == 156
    assert set(tuple(statuses.values()) for statuses in observed.values()) \
        == {("PASS", "FAIL", "UNKNOWN")}
