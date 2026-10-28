"""Source-bound Tier-9 native specimen extension tests."""
from __future__ import annotations

import base64

import pytest

from scripts import build_self_polish_native_tier9_cases as tier9_builder
from verifier.domains.contracts import graph_lineage
from verifier.domains.contracts import receipt_authenticity
from verifier.domains.contracts import receipt_chain
from verifier.domains.contracts import subject_security
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import self_polish_native_adapters as adapters
from verifier.runtime import self_polish_native_tier9_cases as tier9_cases


SPECIAL_NEGATIVE_ADAPTERS = {
    "GRAPH:GRAPH-9.2": "GRAPH_EDGE_CONTENT_SUBSTITUTION",
    "RECEIPT:RECEIPT-9.1": "RECEIPT_CHAIN_ENTRY_SUBSTITUTION",
    "RECEIPT:RECEIPT-9.2": "RECEIPT_ATTESTATION_SIGNATURE_BIT_FLIP",
}

MECHANISMS = {
    "verifier.domains.contracts.graph_lineage.recheck_graph_lineage_certificate": (
        graph_lineage.build_graph_lineage_certificate,
        graph_lineage.recheck_graph_lineage_certificate,
    ),
    (
        "verifier.domains.contracts.receipt_authenticity."
        "recheck_receipt_authenticity_certificate"
    ): (
        receipt_authenticity.build_receipt_authenticity_certificate,
        receipt_authenticity.recheck_receipt_authenticity_certificate,
    ),
    "verifier.domains.contracts.receipt_chain.recheck_receipt_chain_certificate": (
        receipt_chain.build_receipt_chain_certificate,
        receipt_chain.recheck_receipt_chain_certificate,
    ),
    "verifier.domains.contracts.subject_security.recheck_subject_security_certificate": (
        subject_security.build_subject_security_certificate,
        subject_security.recheck_subject_security_certificate,
    ),
}


def _memberships() -> dict[str, dict]:
    inventory = core_tier_progression.installed_core_route_inventory()
    return {
        f"{cell['object_kind']}:{route['coordinate']}": {
            "object_kind": cell["object_kind"],
            **route,
        }
        for cell in inventory["family_cells"]
        if cell["tier"] == 9
        for route in cell["registered_route_memberships"]
    }


def test_tier9_extension_is_exact_source_bound_and_adapter_explicit() -> None:
    selected = tier9_cases.installed_case_inputs()
    memberships = _memberships()

    assert tier9_cases.CASE_REGISTRY_ENTRY_COUNT == 29
    assert set(selected) == set(memberships)
    assert core_obligation_union.value_digest(selected) \
        == tier9_cases.CASE_REGISTRY_DIGEST
    for identifier, case in selected.items():
        route = memberships[identifier]
        request = case["request"]
        assert case["checking_mechanism"] == route["checking_mechanism"]
        assert request["coordinate"] == route["coordinate"]
        assert request["semantic_version"] == route["semantic_version"]
        assert request["proposition_digest"] == route["proposition_digest"]
        assert request["policy_digest"] \
            == core_obligation_union.value_digest(case["policy"])
        assert case["builder_adapter"] == "BOUNDED_EVIDENCE_BYTES"
        assert case["negative_adapter"] == SPECIAL_NEGATIVE_ADAPTERS.get(
            identifier, "SUBJECT_SECURITY_VALID_TRANSPLANT"
        )
        assert case["unknown_adapter"] == "ABSENT_EVIDENCE"


def test_tier9_extension_rejects_payload_drift(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tier9_cases, "_PAYLOAD_B85", b"not-the-payload")

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier9_cases.installed_case_inputs()


def test_tier9_generator_reproduces_embedded_payload() -> None:
    raw, encoded = tier9_builder.build_payload()
    second_raw, second_encoded = tier9_builder.build_payload()

    assert (second_raw, second_encoded) == (raw, encoded)
    assert encoded == tier9_cases._PAYLOAD_B85
    assert core_obligation_union.bytes_digest(raw) \
        == tier9_cases.CASE_REGISTRY_DIGEST


def test_tier9_extension_reproduces_native_triads() -> None:
    selected = tier9_cases.installed_case_inputs()
    observed = {}
    for identifier, case in selected.items():
        builder, rechecker = MECHANISMS[case["checking_mechanism"]]
        request = case["request"]
        policy = case["policy"]
        replay_input = base64.b64decode(
            case["evidence_base64"], validate=True
        )
        negative_request, negative_input = adapters.negative_case(
            case["negative_adapter"], request, replay_input
        )
        built = {
            "POSITIVE": (
                adapters.build_certificate(
                    case["builder_adapter"], "POSITIVE", builder,
                    request, replay_input, policy,
                ),
                request,
            ),
            "NEGATIVE": (
                adapters.build_certificate(
                    case["builder_adapter"], "NEGATIVE", builder,
                    negative_request, negative_input, policy,
                ),
                negative_request,
            ),
            "UNKNOWN": (
                adapters.build_certificate(
                    case["builder_adapter"], case["unknown_adapter"],
                    builder, request, replay_input, policy,
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

    assert len(observed) == 29
    assert set(tuple(statuses.values()) for statuses in observed.values()) \
        == {("PASS", "FAIL", "UNKNOWN")}
