"""Source-bound Tier-5 native specimen extension tests."""
from __future__ import annotations

import base64

import pytest

from verifier.domains.contracts import independence_checks, object_grounding
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import self_polish_native_adapters as adapters
from verifier.runtime import self_polish_native_tier5_cases as tier5_cases


_CHECKING_MECHANISMS = {
    "verifier.domains.contracts.independence_checks.recheck_independence_checks_certificate": (
        independence_checks.build_independence_checks_certificate,
        independence_checks.recheck_independence_checks_certificate,
    ),
    "verifier.domains.contracts.object_grounding.recheck_current_object_certificate": (
        object_grounding.build_current_object_certificate,
        object_grounding.recheck_current_object_certificate,
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
        if cell["tier"] == 5
        for route in cell["registered_route_memberships"]
    }


def test_tier5_extension_is_exact_source_bound_and_adapter_explicit() -> None:
    selected = tier5_cases.installed_case_inputs()
    memberships = _memberships()

    assert tier5_cases.CASE_REGISTRY_ENTRY_COUNT == 26
    assert set(selected) == set(memberships)
    assert set(_CHECKING_MECHANISMS) == {
        case["checking_mechanism"] for case in selected.values()
    }
    assert core_obligation_union.value_digest(selected) \
        == tier5_cases.CASE_REGISTRY_DIGEST
    for identifier, case in selected.items():
        route = memberships[identifier]
        request = case["request"]
        assert case["checking_mechanism"] == route["checking_mechanism"]
        if identifier == "SIM:SIM-5.1":
            assert "object_kind" not in request
        else:
            assert request["object_kind"] == route["object_kind"]
        assert request["coordinate"] == route["coordinate"]
        assert request["semantic_version"] == route["semantic_version"]
        assert request["proposition_digest"] == route["proposition_digest"]
        assert request["policy_digest"] \
            == core_obligation_union.value_digest(case["policy"])
        if identifier == "SIM:SIM-5.1":
            assert case["builder_adapter"] == "SIM_OBJECT_GROUNDING"
            assert case["negative_adapter"] \
                == "SIM_ISOLATION_MALFORMED_REBIND"
        else:
            assert case["builder_adapter"] == "BOUNDED_EVIDENCE_BYTES"
            assert case["negative_adapter"] == "MALFORMED_EVIDENCE_REBIND"
        assert case["unknown_adapter"] == "ABSENT_EVIDENCE"


def test_tier5_extension_rejects_payload_drift(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tier5_cases, "_PAYLOAD_B85", b"not-the-payload")

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier5_cases.installed_case_inputs()


def test_tier5_generator_reproduces_embedded_payload() -> None:
    from scripts import build_self_polish_native_tier5_cases as module

    raw, encoded = module.build_payload()
    second_raw, second_encoded = module.build_payload()

    assert (second_raw, second_encoded) == (raw, encoded)
    assert encoded == tier5_cases._PAYLOAD_B85
    assert core_obligation_union.bytes_digest(raw) \
        == tier5_cases.CASE_REGISTRY_DIGEST


def test_tier5_extension_reproduces_native_triads() -> None:
    selected = tier5_cases.installed_case_inputs()
    observed = {}
    for identifier, case in selected.items():
        builder, rechecker = _CHECKING_MECHANISMS[case["checking_mechanism"]]
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

    assert len(observed) == 26
    assert set(tuple(statuses.values()) for statuses in observed.values()) \
        == {("PASS", "FAIL", "UNKNOWN")}
