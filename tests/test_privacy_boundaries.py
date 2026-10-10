"""Refutable disclosure boundaries for Verifier Standard (VSTD) privacy helpers.

These helper checks do not establish registered normative level 6 conformance.
"""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

from verifier.privacy import (
    CompositionDeltaEvaluator, ContextualIntegrityEvaluator,
    DifferentialPrivacyBudget, DisclosureBound, DisclosureSurface,
    EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty,
)


OBSERVER = ObserverParty("actor:reader", "auditor", "audit", ("credential:a",))
CONTEXT = EmissionContext(OBSERVER, "2026-09-26T00:00:00Z")


def admitted(field: str, **kwargs: object) -> DisclosureBound:
    return DisclosureBound("bound:" + field, field, admitted_roles=("auditor",), **kwargs)


@pytest.mark.parametrize("conditions,expected", [
    ((("purpose", "audit"),), True),
    ((("purpose", "resale"),), False),
    ((("actor_id", "actor:reader"), ("credential", "credential:a")), True),
    ((("credential", "credential:absent"),), False),
    ((("unimplemented_predicate", "true"),), False),
    ((("purpose", "audit"), ("purpose", "resale")), False),
])
def test_admission_conditions_are_conjunctive_and_unknown_is_denied(conditions: tuple, expected: bool) -> None:
    assert admitted("value", conditions=conditions).permits(OBSERVER) is expected


def test_unenumerated_field_is_withheld_even_when_a_bound_admits_it() -> None:
    result = EmissionEvaluator().evaluate_emission(
        {"secret": "nested-or-flat"}, DisclosureSurface("DATA", (), ()),
        (admitted("secret"),), CONTEXT,
    )
    assert "secret" not in result.emitted_certificate
    assert result.redacted_fields == ("secret",)


@pytest.mark.parametrize("field", ["request", "result", "results", "tier_1"])
def test_structural_containers_never_bypass_explicit_withholding(field: str) -> None:
    certificate = {field: {"private_value": "do-not-emit"}}
    try:
        result = EmissionEvaluator().evaluate_emission(
            certificate, DisclosureSurface("DATA", (), (field,)), (), CONTEXT,
        )
    except EmissionRefusalError:
        return
    assert field not in result.emitted_certificate
    assert "do-not-emit" not in str(result.to_dict())


def test_contradictory_surface_is_rejected() -> None:
    with pytest.raises(EmissionRefusalError, match="overlap"):
        EmissionEvaluator().evaluate_emission(
            {"x": 1}, DisclosureSurface("DATA", ("x",), ("x",)),
            (admitted("x"),), CONTEXT,
        )


def test_verdict_without_bound_refuses_instead_of_silently_emitting() -> None:
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(
            {"verdict": "PASS"}, DisclosureSurface("DATA", (), ()), (), CONTEXT,
        )


@pytest.fixture(scope="module")
def real_sim() -> tuple[dict, dict, dict]:
    from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
    path = Path(__file__).resolve().parents[1] / "examples/domain_grounding.py"
    spec = importlib.util.spec_from_file_location("privacy_boundary_example", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bundle = module.specimens()["SIM"]
    policy = domain_policy(trust_roots=["test:retained-inputs", "test:checker"])
    request = domain_request(bundle, target_depth=4)
    certificate = build_domain_certificate(request, bundle, policy=policy)
    assert certificate["result"]["status"] == "PASS"
    return certificate, request, policy


def test_native_sim_certificate_still_rechecks_after_authorized_emission(real_sim: tuple) -> None:
    from verifier.domains.certification import recheck_domain_certificate
    certificate, request, policy = real_sim
    before = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
    emitted = EmissionEvaluator().evaluate_emission(
        certificate, DisclosureSurface("SIM", tuple(certificate), ()),
        tuple(admitted(key) for key in certificate), CONTEXT,
    )
    assert emitted.emitted_certificate == certificate
    assert recheck_domain_certificate(emitted.emitted_certificate, expected_request=request, policy=policy) == before
    assert before["status"] == "PASS"
    assert EmissionEvaluator().recheck_emission(
        emitted, certificate, DisclosureSurface("SIM", tuple(certificate), ()),
        tuple(admitted(key) for key in certificate), CONTEXT,
    ) is True


@pytest.mark.parametrize("field", ["evidence", "request", "result"])
def test_native_sim_refuses_when_required_proof_cannot_be_disclosed(real_sim: tuple, field: str) -> None:
    certificate, _, _ = real_sim
    original = copy.deepcopy(certificate)
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(
            certificate,
            DisclosureSurface("SIM", tuple(key for key in certificate if key != field), (field,)),
            tuple(admitted(key) for key in certificate), CONTEXT,
        )
    assert certificate == original


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_budget_nonfinite_consumption_rejected_without_mutation(value: float) -> None:
    budget = DifferentialPrivacyBudget(1.0, 0.1)
    before = vars(budget).copy()
    with pytest.raises(ValueError):
        budget.consume(value)
    assert vars(budget) == before


@pytest.mark.parametrize("kwargs", [
    {"max_epsilon": float("nan"), "max_delta": 0.1},
    {"max_epsilon": 1.0, "max_delta": 2.0},
    {"max_epsilon": 1.0, "max_delta": 0.1, "consumed_epsilon": -1.0},
])
def test_invalid_budget_state_is_rejected(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        DifferentialPrivacyBudget(**kwargs).consume(0.0)


def test_empty_transmission_policy_is_not_open_admission() -> None:
    allowed, _ = ContextualIntegrityEvaluator().evaluate("sender", OBSERVER, "subject", "records", "confidential")
    assert allowed is False


def test_nested_native_domain_join_is_not_bypassed_by_claimed_auditor_role() -> None:
    allowed, _, _ = CompositionDeltaEvaluator().evaluate_composition_delta(
        {"request": {"domain": "DATA"}}, ({"request": {"domain": "TRAIN"}},), OBSERVER,
    )
    assert allowed is False


def test_no_matched_join_rule_is_not_general_privacy_proof() -> None:
    result = EmissionEvaluator().evaluate_emission({}, DisclosureSurface("DATA", (), ()), (), CONTEXT)
    assert result.receipt["composition_join_check"] == "UNKNOWN"
