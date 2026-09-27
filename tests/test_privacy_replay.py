"""External-input replay gates for the experimental disclosure helper.

Secure Hash Algorithm 256-bit (SHA-256) binding is not authentication or hiding.
JavaScript Object Notation (JSON) comparisons preserve exact serialized types.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from verifier.privacy import (
    CompositionDeltaEvaluator, DisclosureBound, DisclosureSurface,
    EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty,
)


def specimen() -> tuple:
    certificate = {"domain": "DATA", "value": 7, "verdict": "PASS"}
    surface = DisclosureSurface("DATA", tuple(certificate), ())
    bounds = tuple(DisclosureBound("bound:" + key, key, admitted_roles=("reader",))
                   for key in certificate)
    context = EmissionContext(ObserverParty("actor:a", "reader", "audit"),
                              "2026-09-26T00:00:00Z")
    return certificate, surface, bounds, context


@pytest.mark.parametrize("coordinate", ["value", "policy", "co_emission", "rules", "surface"])
def test_receipt_distinguishes_all_disclosure_inputs(coordinate: str) -> None:
    certificate, surface, bounds, context = specimen()
    evaluator = EmissionEvaluator()
    original = evaluator.evaluate_emission(certificate, surface, bounds, context)
    if coordinate == "value":
        certificate["value"] = 8
    elif coordinate == "policy":
        bounds = (*bounds, DisclosureBound("unused", "missing", admitted_roles=("reader",)))
    elif coordinate == "co_emission":
        context = replace(context, co_emitted_certificates=({"domain": "BENCH", "x": 1},))
    elif coordinate == "rules":
        evaluator = EmissionEvaluator(CompositionDeltaEvaluator(()))
    else:
        surface = replace(surface, disclosed_fields=(*surface.disclosed_fields, "absent"))
    changed = evaluator.evaluate_emission(certificate, surface, bounds, context)
    assert original.receipt["receipt_digest"] != changed.receipt["receipt_digest"]


def test_replay_requires_and_matches_external_inputs() -> None:
    inputs = specimen()
    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(*inputs)
    assert evaluator.recheck_emission(result, *inputs) is True
    altered = deepcopy(inputs[0])
    altered["value"] = 8
    assert evaluator.recheck_emission(result, altered, *inputs[1:]) is False
    assert result.receipt["observer_authentication"] == "NOT_CHECKED"
    assert result.receipt["certificate_validation"] == "NOT_CHECKED"
    assert result.receipt["level_6_conformance"] == "UNKNOWN"


@pytest.mark.parametrize("coordinate", ["emission", "receipt", "redactions", "commitments"])
def test_replay_rejects_forged_result_even_with_rehashed_receipt(coordinate: str) -> None:
    inputs = specimen()
    evaluator = EmissionEvaluator()
    result = deepcopy(evaluator.evaluate_emission(*inputs))
    if coordinate == "emission":
        result.emitted_certificate["value"] = 999
    elif coordinate == "receipt":
        result.receipt["level_6_conformance"] = "PASS"
    elif coordinate == "redactions":
        result = replace(result, redacted_fields=("invented",))
    else:
        result = replace(result, transparency_commitments=(object(),))
    receipt = dict(result.receipt)
    receipt.pop("receipt_digest")
    result.receipt["receipt_digest"] = hashlib.sha256(json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()
    assert evaluator.recheck_emission(result, *inputs) is False


def test_replay_checks_serialized_types_and_exact_shape() -> None:
    certificate, *rest = specimen()
    certificate["value"] = 1
    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(certificate, *rest)
    result.emitted_certificate["value"] = True
    assert evaluator.recheck_emission(result, certificate, *rest) is False
    result = evaluator.evaluate_emission(certificate, *rest)
    result.receipt["extra"] = "unbound"
    assert evaluator.recheck_emission(result, certificate, *rest) is False


def test_duplicate_conditions_remain_conjunctive_in_binding() -> None:
    certificate, surface, bounds, context = specimen()
    evaluator = EmissionEvaluator()
    a = DisclosureBound("unused", "missing", admitted_roles=("reader",),
                        conditions=(("purpose", "not-audit"), ("purpose", "audit")))
    b = replace(a, conditions=(("purpose", "audit"),))
    first = evaluator.evaluate_emission(certificate, surface, (*bounds, a), context)
    second = evaluator.evaluate_emission(certificate, surface, (*bounds, b), context)
    assert first.receipt["receipt_digest"] != second.receipt["receipt_digest"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "non-string-key"}, object()])
def test_non_json_certificate_is_refused(value: object) -> None:
    certificate, *rest = specimen()
    certificate["value"] = value
    with pytest.raises(EmissionRefusalError, match="JSON"):
        EmissionEvaluator().evaluate_emission(certificate, *rest)


def test_replay_rejects_legacy_unbound_receipt() -> None:
    inputs = specimen()
    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(*inputs)
    result.receipt.pop("input_binding", None)
    assert evaluator.recheck_emission(result, *inputs) is False


def test_replay_is_deterministic_without_mutating_inputs() -> None:
    inputs = specimen()
    original = deepcopy(inputs)
    evaluator = EmissionEvaluator()
    first = evaluator.evaluate_emission(*inputs)
    second = evaluator.evaluate_emission(*inputs)
    assert first == second
    assert evaluator.recheck_emission(first, *inputs) is True
    assert inputs == original


def test_replay_rejects_changed_observer_and_join_policy() -> None:
    inputs = specimen()
    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(*inputs)
    context = replace(inputs[3], observer=replace(inputs[3].observer, actor_id="actor:b"))
    assert evaluator.recheck_emission(result, *inputs[:3], context) is False
    assert EmissionEvaluator(CompositionDeltaEvaluator(())).recheck_emission(result, *inputs) is False


def test_replay_rejects_changed_mechanism_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    inputs = specimen()
    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(*inputs)
    read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: read(path) + (
        b"\n# changed shipped mechanism\n" if path.name == "composition.py" else b""))
    assert evaluator.recheck_emission(result, *inputs) is False


def test_replay_rejects_refused_or_malformed_input() -> None:
    certificate, surface, bounds, context = specimen()
    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(certificate, surface, bounds, context)
    assert evaluator.recheck_emission(result, certificate, surface, (), context) is False
    assert evaluator.recheck_emission({}, certificate, surface, bounds, context) is False
    certificate["cycle"] = certificate
    assert evaluator.recheck_emission(result, certificate, surface, bounds, context) is False


def test_binding_sidecar_does_not_embed_certificate_or_policy_secrets() -> None:
    certificate, surface, bounds, context = specimen()
    certificate["private"] = "private-test-payload"
    bounds = (*bounds, DisclosureBound("private-policy-name", "absent"))
    result = EmissionEvaluator().evaluate_emission(certificate, surface, bounds, context)
    encoded = json.dumps(result.receipt)
    assert "private-test-payload" not in encoded
    assert "private-policy-name" not in encoded
    assert len(result.receipt["input_binding"]) == 6
