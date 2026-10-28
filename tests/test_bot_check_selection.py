"""Verifier Standard (VSTD) native BOT selection and observation-ceiling regressions.

BOT is the situated-agent object name, not an acronym. These tests compare retained
records; they do not establish actual execution or physical environment separation.
Counts and record positions are dimensionless.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest

from verifier.domains import bot
from verifier.domains.certification import (
    build_domain_certificate, domain_policy, domain_request, implementation_digest,
)
from verifier.domains.common import Budget, Refuted, Unavailable, digest


@pytest.fixture(scope="module")
def bundle() -> dict:
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("bot_selection_example", root / "examples/domain_grounding.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.specimens()["BOT"]


def evaluate(check: object, bundle: dict) -> dict:
    return bot.evaluate(check, bundle["artifact"], bundle["inputs"], Budget(100000),
        mechanism_digest=implementation_digest(),
        policy=domain_policy(trust_roots=["test:bot-selection"]))


@pytest.mark.parametrize("check", ["binding", "alignment", "observation", "actuation", "containment"])
def test_admitted_positive_controls(check: str, bundle: dict) -> None:
    result = evaluate(check, bundle)
    assert result["historical_child_policy_reproduction"] == "NOT_ESTABLISHED"
    assert result["observation_ceiling"] == ["world_action", "world_observation"]


@pytest.mark.parametrize("check", ["bind", "", "BINDING", " binding", None, True, ["binding"]])
def test_unsupported_selection_cannot_return_binding_success(check: object, bundle: dict) -> None:
    with pytest.raises(Unavailable, match="unsupported bot check"):
        evaluate(check, bundle)


def test_string_subclass_cannot_impersonate_admitted_selector(bundle: dict) -> None:
    class Forged(str):
        def __eq__(self, other: object) -> bool:
            return True

        def __ne__(self, other: object) -> bool:
            return False

    with pytest.raises(Unavailable, match="unsupported bot check"):
        evaluate(Forged("unregistered"), bundle)


def test_unknown_selection_does_not_consume_evidence() -> None:
    class Unreadable(dict):
        def __contains__(self, key: object) -> bool:
            raise AssertionError("unsupported selector consumed evidence")

    with pytest.raises(Unavailable, match="unsupported bot check"):
        evaluate("unregistered", {"artifact": Unreadable(), "inputs": Unreadable()})


def restricted_bundle(bundle: dict, include_initial_channel: bool) -> dict:
    changed = deepcopy(bundle)
    evidence = changed["inputs"]["agent_certificate"]["evidence"]
    evidence["artifact"]["required_channels"] = ["world_action"]
    if include_initial_channel:
        evidence["artifact"]["required_channels"].append("world_observation")
    evidence["inputs"]["steps"] = evidence["inputs"]["steps"][1:]
    for index, step in enumerate(evidence["inputs"]["steps"]):
        step["index"] = index
    evidence["artifact"]["steps_digest"] = digest(evidence["inputs"]["steps"])
    child = build_domain_certificate(domain_request(evidence, target_depth=5), evidence,
        policy=domain_policy(trust_roots=["test:bot-selection"]))
    assert child["result"]["status"] == "PASS"
    changed["inputs"]["agent_certificate"] = child
    changed["artifact"]["agent_certificate_digest"] = digest(child)
    return changed


def test_initial_observation_cannot_exceed_agent_ceiling(bundle: dict) -> None:
    with pytest.raises(Unavailable, match="observation ceiling"):
        evaluate("observation", restricted_bundle(bundle, False))


def test_initial_observation_passes_when_its_channel_is_selected(bundle: dict) -> None:
    result = evaluate("observation", restricted_bundle(bundle, True))
    assert result["attributed_transitions"] == 2


def test_in_ceiling_wrong_initial_projection_is_still_refuted(bundle: dict) -> None:
    changed = restricted_bundle(bundle, True)
    changed["artifact"]["initial_observation_record"] = 1
    with pytest.raises(Refuted, match="initial observation differs"):
        evaluate("observation", changed)
