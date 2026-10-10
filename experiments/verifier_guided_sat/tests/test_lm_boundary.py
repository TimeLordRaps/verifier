from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifier_guided_sat.lm_backend import (
    LmConfigurationError,
    LmObservation,
    OpenAICompatibleBackend,
    LmResponseError,
    _parse_json_object,
)
from verifier_guided_sat.external_verifiers import load_verifier
from verifier_guided_sat.harness import VerifierGuidedHarness
from verifier_guided_sat.instances import load_instances
from verifier_guided_sat.prompts import load_prompts, render_user_prompt


ROOT = Path(__file__).resolve().parents[1]


class FixtureLm:
    """Deterministic unit fixture; never empirical LM evidence."""

    def __init__(self, output: dict | None = None, error: LmResponseError | None = None) -> None:
        self.output = output
        self.error = error

    def complete_json(self, system_prompt: str, user_prompt: str) -> LmObservation:
        if self.error is not None:
            raise self.error
        assert self.output is not None
        return LmObservation(self.output, 17, 3, 5)


def test_json_parser_accepts_plain_and_fenced_objects_only() -> None:
    assert _parse_json_object('{"candidate":{"x":1}}') == {"candidate": {"x": 1}}
    assert _parse_json_object('```json\n{"route":{}}\n```') == {"route": {}}
    with pytest.raises(ValueError):
        _parse_json_object("[1,2]")


def test_environment_configuration_fails_without_private_values(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("VGSAT_LM_BASE_URL", "VGSAT_LM_MODEL", "VGSAT_LM_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(LmConfigurationError):
        OpenAICompatibleBackend.from_environment()


def test_public_backend_description_withholds_private_coordinates() -> None:
    backend = OpenAICompatibleBackend("http://loopback.invalid", "test-only", "test-only")
    description = backend.public_configuration()
    assert description["endpoint_disclosure"] == "withheld"
    assert description["model_identity_disclosure"] == "withheld"
    assert "loopback" not in json.dumps(description)


def test_frozen_prompt_rendering_is_generic() -> None:
    system, arm_b, arm_c = load_prompts(ROOT)
    rendered = render_user_prompt(arm_c, instance={"n": 2}, contract={"witness_schema": "object"})
    assert "{{INSTANCE}}" not in rendered
    assert "{{VERIFIER_CONTRACT}}" not in rendered
    assert "route-local" in system
    assert "complete candidate" in arm_b


def test_arm_b_native_acceptance_is_a_bounded_pass() -> None:
    entry = next(item for item in load_instances(ROOT) if item["domain"] == "stable_matching")
    verifier = load_verifier(ROOT, entry["domain"])
    harness = VerifierGuidedHarness(ROOT)
    accepted = harness.run_arm_a(entry["instance_id"], verifier, entry["instance"])
    candidate = accepted.record["stable_payload"]["candidate"]
    trial = harness.run_arm_b(
        entry["instance_id"], verifier, entry["instance"], FixtureLm({"candidate": candidate}), "", ""
    )
    assert trial.record["stable_payload"]["route_status"] == "CANDIDATE_ACCEPTED"
    assert trial.record["stable_payload"]["bounded_claim_status"] == "PASS"
    assert trial.record["stable_payload"]["lm_observation"]["input_tokens"] == 3
    assert trial.record["stable_payload"]["lm_observation"]["output_tokens"] == 5
    assert trial.metrics["accepted"] is True
    assert trial.metrics["vstd_reverification_errors"] == []


def test_arm_b_native_rejection_is_bound_and_remains_unknown() -> None:
    entry = next(item for item in load_instances(ROOT) if item["domain"] == "stable_matching")
    verifier = load_verifier(ROOT, entry["domain"])
    trial = VerifierGuidedHarness(ROOT).run_arm_b(
        entry["instance_id"],
        verifier,
        entry["instance"],
        FixtureLm({"candidate": {"matching": []}}),
        "",
        "",
    )
    stable = trial.record["stable_payload"]
    assert stable["route_status"] == "CANDIDATE_REJECTED"
    assert stable["bounded_claim_status"] == "UNKNOWN"
    assert stable["failure_observation"]["stage"] == "native_verifier"
    assert trial.metrics["final_unknown"] is True


def test_outer_proposal_fields_fail_closed() -> None:
    entry = next(item for item in load_instances(ROOT) if item["domain"] == "stable_matching")
    verifier = load_verifier(ROOT, entry["domain"])
    trial = VerifierGuidedHarness(ROOT).run_arm_c(
        entry["instance_id"],
        verifier,
        entry["instance"],
        FixtureLm({"route": {}, "ignored": "must-not-be-ignored"}),
        "",
        "",
    )
    stable = trial.record["stable_payload"]
    assert stable["bounded_claim_status"] == "UNKNOWN"
    assert stable["failure_observation"]["stage"] == "proposal_contract"


def test_real_backend_failure_is_bound_as_unknown() -> None:
    entry = next(item for item in load_instances(ROOT) if item["domain"] == "stable_matching")
    verifier = load_verifier(ROOT, entry["domain"])
    trial = VerifierGuidedHarness(ROOT).run_arm_b(
        entry["instance_id"],
        verifier,
        entry["instance"],
        FixtureLm(error=LmResponseError("real LM request failed: TimeoutError", elapsed_ns=23)),
        "",
        "",
    )
    stable = trial.record["stable_payload"]
    assert stable["bounded_claim_status"] == "UNKNOWN"
    assert stable["failure_observation"]["stage"] == "lm_generation"
    assert stable["timings_ns"]["lm_generation"] == 23
    assert trial.metrics["vstd_reverification_errors"] == []
