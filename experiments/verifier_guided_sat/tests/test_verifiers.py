from __future__ import annotations

from pathlib import Path

import pytest

from verifier_guided_sat.contracts import NativeVerdict
from verifier_guided_sat.external_verifiers import load_verifier
from verifier_guided_sat.harness import VerifierGuidedHarness
from verifier_guided_sat.instances import load_instances
from verifier_guided_sat.reserve_verifiers import verify_with_reserve


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("domain", ["stable_matching", "graph_isomorphism", "integer_factorization"])
def test_complete_baseline_reaches_native_and_reserve_acceptance(domain: str) -> None:
    entry = next(item for item in load_instances(ROOT) if item["domain"] == domain)
    verifier = load_verifier(ROOT, domain)
    trial = VerifierGuidedHarness(ROOT).run_arm_a(entry["instance_id"], verifier, entry["instance"])
    assert trial.metrics["accepted"] is True
    assert trial.metrics["false_acceptance"] is False
    assert trial.metrics["vstd_reverification_errors"] == []
    reserve = verify_with_reserve(domain, entry["instance"], trial.record["stable_payload"]["candidate"])
    assert reserve.verdict is NativeVerdict.ACCEPTED


@pytest.mark.parametrize("domain", ["stable_matching", "graph_isomorphism", "integer_factorization"])
def test_primary_and_reserve_reject_bounded_bad_candidate(domain: str) -> None:
    entry = next(item for item in load_instances(ROOT) if item["domain"] == domain)
    verifier = load_verifier(ROOT, domain)
    bad = {
        "stable_matching": {"matching": []},
        "graph_isomorphism": {"mapping": []},
        "integer_factorization": {"p": 1, "q": 1},
    }[domain]
    assert verifier.verify(entry["instance"], bad).verdict is NativeVerdict.REJECTED
    assert verify_with_reserve(domain, entry["instance"], bad).verdict is NativeVerdict.REJECTED


def test_contract_has_complete_result_and_claim_boundaries() -> None:
    contract = load_verifier(ROOT, "stable_matching").contract.to_dict()
    assert set(contract["result_semantics"]) == {"accepted", "rejected", "error", "indeterminate"}
    assert contract["resource_limits"]
    assert contract["candidate_canonicalization"]
    assert "global nonexistence of a witness" in contract["neither_proves"]
