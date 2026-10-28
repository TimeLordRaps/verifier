from __future__ import annotations

from verifier_guided_sat.analysis import classify_live_result


def _trial(instance_id: str, domain: str, arm: str, *, accepted: bool, work: int) -> dict:
    return {
        "instance_id": instance_id,
        "domain": domain,
        "arm": arm,
        "metrics": {
            "accepted": accepted,
            "false_acceptance": False,
            "final_unknown": not accepted,
            "generate_and_check_equivalent": arm == "B",
            "vstd_reverification_errors": [],
            "decisions": work,
            "conflicts": work,
            "propagations": work,
            "elapsed_ns": work,
            "total_time_to_outcome_ns": work,
        },
        "record": {"stable_payload": {"failure_observation": None}},
    }


def test_classifier_recognizes_complete_primary_success_shape() -> None:
    baseline = []
    live = []
    for domain in ("stable_matching", "graph_isomorphism", "integer_factorization"):
        for index in range(20):
            instance_id = f"{domain}-{index:03d}"
            baseline.append(_trial(instance_id, domain, "A", accepted=True, work=100))
            live.append(_trial(instance_id, domain, "B", accepted=True, work=0))
            live.append(_trial(instance_id, domain, "C", accepted=True, work=10))
    analysis = classify_live_result(live, baseline, success_threshold=0.1)
    assert analysis["status"] == "PRIMARY_SUCCESS"
    assert analysis["primary_success"] is True


def test_classifier_preserves_real_lm_runtime_blocker() -> None:
    blocked = _trial("development-000", "stable_matching", "B", accepted=False, work=0)
    blocked["record"]["stable_payload"]["failure_observation"] = {
        "stage": "lm_generation",
        "status": "ERROR",
    }
    analysis = classify_live_result([blocked], [], success_threshold=0.1)
    assert analysis["status"] == "BLOCKED_NO_REAL_LM_RUNTIME"
