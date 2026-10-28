"""Physical-boundary regressions for CONTROLLER, ACTUATOR, and ROBOT.

Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256).  The
installed emulator may establish only its finite simulated routes.  A ROBOT
certificate with no selected source evidence must expose each external
physical proposition as NOT_ESTABLISHED instead of letting one broad safety or
actuation field obscure the missing endpoint-specific evidence.
"""
from __future__ import annotations

import pytest

from verifier.domains.contracts import robot_checks


_DIGEST = "sha256:" + "0" * 64
_PHYSICAL_UNKNOWN_FIELDS = (
    "physical_endpoint_identity",
    "physical_effect_feedback",
    "physical_interlock_execution",
    "physical_stability",
    "command_authority",
    "operating_limit_adequacy",
    "intervention_execution",
)


@pytest.mark.parametrize("check", tuple(robot_checks.CHECKS))
def test_robot_without_source_evidence_exposes_each_physical_unknown(check: str) -> None:
    """Missing evidence stays UNKNOWN and names every unsupported physical claim."""
    policy = robot_checks.robot_checks_policy(trust_roots=["retained-boundary-test"])
    request = robot_checks.robot_checks_request(
        check=check,
        subject_id="robot-under-test",
        source_digest=_DIGEST,
        evidence_ref=_DIGEST,
        policy=policy,
    )
    certificate = robot_checks.build_robot_checks_certificate(
        request, None, policy=policy
    )
    result = robot_checks.recheck_robot_checks_certificate(
        certificate, expected_request=request, policy=policy
    )

    assert result["status"] == "UNKNOWN"
    assert result["evaluation"]["reason"] == "selected retained evidence is unavailable"
    assert {
        field: result.get(field) for field in _PHYSICAL_UNKNOWN_FIELDS
    } == {field: "NOT_ESTABLISHED" for field in _PHYSICAL_UNKNOWN_FIELDS}


def test_emulator_routes_never_claim_a_physical_boundary() -> None:
    """A passing emulator route remains a simulated software observation only."""
    from verifier.runtime import emulator_control_execution as execution

    assert {row["object_kind"] for row in execution.catalog()} == {
        "CONTROLLER",
        "ACTUATOR",
    }
    for route in execution.catalog():
        claim = route["exact_claim"].lower()
        assert "not_established" in claim
        assert not any(
            phrase in claim
            for phrase in (
                "physical effect is established",
                "physical stability is established",
                "real-world actuation is established",
                "physical recovery is established",
            )
        )
