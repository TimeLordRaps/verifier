"""One-file reason authority regressions for compiled package obligations."""
from __future__ import annotations

from verifier.runtime.tier_zero_reasoning import reasons_dsl


def test_root_reason_can_name_one_exact_object_obligation_decision() -> None:
    """Higher-tier applicability belongs in reasons.vstd, not a Python ledger."""

    source = """\
reason verifier-core-self-actuator-1-1
  about    verifier-core-self
  claim    obligation verifier-core-self ACTUATOR-1.1-simulated-command-to-effect REQUIRED
  basis    declared src/verifier/runtime/package_polish.py src/verifier/runtime/package_verifier_graph.py
  note     The aggregate verifier owns the package checking path, so its simulated command-to-effect route remains in the Tier 1 denominator.
"""

    parsed = reasons_dsl.parse(source, "reasons.vstd")

    assert parsed["errors"] == []
    assert parsed["malformed"] == {}
    assert parsed["ir"]["reasons"] == [{
        "id": "verifier-core-self-actuator-1-1",
        "about": ["verifier-core-self"],
        "claim": {
            "form": "obligation",
            "object": "verifier-core-self",
            "coordinate": "ACTUATOR-1.1-simulated-command-to-effect",
            "decision": "REQUIRED",
        },
        "basis": [{
            "kind": "declared",
            "evidence": [
                "src/verifier/runtime/package_polish.py",
                "src/verifier/runtime/package_verifier_graph.py",
            ],
        }],
        "note": (
            "The aggregate verifier owns the package checking path, so its "
            "simulated command-to-effect route remains in the Tier 1 denominator."
        ),
    }]


def test_root_reason_refuses_an_obligation_decision_that_could_weaken_the_denominator() -> None:
    source = """\
reason verifier-core-self-actuator-1-1
  about    verifier-core-self
  claim    obligation verifier-core-self ACTUATOR-1.1-simulated-command-to-effect DOES_NOT_APPLY
  basis    declared src/verifier/runtime/package_polish.py
  note     A reason must not withdraw a compiled obligation.
"""

    parsed = reasons_dsl.parse(source, "reasons.vstd")

    assert parsed["errors"] == []
    assert parsed["ir"]["reasons"] == []
    assert "verifier-core-self-actuator-1-1" in parsed["malformed"]
    assert "decision must be one of REQUIRED" in parsed["malformed"][
        "verifier-core-self-actuator-1-1"
    ][0]
