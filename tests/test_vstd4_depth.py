"""The ladder internal to VSTD-4, and the gate it guards.

``vstd4_depth`` is computed, never declared. That is the whole point: standing
up an external verification node is VSTD-5, and reaching it must be
*computationally costly*, because verification is the new scaling. A rung that
could be declared would let an implementer skip the climb.

The tests below check the two halves of an honest answer. The witness certifies
the rungs that were climbed; the refutation certifies why the next one was not,
and its conflict clause names the missing rung. Both are checked by the same
kernel that checks any other VSTD-4 claim -- the layer certifies its own ceiling
using its own mechanism.
"""

from __future__ import annotations

import pytest

from verifier.core.certificate import (
    ClaimBinding,
    ClaimCoordinate,
    CostTier,
    ResourceBounds,
    Verdict,
)
from verifier.core.depth import (
    BY_ID,
    MAX_DEPTH,
    RUNGS,
    DepthResult,
    VSTD5EntryError,
    require_vstd5_entry,
    vstd4_depth,
)
from verifier.core.kernel import KernelOutcome, check, is_horn, reference_descriptor

CLAIM = "claim:accuracy-0.95"
BUDGET = 10_000


def _binding() -> ClaimBinding:
    return ClaimBinding(
        claim="accuracy >= 0.95",
        coordinate=ClaimCoordinate("model:sha256:ab", "accuracy"),
        policy_root="sha256:policy",
        evidence_root="sha256:evidence",
        verifier=reference_descriptor(),
        bounds=ResourceBounds(BUDGET, BUDGET, BUDGET),
    )


def _evidence(*, without: tuple[str, ...] = (), only: int | None = None) -> dict[str, str]:
    rungs = RUNGS if only is None else RUNGS[:only]
    return {
        rung.id: f"sha256:evidence-{rung.id}"
        for rung in rungs
        if rung.id not in without
    }


def _depth(evidence: dict[str, str]) -> DepthResult:
    return vstd4_depth(evidence, claim_id=CLAIM, binding=_binding())


def _assert_certificates_check(result: DepthResult) -> None:
    binding = _binding()
    for certificate in (result.witness, result.refutation):
        if certificate is None:
            continue
        assert is_horn(certificate.formula)
        assert certificate.header.tier is CostTier.UP
        verdict = check(certificate, budget=BUDGET, binding=binding)
        assert verdict.outcome is KernelOutcome.ACCEPTED, verdict.details


# --------------------------------------------------------------------------
# The ladder itself
# --------------------------------------------------------------------------


def test_the_ladder_is_a_topological_order():
    """Each rung is unstatable without the one below it, and the numbering says so."""
    assert len(RUNGS) == MAX_DEPTH
    for rung in RUNGS:
        for dependency in rung.depends_on:
            assert dependency < rung.index, f"{rung.id} depends upward on {dependency}"


def test_the_top_rung_depends_on_every_other():
    """4.14 is the handoff: only fully-defined refutability can be propagated."""
    top = BY_ID["4.14"]
    assert set(top.depends_on) == set(range(1, MAX_DEPTH))


# --------------------------------------------------------------------------
# Computed depth
# --------------------------------------------------------------------------


def test_full_evidence_reaches_the_top_and_admits_vstd5():
    result = _depth(_evidence())
    assert result.depth == MAX_DEPTH
    assert result.admits_vstd5 is True
    assert result.refutation is None
    assert result.blocking_rungs == ()
    assert result.witness is not None
    assert result.witness.header.verdict is Verdict.PASS
    _assert_certificates_check(result)


def test_a_missing_rung_caps_the_depth_below_it_and_is_named():
    result = _depth(_evidence(without=("4.8",)))
    assert result.depth == 7
    assert result.admits_vstd5 is False
    assert result.blocking_rungs == ("4.8",)
    assert result.refutation is not None
    assert result.refutation.header.verdict is Verdict.FAIL
    _assert_certificates_check(result)


def test_the_refutation_is_the_explanation_not_a_separate_report():
    """The UNSAT certificate at k+1 *is* why the claim cannot climb higher."""
    result = _depth(_evidence(without=("4.11",)))
    assert result.depth == 10
    assert result.refutation is not None

    proof = result.refutation.decision.propagation
    assert proof is not None
    conflict = result.refutation.grounding.clauses[proof.conflict_clause_index]
    assert conflict.rule_id == "RULE:RUNG_ABSENT"
    assert conflict.bindings["rung"] == BY_ID["4.11"].index


def test_removing_evidence_can_only_lower_the_depth():
    """Rung 4.13, applied to the ladder itself: weakening never strengthens."""
    baseline = _depth(_evidence()).depth
    previous = baseline
    for rung in reversed(RUNGS):
        result = _depth(_evidence(without=(rung.id,)))
        assert result.depth <= previous or result.depth <= baseline
        assert result.depth < baseline
        assert result.depth == rung.index - 1
        previous = result.depth


def test_depth_is_monotone_in_the_prefix():
    for level in range(0, MAX_DEPTH + 1):
        result = _depth(_evidence(only=level))
        assert result.depth == level
        _assert_certificates_check(result)


def test_no_evidence_is_depth_zero_with_a_refutation_and_no_witness():
    result = _depth({})
    assert result.depth == 0
    assert result.witness is None
    assert result.refutation is not None
    assert result.blocking_rungs == ("4.1",)
    _assert_certificates_check(result)


def test_the_vstd5_gate_refuses_anything_below_fourteen():
    """Layer 4 asks *could a stranger check this?*; layer 5 asks *did one?*"""
    for level in range(0, MAX_DEPTH):
        result = _depth(_evidence(only=level))
        assert result.admits_vstd5 is False
        with pytest.raises(VSTD5EntryError, match="requires computed vstd4_depth"):
            require_vstd5_entry(result)
    complete = _depth(_evidence())
    assert complete.admits_vstd5 is True
    assert require_vstd5_entry(complete) is complete


def test_unknown_rung_ids_are_refused():
    with pytest.raises(ValueError, match="rungs that do not exist"):
        vstd4_depth({"4.99": "sha256:x"}, claim_id=CLAIM, binding=_binding())


def test_depth_summary_carries_both_certificate_digests():
    summary = _depth(_evidence(without=("4.5",))).to_dict()
    assert summary["depth"] == 4
    assert summary["admits_vstd5"] is False
    assert summary["blocking_rungs"] == ["4.5"]
    assert summary["witness_digest"] is not None
    assert summary["refutation_digest"] is not None
    assert summary["witness_digest"] != summary["refutation_digest"]
