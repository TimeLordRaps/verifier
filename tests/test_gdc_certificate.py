"""Terminology: conjunctive normal form (CNF); grounded decision certificate (GDC);
Boolean satisfiability problem (SAT); trusted computing base (TCB); unsatisfiable (UNSAT);
Verifier Standard (VSTD).

``VSTD4-GDC-1`` conformance, and regressions pinning the three retrofits.

The tests that matter most here are the ones no competition proof format could
express: the keystone test, where a decision block is perfectly valid and the
grounding points at the wrong artifact, and the tier-inflation test, where a
linear-time check is dressed in general-resolution machinery to look rigorous.

The retrofit regressions at the bottom assert that the *old* behaviour is gone,
not merely that the new behaviour works. Three things shipped that layer 4
prohibits, and a test that only exercises the fix would pass again the moment
someone reintroduced the shortcut beside it.
"""

from __future__ import annotations

import ast
from dataclasses import replace
from itertools import product
from pathlib import Path

import pytest

from verifier.core.certificate import (
    CertificateHeader,
    ClaimBinding,
    ClaimCoordinate,
    ClauseGrounding,
    CostTier,
    DecisionBlock,
    DecisionCertificate,
    EncodingRule,
    FORMAT,
    GroundedFact,
    Grounding,
    IndeterminacyReason,
    IndeterminacyTranscript,
    PropagationStep,
    ResolutionProof,
    ResourceBounds,
    UnitPropagationProof,
    VariableGrounding,
    Verdict,
    canonical_bytes,
    canonical_digest,
    certificate_from_canonical_bytes,
    normalize_clause,
)
from verifier.core.grounding import verify_grounding
from verifier.core.kernel import (
    KernelOutcome,
    check,
    is_horn,
    reference_descriptor,
    tightest_tier,
    violating_subjects,
)
from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    RightsSpec,
    TransformationHyperedge,
    TransformationType,
)
from verifier.data.policy import (
    PolicyEncodingError,
    ProvenancePolicyVerifier,
    certify_policy_cnf,
    ground_policy_cnf,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

TARGET = "artifact:target"
ANCESTOR = "artifact:ancestor-1"

RULES = (
    EncodingRule("ASSERT_TARGET", ("target",), ((1, "target"),)),
    EncodingRule(
        "TARGET_REQUIRES", ("target", "member"), ((-1, "target"), (1, "member"))
    ),
    EncodingRule("MEMBER_VIOLATES", ("member",), ((-1, "member"),)),
)

FORMULA = ((1,), (-1, 2), (-2,))


def _binding(claim: str = "no ancestor is revoked") -> ClaimBinding:
    return ClaimBinding(
        claim=claim,
        coordinate=ClaimCoordinate(TARGET, "no_revoked_ancestors"),
        policy_root=canonical_digest([list(clause) for clause in FORMULA]),
        evidence_root=canonical_digest([TARGET, ANCESTOR]),
        verifier=reference_descriptor(),
        bounds=ResourceBounds(1000, 1000, 10000),
    )


def _grounding(ancestor: str = ANCESTOR) -> Grounding:
    return Grounding(
        variables=(
            VariableGrounding(1, GroundedFact(TARGET, "policy_admissible", "ASSERTED")),
            VariableGrounding(2, GroundedFact(ancestor, "clean", "REVOKED")),
        ),
        clauses=(
            ClauseGrounding(0, "ASSERT_TARGET", {"target": 1}, {"target": TARGET}),
            ClauseGrounding(
                1,
                "TARGET_REQUIRES",
                {"target": 1, "member": 2},
                {"target": TARGET, "member": ancestor},
            ),
            ClauseGrounding(2, "MEMBER_VIOLATES", {"member": 2}, {"member": ancestor}),
        ),
        rules=RULES,
    )


def _fail_certificate(**overrides) -> DecisionCertificate:
    binding = overrides.pop("binding", _binding())
    grounding = overrides.pop("grounding", _grounding())
    header = CertificateHeader(
        Verdict.FAIL,
        overrides.pop("tier", CostTier.UP),
        2,
        3,
        4,
        2,
        binding.digest(),
        width=overrides.pop("width", 0),
    )
    decision = overrides.pop(
        "decision",
        DecisionBlock(
            propagation=UnitPropagationProof(
                (PropagationStep(0, 1), PropagationStep(1, 2)), 2
            )
        ),
    )
    assert not overrides, overrides
    return DecisionCertificate(header, FORMULA, grounding, decision)


# --------------------------------------------------------------------------
# The format checks
# --------------------------------------------------------------------------


def test_horn_refutation_is_accepted_and_names_the_offender():
    certificate = _fail_certificate()
    result = check(certificate, budget=1000, binding=_binding())
    assert result.outcome is KernelOutcome.ACCEPTED
    assert result.verdict is Verdict.FAIL
    assert result.steps_checked == 2
    # The conflict clause's grounding is the counterexample. For an enumerable
    # universal that is the whole refutation -- no resolution proof required.
    assert violating_subjects(certificate) == (ANCESTOR,)


def test_enumerable_universal_needs_no_resolution_proof():
    """FAIL over "every ancestor is clean" is a witness, not a proof search."""
    certificate = _fail_certificate()
    assert certificate.decision.resolution is None
    assert certificate.decision.propagation is not None
    assert certificate.header.tier is CostTier.UP

    with_proof = _fail_certificate(
        decision=DecisionBlock(
            propagation=certificate.decision.propagation,
            resolution=ResolutionProof(steps=((),)),
        )
    )
    result = check(with_proof, budget=1000)
    assert result.outcome is KernelOutcome.REJECTED
    assert "general resolution is inadmissible" in result.details


def test_tier_inflation_over_a_horn_formula_is_rejected():
    """The tightest admissible tier is mandatory, not a stylistic choice."""
    assert is_horn(FORMULA)
    assert tightest_tier(FORMULA) is CostTier.UP

    inflated = _fail_certificate(
        tier=CostTier.RES, decision=DecisionBlock(resolution=ResolutionProof(steps=((),)))
    )
    result = check(inflated, budget=1000)
    assert result.outcome is KernelOutcome.REJECTED
    assert "Horn" in result.details and "mandatory" in result.details


def test_width_k_without_a_width_is_rejected():
    """A WIDTH-K header with no width advertises a bound it does not carry."""
    formula = ((1, 2), (1, -2), (-1, 2), (-1, -2))
    binding = _binding()
    rules = tuple(
        EncodingRule(f"R{index}", ("a", "b"), template)
        for index, template in enumerate(
            (
                ((1, "a"), (1, "b")),
                ((1, "a"), (-1, "b")),
                ((-1, "a"), (1, "b")),
                ((-1, "a"), (-1, "b")),
            )
        )
    )
    subjects = {"a": TARGET, "b": ANCESTOR}
    grounding = Grounding(
        (
            VariableGrounding(1, GroundedFact(TARGET, "flag", "?")),
            VariableGrounding(2, GroundedFact(ANCESTOR, "flag", "?")),
        ),
        tuple(
            ClauseGrounding(index, rule.rule_id, {"a": 1, "b": 2}, dict(subjects))
            for index, rule in enumerate(rules)
        ),
        rules,
    )
    proof = DecisionBlock(resolution=ResolutionProof(steps=((1,), (-1,), ())))

    def certificate(width: int) -> DecisionCertificate:
        header = CertificateHeader(
            Verdict.FAIL, CostTier.WIDTH_K, 2, 4, 8, 3, binding.digest(), width=width
        )
        return DecisionCertificate(header, formula, grounding, proof)

    assert check(certificate(0), budget=99).outcome is KernelOutcome.REJECTED
    assert check(certificate(1), budget=99).outcome is KernelOutcome.ACCEPTED


def test_cost_refusal_happens_before_any_checking():
    """Rung 4.5: the header states the cost, so refusal costs nothing."""
    result = check(_fail_certificate(), budget=2)
    assert result.outcome is KernelOutcome.REFUSED
    assert result.verdict is Verdict.UNKNOWN
    assert result.reason is IndeterminacyReason.PROOF_BOUND_EXCEEDED
    assert result.literals_processed == 0
    assert result.steps_checked == 0


def test_understated_header_cannot_buy_its_way_past_the_budget():
    """A small lying header must not induce unbounded work before detection."""
    binding = _binding()
    big = tuple((index,) for index in range(1, 200))
    header = CertificateHeader(Verdict.PASS, CostTier.UP, 199, 199, 1, 0, binding.digest())
    grounding = Grounding(
        tuple(VariableGrounding(index, GroundedFact(f"a{index}", "p", "v")) for index in range(1, 200)),
        tuple(
            ClauseGrounding(index - 1, "MEMBER", {"member": index}, {"member": f"a{index}"})
            for index in range(1, 200)
        ),
        (EncodingRule("MEMBER", ("member",), ((1, "member"),)),),
    )
    certificate = DecisionCertificate(
        header, big, grounding, DecisionBlock(model={i: True for i in range(1, 200)})
    )
    result = check(certificate, budget=5)
    assert result.outcome is KernelOutcome.REFUSED
    assert result.reason is IndeterminacyReason.PROOF_BOUND_EXCEEDED
    assert result.literals_processed <= 6


def test_understated_step_count_is_refused_before_proof_replay():
    base = _fail_certificate()
    lying_header = replace(base.header, step_count=0)
    certificate = replace(base, header=lying_header)

    refused = check(certificate, budget=5)
    assert refused.outcome is KernelOutcome.REFUSED
    assert refused.steps_checked == 0
    assert refused.literals_processed == 0

    rejected = check(certificate, budget=1000)
    assert rejected.outcome is KernelOutcome.REJECTED
    assert "decision block contains 2" in rejected.details


@pytest.mark.parametrize(
    ("bounds", "message"),
    (
        (ResourceBounds(5, 1000, 10000), "checking cost"),
        (ResourceBounds(1000, 2, 10000), "memory bound"),
        (ResourceBounds(1000, 1000, 10), "canonical certificate size"),
    ),
)
def test_committed_resource_bounds_are_enforced_before_decision_checking(bounds, message):
    binding = replace(_binding(), bounds=bounds)
    certificate = _fail_certificate(binding=binding)
    result = check(certificate, budget=1000, binding=binding)
    assert result.outcome is KernelOutcome.REFUSED
    assert result.steps_checked == 0
    assert message in result.details


def test_decision_arms_are_mutually_exclusive():
    base = _fail_certificate()
    transcript = IndeterminacyTranscript(
        IndeterminacyReason.DEPENDENCY_UNAVAILABLE,
        canonical_digest([list(clause) for clause in FORMULA]),
        declared_bound=1,
        observed_cost=1,
    )
    malformed = replace(
        base,
        decision=replace(base.decision, transcript=transcript),
    )
    result = check(malformed, budget=1000)
    assert result.outcome is KernelOutcome.REJECTED
    assert "requires only the propagation decision arm" in result.details


def test_resource_bounds_cannot_be_negative():
    with pytest.raises(Exception, match="cannot be negative"):
        ResourceBounds(-1, 0, 0)


def test_sat_preserving_is_refused_not_mis_accepted():
    """A tier this kernel does not implement is UNKNOWN, never a verdict."""
    assert not reference_descriptor().implements(CostTier.SAT_PRESERVING)
    certificate = _fail_certificate(tier=CostTier.SAT_PRESERVING)
    result = check(certificate, budget=1000)
    assert result.outcome is KernelOutcome.REFUSED
    assert result.reason is IndeterminacyReason.VERIFIER_UNAVAILABLE


# --------------------------------------------------------------------------
# Grounding -- rung 4.2
# --------------------------------------------------------------------------


def test_grounding_rejects_a_variable_with_no_fact():
    partial = Grounding(
        variables=_grounding().variables[:1],
        clauses=_grounding().clauses,
        rules=RULES,
    )
    result = verify_grounding(FORMULA, partial)
    assert not result.accepted
    assert "no grounded fact" in result.details


def test_grounding_rejects_a_clause_that_is_not_an_instance_of_its_rule():
    base = _grounding()
    mislabelled = Grounding(
        variables=base.variables,
        clauses=(
            base.clauses[0],
            base.clauses[1],
            # Clause 2 is [-2] but is declared an instance of TARGET_REQUIRES.
            ClauseGrounding(
                2,
                "TARGET_REQUIRES",
                {"target": 1, "member": 2},
                {"target": TARGET, "member": ANCESTOR},
            ),
        ),
        rules=RULES,
    )
    result = verify_grounding(FORMULA, mislabelled)
    assert not result.accepted
    assert "is not an instance of" in result.details


def test_keystone_valid_proof_of_the_wrong_artifact_is_rejected():
    """The failure no competition proof format can see.

    The decision block below is *correct*. Replay it and unit propagation really
    does reach a conflict. What is wrong is that the clause claims to be about
    one artifact while the variable it binds is grounded in a fact about
    another -- an impeccable proof of the wrong formula.
    """
    honest = _fail_certificate()
    assert check(honest, budget=1000).outcome is KernelOutcome.ACCEPTED

    base = _grounding()
    wrong = Grounding(
        variables=base.variables,
        clauses=(
            base.clauses[0],
            base.clauses[1],
            ClauseGrounding(
                2, "MEMBER_VIOLATES", {"member": 2}, {"member": "artifact:somebody-else"}
            ),
        ),
        rules=RULES,
    )
    forged = _fail_certificate(grounding=wrong)
    assert forged.decision == honest.decision

    result = check(forged, budget=1000)
    assert result.outcome is KernelOutcome.REJECTED
    assert "artifact:somebody-else" in result.details
    assert ANCESTOR in result.details


def test_binding_mismatch_is_rejected():
    """Rung 4.3: a certificate must be about the claim it is presented against."""
    result = check(_fail_certificate(), budget=1000, binding=_binding("a different claim"))
    assert result.outcome is KernelOutcome.REJECTED
    assert "not about this claim" in result.details


# --------------------------------------------------------------------------
# Hints, transcripts, serialization
# --------------------------------------------------------------------------


def test_hint_corruption_cannot_change_a_verdict():
    """Soundness may not depend on a field whose corruption is undetectable."""
    base = _fail_certificate()
    clean = check(base, budget=1000)

    for hints in ({"note": "fast path"}, {"note": "garbage"}, {"conflict": 999}):
        corrupted = DecisionCertificate(
            base.header, base.formula, base.grounding, base.decision, hints
        )
        result = check(corrupted, budget=1000)
        assert result.outcome is clean.outcome
        assert result.verdict is clean.verdict
        assert result.details == clean.details
        assert result.hints_present is True
        assert check(corrupted.without_hints(), budget=1000).details == clean.details


def test_unknown_carries_a_replayable_transcript_not_a_claim_of_no_proof():
    good = IndeterminacyTranscript(
        IndeterminacyReason.PROOF_BOUND_EXCEEDED,
        canonical_digest([list(clause) for clause in FORMULA]),
        declared_bound=3,
        observed_cost=9,
        stopped_at_step=3,
    )
    header = CertificateHeader(
        Verdict.UNKNOWN, CostTier.UP, 2, 3, 4, 0, _binding().digest()
    )
    certificate = DecisionCertificate(
        header, FORMULA, _grounding(), DecisionBlock(transcript=good)
    )
    result = check(certificate, budget=1000)
    assert result.outcome is KernelOutcome.ACCEPTED
    assert result.verdict is Verdict.UNKNOWN

    # A transcript claiming exhaustion while reporting a cost inside its own
    # bound is not evidence of anything.
    liar = IndeterminacyTranscript(
        IndeterminacyReason.PROOF_BOUND_EXCEEDED,
        good.formula_digest,
        declared_bound=9,
        observed_cost=3,
    )
    rejected = check(
        DecisionCertificate(header, FORMULA, _grounding(), DecisionBlock(transcript=liar)),
        budget=1000,
    )
    assert rejected.outcome is KernelOutcome.REJECTED

    # A transcript about some other formula does not describe this refusal.
    wrong = IndeterminacyTranscript(
        IndeterminacyReason.PROOF_BOUND_EXCEEDED, "0" * 64, 3, 9
    )
    assert (
        check(
            DecisionCertificate(header, FORMULA, _grounding(), DecisionBlock(transcript=wrong)),
            budget=1000,
        ).outcome
        is KernelOutcome.REJECTED
    )


def test_unknown_without_a_transcript_is_not_a_verdict():
    header = CertificateHeader(
        Verdict.UNKNOWN, CostTier.UP, 2, 3, 4, 0, _binding().digest()
    )
    result = check(
        DecisionCertificate(header, FORMULA, _grounding(), DecisionBlock()), budget=1000
    )
    assert result.outcome is KernelOutcome.REJECTED
    assert "without evidence" in result.details


def test_canonical_round_trip_and_binding_digest():
    certificate = _fail_certificate()
    raw = canonical_bytes(certificate.to_dict())
    decoded = certificate_from_canonical_bytes(raw)
    assert decoded == certificate
    assert canonical_bytes(decoded.to_dict()) == raw
    assert certificate.digest() == canonical_digest(certificate.to_dict())
    assert certificate.header.binding == _binding().digest()
    assert certificate.header.format == FORMAT


def test_parser_rejects_noncanonical_certificate_bytes():
    certificate = _fail_certificate()
    raw = canonical_bytes(certificate.to_dict()) + b"\n"
    with pytest.raises(Exception, match="not in canonical form"):
        certificate_from_canonical_bytes(raw)


def test_normalize_clause_is_order_and_duplicate_insensitive():
    assert normalize_clause([2, -1, 2]) == normalize_clause([-1, 2]) == (-1, 2)
    with pytest.raises(Exception):
        normalize_clause([0])


# --------------------------------------------------------------------------
# Rung 4.7 -- the isolation claim, checked rather than asserted
# --------------------------------------------------------------------------


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(f"{'.' * node.level}{node.module or ''}")
    return names


def test_kernel_shares_no_code_with_any_verdict_producer():
    """The isolation claim that ``TCB`` used to make only in prose."""
    forbidden = {"checker", "refutation", "policy", "run", "receipt", "builder"}
    for module in ("kernel.py", "certificate.py", "grounding.py"):
        path = REPO_ROOT / "src" / "verifier" / "core" / module
        for imported in _imported_modules(path):
            tail = imported.lstrip(".").split(".")[-1]
            assert tail not in forbidden, f"{module} imports {imported}"


def test_kernel_stays_small_enough_to_reimplement():
    """Rung 4.7 is a size claim as much as a semantic one."""
    source = (REPO_ROOT / "src" / "verifier" / "core" / "kernel.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    executable = sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.stmt) and not isinstance(node, (ast.Expr, ast.ClassDef))
    )
    assert executable < 400, f"kernel has grown to {executable} statements"


# --------------------------------------------------------------------------
# Regressions pinning the three retrofits -- the OLD behaviour must be gone
# --------------------------------------------------------------------------


def test_conflicting_clause_is_never_just_the_first_clause():
    """Was: ``conflicting_clause = list(clauses[0])`` on any UNSAT result."""
    from verifier.core.checker import IndependentAuditor

    # Horn, and the genuine conflict is the LAST clause, not the first.
    report = IndependentAuditor.audit_claim_derivation(
        "claim", 2, [[1], [-1, 2], [-2]], [], expected_satisfiable=False
    )
    assert report.sat_result.conflicting_clause == [-2]
    assert report.sat_result.conflicting_clause != [1]

    # Where propagation reaches no conflict, the honest answer is None -- not
    # an arbitrary clause dressed up as a conflict analysis.
    searched = IndependentAuditor.audit_claim_derivation(
        "claim", 2, [[1, 2], [1, -2], [-1, 2], [-1, -2]], [], expected_satisfiable=False
    )
    assert searched.sat_result.conflicting_clause is None
    assert "search was required" in searched.audit_notes[-1]


def test_trusted_computing_base_is_hashes_not_a_literal_dict():
    """Was: a hardcoded dict asserting its own isolation."""
    from verifier.core import checker
    from verifier.core.checker import IndependentAuditor

    assert not hasattr(IndependentAuditor, "TCB"), (
        "the self-reported TCB dict is back"
    )

    descriptor = IndependentAuditor.verifier_descriptor()
    assert descriptor.implementation_hash.startswith("sha256:")
    assert descriptor.specification_hash.startswith("sha256:")

    # Computed from the file on disk, not from a string constant.
    import hashlib

    expected = "sha256:" + hashlib.sha256(
        Path(checker.__file__).read_bytes()
    ).hexdigest()
    assert descriptor.implementation_hash == expected

    # And it declares what it actually implements, not VSTD4-GDC-1.
    assert descriptor.certificate_format != FORMAT
    assert "isolation" not in IndependentAuditor.tcb()


def _graph_with_revoked_ancestor() -> ProvenanceHypergraph:
    graph = ProvenanceHypergraph()
    for artifact_id, status in (
        (TARGET, ArtifactStatus.VALID),
        (ANCESTOR, ArtifactStatus.REVOKED),
    ):
        graph.add_artifact(
            ArtifactNode(
                artifact_id=artifact_id,
                label=artifact_id,
                artifact_type=ArtifactType.RAW_SOURCE_FILE,
                content_digest="0" * 64,
                status=status,
            )
        )
    graph.add_transformation(
        TransformationHyperedge(
            transformation_id="transform:derive",
            label="derive target from ancestor",
            transformation_type=TransformationType.EVALUATION,
            inputs=(HyperedgePort(ANCESTOR, "INPUT"),),
            outputs=(HyperedgePort(TARGET, "OUTPUT"),),
            software_provenance={},
            parameters={},
            execution_environment={},
        )
    )
    return graph


def test_policy_verdict_comes_from_the_certified_encoding():
    """Was: ``passed = bool(sat and not revoked_nodes)`` -- the list decided."""
    graph = _graph_with_revoked_ancestor()
    assert ANCESTOR in graph.ancestors([TARGET])

    result = ProvenancePolicyVerifier.verify_no_revoked_ancestors(graph, TARGET)
    assert result.passed is False

    # Every clause the encoder emitted is Horn, so tier UP is mandatory and the
    # certificate is checkable in one linear pass.
    assert is_horn(result.clauses)
    assert tightest_tier(result.clauses) is CostTier.UP


def test_policy_encoding_divergence_is_a_hard_error_with_a_certificate():
    """The bug an encoding error would produce is now loud instead of silent."""
    clauses = [[-1, 2], [-2], [1]]
    var_map = {"TARGET_ADMISSIBLE": 1, "CLEAN_" + ANCESTOR: 2}

    with pytest.raises(PolicyEncodingError) as caught:
        certify_policy_cnf(
            satisfiable=False,
            direct_result=True,  # the list says "clean"; the CNF says otherwise
            policy_id="POL-TEST",
            target_artifact_id=TARGET,
            clauses=clauses,
            var_map=var_map,
        )
    assert "disagree" in str(caught.value)
    assert caught.value.certificate is not None
    # The attached certificate is checkable, so a reader can see which side lied.
    assert check(caught.value.certificate, budget=1000).outcome is KernelOutcome.ACCEPTED
    assert caught.value.certificate.header.verdict is Verdict.FAIL


def test_unrecognized_clause_shape_cannot_be_silently_grounded():
    with pytest.raises(PolicyEncodingError, match="matches no declared policy encoding"):
        ground_policy_cnf([[2, 3]], {"TARGET_ADMISSIBLE": 1, "A_x": 2, "A_y": 3}, TARGET)


def test_every_policy_encoder_emits_horn_clauses_across_input_classes():
    """Exhaust the status/license classes that change every policy encoder."""
    statuses = (
        ArtifactStatus.VALID,
        ArtifactStatus.REVOKED,
        ArtifactStatus.STALE,
        ArtifactStatus.UNKNOWN,
    )
    licenses = ("MIT", "PROPRIETARY", None)

    for (root_status, middle_status), license_spdx in product(
        product(statuses, repeat=2), licenses
    ):
        graph = ProvenanceHypergraph()
        rights_id = "rights:root" if license_spdx is not None else None
        if rights_id is not None:
            graph.add_rights(RightsSpec(rights_id, license_spdx))

        for artifact_id, status, rights in (
            ("artifact:root", root_status, rights_id),
            ("artifact:middle", middle_status, None),
            ("artifact:target", ArtifactStatus.VALID, None),
        ):
            graph.add_artifact(
                ArtifactNode(
                    artifact_id=artifact_id,
                    label=artifact_id,
                    artifact_type=ArtifactType.RAW_SOURCE_FILE,
                    content_digest=canonical_digest(artifact_id),
                    status=status,
                    rights_id=rights,
                )
            )
        for index, (source, target) in enumerate(
            (
                ("artifact:root", "artifact:middle"),
                ("artifact:middle", "artifact:target"),
            )
        ):
            graph.add_transformation(
                TransformationHyperedge(
                    transformation_id=f"transform:{index}",
                    label=f"transform:{index}",
                    transformation_type=TransformationType.NORMALIZATION,
                    inputs=(HyperedgePort(source, "INPUT"),),
                    outputs=(HyperedgePort(target, "OUTPUT"),),
                    software_provenance={},
                    parameters={},
                    execution_environment={},
                )
            )

        for verifier in (
            ProvenancePolicyVerifier.verify_no_revoked_ancestors,
            ProvenancePolicyVerifier.verify_all_ancestors_valid,
            ProvenancePolicyVerifier.verify_approved_licenses,
        ):
            result = verifier(graph, "artifact:target")
            assert is_horn(result.clauses), (
                f"{result.policy_id} emitted a non-Horn clause for "
                f"statuses={root_status, middle_status}, license={license_spdx}"
            )
            assert tightest_tier(result.clauses) is CostTier.UP
