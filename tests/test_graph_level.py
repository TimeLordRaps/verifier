"""Terminology: Verifier Standard (VSTD).

The VSTD-Graph axis: a computed level, and the proof of its ceiling.

The level is never declared. Each test below pins one of the four conditions --
membership floor, provenance closure, status admissibility, edge evidence --
and checks not just that the level dropped but that the certificate at ``N+1``
*says why*. A level without that certificate would be an assertion, and the
whole point of this axis is that a collection of well-rated members can still
be badly rated as a collection.
"""

from __future__ import annotations

import importlib

import pytest

from verifier.core.certificate import (
    ClaimBinding,
    ClaimCoordinate,
    CostTier,
    ResourceBounds,
    Verdict,
)
from verifier.core.kernel import KernelOutcome, check, is_horn, reference_descriptor
from verifier.data.graph_level import (
    GRAPH_MAX_LEVEL,
    GraphCollection,
    GraphEncodingError,
    INADMISSIBLE_STATUSES,
    ObligationKind,
    certify_graph_cnf,
    encode,
    graph_level,
    obligations,
)

from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    TransformationHyperedge,
    TransformationType,
)

graph_module = importlib.import_module("verifier.data.graph_level")

BUDGET = 10_000


def _binding() -> ClaimBinding:
    return ClaimBinding(
        claim="corpus graph level",
        coordinate=ClaimCoordinate("collection:C", "vstd_graph_level"),
        policy_root="sha256:policy",
        evidence_root="sha256:evidence",
        verifier=reference_descriptor(),
        bounds=ResourceBounds(BUDGET, BUDGET, BUDGET),
    )


def _node(artifact_id: str, status: ArtifactStatus = ArtifactStatus.VALID) -> ArtifactNode:
    return ArtifactNode(artifact_id, artifact_id, ArtifactType.CORPUS, "a" * 64, status=status)


def _graph(**statuses: ArtifactStatus) -> ProvenanceHypergraph:
    """src -> (t1) -> mid -> (t2) -> corpus."""
    graph = ProvenanceHypergraph()
    for artifact_id in ("src", "mid", "corpus"):
        graph.add_artifact(_node(artifact_id, statuses.get(artifact_id, ArtifactStatus.VALID)))
    graph.add_transformation(
        TransformationHyperedge(
            "t1", "extract", TransformationType.EXTRACTION,
            (HyperedgePort("src", "IN"),), (HyperedgePort("mid", "OUT"),), {}, {}, {},
        )
    )
    graph.add_transformation(
        TransformationHyperedge(
            "t2", "collect", TransformationType.COLLECTION,
            (HyperedgePort("mid", "IN"),), (HyperedgePort("corpus", "OUT"),), {}, {}, {},
        )
    )
    return graph


def _collection(objects=None, edges=None) -> GraphCollection:
    return GraphCollection(
        "collection:C",
        ("corpus",),
        objects if objects is not None else {"src": 5, "mid": 5, "corpus": 5},
        edges if edges is not None else {"t1": 5, "t2": 5},
    )


def _level(graph: ProvenanceHypergraph, collection: GraphCollection):
    return graph_level(graph, collection, binding=_binding())


def _assert_certificates_check(result) -> None:
    binding = _binding()
    for certificate in (result.witness, result.refutation):
        if certificate is None:
            continue
        assert is_horn(certificate.formula)
        assert certificate.header.tier is CostTier.UP
        verdict = check(certificate, budget=BUDGET, binding=binding)
        assert verdict.outcome is KernelOutcome.ACCEPTED, verdict.details


# --------------------------------------------------------------------------
# The four conditions
# --------------------------------------------------------------------------


def test_a_fully_rated_collection_reaches_the_top():
    result = _level(_graph(), _collection())
    assert result.level == GRAPH_MAX_LEVEL
    assert result.refutation is None
    assert result.blocking_obligations == ()
    assert result.witness is not None
    assert result.witness.header.verdict is Verdict.PASS
    _assert_certificates_check(result)


def test_a_member_downgrade_lowers_the_collection():
    result = _level(_graph(), _collection({"src": 5, "mid": 5, "corpus": 3}))
    assert result.level == 3
    assert [item.kind for item in result.blocking_obligations] == [
        ObligationKind.MEMBERSHIP_FLOOR
    ]
    assert result.blocking_obligations[0].subject == "corpus"
    _assert_certificates_check(result)


def test_an_ancestor_nobody_looked_at_lowers_the_collection():
    """Provenance closure is what a minimum-over-members misses."""
    result = _level(_graph(), _collection({"src": 2, "mid": 5, "corpus": 5}))
    assert result.level == 2
    blocking = result.blocking_obligations[0]
    assert blocking.kind is ObligationKind.PROVENANCE_CLOSURE
    assert blocking.subject == "src"
    assert "src" in result.explanation


def test_a_weak_edge_lowers_the_collection_even_with_perfect_nodes():
    """A graph is only as verified as its edges."""
    result = _level(_graph(), _collection(edges={"t1": 1, "t2": 5}))
    assert result.level == 1
    blocking = result.blocking_obligations[0]
    assert blocking.kind is ObligationKind.EDGE_EVIDENCE
    assert blocking.subject == "t1"
    _assert_certificates_check(result)


def test_an_unrated_edge_is_not_a_passing_grade():
    result = _level(_graph(), _collection(edges={"t2": 5}))
    assert result.level == 0
    assert result.witness is None
    assert result.blocking_obligations[0].subject == "t1"


def test_a_revoked_ancestor_disqualifies_the_collection_entirely():
    result = _level(_graph(src=ArtifactStatus.REVOKED), _collection())
    assert result.level == 0
    assert result.witness is None
    blocking = result.blocking_obligations[0]
    assert blocking.kind is ObligationKind.STATUS_ADMISSIBILITY
    assert blocking.observed == ArtifactStatus.REVOKED.value
    _assert_certificates_check(result)


@pytest.mark.parametrize("status", sorted(INADMISSIBLE_STATUSES, key=lambda s: s.value))
def test_every_inadmissible_status_fails_closed(status):
    assert _level(_graph(mid=status), _collection()).level == 0


def test_superseded_is_admissible_and_documented_as_such():
    """A superseded ancestor was replaced going forward; its history is unchanged."""
    assert ArtifactStatus.SUPERSEDED not in INADMISSIBLE_STATUSES
    assert _level(_graph(src=ArtifactStatus.SUPERSEDED), _collection()).level == GRAPH_MAX_LEVEL


def test_an_artifact_missing_from_the_graph_is_unknown_not_absent():
    graph = _graph()
    del graph.artifacts["mid"]
    assert _level(graph, _collection()).level == 0


# --------------------------------------------------------------------------
# The certificate at N+1 is the explanation
# --------------------------------------------------------------------------


def test_the_refutation_is_the_explanation_not_a_separate_report():
    result = _level(_graph(), _collection({"src": 5, "mid": 4, "corpus": 5}))
    assert result.level == 4
    assert result.refutation is not None
    assert result.refutation.header.verdict is Verdict.FAIL

    proof = result.refutation.decision.propagation
    assert proof is not None
    conflict = result.refutation.grounding.clauses[proof.conflict_clause_index]
    assert conflict.rule_id == "RULE:GRAPH_OBLIGATION_UNMET"
    assert conflict.subjects["obligation"] == "mid"


def test_the_witness_and_the_refutation_are_different_certificates():
    summary = _level(_graph(), _collection({"src": 5, "mid": 5, "corpus": 2})).to_dict()
    assert summary["level"] == 2
    assert summary["witness_digest"] is not None
    assert summary["refutation_digest"] is not None
    assert summary["witness_digest"] != summary["refutation_digest"]


def test_variable_numbering_is_stable_across_adjacent_levels():
    """Two levels of the same collection are comparable, not unrelated formulas."""
    items = obligations(_graph(), _collection({"src": 5, "mid": 3, "corpus": 5}))
    low, low_grounding = encode("collection:C", items, 3)
    high, high_grounding = encode("collection:C", items, 4)

    assert len(low) == len(high)
    assert [v.var for v in low_grounding.variables] == [v.var for v in high_grounding.variables]
    differing = [index for index, clause in enumerate(low) if clause != high[index]]
    assert len(differing) == 1, "only the unit clause for the failing obligation may move"


# --------------------------------------------------------------------------
# Monotonicity, and the things the level must refuse to say
# --------------------------------------------------------------------------


def test_the_level_is_monotone_in_the_ratings():
    graph = _graph()
    for rating in range(0, GRAPH_MAX_LEVEL + 1):
        collection = _collection({"src": rating, "mid": 5, "corpus": 5})
        assert _level(graph, collection).level == rating


def test_lowering_any_single_rating_can_only_lower_the_level():
    graph = _graph()
    baseline = _level(graph, _collection()).level
    for subject in ("src", "mid", "corpus"):
        objects = {"src": 5, "mid": 5, "corpus": 5}
        objects[subject] = 2
        assert _level(graph, _collection(objects)).level < baseline
    for subject in ("t1", "t2"):
        edges = {"t1": 5, "t2": 5}
        edges[subject] = 2
        assert _level(graph, _collection(edges=edges)).level < baseline


def test_an_empty_collection_has_no_level():
    """Vacuous truth would hand out level 5 for a collection nobody can refute."""
    with pytest.raises(GraphEncodingError, match="no members"):
        _level(_graph(), GraphCollection("collection:empty", ()))


def test_the_weakest_condition_decides_not_the_average():
    result = _level(
        _graph(), _collection({"src": 1, "mid": 5, "corpus": 5}, {"t1": 5, "t2": 5})
    )
    assert result.level == 1


# --------------------------------------------------------------------------
# Three opinions, and what happens when they disagree
# --------------------------------------------------------------------------


def test_encoding_divergence_raises_with_a_certificate_attached(monkeypatch):
    """The failure an encoding bug produces: the two opinions come apart."""
    monkeypatch.setattr(graph_module, "holds_at", lambda items, level: False)

    items = obligations(_graph(), _collection())
    with pytest.raises(GraphEncodingError) as excinfo:
        certify_graph_cnf(
            collection_id="collection:C", items=items, level=GRAPH_MAX_LEVEL,
            binding=_binding(),
        )

    assert "direct computation disagree" in str(excinfo.value)
    assert excinfo.value.cnf_satisfiable is True
    assert excinfo.value.direct_result is False

    attached = excinfo.value.certificate
    assert attached is not None
    assert check(attached, binding=_binding()).outcome is KernelOutcome.ACCEPTED


def test_solver_divergence_is_caught_before_the_direct_check(monkeypatch):
    """The encoding and the independent solver must agree first, or nothing else counts."""

    class ContrarySolver:
        def __init__(self, **_kwargs):
            pass

        def solve(self):
            return False, {}

    monkeypatch.setattr(graph_module, "MinimalIndependentDPLL", ContrarySolver)

    items = obligations(_graph(), _collection())
    with pytest.raises(GraphEncodingError, match="independent solver said False"):
        certify_graph_cnf(
            collection_id="collection:C", items=items, level=GRAPH_MAX_LEVEL,
            binding=_binding(),
        )


def test_the_encoding_is_authoritative_and_the_kernel_endorses_it():
    items = obligations(_graph(), _collection())
    passed, certificate, blocking = certify_graph_cnf(
        collection_id="collection:C", items=items, level=GRAPH_MAX_LEVEL, binding=_binding()
    )
    assert passed is True
    assert blocking == ()
    assert check(certificate, binding=_binding()).outcome is KernelOutcome.ACCEPTED


def test_every_graph_formula_is_horn_and_therefore_tier_up():
    """The tightest admissible tier is mandatory, on this axis too."""
    graph = _graph()
    for rating in range(0, GRAPH_MAX_LEVEL + 1):
        items = obligations(graph, _collection({"src": rating, "mid": rating, "corpus": rating}))
        for level in range(1, GRAPH_MAX_LEVEL + 1):
            formula, _grounding = encode("collection:C", items, level)
            assert is_horn(formula)
