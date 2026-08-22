"""``graph_level`` -- how far up the VSTD-Graph ladder a collection actually got.

VSTD is verification *mechanics* over one object. VSTD-Graph is verification
*dynamics* over a collection, and the two axes are coupled rather than parallel:
a collection holds at Graph level ``N`` only when four conditions hold at once.

1. **Membership floor** -- every member object is at object level >= N.
2. **Provenance closure** -- every ancestor reachable from any member is also
   >= N. A plain minimum-over-members misses this, which is the whole reason a
   corpus of well-rated repositories can still be badly rated as a corpus.
3. **Status admissibility** -- no artifact in the closure is ``REVOKED``,
   ``CHALLENGED``, ``STALE`` or ``UNKNOWN``. Fail-closed, per the ``UNKNOWN``
   principle the data layer already applies elsewhere.
4. **Edge evidence** -- the transformation hyperedges themselves carry level-N
   evidence. A graph is only as verified as its edges, and this is the condition
   that makes the axis dynamics rather than aggregation.

Then, exactly as on the object axis::

    graph_level(C) = max { N : CNF_N(C) is satisfiable }

computed by iterated SAT descending 5 -> 1, and **the UNSAT certificate at N+1
is the explanation of why the collection cannot rate higher**. That certificate
is a VSTD4-GDC-1 refutation, which is where the two axes close on each other:
the object axis supplies the machinery the graph axis uses to justify its own
ceiling.

Three independent opinions must agree before this module reports a level: the
certified Horn encoding, :class:`MinimalIndependentDPLL`, and a direct Python
evaluation of the four conditions. Divergence raises rather than silently
preferring one, because an encoding bug is precisely the failure that makes two
of them disagree.

The cross-check in :func:`certify_graph_cnf` deliberately mirrors
:func:`verifiable.data.policy.certify_policy_cnf` instead of sharing it. Two
cross-checks that share an implementation are not two cross-checks; a single bug
in a common helper would corrupt both axes at once, which is rung 4.7's argument
applied to this module.

This module *produces* certificates and is not part of the trusted computing
base. :mod:`verifiable.core.kernel` checks everything it emits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence

from verifiable.core.certificate import (
    ClaimBinding,
    ClauseGrounding,
    DecisionCertificate,
    EncodingRule,
    GroundedFact,
    Grounding,
    VariableGrounding,
    Verdict,
)
from verifiable.core.checker import MinimalIndependentDPLL
from verifiable.core.kernel import check as kernel_check
from verifiable.core.refutation import build_horn_certificate
from verifiable.data.models import ArtifactStatus, ProvenanceHypergraph

GRAPH_MIN_LEVEL = 1
GRAPH_MAX_LEVEL = 5

INADMISSIBLE_STATUSES = frozenset(
    {
        ArtifactStatus.REVOKED,
        ArtifactStatus.CHALLENGED,
        ArtifactStatus.STALE,
        ArtifactStatus.UNKNOWN,
    }
)
"""Statuses that disqualify an artifact from any graph level.

``SUPERSEDED`` is deliberately absent: a superseded artifact was replaced going
forward, but its historical role in a lineage is unchanged and re-rating the
past every time something is superseded would make levels unstable for reasons
having nothing to do with evidence. A caller wanting the stricter reading has
:meth:`~verifiable.data.policy.ProvenancePolicyVerifier.verify_all_ancestors_valid`,
which admits ``VALID`` and nothing else.
"""


class GraphEncodingError(RuntimeError):
    """The encoding, the solver and the direct computation do not all agree.

    Carries the certificate the encoding actually supports, so a reader can see
    which of the three is lying instead of being handed whichever branch this
    module happened to prefer.
    """

    def __init__(
        self,
        message: str,
        *,
        certificate: Optional[DecisionCertificate] = None,
        cnf_satisfiable: bool = False,
        direct_result: bool = False,
    ) -> None:
        super().__init__(message)
        self.certificate = certificate
        self.cnf_satisfiable = cnf_satisfiable
        self.direct_result = direct_result


# --------------------------------------------------------------------------
# Obligations -- what a level actually asks of a collection
# --------------------------------------------------------------------------


class ObligationKind(str, Enum):
    MEMBERSHIP_FLOOR = "MEMBERSHIP_FLOOR"
    PROVENANCE_CLOSURE = "PROVENANCE_CLOSURE"
    STATUS_ADMISSIBILITY = "STATUS_ADMISSIBILITY"
    EDGE_EVIDENCE = "EDGE_EVIDENCE"


_PREDICATE = {
    ObligationKind.MEMBERSHIP_FLOOR: "vstd_object_level",
    ObligationKind.PROVENANCE_CLOSURE: "vstd_object_level",
    ObligationKind.STATUS_ADMISSIBILITY: "artifact_status",
    ObligationKind.EDGE_EVIDENCE: "vstd_edge_evidence_level",
}

_KIND_ORDER = {kind: index for index, kind in enumerate(ObligationKind)}


@dataclass(frozen=True)
class Obligation:
    """One thing a level requires, and what the graph actually says about it.

    ``observed`` is level-independent -- it is the ground fact. Whether the
    obligation is *met* is a question asked of that fact once per level, which
    is why the variable numbering below is stable across all five encodings and
    only the unit clauses move.
    """

    kind: ObligationKind
    subject: str
    observed: str
    level: int = 0
    """The rated level behind ``observed``; unused for status obligations."""

    @property
    def predicate(self) -> str:
        return _PREDICATE[self.kind]

    def met_at(self, level: int) -> bool:
        if self.kind is ObligationKind.STATUS_ADMISSIBILITY:
            return self.observed not in {status.value for status in INADMISSIBLE_STATUSES}
        return self.level >= level

    def describe(self, level: int) -> str:
        if self.kind is ObligationKind.STATUS_ADMISSIBILITY:
            return f"{self.kind.value}: {self.subject} is {self.observed}"
        return (
            f"{self.kind.value}: {self.subject} is rated {self.level}, "
            f"which is below {level}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "subject": self.subject,
            "predicate": self.predicate,
            "observed": self.observed,
            "level": self.level,
        }


@dataclass(frozen=True)
class GraphCollection:
    """A collection under test, with the ratings its level will be computed from.

    ``object_levels`` and ``edge_levels`` are read as ratings someone else
    established. An artifact or edge with no entry is rated ``0``: unrated is
    not a passing grade, and reading it as one is how a collection of unknowns
    becomes a level-5 corpus.
    """

    collection_id: str
    members: tuple[str, ...]
    object_levels: Mapping[str, int] = field(default_factory=dict)
    edge_levels: Mapping[str, int] = field(default_factory=dict)

    def object_level(self, artifact_id: str) -> int:
        return int(dict(self.object_levels).get(artifact_id, 0))

    def edge_level(self, transformation_id: str) -> int:
        return int(dict(self.edge_levels).get(transformation_id, 0))


def obligations(graph: ProvenanceHypergraph, collection: GraphCollection) -> tuple[Obligation, ...]:
    """Everything the four conditions range over, in a deterministic order."""
    members = tuple(sorted(set(collection.members)))
    closure = graph.ancestors(members)
    ancestors = tuple(sorted(closure - set(members)))

    found: list[Obligation] = []
    for artifact_id in members:
        level = collection.object_level(artifact_id)
        found.append(
            Obligation(ObligationKind.MEMBERSHIP_FLOOR, artifact_id, str(level), level)
        )
    for artifact_id in ancestors:
        level = collection.object_level(artifact_id)
        found.append(
            Obligation(ObligationKind.PROVENANCE_CLOSURE, artifact_id, str(level), level)
        )
    for artifact_id in sorted(closure):
        node = graph.artifacts.get(artifact_id)
        status = ArtifactStatus.UNKNOWN.value if node is None else node.status.value
        found.append(Obligation(ObligationKind.STATUS_ADMISSIBILITY, artifact_id, status))

    edges = sorted(
        {
            edge.transformation_id
            for artifact_id in closure
            for edge in graph.incoming_hyperedges(artifact_id)
        }
    )
    for transformation_id in edges:
        level = collection.edge_level(transformation_id)
        found.append(
            Obligation(ObligationKind.EDGE_EVIDENCE, transformation_id, str(level), level)
        )

    return tuple(sorted(found, key=lambda item: (_KIND_ORDER[item.kind], item.subject)))


def holds_at(items: Sequence[Obligation], level: int) -> bool:
    """The direct computation: the four conditions, evaluated without a solver."""
    return all(item.met_at(level) for item in items)


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------

RULE_ASSERT_COLLECTION = EncodingRule(
    "RULE:GRAPH_ASSERT_COLLECTION", ("collection",), ((1, "collection"),)
)
RULE_COLLECTION_REQUIRES = EncodingRule(
    "RULE:GRAPH_COLLECTION_REQUIRES",
    ("collection", "obligation"),
    ((-1, "collection"), (1, "obligation")),
)
RULE_OBLIGATION_MET = EncodingRule(
    "RULE:GRAPH_OBLIGATION_MET", ("obligation",), ((1, "obligation"),)
)
RULE_OBLIGATION_UNMET = EncodingRule(
    "RULE:GRAPH_OBLIGATION_UNMET", ("obligation",), ((-1, "obligation"),)
)
GRAPH_RULES = (
    RULE_ASSERT_COLLECTION,
    RULE_COLLECTION_REQUIRES,
    RULE_OBLIGATION_MET,
    RULE_OBLIGATION_UNMET,
)


def encode(
    collection_id: str, items: Sequence[Obligation], level: int
) -> tuple[tuple[tuple[int, ...], ...], Grounding]:
    """CNF_N, together with the grounding that says what its variables mean.

    Variable 1 is the collection holding at ``level``; variable ``1 + i`` is
    obligation ``i``. The numbering does not move between levels -- only the
    unit clauses do -- so two certificates for adjacent levels are directly
    comparable rather than being two unrelated formulas that happen to share a
    subject.
    """
    formula: list[tuple[int, ...]] = []
    clauses: list[ClauseGrounding] = []

    def emit(literals: Sequence[int], rule: EncodingRule, bindings, subjects) -> None:
        clauses.append(
            ClauseGrounding(len(formula), rule.rule_id, dict(bindings), dict(subjects))
        )
        formula.append(tuple(literals))

    emit([1], RULE_ASSERT_COLLECTION, {"collection": 1}, {"collection": collection_id})

    for offset, item in enumerate(items):
        var = offset + 2
        emit(
            [-1, var],
            RULE_COLLECTION_REQUIRES,
            {"collection": 1, "obligation": var},
            {"collection": collection_id, "obligation": item.subject},
        )
        if item.met_at(level):
            emit([var], RULE_OBLIGATION_MET, {"obligation": var}, {"obligation": item.subject})
        else:
            emit([-var], RULE_OBLIGATION_UNMET, {"obligation": var}, {"obligation": item.subject})

    variables = [
        VariableGrounding(
            1, GroundedFact(collection_id, f"vstd_graph_level>={level}", "ASSERTED")
        )
    ]
    variables.extend(
        VariableGrounding(
            offset + 2, GroundedFact(item.subject, item.predicate, item.observed)
        )
        for offset, item in enumerate(items)
    )

    return tuple(formula), Grounding(tuple(variables), tuple(clauses), GRAPH_RULES)


def certify_graph_cnf(
    *,
    collection_id: str,
    items: Sequence[Obligation],
    level: int,
    binding: ClaimBinding,
) -> tuple[bool, DecisionCertificate, tuple[Obligation, ...]]:
    """Make the encoding authoritative, and prove it rather than assert it.

    Returns the verdict the encoding supports, a certificate the kernel accepts,
    and the obligations named by the conflict clause when the verdict is FAIL.
    Raises :class:`GraphEncodingError` unless the encoding, the solver and the
    direct computation all agree.
    """
    formula, grounding = encode(collection_id, items, level)
    certificate = build_horn_certificate(formula, grounding, binding)

    verdict = kernel_check(certificate, binding=binding)
    if not verdict.accepted:
        raise GraphEncodingError(
            f"{collection_id} at level {level}: the kernel refused this "
            f"collection's own certificate: {verdict.details}",
            certificate=certificate,
        )

    encoded = certificate.header.verdict is Verdict.PASS

    solver = MinimalIndependentDPLL(
        n_vars=len(items) + 1, clauses=[list(clause) for clause in formula]
    )
    satisfiable, _model = solver.solve()
    if encoded != satisfiable:
        raise GraphEncodingError(
            f"{collection_id} at level {level}: the certified encoding says "
            f"{encoded} but the independent solver said {satisfiable}",
            certificate=certificate,
            cnf_satisfiable=satisfiable,
            direct_result=holds_at(items, level),
        )

    direct = holds_at(items, level)
    if encoded != direct:
        raise GraphEncodingError(
            f"{collection_id} at level {level}: CNF encoding and direct "
            f"computation disagree -- encoding says {encoded}, direct "
            f"computation says {direct}. One of them is wrong and the "
            "certificate attached shows what the encoding actually proves.",
            certificate=certificate,
            cnf_satisfiable=satisfiable,
            direct_result=direct,
        )

    blocking: tuple[Obligation, ...] = ()
    proof = certificate.decision.propagation
    if proof is not None:
        conflict = formula[proof.conflict_clause_index]
        blocking = tuple(
            items[abs(literal) - 2]
            for literal in conflict
            if abs(literal) >= 2
        )

    return encoded, certificate, blocking


# --------------------------------------------------------------------------
# The computed level
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphLevelResult:
    """A computed level, with the evidence for both halves of the answer.

    ``witness`` certifies the level reached. ``refutation`` certifies why the
    next one was not, and ``blocking_obligations`` names what stopped it. A
    level reported without a refutation at anything below
    :data:`GRAPH_MAX_LEVEL` would be a declaration, which is the thing this
    module exists to avoid.
    """

    collection_id: str
    level: int
    witness: Optional[DecisionCertificate]
    refutation: Optional[DecisionCertificate]
    blocking_obligations: tuple[Obligation, ...]

    @property
    def explanation(self) -> str:
        if self.level >= GRAPH_MAX_LEVEL:
            return f"{self.collection_id} holds at graph level {GRAPH_MAX_LEVEL}."
        blocked = "; ".join(
            item.describe(self.level + 1) for item in self.blocking_obligations
        )
        return (
            f"{self.collection_id} holds at graph level {self.level}. "
            f"Level {self.level + 1} is refuted by: {blocked or 'no obligation'}."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "collection_id": self.collection_id,
            "level": self.level,
            "max_level": GRAPH_MAX_LEVEL,
            "blocking_obligations": [item.to_dict() for item in self.blocking_obligations],
            "witness_digest": None if self.witness is None else self.witness.digest(),
            "refutation_digest": (
                None if self.refutation is None else self.refutation.digest()
            ),
            "explanation": self.explanation,
        }


def graph_level(
    graph: ProvenanceHypergraph,
    collection: GraphCollection,
    *,
    binding: ClaimBinding,
) -> GraphLevelResult:
    """Compute the graph level of ``collection``, with the proof of its ceiling.

    Descends from :data:`GRAPH_MAX_LEVEL`, so the first satisfiable level found
    is the answer. The conditions are monotone in the level by construction --
    an obligation met at ``N`` is met at every ``N' <= N`` -- so descending
    means a fully-conformant collection costs one solve rather than five.
    """
    if not collection.members:
        raise GraphEncodingError(
            f"{collection.collection_id} has no members, so every obligation is "
            "vacuously met and the encoding would hand out level "
            f"{GRAPH_MAX_LEVEL} for a collection nobody can refute. An empty "
            "collection has no level."
        )

    items = obligations(graph, collection)

    for level in range(GRAPH_MAX_LEVEL, GRAPH_MIN_LEVEL - 1, -1):
        passed, certificate, _blocking = certify_graph_cnf(
            collection_id=collection.collection_id,
            items=items,
            level=level,
            binding=binding,
        )
        if passed:
            refutation: Optional[DecisionCertificate] = None
            blocked: tuple[Obligation, ...] = ()
            if level < GRAPH_MAX_LEVEL:
                _next, refutation, blocked = certify_graph_cnf(
                    collection_id=collection.collection_id,
                    items=items,
                    level=level + 1,
                    binding=binding,
                )
            return GraphLevelResult(
                collection.collection_id, level, certificate, refutation, blocked
            )

    _passed, refutation, blocked = certify_graph_cnf(
        collection_id=collection.collection_id,
        items=items,
        level=GRAPH_MIN_LEVEL,
        binding=binding,
    )
    return GraphLevelResult(collection.collection_id, 0, None, refutation, blocked)
