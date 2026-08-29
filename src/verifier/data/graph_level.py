"""Terminology: application programming interface (API); conjunctive normal form (CNF); grounded decision certificate (GDC);
Boolean satisfiability problem (SAT); unsatisfiable (UNSAT); Verifier Standard (VSTD).

``graph_level`` -- compatibility API for the candidate Graph profile satisfied by supplied collection ratings.

VSTD is verification *mechanics* over one object. VSTD-Graph is verification
*dynamics* over a collection. The axes remain distinct. This module computes a
candidate Graph profile from caller-supplied ratings; that computation is not
conformance unless a separate profile validates and binds those ratings.

1. **Membership floor** -- every member object has an object-profile rating >= N.
2. **Provenance closure** -- every ancestor reachable from any member is also
   >= N. A plain minimum-over-members misses this, which is the whole reason a
   corpus of well-rated repositories can still be badly rated as a corpus.
3. **Status admissibility** -- no artifact in the closure is ``REVOKED``,
   ``CHALLENGED``, ``STALE`` or ``UNKNOWN``. Fail-closed, per the ``UNKNOWN``
   principle the data package already applies elsewhere.
4. **Edge evidence** -- the transformation hyperedges themselves carry profile-N
   ratings. A graph is only as verified as its edges, and this is the condition
   that makes the axis dynamics rather than aggregation.

Then, exactly as on the object axis::

    graph_level(C) = max { N : CNF_N(C) is satisfiable }

computed by iterated SAT descending 5 -> 1, and **the UNSAT certificate at N+1
is the explanation of why those supplied ratings do not support a higher candidate**.
That certificate is a VSTD4-GDC-1 refutation of the encoded candidate only. It is not
evidence that any object or Graph profile was satisfied, and does not supply, imply,
upgrade, or repair evidence for one.

Three separately implemented checks must agree before this module reports a candidate: the
certified Horn encoding, :class:`MinimalIndependentDPLL`, and a direct Python
evaluation of the four conditions. Divergence raises rather than silently
preferring one, because an encoding bug is precisely the failure that makes two
of them disagree.

The cross-check in :func:`certify_graph_cnf` deliberately mirrors
:func:`verifier.data.policy.certify_policy_cnf` instead of sharing it. Two
cross-checks that share an implementation are not two cross-checks; a single bug
in a common helper would corrupt both axes at once, which is rung 4.7's argument
applied to this module.

This module *produces* certificates and is not part of the trusted computing
base. :mod:`verifier.core.kernel` checks everything it emits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence

from verifier.core.certificate import (
    ClaimBinding,
    ClauseGrounding,
    DecisionCertificate,
    EncodingRule,
    GroundedFact,
    Grounding,
    VariableGrounding,
    Verdict,
    canonical_digest,
)
from verifier.core.checker import MinimalIndependentDPLL
from verifier.core.evidence import (
    BoundProposition,
    EvidenceStore,
    EvaluatedProposition,
    MechanismOutcome,
    VerificationMechanism,
    VerificationSession,
)
from verifier.core.depth import claim_binding_from_dict
from verifier.core.kernel import check as kernel_check
from verifier.core.refutation import build_horn_certificate
from verifier.data.models import ArtifactStatus, ProvenanceHypergraph

GRAPH_MIN_LEVEL = 1
GRAPH_MAX_LEVEL = 5

INADMISSIBLE_STATUSES = frozenset(
    {
        ArtifactStatus.REVOKED.value,
        ArtifactStatus.CHALLENGED.value,
        ArtifactStatus.STALE.value,
        ArtifactStatus.UNKNOWN.value,
        "CONFLICTED",
    }
)
"""Statuses that disqualify an artifact from any candidate Graph profile.

``SUPERSEDED`` is deliberately absent: a superseded artifact was replaced going
forward, but its historical role in a lineage is unchanged and re-rating the
past every time something is superseded would make candidate profiles unstable for reasons
having nothing to do with evidence. A caller wanting the stricter reading has
:meth:`~verifier.data.policy.ProvenancePolicyVerifier.verify_all_ancestors_valid`,
which admits ``VALID`` and nothing else.
"""


def graph_collection_binding_digest(
    graph: ProvenanceHypergraph,
    *,
    collection_id: str,
    members: Sequence[str],
    binding: ClaimBinding,
) -> str:
    """Bind ratings to one Graph, member set, collection, and claim coordinate."""
    return canonical_digest(
        {
            "collection_id": collection_id,
            "members": sorted(set(members)),
            "historical_graph_digest": canonical_digest(graph.to_dict()),
            "claim_binding_digest": binding.digest(),
        }
    )


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
# Obligations -- what a candidate Graph profile asks of a collection
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
    """One thing a candidate Graph profile requires and what the graph records.

    ``observed`` is profile-independent -- it is the ground fact. Whether the
    obligation is *met* is a question asked of that fact once per profile, which
    is why the variable numbering below is stable across all five encodings and
    only the unit clauses move.
    """

    kind: ObligationKind
    subject: str
    observed: str
    level: int = 0
    """Compatibility field carrying the profile rating; unused for status obligations."""

    @property
    def predicate(self) -> str:
        return _PREDICATE[self.kind]

    def met_at(self, level: int) -> bool:
        if self.kind is ObligationKind.STATUS_ADMISSIBILITY:
            return self.observed not in INADMISSIBLE_STATUSES
        return self.level >= level

    def describe(self, level: int) -> str:
        if self.kind is ObligationKind.STATUS_ADMISSIBILITY:
            return f"{self.kind.value}: {self.subject} is {self.observed}"
        return (
            f"{self.kind.value}: {self.subject} has profile rating {self.level}, "
            f"below required profile {level}"
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
    """A collection under test, with ratings for its candidate Graph profile.

    ``object_levels`` and ``edge_levels`` retain compatibility field names and are
    read as profile ratings someone else established. An artifact or edge with
    no entry is rated ``0``: unrated is not passing, and reading it as one is how
    a collection of unknowns becomes a candidate Graph-5 collection.
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
        if graph.has_conflict(artifact_id):
            status = "CONFLICTED"
        else:
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
        level = 0 if graph.has_conflict(transformation_id) else collection.edge_level(
            transformation_id
        )
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

    Variable 1 is the collection satisfying the profile number stored in ``level``;
    variable ``1 + i`` is obligation ``i``. The numbering does not move between
    profiles -- only the unit clauses do -- so two certificates for adjacent profiles are directly
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
            f"{collection_id} at candidate Graph profile {level}: the kernel refused this "
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
            f"{collection_id} at candidate Graph profile {level}: the certified encoding says "
            f"{encoded} but the separately implemented solver said {satisfiable}",
            certificate=certificate,
            cnf_satisfiable=satisfiable,
            direct_result=holds_at(items, level),
        )

    direct = holds_at(items, level)
    if encoded != direct:
        raise GraphEncodingError(
            f"{collection_id} at candidate Graph profile {level}: CNF encoding and direct "
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
# The computed candidate Graph profile
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphLevelResult:
    """A candidate Graph profile computed from declared ratings, with its SAT evidence.

    ``witness`` certifies the profile formula satisfied. ``refutation`` certifies
    why the next one was not, and ``blocking_obligations`` names what stopped it.
    A candidate reported without a refutation at anything below
    :data:`GRAPH_MAX_LEVEL` would be a declaration, which is the thing this
    module exists to avoid.
    """

    collection_id: str
    level: int
    witness: Optional[DecisionCertificate]
    refutation: Optional[DecisionCertificate]
    blocking_obligations: tuple[Obligation, ...]
    rating_basis: str = field(default="CALLER_SUPPLIED", init=False)
    conformance_status: str = field(default="NOT_ESTABLISHED", init=False)

    @property
    def explanation(self) -> str:
        if self.level >= GRAPH_MAX_LEVEL:
            return (
                f"{self.collection_id} computes to candidate Graph profile "
                f"{GRAPH_MAX_LEVEL} from caller-supplied ratings; conformance is not established."
            )
        blocked = "; ".join(
            item.describe(self.level + 1) for item in self.blocking_obligations
        )
        return (
            f"{self.collection_id} computes to candidate Graph profile {self.level} "
            "from caller-supplied ratings; conformance is not established. "
            f"Graph profile {self.level + 1} is refuted by: {blocked or 'no obligation'}."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "collection_id": self.collection_id,
            "level": self.level,
            "max_level": GRAPH_MAX_LEVEL,
            "rating_basis": self.rating_basis,
            "conformance_status": self.conformance_status,
            "blocking_obligations": [item.to_dict() for item in self.blocking_obligations],
            "witness_digest": None if self.witness is None else self.witness.digest(),
            "refutation_digest": (
                None if self.refutation is None else self.refutation.digest()
            ),
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class EvidenceBoundGraphLevelResult:
    """Graph profile whose object and edge ratings were rerun and bound."""

    candidate: GraphLevelResult
    object_evaluations: tuple[tuple[str, EvaluatedProposition], ...]
    edge_evaluations: tuple[tuple[str, EvaluatedProposition], ...]
    binding_errors: tuple[str, ...]
    kernel_outcome: str

    @property
    def level(self) -> int:
        return self.candidate.level

    @property
    def conformance_status(self) -> str:
        if (
            self.level < GRAPH_MIN_LEVEL
            or self.binding_errors
            or self.kernel_outcome != "ACCEPTED"
        ):
            return "NOT_ESTABLISHED"
        evaluations = self.object_evaluations + self.edge_evaluations
        if not evaluations or any(not result.passed for _, result in evaluations):
            return "NOT_ESTABLISHED"
        return "ESTABLISHED"

    @property
    def rating_basis(self) -> str:
        return "MECHANISM_EVALUATED"

    def to_dict(self) -> dict[str, Any]:
        payload = self.candidate.to_dict()
        payload.update(
            {
                "rating_basis": self.rating_basis,
                "conformance_status": self.conformance_status,
                "object_evaluations": {
                    subject: result.to_dict()
                    for subject, result in self.object_evaluations
                },
                "edge_evaluations": {
                    subject: result.to_dict()
                    for subject, result in self.edge_evaluations
                },
                "binding_errors": list(self.binding_errors),
                "kernel_outcome": self.kernel_outcome,
            }
        )
        return payload


def graph_level(
    graph: ProvenanceHypergraph,
    collection: GraphCollection,
    *,
    binding: ClaimBinding,
) -> GraphLevelResult:
    """Compute the candidate Graph profile, retaining the compatibility API name.

    Descends from :data:`GRAPH_MAX_LEVEL`, so the first satisfiable profile formula
    is the answer. The conditions are monotone in the profile number by construction --
    an obligation met at ``N`` is met at every ``N' <= N`` -- so descending
    means a collection meeting its supplied ratings costs one solve rather than five.
    """
    if not collection.members:
        raise GraphEncodingError(
            f"{collection.collection_id} has no members, so every obligation is "
            "vacuously met and the encoding would hand out candidate Graph profile "
            f"{GRAPH_MAX_LEVEL} for a collection nobody can refute. An empty "
            "collection satisfies no Graph profile."
        )

    closure = graph.ancestors(collection.members)
    if not graph.verify_acyclicity(closure):
        raise GraphEncodingError(
            f"{collection.collection_id} has cyclic recorded ancestry, so recursive "
            "reachability cannot establish a candidate Graph profile."
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


def establish_graph_level(
    graph: ProvenanceHypergraph,
    *,
    collection_id: str,
    members: Sequence[str],
    object_evidence: Mapping[str, BoundProposition],
    edge_evidence: Mapping[str, BoundProposition],
    session: VerificationSession,
    binding: ClaimBinding,
) -> EvidenceBoundGraphLevelResult:
    """Rerun rating mechanisms before computing a conforming Graph profile.

    Each reachable artifact must bind ``vstd.object_profile`` and each reachable
    transformation must bind ``vstd.graph_edge_profile`` to an integer in
    ``1..5`` under ``parameters['collection_id']``.  Missing, neighboring,
    duplicate, failed, or uncertain propositions contribute rating zero and
    prevent conformance; their field placement cannot promote the collection.
    """

    if not members:
        raise GraphEncodingError("an evidence-bound Graph collection must have members")
    identifier_overlap = sorted(
        set(graph.artifacts) & set(graph.transformations)
    )
    if identifier_overlap:
        raise GraphEncodingError(
            "evidence-bound Graph establishment requires globally disjoint "
            "artifact and transformation identifiers: "
            + ", ".join(identifier_overlap)
        )
    normalized_members = tuple(sorted(set(members)))
    closure = graph.ancestors(normalized_members)
    edges = {
        edge.transformation_id
        for artifact_id in closure
        for edge in graph.incoming_hyperedges(artifact_id)
    }
    errors: list[str] = []
    object_results: list[tuple[str, EvaluatedProposition]] = []
    edge_results: list[tuple[str, EvaluatedProposition]] = []
    object_levels: dict[str, int] = {}
    edge_levels: dict[str, int] = {}
    exact_collection_binding = graph_collection_binding_digest(
        graph,
        collection_id=collection_id,
        members=normalized_members,
        binding=binding,
    )

    extra_objects = set(object_evidence) - closure
    extra_edges = set(edge_evidence) - edges
    if extra_objects:
        errors.append(f"object ratings outside provenance closure: {sorted(extra_objects)}")
    if extra_edges:
        errors.append(f"edge ratings outside provenance closure: {sorted(extra_edges)}")

    def evaluate_rating(
        subject: str,
        proposition: Optional[BoundProposition],
        predicate: str,
        sink: list[tuple[str, EvaluatedProposition]],
    ) -> int:
        if proposition is None:
            errors.append(f"missing rating evidence for {subject}")
            return 0
        if type(proposition.expected) is not int:
            errors.append(f"rating for {subject} is not an integer")
            return 0
        rating = proposition.expected
        if not GRAPH_MIN_LEVEL <= rating <= GRAPH_MAX_LEVEL:
            errors.append(f"rating for {subject} is outside 1..5")
            return 0
        if (
            proposition.subject_id != subject
            or proposition.predicate != predicate
            or proposition.parameters.get("collection_id") != collection_id
            or proposition.parameters.get("collection_binding_digest")
            != exact_collection_binding
        ):
            errors.append(f"rating evidence for {subject} is not exactly collection-bound")
            return 0
        result = session.evaluate(proposition)
        sink.append((subject, result))
        if result.outcome is not MechanismOutcome.PASS:
            errors.append(
                f"rating mechanism for {subject} returned {result.outcome.value}"
            )
            return 0
        return rating

    for artifact_id in sorted(closure):
        object_levels[artifact_id] = evaluate_rating(
            artifact_id,
            object_evidence.get(artifact_id),
            "vstd.object_profile",
            object_results,
        )
    for transformation_id in sorted(edges):
        edge_levels[transformation_id] = evaluate_rating(
            transformation_id,
            edge_evidence.get(transformation_id),
            "vstd.graph_edge_profile",
            edge_results,
        )

    candidate = graph_level(
        graph,
        GraphCollection(
            collection_id,
            normalized_members,
            object_levels,
            edge_levels,
        ),
        binding=binding,
    )
    kernel_outcome = "REJECTED"
    certificate = candidate.witness or candidate.refutation
    if certificate is not None:
        kernel_outcome = kernel_check(certificate, binding=binding).outcome.value
    return EvidenceBoundGraphLevelResult(
        candidate,
        tuple(object_results),
        tuple(edge_results),
        tuple(errors),
        kernel_outcome,
    )


def build_evidence_bound_graph_level_record(
    result: EvidenceBoundGraphLevelResult,
    *,
    graph: ProvenanceHypergraph,
    members: Sequence[str],
    binding: ClaimBinding,
    object_evidence: Mapping[str, BoundProposition],
    edge_evidence: Mapping[str, BoundProposition],
    session: VerificationSession,
) -> dict[str, Any]:
    """Serialize exact Graph rating bindings and bytes for offline replay."""
    recomputed = establish_graph_level(
        graph,
        collection_id=result.candidate.collection_id,
        members=members,
        object_evidence=object_evidence,
        edge_evidence=edge_evidence,
        session=session,
        binding=binding,
    )
    if canonical_digest(recomputed.to_dict()) != canonical_digest(result.to_dict()):
        raise ValueError("Graph profile result does not match the supplied replay inputs")
    all_refs = tuple(
        sorted(
            {
                reference
                for proposition in (*object_evidence.values(), *edge_evidence.values())
                for reference in proposition.evidence_refs
            }
        )
    )
    normalized_members = tuple(sorted(set(members)))
    payload = result.to_dict()
    payload.update(
        {
            "members": list(normalized_members),
            "binding": binding.to_dict(),
            "evidence_bindings": {
                "objects": {
                    subject: proposition.to_dict()
                    for subject, proposition in sorted(object_evidence.items())
                },
                "edges": {
                    subject: proposition.to_dict()
                    for subject, proposition in sorted(edge_evidence.items())
                },
            },
            "evidence_payloads": session.evidence.export_base64(all_refs),
        }
    )
    return payload


def recheck_evidence_bound_graph_level_record(
    graph: ProvenanceHypergraph,
    record: Mapping[str, Any],
    *,
    mechanisms: Sequence[VerificationMechanism],
) -> EvidenceBoundGraphLevelResult:
    """Rebuild the evidence store, rerun rating mechanisms, and compare result."""
    if record.get("rating_basis") != "MECHANISM_EVALUATED":
        raise ValueError("Graph profile record is not mechanism-evaluated")
    payloads = record.get("evidence_payloads")
    bindings = record.get("evidence_bindings")
    binding_data = record.get("binding")
    members = record.get("members")
    if (
        not isinstance(payloads, Mapping)
        or not isinstance(bindings, Mapping)
        or not isinstance(binding_data, Mapping)
        or not isinstance(members, Sequence)
        or isinstance(members, (str, bytes))
    ):
        raise ValueError("evidence-bound Graph record is missing replay inputs")
    store = EvidenceStore()
    store.import_base64({str(key): str(value) for key, value in payloads.items()})
    session = VerificationSession(store)
    for mechanism in mechanisms:
        session.register(mechanism)
    objects_data = bindings.get("objects")
    edges_data = bindings.get("edges")
    if not isinstance(objects_data, Mapping) or not isinstance(edges_data, Mapping):
        raise ValueError("Graph evidence binding maps are missing")
    objects = {
        str(subject): BoundProposition.from_dict(proposition)
        for subject, proposition in objects_data.items()
        if isinstance(proposition, Mapping)
    }
    edges = {
        str(subject): BoundProposition.from_dict(proposition)
        for subject, proposition in edges_data.items()
        if isinstance(proposition, Mapping)
    }
    result = establish_graph_level(
        graph,
        collection_id=str(record["collection_id"]),
        members=tuple(str(item) for item in members),
        object_evidence=objects,
        edge_evidence=edges,
        session=session,
        binding=claim_binding_from_dict(binding_data),
    )
    for result_field, value in result.to_dict().items():
        if record.get(result_field) != value:
            raise ValueError(
                f"recomputed Graph field does not match receipt: {result_field}"
            )
    return result
