"""Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD).

Adversarial tests for evidence-bound object, Graph, lifecycle, and witness paths.
"""

from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from verifier.core.certificate import (
    ClaimBinding,
    ClaimCoordinate,
    ResourceBounds,
    canonical_digest,
)
from verifier.core.depth import (
    build_evidence_bound_vstd4_receipt,
    establish_vstd4,
    recheck_evidence_bound_vstd4_receipt,
    require_vstd5_entry,
)
from verifier.core.evidence import (
    BoundProposition,
    EvidenceBindingError,
    EvidenceBounds,
    EvidenceStore,
    MechanismDecision,
    MechanismOutcome,
    VerificationSession,
)
from verifier.core.kernel import reference_descriptor
from verifier.core.witness import (
    CorroborationOutcome,
    CorroborationRecord,
    IndependenceAssertion,
    IndependenceDimension,
    RelationshipState,
    WitnessBundle,
    WitnessIdentity,
    WitnessResultStatus,
    assess_witness_corroboration,
    build_vstd5_receipt,
    recheck_vstd5_receipt,
)
from verifier.data.assurance import (
    AssuranceEventKind,
    AssuranceFlowError,
    AssuranceLedger,
    ChallengeProjectionMechanism,
    DiagnosticKind,
    recheck_assurance_log,
)
from verifier.data.graph_level import (
    GraphEncodingError,
    GraphCollection,
    build_evidence_bound_graph_level_record,
    establish_graph_level,
    graph_collection_binding_digest,
    graph_level,
    recheck_evidence_bound_graph_level_record,
)
from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    ConflictRecord,
    HyperedgePort,
    ProvenanceHypergraph,
    TransformationHyperedge,
    TransformationType,
)
from verifier.layer4.challenge import (
    Adjudication,
    Challenge,
    ChallengeLedger,
    ChallengeOutcome,
)
from verifier.layer4.surface import RefutationType, surface_from_types


class ExactFactMechanism:
    """Test mechanism: compare exact JSON fact bytes with the bound proposition."""

    mechanism_id = "test.exact-json-fact"
    mechanism_digest = "sha256:" + hashlib.sha256(
        b"tests.ExactFactMechanism:v1"
    ).hexdigest()

    def evaluate(self, binding, evidence):
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one fact required")
        try:
            observed = json.loads(evidence[0])
        except (UnicodeDecodeError, json.JSONDecodeError):
            return MechanismDecision(MechanismOutcome.FAIL, "fact is not JSON")
        expected = {
            "subject_id": binding.subject_id,
            "predicate": binding.predicate,
            "expected": binding.expected,
        }
        outcome = MechanismOutcome.PASS if observed == expected else MechanismOutcome.FAIL
        return MechanismDecision(outcome, f"exact fact comparison: {outcome.value}")


def _session() -> tuple[EvidenceStore, VerificationSession]:
    store = EvidenceStore()
    session = VerificationSession(store)
    session.register(ExactFactMechanism())
    return store, session


def _proposition(
    store: EvidenceStore,
    subject: str,
    predicate: str,
    expected,
    *,
    parameters=None,
) -> BoundProposition:
    payload = json.dumps(
        {"subject_id": subject, "predicate": predicate, "expected": expected},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    reference = store.add(payload)
    return BoundProposition(
        subject,
        predicate,
        expected,
        ExactFactMechanism.mechanism_id,
        ExactFactMechanism.mechanism_digest,
        (reference,),
        ("test:exact-fact-policy",),
        EvidenceBounds(1, 20_000),
        parameters or {},
    )


def _binding() -> ClaimBinding:
    return ClaimBinding(
        "fixture claim",
        ClaimCoordinate("claim:fixture", "fixture", {"scope": "test"}),
        "a" * 64,
        "b" * 64,
        reference_descriptor(),
        ResourceBounds(20_000, 20_000, 200_000),
    )


def _established_vstd4(store, session, *, binding=None):
    binding = binding or _binding()
    parameters = {"claim_binding_digest": binding.digest()}
    prerequisites = {
        profile: _proposition(
            store,
            "claim:fixture",
            f"vstd.object_profile.{profile}",
            True,
            parameters=parameters,
        )
        for profile in (1, 2, 3)
    }
    rungs = {
        f"4.{index}": _proposition(
            store,
            "claim:fixture",
            f"vstd4.rung.4.{index}",
            True,
            parameters=parameters,
        )
        for index in range(1, 15)
    }
    return establish_vstd4(
        rungs,
        prerequisite_evidence=prerequisites,
        session=session,
        claim_id="claim:fixture",
        binding=binding,
    )


def _graph() -> ProvenanceHypergraph:
    graph = ProvenanceHypergraph()
    for artifact_id in ("source", "middle", "result"):
        graph.add_artifact(
            ArtifactNode(
                artifact_id,
                artifact_id,
                ArtifactType.MODEL,
                hashlib.sha256(artifact_id.encode()).hexdigest(),
                status=ArtifactStatus.VALID,
            )
        )
    graph.add_transformation(
        TransformationHyperedge(
            "first",
            "first",
            TransformationType.EXTRACTION,
            (HyperedgePort("source", "INPUT"),),
            (HyperedgePort("middle", "OUTPUT"),),
            {},
            {},
            {},
        )
    )
    graph.add_transformation(
        TransformationHyperedge(
            "second",
            "second",
            TransformationType.EVALUATION,
            (HyperedgePort("middle", "INPUT"),),
            (HyperedgePort("result", "OUTPUT"),),
            {},
            {},
            {},
        )
    )
    return graph


def _graph_rating_evidence(graph, store, binding, *, members=("result",), rating=5):
    collection_id = "collection:fixture"
    parameters = {
        "collection_id": collection_id,
        "collection_binding_digest": graph_collection_binding_digest(
            graph,
            collection_id=collection_id,
            members=members,
            binding=binding,
        ),
    }
    objects = {
        subject: _proposition(
            store,
            subject,
            "vstd.object_profile",
            rating,
            parameters=parameters,
        )
        for subject in graph.artifacts
    }
    edges = {
        subject: _proposition(
            store,
            subject,
            "vstd.graph_edge_profile",
            rating,
            parameters=parameters,
        )
        for subject in graph.transformations
    }
    return objects, edges


def _trust_proposition(
    store: EvidenceStore,
    ledger: AssuranceLedger,
    transformation_id: str,
    target_id: str,
    prerequisite_digests=(),
) -> BoundProposition:
    transform = ledger.graph.transformations[transformation_id]
    inputs = sorted({port.artifact_id for port in transform.inputs})
    prerequisites = sorted(set(prerequisite_digests))
    return _proposition(
        store,
        target_id,
        "vstd.graph.support",
        {
            "historical_graph_digest": ledger.graph_digest,
            "inputs": inputs,
            "output": target_id,
            "prerequisite_trust_event_digests": prerequisites,
            "transformation_id": transformation_id,
        },
    )


def _record_trust_chain(
    ledger: AssuranceLedger,
    store: EvidenceStore,
    session: VerificationSession,
):
    first_binding = _trust_proposition(store, ledger, "first", "middle")
    first = ledger.record_trust(
        "middle",
        ("source",),
        first_binding,
        transformation_id="first",
        session=session,
        recorded_at="2026-08-29T00:00:00Z",
    )
    second_binding = _trust_proposition(
        store, ledger, "second", "result", (first.digest(),)
    )
    second = ledger.record_trust(
        "result",
        ("middle",),
        second_binding,
        transformation_id="second",
        prerequisite_trust_event_digests=(first.digest(),),
        session=session,
        recorded_at="2026-08-29T00:00:01Z",
    )
    return first, second


def _witness_components(
    store: EvidenceStore,
    entry,
    witness_id: str,
    *,
    declarant_id: str = "declarant:one",
    identity_evidence_ref: str | None = None,
):
    binding_digest = entry.witness.header.binding
    identity_ref = identity_evidence_ref or store.add(
        f"identity coordinate:{witness_id}".encode()
    )
    witness = WitnessIdentity(witness_id, identity_ref)
    relation = f"{declarant_id}->{witness_id}"
    relationships = {
        dimension: RelationshipState.SEPARATE for dimension in IndependenceDimension
    }
    assertion = IndependenceAssertion(
        witness_id,
        relationships,
        {
            dimension: _proposition(
                store,
                relation,
                f"vstd5.shared.{dimension.value}",
                False,
                parameters={"claim_binding_digest": binding_digest},
            )
            for dimension in IndependenceDimension
        },
    )
    checker_digest = hashlib.sha256(witness_id.encode()).hexdigest()
    certificate_digest = entry.witness.digest()
    expected = {
        "claim_binding_digest": binding_digest,
        "vstd4_certificate_digest": certificate_digest,
        "checker_descriptor_digest": checker_digest,
        "corroboration_class": "TEST",
        "result": CorroborationOutcome.CORROBORATED.value,
    }
    verification = _proposition(
        store,
        "claim:fixture",
        "vstd5.corroboration",
        expected,
        parameters={
            "witness_id": witness_id,
            "observed_at": "2026-08-29T00:00:00Z",
        },
    )
    corroboration = CorroborationRecord(
        f"corroboration:{witness_id}",
        witness_id,
        binding_digest,
        certificate_digest,
        checker_digest,
        verification.evidence_refs,
        CorroborationOutcome.CORROBORATED,
        "2026-08-29T00:00:00Z",
        verification,
        "TEST",
    )
    return witness, assertion, corroboration


def _vstd5_schema_validator() -> Draft202012Validator:
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "receipts/schema/vstd5_receipt.json").read_text())
    vstd4_schema = json.loads(
        (root / "receipts/schema/vstd4_receipt.json").read_text()
    )
    assurance_schema = json.loads(
        (root / "standard/schemas/vstd-graph-assurance-1.schema.json").read_text()
    )
    registry = Registry().with_resource(
        vstd4_schema["$id"], Resource.from_contents(vstd4_schema)
    ).with_resource(
        assurance_schema["$id"], Resource.from_contents(assurance_schema)
    )
    return Draft202012Validator(schema, registry=registry)


def test_serialized_pass_is_not_an_input_to_evidence_evaluation() -> None:
    assert MechanismOutcome.__doc__ == "Enumeration of the exported result values."
    store, session = _session()
    proposition = _proposition(store, "a", "p", True)
    assert not hasattr(proposition, "outcome")
    assert session.evaluate(proposition).outcome is MechanismOutcome.PASS

    missing_mechanism = BoundProposition(
        "a",
        "p",
        True,
        "not.registered",
        "a" * 64,
        proposition.evidence_refs,
        ("test",),
        EvidenceBounds(1, 1000),
    )
    assert session.evaluate(missing_mechanism).outcome is MechanismOutcome.UNKNOWN


def test_duplicate_evidence_never_multiplies_support() -> None:
    store, _session_value = _session()
    reference = store.add(b"one")
    with pytest.raises(EvidenceBindingError, match="duplicate evidence"):
        BoundProposition(
            "a",
            "p",
            True,
            ExactFactMechanism.mechanism_id,
            ExactFactMechanism.mechanism_digest,
            (reference, reference),
            ("test",),
            EvidenceBounds(2, 100),
        )


def test_vstd4_can_be_established_only_by_rerunning_every_exact_binding() -> None:
    store, session = _session()
    result = _established_vstd4(store, session)
    assert result.depth == 14
    assert result.conformance_status == "ESTABLISHED"
    assert result.admits_vstd5 is True
    assert require_vstd5_entry(result) is result


def test_neighboring_rung_evidence_cannot_establish_vstd4() -> None:
    store, session = _session()
    binding = _binding()
    parameters = {"claim_binding_digest": binding.digest()}
    prerequisites = {
        profile: _proposition(
            store, "claim:fixture", f"vstd.object_profile.{profile}", True,
            parameters=parameters,
        )
        for profile in (1, 2, 3)
    }
    rungs = {
        f"4.{index}": _proposition(
            store,
            "claim:fixture",
            f"vstd4.rung.4.{index}",
            True,
            parameters=parameters,
        )
        for index in range(1, 15)
    }
    rungs["4.7"] = _proposition(
        store,
        "claim:neighbor",
        "vstd4.rung.4.7",
        True,
        parameters=parameters,
    )
    result = establish_vstd4(
        rungs,
        prerequisite_evidence=prerequisites,
        session=session,
        claim_id="claim:fixture",
        binding=binding,
    )
    assert result.depth == 6
    assert result.conformance_status == "NOT_ESTABLISHED"
    assert any("rung 4.7 targets" in error for error in result.binding_errors)


def test_evidence_bound_vstd4_receipt_replays_offline_and_matches_schema() -> None:
    store, session = _session()
    binding = _binding()
    parameters = {"claim_binding_digest": binding.digest()}
    prerequisites = {
        profile: _proposition(
            store, "claim:fixture", f"vstd.object_profile.{profile}", True,
            parameters=parameters,
        )
        for profile in (1, 2, 3)
    }
    rungs = {
        f"4.{index}": _proposition(
            store,
            "claim:fixture",
            f"vstd4.rung.4.{index}",
            True,
            parameters=parameters,
        )
        for index in range(1, 15)
    }
    result = establish_vstd4(
        rungs,
        prerequisite_evidence=prerequisites,
        session=session,
        claim_id="claim:fixture",
        binding=binding,
    )
    receipt = build_evidence_bound_vstd4_receipt(
        result,
        receipt_id="VFY-4-EVIDENCE-TEST",
        claim_id="claim:fixture",
        binding=binding,
        prerequisite_evidence=prerequisites,
        rung_evidence=rungs,
        session=session,
    )

    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "receipts/schema/vstd4_receipt.json").read_text())
    certificate_schema = json.loads(
        (root / "receipts/schema/vstd4_certificate.json").read_text()
    )
    registry = Registry().with_resource(
        certificate_schema["$id"], Resource.from_contents(certificate_schema)
    )
    Draft202012Validator(schema, registry=registry).validate(receipt)
    rechecked = recheck_evidence_bound_vstd4_receipt(
        receipt, mechanisms=(ExactFactMechanism(),)
    )
    assert rechecked.claim_id == "claim:fixture"
    assert rechecked.conformance_status == "ESTABLISHED"

    reference = next(iter(receipt["evidence_payloads"]))
    receipt["evidence_payloads"][reference] = "bm90LXRoZS1ldmlkZW5jZQ=="
    with pytest.raises(EvidenceBindingError, match="does not match"):
        recheck_evidence_bound_vstd4_receipt(
            receipt, mechanisms=(ExactFactMechanism(),)
        )


def test_graph_profile_can_be_established_from_mechanism_evaluated_ratings() -> None:
    graph = _graph()
    store, session = _session()
    binding = _binding()
    collection_parameters = {
        "collection_id": "collection:fixture",
        "collection_binding_digest": graph_collection_binding_digest(
            graph,
            collection_id="collection:fixture",
            members=("result",),
            binding=binding,
        ),
    }
    objects = {
        subject: _proposition(
            store,
            subject,
            "vstd.object_profile",
            5,
            parameters=collection_parameters,
        )
        for subject in graph.artifacts
    }
    edges = {
        subject: _proposition(
            store,
            subject,
            "vstd.graph_edge_profile",
            5,
            parameters=collection_parameters,
        )
        for subject in graph.transformations
    }
    result = establish_graph_level(
        graph,
        collection_id="collection:fixture",
        members=("result",),
        object_evidence=objects,
        edge_evidence=edges,
        session=session,
        binding=binding,
    )
    assert result.level == 5
    assert result.rating_basis == "MECHANISM_EVALUATED"
    assert result.conformance_status == "ESTABLISHED"

    caller_only = graph_level(
        graph,
        GraphCollection(
            "collection:fixture", ("result",),
            {item: 5 for item in graph.artifacts},
            {item: 5 for item in graph.transformations},
        ),
        binding=_binding(),
    )
    assert caller_only.conformance_status == "NOT_ESTABLISHED"

    record = build_evidence_bound_graph_level_record(
        result,
        graph=graph,
        members=("result",),
        binding=binding,
        object_evidence=objects,
        edge_evidence=edges,
        session=session,
    )
    root = Path(__file__).resolve().parents[1]
    graph_schema = json.loads(
        (root / "receipts/schema/vstd_graph_receipt.json").read_text()
    )
    vstd4_schema = json.loads((root / "receipts/schema/vstd4_receipt.json").read_text())
    assurance_schema = json.loads(
        (root / "standard/schemas/vstd-graph-assurance-1.schema.json").read_text()
    )
    registry = Registry()
    registry = registry.with_resource(vstd4_schema["$id"], Resource.from_contents(vstd4_schema))
    registry = registry.with_resource(
        assurance_schema["$id"], Resource.from_contents(assurance_schema)
    )
    Draft202012Validator(
        graph_schema["properties"]["computed_graph_level"], registry=registry
    ).validate(record)
    invalid_zero = copy.deepcopy(record)
    invalid_zero["level"] = 0
    assert list(
        Draft202012Validator(
            graph_schema["properties"]["computed_graph_level"], registry=registry
        ).iter_errors(invalid_zero)
    )
    rechecked = recheck_evidence_bound_graph_level_record(
        graph, record, mechanisms=(ExactFactMechanism(),)
    )
    assert rechecked.conformance_status == "ESTABLISHED"


def test_evidence_bound_graph_refuses_frozen_cross_kind_identifier_overlap() -> None:
    graph = _graph()
    graph.transformations["source"] = replace(
        graph.transformations["first"], transformation_id="source"
    )
    with pytest.raises(GraphEncodingError, match="globally disjoint"):
        establish_graph_level(
            graph,
            collection_id="collection:fixture",
            members=("result",),
            object_evidence={},
            edge_evidence={},
            session=_session()[1],
            binding=_binding(),
        )


def test_graph_ratings_are_bound_to_exact_collection_and_integer_type() -> None:
    graph = _graph()
    store, session = _session()
    binding = _binding()
    objects, edges = _graph_rating_evidence(graph, store, binding)

    neighboring = dict(objects)
    neighboring["source"] = _proposition(
        store,
        "source",
        "vstd.object_profile",
        5,
        parameters={
            "collection_id": "collection:fixture",
            "collection_binding_digest": "0" * 64,
        },
    )
    result = establish_graph_level(
        graph,
        collection_id="collection:fixture",
        members=("result",),
        object_evidence=neighboring,
        edge_evidence=edges,
        session=session,
        binding=binding,
    )
    assert result.level == 0
    assert result.conformance_status == "NOT_ESTABLISHED"
    assert any("not exactly collection-bound" in item for item in result.binding_errors)

    boolean_rating = dict(objects)
    boolean_rating["source"] = _proposition(
        store,
        "source",
        "vstd.object_profile",
        True,
        parameters=objects["source"].parameters,
    )
    result = establish_graph_level(
        graph,
        collection_id="collection:fixture",
        members=("result",),
        object_evidence=boolean_rating,
        edge_evidence=edges,
        session=session,
        binding=binding,
    )
    assert result.level == 0
    assert result.conformance_status == "NOT_ESTABLISHED"
    assert any("is not an integer" in item for item in result.binding_errors)


def test_profile_zero_never_becomes_established_conformance() -> None:
    graph = _graph()
    graph.artifacts["source"] = ArtifactNode(
        "source",
        "source",
        ArtifactType.MODEL,
        hashlib.sha256(b"source").hexdigest(),
        status=ArtifactStatus.CHALLENGED,
    )
    store, session = _session()
    binding = _binding()
    objects, edges = _graph_rating_evidence(graph, store, binding)
    result = establish_graph_level(
        graph,
        collection_id="collection:fixture",
        members=("result",),
        object_evidence=objects,
        edge_evidence=edges,
        session=session,
        binding=binding,
    )
    assert result.level == 0
    assert result.conformance_status == "NOT_ESTABLISHED"


def test_challenge_projection_changes_current_admissibility_not_history() -> None:
    graph = _graph()
    ledger = AssuranceLedger(graph)
    challenges = ChallengeLedger()
    surface = surface_from_types(
        ClaimCoordinate("source", "digest"),
        (RefutationType.EVIDENCE_HASH_MISMATCH,),
        overturning_evidence="a mismatching digest",
    )
    challenges.file(
        Challenge(
            "challenge:1",
            "source",
            "certificate:1",
            "digest",
            RefutationType.EVIDENCE_HASH_MISMATCH,
            "sha256:mismatch",
            "2026-08-29T00:00:00Z",
        ),
        surface,
    )
    events = ledger.project_challenges(challenges, recorded_at="2026-08-29T00:01:00Z")
    assert events[0].kind is AssuranceEventKind.STATUS_PROJECTION
    assert ledger.current_status("source") is ArtifactStatus.CHALLENGED
    assert graph.artifacts["source"].status is ArtifactStatus.VALID
    assert ledger.materialize_current_graph().artifacts["source"].status is ArtifactStatus.CHALLENGED


def test_upstream_challenge_invalidates_current_trust_and_graph_admission() -> None:
    graph = _graph()
    ledger = AssuranceLedger(graph)
    store, session = _session()
    first_binding = _trust_proposition(store, ledger, "first", "middle")
    first = ledger.record_trust(
        "middle",
        ("source",),
        first_binding,
        transformation_id="first",
        session=session,
        recorded_at="2026-08-29T00:00:00Z",
    )
    second_binding = _trust_proposition(
        store, ledger, "second", "result", (first.digest(),)
    )
    ledger.record_trust(
        "result",
        ("middle",),
        second_binding,
        transformation_id="second",
        prerequisite_trust_event_digests=(first.digest(),),
        session=session,
        recorded_at="2026-08-29T00:00:01Z",
    )
    assert len(ledger.current_trust_events()) == 2
    assert ledger.impacted_descendants("source") == ("middle", "result")

    challenges = ChallengeLedger()
    surface = surface_from_types(
        ClaimCoordinate("source", "digest"),
        (RefutationType.EVIDENCE_HASH_MISMATCH,),
        overturning_evidence="a mismatching digest",
    )
    challenges.file(
        Challenge(
            "challenge:impact",
            "source",
            "certificate:1",
            "digest",
            RefutationType.EVIDENCE_HASH_MISMATCH,
            "sha256:mismatch",
            "2026-08-29T00:01:00Z",
        ),
        surface,
    )
    ledger.project_challenges(challenges, recorded_at="2026-08-29T00:02:00Z")
    assert ledger.current_trust_events() == ()
    current = ledger.materialize_current_graph()
    candidate = graph_level(
        current,
        GraphCollection(
            "collection:fixture",
            ("result",),
            {item: 5 for item in current.artifacts},
            {item: 5 for item in current.transformations},
        ),
        binding=_binding(),
    )
    assert candidate.level == 0


def test_challenge_recovery_does_not_undo_independent_rot() -> None:
    graph = _graph()
    ledger = AssuranceLedger(graph)
    store, session = _session()
    rot = _proposition(
        store,
        "source",
        "vstd.graph.current_status",
        ArtifactStatus.STALE.value,
    )
    ledger.record_rot(
        "source",
        ArtifactStatus.STALE,
        rot,
        session=session,
        recorded_at="2026-08-29T00:00:00Z",
    )
    challenges = ChallengeLedger()
    surface = surface_from_types(
        ClaimCoordinate("source", "digest"),
        (RefutationType.EVIDENCE_HASH_MISMATCH,),
        overturning_evidence="a mismatching digest",
    )
    challenges.file(
        Challenge(
            "challenge:recovered",
            "source",
            "certificate:1",
            "digest",
            RefutationType.EVIDENCE_HASH_MISMATCH,
            "sha256:mismatch",
            "2026-08-29T00:01:00Z",
        ),
        surface,
    )
    challenges.adjudicate(
        Adjudication(
            "challenge:recovered",
            ChallengeOutcome.REJECTED,
            "counterevidence disproven",
            "2026-08-29T00:02:00Z",
        )
    )
    ledger.project_challenges(challenges, recorded_at="2026-08-29T00:03:00Z")
    assert ledger.current_status("source") is ArtifactStatus.STALE
    with pytest.raises(AssuranceFlowError, match="strictly degrade"):
        ledger.record_rot(
            "source",
            ArtifactStatus.STALE,
            rot,
            session=session,
            recorded_at="2026-08-29T00:04:00Z",
        )


def test_non_status_conflict_resolution_remains_admissibility_blocking() -> None:
    graph = _graph()
    graph.add_conflict(
        ConflictRecord(
            "conflict:digest",
            "source",
            "content_digest",
            ("sha256:a", "sha256:b"),
            ("receipt:a", "receipt:b"),
        )
    )
    ledger = AssuranceLedger(graph)
    store, session = _session()
    resolution = _proposition(
        store,
        "source",
        "vstd.graph.resolve.content_digest",
        "sha256:a",
        parameters={"conflict_id": "conflict:digest"},
    )
    ledger.resolve_conflict(
        "conflict:digest",
        "sha256:a",
        resolution,
        session=session,
        recorded_at="2026-08-29T00:00:00Z",
    )
    assert "conflict:digest" in graph.conflicts
    assert ledger.unresolved_conflicts() == ()
    assert tuple(
        item.conflict_id for item in ledger.admissibility_blocking_conflicts()
    ) == ("conflict:digest",)
    assert "conflict:digest" in ledger.materialize_current_graph().conflicts


def test_trust_rot_and_rust_follow_direction_without_recursive_amplification() -> None:
    graph = _graph()
    ledger = AssuranceLedger(graph)
    store, session = _session()

    trust = _trust_proposition(store, ledger, "first", "middle")
    first = ledger.record_trust(
        "middle", ("source", "source"), trust,
        transformation_id="first",
        session=session, recorded_at="2026-08-29T00:00:00Z",
    )
    second = ledger.record_trust(
        "middle", ("source",), trust,
        transformation_id="first",
        session=session, recorded_at="2026-08-29T00:00:00Z",
    )
    assert first.digest() == second.digest()
    assert len(ledger.events()) == 1

    rust = _proposition(store, "result", "vstd.graph.descendant_deviation", True)
    ledger.record_rust(
        "result", rust, session=session, recorded_at="2026-08-29T00:01:00Z"
    )
    ledger.record_rust(
        "result", rust, session=session, recorded_at="2026-08-29T00:01:00Z"
    )
    concentration = {item.ancestor_id: item for item in ledger.rust_concentration()}
    assert concentration["source"].count == 1

    rot = _proposition(
        store, "source", "vstd.graph.current_status", ArtifactStatus.REVOKED.value
    )
    ledger.record_rot(
        "source", ArtifactStatus.REVOKED, rot,
        session=session, recorded_at="2026-08-29T00:02:00Z",
    )
    assert ledger.current_status("source") is ArtifactStatus.REVOKED
    with pytest.raises(AssuranceFlowError, match="inadmissible target or transformation input"):
        ledger.record_trust(
            "middle", ("source",), trust,
            transformation_id="first",
            session=session, recorded_at="2026-08-29T00:03:00Z",
        )
    assert ledger.verify_hash_chain() is True


def test_trust_cannot_jump_over_an_unbound_transformation() -> None:
    ledger = AssuranceLedger(_graph())
    store, session = _session()
    direct = _proposition(
        store,
        "result",
        "vstd.graph.support",
        {
            "historical_graph_digest": ledger.graph_digest,
            "inputs": ["source"],
            "output": "result",
            "prerequisite_trust_event_digests": [],
            "transformation_id": "second",
        },
    )
    with pytest.raises(AssuranceFlowError, match="exact transformation input set"):
        ledger.record_trust(
            "result",
            ("source",),
            direct,
            transformation_id="second",
            session=session,
            recorded_at="2026-08-29T00:00:00Z",
        )

    missing_prerequisite = _trust_proposition(
        store, ledger, "second", "result"
    )
    with pytest.raises(AssuranceFlowError, match="exactly one current prerequisite"):
        ledger.record_trust(
            "result",
            ("middle",),
            missing_prerequisite,
            transformation_id="second",
            session=session,
            recorded_at="2026-08-29T00:00:01Z",
        )


@pytest.mark.parametrize(
    "status",
    (
        ArtifactStatus.CHALLENGED,
        ArtifactStatus.STALE,
        ArtifactStatus.REVOKED,
        ArtifactStatus.SUPERSEDED,
    ),
)
def test_intermediate_degradation_excludes_but_does_not_rewrite_trust(
    status: ArtifactStatus,
) -> None:
    ledger = AssuranceLedger(_graph())
    store, session = _session()
    first, second = _record_trust_chain(ledger, store, session)
    historical_digests = (first.digest(), second.digest())
    rot = _proposition(
        store, "middle", "vstd.graph.current_status", status.value
    )
    ledger.record_rot(
        "middle",
        status,
        rot,
        session=session,
        recorded_at="2026-08-29T00:01:00Z",
    )

    assert ledger.current_trust_events() == ()
    assert tuple(event.digest() for event in ledger.events()[:2]) == historical_digests
    assert all(event.outcome is MechanismOutcome.PASS for event in ledger.events()[:2])


@pytest.mark.parametrize("conflict_subject", ("middle", "first"))
def test_non_status_resolution_does_not_manufacture_current_trust(
    conflict_subject: str,
) -> None:
    ledger = AssuranceLedger(_graph())
    store, session = _session()
    first, second = _record_trust_chain(ledger, store, session)
    assert tuple(event.digest() for event in ledger.current_trust_events()) == (
        first.digest(),
        second.digest(),
    )

    conflict = ConflictRecord(
        f"conflict:{conflict_subject}",
        conflict_subject,
        "current_dependency_state",
        ("candidate:a", "candidate:b"),
        ("evidence:a", "evidence:b"),
    )
    conflict_binding = _proposition(
        store,
        conflict_subject,
        "vstd.graph.conflict",
        conflict.to_dict(),
    )
    ledger.record_conflict(
        conflict,
        conflict_binding,
        session=session,
        recorded_at="2026-08-29T00:01:00Z",
    )
    assert ledger.current_trust_events() == ()
    assert len(ledger.events()) == 3

    resolution = _proposition(
        store,
        conflict_subject,
        "vstd.graph.resolve.current_dependency_state",
        "candidate:a",
        parameters={"conflict_id": conflict.conflict_id},
    )
    ledger.resolve_conflict(
        conflict.conflict_id,
        "candidate:a",
        resolution,
        session=session,
        recorded_at="2026-08-29T00:02:00Z",
    )
    assert ledger.current_trust_events() == ()
    assert conflict.conflict_id in ledger.materialize_current_graph().conflicts
    with pytest.raises(AssuranceFlowError, match="admissible current-state consequence"):
        ledger.record_trust(
            "middle",
            ("source",),
            _trust_proposition(store, ledger, "first", "middle"),
            transformation_id="first",
            session=session,
            recorded_at="2026-08-29T00:02:01Z",
        )
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "standard/schemas/vstd-graph-assurance-1.schema.json").read_text()
    )
    graph_schema = json.loads(
        (root / "receipts/schema/vstd_graph_receipt.json").read_text()
    )
    registry = Registry().with_resource(
        graph_schema["$id"], Resource.from_contents(graph_schema)
    )
    Draft202012Validator(schema, registry=registry).validate(ledger.to_dict())
    replayed = recheck_assurance_log(
        ledger.to_dict(), mechanisms=(ExactFactMechanism(),)
    )
    assert replayed.current_trust_events() == ()
    assert conflict.conflict_id in replayed.materialize_current_graph().conflicts


@pytest.mark.parametrize(
    ("conflict_subject", "selected_value", "expected_current"),
    (
        ("middle", "VALID", True),
        ("middle", "REVOKED", False),
        ("first", "COMPLETED", True),
        ("first", "FAILED", False),
    ),
)
def test_status_resolution_projects_current_admissibility_and_replays(
    conflict_subject: str,
    selected_value: str,
    expected_current: bool,
) -> None:
    ledger = AssuranceLedger(_graph())
    store, session = _session()
    first, second = _record_trust_chain(ledger, store, session)
    competing = (
        ("VALID", "REVOKED")
        if conflict_subject == "middle"
        else ("COMPLETED", "FAILED")
    )
    conflict = ConflictRecord(
        f"conflict:{conflict_subject}-status",
        conflict_subject,
        "status",
        competing,
        ("evidence:admissible", "evidence:inadmissible"),
    )
    ledger.record_conflict(
        conflict,
        _proposition(store, conflict_subject, "vstd.graph.conflict", conflict.to_dict()),
        session=session,
        recorded_at="2026-08-29T00:01:00Z",
    )
    assert ledger.current_trust_events() == ()
    ledger.resolve_conflict(
        conflict.conflict_id,
        selected_value,
        _proposition(
            store,
            conflict_subject,
            "vstd.graph.resolve.status",
            selected_value,
            parameters={"conflict_id": conflict.conflict_id},
        ),
        session=session,
        recorded_at="2026-08-29T00:02:00Z",
    )

    expected_digests = (first.digest(), second.digest()) if expected_current else ()
    assert tuple(event.digest() for event in ledger.current_trust_events()) == expected_digests
    if conflict_subject == "middle":
        assert ledger.current_status("middle").value == selected_value
    else:
        assert ledger.current_transformation_status("first") == selected_value
    assert conflict.conflict_id not in ledger.materialize_current_graph().conflicts

    serialized = ledger.to_dict()
    assert any(
        event["kind"] == AssuranceEventKind.CONFLICT_DECLARATION.value
        and event["attributes"]["conflict"]["conflict_id"] == conflict.conflict_id
        for event in serialized["events"]
    )
    assert serialized["conflict_resolutions"][0]["conflict_id"] == conflict.conflict_id
    replayed = recheck_assurance_log(
        serialized, mechanisms=(ExactFactMechanism(),)
    )
    assert tuple(event.digest() for event in replayed.current_trust_events()) == expected_digests
    if conflict_subject == "middle":
        assert replayed.current_status("middle").value == selected_value
    else:
        assert replayed.current_transformation_status("first") == selected_value


def test_rust_requires_separate_localization_before_blame_or_guilt() -> None:
    graph = _graph()
    ledger = AssuranceLedger(graph)
    store, session = _session()
    rust = _proposition(store, "result", "vstd.graph.descendant_deviation", True)
    rust_event = ledger.record_rust(
        "result", rust, session=session, recorded_at="2026-08-29T00:00:00Z"
    )
    refused = ledger.diagnose(
        DiagnosticKind.BLAME,
        "source",
        "result",
        None,
        session=session,
        recorded_at="2026-08-29T00:01:00Z",
    )
    assert refused.status == "NOT_ESTABLISHED"

    localization = _proposition(
        store,
        "result",
        "vstd.graph.causal_localization",
        {
            "ancestor": "source",
            "descendant": "result",
            "rust_event_digest": rust_event.digest(),
            "deviation_binding_digest": rust.digest(),
        },
    )
    event = ledger.localize_cause(
        "source", "result", localization,
        rust_event_digest=rust_event.digest(),
        session=session, recorded_at="2026-08-29T00:02:00Z",
    )
    attribution = _proposition(
        store,
        "source",
        "vstd.graph.diagnostic.blame",
        {
            "ancestor": "source",
            "descendant": "result",
            "localization_event_digest": event.digest(),
        },
    )
    result = ledger.diagnose(
        DiagnosticKind.BLAME,
        "source",
        "result",
        attribution,
        session=session,
        recorded_at="2026-08-29T00:03:00Z",
    )
    assert result.status == "ESTABLISHED"
    assert "actor" not in result.details.lower()

    opaque_guilt = _proposition(
        store,
        "source",
        "vstd.graph.diagnostic.guilt",
        {
            "ancestor": "source",
            "descendant": "result",
            "localization_event_digest": event.digest(),
            "violated_obligation": "obligation:preserve-result-integrity",
        },
        parameters={"obligation": "obligation:preserve-result-integrity"},
    )
    guilt_result = ledger.diagnose(
        DiagnosticKind.GUILT,
        "source",
        "result",
        opaque_guilt,
        session=session,
        recorded_at="2026-08-29T00:04:00Z",
    )
    assert guilt_result.status == "NOT_ESTABLISHED"
    assert guilt_result.evaluation is None


def test_localization_selects_one_exact_passing_deviation() -> None:
    ledger = AssuranceLedger(_graph())
    store, session = _session()
    first_deviation = _proposition(
        store,
        "result",
        "vstd.graph.descendant_deviation",
        True,
        parameters={"deviation_id": "D1"},
    )
    second_deviation = _proposition(
        store,
        "result",
        "vstd.graph.descendant_deviation",
        True,
        parameters={"deviation_id": "D2"},
    )
    first_rust = ledger.record_rust(
        "result",
        first_deviation,
        session=session,
        recorded_at="2026-08-29T00:00:00Z",
    )
    second_rust = ledger.record_rust(
        "result",
        second_deviation,
        session=session,
        recorded_at="2026-08-29T00:01:00Z",
    )

    with pytest.raises(AssuranceFlowError, match="exact passing RUST event"):
        ledger.localize_cause(
            "source",
            "result",
            _proposition(
                store,
                "result",
                "vstd.graph.causal_localization",
                {
                    "ancestor": "source",
                    "descendant": "result",
                    "rust_event_digest": "0" * 64,
                    "deviation_binding_digest": first_deviation.digest(),
                },
            ),
            rust_event_digest="0" * 64,
            session=session,
            recorded_at="2026-08-29T00:02:00Z",
        )

    neighboring_rust = ledger.record_rust(
        "middle",
        _proposition(
            store,
            "middle",
            "vstd.graph.descendant_deviation",
            True,
            parameters={"deviation_id": "neighbor"},
        ),
        session=session,
        recorded_at="2026-08-29T00:03:00Z",
    )
    with pytest.raises(AssuranceFlowError, match="exact passing RUST event"):
        ledger.localize_cause(
            "source",
            "result",
            _proposition(
                store,
                "result",
                "vstd.graph.causal_localization",
                {
                    "ancestor": "source",
                    "descendant": "result",
                    "rust_event_digest": neighboring_rust.digest(),
                    "deviation_binding_digest": str(
                        neighboring_rust.attributes["binding_digest"]
                    ),
                },
            ),
            rust_event_digest=neighboring_rust.digest(),
            session=session,
            recorded_at="2026-08-29T00:04:00Z",
        )

    failed_reference = store.add(
        json.dumps(
            {
                "subject_id": "result",
                "predicate": "vstd.graph.descendant_deviation",
                "expected": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    failed_deviation = replace(first_deviation, evidence_refs=(failed_reference,))
    failed_rust = ledger.record_rust(
        "result",
        failed_deviation,
        session=session,
        recorded_at="2026-08-29T00:05:00Z",
    )
    assert failed_rust.outcome is MechanismOutcome.FAIL
    with pytest.raises(AssuranceFlowError, match="exact passing RUST event"):
        ledger.localize_cause(
            "source",
            "result",
            _proposition(
                store,
                "result",
                "vstd.graph.causal_localization",
                {
                    "ancestor": "source",
                    "descendant": "result",
                    "rust_event_digest": failed_rust.digest(),
                    "deviation_binding_digest": failed_deviation.digest(),
                },
            ),
            rust_event_digest=failed_rust.digest(),
            session=session,
            recorded_at="2026-08-29T00:06:00Z",
        )

    missing_ancestor_ledger = AssuranceLedger(_graph())
    missing_ancestor_store, missing_ancestor_session = _session()
    complete_rust = missing_ancestor_ledger.record_rust(
        "result",
        _proposition(
            missing_ancestor_store,
            "result",
            "vstd.graph.descendant_deviation",
            True,
        ),
        session=missing_ancestor_session,
        recorded_at="2026-08-29T00:06:01Z",
    )
    missing_ancestor_event = replace(complete_rust, source_ids=("middle",))
    missing_ancestor_ledger._events[0] = missing_ancestor_event
    with pytest.raises(AssuranceFlowError, match="exact passing RUST event"):
        missing_ancestor_ledger.localize_cause(
            "source",
            "result",
            _proposition(
                missing_ancestor_store,
                "result",
                "vstd.graph.causal_localization",
                {
                    "ancestor": "source",
                    "descendant": "result",
                    "rust_event_digest": missing_ancestor_event.digest(),
                    "deviation_binding_digest": str(
                        missing_ancestor_event.attributes["binding_digest"]
                    ),
                },
            ),
            rust_event_digest=missing_ancestor_event.digest(),
            session=missing_ancestor_session,
            recorded_at="2026-08-29T00:06:02Z",
        )

    localization = ledger.localize_cause(
        "source",
        "result",
        _proposition(
            store,
            "result",
            "vstd.graph.causal_localization",
            {
                "ancestor": "source",
                "descendant": "result",
                "rust_event_digest": first_rust.digest(),
                "deviation_binding_digest": first_deviation.digest(),
            },
        ),
        rust_event_digest=first_rust.digest(),
        session=session,
        recorded_at="2026-08-29T00:07:00Z",
    )
    assert localization.attributes["rust_event_digest"] == first_rust.digest()
    assert localization.attributes["deviation_binding_digest"] == first_deviation.digest()
    assert second_rust.digest() not in json.dumps(localization.to_dict())

    blame = _proposition(
        store,
        "source",
        "vstd.graph.diagnostic.blame",
        {
            "ancestor": "source",
            "descendant": "result",
            "localization_event_digest": localization.digest(),
        },
    )
    assert ledger.diagnose(
        DiagnosticKind.BLAME,
        "source",
        "result",
        blame,
        session=session,
        recorded_at="2026-08-29T00:08:00Z",
    ).status == "ESTABLISHED"

    tampered = copy.deepcopy(ledger.to_dict())
    localization_record = next(
        event
        for event in tampered["events"]
        if event["kind"] == AssuranceEventKind.CAUSAL_LOCALIZATION.value
    )
    localization_record["attributes"]["rust_event_digest"] = second_rust.digest()
    with pytest.raises(AssuranceFlowError):
        recheck_assurance_log(tampered, mechanisms=(ExactFactMechanism(),))


def test_assurance_event_log_is_portable_strict_and_evidence_complete() -> None:
    graph = _graph()
    ledger = AssuranceLedger(graph)
    store, session = _session()
    deviation = _proposition(store, "result", "vstd.graph.descendant_deviation", True)
    ledger.record_rust(
        "result",
        deviation,
        session=session,
        recorded_at="2026-08-29T00:00:00Z",
    )
    payload = ledger.to_dict()
    assert payload["historical_graph"] == graph.to_dict()
    assert set(payload["events"][0]["evidence_payloads"]) == set(
        payload["events"][0]["evidence_refs"]
    )

    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "standard/schemas/vstd-graph-assurance-1.schema.json").read_text()
    )
    graph_schema = json.loads(
        (root / "receipts/schema/vstd_graph_receipt.json").read_text()
    )
    registry = Registry().with_resource(
        graph_schema["$id"], Resource.from_contents(graph_schema)
    )
    Draft202012Validator(schema, registry=registry).validate(payload)

    restored = EvidenceStore()
    restored.import_base64(payload["events"][0]["evidence_payloads"])
    assert deviation.evidence_refs[0] in restored

    rechecked = recheck_assurance_log(
        payload,
        mechanisms=(ExactFactMechanism(),),
    )
    assert rechecked.to_dict() == payload

    tampered = copy.deepcopy(payload)
    tampered["events"][0]["details"] = "caller-rewritten outcome"
    with pytest.raises(AssuranceFlowError, match="does not match"):
        recheck_assurance_log(tampered, mechanisms=(ExactFactMechanism(),))


def test_assurance_replay_recomputes_challenge_projection() -> None:
    graph = _graph()
    ledger = AssuranceLedger(graph)
    challenges = ChallengeLedger()
    surface = surface_from_types(
        ClaimCoordinate("source", "digest"),
        (RefutationType.EVIDENCE_HASH_MISMATCH,),
        overturning_evidence="a mismatching digest",
    )
    challenges.file(
        Challenge(
            "challenge:replay",
            "source",
            "certificate:1",
            "digest",
            RefutationType.EVIDENCE_HASH_MISMATCH,
            "sha256:mismatch",
            "2026-08-29T00:00:00Z",
        ),
        surface,
    )
    ledger.project_challenges(challenges, recorded_at="2026-08-29T00:01:00Z")
    replayed = recheck_assurance_log(ledger.to_dict(), mechanisms=())
    assert replayed.current_status("source") is ArtifactStatus.CHALLENGED

    with pytest.raises(AssuranceFlowError, match="cannot be replaced"):
        recheck_assurance_log(
            ledger.to_dict(), mechanisms=(ChallengeProjectionMechanism(),)
        )


def test_assurance_ledger_refuses_recursive_cycle() -> None:
    graph = _graph()
    graph.add_transformation(
        TransformationHyperedge(
            "cycle",
            "cycle",
            TransformationType.EVALUATION,
            (HyperedgePort("result", "INPUT"),),
            (HyperedgePort("source", "OUTPUT"),),
            {},
            {},
            {},
        )
    )
    with pytest.raises(AssuranceFlowError, match="cyclic provenance"):
        AssuranceLedger(graph)


def test_vstd5_requires_every_independence_seam_and_preserves_disagreement() -> None:
    store, session = _session()
    entry = _established_vstd4(store, session)
    binding_digest = entry.witness.header.binding  # type: ignore[union-attr]
    witness = WitnessIdentity("witness:one", store.add(b"identity coordinate"))
    relation = "declarant:one->witness:one"
    relationships = {
        dimension: RelationshipState.SEPARATE for dimension in IndependenceDimension
    }
    independence = IndependenceAssertion(
        witness.witness_id,
        relationships,
        {
            dimension: _proposition(
                store,
                relation,
                f"vstd5.shared.{dimension.value}",
                False,
                parameters={"claim_binding_digest": binding_digest},
            )
            for dimension in IndependenceDimension
        },
    )

    def corroboration(record_id, outcome, observation):
        certificate_digest = entry.witness.digest()  # type: ignore[union-attr]
        expected = {
            "claim_binding_digest": binding_digest,
            "vstd4_certificate_digest": certificate_digest,
            "checker_descriptor_digest": "b" * 64,
            "corroboration_class": "TEST",
            "result": outcome.value,
        }
        verification = _proposition(
            store,
            "claim:fixture",
            "vstd5.corroboration",
            expected,
            parameters={
                "witness_id": witness.witness_id,
                "observed_at": "2026-08-29T00:00:00Z",
            },
        )
        # The observation is the exact fact the mechanism reruns.
        return CorroborationRecord(
            record_id,
            witness.witness_id,
            binding_digest,
            certificate_digest,
            "b" * 64,
            verification.evidence_refs,
            outcome,
            "2026-08-29T00:00:00Z",
            verification,
            observation,
        )

    yes = corroboration("corroboration:yes", CorroborationOutcome.CORROBORATED, "TEST")
    no = corroboration("corroboration:no", CorroborationOutcome.REFUTED, "TEST")
    bundle = WitnessBundle(
        "claim:fixture",
        "declarant:one",
        binding_digest,
        (witness,),
        (independence,),
        (yes, no),
    )
    result = assess_witness_corroboration(entry, bundle, session=session)
    assert result.conformance_status == "ESTABLISHED"
    assert result.computed_independence == "INDEPENDENT"
    assert result.status is WitnessResultStatus.CONFLICTED
    assert result.disagreements == (("corroboration:no", "corroboration:yes"),)

    receipt = build_vstd5_receipt(
        entry,
        bundle,
        result,
        receipt_id="VFY-5-EVIDENCE-TEST",
        session=session,
    )
    validator = _vstd5_schema_validator()
    validator.validate(receipt)
    false_positive = copy.deepcopy(receipt)
    false_positive["result"]["status"] = "CORROBORATED"
    false_positive["result"]["conformance_status"] = "NOT_ESTABLISHED"
    false_positive["result"]["computed_independence"] = "UNKNOWN"
    assert list(
        validator.iter_errors(false_positive)
    )
    false_independence = copy.deepcopy(receipt)
    false_independence["result"]["conformance_status"] = "NOT_ESTABLISHED"
    false_independence["result"]["identity_errors"] = [
        "duplicate witness identifier: witness:one"
    ]
    false_independence["result"]["errors"] = list(
        false_independence["result"]["identity_errors"]
    )
    assert list(
        validator.iter_errors(false_independence)
    )
    rechecked = recheck_vstd5_receipt(
        entry, receipt, mechanisms=(ExactFactMechanism(),)
    )
    assert rechecked.status is WitnessResultStatus.CONFLICTED

    uncertain = IndependenceAssertion(
        witness.witness_id,
        {**relationships, IndependenceDimension.CONTROL: RelationshipState.UNKNOWN},
        independence.evidence,
    )
    result = assess_witness_corroboration(
        entry,
        WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (witness,),
            (uncertain,),
            (yes,),
        ),
        session=session,
    )
    assert result.conformance_status == "NOT_ESTABLISHED"
    assert result.status is WitnessResultStatus.UNKNOWN
    assert result.computed_independence == "UNKNOWN"


def test_computed_independence_fails_closed_on_identity_and_assertion_errors() -> None:
    store, session = _session()
    entry = _established_vstd4(store, session)
    binding_digest = entry.witness.header.binding  # type: ignore[union-attr]
    witness, assertion, corroboration = _witness_components(
        store, entry, "witness:one"
    )

    duplicate_witness = assess_witness_corroboration(
        entry,
        WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (witness, witness),
            (assertion,),
            (corroboration,),
        ),
        session=session,
    )
    assert duplicate_witness.computed_independence == "UNKNOWN"
    assert any("duplicate witness identifier" in item for item in duplicate_witness.identity_errors)

    shared_identity = store.add(b"shared identity evidence")
    first = _witness_components(
        store, entry, "witness:first", identity_evidence_ref=shared_identity
    )
    second = _witness_components(
        store, entry, "witness:second", identity_evidence_ref=shared_identity
    )
    repeated_identity = assess_witness_corroboration(
        entry,
        WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (first[0], second[0]),
            (first[1], second[1]),
            (first[2], second[2]),
        ),
        session=session,
    )
    assert repeated_identity.computed_independence == "UNKNOWN"
    assert any("repeats another witness identity" in item for item in repeated_identity.identity_errors)

    missing = _witness_components(
        store,
        entry,
        "witness:missing",
        identity_evidence_ref="sha256:" + "0" * 64,
    )
    missing_identity = assess_witness_corroboration(
        entry,
        WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (missing[0],),
            (missing[1],),
            (missing[2],),
        ),
        session=session,
    )
    assert missing_identity.computed_independence == "UNKNOWN"
    assert any("identity evidence unavailable" in item for item in missing_identity.identity_errors)

    declarant = _witness_components(
        store, entry, "declarant:one", declarant_id="declarant:one"
    )
    reused_declarant = assess_witness_corroboration(
        entry,
        WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (declarant[0],),
            (declarant[1],),
            (declarant[2],),
        ),
        session=session,
    )
    assert reused_declarant.computed_independence == "UNKNOWN"
    assert any("is the declarant" in item for item in reused_declarant.identity_errors)

    missing_assertion = assess_witness_corroboration(
        entry,
        WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (witness,),
            (),
            (corroboration,),
        ),
        session=session,
    )
    assert missing_assertion.computed_independence == "UNKNOWN"
    assert any("no independence assertion" in item for item in missing_assertion.separation_errors)

    duplicate_assertion = assess_witness_corroboration(
        entry,
        WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (witness,),
            (assertion, assertion),
            (corroboration,),
        ),
        session=session,
    )
    assert duplicate_assertion.computed_independence == "UNKNOWN"
    assert any("duplicate independence assertion" in item for item in duplicate_assertion.separation_errors)


def test_vstd5_receipts_preserve_noncanonical_replay_inputs() -> None:
    store, session = _session()
    entry = _established_vstd4(store, session)
    binding_digest = entry.witness.header.binding  # type: ignore[union-attr]
    witness, assertion, corroboration = _witness_components(
        store, entry, "witness:one"
    )
    shared_identity = store.add(b"shared identity evidence for replay")
    first = _witness_components(
        store,
        entry,
        "witness:first",
        identity_evidence_ref=shared_identity,
    )
    second = _witness_components(
        store,
        entry,
        "witness:second",
        identity_evidence_ref=shared_identity,
    )
    orphan = replace(assertion, witness_id="witness:orphan")
    bundles = {
        "duplicate-assertion": WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (witness,),
            (assertion, assertion),
            (corroboration,),
        ),
        "orphan-assertion": WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (witness,),
            (assertion, orphan),
            (corroboration,),
        ),
        "duplicate-witness": WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (witness, witness),
            (assertion,),
            (corroboration,),
        ),
        "missing-assertion": WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (witness,),
            (),
            (corroboration,),
        ),
        "reused-identity": WitnessBundle(
            "claim:fixture",
            "declarant:one",
            binding_digest,
            (first[0], second[0]),
            (first[1], second[1]),
            (first[2], second[2]),
        ),
    }
    validator = _vstd5_schema_validator()

    for name, bundle in bundles.items():
        result = assess_witness_corroboration(entry, bundle, session=session)
        assert result.conformance_status == "NOT_ESTABLISHED", name
        receipt = build_vstd5_receipt(
            entry,
            bundle,
            result,
            receipt_id=f"VFY-5-{name.upper()}",
            session=session,
        )
        validator.validate(receipt)
        assert len(receipt["bundle"]["independence_assertions"]) == len(
            bundle.independence
        )
        rechecked = recheck_vstd5_receipt(
            entry, receipt, mechanisms=(ExactFactMechanism(),)
        )
        assert rechecked.to_dict() == result.to_dict(), name


def test_vstd5_builder_returns_only_strict_replayable_receipts() -> None:
    store, session = _session()
    entry = _established_vstd4(store, session)
    binding_digest = entry.witness.header.binding  # type: ignore[union-attr]
    witness, assertion, corroboration = _witness_components(
        store, entry, "witness:one"
    )
    valid = WitnessBundle(
        "claim:fixture",
        "declarant:one",
        binding_digest,
        (witness,),
        (assertion,),
        (corroboration,),
    )
    result = assess_witness_corroboration(entry, valid, session=session)
    assert result.status is WitnessResultStatus.CORROBORATED
    receipt = build_vstd5_receipt(
        entry, valid, result, receipt_id="VFY-5-STRICT", session=session
    )
    _vstd5_schema_validator().validate(receipt)
    assert recheck_vstd5_receipt(
        entry, receipt, mechanisms=(ExactFactMechanism(),)
    ).to_dict() == result.to_dict()

    invalid_bundles = {
        "no-witnesses": WitnessBundle(
            "claim:fixture", "declarant:one", binding_digest, (), (), ()
        ),
        "no-corroborations": replace(valid, corroborations=()),
        "empty-claim": replace(valid, claim_id=""),
        "empty-declarant": replace(valid, declarant_id=""),
        "empty-witness": replace(
            valid, witnesses=(replace(witness, witness_id=""),)
        ),
    }
    for name, bundle in invalid_bundles.items():
        result = assess_witness_corroboration(entry, bundle, session=session)
        with pytest.raises(ValueError, match="invalid VSTD-5 receipt shape"):
            build_vstd5_receipt(
                entry,
                bundle,
                result,
                receipt_id=f"VFY-5-{name.upper()}",
                session=session,
            )

    for receipt_id in ("", "invalid id"):
        with pytest.raises(ValueError, match="receipt_id"):
            build_vstd5_receipt(
                entry,
                valid,
                assess_witness_corroboration(entry, valid, session=session),
                receipt_id=receipt_id,
                session=session,
            )


def test_vstd5_claim_id_must_match_the_admitted_vstd4_claim() -> None:
    store, session = _session()
    entry = _established_vstd4(store, session)
    witness, assertion, corroboration = _witness_components(
        store, entry, "witness:one"
    )
    valid = WitnessBundle(
        entry.claim_id,
        "declarant:one",
        entry.witness.header.binding,  # type: ignore[union-attr]
        (witness,),
        (assertion,),
        (corroboration,),
    )
    positive = assess_witness_corroboration(entry, valid, session=session)
    assert positive.status is WitnessResultStatus.CORROBORATED
    assert positive.conformance_status == "ESTABLISHED"

    name_only = assess_witness_corroboration(
        entry, replace(valid, claim_id="claim:neighbor"), session=session
    )
    assert name_only.status is WitnessResultStatus.UNKNOWN
    assert name_only.conformance_status == "NOT_ESTABLISHED"
    assert (
        "witness bundle claim_id does not match the admitted VSTD-4 claim_id"
        in name_only.binding_errors
    )

    neighbor_verification = _proposition(
        store,
        "claim:neighbor",
        "vstd5.corroboration",
        dict(corroboration.verification.expected),
        parameters=dict(corroboration.verification.parameters),
    )
    neighbor_record = replace(
        corroboration,
        observed_evidence_refs=neighbor_verification.evidence_refs,
        verification=neighbor_verification,
    )
    neighbor = replace(
        valid,
        claim_id="claim:neighbor",
        corroborations=(neighbor_record,),
    )
    result = assess_witness_corroboration(entry, neighbor, session=session)
    assert result.status is WitnessResultStatus.UNKNOWN
    assert result.conformance_status == "NOT_ESTABLISHED"
    assert result.binding_errors == (
        "witness bundle claim_id does not match the admitted VSTD-4 claim_id",
    )

    receipt = build_vstd5_receipt(
        entry,
        neighbor,
        result,
        receipt_id="VFY-5-NEIGHBOR-CLAIM",
        session=session,
    )
    _vstd5_schema_validator().validate(receipt)
    assert recheck_vstd5_receipt(
        entry, receipt, mechanisms=(ExactFactMechanism(),)
    ).to_dict() == result.to_dict()

    positive_receipt = build_vstd5_receipt(
        entry,
        valid,
        positive,
        receipt_id="VFY-5-CLAIM-TAMPER",
        session=session,
    )
    positive_receipt["bundle"]["claim_id"] = "claim:neighbor"
    _vstd5_schema_validator().validate(positive_receipt)
    with pytest.raises(ValueError, match="recomputed VSTD-5 result"):
        recheck_vstd5_receipt(
            entry, positive_receipt, mechanisms=(ExactFactMechanism(),)
        )


def test_vstd5_entry_digest_binds_the_admitted_vstd4_claim_id() -> None:
    store, session = _session()
    entry = _established_vstd4(store, session)
    neighbor = replace(entry, claim_id="claim:neighbor")
    entry_digest = canonical_digest(entry.to_dict())
    neighbor_digest = canonical_digest(neighbor.to_dict())
    assert neighbor_digest != entry_digest

    witness, assertion, corroboration = _witness_components(
        store, entry, "witness:one"
    )
    bundle = WitnessBundle(
        entry.claim_id,
        "declarant:one",
        entry.witness.header.binding,  # type: ignore[union-attr]
        (witness,),
        (assertion,),
        (corroboration,),
    )
    result = assess_witness_corroboration(entry, bundle, session=session)
    receipt = build_vstd5_receipt(
        entry,
        bundle,
        result,
        receipt_id="VFY-5-ENTRY-CLAIM-DIGEST",
        session=session,
    )
    assert receipt["entry_vstd4"]["result_digest"] == entry_digest
    assert receipt["entry_vstd4"]["result_digest"] != neighbor_digest


def test_vstd5_claim_id_is_distinct_from_the_claim_coordinate_subject() -> None:
    store, session = _session()
    binding = replace(
        _binding(),
        coordinate=ClaimCoordinate(
            "artifact:coordinate-subject", "fixture", {"scope": "test"}
        ),
    )
    entry = _established_vstd4(store, session, binding=binding)
    witness, assertion, corroboration = _witness_components(
        store, entry, "witness:one"
    )
    bundle = WitnessBundle(
        "claim:fixture",
        "declarant:one",
        entry.witness.header.binding,  # type: ignore[union-attr]
        (witness,),
        (assertion,),
        (corroboration,),
    )
    result = assess_witness_corroboration(entry, bundle, session=session)
    assert entry.claim_id == "claim:fixture"
    assert entry.claim_id != binding.coordinate.subject
    assert result.status is WitnessResultStatus.CORROBORATED
    assert result.conformance_status == "ESTABLISHED"


def test_vstd5_rechecker_refuses_external_shape_and_payload_defects() -> None:
    store, session = _session()
    entry = _established_vstd4(store, session)
    binding_digest = entry.witness.header.binding  # type: ignore[union-attr]
    witness, assertion, corroboration = _witness_components(
        store, entry, "witness:one"
    )
    bundle = WitnessBundle(
        "claim:fixture",
        "declarant:one",
        binding_digest,
        (witness,),
        (assertion,),
        (corroboration,),
    )
    receipt = build_vstd5_receipt(
        entry,
        bundle,
        assess_witness_corroboration(entry, bundle, session=session),
        receipt_id="VFY-5-EXTERNAL",
        session=session,
    )
    malformed = []
    for coordinate, value in (
        (("receipt_id",), "invalid id"),
        (("bundle", "claim_id"), ""),
        (("bundle", "witnesses"), []),
        (("bundle", "corroborations"), []),
        (("bundle", "witnesses", 0, "witness_id"), ""),
    ):
        candidate = copy.deepcopy(receipt)
        target = candidate
        for part in coordinate[:-1]:
            target = target[part]
        target[coordinate[-1]] = value
        malformed.append(candidate)
    extra = copy.deepcopy(receipt)
    extra["result"]["unexpected"] = True
    malformed.append(extra)

    validator = _vstd5_schema_validator()
    for candidate in malformed:
        assert list(validator.iter_errors(candidate))
        with pytest.raises(ValueError, match="invalid VSTD-5 receipt shape"):
            recheck_vstd5_receipt(entry, candidate, mechanisms=())

    missing_payload = copy.deepcopy(receipt)
    missing_payload["evidence_payloads"].pop(
        next(iter(missing_payload["evidence_payloads"]))
    )
    with pytest.raises(ValueError, match="missing verdict-material bytes"):
        recheck_vstd5_receipt(entry, missing_payload, mechanisms=())


def test_vstd5_rechecker_refuses_schema_valid_cross_field_contradictions() -> None:
    store, session = _session()
    entry = _established_vstd4(store, session)
    witness, assertion, corroboration = _witness_components(
        store, entry, "witness:one"
    )
    bundle = WitnessBundle(
        "claim:fixture",
        "declarant:one",
        entry.witness.header.binding,  # type: ignore[union-attr]
        (witness,),
        (assertion,),
        (corroboration,),
    )
    result = assess_witness_corroboration(entry, bundle, session=session)
    receipt = build_vstd5_receipt(
        entry,
        bundle,
        result,
        receipt_id="VFY-5-CROSS-FIELD",
        session=session,
    )
    validator = _vstd5_schema_validator()

    for field_name in ("result_digest", "witness_digest"):
        candidate = copy.deepcopy(receipt)
        candidate["entry_vstd4"][field_name] = "0" * 64
        validator.validate(candidate)
        with pytest.raises(ValueError, match="inconsistent VSTD-4 entry"):
            recheck_vstd5_receipt(
                entry, candidate, mechanisms=(ExactFactMechanism(),)
            )

    relabeled = copy.deepcopy(receipt)
    relabeled["bundle"]["corroborations"][0][
        "corroboration_class"
    ] = "UNIVERSAL_FORMAL_PROOF"
    validator.validate(relabeled)
    with pytest.raises(ValueError, match="recomputed VSTD-5 result"):
        recheck_vstd5_receipt(
            entry, relabeled, mechanisms=(ExactFactMechanism(),)
        )

    relabeled_bundle = WitnessBundle.from_dict(relabeled["bundle"])
    relabeled_result = assess_witness_corroboration(
        entry, relabeled_bundle, session=session
    )
    assert relabeled_result.status is WitnessResultStatus.UNKNOWN
    assert relabeled_result.conformance_status == "NOT_ESTABLISHED"
    assert relabeled_result.corroboration_errors == (
        "corroboration corroboration:witness:one is not exactly bound",
    )
