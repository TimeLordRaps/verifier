"""Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD).

Adversarial tests for evidence-bound object, Graph, lifecycle, and witness paths.
"""

from __future__ import annotations

import copy
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
    trust = _proposition(
        store,
        "result",
        "vstd.graph.support",
        {"sources": ["source"], "target": "result"},
    )
    ledger.record_trust(
        "result",
        ("source",),
        trust,
        session=session,
        recorded_at="2026-08-29T00:00:00Z",
    )
    assert len(ledger.current_trust_events()) == 1
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


def test_conflict_resolution_is_additive_and_mechanism_bound() -> None:
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
    assert ledger.materialize_current_graph().conflicts == {}


def test_trust_rot_and_rust_follow_direction_without_recursive_amplification() -> None:
    graph = _graph()
    ledger = AssuranceLedger(graph)
    store, session = _session()

    trust = _proposition(
        store,
        "result",
        "vstd.graph.support",
        {"sources": ["source"], "target": "result"},
    )
    first = ledger.record_trust(
        "result", ("source", "source"), trust,
        session=session, recorded_at="2026-08-29T00:00:00Z",
    )
    second = ledger.record_trust(
        "result", ("source",), trust,
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
    with pytest.raises(AssuranceFlowError, match="inadmissible target or ancestry"):
        ledger.record_trust(
            "result", ("source",), trust,
            session=session, recorded_at="2026-08-29T00:03:00Z",
        )
    assert ledger.verify_hash_chain() is True


def test_rust_requires_separate_localization_before_blame_or_guilt() -> None:
    graph = _graph()
    ledger = AssuranceLedger(graph)
    store, session = _session()
    rust = _proposition(store, "result", "vstd.graph.descendant_deviation", True)
    ledger.record_rust(
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
        {"ancestor": "source", "descendant": "result"},
    )
    event = ledger.localize_cause(
        "source", "result", localization,
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

    guilt = _proposition(
        store,
        "source",
        "vstd.graph.diagnostic.guilt",
        {
            "ancestor": "source",
            "descendant": "result",
            "localization_event_digest": event.digest(),
        },
    )
    with pytest.raises(AssuranceFlowError, match="violated obligation"):
        ledger.diagnose(
            DiagnosticKind.GUILT,
            "source",
            "result",
            guilt,
            session=session,
            recorded_at="2026-08-29T00:04:00Z",
        )


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
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "receipts/schema/vstd5_receipt.json").read_text())
    vstd4_schema = json.loads((root / "receipts/schema/vstd4_receipt.json").read_text())
    assurance_schema = json.loads(
        (root / "standard/schemas/vstd-graph-assurance-1.schema.json").read_text()
    )
    registry = Registry()
    registry = registry.with_resource(vstd4_schema["$id"], Resource.from_contents(vstd4_schema))
    registry = registry.with_resource(
        assurance_schema["$id"], Resource.from_contents(assurance_schema)
    )
    Draft202012Validator(schema, registry=registry).validate(receipt)
    false_positive = copy.deepcopy(receipt)
    false_positive["result"]["status"] = "CORROBORATED"
    false_positive["result"]["conformance_status"] = "NOT_ESTABLISHED"
    false_positive["result"]["computed_independence"] = "UNKNOWN"
    assert list(
        Draft202012Validator(schema, registry=registry).iter_errors(false_positive)
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
