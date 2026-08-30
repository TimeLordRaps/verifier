"""Adversarial tests for component-earned artifact-relative GUILT."""

from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from verifier.core.evidence import (
    BoundProposition,
    EvidenceBindingError,
    EvidenceBounds,
    EvidenceStore,
    MechanismDecision,
    MechanismOutcome,
    VerificationSession,
)
from verifier.data.assurance import (
    AssuranceFlowError,
    AssuranceLedger,
    DiagnosticKind,
    ObligationCoordinate,
    recheck_assurance_log,
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


class ExactFactMechanism:
    mechanism_id = "test.guilt-exact-fact"
    mechanism_digest = "sha256:" + hashlib.sha256(b"guilt-exact-fact:v1").hexdigest()

    def evaluate(self, binding, evidence):
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one fact required")
        try:
            observed = json.loads(evidence[0])
        except (UnicodeDecodeError, json.JSONDecodeError):
            return MechanismDecision(MechanismOutcome.FAIL, "invalid fact")
        expected = {
            "subject_id": binding.subject_id,
            "predicate": binding.predicate,
            "expected": binding.expected,
        }
        outcome = MechanismOutcome.PASS if observed == expected else MechanismOutcome.FAIL
        return MechanismDecision(outcome, f"exact fact: {outcome.value}")


class CompoundExactFactMechanism(ExactFactMechanism):
    mechanism_id = "test.guilt-compound-facts"
    mechanism_digest = "sha256:" + hashlib.sha256(b"guilt-compound-facts:v1").hexdigest()

    def __init__(self):
        self.compound_calls = 0
        self.ordinary_calls = 0

    def evaluate(self, binding, evidence):
        self.ordinary_calls += 1
        return MechanismDecision(MechanismOutcome.UNKNOWN, "compound entry point required")

    def evaluate_compound(self, bindings, evidence_sets):
        self.compound_calls += 1
        return tuple(
            super(CompoundExactFactMechanism, self).evaluate(binding, evidence)
            for binding, evidence in zip(bindings, evidence_sets)
        )


class GuiltRig:
    def __init__(self):
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
        for identity, source, target in (
            ("first", "source", "middle"),
            ("second", "middle", "result"),
        ):
            graph.add_transformation(
                TransformationHyperedge(
                    identity,
                    identity,
                    TransformationType.EVALUATION,
                    (HyperedgePort(source, "INPUT"),),
                    (HyperedgePort(target, "OUTPUT"),),
                    {},
                    {},
                    {},
                )
            )
        self.ledger = AssuranceLedger(graph)
        self.store = EvidenceStore()
        self.session = VerificationSession(self.store)
        self.session.register(ExactFactMechanism())
        self.obligation = ObligationCoordinate(
            obligation_id="obligation:integrity",
            content_digest="sha256:" + "a" * 64,
            scope={"policy": "fixture-v1", "realm": "test", "version": "1"},
            assumptions=("fixture policy governs source",),
            exclusions=("no legal-liability conclusion",),
        )
        self.rust, self.localization = self.localize("source", "D1", minute=0)

    def proposition(
        self,
        subject,
        predicate,
        expected,
        *,
        outcome=MechanismOutcome.PASS,
        mechanism=ExactFactMechanism,
        parameters=None,
    ):
        payload = json.dumps(
            {"subject_id": subject, "predicate": predicate, "expected": expected},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        reference = self.store.add(payload)
        proposition = BoundProposition(
            subject,
            predicate,
            expected,
            mechanism.mechanism_id,
            mechanism.mechanism_digest,
            (reference,),
            ("test:guilt-policy",),
            EvidenceBounds(1, 20_000),
            parameters or {},
        )
        if outcome is MechanismOutcome.UNKNOWN:
            return replace(proposition, bounds=EvidenceBounds(0, 20_000))
        if outcome is MechanismOutcome.FAIL:
            wrong = self.store.add(
                json.dumps(
                    {"subject_id": subject, "predicate": predicate, "expected": "neighbor"},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            )
            return replace(proposition, evidence_refs=(wrong,))
        return proposition

    def localize(self, ancestor, deviation_id, *, minute):
        deviation = self.proposition(
            "result",
            "vstd.graph.descendant_deviation",
            True,
            parameters={"deviation_id": deviation_id},
        )
        rust = self.ledger.record_rust(
            "result",
            deviation,
            session=self.session,
            recorded_at=f"2026-08-29T10:{minute:02d}:00Z",
        )
        expected = {
            "ancestor": ancestor,
            "descendant": "result",
            "rust_event_digest": rust.digest(),
            "deviation_binding_digest": deviation.digest(),
        }
        localization = self.ledger.localize_cause(
            ancestor,
            "result",
            self.proposition("result", "vstd.graph.causal_localization", expected),
            rust_event_digest=rust.digest(),
            session=self.session,
            recorded_at=f"2026-08-29T10:{minute + 1:02d}:00Z",
        )
        return rust, localization

    def responsibility(self, *, ancestor="source", localization=None, outcome=MechanismOutcome.PASS):
        localization = localization or self.localization
        expected = {
            "ancestor_id": ancestor,
            "descendant_id": "result",
            "localization_event_digest": localization.digest(),
            "rust_event_digest": localization.attributes["rust_event_digest"],
            "deviation_binding_digest": localization.attributes["deviation_binding_digest"],
        }
        return self.ledger.establish_responsibility(
            ancestor,
            "result",
            self.proposition(
                ancestor, "vstd.graph.responsibility", expected, outcome=outcome
            ),
            localization_event_digest=localization.digest(),
            session=self.session,
            recorded_at="2026-08-29T10:10:00Z",
        )

    def applicability(self, *, artifact="source", obligation=None, outcome=MechanismOutcome.PASS):
        obligation = obligation or self.obligation
        expected = {
            "artifact_id": artifact,
            "obligation_coordinate": obligation.to_dict(),
        }
        proposition = self.proposition(
            artifact,
            "vstd.graph.obligation_applicability",
            expected,
            outcome=outcome,
        )
        event = self.ledger.establish_obligation_applicability(
            artifact,
            obligation,
            proposition,
            session=self.session,
            recorded_at="2026-08-29T10:11:00Z",
        )
        return proposition, event

    def violation(
        self,
        applicability,
        *,
        artifact="source",
        obligation=None,
        localization=None,
        outcome=MechanismOutcome.PASS,
    ):
        obligation = obligation or self.obligation
        localization = localization or self.localization
        expected = {
            "artifact_id": artifact,
            "descendant_id": "result",
            "localization_event_digest": localization.digest(),
            "rust_event_digest": localization.attributes["rust_event_digest"],
            "deviation_binding_digest": localization.attributes["deviation_binding_digest"],
            "obligation_coordinate": obligation.to_dict(),
            "applicability_binding_digest": applicability.attributes["binding_digest"],
        }
        return self.ledger.establish_obligation_violation(
            artifact,
            "result",
            obligation,
            self.proposition(
                artifact, "vstd.graph.obligation_violation", expected, outcome=outcome
            ),
            localization_event_digest=localization.digest(),
            applicability_component_digest=applicability.digest(),
            session=self.session,
            recorded_at="2026-08-29T10:12:00Z",
        )

    def compose(self, responsibility=None, applicability=None, violation=None, *, digests=None):
        component_digests = digests or (
            responsibility.digest() if responsibility else "1" * 64,
            applicability.digest() if applicability else "2" * 64,
            violation.digest() if violation else "3" * 64,
        )
        expected = {
            "ancestor_id": "source",
            "descendant_id": "result",
            "localization_event_digest": self.localization.digest(),
            "obligation_coordinate": self.obligation.to_dict(),
            "responsibility_component_digest": component_digests[0],
            "applicability_component_digest": component_digests[1],
            "violation_component_digest": component_digests[2],
        }
        return self.ledger.compose_guilt(
            "source",
            "result",
            self.obligation,
            self.proposition("source", "vstd.graph.diagnostic.guilt", expected),
            localization_event_digest=self.localization.digest(),
            responsibility_component_digest=component_digests[0],
            applicability_component_digest=component_digests[1],
            violation_component_digest=component_digests[2],
            session=self.session,
            recorded_at="2026-08-29T10:13:00Z",
        )

    def passing_components(self):
        responsibility = self.responsibility()
        _, applicability = self.applicability()
        violation = self.violation(applicability)
        return responsibility, applicability, violation


def test_opaque_or_incomplete_components_never_establish_guilt():
    rig = GuiltRig()
    decorative = rig.proposition(
        "source",
        "vstd.graph.diagnostic.guilt",
        {
            "ancestor": "source",
            "descendant": "result",
            "localization_event_digest": rig.localization.digest(),
            "violated_obligation": "obligation:decorative",
        },
        parameters={"obligation": "obligation:decorative"},
    )
    opaque = rig.ledger.diagnose(
        DiagnosticKind.GUILT,
        "source",
        "result",
        decorative,
        session=rig.session,
        recorded_at="2026-08-29T10:09:00Z",
    )
    assert opaque.status == "NOT_ESTABLISHED" and opaque.evaluation is None

    responsibility = rig.responsibility()
    assert rig.compose(responsibility).status == "NOT_ESTABLISHED"
    _, applicability = rig.applicability()
    assert rig.compose(responsibility, applicability).status == "NOT_ESTABLISHED"
    assert not any(event.attributes.get("diagnostic_kind") == "GUILT" for event in rig.ledger.events())


@pytest.mark.parametrize(
    ("component", "outcome"),
    [
        ("responsibility", MechanismOutcome.FAIL),
        ("responsibility", MechanismOutcome.UNKNOWN),
        ("applicability", MechanismOutcome.FAIL),
        ("applicability", MechanismOutcome.UNKNOWN),
        ("violation", MechanismOutcome.FAIL),
        ("violation", MechanismOutcome.UNKNOWN),
    ],
)
def test_fail_or_unknown_component_never_composes(component, outcome):
    rig = GuiltRig()
    responsibility = rig.responsibility(
        outcome=outcome if component == "responsibility" else MechanismOutcome.PASS
    )
    _, applicability = rig.applicability(
        outcome=outcome if component == "applicability" else MechanismOutcome.PASS
    )
    violation = None
    if applicability.outcome is MechanismOutcome.PASS:
        violation = rig.violation(
            applicability,
            outcome=outcome if component == "violation" else MechanismOutcome.PASS,
        )
    result = rig.compose(responsibility, applicability, violation)
    assert result.status == "NOT_ESTABLISHED" and result.evaluation is None


def test_neighboring_artifact_obligation_deviation_or_localization_cannot_compose():
    rig = GuiltRig()
    responsibility, applicability, _ = rig.passing_components()
    _, neighbor_app = rig.applicability(artifact="middle")
    assert rig.compose(responsibility, neighbor_app).status == "NOT_ESTABLISHED"

    other = ObligationCoordinate(
        obligation_id="obligation:neighbor",
        scope={"policy": "neighbor", "realm": "test"},
    )
    _, other_app = rig.applicability(obligation=other)
    assert rig.compose(responsibility, other_app).status == "NOT_ESTABLISHED"

    _, middle_localization = rig.localize("middle", "D-middle", minute=20)
    _, middle_app = rig.applicability(artifact="middle")
    middle_violation = rig.violation(
        middle_app, artifact="middle", localization=middle_localization
    )
    assert rig.compose(responsibility, applicability, middle_violation).status == "NOT_ESTABLISHED"

    _, second_localization = rig.localize("source", "D2", minute=30)
    second_violation = rig.violation(applicability, localization=second_localization)
    assert rig.compose(responsibility, applicability, second_violation).status == "NOT_ESTABLISHED"

    other_violation = rig.violation(other_app, obligation=other)
    assert rig.compose(responsibility, applicability, other_violation).status == "NOT_ESTABLISHED"


def test_exact_components_and_existing_blame_can_each_supply_responsibility():
    rig = GuiltRig()
    responsibility, applicability, violation = rig.passing_components()
    direct = rig.compose(responsibility, applicability, violation)
    assert direct.status == "ESTABLISHED"

    second = GuiltRig()
    blame_expected = {
        "ancestor": "source",
        "descendant": "result",
        "localization_event_digest": second.localization.digest(),
    }
    blame = second.ledger.diagnose(
        DiagnosticKind.BLAME,
        "source",
        "result",
        second.proposition("source", "vstd.graph.diagnostic.blame", blame_expected),
        session=second.session,
        recorded_at="2026-08-29T10:10:00Z",
    )
    assert blame.status == "ESTABLISHED"
    blame_event = second.ledger.events()[-1]
    _, second_applicability = second.applicability()
    second_violation = second.violation(second_applicability)
    assert second.compose(blame_event, second_applicability, second_violation).status == "ESTABLISHED"


def test_one_compound_invocation_emits_three_bound_results_and_replays_once():
    rig = GuiltRig()
    compound = CompoundExactFactMechanism()
    rig.session.register(compound)
    responsibility_expected = {
        "ancestor_id": "source",
        "descendant_id": "result",
        "localization_event_digest": rig.localization.digest(),
        "rust_event_digest": rig.localization.attributes["rust_event_digest"],
        "deviation_binding_digest": rig.localization.attributes["deviation_binding_digest"],
    }
    applicability_expected = {
        "artifact_id": "source",
        "obligation_coordinate": rig.obligation.to_dict(),
    }
    responsibility_proposition = rig.proposition(
        "source", "vstd.graph.responsibility", responsibility_expected,
        mechanism=CompoundExactFactMechanism,
    )
    applicability_proposition = rig.proposition(
        "source", "vstd.graph.obligation_applicability", applicability_expected,
        mechanism=CompoundExactFactMechanism,
    )
    violation_expected = {
        "artifact_id": "source",
        "descendant_id": "result",
        "localization_event_digest": rig.localization.digest(),
        "rust_event_digest": rig.localization.attributes["rust_event_digest"],
        "deviation_binding_digest": rig.localization.attributes["deviation_binding_digest"],
        "obligation_coordinate": rig.obligation.to_dict(),
        "applicability_binding_digest": applicability_proposition.digest(),
    }
    violation_proposition = rig.proposition(
        "source", "vstd.graph.obligation_violation", violation_expected,
        mechanism=CompoundExactFactMechanism,
    )
    components = rig.ledger.establish_guilt_components(
        "source",
        "result",
        rig.obligation,
        responsibility_proposition,
        applicability_proposition,
        violation_proposition,
        localization_event_digest=rig.localization.digest(),
        session=rig.session,
        recorded_at="2026-08-29T10:10:00Z",
    )
    assert compound.compound_calls == 1 and compound.ordinary_calls == 0
    assert all(event.outcome is MechanismOutcome.PASS for event in components)
    assert len({event.attributes["binding_digest"] for event in components}) == 3
    assert rig.compose(*components).status == "ESTABLISHED"

    replay_mechanism = CompoundExactFactMechanism()
    payload = rig.ledger.to_dict()
    replayed = recheck_assurance_log(
        payload, mechanisms=(ExactFactMechanism(), replay_mechanism)
    )
    assert replayed.to_dict() == payload
    assert replay_mechanism.compound_calls == 1 and replay_mechanism.ordinary_calls == 0


def _passing_payload():
    rig = GuiltRig()
    components = rig.passing_components()
    result = rig.compose(*components)
    assert result.status == "ESTABLISHED"
    return rig, components, result, rig.ledger.to_dict()


def test_schema_and_replay_accept_exact_component_log():
    _, _, _, payload = _passing_payload()
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "standard/schemas/vstd-graph-assurance-1.schema.json").read_text())
    graph_schema = json.loads((root / "receipts/schema/vstd_graph_receipt.json").read_text())
    registry = Registry().with_resource(graph_schema["$id"], Resource.from_contents(graph_schema))
    Draft202012Validator(schema, registry=registry).validate(payload)
    assert recheck_assurance_log(payload, mechanisms=(ExactFactMechanism(),)).to_dict() == payload


def test_duplicate_component_references_do_not_manufacture_strength():
    rig = GuiltRig()
    responsibility = rig.responsibility()
    duplicate = responsibility.digest()
    result = rig.compose(digests=(duplicate, duplicate, duplicate))
    assert result.status == "NOT_ESTABLISHED" and "distinct" in result.details


@pytest.mark.parametrize(
    "field",
    ["responsibility_component_digest", "applicability_component_digest", "violation_component_digest"],
)
def test_replay_refuses_changed_component_digest(field):
    _, _, _, payload = _passing_payload()
    guilt = next(event for event in payload["events"] if event["attributes"].get("diagnostic_kind") == "GUILT")
    guilt["attributes"][field] = "f" * 64
    with pytest.raises(AssuranceFlowError):
        recheck_assurance_log(payload, mechanisms=(ExactFactMechanism(),))


@pytest.mark.parametrize(
    ("kind", "path", "value"),
    [
        ("OBLIGATION_APPLICABILITY", ("artifact_id",), "middle"),
        ("OBLIGATION_APPLICABILITY", ("obligation_coordinate", "obligation_id"), "obligation:neighbor"),
        ("OBLIGATION_APPLICABILITY", ("obligation_coordinate", "scope", "policy"), "neighbor"),
        ("OBLIGATION_VIOLATION", ("descendant_id",), "middle"),
        ("OBLIGATION_VIOLATION", ("localization_event_digest",), "e" * 64),
    ],
)
def test_replay_refuses_changed_artifact_obligation_scope_deviation_or_localization(kind, path, value):
    _, _, _, payload = _passing_payload()
    event = next(item for item in payload["events"] if item["kind"] == kind)
    target = event["attributes"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(AssuranceFlowError):
        recheck_assurance_log(payload, mechanisms=(ExactFactMechanism(),))


def test_replay_refuses_changed_evidence_outcome_or_event_order():
    _, _, _, original = _passing_payload()
    evidence = copy.deepcopy(original)
    applicability = next(event for event in evidence["events"] if event["kind"] == "OBLIGATION_APPLICABILITY")
    reference = next(iter(applicability["evidence_payloads"]))
    applicability["evidence_payloads"][reference] = "bmVpZ2hib3I="
    with pytest.raises(EvidenceBindingError):
        recheck_assurance_log(evidence, mechanisms=(ExactFactMechanism(),))

    outcome = copy.deepcopy(original)
    next(event for event in outcome["events"] if event["kind"] == "OBLIGATION_VIOLATION")["outcome"] = "FAIL"
    with pytest.raises(AssuranceFlowError):
        recheck_assurance_log(outcome, mechanisms=(ExactFactMechanism(),))

    order = copy.deepcopy(original)
    first = next(index for index, event in enumerate(order["events"]) if event["kind"] == "RESPONSIBILITY_COMPONENT")
    second = next(index for index, event in enumerate(order["events"]) if event["kind"] == "OBLIGATION_APPLICABILITY")
    order["events"][first], order["events"][second] = order["events"][second], order["events"][first]
    with pytest.raises(AssuranceFlowError):
        recheck_assurance_log(order, mechanisms=(ExactFactMechanism(),))


def test_result_never_renders_innocence_morality_reputation_or_legal_liability():
    _, _, result, _ = _passing_payload()
    rendered = json.dumps(result.to_dict(), sort_keys=True).lower()
    for prohibited in (
        "innocence",
        "moral culpability",
        "actor reputation",
        "general actor trust",
        "legal liability",
    ):
        assert prohibited not in rendered
