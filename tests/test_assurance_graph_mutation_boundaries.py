"""Owner-scaffold regression handoff for the historical Graph invariant.

No threads, real-world deviation oracle, native binaries, or shared file writes.
"""
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from verifier.core.certificate import canonical_digest
from verifier.core.evidence import VerificationSession, EvidenceStore
from verifier.data.assurance import AssuranceLedger, AssuranceFlowError, ObligationCoordinate
from verifier.data.models import ArtifactStatus, ConflictRecord
from test_evidence_bound_assurance import (
    ExactFactMechanism, _graph, _session, _proposition, _trust_proposition, _add_late_edge,
    ChallengeLedger, ClaimCoordinate, RefutationType, surface_from_types, Challenge,
)


def prepare(ledger, store, session, entrypoint, bind=lambda p: p):
    when = '2026-10-08T00:00:00Z'
    if entrypoint == 'record_trust':
        p = bind(_trust_proposition(store, ledger, 'first', 'middle'))
        return lambda: ledger.record_trust('middle', ['source'], p,
            transformation_id='first', session=session, recorded_at=when)
    if entrypoint == 'record_rot':
        p = bind(_proposition(store, 'result', 'vstd.graph.current_status', 'REVOKED'))
        return lambda: ledger.record_rot('result', ArtifactStatus.REVOKED, p, session=session, recorded_at=when)
    if entrypoint == 'record_rust':
        p = bind(_proposition(store, 'result', 'vstd.graph.descendant_deviation', True))
        return lambda: ledger.record_rust('result', p, session=session, recorded_at=when)
    if entrypoint == 'localize_cause':
        # Preparation consumes only the unchanged exact-fact session.
        stable_store, stable_session = _session()
        deviation = _proposition(stable_store, 'result', 'vstd.graph.descendant_deviation', True)
        rust = ledger.record_rust('result', deviation, session=stable_session, recorded_at=when)
        p = bind(_proposition(store, 'result', 'vstd.graph.causal_localization', {
            'ancestor':'source','descendant':'result','rust_event_digest':rust.digest(),
            'deviation_binding_digest':rust.attributes['binding_digest']}))
        return lambda: ledger.localize_cause('source', 'result', p,
            rust_event_digest=rust.digest(),session=session,recorded_at=when)
    if entrypoint == 'impacted_descendants':
        return lambda: ledger.impacted_descendants('source')
    raise AssertionError(entrypoint)


@pytest.mark.parametrize('entrypoint', ['record_trust','record_rot','record_rust','localize_cause','impacted_descendants'])
@pytest.mark.parametrize('container', ['artifact_attributes','transform_parameters','software_provenance','execution_environment'])
def test_existing_guard_detects_nested_mutable_content(entrypoint, container):
    graph = _graph()
    if container == 'artifact_attributes':
        original = graph.artifacts['source'].attributes
    else:
        key = {'transform_parameters':'parameters','software_provenance':'software_provenance',
            'execution_environment':'execution_environment'}[container]
        original = getattr(graph.transformations['first'], key)
    original['nested'] = {'values':[0]}
    ledger = AssuranceLedger(graph)
    store, session = _session()
    action = prepare(ledger,store,session,entrypoint)
    events = ledger.events()
    target = ledger.graph.artifacts['source'].attributes if container == 'artifact_attributes' else getattr(ledger.graph.transformations['first'],key)
    target['nested']['values'].append(1)
    assert canonical_digest(ledger.graph.to_dict()) != ledger.graph_digest
    with pytest.raises(AssuranceFlowError, match='historical Graph changed after ledger creation'):
        action()
    assert ledger.events() == events


@pytest.mark.parametrize('entrypoint', ['record_trust','record_rot','record_rust','localize_cause'])
def test_synchronous_mechanism_mutation_cannot_commit_event(entrypoint):
    ledger = AssuranceLedger(_graph())

    class MutatingFact(ExactFactMechanism):
        mechanism_id = 'reviewer-b.exact-fact-mutating-ledger'
        mechanism_digest = 'sha256:' + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

        def evaluate(self, binding, evidence):
            decision = super().evaluate(binding,evidence)
            _add_late_edge(ledger.graph,'late-source','result','late-callback-edge')
            return decision

    store = EvidenceStore()
    session = VerificationSession(store)
    mechanism = MutatingFact()
    session.register(mechanism)
    action = prepare(ledger,store,session,entrypoint,
        bind=lambda p:replace(p,mechanism_id=mechanism.mechanism_id,mechanism_digest=mechanism.mechanism_digest))
    before = ledger.events()
    with pytest.raises(AssuranceFlowError,match='historical Graph changed after ledger creation'):
        action()
    assert ledger.events() == before


def test_trust_prerequisite_iterator_mutation_cannot_commit_event():
    ledger = AssuranceLedger(_graph())
    store, session = _session()
    p = _trust_proposition(store,ledger,'first','middle')
    before = ledger.events()

    def prerequisites():
        _add_late_edge(ledger.graph,'late-source','result','late-iterator-edge')
        yield from ()

    with pytest.raises(AssuranceFlowError,match='historical Graph changed after ledger creation'):
        ledger.record_trust('middle',['source'],p,transformation_id='first',
            prerequisite_trust_event_digests=prerequisites(),session=session,recorded_at='2026-10-08T00:00:00Z')
    assert ledger.events() == before


def test_builtin_challenge_projection_cannot_append_for_late_artifact():
    ledger = AssuranceLedger(_graph())
    before = ledger.events()
    _add_late_edge(ledger.graph,'source','late-result','late-projection-edge')
    c = ChallengeLedger()
    surface = surface_from_types(ClaimCoordinate('late-result','digest'),
        (RefutationType.EVIDENCE_HASH_MISMATCH,),overturning_evidence='a mismatching digest')
    c.file(Challenge('challenge:late','late-result','certificate:late','digest',
        RefutationType.EVIDENCE_HASH_MISMATCH,'sha256:mismatch','2026-08-29T00:00:00Z'),surface)
    with pytest.raises(AssuranceFlowError,match='historical Graph changed after ledger creation'):
        ledger.project_challenges(c,recorded_at='2026-10-08T00:00:00Z')
    assert ledger.events() == before


@pytest.mark.parametrize('entrypoint', [
    'project_challenges', 'record_status_projection', 'record_conflict', 'resolve_conflict',
    'record_trust', 'record_rot', 'record_rust', 'localize_cause',
    'establish_responsibility', 'establish_obligation_applicability',
    'establish_obligation_violation', 'establish_guilt_components',
    'compose_guilt', 'diagnose',
])
def test_event_entrypoints_refuse_preexisting_graph_drift(entrypoint):
    ledger = AssuranceLedger(_graph())
    _add_late_edge(ledger.graph, 'late-source', 'result', 'late-entrypoint-edge')
    before_events = ledger.events()
    before_resolutions = ledger.resolutions()

    when = '2026-10-08T00:00:00Z'
    if entrypoint == 'project_challenges':
        action = lambda: ledger.project_challenges(None, recorded_at=when)
    elif entrypoint == 'record_status_projection':
        action = lambda: ledger.record_status_projection(None, None, session=None, recorded_at=when)
    elif entrypoint == 'record_conflict':
        action = lambda: ledger.record_conflict(None, None, session=None, recorded_at=when)
    elif entrypoint == 'resolve_conflict':
        action = lambda: ledger.resolve_conflict('absent', '', None, session=None, recorded_at=when)
    elif entrypoint == 'record_trust':
        action = lambda: ledger.record_trust(None, (), None, transformation_id='', session=None, recorded_at=when)
    elif entrypoint == 'record_rot':
        action = lambda: ledger.record_rot(None, None, None, session=None, recorded_at=when)
    elif entrypoint == 'record_rust':
        action = lambda: ledger.record_rust(None, None, session=None, recorded_at=when)
    elif entrypoint == 'localize_cause':
        action = lambda: ledger.localize_cause(None, None, None, rust_event_digest='', session=None, recorded_at=when)
    elif entrypoint == 'establish_responsibility':
        action = lambda: ledger.establish_responsibility(None, None, None, localization_event_digest='', session=None, recorded_at=when)
    elif entrypoint == 'establish_obligation_applicability':
        action = lambda: ledger.establish_obligation_applicability(None, None, None, session=None, recorded_at=when)
    elif entrypoint == 'establish_obligation_violation':
        action = lambda: ledger.establish_obligation_violation(None, None, None, None, localization_event_digest='', applicability_component_digest='', session=None, recorded_at=when)
    elif entrypoint == 'establish_guilt_components':
        action = lambda: ledger.establish_guilt_components(None, None, None, None, None, None, localization_event_digest='', session=None, recorded_at=when)
    elif entrypoint == 'compose_guilt':
        action = lambda: ledger.compose_guilt(None, None, None, None, localization_event_digest='', responsibility_component_digest='', applicability_component_digest='', violation_component_digest='', session=None, recorded_at=when)
    else:
        action = lambda: ledger.diagnose(None, None, None, None, session=None, recorded_at=when)

    with pytest.raises(AssuranceFlowError, match='historical Graph changed after ledger creation'):
        action()
    assert ledger.events() == before_events
    assert ledger.resolutions() == before_resolutions


def test_resolution_callback_mutation_leaves_no_event_or_resolution():
    ledger = AssuranceLedger(_graph())
    store, session = _session()
    conflict = ConflictRecord(
        'conflict:callback', 'source', 'content_digest',
        ('sha256:a', 'sha256:b'), ('receipt:a', 'receipt:b'),
    )
    ledger.record_conflict(
        conflict,
        _proposition(store, 'source', 'vstd.graph.conflict', conflict.to_dict()),
        session=session,
        recorded_at='2026-10-08T00:00:00Z',
    )

    class MutatingResolution(ExactFactMechanism):
        mechanism_id = 'reviewer-b.exact-fact-mutating-resolution'
        mechanism_digest = 'sha256:' + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

        def evaluate(self, binding, evidence):
            decision = super().evaluate(binding, evidence)
            _add_late_edge(ledger.graph, 'late-source', 'result', 'late-resolution-edge')
            return decision

    resolution_store = EvidenceStore()
    resolution_session = VerificationSession(resolution_store)
    mechanism = MutatingResolution()
    resolution_session.register(mechanism)
    resolution = replace(
        _proposition(
            resolution_store,
            'source',
            'vstd.graph.resolve.content_digest',
            'sha256:a',
            parameters={'conflict_id': conflict.conflict_id},
        ),
        mechanism_id=mechanism.mechanism_id,
        mechanism_digest=mechanism.mechanism_digest,
    )
    before_events = ledger.events()
    before_resolutions = ledger.resolutions()
    with pytest.raises(AssuranceFlowError, match='historical Graph changed after ledger creation'):
        ledger.resolve_conflict(
            conflict.conflict_id,
            'sha256:a',
            resolution,
            session=resolution_session,
            recorded_at='2026-10-08T00:01:00Z',
        )
    assert ledger.events() == before_events
    assert ledger.resolutions() == before_resolutions


def test_compound_mechanism_mutation_commits_no_partial_components():
    ledger = AssuranceLedger(_graph())
    store, session = _session()
    localization = prepare(ledger, store, session, 'localize_cause')()
    obligation = ObligationCoordinate(
        obligation_id='test:obligation', scope={'jurisdiction': 'fixture'}
    )

    class MutatingCompound(ExactFactMechanism):
        mechanism_id = 'reviewer-b.exact-fact-mutating-compound'
        mechanism_digest = 'sha256:' + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

        def evaluate_compound(self, bindings, evidence_sets):
            decisions = tuple(
                super(MutatingCompound, self).evaluate(binding, evidence)
                for binding, evidence in zip(bindings, evidence_sets)
            )
            _add_late_edge(ledger.graph, 'late-source', 'result', 'late-compound-edge')
            return decisions

    compound_store = EvidenceStore()
    compound_session = VerificationSession(compound_store)
    mechanism = MutatingCompound()
    compound_session.register(mechanism)
    rust_digest = str(localization.attributes['rust_event_digest'])
    deviation_digest = str(localization.attributes['deviation_binding_digest'])
    responsibility = replace(
        _proposition(compound_store, 'source', 'vstd.graph.responsibility', {
            'ancestor_id': 'source', 'descendant_id': 'result',
            'localization_event_digest': localization.digest(),
            'rust_event_digest': rust_digest,
            'deviation_binding_digest': deviation_digest,
        }),
        mechanism_id=mechanism.mechanism_id,
        mechanism_digest=mechanism.mechanism_digest,
    )
    applicability = replace(
        _proposition(compound_store, 'source', 'vstd.graph.obligation_applicability', {
            'artifact_id': 'source', 'obligation_coordinate': obligation.to_dict(),
        }),
        mechanism_id=mechanism.mechanism_id,
        mechanism_digest=mechanism.mechanism_digest,
    )
    violation = replace(
        _proposition(compound_store, 'source', 'vstd.graph.obligation_violation', {
            'artifact_id': 'source', 'descendant_id': 'result',
            'localization_event_digest': localization.digest(),
            'rust_event_digest': rust_digest,
            'deviation_binding_digest': deviation_digest,
            'obligation_coordinate': obligation.to_dict(),
            'applicability_binding_digest': applicability.digest(),
        }),
        mechanism_id=mechanism.mechanism_id,
        mechanism_digest=mechanism.mechanism_digest,
    )
    before_events = ledger.events()
    with pytest.raises(AssuranceFlowError, match='historical Graph changed after ledger creation'):
        ledger.establish_guilt_components(
            'source', 'result', obligation, responsibility, applicability, violation,
            localization_event_digest=localization.digest(),
            session=compound_session,
            recorded_at='2026-10-08T00:02:00Z',
        )
    assert ledger.events() == before_events
