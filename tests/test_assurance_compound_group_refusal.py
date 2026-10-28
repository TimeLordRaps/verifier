"""Finite lifecycle boundaries from actual owner scaffolds; no concurrency."""
import copy
import json

import pytest
from verifier.core.evidence import EvidenceStore, VerificationSession
from verifier.data.assurance import AssuranceFlowError, recheck_assurance_log
from verifier.data.models import ConflictRecord, ProvenanceHypergraph
from test_evidence_bound_assurance import _add_late_edge
from test_guilt_composition import GuiltRig, ExactFactMechanism, CompoundExactFactMechanism


class TruthfulExportHook(EvidenceStore):
    """Keep exact export behavior, then execute a synchronous observation hook."""
    def __init__(self, payloads, callback, at_export):
        super().__init__()
        self._payloads = dict(payloads)
        self.callback = callback
        self.at_export = at_export
        self.export_calls = 0

    def export_base64(self, references):
        result = super().export_base64(references)
        self.export_calls += 1
        if self.export_calls == self.at_export:
            self.callback()
        return result


def rig_with_export_hook(at_export):
    rig = GuiltRig()
    store = TruthfulExportHook(rig.store._payloads,
        lambda:_add_late_edge(rig.ledger.graph,'late-source','result','late-export-edge'), at_export)
    rig.store = store
    rig.session = VerificationSession(store)
    rig.session.register(ExactFactMechanism())
    return rig


def compound_action(rig):
    compound = CompoundExactFactMechanism()
    rig.session.register(compound)
    responsibility_expected={'ancestor_id':'source','descendant_id':'result',
        'localization_event_digest':rig.localization.digest(),
        'rust_event_digest':rig.localization.attributes['rust_event_digest'],
        'deviation_binding_digest':rig.localization.attributes['deviation_binding_digest']}
    applicability_expected={'artifact_id':'source','obligation_coordinate':rig.obligation.to_dict()}
    r=rig.proposition('source','vstd.graph.responsibility',responsibility_expected,mechanism=CompoundExactFactMechanism)
    a=rig.proposition('source','vstd.graph.obligation_applicability',applicability_expected,mechanism=CompoundExactFactMechanism)
    violation_expected={'artifact_id':'source','descendant_id':'result',
        'localization_event_digest':rig.localization.digest(),
        'rust_event_digest':rig.localization.attributes['rust_event_digest'],
        'deviation_binding_digest':rig.localization.attributes['deviation_binding_digest'],
        'obligation_coordinate':rig.obligation.to_dict(),'applicability_binding_digest':a.digest()}
    v=rig.proposition('source','vstd.graph.obligation_violation',violation_expected,mechanism=CompoundExactFactMechanism)
    action=lambda:rig.ledger.establish_guilt_components('source','result',rig.obligation,r,a,v,
        localization_event_digest=rig.localization.digest(),session=rig.session,recorded_at='2026-10-08T00:00:00Z')
    return action,compound


@pytest.mark.parametrize('at_export',[1,2,3])
def test_compound_graph_refusal_keeps_entire_event_group_uncommitted(at_export):
    rig=rig_with_export_hook(at_export)
    before=rig.ledger.events()
    graph_before=copy.deepcopy(rig.ledger.graph.to_dict())
    action,compound=compound_action(rig)
    with pytest.raises(AssuranceFlowError,match='historical Graph changed after ledger creation'):
        action()
    appended=rig.ledger.events()[len(before):]
    # Diagnostic reset of this disposable Graph distinguishes an incomplete
    # group from the already-known raw Graph drift; it is not a repair proposal.
    rig.ledger.graph=ProvenanceHypergraph.from_dict(graph_before)
    replay_error=None
    try:
        recheck_assurance_log(rig.ledger.to_dict(),mechanisms=[ExactFactMechanism(),CompoundExactFactMechanism()])
    except AssuranceFlowError as exc:
        replay_error=str(exc)
    print('ATOMIC_GROUP_OBSERVATION',json.dumps({'at_export':at_export,
        'compound_calls':compound.compound_calls,'ordinary_calls':compound.ordinary_calls,
        'appended_count':len(appended),'appended_kinds':[e.kind.value for e in appended],
        'component_indices':[e.attributes.get('compound_component_index') for e in appended],
        'hash_chain_valid':rig.ledger.verify_hash_chain(),'replay_error_after_graph_reset':replay_error},sort_keys=True))
    assert compound.compound_calls==1 and compound.ordinary_calls==0
    assert rig.ledger.events()==before,'refused compound transition left a partial component group'
    assert replay_error is None


def conflict_for(rig):
    refs=(rig.store.add(b'competing first record'),rig.store.add(b'competing second record'))
    return ConflictRecord('conflict:lifecycle','source','status',('VALID','REVOKED'),refs)


def test_conflict_export_refusal_does_not_update_conflict_or_events():
    rig=rig_with_export_hook(1)
    conflict=conflict_for(rig)
    p=rig.proposition('source','vstd.graph.conflict',conflict.to_dict())
    before_events=rig.ledger.events()
    before_conflicts=dict(rig.ledger._conflicts)
    with pytest.raises(AssuranceFlowError,match='historical Graph changed after ledger creation'):
        rig.ledger.record_conflict(conflict,p,session=rig.session,recorded_at='2026-10-08T00:00:00Z')
    assert rig.ledger.events()==before_events and rig.ledger._conflicts==before_conflicts


def test_resolution_export_refusal_does_not_update_resolution_or_events():
    rig=rig_with_export_hook(2)
    conflict=conflict_for(rig)
    p=rig.proposition('source','vstd.graph.conflict',conflict.to_dict())
    rig.ledger.record_conflict(conflict,p,session=rig.session,recorded_at='2026-10-08T00:00:00Z')
    p=rig.proposition('source','vstd.graph.resolve.status','VALID',parameters={'conflict_id':conflict.conflict_id})
    before_events=rig.ledger.events()
    before_resolutions=rig.ledger.resolutions()
    with pytest.raises(AssuranceFlowError,match='historical Graph changed after ledger creation'):
        rig.ledger.resolve_conflict(conflict.conflict_id,'VALID',p,session=rig.session,recorded_at='2026-10-08T00:00:01Z')
    assert rig.ledger.events()==before_events and rig.ledger.resolutions()==before_resolutions
