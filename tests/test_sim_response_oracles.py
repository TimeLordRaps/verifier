"""Independent integer action-response oracles for the selected finite model."""
from __future__ import annotations
import base64
from copy import deepcopy
import hashlib
import json
from typing import Any
import pytest
from test_current_sim_response import selected
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject,composition_digest
from verifier.domains.contracts import sim_dynamics,sim_response

def digest(value: Any) -> str:
    return 'sha256:'+hashlib.sha256(canonical_bytes(value)).hexdigest()

def raw_digest(raw: bytes) -> str:
    return 'sha256:'+hashlib.sha256(raw).hexdigest()

def fixture(gain: int=2,actions: tuple[int,...]=(1,-1,2),start: int=-3,delay: float=0.5,*,integer_encoding: bool=False) -> tuple[dict,dict,dict]:
    # Ordinary integer arithmetic constructs the trajectory without either native interpreter.
    states=[{'x':start}]
    for action in actions:states.append({'x':states[-1]['x']+gain*action})
    # The selected native interpreter emits floats; exact canonical-byte replay
    # distinguishes 1 from 1.0. These small integers convert without rounding.
    if not integer_encoding:states=[{'x':float(row['x'])} for row in states]
    trace={'states':states,'entropy':[gain*a for a in actions],'times':[i*delay for i in range(len(states))]}
    program={'transition':{'x':{'op':'add','args':[{'var':'x'},{'var':'entropy'}]}},
        'initial_state':states[0],'trajectory_digest':digest(states),'entropy_digest':digest(trace['entropy']),'times_digest':digest(trace['times'])}
    objects=[NamespaceObject.create('data','DATA',{}),NamespaceObject.create('checker','VERIFIER',{}),NamespaceObject.create('world','OBJECT',{}),NamespaceObject.create('env','ENV',{})]
    subject=NamespaceObject.create('sim','SIM',{'scope':'selected-retained-trajectory-replay','artifact_digest':digest(program),'inputs_digest':digest(trace)},
        {'data':['data'],'verifier':['checker'],'objects':['world'],'env':['env']});objects.append(subject)
    child_evidence=canonical_bytes({'schema_version':sim_dynamics.EVIDENCE_VERSION,'objects':[o.to_dict() for o in objects],'artifact':program,'inputs':trace})
    child_policy=sim_dynamics.sim_dynamics_policy(trust_roots=['independent-model-oracle'])
    child_request=sim_dynamics.sim_dynamics_request(subject_id='sim',object_digest=subject.digest,collection_digest=composition_digest(objects),artifact_digest=digest(program),inputs_digest=digest(trace),expected_counts={'states':len(states),'transitions':len(actions)},evidence_ref=raw_digest(child_evidence),policy=child_policy)
    child=sim_dynamics.build_sim_dynamics_certificate(child_request,child_evidence,policy=child_policy)
    child_result=sim_dynamics.recheck_sim_dynamics_certificate(child,expected_request=child_request,policy=child_policy)
    assert child_result['status']==('FAIL' if integer_encoding else 'PASS'),child_result['evaluation']
    action_program={'program':{'x':{'op':'add','args':[{'var':'x'},{'op':'mul','args':[gain,{'var':'action.force'}]}]}},
        'baseline_action':{'force':0},'action_bounds':{'force':{'minimum':-2,'maximum':2}},'time_unit':'model_ticks'}
    action_inputs={'actions':[{'force':a} for a in actions]}
    evidence={'schema_version':sim_response.EVIDENCE_VERSION,'trajectory_certificate':base64.b64encode(child).decode(),
        'action_artifact':action_program,'action_inputs':action_inputs}
    policy=sim_response.sim_response_policy(trust_roots=['independent-model-oracle'])
    request=sim_response.sim_response_request(subject_id='sim',object_digest=subject.digest,collection_digest=composition_digest(objects),
        trajectory_request=child_request,trajectory_policy=child_policy,trajectory_certificate_digest=raw_digest(child),
        action_artifact_digest=digest(action_program),action_inputs_digest=digest(action_inputs),max_response_delay=delay,time_unit='model_ticks',evidence_ref=digest(evidence),policy=policy)
    return request,policy,evidence

def run(request: dict,policy: dict,evidence: dict,*,reselect: bool=True) -> dict:
    if reselect:
        for field in ('action_artifact','action_inputs'):
            if evidence[field] is not None:request[field+'_digest']=digest(evidence[field])
    raw=canonical_bytes(evidence);request['evidence_ref']=raw_digest(raw)
    certificate=sim_response.build_sim_response_certificate(request,raw,policy=policy)
    assert certificate==sim_response.build_sim_response_certificate(request,raw,policy=policy)
    return sim_response.recheck_sim_response_certificate(certificate,expected_request=request,policy=policy)

@pytest.mark.parametrize('gain',[-2,-1,1,2])
@pytest.mark.parametrize('actions',[(-2,),(-1,),(1,),(2,),(1,-1,2),(-2,1,-1)])
def test_integer_counterfactual_oracle(gain: int,actions: tuple[int,...]) -> None:
    request,policy,evidence=fixture(gain,actions)
    result=run(request,policy,evidence)
    assert result['status']=='PASS'
    assert result['evaluation']['observations']['responsive_steps']==len(actions)
    assert result['physical_time_truth']=='NOT_ESTABLISHED' and result['authority']=='NOT_ESTABLISHED'

def test_integer_encoded_trace_is_distinct_from_native_float_output() -> None:
    request,policy,evidence=fixture(integer_encoding=True)
    assert run(request,policy,evidence)['status']=='FAIL'

@pytest.mark.parametrize('mutation',['same_baseline','wrong_next','no_action_effect','wrong_unit','empty_actions','missing_action_name','action_outside','baseline_outside','reversed_bounds','extra_action_name','missing_program_state','delay_exceeded'])
def test_reselected_false_action_claim_is_refuted(mutation: str) -> None:
    request,policy,evidence=fixture();artifact=evidence['action_artifact'];inputs=evidence['action_inputs']
    if mutation=='same_baseline':artifact['baseline_action']['force']=1
    elif mutation=='wrong_next':artifact['program']['x']['args'][1]['args'][0]=1
    elif mutation=='no_action_effect':artifact['program']['x']={'op':'add','args':[{'var':'x'},{'var':'entropy'}]}
    elif mutation=='wrong_unit':artifact['time_unit']='another_unit'
    elif mutation=='empty_actions':inputs['actions']=[]
    elif mutation=='missing_action_name':artifact['program']['x']['args'][1]['args'][1]={'var':'action.absent'}
    elif mutation=='action_outside':artifact['action_bounds']['force']['maximum']=1
    elif mutation=='baseline_outside':artifact['baseline_action']['force']=3
    elif mutation=='reversed_bounds':artifact['action_bounds']['force']={'minimum':2,'maximum':-2}
    elif mutation=='extra_action_name':inputs['actions'][0]['extra']=1
    elif mutation=='missing_program_state':artifact['program']={}
    elif mutation=='delay_exceeded':request['max_response_delay']=0.25
    assert run(request,policy,evidence)['status']=='FAIL'

@pytest.mark.parametrize('field',['trajectory_certificate','action_artifact','action_inputs'])
def test_genuine_missing_evidence_remains_unknown(field: str) -> None:
    request,policy,evidence=fixture();evidence[field]=None
    assert run(request,policy,evidence)['status']=='UNKNOWN'

@pytest.mark.parametrize('field',['max_operations','max_items','max_evidence_bytes'])
def test_selected_resource_shortfall_remains_unknown(field: str) -> None:
    request,policy,evidence=fixture();request['limits'][field]=1
    assert run(request,policy,evidence)['status']=='UNKNOWN'

@pytest.mark.parametrize('field',['subject_id','time_unit','max_response_delay'])
def test_external_selection_cannot_be_substituted(field: str) -> None:
    request,policy,evidence=fixture();raw=canonical_bytes(evidence)
    cert=sim_response.build_sim_response_certificate(request,raw,policy=policy)
    changed=deepcopy(request);changed[field]='substitute' if field!='max_response_delay' else 1.0
    with pytest.raises(ValueError):sim_response.recheck_sim_response_certificate(cert,expected_request=changed,policy=policy)


@pytest.mark.parametrize('child_status',['PASS','FAIL','UNKNOWN','FORGED'])
@pytest.mark.parametrize('omitted',[(),('action_artifact',),('action_inputs',),('action_artifact','action_inputs')])
def test_available_child_refutation_survives_unavailable_action_evidence(child_status: str,omitted: tuple[str,...]) -> None:
    request,policy,evidence=selected();request=deepcopy(request);value=json.loads(evidence)
    original=base64.b64decode(value['trajectory_certificate'])
    child=json.loads(original);child_req=request['trajectory_request'];child_policy=request['trajectory_policy']
    child_evidence=base64.b64decode(child['evidence_payloads'][child_req['evidence_ref']])
    if child_status=='FAIL':
        child_req['expected_counts']['states']+=1
        child_req['expected_counts']['transitions']+=1
    child_bytes=sim_dynamics.build_sim_dynamics_certificate(child_req,None if child_status=='UNKNOWN' else child_evidence,policy=child_policy)
    assert sim_dynamics.recheck_sim_dynamics_certificate(child_bytes,expected_request=child_req,policy=child_policy)['status']==('PASS' if child_status=='FORGED' else child_status)
    if child_status=='FORGED':
        forged=json.loads(child_bytes);forged['result']['status']='FAIL';forged.pop('digest');forged['digest']=raw_digest(canonical_bytes(forged));child_bytes=canonical_bytes(forged)
        with pytest.raises(ValueError):sim_dynamics.recheck_sim_dynamics_certificate(child_bytes,expected_request=child_req,policy=child_policy)
    value['trajectory_certificate']=base64.b64encode(child_bytes).decode('ascii')
    request['trajectory_certificate_digest']=raw_digest(child_bytes)
    for field in omitted:value[field]=None
    evidence=canonical_bytes(value);request['evidence_ref']=raw_digest(evidence)
    cert=sim_response.build_sim_response_certificate(request,evidence,policy=policy)
    result=sim_response.recheck_sim_response_certificate(cert,expected_request=request,policy=policy)
    expected='FAIL' if child_status in ('FAIL','FORGED') else 'UNKNOWN' if omitted or child_status=='UNKNOWN' else 'PASS'
    assert result['status']==expected,(child_status,omitted,result['evaluation'])


@pytest.mark.parametrize('baseline,expected',[(0.0,'FAIL'),(-0.0,'FAIL'),(1.0,'PASS')])
def test_numerically_identical_action_and_next_state_do_not_establish_response(baseline: float,expected: str) -> None:
    request,policy,evidence=fixture(gain=1,actions=(0,),start=0)
    evidence['action_artifact']['program']={'x':{'var':'action.force'}}
    evidence['action_artifact']['baseline_action']['force']=baseline
    evidence['action_inputs']['actions'][0]['force']=0.0
    assert (0.0==baseline)==(expected=='FAIL')
    result=run(request,policy,evidence)
    assert result['status']==expected,result['evaluation']
