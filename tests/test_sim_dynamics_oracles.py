"""Independent multi-step arithmetic and adversarial selected-trace oracles."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable
import hashlib,json
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject,composition_digest
from verifier.domains.contracts import sim_dynamics as api

def digest(x: Any) -> str:return 'sha256:'+hashlib.sha256(canonical_bytes(x)).hexdigest()

def fixture(start: float = 0.0, steps: int = 3,
            corrupt: Callable[[dict[str, Any], dict[str, Any]], None] | None = None
            ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    # The arithmetic oracle is ordinary Python over exactly represented small integers.
    # The production expression interpreter is not used to build expected states.
    states=[{'x':float(start),'y':2.0}]; entropy=[]; times=[-10.0]
    for i in range(steps):
        e=float(i-1);prev=states[-1]
        states.append({'x':-prev['x']+e,'y':prev['y']*2.0})
        entropy.append(e);times.append(times[-1]+2.0)
    artifact={'transition':{
        'x':{'op':'add','args':[{'op':'neg','args':[{'var':'x'}]},{'var':'entropy'}]},
        'y':{'op':'mul','args':[{'var':'y'},2.0]}},'initial_state':deepcopy(states[0])}
    inputs={'states':states,'entropy':entropy,'times':times}
    if corrupt is not None:corrupt(artifact,inputs)
    artifact.update(trajectory_digest=digest(inputs['states']),entropy_digest=digest(inputs['entropy']),times_digest=digest(inputs['times']))
    objects=[NamespaceObject.create('d','DATA',{}),NamespaceObject.create('v','VERIFIER',{}),NamespaceObject.create('w','OBJECT',{}),NamespaceObject.create('e','ENV',{})]
    subject=NamespaceObject.create('s','SIM',{'scope':'selected-retained-trajectory-replay','artifact_digest':digest(artifact),'inputs_digest':digest(inputs)}, {'data':['d'],'verifier':['v'],'objects':['w'],'env':['e']})
    objects.append(subject)
    evidence={'schema_version':api.EVIDENCE_VERSION,'objects':[o.to_dict() for o in objects],'artifact':artifact,'inputs':inputs}
    policy=api.sim_dynamics_policy(trust_roots=['root-independent-finite-trace'])
    request=api.sim_dynamics_request(subject_id='s',object_digest=subject.digest,collection_digest=composition_digest(objects),artifact_digest=digest(artifact),inputs_digest=digest(inputs),expected_counts={'states':steps+1,'transitions':steps},evidence_ref=digest(evidence),policy=policy)
    return request,policy,evidence

def result(request: dict[str, Any], policy: dict[str, Any],
           evidence: dict[str, Any] | None) -> str:
    encoded=None if evidence is None else canonical_bytes(evidence)
    cert=api.build_sim_dynamics_certificate(request,encoded,policy=policy)
    outcome=api.recheck_sim_dynamics_certificate(cert,expected_request=request,policy=policy)
    assert outcome['sim_tier_2_conformance']=='NOT_ESTABLISHED'
    return outcome['status']

@pytest.mark.parametrize('start',[-3.0,0.0,7.0])
@pytest.mark.parametrize('steps',[1,2,5,9])
def test_independent_multivariable_multistep_trace(start: float, steps: int) -> None:
    assert result(*fixture(start,steps))=='PASS'

@pytest.mark.parametrize('step',[1,2,3])
@pytest.mark.parametrize('field',['x','y'])
def test_rehashed_single_internal_state_substitution(step: int, field: str) -> None:
    def mutate(artifact: dict[str, Any], inputs: dict[str, Any]) -> None:inputs['states'][step][field]+=1.0
    assert result(*fixture(corrupt=mutate))=='FAIL'

@pytest.mark.parametrize('kind',['same_time','reversed_time','extra_entropy','missing_entropy','missing_variable','extra_variable','wrong_initial','reserved_entropy','wrong_arity'])
def test_rehashed_structure_and_native_contradictions(kind: str) -> None:
    def mutate(a: dict[str, Any], b: dict[str, Any]) -> None:
        if kind=='same_time':b['times'][2]=b['times'][1]
        elif kind=='reversed_time':b['times'][2]=b['times'][1]-1.0
        elif kind=='extra_entropy':b['entropy'].append(0.0)
        elif kind=='missing_entropy':b['entropy'].pop()
        elif kind=='missing_variable':del b['states'][1]['y']
        elif kind=='extra_variable':b['states'][1]['z']=0.0
        elif kind=='wrong_initial':a['initial_state']['x']=91.0
        elif kind=='reserved_entropy':
            for state in b['states']:state['entropy']=0.0
            a['initial_state']['entropy']=0.0;a['transition']['entropy']=0.0
        elif kind=='wrong_arity':a['transition']['x']['args'].append(0.0)
    assert result(*fixture(corrupt=mutate))=='FAIL'

@pytest.mark.parametrize('missing',['artifact','inputs'])
def test_available_contradiction_is_not_masked_by_missing_counterpart(missing: str) -> None:
    r,p,e=fixture();e[missing]=None
    available='inputs' if missing=='artifact' else 'artifact'
    if available=='inputs':e['inputs']['times'][0]=300.0
    else:e['artifact']['initial_state']['x']=300.0
    r['evidence_ref']=digest(e)
    assert result(r,p,e)=='FAIL'

@pytest.mark.parametrize('missing',['artifact','inputs','bundle'])
def test_absent_selected_evidence_stays_unknown(missing: str) -> None:
    r,p,e=fixture()
    if missing=='bundle':e=None
    else:e[missing]=None;r['evidence_ref']=digest(e)
    assert result(r,p,e)=='UNKNOWN'

@pytest.mark.parametrize('limit',['max_operations','max_items','max_composition_operations'])
def test_bounded_resource_exhaustion_stays_unknown(limit: str) -> None:
    r,p,e=fixture();r['limits'][limit]=1
    assert result(r,p,e)=='UNKNOWN'

def test_recomputed_certificate_result_cannot_replace_native_replay() -> None:
    r,p,e=fixture();raw=api.build_sim_dynamics_certificate(r,canonical_bytes(e),policy=p)
    forged=json.loads(raw);forged['result']['historical_execution']='PASS'
    forged.pop('digest');forged['digest']=digest(forged)
    with pytest.raises(api.SimDynamicsError):api.recheck_sim_dynamics_certificate(canonical_bytes(forged),expected_request=r,policy=p)
