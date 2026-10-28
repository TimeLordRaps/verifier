"""Public replay checked against finite polynomial support, including negatives.

Distinct square-free monomials form an independent basis over the Boolean
endpoint cube. A variable is visible exactly when its coefficient support
contains a monomial using it. Test values and step counts are dimensionless.
"""
import base64
from copy import deepcopy
from itertools import combinations, product
import hashlib
import json
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import sim_dynamics, sim_internal_state as internal


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(names, expression, hidden):
    before=dict.fromkeys(names,0.0)
    trace={'states':[before,dict.fromkeys(names,1.0)],'entropy':[1.0],'times':[0.0,1.0]}
    program={'transition':{name:{'op':'add','args':[{'var':name},{'var':'entropy'}]} for name in names},
        'initial_state':before,'trajectory_digest':digest(trace['states']),
        'entropy_digest':digest(trace['entropy']),'times_digest':digest(trace['times'])}
    objects=[NamespaceObject.create(name,kind,{}) for name,kind in
        [('data','DATA'),('checker','VERIFIER'),('world','OBJECT'),('env','ENV')]]
    subject=NamespaceObject.create('sim','SIM',
        {'scope':'selected-retained-trajectory-replay','artifact_digest':digest(program),'inputs_digest':digest(trace)},
        {'data':['data'],'verifier':['checker'],'objects':['world'],'env':['env']})
    objects.append(subject)
    evidence={'schema_version':sim_dynamics.EVIDENCE_VERSION,
        'objects':[obj.to_dict() for obj in objects],'artifact':program,'inputs':trace}
    child_policy=sim_dynamics.sim_dynamics_policy(trust_roots=['independent-polynomial-oracle'])
    child_request=sim_dynamics.sim_dynamics_request(subject_id='sim',object_digest=subject.digest,
        collection_digest=composition_digest(objects),artifact_digest=digest(program),inputs_digest=digest(trace),
        expected_counts={'states':2,'transitions':1},evidence_ref=digest(evidence),policy=child_policy)
    child=sim_dynamics.build_sim_dynamics_certificate(child_request,canonical_bytes(evidence),policy=child_policy)
    assert json.loads(child)['result']['status']=='PASS'
    artifact={'declared_complete':True,'channels':{'polynomial':expression}}
    evidence={'schema_version':internal.EVIDENCE_VERSION,'trajectory_certificate':base64.b64encode(child).decode('ascii'),
        'observation_artifact':artifact,'declared_hidden_changes':hidden}
    policy=internal.sim_internal_state_policy(trust_roots=['independent-polynomial-oracle'])
    request=internal.sim_internal_state_request(subject_id='sim',object_digest=subject.digest,
        collection_digest=composition_digest(objects),trajectory_request=child_request,trajectory_policy=child_policy,
        trajectory_certificate_digest='sha256:'+hashlib.sha256(child).hexdigest(),
        observation_artifact_digest=digest(artifact),hidden_changes_digest=digest(hidden),
        evidence_ref=digest(evidence),policy=policy)
    return request,policy,evidence


def replay(request,policy,evidence):
    request=deepcopy(request)
    request['evidence_ref']=digest(evidence)
    request['hidden_changes_digest']=digest(evidence['declared_hidden_changes'])
    certificate=internal.build_sim_internal_state_certificate(request,canonical_bytes(evidence),policy=policy)
    result=routes.replay_current_object_certificate(certificate,semantic_version=internal.SEMANTIC_VERSION,
        objective=internal.COORDINATE,represented_kind='SIM',expected_request=request,policy=policy)
    assert result['native_result']['sim_tier_2_conformance']=='NOT_ESTABLISHED'
    return result


CASES=[(('x','y','z'),row) for row in product((0,1),repeat=7)]
CASES += [(('x','y'),row) for row in product((-1,0,1),repeat=3)]


@pytest.mark.parametrize('names,coefficients',CASES)
def test_public_replay_matches_independent_support_and_rejects_inverted_membership(names,coefficients):
    monomials=[subset for width in range(1,len(names)+1) for subset in combinations(names,width)]
    expression=0.0
    visible=set()
    for coefficient,variables in zip(coefficients,monomials):
        if not coefficient:
            continue
        visible.update(variables)
        term=float(coefficient)
        for name in variables:
            term={'op':'mul','args':[term,{'var':name}]}
        expression={'op':'add','args':[expression,term]}
    hidden=[{'step':0,'state_key':name,'before':0.0,'after':1.0} for name in names if name not in visible]
    request,policy,evidence=selected(names,expression,hidden)
    assert replay(request,policy,evidence)['computational_status']=='PASS'
    # Independently select a wrong assertion, maintaining every transport digest.
    # The mechanism must refute its meaning, not merely detect stale transport.
    wrong=deepcopy(hidden)
    if names[0] in visible:
        wrong.append({'step':0,'state_key':names[0],'before':0.0,'after':1.0})
    else:
        wrong=[row for row in wrong if row['state_key']!=names[0]]
    evidence['declared_hidden_changes']=sorted(wrong,key=lambda row:row['state_key'])
    assert replay(request,policy,evidence)['computational_status']=='FAIL'


def test_ten_variable_sum_completes_within_selected_public_bound():
    names=tuple(f's{i:02d}' for i in range(10))
    expression=0.0
    for name in names:
        expression={'op':'add','args':[expression,{'var':name}]}
    request,policy,evidence=selected(names,expression,[])
    assert request['limits']['max_operations']==100000
    result=replay(request,policy,evidence)
    assert result['computational_status']=='PASS',result['native_result']['evaluation']
