"""Independent selected-artifact contradictions versus unavailable prerequisites."""
import base64
from copy import deepcopy
import hashlib
import json
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import sim_dynamics, sim_internal_state as internal


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical_bytes(value)).hexdigest()


def fixture(context):
    trace = {'states': [{'x': 2.0}, {'x': 5.0}], 'entropy': [3.0], 'times': [0.0, 1.0]}
    program = {'transition': {'x': {'op': 'add', 'args': [{'var': 'x'}, {'var': 'entropy'}]}},
               'initial_state': {'x': 2.0}, 'trajectory_digest': digest(trace['states']),
               'entropy_digest': digest(trace['entropy']), 'times_digest': digest(trace['times'])}
    objects = [NamespaceObject.create(name,kind,{}) for name,kind in
               [('data','DATA'),('checker','VERIFIER'),('world','OBJECT'),('env','ENV')]]
    subject = NamespaceObject.create('sim','SIM',
        {'scope':'selected-retained-trajectory-replay','artifact_digest':digest(program),'inputs_digest':digest(trace)},
        {'data':['data'],'verifier':['checker'],'objects':['world'],'env':['env']})
    objects.append(subject)
    child_evidence = {'schema_version':sim_dynamics.EVIDENCE_VERSION,
        'objects':[obj.to_dict() for obj in objects],'artifact':program,'inputs':trace}
    child_policy = sim_dynamics.sim_dynamics_policy(trust_roots=['independent-wrapper-oracle'])
    child_request = sim_dynamics.sim_dynamics_request(subject_id='sim',object_digest=subject.digest,
        collection_digest=composition_digest(objects),artifact_digest=digest(program),inputs_digest=digest(trace),
        expected_counts={'states':2,'transitions':1},evidence_ref=digest(child_evidence),policy=child_policy)
    child = sim_dynamics.build_sim_dynamics_certificate(child_request,
        None if context == 'unknown-child' else canonical_bytes(child_evidence),policy=child_policy)
    assert json.loads(child)['result']['status'] == ('UNKNOWN' if context == 'unknown-child' else 'PASS')
    artifact = {'declared_complete':True,'channels':{'constant':0.0}}
    hidden = [{'step':0,'state_key':'x','before':2.0,'after':5.0}]
    evidence = {'schema_version':internal.EVIDENCE_VERSION,
        'trajectory_certificate':None if context == 'absent-child' else base64.b64encode(child).decode('ascii'),
        'observation_artifact':artifact,
        'declared_hidden_changes':None if context == 'absent-enumeration' else hidden}
    policy = internal.sim_internal_state_policy(trust_roots=['independent-wrapper-oracle'])
    request = internal.sim_internal_state_request(subject_id='sim',object_digest=subject.digest,
        collection_digest=composition_digest(objects),trajectory_request=child_request,
        trajectory_policy=child_policy,trajectory_certificate_digest='sha256:'+hashlib.sha256(child).hexdigest(),
        observation_artifact_digest=digest(artifact),hidden_changes_digest=digest(hidden),
        evidence_ref=digest(evidence),policy=policy)
    return request,policy,evidence


def replay(request,policy,evidence):
    request = deepcopy(request)
    request['evidence_ref'] = digest(evidence)
    certificate = internal.build_sim_internal_state_certificate(request,canonical_bytes(evidence),policy=policy)
    result = routes.replay_current_object_certificate(certificate,
        semantic_version=internal.SEMANTIC_VERSION,objective=internal.COORDINATE,
        represented_kind='SIM',expected_request=request,policy=policy)
    assert result['native_result']['channel_inventory_authority'] == 'NOT_ESTABLISHED'
    return result


CONTEXTS = ['complete','absent-child','unknown-child','absent-enumeration']
INVALID_ARTIFACTS = {
    'nonboolean-completeness': {'declared_complete':1,'channels':{'constant':0.0}},
    'missing-completeness': {'channels':{'constant':0.0}},
    'unexpected-artifact-field': {'declared_complete':True,'channels':{'constant':0.0},'extra':0},
    'channels-array': {'declared_complete':True,'channels':[]},
}


@pytest.mark.parametrize('context',CONTEXTS)
@pytest.mark.parametrize('variant',INVALID_ARTIFACTS)
def test_present_invalid_artifact_is_not_masked_by_unavailable_dependency(context,variant):
    request,policy,evidence = fixture(context)
    evidence['observation_artifact'] = deepcopy(INVALID_ARTIFACTS[variant])
    request['observation_artifact_digest'] = digest(evidence['observation_artifact'])
    result = replay(request,policy,evidence)
    assert result['computational_status'] == 'FAIL', result['native_result']['evaluation']


@pytest.mark.parametrize('context',CONTEXTS)
def test_genuine_missing_dependency_is_unknown_and_complete_evidence_passes(context):
    request,policy,evidence = fixture(context)
    result = replay(request,policy,evidence)
    assert result['computational_status'] == ('PASS' if context == 'complete' else 'UNKNOWN')


@pytest.mark.parametrize('context',CONTEXTS)
def test_selected_artifact_digest_contradiction_remains_fail(context):
    request,policy,evidence = fixture(context)
    evidence['observation_artifact']['channels']['constant'] = 1.0
    assert replay(request,policy,evidence)['computational_status'] == 'FAIL'


@pytest.mark.parametrize('max_items,invalid_child,expected',[(4,False,'UNKNOWN'),(8,False,'PASS'),(8,True,'FAIL')])
def test_owner_public_item_bound_controls_reproduce(max_items,invalid_child,expected):
    from test_current_sim_internal_state import _five_state_selected
    request,policy,raw = _five_state_selected(max_items=max_items,invalid_child=invalid_child)
    result = replay(request,policy,json.loads(raw))
    assert result['computational_status'] == expected
    if expected == 'UNKNOWN':
        assert 'state item bound' in result['native_result']['evaluation']['details']
