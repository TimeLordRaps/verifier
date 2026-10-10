"""Supplemental installed public-boundary checks for selected response replay."""
from copy import deepcopy
import hashlib,json
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import sim_response as response
from test_current_sim_response import selected

def digest(value):return 'sha256:'+hashlib.sha256(canonical_bytes(value)).hexdigest()

@pytest.mark.parametrize('field,value',[
 ('schema_version','wrong'),('semantic_version','wrong'),('coordinate','SIM-2.9'),
 ('object_kind','BOT'),('proposition_digest','sha256:'+'0'*64),
 ('subject_id',''),('subject_id',True),
 ('max_response_delay',0),('max_response_delay',-1),('max_response_delay',True),
 ('max_response_delay',float('inf')),('max_response_delay',float('nan')),
 ('time_unit',''),('time_unit',True),('time_unit','x'*65),
])
def test_malformed_independent_selection_is_refused(field,value):
    request,policy,evidence=selected();request[field]=value
    with pytest.raises(response.SimResponseError):
        response.build_sim_response_certificate(request,evidence,policy=policy)

@pytest.mark.parametrize('kind',['text','bytearray','changed-bytes','wrong-policy','certificate-size'])
def test_builder_enforces_immutable_evidence_selection_and_policy(kind):
    request,policy,evidence=selected()
    if kind=='text':evidence=evidence.decode()
    elif kind=='bytearray':evidence=bytearray(evidence)
    elif kind=='changed-bytes':evidence=evidence+b' '
    elif kind=='wrong-policy':policy=response.sim_response_policy(trust_roots=['other-selection'])
    else:
        policy=response.sim_response_policy(trust_roots=policy['trust_roots'],max_certificate_bytes=1)
        request['policy_digest']=digest(policy)
    with pytest.raises(response.SimResponseError):
        response.build_sim_response_certificate(request,evidence,policy=policy)

@pytest.mark.parametrize('kind',['text','bytearray','malformed','noncanonical','version','foreign-payload','payload-value','too-large'])
def test_rechecker_refuses_malformed_or_unselected_certificate(kind):
    request,policy,evidence=selected();certificate=response.build_sim_response_certificate(request,evidence,policy=policy)
    if kind=='text':certificate=certificate.decode()
    elif kind=='bytearray':certificate=bytearray(certificate)
    elif kind=='malformed':certificate=b'['
    elif kind=='noncanonical':certificate=json.dumps(json.loads(certificate),indent=2).encode()
    elif kind=='too-large':
        policy=response.sim_response_policy(trust_roots=policy['trust_roots'],max_certificate_bytes=1)
        request['policy_digest']=digest(policy)
    else:
        envelope=json.loads(certificate)
        if kind=='version':envelope['schema_version']='wrong'
        elif kind=='foreign-payload':envelope['evidence_payloads']['sha256:'+'0'*64]=''
        else:envelope['evidence_payloads'][request['evidence_ref']]=False
        envelope.pop('digest');envelope['digest']=digest(envelope);certificate=canonical_bytes(envelope)
    with pytest.raises(response.SimResponseError):
        response.recheck_sim_response_certificate(certificate,expected_request=request,policy=policy)

@pytest.mark.parametrize('value',[True,'!',123])
def test_rebound_malformed_child_encoding_is_refuted(value):
    request,policy,evidence=selected();body=json.loads(evidence);body['trajectory_certificate']=value
    request['evidence_ref']=digest(body)
    certificate=response.build_sim_response_certificate(request,canonical_bytes(body),policy=policy)
    assert response.recheck_sim_response_certificate(certificate,expected_request=request,policy=policy)['status']=='FAIL'

@pytest.mark.parametrize('name',['','a.b',' '])
def test_rebound_invalid_action_identifier_is_refuted(name):
    request,policy,evidence=selected();body=json.loads(evidence);artifact=body['action_artifact'];inputs=body['action_inputs']
    artifact['action_bounds']={name:artifact['action_bounds']['push']};artifact['baseline_action']={name:0.0}
    inputs['actions']=[{name:1.0}]
    artifact['program']={'x':{'var':'action.'+name}}
    request.update(action_artifact_digest=digest(artifact),action_inputs_digest=digest(inputs),evidence_ref=digest(body))
    certificate=response.build_sim_response_certificate(request,canonical_bytes(body),policy=policy)
    assert response.recheck_sim_response_certificate(certificate,expected_request=request,policy=policy)['status']=='FAIL'

def test_genuinely_unsupported_action_expression_remains_unknown():
    request,policy,evidence=selected();body=json.loads(evidence)
    body['action_artifact']['program']['x']={'op':'future-expression','args':[1.0,2.0]}
    request.update(action_artifact_digest=digest(body['action_artifact']),evidence_ref=digest(body))
    certificate=response.build_sim_response_certificate(request,canonical_bytes(body),policy=policy)
    assert response.recheck_sim_response_certificate(certificate,expected_request=request,policy=policy)['status']=='UNKNOWN'

def test_complete_evidence_with_substituted_schema_is_refuted():
    request,policy,evidence=selected();body=json.loads(evidence);body['schema_version']='wrong'
    request['evidence_ref']=digest(body)
    certificate=response.build_sim_response_certificate(request,canonical_bytes(body),policy=policy)
    assert response.recheck_sim_response_certificate(certificate,expected_request=request,policy=policy)['status']=='FAIL'
