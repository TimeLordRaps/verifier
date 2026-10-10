"""Supplemental public input-boundary checks against the frozen installed package."""
from __future__ import annotations
from copy import deepcopy
import hashlib,json
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import sim_dynamics as api
from test_current_sim_dynamics import selected

def digest(raw: bytes) -> str:
    return 'sha256:'+hashlib.sha256(raw).hexdigest()

@pytest.mark.parametrize('field,value',[
 ('schema_version','wrong'),('semantic_version','wrong'),('coordinate','SIM-2.2'),('object_kind','MODEL'),('proposition_digest','sha256:'+'0'*64),
 ('subject_id',None),('subject_id',' '),('subject_id','x'*257),
 ('expected_counts',{'states':True,'transitions':1}),('expected_counts',{'states':2,'transitions':0}),('expected_counts',{'states':3,'transitions':1})])
def test_malformed_external_selection_refused(field: str,value: object) -> None:
    request,policy,evidence=selected();request[field]=value
    with pytest.raises(ValueError):api.build_sim_dynamics_certificate(request,evidence,policy=policy)

@pytest.mark.parametrize('limits',[[],{'unknown_limit':1},{'max_items':True},{'max_items':0}])
def test_invalid_limit_selection_refused(limits: object) -> None:
    with pytest.raises(ValueError):selected(limits=limits)

@pytest.mark.parametrize('mutation',['version','noncanonical','collection_type','record_kind','subject_digest','scope'])
def test_known_retained_input_contradiction_refuted(mutation: str) -> None:
    request,policy,evidence=selected();value=json.loads(evidence)
    if mutation=='version':value['schema_version']='wrong'
    elif mutation=='collection_type':value['objects']={}
    elif mutation=='record_kind':value['objects'][0]['kind']='data'
    elif mutation=='subject_digest':request['object_digest']='sha256:'+'0'*64
    elif mutation=='scope':
        from verifier.core.namespace import NamespaceObject,composition_digest
        row=next(o for o in value['objects'] if o['object_id']=='sim');row['payload']['scope']='unselected'
        objects=[NamespaceObject.create(**o) for o in value['objects']]
        request['object_digest']=next(o.digest for o in objects if o.object_id=='sim');request['collection_digest']=composition_digest(objects)
    raw=json.dumps(value,indent=2).encode() if mutation=='noncanonical' else canonical_bytes(value)
    request['evidence_ref']=digest(raw);cert=api.build_sim_dynamics_certificate(request,raw,policy=policy)
    assert api.recheck_sim_dynamics_certificate(cert,expected_request=request,policy=policy)['status']=='FAIL'

def test_selected_object_budget_shortfall_unknown() -> None:
    request,policy,evidence=selected(limits={'max_objects':1})
    cert=api.build_sim_dynamics_certificate(request,evidence,policy=policy)
    assert api.recheck_sim_dynamics_certificate(cert,expected_request=request,policy=policy)['status']=='UNKNOWN'

@pytest.mark.parametrize('mutation',['version','pretty','payload_type','extra_payload','invalid_utf8','bytearray'])
def test_malformed_or_substituted_certificate_refused(mutation: str) -> None:
    request,policy,evidence=selected();raw=api.build_sim_dynamics_certificate(request,evidence,policy=policy);cert=json.loads(raw)
    if mutation=='version':cert['schema_version']='wrong'
    elif mutation=='payload_type':cert['evidence_payloads']=[]
    elif mutation=='extra_payload':cert['evidence_payloads']['sha256:'+'0'*64]=''
    if mutation=='pretty':raw=json.dumps(cert,indent=2).encode()
    elif mutation=='invalid_utf8':raw=b'\xff'
    elif mutation=='bytearray':raw=bytearray(raw)
    else:raw=canonical_bytes(cert)
    with pytest.raises(ValueError):api.recheck_sim_dynamics_certificate(raw,expected_request=request,policy=policy)

@pytest.mark.parametrize('case',['mutable_evidence','different_evidence','different_policy','certificate_budget'])
def test_selected_byte_and_policy_boundary_refused(case: str) -> None:
    request,policy,evidence=selected()
    if case=='mutable_evidence':evidence=bytearray(evidence)
    elif case=='different_evidence':evidence=b'{}'
    elif case=='different_policy':policy=api.sim_dynamics_policy(trust_roots=['other-selection'])
    else:
        policy=api.sim_dynamics_policy(trust_roots=['small-selected-certificate'],max_certificate_bytes=128)
        request['policy_digest']=digest(canonical_bytes(policy))
    with pytest.raises(ValueError):api.build_sim_dynamics_certificate(request,evidence,policy=policy)

@pytest.mark.parametrize('result',[{'states':2.0,'transitions':1},{},None])
def test_unsupported_trusted_backend_result_stays_unknown(monkeypatch: pytest.MonkeyPatch,result: object) -> None:
    request,policy,evidence=selected()
    monkeypatch.setattr(api.native_sim,'evaluate',lambda *args,**kwargs:deepcopy(result))
    cert=api.build_sim_dynamics_certificate(request,evidence,policy=policy)
    assert api.recheck_sim_dynamics_certificate(cert,expected_request=request,policy=policy)['status']=='UNKNOWN'
