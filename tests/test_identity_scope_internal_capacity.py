"""Actual IDENTITY3 evidence-decoder exhaustion during exact certificate replay."""
import json
import pytest
from verifier.core.certificate import canonical_bytes,canonical_digest
from verifier.domains.contracts import identity_scope as native,current_object_routes as routes
from test_current_identity_scope import inputs

def inject_evidence_decoder_failure(monkeypatch,error):
    original=native.strict_json_loads
    def decode(text):
        value=original(text)
        if type(value) is dict and value.get("schema_version")==native.EVIDENCE_VERSION:
            raise error("actual inner evidence decoder capacity")
        return value
    monkeypatch.setattr(native,"strict_json_loads",decode)

@pytest.mark.parametrize("error",[RecursionError,OverflowError])
def test_actual_inner_decoder_capacity_is_unavailable_not_semantic_refusal(error,monkeypatch):
    module,request,policy,evidence=inputs()
    certificate=native.build_identity_scope_certificate(request,evidence,policy=policy)
    inject_evidence_decoder_failure(monkeypatch,error)
    with pytest.raises(native.IdentityScopeUnavailable):
        native.recheck_identity_scope_certificate(certificate,expected_request=request,policy=policy)
    with pytest.raises(routes.CurrentObjectRouteUnavailable):
        routes.replay_current_object_certificate(certificate,semantic_version=native.SEMANTIC_VERSION,
            objective=native.COORDINATE,represented_kind="IDENTITY",expected_request=request,policy=policy)

@pytest.mark.parametrize("field,value",[("authority","PASS"),("scope","other"),("evaluation",None),("status",True)])
def test_known_carried_result_boundary_contradiction_survives_inner_capacity(field,value,monkeypatch):
    module,request,policy,evidence=inputs()
    carried=json.loads(native.build_identity_scope_certificate(request,evidence,policy=policy))
    carried["result"][field]=value
    carried["digest"]="sha256:"+canonical_digest({k:v for k,v in carried.items() if k!="digest"})
    inject_evidence_decoder_failure(monkeypatch,RecursionError)
    with pytest.raises(native.IdentityScopeError):
        native.recheck_identity_scope_certificate(canonical_bytes(carried),expected_request=request,policy=policy)

def test_actual_inner_semantic_valueerror_remains_refusal(monkeypatch):
    module,request,policy,evidence=inputs()
    certificate=native.build_identity_scope_certificate(request,evidence,policy=policy)
    inject_evidence_decoder_failure(monkeypatch,ValueError)
    with pytest.raises(native.IdentityScopeError):
        native.recheck_identity_scope_certificate(certificate,expected_request=request,policy=policy)

@pytest.mark.parametrize("limits",[{},{"max_operations":1}])
def test_genuine_complete_or_selected_bounded_result_replays_exact_bytes(limits):
    module,request,policy,evidence=inputs(**limits)
    certificate=native.build_identity_scope_certificate(request,evidence,policy=policy)
    result=native.recheck_identity_scope_certificate(certificate,expected_request=request,policy=policy)
    assert result["status"]==("UNKNOWN" if limits else "PASS")


@pytest.mark.parametrize("error",[RecursionError,OverflowError])
def test_known_wrong_observed_count_survives_inner_decoder_capacity(error,monkeypatch):
    module,request,policy,evidence=inputs()
    carried=json.loads(native.build_identity_scope_certificate(request,evidence,policy=policy))
    carried["result"]["evaluation"]["observed_evidence_bytes"]+=1
    carried["digest"]="sha256:"+canonical_digest({k:v for k,v in carried.items() if k!="digest"})
    inject_evidence_decoder_failure(monkeypatch,error)
    with pytest.raises(native.IdentityScopeError):
        native.recheck_identity_scope_certificate(canonical_bytes(carried),expected_request=request,policy=policy)

def test_absent_selected_evidence_exact_zero_count_replays_unknown():
    module,request,policy,evidence=inputs()
    certificate=native.build_identity_scope_certificate(request,None,policy=policy)
    result=native.recheck_identity_scope_certificate(certificate,expected_request=request,policy=policy)
    assert result["status"]=="UNKNOWN" and result["evaluation"]["observed_evidence_bytes"]==0
