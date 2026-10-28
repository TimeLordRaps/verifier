"""Genuine later native failures survive early child checker capacity loss."""
from __future__ import annotations
import hashlib
import pytest
from verifier.domains.contracts import role_constraints,role_lifecycle,collective_constraints,collective_lifecycle

def bytes_digest(raw):return "sha256:"+hashlib.sha256(raw).hexdigest()

def fixture(family):
    if family=="role":
        from test_current_role_lifecycle import selected
        def false_final_matrix(value,position):
            if position==3:value["roles"][0]["max_occupants"]=-1
        request,policy,evidence=selected(mutate_matrix=false_final_matrix)
        first=request["endpoint_selections"][0]["child_certificate_digest"]
        module=role_constraints;read=module.recheck_role_constraints_certificate
        unavailable=module.RoleConstraintsUnavailable
    else:
        from test_current_collective_lifecycle import specimen,defaults
        states=defaults();states[-1]["quorum"]=4
        request,policy,evidence=specimen(states=states)
        first=request["endpoints"][0]["certificate_ref"]
        module=collective_constraints;read=module.recheck_collective_constraints_certificate
        unavailable=module.CollectiveConstraintsUnavailable
    parent=role_lifecycle if family=="role" else collective_lifecycle
    name="role_lifecycle" if family=="role" else "collective_lifecycle"
    def replay(req,pol,data):
        certificate=getattr(parent,"build_"+name+"_certificate")(req,data,policy=pol)
        return getattr(parent,"recheck_"+name+"_certificate")(certificate,expected_request=req,policy=pol)
    assert replay(request,policy,evidence)["status"]=="FAIL"
    return request,policy,evidence,first,module,read,unavailable,replay

@pytest.mark.parametrize("family",["role","collective"])
def test_early_typed_child_unavailability_preserves_later_genuine_fail(family,monkeypatch):
    request,policy,evidence,first,module,read,unavailable,replay=fixture(family)
    def first_unavailable(certificate,**selection):
        if bytes_digest(certificate)==first:raise unavailable("first exact reader unavailable")
        return read(certificate,**selection)
    monkeypatch.setattr(module,read.__name__,first_unavailable)
    assert replay(request,policy,evidence)["status"]=="FAIL"

@pytest.mark.parametrize("family",["role","collective"])
def test_all_unavailable_children_remain_unknown(family,monkeypatch):
    request,policy,evidence,first,module,read,unavailable,replay=fixture(family)
    def all_unavailable(certificate,**selection):raise unavailable("every exact reader unavailable")
    monkeypatch.setattr(module,read.__name__,all_unavailable)
    assert replay(request,policy,evidence)["status"]=="UNKNOWN"

@pytest.mark.parametrize("family",["role","collective"])
def test_early_semantic_child_refusal_remains_fail(family,monkeypatch):
    request,policy,evidence,first,module,read,unavailable,replay=fixture(family)
    def semantic_refusal(certificate,**selection):raise ValueError("actual semantic reconstruction refusal")
    monkeypatch.setattr(module,read.__name__,semantic_refusal)
    assert replay(request,policy,evidence)["status"]=="FAIL"
