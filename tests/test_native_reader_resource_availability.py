"""Actual inherited native-reader resource errors and semantic refusal controls."""
from __future__ import annotations
import json
from verifier.core.certificate import canonical_bytes
import pytest
from verifier.domains.common import Unavailable
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import collective_constraints
from verifier.domains.contracts import identity_scope
from verifier.domains.contracts import role_constraints
from verifier.domains.contracts import role_lifecycle
from verifier.domains.contracts import time_order
from test_current_collective_constraints import specimen as collective_specimen
from test_current_identity_scope import inputs as identity_inputs
from test_current_role_constraints import selected as role_constraints_selected
from test_current_role_lifecycle import selected as role_lifecycle_selected
from test_current_time_order import selected as time_order_selected

FAMILIES = [
    ("role_constraints", "ROLE", "selected"),
    ("role_lifecycle", "ROLE", "selected"),
    ("collective_constraints", "COLLECTIVE", "specimen"),
    ("time_order", "TIME", "selected"),
    ("identity_scope", "IDENTITY", "inputs"),
]

CONTRACT_MODULES = {
    "role_constraints": role_constraints,
    "role_lifecycle": role_lifecycle,
    "collective_constraints": collective_constraints,
    "time_order": time_order,
    "identity_scope": identity_scope,
}
FIXTURE_FACTORIES = {
    "role_constraints": role_constraints_selected,
    "role_lifecycle": role_lifecycle_selected,
    "collective_constraints": collective_specimen,
    "time_order": time_order_selected,
    "identity_scope": identity_inputs,
}

def selected(row):
    name,kind,factory=row
    assert factory in {"selected", "specimen", "inputs"}
    module=CONTRACT_MODULES[name]
    value=FIXTURE_FACTORIES[name]()
    if name=="identity_scope":
        _,request,policy,evidence=value
    else:
        request,policy,evidence=value
    return module,request,policy,evidence

def unavailable_loader(error):
    def load(*args,**kwargs):
        raise error("injected actual reader capacity boundary")
    return load

@pytest.mark.parametrize("row",FAMILIES,ids=lambda r:r[0])
@pytest.mark.parametrize("error",[Unavailable,RecursionError,OverflowError])
def test_actual_retained_reader_capacity_is_not_semantic_refusal(row,error,monkeypatch):
    module,request,policy,evidence=selected(row)
    certificate=getattr(module,"build_"+row[0]+"_certificate")(request,evidence,policy=policy)
    monkeypatch.setattr(module,"strict_json_loads",unavailable_loader(error))
    with pytest.raises(OSError):
        getattr(module,"recheck_"+row[0]+"_certificate")(certificate,expected_request=request,policy=policy)

@pytest.mark.parametrize("row",FAMILIES,ids=lambda r:r[0])
@pytest.mark.parametrize("error",[Unavailable,RecursionError,OverflowError])
def test_public_route_preserves_actual_reader_capacity_unknown(row,error,monkeypatch,tmp_path,capsys):
    module,request,policy,evidence=selected(row)
    certificate=getattr(module,"build_"+row[0]+"_certificate")(request,evidence,policy=policy)
    monkeypatch.setattr(module,"strict_json_loads",unavailable_loader(error))
    with pytest.raises(routes.CurrentObjectRouteUnavailable):
        routes.replay_current_object_certificate(certificate,semantic_version=module.SEMANTIC_VERSION,
            objective=module.COORDINATE,represented_kind=row[1],expected_request=request,policy=policy)
    from verifier.runtime.public_cli import main
    for name,raw in (("certificate",certificate),("request",canonical_bytes(request)),("policy",canonical_bytes(policy))):
        (tmp_path/(name+".json")).write_bytes(raw)
    assert main(["current-object","check",str(tmp_path/"certificate.json"),"--semantic-version",module.SEMANTIC_VERSION,
        "--objective",module.COORDINATE,"--represented-kind",row[1],"--request",str(tmp_path/"request.json"),
        "--policy",str(tmp_path/"policy.json"),"--json"])==2
    assert json.loads(capsys.readouterr().out)["computational_status"]=="UNKNOWN"

@pytest.mark.parametrize("row",FAMILIES,ids=lambda r:r[0])
def test_semantic_reader_valueerror_remains_native_refusal(row,monkeypatch):
    module,request,policy,evidence=selected(row)
    certificate=getattr(module,"build_"+row[0]+"_certificate")(request,evidence,policy=policy)
    monkeypatch.setattr(module,"strict_json_loads",unavailable_loader(ValueError))
    with pytest.raises(ValueError):
        getattr(module,"recheck_"+row[0]+"_certificate")(certificate,expected_request=request,policy=policy)

@pytest.mark.parametrize("row",FAMILIES,ids=lambda r:r[0])
@pytest.mark.parametrize("error",[RecursionError,OverflowError])
def test_actual_native_evaluator_capacity_is_unknown(row,error,monkeypatch):
    module,request,policy,evidence=selected(row)
    monkeypatch.setattr(module,"strict_json_loads",unavailable_loader(error))
    assert (module._evaluate(evidence,request,policy) if row[0]=="collective_constraints" else module._evaluate(evidence,request)).outcome.value=="UNKNOWN"

@pytest.mark.parametrize("row",FAMILIES,ids=lambda r:r[0])
def test_actual_native_evaluator_valueerror_remains_fail(row,monkeypatch):
    module,request,policy,evidence=selected(row)
    monkeypatch.setattr(module,"strict_json_loads",unavailable_loader(ValueError))
    assert (module._evaluate(evidence,request,policy) if row[0]=="collective_constraints" else module._evaluate(evidence,request)).outcome.value=="FAIL"

@pytest.mark.parametrize("error",[Unavailable,RecursionError,OverflowError])
def test_new_role_parent_preserves_actual_lifecycle_reader_unavailability(error,monkeypatch):
    from verifier.domains.contracts import role_closure as parent,role_lifecycle as child
    from test_current_role_closure import fixture,replay
    request,policy,evidence=fixture()
    monkeypatch.setattr(child,"strict_json_loads",unavailable_loader(error))
    assert replay(request,policy,evidence)[1]["status"]=="UNKNOWN"

@pytest.mark.parametrize("error",[Unavailable,RecursionError,OverflowError])
def test_role_known_time_contradiction_survives_unavailable_lifecycle(error,monkeypatch):
    from verifier.domains.contracts import role_lifecycle as child
    from test_current_role_closure import fixture,replay
    request,policy,evidence=fixture(mutate=lambda v:v["decisions"][0].update(time_us=20))
    monkeypatch.setattr(child,"strict_json_loads",unavailable_loader(error))
    assert replay(request,policy,evidence)[1]["status"]=="FAIL"
