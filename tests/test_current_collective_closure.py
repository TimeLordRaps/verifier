"""Native fixed-membership COLLECTIVE point-decision closure regressions."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import collective_closure as closure
from verifier.domains.contracts import collective_constraints as collective_static
from verifier.domains.contracts import role_constraints as role_static
from verifier.domains.contracts import role_lifecycle as lifecycle
from verifier.domains.contracts import role_closure as role
from test_current_role_constraints import selected as static_selected

def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()

def byte_digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()

def fixture(*, quorum=2, nested_graph=False, shared_actor=False, shared_human=False,
            role_status=None, static_status="PASS", mutate=None, mutate_protocol=None, **limits):
    protocol = {"schema_version":closure.PROTOCOL_VERSION, "classes":[{
        "decision_class":"assemble", "required_roles":["author","reviewer"],
        "countersign":[{"source_role":"author","target_role":"reviewer"}],
        "distinct_actors":True, "distinct_root_humans":True}]}
    if mutate_protocol:
        mutate_protocol(protocol)
    charter=b"Explicit selected research assembly protocol; no legal authority claim."
    def objects(rows):
        for row in rows:
            if row["object_id"] in ("author", "reviewer"):
                row["payload"].update(permissions=["assemble"], admitted_scopes=["project"], lifecycle_state="active")
        members=[{"role_id":r["object_id"], "role_digest":NamespaceObject.create(**r).digest}
                 for r in rows if r["object_id"] in ("author","reviewer")]
        collective=next(r for r in rows if r["object_id"]=="team")
        collective["payload"].update(decision_protocol_digest=digest(protocol), static_constraints={
            "schema_version":collective_static.CONSTRAINTS_VERSION,"membership_digest":digest(members),
            "charter_digest":byte_digest(charter), "quorum":quorum})
        if nested_graph:
            rows.extend([NamespaceObject.create("role-inner", "GRAPH", {"element_kind":"ROLE"},
                {"members":["author","reviewer"]}).to_dict(),
                NamespaceObject.create("role-outer", "GRAPH", {"element_kind":"ROLE"},
                {"members":["author","role-inner"]}).to_dict()])
            collective["operands"]["roles"]=["role-outer"]
        if shared_actor:
            next(r for r in rows if r["object_id"]=="identity-b")["operands"]["actor"]=["actor-a"]
        if shared_human:
            next(r for r in rows if r["object_id"]=="actor-b")["operands"].update(
                representation=["human-a"], root_human=["human-a"])
    def matrix(value):
        for row in value["roles"]:
            row["allowed_permissions"]=["assemble"]
        value["exclusive_role_sets"]=[]
        if shared_actor:
            value["actors"][0]["allowed_roles"]=["author","reviewer"]
            value["occupancies"][1]["actor_id"]="actor-a"
    base_request, base_policy, base_evidence=static_selected(mutate_objects=objects,mutate_matrix=matrix)
    retained=json.loads(base_evidence)
    members=[{"role_id":name,"role_digest":NamespaceObject.create(**next(r for r in retained["objects"] if r["object_id"]==name)).digest}
             for name in ("author","reviewer")]
    role_selections=[]
    role_certificates={}
    life_protocol={"schema_version":lifecycle.PROTOCOL_VERSION, "states":["active"], "transitions":[{
        "from_state":"active","to_state":"active","add_permissions":[],"remove_permissions":[],
        "add_scopes":[],"remove_scopes":[],"allow_taking":False,"allow_leaving":False}]}
    for member in members:
        static_request=deepcopy(base_request)
        static_request.update(subject_id=member["role_id"], object_digest=member["role_digest"])
        static_certificate=role_static.build_role_constraints_certificate(static_request,base_evidence,policy=base_policy)
        endpoint={"child_request":static_request,"child_policy":base_policy,
            "child_certificate":base64.b64encode(static_certificate).decode("ascii")}
        selection={"object_digest":static_request["object_digest"],"collection_digest":static_request["collection_digest"],
            "child_request_digest":digest(static_request),"child_policy_digest":digest(base_policy),
            "child_certificate_digest":byte_digest(static_certificate)}
        child_value={"schema_version":lifecycle.EVIDENCE_VERSION,"protocol":life_protocol,
            "endpoints":[deepcopy(endpoint),deepcopy(endpoint)],"events":[{"position":1,"taking":[],"leaving":[]}]}
        child_evidence=canonical_bytes(child_value)
        child_policy=lifecycle.role_lifecycle_policy(trust_roots=["selected-role-history"])
        child_request=lifecycle.role_lifecycle_request(subject_id=member["role_id"],object_digest=member["role_digest"],
            collection_digest=base_request["collection_digest"],endpoint_selections=[deepcopy(selection),deepcopy(selection)],
            protocol_digest=digest(life_protocol),evidence_ref=byte_digest(child_evidence),policy=child_policy)
        child_certificate=lifecycle.build_role_lifecycle_certificate(child_request,child_evidence,policy=child_policy)
        is_author=member["role_id"]=="author"
        actor_id="actor-a" if is_author or shared_actor else "actor-b"
        decisions=[{"position":0,"decision_id":"member-decision", "time_us":9,"actor_id":actor_id,
            "identity_id":"identity-a" if is_author else "identity-b", "scope":"project",
            "decision_class":"assemble","content_digest":"sha256:"+"a"*64}]
        events=[{"position":1,"time_us":10,"action":"CHECKPOINT","taking":[],"leaving":[]}]
        status=(role_status or {}).get(member["role_id"],"PASS")
        if status=="FAIL":
            decisions[0]["actor_id"]="unoccupied-actor"
        role_value={"schema_version":role.EVIDENCE_VERSION,"lifecycle_certificate":base64.b64encode(child_certificate).decode("ascii"),
                    "events":None if status=="UNKNOWN" else events,"decisions":decisions}
        role_evidence=canonical_bytes(role_value)
        role_policy=role.role_closure_policy(trust_roots=["selected-role-decisions"])
        role_request=role.role_closure_request(subject_id=member["role_id"],object_digest=member["role_digest"],
            collection_digest=base_request["collection_digest"],collective_id="team",clock_id="declared-clock",
            period_us=[0,20],endpoint_times_us=[0,10],lifecycle_request=child_request,lifecycle_policy=child_policy,
            lifecycle_certificate_digest=byte_digest(child_certificate),events_digest=digest(events),
            decisions_digest=digest(decisions),evidence_ref=byte_digest(role_evidence),policy=role_policy)
        certificate=role.build_role_closure_certificate(role_request,role_evidence,policy=role_policy)
        role_selections.append({"role_id":member["role_id"],"request":role_request,"policy":role_policy,"certificate_digest":byte_digest(certificate)})
        role_certificates[member["role_id"]]=base64.b64encode(certificate).decode("ascii")
    collective_obj=NamespaceObject.create(**next(r for r in retained["objects"] if r["object_id"]=="team"))
    static_policy=collective_static.collective_constraints_policy(trust_roots=["selected-charter"],selected_members=members,
        charter_digest=byte_digest(charter),quorum=quorum)
    static_value={"schema_version":collective_static.EVIDENCE_VERSION,"objects":retained["objects"],"inputs":{
        "membership":members,"quorum":1 if static_status=="FAIL" else quorum,
        "charter":None if static_status=="UNKNOWN" else {"sha256":byte_digest(charter),"base64":base64.b64encode(charter).decode("ascii")}}}
    static_evidence=canonical_bytes(static_value)
    static_request=collective_static.collective_constraints_request(subject_id="team",object_digest=collective_obj.digest,
        collection_digest=base_request["collection_digest"],evidence_ref=byte_digest(static_evidence),policy=static_policy)
    static_certificate=collective_static.build_collective_constraints_certificate(static_request,static_evidence,policy=static_policy)
    decisions=[{"position":0,"decision_id":"collective-decision","time_us":9,"decision_class":"assemble",
        "content_digest":"sha256:"+"a"*64,"components":[{"role_id":m["role_id"],"decision_id":"member-decision"} for m in members]}]
    value={"schema_version":closure.EVIDENCE_VERSION,"static_certificate":base64.b64encode(static_certificate).decode("ascii"),
        "role_certificates":role_certificates,"protocol":protocol,"decisions":decisions}
    if mutate:
        mutate(value)
    evidence=canonical_bytes(value)
    policy=closure.collective_closure_policy(trust_roots=["selected-collective-assemblies"])
    request=closure.collective_closure_request(subject_id="team",object_digest=collective_obj.digest,collection_digest=base_request["collection_digest"],
        clock_id="declared-clock",period_us=[0,20],static_request=static_request,static_policy=static_policy,
        static_certificate_digest=byte_digest(static_certificate),role_selections=role_selections,
        protocol_digest=digest(protocol),decisions_digest=digest(decisions),evidence_ref=byte_digest(evidence),policy=policy,limits=limits)
    return request,policy,evidence

def replay(request,policy,evidence):
    certificate=closure.build_collective_closure_certificate(request,evidence,policy=policy)
    return certificate,closure.recheck_collective_closure_certificate(certificate,expected_request=request,policy=policy)

@pytest.mark.parametrize("nested_graph",[False,True])
def test_genuine_complete_member_decision_assembly(nested_graph):
    request,policy,evidence=fixture(nested_graph=nested_graph)
    certificate,result=replay(request,policy,evidence)
    assert result["status"]=="PASS"
    assert result["actual_quorum_decision"]==result["authority"]==result["object_profile_conformance"]=="NOT_ESTABLISHED"
    assert len(result["evaluation"]["observations"]["assemblies"][0]["components"])==2
    assert certificate==closure.build_collective_closure_certificate(request,evidence,policy=policy)

@pytest.mark.parametrize("mutation",[
    lambda v:v["decisions"][0].update(content_digest="sha256:"+"b"*64),
    lambda v:v["decisions"][0].update(time_us=10),
    lambda v:v["decisions"][0].update(time_us=True),
    lambda v:v["decisions"][0].update(decision_class="unselected"),
    lambda v:v["decisions"][0]["components"].pop(),
    lambda v:v["decisions"][0]["components"][1].update(role_id="author"),
    lambda v:v["decisions"][0]["components"][1].update(role_id="outsider"),
    lambda v:v["decisions"][0]["components"][1].update(decision_id="absent"),
])
def test_reselected_collective_contradiction_fails(mutation):
    assert replay(*fixture(mutate=mutation))[1]["status"]=="FAIL"

def test_component_reuse_cannot_split_or_inflate_decisions():
    def mutate(value):
        duplicate=deepcopy(value["decisions"][0]);duplicate.update(position=1,decision_id="split-decision")
        value["decisions"].append(duplicate)
    assert replay(*fixture(mutate=mutate))[1]["status"]=="FAIL"

@pytest.mark.parametrize("component",["protocol","decisions","static_certificate","role_certificates"])
def test_missing_required_support_stays_unknown(component):
    assert replay(*fixture(mutate=lambda v:v.update({component:None})))[1]["status"]=="UNKNOWN"

def test_missing_early_role_cannot_hide_later_false_prerequisite():
    assert replay(*fixture(role_status={"reviewer":"FAIL"},mutate=lambda v:v["role_certificates"].update(author=None)))[1]["status"]=="FAIL"

def test_missing_protocol_cannot_hide_false_available_component_content():
    def mutate(value):
        value["protocol"]=None;value["decisions"][0]["content_digest"]="sha256:"+"b"*64
    assert replay(*fixture(mutate=mutate))[1]["status"]=="FAIL"

def test_unknown_role_never_passes_but_literal_component_equality_still_refutes():
    assert replay(*fixture(role_status={"author":"UNKNOWN"}))[1]["status"]=="UNKNOWN"
    assert replay(*fixture(role_status={"author":"UNKNOWN"},mutate=lambda v:v["decisions"][0].update(content_digest="sha256:"+"b"*64)))[1]["status"]=="FAIL"

@pytest.mark.parametrize("static_status",["UNKNOWN","FAIL"])
def test_fresh_static_outcome_preserved(static_status):
    assert replay(*fixture(static_status=static_status))[1]["status"]==static_status

@pytest.mark.parametrize("separation",["actor","human"])
def test_declared_separation_uses_real_fresh_role_bindings(separation):
    assert replay(*fixture(shared_actor=separation=="actor",shared_human=separation=="human"))[1]["status"]=="FAIL"

@pytest.mark.parametrize("rule",["required","countersign"])
def test_required_role_and_countersign_are_not_only_quorum_count(rule):
    def protocol(value):
        value["classes"][0]["required_roles"]=["reviewer"] if rule=="required" else []
    assert replay(*fixture(quorum=1,mutate_protocol=protocol,mutate=lambda v:v["decisions"][0]["components"].pop()))[1]["status"]=="FAIL"

@pytest.mark.parametrize("limits",[{"max_operations":1},{"max_child_operations":1},{"max_evidence_bytes":1},{"max_roles":1}])
def test_resource_fence_stays_unknown(limits):
    assert replay(*fixture(**limits))[1]["status"]=="UNKNOWN"

def test_independent_clock_and_carried_pass_cannot_substitute():
    request,policy,evidence=fixture(mutate=lambda v:v["decisions"][0].update(content_digest="sha256:"+"b"*64))
    certificate,result=replay(request,policy,evidence)
    assert result["status"]=="FAIL"
    forged=json.loads(certificate);forged["result"]["status"]="PASS";del forged["digest"];forged["digest"]=digest(forged)
    with pytest.raises(closure.CollectiveClosureError):
        closure.recheck_collective_closure_certificate(canonical_bytes(forged),expected_request=request,policy=policy)
    changed=deepcopy(request);changed["clock_id"]="other-clock"
    with pytest.raises(closure.CollectiveClosureError):
        closure.recheck_collective_closure_certificate(certificate,expected_request=changed,policy=policy)


def test_selected_input_byte_capacity_is_unavailable_not_semantic_failure():
    request,policy,evidence=fixture()
    certificate,_=replay(request,policy,evidence)
    policy=deepcopy(policy);policy["max_certificate_bytes"]=1
    request=deepcopy(request);request["policy_digest"]=digest(policy)
    with pytest.raises(closure.CollectiveClosureUnavailable):
        closure.recheck_collective_closure_certificate(certificate,expected_request=request,policy=policy)

def test_public_route_and_inventory_preserve_finite_scope(tmp_path,capsys):
    from verifier.domains.inventory import get_slot
    from verifier.domains.contracts.current_object_routes import replay_current_object_certificate
    from verifier.runtime.public_cli import main
    request,policy,evidence=fixture(nested_graph=True)
    certificate,result=replay(request,policy,evidence)
    public=replay_current_object_certificate(certificate,semantic_version=closure.SEMANTIC_VERSION,
        objective=closure.COORDINATE,represented_kind="COLLECTIVE",expected_request=request,policy=policy)
    assert public["computational_status"]=="PASS" and public["native_result"]==result
    assert result["whole_tier_conformance"]==result["authority"]=="NOT_ESTABLISHED"
    slot=get_slot("COLLECTIVE",4)
    assert slot.coordinate=="COLLECTIVE-4.1" and slot.mechanized and slot.status=="REPLAYABLE"
    for name,raw in (("certificate",certificate),("request",canonical_bytes(request)),("policy",canonical_bytes(policy))):
        (tmp_path/(name+".json")).write_bytes(raw)
    assert main(["current-object","check",str(tmp_path/"certificate.json"),"--semantic-version",closure.SEMANTIC_VERSION,
        "--objective",closure.COORDINATE,"--represented-kind","COLLECTIVE","--request",str(tmp_path/"request.json"),
        "--policy",str(tmp_path/"policy.json"),"--json"])==0
    assert json.loads(capsys.readouterr().out)["computational_status"]=="PASS"

@pytest.mark.parametrize("error",[RecursionError,OverflowError])
def test_actual_inherited_static_reader_capacity_is_unknown(error,monkeypatch):
    request,policy,evidence=fixture()
    def unavailable(*args,**kwargs):raise error("actual inherited static decoder capacity")
    monkeypatch.setattr(collective_static,"strict_json_loads",unavailable)
    assert replay(request,policy,evidence)[1]["status"]=="UNKNOWN"

@pytest.mark.parametrize("field,value",[("time_us",20),("content_digest","sha256:"+"b"*64)])
def test_known_assembly_refutation_survives_unavailable_static(field,value,monkeypatch):
    request,policy,evidence=fixture(mutate=lambda v:v["decisions"][0].update({field:value}))
    def unavailable(*args,**kwargs):raise RecursionError("actual inherited static decoder capacity")
    monkeypatch.setattr(collective_static,"strict_json_loads",unavailable)
    assert replay(request,policy,evidence)[1]["status"]=="FAIL"
