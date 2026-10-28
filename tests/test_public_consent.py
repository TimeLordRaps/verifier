"""Independent Ed25519 consent signatures, authority boundaries and replay cases.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). All signing seeds are
test fixtures, not operational credentials. No production private key is loaded.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519",
    reason="OPTIONAL_DEPENDENCY_ABSENT: the consent signature tests need the Ed25519 primitives of the seal extra (cryptography); the platform-python-contracts workflow job installs it; the checks that need no signing backend are in test_consent_capabilities.py")
from verifier.consent import public as public_consent
from verifier.consent.engine import ConsentContext

PREFIX=b"vstd-consent-ed25519-1\0"

def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()

def module():
    assert importlib.util.find_spec("verifier.consent.public") is not None, "Public-key consent capability is absent"
    return public_consent

@pytest.fixture
def specimen():
    candidate=module()
    crypto=pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519",
        reason="OPTIONAL_DEPENDENCY_ABSENT: cryptography.hazmat.primitives.asymmetric.ed25519 (seal extra) is absent, so the Ed25519 private-key specimen of the public consent fixture stays unexecuted here; the platform-python-contracts workflow job installs the seal extra and runs the complete suite, including this file")
    serialization=pytest.importorskip("cryptography.hazmat.primitives.serialization",
        reason="OPTIONAL_DEPENDENCY_ABSENT: cryptography.hazmat.primitives.serialization (seal extra) is absent, so the raw public-key serialization of the public consent fixture stays unexecuted here; the platform-python-contracts workflow job installs the seal extra and runs the complete suite, including this file")
    private={name:crypto.Ed25519PrivateKey.from_private_bytes(bytes([index])*32)
        for index,name in enumerate(("root","delegate","status"),1)}
    actors={"root":"holder","delegate":"operator","status":"registry"}
    keys=[{"key_id":name,"actor_id":actors[name],"public_key":key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()} for name,key in private.items()]
    selection=dict(policy_id="test-policy",grantor_id="holder",keys=keys,root_key_ids=["root"],
        revocation_key_ids=["status"],artifact_bindings=[["OBJECT","a"*64]],
        max_revocation_age_seconds=30,minimum_revocation_as_of=80,max_chain_length=4)
    policy=candidate.public_consent_policy(**selection)
    context=ConsentContext("OBJECT","a"*64,"publish","operator","reader","review",100)
    grant={"schema_version":"verifier-consent-public-grant-1","grant_id":"grant-root","issuer_id":"holder",
        "actor_id":"operator","object_name":"OBJECT","artifact_digest":"a"*64,"operations":["publish","read"],
        "observer_ids":["reader"],"purposes":["review"],"not_before":90,"not_after":110,
        "parent_digest":None,"allow_delegation":True,"effect":"ALLOW"}
    status={"schema_version":"verifier-consent-public-revocations-1","issuer_id":"registry", "policy_id":"test-policy",
        "as_of":95,"next_update":105,"revoked_grant_ids":[]}
    return candidate,context,selection,policy,private,grant,status

def sign(payload,key_id,private):
    body={"schema_version":"verifier-consent-public-envelope-1","algorithm":"Ed25519","key_id":key_id,
        "payload":deepcopy(payload),"payload_digest":hashlib.sha256(encoded(payload)).hexdigest()}
    return {**body,"signature":private[key_id].sign(PREFIX+encoded(body)).hex()}

def run(specimen,**changes):
    candidate,context,_,policy,private,grant,status=specimen
    args=dict(context=context,grants=(sign(grant,"root",private),),policy=policy,
        revocation=sign(status,"status",private),evaluation_time=100,computational_verdict="FAIL")
    args.update(changes)
    return candidate.evaluate_public_consent(**args)

def test_independently_signed_exact_action_replays_without_private_keys(specimen):
    c,context,_,policy,private,grant,status=specimen
    grant=sign(grant,"root",private);status=sign(status,"status",private)
    assert c.consent_signing_bytes(grant["payload"],"root")==PREFIX+encoded({k:v for k,v in grant.items() if k!="signature"})
    report=c.evaluate_public_consent(context,(grant,),policy=policy,revocation=status,evaluation_time=100,computational_verdict="FAIL")
    assert report.verdict.value=="PASS" and report.receipt["computational_verdict"]=="FAIL"
    assert report.receipt["enforcement"]=="NOT_ESTABLISHED"
    replay=c.recheck_public_consent(report.receipt,context,(grant,),policy=policy,revocation=status,evaluation_time=100,computational_verdict="FAIL")
    assert replay["replay_status"]=="REPRODUCED" and replay["admission_status"]=="PASS"
    assert all(bytes([i])*32 not in encoded(report.receipt) for i in (1,2,3))
    assert all((bytes([i])*32).hex() not in json.dumps(report.receipt) for i in (1,2,3))

@pytest.mark.parametrize("field,value",[("object_name","DATA"),("artifact_digest","b"*64),("operation","sell"),
    ("actor_id","other"),("observer_id","other"),("purpose","sell"),("timestamp",101)])
def test_exact_action_scope_is_not_inferred(specimen,field,value):
    assert run(specimen,context=replace(specimen[1],**{field:value})).verdict.value=="REJECTED"

@pytest.mark.parametrize("case,expected",[("missing-policy","UNKNOWN"),("missing-grant","UNKNOWN"),("missing-status","UNKNOWN"),
    ("missing-clock","UNKNOWN"),("authority-missing","UNKNOWN"),("foreign-authority","REJECTED"),
    ("expired","REJECTED"),("start-inclusive","PASS"),("end-exclusive","REJECTED"),
    ("stale","UNKNOWN"),("future","UNKNOWN"),("rollback","UNKNOWN"),("revoked-stale","REJECTED"),
    ("denied","REJECTED"),("root-role","REJECTED"),("status-role","REJECTED")])
def test_authority_time_revocation_and_roles(specimen,case,expected):
    c,ctx,selection,policy,private,grant,status=specimen;changes={}
    if case=="missing-policy":changes["policy"]=None
    if case=="missing-grant":changes["grants"]=()
    if case=="missing-status":changes["revocation"]=None
    if case=="missing-clock":changes["evaluation_time"]=None
    if case=="authority-missing":selection["artifact_bindings"]=[];changes["policy"]=c.public_consent_policy(**selection)
    if case=="foreign-authority":selection["artifact_bindings"]=[["OBJECT","b"*64]];changes["policy"]=c.public_consent_policy(**selection)
    if case=="expired":grant["not_after"]=99
    if case=="start-inclusive":grant["not_before"]=100
    if case=="end-exclusive":grant["not_after"]=100
    if case=="stale":status.update(as_of=60,next_update=105)
    if case=="future":status.update(as_of=101,next_update=110)
    if case=="rollback":status.update(as_of=79,next_update=105)
    if case=="revoked-stale":status.update(as_of=60,next_update=70,revoked_grant_ids=["grant-root"])
    if case=="denied":grant["effect"]="DENY"
    if case=="root-role":grant["issuer_id"]="operator";changes["grants"]=(sign(grant,"delegate",private),)
    if case=="status-role":status["issuer_id"]="operator";changes["revocation"]=sign(status,"delegate",private)
    assert run(specimen,**changes).verdict.value==expected

@pytest.mark.parametrize("case",["signature","payload","rehashed-payload","key","algorithm","schema","extra","nonhex","short"])
def test_signature_and_envelope_substitution(specimen,case):
    c,ctx,_,policy,private,grant,status=specimen;record=sign(grant,"root",private)
    if case=="signature":record["signature"]="0"*128
    if case in ("payload","rehashed-payload"):
        record["payload"]["actor_id"]="outsider"
        if case=="rehashed-payload":record["payload_digest"]=hashlib.sha256(encoded(record["payload"])).hexdigest()
    if case=="key":record["key_id"]="delegate"
    if case=="algorithm":record["algorithm"]="HMAC-SHA256"
    if case=="schema":record["schema_version"]="verifier-consent-envelope-1"
    if case=="extra":record["unselected"]=True
    if case=="nonhex":record["signature"]="g"*128
    if case=="short":record["signature"]="00"
    assert run(specimen,grants=(record,),evaluation_time=None).verdict.value=="REJECTED"

@pytest.mark.parametrize("case",["operation","interval","parent","issuer","identifier","disabled","revoked"])
def test_delegation_does_not_widen_or_escape_revocation(specimen,case):
    c,ctx,_,policy,private,parent,status=specimen
    child={**parent,"grant_id":"child","issuer_id":"operator","actor_id":"operator",
        "operations":["publish"],"parent_digest":hashlib.sha256(encoded(parent)).hexdigest(),"allow_delegation":False}
    positive=(sign(parent,"root",private),sign(child,"delegate",private))
    assert run(specimen,grants=positive).verdict.value=="PASS"
    if case=="operation":child["operations"].append("sell")
    if case=="interval":child["not_after"]=111
    if case=="parent":child["parent_digest"]="0"*64
    if case=="issuer":child["issuer_id"]="other"
    if case=="identifier":child["grant_id"]="grant-root"
    if case=="disabled":parent["allow_delegation"]=False;child["parent_digest"]=hashlib.sha256(encoded(parent)).hexdigest()
    if case=="revoked":status["revoked_grant_ids"]=["grant-root"]
    assert run(specimen,grants=(sign(parent,"root",private),sign(child,"delegate",private))).verdict.value=="REJECTED"

@pytest.mark.parametrize("verdict",["PASS","FAIL","UNKNOWN","REJECTED","CONFLICTED"])
def test_computational_verdict_is_never_used_as_consent(specimen,verdict):
    report=run(specimen,computational_verdict=verdict)
    assert report.verdict.value=="PASS" and report.receipt["computational_verdict"]==verdict
    specimen[5]["effect"]="DENY"
    report=run(specimen,computational_verdict=verdict)
    assert report.verdict.value=="REJECTED" and report.receipt["computational_verdict"]==verdict

def test_unknown_key_and_backend_are_unavailable_not_positive_reproduction(specimen,monkeypatch):
    c,ctx,selection,policy,private,grant,status=specimen;receipt=run(specimen).receipt
    args=dict(policy=policy,revocation=sign(status,"status",private),evaluation_time=100,computational_verdict="FAIL")
    monkeypatch.setattr(c,"_verify_signature",lambda *args: (_ for _ in ()).throw(c._Unknown("signature backend unavailable")))
    assert run(specimen).verdict.value=="UNKNOWN"
    report=c.recheck_public_consent(receipt,ctx,(sign(grant,"root",private),),**args)
    assert report["replay_status"]=="UNAVAILABLE" and report["admission_status"]=="UNKNOWN"

@pytest.mark.parametrize("field,value",[("verdict","UNKNOWN"),("enforcement","ESTABLISHED"),("computational_verdict","PASS"),("mechanism_digest","0"*64)])
def test_rehashed_receipt_forgery_does_not_replay(specimen,field,value):
    c,ctx,_,policy,private,grant,status=specimen;receipt=deepcopy(run(specimen).receipt);receipt[field]=value
    receipt["receipt_digest"]=hashlib.sha256(encoded({k:v for k,v in receipt.items() if k!="receipt_digest"})).hexdigest()
    report=c.recheck_public_consent(receipt,ctx,(sign(grant,"root",private),),policy=policy,
        revocation=sign(status,"status",private),evaluation_time=100,computational_verdict="FAIL")
    assert report["replay_status"]=="REJECTED"

def test_module_import_is_lazy_and_backend_absence_is_unknown(specimen,tmp_path):
    c,ctx,_,policy,private,grant,status=specimen
    data={"context":ctx.__dict__,"grants":[sign(grant,"root",private)],"policy":policy,"revocation":sign(status,"status",private)}
    path=tmp_path/'selection.json';path.write_bytes(encoded(data))
    program='''import json,sys
from verifier.consent.engine import ConsentContext
from verifier.consent.public import evaluate_public_consent
assert not any(n=="cryptography" or n.startswith("cryptography.") for n in sys.modules)
v=json.load(open(sys.argv[1]));r=evaluate_public_consent(ConsentContext(**v["context"]),tuple(v["grants"]),policy=v["policy"],revocation=v["revocation"],evaluation_time=100)
assert r.verdict.value=="UNKNOWN",r
print("STDLIB_IMPORT_AND_UNAVAILABLE_BACKEND_PASS")
'''
    env=dict(os.environ,PYTHONPATH=str(Path(c.__file__).resolve().parents[2]))
    result=subprocess.run([sys.executable,'-S','-c',program,str(path)],env=env,capture_output=True,text=True,timeout=20)
    assert result.returncode==0,(result.stdout,result.stderr)


@pytest.mark.parametrize("case",["receipt-evidence", "selected-grant", "selected-status", "null-evidence", "reason-type", "null-policy", "clock-type"])
def test_detectable_binding_refusal_precedes_unavailable_backend(specimen,monkeypatch,case):
    c,ctx,_,policy,private,grant,status=specimen
    receipt=deepcopy(run(specimen).receipt)
    selected_time=100
    if case=="receipt-evidence":receipt["evidence_digest"]="0"*64
    if case=="selected-grant":grant["operations"]=["publish"]
    if case=="selected-status":status["as_of"]=96
    if case=="null-evidence":receipt["evidence_digest"]=None
    if case=="reason-type":receipt["reason"]=False
    if case=="null-policy":receipt["policy_digest"]=None;policy=None
    if case=="clock-type":receipt["evaluation_time"]=True;selected_time=None
    receipt["receipt_digest"]=hashlib.sha256(encoded({k:v for k,v in receipt.items() if k!="receipt_digest"})).hexdigest()
    monkeypatch.setattr(c,"_verify_signature",lambda *args: (_ for _ in ()).throw(c._Unknown("signature backend unavailable")))
    result=c.recheck_public_consent(receipt,ctx,(sign(grant,"root",private),),policy=policy,
        revocation=sign(status,"status",private),evaluation_time=selected_time,computational_verdict="FAIL")
    assert result["replay_status"]=="REJECTED",result


@pytest.mark.parametrize("case",["extra", "schema", "mechanism", "key-length", "key-case", "key-duplicate", "id-duplicate", "key-empty",
    "key-overflow", "role-empty", "role-duplicate", "role-unknown", "role-overlap", "root-actor", "binding-duplicate",
    "binding-shape", "binding-digest", "binding-overflow", "age-bool", "age-negative", "age-overflow", "floor-float", "chain-bool", "chain-overflow"])
def test_malformed_public_authority_is_rejected(specimen,case):
    policy=deepcopy(specimen[3])
    if case=="extra":policy["extra"]=True
    if case=="schema":policy["schema_version"]="verifier-consent-policy-1"
    if case=="mechanism":policy["mechanism_digest"]="0"*64
    if case=="key-length":policy["keys"][0]["public_key"]="00"
    if case=="key-case":policy["keys"][0]["public_key"]=policy["keys"][0]["public_key"].upper()
    if case=="key-duplicate":policy["keys"][1]["public_key"]=policy["keys"][0]["public_key"]
    if case=="id-duplicate":policy["keys"][1]["key_id"]="root"
    if case=="key-empty":policy["keys"]=[]
    if case=="key-overflow":policy["keys"]*=86
    if case=="role-empty":policy["root_key_ids"]=[]
    if case=="role-duplicate":policy["root_key_ids"]=["root","root"]
    if case=="role-unknown":policy["root_key_ids"]=["missing"]
    if case=="role-overlap":policy["revocation_key_ids"]=["root"]
    if case=="root-actor":policy["keys"][0]["actor_id"]="other"
    if case=="binding-duplicate":policy["artifact_bindings"]*=2
    if case=="binding-shape":policy["artifact_bindings"][0].append("other")
    if case=="binding-digest":policy["artifact_bindings"][0][1]="00"
    if case=="binding-overflow":policy["artifact_bindings"]*=257
    if case=="age-bool":policy["max_revocation_age_seconds"]=True
    if case=="age-negative":policy["max_revocation_age_seconds"]=-1
    if case=="age-overflow":policy["max_revocation_age_seconds"]=2**53
    if case=="floor-float":policy["minimum_revocation_as_of"]=80.0
    if case=="chain-bool":policy["max_chain_length"]=True
    if case=="chain-overflow":policy["max_chain_length"]=17
    assert run(specimen,policy=policy).verdict.value=="REJECTED"


@pytest.mark.parametrize("boundary",["context", "policy", "grants", "revocation"])
def test_custom_candidate_callbacks_are_not_executed(specimen,boundary):
    class Hostile(dict):
        def items(self):raise AssertionError("candidate callback executed")
        def __iter__(self):raise AssertionError("candidate callback executed")
    c,ctx,_,policy,private,grant,status=specimen
    changes={boundary:Hostile({})}
    if boundary=="grants":changes[boundary]=(Hostile(sign(grant,"root",private)),)
    assert run(specimen,**changes).verdict.value=="REJECTED"


def test_capture_survives_caller_mutation_during_authentication(specimen,monkeypatch):
    c,ctx,_,policy,private,grant,status=specimen
    grants=(sign(grant,"root",private),);revocation=sign(status,"status",private)
    expected=c.evaluate_public_consent(ctx,grants,policy=policy,revocation=revocation,evaluation_time=100)
    original=c._verify_signature
    def mutate(*args):
        policy["artifact_bindings"].clear()
        grants[0]["payload"]["actor_id"]="other"
        revocation["payload"]["revoked_grant_ids"].append("grant-root")
        object.__setattr__(ctx,"actor_id","other")
        original(*args)
    monkeypatch.setattr(c,"_verify_signature",mutate)
    result=c.recheck_public_consent(expected.receipt,ctx,grants,policy=policy,revocation=revocation,evaluation_time=100)
    assert result["replay_status"]=="REPRODUCED" and result["admission_status"]=="PASS"
    assert result["evaluation"]==expected.receipt


def test_unknown_key_is_not_positive_admission(specimen):
    c,ctx,_,policy,private,grant,status=specimen
    record=sign(grant,"root",private);record["key_id"]="unconfigured"
    assert run(specimen,grants=(record,)).verdict.value=="UNKNOWN"


@pytest.mark.parametrize("case",["canonical-size", "recursive"])
def test_evidence_capture_failure_returns_bounded_rejection(specimen,case):
    if case=="canonical-size":
        record={"padding":["x"*512]*2000,"structure":[None]*9999}
    else:
        record={};record["cycle"]=record
    result=run(specimen,grants=(record,))
    assert result.verdict.value=="REJECTED"
    assert len(encoded(result.receipt))<4096


@pytest.mark.parametrize("sign_bit",[0,1])
@pytest.mark.parametrize("y",[0,1,2**255-20,2707385501144840649318225287225658788936804267575313519463743609750303402022,
    55188659117513257062467267217118295137698188065244968500265048394206261417927,2**255-19,2**255-18,2**255-1])
def test_public_policy_refuses_small_order_and_noncanonical_keys(specimen,y,sign_bit):
    c,_,selection,_,_,_,_=specimen
    selection["keys"][0]["public_key"]=(y | (sign_bit<<255)).to_bytes(32,"little").hex()
    with pytest.raises(ValueError):c.public_consent_policy(**selection)


@pytest.mark.parametrize("role",["root","status"])
def test_forged_identity_point_signature_cannot_admit_action(specimen,role):
    c,ctx,_,policy,private,grant,status=specimen
    next(row for row in policy["keys"] if row["key_id"]==role)["public_key"]="01"+"00"*31
    grants=(sign(grant,"root",private),);state=sign(status,"status",private)
    (grants[0] if role=="root" else state)["signature"]="01"+"00"*63
    result=c.evaluate_public_consent(ctx,grants,policy=policy,revocation=state,evaluation_time=100)
    assert result.verdict.value=="REJECTED"
