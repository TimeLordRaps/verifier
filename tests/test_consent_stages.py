"""Distinct consent predicates, independently signed refuters and exact replay.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). Signing seeds are
public test fixtures only. Time values are integer Unix seconds.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib
import importlib.util
import json

import pytest

# test_public_consent skips this whole module where the signing backend is absent (see its module-level guard).
from test_public_consent import specimen, sign
from verifier.consent import public


def module():
    assert importlib.util.find_spec("verifier.consent.stages") is not None, "Distinct consent stages are absent"
    return importlib.import_module("verifier.consent.stages")


def selected(specimen, **changes):
    _, context, _, policy, private, grant, status = specimen
    args = dict(context=context, grants=(sign(grant, "root", private),), policy=policy,
        revocation=sign(status, "status", private), evaluation_time=100, computational_verdict="FAIL")
    args.update(changes)
    return args


def evaluate(specimen, **changes):
    return module().evaluate_consent_stages(**selected(specimen, **changes))


def statuses(report):
    return {key: value["status"] for key, value in report["stages"].items()}


def test_positive_stages_and_independent_reproduction(specimen):
    candidate = module()
    report = evaluate(specimen)
    assert statuses(report) == {name: "PASS" for name in ("7.1", "7.2", "7.3", "7.4", "7.6")}
    assert report["selection"]["computational_verdict"] == "FAIL"
    assert report["admission_status"] == "PASS" and report["enforcement"] == "NOT_ESTABLISHED"
    replay = candidate.recheck_consent_stages(report, **selected(specimen))
    assert replay["replay_status"] == "REPRODUCED" and replay["reproduction_status"] == "PASS"
    assert replay["objective"] == "7.5" and replay["admission_status"] == "PASS"
    assert replay["evaluation"] == report


@pytest.mark.parametrize("case,expected", [
    ("scope", {"7.1":"FAIL","7.2":"PASS","7.3":"PASS","7.4":"PASS","7.6":"PASS"}),
    ("missing-status", {"7.1":"PASS","7.2":"PASS","7.3":"UNKNOWN","7.4":"UNKNOWN","7.6":"PASS"}),
    ("expired", {"7.1":"PASS","7.2":"PASS","7.3":"FAIL","7.4":"FAIL","7.6":"PASS"}),
    ("empty-authority", {"7.1":"PASS","7.2":"UNKNOWN","7.3":"PASS","7.4":"UNKNOWN","7.6":"PASS"}),
])
def test_stage_results_do_not_alias_aggregate(specimen, case, expected):
    changes={}
    if case=="scope": changes["context"]=replace(specimen[1], operation="sell")
    if case=="missing-status": changes["revocation"]=None
    if case=="expired": specimen[5]["not_after"]=100
    if case=="empty-authority": specimen[3]["artifact_bindings"]=[]
    report=evaluate(specimen, **changes)
    assert statuses(report)==expected
    assert report["admission_status"] != "PASS"


@pytest.mark.parametrize("field,value", [("object_name","DATA"),("artifact_digest","b"*64),
    ("operation","sell"),("actor_id","other"),("observer_id","other"),("purpose","sell")])
def test_scope_refuters_are_independent_of_time(specimen,field,value):
    report=evaluate(specimen,context=replace(specimen[1],**{field:value}),evaluation_time=None)
    assert report["stages"]["7.1"]["status"]=="FAIL"


@pytest.mark.parametrize("case,expected", [("missing-clock","UNKNOWN"),("wrong-clock","FAIL"),
    ("end-exclusive","FAIL"),("start-inclusive","PASS"),("future","UNKNOWN"),
    ("stale","UNKNOWN"),("rollback","UNKNOWN"),("revoked-stale","FAIL"),("status-role","FAIL")])
def test_time_and_revocation_refuters(specimen,case,expected):
    changes={}
    if case=="missing-clock": changes["evaluation_time"]=None
    if case=="wrong-clock": changes["evaluation_time"]=101
    if case=="end-exclusive": specimen[5]["not_after"]=100
    if case=="start-inclusive": specimen[5]["not_before"]=100
    if case=="future": specimen[6].update(as_of=101,next_update=110)
    if case=="stale": specimen[6].update(as_of=60,next_update=105)
    if case=="rollback": specimen[6].update(as_of=79,next_update=105)
    if case=="revoked-stale": specimen[6].update(as_of=60,next_update=70,revoked_grant_ids=["grant-root"])
    if case=="status-role":
        specimen[6]["issuer_id"]="operator"
        changes["revocation"]=sign(specimen[6],"delegate",specimen[4])
    report=evaluate(specimen,**changes)
    assert report["stages"]["7.3"]["status"]==expected


@pytest.mark.parametrize("case", ["parent", "disabled", "issuer", "widen", "interval", "duplicate", "revoked", "deny"])
def test_delegation_checks_edges_and_prerequisites(specimen,case):
    parent=specimen[5];private=specimen[4]
    child={**parent,"grant_id":"child","issuer_id":"operator","actor_id":"operator",
        "operations":["publish"],"parent_digest":sign(parent,"root",private)["payload_digest"],"allow_delegation":False}
    def grants():return (sign(parent,"root",private),sign(child,"delegate",private))
    assert evaluate(specimen,grants=grants())["stages"]["7.4"]["status"]=="PASS"
    if case=="parent":child["parent_digest"]="0"*64
    if case=="disabled":parent["allow_delegation"]=False;child["parent_digest"]=sign(parent,"root",private)["payload_digest"]
    if case=="issuer":child["issuer_id"]="foreign"
    if case=="widen":child["operations"].append("sell")
    if case=="interval":child["not_after"]=111
    if case=="duplicate":child["grant_id"]=parent["grant_id"]
    if case=="revoked":specimen[6]["revoked_grant_ids"]=[parent["grant_id"]]
    if case=="deny":parent["effect"]="DENY";child["parent_digest"]=sign(parent,"root",private)["payload_digest"]
    assert evaluate(specimen,grants=grants())["stages"]["7.4"]["status"]=="FAIL"


@pytest.mark.parametrize("verdict", ["PASS","FAIL","UNKNOWN","REJECTED","CONFLICTED"])
@pytest.mark.parametrize("effect", ["ALLOW","DENY"])
def test_all_computational_verdicts_preserved_without_admission_effect(specimen,verdict,effect):
    specimen[5]["effect"]=effect
    report=evaluate(specimen,computational_verdict=verdict)
    assert report["stages"]["7.6"]["status"]=="PASS"
    assert report["selection"]["computational_verdict"]==verdict
    assert report["admission_status"]==("PASS" if effect=="ALLOW" else "FAIL")


def unavailable(*args):
    raise public._Unknown("public signature backend unavailable")


def test_missing_backend_separates_reproduction_and_admission(specimen,monkeypatch):
    candidate=module();before=evaluate(specimen)
    monkeypatch.setattr(public,"_verify_signature",unavailable)
    current=evaluate(specimen)
    assert current["admission_status"]=="UNKNOWN"
    replay=candidate.recheck_consent_stages(before,**selected(specimen))
    assert replay["replay_status"]=="UNAVAILABLE" and replay["reproduction_status"]=="UNKNOWN"
    assert replay["admission_status"]=="UNKNOWN"
    same=candidate.recheck_consent_stages(current,**selected(specimen))
    assert same["replay_status"]=="REPRODUCED" and same["reproduction_status"]=="PASS"
    assert same["admission_status"]=="UNKNOWN"


@pytest.mark.parametrize("field,value", [("operation","sell"),("artifact_digest","b"*64),("timestamp",101)])
def test_selected_substitution_rejected_before_unavailable_backend(specimen,monkeypatch,field,value):
    candidate=module();report=evaluate(specimen)
    monkeypatch.setattr(public,"_verify_signature",unavailable)
    result=candidate.recheck_consent_stages(report,**selected(specimen,context=replace(specimen[1],**{field:value})))
    assert result["replay_status"]=="REJECTED" and result["reproduction_status"]=="FAIL"


def test_known_wrong_root_role_cannot_hide_behind_missing_backend(specimen,monkeypatch):
    module();specimen[5]["issuer_id"]="operator"
    args=selected(specimen,grants=(sign(specimen[5],"delegate",specimen[4]),))
    monkeypatch.setattr(public,"_verify_signature",unavailable)
    report=module().evaluate_consent_stages(**args)
    assert report["stages"]["7.2"]["status"]=="FAIL"


def test_rehashed_forged_stage_result_is_rejected(specimen):
    candidate=module();report=evaluate(specimen,revocation=None)
    report["stages"]["7.3"]={"status":"PASS","reason":"forged"}
    body={k:v for k,v in report.items() if k!="receipt_digest"}
    report["receipt_digest"]=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    assert candidate.recheck_consent_stages(report,**selected(specimen,revocation=None))["replay_status"]=="REJECTED"


def test_noninterference_gate_detects_a_verdict_sensitive_evaluator(specimen,monkeypatch):
    module();original=public.evaluate_public_consent
    def altered(*args,**kwargs):
        result=original(*args,**kwargs)
        if kwargs["computational_verdict"]=="FAIL":result.receipt["reason"]="verdict-dependent admission"
        return result
    monkeypatch.setattr(public,"evaluate_public_consent",altered)
    assert evaluate(specimen)["stages"]["7.6"]["status"]=="FAIL"


@pytest.mark.parametrize("boundary", ["policy","grants","revocation"])
def test_plain_capture_rejects_foreign_callbacks(specimen,boundary):
    class Hostile(dict):
        def items(self):raise AssertionError("candidate callback executed")
        def __iter__(self):raise AssertionError("candidate callback executed")
    args=selected(specimen);args[boundary]=(Hostile({}),) if boundary=="grants" else Hostile({})
    report=module().evaluate_consent_stages(**args)
    assert report["admission_status"]=="FAIL"


def test_shared_source_is_bound_to_replay_descriptor(specimen,monkeypatch):
    candidate=module();before=candidate.mechanism_digest()
    from pathlib import Path
    original=Path.read_bytes;target=Path(public.__file__).resolve()
    def changed(path):
        data=original(path)
        return data+b"\n# source changed\n" if path.resolve()==target else data
    monkeypatch.setattr(Path,"read_bytes",changed)
    assert candidate.mechanism_digest()!=before


def test_known_status_forgery_is_not_hidden_by_missing_grants(specimen):
    args=selected(specimen,grants=())
    args["revocation"]["signature"]="00"*64
    assert module().evaluate_consent_stages(**args)["admission_status"]=="FAIL"


def test_known_revoked_root_is_not_hidden_by_unknown_delegate_key(specimen):
    parent=specimen[5]
    child={**parent,"grant_id":"child","issuer_id":"operator","actor_id":"operator",
        "parent_digest":sign(parent,"root",specimen[4])["payload_digest"]}
    leaf=sign(child,"delegate",specimen[4]);leaf["key_id"]="unconfigured"
    specimen[6]["revoked_grant_ids"]=[parent["grant_id"]]
    args=selected(specimen,grants=(sign(parent,"root",specimen[4]),leaf))
    assert module().evaluate_consent_stages(**args)["stages"]["7.3"]["status"]=="FAIL"


def test_known_issuer_key_mismatch_rejects_without_backend(specimen,monkeypatch):
    module();parent=specimen[5]
    child={**parent,"grant_id":"child","issuer_id":"operator","actor_id":"operator",
        "parent_digest":sign(parent,"root",specimen[4])["payload_digest"]}
    args=selected(specimen,grants=(sign(parent,"root",specimen[4]),sign(child,"root",specimen[4])))
    monkeypatch.setattr(public,"_verify_signature",unavailable)
    assert module().evaluate_consent_stages(**args)["stages"]["7.2"]["status"]=="FAIL"


@pytest.mark.parametrize("missing", ["policy_digest","evaluation_time"])
def test_positive_receipt_requires_bindings_even_when_replay_input_unavailable(specimen,missing):
    candidate=module();report=evaluate(specimen)
    report["selection"][missing]=None
    report["receipt_digest"]=hashlib.sha256(json.dumps({k:v for k,v in report.items() if k!="receipt_digest"},
        sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    args=selected(specimen,**({"policy":None} if missing=="policy_digest" else {"evaluation_time":None}))
    assert candidate.recheck_consent_stages(report,**args)["replay_status"]=="REJECTED"


def test_refusal_does_not_authenticate_an_unsigned_denial(specimen):
    args=selected(specimen)
    args["grants"][0]["payload"]["effect"]="DENY"
    args["grants"][0]["signature"]="00"*64
    report=module().evaluate_consent_stages(**args)
    assert report["stages"]["7.2"]["status"]=="FAIL"
    assert report["stages"]["7.4"]["status"]=="FAIL"
    assert "authenticated denial" not in report["stages"]["7.4"]["reason"]


@pytest.mark.parametrize("case", ["scope-without-policy","validity-without-time","delegation-without-validity","scope-without-chain"])
def test_partial_positive_predicate_retains_its_own_prerequisites(specimen,case):
    candidate=module();positive=evaluate(specimen);args=selected(specimen)
    args["policy" if case=="scope-without-policy" else "evaluation_time"]=None
    if case=="scope-without-chain":args["grants"]=()
    report=candidate.evaluate_consent_stages(**args)
    stage={"scope-without-policy":"7.1","validity-without-time":"7.3",
        "delegation-without-validity":"7.4","scope-without-chain":"7.1"}[case]
    report["stages"][stage]=positive["stages"][stage]
    assert report["admission_status"]=="UNKNOWN"
    report["receipt_digest"]=hashlib.sha256(json.dumps({k:v for k,v in report.items() if k!="receipt_digest"},
        sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    assert candidate.recheck_consent_stages(report,**args)["replay_status"]=="REJECTED"
