"""Current agent trajectory (AGENT) predicates over retained observations.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). Counts and record
indices are dimensionless. These fixtures execute no model, tool or training job.
"""
from __future__ import annotations

from copy import deepcopy
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject,composition_digest
from verifier.domains import agent
from verifier.domains.common import Budget,Refuted,Unavailable,digest
from verifier.domains.certification import build_domain_certificate,domain_policy,domain_request,implementation_digest
from verifier.domains.contracts import current_object_routes as routes
from test_current_harness_checks import specimen as harness_specimen
from test_current_typed_facets import collection as typed_collection

SEMANTIC='verifier-current-object-obligations-1'
CHECKS={'harness':'AGENT-1.8','trajectory':'AGENT-2.1','actions':'AGENT-2.3',
        'outcomes':'AGENT-4.1','claims':'AGENT-4.3'}


def specimen() -> tuple[dict,dict]:
    harness,retained=harness_specimen()
    harness.pop('invocations_digest');harness.pop('effects_digest');retained.pop('declarations')
    evidence={'schema_version':'verifier-domain-evidence-1','domain':'HARNESS','subject_id':'harness',
        'artifact':harness,'inputs':retained}
    policy=domain_policy(trust_roots=['historical-retained-harness'])
    child=build_domain_certificate(domain_request(evidence,target_depth=5),evidence,policy=policy)
    assert child['result']['status']=='PASS'
    steps=[{'index':i,'record':i,'decision':'retained declaration '+str(i)} for i in range(5)]
    actions=[{'tool':'sum','record':i} for i in (2,3)]
    outcomes={'retained_totals':[5,3]}
    return ({'harness_certificate_digest':digest(child),'harness_subject_id':'harness',
        'required_channels':['chat','tool_io'],'steps_digest':digest(steps),'actions_digest':digest(actions),
        'outcomes':outcomes,'claims':[{'id':'totals','statement':'The retained records contain five and three.',
            'support':[2,3],'channels':['tool_io']}]},
        {'harness_certificate':child,'steps':steps,'actions':actions,'outcomes':deepcopy(outcomes)})


def native(check: Any,artifact: dict,retained: dict,budget: Budget | None=None) -> dict:
    policy=domain_policy(trust_roots=['current-external-selection'])
    return agent.evaluate(check,artifact,retained,budget or Budget(100000),
        mechanism_digest=implementation_digest(),policy=policy)


@pytest.mark.parametrize('check',CHECKS)
def test_current_agent_route_is_explicitly_selected(check):
    route=routes.select_current_object_route(semantic_version=SEMANTIC,objective=CHECKS[check],represented_kind='AGENT')
    assert route.fixed_kind=='AGENT' and route.scope=='finite_retained_agent_'+check


@pytest.mark.parametrize('check',CHECKS)
def test_native_positive_controls_execute_selected_check(check):
    result=native(check,*specimen())
    assert result['observation_ceiling']==['chat','tool_io']
    assert result['steps']==(0 if check=='harness' else 5)
    assert result['actions']==(2 if check=='actions' else 0)
    assert result['historical_child_policy_reproduction']=='NOT_ESTABLISHED'


@pytest.mark.parametrize('check',['trajectories','','CLAIMS',' claims',None,True,['harness']])
def test_unsupported_native_selection_cannot_return_trajectory_success(check):
    with pytest.raises(Unavailable,match='unsupported agent check'):
        native(check,*specimen())


def test_subclass_selector_cannot_impersonate_harness():
    class Forged(str):
        def __eq__(self,other):return True
        def __ne__(self,other):return False
    with pytest.raises(Unavailable,match='unsupported agent check'):
        native(Forged('unregistered'),*specimen())


def test_unknown_selection_refuses_before_evidence_access():
    class Unreadable(dict):
        def __contains__(self,key):raise AssertionError('unsupported selector consumed evidence')
    with pytest.raises(Unavailable,match='unsupported agent check'):
        native('unregistered',Unreadable(),Unreadable(),Budget(0))


@pytest.mark.parametrize('check',['trajectory','actions','outcomes','claims'])
@pytest.mark.parametrize('position,value',[(0,False),(0,0.0),(1,True),(1,1.0)])
def test_trajectory_indices_cannot_pass_by_numeric_coercion(check,position,value):
    artifact,retained=specimen();retained['steps'][position]['index']=value
    artifact['steps_digest']=digest(retained['steps'])
    with pytest.raises(Refuted,match='trajectory indices'):
        native(check,artifact,retained)


@pytest.mark.parametrize('expected,reported',[(True,1),(1,True),(1,1.0),(1.0,1),({'n':1},{'n':True}),([1],[1.0])])
def test_outcome_inventory_preserves_exact_value_types(expected,reported):
    artifact,retained=specimen();artifact['outcomes']={'reported':expected};retained['outcomes']={'reported':reported}
    with pytest.raises(Refuted,match='outcomes differ'):
        native('outcomes',artifact,retained)


def inputs(check: str, *, artifact=None, retained=None, objects=None, **limits):
    contract=importlib.import_module('verifier.domains.contracts.agent_checks')
    if artifact is None: artifact,retained=specimen()
    artifact,retained=deepcopy(artifact),deepcopy(retained)
    if objects is None:
        objects=typed_collection()
        child_artifact=(retained['harness_certificate']['evidence']['artifact'] if retained is not None
            and 'harness_certificate' in retained else specimen()[1]['harness_certificate']['evidence']['artifact'])
        objects=[NamespaceObject.create(item.object_id,item.kind,artifact if item.kind.value=='AGENT' else child_artifact,
            dict(item.operands)) if item.kind.value in ('AGENT','HARNESS') else item for item in objects]
    subject=next(item for item in objects if item.object_id=='agent')
    if retained is not None:
        retained.setdefault('model',next(item.payload for item in objects if item.object_id=='model'))
        retained.setdefault('environment',next(item.payload for item in objects if item.object_id=='env'))
    evidence=canonical_bytes({'schema_version':'verifier-current-agent-checks-evidence-1',
        'objects':[item.to_dict() for item in objects],'inputs':retained})
    policy=contract.agent_checks_policy(trust_roots=['current-retained-agent-only'])
    request=contract.agent_checks_request(check=check,subject_id=subject.object_id,object_digest=subject.digest,
        collection_digest=composition_digest(objects),evidence_ref=digest(json.loads(evidence)),policy=policy,limits=limits)
    return contract,request,policy,evidence


def replay(contract,request,policy,evidence):
    certificate=contract.build_agent_checks_certificate(request,evidence,policy=policy)
    return routes.replay_current_object_certificate(certificate,semantic_version=SEMANTIC,
        objective=request['coordinate'],represented_kind='AGENT',expected_request=request,policy=policy)


@pytest.mark.parametrize('check',CHECKS)
def test_current_agent_positive_replay_is_bounded_and_deterministic(check):
    contract,request,policy,evidence=inputs(check)
    first=contract.build_agent_checks_certificate(request,evidence,policy=policy)
    assert first==contract.build_agent_checks_certificate(request,evidence,policy=policy)
    report=replay(contract,request,policy,evidence)
    assert report['computational_status']=='PASS',report
    result=report['native_result']
    assert result['object_profile_conformance']==result['authority']=='NOT_ESTABLISHED'
    assert result['evaluation']['observations']['agent']['historical_child_policy_reproduction']=='NOT_ESTABLISHED'


@pytest.mark.parametrize('check',CHECKS)
def test_rehashed_rebound_false_native_evidence_is_refuted(check):
    artifact,retained=specimen()
    if check=='harness': artifact['harness_subject_id']='another-harness'
    elif check=='trajectory':
        retained['steps'][1]['index']=9;artifact['steps_digest']=digest(retained['steps'])
    elif check=='actions':
        retained['actions'][0]['tool']='unregistered';artifact['actions_digest']=digest(retained['actions'])
    elif check=='outcomes':retained['outcomes']['retained_totals']=[99,3]
    else:artifact['claims'][0]['support']=[99]
    assert replay(*inputs(check,artifact=artifact,retained=retained))['computational_status']=='FAIL'


@pytest.mark.parametrize('check',CHECKS)
@pytest.mark.parametrize('bound',['max_operations','max_composition_operations','max_evidence_bytes',
    'max_payload_bytes','max_reference_bytes','max_items','max_objects'])
def test_selected_resource_exhaustion_remains_unknown(check,bound):
    assert replay(*inputs(check,**{bound:1}))['computational_status']=='UNKNOWN'
@pytest.mark.parametrize("check", CHECKS)
def test_missing_retained_evidence_is_unknown(check):
    contract, request, policy, evidence = inputs(check)
    assert replay(contract, request, policy, None)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest"])
def test_certificate_cannot_select_its_own_subject_or_evidence(field):
    contract, request, policy, evidence = inputs("trajectory")
    certificate = contract.build_agent_checks_certificate(request, evidence, policy=policy)
    request[field] = "other-subject" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        contract.recheck_agent_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field,value", [("status", "FAIL"), ("authority", "ESTABLISHED"),
                                         ("object_profile_conformance", "ESTABLISHED")])
def test_rehashed_claim_promotion_is_rejected(field, value):
    contract, request, policy, evidence = inputs("harness")
    certificate = json.loads(contract.build_agent_checks_certificate(request, evidence, policy=policy))
    certificate["result"][field] = value
    certificate["digest"] = digest({key: val for key, val in certificate.items() if key != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_agent_checks_certificate(canonical_bytes(certificate), expected_request=request, policy=policy)


@pytest.mark.parametrize("bad", [None, [], "", False])
def test_falsey_operands_cannot_normalize_into_valid_agent_record(bad):
    contract, request, policy, evidence = inputs("harness")
    value = json.loads(evidence); next(row for row in value["objects"] if row["object_id"] == "agent")["operands"] = bad
    evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
def test_public_agent_command_executes_native_replay(check, tmp_path, capsys):
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs(check)
    values = {"request": canonical_bytes(request), "policy": canonical_bytes(policy),
              "certificate": contract.build_agent_checks_certificate(request, evidence, policy=policy)}
    for name, content in values.items():
        (tmp_path / (name + ".json")).write_bytes(content)
    result = main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", CHECKS[check], "--represented-kind", "AGENT", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert result == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_agent_certificate_cannot_shed_canonical_evidence():
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs("harness")
    value = json.loads(contract.build_agent_checks_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("AGENT", tuple(key for key in value if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/agent_checks.py", "domains/agent.py", "standard/CURRENT_AGENT_CHECKS.md"])
def test_agent_dependencies_invalidate_polish(relative, monkeypatch):
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def changed(path):
        value = original(path)
        return value + b"\nchanged benchmark dependency\n" if path == target else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("check", CHECKS)
def test_agent_inventory_preserves_each_registered_objective(check):
    from verifier.domains.inventory import get_slot
    tier = int(CHECKS[check].split("-")[1].split(".")[0])
    row = get_slot("AGENT", tier).to_dict()
    assert row["mechanized"]
    selected = next(item for item in row["registered_objectives"] if item["coordinate"] == CHECKS[check])
    assert "agent_checks" in selected["binding"]["checking_mechanism"]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", ["domains/contracts/agent_checks.py", "domains/agent.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_AGENT_CHECKS.md", "standard/NAMESPACE_OBJECTS.md"])
def test_changed_direct_dependency_invalidates_agent_policy(relative, monkeypatch):
    contract, request, policy, evidence = inputs("harness")
    certificate = contract.build_agent_checks_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(contract.__file__).parents[2] / relative
    def changed(path):
        content = original(path)
        return content + b"\nchanged dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_agent_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_native_operation_limit_has_exact_and_one_under_controls(check):
    contract, request, policy, evidence = inputs(check)
    result = replay(contract, request, policy, evidence)
    used = result["native_result"]["evaluation"]["observations"]["operations"]
    request["limits"]["max_operations"] = used
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    request["limits"]["max_operations"] = used - 1
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"







@pytest.mark.parametrize('check',CHECKS)
@pytest.mark.parametrize('field',['model','environment'])
def test_native_context_must_equal_the_selected_operand(check,field):
    artifact,retained=specimen();retained[field]={'substituted':True}
    assert replay(*inputs(check,artifact=artifact,retained=retained))['computational_status']=='FAIL'


@pytest.mark.parametrize('mutation',['subject','payload','operand'])
def test_child_harness_must_be_the_exact_namespace_operand(mutation):
    artifact,retained=specimen();contract,request,policy,evidence=inputs('harness',artifact=artifact,retained=retained)
    value=json.loads(evidence);objects=[NamespaceObject.create(**row) for row in value['objects']]
    harness=next(item for item in objects if item.object_id=='harness')
    if mutation=='subject':
        changed=NamespaceObject.create('another-harness','HARNESS',harness.payload)
        item=next(item for item in objects if item.object_id=='agent')
        operands=dict(item.operands);operands['harness']=['another-harness']
        objects=[NamespaceObject.create(item.object_id,item.kind,item.payload,operands) if row.object_id=='agent' else row for row in objects]
    elif mutation=='payload': changed=NamespaceObject.create('harness','HARNESS',{**harness.payload,'record_count':99})
    else:
        item=next(item for item in objects if item.object_id=='agent');operands=dict(item.operands);operands['harness']=['env']
        objects=[NamespaceObject.create(item.object_id,item.kind,item.payload,operands) if row.object_id=='agent' else row for row in objects]
        changed=harness
    objects=[changed if row.object_id=='harness' else row for row in objects]
    assert replay(*inputs('harness',artifact=artifact,retained=retained,objects=objects))['computational_status']=='FAIL'


@pytest.mark.parametrize('field',['harness_certificate','model','environment'])
def test_absent_selected_context_stays_unknown(field):
    contract,request,policy,evidence=inputs('harness');value=json.loads(evidence);value['inputs'].pop(field)
    encoded=canonical_bytes(value);request['evidence_ref']=digest(value)
    assert replay(contract,request,policy,encoded)['computational_status']=='UNKNOWN'


@pytest.mark.parametrize('check',CHECKS)
def test_absent_native_inputs_are_unknown(check):
    artifact,_=specimen()
    assert replay(*inputs(check,artifact=artifact,retained=None))['computational_status']=='UNKNOWN'


@pytest.mark.parametrize('check,field',[('trajectory','steps'),('actions','actions'),('outcomes','outcomes'),('claims','steps')])
def test_missing_selected_native_support_stays_unknown(check,field):
    artifact,retained=specimen();retained.pop(field)
    assert replay(*inputs(check,artifact=artifact,retained=retained))['computational_status']=='UNKNOWN'


@pytest.mark.parametrize('mutation',['duplicate-id','duplicate-support','duplicate-channel','wrong-support-channel'])
def test_claim_support_inventory_is_unique_and_channel_exact(mutation):
    artifact,retained=specimen();claim=artifact['claims'][0]
    if mutation=='duplicate-id': artifact['claims'].append(deepcopy(claim))
    elif mutation=='duplicate-support':claim['support'].append(2)
    elif mutation=='duplicate-channel':claim['channels'].append('tool_io')
    else:claim['channels']=['chat']
    assert replay(*inputs('claims',artifact=artifact,retained=retained))['computational_status']=='FAIL'


def test_duplicate_declared_action_is_not_a_second_witness():
    artifact,retained=specimen();retained['actions'].append(deepcopy(retained['actions'][0]))
    artifact['actions_digest']=digest(retained['actions'])
    assert replay(*inputs('actions',artifact=artifact,retained=retained))['computational_status']=='FAIL'


@pytest.mark.parametrize('check',CHECKS)
def test_declared_gap_cannot_become_an_observation_ceiling(check):
    artifact,retained=specimen();artifact['required_channels'].append('hidden')
    assert replay(*inputs(check,artifact=artifact,retained=retained))['computational_status']=='UNKNOWN'


def test_structural_claim_support_does_not_prove_statement_truth():
    artifact,retained=specimen();artifact['claims'][0]['statement']='All mathematical conjectures are resolved.'
    assert replay(*inputs('claims',artifact=artifact,retained=retained))['computational_status']=='PASS'


def test_empty_declared_actions_do_not_prove_absence_of_actual_actions():
    artifact,retained=specimen();retained['actions']=[];artifact['actions_digest']=digest([])
    assert replay(*inputs('actions',artifact=artifact,retained=retained))['computational_status']=='PASS'


@pytest.mark.parametrize('check',CHECKS)
def test_current_agent_rejects_legacy_semantic_selection(check):
    with pytest.raises(ValueError):
        routes.select_current_object_route(semantic_version='verifier-domain-obligations-1',
            objective=CHECKS[check],represented_kind='AGENT')


def test_actual_native_checker_and_external_child_policy_are_used(monkeypatch):
    calls=[];original=agent.evaluate
    def tracked(check,artifact,retained,budget,**kwargs):
        calls.append((check,deepcopy(kwargs['policy']),budget.limit))
        return original(check,artifact,retained,budget,**kwargs)
    monkeypatch.setattr(agent,'evaluate',tracked)
    assert replay(*inputs('claims'))['computational_status']=='PASS'
    assert len(calls)==2
    for check,policy,limit in calls:
        assert check=='claims' and policy['trust_roots']==['current-retained-agent-only']
        assert policy['max_operations']==limit and policy['max_tolerance']==0
        assert policy['witness_keys']=={}


@pytest.mark.parametrize('target',['agent','polish'])
def test_transitive_native_descriptor_invalidates_every_replay_policy(target,monkeypatch):
    from verifier.domains import certification
    from verifier.runtime import polish
    contract,request,policy,evidence=inputs('harness')
    certificate=contract.build_agent_checks_certificate(request,evidence,policy=policy)
    before=polish.mechanism_digest()
    monkeypatch.setattr(certification,'implementation_digest',lambda:'sha256:'+'0'*64)
    if target=='agent':
        with pytest.raises(ValueError,match='installed mechanism'):
            contract.recheck_agent_checks_certificate(certificate,expected_request=request,policy=policy)
    else:assert polish.mechanism_digest()!=before


@pytest.mark.parametrize('mutation',['record','result','mechanism','domain-depth'])
def test_child_success_label_cannot_replace_native_support(mutation):
    artifact,retained=specimen();child=retained['harness_certificate']
    if mutation=='record':
        record=child['evidence']['inputs']['records'][1];record['payload']={'changed':True};record['payload_digest']=digest(record['payload'])
        child['request']=domain_request(child['evidence'],target_depth=5)
    elif mutation=='result':child['result']['scope']='a forged broader claim'
    elif mutation=='mechanism':child['mechanism_digest']='sha256:'+'0'*64
    else:child['result']['domain_depth']=4
    child['certificate_digest']=digest({k:v for k,v in child.items() if k!='certificate_digest'})
    artifact['harness_certificate_digest']=digest(child)
    expected='UNKNOWN' if mutation in ('mechanism','domain-depth') else 'FAIL'
    assert replay(*inputs('harness',artifact=artifact,retained=retained))['computational_status']==expected


def test_ambiguous_child_invocation_does_not_identify_one_declared_action():
    artifact,retained=specimen();child=retained['harness_certificate'];bundle=child['evidence']
    bundle['inputs']['invocations'].append(deepcopy(bundle['inputs']['invocations'][0]))
    child=build_domain_certificate(domain_request(bundle,target_depth=5),bundle,
        policy=domain_policy(trust_roots=['historical-retained-harness']))
    assert child['result']['status']=='PASS'
    retained['harness_certificate']=child;artifact['harness_certificate_digest']=digest(child)
    assert replay(*inputs('actions',artifact=artifact,retained=retained))['computational_status']=='FAIL'


def test_historical_policy_digest_is_retained_without_claiming_its_reproduction():
    artifact,retained=specimen();child=retained['harness_certificate'];child['policy_digest']='sha256:'+'0'*64
    child['certificate_digest']=digest({k:v for k,v in child.items() if k!='certificate_digest'})
    artifact['harness_certificate_digest']=digest(child)
    report=replay(*inputs('harness',artifact=artifact,retained=retained))
    assert report['computational_status']=='PASS'
    assert report['native_result']['evaluation']['observations']['agent']['historical_child_policy_reproduction']=='NOT_ESTABLISHED'


def test_harness_selection_does_not_require_unselected_trajectory_evidence():
    artifact,retained=specimen()
    for key in ('steps','actions','outcomes'):retained.pop(key)
    assert replay(*inputs('harness',artifact=artifact,retained=retained))['computational_status']=='PASS'
