"""Adversarial and compatibility controls for separately selected TIME/SPACE."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, ObjectKind, assess_composition, composition_digest
from verifier.core.contextual_namespace import ContextReference, ContextualObject, contextual_digest, assess_contextual_composition, decode_contextual_object, decode_contextual_collection, COLLECTION_VERSION
from verifier.domains.contracts import spacetime_profiles as p, spacetime_mapping as mapping, spacetime_execution as execution


def digest(value):
    return "sha256:" + canonical_digest(value)


def time(domain="sim-clock", branch="main", values=(0,1,2,3,4,5), *, profile="logical-strict/1", unit="sim-step", uncertainty=0):
    return {"schema_version":p.TIME_VERSION,"profile":profile,"domain":domain,"unit":unit,
        "epoch":"declared-epoch" if profile=="physical-clock/1" else None,
        "resolution":p.rational(1),"uncertainty":p.rational(uncertainty),"run_id":"run-1","branch_id":branch,
        "points":[{"id":"p"+str(index),"value":p.rational(value)} for index,value in enumerate(values)],"order":[]}


def space():
    return {"schema_version":p.SPACE_VERSION,"profile":"directed-adjacency/1","domain":"sim-space",
        "unit":None,"frame":"grid-frame","nodes":["a","b","c"],
        "relations":[{"source":"a","target":"b"}]}


def wrapped(name, kind, payload=None, operands=None):
    return ContextualObject(NamespaceObject.create(name,kind,payload or {},operands))


def ref(target, role="execution"):
    payload=target.record.payload
    return ContextReference(role,target.record.kind,target.record.object_id,target.digest,payload["domain"],payload["profile"])


def inventory():
    """All 26 existing kinds with complete unchanged namespace operand slots."""
    objects={}
    def add(kind, operands=None, payload=None):
        objects[kind]=wrapped(kind,kind,payload,operands)
    for kind in ("HUMAN","ROLE","HARDWARE","OBJECT","ENV","DATA","VERIFIER","ARCH","HARNESS","TOKEN"):
        add(kind)
    add("TIME",payload=time())
    add("SPACE",payload=space())
    add("ACTOR",{"representation":["HUMAN"],"root_human":["HUMAN"]})
    add("COLLECTIVE",{"roles":["ROLE"]})
    add("IDENTITY",{"actor":["ACTOR"],"role":["ROLE"]})
    add("OWNER",{"actor":["ACTOR"],"object":["OBJECT"]})
    add("RECEIPT",{"subject":["OBJECT"],"hardware":["HARDWARE"]})
    add("EVENT",{"time":["TIME"],"space":["SPACE"],"meaning":["OBJECT"]})
    add("BENCH",{"verifier":["VERIFIER"],"data":["DATA"]})
    add("TRAIN",{"data":["DATA"],"events":["EVENT"],"bench":["BENCH"],"arch":["ARCH"]})
    add("MODEL",{"train":["TRAIN"],"data":["DATA"],"events":["EVENT"],"bench":["BENCH"],"arch":["ARCH"],"env":["ENV"],"hardware":["HARDWARE"]})
    add("AGENT",{"model":["MODEL"],"harness":["HARNESS"],"env":["ENV"]})
    add("SIM",{"data":["DATA"],"verifier":["VERIFIER"],"objects":["OBJECT"],"env":["ENV"]})
    add("BOT",{"agent":["AGENT"],"sim":["SIM"],"env":["ENV"]})
    add("GRAPH",{"members":["OBJECT"]},{"element_kind":"OBJECT"})
    add("HYPER",{"related":["OBJECT"]})
    assert set(objects)=={kind.value for kind in ObjectKind}
    return objects


@pytest.mark.parametrize("kind",[kind.value for kind in ObjectKind])
def test_each_kind_has_optional_typed_context_without_hyper_wrapper(kind):
    objects=inventory()
    clock=wrapped("extra-clock","TIME",time(domain="observation-clock"))
    objects[kind]=ContextualObject(objects[kind].record,(ref(clock,"observation"),))
    rows=[*objects.values(),clock]
    assert assess_contextual_composition(rows,expected_digest=contextual_digest(rows))["status"]=="PASS"
    assert p.assess_context_capabilities(rows,expected_digest=contextual_digest(rows))["status"]=="PASS"


def test_context_wire_is_closed_and_legacy_digests_remain_identical():
    record=NamespaceObject.create("plain","OBJECT",{"meaning":"retained"})
    old_digest=record.digest
    obj=ContextualObject(record)
    assert ContextualObject.from_dict(obj.to_dict())==obj
    assert obj.digest!=old_digest and obj.record.digest==old_digest
    value=obj.to_dict();value["arbitrary_context_bypass"]=[]
    with pytest.raises(ValueError):
        ContextualObject.from_dict(value)
    legacy=[record]
    assert assess_composition(legacy,expected_digest=composition_digest(legacy)).verdict.value=="PASS"
    assert assess_composition([obj],expected_digest=composition_digest(legacy)).verdict.value=="FAIL"


@pytest.mark.parametrize("mutation",["missing_target","digest","domain","profile","kind","required_absent","payload_bypass"])
def test_missing_or_substituted_context_cannot_pass(mutation):
    clock=wrapped("clock","TIME",time())
    selected=ref(clock)
    subject=ContextualObject(NamespaceObject.create("subject","OBJECT",{}),(selected,))
    rows=[clock,subject]
    policy=(("subject",selected),)
    if mutation=="missing_target":
        rows=[subject]
    elif mutation in ("required_absent","payload_bypass"):
        payload={"contexts":[selected.to_dict()]} if mutation=="payload_bypass" else {}
        rows=[clock,wrapped("subject","OBJECT",payload)]
    else:
        value=selected.to_dict()
        value[{"digest":"object_digest","domain":"domain","profile":"profile","kind":"kind"}[mutation]]= {
            "digest":"sha256:"+"f"*64,"domain":"other-clock","profile":"physical-clock/1","kind":"SPACE"}[mutation]
        rows=[clock,ContextualObject(subject.record,(ContextReference.from_dict(value),))]
    result=assess_contextual_composition(rows,expected_digest=contextual_digest(rows),required_contexts=policy)
    assert result["status"]==("UNKNOWN" if mutation in ("missing_target","required_absent","payload_bypass") else "FAIL")


def test_context_cycles_and_event_operand_bypass_are_refuted():
    fake="sha256:"+"0"*64
    a=ContextualObject(NamespaceObject.create("a","TIME",time()),(ContextReference("execution",ObjectKind.TIME,"b",fake,"sim-clock","logical-strict/1"),))
    b=ContextualObject(NamespaceObject.create("b","TIME",time()),(ContextReference("execution",ObjectKind.TIME,"a",fake,"sim-clock","logical-strict/1"),))
    result=assess_contextual_composition([a,b],expected_digest=contextual_digest([a,b]))
    assert result["status"]=="FAIL" and "cycle" in result["reason"]
    objects=inventory();event=objects["EVENT"]
    objects["EVENT"]=ContextualObject(NamespaceObject.create("EVENT","EVENT",{}, {"time":["TIME"],"meaning":["OBJECT"]}),(ref(objects["SPACE"],"location"),))
    rows=list(objects.values())
    assert assess_contextual_composition(rows,expected_digest=contextual_digest(rows))["status"]=="FAIL"


@pytest.mark.parametrize("value",[{"numerator":1,"denominator":0},{"numerator":2,"denominator":4},{"numerator":True,"denominator":1},{"numerator":1.0,"denominator":1},{"numerator":1,"denominator":-1}])
def test_rational_parser_refuses_nonexact_or_nonnormalized(value):
    with pytest.raises(ValueError):
        p.fraction(value)


def test_rational_normalization_and_representation_bound():
    assert p.rational(2,-4)=={"numerator":-1,"denominator":2}
    assert p.rational(0,7)=={"numerator":0,"denominator":1}
    with pytest.raises(p.Exhausted):
        p.rational(1<<128)
    with pytest.raises(ValueError):
        p.rational(False)


@pytest.mark.parametrize("mutation",["clock","unit","branch","epoch","profile"])
def test_no_wrong_clock_or_implicit_unit_comparison(mutation):
    first=time()
    second=copy.deepcopy(first)
    if mutation=="profile":
        second=time(profile="physical-clock/1",domain="sim-clock",unit="sim-step")
    elif mutation=="epoch":
        first=time(profile="physical-clock/1")
        second=copy.deepcopy(first);second["epoch"]="other-epoch"
    else:
        second[{"clock":"domain","unit":"unit","branch":"branch_id"}[mutation]]="different"
    assert p.compare_time(first,"p0",second,"p1")["status"]=="UNKNOWN"


def test_logical_partial_order_and_declared_concurrency_are_not_scalar_time():
    value=time(profile="logical-partial/1")
    for field in ("unit","epoch","resolution","uncertainty"):
        value[field]=None
    for point in value["points"]:
        point["value"]=None
    value["order"]=[["p0","p1"],["p1","p2"]]
    assert p.compare_time(value,"p0",value,"p2")["relation"]=="BEFORE"
    assert p.compare_time(value,"p0",value,"p5")["relation"]=="INCOMPARABLE"
    value["order"].append(["p2","p0"])
    assert p.assess_profile(canonical_bytes(value),expected_digest=digest(value),kind="TIME")["status"]=="FAIL"


def test_uncertainty_resolution_and_missing_observations_stay_separate():
    value=time(profile="physical-clock/1",unit="second",uncertainty=1)
    assert p.compare_time(value,"p0",value,"p1")["status"]=="UNKNOWN"
    assert p.compare_time(value,"p0",value,"p5")["relation"]=="BEFORE"
    assert p.assess_profile(None,expected_digest=digest(value),kind="TIME")["status"]=="UNKNOWN"
    assert p.assess_profile(canonical_bytes(value),expected_digest=None,kind="TIME")["status"]=="UNKNOWN"
    value["points"]=[]
    assert p.assess_profile(canonical_bytes(value),expected_digest=digest(value),kind="TIME")["status"]=="UNKNOWN"


def test_space_capability_surface_does_not_assume_euclidean_geometry():
    value=space()
    assert p.query_space(value,capability="adjacency",source="a",target="b")["adjacent"] is True
    assert p.query_space(value,capability="adjacency",source="b",target="a")["adjacent"] is False
    for capability in ("distance","direction","transform","clock_conversion"):
        assert p.query_space(value,capability=capability,source="a",target="b")["status"]=="UNKNOWN"
    value["profile"]="unimplemented-frame-profile/1"
    assert p.assess_profile(canonical_bytes(value),expected_digest=digest(value),kind="SPACE")["status"]=="UNKNOWN"


def test_finite_metric_predicate_and_missing_or_false_metric_controls():
    value=space();value["profile"]="finite-metric/1";value["unit"]="declared-distance-unit"
    positions={"a":0,"b":1,"c":2}
    value["relations"]=[{"source":left,"target":right,"distance":p.rational(abs(a-b))} for left,a in positions.items() for right,b in positions.items()]
    assert p.assess_profile(canonical_bytes(value),expected_digest=digest(value),kind="SPACE")["status"]=="PASS"
    assert p.query_space(value,capability="distance",source="a",target="c")["distance"]==p.rational(2)
    partial=copy.deepcopy(value);partial["relations"].pop()
    assert p.assess_profile(canonical_bytes(partial),expected_digest=digest(partial),kind="SPACE")["status"]=="UNKNOWN"
    for row in value["relations"]:
        if {row["source"],row["target"]}=={"a","c"}:
            row["distance"]=p.rational(5)
    assert p.assess_profile(canonical_bytes(value),expected_digest=digest(value),kind="SPACE")["status"]=="FAIL"


def mapping_case():
    objects=inventory()
    objects["TIME"]=wrapped("TIME","TIME",time(values=(0,1,2,3)))
    rollback=wrapped("rollback-clock","TIME",time(branch="rollback-1",values=(0,1,2)))
    host=wrapped("host-clock","TIME",time(domain="host-run-clock",unit="host-step",values=tuple(range(12))))
    subject=wrapped("map","HYPER",{"schema_version":mapping.SUBJECT_VERSION,"run_id":"run-1","sim_id":"SIM"},
        {"simulation":["SIM"],"sim_times":["TIME","rollback-clock"],"host_time":["host-clock"]})
    rows=[*objects.values(),rollback,host,subject]
    evidence={"schema_version":mapping.EVIDENCE_VERSION,"subject_digest":subject.digest,"collection_digest":contextual_digest(rows),"run_id":"run-1","pieces":[
        {"kind":"advance","sim_time_id":"TIME","host_time_id":"host-clock","pairs":[{"sim":"p0","host":"p0"},{"sim":"p2","host":"p1"}],"rollback_from":None},
        {"kind":"pause","sim_time_id":"TIME","host_time_id":"host-clock","pairs":[{"sim":"p2","host":"p1"},{"sim":"p2","host":"p3"}],"rollback_from":None},
        {"kind":"step","sim_time_id":"TIME","host_time_id":"host-clock","pairs":[{"sim":"p2","host":"p3"},{"sim":"p3","host":"p3"}],"rollback_from":None},
        {"kind":"rollback","sim_time_id":"rollback-clock","host_time_id":"host-clock","pairs":[{"sim":"p0","host":"p4"},{"sim":"p1","host":"p5"}],"rollback_from":{"sim_time_id":"TIME","point":"p3"}}]}
    return rows,subject,evidence


def assess_map(rows,subject,evidence,**kwargs):
    return mapping.assess_mapping(rows,subject_id="map",expected_subject_digest=subject.digest,
        expected_collection_digest=contextual_digest(rows),expected_evidence_digest=digest(evidence),expected_run_id="run-1",evidence_bytes=canonical_bytes(evidence),**kwargs)


def test_partial_piecewise_mapping_supports_pause_accelerated_rate_step_and_explicit_rollback():
    rows,subject,evidence=mapping_case()
    result=assess_map(rows,subject,evidence)
    assert result["status"]=="PASS"
    assert result["pieces"][0]["rates"][0]["ratio"]==p.rational(2)
    assert result["pieces"][1]["rates"][0]["ratio"]==p.rational(0)
    assert result["pieces"][2]["rates"][0]["kind"]=="NONINVERTIBLE_STEP"
    assert result["interpolation"]=="UNSUPPORTED"
    assert result["clock_authenticity_and_synchronization"]=="UNKNOWN"


@pytest.mark.parametrize("mutation",["silent_rollback","wrong_prior_endpoint","same_branch","wrong_host","run","missing_point","empty","unsupported"])
def test_mapping_false_pass_controls(mutation):
    rows,subject,evidence=mapping_case()
    if mutation=="silent_rollback":
        evidence["pieces"][1]["pairs"][0]["sim"]="p0"
    elif mutation=="wrong_prior_endpoint":
        evidence["pieces"][-1]["rollback_from"]["point"]="p2"
    elif mutation=="same_branch":
        evidence["pieces"][-1]["sim_time_id"]="TIME"
    elif mutation=="wrong_host":
        evidence["pieces"][0]["host_time_id"]="TIME"
    elif mutation=="run":
        evidence["run_id"]="other-run"
    elif mutation=="missing_point":
        evidence["pieces"][0]["pairs"][0]["sim"]="missing"
    elif mutation=="empty":
        evidence["pieces"]=[]
    else:
        evidence["pieces"][0]["kind"]="clock-synchronization-proof"
    result=assess_map(rows,subject,evidence)
    assert result["status"]==("UNKNOWN" if mutation in ("missing_point","empty","unsupported") else "FAIL")


def computational_binding():
    return {"schema_version":"verifier-spacetime-computation-binding-1","implementation_digest":"sha256:"+"a"*64,"operation":"selected-operation",
        "input_size_definition":"number of retained input bytes","computational_model":"retained-rational-charge-model/1",
        "assumptions":["charges are caller-selected abstract units"],"run_id":"run-1","domain":"cost-domain","unit":"charge"}


def cost_case():
    selected=computational_binding()
    policy={"schema_version":"verifier-deny-before-charge-policy-1","limit":p.rational(3)}
    evidence={"schema_version":execution.COST_VERSION,"binding":copy.deepcopy(selected),"budget":policy,"complexity":None,"records":[
        {"operation_id":"one","input_size":2,"charge":p.rational(2),"decision":"ALLOW"},
        {"operation_id":"two","input_size":2,"charge":p.rational(2),"decision":"REFUSE"}]}
    return selected,policy,evidence


def test_retained_enforcement_replay_is_separate_from_complexity_and_live_enforcement():
    selected,policy,evidence=cost_case()
    def run(capability="budget_replay",budget=policy):
        return execution.assess_cost(canonical_bytes(evidence),expected_evidence_digest=digest(evidence),expected_binding_bytes=canonical_bytes(selected),capability=capability,expected_budget_bytes=canonical_bytes(budget) if budget else None)
    result=run()
    assert result["status"]=="PASS" and result["retained_total"]==p.rational(2)
    assert result["actual_cost_and_live_enforcement"]=="UNKNOWN"
    assert run("complexity_bound")["status"]=="UNKNOWN"
    assert run("live_enforced_budget")["status"]=="UNKNOWN"
    assert run(budget=None)["status"]=="UNKNOWN"
    evidence["records"][1]["decision"]="ALLOW"
    assert run()["status"]=="FAIL"


@pytest.mark.parametrize("field",["implementation_digest","operation","input_size_definition","computational_model","assumptions","run_id","domain","unit"])
def test_computational_model_input_and_implementation_substitution_refuted(field):
    selected,policy,evidence=cost_case()
    evidence["binding"][field]=["substituted"] if field=="assumptions" else "substituted"
    result=execution.assess_cost(canonical_bytes(evidence),expected_evidence_digest=digest(evidence),expected_binding_bytes=canonical_bytes(selected),capability="budget_replay",expected_budget_bytes=canonical_bytes(policy))
    assert result["status"]=="FAIL"


def execution_case():
    clock=wrapped("execution-clock","TIME",time(domain="execution-domain"))
    rows=[clock]
    graph={"schema_version":execution.ORDER_VERSION,"nodes":["first","second"],"edges":[["first","second"]]}
    selected=computational_binding()
    reference=ref(clock)
    policy={"schema_version":"verifier-execution-time-context-policy-1","contexts":[{"operation_id":name,"context":reference.to_dict()} for name in graph["nodes"]]}
    trace={"schema_version":execution.TRACE_VERSION,"binding":selected,"prerequisite_digest":digest(graph),"collection_digest":contextual_digest(rows),
        "records":[{"operation_id":"first","context":reference.to_dict(),"start":"p0","end":"p1"},
        {"operation_id":"second","context":reference.to_dict(),"start":"p2","end":"p3"}]}
    return rows,graph,selected,policy,trace


def assess_trace(rows,graph,selected,policy,trace):
    return execution.assess_execution_order(rows,canonical_bytes(graph),canonical_bytes(trace) if trace else None,
        expected_collection_digest=contextual_digest(rows),expected_prerequisite_digest=digest(graph),expected_trace_digest=digest(trace) if trace else None,
        expected_binding_bytes=canonical_bytes(selected),expected_context_policy_bytes=canonical_bytes(policy))


def test_dag_prerequisites_and_actual_execution_observations_are_distinct():
    rows,graph,selected,policy,trace=execution_case()
    assert assess_trace(rows,graph,selected,policy,trace)["status"]=="PASS"
    assert assess_trace(rows,graph,selected,policy,None)["status"]=="UNKNOWN"
    trace["records"].pop()
    assert assess_trace(rows,graph,selected,policy,trace)["status"]=="UNKNOWN"


@pytest.mark.parametrize("mutation",["order","reverse_interval","context_digest","wrong_domain","wrong_role","cycle","run","point"])
def test_execution_order_negative_controls(mutation):
    rows,graph,selected,policy,trace=execution_case()
    if mutation=="order":
        trace["records"][1].update(start="p0",end="p0")
    elif mutation=="reverse_interval":
        trace["records"][0].update(start="p3",end="p0")
    elif mutation in ("context_digest","wrong_domain","wrong_role"):
        key={"context_digest":"object_digest","wrong_domain":"domain","wrong_role":"role"}[mutation]
        trace["records"][0]["context"][key]="sha256:"+"f"*64 if key=="object_digest" else "substituted"
    elif mutation=="cycle":
        graph["edges"].append(["second","first"])
        trace["prerequisite_digest"]=digest(graph)
    elif mutation=="run":
        trace["binding"]=copy.deepcopy(selected);trace["binding"]["run_id"]="other-run"
    else:
        trace["records"][0]["start"]="missing"
    assert assess_trace(rows,graph,selected,policy,trace)["status"]==("UNKNOWN" if mutation=="point" else "FAIL")


def test_cancellation_does_not_establish_mapping_or_cost_execution():
    rows,subject,evidence=mapping_case()
    assert assess_map(rows,subject,evidence,cancelled=lambda:True)["status"]=="UNKNOWN"
    selected,policy,evidence=cost_case()
    assert execution.assess_cost(canonical_bytes(evidence),expected_evidence_digest=digest(evidence),expected_binding_bytes=canonical_bytes(selected),capability="budget_replay",expected_budget_bytes=canonical_bytes(policy),cancelled=lambda:True)["status"]=="UNKNOWN"


def test_duplicate_context_policy_and_noncanonical_wire_are_not_accepted():
    clock=wrapped("clock","TIME",time())
    selected=ref(clock)
    subject=ContextualObject(NamespaceObject.create("subject","OBJECT",{}),(selected,))
    rows=[clock,subject]
    assert assess_contextual_composition(rows,expected_digest=contextual_digest(rows),required_contexts=(("subject",selected),("subject",selected)))["status"]=="REFUSAL"
    raw=canonical_bytes(subject.to_dict())
    assert decode_contextual_object(raw)==subject
    with pytest.raises(ValueError):
        decode_contextual_object(raw+b" ")
    with pytest.raises(ValueError):
        decode_contextual_object(b'{"schema_version":"one","schema_version":"two"}')
    collection={"schema_version":COLLECTION_VERSION,"objects":[row.to_dict() for row in rows]}
    assert decode_contextual_collection(canonical_bytes(collection))==tuple(rows)
    collection["schema_version"]="verifier-object-composition-1"
    with pytest.raises(ValueError):
        decode_contextual_collection(canonical_bytes(collection))


def test_valid_but_different_execution_clocks_remain_unknown():
    rows,graph,selected,policy,trace=execution_case()
    other=wrapped("other-clock","TIME",time(domain="other-execution-domain"))
    rows.append(other)
    reference=ref(other)
    policy["contexts"][1]["context"]=reference.to_dict()
    trace["records"][1]["context"]=reference.to_dict()
    trace["collection_digest"]=contextual_digest(rows)
    assert assess_trace(rows,graph,selected,policy,trace)["status"]=="UNKNOWN"


def test_real_finite_metric_operation_ceiling_cannot_produce_pass():
    value=space();value.update(profile="finite-metric/1",unit="discrete-unit",nodes=[str(i) for i in range(47)])
    value["relations"]=[{"source":a,"target":b,"distance":p.rational(0 if a==b else 1)} for a in value["nodes"] for b in value["nodes"]]
    result=p.assess_profile(canonical_bytes(value),expected_digest=digest(value),kind="SPACE")
    assert result["status"]=="UNKNOWN" and "operation bound" in result["reason"]


def test_published_new_schema_is_closed_and_old_wire_has_no_new_alias():
    import jsonschema
    schema_path=Path(__file__).with_name("spacetime-context-extension-1.schema.json")
    if not schema_path.exists():
        import verifier
        schema_path=Path(verifier.__file__).parent/"schemas/spacetime-context-extension-1.schema.json"
    schema=json.loads(schema_path.read_bytes())
    validator=jsonschema.Draft202012Validator(schema)
    validator.check_schema(schema)
    rows,subject,evidence=mapping_case()
    _,graph,selected,policy,trace=execution_case()
    _,budget,cost=cost_case()
    for value in (subject.to_dict(),time(),space(),evidence,graph,selected,policy,trace,budget,cost):
        validator.validate(value)
    assert list(validator.iter_errors(subject.record.to_dict()))
    changed=subject.to_dict();changed["contexts_from_payload"]=[]
    assert list(validator.iter_errors(changed))
    invalid=time();invalid["points"][0]["value"]["numerator"]=1.5
    assert list(validator.iter_errors(invalid))


def test_rollback_cannot_reuse_a_previously_advanced_trajectory():
    rows,subject,evidence=mapping_case()
    evidence["pieces"].append({"kind":"rollback","sim_time_id":"TIME","host_time_id":"host-clock",
        "pairs":[{"sim":"p0","host":"p6"}],"rollback_from":{"sim_time_id":"rollback-clock","point":"p1"}})
    assert assess_map(rows,subject,evidence)["status"]=="FAIL"


def test_physical_time_endpoint_overflow_remains_unknown():
    value=time(profile='physical-clock/1',values=(0,1))
    value['points'][0]['value']=p.rational(1,(1<<127)-1)
    value['uncertainty']=p.rational(1,(1<<127)-3)
    result=p.compare_time(value,'p0',value,'p1')
    assert result['status']=='UNKNOWN', result


def test_finite_metric_triangle_sum_overflow_remains_unknown():
    value=space();value['profile']='finite-metric/1';value['unit']='distance-unit'
    distances={frozenset(('a','c')):p.rational(1,(1<<128)-1),
        frozenset(('c','b')):p.rational(1,(1<<128)-3),
        frozenset(('a','b')):p.rational(1,(1<<127)-1)}
    value['relations']=[{'source':left,'target':right,'distance':p.rational(0) if left==right else distances[frozenset((left,right))]} for left in value['nodes'] for right in value['nodes']]
    result=p.assess_profile(canonical_bytes(value),expected_digest=digest(value),kind='SPACE')
    assert result['status']=='UNKNOWN', result


def test_mapping_overlapping_physical_host_intervals_remain_unknown():
    rows,subject,evidence=mapping_case()
    host=wrapped('host-clock','TIME',time(domain='host-run-clock',unit='host-step',profile='physical-clock/1',values=(0,1),uncertainty=1))
    rows=[host if row.record.object_id=='host-clock' else row for row in rows]
    evidence['pieces']=evidence['pieces'][:1]
    evidence['collection_digest']=contextual_digest(rows)
    result=assess_map(rows,subject,evidence)
    assert result['status']=='UNKNOWN', result


def test_refused_tentative_cost_sum_overflow_remains_unknown():
    selected,policy,evidence=cost_case()
    small=p.rational(1,(1<<127)-1)
    policy['limit']=small;evidence['budget']=policy
    evidence['records'][0]['charge']=small
    evidence['records'][1]['charge']=p.rational(1,(1<<127)-3)
    result=execution.assess_cost(canonical_bytes(evidence),expected_evidence_digest=digest(evidence),expected_binding_bytes=canonical_bytes(selected),capability='budget_replay',expected_budget_bytes=canonical_bytes(policy))
    assert result['status']=='UNKNOWN', result


def test_mapping_oversized_delta_cannot_cancel_in_rate_to_pass():
    rows,subject,evidence=mapping_case()
    for name in ('TIME','host-clock'):
        old=next(row for row in rows if row.record.object_id==name)
        value=time(domain='sim-clock' if name=='TIME' else 'host-run-clock',unit='sim-step' if name=='TIME' else 'host-step',values=(0,1))
        value['points'][0]['value']=p.rational(1,(1<<127)-1)
        value['points'][1]['value']=p.rational(1,(1<<127)-3)
        rows=[wrapped(name,'TIME',value) if row is old else row for row in rows]
    evidence['pieces']=evidence['pieces'][:1]
    evidence['pieces'][0]['pairs'][1]['sim']='p1'
    evidence['collection_digest']=contextual_digest(rows)
    result=assess_map(rows,subject,evidence)
    assert result['status']=='UNKNOWN', result


def test_checked_arithmetic_bounds_normalized_results_and_allows_reduction():
    from fractions import Fraction
    limit=(1<<128)-1
    assert p.checked_fraction(Fraction(limit,limit))==1
    assert p.checked_fraction(Fraction(1,limit)+Fraction(-1,limit))==0
    assert p.checked_fraction(Fraction(limit))==limit
    with pytest.raises(p.Exhausted):
        p.checked_fraction(Fraction(limit)+1)


@pytest.mark.parametrize("values,expected",[((0,5),"PASS"),((5,0),"FAIL"),((0,1),"UNKNOWN")])
def test_physical_host_mapping_uses_proven_interval_order(values,expected):
    rows,subject,evidence=mapping_case()
    host=wrapped("host-clock","TIME",time(domain="host-run-clock",unit="host-step",profile="physical-clock/1",values=values,uncertainty=1))
    rows=[host if row.record.object_id=="host-clock" else row for row in rows]
    evidence["pieces"]=evidence["pieces"][:1]
    evidence["collection_digest"]=contextual_digest(rows)
    result=assess_map(rows,subject,evidence)
    assert result["status"]==expected
    assert result["clock_authenticity_and_synchronization"]=="UNKNOWN"


def test_physical_host_piece_boundary_overlap_remains_unknown():
    rows,subject,evidence=mapping_case()
    host=wrapped("host-clock","TIME",time(domain="host-run-clock",unit="host-step",profile="physical-clock/1",values=(0,5,6,11),uncertainty=1))
    rows=[host if row.record.object_id=="host-clock" else row for row in rows]
    evidence["pieces"]=evidence["pieces"][:2]
    evidence["pieces"][1]["pairs"][0]["host"]="p2"
    evidence["collection_digest"]=contextual_digest(rows)
    assert assess_map(rows,subject,evidence)["status"]=="UNKNOWN"
