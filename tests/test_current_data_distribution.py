"""Current DATA statistics over exact retained values.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts and proportions are dimensionless;
Shannon entropy and its absolute numerical tolerance use bits per observation.
"""
from copy import deepcopy
from itertools import product
import hashlib
import json
import math
from pathlib import Path

import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import Budget, Refuted, Unavailable, merkle_root
from verifier.domains import data as native_data
from verifier.domains.contracts import current_object_routes as routes, data_distribution

def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()

def summary(values):
    keys = sorted(set(canonical_bytes(v) for v in values))
    classes = [{"value": json.loads(k), "count": sum(canonical_bytes(v)==k for v in values)} for k in keys]
    n = len(values)
    # Independent algebraic oracle: H = log2(N) - sum(c*log2(c))/N.
    entropy = math.log2(n) - sum(c["count"] * math.log2(c["count"]) for c in classes)/n if n else 0
    return {"cardinality":len(classes), "classes":classes, "entropy_bits":entropy}

def artifact(shards, declaration):
    return {"shards":{name:{"digest":digest(rows), "records":len(rows),
        "bytes":len(canonical_bytes(rows)), "record_digests":[digest(r) for r in rows],
        "merkle_root":merkle_root(rows,Budget(100000))} for name,rows in shards.items()},
        "distribution":declaration}

def selected(*, values=None, declaration=None, include_inputs=True, tolerance=1e-12, **limits):
    values = [1, digest(1), True, None, "null", [1], {"x":1}] if values is None else values
    shards={"s":[{"class":v} for v in values]}
    payload=artifact(shards, {"class":summary(values)} if declaration is None else declaration)
    subject=NamespaceObject.create("data-root","DATA",payload)
    evidence=canonical_bytes({"schema_version":data_distribution.EVIDENCE_VERSION,
        "objects":[subject.to_dict()], "inputs":{"shards":shards} if include_inputs else None})
    policy=data_distribution.data_distribution_policy(trust_roots=["selected-retained-data"], entropy_tolerance_bits=tolerance)
    request=data_distribution.data_distribution_request(subject_id=subject.object_id,
        object_digest=subject.digest,collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)),policy=policy,limits=limits)
    return request,policy,evidence

def replay(request,policy,evidence):
    certificate=data_distribution.build_data_distribution_certificate(request,evidence,policy=policy)
    result=routes.replay_current_object_certificate(certificate,
        semantic_version=data_distribution.SEMANTIC_VERSION, objective=data_distribution.COORDINATE,
        represented_kind="DATA",expected_request=request,policy=policy)
    return certificate,result

def test_exact_values_do_not_alias_and_do_not_promote_population_truth():
    request,policy,evidence=selected()
    certificate,result=replay(request,policy,evidence)
    assert result["computational_status"]=="PASS"
    assert certificate==replay(request,policy,evidence)[0]
    for field in ("population_representativeness","external_origin","object_profile_conformance"):
        assert result["native_result"][field]=="NOT_ESTABLISHED"

@pytest.mark.parametrize("counts",[c for c in product(range(4),repeat=3) if sum(c)])
def test_native_counts_against_independent_entropy_identity(counts):
    labels=[1,digest(1),True]
    values=[v for v,c in zip(labels,counts) for _ in range(c)]
    shards={"s":[{"class":v} for v in values]}
    claim={"class":summary(values)}
    result=native_data.distribution(artifact(shards,claim),{"shards":shards},Budget(100000),entropy_tolerance_bits=1e-12)
    assert result["records"]==sum(counts)
    assert sorted(c["count"] for c in result["fields"]["class"]["classes"])==sorted(c for c in counts if c)
    bad=deepcopy(claim);bad["class"]["classes"][0]["count"]+=1
    with pytest.raises(Refuted):
        native_data.distribution(artifact(shards,bad),{"shards":shards},Budget(100000),entropy_tolerance_bits=1e-12)

@pytest.mark.parametrize("field,value",[("cardinality",1),("entropy_bits",0),
    ("classes",[{"value":"a","count":2}]),("classes",[{"value":"a","count":True},{"value":"b","count":1}])])
def test_fully_rehashed_false_declarations_fail(field,value):
    claim=summary(["a","b"]);claim[field]=value
    assert replay(*selected(values=["a","b"],declaration={"class":claim}))[1]["computational_status"]=="FAIL"

def test_missing_evidence_and_exhausted_limits_are_unknown():
    req,pol,evidence=selected()
    assert replay(req,pol,None)[1]["computational_status"]=="UNKNOWN"
    assert replay(*selected(include_inputs=False))[1]["computational_status"]=="UNKNOWN"
    assert replay(*selected(values=[]))[1]["computational_status"]=="UNKNOWN"
    assert replay(*selected(declaration={}))[1]["computational_status"]=="UNKNOWN"
    for bound in ("max_operations","max_composition_operations","max_items","max_evidence_bytes","max_payload_bytes","max_reference_bytes"):
        assert replay(*selected(**{bound:1}))[1]["computational_status"]=="UNKNOWN"

@pytest.mark.parametrize("tolerance",[-1,1e-8,True,"0",float("nan"),float("inf")])
def test_unsupported_entropy_policy_refuses(tolerance):
    with pytest.raises(data_distribution.DataDistributionError):selected(tolerance=tolerance)

def test_independent_entropy_tolerance_is_bound_and_effective():
    declared={"class":summary(["a","b"])};declared["class"]["entropy_bits"]+=5e-10
    assert replay(*selected(values=["a","b"],declaration=declared,tolerance=1e-9))[1]["computational_status"]=="PASS"
    assert replay(*selected(values=["a","b"],declaration=declared,tolerance=1e-12))[1]["computational_status"]=="FAIL"
    req,pol,evidence=selected(tolerance=1e-9);cert,_=replay(req,pol,evidence)
    changed={**pol,"entropy_tolerance_bits":1e-12}
    with pytest.raises(ValueError):data_distribution.recheck_data_distribution_certificate(cert,expected_request=req,policy=changed)

def test_partition_permutation_and_replication_preserve_normalized_statistics():
    values=["a","b","a","c"]
    variants=[{"s":[{"class":v} for v in values]},
        {"z":[{"class":v} for v in reversed(values[:2])],"a":[{"class":v} for v in values[2:]]},
        {"s":[{"class":v} for v in values*2]}]
    results=[]
    for shards in variants:
        flattened=[r["class"] for rows in shards.values() for r in rows]
        result=native_data.distribution(artifact(shards,{"class":summary(flattened)}),{"shards":shards},Budget(100000),entropy_tolerance_bits=1e-12)
        results.append(result)
    assert results[0]==results[1]
    assert results[2]["records"]==2*results[0]["records"]
    assert results[0]["fields"]["class"]["entropy_bits"]==results[2]["fields"]["class"]["entropy_bits"]

def test_retained_bytes_missing_fields_duplicate_classes_and_stale_commitments_refute():
    shards={"s":[{"class":"a"},{"class":"b"}]};claim={"class":summary(["a","b"])}
    original=artifact(shards,claim)
    changed=deepcopy(shards);changed["s"][0]["class"]="b"
    with pytest.raises(Refuted):native_data.distribution(original,{"shards":changed},Budget(100000),entropy_tolerance_bits=1e-12)
    for rows,declared in [([{"class":"a"},{}],claim),
        (shards["s"],{"class":{"cardinality":2,"classes":[{"value":"a","count":1}]*2,"entropy_bits":1}})]:
        inputs={"shards":{"s":rows}}
        with pytest.raises(Refuted):native_data.distribution(artifact(inputs["shards"],declared),inputs,Budget(100000),entropy_tolerance_bits=1e-12)

def test_class_declaration_order_and_pipeline_choice_do_not_change_statistics():
    shards={"s":[{"class":1},{"class":digest(1)}]}
    first=artifact(shards,{"class":summary([1,digest(1)])})
    changed=deepcopy(first)
    changed["distribution"]["class"]["classes"].reverse()
    changed["pipeline"]={"self_reported_accuracy":1.0}
    inputs={"shards":shards}
    assert native_data.distribution(first,inputs,Budget(100000),entropy_tolerance_bits=1e-12)==native_data.distribution(changed,inputs,Budget(100000),entropy_tolerance_bits=1e-12)

def test_actual_distribution_certificate_cannot_discard_replay_evidence():
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureBound, DisclosureSurface, EmissionContext, ObserverParty
    certificate,_=replay(*selected())
    value=json.loads(certificate)
    fields=tuple(k for k in value if k!="evidence_payloads")
    surface=DisclosureSurface("DATA",fields,("evidence_payloads",))
    bounds=tuple(DisclosureBound(k,k,admitted_observers=("reader",)) for k in fields)
    context=EmissionContext(ObserverParty("reader","reviewer","local"),"2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError,match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value,surface,bounds,context)

def test_external_selection_and_rehashed_certificate_substitution_refuse():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed = deepcopy(request)
    changed["subject_id"] = "other-data"
    with pytest.raises(ValueError):
        data_distribution.recheck_data_distribution_certificate(
            certificate, expected_request=changed, policy=policy)
    changed_policy = deepcopy(policy)
    changed_policy["trust_roots"] = ["other-root"]
    with pytest.raises(ValueError):
        data_distribution.recheck_data_distribution_certificate(
            certificate, expected_request=request, policy=changed_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        data_distribution.recheck_data_distribution_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def test_direct_builder_rejects_foreign_comparison_before_callback():
    class HostileText(str):
        def __eq__(self, other):
            raise AssertionError("foreign equality callback invoked")

        def __ne__(self, other):
            raise AssertionError("foreign inequality callback invoked")

        __hash__ = str.__hash__

    request, policy, evidence = selected()
    policy["schema_version"] = HostileText(data_distribution.POLICY_VERSION)
    with pytest.raises(data_distribution.DataDistributionError):
        data_distribution.build_data_distribution_certificate(request, evidence, policy=policy)
    request, policy, evidence = selected()
    request["coordinate"] = HostileText(data_distribution.COORDINATE)
    with pytest.raises(data_distribution.DataDistributionError):
        data_distribution.build_data_distribution_certificate(request, evidence, policy=policy)
    request, policy, evidence = selected()
    policy[HostileText("extra")] = 1
    with pytest.raises(data_distribution.DataDistributionError):
        data_distribution.build_data_distribution_certificate(request, evidence, policy=policy)


def test_policy_factory_owns_mutable_trust_root_list():
    roots = ["selected-retained-data"]
    policy = data_distribution.data_distribution_policy(trust_roots=roots, entropy_tolerance_bits=1e-12)
    roots[0] = "changed"
    assert policy["trust_roots"] == ["selected-retained-data"]


@pytest.mark.parametrize("relative", [
    "domains/contracts/data_distribution.py", "domains/contracts/retained_selection.py", "domains/common.py", "domains/data.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py",
    "core/receipt.py", "standard/CURRENT_DATA_DISTRIBUTION.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = data_distribution.build_data_distribution_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(data_distribution.__file__).parents[2] / relative
    def changed(path):
        data = original(path)
        return data + b"\nchanged time dependency\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        data_distribution.recheck_data_distribution_certificate(
            certificate, expected_request=request, policy=policy)


def test_public_command_and_polish_keep_boundary(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish
    request, policy, evidence = selected()
    certificate = data_distribution.build_data_distribution_certificate(request, evidence, policy=policy)
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", data_distribution.SEMANTIC_VERSION,
        "--objective", data_distribution.COORDINATE, "--represented-kind", "DATA",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "data-root", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "data-root", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected retained distribution only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][2]["objectives"] = [{
        "semantic_version": data_distribution.SEMANTIC_VERSION,
        "coordinate": data_distribution.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": certificate_digest}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
