"""Independent native evaluation preservation and malformed-container controls.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). These fresh
declared identity records do not establish real identity, custody or authority.
Native certificate reproduction and disclosure preservation are distinct.
"""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import identity_scope, current_object_routes as routes
from verifier.privacy import assert_verdict_independence, MalformedRedactionError
import verifier.privacy.independence as helper

BAD = ("outcome_fail", "outcome_unknown", "outcome_missing", "evaluation_null", "evaluation_list", "evaluation_string",
       "result_null", "result_list", "result_string")

def specimen():
    make = NamespaceObject.create
    declaration = {"schema_version": "verifier-namespace-identity-evidence-1", "identity_id": "identity", "actor_id": "actor",
        "role_id": "role", "collective_id": "collective", "representation_id": "human", "actor_kind": "HUMAN",
        "root_human_id": "human", "scope": "probe:validation", "evidence_ref": digest("declaration-only")}
    objects = [make("human", "HUMAN", {}), make("role", "ROLE", {"admitted_scopes": ["probe:validation"]}),
        make("collective", "COLLECTIVE", {}, {"roles": ["role"]}),
        make("actor", "ACTOR", {}, {"representation": ["human"], "root_human": ["human"]}),
        make("identity", "IDENTITY", {"scope": "probe:validation", "binding_evidence_digest": digest(declaration)},
             {"actor": ["actor"], "role": ["role"]})]
    evidence = canonical_bytes({"schema_version": identity_scope.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects], "declaration": declaration})
    policy = identity_scope.identity_scope_policy(trust_roots=["selected-probe-declarations"])
    request = identity_scope.identity_scope_request(subject_id="identity", object_digest=objects[-1].digest,
        collective_id="collective", declaration_digest=digest(declaration), collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    certificate = identity_scope.build_identity_scope_certificate(request, evidence, policy=policy)
    report = routes.replay_current_object_certificate(certificate, semantic_version="verifier-current-object-obligations-1",
        objective="IDENTITY-3.1", represented_kind="IDENTITY", expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    original = json.loads(certificate)
    assert original["result"]["status"] == original["result"]["evaluation"]["outcome"] == "PASS"
    return original, request, policy

@pytest.mark.parametrize("mutation", BAD)
def test_disclosure_preserves_native_outcome_and_typed_container_refusals(mutation: str) -> None:
    original, request, policy = specimen()
    changed = deepcopy(original)
    if mutation == "outcome_fail":
        changed["result"]["evaluation"]["outcome"] = "FAIL"
    elif mutation == "outcome_unknown":
        changed["result"]["evaluation"]["outcome"] = "UNKNOWN"
    elif mutation == "outcome_missing":
        del changed["result"]["evaluation"]["outcome"]
    elif mutation.startswith("evaluation_"):
        changed["result"]["evaluation"] = {"evaluation_null": None, "evaluation_list": [], "evaluation_string": "PASS"}[mutation]
    else:
        changed["result"] = {"result_null": None, "result_list": [], "result_string": "PASS"}[mutation]
    changed.pop("digest")
    changed["digest"] = digest(changed)
    if mutation.startswith("outcome_"):
        with pytest.raises(routes.CurrentObjectRouteRefusal) as refused:
            routes.replay_current_object_certificate(canonical_bytes(changed), semantic_version="verifier-current-object-obligations-1",
                objective="IDENTITY-3.1", represented_kind="IDENTITY", expected_request=request, policy=policy)
        assert isinstance(refused.value.__cause__, identity_scope.IdentityScopeError)
        expected_reason = ("evaluation fields differ" if mutation == "outcome_missing"
                           else "retained evaluation differs from exact independent proposition")
        assert str(refused.value.__cause__) == expected_reason
    try:
        assert_verdict_independence(original, changed)
    except Exception as error:
        observed = error
    else:
        observed = None
    # Assert the intended typed refusal, so pre-existing AttributeError produces
    # a refutable assertion failure instead of being counted as generic ERROR.
    assert isinstance(observed, MalformedRedactionError), (mutation, type(observed).__name__, str(observed))

def test_unchanged_fresh_native_certificate_control() -> None:
    original, _, _ = specimen()
    assert_verdict_independence(original, deepcopy(original))

def test_existing_status_refusal_control() -> None:
    original, _, _ = specimen()
    changed = deepcopy(original)
    changed["result"]["status"] = "FAIL"
    with pytest.raises(MalformedRedactionError, match="Result status moved"):
        assert_verdict_independence(original, changed)


"""Independent typed refusals for supported legacy verdict containers.

These plain dictionary specimens exercise local projection preservation,
not native certificates, authenticated results or whole privacy conformance.
"""
from copy import deepcopy
import pytest
from verifier.privacy import assert_verdict_independence, MalformedRedactionError

FAMILIES = ["checks-map","check-record","check-evaluation",*["tier-"+str(t) for t in range(1,6)],"results-map"]
FORMS = ["checks",*["tier-"+str(t) for t in range(1,6)],"results"]
STATES = ["PASS","FAIL","UNKNOWN"]
VALUES = {"null":None,"list":[],"string":"PASS"}

def fixture(form,status):
    if form == "checks" or form.startswith("check"):
        return {"object_name":"MODEL","result":{"checks":{"probe":{"evaluation":{"outcome":status}}}}}
    if form.startswith("tier-"):
        return {"object_name":"MODEL","tier_"+form.split("-")[1]:{"verdict":status}}
    return {"object_name":"MODEL","results":{"MODEL-3.1":status}}

@pytest.mark.parametrize("family,status,container",[
    pytest.param(f,s,c,id=f+"-"+s+"-"+c) for f in FAMILIES for s in STATES for c in VALUES])
def test_malformed_redacted_legacy_container_is_typed_refusal(family,status,container):
    original = fixture(family,status); changed = deepcopy(original); bad = deepcopy(VALUES[container])
    if family == "checks-map": changed["result"]["checks"] = bad
    elif family == "check-record": changed["result"]["checks"]["probe"] = bad
    elif family == "check-evaluation": changed["result"]["checks"]["probe"]["evaluation"] = bad
    elif family.startswith("tier-"): changed["tier_"+family.split("-")[1]] = bad
    else: changed["results"] = bad
    try:
        assert_verdict_independence(original,changed)
    except Exception as error:
        observed = error
    else:
        observed = None
    assert isinstance(observed,MalformedRedactionError),(family,status,container,type(observed).__name__,str(observed))

@pytest.mark.parametrize("form,status,control",[
    pytest.param(f,s,c,id=f+"-"+s+"-"+c) for f in FORMS for s in STATES for c in ("unchanged","verdict-movement")])
def test_retained_legacy_unchanged_and_existing_movement_controls(form,status,control):
    original = fixture(form,status); changed = deepcopy(original)
    if control == "unchanged":
        assert_verdict_independence(original,changed)
        return
    next_status = {"PASS":"FAIL","FAIL":"UNKNOWN","UNKNOWN":"PASS"}[status]
    if form == "checks": changed["result"]["checks"]["probe"]["evaluation"]["outcome"] = next_status
    elif form.startswith("tier-"): changed["tier_"+form.split("-")[1]]["verdict"] = next_status
    else: changed["results"]["MODEL-3.1"] = next_status
    with pytest.raises(MalformedRedactionError):
        assert_verdict_independence(original,changed)
