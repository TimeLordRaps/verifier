"""Independent public reachability and evidence-binding gates for mainstays.

JavaScript Object Notation (JSON)."""
from importlib.util import find_spec
import json
import subprocess
import sys

import pytest

from verifier.domains.common import digest
from test_mainstay_carriers import har_fixture, model_fixture


def api():
    from verifier.domains import mainstay_certification
    return mainstay_certification


def bundle(domain="HARNESS"):
    artifact, inputs = (har_fixture if domain == "HARNESS" else model_fixture)()
    return {"schema_version": "verifier-mainstay-evidence-1", "object_name": domain,
            "subject_id": "retained-subject", "artifact": artifact, "inputs": inputs}


def selected(evidence, checks=("binding", "roundtrip"), **bounds):
    interface = api()
    return interface.mainstay_request(evidence, checks=checks), interface.mainstay_policy(
        trust_roots=["retained fixture provenance accepted by this checker"], **bounds)


def rehash(certificate):
    certificate["certificate_digest"] = digest({k: v for k, v in certificate.items() if k != "certificate_digest"})


def test_mainstay_assessment_module_is_publicly_importable():
    assert find_spec("verifier.domains.mainstay_certification") is not None


def test_public_mainstay_catalog_route_is_reachable():
    result = subprocess.run([sys.executable, "-B", "-m", "verifier", "certification",
                             "mainstay-catalog", "--json"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert observed["runtime_support"]["HARNESS"]["har"]["versions"] == ["1.2"]
    assert observed["runtime_support"]["MODEL"]["safetensors"]["versions"] == ["0.5.3"]


@pytest.mark.parametrize("domain", ["HARNESS", "MODEL"])
def test_public_api_build_and_recheck_preserve_bounded_claims(domain):
    evidence = bundle(domain)
    request, policy = selected(evidence)
    certificate = api().build_mainstay_certificate(request, evidence, policy=policy)
    result = api().recheck_mainstay_certificate(certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert set(result["checks"]) == {"binding", "roundtrip"}
    for field in ("object_profile_conformance", "domain_tier_5_conformance", "native_format_conformance", "authentication"):
        assert result[field] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("mutation", ["result", "evidence", "request", "policy", "mechanism", "extra", "schema"])
def test_rehashed_certificate_substitutions_are_rejected(mutation):
    evidence = bundle()
    request, policy = selected(evidence)
    certificate = api().build_mainstay_certificate(request, evidence, policy=policy)
    if mutation == "result": certificate["result"]["checks"]["roundtrip"]["observations"]["records"] = 100
    elif mutation == "evidence": certificate["evidence"]["inputs"]["transcript"][0]["response"]["status"] = 500
    elif mutation == "request": certificate["request"]["checks"] = ["binding"]
    elif mutation == "policy": certificate["policy_digest"] = "sha256:" + "0" * 64
    elif mutation == "mechanism": certificate["mechanism_digest"] = "sha256:" + "0" * 64
    elif mutation == "extra": certificate["trusted"] = True
    else: certificate["schema_version"] = "verifier-domain-certification-1"
    rehash(certificate)
    assert api().recheck_mainstay_certificate(certificate, expected_request=request, policy=policy)["status"] == "REJECTED"


def test_a_rehashed_pass_does_not_replace_actual_refutation():
    evidence = bundle()
    evidence["inputs"]["transcript"][0]["response"]["status"] = 500
    request, policy = selected(evidence)
    certificate = api().build_mainstay_certificate(request, evidence, policy=policy)
    assert certificate["result"]["status"] == "FAIL"
    certificate["result"]["status"] = "PASS"
    certificate["result"]["checks"]["roundtrip"]["status"] = "PASS"
    rehash(certificate)
    assert api().recheck_mainstay_certificate(certificate, expected_request=request, policy=policy)["status"] == "REJECTED"


@pytest.mark.parametrize("bound,value", [("max_operations", 1), ("max_items", 1), ("max_evidence_bytes", 1)])
def test_current_resource_policy_can_only_reduce_support(bound, value):
    evidence = bundle()
    request, policy = selected(evidence)
    certificate = api().build_mainstay_certificate(request, evidence, policy=policy)
    strict = dict(policy, **{bound: value})
    assert api().build_mainstay_certificate(request, evidence, policy=strict)["result"]["status"] == "UNKNOWN"
    assert api().recheck_mainstay_certificate(certificate, expected_request=request, policy=strict)["status"] == "REJECTED"


def test_current_tolerance_policy_is_not_borrowed_from_certificate():
    evidence = bundle("MODEL")
    evidence["artifact"]["model"]["tolerance"] = 1e-9
    request, policy = selected(evidence)
    certificate = api().build_mainstay_certificate(request, evidence, policy=policy)
    assert certificate["result"]["status"] == "PASS"
    strict = dict(policy, max_tolerance=0.0)
    result = api().build_mainstay_certificate(request, evidence, policy=strict)["result"]
    assert result["status"] == "UNKNOWN"
    assert "checker policy" in result["checks"]["roundtrip"]["details"]
    assert api().recheck_mainstay_certificate(certificate, expected_request=request, policy=strict)["status"] == "REJECTED"


def test_selected_checks_share_one_operation_budget():
    evidence = bundle()
    request, policy = selected(evidence, checks=("binding",))
    first = api().build_mainstay_certificate(request, evidence, policy=policy)
    budget = first["result"]["operations"]
    request, policy = selected(evidence, checks=("binding", "roundtrip"), max_operations=budget + 1)
    result = api().build_mainstay_certificate(request, evidence, policy=policy)["result"]
    assert result["checks"]["binding"]["status"] == "PASS"
    assert result["checks"]["roundtrip"]["status"] == "UNKNOWN"
    assert result["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["checks-empty", "checks-duplicate", "checks-unknown", "request-extra",
                                      "request-type", "evidence-extra", "artifact-extra", "policy-extra",
                                      "policy-empty-roots", "policy-mechanism", "policy-bool", "policy-negative"])
def test_ambiguous_or_unadmitted_envelopes_are_rejected(mutation):
    evidence = bundle()
    request, policy = selected(evidence)
    if mutation == "checks-empty": request["checks"] = []
    elif mutation == "checks-duplicate": request["checks"] = ["binding", "binding"]
    elif mutation == "checks-unknown": request["checks"] = ["authoritative"]
    elif mutation == "request-extra": request["trusted"] = True
    elif mutation == "request-type": request["checks"] = "binding"
    elif mutation == "evidence-extra": evidence["trusted"] = True
    elif mutation == "artifact-extra": evidence["artifact"]["trusted"] = True
    elif mutation == "policy-extra": policy["trusted"] = True
    elif mutation == "policy-empty-roots": policy["trust_roots"] = []
    elif mutation == "policy-mechanism": policy["mechanism_digest"] = "sha256:" + "0" * 64
    elif mutation == "policy-bool": policy["max_items"] = True
    else: policy["max_tolerance"] = -1
    with pytest.raises(ValueError):
        api().build_mainstay_certificate(request, evidence, policy=policy)


def test_registered_unimplemented_formats_and_checks_remain_unknown():
    evidence = {"schema_version": "verifier-mainstay-evidence-1", "object_name": "SIM", "subject_id": "sim",
                "artifact": {"mainstay": {"format_id": "gymnasium", "version": "1.0.0", "carrier_digest": "sha256:" + "0" * 64}},
                "inputs": {}}
    request, policy = selected(evidence, checks=("binding",))
    assert api().build_mainstay_certificate(request, evidence, policy=policy)["result"]["status"] == "UNKNOWN"
    evidence = bundle()
    request, policy = selected(evidence, checks=("binding", "protocol"))
    result = api().build_mainstay_certificate(request, evidence, policy=policy)["result"]
    assert result["checks"]["binding"]["status"] == "PASS"
    assert result["checks"]["protocol"]["status"] == "UNKNOWN"


def test_structural_size_depth_and_non_json_inputs_are_bounded():
    evidence = bundle()
    deep = {}
    root = deep
    for _ in range(70):
        root["next"] = {}
        root = root["next"]
    for invalid in (dict(evidence, inputs=deep), dict(evidence, subject_id=b"not JSON"),
                    dict(evidence, subject_id="x" * (api().MAX_DOCUMENT_BYTES + 1))):
        with pytest.raises(ValueError):
            api().mainstay_request(invalid, checks=("binding",))


def test_catalogue_runtime_support_matches_actual_carrier_versions():
    from verifier.domains.carriers import SUPPORTED
    support = api().mainstay_runtime_catalog()["runtime_support"]
    assert support["HARNESS"]["har"]["versions"] == list(SUPPORTED["har"])
    assert support["MODEL"]["safetensors"]["versions"] == list(SUPPORTED["safetensors"])
    assert "ENV" not in support and "HYPER" not in support


@pytest.mark.parametrize("checks", [None, True, {}, [["binding"]], ["binding", {}], [1]])
def test_malformed_check_selectors_are_not_coerced(checks):
    evidence = bundle()
    request, policy = selected(evidence)
    request["checks"] = checks
    with pytest.raises(ValueError):
        api().build_mainstay_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("name,value", [("max_operations", 0), ("max_operations", 10000001),
    ("max_operations", True), ("max_operations", 1.5), ("max_items", 0), ("max_items", 100001),
    ("max_evidence_bytes", 0), ("max_evidence_bytes", 16777217), ("max_evidence_bytes", {}),
    ("max_tolerance", float("nan")), ("max_tolerance", float("inf"))])
def test_malformed_or_excessive_checker_budgets_are_refused(name, value):
    evidence = bundle()
    request, policy = selected(evidence)
    policy[name] = value
    with pytest.raises(ValueError):
        api().build_mainstay_certificate(request, evidence, policy=policy)


def test_public_accountable_catalog_is_explicitly_opted_in():
    command = [sys.executable, "-B", "-m", "verifier", "certification", "domain-catalog", "--json"]
    default = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert default.returncode == 0, default.stdout + default.stderr
    ordinary = json.loads(default.stdout)["domains"]
    assert "ACTOR" not in ordinary and "OWNER" not in ordinary
    opted = subprocess.run(command + ["--accountable"], capture_output=True, text=True, timeout=30)
    assert opted.returncode == 0, opted.stdout + opted.stderr
    augmented = json.loads(opted.stdout)["domains"]
    assert set(augmented) == set(ordinary) | {
        "ACTOR", "OWNER", "HUMAN", "IDENTITY", "ROLE", "COLLECTIVE",
    }
    assert len(augmented["ACTOR"]["checks"]) + len(augmented["OWNER"]["checks"]) == 8


def test_public_cli_assess_check_forgery_and_exclusive_output(tmp_path):
    evidence = bundle()
    request, policy = selected(evidence)
    paths = {name: tmp_path / (name + ".json") for name in ("evidence", "request", "policy", "certificate")}
    for name, value in (("evidence", evidence), ("request", request), ("policy", policy)):
        paths[name].write_text(json.dumps(value), encoding="utf-8")
    base = [sys.executable, "-B", "-m", "verifier", "certification"]
    arguments = ["--request", str(paths["request"]), "--policy", str(paths["policy"]), "--json"]
    assess = subprocess.run(base + ["mainstay-assess", str(paths["evidence"]), *arguments,
                                   "--output", str(paths["certificate"])], capture_output=True, text=True, timeout=30)
    assert assess.returncode == 0, assess.stdout + assess.stderr
    certificate = json.loads(paths["certificate"].read_text(encoding="utf-8"))
    before = paths["certificate"].read_bytes()
    again = subprocess.run(base + ["mainstay-assess", str(paths["evidence"]), *arguments,
                                  "--output", str(paths["certificate"])], capture_output=True, text=True, timeout=30)
    assert again.returncode == 1
    assert paths["certificate"].read_bytes() == before
    check = subprocess.run(base + ["mainstay-check", str(paths["certificate"]), *arguments],
                           capture_output=True, text=True, timeout=30)
    assert check.returncode == 0, check.stdout + check.stderr
    certificate["result"]["authentication"] = "ESTABLISHED"
    rehash(certificate)
    paths["certificate"].write_text(json.dumps(certificate), encoding="utf-8")
    forged = subprocess.run(base + ["mainstay-check", str(paths["certificate"]), *arguments],
                            capture_output=True, text=True, timeout=30)
    assert forged.returncode == 1
    assert json.loads(forged.stdout)["status"] == "REJECTED"
