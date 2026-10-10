"""Current bounded native Simulation (SIM) checker dynamics certificate tests.

JavaScript Object Notation (JSON); command-line interface (CLI). Synthetic state,
action and time values count steps. Expected outcomes are analytic test oracles.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts.current_object_routes import current_object_route_catalog, replay_current_object_certificate
from verifier.runtime.public_cli import main


VERSION = "verifier-current-object-obligations-1"


def test_native_checker_dynamics_objective_is_publicly_registered() -> None:
    rows = [row for row in current_object_route_catalog() if row["objective"] == "VERIFIER-2.1"]
    assert len(rows) == 1
    assert rows[0]["semantic_version"] == VERSION
    assert rows[0]["represented_kind_rule"] == "VERIFIER"
    assert rows[0]["object_profile_conformance"] == "NOT_ESTABLISHED"


@pytest.fixture
def contract() -> Any:
    return importlib.import_module("verifier.domains.contracts.sim_checker")


def case() -> dict[str, Any]:
    inputs = {"states": [{"x": 0.0}, {"x": 1.0}], "entropy": [1.0], "times": [0.0, 1.0],
              "observations": [{"position": 0.0}, {"position": 1.0}], "actions": [{"action": 1.0}]}
    artifact = {"transition": {"x": {"op": "add", "args": [{"var": "x"}, {"var": "entropy"}]}},
                "initial_state": {"x": 0.0}, "trajectory_digest": digest(inputs["states"]),
                "entropy_digest": digest(inputs["entropy"]), "times_digest": digest(inputs["times"]),
                "invariants": [{"op": "le", "args": [{"var": "x"}, 1.0]}],
                "observation": {"position": {"var": "x"}},
                "action_bounds": {"action": {"minimum": 0.0, "maximum": 1.0}}}
    return {"artifact": artifact, "inputs": inputs}


def inputs(contract: Any) -> tuple[dict, dict, bytes]:
    valid = case()
    invalid = deepcopy(valid)
    invalid["inputs"]["states"][1]["x"] = 2.0
    invalid["artifact"]["trajectory_digest"] = digest(invalid["inputs"]["states"])
    policy = contract.sim_checker_policy(trust_roots=["selected-installed-native-checker"])
    item = NamespaceObject.create("checker:counter", "VERIFIER", {
        "checker_kind": "CHECKER", "checker": contract.CHECKER, "mechanism_digest": policy["mechanism_digest"]})
    suite = {"schema_version": contract.EVIDENCE_VERSION, "checker_object": item.to_dict(),
             "cases": {"valid": valid, "invalid": invalid}}
    encoded = canonical_bytes(suite)
    expected = [
        {"case_id": "valid", "check": "invariants", "input_digest": digest(valid),
         "expected": {"status": "PASS", "result": {"states": 2, "transitions": 1}}, "max_operations": 10000},
        {"case_id": "valid", "check": "channels", "input_digest": digest(valid),
         "expected": {"status": "PASS", "result": {"states": 2, "transitions": 1}}, "max_operations": 10000},
        {"case_id": "invalid", "check": "invariants", "input_digest": digest(invalid),
         "expected": {"status": "FAIL", "reason": "transition replay differs"}, "max_operations": 10000},
    ]
    request = contract.sim_checker_request(object_id=item.object_id, object_digest=item.digest, evidence_digest=digest(suite),
                                           expectations=expected, policy=policy)
    return request, policy, encoded


def replay(contract: Any, request: dict, policy: dict, encoded: bytes | None) -> tuple[bytes, dict]:
    certificate = contract.build_sim_checker_certificate(request, encoded, policy=policy)
    result = contract.recheck_sim_checker_certificate(certificate, expected_request=request, policy=policy)
    return certificate, result


def test_positive_and_refutation_oracles_replay_without_scope_promotion(contract: Any) -> None:
    request, policy, encoded = inputs(contract)
    certificate, result = replay(contract, request, policy, encoded)
    assert result["status"] == "PASS"
    assert [row["outcome"]["status"] for row in result["observations"]] == ["PASS", "PASS", "FAIL"]
    for key in ("class_wide_soundness", "historical_execution", "public_checkability", "object_profile_conformance", "authority"):
        assert result[key] == "NOT_ESTABLISHED"
    observed = replay_current_object_certificate(certificate, semantic_version=VERSION,
        objective="VERIFIER-2.1", represented_kind="VERIFIER", expected_request=request, policy=policy)
    assert observed["computational_status"] == "PASS"
    assert certificate == replay(contract, request, policy, encoded)[0]


def test_missing_evidence_stays_unknown(contract: Any) -> None:
    request, policy, _ = inputs(contract)
    _, result = replay(contract, request, policy, None)
    assert result["status"] == "UNKNOWN" and result["observations"] == []


def test_exact_checker_object_record_is_bound(contract: Any) -> None:
    request, policy, encoded = inputs(contract)
    suite = json.loads(encoded)
    assert "object_digest" in request and "checker_object" in suite
    assert request["object_digest"] == digest(suite["checker_object"])


def test_canonical_checker_certificate_cannot_be_selectively_redacted(contract: Any) -> None:
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty

    request, policy, encoded = inputs(contract)
    certificate = json.loads(replay(contract, request, policy, encoded)[0])
    surface = DisclosureSurface("VERIFIER", tuple(key for key in certificate if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("local-reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("local-reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(certificate, surface, bounds, context)


@pytest.mark.parametrize("field", ["max_total_operations", "max_evidence_bytes"])
def test_selected_resource_exhaustion_stays_unknown(contract: Any, field: str) -> None:
    request, policy, encoded = inputs(contract)
    request["limits"][field] = 1
    _, result = replay(contract, request, policy, encoded)
    assert result["status"] == "UNKNOWN"


def test_per_check_budget_exhaustion_stays_unknown(contract: Any) -> None:
    request, policy, encoded = inputs(contract)
    request["expectations"][0]["max_operations"] = 1
    _, result = replay(contract, request, policy, encoded)
    assert result["status"] == "UNKNOWN"
    assert result["observations"][0]["outcome"]["status"] == "UNKNOWN"


def test_wrong_selected_expected_outcome_is_refuted(contract: Any) -> None:
    request, policy, encoded = inputs(contract)
    request["expectations"][0]["expected"]["result"]["transitions"] = 7
    _, result = replay(contract, request, policy, encoded)
    assert result["status"] == "FAIL"


def test_selected_refutation_is_not_promoted_to_simulation_validity(contract: Any) -> None:
    request, policy, encoded = inputs(contract)
    request["expectations"][2]["expected"] = {"status": "PASS", "result": {"states": 2, "transitions": 1}}
    _, result = replay(contract, request, policy, encoded)
    assert result["status"] == "FAIL"


@pytest.mark.parametrize("change", ["check", "implementation", "request", "kind", "version"])
def test_external_selection_substitution_refuses(contract: Any, change: str) -> None:
    request, policy, encoded = inputs(contract)
    certificate, _ = replay(contract, request, policy, encoded)
    selected = {"semantic_version": VERSION, "objective": "VERIFIER-2.1", "represented_kind": "VERIFIER"}
    if change == "check":
        request["expectations"][0]["check"] = "invariant"
    elif change == "implementation":
        policy["mechanism_digest"] = "sha256:" + "0" * 64
    elif change == "request":
        request["object_id"] = "checker:other"
    elif change == "kind":
        selected["represented_kind"] = "SIM"
    else:
        selected["semantic_version"] = "legacy"
    with pytest.raises(ValueError):
        replay_current_object_certificate(certificate, **selected, expected_request=request, policy=policy)


@pytest.mark.parametrize("substitution", ["result", "evidence", "request"])
def test_rehashed_certificate_substitution_refuses(contract: Any, substitution: str) -> None:
    request, policy, encoded = inputs(contract)
    certificate, _ = replay(contract, request, policy, encoded)
    document = json.loads(certificate)
    if substitution == "result":
        document["result"]["status"] = "FAIL"
    elif substitution == "evidence":
        document["evidence_payloads"] = {}
    else:
        document["request"]["expectations"][0]["max_operations"] = 9999
    document["digest"] = digest({key: value for key, value in document.items() if key != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_sim_checker_certificate(canonical_bytes(document), expected_request=request, policy=policy)


@pytest.mark.parametrize("change", ["extra", "missing", "wrong_input_digest", "duplicate_expectation"])
def test_case_inventory_and_bindings_cannot_be_omitted_or_substituted(contract: Any, change: str) -> None:
    request, policy, encoded = inputs(contract)
    suite = json.loads(encoded)
    if change == "extra":
        suite["cases"]["extra"] = case()
    elif change == "missing":
        del suite["cases"]["invalid"]
    elif change == "wrong_input_digest":
        request["expectations"][0]["input_digest"] = "sha256:" + "0" * 64
    else:
        request["expectations"].append(deepcopy(request["expectations"][0]))
    encoded = canonical_bytes(suite)
    request["evidence_digest"] = digest(suite)
    if change == "duplicate_expectation":
        with pytest.raises(ValueError):
            replay(contract, request, policy, encoded)
    else:
        assert replay(contract, request, policy, encoded)[1]["status"] == "FAIL"


def test_noncanonical_and_duplicate_key_evidence_is_refuted(contract: Any) -> None:
    request, policy, encoded = inputs(contract)
    encoded = encoded.replace(b'{"cases":', b'{"cases":{},"cases":', 1)
    import hashlib
    request["evidence_digest"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    assert replay(contract, request, policy, encoded)[1]["status"] == "FAIL"


def test_request_and_policy_captured_before_digest_callback(contract: Any, monkeypatch: Any) -> None:
    request, policy, encoded = inputs(contract)
    original = contract.mechanism_digest
    expected_object = request["object_id"]
    def mutate() -> str:
        request["object_id"] = "checker:mutated"
        request["expectations"][0]["expected"]["result"]["states"] = 99
        return original()
    monkeypatch.setattr(contract, "mechanism_digest", mutate)
    certificate = contract.build_sim_checker_certificate(request, encoded, policy=policy)
    document = json.loads(certificate)
    assert document["request"]["object_id"] == expected_object
    assert document["result"]["status"] == "PASS"


@pytest.mark.parametrize("status,exit_code", [("PASS", 0), ("FAIL", 1), ("UNKNOWN", 2)])
def test_public_command_executes_new_native_route(contract: Any, tmp_path: Path, capsys: Any, status: str, exit_code: int) -> None:
    request, policy, encoded = inputs(contract)
    if status == "FAIL":
        request["expectations"][0]["expected"]["result"]["states"] = 7
    elif status == "UNKNOWN":
        encoded = None
    certificate, _ = replay(contract, request, policy, encoded)
    for name, value in (("certificate", certificate), ("request", canonical_bytes(request)), ("policy", canonical_bytes(policy))):
        (tmp_path/name).write_bytes(value)
    assert main(["current-object", "check", str(tmp_path/"certificate"),
        "--semantic-version", VERSION, "--objective", "VERIFIER-2.1", "--represented-kind", "VERIFIER",
        "--request", str(tmp_path/"request"), "--policy", str(tmp_path/"policy"), "--json"]) == exit_code
    assert json.loads(capsys.readouterr().out)["computational_status"] == status


@pytest.mark.parametrize("check", ["replay", "invariants", "refinement", "channels", "shards"])
def test_each_fixed_native_check_has_an_analytic_positive_oracle(contract: Any, check: str) -> None:
    request, policy, encoded = inputs(contract)
    suite = json.loads(encoded)
    selected = suite["cases"]["valid"]
    artifact, values = selected["artifact"], selected["inputs"]
    if check == "refinement":
        values["macro_states"] = [{"coarse": 0.0}, {"coarse": 2.0}]
        artifact.update(projection={"coarse": {"op": "mul", "args": [{"var": "x"}, 2.0]}},
                        macro_digest=digest(values["macro_states"]), tolerance=0.0)
    elif check == "shards":
        artifact["shards"] = {"ids": ["a", "b"], "require_signatures": False,
            "relations": [{"op": "eq", "args": [{"var": "a.x"}, {"var": "b.x"}]}]}
        values["shards"] = {name: [{"time": float(i), "state": {"x": float(i)}, "signature": None}
                                    for i in range(2)] for name in ("a", "b")}
    suite["cases"] = {"valid": selected}
    request["expectations"] = [{**request["expectations"][0], "check": check, "input_digest": digest(selected)}]
    request["evidence_digest"] = digest(suite)
    assert replay(contract, request, policy, canonical_bytes(suite))[1]["status"] == "PASS"
    if check == "shards":
        artifact["shards"]["require_signatures"] = True
        request["expectations"][0]["input_digest"] = digest(selected)
        request["evidence_digest"] = digest(suite)
        result = replay(contract, request, policy, canonical_bytes(suite))[1]
        assert result["status"] == "UNKNOWN"
        assert result["observations"][0]["outcome"]["reason"] == "external witness key absent"


@pytest.mark.parametrize("change", ["identifier", "payload", "kind", "mechanism", "operands"])
def test_checker_record_substitution_is_refuted(contract: Any, change: str) -> None:
    request, policy, encoded = inputs(contract)
    suite = json.loads(encoded)
    record = suite["checker_object"]
    if change == "identifier":
        record["object_id"] = "checker:other"
    elif change == "payload":
        record["payload"]["unselected"] = True
    elif change == "kind":
        record["kind"] = "SIM"
    elif change == "mechanism":
        record["payload"]["mechanism_digest"] = "sha256:" + "0" * 64
    else:
        record["operands"] = {"dependency": ["absent"]}
    # Rebasing the evidence cannot change the externally selected subject record.
    request["evidence_digest"] = digest(suite)
    assert replay(contract, request, policy, canonical_bytes(suite))[1]["status"] == "FAIL"
    # Selecting a different digest still cannot admit a false checker description.
    request["object_digest"] = digest(record)
    assert replay(contract, request, policy, canonical_bytes(suite))[1]["status"] == "FAIL"


@pytest.mark.parametrize("field", ["max_items", "max_capture_nodes", "max_expectations"])
def test_structural_bounds_stay_unknown(contract: Any, field: str) -> None:
    request, policy, encoded = inputs(contract)
    request["limits"][field] = 1
    assert replay(contract, request, policy, encoded)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("failure", ["unsupported", "arithmetic"])
def test_unavailable_native_semantics_never_pass(contract: Any, failure: str) -> None:
    request, policy, encoded = inputs(contract)
    suite = json.loads(encoded)
    suite["cases"]["valid"]["artifact"]["transition"]["x"] = {
        "op": "unknown" if failure == "unsupported" else "div", "args": [1.0, 0.0]}
    for row in request["expectations"]:
        row["input_digest"] = digest(suite["cases"][row["case_id"]])
    request["evidence_digest"] = digest(suite)
    result = replay(contract, request, policy, canonical_bytes(suite))[1]
    assert result["status"] == "UNKNOWN"
    assert result["observations"][0]["outcome"]["status"] == "UNKNOWN"


def test_known_mismatch_dominates_later_exhaustion(contract: Any) -> None:
    request, policy, encoded = inputs(contract)
    request["expectations"][0]["expected"]["result"]["states"] = 9
    request["expectations"][1]["max_operations"] = 1
    result = replay(contract, request, policy, encoded)[1]
    assert result["status"] == "FAIL"
    assert result["observations"][1]["outcome"]["status"] == "UNKNOWN"


def test_no_native_execution_before_input_binding(contract: Any, monkeypatch: Any) -> None:
    request, policy, encoded = inputs(contract)
    request["expectations"][-1]["input_digest"] = "sha256:" + "0" * 64
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("unbound input reached native execution")
    monkeypatch.setattr(contract.sim, "evaluate", forbidden)
    assert replay(contract, request, policy, encoded)[1]["status"] == "FAIL"


def test_different_refutation_reason_is_a_mismatch(contract: Any) -> None:
    request, policy, encoded = inputs(contract)
    request["expectations"][-1]["expected"]["reason"] = "unrelated failure"
    assert replay(contract, request, policy, encoded)[1]["status"] == "FAIL"


def test_polish_binds_exact_checker_without_promoting_whole_profile(contract: Any) -> None:
    from verifier.runtime.polish import assess_polish
    request, policy, encoded = inputs(contract)
    item = NamespaceObject.create(**json.loads(encoded)["checker_object"])
    certificate, _ = replay(contract, request, policy, encoded)
    certificate_digest = "sha256:" + hashlib.sha256(certificate).hexdigest()
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": [item.to_dict()],
              "certificates": {certificate_digest: certificate.decode("utf-8")}}
    assessment = {"schema_version": "verifier-polish-request-1", "root_id": item.object_id,
        "collection_digest": composition_digest([item]), "bundle_digest": digest(bundle),
        "requirements": [{"object_id": item.object_id, "tier": n, "applicability": "REQUIRED",
                          "rationale": "Selected checker assessment", "objectives": []} for n in range(1, 10)]}
    assessment["requirements"][1]["objectives"] = [{"semantic_version": VERSION,
        "coordinate": contract.COORDINATE, "request": request, "policy": policy,
        "certificate_digest": certificate_digest}]
    result = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(assessment))
    assert result["objectives"][0]["status"] == "PASS"
    assert result["status"] == "UNKNOWN" and result["polished"] is False
    bundle["objects"][0]["payload"]["changed"] = True
    assessment["bundle_digest"] = digest(bundle)
    assessment["collection_digest"] = composition_digest([NamespaceObject.create(**bundle["objects"][0])])
    result = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(assessment))
    assert result["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"
    assert result["status"] == "FAIL" and result["polished"] is False


@pytest.mark.parametrize("relative", ["domains/contracts/sim_checker.py", "domains/sim.py",
                                      "core/evidence.py", "standard/CURRENT_SIM_CHECKER.md"])
def test_polish_fingerprint_tracks_native_checker_dependencies(relative: str, monkeypatch: Any) -> None:
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1]/relative
    before = polish.mechanism_digest()
    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged dependency bytes\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before
