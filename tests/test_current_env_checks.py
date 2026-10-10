"""Current verifiable execution environment (ENV) independently selected checks.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). Counts are
dimensionless and byte commitments count canonical encoded bytes.
"""
from __future__ import annotations

from copy import deepcopy
import base64
import hashlib
import math
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains import env
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import current_object_routes as routes

SEMANTIC = "verifier-current-object-obligations-1"
CHECKS = {"closure": "ENV-1.2", "configuration": "ENV-1.5",
          "resources": "ENV-3.3", "reproduction": "ENV-2.3"}


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def specimen() -> tuple[dict, dict]:
    files = {name: {"base64": base64.b64encode(value).decode(),
                    "sha256": "sha256:" + hashlib.sha256(value).hexdigest()}
             for name, value in {"program.py": b"print(42)\n", "library.py": b"VALUE = 42\n"}.items()}
    inventory = {name: record["sha256"] for name, record in files.items()}
    config = {"byteorder": "little", "engine": "retained-test-engine"}
    artifact = {"scope": "retained-process-observations", "files": inventory,
                "configuration": config, "execution_ids": ["first", "second"],
                "ceilings": {"wall_seconds": 2, "memory_bytes": 4096, "threads": 2},
                "execution": {"executable": "program.py", "input_digest": digest([21]),
                              "output_digest": digest([42])}}
    retained = {"files": files, "configuration": deepcopy(config),
        "measurements": [{"id": name, "wall_seconds": 2, "memory_bytes": 4096, "threads": 2}
                         for name in artifact["execution_ids"]],
        "executions": [{"id": name, "software_digest": digest(inventory),
            "configuration_digest": digest(config), "executable": "program.py", "input": [21],
            "output": [42], "exit_code": 0} for name in artifact["execution_ids"]]}
    return artifact, retained


def inputs(check: str, *, artifact=None, retained=None, **limits):
    contract = importlib.import_module("verifier.domains.contracts.env_checks")
    if artifact is None:
        artifact, retained = specimen()
    subject = NamespaceObject.create("environment", "ENV", artifact)
    objects = [subject]
    evidence = canonical_bytes({"schema_version": "verifier-current-env-checks-evidence-1",
                               "objects": [obj.to_dict() for obj in objects], "inputs": retained})
    policy = contract.env_checks_policy(trust_roots=["selected-retained-env-only"])
    request = contract.env_checks_request(check=check, subject_id="environment", object_digest=subject.digest,
        collection_digest=composition_digest(objects), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits)
    return contract, request, policy, evidence


def replay(contract, request, policy, evidence):
    certificate = contract.build_env_checks_certificate(request, evidence, policy=policy)
    return routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=request["coordinate"], represented_kind="ENV", expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_current_env_route_is_explicitly_selected(check):
    route = routes.select_current_object_route(semantic_version=SEMANTIC,
        objective=CHECKS[check], represented_kind="ENV")
    assert route.fixed_kind == "ENV"
    assert route.scope == "finite_retained_env_" + check


@pytest.mark.parametrize("check", CHECKS)
def test_native_positive_controls_execute_every_selected_check(check):
    artifact, retained = specimen()
    assert env.evaluate(check, artifact, retained, Budget(10000)) == {"files": 2, "scope": "retained-process-observations"}


@pytest.mark.parametrize("check", ["inventories", "", "SCHEMA", " schema", None, True, ["closure"]])
def test_unsupported_native_selection_cannot_return_inventory_success(check):
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported environment check"):
        env.evaluate(check, artifact, retained, Budget(10000))


def test_subclass_selection_cannot_choose_a_different_check():
    class Forged(str):
        def __eq__(self, other):
            return True
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported environment check"):
        env.evaluate(Forged("inventories"), artifact, retained, Budget(10000))


def test_unknown_selection_refuses_before_evidence_access():
    class Unreadable(dict):
        def __contains__(self, key):
            raise AssertionError("unsupported selector consumed evidence")
    budget = Budget(0)
    with pytest.raises(Unavailable, match="unsupported environment check"):
        env.evaluate("inventories", {}, Unreadable(), budget)
    assert budget.used == 0


@pytest.mark.parametrize("check", CHECKS)
def test_current_env_positive_replay_is_bounded_and_deterministic(check):
    contract, request, policy, evidence = inputs(check)
    first = contract.build_env_checks_certificate(request, evidence, policy=policy)
    assert first == contract.build_env_checks_certificate(request, evidence, policy=policy)
    report = replay(contract, request, policy, evidence)
    assert report["computational_status"] == "PASS"
    result = report["native_result"]
    assert result["object_profile_conformance"] == result["authority"] == "NOT_ESTABLISHED"
    assert result["evaluation"]["observations"]["environment"] == {"files": 2, "scope": "retained-process-observations"}


@pytest.mark.parametrize("check", CHECKS)
def test_rehashed_rebound_false_native_evidence_is_refuted(check):
    artifact, retained = specimen()
    if check == "closure":
        artifact["files"]["program.py"] = "sha256:" + "0" * 64
    elif check == "configuration":
        retained["configuration"]["byteorder"] = "big"
    elif check == "resources":
        retained["measurements"][1]["memory_bytes"] = 4097
    else:
        retained["executions"][1]["input"] = [22]
    contract, request, policy, evidence = inputs(check, artifact=artifact, retained=retained)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("bound", ["max_operations", "max_composition_operations", "max_evidence_bytes",
                                  "max_payload_bytes", "max_reference_bytes", "max_items"])
def test_selected_resource_exhaustion_remains_unknown(check, bound):
    contract, request, policy, evidence = inputs(check, **{bound: 1})
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("check", CHECKS)
def test_missing_retained_evidence_is_unknown(check):
    contract, request, policy, evidence = inputs(check)
    assert replay(contract, request, policy, None)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest"])
def test_certificate_cannot_select_its_own_subject_or_evidence(field):
    contract, request, policy, evidence = inputs("configuration")
    certificate = contract.build_env_checks_certificate(request, evidence, policy=policy)
    request[field] = "other-subject" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        contract.recheck_env_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field,value", [("status", "FAIL"), ("authority", "ESTABLISHED"),
                                         ("object_profile_conformance", "ESTABLISHED")])
def test_rehashed_claim_promotion_is_rejected(field, value):
    contract, request, policy, evidence = inputs("closure")
    certificate = json.loads(contract.build_env_checks_certificate(request, evidence, policy=policy))
    certificate["result"][field] = value
    certificate["digest"] = digest({key: val for key, val in certificate.items() if key != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_env_checks_certificate(canonical_bytes(certificate), expected_request=request, policy=policy)


@pytest.mark.parametrize("bad", [None, [], "", False])
def test_falsey_operands_cannot_normalize_into_valid_env_record(bad):
    contract, request, policy, evidence = inputs("closure")
    value = json.loads(evidence); value["objects"][0]["operands"] = bad
    evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
def test_public_env_command_executes_native_replay(check, tmp_path, capsys):
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs(check)
    values = {"request": canonical_bytes(request), "policy": canonical_bytes(policy),
              "certificate": contract.build_env_checks_certificate(request, evidence, policy=policy)}
    for name, content in values.items():
        (tmp_path / (name + ".json")).write_bytes(content)
    result = main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", CHECKS[check], "--represented-kind", "ENV", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert result == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_env_certificate_cannot_shed_canonical_evidence():
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs("closure")
    value = json.loads(contract.build_env_checks_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("ENV", tuple(key for key in value if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/env_checks.py", "domains/env.py", "standard/CURRENT_ENV_CHECKS.md"])
def test_env_dependencies_invalidate_polish(relative, monkeypatch):
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def changed(path):
        value = original(path)
        return value + b"\nchanged environment dependency\n" if path == target else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("check", CHECKS)
def test_env_inventory_preserves_each_registered_objective(check):
    from verifier.domains.inventory import get_slot
    tier = int(CHECKS[check].split("-")[1].split(".")[0])
    row = get_slot("ENV", tier).to_dict()
    assert row["mechanized"]
    selected = next(item for item in row["registered_objectives"] if item["coordinate"] == CHECKS[check])
    assert "env_checks" in selected["binding"]["checking_mechanism"]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", ["domains/contracts/env_checks.py", "domains/env.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_ENV_CHECKS.md", "standard/NAMESPACE_OBJECTS.md"])
def test_changed_direct_dependency_invalidates_environment_policy(relative, monkeypatch):
    contract, request, policy, evidence = inputs("closure")
    certificate = contract.build_env_checks_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(contract.__file__).parents[2] / relative
    def changed(path):
        content = original(path)
        return content + b"\nchanged dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_env_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_native_operation_limit_has_exact_and_one_under_controls(check):
    contract, request, policy, evidence = inputs(check)
    result = replay(contract, request, policy, evidence)
    used = result["native_result"]["evaluation"]["observations"]["operations"]
    request["limits"]["max_operations"] = used
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    request["limits"]["max_operations"] = used - 1
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("case", ["missing-inputs", "missing-configuration", "physical-attestation", "missing-execution"])
def test_unavailable_environment_support_is_unknown(case):
    artifact, retained = specimen()
    check = "reproduction" if case == "missing-execution" else "configuration"
    if case == "missing-configuration":
        del retained["configuration"]
    elif case == "physical-attestation":
        artifact["scope"] = "physical-attestation"
    elif case == "missing-execution":
        retained["executions"] = retained["executions"][:1]
    contract, request, policy, evidence = inputs(check, artifact=artifact, retained=retained)
    if case == "missing-inputs":
        value = json.loads(evidence); value["inputs"] = None
        evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


def test_same_spelling_under_legacy_semantics_cannot_select_current_env():
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.select_current_object_route(semantic_version="legacy-domain", objective="ENV-1.2", represented_kind="ENV")


def test_wrong_check_cannot_reuse_another_proposition():
    contract, request, policy, evidence = inputs("closure")
    request["check"] = "configuration"
    with pytest.raises(ValueError, match="objective differs"):
        contract.build_env_checks_certificate(request, evidence, policy=policy)


def test_one_byte_tamper_is_rejected():
    contract, request, policy, evidence = inputs("closure")
    certificate = bytearray(contract.build_env_checks_certificate(request, evidence, policy=policy))
    certificate[-3] ^= 1
    with pytest.raises(ValueError):
        contract.recheck_env_checks_certificate(bytes(certificate), expected_request=request, policy=policy)


def test_env_polish_replay_binds_subject_and_collection_without_issuing_polished_status():
    from verifier.runtime.polish import assess_polish
    contract, request, policy, evidence = inputs("closure")
    certificate = contract.build_env_checks_certificate(request, evidence, policy=policy)
    objects = json.loads(evidence)["objects"]
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": objects,
              "certificates": {digest(json.loads(certificate)): certificate.decode()}}
    selected = {"schema_version": "verifier-polish-request-1", "root_id": "environment",
        "collection_digest": request["collection_digest"], "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "environment", "tier": tier, "applicability": "REQUIRED",
                          "rationale": "Selected environment proposition only", "objectives": []} for tier in range(1, 10)]}
    selected["requirements"][0]["objectives"] = [{"semantic_version": SEMANTIC, "coordinate": "ENV-1.2",
        "request": request, "policy": policy, "certificate_digest": digest(json.loads(certificate))}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    request["collection_digest"] = "sha256:" + "0" * 64
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected))
    assert report["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"


@pytest.mark.parametrize("ceiling", [2**53, float(2**53), 2**80, float(2**80)])
def test_native_wall_seconds_integer_excess_cannot_round_into_pass(ceiling):
    artifact, retained = specimen()
    artifact["ceilings"]["wall_seconds"] = ceiling
    retained["measurements"][0]["wall_seconds"] = int(ceiling) + 1
    with pytest.raises(Refuted, match="exceeds bound"):
        env.evaluate("resources", artifact, retained, Budget(10000))


@pytest.mark.parametrize("field", ["wall_seconds", "memory_bytes", "threads"])
def test_native_exact_ceiling_passes_and_smallest_representable_excess_fails(field):
    artifact, retained = specimen()
    assert env.evaluate("resources", artifact, retained, Budget(10000))["files"] == 2
    bound = artifact["ceilings"][field]
    retained["measurements"][0][field] = math.nextafter(float(bound), math.inf) if field == "wall_seconds" else bound + 1
    with pytest.raises(Refuted, match="exceeds bound"):
        env.evaluate("resources", artifact, retained, Budget(10000))


@pytest.mark.parametrize("field", ["software_digest", "configuration_digest", "executable", "input", "output", "exit_code"])
def test_every_retained_execution_binding_has_an_independent_negative(field):
    artifact, retained = specimen()
    row = retained["executions"][1]
    row[field] = {"software_digest": "sha256:" + "0" * 64,
                  "configuration_digest": "sha256:" + "0" * 64, "executable": "library.py",
                  "input": [22], "output": [43], "exit_code": 1}[field]
    contract, request, policy, evidence = inputs("reproduction", artifact=artifact, retained=retained)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check,key", [("closure", "files"), ("configuration", "configuration"),
                                       ("resources", "measurements"), ("reproduction", "executions")])
def test_missing_required_native_input_is_unknown(check, key):
    artifact, retained = specimen()
    del retained[key]
    contract, request, policy, evidence = inputs(check, artifact=artifact, retained=retained)
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"
