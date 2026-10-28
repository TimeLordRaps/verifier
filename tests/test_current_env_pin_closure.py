"""Finite selected ENV resolver trace closure; no live-host completeness claim.

Verifier Standard (VSTD); verifiable execution environment (ENV);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Counts are dimensionless, certificate and evidence ceilings measure bytes.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import env_checks, env_pin_closure


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def selected(*, pins=None, observations=None, missing_child=False, limits=None):
    module = env_pin_closure
    raw_files = {"program.py": b"import library\n", "library.py": b"ANSWER = 42\n"}
    files = {name: {"base64": base64.b64encode(raw).decode("ascii"),
                    "sha256": digest(raw)} for name, raw in raw_files.items()}
    inventory = {name: item["sha256"] for name, item in files.items()}
    subject = NamespaceObject.create("environment", "ENV", {
        "scope": "retained-process-observations", "files": inventory,
    })
    collection = composition_digest([subject])
    child_evidence = canonical_bytes({
        "schema_version": env_checks.EVIDENCE_VERSION,
        "objects": [subject.to_dict()], "inputs": {"files": files},
    })
    child_policy = env_checks.env_checks_policy(trust_roots=["selected-env-inventory"])
    child_request = env_checks.env_checks_request(
        check="closure", subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=collection,
        evidence_ref=digest(child_evidence), policy=child_policy,
    )
    child_certificate = env_checks.build_env_checks_certificate(
        child_request, child_evidence, policy=child_policy,
    )
    assert env_checks.recheck_env_checks_certificate(
        child_certificate, expected_request=child_request, policy=child_policy,
    )["status"] == "PASS"
    required = [
        {"id": "entry", "requester": "@entry", "specifier": "./program.py",
         "target": "program.py"},
        {"id": "import", "requester": "program.py", "specifier": "./library.py",
         "target": "library.py"},
    ]
    selected_pins = inventory if pins is None else pins
    observed = ([{"id": row["id"], "target": row["target"],
                  "digest": inventory[row["target"]]} for row in required]
                if observations is None else observations)
    evidence = canonical_bytes({
        "schema_version": module.EVIDENCE_VERSION,
        "closure_certificate_b64": ("" if missing_child else
                                    base64.b64encode(child_certificate).decode("ascii")),
        "observations": observed,
    })
    policy = module.env_pin_closure_policy(trust_roots=["selected-env-resolution"])
    request = module.env_pin_closure_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=collection, evidence_ref=digest(evidence),
        pins=selected_pins, required_resolutions=required,
        closure_certificate_digest=digest(child_certificate),
        closure_request=child_request, closure_policy=child_policy,
        policy=policy, limits=limits,
    )
    return module, request, policy, evidence


def replay(module, request, policy, evidence):
    certificate = module.build_env_pin_closure_certificate(
        request, evidence, policy=policy,
    )
    return module.recheck_env_pin_closure_certificate(
        certificate, expected_request=request, policy=policy,
    )["status"]


def test_selected_finite_resolution_trace_replays():
    assert replay(*selected()) == "PASS"


def test_selected_pin_substitution_fails_even_when_observation_matches_it():
    module, request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["pins"]["library.py"] = digest(b"different bytes")
    assert replay(module, changed, policy, evidence) == "FAIL"


def test_unpinned_retained_target_fails():
    module, request, policy, evidence = selected()
    changed = json.loads(evidence)
    changed["observations"][1]["target"] = "elsewhere.py"
    changed["observations"][1]["digest"] = digest(b"elsewhere")
    changed_evidence = canonical_bytes(changed)
    selected_request = deepcopy(request)
    selected_request["evidence_ref"] = digest(changed_evidence)
    assert replay(module, selected_request, policy, changed_evidence) == "FAIL"


def test_missing_selected_observation_is_unknown():
    module, request, policy, evidence = selected()
    changed = json.loads(evidence)
    changed["observations"].pop()
    changed_evidence = canonical_bytes(changed)
    selected_request = deepcopy(request)
    selected_request["evidence_ref"] = digest(changed_evidence)
    assert replay(module, selected_request, policy, changed_evidence) == "UNKNOWN"


def test_missing_selected_inventory_child_is_unknown():
    assert replay(*selected(missing_child=True)) == "UNKNOWN"


@pytest.mark.parametrize("available", [0, 1])
@pytest.mark.parametrize("mode", [
    "missing_only", "wrong_target", "wrong_digest",
    "missing_wrong_target", "missing_wrong_digest",
])
def test_available_contradiction_survives_missing_selected_row(available, mode):
    module, request, policy, evidence = selected()
    changed = json.loads(evidence)
    row = changed["observations"][available]
    if mode.endswith("wrong_target"):
        row["target"] = "unpinned-target"
    elif mode.endswith("wrong_digest"):
        row["digest"] = digest(b"wrong digest")
    if mode.startswith("missing"):
        changed["observations"] = [row]
    changed_evidence = canonical_bytes(changed)
    request["evidence_ref"] = digest(changed_evidence)
    expected = "UNKNOWN" if mode == "missing_only" else "FAIL"
    assert replay(module, request, policy, changed_evidence) == expected


@pytest.mark.parametrize("child_state", ["PASS", "missing", "UNKNOWN", "FAIL"])
@pytest.mark.parametrize("observation", [
    "correct", "missing", "target", "digest", "extra", "duplicate",
])
def test_parent_contradiction_survives_unavailable_child(child_state, observation):
    module, request, policy, evidence = selected()
    changed = json.loads(evidence)
    child_bytes = base64.b64decode(changed["closure_certificate_b64"])
    if child_state in ("UNKNOWN", "FAIL"):
        child_evidence = None
        if child_state == "FAIL":
            envelope = json.loads(child_bytes)
            child_evidence = json.loads(base64.b64decode(
                envelope["evidence_payloads"][request["closure_request"]["evidence_ref"]],
            ))
            child_evidence["inputs"]["files"]["program.py"]["base64"] = (
                base64.b64encode(b"changed executable").decode("ascii")
            )
            child_evidence = canonical_bytes(child_evidence)
            request["closure_request"]["evidence_ref"] = digest(child_evidence)
        child_bytes = env_checks.build_env_checks_certificate(
            request["closure_request"], child_evidence,
            policy=request["closure_policy"],
        )
        assert env_checks.recheck_env_checks_certificate(
            child_bytes, expected_request=request["closure_request"],
            policy=request["closure_policy"],
        )["status"] == child_state
        request["closure_certificate_digest"] = digest(child_bytes)
        changed["closure_certificate_b64"] = base64.b64encode(child_bytes).decode("ascii")
    elif child_state == "missing":
        changed["closure_certificate_b64"] = ""
    if observation == "missing":
        changed["observations"].pop()
    elif observation == "target":
        changed["observations"][0]["target"] = "unselected-target"
    elif observation == "digest":
        changed["observations"][0]["digest"] = digest(b"unselected bytes")
    elif observation == "extra":
        changed["observations"].append(dict(
            changed["observations"][0], id="unselected-resolution",
        ))
    elif observation == "duplicate":
        changed["observations"].append(dict(changed["observations"][0]))
    changed_evidence = canonical_bytes(changed)
    request["evidence_ref"] = digest(changed_evidence)
    if observation in ("target", "digest", "extra", "duplicate") or child_state == "FAIL":
        expected = "FAIL"
    elif child_state in ("missing", "UNKNOWN") or observation == "missing":
        expected = "UNKNOWN"
    else:
        expected = "PASS"
    assert replay(module, request, policy, changed_evidence) == expected


def test_selected_child_collection_substitution_is_rejected():
    module, request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["closure_request"]["collection_digest"] = digest(b"other collection")
    with pytest.raises(module.EnvPinClosureError):
        module.build_env_pin_closure_certificate(changed, evidence, policy=policy)


def test_externally_selected_unpinned_target_is_rejected():
    module, request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["required_resolutions"][1]["target"] = "undeclared.py"
    with pytest.raises(module.EnvPinClosureError):
        module.build_env_pin_closure_certificate(changed, evidence, policy=policy)


def test_duplicate_resolution_identifier_is_rejected():
    module, request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["required_resolutions"][1]["id"] = "entry"
    with pytest.raises(module.EnvPinClosureError):
        module.build_env_pin_closure_certificate(changed, evidence, policy=policy)


def test_entrypoint_sentinel_cannot_also_be_a_pinned_file():
    module, request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["pins"]["@entry"] = digest(b"shadowed entrypoint")
    with pytest.raises(module.EnvPinClosureError):
        module.build_env_pin_closure_certificate(changed, evidence, policy=policy)


def test_child_certificate_byte_limit_stays_unknown():
    module, request, policy, evidence = selected()
    child = base64.b64decode(json.loads(evidence)["closure_certificate_b64"])
    changed = deepcopy(request)
    changed["limits"]["max_child_certificate_bytes"] = len(child) - 1
    assert replay(module, changed, policy, evidence) == "UNKNOWN"


def test_recomputed_parent_result_forgery_rejected():
    module, request, policy, evidence = selected()
    forged = json.loads(module.build_env_pin_closure_certificate(
        request, evidence, policy=policy,
    ))
    forged["result"]["status"] = "UNKNOWN"
    forged.pop("digest")
    forged["digest"] = digest(canonical_bytes(forged))
    with pytest.raises(module.EnvPinClosureError):
        module.recheck_env_pin_closure_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy,
        )


def test_rehashed_forged_child_result_cannot_supply_inventory_prerequisite():
    module, request, policy, evidence = selected()
    retained = json.loads(evidence)
    child = json.loads(base64.b64decode(retained["closure_certificate_b64"]))
    child["result"]["status"] = "FAIL"
    child.pop("digest")
    child["digest"] = digest(canonical_bytes(child))
    forged_child = canonical_bytes(child)
    retained["closure_certificate_b64"] = base64.b64encode(forged_child).decode("ascii")
    changed_evidence = canonical_bytes(retained)
    changed_request = deepcopy(request)
    changed_request["closure_certificate_digest"] = digest(forged_child)
    changed_request["evidence_ref"] = digest(changed_evidence)
    assert replay(module, changed_request, policy, changed_evidence) == "FAIL"


def test_parent_operation_exhaustion_is_unknown():
    module, request, policy, evidence = selected(limits={"max_operations": 1})
    assert replay(module, request, policy, evidence) == "UNKNOWN"


def test_public_route_replays_pin_closure(tmp_path, capsys):
    from verifier.domains.contracts import current_object_routes as routes
    from verifier.runtime.public_cli import main

    module, request, policy, evidence = selected()
    certificate = module.build_env_pin_closure_certificate(
        request, evidence, policy=policy,
    )
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=module.SEMANTIC_VERSION,
        objective=module.COORDINATE, represented_kind="ENV",
        expected_request=request, policy=policy,
    )
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["live_resolution_completeness"] == "NOT_ESTABLISHED"
    for stem, raw in (("certificate", certificate), ("request", canonical_bytes(request)),
                      ("policy", canonical_bytes(policy))):
        (tmp_path / (stem + ".json")).write_bytes(raw)
    assert main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", module.SEMANTIC_VERSION,
        "--objective", module.COORDINATE, "--represented-kind", "ENV",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_canonical_pin_closure_certificate_cannot_redact_child_evidence():
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    module, request, policy, evidence = selected()
    envelope = json.loads(module.build_env_pin_closure_certificate(
        request, evidence, policy=policy,
    ))
    fields = tuple(key for key in envelope if key != "evidence_payloads")
    surface = DisclosureSurface("ENV", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(envelope, surface, bounds, context)
