"""Exact retained executable coordinates for verifiable execution environments.

Verifier Standard (VSTD); verifiable execution environment (ENV); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Counts are
dimensionless. Version strings are selected labels bound to bytes, not proof of
the program's self-reported version or actual execution.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy

from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import env_checks, env_executable


def digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(value: object) -> str:
    return digest_bytes(canonical_bytes(value))


def selected(*, changed_label: bool = False, changed_bytes: bool = False,
             missing_child: bool = False, limits: dict | None = None) -> Any:
    module = env_executable
    fixture = runpy.run_path(str(Path(__file__).with_name("test_current_env_checks.py")))
    artifact, retained = fixture["specimen"]()
    runtime_bytes = b"synthetic runtime image\n"
    runtime_path = "runtime.bin"
    retained["files"][runtime_path] = {
        "base64": base64.b64encode(runtime_bytes).decode("ascii"),
        "sha256": digest_bytes(runtime_bytes),
    }
    artifact["files"][runtime_path] = digest_bytes(runtime_bytes)
    artifact["runtime"] = {
        "entrypoint": {"path": "program.py", "version": "demo-1.0.0"},
        "interpreter": {"path": runtime_path,
                        "version": "changed-runtime" if changed_label else "synthetic-runtime-1.0"},
    }
    if changed_bytes:
        retained["files"][runtime_path]["base64"] = base64.b64encode(
            b"substituted runtime image\n",
        ).decode("ascii")
    subject = NamespaceObject.create("environment", "ENV", artifact)
    rows = [subject.to_dict()]
    collection = composition_digest([subject])
    child_evidence = canonical_bytes({
        "schema_version": env_checks.EVIDENCE_VERSION,
        "objects": rows, "inputs": retained,
    })
    child_policy = env_checks.env_checks_policy(trust_roots=["selected-env-inventory"])
    child_request = env_checks.env_checks_request(
        check="closure", subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=collection, evidence_ref=digest_bytes(child_evidence),
        policy=child_policy,
    )
    child_cert = env_checks.build_env_checks_certificate(
        child_request, child_evidence, policy=child_policy,
    )
    assert env_checks.recheck_env_checks_certificate(
        child_cert, expected_request=child_request, policy=child_policy,
    )["status"] == ("FAIL" if changed_bytes else "PASS")
    evidence = canonical_bytes({
        "schema_version": module.EVIDENCE_VERSION,
        "inventory_certificate_b64": "" if missing_child else base64.b64encode(
            child_cert,
        ).decode("ascii"),
    })
    policy = module.env_executable_policy(trust_roots=["selected-env-executable"])
    request = module.env_executable_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=collection, evidence_ref=digest_bytes(evidence),
        entrypoint_path="program.py",
        entrypoint_digest=artifact["files"]["program.py"],
        entrypoint_version="demo-1.0.0",
        interpreter_path=runtime_path,
        interpreter_digest=artifact["files"][runtime_path],
        interpreter_version="synthetic-runtime-1.0",
        inventory_certificate_digest=digest_bytes(child_cert),
        inventory_request=child_request, inventory_policy=child_policy,
        policy=policy, limits=limits,
    )
    return module, request, policy, evidence


def replay(module: Any, request: Any, policy: Any, evidence: Any) -> Any:
    cert = module.build_env_executable_certificate(request, evidence, policy=policy)
    return module.recheck_env_executable_certificate(
        cert, expected_request=request, policy=policy,
    )["status"]


def test_exact_entrypoint_interpreter_and_selected_versions_replay() -> None:
    assert replay(*selected()) == "PASS"


def test_relabelled_interpreter_cannot_pass_even_with_valid_inventory() -> None:
    assert replay(*selected(changed_label=True)) == "FAIL"


def test_changed_interpreter_bytes_refute_retained_inventory() -> None:
    assert replay(*selected(changed_bytes=True)) == "FAIL"


def test_missing_selected_inventory_is_unknown() -> None:
    assert replay(*selected(missing_child=True)) == "UNKNOWN"


def test_selected_child_collection_substitution_rejected() -> None:
    module, request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["inventory_request"]["collection_digest"] = digest_bytes(b"other collection")
    with pytest.raises(module.EnvExecutableError):
        module.build_env_executable_certificate(changed, evidence, policy=policy)


def test_public_route_replays_selected_executable(tmp_path: Any, capsys: Any) -> None:
    from verifier.domains.contracts import current_object_routes as routes
    from verifier.runtime.public_cli import main

    module, request, policy, evidence = selected()
    certificate = module.build_env_executable_certificate(request, evidence, policy=policy)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=module.SEMANTIC_VERSION,
        objective=module.COORDINATE, represented_kind="ENV",
        expected_request=request, policy=policy,
    )
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["observed_program_version"] == "NOT_ESTABLISHED"
    assert report["native_result"]["actual_execution"] == "NOT_ESTABLISHED"
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


@pytest.mark.parametrize("field", ("entrypoint_digest", "interpreter_digest",
                                    "entrypoint_version", "interpreter_version"))
def test_external_coordinate_substitution_rejected(field: Any) -> None:
    module, request, policy, evidence = selected()
    certificate = module.build_env_executable_certificate(request, evidence, policy=policy)
    changed = deepcopy(request)
    changed[field] = (digest_bytes(b"substitute") if field.endswith("digest")
                      else "substituted-version")
    with pytest.raises(module.EnvExecutableError):
        module.recheck_env_executable_certificate(
            certificate, expected_request=changed, policy=policy,
        )


def test_conflicting_labels_for_same_runtime_file_refused() -> None:
    module, request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["interpreter_path"] = changed["entrypoint_path"]
    changed["interpreter_digest"] = changed["entrypoint_digest"]
    with pytest.raises(module.EnvExecutableError):
        module.build_env_executable_certificate(changed, evidence, policy=policy)


def test_child_certificate_byte_bound_stays_unknown() -> None:
    module, request, policy, evidence = selected()
    child = base64.b64decode(json.loads(evidence)["inventory_certificate_b64"])
    changed = deepcopy(request)
    changed["limits"]["max_child_certificate_bytes"] = len(child) - 1
    assert replay(module, changed, policy, evidence) == "UNKNOWN"


def test_rehashed_parent_result_substitution_refused() -> None:
    module, request, policy, evidence = selected()
    certificate = module.build_env_executable_certificate(request, evidence, policy=policy)
    changed = json.loads(certificate)
    changed["result"]["status"] = "UNKNOWN"
    changed.pop("digest")
    changed["digest"] = digest(changed)
    with pytest.raises(module.EnvExecutableError):
        module.recheck_env_executable_certificate(
            canonical_bytes(changed), expected_request=request, policy=policy,
        )


def test_canonical_executable_cannot_redact_child_evidence() -> None:
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    module, request, policy, evidence = selected()
    envelope = json.loads(module.build_env_executable_certificate(
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
