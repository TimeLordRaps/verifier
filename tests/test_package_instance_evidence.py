"""Exact package-instance evidence, not a selected specimen or asserted verdict.

Verifier Standard (VSTD) fixtures use the actual selected manifest records and
native checkers. Source recapture is isolated only by the imported root fixture.
"""
from __future__ import annotations

from copy import deepcopy
import json
import subprocess
from pathlib import Path

import pytest

from test_manifest_gate import selected_root
from verifier.runtime import package_polish as package
from verifier.runtime import core_obligation_union as binding
from verifier.runtime.manifest_gate import assess_object_gate
from verifier.runtime.namespace_contracts import namespace_registry, registry_document
from verifier.domains.contracts import object_facets, typed_facets
from verifier.core.namespace import composition_digest


def prepare(root: Path, *, typed: bool = False) -> tuple[dict, dict]:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    retained = json.loads((root / "objects.vstd").read_bytes())
    objects = package.tier_zero_manifest._namespace_objects(retained["objects"])
    subject = next(item for item in objects if item.object_id == "vstd-package-object")
    (root / "subject.py").write_text("def represented_boundary(): pass\n", encoding="utf-8")
    policy = (typed_facets.typed_facets_policy if typed else object_facets.object_facets_policy)(
        trust_roots=["explicit-local-selection-not-external-authority"])
    evidence = binding.canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION,
        "objects": [item.to_dict() for item in objects]}) if typed else binding.canonical_bytes(subject.to_dict())
    request = (typed_facets.typed_facets_request(object_kind=subject.kind.value, subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=composition_digest(objects),
        evidence_ref=binding.bytes_digest(evidence), policy=policy) if typed
        else object_facets.object_facets_request(subject, policy=policy))
    certificate = (typed_facets.build_typed_facets_certificate if typed else object_facets.build_object_facets_certificate)(
        request, evidence, policy=policy)
    check = {"object_id": subject.object_id, "coordinate": request["coordinate"],
        "semantic_version": request["semantic_version"], "proposition_digest": request["proposition_digest"],
        "reason": "This selected object requires an exact recoverable record and its declared operand layout.",
        "evidence": [{"path": "subject.py", "sha256": binding.bytes_digest((root / "subject.py").read_bytes())}]}
    for name, raw in (("request", binding.canonical_bytes(request)),
                      ("policy", binding.canonical_bytes(policy)), ("certificate", certificate)):
        path = name + ".json"
        (root / path).write_bytes(raw)
        check[name] = {"path": path, "sha256": binding.bytes_digest(raw)}
    document = {**retained, "schema_version": "verifier-objects-manifest-3", "namespace": {
        "schema_version": "verifier-objects-manifest-2", "registry_digest": registry_document(namespace_registry())["digest"],
        "extensions": [], "objects": [{**item.to_dict(), "specializations": [],
            "surfaces": ["file:subject.py"] if item == subject else [], "reason": "Fixture representation.",
            "classification": {}, "obligations": {}} for item in objects], "instance_checks": [check]}}
    save(root, document)
    return document, check


def save(root: Path, document: dict) -> None:
    (root / "objects.vstd").write_bytes(binding.canonical_bytes(document) + b"\n")


@pytest.mark.parametrize("typed,obligation", [
    (False, "OBJECT-1.1-canonical-representation-and-address"),
    (True, "OBJECT-1.2-declared-operand-facets"),
])
def test_selected_exact_native_evidence_can_discharge_its_structural_instance(selected_root, typed, obligation):
    prepare(selected_root, typed=typed)
    result = assess_object_gate("vstd-package-object", obligation, selected_root)
    assert result["status"] == "PASS", result["findings"]
    assert result["instance"]["applicability"]["classification"] == "NECESSARY"
    assert result["instance"]["selected_package_check"]["evidence_origin"] == "MANIFEST_SELECTED_INSTANCE"
    assert result["instance"]["selected_package_check"]["replay"]["computational_status"] == "PASS"
    assert not result["instance"]["native_specimen_is_instance_evidence"]
    assert not result["polished"] and not result["release_authorized"]


@pytest.mark.parametrize("field", ["request", "policy", "certificate"])
def test_stale_selected_artifact_fails_before_replay(selected_root, field):
    document, check = prepare(selected_root)
    (selected_root / check[field]["path"]).write_bytes(b"{}")
    result = assess_object_gate("vstd-package-object", "OBJECT-1.1-canonical-representation-and-address", selected_root)
    assert result["status"] == "FAIL"
    assert any("DIGEST_DIFFERS" in row["explanation"] for row in result["findings"])


def test_valid_certificate_for_other_record_cannot_count(selected_root):
    document, check = prepare(selected_root)
    # Keep a real passing certificate, but change its manifest's selected record.
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "vstd-package-object")
    check["object_id"] = "vstd-role"
    check["coordinate"] = "ROLE-1.1"
    save(selected_root, document)
    result = assess_object_gate("vstd-role", "ROLE-1.1-declared-operand-facets", selected_root)
    assert result["status"] == "FAIL"


# Construct synthetic absolute paths; no actual workstation or share is selected.
@pytest.mark.parametrize("name", ["../outside.json", "/".join(("C:", "outside.json")),
                                 "\\" * 2 + "\\".join(("server", "share", "file.json")), "objects.vstd"],
                         ids=["traversal", "drive", "network", "self-reference"])
def test_selected_paths_cannot_escape_or_reference_their_own_manifest(selected_root, name):
    document, check = prepare(selected_root)
    check["certificate"]["path"] = name
    save(selected_root, document)
    result = assess_object_gate("vstd-package-object", "OBJECT-1.1-canonical-representation-and-address", selected_root)
    assert result["status"] == "FAIL"


def test_missing_selected_certificate_is_unknown_not_a_facet_fallback(selected_root):
    document, check = prepare(selected_root)
    (selected_root / check["certificate"]["path"]).unlink()
    result = assess_object_gate("vstd-package-object", "OBJECT-1.1-canonical-representation-and-address", selected_root)
    assert result["status"] == "UNKNOWN"
    assert result["instance"]["checker_status"] != "PASS"
    assert result["instance"]["selected_package_check"]["replay"] is None


def test_duplicate_selection_is_rejected_not_last_one_wins(selected_root):
    document, check = prepare(selected_root)
    document["namespace"]["instance_checks"].append(deepcopy(check))
    save(selected_root, document)
    result = assess_object_gate("vstd-package-object", "OBJECT-1.1-canonical-representation-and-address", selected_root)
    assert result["status"] == "FAIL"
    assert any("DUPLICATED" in row["code"] for row in result["findings"])


def replace_artifact(root: Path, check: dict, name: str, raw: bytes) -> None:
    (root / check[name]["path"]).write_bytes(raw)
    check[name]["sha256"] = binding.bytes_digest(raw)


def test_passing_foreign_certificate_is_rejected_even_with_correct_kind(selected_root):
    from verifier.core.namespace import NamespaceObject
    document, check = prepare(selected_root)
    policy = json.loads((selected_root / "policy.json").read_bytes())
    foreign = NamespaceObject.create("a-different-object", "OBJECT", {})
    request = object_facets.object_facets_request(foreign, policy=policy)
    certificate = object_facets.build_object_facets_certificate(request, binding.canonical_bytes(foreign.to_dict()), policy=policy)
    assert object_facets.recheck_object_facets_certificate(certificate, expected_request=request, policy=policy)["status"] == "PASS"
    replace_artifact(selected_root, check, "request", binding.canonical_bytes(request))
    replace_artifact(selected_root, check, "certificate", certificate)
    save(selected_root, document)
    report = assess_object_gate("vstd-package-object", "OBJECT-1.1-canonical-representation-and-address", selected_root)
    assert report["status"] == "FAIL"
    selected = report["instance"]["selected_package_check"]
    assert selected["reason"] == "PACKAGE_INSTANCE_SUBJECT_OR_GRAPH_DIFFERS"
    assert selected["replay"] is None


def test_same_subject_in_another_valid_graph_is_rejected(selected_root):
    from verifier.core.namespace import NamespaceObject
    document, check = prepare(selected_root, typed=True)
    objects = list(package.tier_zero_manifest._namespace_objects(document["objects"]))
    index = next(i for i, row in enumerate(objects) if row.kind.value == "ENV")
    old = objects[index]
    objects[index] = NamespaceObject.create(old.object_id, old.kind, {"different_context": True}, dict(old.operands))
    policy = json.loads((selected_root / "policy.json").read_bytes())
    request = json.loads((selected_root / "request.json").read_bytes())
    evidence = binding.canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION,
        "objects": [item.to_dict() for item in objects]})
    request.update(collection_digest=composition_digest(objects), evidence_ref=binding.bytes_digest(evidence))
    certificate = typed_facets.build_typed_facets_certificate(request, evidence, policy=policy)
    assert typed_facets.recheck_typed_facets_certificate(certificate, expected_request=request, policy=policy)["status"] == "PASS"
    replace_artifact(selected_root, check, "request", binding.canonical_bytes(request))
    replace_artifact(selected_root, check, "certificate", certificate)
    save(selected_root, document)
    report = assess_object_gate("vstd-package-object", "OBJECT-1.2-declared-operand-facets", selected_root)
    assert report["status"] == "FAIL"
    assert report["instance"]["selected_package_check"]["reason"] == "PACKAGE_INSTANCE_SUBJECT_OR_GRAPH_DIFFERS"


def test_changed_file_after_native_pass_is_caught_by_explicit_recapture(selected_root, monkeypatch):
    from verifier.runtime import package_instance_evidence as evidence
    document, check = prepare(selected_root)
    replay = evidence.routes.replay_current_object_certificate

    def changed(*args, **kwargs):
        result = replay(*args, **kwargs)
        (selected_root / check["certificate"]["path"]).write_bytes(b"changed after native replay")
        return result

    monkeypatch.setattr(evidence.routes, "replay_current_object_certificate", changed)
    report = assess_object_gate("vstd-package-object", "OBJECT-1.1-canonical-representation-and-address", selected_root)
    assert report["instance"]["selected_package_check"]["replay"]["computational_status"] == "PASS"
    assert report["status"] == "FAIL"
    assert any(row["code"] == "PACKAGE_INSTANCE_EVIDENCE_DIGEST_DIFFERS" for row in report["findings"])


def test_capacity_exhaustion_does_not_fall_back_or_claim_refutation(selected_root, monkeypatch):
    from verifier.runtime import package_instance_evidence as evidence
    prepare(selected_root)
    monkeypatch.setattr(evidence, "MAX_TOTAL_BYTES", 1)
    report = assess_object_gate("vstd-package-object", "OBJECT-1.1-canonical-representation-and-address", selected_root)
    assert report["status"] == "UNKNOWN"
    assert report["instance"]["selected_package_check"]["replay"] is None


def test_shared_files_are_read_once_and_recaptured_without_cache(selected_root, monkeypatch):
    from verifier.runtime import package_instance_evidence as evidence
    document, check = prepare(selected_root)
    objects = package.tier_zero_manifest._namespace_objects(document["objects"])
    captured = evidence.InstanceEvidence(selected_root, objects, document["namespace"])
    read = captured._read
    calls = []

    def counted(ref, limit):
        calls.append(ref["path"])
        return read(ref, limit)

    monkeypatch.setattr(captured, "_read", counted)
    first = captured.read(check["request"])
    assert captured.read(check["request"]) == first
    assert len(calls) == 1
    captured.recapture()
    assert len(calls) == 2


def test_package_and_gate_share_the_exact_selected_instance_path(selected_root, monkeypatch):
    document, check = prepare(selected_root)

    def unavailable_native_prefix(tier: int, _root: Path) -> dict:
        blocking = {
            "tier": 0,
            "tier_name": "ADMISSION",
            "required_status": "PASS",
            "observed_status": "UNKNOWN",
            "report_digest": None,
            "blockers": ["FIXTURE_NATIVE_DIAGNOSTICS_UNAVAILABLE"],
        }
        body = {
            "status": "UNKNOWN",
            "prerequisites": {},
            "tier_execution": {
                str(depth): package._native_execution_record(
                    depth,
                    execution_status="NOT_RUN",
                    status="UNKNOWN",
                    reason=(
                        "Fixture deliberately leaves the cumulative native "
                        "diagnostic prefix unavailable."
                    ),
                    blocking_prerequisite=blocking,
                )
                for depth in range(tier + 1)
            },
            "claim_scope": "SOURCE_NATIVE_DIAGNOSTICS_NOT_PACKAGE_INSTANCES",
        }
        return {**body, "report_digest": binding.value_digest(body)}

    monkeypatch.setattr(
        package, "_run_native_diagnostics", unavailable_native_prefix
    )
    report = package.assess_package_polish(1, selected_root)
    instance = next(row for row in report["obligation_instances"] if row["object_id"] == check["object_id"]
                    and row["coordinate"] == check["coordinate"])
    assert instance["status"] == "PASS"
    assert report["status"] == "UNKNOWN" and not report["polished"]
    import jsonschema
    schema = json.loads((Path(__file__).parents[1] / "src/verifier/schemas/verifier-manifest-package-polish-2.schema.json").read_bytes())
    jsonschema.Draft202012Validator(schema).validate(report)


def test_admission_rejects_stale_selected_input_without_replaying_it(selected_root, monkeypatch):
    import subprocess
    from verifier.runtime import namespace_admission
    from verifier.runtime import package_instance_evidence as evidence
    document, check = prepare(selected_root)
    subprocess.run(["git", "init", "-q", str(selected_root)], check=True)
    (selected_root / check["certificate"]["path"]).write_bytes(b"stale selected evidence")
    monkeypatch.setattr(evidence.routes, "replay_current_object_certificate",
                        lambda *args, **kwargs: pytest.fail("Tier zero must not execute an instance checker"))
    report = namespace_admission.assess(selected_root)
    assert any(row["code"] == "PACKAGE_INSTANCE_EVIDENCE_DIGEST_DIFFERS" and row["status"] == "FAIL"
               and row["coordinate"] == "VSTD-T0.7" and row["object_id"] == check["object_id"]
               for row in report["findings"])
