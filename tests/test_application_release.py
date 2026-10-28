"""Finite application evidence controls with actual native certificate replay.

JavaScript Object Notation (JSON); directed acyclic graph (DAG); command-line
interface (CLI); Secure Hash Algorithm 256-bit (SHA-256). Fixtures declare selected
finite records; they supply no production applicability or acceptance authority.
"""
from __future__ import annotations

from copy import deepcopy
from io import BytesIO
import json
import struct
import zipfile

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import object_facets
from verifier.runtime import application_release as app
from verifier.runtime import tier_progression as gate


def native(item: NamespaceObject, node_id: str = "native") -> tuple[dict, dict, dict, bytes]:
    policy = object_facets.object_facets_policy(trust_roots=("finite-declared-fixture",))
    request = object_facets.object_facets_request(item, policy=policy)
    raw = object_facets.build_object_facets_certificate(request, canonical_bytes(item.to_dict()), policy=policy)
    route = next(row for row in routes.current_object_route_catalog() if row["objective"] == "OBJECT-1.1")
    replay = routes.replay_current_object_certificate(raw, semantic_version=route["semantic_version"],
        objective="OBJECT-1.1", represented_kind=item.kind.value, expected_request=request, policy=policy)
    assert replay["computational_status"] == "PASS"
    claim = {"claim_id": node_id, **{key: route[key] for key in
        ("semantic_version", "objective", "proposition_digest", "scope")}, "assumptions": [], "dependencies": []}
    profile = {"schema_version": dag.PROFILE, "profile_id": "finite-application", "profile_version": "1",
        "object_kind": item.kind.value, "obligations": [claim]}
    node = {"node_id": node_id, "object_id": item.object_id, "claim_id": node_id,
        "certificate_path": node_id+".json", "certificate_digest": app.digest(raw), "request": request,
        "checker_policy": policy, "contract_version": replay["schema_version"].rsplit("-", 1)[1],
        "artifact_bindings": [{"path": node_id+".json", "digest": app.digest(raw)}],
        "facet_bindings": {"payload_digest": app.digest(item.payload_bytes),
                           "operands_digest": app.digest(canonical_bytes(item.to_dict()["operands"]))}}
    bundle = {"schema_version": dag.BUNDLE, "profiles": [profile], "objects": [item.to_dict()], "nodes": [node], "edges": []}
    files = {node_id+".json": raw}
    selected = {"schema_version": dag.POLICY, "approved_profiles": [app.digest(canonical_bytes(profile))],
        "required_objects": [{"object_id": item.object_id, "object_kind": item.kind.value,
            "record_digest": item.digest, "profile_digest": app.digest(canonical_bytes(profile))}],
        "required_roots": [node_id], "nodes": deepcopy(bundle["nodes"]), "artifact_files_digest": dag.artifact_files_digest(files)}
    selection = {"schema_version": gate.SELECTION, "semantic_version": gate.PROFILE,
        "profile_id": "finite-application", "subject": {key: selected["required_objects"][0][key]
            for key in ("object_id", "object_kind", "record_digest")}, "target_tier": 1,
        "bundle_digest": app.digest(canonical_bytes(bundle)), "policy_digest": app.digest(canonical_bytes(selected)),
        "artifact_files_digest": dag.artifact_files_digest(files), "ranks": [{"node_id": node_id, "tier": 1}],
        "tiers": [{"tier": tier, "census": "COMPLETE" if tier == 1 else "UNKNOWN",
                   "required_nodes": [node_id] if tier == 1 else []} for tier in range(1, 11)]}
    return bundle, selected, selection, raw


def fixture(*, archive_transform=None, context_generation=True, declared_operation=True) -> dict:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("src/finite.py", b"x = 1\n")
    archive_raw = buffer.getvalue()
    if archive_transform:
        archive_raw = archive_transform(archive_raw)
    source = {"schema_version": "verifier-actual-source-manifest-1", "source_files": [
        {"path": "src/finite.py", "bytes": 6, "digest": app.digest(b"x = 1\n")}],
        "preserved_source_archive": {"digest": app.digest(archive_raw)}}
    source_item = NamespaceObject.create("source", "DATA", {"manifest_digest": app.digest(canonical_bytes(source)),
        "source_archive_digest": app.digest(archive_raw)}, {})
    artifact = NamespaceObject.create("wheel", "DATA", {"name": "dist/finite.whl", "bytes": 5,
        "digest": app.digest(b"wheel")}, {})
    operations = [{"operation_id": "fixture:replay", "category": "declared-finite-replay"}] if declared_operation else []
    context = {"operation_id": "fixture:replay", "instruction": {"arguments": ["fixture"]}}
    context["instruction_revision_digest"] = app.digest(canonical_bytes(context["instruction"]))
    if context_generation:
        context["generation"] = 0
    context["context_revision_digest"] = app.digest(canonical_bytes(context))
    contexts = [context]
    root = NamespaceObject.create("own-application", "VERIFIER", {
        "exact_member_records_digest": app.digest(canonical_bytes({"source": source_item.digest, "wheel": artifact.digest})),
        "operation_definition_digest": app.digest(canonical_bytes(operations)),
        "actual_operation_context_digest": app.digest(canonical_bytes(contexts))}, {})
    envelope = NamespaceObject.create("membership", "HYPER", {}, {"application": [root.object_id],
        "source": [source_item.object_id], "artifacts": [artifact.object_id]})
    objects = [root, source_item, artifact, envelope]
    membership = {"schema_version": "verifier-own-application-membership-manifest-1",
        "objects": [item.to_dict() for item in objects], "application_root": root.to_dict(),
        "application_root_digest": root.digest, "membership_envelope_id": envelope.object_id,
        "membership_envelope_digest": envelope.digest, "collection_digest": composition_digest(objects)}
    bundle, policy, chosen, raw = native(root)
    claim, node = bundle["profiles"][0]["obligations"][0], bundle["nodes"][0]
    root_selection = {"object_id": root.object_id, "object_kind": "VERIFIER", "record_digest": root.digest}
    requirement = {"instance_id": "required:representation", "object_id": root.object_id,
        "operation_id": "fixture:replay", "context_digest": context["context_revision_digest"],
        "instruction_digest": context["instruction_revision_digest"], "generation": 0,
        "shard_id": "one", "node_id": "native", "tier": 1,
        **{key: claim[key] for key in ("semantic_version", "objective", "proposition_digest")},
        "request_digest": app.digest(canonical_bytes(node["request"])),
        "checker_policy_digest": app.digest(canonical_bytes(node["checker_policy"]))}
    requirements = {"schema_version": app.REQUIREMENTS, "root": root_selection,
        "instances": [requirement], "tiers": [{"tier": tier, "census": "COMPLETE" if tier == 1 else "UNKNOWN",
            "required_instances": [requirement["instance_id"]] if tier == 1 else []} for tier in range(1, 11)]}
    data = {"membership": membership, "source_manifest": source, "operation_definitions": operations,
        "contexts": contexts, "requirements": requirements,
        "files": {"src.zip": archive_raw, "dist/finite.whl": b"wheel", "native.json": raw},
        "shards": {"one": {"selection": chosen, "bundle": bundle, "policy": policy, "artifact_paths": ["native.json"]}}}
    data["selection"] = {"schema_version": app.SELECTION, "root": root_selection,
        "source_member_id": "source", "source_archive_path": "src.zip", "shards": []}
    repin(data)
    return data


def repin(data: dict) -> None:
    selection = data["selection"]
    for name in ("membership", "source_manifest", "operation_definitions", "contexts", "requirements"):
        selection[name+"_digest"] = app.digest(canonical_bytes(data[name]))
    selection["artifact_files_digest"] = dag.artifact_files_digest(data["files"])
    rows = []
    for sid, inputs in data["shards"].items():
        files = {name: data["files"][name] for name in inputs["artifact_paths"] if name in data["files"]}
        inputs["policy"]["artifact_files_digest"] = dag.artifact_files_digest(files)
        inputs["selection"].update(bundle_digest=app.digest(canonical_bytes(inputs["bundle"])),
            policy_digest=app.digest(canonical_bytes(inputs["policy"])), artifact_files_digest=dag.artifact_files_digest(files))
        rows.append({"shard_id": sid, **{name+"_digest": app.digest(canonical_bytes(inputs[name]))
            for name in ("selection", "bundle", "policy")}, "artifact_files_digest": dag.artifact_files_digest(files)})
    selection["shards"] = rows


def inputs(data: dict) -> dict:
    return {**{name+"_bytes": canonical_bytes(data[name]) for name in
        ("membership", "source_manifest", "operation_definitions", "contexts", "requirements")},
        "artifact_files": data["files"], "shard_inputs": {sid: {
            **{name+"_bytes": canonical_bytes(row[name]) for name in ("selection", "bundle", "policy")},
            "artifact_paths": row["artifact_paths"]} for sid, row in data["shards"].items()},
        "expected_selection_digest": app.digest(canonical_bytes(data["selection"])), "expected_mechanism_digest": app.mechanism_digest()}


def add_second(data: dict) -> None:
    root = NamespaceObject.create(**data["membership"]["application_root"])
    bundle, policy, chosen, raw = native(root, "second")
    data["files"]["second.json"] = raw
    data["shards"]["two"] = {"selection": chosen, "bundle": bundle, "policy": policy, "artifact_paths": ["second.json"]}
    requirement = deepcopy(data["requirements"]["instances"][0])
    requirement.update(instance_id="required:second", shard_id="two", node_id="second")
    data["requirements"]["instances"].append(requirement)
    data["requirements"]["tiers"][0]["required_instances"].append(requirement["instance_id"])
    repin(data)


def assess(data: dict, **changes) -> dict:
    options = inputs(data)
    options.update(changes)
    return app.assess_application_release(canonical_bytes(data["selection"]), **options)


def test_actual_finite_native_pass_cannot_authorize_application_release() -> None:
    data = fixture()
    result = assess(data)
    assert result["binding_status"] == result["native_status"] == "PASS"
    assert result["status"] == result["full_application_status"] == "UNKNOWN"
    assert result["required_operational_certificate_instances"] == "UNKNOWN"
    assert set(result["full_gates"].values()) == {"UNKNOWN"}
    assert result["polished"] is result["release_authorized"] is False
    assert app.recheck_application_release(canonical_bytes(result), canonical_bytes(data["selection"]), **inputs(data)) == result


@pytest.mark.parametrize("cancelled", [False, True])
def test_independently_valid_other_payload_same_id_refused(cancelled) -> None:
    data = fixture()
    root = NamespaceObject.create(**data["membership"]["application_root"])
    other = NamespaceObject.create(root.object_id, "VERIFIER", {"other": "payload"}, {})
    bundle, policy, chosen, raw = native(other)
    data["files"]["native.json"] = raw
    data["shards"]["one"].update(bundle=bundle, policy=policy, selection=chosen)
    repin(data)
    # The other-object native evidence actually passes its independently selected DAG.
    assert dag.assess_certificate_dependencies(canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy),
        artifact_files={"native.json": raw})["status"] == "PASS"
    result = assess(data, cancelled=cancelled)
    assert result["status"] == result["binding_status"] == "FAIL"
    assert "APPLICATION_NATIVE_SUBJECT_DIFFERS" in result["blockers"]


@pytest.mark.parametrize("change", ["root", "duplicate-instance", "tier", "request", "policy", "proposition", "instruction", "generation"])
def test_available_requirement_contradiction_precedes_missing_archive(change) -> None:
    data = fixture()
    del data["files"]["src.zip"]
    required = data["requirements"]["instances"][0]
    if change == "root":
        data["requirements"]["root"]["record_digest"] = "sha256:"+"0"*64
    elif change == "duplicate-instance":
        data["requirements"]["instances"].append(deepcopy(required))
    elif change == "tier":
        data["requirements"]["tiers"][1]["tier"] = 1
    elif change == "generation":
        required["generation"] = 1
    else:
        required[{"request": "request_digest", "policy": "checker_policy_digest", "proposition": "proposition_digest",
                  "instruction": "instruction_digest"}[change]] = "sha256:"+"0"*64
    repin(data)
    result = assess(data, cancelled=True)
    assert result["status"] == "FAIL"


def test_available_artifact_refutation_survives_missing_archive() -> None:
    data = fixture()
    del data["files"]["src.zip"]
    data["files"]["dist/finite.whl"] = b"wrong"
    repin(data)
    result = assess(data)
    assert result["status"] == "FAIL" and "APPLICATION_ARTIFACT_BYTES_DIFFER" in result["blockers"]


def test_missing_archive_does_not_mask_duplicate_source_members() -> None:
    data = fixture()
    del data["files"]["src.zip"]
    data["source_manifest"]["source_files"].append(deepcopy(data["source_manifest"]["source_files"][0]))
    repin(data)
    result = assess(data)
    assert result["status"] == "FAIL"


def test_missing_required_instance_cannot_report_complete_binding() -> None:
    data = fixture()
    extra = deepcopy(data["requirements"]["instances"][0])
    extra.update(instance_id="required:absent", node_id="absent")
    data["requirements"]["instances"].append(extra)
    data["requirements"]["tiers"][0]["required_instances"].append(extra["instance_id"])
    repin(data)
    result = assess(data)
    assert result["binding_status"] == result["status"] == "UNKNOWN"
    assert "APPLICATION_REQUIRED_NATIVE_INSTANCE_MISSING" in result["blockers"]


@pytest.mark.parametrize("missing", ["archive", "generation", "operation", "context", "shard", "external-pin"])
def test_missing_required_evidence_remains_unknown(missing) -> None:
    data = fixture(context_generation=missing != "generation", declared_operation=missing != "operation")
    options = {}
    if missing == "archive":
        del data["files"]["src.zip"]
    if missing == "context":
        data["requirements"]["instances"][0]["context_digest"] = "sha256:"+"0"*64
    repin(data)
    if missing == "shard":
        options["shard_inputs"] = {}
    if missing == "external-pin":
        options["expected_selection_digest"] = None
    result = assess(data, **options)
    assert result["status"] == "UNKNOWN" and not result["release_authorized"]
    assert len(result["blockers"]) > len(app.FULL_GATES)


def test_cancel_fences_valid_native_replay(monkeypatch) -> None:
    data = fixture()
    def refused(*args, **kwargs):
        pytest.fail("cancelled replay must not execute")
    monkeypatch.setattr(gate, "assess_tier_progression", refused)
    result = assess(data, cancelled=True)
    assert result["status"] == result["native_status"] == "UNKNOWN" and result["shards"] == []


@pytest.mark.parametrize("field", ["bundle_digest", "policy_digest", "artifact_files_digest"])
def test_nested_native_selection_refutation_precedes_cancellation(field) -> None:
    data = fixture()
    data["shards"]["one"]["selection"][field] = "sha256:"+"0"*64
    # Preserve the adversarial nested pin while selecting the exact changed bytes.
    data["selection"]["shards"][0]["selection_digest"] = app.digest(canonical_bytes(data["shards"]["one"]["selection"]))
    result = assess(data, cancelled=True)
    assert result["status"] == "FAIL" and "APPLICATION_NATIVE_SELECTION_DIFFERS" in result["blockers"]


def test_exact_policy_nodes_refutation_precedes_cancellation() -> None:
    data = fixture()
    data["shards"]["one"]["policy"]["nodes"][0]["contract_version"] = "other"
    repin(data)
    assert assess(data, cancelled=True)["status"] == "FAIL"


@pytest.mark.parametrize("field", ["polished", "release_authorized"])
def test_carried_false_to_zero_substitution_is_not_exact_replay(field) -> None:
    data = fixture()
    result = assess(data)
    result[field] = 0
    result["assessment_digest"] = app.digest(canonical_bytes({key: value for key, value in result.items() if key != "assessment_digest"}))
    checked = app.recheck_application_release(canonical_bytes(result), canonical_bytes(data["selection"]), **inputs(data))
    assert checked["status"] == "FAIL"


def test_oversized_carried_receipt_returns_capacity_unknown() -> None:
    data = fixture()
    result = app.recheck_application_release(b" "*(app.MAX_RECORD_BYTES+1), canonical_bytes(data["selection"]), **inputs(data))
    assert result["status"] == "UNKNOWN" and result["reason"] == "APPLICATION_CAPACITY_EXHAUSTED"


def test_missing_context_does_not_skip_instruction_digest_validation() -> None:
    data = fixture()
    data["requirements"]["instances"][0].update(context_digest="sha256:"+"0"*64, instruction_digest="invalid")
    repin(data)
    assert assess(data)["status"] == "FAIL"


def test_central_directory_actual_count_not_claimed_count_bounds_allocation() -> None:
    def corrupt(raw):
        changed = bytearray(raw)
        end = raw.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", changed, end+8, 0, 0)
        return bytes(changed)
    result = assess(fixture(archive_transform=corrupt))
    assert result["status"] == "FAIL" and "APPLICATION_SOURCE_ARCHIVE" in result["blockers"]


def test_unsupported_archive_compression_remains_unknown() -> None:
    def unsupported(raw):
        changed = bytearray(raw)
        central = raw.find(b"PK\x01\x02")
        struct.pack_into("<H", changed, central+10, 99)
        return bytes(changed)
    result = assess(fixture(archive_transform=unsupported))
    assert result["status"] == "UNKNOWN" and "APPLICATION_SOURCE_ARCHIVE_COMPRESSION_UNSUPPORTED" in result["blockers"]


def test_native_input_capacity_exhaustion_is_unknown() -> None:
    data = fixture()
    options = inputs(data)
    options["shard_inputs"]["one"]["bundle_bytes"] = b" "*(gate.MAX_RECORD_BYTES+1)
    result = app.assess_application_release(canonical_bytes(data["selection"]), **options)
    assert result["status"] == "UNKNOWN" and "APPLICATION_CAPACITY_EXHAUSTED" in result["blockers"]


def test_actual_native_failure_is_retained() -> None:
    data = fixture()
    data["files"]["native.json"] = b"{"
    node = data["shards"]["one"]["bundle"]["nodes"][0]
    node["certificate_digest"] = app.digest(b"{")
    node["artifact_bindings"][0]["digest"] = app.digest(b"{")
    data["shards"]["one"]["policy"]["nodes"] = deepcopy(data["shards"]["one"]["bundle"]["nodes"])
    repin(data)
    result = assess(data)
    assert result["status"] == result["native_status"] == "FAIL"
    assert result["binding_status"] == "PASS"


def test_later_available_shard_refutation_precedes_earlier_outage(monkeypatch) -> None:
    data = fixture()
    add_second(data)
    options = inputs(data)
    options["shard_inputs"]["two"]["bundle_bytes"] += b" "
    def unavailable(*args, **kwargs):
        pytest.fail("global preflight must refuse before native replay")
    monkeypatch.setattr(gate, "assess_tier_progression", unavailable)
    result = app.assess_application_release(canonical_bytes(data["selection"]), **options)
    assert result["status"] == "FAIL" and "APPLICATION_SHARD_BYTES_DIFFER" in result["blockers"]


def test_actual_native_failure_survives_later_replay_outage(monkeypatch) -> None:
    data = fixture()
    add_second(data)
    data["files"]["native.json"] = b"{"
    node = data["shards"]["one"]["bundle"]["nodes"][0]
    node["certificate_digest"] = node["artifact_bindings"][0]["digest"] = app.digest(b"{")
    data["shards"]["one"]["policy"]["nodes"] = deepcopy(data["shards"]["one"]["bundle"]["nodes"])
    repin(data)
    original, calls = gate.assess_tier_progression, []
    def replay(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise OSError("explicit fixture outage")
        return original(*args, **kwargs)
    monkeypatch.setattr(gate, "assess_tier_progression", replay)
    result = assess(data)
    assert len(calls) == 2 and result["status"] == result["native_status"] == "FAIL"
    assert [row["status"] for row in result["shards"]] == ["FAIL", "UNKNOWN"]


def test_caller_inner_maps_are_captured_before_native_replay(monkeypatch) -> None:
    data = fixture()
    add_second(data)
    options = inputs(data)
    original, calls = gate.assess_tier_progression, []
    def replay(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            options["shard_inputs"]["two"]["bundle_bytes"] = b"{}"
            options["shard_inputs"]["two"]["artifact_paths"].append("unavailable")
            options["artifact_files"].clear()
        return original(*args, **kwargs)
    monkeypatch.setattr(gate, "assess_tier_progression", replay)
    result = app.assess_application_release(canonical_bytes(data["selection"]), **options)
    assert len(calls) == 2 and result["binding_status"] == result["native_status"] == "PASS"


def test_cli_locator_refutation_is_fail_not_missing_evidence(tmp_path, capsys) -> None:
    from argparse import Namespace
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "ordinary.json").write_bytes(b"{}")
    shards = tmp_path / "shards.json"
    shards.write_bytes(canonical_bytes({"schema_version": "wrong", "shards": []}))
    args = Namespace(artifacts=str(artifacts), shards=str(shards), json=True)
    assert app.handle_application_command(args) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "FAIL"


@pytest.mark.parametrize("change", ["duplicate", "path", "extra-field"])
def test_known_locator_refutation_precedes_missing_selected_carrier(change, tmp_path, capsys) -> None:
    from argparse import Namespace
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "ordinary.json").write_bytes(b"{}")
    first = {"shard_id": "first", "selection_path": "missing-selection.json", "bundle_path": "missing-bundle.json",
             "policy_path": "missing-policy.json", "artifact_paths": []}
    second = deepcopy(first)
    second["shard_id"] = "second"
    if change == "duplicate":
        second["shard_id"] = "first"
    elif change == "path":
        second["bundle_path"] = "../outside.json"
    else:
        second["unselected"] = True
    shards = tmp_path / "shards.json"
    shards.write_bytes(canonical_bytes({"schema_version": "verifier-application-shard-locators-1", "shards": [first, second]}))
    args = Namespace(artifacts=str(artifacts), shards=str(shards), json=True)
    assert app.handle_application_command(args) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "FAIL"
