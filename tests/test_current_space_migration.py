"""Current SPACE-2.1 length-preserving partition migration between two layouts.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Offsets, lengths and extents are bytes; counts
and checker budgets are dimensionless. No physical data movement is proved.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import space_layout, space_migration
from verifier.domains.inventory import get_slot


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


BEFORE = [
    {"id": "code", "start_byte": 0, "end_byte": 16, "alignment_bytes": 16},
    {"id": "heap", "start_byte": 16, "end_byte": 48, "alignment_bytes": 16},
]
AFTER = [
    {"id": "heap-moved", "start_byte": 0, "end_byte": 32, "alignment_bytes": 32},
    {"id": "code-moved", "start_byte": 64, "end_byte": 80, "alignment_bytes": 16},
]
MIGRATION = [
    {"from": "code", "to": "code-moved", "start_byte": 64},
    {"from": "heap", "to": "heap-moved", "start_byte": 0},
]


def oracle(before: list, after: list, migration: list) -> str:
    """Independent sorted-multiset reading of bijection, length and offset."""
    before_by_id = {row["id"]: row for row in before}
    after_by_id = {row["id"]: row for row in after}
    if sorted(row["from"] for row in migration) != sorted(before_by_id):
        return "FAIL"
    if sorted(row["to"] for row in migration) != sorted(after_by_id):
        return "FAIL"
    for row in migration:
        old, new = before_by_id[row["from"]], after_by_id[row["to"]]
        if new["start_byte"] != row["start_byte"]:
            return "FAIL"
        if new["end_byte"] - new["start_byte"] != old["end_byte"] - old["start_byte"]:
            return "FAIL"
    return "PASS"


def layout(partitions: list, *, extent: int, subject_id: str = "space-root",
           limits: dict | None = None) -> dict:
    subject = NamespaceObject.create(subject_id, "SPACE", {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": extent, "partitions_digest": digest(partitions)})
    evidence = canonical_bytes({
        "schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [subject.to_dict()], "inputs": {"partitions": partitions}})
    policy = space_layout.space_layout_policy(trust_roots=["layout-root"])
    request = space_layout.space_layout_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    certificate = space_layout.build_space_layout_certificate(
        request, evidence, policy=policy)
    return {"request": request, "policy": policy, "certificate": certificate,
            "subject": subject, "evidence": evidence}


def selected(before: list | None = None, after: list | None = None,
             migration: list | None = None, *, before_extent: int = 48,
             after_extent: int = 128, before_limits: dict | None = None,
             after_limits: dict | None = None, before_subject: str = "space-root",
             include_evidence: bool = True, **limits: int):
    old = layout(BEFORE if before is None else before, extent=before_extent,
                 subject_id=before_subject, limits=before_limits)
    new = layout(AFTER if after is None else after, extent=after_extent,
                 limits=after_limits)
    migration = MIGRATION if migration is None else migration

    def child(side: dict) -> dict:
        return {"request": side["request"], "policy": side["policy"],
                "certificate": base64.b64encode(side["certificate"]).decode("ascii")}

    evidence = canonical_bytes({
        "schema_version": space_migration.EVIDENCE_VERSION,
        "before": child(old), "after": child(new), "migration": migration,
    }) if include_evidence else None
    policy = space_migration.space_migration_policy(trust_roots=["migration-root"])
    request = space_migration.space_migration_request(
        subject_id="space-root", object_digest=new["subject"].digest,
        collection_digest=composition_digest([new["subject"]]),
        before_request_digest=digest(old["request"]),
        before_policy_digest=digest(old["policy"]),
        before_certificate_digest="sha256:" + hashlib.sha256(old["certificate"]).hexdigest(),
        after_request_digest=digest(new["request"]),
        after_policy_digest=digest(new["policy"]),
        after_certificate_digest="sha256:" + hashlib.sha256(new["certificate"]).hexdigest(),
        evidence_ref=digest(json.loads(evidence)) if evidence is not None
        else "sha256:" + "0" * 64,
        policy=policy, limits=limits)
    return request, policy, evidence, old, new


def child_status(side: dict) -> str:
    return json.loads(side["certificate"])["result"]["status"]


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = space_migration.build_space_migration_certificate(
        request, evidence, policy=policy)
    result = space_migration.recheck_space_migration_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def test_inventory_selects_space_migration_for_space_dynamics():
    slot = get_slot("SPACE", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "SPACE-2.1"
    assert slot.mechanized_route["artifact_coordinate"] == "SPACE-2.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.space_migration.recheck_space_migration_certificate")


def test_length_preserving_bijection_passes_and_rechecks_from_decoded_bytes(tmp_path):
    assert oracle(BEFORE, AFTER, MIGRATION) == "PASS"
    request, policy, evidence, old, new = selected()
    assert child_status(old) == child_status(new) == "PASS"
    certificate = space_migration.build_space_migration_certificate(
        request, evidence, policy=policy)
    (tmp_path / "certificate.json").write_bytes(certificate)
    reread = canonical_bytes(json.loads((tmp_path / "certificate.json").read_bytes()))
    assert reread == certificate
    result = space_migration.recheck_space_migration_certificate(
        reread, expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))
    assert result["status"] == "PASS"
    assert result["partition_migration"] == "PASS"
    for field in ("host_allocation", "data_movement", "physical_non_leakage",
                  "whole_space_dynamics", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"


def _shift(rows: list, offset: int) -> list:
    return [{**row, "start_byte": row["start_byte"] + offset,
             "end_byte": row["end_byte"] + offset} for row in rows]


MUTANTS = {
    # Two equal-length before partitions mapped onto the only after partition:
    # total, surjective, offset- and length-correct, but not injective.
    "not-injective": ([
        {"id": "code", "start_byte": 0, "end_byte": 16, "alignment_bytes": 16},
        {"id": "data", "start_byte": 16, "end_byte": 32, "alignment_bytes": 16}],
        [{"id": "code-moved", "start_byte": 64, "end_byte": 80, "alignment_bytes": 16}], [
        {"from": "code", "to": "code-moved", "start_byte": 64},
        {"from": "data", "to": "code-moved", "start_byte": 64}]),
    # A before partition has no image: not total.
    "before-partition-dropped": (BEFORE, AFTER[:1], MIGRATION[1:]),
    # An after partition has no preimage: not surjective.
    "after-partition-appears": (BEFORE, [*AFTER,
        {"id": "stack", "start_byte": 96, "end_byte": 128, "alignment_bytes": 32}],
        MIGRATION),
    # The mapped after partition is shorter than its before partition.
    "length-shrinks": (BEFORE, [AFTER[0],
        {"id": "code-moved", "start_byte": 64, "end_byte": 72, "alignment_bytes": 8}],
        MIGRATION),
    # The after layout places the partition elsewhere than the declared remap.
    "offset-not-as-remapped": (BEFORE, AFTER, [
        {"from": "code", "to": "code-moved", "start_byte": 96}, MIGRATION[1]]),
    # The map names a partition that the before layout does not retain.
    "unknown-before-partition": (BEFORE, AFTER, [
        {"from": "ghost", "to": "code-moved", "start_byte": 64}, MIGRATION[1]]),
}


# Each mutant must be refuted by the property it names, not an incidental one.
MUTANT_REASONS = {
    "not-injective": "not injective",
    "before-partition-dropped": "omits a before partition",
    "after-partition-appears": "outside the migration map",
    "length-shrinks": "preserve partition byte length",
    "offset-not-as-remapped": "offset differs",
    "unknown-before-partition": "not a retained before partition",
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_passing_layouts_with_wrong_migration_fail(name):
    before, after, migration = MUTANTS[name]
    assert oracle(before, after, migration) == "FAIL"
    request, policy, evidence, old, new = selected(before, after, migration)
    assert child_status(old) == child_status(new) == "PASS"
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert MUTANT_REASONS[name] in result["evaluation"]["details"]


def test_seeded_random_relocations_agree_with_independent_oracle():
    rng = random.Random(20261001)
    seen = {"PASS": 0, "FAIL": 0}
    for _ in range(24):
        lengths = [rng.choice([8, 16, 32]) for _ in range(rng.randint(1, 3))]
        before, cursor = [], 0
        for index, length in enumerate(lengths):
            before.append({"id": "p" + str(index), "start_byte": cursor,
                           "end_byte": cursor + length, "alignment_bytes": 8})
            cursor += length
        order = list(range(len(before)))
        rng.shuffle(order)
        after, migration, cursor = [], [], 256
        for index in order:
            length = lengths[index]
            if rng.random() < 0.2:
                length = rng.choice([8, 16, 32])
            after.append({"id": "q" + str(index), "start_byte": cursor,
                          "end_byte": cursor + length, "alignment_bytes": 8})
            declared = cursor if rng.random() > 0.15 else cursor + 8
            migration.append({"from": "p" + str(index), "to": "q" + str(index),
                              "start_byte": declared})
            cursor += 32
        if rng.random() < 0.15:
            migration = migration[1:]
        expected = oracle(before, after, migration)
        request, policy, evidence, old, new = selected(
            before, after, migration, before_extent=128, after_extent=512)
        assert child_status(old) == child_status(new) == "PASS"
        assert replay(request, policy, evidence)[1]["status"] == expected
        seen[expected] += 1
    assert seen["PASS"] > 0 and seen["FAIL"] > 0


def test_identity_migration_of_the_same_layout_passes():
    identity = [{"from": row["id"], "to": row["id"], "start_byte": row["start_byte"]}
                for row in BEFORE]
    assert oracle(BEFORE, BEFORE, identity) == "PASS"
    request, policy, evidence, _, _ = selected(BEFORE, BEFORE, identity, after_extent=48)
    assert replay(request, policy, evidence)[1]["status"] == "PASS"


def test_child_unknown_makes_parent_unknown():
    request, policy, evidence, _, new = selected(after_limits={"max_operations": 1})
    assert child_status(new) == "UNKNOWN"
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    request, policy, evidence, old, _ = selected(before_limits={"max_items": 1})
    assert child_status(old) == "UNKNOWN"
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_child_fail_makes_parent_fail_even_beside_unknown():
    overlapping = [AFTER[0], {"id": "code-moved", "start_byte": 16, "end_byte": 32,
                              "alignment_bytes": 16}]
    migration = [{"from": "code", "to": "code-moved", "start_byte": 16}, MIGRATION[1]]
    assert oracle(BEFORE, overlapping, migration) == "PASS"
    request, policy, evidence, _, new = selected(BEFORE, overlapping, migration)
    assert child_status(new) == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"
    request, policy, evidence, old, new = selected(
        BEFORE, overlapping, migration, before_limits={"max_operations": 1})
    assert (child_status(old), child_status(new)) == ("UNKNOWN", "FAIL")
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_rehashed_child_verdict_and_other_subject_child_fail():
    request, policy, evidence, _, new = selected()
    altered = json.loads(new["certificate"])
    altered["result"]["status"] = "FAIL"
    altered.pop("digest")
    altered["digest"] = digest(altered)
    altered_bytes = canonical_bytes(altered)
    bundle = json.loads(evidence)
    bundle["after"]["certificate"] = base64.b64encode(altered_bytes).decode("ascii")
    altered_request = deepcopy(request)
    altered_request["after_certificate_digest"] = (
        "sha256:" + hashlib.sha256(altered_bytes).hexdigest())
    altered_request["evidence_ref"] = digest(bundle)
    assert replay(altered_request, policy, canonical_bytes(bundle))[1]["status"] == "FAIL"
    request, policy, evidence, old, _ = selected(before_subject="other-space")
    assert child_status(old) == "PASS"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_missing_evidence_and_exhausted_parent_limits_are_unknown():
    request, policy, _, _, _ = selected(include_evidence=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"
    for bound in ("max_operations", "max_items", "max_evidence_bytes"):
        request, policy, evidence, _, _ = selected(**{bound: 1})
        assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN", bound


def test_one_bit_certificate_tamper_is_refused():
    request, policy, evidence, _, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    for position in (0, len(certificate) // 3, len(certificate) // 2, len(certificate) - 2):
        tampered = bytearray(certificate)
        tampered[position] ^= 0x01
        with pytest.raises(space_migration.SpaceMigrationError):
            space_migration.recheck_space_migration_certificate(
                bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_and_verdict_are_refused():
    request, policy, evidence, _, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    for field, value in (("subject_id", "other-space"),
                         ("before_request_digest", "sha256:" + "1" * 64),
                         ("after_policy_digest", "sha256:" + "2" * 64)):
        changed = deepcopy(request)
        changed[field] = value
        with pytest.raises(space_migration.SpaceMigrationError):
            space_migration.recheck_space_migration_certificate(
                certificate, expected_request=changed, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(space_migration.SpaceMigrationError):
        space_migration.recheck_space_migration_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(space_migration.SpaceMigrationError):
        space_migration.recheck_space_migration_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    wrong_kind = deepcopy(request)
    wrong_kind["object_kind"] = "EVENT"
    with pytest.raises(space_migration.SpaceMigrationError):
        space_migration.build_space_migration_certificate(wrong_kind, evidence, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/space_migration.py", "domains/contracts/space_layout.py",
    "domains/contracts/retained_selection.py", "standard/CURRENT_SPACE_MIGRATION.md",
    "standard/CURRENT_SPACE_LAYOUT.md", "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(space_migration.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged migration dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        space_migration.recheck_space_migration_certificate(
            certificate, expected_request=request, policy=policy)


def test_public_route_command_and_polish_keep_dynamics_boundary(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence, _, new = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=space_migration.SEMANTIC_VERSION,
        objective=space_migration.COORDINATE, represented_kind="SPACE",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["data_movement"] == "NOT_ESTABLISHED"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", space_migration.SEMANTIC_VERSION,
        "--objective", space_migration.COORDINATE, "--represented-kind", "SPACE",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(new["evidence"])["objects"],
              "certificates": {digest(json.loads(certificate)): certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "space-root", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "space-root", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected logical migration only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][1]["objectives"] = [{
        "semantic_version": space_migration.SEMANTIC_VERSION,
        "coordinate": space_migration.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": digest(json.loads(certificate))}]
    polished = assess_polish(canonical_bytes(bundle),
                             request_bytes=canonical_bytes(selected_request))
    assert polished["objectives"][0]["status"] == "PASS", polished["objectives"][0]
    assert polished["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert polished["status"] == "UNKNOWN" and polished["polished"] is False
