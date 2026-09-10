"""Retained formation evidence never substitutes for Verifier Standard (VSTD) axes."""

from __future__ import annotations

import importlib
from copy import deepcopy
from dataclasses import replace
from typing import Any

import pytest

from verifier.interoperability import formation_storage as storage
from verifier.interoperability.formation_producer import produce_formation_certificate
from verifier.interoperability.formation_wire import (
    CERTIFICATE_SCHEMA, SUBJECT_SCHEMA, RESIDUAL_OBLIGATIONS, profile_bytes, profile_digest,
)
from verifier.interoperability.network import (
    AUTHORITY_AXIOM_AGENCY, AUTHORITY_AXIOM_AGENCY_VERSION, CensusEntry,
    NetworkError, ObjectRecord, SelfDerivationRecord, SiloCommit, assess_silo, authority_axiom_agency_digest,
    canonical_bytes, digest_bytes,
)


def test_stored_formation_inspector_is_available() -> None:
    module = importlib.import_module("verifier.interoperability.formation_storage")
    assert callable(module.inspect_silo_formation)


def specimen() -> tuple[SiloCommit, dict[str, bytes]]:
    ground = b"opaque declared ground; not source derivation evidence"
    subject = canonical_bytes({
        "schema_version": SUBJECT_SCHEMA, "profile_digest": profile_digest(),
        "context": {
            "ground_artifact_digest": digest_bytes(ground),
            "authority_axiom_agency_digest": authority_axiom_agency_digest(),
        },
        "nodes": [{"tag": "ATOM", "payload_digest": digest_bytes(b"unretrieved atom")}],
        "root": 0,
    })
    payloads = {
        "ground.txt": (ground, "text/plain", "opaque-ground", "NOT_DECLARED"),
        "subject.json": (subject, "application/json", "typed-formation-subject", SUBJECT_SCHEMA),
        "certificate.json": (produce_formation_certificate(subject), "application/json",
                             "typed-formation-certificate", CERTIFICATE_SCHEMA),
        "profile.json": (profile_bytes(), "application/json", "typed-formation-profile", storage.PROFILE_SCHEMA),
        "unrelated.txt": (b"dispensable but retained", "text/plain", "opaque", "NOT_DECLARED"),
    }
    census = tuple(CensusEntry(path, ObjectRecord.from_payload(*values),
                              "NECESSARY" if path == "ground.txt" else "DISPENSABLE")
                   for path, values in payloads.items())
    witness = SelfDerivationRecord(
        "ground.txt", ("ground.txt",), "ground.txt", ("ground.txt",), "DERIVES",
        False, False, False, False, "ground.txt", "ground.txt", "ground.txt", "ground.txt",
        ("source bridge not established",),
    )
    commit = SiloCommit(
        "publisher:sha256:" + "a" * 64, (), census, ("ground.txt",), (), (),
        ("source bridge not established",), (), "DERIVATIONAL_COVERAGE", (),
        AUTHORITY_AXIOM_AGENCY, AUTHORITY_AXIOM_AGENCY_VERSION, authority_axiom_agency_digest(),
        None, witness, "2026-09-09T00:00:00Z",
    )
    return commit, {digest_bytes(values[0]): values[0] for values in payloads.values()}


def inspect(commit: SiloCommit, evidence: dict[str, bytes], **paths: str) -> dict[str, Any]:
    return storage.inspect_silo_formation(canonical_bytes(commit.to_dict()), evidence, **{
        "subject_path": "subject.json", "certificate_path": "certificate.json",
        "profile_path": "profile.json", "ground_path": "ground.txt", **paths,
    })


def record(commit: SiloCommit, path: str) -> ObjectRecord:
    return next(entry.object_record for entry in commit.census if entry.path == path)


def substitute(commit: SiloCommit, evidence: dict[str, bytes], path: str, payload: bytes) -> SiloCommit:
    old = record(commit, path)
    replacement = replace(old, object_digest=digest_bytes(payload), size_bytes=len(payload))
    evidence.pop(old.object_digest, None)
    evidence[replacement.object_digest] = payload
    return replace(commit, census=tuple(
        replace(entry, object_record=replacement) if entry.path == path else entry for entry in commit.census
    ))


def rebind_subject(commit: SiloCommit, evidence: dict[str, bytes], subject: dict[str, Any]) -> SiloCommit:
    payload = canonical_bytes(subject)
    commit = substitute(commit, evidence, "subject.json", payload)
    certificate = {
        "schema_version": CERTIFICATE_SCHEMA, "subject_digest": digest_bytes(payload),
        "profile_digest": subject["profile_digest"], "root": subject["root"],
        "steps": [{"node": 0, "rule": "ATOM", "premises": []}],
    }
    return substitute(commit, evidence, "certificate.json", canonical_bytes(certificate))


def test_complete_retention_and_checked_formation_are_separate_from_silo_axes() -> None:
    commit, evidence = specimen()
    before = deepcopy((commit.to_dict(), evidence))
    result = inspect(commit, evidence)
    assert result["coordinate_binding"] == "BOUND"
    assert result["snapshot_retention"] == "COMPLETE"
    assert result["agency_declaration"] == "MATCHED"
    assert result["formation_report"]["status"] == "CHECKED"
    assert result["formation_report"]["observation"]["dependency_nodes"] == [0]
    assert result["commit_digest"] == commit.canonical_digest()
    assert result["coordinates"]["subject"] == {
        "path": "subject.json", "object_digest": record(commit, "subject.json").object_digest,
    }
    assert result["residual_obligations"] == list(RESIDUAL_OBLIGATIONS)
    assert result["formation_report"]["residual_obligations"] == list(RESIDUAL_OBLIGATIONS)
    assert result["reason_codes"] == []
    assert not {"reconstructibility", "self_derivability", "derivation_closure", "completeness",
                "silo_grounding", "authority_axiom_agency", "trust"} & result.keys()
    assert (commit.to_dict(), evidence) == before


@pytest.mark.parametrize("failure,retention", [("missing", "INCOMPLETE"), ("substituted", "INVALID"),
                                               ("wrong_type", "INVALID"), ("wrong_size", "INVALID")])
def test_unrelated_retention_failure_preserves_fresh_checked_formation(failure: str, retention: str) -> None:
    commit, evidence = specimen()
    item = record(commit, "unrelated.txt")
    if failure == "missing":
        del evidence[item.object_digest]
    elif failure == "substituted":
        evidence[item.object_digest] = b"not the retained object"
    elif failure == "wrong_type":
        evidence[item.object_digest] = None
    else:
        commit = replace(commit, census=tuple(
            replace(entry, object_record=replace(item, size_bytes=item.size_bytes + 1))
            if entry.path == "unrelated.txt" else entry for entry in commit.census
        ))
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == retention
    assert result["coordinate_binding"] == "BOUND"
    assert result["formation_report"]["status"] == "CHECKED"


def test_known_digest_mismatch_dominates_another_missing_object() -> None:
    commit, evidence = specimen()
    evidence.pop(record(commit, "ground.txt").object_digest)
    evidence[record(commit, "unrelated.txt").object_digest] = b"substituted"
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == "INVALID"
    assert result["coordinate_binding"] == "UNKNOWN"
    assert result["formation_report"]["status"] == "CHECKED"
    assert {"OBJECT_DIGEST_MISMATCH", "CENSUS_OBJECT_MISSING"} <= set(result["reason_codes"])


@pytest.mark.parametrize("path", ["subject.json", "certificate.json", "profile.json", "ground.txt"])
@pytest.mark.parametrize("failure,status", [("missing", "UNKNOWN"), ("substituted", "INVALID"),
                                           ("wrong_type", "INVALID")])
def test_selected_payload_refuses_missing_substituted_and_malformed_bytes(path: str, failure: str, status: str) -> None:
    commit, evidence = specimen()
    digest = record(commit, path).object_digest
    if failure == "missing":
        del evidence[digest]
    else:
        evidence[digest] = b"substituted" if failure == "substituted" else None
    result = inspect(commit, evidence)
    assert result["coordinate_binding"] == status
    if path in {"subject.json", "certificate.json"}:
        assert result["formation_report"] is None
    else:
        assert result["formation_report"]["status"] == "CHECKED"


@pytest.mark.parametrize("path", ["subject.json", "certificate.json", "profile.json"])
@pytest.mark.parametrize("field,value", [("artifact_kind", "foreign-kind"),
                                         ("declared_schema_id", "FOREIGN-SCHEMA"),
                                         ("media_type", "text/plain")])
def test_foreign_role_labels_do_not_erase_payload_semantics(path: str, field: str, value: str) -> None:
    commit, evidence = specimen()
    commit = replace(commit, census=tuple(
        replace(entry, object_record=replace(entry.object_record, **{field: value}))
        if entry.path == path else entry for entry in commit.census
    ))
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == "COMPLETE"
    assert result["coordinate_binding"] == "INVALID"
    assert result["formation_report"]["status"] == "CHECKED"


@pytest.mark.parametrize("field", ["ground_artifact_digest", "authority_axiom_agency_digest"])
def test_declared_context_mismatch_does_not_invalidate_finite_construction(field: str) -> None:
    commit, evidence = specimen()
    subject = storage.decode_subject(evidence[record(commit, "subject.json").object_digest])
    subject["context"][field] = digest_bytes(b"different declared context")
    commit = rebind_subject(commit, evidence, subject)
    result = inspect(commit, evidence)
    assert result["coordinate_binding"] == "INVALID"
    assert result["formation_report"]["status"] == "CHECKED"
    assert "AGENCY_NOT_CHECKED" in result["residual_obligations"]


def test_unsupported_profile_is_unknown_when_its_bytes_are_exactly_bound() -> None:
    commit, evidence = specimen()
    foreign = canonical_bytes({"schema_version": "FUTURE-FORMATION-PROFILE"})
    commit = substitute(commit, evidence, "profile.json", foreign)
    subject = storage.decode_subject(evidence[record(commit, "subject.json").object_digest])
    subject["profile_digest"] = digest_bytes(foreign)
    commit = rebind_subject(commit, evidence, subject)
    result = inspect(commit, evidence)
    assert result["coordinate_binding"] == "UNKNOWN"
    assert result["snapshot_retention"] == "COMPLETE"
    assert result["formation_report"]["status"] == "UNKNOWN"


def test_known_profile_coordinate_mismatch_dominates_missing_ground() -> None:
    commit, evidence = specimen()
    commit = substitute(commit, evidence, "profile.json", b"unsupported profile")
    evidence.pop(record(commit, "ground.txt").object_digest)
    result = inspect(commit, evidence)
    assert result["coordinate_binding"] == "INVALID"
    assert result["formation_report"]["status"] == "CHECKED"


@pytest.mark.parametrize("role", ["subject", "certificate"])
def test_publisher_checked_flags_are_invalid_not_accepted(role: str) -> None:
    import json
    commit, evidence = specimen()
    path = role + ".json"
    value = json.loads(evidence[record(commit, path).object_digest])
    value["checked"] = True
    commit = substitute(commit, evidence, path, canonical_bytes(value))
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == "COMPLETE"
    assert result["coordinate_binding"] == "INVALID"
    assert result["formation_report"]["status"] == "INVALID"


@pytest.mark.parametrize("field", ["subject_digest", "profile_digest", "root"])
def test_certificate_coordinate_mismatch_is_invalid(field: str) -> None:
    import json
    commit, evidence = specimen()
    value = json.loads(evidence[record(commit, "certificate.json").object_digest])
    value[field] = 1 if field == "root" else digest_bytes(b"foreign coordinate")
    commit = substitute(commit, evidence, "certificate.json", canonical_bytes(value))
    result = inspect(commit, evidence)
    assert result["coordinate_binding"] == "INVALID"
    assert result["formation_report"]["status"] == "INVALID"


def test_declared_ground_membership_is_required_not_just_a_retained_digest() -> None:
    commit, evidence = specimen()
    result = inspect(commit, evidence, ground_path="unrelated.txt")
    assert result["coordinate_binding"] == "INVALID"
    assert "SELECTED_GROUND_NOT_DECLARED" in result["reason_codes"]
    assert result["formation_report"]["status"] == "CHECKED"


@pytest.mark.parametrize("path", ["absent.json", "../subject.json", "drive-qualified", None])
def test_selected_paths_are_explicit_portable_census_coordinates(path: Any) -> None:
    commit, evidence = specimen()
    if path == "drive-qualified":
        # Generate a synthetic drive path, not a workstation document locator.
        path = chr(90) + ":/subject.json"
    result = inspect(commit, evidence, subject_path=path)
    assert result["coordinate_binding"] == "INVALID"
    assert result["formation_report"] is None
    assert ("SELECTED_PATH_NOT_IN_CENSUS" if path == "absent.json" else
            "SELECTED_PATH_INVALID") in result["reason_codes"]


@pytest.mark.parametrize("version,status", [("FOREIGN-AGENCY", "UNKNOWN"),
                                           (AUTHORITY_AXIOM_AGENCY_VERSION, "INVALID")])
def test_agency_declaration_consistency_is_separate_from_preservation(version: str, status: str) -> None:
    commit, evidence = specimen()
    # Preserve subject/commit equality while making the declaration uninterpretable or inconsistent.
    commit = replace(commit, authority_axiom_agency=("EXIT_COMPOSITION",),
                     authority_axiom_agency_version=version)
    result = inspect(commit, evidence)
    assert result["coordinate_binding"] == status
    assert result["agency_declaration"] == status
    assert result["formation_report"]["status"] == "CHECKED"
    assert "AGENCY_NOT_CHECKED" in result["residual_obligations"]


@pytest.mark.parametrize("actions", [("EXIT_COMPOSITION",), (*AUTHORITY_AXIOM_AGENCY, "NEW_ACTION")])
def test_self_consistent_foreign_action_set_does_not_redefine_canonical_agency(actions: tuple[str, ...]) -> None:
    commit, evidence = specimen()
    digest = authority_axiom_agency_digest(actions)
    commit = replace(commit, authority_axiom_agency=actions, authority_axiom_agency_digest=digest)
    subject = storage.decode_subject(evidence[record(commit, "subject.json").object_digest])
    subject["context"]["authority_axiom_agency_digest"] = digest
    commit = rebind_subject(commit, evidence, subject)
    result = inspect(commit, evidence)
    assert result["coordinate_binding"] == "UNKNOWN"
    assert result["agency_declaration"] == "UNKNOWN"
    assert result["formation_report"]["status"] == "CHECKED"


@pytest.mark.parametrize("payload,status", [
    (b'{"schema_version":"FUTURE-COMMIT"}', "UNKNOWN"),
    (b'{"schema_version":"x","schema_version":"y"}', "INVALID"),
    (b'{ "schema_version":"x"}', "INVALID"),
    (b"[" * 17 + b"0" + b"]" * 17, "UNKNOWN"),
    (b"x" * (storage.MAX_COMMIT_BYTES + 1), "UNKNOWN"),
    (b"null", "INVALID"), (None, "INVALID"),
], ids=["unsupported", "duplicate", "noncanonical", "deep", "oversized", "null", "nonbytes"])
def test_commit_admission_is_bounded_before_recursive_decoding(payload: Any, status: str) -> None:
    _, evidence = specimen()
    result = storage.inspect_silo_formation(payload, evidence, subject_path="subject.json",
        certificate_path="certificate.json", profile_path="profile.json", ground_path="ground.txt")
    assert result["coordinate_binding"] == status
    assert result["commit_digest"] is None
    assert result["formation_report"] is None


def test_budget_refusal_skips_nonfitting_object_and_preserves_checked_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    commit, evidence = specimen()
    # Choose a large payload whose digest sorts first, forcing the skip branch before selected bytes.
    selected_minimum = min(evidence)
    for index in range(1000):
        payload = str(index).encode() + b"x" * 4000
        if digest_bytes(payload) < selected_minimum:
            break
    else:
        pytest.fail("bounded fixture search failed")
    commit = substitute(commit, evidence, "unrelated.txt", payload)
    monkeypatch.setattr(storage, "MAX_SNAPSHOT_BYTES", 3000)
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == "UNKNOWN"
    assert result["coordinate_binding"] == "BOUND"
    assert result["formation_report"]["status"] == "CHECKED"


def test_evidence_count_bound_refuses_without_callbacks() -> None:
    commit, evidence = specimen()
    for index in range(storage.MAX_EVIDENCE_ENTRIES):
        payload = str(index).encode()
        evidence[digest_bytes(payload)] = payload
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == "UNKNOWN"
    assert result["coordinate_binding"] == "UNKNOWN"
    assert result["reason_codes"] == ["EVIDENCE_ENTRY_LIMIT", "SELECTED_OBJECT_UNAVAILABLE"]


def test_mapping_subclass_is_not_called() -> None:
    class Foreign(dict):
        def __len__(self) -> int:
            raise AssertionError("caller hook must not run")

        def items(self) -> Any:
            raise AssertionError("caller hook must not run")

    commit, evidence = specimen()
    result = inspect(commit, Foreign(evidence))
    assert result["coordinate_binding"] == "UNKNOWN"
    assert result["snapshot_retention"] == "UNKNOWN"


def test_value_hooks_are_not_called() -> None:
    class Foreign:
        def __bytes__(self) -> bytes:
            raise AssertionError("caller hook must not run")

        def __len__(self) -> int:
            raise AssertionError("caller hook must not run")

    commit, evidence = specimen()
    evidence[record(commit, "unrelated.txt").object_digest] = Foreign()
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == "INVALID"
    assert result["formation_report"]["status"] == "CHECKED"


def test_fresh_check_uses_captured_bytes_not_mutated_caller_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    commit, evidence = specimen()
    real_check = storage.check_formation

    def mutation(subject: bytes, certificate: bytes) -> dict[str, Any]:
        evidence.clear()
        return real_check(subject, certificate)

    monkeypatch.setattr(storage, "check_formation", mutation)
    result = inspect(commit, evidence)
    assert evidence == {}
    assert result["snapshot_retention"] == "COMPLETE"
    assert result["coordinate_binding"] == "BOUND"
    assert result["formation_report"]["status"] == "CHECKED"


@pytest.mark.parametrize("path", ["subject.json", "certificate.json", "profile.json", "ground.txt"])
def test_selected_size_mismatch_preserves_identity_bound_fresh_formation(path: str) -> None:
    commit, evidence = specimen()
    commit = replace(commit, census=tuple(
        replace(entry, object_record=replace(entry.object_record, size_bytes=entry.object_record.size_bytes + 1))
        if entry.path == path else entry for entry in commit.census
    ))
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == "INVALID"
    assert result["coordinate_binding"] == "INVALID"
    assert result["formation_report"]["status"] == "CHECKED"


def test_missing_certificate_does_not_erase_available_context_mismatch() -> None:
    commit, evidence = specimen()
    subject = storage.decode_subject(evidence[record(commit, "subject.json").object_digest])
    subject["context"]["ground_artifact_digest"] = digest_bytes(b"foreign ground")
    commit = rebind_subject(commit, evidence, subject)
    evidence.pop(record(commit, "certificate.json").object_digest)
    result = inspect(commit, evidence)
    assert result["coordinate_binding"] == "INVALID"
    assert result["formation_report"] is None
    assert "SUBJECT_GROUND_CONTEXT_MISMATCH" in result["reason_codes"]


def test_malformed_certificate_does_not_become_unknown_when_unrelated_object_missing() -> None:
    commit, evidence = specimen()
    commit = substitute(commit, evidence, "certificate.json", b"malformed")
    evidence.pop(record(commit, "unrelated.txt").object_digest)
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == "INCOMPLETE"
    assert result["coordinate_binding"] == "INVALID"
    assert result["formation_report"]["status"] == "INVALID"


def test_case_colliding_commit_refused_before_evidence_admission(monkeypatch: pytest.MonkeyPatch) -> None:
    commit, evidence = specimen()
    value = commit.to_dict()
    alias = deepcopy(value["census"][0])
    alias["path"] = alias["path"].upper()
    value["census"].insert(0, alias)

    def forbidden(_: Any) -> Any:
        pytest.fail("malformed commit must refuse before evidence observation")

    monkeypatch.setattr(storage, "_snapshot", forbidden)
    result = storage.inspect_silo_formation(canonical_bytes(value), evidence,
        subject_path="subject.json", certificate_path="certificate.json",
        profile_path="profile.json", ground_path="ground.txt")
    assert result["coordinate_binding"] == "INVALID"
    assert result["commit_digest"] is None


def test_same_digest_aliases_are_rehashed_once_and_each_census_size_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    commit, evidence = specimen()
    item = record(commit, "unrelated.txt")
    commit = replace(commit, census=(*commit.census, CensusEntry("alias.txt", item, "DISPENSABLE")))
    hashed: list[bytes] = []
    real_digest = storage.digest_bytes

    def counted(payload: bytes) -> str:
        hashed.append(payload)
        return real_digest(payload)

    monkeypatch.setattr(storage, "digest_bytes", counted)
    result = inspect(commit, evidence)
    assert result["snapshot_retention"] == "COMPLETE"
    assert hashed.count(evidence[item.object_digest]) == 1
    commit = replace(commit, census=tuple(
        replace(entry, object_record=replace(item, size_bytes=item.size_bytes + 1))
        if entry.path == "alias.txt" else entry for entry in commit.census
    ))
    assert inspect(commit, evidence)["snapshot_retention"] == "INVALID"


def test_ground_can_alias_profile_but_this_does_not_prove_ground_origin() -> None:
    commit, evidence = specimen()
    commit = replace(commit, ground_paths=("ground.txt", "profile.json"))
    subject = storage.decode_subject(evidence[record(commit, "subject.json").object_digest])
    subject["context"]["ground_artifact_digest"] = profile_digest()
    commit = rebind_subject(commit, evidence, subject)
    result = inspect(commit, evidence, ground_path="profile.json")
    assert result["coordinate_binding"] == "BOUND"
    assert result["formation_report"]["status"] == "CHECKED"
    assert "GROUND_DERIVATION_NOT_ESTABLISHED" in result["residual_obligations"]


def test_existing_six_axis_assessment_is_unchanged_by_inspection() -> None:
    commit, evidence = specimen()

    class RetainedStore:
        def read_object(self, item: ObjectRecord) -> bytes:
            payload = evidence.get(item.object_digest)
            if payload is None or len(payload) != item.size_bytes or digest_bytes(payload) != item.object_digest:
                raise NetworkError("object unavailable")
            return payload

    before = assess_silo(commit, RetainedStore()).to_dict()
    result = inspect(commit, evidence)
    after = assess_silo(commit, RetainedStore()).to_dict()
    assert result["formation_report"]["status"] == "CHECKED"
    assert before == after
    assert after["completeness"] == "UNKNOWN"
    assert after["authority_axiom_agency"] == "UNKNOWN"
