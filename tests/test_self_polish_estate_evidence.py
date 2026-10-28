"""Adversarial replay tests for the candidate-estate semantic denominator.

Edwards-curve Digital Signature Algorithm with a 255-bit field (Ed25519)
fixtures authenticate only synthetic test subjects; they confer no real-world
authority or Verifier Standard (VSTD) closure.
"""
from __future__ import annotations

from copy import deepcopy
import dataclasses

import pytest

pytest.importorskip(
    "cryptography",
    reason=(
        "OPTIONAL_DEPENDENCY_ABSENT: estate evidence receipts use Ed25519 "
        "and require the seal extra (cryptography)"
    ),
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifier.runtime import core_application_authority as binding
from verifier.runtime import self_polish_estate
from verifier.runtime import self_polish_estate_authority
from verifier.runtime import self_polish_estate_evidence as evidence
from verifier.runtime import self_polish_estate_native_evidence as native_evidence


NOW = 1_800_000_000


@pytest.fixture(autouse=True)
def _trusted_assessment_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence.time, "time", lambda: NOW)


def _digest(seed: int) -> str:
    return "sha256:" + f"{seed:064x}"


def _redigest(document: dict, field: str) -> dict:
    body = {key: value for key, value in document.items() if key != field}
    document[field] = evidence.value_digest(body)
    return document


def _redigest_estate_census(selected: dict) -> dict:
    for name in ("pre_source_census", "post_source_census"):
        _redigest(selected[name], "census_digest")
    selected["source_coordinate"]["candidate_source_census_digest"] = (
        selected["pre_source_census"]["census_digest"]
    )
    return _redigest(selected, "estate_digest")


def _candidate(category: str, index: int) -> dict:
    identifier = (
        "candidate-source-file:src/verifier/example.py"
        if category == "candidate_source_file"
        else "unresolved-surface:external-plugin-estate"
        if category == "unresolved_surface"
        else f"candidate:{index:02d}:{category}"
    )
    metadata = (
        {"size": 1, "provenance": "GIT_TRACKED", "git_mode": "100644"}
        if category == "candidate_source_file"
        else {"fixture_index": index, "qualname": "example", "line": 1}
        if category == "python_function"
        else {
            "surface_id": "external-plugin-estate",
            "enumeration_status": "UNKNOWN",
            "reason": "Synthetic declared boundary surface.",
        }
        if category == "unresolved_surface"
        else {"fixture_index": index}
    )
    source_path = (
        "src/verifier/runtime/public_cli.py"
        if category in {"public_cli_route", "public_cli_preparser_route"}
        else "src/verifier/schemas/example.json"
        if category == "schema"
        else "src/verifier/example.py"
    )
    body = {
        "candidate_id": identifier,
        "category": category,
        "candidate_type": (
            "CANDIDATE_SOURCE_FILE"
            if category == "candidate_source_file"
            else "EXPLICIT_UNKNOWN_SURFACE"
            if category == "unresolved_surface"
            else "SYNTHETIC_MECHANICAL_CANDIDATE"
        ),
        "source_refs": [{"path": source_path, "sha256": _digest(1)}],
        "mechanical_status": "PASS",
        "applicability_status": "UNKNOWN",
        "authority_status": "NOT_ESTABLISHED",
        "evidence_status": "NOT_ESTABLISHED",
        "semantic_status": "NOT_ESTABLISHED",
        "metadata": metadata,
    }
    return {**body, "candidate_digest": evidence.value_digest(body)}


@pytest.fixture
def estate() -> dict:
    files = [{
        "path": "src/verifier/example.py",
        "size": 1,
        "sha256": _digest(1),
        "provenance": "GIT_TRACKED",
        "git_mode": "100644",
    }]
    empty_digest = evidence.value_digest([])
    census_body = {
        "schema_version": self_polish_estate.CANDIDATE_SOURCE_CENSUS_SCHEMA,
        "file_count": 1,
        "total_bytes": 1,
        "provenance_counts": {
            "GIT_TRACKED": 1,
            "WORKTREE_UNTRACKED_NONIGNORED": 0,
        },
        "git_index_digest": _digest(10),
        "git_status_digest": _digest(11),
        "files": files,
        "ignored_scan": {
            "ignored_path_count": 0,
            "ignored_path_set_digest": empty_digest,
            "exclusion_taxonomy_digest": (
                self_polish_estate.IGNORED_EXCLUSION_TAXONOMY_DIGEST
            ),
            "excluded_cache_build_path_count": 0,
            "excluded_cache_build_paths_digest": empty_digest,
            "inert_ignored_path_count": 0,
            "inert_ignored_paths_digest": empty_digest,
            "excluded_bytes_status": "NOT_VERIFIED",
        },
    }
    census = {
        **census_body,
        "census_digest": evidence.value_digest(census_body),
    }
    candidates = sorted(
        (_candidate(category, index) for index, category in enumerate(
            self_polish_estate.REQUIRED_CATEGORIES, 1)),
        key=lambda row: row["candidate_id"],
    )
    summaries = []
    for category in self_polish_estate.REQUIRED_CATEGORIES:
        selected = [row for row in candidates if row["category"] == category]
        summaries.append({
            "category": category,
            "mechanical_status": "PASS",
            "candidate_count": len(selected),
            "candidate_digest": evidence.value_digest(selected),
            "semantic_status": "NOT_ESTABLISHED",
        })
    crosswalk = {
        "status": "NOT_ESTABLISHED",
        "structural_membership_count": 52,
        "route_tier1_membership_count": 45,
        "shared_identity_count": 27,
        "structural_only_identity_count": 25,
        "route_only_identity_count": 18,
        "structural_identity_digest": _digest(20),
        "route_identity_digest": _digest(21),
        "shared_identity_digest": _digest(22),
        "claim_boundary": "Synthetic crosswalk fixture; no semantic closure.",
    }
    coordinate = {
        "repository": "https://example.invalid/verifier.git",
        "revision": "a" * 40,
        "candidate_source_file_count": 1,
        "candidate_source_byte_count": 1,
        "candidate_source_census_digest": census["census_digest"],
        "tracked_file_count": 1,
        "untracked_nonignored_file_count": 0,
    }
    body = {
        "schema_version": self_polish_estate.ESTATE_SCHEMA,
        "mechanical_census_status": "PASS",
        "semantic_applicability_status": "NOT_ESTABLISHED",
        "full_estate_closure": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "source_coordinate": coordinate,
        "pre_source_census": census,
        "post_source_census": deepcopy(census),
        "required_categories": list(self_polish_estate.REQUIRED_CATEGORIES),
        "category_summaries": summaries,
        "structural_route_crosswalk": crosswalk,
        "candidate_count": len(candidates),
        "candidate_universe_digest": evidence.value_digest(candidates),
        "candidates": candidates,
        "applicability_ledger": None,
        "claim_boundary": self_polish_estate.CLAIM_BOUNDARY,
    }
    return {**body, "estate_digest": evidence.value_digest(body)}


def _ledger(selected_estate: dict, *, all_unknown: bool = False) -> dict:
    ledger = self_polish_estate.applicability_ledger_template(selected_estate)
    if not all_unknown:
        candidates = {
            row["candidate_id"]: row for row in selected_estate["candidates"]
        }
        for index, row in enumerate(ledger["rows"]):
            row.update({
                "applicability_status": (
                    native_evidence.native_applicability_status(
                        candidates[row["candidate_id"]]
                    )
                ),
                "authority_status": "PASS",
                "authority_digest": _digest(100 + index),
                "justification": "Synthetic independently replayed disposition.",
            })
    return _redigest(ledger, "ledger_digest")


def _authority_subject(selected_estate: dict, ledger: dict) -> dict:
    crosswalk = selected_estate["structural_route_crosswalk"]
    coordinate_digest = evidence.value_digest(selected_estate["source_coordinate"])
    return self_polish_estate_authority.estate_authority_subject(
        source_coordinate_digest=coordinate_digest,
        estate_source_coordinate_digest=coordinate_digest,
        candidate_source_census_digest=selected_estate["pre_source_census"][
            "census_digest"
        ],
        estate_digest=selected_estate["estate_digest"],
        candidate_universe_digest=selected_estate[
            "candidate_universe_digest"
        ],
        required_categories_digest=evidence.value_digest(
            selected_estate["required_categories"]
        ),
        category_summaries_digest=evidence.value_digest(
            selected_estate["category_summaries"]
        ),
        applicability_ledger_digest=ledger["ledger_digest"],
        installed_inventory_digest=_digest(30),
        objective_catalog_digest=_digest(31),
        structural_route_crosswalk_digest=evidence.value_digest(crosswalk),
        structural_identity_digest=crosswalk["structural_identity_digest"],
        route_identity_digest=crosswalk["route_identity_digest"],
        shared_identity_digest=crosswalk["shared_identity_digest"],
    )


def _signed(payload: dict, *, key_id: str,
        private_key: Ed25519PrivateKey) -> dict:
    raw = binding.canonical_bytes(payload)
    return {
        "schema_version": binding.AUTHORITY_SIGNATURE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "payload": payload,
        "payload_digest": binding.bytes_digest(raw),
        "signature": private_key.sign(
            binding.authority_signing_bytes(raw, key_id=key_id)
        ).hex(),
    }


def _selection(operation: str, subject_digest: str, *, token: str,
        revoked: bool = False, stale: bool = False,
        evidence_state: str = "CURRENT") \
        -> binding.QualifiedAuthorityReplaySelection:
    voter_a = Ed25519PrivateKey.generate()
    voter_b = Ed25519PrivateKey.generate()
    status_key = Ed25519PrivateKey.generate()
    keys = {
        "voter-a": ("reviewer-a", voter_a),
        "voter-b": ("reviewer-b", voter_b),
        "status": ("status-operator", status_key),
    }
    public_rows = [{
        "key_id": key_id,
        "actor_id": actor_id,
        "public_key": private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex(),
    } for key_id, (actor_id, private) in keys.items()]
    mechanism = binding.qualified_authority_mechanism_digest(operation)
    operation_revision = _digest(40)
    instruction_revision = _digest(41)
    context_revision = _digest(42)
    policy = {
        "schema_version": binding.AUTHORITY_POLICY_SCHEMA,
        "mechanism_digest": mechanism,
        "policy_id": "estate-evidence-policy-" + token,
        "revision": 1,
        "operation": operation,
        "operation_revision_digest": operation_revision,
        "instruction_revision_digest": instruction_revision,
        "context_revision_digest": context_revision,
        "keys": public_rows,
        "approval_key_ids": ["voter-a", "voter-b"],
        "status_key_id": "status",
        "quorum": 2,
        "effective_from": NOW - 100,
        "effective_until": NOW + 100,
        "max_status_age_seconds": 20,
    }
    policy_bytes = binding.canonical_bytes(policy)
    policy_digest = binding.bytes_digest(policy_bytes)
    body = {
        "schema_version": binding.AUTHORITY_RECEIPT_SCHEMA,
        "mechanism_digest": mechanism,
        "receipt_id": "estate-evidence-receipt-" + token,
        "requester_id": "candidate-producer",
        "policy_digest": policy_digest,
        "operation": operation,
        "operation_revision_digest": operation_revision,
        "instruction_revision_digest": instruction_revision,
        "context_revision_digest": context_revision,
        "subject_digest": subject_digest,
        "decision": "ADMIT",
        "execution_status": "COMPLETED",
        "evidence_state": evidence_state,
        "issued_at": NOW - 10,
        "expires_at": NOW - 1 if stale else NOW + 50,
    }
    body_digest = binding.value_digest(body)
    approvals = []
    for index, key_id in enumerate(("voter-a", "voter-b"), 1):
        actor_id, private = keys[key_id]
        approvals.append(_signed({
            "schema_version": binding.AUTHORITY_APPROVAL_SCHEMA,
            "approval_id": f"approval-{token}-{index}",
            "actor_id": actor_id,
            "receipt_body_digest": body_digest,
            "decision": "APPROVE",
            "issued_at": NOW - 10,
            "expires_at": NOW + 50,
        }, key_id=key_id, private_key=private))
    status_payload = {
        "schema_version": binding.AUTHORITY_STATUS_SCHEMA,
        "policy_digest": policy_digest,
        "receipt_id": body["receipt_id"],
        "sequence": 11,
        "observed_at": NOW - 5,
        "expires_at": NOW + 20,
        "revoked_approval_ids": (
            [f"approval-{token}-1"] if revoked else []
        ),
        "revoked_actor_ids": [],
    }
    receipt = {
        **body,
        "approvals": approvals,
        "status": _signed(
            status_payload, key_id="status", private_key=status_key
        ),
    }
    receipt_bytes = binding.canonical_bytes(receipt)
    return binding.QualifiedAuthorityReplaySelection(
        policy_bytes=policy_bytes,
        expected_policy_digest=policy_digest,
        receipt_bytes=receipt_bytes,
        expected_receipt_digest=binding.bytes_digest(receipt_bytes),
        expected_mechanism_digest=mechanism,
        expected_operation=operation,
        expected_operation_revision_digest=operation_revision,
        expected_instruction_revision_digest=instruction_revision,
        expected_context_revision_digest=context_revision,
        expected_subject_digest=subject_digest,
        evaluation_time=NOW - 1_000_000 if stale else NOW,
        minimum_status_sequence=10,
    )


def _manifest(selected_estate: dict, ledger: dict, subject: dict,
        *, evidence_disposition: str = "PASS") -> dict:
    manifest = evidence.evidence_manifest_template(
        selected_estate,
        evidence.canonical_bytes(ledger),
        expected_ledger_digest=ledger["ledger_digest"],
        estate_authority_subject=subject,
    )
    if ledger["rows"][0]["applicability_status"] == "APPLICABLE":
        manifest["rows"][0].update({
            "evidence_disposition": evidence_disposition,
            "evidence_artifact_digest": (
                _digest(200) if evidence_disposition in {"PASS", "FAIL"}
                else None
            ),
        })
    return _redigest(manifest, "manifest_digest")


def _candidate_selections(manifest: dict) -> dict[str, object]:
    return {
        row["candidate_id"]: _selection(
            evidence.OPERATION,
            evidence.value_digest(evidence.candidate_evidence_subject(
                manifest, row
            )),
            token=f"candidate-{index}",
        )
        for index, row in enumerate(manifest["rows"], 1)
    }


def _replay(selected_estate: dict, ledger: dict, subject: dict,
        manifest: dict, *, estate_selection=None,
        candidate_selections=None, source_root=None,
        evidence_artifacts=None) -> dict:
    return evidence.replay_estate_evidence(
        estate=selected_estate,
        ledger_bytes=evidence.canonical_bytes(ledger),
        expected_ledger_digest=ledger["ledger_digest"],
        manifest_bytes=evidence.canonical_bytes(manifest),
        expected_manifest_digest=manifest["manifest_digest"],
        estate_authority_subject=subject,
        estate_authority_replay=estate_selection,
        candidate_replays=candidate_selections or {},
        source_root=source_root,
        evidence_artifacts=evidence_artifacts,
    )


def _native_artifacts(selected_estate: dict, manifest: dict) -> dict[str, bytes]:
    candidates = {
        row["candidate_id"]: row for row in selected_estate["candidates"]
    }
    artifacts = {}
    for row in manifest["rows"]:
        if row["applicability_disposition"] != "APPLICABLE":
            continue
        artifact = native_evidence.evidence_artifact_template(
            selected_estate, candidates[row["candidate_id"]]
        )
        raw = native_evidence.canonical_bytes(artifact)
        row["evidence_disposition"] = "PASS"
        row["evidence_artifact_digest"] = native_evidence.bytes_digest(raw)
        artifacts[row["candidate_id"]] = raw
    _redigest(manifest, "manifest_digest")
    return artifacts


def _synthetic_native_context(selected: dict, root: object) -> dict:
    return {
        "source_root": root,
        "source_coordinate_digest": evidence.value_digest(
            selected["source_coordinate"]
        ),
        "estate_digest": selected["estate_digest"],
        "candidates": {
            row["candidate_id"]: row for row in selected["candidates"]
        },
    }


def test_manifest_binds_source_census_estate_categories_and_complete_ids(
        estate: dict) -> None:
    ledger = _ledger(estate, all_unknown=True)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)

    assert manifest["source_coordinate"] == estate["source_coordinate"]
    assert manifest["candidate_source_census_digest"] \
        == estate["pre_source_census"]["census_digest"]
    assert manifest["estate_digest"] == estate["estate_digest"]
    assert manifest["candidate_universe_digest"] \
        == estate["candidate_universe_digest"]
    assert manifest["category_summaries_digest"] \
        == evidence.value_digest(estate["category_summaries"])
    assert len(manifest["rows"]) == estate["candidate_count"]
    assert {row["candidate_id"] for row in manifest["rows"]} == {
        row["candidate_id"] for row in estate["candidates"]
    }


def test_native_registry_refuses_meta_condition_as_boundary_not_applicable(
        ) -> None:
    candidate = _candidate("unresolved_surface", 23)
    candidate["metadata"]["surface_id"] = "semantic-applicability"
    candidate["candidate_id"] = "unresolved-surface:semantic-applicability"
    _redigest(candidate, "candidate_digest")
    with pytest.raises(
        native_evidence.NativeEvidenceError,
        match="^NATIVE_BOUNDARY_SURFACE_BINDING_DIFFERS$",
    ):
        native_evidence.native_applicability_status(candidate)


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        ("mode", "ESTATE_SOURCE_FILE_BINDING_DIFFERS"),
        ("taxonomy", "ESTATE_IGNORED_SCAN_BINDING_DIFFERS"),
    ),
)
def test_estate_validation_rejects_invalid_source_mode_or_exclusion_taxonomy(
        estate: dict, mutation: str, error: str) -> None:
    changed = deepcopy(estate)
    for name in ("pre_source_census", "post_source_census"):
        census = changed[name]
        if mutation == "mode":
            census["files"][0]["git_mode"] = "120000"
        else:
            census["ignored_scan"]["exclusion_taxonomy_digest"] = _digest(99)
    _redigest_estate_census(changed)
    with pytest.raises(evidence.EstateEvidenceError, match=f"^{error}$"):
        evidence._validated_estate(changed)


def test_structural_validation_and_caller_pass_do_not_establish_closure(
        estate: dict) -> None:
    ledger = _ledger(estate)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)
    authority_selection = _selection(
        self_polish_estate_authority.OPERATION,
        evidence.value_digest(subject), token="estate",
    )

    report = _replay(
        estate, ledger, subject, manifest,
        estate_selection=authority_selection,
    )

    assert report["mechanical_validation_status"] == "PASS"
    assert report["estate_authority_status"] == "PASS"
    assert report["status"] == "UNKNOWN"
    assert report["per_candidate_evidence_status"] == "NOT_ESTABLISHED"
    assert report["full_estate_closure"] == "NOT_ESTABLISHED"
    assert report["candidate_unknown_count"] == estate["candidate_count"]
    assert report["tier1_status"] == "NOT_ESTABLISHED"
    assert report["polished"] is False
    assert report["release_authorized"] is False


def test_complete_native_replay_closes_only_exact_estate_evidence(
        estate: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = _ledger(estate)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)
    authority_selection = _selection(
        self_polish_estate_authority.OPERATION,
        evidence.value_digest(subject), token="estate",
    )
    artifacts = _native_artifacts(estate, manifest)
    candidate_selections = _candidate_selections(manifest)
    authority_selection = dataclasses.replace(
        authority_selection, evaluation_time=1
    )
    candidate_selections = {
        identifier: dataclasses.replace(selection, evaluation_time=1)
        for identifier, selection in candidate_selections.items()
    }
    monkeypatch.setattr(
        native_evidence, "prepare_replay_context",
        _synthetic_native_context,
    )

    report = _replay(
        estate, ledger, subject, manifest,
        estate_selection=authority_selection,
        candidate_selections=candidate_selections,
        source_root=".",
        evidence_artifacts=artifacts,
    )

    assert report["status"] == "PASS", report
    assert report["semantic_applicability_status"] == "PASS"
    assert report["per_candidate_evidence_status"] == "PASS"
    assert report["full_estate_closure"] == "PASS"
    assert report["native_self_verification_status"] == "PASS"
    assert report["native_semantic_applicability_status"] == "PASS"
    assert report["native_per_candidate_evidence_status"] == "PASS"
    assert report["independent_authority_status"] == "PASS"
    assert report["authenticated_candidate_count"] == estate["candidate_count"]
    assert report["candidate_pass_count"] == estate["candidate_count"]
    assert report["candidate_fail_count"] == 0
    assert report["candidate_unknown_count"] == 0
    assert report["tier1_status"] == "NOT_ESTABLISHED"
    assert report["polished"] is False
    assert report["release_authorized"] is False


def test_native_self_verification_passes_without_configured_key_authority(
        estate: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = _ledger(estate)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)
    artifacts = _native_artifacts(estate, manifest)
    monkeypatch.setattr(
        native_evidence, "prepare_replay_context", _synthetic_native_context,
    )

    report = _replay(
        estate, ledger, subject, manifest,
        source_root=".",
        evidence_artifacts=artifacts,
    )

    applicable = next(
        row for row in report["candidate_results"]
        if row["declared_applicability"] == "APPLICABLE"
    )
    assert applicable["native_replay_status"] == "PASS"
    assert applicable["native_semantic_status"] == "PASS"
    assert applicable["replay_status"] == "NOT_ESTABLISHED"
    assert applicable["semantic_status"] == "UNKNOWN"
    assert report["native_replayed_candidate_count"] == estate["candidate_count"]
    assert report["authenticated_candidate_count"] == 0
    assert report["status"] == "UNKNOWN"
    assert report["native_self_verification_status"] == "PASS"
    assert report["native_semantic_applicability_status"] == "PASS"
    assert report["native_per_candidate_evidence_status"] == "PASS"
    assert report["independent_authority_status"] == "NOT_ESTABLISHED"
    assert report["full_estate_closure"] == "NOT_ESTABLISHED"
    assert "CANDIDATE_EVIDENCE_RECEIPT_UNAVAILABLE" in report["blockers"]


def test_native_artifact_bytes_are_replayed_not_just_digest_declared(
        estate: dict) -> None:
    ledger = _ledger(estate)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)
    artifacts = _native_artifacts(estate, manifest)
    candidate_selections = _candidate_selections(manifest)
    authority_selection = _selection(
        self_polish_estate_authority.OPERATION,
        evidence.value_digest(subject), token="estate-tamper",
    )
    identifier = next(iter(artifacts))
    artifacts[identifier] = artifacts[identifier] + b" "

    report = _replay(
        estate, ledger, subject, manifest,
        estate_selection=authority_selection,
        candidate_selections=candidate_selections,
        evidence_artifacts=artifacts,
    )

    assert report["status"] == "FAIL"
    assert report["candidate_results"][0]["semantic_status"] == "FAIL"
    assert any(
        blocker.startswith("NATIVE_EVIDENCE_ARTIFACT_")
        for blocker in report["blockers"]
    )


@pytest.mark.parametrize("disposition", ("FAIL", "UNKNOWN"))
def test_authenticated_caller_disposition_without_native_replay_is_unknown(
        estate: dict, disposition: str) -> None:
    ledger = _ledger(estate)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(
        estate, ledger, subject, evidence_disposition=disposition
    )
    authority_selection = _selection(
        self_polish_estate_authority.OPERATION,
        evidence.value_digest(subject), token="estate",
    )
    report = _replay(
        estate, ledger, subject, manifest,
        estate_selection=authority_selection,
        candidate_selections=_candidate_selections(manifest),
    )

    assert report["status"] == "UNKNOWN"
    assert report["candidate_results"][0]["semantic_status"] == "UNKNOWN"
    assert report["full_estate_closure"] == "NOT_ESTABLISHED"
    assert "NATIVE_EVIDENCE_ARTIFACT_UNAVAILABLE" in report["blockers"]


def test_missing_estate_authority_keeps_complete_candidate_replays_unknown(
        estate: dict) -> None:
    ledger = _ledger(estate)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)

    report = _replay(
        estate, ledger, subject, manifest,
        candidate_selections=_candidate_selections(manifest),
    )

    assert report["status"] == "UNKNOWN"
    assert report["estate_authority_status"] == "UNKNOWN"
    assert report["semantic_applicability_status"] == "NOT_ESTABLISHED"
    assert report["full_estate_closure"] == "NOT_ESTABLISHED"
    assert "ESTATE_AUTHORITY_NOT_ESTABLISHED" in report["blockers"]


def test_blanket_not_applicable_declaration_contradicts_native_registry(
        estate: dict) -> None:
    ledger = self_polish_estate.applicability_ledger_template(estate)
    for index, row in enumerate(ledger["rows"]):
        row.update({
            "applicability_status": "NOT_APPLICABLE",
            "authority_status": "PASS",
            "authority_digest": _digest(300 + index),
            "justification": "Synthetic independently replayed exclusion.",
        })
    _redigest(ledger, "ledger_digest")
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)
    authority_selection = _selection(
        self_polish_estate_authority.OPERATION,
        evidence.value_digest(subject), token="estate-all-na",
    )

    report = _replay(
        estate, ledger, subject, manifest,
        estate_selection=authority_selection,
        candidate_selections=_candidate_selections(manifest),
    )

    assert report["status"] == "FAIL"
    assert report["native_self_verification_status"] == "FAIL"
    assert report["native_semantic_applicability_status"] == "FAIL"
    assert report["native_per_candidate_evidence_status"] == "FAIL"
    assert report["full_estate_closure"] == "FAIL"
    assert "CANDIDATE_DECLARATION_DIFFERS_FROM_NATIVE_APPLICABILITY" \
        in report["blockers"]


@pytest.mark.parametrize(
    ("mutation", "blocker"),
    (
        ("missing", "EVIDENCE_MANIFEST_DENOMINATOR_DIFFERS"),
        ("duplicate", "EVIDENCE_MANIFEST_ID_SET_DIFFERS"),
        ("substituted", "EVIDENCE_MANIFEST_CANDIDATE_SUBSTITUTED"),
        ("source", "EVIDENCE_MANIFEST_BINDING_DIFFERS"),
        ("category", "EVIDENCE_MANIFEST_BINDING_DIFFERS"),
        ("identity", "EVIDENCE_MANIFEST_BINDING_DIFFERS"),
    ),
)
def test_incomplete_duplicate_substituted_and_stale_manifests_fail(
        estate: dict, mutation: str, blocker: str) -> None:
    ledger = _ledger(estate)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)
    if mutation == "missing":
        manifest["rows"].pop()
    elif mutation == "duplicate":
        manifest["rows"][-1] = deepcopy(manifest["rows"][0])
    elif mutation == "substituted":
        manifest["rows"][0]["candidate_digest"] = _digest(999)
    elif mutation == "source":
        manifest["source_coordinate"] = {
            **manifest["source_coordinate"], "revision": "b" * 40,
        }
    elif mutation == "category":
        manifest["category_summaries_digest"] = _digest(998)
    else:
        manifest["candidate_identity_set_digest"] = _digest(997)
    _redigest(manifest, "manifest_digest")

    report = _replay(estate, ledger, subject, manifest)

    assert report["status"] == "FAIL"
    assert report["mechanical_validation_status"] == "FAIL"
    assert blocker in report["blockers"]


@pytest.mark.parametrize("failure", ("wrong-subject", "stale", "revoked"))
def test_wrong_subject_stale_and_revoked_candidate_evidence_fail(
        estate: dict, failure: str) -> None:
    ledger = _ledger(estate)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)
    first = manifest["rows"][0]
    candidate_subject_digest = evidence.value_digest(
        evidence.candidate_evidence_subject(manifest, first)
    )
    selection = _selection(
        evidence.OPERATION, candidate_subject_digest,
        token="adversarial", stale=failure == "stale",
        revoked=failure == "revoked",
    )
    if failure == "wrong-subject":
        selection = dataclasses.replace(
            selection, expected_subject_digest=_digest(996)
        )
    authority_selection = _selection(
        self_polish_estate_authority.OPERATION,
        evidence.value_digest(subject), token="estate",
    )

    report = _replay(
        estate, ledger, subject, manifest,
        estate_selection=authority_selection,
        candidate_selections={first["candidate_id"]: selection},
    )

    assert report["status"] == "FAIL"
    assert report["candidate_results"][0]["semantic_status"] == "FAIL"
    assert report["candidate_results"][0]["replay_status"] == "REJECTED"
    assert report["full_estate_closure"] == "FAIL"


def test_extra_candidate_replay_selection_is_rejected(estate: dict) -> None:
    ledger = _ledger(estate, all_unknown=True)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)

    report = _replay(
        estate, ledger, subject, manifest,
        candidate_selections={"substituted-candidate": None},
    )

    assert report["status"] == "FAIL"
    assert "CANDIDATE_REPLAY_SELECTION_SET_DIFFERS" in report["blockers"]


def test_manifest_digest_and_estate_coordinate_substitution_fail(
        estate: dict) -> None:
    ledger = _ledger(estate, all_unknown=True)
    subject = _authority_subject(estate, ledger)
    manifest = _manifest(estate, ledger, subject)

    report = evidence.replay_estate_evidence(
        estate=estate,
        ledger_bytes=evidence.canonical_bytes(ledger),
        expected_ledger_digest=ledger["ledger_digest"],
        manifest_bytes=evidence.canonical_bytes(manifest),
        expected_manifest_digest=_digest(995),
        estate_authority_subject=subject,
        estate_authority_replay=None,
        candidate_replays={},
    )
    assert report["status"] == "FAIL"
    assert "EVIDENCE_MANIFEST_DIGEST_DIFFERS" in report["blockers"]

    changed = deepcopy(estate)
    changed["source_coordinate"]["revision"] = "b" * 40
    report = _replay(changed, ledger, subject, manifest)
    assert report["status"] == "FAIL"
    assert "ESTATE_BINDING_DIFFERS" in report["blockers"]
