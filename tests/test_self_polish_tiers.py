"""Numeric Verifier Standard (VSTD) self-polish tier orchestration tests."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_estate as estate
from verifier.runtime import self_polish_estate_authority as estate_authority
from verifier.runtime import self_polish_estate_evidence as estate_evidence
from verifier.runtime import self_polish_estate_native_evidence as estate_native
from verifier.runtime import self_polish_evidence as evidence
from verifier.runtime import self_polish_facet_reasons as facet_reasons
from verifier.runtime import polish_requirements
from verifier.runtime import self_polish_tiers as tiers


def _source_capture() -> dict:
    census = {
        "schema_version": "verifier-self-polish-candidate-source-census-1",
        "file_count": 1,
        "total_bytes": 1,
        "provenance_counts": {
            "GIT_TRACKED": 1,
            "WORKTREE_UNTRACKED_NONIGNORED": 0,
        },
        "git_index_digest": "sha256:" + "1" * 64,
        "git_status_digest": "sha256:" + "c" * 64,
        "files": [{
            "path": "selected.py", "size": 1,
            "sha256": "sha256:" + "f" * 64,
            "provenance": "GIT_TRACKED", "git_mode": "100644",
        }],
        "ignored_scan": {
            "ignored_path_count": 0,
            "ignored_path_set_digest": estate.value_digest([]),
            "exclusion_taxonomy_digest": estate.value_digest(
                estate.IGNORED_EXCLUSION_TAXONOMY
            ),
            "excluded_cache_build_path_count": 0,
            "excluded_cache_build_paths_digest": estate.value_digest([]),
            "inert_ignored_path_count": 0,
            "inert_ignored_paths_digest": estate.value_digest([]),
            "excluded_bytes_status": "NOT_VERIFIED",
        },
    }
    census["census_digest"] = estate.value_digest(census)
    return {
        "schema_version": polish_requirements.CORE_SELF_POLISH_SOURCE,
        "git_head": "a" * 40,
        "git_tree": "b" * 40,
        "worktree_clean": False,
        "worktree_status_digest": "sha256:" + "c" * 64,
        "candidate_source_census_digest": census["census_digest"],
        "candidate_source_file_count": 1,
        "candidate_source_bytes": 1,
        "tracked_file_count": 1,
        "untracked_nonignored_file_count": 0,
        "candidate_source_census": census,
    }


def test_tier1_parser_exposes_exact_candidate_estate_evidence_inputs() -> None:
    parsed = tiers.build_self_polish_tier_parser().parse_args([
        "1",
        "--candidate-estate-evidence-manifest", "estate-evidence.json",
        "--candidate-estate-evidence-manifest-digest", "sha256:" + "1" * 64,
        "--candidate-estate-evidence-mechanism-digest",
        estate_evidence.mechanism_digest(),
        "--candidate-estate-evidence-selection", "candidate-a.json",
    ])

    assert parsed.candidate_estate_evidence_manifest == "estate-evidence.json"
    assert parsed.candidate_estate_evidence_manifest_digest \
        == "sha256:" + "1" * 64
    assert parsed.candidate_estate_evidence_mechanism_digest \
        == estate_evidence.mechanism_digest()
    assert parsed.candidate_estate_evidence_selection == ["candidate-a.json"]


def _candidate_selection_document(candidate_id: str = "candidate-a") -> dict:
    return {
        "candidate_id": candidate_id,
        "policy": {"selected": "policy"},
        "expected_policy_digest": "sha256:" + "1" * 64,
        "receipt": {"selected": "receipt"},
        "expected_receipt_digest": "sha256:" + "2" * 64,
        "expected_mechanism_digest": "sha256:" + "3" * 64,
        "expected_operation_revision_digest": "sha256:" + "4" * 64,
        "expected_instruction_revision_digest": "sha256:" + "5" * 64,
        "expected_context_revision_digest": "sha256:" + "6" * 64,
        "expected_subject_digest": "sha256:" + "7" * 64,
        "evaluation_time": 1_800_000_000,
        "minimum_status_sequence": 10,
    }


def test_candidate_estate_evidence_selection_loader_is_exact_and_unique(
        tmp_path) -> None:
    path = tmp_path / "candidate.json"
    path.write_text(
        json.dumps(_candidate_selection_document()), encoding="utf-8"
    )

    selections = tiers._candidate_estate_evidence_selections([str(path)])

    assert set(selections) == {"candidate-a"}
    assert selections["candidate-a"].expected_operation \
        == estate_evidence.OPERATION
    assert selections["candidate-a"].expected_subject_digest \
        == "sha256:" + "7" * 64
    with pytest.raises(ValueError, match=(
        "CANDIDATE_ESTATE_EVIDENCE_SELECTION_INVALID"
    )):
        tiers._candidate_estate_evidence_selections([str(path), str(path)])


def test_tier1_cli_handler_wires_authority_and_candidate_evidence_files(
        tmp_path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    policy = tmp_path / "authority-policy.json"
    receipt = tmp_path / "authority-receipt.json"
    manifest = tmp_path / "estate-evidence.json"
    candidate = tmp_path / "candidate-selection.json"
    policy.write_text("{}", encoding="utf-8")
    receipt.write_text("{}", encoding="utf-8")
    manifest.write_text("{}", encoding="utf-8")
    candidate.write_text(
        json.dumps(_candidate_selection_document()), encoding="utf-8"
    )
    observed = {}

    def assess(tier: int, **kwargs):
        observed.update(tier=tier, **kwargs)
        return {"status": "UNKNOWN"}

    monkeypatch.setattr(tiers, "assess_self_polish_tier", assess)
    result = tiers.handle_self_polish_tier_argv([
        "1", "--native-specimens", "--json",
        "--candidate-estate-authority-policy", str(policy),
        "--candidate-estate-authority-policy-digest", "sha256:" + "1" * 64,
        "--candidate-estate-authority-receipt", str(receipt),
        "--candidate-estate-authority-receipt-digest", "sha256:" + "2" * 64,
        "--candidate-estate-authority-mechanism-digest", "sha256:" + "3" * 64,
        "--candidate-estate-authority-operation-revision-digest",
        "sha256:" + "4" * 64,
        "--candidate-estate-authority-instruction-revision-digest",
        "sha256:" + "5" * 64,
        "--candidate-estate-authority-context-revision-digest",
        "sha256:" + "6" * 64,
        "--candidate-estate-authority-subject-digest", "sha256:" + "7" * 64,
        "--candidate-estate-authority-evaluation-time", "1800000000",
        "--candidate-estate-authority-minimum-status-sequence", "10",
        "--candidate-estate-evidence-manifest", str(manifest),
        "--candidate-estate-evidence-manifest-digest", "sha256:" + "8" * 64,
        "--candidate-estate-evidence-mechanism-digest", "sha256:" + "9" * 64,
        "--candidate-estate-evidence-selection", str(candidate),
    ])

    assert result == 2
    assert json.loads(capsys.readouterr().out) == {"status": "UNKNOWN"}
    assert observed["tier"] == 1
    assert observed["candidate_estate_evidence_manifest_bytes"] == b"{}"
    assert observed["expected_candidate_estate_evidence_manifest_digest"] \
        == "sha256:" + "8" * 64
    assert observed["expected_candidate_estate_evidence_mechanism_digest"] \
        == "sha256:" + "9" * 64
    assert set(observed["candidate_estate_evidence_replays"]) == {"candidate-a"}
    assert observed["candidate_estate_authority_replay"].expected_subject_digest \
        == "sha256:" + "7" * 64


def _source_coordinate() -> dict[str, str]:
    captured = _source_capture()
    return {
        "source_head": "a" * 40,
        "source_tree": "b" * 40,
        "source_worktree_status_digest": "sha256:" + "c" * 64,
        "source_manifest_digest": (
            polish_requirements.source_manifest_digest(captured)
        ),
    }


def test_non_ascii_source_recapture_uses_selection_digest_encoding(
        monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _source_capture()
    census = captured["candidate_source_census"]
    census["files"][0]["path"] = "sélected.py"
    census.pop("census_digest")
    census["census_digest"] = polish_requirements.polish._digest(
        polish_requirements.canonical_bytes(census)
    )
    captured["candidate_source_census_digest"] = census["census_digest"]
    coordinate = {
        "source_head": captured["git_head"],
        "source_tree": captured["git_tree"],
        "source_worktree_status_digest": captured["worktree_status_digest"],
        "source_manifest_digest": (
            polish_requirements.source_manifest_digest(captured)
        ),
    }
    assert coordinate["source_manifest_digest"] != (
        core_obligation_union.value_digest(captured)
    )
    monkeypatch.setattr(
        polish_requirements,
        "capture_core_self_polish_source",
        lambda _root: deepcopy(captured),
    )

    result = tiers._post_replay_source_recapture("selected", coordinate)

    assert result["status"] == "PASS"
    assert result["matches_selected_source"] is True


def _attempt(*, external_pin: str = "MATCHED") -> dict:
    coordinate = _source_coordinate()
    return {
        "status": "PASS",
        "gate_status": "PASS",
        "receipt_status": "ISSUED",
        "assessment_digest": "sha256:" + "1" * 64,
        "receipt_digest": "sha256:" + "2" * 64,
        "selection_digest": "sha256:" + "3" * 64,
        "external_selection_pin": external_pin,
        "source_coordinate": coordinate,
        "source_coordinate_digest": core_obligation_union.value_digest(coordinate),
        "root_id": "verifier-core-self",
        "installed_definition_count": 27,
        "installed_membership_count": 52,
        "instantiated_obligation_count": 2,
        "full_application_status": "UNKNOWN",
        "polished": False,
        "reason": None,
    }


def test_installed_route_union_and_application_authority_are_derived(
        ) -> None:
    denominators = tiers._denominators("verifier-core-self")
    coordinate = _source_coordinate()
    union = tiers._derived_route_union_summary(
        source_coordinate=coordinate,
        tier=1,
        expected_members=45,
        denominators=denominators,
    )
    authority = tiers._derived_application_authority_summary(
        union_summary=union,
        expected_instances=denominators["facets"][
            "instantiated_obligation_count"
        ],
        source_coordinate=coordinate,
        tier=1,
        denominators=denominators,
    )

    assert union["status"] == "PASS"
    assert union["derivation"] == "INSTALLED_REGISTRY_CLOSURE"
    assert union["selected_verifier_tier_member_count"] == 45
    assert authority["status"] == "UNKNOWN"
    assert authority["derivation"] \
        == "COMMAND_SELECTED_INSTALLED_SELF_REPRESENTATION"
    assert authority["independent_authority_status"] == "NOT_ESTABLISHED"
    assert authority["authority_status"] == "NOT_ESTABLISHED"
    assert authority["semantic_completeness"] == "NOT_ESTABLISHED"
    assert authority["blockers"] == [
        "INDEPENDENT_APPLICATION_AUTHORITY_NOT_ESTABLISHED"
    ]
    assert authority["release_authorized"] is False


def _candidate_estate(candidate_count: int | None = None) -> dict:
    census = {
        "schema_version": "verifier-self-polish-candidate-source-census-1",
        "file_count": 1,
        "total_bytes": 1,
        "provenance_counts": {
            "GIT_TRACKED": 1,
            "WORKTREE_UNTRACKED_NONIGNORED": 0,
        },
        "git_index_digest": "sha256:" + "1" * 64,
        "git_status_digest": "sha256:" + "2" * 64,
        "files": [{
            "path": "selected.py", "size": 1,
            "sha256": "sha256:" + "f" * 64,
            "provenance": "GIT_TRACKED",
            "git_mode": "100644",
        }],
        "ignored_scan": {
            "ignored_path_count": 0,
            "ignored_path_set_digest": estate.value_digest([]),
            "exclusion_taxonomy_digest": estate.value_digest(
                estate.IGNORED_EXCLUSION_TAXONOMY
            ),
            "excluded_cache_build_path_count": 0,
            "excluded_cache_build_paths_digest": estate.value_digest([]),
            "inert_ignored_path_count": 0,
            "inert_ignored_paths_digest": estate.value_digest([]),
            "excluded_bytes_status": "NOT_VERIFIED",
        },
    }
    census["census_digest"] = estate.value_digest({
        key: value for key, value in census.items()
        if key != "census_digest"
    })
    candidates = []
    for index, category in enumerate(estate.REQUIRED_CATEGORIES):
        if category == "candidate_source_file":
            candidate_body = {
                "candidate_id": "candidate-source-file:selected.py",
                "category": category,
                "candidate_type": "CANDIDATE_SOURCE_FILE",
                "source_refs": [{
                    "path": "selected.py", "sha256": "sha256:" + "f" * 64,
                }],
                "metadata": {
                    "size": 1,
                    "provenance": "GIT_TRACKED",
                    "git_mode": "100644",
                },
            }
        elif category == "unresolved_surface":
            candidate_body = {
                "candidate_id": (
                    "unresolved-surface:external-plugin-estate"
                ),
                "category": category,
                "candidate_type": "EXPLICIT_UNKNOWN_SURFACE",
                "source_refs": [],
                "metadata": {
                    "surface_id": "external-plugin-estate",
                    "enumeration_status": "UNKNOWN",
                    "reason": "Synthetic declared boundary surface.",
                },
            }
        else:
            candidate_body = {
                "candidate_id": f"{category}:candidate-{index}",
                "category": category,
                "source_refs": [{
                    "path": "selected.py", "sha256": "sha256:" + "f" * 64,
                }],
                "metadata": {},
            }
        candidate = {
            **candidate_body,
            "candidate_digest": estate.value_digest(candidate_body),
        }
        candidates.append(candidate)
    target_count = candidate_count or len(candidates)
    assert target_count >= len(candidates)
    for index in range(target_count - len(candidates)):
        candidate_body = {
            "candidate_id": (
                f"candidate-source-file:generated-{index:05d}.py"
            ),
            "category": "candidate_source_file",
            "candidate_type": "CANDIDATE_SOURCE_FILE",
            "source_refs": [{
                "path": "selected.py", "sha256": "sha256:" + "f" * 64,
            }],
            "metadata": {
                "size": 1,
                "provenance": "GIT_TRACKED",
                "git_mode": "100644",
            },
        }
        candidates.append({
            **candidate_body,
            "candidate_digest": estate.value_digest(candidate_body),
        })
    candidates.sort(key=lambda row: row["candidate_id"])
    category_summaries = []
    for category in estate.REQUIRED_CATEGORIES:
        selected = [
            candidate for candidate in candidates
            if candidate["category"] == category
        ]
        category_summaries.append({
            "category": category,
            "mechanical_status": "PASS",
            "candidate_count": len(selected),
            "candidate_digest": estate.value_digest(selected),
            "semantic_status": "NOT_ESTABLISHED",
        })
    source_coordinate = {
        "repository": "https://example.invalid/verifier.git",
        "revision": "a" * 40,
        "candidate_source_file_count": 1,
        "candidate_source_byte_count": 1,
        "candidate_source_census_digest": census["census_digest"],
        "tracked_file_count": 1,
        "untracked_nonignored_file_count": 0,
    }
    body = {
        "schema_version": estate.ESTATE_SCHEMA,
        "mechanical_census_status": "PASS",
        "semantic_applicability_status": "NOT_ESTABLISHED",
        "full_estate_closure": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "source_coordinate": source_coordinate,
        "pre_source_census": census,
        "post_source_census": deepcopy(census),
        "required_categories": list(estate.REQUIRED_CATEGORIES),
        "category_summaries": category_summaries,
        "structural_route_crosswalk": {
            "status": "NOT_ESTABLISHED",
            "structural_membership_count": 52,
            "route_tier1_membership_count": 45,
            "shared_identity_count": 27,
            "structural_only_identity_count": 25,
            "route_only_identity_count": 18,
            "structural_identity_digest": "sha256:" + "4" * 64,
            "route_identity_digest": "sha256:" + "5" * 64,
            "shared_identity_digest": "sha256:" + "6" * 64,
        },
        "candidate_count": len(candidates),
        "candidate_universe_digest": estate.value_digest(candidates),
        "candidates": candidates,
        "applicability_ledger": None,
        "claim_boundary": estate.CLAIM_BOUNDARY,
    }
    return {**body, "estate_digest": estate.value_digest(body)}


def _candidate_estate_kwargs(candidate_estate: dict, ledger: dict | None = None,
        *, estate_digest: str | None = None) -> dict:
    selected = {
        "expected_candidate_estate_repository": candidate_estate[
            "source_coordinate"
        ]["repository"],
        "expected_candidate_estate_revision": candidate_estate[
            "source_coordinate"
        ]["revision"],
        "expected_candidate_estate_digest": (
            estate_digest or candidate_estate["estate_digest"]
        ),
    }
    if ledger is not None:
        selected.update(
            candidate_estate_applicability_ledger_bytes=(
                estate.canonical_bytes(ledger)
            ),
            expected_candidate_estate_applicability_ledger_digest=ledger[
                "ledger_digest"
            ],
        )
    return selected


def test_derived_estate_evidence_builds_native_requests_without_authority(
        ) -> None:
    candidate_estate = _candidate_estate()
    ledger = estate.applicability_ledger_template(candidate_estate)
    candidates_by_id = {
        row["candidate_id"]: row for row in candidate_estate["candidates"]
    }
    for row in ledger["rows"]:
        applicability = estate_native.native_applicability_status(
            candidates_by_id[row["candidate_id"]]
        )
        row.update(
            applicability_status=applicability,
            justification=(
                "Native replay selected; independent authority is absent."
            ),
        )
    ledger.pop("ledger_digest")
    ledger["ledger_digest"] = estate.value_digest(ledger)
    subject = _exact_estate_authority_subject(candidate_estate, ledger)

    manifest_bytes, manifest_digest, mechanism_digest, artifacts = (
        tiers._derived_estate_evidence_inputs(
            estate=candidate_estate,
            ledger_bytes=estate.canonical_bytes(ledger),
            expected_ledger_digest=ledger["ledger_digest"],
            authority_subject=subject,
        )
    )
    manifest = json.loads(manifest_bytes)

    assert manifest["manifest_digest"] == manifest_digest
    assert mechanism_digest == estate_evidence.mechanism_digest()
    assert set(artifacts) == {
        row["candidate_id"] for row in ledger["rows"]
        if row["applicability_status"] == "APPLICABLE"
    }
    assert all(
        row["semantic_basis_digest"] is None
        and (
            row["applicability_disposition"] == "APPLICABLE"
            and row["evidence_disposition"] == "PASS"
            and row["evidence_artifact_digest"] is not None
            or row["applicability_disposition"] == "NOT_APPLICABLE"
            and row["evidence_disposition"] == "UNKNOWN"
            and row["evidence_artifact_digest"] is None
        )
        for row in manifest["rows"]
    )


def _estate_evidence_result(candidate_estate: dict, ledger: dict, *,
        manifest_digest: str, status: str = "PASS",
        blocker: str | None = None) -> dict:
    candidate_count = candidate_estate["candidate_count"]
    semantic = (
        "PASS" if status == "PASS" else
        "FAIL" if status == "FAIL" else "NOT_ESTABLISHED"
    )
    results = [
        {
            "candidate_id": row["candidate_id"],
            "candidate_digest": row["candidate_digest"],
            "category": row["category"],
            "declared_applicability": (
                "APPLICABLE" if status != "UNKNOWN" else "UNKNOWN"
            ),
            "declared_evidence_disposition": (
                "PASS" if status == "PASS" else
                "FAIL" if status == "FAIL" else "UNKNOWN"
            ),
            "subject_digest": "sha256:" + "8" * 64,
            "replay_status": (
                "REPRODUCED" if status == "PASS" else
                "REJECTED" if status == "FAIL" else "NOT_ESTABLISHED"
            ),
            "independent_authority_status": (
                "PASS" if status == "PASS" else
                "FAIL" if status == "FAIL" else "NOT_ESTABLISHED"
            ),
            "native_applicability_status": "APPLICABLE",
            "native_replay_status": (
                "PASS" if status == "PASS" else
                "FAIL" if status == "FAIL" else "NOT_ESTABLISHED"
            ),
            "native_replay_digest": (
                "sha256:" + "9" * 64 if status == "PASS" else None
            ),
            "native_semantic_status": (
                "PASS" if status == "PASS" else
                "FAIL" if status == "FAIL" else "UNKNOWN"
            ),
            "receipt_digest": (
                "sha256:" + "a" * 64 if status != "UNKNOWN" else None
            ),
            "policy_digest": (
                "sha256:" + "b" * 64 if status != "UNKNOWN" else None
            ),
            "approving_actors": ["test-authority"] if status == "PASS" else [],
            "applicability_status": (
                "APPLICABLE" if status == "PASS" else
                "FAIL" if status == "FAIL" else "UNKNOWN"
            ),
            "evidence_status": semantic,
            "semantic_status": semantic,
            "blockers": [blocker] if blocker is not None else [],
        }
        for row in candidate_estate["candidates"]
    ]
    body = {
        "schema_version": estate_evidence.RESULT_SCHEMA,
        "status": status,
        "mechanical_validation_status": "PASS",
        "estate_authority_status": "PASS",
        "independent_authority_status": (
            "PASS" if status == "PASS" else
            "FAIL" if status == "FAIL" else "NOT_ESTABLISHED"
        ),
        "native_self_verification_status": (
            "PASS" if status == "PASS" else
            "FAIL" if status == "FAIL" else "UNKNOWN"
        ),
        "native_semantic_applicability_status": (
            "PASS" if status == "PASS" else
            "FAIL" if status == "FAIL" else "UNKNOWN"
        ),
        "native_per_candidate_evidence_status": (
            "PASS" if status == "PASS" else
            "FAIL" if status == "FAIL" else "UNKNOWN"
        ),
        "semantic_applicability_status": semantic,
        "per_candidate_evidence_status": semantic,
        "full_estate_closure": semantic,
        "tier1_status": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "source_coordinate_digest": estate.value_digest(
            candidate_estate["source_coordinate"]
        ),
        "candidate_source_census_digest": candidate_estate["source_coordinate"][
            "candidate_source_census_digest"
        ],
        "estate_digest": candidate_estate["estate_digest"],
        "candidate_universe_digest": candidate_estate[
            "candidate_universe_digest"
        ],
        "candidate_identity_set_digest": estate_evidence.value_digest([{
            "candidate_id": row["candidate_id"],
            "candidate_digest": row["candidate_digest"],
            "category": row["category"],
        } for row in candidate_estate["candidates"]]),
        "applicability_ledger_digest": ledger["ledger_digest"],
        "manifest_digest": manifest_digest,
        "estate_authority_replay_digest": "sha256:" + "6" * 64,
        "assessment_time": 1_800_000_000,
        "native_source_recapture_status": (
            "PASS" if status == "PASS" else
            "FAIL" if status == "FAIL" else "NOT_ESTABLISHED"
        ),
        "native_replayed_candidate_count": (
            candidate_count if status == "PASS" else 0
        ),
        "native_applicable_candidate_count": candidate_count,
        "native_candidate_pass_count": (
            candidate_count if status == "PASS" else 0
        ),
        "native_candidate_fail_count": (
            candidate_count if status == "FAIL" else 0
        ),
        "native_candidate_unknown_count": (
            candidate_count if status == "UNKNOWN" else 0
        ),
        "native_evidence_artifact_count": (
            candidate_count if status == "PASS" else 0
        ),
        "candidate_count": candidate_count,
        "applicable_candidate_count": candidate_count,
        "authenticated_candidate_count": (
            candidate_count if status == "PASS" else 0
        ),
        "candidate_pass_count": candidate_count if status == "PASS" else 0,
        "candidate_fail_count": candidate_count if status == "FAIL" else 0,
        "candidate_unknown_count": candidate_count if status == "UNKNOWN" else 0,
        "candidate_results": results,
        "blockers": [blocker] if blocker is not None else [],
        "claim_boundary": "Candidate-estate evidence only.",
    }
    return {**body, "result_digest": estate_evidence.value_digest(body)}


def _native_authority_unknown_evidence_result(
        candidate_estate: dict, ledger: dict, *, manifest_digest: str,
        authority: dict) -> dict:
    """Represent full native replay with no configured-key receipt."""

    result = _estate_evidence_result(
        candidate_estate,
        ledger,
        manifest_digest=manifest_digest,
    )
    candidate_count = candidate_estate["candidate_count"]
    result.update(
        status="UNKNOWN",
        estate_authority_status="UNKNOWN",
        independent_authority_status="NOT_ESTABLISHED",
        semantic_applicability_status="NOT_ESTABLISHED",
        per_candidate_evidence_status="NOT_ESTABLISHED",
        full_estate_closure="NOT_ESTABLISHED",
        estate_authority_replay_digest=authority["result_digest"],
        authenticated_candidate_count=0,
        candidate_pass_count=0,
        candidate_unknown_count=candidate_count,
        blockers=[
            "CANDIDATE_EVIDENCE_RECEIPT_UNAVAILABLE",
            "ESTATE_AUTHORITY_NOT_ESTABLISHED",
            "ESTATE_AUTHORITY_RECEIPT_UNAVAILABLE",
            "PER_CANDIDATE_EVIDENCE_NOT_ESTABLISHED",
        ],
    )
    for row in result["candidate_results"]:
        row.update(
            replay_status="NOT_ESTABLISHED",
            independent_authority_status="NOT_ESTABLISHED",
            receipt_digest=None,
            policy_digest=None,
            approving_actors=[],
            applicability_status="UNKNOWN",
            evidence_status="UNKNOWN",
            semantic_status="UNKNOWN",
            blockers=["CANDIDATE_EVIDENCE_RECEIPT_UNAVAILABLE"],
        )
    result.pop("result_digest")
    result["result_digest"] = estate_evidence.value_digest(result)
    return result


def _passing_estate_authority() -> dict:
    return {
        "status": "PASS",
        "independent_authority_status": "PASS",
        "semantic_applicability_status": "NOT_ESTABLISHED",
        "per_candidate_evidence_status": "NOT_ESTABLISHED",
        "full_estate_closure": "NOT_ESTABLISHED",
        "blockers": [],
    }


def _authenticated_candidate_ledger(candidate_estate: dict) -> dict:
    ledger = estate.applicability_ledger_template(candidate_estate)
    for index, row in enumerate(ledger["rows"]):
        row.update({
            "applicability_status": (
                "APPLICABLE" if index == 0 else "NOT_APPLICABLE"
            ),
            "authority_status": "PASS",
            "authority_digest": "sha256:" + f"{index + 3000:064x}",
            "justification": "Synthetic independently replayed disposition.",
        })
    ledger.pop("ledger_digest")
    ledger["ledger_digest"] = estate.value_digest(ledger)
    return ledger


def _exact_estate_authority_subject(candidate_estate: dict,
        ledger: dict) -> dict:
    denominators = tiers._denominators("verifier-core-self")
    crosswalk = candidate_estate["structural_route_crosswalk"]
    return estate_authority.estate_authority_subject(
        source_coordinate_digest=_attempt()["source_coordinate_digest"],
        estate_source_coordinate_digest=estate.value_digest(
            candidate_estate["source_coordinate"]
        ),
        candidate_source_census_digest=candidate_estate["source_coordinate"][
            "candidate_source_census_digest"
        ],
        estate_digest=candidate_estate["estate_digest"],
        candidate_universe_digest=candidate_estate["candidate_universe_digest"],
        required_categories_digest=estate.value_digest(
            candidate_estate["required_categories"]
        ),
        category_summaries_digest=estate.value_digest(
            candidate_estate["category_summaries"]
        ),
        applicability_ledger_digest=ledger["ledger_digest"],
        installed_inventory_digest=denominators[
            "installed_route_inventory_digest"
        ],
        objective_catalog_digest=denominators["objective_inventory_digest"],
        structural_route_crosswalk_digest=estate.value_digest(crosswalk),
        structural_identity_digest=crosswalk["structural_identity_digest"],
        route_identity_digest=crosswalk["route_identity_digest"],
        shared_identity_digest=crosswalk["shared_identity_digest"],
    )


def _membership_replay_digest(index: int) -> str:
    return "sha256:" + f"{index + 1000:064x}"


def _complete_ledger(tier: int, *, provider_status: str = "PASS",
        provider_states: tuple[str, str] = (
            "CLAUDE_PROVIDER_BLOCKED", "ANTIGRAVITY_PROVIDER_BLOCKED"
        )) -> dict:
    denominators = tiers._denominators("verifier-core-self")
    selected = denominators["complete_tiers"][str(tier)]
    entries = []
    for index, membership in enumerate(selected["membership_identities"]):
        mechanism = membership["checking_mechanism"]
        evidence_digest = "sha256:" + f"{index + 1:064x}"
        entries.append({
            "membership": membership,
            "applicability_status": "PASS",
            "authority_status": "PASS",
            "observation_status": "PASS",
            "native_assessment_status": "PASS",
            "provider_review_status": provider_status,
            "native_assessment_digest": evidence_digest,
            "obligation_id": (
                f"{membership['object_kind']}:{membership['coordinate']}"
            ),
            "definition_source": {
                "proposition_digest": membership["proposition_digest"],
                "scope": membership["scope"],
            },
            "definition_version": membership["semantic_version"],
            "implementation": {
                "checking_mechanism": mechanism,
                "files": [mechanism.rsplit(".", 1)[0].replace(".", "/") + ".py"],
                "symbols": [mechanism.rsplit(".", 1)[-1]],
            },
            "evidence": {
                "native_assessment_digest": evidence_digest,
                "source_coordinate_digest": core_obligation_union.value_digest(
                    _source_coordinate()
                ),
                "freshness": "CURRENT",
                "sources": [membership["coordinate"]],
            },
            "dependencies": [],
            "prerequisites": [],
            "applicability": {
                "platform_status": "PASS",
                "binding_status": "PASS",
            },
            "expected_behavior": {
                "positive": "admit exact valid evidence",
                "negative": "refuse contradictory evidence",
                "unknown": "preserve unavailable evidence as UNKNOWN",
            },
            "ownership": {
                "supervisor": "PRODUCTION_SUPERVISOR_B",
                "owner": "AGENT_3",
            },
            "provider_records": {
                "claude": {
                    "state": provider_states[0],
                    "receipt_digest": ("sha256:" + "9" * 64
                                       if provider_states[0] == "PASS" else None),
                },
                "antigravity": {
                    "state": provider_states[1],
                    "receipt_digest": ("sha256:" + "a" * 64
                                       if provider_states[1] == "PASS" else None),
                },
            },
            "implementation_status": "PASS",
            "focused_validation": {
                "status": "PASS", "receipt_digest": "sha256:" + "b" * 64,
            },
            "independent_replay": {
                "status": "PASS",
                "receipt_digest": _membership_replay_digest(index),
            },
            "final_disposition": "PASS",
            "justified_exclusion": None,
        })
    ledger = {
        "schema_version": tiers.TIER_LEDGER_SCHEMA,
        "tier": tier,
        "tier_name": selected["tier_name"],
        "source_coordinate": _source_coordinate(),
        "source_coordinate_digest": core_obligation_union.value_digest(
            _source_coordinate()
        ),
        "installed_inventory_digest": denominators[
            "installed_route_inventory_digest"
        ],
        "installed_family_cell_count_total": denominators[
            "installed_route_family_cell_count"
        ],
        "installed_membership_count_total": denominators[
            "installed_route_membership_count"
        ],
        "tier_family_cell_count": selected["family_cell_count"],
        "tier_membership_count": selected["registered_route_membership_count"],
        "entries": entries,
    }
    ledger["ledger_digest"] = core_obligation_union.value_digest(ledger)
    return ledger


def _reason_representation_bindings(reasons: dict) -> dict:
    partition = reasons["consumer_route_partition"]
    return {
        "tier1_facet_reason_assessment_digest": reasons[
            "assessment_digest"
        ],
        "tier1_facet_reason_ledger_digest": reasons["ledger_digest"],
        "tier1_facet_choice_identity_digest": reasons[
            "choice_identity_digest"
        ],
        "tier1_reasoned_structural_membership_digest": reasons[
            "reasoned_structural_membership_digest"
        ],
        "tier1_reasoned_route_membership_digest": reasons[
            "reasoned_route_membership_digest"
        ],
        "tier1_reasoned_slot_digest": reasons["reasoned_slot_digest"],
        "tier1_domain_route_reason_status": reasons[
            "domain_route_reason_status"
        ],
        "tier1_domain_route_reason_identity_digest": reasons[
            "domain_route_reason_identity_digest"
        ],
        "tier1_domain_route_reasons_digest": partition[
            "domain_route_reasons_digest"
        ],
        "tier1_facet_direct_route_membership_count": partition[
            "facet_direct_route_membership_count"
        ],
        "tier1_facet_direct_route_membership_digest": partition[
            "facet_direct_route_membership_digest"
        ],
        "tier1_domain_route_membership_count": partition[
            "domain_route_membership_count"
        ],
        "tier1_domain_route_membership_digest": partition[
            "domain_route_membership_digest"
        ],
        "tier1_reason_route_union_membership_count": partition[
            "route_union_membership_count"
        ],
        "tier1_reason_route_union_membership_digest": partition[
            "route_union_membership_digest"
        ],
        "tier1_reason_route_partition_digest": reasons[
            "consumer_route_partition_digest"
        ],
    }


def _complete_representation(tier: int, ledger: dict, *,
        provider_status: str = "PASS", prior_digest: str | None = None,
        evidence_digest: str = "sha256:" + "8" * 64,
        estate_evidence_digest: str | None = None) -> dict:
    denominators = tiers._denominators("verifier-core-self")
    reasons = tiers._validated_facet_reason_assessment(denominators)
    representation = {
        "schema_version": tiers.SELF_REPRESENTATION_SCHEMA,
        "subject": {"object_id": "verifier-core-self", "object_kind": "VERIFIER"},
        "source_coordinate": _source_coordinate(),
        "source_coordinate_digest": core_obligation_union.value_digest(
            _source_coordinate()
        ),
        "installed_inventory_digest": denominators[
            "installed_route_inventory_digest"
        ],
        "installed_family_cell_count_total": denominators[
            "installed_route_family_cell_count"
        ],
        "installed_membership_count_total": denominators[
            "installed_route_membership_count"
        ],
        "represented_tiers": list(range(1, tier + 1)),
        "tier_ledger_digest": ledger["ledger_digest"],
        "prior_whole_tier_report_digest": prior_digest,
        "representation_status": "PASS",
        "provider_review_status": provider_status,
        "unobserved_fields": [],
        "representation_evidence_digest": evidence_digest,
        "estate_evidence_result_digest": estate_evidence_digest,
        **_reason_representation_bindings(reasons),
    }
    representation["representation_digest"] = core_obligation_union.value_digest(
        representation
    )
    return representation


def _replay_receipt(*, source_revision: str = "a" * 40,
        omitted_id: str | None = None, duplicate_id: str | None = None,
        case_kind: str | None = None) -> dict:
    selected = tiers._denominators("verifier-core-self")["complete_tiers"]["1"]
    identifiers = [
        f"{row['object_kind']}:{row['coordinate']}"
        for row in selected["membership_identities"]
    ]
    mapping = [
        {
            "obligation_id": identifier,
            "required_case_kinds": list(evidence.CASE_KIND_ORDER),
        }
        for identifier in identifiers
    ]
    memberships = []
    for index, identifier in enumerate(identifiers):
        if identifier == omitted_id:
            continue
        kinds = list(evidence.CASE_KIND_ORDER)
        if case_kind is not None and index == 0:
            kinds[2] = case_kind
        memberships.append({
            "obligation_id": identifier,
            "cases": [
                {
                    "case_kind": kind,
                    "node_id": f"tests/qualified_tier1.py::{identifier}-{kind}",
                    "source": {
                        "path": "src/verifier/runtime/self_polish_tiers.py",
                        "sha256": "sha256:" + "1" * 64,
                    },
                    "test": {
                        "path": "tests/qualified_tier1.py",
                        "sha256": "sha256:" + "2" * 64,
                    },
                    "mechanism": {
                        "path": "src/verifier/runtime/self_polish_evidence.py",
                        "sha256": evidence.mechanism_digest(),
                    },
                    "status": "PASS",
                }
                for kind in kinds
            ],
            "status": "PASS",
            "stable_replay_digest": _membership_replay_digest(index),
        })
    if duplicate_id is not None:
        memberships.append(deepcopy(next(
            row for row in memberships if row["obligation_id"] == duplicate_id
        )))
    receipt = {
        "schema_version": evidence.RECEIPT_SCHEMA,
        "status": "PASS",
        "tier": 1,
        "polished": False,
        "release_authority": "NONE",
        "whole_tier_conformance": "NOT_ESTABLISHED",
        "provider_states": "OUT_OF_SCOPE",
        "manifest_digest": "sha256:" + "e" * 64,
        "expected_manifest_digest": "sha256:" + "e" * 64,
        "mechanism_digest": evidence.mechanism_digest(),
        "expected_mechanism_digest": evidence.mechanism_digest(),
        "obligation_mapping_digest": evidence.bytes_digest(
            evidence.canonical_bytes(mapping)
        ),
        "stable_replay_set_digest": "sha256:" + "5" * 64,
        "evidence_digest": "sha256:" + "7" * 64,
        "run_artifacts": {
            "pytest_trace_digest": "sha256:" + "3" * 64,
            "junit_xml_digest": "sha256:" + "4" * 64,
            "stdout_digest": "sha256:" + "8" * 64,
            "stderr_digest": "sha256:" + "9" * 64,
        },
        "source_coordinate": {
            "repository": "https://example.invalid/verifier.git",
            "revision": source_revision,
            "selected_files_digest": "sha256:" + "6" * 64,
            "scope": "SELECTED_FILES_ONLY",
        },
        "memberships": memberships,
        "counts": {
            "expected": 135, "collected": 135, "passed": 135,
            "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0,
        },
        "invalidators": [],
        "claim_boundary": "bounded replay only",
    }
    receipt["receipt_digest"] = evidence.bytes_digest(
        evidence.canonical_bytes(receipt)
    )
    return receipt


def _install_tier1_outer_pass(
        monkeypatch: pytest.MonkeyPatch, replay: dict) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        tiers, "_union_summary", lambda *_args, **kwargs:
        tiers._derived_route_union_summary(
            source_coordinate=kwargs["source_coordinate"], tier=kwargs["tier"],
            expected_members=kwargs["expected_members"],
            denominators=tiers._denominators("verifier-core-self"),
        )
    )
    monkeypatch.setattr(
        tiers,
        "_authority_summary",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        evidence,
        "replay_self_polish_evidence",
        lambda *_args, **_kwargs: deepcopy(replay),
    )
    monkeypatch.setattr(
        tiers.polish_requirements,
        "capture_core_self_polish_source",
        lambda *_args, **_kwargs: deepcopy(_source_capture()),
    )


def _assess_with_replay(replay: dict, *, ledger: dict | None = None,
        representation: dict | None = None) -> dict:
    return tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        complete_tier_evidence_manifest_bytes=b"{}",
        expected_complete_tier_evidence_manifest_digest="sha256:" + "e" * 64,
        expected_evidence_replay_mechanism_digest=evidence.mechanism_digest(),
        complete_tier_ledger_bytes=(
            core_obligation_union.canonical_bytes(ledger)
            if ledger is not None else None
        ),
        expected_complete_tier_ledger_digest=(
            ledger["ledger_digest"] if ledger is not None else None
        ),
        complete_self_representation_bytes=(
            core_obligation_union.canonical_bytes(representation)
            if representation is not None else None
        ),
        expected_complete_self_representation_digest=(
            representation["representation_digest"]
            if representation is not None else None
        ),
    )


def _retained_tier1(status: str) -> dict:
    denominators = tiers._denominators("verifier-core-self")
    report = tiers._base_report(1, denominators)
    attempt = _attempt()
    report.update(
        status=status,
        selected_tier_status=status,
        source_binding_status="PASS" if status == "PASS" else "UNKNOWN",
        source_coordinate=attempt["source_coordinate"],
        source_coordinate_digest=attempt["source_coordinate_digest"],
        core_self_polish_attempt=attempt,
    )
    return tiers._finish(report)


def _fully_pass_retained_tier1(*, replay_complete: bool = False) -> dict:
    report = _retained_tier1("PASS")
    ledger = _complete_ledger(1, provider_states=("PASS", "PASS"))
    replay = _replay_receipt() if replay_complete else None
    estate_result = None
    if replay_complete:
        estate_result = {
            "schema_version": estate_evidence.RESULT_SCHEMA,
            "status": "PASS",
            "native_self_verification_status": "PASS",
            "native_semantic_applicability_status": "PASS",
            "native_per_candidate_evidence_status": "PASS",
            "semantic_applicability_status": "PASS",
            "per_candidate_evidence_status": "PASS",
            "full_estate_closure": "PASS",
        }
        estate_result["result_digest"] = estate_evidence.value_digest(
            estate_result
        )
    representation = _complete_representation(
        1,
        ledger,
        evidence_digest=(replay["stable_replay_set_digest"]
                         if replay is not None else "sha256:" + "8" * 64),
        estate_evidence_digest=(
            estate_result["result_digest"]
            if estate_result is not None else None
        ),
    )
    selected = report["installed_denominators"]["complete_tiers"]["1"]
    reasons = tiers._validated_facet_reason_assessment(
        report["installed_denominators"]
    )
    route_union = tiers._derived_route_union_summary(
        source_coordinate=report["source_coordinate"], tier=1,
        expected_members=selected["registered_route_membership_count"],
        denominators=report["installed_denominators"],
    )
    application_authority = tiers._derived_application_authority_summary(
        union_summary=route_union, expected_instances=2,
        source_coordinate=report["source_coordinate"], tier=1,
        denominators=report["installed_denominators"],
    )
    report.update(
        whole_tier_conformance="PASS",
        applicability_status="PASS",
        authority_status="NOT_ESTABLISHED",
        dependency_status="PASS",
        interaction_status="PASS",
        installed_route_normative_closure="PASS",
        objective_inventory_closure="PASS",
        structural_route_crosswalk_closure="PASS",
        tier1_facet_choice_reasons=reasons,
        union_validation=route_union,
        application_authority=application_authority,
        complete_tier_evidence_replay=replay,
        candidate_estate_evidence=estate_result,
        complete_tier_ledger={
            "status": "PASS" if replay_complete else "UNKNOWN",
            "declared_status": "PASS",
            "mechanical_replay_status": (
                "PASS" if replay_complete else "NOT_ESTABLISHED"
            ),
            "replay_receipt_digest": (
                replay["receipt_digest"] if replay is not None else None
            ),
            "ledger_digest": ledger["ledger_digest"],
            "tier_family_cell_count": selected["family_cell_count"],
            "tier_membership_count": selected[
                "registered_route_membership_count"
            ],
        },
        complete_self_representation={
            "status": "PASS" if replay_complete else "UNKNOWN",
            "declared_status": "PASS",
            "independent_evidence_status": (
                "PASS" if replay_complete else "NOT_ESTABLISHED"
            ),
            "replay_receipt_digest": (
                replay["receipt_digest"] if replay is not None else None
            ),
            "stable_replay_set_digest": (
                replay["stable_replay_set_digest"]
                if replay is not None else None
            ),
            "represented_tiers": [1],
            "tier_ledger_digest": ledger["ledger_digest"],
            "representation_digest": representation["representation_digest"],
            "estate_evidence_result_digest": (
                estate_result["result_digest"]
                if estate_result is not None else None
            ),
            **_reason_representation_bindings(reasons),
        },
        retained_core_subset={
            "relationship_to_complete_tier": "NARROW_EVIDENCE_SUBSET",
            "retained_concrete_instance_count": 2,
            "complete_tier_family_cell_count": selected["family_cell_count"],
            "complete_tier_membership_count": selected[
                "registered_route_membership_count"
            ],
            "establishes_complete_tier": False,
        },
        blockers=[],
    )
    report.pop("report_digest")
    return tiers._finish(report)


def _fully_bound_retained_tier1(
        monkeypatch: pytest.MonkeyPatch, *, candidate_count: int | None = None,
        authority_unknown: bool = False) -> tuple[dict, dict]:
    """Return a full PASS report whose retained estate can be recaptured."""

    report = _fully_pass_retained_tier1(replay_complete=True)
    candidate_estate = _candidate_estate(candidate_count)
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )
    census, _, observed, _, _ = tiers._candidate_estate_inputs(
        source_root="selected-source",
        source_coordinate=report["source_coordinate"],
        denominators=report["installed_denominators"],
        expected_repository=candidate_estate["source_coordinate"]["repository"],
        expected_revision=candidate_estate["source_coordinate"]["revision"],
        expected_estate_digest=candidate_estate["estate_digest"],
        applicability_ledger_bytes=None,
        expected_applicability_ledger_digest=None,
    )
    assert observed == candidate_estate
    ledger = _authenticated_candidate_ledger(candidate_estate)
    applicability = estate.validate_applicability_ledger(
        candidate_estate,
        estate.canonical_bytes(ledger),
        expected_ledger_digest=ledger["ledger_digest"],
    )
    subject = _exact_estate_authority_subject(candidate_estate, ledger)
    absent_authority = estate_authority.replay_estate_authority(
        subject, authority_replay=None
    )
    if authority_unknown:
        authority = absent_authority
        evidence_result = _native_authority_unknown_evidence_result(
            candidate_estate,
            ledger,
            manifest_digest="sha256:" + "d" * 64,
            authority=authority,
        )
    else:
        authority_body = {
            "schema_version": estate_authority.RESULT_SCHEMA,
            "status": "PASS",
            "independent_authority_status": "PASS",
            "replay_status": "REPRODUCED",
            "subject_digest": estate.value_digest(subject),
            "policy_digest": "sha256:" + "1" * 64,
            "receipt_digest": "sha256:" + "2" * 64,
            "approving_actors": ["test-authority"],
            "semantic_applicability_status": "NOT_ESTABLISHED",
            "per_candidate_evidence_status": "NOT_ESTABLISHED",
            "full_estate_closure": "NOT_ESTABLISHED",
            "blockers": [],
            "claim_boundary": absent_authority["claim_boundary"],
        }
        authority = {
            **authority_body,
            "result_digest": estate.value_digest(authority_body),
        }
        evidence_result = _estate_evidence_result(
            candidate_estate,
            ledger,
            manifest_digest="sha256:" + "d" * 64,
        )
        evidence_result["estate_authority_replay_digest"] = authority[
            "result_digest"
        ]
        evidence_result.pop("result_digest")
        evidence_result["result_digest"] = estate_evidence.value_digest(
            evidence_result
        )
    report.update(
        candidate_estate_census=census,
        candidate_estate_applicability=applicability,
        candidate_estate_authority=authority,
        candidate_estate_evidence=evidence_result,
        repository_package_estate_closure="PASS",
        post_replay_full_source_recapture="PASS",
        post_replay_source_recapture={"status": "PASS"},
    )
    report["complete_self_representation"][
        "estate_evidence_result_digest"
    ] = evidence_result["result_digest"]
    report["repository_package_estate"][
        "estate_evidence_result_digest"
    ] = evidence_result["result_digest"]
    report.pop("report_digest")
    return tiers._finish(report), candidate_estate


def test_tier1_enumerates_installed_counts_but_missing_authority_blocks_pass(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
    )

    denominator = report["installed_denominators"]
    assert (
        denominator["installed_structural_definition_count"],
        denominator["installed_structural_membership_count"],
        denominator["facets"]["instantiated_obligation_count"],
    ) == (27, 52, 2)
    assert report["core_self_polish_attempt"]["status"] == "PASS"
    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert report["polished"] is report["release_authorized"] is False
    assert "OBLIGATION_UNION_AUTHORITY_UNAVAILABLE" in report["blockers"]
    assert "APPLICATION_AUTHORITY_UNAVAILABLE" in report["blockers"]
    body = {key: value for key, value in report.items() if key != "report_digest"}
    assert report["report_digest"] == core_obligation_union.value_digest(body)


def test_narrow_selected_subset_can_never_pass_complete_tier_gate(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        tiers,
        "_union_summary",
        lambda *_args, **_kwargs: {"status": "PASS"},
    )
    monkeypatch.setattr(
        tiers,
        "_authority_summary",
        lambda *_args, **_kwargs: {
            "status": "PASS",
            "binding_status": "PASS",
            "authority_status": "PASS",
            "child_status": "PASS",
            "interaction_status": "PASS",
        },
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
    )

    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert "COMPLETE_TIER_LEDGER_UNAVAILABLE" in report["blockers"]
    assert "COMPLETE_SELF_REPRESENTATION_UNAVAILABLE" in report["blockers"]
    assert report["retained_core_subset"] == {
        "relationship_to_complete_tier": "NARROW_EVIDENCE_SUBSET",
        "retained_concrete_instance_count": 2,
        "complete_tier_family_cell_count": 26,
        "complete_tier_membership_count": 45,
        "establishes_complete_tier": False,
    }


def test_complete_denominator_totals_are_exposed_from_installed_inventory() -> None:
    denominator = tiers._denominators("verifier-core-self")

    assert (
        denominator["installed_route_family_cell_count"],
        denominator["installed_route_membership_count"],
        denominator["complete_tiers"]["1"]["family_cell_count"],
        denominator["complete_tiers"]["1"][
            "registered_route_membership_count"
        ],
        denominator["complete_tiers"]["1"][
            "unique_checking_mechanism_count"
        ],
        denominator["complete_tiers"]["2"]["family_cell_count"],
        denominator["complete_tiers"]["2"][
            "registered_route_membership_count"
        ],
        denominator["complete_tiers"]["2"][
            "unique_checking_mechanism_count"
        ],
    ) == (234, 408, 26, 45, 15, 26, 37, 31)
    crosswalk = denominator["structural_route_crosswalk"]
    assert (
        crosswalk["structural_membership_count"],
        crosswalk["route_tier1_membership_count"],
        crosswalk["shared_identity_count"],
        crosswalk["structural_only_identity_count"],
        crosswalk["route_only_identity_count"],
    ) == (52, 45, 27, 25, 18)


def test_pinned_candidate_estate_is_recomputed_without_semantic_promotion(
        monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    ledger = estate.applicability_ledger_template(candidate_estate)
    observed = {}

    def build(root, *, expected_repository, expected_revision):
        observed.update(
            root=root,
            expected_repository=expected_repository,
            expected_revision=expected_revision,
        )
        return deepcopy(candidate_estate)

    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(estate, "build_candidate_estate", build)

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        expected_candidate_estate_repository=(
            candidate_estate["source_coordinate"]["repository"]
        ),
        expected_candidate_estate_revision=(
            candidate_estate["source_coordinate"]["revision"]
        ),
        expected_candidate_estate_digest=candidate_estate["estate_digest"],
        candidate_estate_applicability_ledger_bytes=(
            estate.canonical_bytes(ledger)
        ),
        expected_candidate_estate_applicability_ledger_digest=ledger[
            "ledger_digest"
        ],
    )

    assert observed == {
        "root": "selected-source",
        "expected_repository": "https://example.invalid/verifier.git",
        "expected_revision": "a" * 40,
    }
    assert report["candidate_estate_census"]["mechanical_census_status"] \
        == "PASS"
    assert report["candidate_estate_applicability"][
        "mechanical_validation_status"
    ] == "PASS"
    assert report["repository_package_estate_closure"] == "NOT_ESTABLISHED"
    assert report["repository_package_estate"][
        "semantic_applicability_status"
    ] == "NOT_ESTABLISHED"
    assert report["repository_package_estate"][
        "independent_authority_status"
    ] == "NOT_ESTABLISHED"
    assert report["repository_package_estate"][
        "per_obligation_replay_status"
    ] == "NOT_ESTABLISHED"
    assert report["candidate_estate_authority"]["status"] == "UNKNOWN"
    assert report["candidate_estate_authority"][
        "independent_authority_status"
    ] == "NOT_ESTABLISHED"
    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert "CANDIDATE_ESTATE_SEMANTIC_CLOSURE_NOT_ESTABLISHED" \
        in report["blockers"]


def test_candidate_estate_digest_substitution_fails_closed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        **_candidate_estate_kwargs(
            candidate_estate, estate_digest="sha256:" + "0" * 64
        ),
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "CANDIDATE_ESTATE_DIGEST_DIFFERS" in report["blockers"]


def test_candidate_estate_ledger_candidate_substitution_fails_closed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    ledger = estate.applicability_ledger_template(candidate_estate)
    ledger["rows"][0]["candidate_digest"] = "sha256:" + "0" * 64
    ledger.pop("ledger_digest")
    ledger["ledger_digest"] = estate.value_digest(ledger)
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        **_candidate_estate_kwargs(candidate_estate, ledger),
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "APPLICABILITY_LEDGER_CANDIDATE_SUBSTITUTED" \
        in report["blockers"]


@pytest.mark.parametrize(
    "error", ["TRACKED_SOURCE_MUTATED", "UNTRACKED_FILES_PRESENT"]
)
def test_candidate_estate_mutation_and_untracked_refusals_remain_fail(
        error: str, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())

    def refuse(*_args, **_kwargs):
        raise estate.EstateError(error)

    monkeypatch.setattr(estate, "build_candidate_estate", refuse)

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        **_candidate_estate_kwargs(candidate_estate),
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert error in report["blockers"]


def test_caller_pass_estate_ledger_remains_unauthenticated_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    ledger = estate.applicability_ledger_template(candidate_estate)
    fake = "sha256:" + "9" * 64
    for row in ledger["rows"]:
        row.update({
            "applicability_status": "APPLICABLE",
            "authority_status": "PASS",
            "evidence_status": "PASS",
            "authority_digest": fake,
            "evidence_digest": fake,
            "justification": "Caller declaration is not authentication.",
        })
    ledger.pop("ledger_digest")
    ledger["ledger_digest"] = estate.value_digest(ledger)
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        **_candidate_estate_kwargs(candidate_estate, ledger),
    )

    applicability = report["candidate_estate_applicability"]
    assert applicability["caller_declared_pass_count"] \
        == candidate_estate["candidate_count"]
    assert applicability["caller_pass_authentication"] == "NOT_ESTABLISHED"
    assert applicability["semantic_applicability_status"] == "NOT_ESTABLISHED"
    assert report["repository_package_estate_closure"] == "NOT_ESTABLISHED"
    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"


def test_valid_estate_authority_sets_only_independent_authority_pass(
        monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    ledger = estate.applicability_ledger_template(candidate_estate)
    observed = {}

    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )

    def replay(subject, *, authority_replay):
        observed.update(subject=subject, authority_replay=authority_replay)
        return {
            "status": "PASS",
            "independent_authority_status": "PASS",
            "semantic_applicability_status": "NOT_ESTABLISHED",
            "per_candidate_evidence_status": "NOT_ESTABLISHED",
            "full_estate_closure": "NOT_ESTABLISHED",
            "blockers": [],
        }

    monkeypatch.setattr(estate_authority, "replay_estate_authority", replay)
    replay_selection = object()
    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        candidate_estate_authority_replay=replay_selection,
        **_candidate_estate_kwargs(candidate_estate, ledger),
    )

    subject = observed["subject"]
    crosswalk = candidate_estate["structural_route_crosswalk"]
    assert observed["authority_replay"] is replay_selection
    assert subject["source_coordinate_digest"] \
        == report["source_coordinate_digest"]
    assert subject["estate_source_coordinate_digest"] == estate.value_digest(
        candidate_estate["source_coordinate"]
    )
    assert subject["candidate_source_census_digest"] \
        == candidate_estate["source_coordinate"][
            "candidate_source_census_digest"
        ]
    assert subject["estate_digest"] == candidate_estate["estate_digest"]
    assert subject["candidate_universe_digest"] \
        == candidate_estate["candidate_universe_digest"]
    assert subject["required_categories_digest"] == estate.value_digest(
        candidate_estate["required_categories"]
    )
    assert subject["category_summaries_digest"] == estate.value_digest(
        candidate_estate["category_summaries"]
    )
    assert subject["applicability_ledger_digest"] == ledger["ledger_digest"]
    assert subject["installed_inventory_digest"] == report[
        "installed_denominators"
    ]["installed_route_inventory_digest"]
    assert subject["objective_catalog_digest"] == report[
        "installed_denominators"
    ]["objective_inventory_digest"]
    assert subject["structural_route_crosswalk_digest"] == estate.value_digest(
        crosswalk
    )
    assert subject["structural_identity_digest"] \
        == crosswalk["structural_identity_digest"]
    assert subject["route_identity_digest"] \
        == crosswalk["route_identity_digest"]
    assert subject["shared_identity_digest"] \
        == crosswalk["shared_identity_digest"]
    assert report["candidate_estate_authority"]["status"] == "PASS"
    assert report["repository_package_estate"][
        "independent_authority_status"
    ] == "PASS"
    assert report["repository_package_estate"][
        "semantic_applicability_status"
    ] == "NOT_ESTABLISHED"
    assert report["repository_package_estate_closure"] == "NOT_ESTABLISHED"
    assert report["candidate_estate_evidence"] is None
    assert report["repository_package_estate"][
        "per_obligation_replay_status"
    ] == "NOT_ESTABLISHED"
    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert "CANDIDATE_ESTATE_EVIDENCE_MANIFEST_UNAVAILABLE" \
        in report["blockers"]
    assert "CANDIDATE_ESTATE_SEMANTIC_CLOSURE_NOT_ESTABLISHED" \
        in report["blockers"]


def test_authenticated_candidate_estate_evidence_closes_only_estate_gate(
        monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    ledger = estate.applicability_ledger_template(candidate_estate)
    manifest_digest = "sha256:" + "d" * 64
    evidence_result = _estate_evidence_result(
        candidate_estate, ledger, manifest_digest=manifest_digest
    )
    observed = {}
    authority_selection = object()
    candidate_selections = {
        row["candidate_id"]: object()
        for row in candidate_estate["candidates"]
    }
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )
    monkeypatch.setattr(
        estate_authority, "replay_estate_authority",
        lambda *_args, **_kwargs: _passing_estate_authority(),
    )

    def replay(**kwargs):
        observed.update(kwargs)
        return deepcopy(evidence_result)

    monkeypatch.setattr(estate_evidence, "replay_estate_evidence", replay)

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        candidate_estate_authority_replay=authority_selection,
        candidate_estate_evidence_manifest_bytes=b"{}",
        expected_candidate_estate_evidence_manifest_digest=manifest_digest,
        expected_candidate_estate_evidence_mechanism_digest=(
            estate_evidence.mechanism_digest()
        ),
        candidate_estate_evidence_replays=candidate_selections,
        **_candidate_estate_kwargs(candidate_estate, ledger),
    )

    assert observed["estate"] == candidate_estate
    assert observed["ledger_bytes"] == estate.canonical_bytes(ledger)
    assert observed["estate_authority_replay"] is authority_selection
    assert observed["candidate_replays"] is candidate_selections
    assert report["candidate_estate_evidence"] == evidence_result
    assert report["repository_package_estate"][
        "semantic_applicability_status"
    ] == "PASS"
    assert report["repository_package_estate"][
        "per_obligation_replay_status"
    ] == "PASS"
    assert report["repository_package_estate_closure"] == "PASS"
    assert report["repository_package_estate"][
        "estate_evidence_result_digest"
    ] == evidence_result["result_digest"]
    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert report["polished"] is report["release_authorized"] is False


def test_historical_candidate_estate_authority_replays_without_promoting_tier1(
        monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: cryptography (seal extra) is absent, so test_historical_candidate_estate_authority_replays_without_promoting_tier1 cannot replay its Ed25519-signed estate authority here (the signed selection comes from test_self_polish_estate_evidence._selection); the platform-python-contracts workflow job installs the seal extra and runs the complete suite, including this file")
    from test_self_polish_estate_evidence import _selection

    candidate_estate = _candidate_estate()
    ledger = _authenticated_candidate_ledger(candidate_estate)
    authority_subject = _exact_estate_authority_subject(
        candidate_estate, ledger
    )
    authority_selection = _selection(
        estate_authority.OPERATION,
        estate_evidence.value_digest(authority_subject),
        token="tier-estate-authority",
    )
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        candidate_estate_authority_replay=authority_selection,
        **_candidate_estate_kwargs(candidate_estate, ledger),
    )

    # The historical coordinate is reproducible at its caller-selected time,
    # but reproduction alone is not current per-candidate estate evidence and
    # therefore cannot promote Tier 1.
    assert report["candidate_estate_authority"]["status"] == "PASS"
    assert report["candidate_estate_authority"]["blockers"] == []
    assert report["candidate_estate_evidence"] is None
    assert "CANDIDATE_ESTATE_EVIDENCE_MANIFEST_UNAVAILABLE" in report[
        "blockers"
    ]
    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert report["polished"] is report["release_authorized"] is False


@pytest.mark.parametrize(
    "blocker",
    [
        "EVIDENCE_MANIFEST_CANDIDATE_SUBSTITUTED",
        "ESTATE_EVIDENCE_CONTRACT_REJECTED",
        "AUTHORITY_EVIDENCE_NOT_CURRENT",
        "AUTHORITY_APPROVAL_REVOKED",
        "CANDIDATE_REPLAY_SELECTION_SET_DIFFERS",
    ],
)
def test_candidate_estate_evidence_rejection_is_a_definite_tier_failure(
        blocker: str, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    ledger = estate.applicability_ledger_template(candidate_estate)
    manifest_digest = "sha256:" + "d" * 64
    evidence_result = _estate_evidence_result(
        candidate_estate,
        ledger,
        manifest_digest=manifest_digest,
        status="FAIL",
        blocker=blocker,
    )
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )
    monkeypatch.setattr(
        estate_authority, "replay_estate_authority",
        lambda *_args, **_kwargs: _passing_estate_authority(),
    )
    monkeypatch.setattr(
        estate_evidence, "replay_estate_evidence",
        lambda **_kwargs: deepcopy(evidence_result),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        candidate_estate_authority_replay=object(),
        candidate_estate_evidence_manifest_bytes=b"{}",
        expected_candidate_estate_evidence_manifest_digest=manifest_digest,
        expected_candidate_estate_evidence_mechanism_digest=(
            estate_evidence.mechanism_digest()
        ),
        candidate_estate_evidence_replays={},
        **_candidate_estate_kwargs(candidate_estate, ledger),
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert report["candidate_estate_evidence"]["blockers"] == [blocker]
    assert report["repository_package_estate_closure"] == "FAIL"
    assert "CANDIDATE_ESTATE_EVIDENCE_REJECTED" in report["blockers"]


def test_candidate_estate_evidence_waits_for_exact_estate_subject(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate_evidence,
        "replay_estate_evidence",
        lambda **_kwargs: pytest.fail("replay ran without an exact estate subject"),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        candidate_estate_evidence_manifest_bytes=b"{}",
        expected_candidate_estate_evidence_manifest_digest="sha256:" + "d" * 64,
        expected_candidate_estate_evidence_mechanism_digest=(
            estate_evidence.mechanism_digest()
        ),
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "CANDIDATE_ESTATE_EVIDENCE_SELECTION_INCOMPLETE" \
        in report["blockers"]


def test_untracked_source_failure_preempts_candidate_estate_replay(
        monkeypatch: pytest.MonkeyPatch) -> None:
    attempt = _attempt()
    attempt.update(status="FAIL", gate_status="FAIL",
                   reason="UNTRACKED_SOURCE_PRESENT")
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: attempt)
    monkeypatch.setattr(
        estate_evidence,
        "replay_estate_evidence",
        lambda **_kwargs: pytest.fail("replay ran after source-census failure"),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert report["candidate_estate_evidence"] is None
    assert "UNTRACKED_SOURCE_PRESENT" in report["blockers"]


def test_complete_representation_rejects_spliced_estate_evidence_digest(
        monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    applicability_ledger = estate.applicability_ledger_template(candidate_estate)
    manifest_digest = "sha256:" + "d" * 64
    evidence_result = _estate_evidence_result(
        candidate_estate,
        applicability_ledger,
        manifest_digest=manifest_digest,
    )
    tier_ledger = _complete_ledger(1)
    representation = _complete_representation(
        1,
        tier_ledger,
        estate_evidence_digest="sha256:" + "0" * 64,
    )
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )
    monkeypatch.setattr(
        estate_authority, "replay_estate_authority",
        lambda *_args, **_kwargs: _passing_estate_authority(),
    )
    monkeypatch.setattr(
        estate_evidence, "replay_estate_evidence",
        lambda **_kwargs: deepcopy(evidence_result),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        candidate_estate_authority_replay=object(),
        candidate_estate_evidence_manifest_bytes=b"{}",
        expected_candidate_estate_evidence_manifest_digest=manifest_digest,
        expected_candidate_estate_evidence_mechanism_digest=(
            estate_evidence.mechanism_digest()
        ),
        candidate_estate_evidence_replays={},
        complete_tier_ledger_bytes=core_obligation_union.canonical_bytes(
            tier_ledger
        ),
        expected_complete_tier_ledger_digest=tier_ledger["ledger_digest"],
        complete_self_representation_bytes=(
            core_obligation_union.canonical_bytes(representation)
        ),
        expected_complete_self_representation_digest=representation[
            "representation_digest"
        ],
        **_candidate_estate_kwargs(candidate_estate, applicability_ledger),
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "COMPLETE_SELF_REPRESENTATION_ESTATE_EVIDENCE_DIFFERS" \
        in report["blockers"]


def test_refuted_estate_authority_is_a_definite_tier_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    candidate_estate = _candidate_estate()
    ledger = estate.applicability_ledger_template(candidate_estate)
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        estate, "build_candidate_estate",
        lambda *_args, **_kwargs: deepcopy(candidate_estate),
    )
    monkeypatch.setattr(
        estate_authority,
        "replay_estate_authority",
        lambda *_args, **_kwargs: {
            "status": "FAIL",
            "independent_authority_status": "FAIL",
            "semantic_applicability_status": "NOT_ESTABLISHED",
            "per_candidate_evidence_status": "NOT_ESTABLISHED",
            "full_estate_closure": "NOT_ESTABLISHED",
            "blockers": ["AUTHORITY_APPROVAL_REVOKED"],
        },
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        candidate_estate_authority_replay=object(),
        **_candidate_estate_kwargs(candidate_estate, ledger),
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert report["repository_package_estate"][
        "independent_authority_status"
    ] == "FAIL"
    assert report["repository_package_estate_closure"] == "NOT_ESTABLISHED"
    assert "CANDIDATE_ESTATE_AUTHORITY_REJECTED" in report["blockers"]


def test_estate_authority_without_exact_estate_subject_fails_closed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        candidate_estate_authority_replay=object(),
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "CANDIDATE_ESTATE_AUTHORITY_SELECTION_INCOMPLETE" \
        in report["blockers"]


def test_all_pass_self_attestation_cannot_clear_complete_tier(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        tiers, "_union_summary", lambda *_args, **_kwargs: {"status": "PASS"}
    )
    monkeypatch.setattr(
        tiers,
        "_authority_summary",
        lambda *_args, **_kwargs: {
            "status": "PASS", "binding_status": "PASS",
            "authority_status": "PASS", "child_status": "PASS",
            "interaction_status": "PASS",
        },
    )
    ledger = _complete_ledger(1, provider_states=("PASS", "PASS"))
    representation = _complete_representation(1, ledger)

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        complete_tier_ledger_bytes=core_obligation_union.canonical_bytes(ledger),
        expected_complete_tier_ledger_digest=ledger["ledger_digest"],
        complete_self_representation_bytes=(
            core_obligation_union.canonical_bytes(representation)
        ),
        expected_complete_self_representation_digest=representation[
            "representation_digest"
        ],
    )

    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert report["complete_tier_ledger"]["tier_membership_count"] == 45
    assert report["complete_tier_ledger"][
        "declared_pass_membership_count"
    ] == 45
    assert report["complete_tier_ledger"]["declared_status"] == "PASS"
    assert report["complete_tier_ledger"][
        "provider_coverage_exception_count"
    ] == 0
    assert report["complete_tier_ledger"]["provider_state_counts"] == {
        "antigravity:PASS": 45,
        "claude:PASS": 45,
    }
    assert report["complete_tier_ledger"]["mechanical_replay_status"] \
        == "NOT_ESTABLISHED"
    assert report["complete_self_representation"]["declared_status"] == "PASS"
    assert report["complete_self_representation"][
        "independent_evidence_status"
    ] == "NOT_ESTABLISHED"
    assert "COMPLETE_TIER_EVIDENCE_REPLAY_NOT_ESTABLISHED" in report["blockers"]
    assert "COMPLETE_SELF_REPRESENTATION_REPLAY_NOT_ESTABLISHED" \
        in report["blockers"]
    assert report["full_application_status"] == "UNKNOWN"
    assert report["polished"] is report["release_authorized"] is False


def test_complete_ledger_denominator_mismatch_fails_closed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    ledger = _complete_ledger(1)
    ledger["tier_membership_count"] -= 1
    ledger.pop("ledger_digest")
    ledger["ledger_digest"] = core_obligation_union.value_digest(ledger)

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        complete_tier_ledger_bytes=core_obligation_union.canonical_bytes(ledger),
        expected_complete_tier_ledger_digest=ledger["ledger_digest"],
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "COMPLETE_TIER_LEDGER_DENOMINATOR_DIFFERS" in report["blockers"]
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"


def test_complete_ledger_requires_every_audit_dimension(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    ledger = _complete_ledger(1)
    ledger["entries"][0].pop("expected_behavior")
    ledger.pop("ledger_digest")
    ledger["ledger_digest"] = core_obligation_union.value_digest(ledger)

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        complete_tier_ledger_bytes=core_obligation_union.canonical_bytes(ledger),
        expected_complete_tier_ledger_digest=ledger["ledger_digest"],
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "COMPLETE_TIER_LEDGER_ENTRY_INVALID" in report["blockers"]
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"


def test_blocked_providers_are_counted_exceptions_not_primary_verdicts(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    ledger = _complete_ledger(1, provider_status="NOT_ESTABLISHED")

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        complete_tier_ledger_bytes=core_obligation_union.canonical_bytes(ledger),
        expected_complete_tier_ledger_digest=ledger["ledger_digest"],
    )

    result = report["complete_tier_ledger"]
    assert result["declared_status"] == "PASS"
    assert result["declared_pass_membership_count"] == 45
    assert result["provider_coverage_exception_count"] == 90
    assert result["provider_coverage_exception_membership_count"] == 45
    assert result["provider_review_status_counts"] == {"NOT_ESTABLISHED": 45}
    assert result["provider_state_counts"] == {
        "antigravity:ANTIGRAVITY_PROVIDER_BLOCKED": 45,
        "claude:CLAUDE_PROVIDER_BLOCKED": 45,
    }
    assert result["mechanical_replay_status"] == "NOT_ESTABLISHED"
    assert result["status"] == "UNKNOWN"


def test_provider_fail_cannot_be_hidden_as_a_coverage_exception(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    ledger = _complete_ledger(
        1,
        provider_status="PASS",
        provider_states=("FAIL", "ANTIGRAVITY_PROVIDER_BLOCKED"),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        complete_tier_ledger_bytes=core_obligation_union.canonical_bytes(ledger),
        expected_complete_tier_ledger_digest=ledger["ledger_digest"],
    )

    result = report["complete_tier_ledger"]
    assert result["status"] == result["declared_status"] == "FAIL"
    assert result["provider_fail_status_count"] == 45
    assert result["provider_coverage_exception_count"] == 45
    assert result["provider_coverage_exception_membership_count"] == 45
    assert result["declared_pass_membership_count"] == 0


def test_provider_unreviewed_rows_are_visible_while_replay_remains_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        tiers, "_union_summary", lambda *_args, **_kwargs: {"status": "PASS"}
    )
    monkeypatch.setattr(
        tiers,
        "_authority_summary",
        lambda *_args, **_kwargs: {
            "status": "PASS", "binding_status": "PASS",
            "authority_status": "PASS", "child_status": "PASS",
            "interaction_status": "PASS",
        },
    )
    ledger = _complete_ledger(1, provider_status="UNKNOWN")
    representation = _complete_representation(
        1, ledger, provider_status="UNKNOWN"
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        complete_tier_ledger_bytes=core_obligation_union.canonical_bytes(ledger),
        expected_complete_tier_ledger_digest=ledger["ledger_digest"],
        complete_self_representation_bytes=(
            core_obligation_union.canonical_bytes(representation)
        ),
        expected_complete_self_representation_digest=representation[
            "representation_digest"
        ],
    )

    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["complete_tier_ledger"]["declared_status"] == "PASS"
    assert report["complete_tier_ledger"]["unresolved_status_count"] == 0
    assert report["complete_tier_ledger"][
        "provider_coverage_exception_count"
    ] == 90
    assert report["complete_tier_ledger"][
        "provider_coverage_exception_membership_count"
    ] == 45
    assert report["complete_tier_ledger"]["provider_review_status_counts"] \
        == {"UNKNOWN": 45}
    assert report["complete_tier_ledger"]["provider_state_counts"] == {
        "antigravity:ANTIGRAVITY_PROVIDER_BLOCKED": 45,
        "claude:CLAUDE_PROVIDER_BLOCKED": 45,
    }
    assert report["complete_self_representation"]["declared_status"] == "PASS"
    assert report["complete_self_representation"]["provider_declared_status"] \
        == "UNKNOWN"
    assert report["complete_self_representation"][
        "provider_coverage_exception"
    ] is True
    assert report["complete_self_representation"][
        "independent_evidence_status"
    ] == "NOT_ESTABLISHED"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"


def test_legacy_pytest_route_replay_is_not_native_obligation_evidence(
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        tiers, "_union_summary", lambda *_args, **_kwargs: {"status": "PASS"}
    )
    monkeypatch.setattr(
        tiers,
        "_authority_summary",
        lambda *_args, **_kwargs: {
            "status": "PASS", "binding_status": "PASS",
            "authority_status": "PASS", "child_status": "PASS",
            "interaction_status": "PASS",
        },
    )
    replay = _replay_receipt()
    observed: dict = {}

    def fresh_replay(*args, **kwargs):
        observed.update(manifest_bytes=args[0], repo_root=args[1], **kwargs)
        return deepcopy(replay)

    monkeypatch.setattr(evidence, "replay_self_polish_evidence", fresh_replay)
    monkeypatch.setattr(
        tiers.polish_requirements,
        "capture_core_self_polish_source",
        lambda *_args, **_kwargs: deepcopy(_source_capture()),
    )
    ledger = _complete_ledger(1)
    representation = _complete_representation(
        1, ledger, evidence_digest=replay["stable_replay_set_digest"]
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        complete_tier_evidence_manifest_bytes=b"{}",
        expected_complete_tier_evidence_manifest_digest="sha256:" + "e" * 64,
        expected_evidence_replay_mechanism_digest=evidence.mechanism_digest(),
        complete_tier_ledger_bytes=core_obligation_union.canonical_bytes(ledger),
        expected_complete_tier_ledger_digest=ledger["ledger_digest"],
        complete_self_representation_bytes=(
            core_obligation_union.canonical_bytes(representation)
        ),
        expected_complete_self_representation_digest=representation[
            "representation_digest"
        ],
    )

    assert observed == {}
    assert report["complete_tier_evidence_replay"] is None
    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert "COMPLETE_TIER_EVIDENCE_MECHANISM_DIFFERS" \
        in report["blockers"]
    monkeypatch.setattr(
        tiers, "assess_self_polish_tier", lambda *_args, **_kwargs: report
    )
    assert tiers.handle_self_polish_tier_argv(["1", "--native-specimens", "--json"]) == 1
    capsys.readouterr()


def test_structural_route_crosswalk_digest_mismatch_is_a_definite_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    installed = deepcopy(
        tiers.core_tier_progression.installed_core_route_inventory()
    )
    selected = next(
        row for row in installed["family_cells"]
        if row["object_kind"] == "VERIFIER" and row["tier"] == 1
    )
    shared = next(
        row for row in selected["registered_route_memberships"]
        if row["coordinate"] == "VERIFIER-1.1"
    )
    shared["proposition_digest"] = "sha256:" + "0" * 64
    monkeypatch.setattr(
        tiers.core_tier_progression,
        "installed_core_route_inventory",
        lambda: installed,
    )

    report = tiers.assess_self_polish_tier(
        1, source_root="selected-source"
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "STRUCTURAL_ROUTE_CROSSWALK_CONTRADICTION" \
        in report["blockers"]


def test_discovered_unregistered_objective_candidate_keeps_estate_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = deepcopy(tiers.polish.polish_catalog())
    candidate = deepcopy(catalog["routes"][0])
    candidate["represented_kind_rule"] = "VERIFIER"
    candidate["objective"] = "VERIFIER-1.UNREGISTERED-CANDIDATE"
    catalog["routes"].append(candidate)
    monkeypatch.setattr(tiers.polish, "polish_catalog", lambda: catalog)
    replay = _replay_receipt()
    _install_tier1_outer_pass(monkeypatch, replay)
    ledger = _complete_ledger(1)
    representation = _complete_representation(
        1, ledger, evidence_digest=replay["stable_replay_set_digest"]
    )

    report = _assess_with_replay(
        replay, ledger=ledger, representation=representation
    )

    crosscheck = report["installed_denominators"][
        "objective_inventory_crosscheck"
    ]
    assert crosscheck["unregistered_candidate_status"] == "DISCOVERED"
    assert crosscheck["unregistered_candidate_count"] == 1
    assert report["repository_package_estate"][
        "registry_candidate_classification"
    ] == "UNKNOWN"
    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert "COMPLETE_TIER_EVIDENCE_MECHANISM_DIFFERS" \
        in report["blockers"]


def test_post_replay_source_mutation_is_a_definite_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    mutated = _source_capture()
    mutated["git_head"] = "e" * 40
    monkeypatch.setattr(
        tiers.polish_requirements,
        "capture_core_self_polish_source",
        lambda *_args, **_kwargs: deepcopy(mutated),
    )
    recapture = tiers._post_replay_source_recapture(
        "selected-source", _source_coordinate()
    )

    assert recapture["status"] == "FAIL"
    assert recapture["matches_selected_source"] is False


def test_missing_evidence_manifest_is_unknown_and_never_invokes_replay(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        evidence,
        "replay_self_polish_evidence",
        lambda *_args, **_kwargs: pytest.fail("missing manifest invoked replay"),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
    )

    assert report["status"] == "UNKNOWN"
    assert report["complete_tier_evidence_replay"] is None
    assert "COMPLETE_TIER_EVIDENCE_MANIFEST_UNAVAILABLE" in report["blockers"]


@pytest.mark.parametrize(
    "omission",
    ["manifest", "manifest-digest", "mechanism-digest"],
)
def test_partial_evidence_selection_fails_closed(
        omission: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    selected = {
        "complete_tier_evidence_manifest_bytes": b"{}",
        "expected_complete_tier_evidence_manifest_digest": "sha256:" + "e" * 64,
        "expected_evidence_replay_mechanism_digest": evidence.mechanism_digest(),
    }
    selected[{
        "manifest": "complete_tier_evidence_manifest_bytes",
        "manifest-digest": "expected_complete_tier_evidence_manifest_digest",
        "mechanism-digest": "expected_evidence_replay_mechanism_digest",
    }[omission]] = None

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
        **selected,
    )

    assert report["status"] == "FAIL"
    assert "COMPLETE_TIER_EVIDENCE_SELECTION_INCOMPLETE" in report["blockers"]


@pytest.mark.parametrize(
    "mutation, blocker",
    [
        ("absent-membership", "COMPLETE_TIER_EVIDENCE_MEMBERSHIP_DIFFERS"),
        ("duplicate-membership", "COMPLETE_TIER_EVIDENCE_MEMBERSHIP_DIFFERS"),
        ("mismatched-case", "COMPLETE_TIER_EVIDENCE_CASE_DIFFERS"),
        ("recursive-test", "COMPLETE_TIER_EVIDENCE_CASE_DIFFERS"),
    ],
)
def legacy_pytest_replay_membership_and_case_substitution_fails_closed(
        mutation: str, blocker: str, monkeypatch: pytest.MonkeyPatch) -> None:
    identifier = next(iter(
        _replay_receipt()["memberships"]
    ))["obligation_id"]
    replay = (
        _replay_receipt(omitted_id=identifier)
        if mutation == "absent-membership" else
        _replay_receipt(duplicate_id=identifier)
        if mutation == "duplicate-membership" else
        _replay_receipt(case_kind="POSITIVE")
        if mutation == "mismatched-case" else
        _replay_receipt()
    )
    if mutation == "recursive-test":
        replay["memberships"][0]["cases"][0]["test"]["path"] = (
            "tests/test_self_polish_forged.py"
        )
    _install_tier1_outer_pass(monkeypatch, replay)

    report = _assess_with_replay(replay)

    assert report["status"] == "FAIL"
    assert blocker in report["blockers"]


def legacy_pytest_stale_replay_coordinate_fails_closed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    replay = _replay_receipt(source_revision="b" * 40)
    _install_tier1_outer_pass(monkeypatch, replay)

    report = _assess_with_replay(replay)

    assert report["status"] == "FAIL"
    assert "COMPLETE_TIER_EVIDENCE_SOURCE_DIFFERS" in report["blockers"]


def legacy_pytest_forged_ledger_replay_digest_cannot_use_fresh_aggregate_pass(
        monkeypatch: pytest.MonkeyPatch) -> None:
    replay = _replay_receipt()
    _install_tier1_outer_pass(monkeypatch, replay)
    ledger = _complete_ledger(1)
    ledger["entries"][0]["independent_replay"]["receipt_digest"] = (
        "sha256:" + "f" * 64
    )
    ledger.pop("ledger_digest")
    ledger["ledger_digest"] = core_obligation_union.value_digest(ledger)

    report = _assess_with_replay(replay, ledger=ledger)

    assert report["status"] == "FAIL"
    assert "COMPLETE_TIER_LEDGER_REPLAY_DIGEST_DIFFERS" in report["blockers"]


def legacy_pytest_representation_must_bind_the_fresh_stable_replay_set(
        monkeypatch: pytest.MonkeyPatch) -> None:
    replay = _replay_receipt()
    _install_tier1_outer_pass(monkeypatch, replay)
    ledger = _complete_ledger(1)
    representation = _complete_representation(1, ledger)

    report = _assess_with_replay(
        replay, ledger=ledger, representation=representation
    )

    assert report["status"] == "FAIL"
    assert "COMPLETE_SELF_REPRESENTATION_REPLAY_DIGEST_DIFFERS" \
        in report["blockers"]


def legacy_pytest_every_assessment_performs_a_fresh_replay(
        monkeypatch: pytest.MonkeyPatch) -> None:
    replay = _replay_receipt()
    _install_tier1_outer_pass(monkeypatch, replay)
    calls = 0

    def fresh_replay(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return deepcopy(replay)

    monkeypatch.setattr(evidence, "replay_self_polish_evidence", fresh_replay)

    first = _assess_with_replay(replay)
    second = _assess_with_replay(replay)

    assert calls == 2
    assert first["complete_tier_evidence_replay"]["receipt_digest"] \
        == second["complete_tier_evidence_replay"]["receipt_digest"]


def test_tier1_cli_parser_exposes_independent_replay_selection() -> None:
    args = tiers.build_self_polish_tier_parser().parse_args([
        "1",
        "--complete-tier-evidence-manifest", "manifest.json",
        "--complete-tier-evidence-manifest-digest", "sha256:" + "e" * 64,
        "--evidence-replay-mechanism-digest", "sha256:" + "f" * 64,
        "--candidate-estate-repository", "https://example.invalid/verifier.git",
        "--candidate-estate-revision", "a" * 40,
        "--candidate-estate-digest", "sha256:" + "d" * 64,
        "--candidate-estate-applicability-ledger", "estate-ledger.json",
        "--candidate-estate-applicability-ledger-digest", "sha256:" + "c" * 64,
        "--candidate-estate-authority-policy", "estate-policy.json",
        "--candidate-estate-authority-policy-digest", "sha256:" + "1" * 64,
        "--candidate-estate-authority-receipt", "estate-receipt.json",
        "--candidate-estate-authority-receipt-digest", "sha256:" + "2" * 64,
        "--candidate-estate-authority-mechanism-digest", "sha256:" + "3" * 64,
        "--candidate-estate-authority-operation-revision-digest",
        "sha256:" + "4" * 64,
        "--candidate-estate-authority-instruction-revision-digest",
        "sha256:" + "5" * 64,
        "--candidate-estate-authority-context-revision-digest",
        "sha256:" + "6" * 64,
        "--candidate-estate-authority-subject-digest", "sha256:" + "7" * 64,
        "--candidate-estate-authority-evaluation-time", "1800000000",
        "--candidate-estate-authority-minimum-status-sequence", "10",
    ])

    assert args.complete_tier_evidence_manifest == "manifest.json"
    assert args.complete_tier_evidence_manifest_digest == "sha256:" + "e" * 64
    assert args.evidence_replay_mechanism_digest == "sha256:" + "f" * 64
    assert args.candidate_estate_repository \
        == "https://example.invalid/verifier.git"
    assert args.candidate_estate_revision == "a" * 40
    assert args.candidate_estate_digest == "sha256:" + "d" * 64
    assert args.candidate_estate_applicability_ledger == "estate-ledger.json"
    assert args.candidate_estate_applicability_ledger_digest \
        == "sha256:" + "c" * 64
    assert args.candidate_estate_authority_policy == "estate-policy.json"
    assert args.candidate_estate_authority_policy_digest \
        == "sha256:" + "1" * 64
    assert args.candidate_estate_authority_receipt == "estate-receipt.json"
    assert args.candidate_estate_authority_receipt_digest \
        == "sha256:" + "2" * 64
    assert args.candidate_estate_authority_subject_digest \
        == "sha256:" + "7" * 64
    assert args.candidate_estate_authority_evaluation_time == 1800000000
    assert args.candidate_estate_authority_minimum_status_sequence == 10


def test_denominator_mutation_fails_before_any_native_attempt(
        monkeypatch: pytest.MonkeyPatch) -> None:
    installed = deepcopy(tiers.core_tier_progression.installed_core_route_inventory())
    selected = next(row for row in installed["family_cells"]
                    if row["object_kind"] == "VERIFIER" and row["tier"] == 1)
    selected["registered_route_membership_count"] += 1
    monkeypatch.setattr(
        tiers.core_tier_progression,
        "installed_core_route_inventory",
        lambda: installed,
    )
    monkeypatch.setattr(
        tiers,
        "_attempt_tier1",
        lambda *_args, **_kwargs: pytest.fail("attempt preceded denominator validation"),
    )

    report = tiers.assess_self_polish_tier(1, source_root="selected-source")

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "INSTALLED_ROUTE_INVENTORY_TOTAL_DIFFERS" in report["blockers"]


def test_tier1_union_count_is_derived_from_installed_denominator(
        monkeypatch: pytest.MonkeyPatch) -> None:
    observed = []
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())

    def union(*_args, **kwargs):
        observed.append(kwargs["expected_members"])
        return None

    monkeypatch.setattr(tiers, "_union_summary", union)
    report = tiers.assess_self_polish_tier(1, source_root="selected-source")

    assert observed == [
        report["installed_denominators"]["complete_tiers"]["1"][
            "registered_route_membership_count"
        ]
    ]


def test_unknown_native_attempt_is_not_retyped_as_denominator_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    unavailable = _attempt()
    unavailable.update(
        status="UNKNOWN",
        gate_status="UNKNOWN",
        installed_definition_count=None,
        installed_membership_count=None,
        instantiated_obligation_count=None,
        reason="native source unavailable",
    )
    monkeypatch.setattr(
        tiers, "_attempt_tier1", lambda *_args, **_kwargs: unavailable
    )

    report = tiers.assess_self_polish_tier(1, source_root="selected-source")

    assert report["status"] == "UNKNOWN"
    assert "CORE_SELF_POLISH_ATTEMPT_NOT_PASS" in report["blockers"]
    assert "SELF_POLISH_DENOMINATOR_DIFFERS" not in report["blockers"]


def test_unknown_native_attempt_with_declared_wrong_counts_fails_closed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    inconsistent = _attempt()
    inconsistent.update(
        status="UNKNOWN",
        gate_status="UNKNOWN",
        installed_definition_count=999,
        reason="native replay incomplete",
    )
    monkeypatch.setattr(
        tiers, "_attempt_tier1", lambda *_args, **_kwargs: inconsistent
    )

    report = tiers.assess_self_polish_tier(1, source_root="selected-source")

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "SELF_POLISH_DENOMINATOR_DIFFERS" in report["blockers"]


def test_tier1_removed_facet_reason_stops_before_downstream_closure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = facet_reasons.installed_facet_reason_ledger()
    choices = deepcopy(ledger["choices"])
    choices[0]["reason"] = ""
    choices[0]["reason_digest"] = core_obligation_union.value_digest("")
    choices[0].pop("choice_digest")
    choices[0]["choice_digest"] = core_obligation_union.value_digest(
        choices[0]
    )
    incomplete = facet_reasons.assess_facet_reason_choices(
        choices, ledger["domain_route_reasons"]
    )
    assert incomplete["status"] == "UNKNOWN"
    assert incomplete["qualifying_facet_choice_reason_count"] == 129

    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        facet_reasons,
        "installed_facet_reason_assessment",
        lambda: deepcopy(incomplete),
    )
    monkeypatch.setattr(
        tiers,
        "_candidate_estate_inputs",
        lambda **_kwargs: pytest.fail("estate ran before the reason gate"),
    )
    monkeypatch.setattr(
        tiers,
        "_union_summary",
        lambda *_args, **_kwargs: pytest.fail("union ran before the reason gate"),
    )

    report = tiers.assess_self_polish_tier(
        1,
        source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
    )

    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert report["tier1_facet_choice_reasons"]["assessment_digest"] \
        == incomplete["assessment_digest"]
    assert report["tier1_facet_choice_reasons"][
        "consumer_route_partition"
    ]["route_union_membership_count"] == 45
    assert "FACET_CHOICE_NECESSITY_REASON_NOT_ESTABLISHED" \
        in report["blockers"]
    assert report["installed_route_normative_closure"] == "NOT_ESTABLISHED"
    assert report["structural_route_crosswalk_closure"] == "NOT_ESTABLISHED"
    assert report["union_validation"] is None
    assert report["complete_tier_ledger"] is None
    assert report["complete_self_representation"] is None


def test_tier1_missing_domain_route_reason_stops_before_downstream_closure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = facet_reasons.installed_facet_reason_ledger()
    incomplete = facet_reasons.assess_facet_reason_choices(
        ledger["choices"], ledger["domain_route_reasons"][:-1]
    )
    assert incomplete["status"] == "UNKNOWN"
    assert incomplete["qualifying_domain_route_reason_count"] == 17
    assert incomplete["domain_route_reason_deficit"] == 1
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        facet_reasons,
        "installed_facet_reason_assessment",
        lambda: deepcopy(incomplete),
    )
    monkeypatch.setattr(
        tiers, "_candidate_estate_inputs",
        lambda **_kwargs: pytest.fail("estate ran before the reason gate"),
    )
    monkeypatch.setattr(
        tiers, "_union_summary",
        lambda *_args, **_kwargs: pytest.fail("union ran before the reason gate"),
    )

    report = tiers.assess_self_polish_tier(
        1, source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
    )

    assert report["status"] == report["selected_tier_status"] == "UNKNOWN"
    assert "FACET_CHOICE_NECESSITY_REASON_NOT_ESTABLISHED" \
        in report["blockers"]
    assert "DOMAIN_ROUTE_REASONS_MISSING" in report["blockers"]
    assert report["union_validation"] is None
    assert report["complete_tier_ledger"] is None
    assert report["complete_self_representation"] is None


def test_tier1_stale_blank_reason_digests_propagate_producer_fail(
        monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = facet_reasons.installed_facet_reason_ledger()
    choices = deepcopy(ledger["choices"])
    choices[0]["reason"] = ""
    rejected = facet_reasons.assess_facet_reason_choices(
        choices, ledger["domain_route_reasons"]
    )
    assert rejected["status"] == "FAIL"
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())
    monkeypatch.setattr(
        facet_reasons,
        "installed_facet_reason_assessment",
        lambda: deepcopy(rejected),
    )
    monkeypatch.setattr(
        tiers, "_candidate_estate_inputs",
        lambda **_kwargs: pytest.fail("estate ran after producer FAIL"),
    )

    report = tiers.assess_self_polish_tier(
        1, source_root="selected-source",
        expected_core_selection_digest="sha256:" + "3" * 64,
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "FACET_CHOICE_NECESSITY_REASON_REJECTED" in report["blockers"]
    assert "FACET_REASON_DIGEST_OR_CHOICE_INVALID" in report["blockers"]
    assert report["candidate_estate_census"] is None


def test_tier1_report_parser_has_dedicated_cap_without_widening_other_inputs(
        ) -> None:
    raw = b'"' + (b"x" * (tiers.MAX_INPUT_BYTES + 1)) + b'"'

    with pytest.raises(tiers._ContractError, match="ORDINARY_INPUT_INVALID"):
        tiers._parse(raw, "ORDINARY_INPUT_INVALID")

    assert len(tiers._parse(
        raw,
        "TIER1_REPORT_INVALID",
        max_bytes=tiers.MAX_TIER1_REPORT_BYTES,
    )) == tiers.MAX_INPUT_BYTES + 1


def test_tier1_report_reader_rejects_sixteen_mib_plus_one(
        tmp_path: Path) -> None:
    selected = tmp_path / "oversized-tier1.json"
    selected.write_bytes(b"x" * (tiers.MAX_TIER1_REPORT_BYTES + 1))

    with pytest.raises(OSError, match="bounded input unavailable"):
        tiers._read(str(selected), tiers.MAX_TIER1_REPORT_BYTES)


def test_tier2_cli_ingests_dedicated_cap_without_running_progression(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    selected = tmp_path / "large-tier1.json"
    selected.write_bytes(
        b'"' + (b"x" * (tiers.MAX_INPUT_BYTES + 1)) + b'"'
    )
    observed = {}

    def assess(tier, **kwargs):
        observed.update(tier=tier, report=kwargs["tier1_report_bytes"])
        return tiers._finish(tiers._base_report(tier, {}))

    monkeypatch.setattr(tiers, "assess_self_polish_tier", assess)
    exit_code = tiers.handle_self_polish_tier_argv([
        "2", "--native-specimens", "--tier1-report", str(selected),
        "--tier1-report-digest", "sha256:" + "1" * 64,
        "--json",
    ])

    assert exit_code == 2
    assert observed == {"tier": 2, "report": selected.read_bytes()}
    assert json.loads(capsys.readouterr().out)["status"] == "UNKNOWN"


def test_tier1_pass_wire_is_self_consumable_and_counts_final_newline(
        monkeypatch: pytest.MonkeyPatch) -> None:
    report, _ = _fully_bound_retained_tier1(monkeypatch)
    retained = tiers._guard_tier1_report_wire_capacity(report)
    wire = tiers._json_report_wire_bytes(retained)

    assert retained["status"] == "PASS"
    assert len(wire) <= tiers.MAX_TIER1_REPORT_BYTES
    assert tiers._parse(
        wire, "TIER1_REPORT_INVALID",
        max_bytes=tiers.MAX_TIER1_REPORT_BYTES,
    )["report_digest"] == report["report_digest"]

    exact = {
        "status": "PASS", "selected_tier_status": "PASS",
        "whole_tier_conformance": "PASS", "blockers": [], "padding": "",
    }
    without_newline = tiers._json_report_wire_bytes(exact)[:-1]
    monkeypatch.setattr(tiers, "MAX_TIER1_REPORT_BYTES", len(without_newline))
    refused = tiers._guard_tier1_report_wire_capacity(exact)
    assert len(tiers._json_report_wire_bytes(exact)) \
        == tiers.MAX_TIER1_REPORT_BYTES + 1
    assert refused["status"] == refused["selected_tier_status"] == "FAIL"
    assert refused["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert refused["blockers"] \
        == ["TIER1_PASS_REPORT_TRANSPORT_CAPACITY_EXHAUSTED"]


def test_retained_native_tier1_accepts_exact_absent_authority_envelope_for_full_estate(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained, candidate_estate = _fully_bound_retained_tier1(
        monkeypatch,
        candidate_count=9_881,
        authority_unknown=True,
    )
    wire = core_obligation_union.canonical_bytes(retained)

    assert len(wire) <= tiers.MAX_TIER1_REPORT_BYTES
    assert candidate_estate["candidate_count"] == 9_881
    selected = tiers._retained_tier1(
        wire,
        retained["report_digest"],
        installed_denominators=retained["installed_denominators"],
        source_root="selected-source",
    )

    assert selected is not None
    assert selected["status"] == "PASS"
    assert selected["candidate_estate_authority"]["status"] == "UNKNOWN"
    assert selected["candidate_estate_authority"]["blockers"] \
        == ["ESTATE_AUTHORITY_RECEIPT_UNAVAILABLE"]
    assert selected["candidate_estate_evidence"][
        "native_self_verification_status"
    ] == "PASS"
    assert len(selected["candidate_estate_evidence"][
        "candidate_results"
    ]) == 9_881
    assert selected["core_progression_attempt"] is None


def test_retained_tier1_rejects_self_hashed_application_authority_pass(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained, _ = _fully_bound_retained_tier1(monkeypatch, authority_unknown=True)
    retained["application_authority"] = {"status": "PASS"}
    retained["authority_status"] = "PASS"
    retained.pop("report_digest")
    retained = tiers._finish(retained)
    with pytest.raises(tiers._ContractError, match="TIER1_APPLICATION_AUTHORITY"):
        tiers._retained_tier1(
            core_obligation_union.canonical_bytes(retained), retained["report_digest"],
            installed_denominators=retained["installed_denominators"],
            source_root="selected-source",
        )


def test_retained_tier1_rejects_rehashed_missing_authority_condition_reason(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained, _ = _fully_bound_retained_tier1(monkeypatch, authority_unknown=True)
    authority = retained["application_authority"]
    authority["obligation"].pop("necessity_reason")
    authority.pop("assessment_digest")
    authority["assessment_digest"] = core_obligation_union.value_digest(authority)
    retained.pop("report_digest")
    retained = tiers._finish(retained)
    with pytest.raises(tiers._ContractError, match="TIER1_APPLICATION_AUTHORITY"):
        tiers._retained_tier1(
            core_obligation_union.canonical_bytes(retained), retained["report_digest"],
            installed_denominators=retained["installed_denominators"],
            source_root="selected-source",
        )


@pytest.mark.parametrize("mutation", [
    "blockers", "policy", "actors", "replay", "status", "boundary",
])
def test_retained_tier1_rejects_rehashed_noncanonical_authority_unknown(
        monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    retained, _ = _fully_bound_retained_tier1(
        monkeypatch, authority_unknown=True
    )
    authority = retained["candidate_estate_authority"]
    if mutation == "blockers":
        authority["blockers"] = []
    elif mutation == "policy":
        authority["policy_digest"] = "sha256:" + "1" * 64
    elif mutation == "actors":
        authority["approving_actors"] = ["unexpected-authority"]
    elif mutation == "replay":
        authority["replay_status"] = "REPRODUCED"
    elif mutation == "status":
        authority["status"] = "FAIL"
        authority["independent_authority_status"] = "FAIL"
    else:
        authority["claim_boundary"] = "Substituted boundary."
    authority.pop("result_digest")
    authority["result_digest"] = estate.value_digest(authority)
    retained.pop("report_digest")
    retained = tiers._finish(retained)

    with pytest.raises(
            tiers._ContractError,
            match="TIER1_CANDIDATE_ESTATE_AUTHORITY_INVALID"):
        tiers._retained_tier1(
            core_obligation_union.canonical_bytes(retained),
            retained["report_digest"],
            installed_denominators=retained["installed_denominators"],
            source_root="selected-source",
        )


def test_retained_tier1_rejects_rehashed_unknown_top_level_field(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained, _ = _fully_bound_retained_tier1(monkeypatch)
    retained["unknown_top_level"] = "rehashed injection"
    retained.pop("report_digest")
    retained = tiers._finish(retained)

    with pytest.raises(tiers._ContractError, match="TIER1_REPORT_INVALID"):
        tiers._retained_tier1(
            core_obligation_union.canonical_bytes(retained),
            retained["report_digest"],
            installed_denominators=retained["installed_denominators"],
            source_root="selected-source",
        )


def test_retained_tier1_rejects_rehashed_stripped_candidate_results(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained, _ = _fully_bound_retained_tier1(monkeypatch)
    evidence_result = retained["candidate_estate_evidence"]
    evidence_result["candidate_results"] = evidence_result[
        "candidate_results"
    ][:-1]
    evidence_result["candidate_count"] -= 1
    evidence_result["candidate_pass_count"] -= 1
    evidence_result["native_candidate_pass_count"] -= 1
    evidence_result["native_replayed_candidate_count"] -= 1
    evidence_result["authenticated_candidate_count"] -= 1
    evidence_result["applicable_candidate_count"] -= 1
    evidence_result["native_applicable_candidate_count"] -= 1
    evidence_result["native_evidence_artifact_count"] -= 1
    evidence_result.pop("result_digest")
    evidence_result["result_digest"] = estate_evidence.value_digest(
        evidence_result
    )
    retained["complete_self_representation"][
        "estate_evidence_result_digest"
    ] = evidence_result["result_digest"]
    retained["repository_package_estate"][
        "estate_evidence_result_digest"
    ] = evidence_result["result_digest"]
    retained.pop("report_digest")
    retained = tiers._finish(retained)

    with pytest.raises(
            tiers._ContractError,
            match="CANDIDATE_ESTATE_EVIDENCE_CANDIDATE_SET_DIFFERS"):
        tiers._retained_tier1(
            core_obligation_union.canonical_bytes(retained),
            retained["report_digest"],
            installed_denominators=retained["installed_denominators"],
            source_root="selected-source",
        )


def test_retained_tier1_rejects_nested_result_digest_and_census_substitution(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained, _ = _fully_bound_retained_tier1(monkeypatch)
    retained["candidate_estate_evidence"]["candidate_results"][0][
        "blockers"
    ] = ["REHASH_REQUIRED"]
    retained.pop("report_digest")
    retained = tiers._finish(retained)

    with pytest.raises(
            tiers._ContractError,
            match="CANDIDATE_ESTATE_EVIDENCE_RESULT_DIGEST_DIFFERS"):
        tiers._retained_tier1(
            core_obligation_union.canonical_bytes(retained),
            retained["report_digest"],
            installed_denominators=retained["installed_denominators"],
            source_root="selected-source",
        )

    retained, _ = _fully_bound_retained_tier1(monkeypatch)
    retained["candidate_estate_census"]["candidate_count"] -= 1
    retained.pop("report_digest")
    retained = tiers._finish(retained)
    with pytest.raises(
            tiers._ContractError,
            match="TIER1_CANDIDATE_ESTATE_CENSUS_DIFFERS"):
        tiers._retained_tier1(
            core_obligation_union.canonical_bytes(retained),
            retained["report_digest"],
            installed_denominators=retained["installed_denominators"],
            source_root="selected-source",
        )


@pytest.mark.parametrize("old_schema", [
    "verifier-self-polish-tier-assessment-1",
    "verifier-self-polish-tier-assessment-2",
    "verifier-self-polish-tier-assessment-3",
])
def test_pre_reason_tier1_report_cannot_promote_tier2(
        monkeypatch: pytest.MonkeyPatch, old_schema: str) -> None:
    retained = _fully_pass_retained_tier1(replay_complete=True)
    retained["schema_version"] = old_schema
    retained.pop("report_digest")
    retained["report_digest"] = core_obligation_union.value_digest(retained)
    monkeypatch.setattr(
        tiers.core_tier_progression,
        "assess_tier_progression",
        lambda *_args, **_kwargs: pytest.fail(
            "Tier 2 ran from a pre-reason Tier 1 report"
        ),
    )

    report = tiers.assess_self_polish_tier(
        2,
        source_root="selected-source",
        tier1_report_bytes=core_obligation_union.canonical_bytes(retained),
        expected_tier1_report_digest=retained["report_digest"],
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "TIER1_REPORT_INVALID" in report["blockers"]
    assert report["core_progression_attempt"] is None


def test_stripped_v4_reason_partition_cannot_promote_tier2(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained = _fully_pass_retained_tier1(replay_complete=True)
    retained["tier1_facet_choice_reasons"].pop(
        "consumer_route_partition"
    )
    retained.pop("report_digest")
    retained["report_digest"] = core_obligation_union.value_digest(retained)
    monkeypatch.setattr(
        tiers.core_tier_progression,
        "assess_tier_progression",
        lambda *_args, **_kwargs: pytest.fail(
            "Tier 2 ran from a stripped Tier 1 reason partition"
        ),
    )

    report = tiers.assess_self_polish_tier(
        2,
        source_root="selected-source",
        tier1_report_bytes=core_obligation_union.canonical_bytes(retained),
        expected_tier1_report_digest=retained["report_digest"],
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "TIER1_FACET_CHOICE_REASONS_NOT_ESTABLISHED" \
        in report["blockers"]
    assert report["core_progression_attempt"] is None


def test_tier2_unknown_tier1_stops_before_progression(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained = _retained_tier1("UNKNOWN")
    raw = core_obligation_union.canonical_bytes(retained)
    monkeypatch.setattr(
        tiers.core_tier_progression,
        "assess_tier_progression",
        lambda *_args, **_kwargs: pytest.fail("tier 2 ran before tier 1 passed"),
    )

    report = tiers.assess_self_polish_tier(
        2,
        tier1_report_bytes=raw,
        expected_tier1_report_digest=retained["report_digest"],
    )

    assert report["status"] == "UNKNOWN"
    assert report["core_progression_attempt"] is None
    assert report["blockers"] == ["TIER1_FULL_PASS_REQUIRED"]


def test_tier2_rejects_tampered_tier1_before_progression(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained = _fully_pass_retained_tier1()
    retained["source_binding_status"] = "UNKNOWN"
    raw = core_obligation_union.canonical_bytes(retained)
    monkeypatch.setattr(
        tiers.core_tier_progression,
        "assess_tier_progression",
        lambda *_args, **_kwargs: pytest.fail("tampered tier 1 reached tier 2"),
    )

    report = tiers.assess_self_polish_tier(
        2,
        tier1_report_bytes=raw,
        expected_tier1_report_digest=retained["report_digest"],
    )

    assert report["status"] == "FAIL"
    assert "TIER1_REPORT_DIGEST_DIFFERS" in report["blockers"]
    assert report["core_progression_attempt"] is None


@pytest.mark.parametrize(
    ("mutation", "blocker"),
    [
        ("component", "TIER1_FULL_ESTATE_CLOSURE_NOT_ESTABLISHED"),
        ("whole-tier", "TIER1_FULL_ESTATE_CLOSURE_NOT_ESTABLISHED"),
        ("denominator", "TIER1_REPORT_DENOMINATOR_DIFFERS"),
    ],
)
def test_tier2_rejects_rehashed_tier1_substitution_before_progression(
        mutation: str, blocker: str,
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained = _fully_pass_retained_tier1(replay_complete=True)
    if mutation == "component":
        retained["source_binding_status"] = "UNKNOWN"
    elif mutation == "whole-tier":
        retained["whole_tier_conformance"] = "NOT_ESTABLISHED"
    else:
        retained["installed_denominators"][
            "installed_structural_membership_count"
        ] += 1
    retained.pop("report_digest")
    retained = tiers._finish(retained)
    monkeypatch.setattr(
        tiers.core_tier_progression,
        "assess_tier_progression",
        lambda *_args, **_kwargs: pytest.fail("invalid tier 1 reached tier 2"),
    )

    report = tiers.assess_self_polish_tier(
        2,
        tier1_report_bytes=core_obligation_union.canonical_bytes(retained),
        expected_tier1_report_digest=retained["report_digest"],
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert blocker in report["blockers"]
    assert report["core_progression_attempt"] is None


def test_tier2_never_runs_from_asserted_tier1_pass_without_mechanical_replay(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained = _fully_pass_retained_tier1()
    retained_bytes = core_obligation_union.canonical_bytes(retained)
    selection = {
        "ranks": [
            {"node_id": "facets-object", "tier": 1},
            {"node_id": "facets-verifier", "tier": 1},
            {"node_id": "dynamics", "tier": 2},
        ]
    }
    bundle = {
        "edges": [
            {"node_id": "dynamics", "prerequisite_id": "facets-object",
             "operand_role": "object"},
            {"node_id": "dynamics", "prerequisite_id": "facets-verifier",
             "operand_role": "verifier"},
        ]
    }
    calls = []

    def progression(*_args, **_kwargs):
        calls.append("progression")
        return {
            "status": "PASS",
            "selected_target_status": "PASS",
            "subject": {"object_id": "verifier-core-self"},
            "tiers": [
                {"cumulative_status": "PASS", "direct_status": "PASS"},
                {"cumulative_status": "PASS", "direct_status": "PASS"},
            ],
        }

    monkeypatch.setattr(tiers.core_tier_progression,
                        "assess_tier_progression", progression)
    report = tiers.assess_self_polish_tier(
        2,
        tier1_report_bytes=retained_bytes,
        expected_tier1_report_digest=retained["report_digest"],
        progression_selection_bytes=core_obligation_union.canonical_bytes(selection),
        progression_bundle_bytes=core_obligation_union.canonical_bytes(bundle),
        progression_policy_bytes=b"{}",
        progression_artifact_files={},
        expected_progression_selection_digest="sha256:" + "4" * 64,
        expected_progression_mechanism_digest="sha256:" + "5" * 64,
    )

    assert calls == []
    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert "TIER1_WHOLE_TIER_REPLAY_NOT_ESTABLISHED" in report["blockers"]
    assert report["core_progression_attempt"] is None
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"


def test_tier2_rejects_forged_nested_replay_flags_before_progression(
        monkeypatch: pytest.MonkeyPatch) -> None:
    retained = _fully_pass_retained_tier1()
    retained["complete_tier_ledger"]["mechanical_replay_status"] = "PASS"
    retained["complete_self_representation"][
        "independent_evidence_status"
    ] = "PASS"
    retained.pop("report_digest")
    retained = tiers._finish(retained)
    selection = {
        "ranks": [
            {"node_id": "facets", "tier": 1},
            {"node_id": "dynamics", "tier": 2},
        ]
    }
    bundle = {"edges": [
        {"node_id": "dynamics", "prerequisite_id": "facets",
         "operand_role": "verifier"},
    ]}
    monkeypatch.setattr(
        tiers.core_tier_progression,
        "assess_tier_progression",
        lambda *_args, **_kwargs: pytest.fail("forged tier 1 reached progression"),
    )

    report = tiers.assess_self_polish_tier(
        2,
        tier1_report_bytes=core_obligation_union.canonical_bytes(retained),
        expected_tier1_report_digest=retained["report_digest"],
        progression_selection_bytes=core_obligation_union.canonical_bytes(selection),
        progression_bundle_bytes=core_obligation_union.canonical_bytes(bundle),
        progression_policy_bytes=b"{}",
        progression_artifact_files={},
        expected_progression_selection_digest="sha256:" + "4" * 64,
        expected_progression_mechanism_digest="sha256:" + "5" * 64,
    )

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert report["blockers"] == ["TIER1_WHOLE_TIER_REPLAY_NOT_ESTABLISHED"]
    assert report["core_progression_attempt"] is None


def test_repeated_missing_input_report_is_canonical_and_stable() -> None:
    first = tiers.assess_self_polish_tier(2)
    second = tiers.assess_self_polish_tier(2)

    assert core_obligation_union.canonical_bytes(first) \
        == core_obligation_union.canonical_bytes(second)
    assert first["blockers"] == ["TIER1_PASS_REPORT_REQUIRED"]


def test_native_replay_refusal_preserves_specific_reason(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiers, "_attempt_tier1", lambda *_args, **_kwargs: _attempt())

    def refuse(*_args, **_kwargs):
        raise tiers.self_polish_native_replay.NativeReplayError(
            "NATIVE_REPLAY_MECHANISM_SOURCE_DIFFERS"
        )

    monkeypatch.setattr(tiers, "_replay_tier_evidence", refuse)
    report = tiers.assess_self_polish_tier(1, source_root="selected-source")
    assert report["status"] == "FAIL"
    assert "NATIVE_REPLAY_MECHANISM_SOURCE_DIFFERS" in report["blockers"]
    assert "SELF_POLISH_TIER_CONTRACT_REJECTED" not in report["blockers"]


@pytest.mark.parametrize("selected", ["1", "2"])
def test_isolated_cli_handler_preserves_literal_numeric_tier(
        selected: str, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    observed = []

    def assess(tier: int, **_kwargs):
        observed.append(tier)
        return tiers._finish(tiers._base_report(tier, {}))

    monkeypatch.setattr(tiers, "assess_self_polish_tier", assess)
    assert tiers.handle_self_polish_tier_argv([selected, "--native-specimens", "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert observed == [int(selected)]
    assert result["tier"] == int(selected)
    assert result["schema_version"] == tiers.REPORT_SCHEMA


def _isolate_tier1_attempt(monkeypatch: pytest.MonkeyPatch, refuse) -> None:
    """Reach only the injected refusal, not the installed-mechanism drift.

    The real ``_denominators`` can raise the same SimDynamicsError before
    ``_attempt_tier1`` runs, so an unisolated test passes or fails for that
    unrelated reason. Tier 1 reads ``denominators`` only after the attempt.
    """

    monkeypatch.setattr(tiers, "_denominators", lambda _object_id: {})
    monkeypatch.setattr(tiers, "_attempt_tier1", refuse)


def test_domain_contract_refusal_retains_bounded_reason_beside_stage_code(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.domains.contracts.sim_dynamics import SimDynamicsError

    def refuse(*_args, **_kwargs):
        raise SimDynamicsError("policy differs from installed mechanism")

    _isolate_tier1_attempt(monkeypatch, refuse)
    report = tiers.assess_self_polish_tier(1, source_root="selected-source")

    assert report["status"] == report["selected_tier_status"] == "FAIL"
    assert report["blockers"] == [
        "SELF_POLISH_TIER_CONTRACT_REJECTED",
        "SELF_POLISH_TIER_CONTRACT_REJECTED:"
        "POLICY_DIFFERS_FROM_INSTALLED_MECHANISM",
    ]


@pytest.mark.parametrize("message", [
    "SUBJECT-LEAK-" + "x" * 400,
    "subject 123 leaks: " + "y" * 300,
    "bad\x1b[31m subject leak",
    "",
])
def test_unbounded_or_punctuated_domain_refusal_keeps_only_stage_code(
        message: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.domains.contracts.sim_dynamics import SimDynamicsError

    def refuse(*_args, **_kwargs):
        raise SimDynamicsError(message)

    _isolate_tier1_attempt(monkeypatch, refuse)
    report = tiers.assess_self_polish_tier(1, source_root="selected-source")

    assert report["blockers"] == ["SELF_POLISH_TIER_CONTRACT_REJECTED"]
    serialized = json.dumps(report, sort_keys=True)
    assert "LEAK" not in serialized
    assert "Traceback" not in serialized
    assert "\x1b" not in serialized


def test_bare_builtin_refusal_text_never_reaches_stage_report(
        monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args, **_kwargs):
        raise ValueError("policy differs from installed mechanism")

    _isolate_tier1_attempt(monkeypatch, refuse)
    report = tiers.assess_self_polish_tier(1, source_root="selected-source")

    assert report["blockers"] == ["SELF_POLISH_TIER_CONTRACT_REJECTED"]
