"""Independent checks for the external Tier 1 (FACETS) ledger builder."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from scripts import build_self_polish_tier1_ledger as builder
from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_evidence
from verifier.runtime import self_polish_tiers
from verifier.runtime.core_tier_progression import installed_core_route_inventory


ROOT = Path(__file__).parents[1]
EXPECTED_INVENTORY_DIGEST = (
    "sha256:674bab9a72bb4e94103c0f582f3fc1e32c87d6a73747400de5e8e9ca792fa07f"
)
EXPECTED_TIER1_IDENTITY_DIGEST = (
    "sha256:c7206a2c3efd9af4c52590ea7d700bb6f6e56d748e888e6e27f42dfedc6d0b95"
)
EXPECTED_MAPPING_DIGEST = (
    "sha256:adc9358a4f73f2a6b673b277ff8fe684f43fc939879d6b2cdaec254fe618bf99"
)
EXPECTED_MANIFEST_DIGEST = (
    "sha256:0b7b0dc14c181f6c4682140740968f11dab20dac2ca8b56b79986f9dad569475"
)


def _source_coordinate(revision: str = "a" * 40) -> dict[str, str]:
    return {
        "source_head": revision,
        "source_tree": "b" * 40,
        "source_worktree_status_digest": "sha256:" + "c" * 64,
        "source_manifest_digest": "sha256:" + "d" * 64,
    }


def _identity_rows(ledger: dict[str, object]) -> list[dict[str, object]]:
    entries = ledger["entries"]
    assert isinstance(entries, list)
    return [entry["membership"] for entry in entries]


def test_tier1_ledger_binds_exact_installed_denominator_and_digests() -> None:
    ledger = builder.build_ledger(_source_coordinate(), root=ROOT)
    body = {key: value for key, value in ledger.items() if key != "ledger_digest"}

    assert ledger["schema_version"] == self_polish_tiers.TIER_LEDGER_SCHEMA
    assert ledger["tier"] == 1
    assert ledger["tier_name"] == "FACETS"
    assert ledger["installed_family_cell_count_total"] == 234
    assert ledger["installed_membership_count_total"] == 408
    assert ledger["tier_family_cell_count"] == 26
    assert ledger["tier_membership_count"] == 45
    assert ledger["installed_inventory_digest"] == EXPECTED_INVENTORY_DIGEST
    assert core_obligation_union.value_digest(_identity_rows(ledger)) \
        == EXPECTED_TIER1_IDENTITY_DIGEST
    assert ledger["ledger_digest"] == core_obligation_union.value_digest(body)


def test_tier1_ledger_has_no_omissions_duplicates_or_unresolved_source_paths() -> None:
    ledger = builder.build_ledger(_source_coordinate(), root=ROOT)
    inventory = installed_core_route_inventory()
    expected = sorted(
        (
            cell["object_kind"],
            member["coordinate"],
            member["checking_mechanism"],
        )
        for cell in inventory["family_cells"]
        if cell["tier"] == 1
        for member in cell["registered_route_memberships"]
    )
    entries = ledger["entries"]
    observed = sorted(
        (
            entry["membership"]["object_kind"],
            entry["membership"]["coordinate"],
            entry["implementation"]["checking_mechanism"],
        )
        for entry in entries
    )

    assert observed == expected
    assert len({entry["obligation_id"] for entry in entries}) == 45
    for entry in entries:
        mechanism = entry["membership"]["checking_mechanism"]
        module_name, symbol = mechanism.rsplit(".", 1)
        source = "src/" + module_name.replace(".", "/") + ".py"
        files = entry["implementation"]["files"]
        assert files[0] == source
        assert (ROOT / source).is_file()
        assert entry["implementation"]["symbols"] == [symbol]
        candidates = files[1:-1]
        assert candidates == sorted(candidates)
        assert candidates
        assert all(path.startswith("tests/test_") and (ROOT / path).is_file()
                   for path in candidates)
        assert files[-1] == self_polish_evidence.PRIMARY_MECHANISM_PATH


def test_template_is_fail_closed_and_consumed_as_unknown() -> None:
    coordinate = _source_coordinate()
    ledger = builder.build_ledger(coordinate, root=ROOT)

    for entry in ledger["entries"]:
        assert all(entry[name] == "UNKNOWN" for name in (
            "applicability_status", "authority_status", "observation_status",
            "native_assessment_status", "provider_review_status",
            "final_disposition",
        ))
        assert entry["implementation_status"] == "NOT_ESTABLISHED"
        assert entry["native_assessment_digest"] is None
        assert entry["evidence"]["freshness"] == "UNKNOWN"
        assert entry["focused_validation"] == {
            "status": "UNKNOWN", "receipt_digest": None,
        }
        assert entry["independent_replay"] == {
            "status": "UNKNOWN", "receipt_digest": None,
        }
        assert entry["provider_records"] == {
            "claude": {
                "state": "CLAUDE_PROVIDER_BLOCKED", "receipt_digest": None,
            },
            "antigravity": {
                "state": "ANTIGRAVITY_PROVIDER_BLOCKED", "receipt_digest": None,
            },
        }
        assert "candidate until" in entry["expected_behavior"]["negative"]
        assert entry["justified_exclusion"] is None

    denominators = self_polish_tiers._denominators("verifier-core-self")
    result = self_polish_tiers._complete_tier_ledger(
        core_obligation_union.canonical_bytes(ledger),
        expected_digest=ledger["ledger_digest"],
        source_coordinate=coordinate,
        tier=1,
        denominators=denominators,
    )
    assert result == {
        "status": "UNKNOWN",
        "declared_status": "UNKNOWN",
        "mechanical_replay_status": "NOT_ESTABLISHED",
        "replay_receipt_digest": None,
        "replay_bound_membership_count": 0,
        "ledger_digest": ledger["ledger_digest"],
        "tier": 1,
        "tier_name": "FACETS",
        "installed_family_cell_count_total": 234,
        "installed_membership_count_total": 408,
        "tier_family_cell_count": 26,
        "tier_membership_count": 45,
        "declared_pass_membership_count": 0,
        "fail_status_count": 0,
        "unresolved_status_count": 495,
        "provider_fail_status_count": 0,
        "provider_coverage_exception_count": 90,
        "provider_coverage_exception_membership_count": 45,
        "provider_review_status_counts": {"UNKNOWN": 45},
        "provider_state_counts": {
            "claude:CLAUDE_PROVIDER_BLOCKED": 45,
            "antigravity:ANTIGRAVITY_PROVIDER_BLOCKED": 45,
        },
        "membership_identity_digest": EXPECTED_TIER1_IDENTITY_DIGEST,
    }


@pytest.mark.parametrize("mutation", ["omit", "duplicate"])
def test_modified_installed_denominator_is_rejected(mutation: str) -> None:
    inventory = deepcopy(installed_core_route_inventory())
    tier1 = next(cell for cell in inventory["family_cells"] if cell["tier"] == 1)
    if mutation == "omit":
        tier1["registered_route_memberships"].pop()
        tier1["registered_route_membership_count"] -= 1
        inventory["registered_route_membership_count"] -= 1
        inventory["registered_route_membership_count_by_tier"]["1"] -= 1
    else:
        inventory["family_cells"].append(deepcopy(tier1))
        inventory["family_cell_count"] += 1

    with pytest.raises(ValueError):
        builder.build_ledger(_source_coordinate(), root=ROOT, inventory=inventory)


def test_cli_writes_an_external_unknown_template(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    coordinate = tmp_path / "source-coordinate.json"
    output = tmp_path / "tier1-ledger.json"
    coordinate.write_text(json.dumps(_source_coordinate()), encoding="utf-8")

    assert builder.main([
        "--source-coordinate", str(coordinate), "--output", str(output),
    ]) == 0
    ledger = json.loads(output.read_text(encoding="utf-8"))
    assert ledger["tier_membership_count"] == 45
    assert all(entry["final_disposition"] == "UNKNOWN"
               for entry in ledger["entries"])
    assert ledger["ledger_digest"] in capsys.readouterr().out


def test_evidence_manifest_has_exact_unique_semantic_denominator_and_digests() -> None:
    manifest = builder.build_evidence_manifest(root=ROOT)
    obligations = manifest["obligations"]
    identifiers = sorted({row["obligation_id"] for row in obligations})

    assert len(identifiers) == 45
    assert len(obligations) == 135
    assert len({row["node_id"] for row in obligations}) == 135
    assert len({entry["membership"]["checking_mechanism"]
                for entry in builder.build_ledger(
                    _source_coordinate(), root=ROOT,
                )["entries"]}) == 15
    assert all(not Path(row["test_path"]).name.startswith("test_self_polish")
               for row in obligations)
    assert all([
        row["case_kind"] for row in obligations
        if row["obligation_id"] == identifier
    ] == list(self_polish_evidence.CASE_KIND_ORDER) for identifier in identifiers)
    assert builder._obligation_mapping_digest(identifiers) == EXPECTED_MAPPING_DIGEST
    assert self_polish_evidence.bytes_digest(
        self_polish_evidence.canonical_bytes(manifest)
    ) == EXPECTED_MANIFEST_DIGEST
    assert len(manifest["files"]) == 32
    assert {row["role"] for row in manifest["files"]} == {
        "SOURCE", "TEST", "MECHANISM",
    }


@pytest.mark.parametrize("mutation", [
    "incomplete", "duplicate", "substituted", "mismatched", "stale",
])
def test_adversarial_manifest_mapping_is_rejected(mutation: str) -> None:
    manifest = builder.build_evidence_manifest(root=ROOT)
    changed = deepcopy(manifest)
    if mutation == "incomplete":
        changed["obligations"].pop()
    elif mutation == "duplicate":
        changed["obligations"][1]["node_id"] = changed["obligations"][0]["node_id"]
    elif mutation == "substituted":
        changed["obligations"][0]["node_id"], changed["obligations"][3]["node_id"] = (
            changed["obligations"][3]["node_id"], changed["obligations"][0]["node_id"]
        )
    elif mutation == "mismatched":
        test = next(row for row in changed["files"] if row["role"] == "TEST")
        test["sha256"] = "sha256:" + "0" * 64
    else:
        source = next(row for row in changed["files"] if row["role"] == "SOURCE")
        source["sha256"] = "sha256:" + "f" * 64

    with pytest.raises(ValueError, match="incomplete, substituted, duplicated, or stale"):
        builder.validate_evidence_manifest(changed, root=ROOT)


def _synthetic_replay_receipt(manifest: dict[str, object]) -> dict[str, object]:
    obligations = manifest["obligations"]
    files = {row["path"]: row for row in manifest["files"]}
    identifiers = sorted({row["obligation_id"] for row in obligations})
    memberships = []
    for index, identifier in enumerate(identifiers, start=1):
        cases = []
        for row in [item for item in obligations if item["obligation_id"] == identifier]:
            cases.append({
                "case_kind": row["case_kind"],
                "node_id": row["node_id"],
                "source": {
                    "path": row["source_path"],
                    "sha256": files[row["source_path"]]["sha256"],
                },
                "test": {
                    "path": row["test_path"],
                    "sha256": files[row["test_path"]]["sha256"],
                },
                "mechanism": {
                    "path": row["mechanism_path"],
                    "sha256": files[row["mechanism_path"]]["sha256"],
                },
                "status": "PASS",
            })
        memberships.append({
            "obligation_id": identifier,
            "cases": cases,
            "status": "PASS",
            "stable_replay_digest": f"sha256:{index:064x}",
        })
    manifest_digest = self_polish_evidence.bytes_digest(
        self_polish_evidence.canonical_bytes(manifest)
    )
    observed = {row["path"]: row["sha256"] for row in manifest["files"]}
    mechanism_digest = files[self_polish_evidence.PRIMARY_MECHANISM_PATH]["sha256"]
    receipt = {
        "schema_version": self_polish_evidence.RECEIPT_SCHEMA,
        "status": "PASS",
        "tier": 1,
        "polished": False,
        "release_authority": "NONE",
        "whole_tier_conformance": "NOT_ESTABLISHED",
        "provider_states": "OUT_OF_SCOPE",
        "manifest_digest": manifest_digest,
        "expected_manifest_digest": manifest_digest,
        "mechanism_digest": mechanism_digest,
        "expected_mechanism_digest": mechanism_digest,
        "obligation_mapping_digest": builder._obligation_mapping_digest(identifiers),
        "stable_replay_set_digest": "sha256:" + "e" * 64,
        "evidence_digest": "sha256:" + "d" * 64,
        "run_artifacts": {
            "pytest_trace_digest": "sha256:" + "1" * 64,
            "junit_xml_digest": "sha256:" + "2" * 64,
            "stdout_digest": "sha256:" + "3" * 64,
            "stderr_digest": "sha256:" + "4" * 64,
        },
        "source_coordinate": {
            **manifest["source_coordinate"],
            "selected_files_digest": self_polish_evidence.bytes_digest(
                self_polish_evidence.canonical_bytes(observed)
            ),
            "scope": "SELECTED_FILES_ONLY",
        },
        "memberships": memberships,
        "counts": {
            "expected": 135, "collected": 135, "passed": 135,
            "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0,
        },
        "invalidators": [],
        "claim_boundary": "Synthetic structural receipt; not replay authentication.",
    }
    receipt["receipt_digest"] = self_polish_evidence.bytes_digest(
        self_polish_evidence.canonical_bytes(receipt)
    )
    return receipt


def test_candidate_pipeline_binds_stable_digests_but_does_not_claim_authentication() -> None:
    manifest = builder.build_evidence_manifest(root=ROOT)
    coordinate = _source_coordinate(manifest["source_coordinate"]["revision"])
    ledger = builder.build_ledger(coordinate, root=ROOT)
    receipt = _synthetic_replay_receipt(manifest)

    candidate = builder.consume_replay_receipt(
        ledger, manifest, receipt, root=ROOT,
    )
    assert candidate["stable_candidate"]["authentication_status"] == "NOT_ESTABLISHED"
    assert candidate["stable_candidate"]["requires_fresh_replay"] is True
    assert "not the complete repository/package VERIFIER denominator" \
        in candidate["claim_boundary"]
    assert "completion of vstd polish 1" in candidate["claim_boundary"]
    assert candidate["volatile_event_receipt"] == receipt
    assert candidate["complete_self_representation"][
        "representation_evidence_digest"
    ] == receipt["stable_replay_set_digest"]
    assert all(entry["independent_replay"]["status"] == "PASS"
               for entry in candidate["candidate_ledger"]["entries"])
    assert all(entry["final_disposition"] == "UNKNOWN"
               for entry in candidate["candidate_ledger"]["entries"])
    assert all(entry["provider_records"]["claude"]["state"]
               == "CLAUDE_PROVIDER_BLOCKED"
               for entry in candidate["candidate_ledger"]["entries"])

    denominators = self_polish_tiers._denominators("verifier-core-self")
    reason_assessment = self_polish_tiers._validated_facet_reason_assessment(
        denominators
    )
    ledger_result = self_polish_tiers._complete_tier_ledger(
        core_obligation_union.canonical_bytes(candidate["candidate_ledger"]),
        expected_digest=candidate["candidate_ledger"]["ledger_digest"],
        source_coordinate=coordinate,
        tier=1,
        denominators=denominators,
        evidence_replay=receipt,
    )
    assert ledger_result is not None
    assert ledger_result["mechanical_replay_status"] == "PASS"
    representation = candidate["complete_self_representation"]
    representation_result = self_polish_tiers._complete_self_representation(
        core_obligation_union.canonical_bytes(representation),
        expected_digest=representation["representation_digest"],
        source_coordinate=coordinate,
        tier=1,
        denominators=denominators,
        ledger_digest=candidate["candidate_ledger"]["ledger_digest"],
        prior_whole_tier_report_digest=None,
        evidence_replay=receipt,
        facet_reason_assessment=reason_assessment,
        ledger_mechanical_replay_status=ledger_result[
            "mechanical_replay_status"
        ],
    )
    assert representation_result is not None
    assert representation_result["status"] == "UNKNOWN"
    assert representation_result["independent_evidence_status"] \
        == "NOT_ESTABLISHED"


def test_builder_output_is_exact_and_reproducible() -> None:
    coordinate = _source_coordinate()
    first = builder.build_ledger(coordinate, root=ROOT)
    second = builder.build_ledger(coordinate, root=ROOT)

    assert first == second
    assert first["schema_version"] == self_polish_tiers.TIER_LEDGER_SCHEMA
    assert first["ledger_digest"] == core_obligation_union.value_digest({
        key: value for key, value in first.items() if key != "ledger_digest"
    })


def test_old_ledger_schema_is_rejected_by_current_consumer() -> None:
    coordinate = _source_coordinate()
    ledger = builder.build_ledger(coordinate, root=ROOT)
    ledger["schema_version"] = "verifier-self-polish-complete-tier-ledger-1"
    ledger["ledger_digest"] = core_obligation_union.value_digest({
        key: value for key, value in ledger.items() if key != "ledger_digest"
    })

    with pytest.raises(ValueError, match="COMPLETE_TIER_LEDGER_TIER_DIFFERS"):
        self_polish_tiers._complete_tier_ledger(
            core_obligation_union.canonical_bytes(ledger),
            expected_digest=ledger["ledger_digest"],
            source_coordinate=coordinate,
            tier=1,
            denominators=self_polish_tiers._denominators(
                "verifier-core-self"
            ),
        )


@pytest.mark.parametrize("mutation", ["stripped", "forged"])
def test_malformed_current_ledger_is_rejected(mutation: str) -> None:
    coordinate = _source_coordinate()
    ledger = builder.build_ledger(coordinate, root=ROOT)
    if mutation == "stripped":
        del ledger["entries"][0]["ownership"]
    else:
        ledger["entries"][0]["membership"]["proposition_digest"] = (
            "sha256:" + "f" * 64
        )
    ledger["ledger_digest"] = core_obligation_union.value_digest({
        key: value for key, value in ledger.items() if key != "ledger_digest"
    })

    with pytest.raises(
        ValueError,
        match=(
            "COMPLETE_TIER_LEDGER_ENTRY_INVALID"
            if mutation == "stripped"
            else "COMPLETE_TIER_LEDGER_MEMBERSHIP_DIFFERS"
        ),
    ):
        self_polish_tiers._complete_tier_ledger(
            core_obligation_union.canonical_bytes(ledger),
            expected_digest=ledger["ledger_digest"],
            source_coordinate=coordinate,
            tier=1,
            denominators=self_polish_tiers._denominators(
                "verifier-core-self"
            ),
        )


@pytest.mark.parametrize("mutation", ["membership", "set"])
def test_stable_digest_mismatch_is_rejected(mutation: str) -> None:
    manifest = builder.build_evidence_manifest(root=ROOT)
    coordinate = _source_coordinate(manifest["source_coordinate"]["revision"])
    ledger = builder.build_ledger(coordinate, root=ROOT)
    receipt = _synthetic_replay_receipt(manifest)
    candidate = builder.consume_replay_receipt(ledger, manifest, receipt, root=ROOT)
    fresh = deepcopy(receipt)
    if mutation == "membership":
        fresh["memberships"][0]["stable_replay_digest"] = "sha256:" + "a" * 64
    else:
        fresh["stable_replay_set_digest"] = "sha256:" + "b" * 64
    fresh["receipt_digest"] = self_polish_evidence.bytes_digest(
        self_polish_evidence.canonical_bytes({
            key: value for key, value in fresh.items() if key != "receipt_digest"
        })
    )
    with pytest.raises(ValueError, match="fresh stable replay digest differs"):
        builder.compare_candidate_to_fresh_replay(candidate, fresh, manifest)


def test_fresh_numeric_gate_rejects_substituted_membership_digest() -> None:
    manifest = builder.build_evidence_manifest(root=ROOT)
    coordinate = _source_coordinate(manifest["source_coordinate"]["revision"])
    ledger = builder.build_ledger(coordinate, root=ROOT)
    receipt = _synthetic_replay_receipt(manifest)
    candidate = builder.consume_replay_receipt(ledger, manifest, receipt, root=ROOT)
    substituted = deepcopy(receipt)
    substituted["memberships"][0]["stable_replay_digest"] = "sha256:" + "a" * 64

    with pytest.raises(ValueError, match="COMPLETE_TIER_LEDGER_REPLAY_DIGEST_DIFFERS"):
        self_polish_tiers._complete_tier_ledger(
            core_obligation_union.canonical_bytes(candidate["candidate_ledger"]),
            expected_digest=candidate["candidate_ledger"]["ledger_digest"],
            source_coordinate=coordinate,
            tier=1,
            denominators=self_polish_tiers._denominators("verifier-core-self"),
            evidence_replay=substituted,
        )
