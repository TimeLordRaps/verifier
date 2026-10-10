"""Native, obligation-bound replay tests for numeric self-polish v2."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import zlib

import pytest

from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_native_cases as native_cases
from verifier.runtime import self_polish_native_replay as replay
from verifier.runtime import self_polish_tiers as tiers


_COORDINATE_DIGEST = "sha256:" + "a" * 64


def test_installed_case_payload_rejects_decompression_bomb(
        monkeypatch: pytest.MonkeyPatch) -> None:
    bomb = b"x" * (native_cases.MAX_DECOMPRESSED_PAYLOAD_BYTES + 1)
    monkeypatch.setattr(
        native_cases,
        "_PAYLOAD_B85",
        base64.b85encode(zlib.compress(bomb)),
    )

    with pytest.raises(
        ValueError, match="NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED"
    ):
        native_cases.installed_case_inputs()


def test_installed_case_payload_rejects_duplicate_json_keys(
        monkeypatch: pytest.MonkeyPatch) -> None:
    duplicate = b'{"duplicate":{},"duplicate":{}}'
    monkeypatch.setattr(
        native_cases,
        "_PAYLOAD_B85",
        base64.b85encode(zlib.compress(duplicate)),
    )

    with pytest.raises(
        ValueError, match="NATIVE_CASE_REGISTRY_DUPLICATE_KEY"
    ):
        native_cases.installed_case_inputs()


def test_installed_case_payload_requires_exact_denominator(
        monkeypatch: pytest.MonkeyPatch) -> None:
    short = json.dumps(
        {"one": {
            "checking_mechanism": "a.b", "request": {}, "policy": {},
            "evidence_base64": "e30=",
        }},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    monkeypatch.setattr(
        native_cases,
        "_PAYLOAD_B85",
        base64.b85encode(zlib.compress(short)),
    )

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        native_cases.installed_case_inputs()


def _manifest(tier: int, *, substitute: tuple[str, str] | None = None) -> bytes:
    registry = replay.installed_native_replay_registry()
    cases = []
    for membership in registry["tiers"][str(tier)]:
        for case_kind in replay.CASE_KINDS:
            native_status = replay.CASE_OUTCOMES[case_kind]
            if substitute == (membership["obligation_id"], case_kind):
                native_status = "PASS" if native_status != "PASS" else "FAIL"
            cases.append({
                "obligation_id": membership["obligation_id"],
                "case_kind": case_kind,
                "checking_mechanism": membership["checking_mechanism"],
                "certificate_base64": base64.b64encode(b"{}").decode("ascii"),
                "expected_request": {"native_status": native_status},
                "policy": {},
            })
    return core_obligation_union.canonical_bytes({
        "schema_version": replay.MANIFEST_SCHEMA,
        "tier": tier,
        "source_coordinate_digest": _COORDINATE_DIGEST,
        "registry_digest": registry["registry_digest"],
        "cases": cases,
    })


def _fake_resolver(_root: Path, dotted: str):
    def native(_certificate: bytes, *, expected_request: dict, policy: dict):
        assert policy == {}
        return {"status": expected_request["native_status"], "native": dotted}
    return native, dotted.rsplit(".", 1)[0].replace(".", "/") + ".py", (
        "sha256:" + "b" * 64
    )


def test_installed_registry_and_closure_are_exact() -> None:
    registry = replay.installed_native_replay_registry()
    closure = replay.installed_registry_closure()

    assert registry["tier_membership_counts"] == {"1": 45, "2": 37}
    assert len(registry["tiers"]["1"]) == 45
    assert len(registry["tiers"]["2"]) == 37
    assert closure["status"] == "PASS"
    assert (
        closure["structural_membership_count"],
        closure["tier1_route_membership_count"],
        closure["tier2_route_membership_count"],
    ) == (52, 45, 37)
    assert closure["scope"] == "INSTALLED_TIER1_TIER2_REGISTRIES_ONLY"


def test_installed_closure_rejects_duplicate_required_catalog_identity(
        monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = replay.polish.polish_catalog()
    duplicated = {**catalog, "routes": [catalog["routes"][0], *catalog["routes"]]}
    monkeypatch.setattr(replay.polish, "polish_catalog", lambda: duplicated)

    with pytest.raises(
        replay.NativeReplayError,
        match="INSTALLED_OBJECTIVE_ROUTE_IDENTITY_DUPLICATED",
    ):
        replay.installed_registry_closure()


def test_every_registered_mechanism_resolves_to_selected_source() -> None:
    root = Path(__file__).parents[1]
    registry = replay.installed_native_replay_registry()
    mechanisms = {
        row["checking_mechanism"]
        for selected in registry["tiers"].values() for row in selected
    }
    for mechanism in mechanisms:
        function, source_path, source_digest = replay._resolve_mechanism(
            root, mechanism
        )
        assert callable(function)
        assert source_path.startswith("src/verifier/domains/contracts/")
        assert source_digest.startswith("sha256:")


def test_installed_tier1_cases_are_built_and_replayed_without_caller_outcomes(
        ) -> None:
    root = Path(__file__).parents[1]
    raw = replay.build_installed_replay_manifest(
        1, root, source_coordinate_digest=_COORDINATE_DIGEST
    )

    receipt = replay.replay_native_obligations(
        raw,
        root,
        tier=1,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )

    assert receipt["status"] == "PASS"
    assert receipt["membership_count"] == 45
    assert receipt["case_count"] == 135
    assert {
        (case["case_kind"], case["native_status"])
        for membership in receipt["memberships"]
        for case in membership["cases"]
    } == {
        ("POSITIVE", "PASS"),
        ("NEGATIVE", "FAIL"),
        ("UNKNOWN", "UNKNOWN"),
    }


def test_installed_tier2_cases_preserve_sim_resource_unknown() -> None:
    root = Path(__file__).parents[1]
    raw = replay.build_installed_replay_manifest(
        2, root, source_coordinate_digest=_COORDINATE_DIGEST
    )

    receipt = replay.replay_native_obligations(
        raw,
        root,
        tier=2,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )

    assert receipt["status"] == "UNKNOWN"
    unresolved = [
        membership for membership in receipt["memberships"]
        if membership["status"] != "PASS"
    ]
    assert [row["obligation_id"] for row in unresolved] == ["SIM:SIM-2.4"]
    assert unresolved[0]["status"] == "UNKNOWN"
    assert unresolved[0]["cases"][0]["native_status"] == "UNKNOWN"
    assert unresolved[0]["cases"][0]["status"] == "UNKNOWN"
    assert receipt["invalidators"] == [
        "SIM_RESOURCE_ACTUAL_CONSUMPTION_CORRESPONDENCE_NOT_ESTABLISHED",
        "SIM_RESOURCE_COLLECTOR_HONESTY_NOT_ESTABLISHED",
    ]


@pytest.mark.parametrize("tier, memberships", [(1, 45), (2, 37)])
def test_native_cases_can_replay_to_pass_without_pytest_nodes(
        tier: int, memberships: int, monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path) -> None:
    monkeypatch.setattr(replay, "_resolve_mechanism", _fake_resolver)
    raw = _manifest(tier)

    receipt = replay.replay_native_obligations(
        raw, tmp_path, tier=tier,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )

    assert receipt["status"] == "PASS"
    assert receipt["membership_count"] == memberships
    assert receipt["case_count"] == memberships * 3
    assert receipt["invalidators"] == []
    assert {
        case["native_status"]
        for row in receipt["memberships"] for case in row["cases"]
    } == {"PASS", "FAIL", "UNKNOWN"}


def test_wrong_native_outcome_is_a_definite_failure(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(replay, "_resolve_mechanism", _fake_resolver)
    first = replay.installed_native_replay_registry()["tiers"]["1"][0]
    raw = _manifest(1, substitute=(first["obligation_id"], "UNKNOWN"))

    receipt = replay.replay_native_obligations(
        raw, tmp_path, tier=1,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )

    assert receipt["status"] == "FAIL"
    assert receipt["memberships"][0]["status"] == "FAIL"


def test_ledger_and_self_representation_are_derived_from_native_receipt(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(replay, "_resolve_mechanism", _fake_resolver)
    raw = _manifest(2)
    receipt = replay.replay_native_obligations(
        raw, tmp_path, tier=2,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )
    denominators = tiers._denominators("verifier-core-self")
    coordinate = {"coordinate": "selected"}
    receipt["source_coordinate_digest"] = core_obligation_union.value_digest(
        coordinate
    )
    receipt.pop("receipt_digest")
    receipt["receipt_digest"] = core_obligation_union.value_digest(receipt)

    ledger = tiers._derived_complete_tier_ledger(
        tier=2, source_coordinate=coordinate, denominators=denominators,
        evidence_replay=receipt,
    )
    reason_assessment = tiers._validated_facet_reason_assessment(denominators)
    partition = reason_assessment["consumer_route_partition"]
    assert reason_assessment["status"] == "PASS"
    assert reason_assessment["reason_completeness_status"] == "PASS"
    assert reason_assessment["source_binding_status"] == "PASS"
    assert reason_assessment["qualifying_facet_choice_reason_count"] == 130
    assert reason_assessment["qualifying_domain_route_reason_count"] == 18
    assert reason_assessment["reasoned_route_membership_count"] == 45
    assert reason_assessment["route_membership_reason_deficit"] == 0
    assert partition["facet_direct_route_membership_count"] == 27
    assert partition["domain_route_membership_count"] == 18
    assert partition["route_union_membership_count"] == 45
    representation = tiers._derived_self_representation(
        tier=2, source_coordinate=coordinate, denominators=denominators,
        ledger=ledger, evidence_replay=receipt,
        prior_whole_tier_report_digest="sha256:" + "c" * 64,
        estate_evidence_result=None,
        facet_reason_assessment=reason_assessment,
    )

    assert ledger["status"] == "PASS"
    assert ledger["derivation"] == "NATIVE_REPLAY_RECEIPT"
    assert len(ledger["entries"]) == 37
    assert ledger["replay_receipt_digest"] == receipt["receipt_digest"]
    assert representation["status"] == "PASS"
    assert representation["derivation"] \
        == "INSTALLED_REGISTRY_AND_NATIVE_REPLAY"
    assert representation["tier_ledger_digest"] == ledger["ledger_digest"]
    assert representation["tier1_facet_reason_assessment_digest"] \
        == reason_assessment["assessment_digest"]
    assert representation["tier1_facet_reason_ledger_digest"] \
        == reason_assessment["ledger_digest"]
    assert representation["tier1_facet_choice_identity_digest"] \
        == reason_assessment["choice_identity_digest"]
    assert representation["tier1_reasoned_structural_membership_digest"] \
        == reason_assessment["reasoned_structural_membership_digest"]
    assert representation["tier1_reasoned_route_membership_digest"] \
        == reason_assessment["reasoned_route_membership_digest"]
    assert representation["tier1_reasoned_slot_digest"] \
        == reason_assessment["reasoned_slot_digest"]
    assert representation["tier1_domain_route_reason_status"] == "PASS"
    assert representation["tier1_domain_route_reason_identity_digest"] \
        == reason_assessment["domain_route_reason_identity_digest"]
    assert representation["tier1_domain_route_reasons_digest"] \
        == partition["domain_route_reasons_digest"]
    assert representation["tier1_facet_direct_route_membership_count"] == 27
    assert representation["tier1_facet_direct_route_membership_digest"] \
        == partition["facet_direct_route_membership_digest"]
    assert representation["tier1_domain_route_membership_count"] == 18
    assert representation["tier1_domain_route_membership_digest"] \
        == partition["domain_route_membership_digest"]
    assert representation["tier1_reason_route_union_membership_count"] == 45
    assert representation["tier1_reason_route_union_membership_digest"] \
        == partition["route_union_membership_digest"]
    assert representation["tier1_reason_route_partition_digest"] \
        == reason_assessment["consumer_route_partition_digest"]
