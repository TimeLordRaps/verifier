"""Native, obligation-bound replay tests for numeric self-polish v2.

Tests that replay through fake resolvers are plumbing-only: they exercise the
manifest and receipt mechanics with a fixture source digest, and they cannot
establish a native semantic PASS. Installed Tier-1/2 replay tests bind to the
exact case registry and source-review ledger, not to a placeholder coordinate.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
import zlib

import pytest

from verifier.domains.contracts import (
    sim_dynamics, sim_internal_state, sim_perspective, sim_resource,
    sim_response,
)
from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_native_cases as native_cases
from verifier.runtime import self_polish_native_replay as replay
from verifier.runtime import self_polish_native_sim_case_patch as sim_case_patch
from verifier.runtime import self_polish_tiers as tiers


# Plumbing-only fixture digest. A receipt carrying it proves manifest mechanics
# and nothing about any installed mechanism's semantics.
_PLUMBING_SOURCE_DIGEST = "sha256:" + "b" * 64


def _source_coordinate_digest() -> str:
    """Bind a replay to the installed ledger and the replay implementation."""

    digest = getattr(native_cases, "SOURCE_REVIEW_DIGEST", None)
    assert digest is not None, (
        "native case source-review ledger is not installed"
    )
    return core_obligation_union.value_digest({
        "case_registry_digest": native_cases.CASE_REGISTRY_DIGEST,
        "replay_mechanism_digest": replay.mechanism_digest(),
        "source_review_digest": digest,
    })


# Plumbing manifests need a stable coordinate only; it is derived, not chosen.
_COORDINATE_DIGEST = core_obligation_union.value_digest({"plumbing_only": True})


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


def test_reviewed_sim_21_specimen_is_rebound_to_current_mechanism() -> None:
    selected = native_cases.installed_case_inputs()["SIM:SIM-2.1"]

    assert selected["policy"]["mechanism_digest"] \
        == sim_dynamics.mechanism_digest()
    assert selected["request"]["policy_digest"] \
        == core_obligation_union.value_digest(selected["policy"])


@pytest.mark.parametrize(
    ("coordinate", "module", "builder", "checker", "expected_status"),
    [
        (
            "SIM:SIM-2.1", sim_dynamics,
            sim_dynamics.build_sim_dynamics_certificate,
            sim_dynamics.recheck_sim_dynamics_certificate, "PASS",
        ),
        (
            "SIM:SIM-2.2", sim_response,
            sim_response.build_sim_response_certificate,
            sim_response.recheck_sim_response_certificate, "PASS",
        ),
        (
            "SIM:SIM-2.3", sim_internal_state,
            sim_internal_state.build_sim_internal_state_certificate,
            sim_internal_state.recheck_sim_internal_state_certificate, "PASS",
        ),
        (
            "SIM:SIM-2.4", sim_resource,
            sim_resource.build_sim_resource_certificate,
            sim_resource.recheck_sim_resource_certificate, "UNKNOWN",
        ),
        (
            "SIM:SIM-2.5", sim_perspective,
            sim_perspective.build_sim_perspective_certificate,
            sim_perspective.recheck_sim_perspective_certificate, "PASS",
        ),
    ],
)
def test_reviewed_sim_patch_dependency_closure_replays_current_source(
        coordinate: str, module, builder, checker,
        expected_status: str) -> None:
    selected = native_cases.installed_case_inputs()[coordinate]
    evidence = base64.b64decode(selected["evidence_base64"], validate=True)

    assert selected["policy"]["mechanism_digest"] == module.mechanism_digest()
    certificate = builder(
        selected["request"], evidence, policy=selected["policy"]
    )
    result = checker(
        certificate,
        expected_request=selected["request"],
        policy=selected["policy"],
    )
    assert result["status"] == expected_status


def test_sim_patch_preserves_base_evidence_while_replacing_stale_binding() -> None:
    base_raw = native_cases._bounded_decompress(
        base64.b85decode(native_cases._PAYLOAD_B85)
    )
    base = json.loads(base_raw.decode("utf-8"))["SIM:SIM-2.1"]
    patched = native_cases.installed_case_inputs()["SIM:SIM-2.1"]

    assert base["policy"]["mechanism_digest"] \
        != sim_dynamics.mechanism_digest()
    assert patched["policy"]["mechanism_digest"] \
        == sim_dynamics.mechanism_digest()
    assert patched["evidence_base64"] == base["evidence_base64"]
    assert {
        key: value for key, value in patched["request"].items()
        if key != "policy_digest"
    } == {
        key: value for key, value in base["request"].items()
        if key != "policy_digest"
    }


def test_reviewed_sim_21_rebinding_rejects_unreviewed_stored_drift(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sim_case_patch,
        "BASE_REGISTRY_DIGEST",
        "sha256:" + "0" * 64,
    )

    with pytest.raises(
        ValueError, match="NATIVE_CASE_PATCH_BASE_DIFFERS"
    ):
        native_cases.installed_case_inputs()


def _sim_patch_builder():
    from scripts import build_self_polish_sim_case_patch

    return build_self_polish_sim_case_patch


def test_sim_case_patch_generator_reproduces_installed_patch() -> None:
    module = _sim_patch_builder()
    generated, base_digest = module.build_patch()
    base_raw = native_cases._bounded_decompress(
        base64.b85decode(native_cases._PAYLOAD_B85)
    )
    installed = sim_case_patch.installed_case_patch(base_raw)

    assert base_digest == sim_case_patch.BASE_REGISTRY_DIGEST
    assert generated == installed
    assert core_obligation_union.value_digest(generated) \
        == sim_case_patch.PATCH_DIGEST


def test_sim_case_patch_generator_writes_installed_source_deterministically(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    module = _sim_patch_builder()
    outputs = [tmp_path / "first.py", tmp_path / "second.py"]
    for output in outputs:
        monkeypatch.setattr(
            module.sys,
            "argv",
            ["build_self_polish_sim_case_patch.py", "--output", str(output)],
        )
        assert module.main() == 0
        capsys.readouterr()

    expected = Path(sim_case_patch.__file__).read_bytes()
    assert outputs[0].read_bytes() == outputs[1].read_bytes() == expected


def test_sim_24_public_seed_is_fixture_only_and_non_authoritative() -> None:
    """The public Ed25519 seed may never satisfy provenance or authority."""

    assert sim_case_patch.FIXTURE_AUTHORITY == (
        "NON_AUTHORITATIVE_PUBLIC_TEST_SEED"
    )
    selected = native_cases.installed_case_inputs()["SIM:SIM-2.4"]
    evidence = json.loads(base64.b64decode(
        selected["evidence_base64"], validate=True
    ).decode("utf-8"))
    assert evidence["collector_key"] == sim_case_patch.FIXTURE_COLLECTOR_KEY
    rows = {row["identifier"]: row for row in native_cases.installed_source_review()}
    assert rows["SIM:SIM-2.4"]["disposition"] == "UNKNOWN_FIXTURE_ONLY_RESOURCE"


def _manifest(
        tier: int, *, substitute: tuple[str, str] | None = None,
        refusal: bool = True) -> bytes:
    """Plumbing manifest; ``refusal`` attaches each NEGATIVE's intended detail.

    The fake resolver echoes ``native_status`` and ``refusal_detail`` verbatim,
    so this bundle exercises replay mechanics, never installed semantics.
    """
    registry = replay.installed_native_replay_registry()
    cases = []
    for membership in registry["tiers"][str(tier)]:
        identifier = membership["obligation_id"]
        for case_kind in replay.CASE_KINDS:
            native_status = replay.CASE_OUTCOMES[case_kind]
            if substitute == (identifier, case_kind):
                native_status = "PASS" if native_status != "PASS" else "FAIL"
            expected_request = {"native_status": native_status}
            if refusal and case_kind == "NEGATIVE":
                expected_request["refusal_detail"] = (
                    native_cases.NEGATIVE_REFUSAL_CODES[identifier]
                )
            cases.append({
                "obligation_id": identifier,
                "case_kind": case_kind,
                "checking_mechanism": membership["checking_mechanism"],
                "certificate_base64": base64.b64encode(b"{}").decode("ascii"),
                "expected_request": expected_request,
                "policy": {},
            })
    return core_obligation_union.canonical_bytes({
        "schema_version": replay.MANIFEST_SCHEMA,
        "tier": tier,
        "source_coordinate_digest": _COORDINATE_DIGEST,
        "registry_digest": registry["registry_digest"],
        "cases": cases,
    })


def _fake_native(dotted: str):
    def native(_certificate: bytes, *, expected_request: dict, policy: dict):
        assert policy == {}
        reply = {"status": expected_request["native_status"], "native": dotted}
        if "refusal_detail" in expected_request:
            reply["evaluation"] = {"details": expected_request["refusal_detail"]}
        return reply
    return native


def _fake_resolver(_root: Path, dotted: str):
    return _fake_native(dotted), dotted.rsplit(".", 1)[0].replace(".", "/") + ".py", (
        _PLUMBING_SOURCE_DIGEST
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


def test_native_replay_refuses_unregistered_module_selection() -> None:
    root = Path(__file__).parents[1]
    with pytest.raises(
        replay.NativeReplayError,
        match="NATIVE_REPLAY_MECHANISM_UNAVAILABLE",
    ):
        replay._resolve_mechanism(root, "substituted.module.recheck_claim")


def test_installed_tier1_cases_are_built_and_replayed_without_caller_outcomes(
        ) -> None:
    root = Path(__file__).parents[1]
    raw = replay.build_installed_replay_manifest(
        1, root, source_coordinate_digest=_source_coordinate_digest()
    )

    receipt = replay.replay_native_obligations(
        raw,
        root,
        tier=1,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_source_coordinate_digest(),
    )

    # Every Tier-1 mechanism executes as its triad requires, and every exact
    # current-source repin is accepted by the installed review ledger.
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
    assert receipt["status"] == "PASS"
    assert all(
        membership["conformance_status"] == "PASS"
        and membership["source_review"]["accepted"] is True
        for membership in receipt["memberships"]
    )
    assert "SOURCE_REVIEW_NOT_ACCEPTED" not in receipt["invalidators"]


def test_installed_tier2_cases_preserve_sim_resource_unknown() -> None:
    root = Path(__file__).parents[1]
    raw = replay.build_installed_replay_manifest(
        2, root, source_coordinate_digest=_source_coordinate_digest()
    )

    receipt = replay.replay_native_obligations(
        raw,
        root,
        tier=2,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_source_coordinate_digest(),
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
    # The SIM-2.4 fixture boundary is preserved, and the tier-2 ledger rows
    # add one aggregate source-review invalidator; no row can establish PASS.
    assert receipt["invalidators"] == [
        "SIM_RESOURCE_ACTUAL_CONSUMPTION_CORRESPONDENCE_NOT_ESTABLISHED",
        "SIM_RESOURCE_COLLECTOR_HONESTY_NOT_ESTABLISHED",
        "SOURCE_REVIEW_NOT_ACCEPTED",
    ]


def test_installed_tier2_fresh_execution_replays_complete_native_graph() -> None:
    root = Path(__file__).parents[1]
    raw = replay.build_installed_replay_manifest(
        2,
        root,
        source_coordinate_digest=_source_coordinate_digest(),
        fresh_execution=True,
    )

    receipt = replay.replay_native_obligations(
        raw,
        root,
        tier=2,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_source_coordinate_digest(),
        fresh_execution=True,
    )

    assert receipt["status"] == "PASS"
    assert receipt["membership_count"] == 37
    assert receipt["case_count"] == 111
    assert receipt["invalidators"] == []
    assert all(
        membership["status"] == "PASS"
        and membership["conformance_status"] == "PASS"
        and membership["source_review"]["accepted"] is True
        for membership in receipt["memberships"]
    )
    sim = next(
        membership for membership in receipt["memberships"]
        if membership["obligation_id"] == "SIM:SIM-2.4"
    )
    assert sim["source_review"]["disposition"] == (
        "ACCEPT_FRESH_EXECUTION_VARIANT"
    )
    assert sim["cases"][1]["refusal_detail"] == "evidence fields differ"
    assert sim["cases"][1]["status"] == "PASS"


@pytest.mark.parametrize("fresh_execution", [False, True])
def test_installed_tier2_builders_cover_exact_case_triads(
        fresh_execution: bool) -> None:
    root = Path(__file__).parents[1]
    registry = replay.installed_native_replay_registry(
        fresh_execution=fresh_execution
    )
    memberships = registry["tiers"]["2"]

    raw = replay.build_installed_replay_manifest(
        2,
        root,
        source_coordinate_digest=_source_coordinate_digest(),
        fresh_execution=fresh_execution,
    )
    manifest = json.loads(raw.decode("utf-8"))
    expected_triads = [
        (membership["obligation_id"], case_kind)
        for membership in memberships
        for case_kind in replay.CASE_KINDS
    ]

    assert len(memberships) == 37
    assert len(manifest["cases"]) == 111
    assert [
        (case["obligation_id"], case["case_kind"])
        for case in manifest["cases"]
    ] == expected_triads


@pytest.mark.parametrize("tier, memberships", [(1, 45), (2, 37)])
def test_fake_echo_replay_is_plumbing_only_and_not_a_native_pass(
        tier: int, memberships: int, monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path) -> None:
    monkeypatch.setattr(replay, "_resolve_mechanism", _fake_resolver)
    raw = _manifest(tier)

    receipt = replay.replay_native_obligations(
        raw, tmp_path, tier=tier,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )

    # The echo proves replay plumbing: every case is bound to the plumbing
    # fixture digest, so no installed mechanism's native semantics were read.
    assert receipt["membership_count"] == memberships
    assert receipt["case_count"] == memberships * 3
    assert {
        case["mechanism_source_digest"]
        for row in receipt["memberships"] for case in row["cases"]
    } == {_PLUMBING_SOURCE_DIGEST}
    assert receipt.get("semantic_pass") is not True


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


def test_negative_case_unknown_is_a_definite_discrimination_failure(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def negative_unknown_resolver(_root: Path, dotted: str):
        def native(
                _certificate: bytes, *, expected_request: dict,
                policy: dict) -> dict:
            assert policy == {}
            status = expected_request["native_status"]
            if status == "FAIL":
                status = "UNKNOWN"
            return {"status": status, "native": dotted}

        return native, dotted.rsplit(".", 1)[0].replace(".", "/") + ".py", (
            _PLUMBING_SOURCE_DIGEST
        )

    monkeypatch.setattr(replay, "_resolve_mechanism", negative_unknown_resolver)
    raw = _manifest(1)

    receipt = replay.replay_native_obligations(
        raw, tmp_path, tier=1,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )

    assert receipt["status"] == "FAIL"
    assert all(
        case["status"] == "FAIL"
        for membership in receipt["memberships"]
        for case in membership["cases"]
        if case["case_kind"] == "NEGATIVE"
    )


def test_negative_fail_without_intended_refusal_code_is_not_a_pass(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A NEGATIVE FAIL must carry the intended refusal code to count.

    The plumbing resolver returns a bare FAIL with no refusal code, so a
    replay that accepts any FAIL as discrimination reports PASS here.
    """
    codes = getattr(native_cases, "NEGATIVE_REFUSAL_CODES", None)
    assert codes, "intended NEGATIVE refusal codes are not installed"
    monkeypatch.setattr(replay, "_resolve_mechanism", _fake_resolver)
    raw = _manifest(1, refusal=False)

    receipt = replay.replay_native_obligations(
        raw, tmp_path, tier=1,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )

    assert receipt["status"] == "FAIL"
    negatives = [
        case for membership in receipt["memberships"]
        for case in membership["cases"] if case["case_kind"] == "NEGATIVE"
    ]
    assert len(negatives) == 45
    assert {(case["status"], case["reason"]) for case in negatives} == {
        ("FAIL", replay.NEGATIVE_REFUSAL_CODE_MISSING),
    }


@pytest.mark.parametrize(
    ("case_kind", "native", "installed", "expected"),
    [
        ("NEGATIVE", {"status": "FAIL", "evaluation": {"details": "EXACT"}},
         True, ("PASS", None)),
        ("NEGATIVE", {"status": "FAIL", "evaluation": {"details": "EXACT"}},
         False, ("UNKNOWN", replay.NOT_INSTALLED_PLUMBING_ONLY)),
        ("NEGATIVE", {"status": "FAIL"}, True,
         ("FAIL", replay.NEGATIVE_REFUSAL_CODE_MISSING)),
        ("NEGATIVE", {"status": "FAIL", "evaluation": {"details": "WRONG"}},
         True, ("FAIL", replay.NEGATIVE_REFUSAL_CODE_DIFFERS)),
        ("NEGATIVE", {"status": "UNKNOWN"}, True,
         ("FAIL", replay.NEGATIVE_NATIVE_UNKNOWN)),
        ("NEGATIVE", {"status": "PASS"}, True,
         ("FAIL", replay.NEGATIVE_ACCEPTED_BY_CHECKER)),
        ("NEGATIVE", "not-a-dict", True,
         ("FAIL", replay.NEGATIVE_NATIVE_REPLY_MALFORMED)),
        ("POSITIVE", {"status": "PASS"}, True, ("PASS", None)),
        ("POSITIVE", {"status": "PASS"}, False,
         ("UNKNOWN", replay.NOT_INSTALLED_PLUMBING_ONLY)),
        ("POSITIVE", {"status": "FAIL"}, True,
         ("FAIL", replay.POSITIVE_NATIVE_FAIL)),
        ("POSITIVE", {"status": "UNKNOWN"}, True,
         ("UNKNOWN", replay.POSITIVE_NATIVE_UNKNOWN)),
        ("UNKNOWN", {"status": "UNKNOWN"}, True, ("PASS", None)),
        ("UNKNOWN", {"status": "PASS"}, True,
         ("FAIL", replay.UNKNOWN_CASE_NATIVE_RESULT_DIFFERS)),
    ],
)
def test_case_outcome_negative_discrimination_needs_exact_installed_refusal(
        monkeypatch: pytest.MonkeyPatch, case_kind: str, native: object,
        installed: bool, expected: tuple[str, str | None]) -> None:
    identifier = "OBJECT:OBJECT-1.1"
    monkeypatch.setitem(
        native_cases.NEGATIVE_REFUSAL_CODES, identifier, "EXACT"
    )

    assert replay._case_outcome(
        case_kind, identifier, native, installed=installed
    ) == expected


def test_unrecognised_positive_reply_is_a_contract_refusal() -> None:
    with pytest.raises(replay.NativeReplayError,
                       match="NATIVE_REPLAY_OUTCOME_INVALID"):
        replay._case_outcome("POSITIVE", "OBJECT:OBJECT-1.1",
                             {"status": "MAYBE"}, installed=True)


@pytest.mark.parametrize(("tier", "expected"), [(1, 45), (2, 37)])
def test_source_review_partitions_ledger_and_honours_only_reviewed_repins(
        tier: int, expected: int) -> None:
    """Pure ledger binding: independent of the case registry and checkers."""

    binding = replay._source_review_binding(tier)
    entries = binding["entries"]

    assert len(entries) == expected
    assert binding["ledger"].keys() >= entries.keys()
    assert all(
        entry["ledger_digest"] == native_cases.SOURCE_REVIEW_DIGEST
        and entry["row_count"] == native_cases.SOURCE_REVIEW_ROW_COUNT
        and (entry["disposition"] == "ACCEPT_REPIN" or entry["next_action"])
        for entry in entries.values()
    )
    accepted = {
        identifier for identifier, entry in entries.items()
        if entry["accepted"] is True
    }
    expected_accepted = (
        native_cases.SOURCE_REVIEW_ACCEPTED_IDENTIFIERS & entries.keys()
    )
    assert accepted == expected_accepted
    assert all(
        (entry["disposition"] == "ACCEPT_REPIN") is (identifier in accepted)
        and (
            entry["disposition"] == "ACCEPT_REPIN"
            or entry["disposition"].startswith("UNKNOWN_")
        )
        for identifier, entry in entries.items()
    )


def test_source_review_keeps_legacy_fixture_pending_and_receipt_bounded() -> None:
    """Legacy SIM remains pending; receipt replay does not promote provenance."""

    sim = replay._source_review_binding(2)["entries"]["SIM:SIM-2.4"]
    receipt_tier = next(
        tier for tier in (1, 2)
        if any(row["obligation_id"] == "RECEIPT:RECEIPT-2.1"
               for row in replay._membership_rows(tier))
    )
    receipt = replay._source_review_binding(receipt_tier)["entries"][
        "RECEIPT:RECEIPT-2.1"
    ]

    assert sim["disposition"] == "UNKNOWN_FIXTURE_ONLY_RESOURCE"
    assert receipt["disposition"] == "ACCEPT_REPIN"
    assert sim["accepted"] is False and receipt["accepted"] is True
    assert "remains non-authoritative" in receipt["reason"]

    fresh = replay._source_review_binding(
        2, fresh_execution=True
    )["entries"]["SIM:SIM-2.4"]
    assert fresh["disposition"] == "ACCEPT_FRESH_EXECUTION_VARIANT"
    assert fresh["accepted"] is True
    assert fresh["reviewed_binding"]["base_ledger_digest"] == (
        native_cases.SOURCE_REVIEW_DIGEST
    )
    assert "NOT_ESTABLISHED" in fresh["reviewed_binding"]["claim_boundary"]


def test_receipt_cases_bind_policy_request_and_evidence_digests() -> None:
    """Each receipt case binds the exact policy, request, and certificate it checked."""
    root = Path(__file__).parents[1]
    raw = replay.build_installed_replay_manifest(
        1, root, source_coordinate_digest=_source_coordinate_digest()
    )
    manifest_cases = json.loads(raw.decode("utf-8"))["cases"]
    receipt = replay.replay_native_obligations(
        raw, root, tier=1,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_source_coordinate_digest(),
    )

    for membership in receipt["memberships"]:
        for case in membership["cases"]:
            source = next(
                item for item in manifest_cases
                if item["obligation_id"] == membership["obligation_id"]
                and item["case_kind"] == case["case_kind"]
            )
            certificate = base64.b64decode(source["certificate_base64"])
            assert case["policy_digest"] == core_obligation_union.value_digest(
                source["policy"]
            )
            assert case["request_digest"] == core_obligation_union.value_digest(
                source["expected_request"]
            )
            assert case["evidence_digest"] == core_obligation_union.bytes_digest(
                certificate
            )
            assert case["coordinate"] == membership["membership"]["coordinate"]
            assert case["expected_native_status"] == replay.CASE_OUTCOMES[
                case["case_kind"]
            ]
            if case["case_kind"] == "NEGATIVE":
                assert case["intended_refusal_codes"] == [
                    native_cases.NEGATIVE_REFUSAL_CODES[
                        membership["obligation_id"]
                    ]
                ]
            else:
                assert case["intended_refusal_codes"] == []


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

    # Plumbing replay can never be PASS: its callables are not installed and
    # every tier-2 ledger row is pending, so the derived ledger is UNKNOWN.
    assert receipt["status"] == "UNKNOWN"
    assert ledger["status"] == "UNKNOWN"
    assert ledger["derivation"] == "NATIVE_REPLAY_RECEIPT"
    assert len(ledger["entries"]) == 37
    assert ledger["replay_receipt_digest"] == receipt["receipt_digest"]
    assert representation["status"] == "UNKNOWN"
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


def _installed_echo(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Treat memoized echoes as the installed callables (logic probe, not semantics)."""
    cache: dict[str, Any] = {}

    def resolver(_root: Path, dotted: str):
        if dotted not in cache:
            cache[dotted] = _fake_native(dotted)
        return cache[dotted], dotted.rsplit(".", 1)[0].replace(".", "/") + ".py", (
            _PLUMBING_SOURCE_DIGEST
        )

    monkeypatch.setattr(replay, "_resolve_mechanism", resolver)
    monkeypatch.setattr(replay, "_installed_callable", lambda dotted: cache.get(dotted))
    return cache


@pytest.mark.parametrize("accepted", [False, True])
def test_pass_requires_installed_callable_and_accepted_ledger(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, accepted: bool) -> None:
    """Execution PASS becomes conformance only after the ledger accepts the rows."""
    _installed_echo(monkeypatch)
    monkeypatch.setattr(
        replay, "SOURCE_REVIEW_ACCEPTED_DISPOSITIONS",
        frozenset({"ACCEPT_REPIN"}) if accepted else frozenset(),
    )
    raw = _manifest(1)

    receipt = replay.replay_native_obligations(
        raw, tmp_path, tier=1,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )

    assert all(member["status"] == "PASS" for member in receipt["memberships"])
    assert {member["conformance_status"] for member in receipt["memberships"]} == (
        {"PASS"} if accepted else {"NOT_ESTABLISHED"}
    )
    assert receipt["status"] == ("PASS" if accepted else "UNKNOWN")
    assert ("SOURCE_REVIEW_NOT_ACCEPTED" in receipt["invalidators"]) is not accepted


def _tamper_cases(tier: int, mutation: str) -> bytes:
    value = json.loads(_manifest(tier).decode("utf-8"))
    cases = value["cases"]
    if mutation == "missing":
        cases.pop()
    elif mutation == "duplicate":
        cases[-1] = dict(cases[0])
    elif mutation == "reordered":
        cases[0], cases[3] = cases[3], cases[0]
    elif mutation == "substituted_identifier":
        cases[0]["obligation_id"] = "NOT-INSTALLED:ROW-0.0"
    elif mutation == "count_preserving_swap":
        # Index 0 and 3 are the POSITIVE cases of two different memberships.
        cases[0]["obligation_id"], cases[3]["obligation_id"] = (
            cases[3]["obligation_id"], cases[0]["obligation_id"],
        )
    return core_obligation_union.canonical_bytes(value)


@pytest.mark.parametrize(
    ("mutation", "codes"),
    [
        ("missing", {"NATIVE_REPLAY_CASE_DENOMINATOR_DIFFERS"}),
        ("duplicate", {"NATIVE_REPLAY_CASE_ORDER_DIFFERS"}),
        ("reordered", {"NATIVE_REPLAY_CASE_ORDER_DIFFERS"}),
        ("substituted_identifier", {"NATIVE_REPLAY_CASE_BINDING_DIFFERS"}),
        # Either the mechanism check or the order check refuses first,
        # depending on whether the two swapped rows share a checker.
        ("count_preserving_swap", {
            "NATIVE_REPLAY_CASE_BINDING_DIFFERS",
            "NATIVE_REPLAY_CASE_ORDER_DIFFERS",
        }),
    ],
)
def test_tampered_manifest_rows_are_refused_not_passed(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        mutation: str, codes: set[str]) -> None:
    _installed_echo(monkeypatch)
    raw = _tamper_cases(1, mutation)

    receipt = replay.replay_native_obligations(
        raw, tmp_path, tier=1,
        expected_manifest_digest=core_obligation_union.bytes_digest(raw),
        expected_source_coordinate_digest=_COORDINATE_DIGEST,
    )

    assert receipt["status"] == "FAIL"
    assert codes & set(receipt["invalidators"])
    assert receipt["membership_count"] == 0
