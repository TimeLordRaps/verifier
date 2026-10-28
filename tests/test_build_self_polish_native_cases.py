"""Deterministic, source-bound Tier-1/2 native registry repair tests.

Terminology: application programming interface (API).

Every closure test below monkeypatches only the in-memory decoded registry or a
mechanism digest. None of them accepts a stored digest as proof of current
source; each stale or swapped binding must be refused by the installed closure.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import zlib

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import current_object_routes
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import self_polish_native_cases as native_cases
from verifier.runtime import self_polish_native_sim_case_patch as sim_case_patch


BASE_RAW_DIGEST = "sha256:" + "0" * 64


def _builder():
    from scripts import build_self_polish_native_cases as module

    return module


def _installed_base_raw() -> bytes:
    return native_cases._bounded_decompress(
        base64.b85decode(native_cases._PAYLOAD_B85)
    )


def _reencode(value: dict) -> bytes:
    raw = canonical_bytes(value)
    return base64.b85encode(zlib.compress(raw))


def _installed_without_patch(monkeypatch: pytest.MonkeyPatch, value: dict) -> None:
    """Install an altered base payload whose registry digest is re-bound.

    The digest guard has its own hand-edit test, so the digest constant is
    re-bound here to reach the per-case check each closure test names. The SIM
    overlay is the installed one computed from the untampered base: the five
    stale SIM seeds in the base are overridden by it, so they cannot raise
    NATIVE_CASE_POLICY_STALE and mask the altered entry under test.
    """
    installed_patch = sim_case_patch.installed_case_patch(_installed_base_raw())
    raw = canonical_bytes(value)
    monkeypatch.setattr(native_cases, "_PAYLOAD_B85", _reencode(value))
    monkeypatch.setattr(
        native_cases, "CASE_REGISTRY_DIGEST",
        core_obligation_union.bytes_digest(raw),
    )
    monkeypatch.setattr(
        sim_case_patch, "installed_case_patch", lambda _raw: installed_patch
    )


def _require_api(name: str):
    value = getattr(native_cases, name, None)
    assert value is not None, f"native case registry API {name} is not installed"
    return value


def test_base_generator_is_deterministic_and_preserves_patch_ownership() -> None:
    module = _builder()

    retained_seed = module._seed_cases()

    raw_first, encoded_first = module.build_payload()
    raw_second, encoded_second = module.build_payload()
    sources = module.build_installed_sources()

    assert raw_first == raw_second
    assert encoded_first == encoded_second
    assert sources["native_cases"] == Path(
        module.self_polish_native_cases.__file__
    ).read_bytes()
    assert sources["sim_patch"] == Path(
        sim_case_patch.__file__
    ).read_bytes()
    assert canonical_bytes(json.loads(raw_first)) == raw_first
    assert core_obligation_union.bytes_digest(raw_first).startswith("sha256:")

    rebuilt = json.loads(raw_first)
    assert len(rebuilt) == module.ENTRY_COUNT == 82
    patch_identifiers = module.PATCH_OWNED_IDENTIFIERS
    assert len(patch_identifiers) == 5
    assert {
        identifier: rebuilt[identifier] for identifier in patch_identifiers
    } == {
        identifier: retained_seed[identifier]
        for identifier in patch_identifiers
    }
    assert len(set(rebuilt) - patch_identifiers) == 77


def test_generator_output_equals_installed_base_registry() -> None:
    """RED until the installed base is regenerated from current builders."""
    module = _builder()
    raw, _ = module.build_payload()

    assert raw == _installed_base_raw()


def test_generated_module_hand_edit_is_refused(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A changed payload byte must fail the registry digest, not the overlay."""
    base = json.loads(_installed_base_raw())
    base["ACTOR:ACTOR-1.1"]["evidence_base64"] = (
        base["ACTOR:ACTOR-1.1"]["evidence_base64"][:-4] + "AAAA"
    )
    monkeypatch.setattr(native_cases, "_PAYLOAD_B85", _reencode(base))

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_DIGEST_DIFFERS"):
        native_cases.installed_case_inputs()


def test_every_installed_policy_pins_current_mechanism_digest() -> None:
    selected = native_cases.installed_case_inputs()
    stale = []
    for identifier, item in sorted(selected.items()):
        module = current_object_routes.registered_mechanism_module(
            item["checking_mechanism"]
        )
        if item["policy"]["mechanism_digest"] != module.mechanism_digest():
            stale.append(identifier)
        if item["request"]["policy_digest"] != core_obligation_union.value_digest(
                item["policy"]):
            stale.append(identifier + ":request")

    assert len(selected) == 82
    assert stale == []


def test_closure_refuses_stale_per_case_policy(
        monkeypatch: pytest.MonkeyPatch) -> None:
    value = json.loads(_installed_base_raw())
    value["ACTOR:ACTOR-1.1"]["policy"]["mechanism_digest"] = (
        "sha256:" + "1" * 64
    )
    _installed_without_patch(monkeypatch, value)

    with pytest.raises(ValueError, match="NATIVE_CASE_POLICY_STALE"):
        native_cases.installed_case_inputs()


def test_count_preserving_policy_swap_is_refused(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap policies across mechanisms: each policy pins the wrong checker.

    Same-mechanism peers share identical policies, so swapping them changes
    nothing; the guard below keeps this test from passing vacuously.
    """
    value = json.loads(_installed_base_raw())
    first = "ACTOR:ACTOR-1.1"
    mechanism = value[first]["checking_mechanism"]
    second = next(
        identifier for identifier in sorted(value)
        if not identifier.startswith("SIM:")
        and value[identifier]["checking_mechanism"] != mechanism
    )
    assert value[first]["policy"] != value[second]["policy"]
    value[first]["policy"], value[second]["policy"] = (
        value[second]["policy"], value[first]["policy"],
    )
    _installed_without_patch(monkeypatch, value)

    with pytest.raises(ValueError, match="NATIVE_CASE_POLICY_STALE"):
        native_cases.installed_case_inputs()


def test_request_policy_pin_mismatch_is_refused(
        monkeypatch: pytest.MonkeyPatch) -> None:
    value = json.loads(_installed_base_raw())
    value["ACTOR:ACTOR-1.1"]["request"]["policy_digest"] = "sha256:" + "4" * 64
    _installed_without_patch(monkeypatch, value)

    with pytest.raises(ValueError, match="NATIVE_CASE_POLICY_BINDING_DIFFERS"):
        native_cases.installed_case_inputs()


def test_coordinate_swap_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    value = json.loads(_installed_base_raw())
    value["ACTOR:ACTOR-1.1"]["request"]["coordinate"] = "AGENT-1.1"
    _installed_without_patch(monkeypatch, value)

    with pytest.raises(ValueError, match="NATIVE_CASE_COORDINATE_DIFFERS"):
        native_cases.installed_case_inputs()


def test_wrong_checker_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    value = json.loads(_installed_base_raw())
    value["AGENT:AGENT-1.8"]["checking_mechanism"] = (
        "verifier.domains.contracts.bot_checks.recheck_bot_checks_certificate"
    )
    _installed_without_patch(monkeypatch, value)

    with pytest.raises(ValueError, match="NATIVE_CASE_MECHANISM_DIFFERS"):
        native_cases.installed_case_inputs()


def test_leaf_source_drift_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    module = current_object_routes.registered_mechanism_module(
        "verifier.domains.contracts.typed_facets.recheck_typed_facets_certificate"
    )
    monkeypatch.setattr(
        module, "mechanism_digest", lambda: "sha256:" + "2" * 64
    )

    with pytest.raises(ValueError, match="NATIVE_CASE_POLICY_STALE"):
        native_cases.installed_case_inputs()


def test_dependency_drift_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    module = current_object_routes.registered_mechanism_module(
        "verifier.domains.contracts.sim_dynamics.recheck_sim_dynamics_certificate"
    )
    monkeypatch.setattr(
        module, "mechanism_digest", lambda: "sha256:" + "3" * 64
    )

    with pytest.raises(ValueError, match="NATIVE_CASE_POLICY_STALE"):
        native_cases.installed_case_inputs()


def test_source_review_ledger_covers_each_entry_exactly() -> None:
    _require_api("SOURCE_REVIEW_DIGEST")
    rows = native_cases.installed_source_review()

    assert [row["identifier"] for row in rows] == sorted(
        native_cases.installed_case_inputs()
    )
    assert len(rows) == 82
    accepted = []
    unknown = []
    selected = native_cases.installed_case_inputs()
    for row in rows:
        assert row["coordinate_digest"].startswith("sha256:")
        assert row["current_policy_mechanism_digest"].startswith("sha256:")
        assert row["reason"]
        assert row["next_action"]
        case = selected[row["identifier"]]
        evidence = base64.b64decode(case["evidence_base64"], validate=True)
        assert row["policy_digest"] == core_obligation_union.value_digest(
            case["policy"]
        )
        assert row["request_digest"] == core_obligation_union.value_digest(
            case["request"]
        )
        assert row["evidence_digest"] == core_obligation_union.bytes_digest(
            evidence
        )
        assert row["case_digest"] == core_obligation_union.value_digest({
            "checking_mechanism": case["checking_mechanism"],
            "evidence_digest": row["evidence_digest"],
            "policy_digest": row["policy_digest"],
            "request_digest": row["request_digest"],
        })
        assert row["intended_negative_refusal_codes"] == [
            native_cases.NEGATIVE_REFUSAL_CODES[row["identifier"]]
        ]
        assert len(row["triad_cases"]) == 3
        for case_kind, binding in sorted(row["triad_cases"].items()):
            assert case_kind == binding["case_kind"]
            assert binding["policy_digest"] == row["policy_digest"]
            expected_digest = core_obligation_union.value_digest({
                "case_kind": case_kind,
                "checking_mechanism": row["checking_mechanism"],
                "evidence_digest": binding["evidence_digest"],
                "expected_native_status": binding["expected_native_status"],
                "intended_refusal_codes": binding[
                    "intended_refusal_codes"
                ],
                "policy_digest": binding["policy_digest"],
                "request_digest": binding["request_digest"],
            })
            assert binding["case_digest"] == expected_digest
        (accepted if row["disposition"] == "ACCEPT_REPIN" else unknown).append(
            row["identifier"]
        )

    expected_tier1 = {
        f"{cell['object_kind']}:{row['coordinate']}"
        for cell in core_tier_progression.installed_core_route_inventory()[
            "family_cells"
        ]
        if cell["tier"] == 1
        for row in cell["registered_route_memberships"]
    }
    assert accepted == sorted(
        set(native_cases.installed_case_inputs()) - {"SIM:SIM-2.4"}
    )
    assert set(expected_tier1) <= set(accepted)
    assert unknown == ["SIM:SIM-2.4"]
    assert all(
        row["disposition"].startswith("UNKNOWN_")
        for row in rows if row["identifier"] in unknown
    )


def test_reviewed_baseline_is_immutable_source_input_not_installed_ledger(
        monkeypatch: pytest.MonkeyPatch) -> None:
    module = _builder()
    pins = module._validated_reviewed_prior_pins(module._seed_cases())
    installed = native_cases._LEDGER_B85
    monkeypatch.setattr(native_cases, "_LEDGER_B85", b"current-self-seed")

    assert module._validated_reviewed_prior_pins(module._seed_cases()) == pins
    assert native_cases._LEDGER_B85 != installed
    assert pins["SPACE:SPACE-2.1"] == (
        "sha256:ad63f4f316a3e82463a570e81c09d6c3b13df760703e6e027fc5342a465f5380"
    )


@pytest.mark.parametrize("mutation", ["missing", "substituted", "duplicate"])
def test_reviewed_baseline_refuses_missing_substituted_or_duplicate_rows(
        monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    module = _builder()
    baseline = deepcopy(module.REVIEWED_PRIOR_BASELINE)
    rows = list(baseline["rows"])
    if mutation == "missing":
        rows.pop()
    elif mutation == "substituted":
        identifier, _ = rows[0]
        rows[0] = (identifier, "sha256:" + "a" * 64)
    else:
        rows[-1] = rows[0]
    baseline["rows"] = tuple(rows)
    monkeypatch.setattr(module, "REVIEWED_PRIOR_BASELINE", baseline)

    with pytest.raises(RuntimeError, match="reviewed prior baseline differs"):
        module._validated_reviewed_prior_pins(module._seed_cases())


def test_reviewed_baseline_refuses_count_preserving_identity_swap(
        monkeypatch: pytest.MonkeyPatch) -> None:
    module = _builder()
    baseline = deepcopy(module.REVIEWED_PRIOR_BASELINE)
    rows = list(baseline["rows"])
    (first_id, first_pin), (second_id, second_pin) = rows[0], rows[1]
    rows[0] = (first_id, second_pin)
    rows[1] = (second_id, first_pin)
    baseline["rows"] = tuple(rows)
    monkeypatch.setattr(module, "REVIEWED_PRIOR_BASELINE", baseline)

    with pytest.raises(RuntimeError, match="reviewed prior baseline differs"):
        module._validated_reviewed_prior_pins(module._seed_cases())


def test_review_dispositions_preserve_fixture_and_provenance_boundaries() -> None:
    rows = {
        row["identifier"]: row for row in native_cases.installed_source_review()
    }

    assert rows["RECEIPT:RECEIPT-2.1"]["disposition"] == "ACCEPT_REPIN"
    assert "remains non-authoritative" in rows[
        "RECEIPT:RECEIPT-2.1"
    ]["reason"]
    assert rows["SIM:SIM-2.4"]["disposition"] == (
        "UNKNOWN_FIXTURE_ONLY_RESOURCE"
    )
    assert rows["SPACE:SPACE-2.1"]["disposition"] == "ACCEPT_REPIN"
    assert rows["SPACE:SPACE-2.1"]["stored_policy_mechanism_digest"] == (
        "sha256:ad63f4f316a3e82463a570e81c09d6c3b13df760703e6e027fc5342a465f5380"
    )


def test_reviewed_payload_contains_no_placeholder_prior_pins() -> None:
    module = _builder()
    pins = module._validated_reviewed_prior_pins(module._seed_cases())
    baseline = module.REVIEWED_PRIOR_BASELINE

    assert len(pins) == 82
    assert set(pins) == set(native_cases.installed_case_inputs())
    assert baseline["source_revision"] == (
        "52550135f67559e37625b398a49ec2e103b65178"
    )
    assert baseline["source_module"]["sha256"] == (
        "sha256:4842c9093a450ce028483743b1d9eb42447a42218a7cfb9c73eca94ae17abdee"
    )
    assert baseline["decoded_payload"]["sha256"] == (
        "sha256:c843e9524da21dedba0945962c842d6c016ff2cb633ad912ff2a6b54441ef64b"
    )
    assert all(
        pin.startswith("sha256:") and len(pin) == 71
        and pin not in {"sha256:" + char * 64 for char in "0a"}
        for pin in pins.values()
    )


def test_source_review_ledger_refuses_altered_row(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _require_api("SOURCE_REVIEW_DIGEST")
    ledger = json.loads(native_cases._bounded_decompress(
        base64.b85decode(native_cases._LEDGER_B85)
    ))
    ledger["rows"][0]["disposition"] = "PASS"
    monkeypatch.setattr(
        native_cases, "_LEDGER_B85", base64.b85encode(
            zlib.compress(canonical_bytes(ledger))
        ),
    )

    with pytest.raises(ValueError, match="NATIVE_CASE_SOURCE_REVIEW_DIFFERS"):
        native_cases.installed_source_review()


def test_ledger_binds_source_coordinate_not_placeholder() -> None:
    digest = _require_api("SOURCE_REVIEW_DIGEST")

    assert digest != "sha256:" + "a" * 64
    assert digest != BASE_RAW_DIGEST
