"""Finite capability-token replay; counts and epochs are dimensionless.

Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256).
Window instants use one declared microsecond clock; no physical time is inferred.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import token_checks


def holding() -> tuple[dict, dict]:
    """Unsigned documentary fixtures carry no signing keys or authority."""
    common = {"issuing_key_id": digest("documentary-key-id"), "issued_at": 100,
              "algorithm": "Ed25519", "audience": ["reader"],
              "signature": "unverified-declaration"}
    birth = {**common, "kind": "birth", "token_id": "birth", "replay_id": "r-birth",
             "birth_epoch": 4, "commitment": digest("opaque-birth-commitment")}
    root = {**common, "kind": "lifetime", "token_id": "root", "replay_id": "r-root",
            "parent_grant_id": "birth", "delegate_key_id": digest("delegate-label"),
            "permitted_scopes": ["read", "write"], "not_before": 100, "not_after": 1000,
            "max_invocations": 10, "soulbound": False, "confirmation_key_id": None,
            "caveats": [{"condition": "region=local", "discharge": None}]}
    child = {**root, "token_id": "child", "replay_id": "r-child",
             "parent_grant_id": "root", "permitted_scopes": ["read"],
             "not_before": 200, "not_after": 800, "max_invocations": 2}
    epochs, head = [], birth["commitment"]
    for epoch, status in enumerate(["ACTIVE", "SUSPENDED", "ACTIVE", "REVOKED"], 5):
        head = digest([head, epoch, status])
        epochs.append({"epoch": epoch, "status": status, "digest": head})
    aging = {**common, "kind": "aging", "token_id": "aging", "replay_id": "r-aging",
             "birth_token_id": "birth", "epoch_start": 5, "epoch_end": 8,
             "accumulated_epochs": 2, "accumulator_digest": head,
             "revocation_status": "REVOKED"}
    inputs = {"tokens": [birth, root, child, aging], "epochs": epochs}
    artifact = {"clock": "fixture:declared-clock", "clock_skew": 30,
                "root_scopes": ["read", "write"],
                "tokens_digest": digest(inputs["tokens"]), "epochs_digest": digest(epochs)}
    return artifact, inputs


def selected(check: str, *, artifact: dict | None = None, inputs: dict | None = None,
             absent: bool = False, unit: str = "microsecond", **limits: int) -> tuple[dict, dict, bytes]:
    default_artifact, default_inputs = holding()
    artifact = deepcopy(artifact if artifact is not None else default_artifact)
    inputs = deepcopy(inputs if inputs is not None else default_inputs)
    if "tokens" in inputs:
        artifact["tokens_digest"] = digest(inputs["tokens"])
    if "epochs" in inputs:
        artifact["epochs_digest"] = digest(inputs["epochs"])
    subject = NamespaceObject.create("token-holding", "TOKEN", {
        "scope": "retained-capability-token-records", "clock_unit": unit,
        "artifact": artifact})
    evidence = canonical_bytes({"schema_version": token_checks.EVIDENCE_VERSION,
                               "objects": [subject.to_dict()],
                               "inputs": None if absent else inputs})
    policy = token_checks.token_checks_policy(trust_roots=["fixture:retained-selection"])
    request = token_checks.token_checks_request(
        check=check, subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits)
    return request, policy, evidence


def replay(check: str, **kwargs: object) -> tuple[bytes, dict]:
    request, policy, evidence = selected(check, **kwargs)
    certificate = token_checks.build_token_checks_certificate(request, evidence, policy=policy)
    result = token_checks.recheck_token_checks_certificate(certificate, expected_request=request, policy=policy)
    return certificate, result


@pytest.mark.parametrize("check", ["tenure", "windows", "delegation"])
def test_each_proposed_token_predicate_replays_with_honest_scope(check: str) -> None:
    certificate, result = replay(check)
    assert result["status"] == "PASS"
    assert result["coordinate"] == token_checks.CHECKS[check]
    for field in ("object_profile_conformance", "authority", "signature_validity",
                  "physical_clock", "holding_completeness", "actual_execution"):
        assert result[field] == "NOT_ESTABLISHED"
    assert certificate == replay(check)[0]


@pytest.mark.parametrize("mutation", ["gap", "revive", "accrual", "head", "issued_before_birth"])
def test_tenure_rehashed_semantic_counterexamples_fail(mutation: str) -> None:
    artifact, inputs = holding()
    if mutation == "gap":
        inputs["epochs"][1]["epoch"] += 1
    elif mutation == "revive":
        last = inputs["epochs"][-1]
        inputs["epochs"].append({"epoch": 9, "status": "ACTIVE",
                                 "digest": digest([last["digest"], 9, "ACTIVE"])})
    elif mutation == "accrual":
        inputs["tokens"][-1]["accumulated_epochs"] = 3
    elif mutation == "head":
        inputs["tokens"][-1]["accumulator_digest"] = digest("other-head")
    else:
        inputs["tokens"][1]["issued_at"] = 99
    assert replay("tenure", artifact=artifact, inputs=inputs)[1]["status"] == "FAIL"


@pytest.mark.parametrize("mutation", ["scope", "parent", "cycle", "caveat", "expiry", "quota", "soulbound"])
def test_delegation_rehashed_semantic_counterexamples_fail(mutation: str) -> None:
    artifact, inputs = holding()
    parent, child = inputs["tokens"][1:3]
    if mutation == "scope": child["permitted_scopes"] = ["admin"]
    elif mutation == "parent": child["parent_grant_id"] = "absent"
    elif mutation == "cycle": parent["parent_grant_id"] = "child"
    elif mutation == "caveat": child["caveats"] = []
    elif mutation == "expiry": child["not_after"] = 1001
    elif mutation == "quota": child["max_invocations"] = 11
    else:
        parent["soulbound"] = True
        child["delegate_key_id"] = digest("other-delegate")
    assert replay("delegation", artifact=artifact, inputs=inputs)[1]["status"] == "FAIL"


def test_window_skew_ambiguity_and_unbounded_windows_remain_explicit() -> None:
    artifact, inputs = holding()
    inputs["tokens"][2]["not_after"] = 220
    assert replay("windows", artifact=artifact, inputs=inputs)[1]["status"] == "UNKNOWN"
    inputs["tokens"][2]["not_after"] = None
    result = replay("windows", artifact=artifact, inputs=inputs)[1]
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["token"]["unbounded_windows"] == ["child"]


@pytest.mark.parametrize("check", ["tenure", "windows", "delegation"])
def test_missing_bytes_inputs_and_finite_capacity_remain_unknown(check: str) -> None:
    assert replay(check, absent=True)[1]["status"] == "UNKNOWN"
    request, policy, evidence = selected(check)
    certificate = token_checks.build_token_checks_certificate(request, None, policy=policy)
    assert token_checks.recheck_token_checks_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "UNKNOWN"
    for bound in ("max_operations", "max_items", "max_composition_operations", "max_evidence_bytes"):
        assert replay(check, **{bound: 1})[1]["status"] == "UNKNOWN"


def test_missing_epochs_and_uncovered_aging_are_unknown() -> None:
    artifact, inputs = holding()
    inputs.pop("epochs")
    assert replay("tenure", artifact=artifact, inputs=inputs)[1]["status"] == "UNKNOWN"
    artifact, inputs = holding()
    inputs["tokens"][-1]["epoch_end"] = 9
    assert replay("tenure", artifact=artifact, inputs=inputs)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["replay", "integer", "window"])
def test_inventory_contradictions_fail_all_three(mutation: str) -> None:
    artifact, inputs = holding()
    if mutation == "replay": inputs["tokens"][2]["replay_id"] = "r-root"
    elif mutation == "integer": inputs["tokens"][1]["not_before"] = True
    else: inputs["tokens"][1]["not_after"] = 100
    for check in token_checks.CHECKS:
        assert replay(check, artifact=artifact, inputs=inputs)[1]["status"] == "FAIL"


def test_unadmitted_unit_and_financial_token_semantics_are_unknown() -> None:
    for check in token_checks.CHECKS:
        assert replay(check, unit="millisecond")[1]["status"] == "UNKNOWN"
    artifact, inputs = holding()
    inputs["tokens"][0]["kind"] = "fungible-balance"
    assert replay("tenure", artifact=artifact, inputs=inputs)[1]["status"] == "UNKNOWN"


def test_predicates_do_not_promote_each_other_or_tenure_to_authority() -> None:
    artifact, inputs = holding()
    inputs["tokens"][-1]["accumulated_epochs"] = 1000000
    assert replay("tenure", artifact=artifact, inputs=inputs)[1]["status"] == "FAIL"
    assert replay("delegation", artifact=artifact, inputs=inputs)[1]["status"] == "PASS"
    assert replay("windows", artifact=artifact, inputs=inputs)[1]["status"] == "PASS"
    inputs["tokens"][2]["permitted_scopes"] = ["admin"]
    assert replay("delegation", artifact=artifact, inputs=inputs)[1]["status"] == "FAIL"


def test_same_unit_clock_offset_preserves_only_declared_window_arithmetic() -> None:
    artifact, inputs = holding()
    for token in inputs["tokens"]:
        token["issued_at"] += 1000000
        if token["kind"] == "lifetime":
            token["not_before"] += 1000000
            token["not_after"] += 1000000
    for check in token_checks.CHECKS:
        result = replay(check, artifact=artifact, inputs=inputs)[1]
        assert result["status"] == "PASS"
        assert result["physical_clock"] == "NOT_ESTABLISHED"


def test_forged_result_and_cross_objective_selection_are_rejected() -> None:
    request, policy, evidence = selected("tenure")
    certificate = token_checks.build_token_checks_certificate(request, evidence, policy=policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        token_checks.recheck_token_checks_certificate(canonical_bytes(forged), expected_request=request, policy=policy)
    other, _, _ = selected("delegation")
    with pytest.raises(ValueError):
        token_checks.recheck_token_checks_certificate(certificate, expected_request=other, policy=policy)
    changed = deepcopy(policy)
    changed["trust_roots"] = ["other-selection"]
    with pytest.raises(ValueError):
        token_checks.recheck_token_checks_certificate(certificate, expected_request=request, policy=changed)


def test_foreign_selection_callbacks_are_refused() -> None:
    class ForeignText(str):
        def __eq__(self, value: object) -> bool:
            raise AssertionError("foreign callback invoked")
        __hash__ = str.__hash__
    request, policy, evidence = selected("tenure")
    request["check"] = ForeignText("tenure")
    with pytest.raises(ValueError):
        token_checks.build_token_checks_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/token_checks.py", "domains/contracts/retained_selection.py",
    "domains/token.py", "domains/statics.py", "domains/common.py", "core/evidence.py",
    "standard/CURRENT_TOKEN_CHECKS.md", "standard/DOMAIN_OBLIGATIONS.md", "standard/ZIZK_TOKENS.md"])
def test_policy_pin_refuses_changed_source(relative: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selected("tenure")
    original = Path.read_bytes
    target = Path(token_checks.__file__).parents[2] / relative
    def altered(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged-pin" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", altered)
    with pytest.raises(ValueError, match="installed mechanism"):
        token_checks.build_token_checks_certificate(request, evidence, policy=policy)


def test_specs_match_and_central_registry_names_only_scoped_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    from importlib.resources import files
    packaged = files("verifier").joinpath("standard/CURRENT_TOKEN_CHECKS.md").read_bytes()
    assert packaged == (root / "src/verifier/standard/CURRENT_TOKEN_CHECKS.md").read_bytes()
    assert packaged == (Path(token_checks.__file__).parents[2] / "standard/CURRENT_TOKEN_CHECKS.md").read_bytes()
    assert not (root / "standard/CURRENT_TOKEN_CHECKS.md").exists()
    from verifier.domains.inventory import slot_inventory
    slots = slot_inventory()
    assert sum(row["mechanized"] for row in slots) == 234
    assert all(row["mechanized"] for row in slots if row["object_kind"] == "TOKEN" and row["tier"] in (2, 3, 4))
