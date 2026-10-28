"""RED-first regression gates for the in-memory ASSET Tier-0 execution mechanism.

These tests exercise `verifier.runtime.asset_execution` only. They establish
finite behavior of a deterministic specimen: typed quantities, claim versus
backing identity, issuance and redemption authority, idempotent supply
journal, custody versus control, encumbrance, atomic refusal and exact
reconciliation diagnostics. They do not establish ASSET-0 conformance.
"""
from __future__ import annotations

import ast
import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest

from verifier.runtime import asset_execution as asset
from verifier.runtime import package_contract_profiles as profiles
from verifier.runtime import token_asset_execution as token_routes
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS
from verifier.runtime.package_semantic_ownership_tests_fixtures import (
    TEST_FIXTURE_OWNERSHIP_SPECS,
)


ISSUER = "principal:issuer"
ALICE = "principal:alice"
BOB = "principal:bob"
NOTE7 = "claim:note-7"
NOTE8 = "claim:note-8"
ALICE_HOLDER = "holder:alice"
BOB_HOLDER = "holder:bob"
CAROL_HOLDER = "holder:carol"
ISSUE_GRANT = "grant:issue-note-7"


def _op(kind: str, operation_id: str, actor: str, holder: str, quantity: Any,
        claim: str = NOTE7, grant_id: str | None = None, ledger: asset.AssetLedger | None = None,
        grant_digest: str | None = None, counterparty: str | None = None,
        encumbrance: str | None = None, unit: str = "instrument") -> asset.Operation:
    if grant_id is not None and grant_digest is None and ledger is not None:
        try:
            grant_digest = ledger.grant_digest(grant_id)
        except asset.AssetRefusal:
            grant_digest = None
    return asset.Operation(
        kind=kind, operation_id=operation_id, actor=actor, claim_id=claim,
        holder_id=holder, quantity=quantity, unit=unit, grant_id=grant_id,
        grant_digest=grant_digest, counterparty_id=counterparty,
        encumbrance_id=encumbrance,
    )


def _issue(ledger: asset.AssetLedger, operation_id: str, quantity: Any, *,
           holder: str = BOB_HOLDER, actor: str = ISSUER, grant_id: str = ISSUE_GRANT,
           grant_digest: str | None = None, unit: str = "instrument",
           claim: str = NOTE7) -> asset.Operation:
    return _op("ISSUE", operation_id, actor, holder, quantity, claim=claim, grant_id=grant_id,
               ledger=ledger, grant_digest=grant_digest, unit=unit)


def test_field_declarations_are_exact_and_each_status_has_a_reason() -> None:
    expected = {
        "ASSET-0.1-identity-and-quantity": {
            "identity": "PARTIAL", "rights": "PARTIAL",
            "units": "MECHANIZED", "precision": "MECHANIZED",
        },
        "ASSET-0.2-issuance-and-redemption": {
            "issuance_authority": "BOUNDARY_EXCLUDED", "supply_changes": "PARTIAL",
            "redemption": "BOUNDARY_EXCLUDED", "backing_claims": "BOUNDARY_EXCLUDED",
        },
        "ASSET-0.3-custody-and-encumbrance": {
            "custody": "BOUNDARY_EXCLUDED", "control": "PARTIAL",
            "encumbrances": "MECHANIZED", "reconciliation": "MECHANIZED",
        },
    }
    observed = {
        obligation: {field: decl.status for field, decl in fields.items()}
        for obligation, fields in asset.FIELD_DECLARATIONS.items()
    }
    assert observed == expected
    assert sum(len(fields) for fields in expected.values()) == 12
    for fields in asset.FIELD_DECLARATIONS.values():
        for decl in fields.values():
            assert decl.status in asset.FIELD_STATUSES
            assert decl.reason.strip()


def test_module_is_stdlib_only_and_never_spawns_or_connects() -> None:
    source = Path(asset.__file__).read_text(encoding="utf-8")
    allowed = {"__future__", "copy", "dataclasses", "enum", "hashlib", "json", "pathlib", "typing"}
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= allowed
    for forbidden in ("subprocess", "socket", "urllib", "http", "os.system"):
        assert forbidden not in source


@pytest.mark.parametrize("value,code", [
    (True, "QUANTITY_TYPE"),
    (1.0, "QUANTITY_TYPE"),
    ("1", "QUANTITY_TYPE"),
    (-1, "QUANTITY_NEGATIVE"),
    (asset.MAX_QUANTITY + 1, "QUANTITY_OVERFLOW"),
])
def test_quantities_are_typed_nonnegative_and_bounded(value: Any, code: str) -> None:
    with pytest.raises(asset.AssetRefusal) as caught:
        asset.Quantity(value, asset.Unit.INSTRUMENT)
    assert caught.value.code == code
    assert asset.Quantity(asset.MAX_QUANTITY, asset.Unit.INSTRUMENT).value == asset.MAX_QUANTITY
    assert asset.Quantity(0, asset.Unit.BACKING_ATOM).value == 0


def test_distinct_claim_instrument_and_backing_identifiers_are_accepted() -> None:
    record = asset.ClaimRecord("claim:n", "instrument:n", "backing:n", "RECORD_CLAIM", 2)
    assert len({record.claim_id, record.instrument_id, record.backing_id}) == 3


@pytest.mark.parametrize("claim,instrument,backing", [
    ("claim:n", "instrument:n", "claim:n"),
    ("claim:n", "backing:n", "backing:n"),
    ("claim:n", "backing:n", "instrument:n"),
])
def test_claim_and_backing_identity_namespaces_refuse_conflation(
    claim: str, instrument: str, backing: str
) -> None:
    with pytest.raises(asset.AssetRefusal) as caught:
        asset.ClaimRecord(claim, instrument, backing, "RECORD_CLAIM", 2)
    assert caught.value.code == "IDENTITY_NAMESPACE"


def test_recorded_claim_identity_is_separate_from_backing_identity() -> None:
    ledger = asset.build_specimen()
    claim = ledger.claim(NOTE7)
    assert claim.backing_id == "backing:reserve-7"
    assert claim.instrument_id != claim.backing_id
    assert claim.backing_id != claim.claim_id
    assert ledger.backing_claim("backing:reserve-7").unit is asset.Unit.BACKING_ATOM
    assert ledger.backing_claim("backing:reserve-7").value == 300


def test_replay_returns_recorded_receipt_without_mutation() -> None:
    ledger = asset.build_specimen()
    first = ledger.apply(_issue(ledger, "op:replay-1", 40))
    assert first["status"] == "APPLIED"
    before, height = ledger.state_digest(), ledger.height
    again = ledger.apply(_issue(ledger, "op:replay-1", 40))
    assert again["status"] == "REPLAYED"
    assert again["digest"] == first["digest"]
    assert ledger.state_digest() == before
    assert ledger.height == height
    assert ledger.balance(NOTE7, BOB_HOLDER) == 40


def test_operation_id_reuse_with_different_payload_is_refused_without_mutation() -> None:
    ledger = asset.build_specimen()
    ledger.apply(_issue(ledger, "op:reuse", 40))
    before = ledger.state_digest()
    with pytest.raises(asset.AssetRefusal) as caught:
        ledger.apply(_issue(ledger, "op:reuse", 41))
    assert caught.value.code == "OPERATION_ID_CONFLICT"
    assert ledger.state_digest() == before


@pytest.mark.parametrize("kind,code,build", [
    ("MISSING", "AUTHORITY_MISSING", lambda L: _issue(L, "op:a", 5, grant_id="grant:none")),
    ("FORGED", "AUTHORITY_FORGED", lambda L: _issue(
        L, "op:b", 5,
        grant_digest=asset.AuthorityGrant(ISSUE_GRANT, ISSUER, "ISSUE", NOTE7, 10**6).digest())),
    ("REVOKED", "AUTHORITY_REVOKED", lambda L: _issue(L, "op:c", 5, grant_id="grant:issue-note-7-revoked")),
    ("ACTOR", "AUTHORITY_ACTOR_MISMATCH", lambda L: _issue(L, "op:d", 5, actor=ALICE)),
    ("BUDGET", "AUTHORITY_BUDGET", lambda L: _issue(L, "op:e", 70)),
    ("UNIT", "UNIT_MISMATCH", lambda L: _issue(L, "op:f", 5, unit="backing_atom")),
    ("NEGATIVE", "QUANTITY_NEGATIVE", lambda L: _issue(L, "op:g", -1)),
    ("BOOLEAN", "QUANTITY_TYPE", lambda L: _issue(L, "op:h", True)),
])
def test_refused_operations_are_exact_and_leave_state_unchanged(
    kind: str, code: str, build: Any
) -> None:
    ledger = asset.build_specimen()
    ledger.apply(_issue(ledger, "op:seed", 40))
    before, height = ledger.state_digest(), ledger.height
    with pytest.raises(asset.AssetRefusal) as caught:
        ledger.apply(build(ledger))
    assert caught.value.code == code, kind
    assert ledger.state_digest() == before
    assert ledger.height == height


def test_custodian_alone_cannot_transfer_but_controller_can() -> None:
    ledger = asset.build_specimen()
    ledger.apply(_issue(ledger, "op:seed", 40, holder=ALICE_HOLDER))
    custodian = ledger.account(NOTE7, ALICE_HOLDER).custodian_id
    before = ledger.state_digest()
    with pytest.raises(asset.AssetRefusal) as caught:
        ledger.apply(_op("TRANSFER", "op:t-custodian", custodian, ALICE_HOLDER, 10,
                         counterparty=BOB_HOLDER))
    assert caught.value.code == "CONTROL_REQUIRED"
    assert ledger.state_digest() == before
    ledger.apply(_op("TRANSFER", "op:t-controller", ALICE, ALICE_HOLDER, 10,
                     counterparty=BOB_HOLDER))
    assert ledger.balance(NOTE7, ALICE_HOLDER) == 30
    assert ledger.balance(NOTE7, BOB_HOLDER) == 10
    assert ledger.account(NOTE7, ALICE_HOLDER).custodian_id == custodian


def test_encumbrance_blocks_transfer_and_redemption_until_released() -> None:
    ledger = asset.build_specimen()
    ledger.apply(_issue(ledger, "op:seed", 40, holder=ALICE_HOLDER))
    ledger.apply(_op("ENCUMBER", "op:enc", ALICE, ALICE_HOLDER, 20, encumbrance="enc:one"))
    before = ledger.state_digest()
    with pytest.raises(asset.AssetRefusal) as transfer:
        ledger.apply(_op("TRANSFER", "op:t-blocked", ALICE, ALICE_HOLDER, 25,
                         counterparty=BOB_HOLDER))
    assert transfer.value.code == "ENCUMBERED_QUANTITY"
    with pytest.raises(asset.AssetRefusal) as redeem:
        ledger.apply(_op("REDEEM", "op:r-blocked", ALICE, ALICE_HOLDER, 25, grant_id="grant:redeem-note-7-alice",
                         ledger=ledger))
    assert redeem.value.code == "ENCUMBERED_QUANTITY"
    assert ledger.state_digest() == before
    ledger.apply(_op("TRANSFER", "op:t-ok", ALICE, ALICE_HOLDER, 20, counterparty=BOB_HOLDER))
    assert ledger.balance(NOTE7, ALICE_HOLDER) == 20


def test_partial_batch_failure_is_atomic() -> None:
    ledger = asset.build_specimen()
    ledger.apply(_issue(ledger, "op:seed", 40, holder=ALICE_HOLDER))
    before = ledger.state_digest()
    batch = [
        _issue(ledger, "op:batch-ok", 5),
        _op("REDEEM", "op:batch-bad", ALICE, ALICE_HOLDER, 999, grant_id="grant:redeem-note-7-alice",
            ledger=ledger),
    ]
    with pytest.raises(asset.BatchRefused) as caught:
        ledger.apply_batch(batch)
    assert caught.value.index == 1
    assert caught.value.cause_code == "INSUFFICIENT_BALANCE"
    assert ledger.state_digest() == before
    assert ledger.balance(NOTE7, BOB_HOLDER) == 0


def test_underflow_and_overflow_are_refused_without_wraparound() -> None:
    ledger = asset.build_specimen()
    ledger.apply(_issue(ledger, "op:seed", 40, holder=ALICE_HOLDER))
    with pytest.raises(asset.AssetRefusal) as underflow:
        ledger.apply(_op("REDEEM", "op:underflow", ALICE, ALICE_HOLDER, 41,
                         grant_id="grant:redeem-note-7-alice", ledger=ledger))
    assert underflow.value.code == "INSUFFICIENT_BALANCE"

    probe = asset.build_specimen()
    probe.apply(_issue(probe, "op:max", asset.MAX_QUANTITY, holder=CAROL_HOLDER,
                       claim=NOTE8, grant_id="grant:issue-note-8-max"))
    before = probe.state_digest()
    with pytest.raises(asset.AssetRefusal) as overflow:
        probe.apply(_issue(probe, "op:over", 1, holder=CAROL_HOLDER,
                           claim=NOTE8, grant_id="grant:issue-note-8-max"))
    assert overflow.value.code == "QUANTITY_OVERFLOW"
    assert probe.state_digest() == before


def test_tampered_payload_under_recorded_operation_id_is_a_conflict() -> None:
    ledger = asset.build_specimen()
    ledger.apply(_issue(ledger, "op:forge", 40))
    tampered = _issue(ledger, "op:forge", 40)
    tampered = asset.Operation(**{**tampered.__dict__, "holder_id": ALICE_HOLDER})
    with pytest.raises(asset.AssetRefusal) as caught:
        ledger.apply(tampered)
    assert caught.value.code == "OPERATION_ID_CONFLICT"


def test_specimen_sequence_reproduces_every_expected_outcome() -> None:
    ledger, scenarios = asset.run_specimen()
    mismatched = [step for step in scenarios if not step["matched"]]
    assert mismatched == []
    assert ledger.height == 9
    issued = ledger.issued_total(NOTE7)
    redeemed = ledger.redeemed_total(NOTE7)
    assert (issued, redeemed) == (70, 15)
    assert ledger.balance(NOTE7, ALICE_HOLDER) == 5
    assert ledger.balance(NOTE7, BOB_HOLDER) == 50
    assert issued - redeemed == ledger.balance(NOTE7, ALICE_HOLDER) + ledger.balance(NOTE7, BOB_HOLDER)


def test_honest_statement_reconciles_and_single_mismatch_is_exact() -> None:
    ledger, _ = asset.run_specimen()
    honest = asset.observed_statement(ledger)
    report = ledger.reconcile(honest)
    assert report["status"] == "PASS"
    assert report["diagnostics"] == []

    tampered = asset.observed_statement(ledger)
    tampered["holdings"][NOTE7][BOB_HOLDER] = 51
    report = ledger.reconcile(tampered)
    assert report["status"] == "FAIL"
    assert {
        "kind": "HOLDING_MISMATCH", "claim_id": NOTE7, "holder_id": BOB_HOLDER,
        "expected": 50, "observed": 51, "delta": 1,
    } in report["diagnostics"]


def test_missing_holding_in_statement_is_a_mismatch_not_zero() -> None:
    ledger, _ = asset.run_specimen()
    statement = asset.observed_statement(ledger)
    del statement["holdings"][NOTE8][CAROL_HOLDER]
    report = ledger.reconcile(statement)
    assert report["status"] == "FAIL"
    assert any(
        d["kind"] == "HOLDING_MISMATCH" and d["holder_id"] == CAROL_HOLDER and d["observed"] is None
        for d in report["diagnostics"]
    )


def test_backing_shortfall_reports_exact_required_and_observed_atoms() -> None:
    ledger, _ = asset.run_specimen()
    statement = asset.observed_statement(ledger)
    statement["backing_atoms"]["backing:reserve-7"] = 164
    report = ledger.reconcile(statement)
    assert report["status"] == "FAIL"
    assert {
        "kind": "BACKING_SHORTFALL", "backing_id": "backing:reserve-7",
        "required": 165, "observed": 164, "delta": -1,
    } in report["diagnostics"]


def test_stale_statement_is_unknown_not_pass() -> None:
    ledger, _ = asset.run_specimen()
    statement = asset.observed_statement(ledger)
    statement["height"] = ledger.height - 1
    report = ledger.reconcile(statement)
    assert report["status"] == "UNKNOWN"
    assert report["reason"] == "STATEMENT_STALE"


def test_malformed_statement_is_unknown_not_coerced() -> None:
    ledger, _ = asset.run_specimen()
    statement = asset.observed_statement(ledger)
    del statement["backing_atoms"]
    report = ledger.reconcile(statement)
    assert report["status"] == "UNKNOWN"
    assert report["reason"] == "STATEMENT_MALFORMED"


def test_silent_internal_mutation_is_detected_by_conservation_and_holdings() -> None:
    ledger, _ = asset.run_specimen()
    statement = asset.observed_statement(ledger)
    mutated = ledger.clone()
    mutated._state.accounts[NOTE7][ALICE_HOLDER].balance += 1
    report = mutated.reconcile(statement)
    assert report["status"] == "FAIL"
    kinds = {d["kind"] for d in report["diagnostics"]}
    assert {"CONSERVATION_MISMATCH", "HOLDING_MISMATCH"} <= kinds
    assert {
        "kind": "CONSERVATION_MISMATCH", "claim_id": NOTE7,
        "issued_minus_redeemed": 55, "current_holdings": 56,
    } in report["diagnostics"]


def test_callable_report_is_deterministic_and_binds_current_source_bytes() -> None:
    first = asset.evaluate()
    second = asset.evaluate()
    assert first == second
    assert first["status"] == "PASS"
    assert first["conformance"] == "NOT_ESTABLISHED"
    expected_digest = "sha256:" + hashlib.sha256(Path(asset.__file__).read_bytes()).hexdigest()
    assert first["source_digest"] == expected_digest
    assert first["specimen_digest"] == asset.build_specimen().state_digest()


def test_report_never_upgrades_real_world_claims() -> None:
    report = asset.evaluate()
    assert report["claim_boundary"] == asset.CLAIM_BOUNDARY
    assert set(asset.CLAIM_BOUNDARY) == {
        "issuer_authority", "signature_validity", "real_custody", "holding_completeness",
        "redemption", "application_enforcement", "supply_conservation", "backing",
    }
    assert set(asset.CLAIM_BOUNDARY.values()) == {"NOT_ESTABLISHED"}
    assert report["field_statuses"] == {
        obligation: {
            field: {"status": decl.status, "reason": decl.reason}
            for field, decl in fields.items()
        }
        for obligation, fields in asset.FIELD_DECLARATIONS.items()
    }


ROUTES = ("ASSET-1.1", "ASSET-2.1", "ASSET-3.1")
FIELD_TIER_ROUTE = {
    "ASSET-0.1-identity-and-quantity": "ASSET-1.1",
    "ASSET-0.2-issuance-and-redemption": "ASSET-2.1",
    "ASSET-0.3-custody-and-encumbrance": "ASSET-3.1",
}


def _forged_copy(report: dict[str, Any], mutate: Any) -> dict[str, Any]:
    forged = copy.deepcopy(report)
    mutate(forged)
    return forged


def _mutant_check_quantity(original: Any) -> Any:
    def mutant(value: object, unit: str, expected_unit: str) -> int:
        return original(value, expected_unit, expected_unit)
    return mutant


def _mutant_authorize(original: Any) -> Any:
    def mutant(state: Any, op: Any, action: str) -> Any:
        if not op.grant_id:
            raise asset.AssetRefusal("AUTHORITY_MISSING", "operation cites no grant")
        grant = state.grants.get(op.grant_id)
        if grant is None:
            raise asset.AssetRefusal("AUTHORITY_MISSING", "grant is not registered")
        if op.grant_digest != grant.digest():
            raise asset.AssetRefusal("AUTHORITY_FORGED", "cited grant digest does not match the registry")
        if grant.action != action:
            raise asset.AssetRefusal("AUTHORITY_ACTION", "grant does not admit the action")
        if grant.claim_id != op.claim_id:
            raise asset.AssetRefusal("AUTHORITY_SCOPE", "grant is scoped to a different claim")
        if grant.principal != op.actor:
            raise asset.AssetRefusal("AUTHORITY_ACTOR_MISMATCH", "actor is not the grant principal")
        return grant
    return mutant


def _mutant_available(original: Any) -> Any:
    def mutant(account: Any, quantity: int) -> None:
        if quantity > account.balance:
            raise asset.AssetRefusal("INSUFFICIENT_BALANCE", "encumbrances ignored by mutant")
    return mutant


def test_catalog_maps_each_declaration_field_to_its_tier_route_exactly() -> None:
    rows = asset.catalog()
    assert [row["field_id"] for row in rows] == [
        f"{obligation}.{field}"
        for obligation, fields in asset.FIELD_DECLARATIONS.items()
        for field in fields
    ]
    for row in rows:
        coordinate = FIELD_TIER_ROUTE[row["obligation_id"]]
        assert row["route_coordinate"] == coordinate
        assert row["tier"] == asset.ROUTE_TIERS[coordinate]
        assert row["route_proposition_digest"] == asset.ROUTE_PROPOSITION_DIGESTS[coordinate]
        declared = asset.FIELD_DECLARATIONS[row["obligation_id"]][row["field"]]
        assert row["field_status"] == declared.status
        assert row["field_reason"] == declared.reason


def test_route_correspondence_matches_the_central_tier_table() -> None:
    central = profiles._ADDED_ROUTES["ASSET"]
    assert {tier: central[tier] for tier in (1, 2, 3)} == {
        1: ("ASSET-1.1",), 2: ("ASSET-2.1",), 3: ("ASSET-3.1",),
    }
    assert set(asset.ROUTE_COORDINATES) == set(ROUTES)
    for row in asset.catalog():
        assert row["route_coordinate"] in central[row["tier"]]


def test_no_declaration_field_is_carried_by_an_existing_route_replay() -> None:
    rows = asset.catalog()
    assert {row["carried_by_route"] for row in rows} == {False}
    assert {row["coverage"] for row in rows} == {"AUXILIARY_FIELD_MECHANISM"}
    assert {row["route_replay_subject"] for row in rows} == {"TOKEN"}
    assert {row["execution_status"] for row in rows} == {"NOT_EXECUTED"}
    assert {row["auxiliary_interface"] for row in rows} == {asset.AUXILIARY_INTERFACE}


def test_route_clauses_are_verbatim_in_live_route_claims_and_stances_are_closed() -> None:
    live = {row["coordinate"]: row["exact_claim"] for row in token_routes.catalog()}
    stances = set()
    for row in asset.catalog():
        clause = row["route_clause"]
        stances.add(row["route_stance"])
        if clause is None:
            assert row["route_stance"] == asset.NOT_NAMED
        else:
            assert clause in live[row["route_coordinate"]], row["field_id"]
            assert row["route_stance"] in (asset.NAMED_CLAIM, asset.NAMED_BOUNDARY)
    assert stances == {asset.NOT_NAMED, asset.NAMED_CLAIM, asset.NAMED_BOUNDARY}


def test_catalog_rows_cannot_be_mistaken_for_route_rows() -> None:
    for row in asset.catalog():
        assert not {"coordinate", "checking_mechanism", "proposition_digest", "scope"} & set(row)


def test_pinned_route_bindings_match_the_live_token_routes() -> None:
    live = token_routes.catalog()
    assert asset.route_drift(live) == []
    assert {row["coordinate"]: row["proposition_digest"] for row in live} == asset.ROUTE_PROPOSITION_DIGESTS
    assert asset.ROUTE_CHECKING_MECHANISM == "verifier.runtime.token_asset_execution.evaluate"
    assert {row["checking_mechanism"] for row in live} == {asset.ROUTE_CHECKING_MECHANISM}
    token_bytes = Path(token_routes.__file__).read_bytes()
    assert asset.ROUTE_SOURCE == "src/verifier/runtime/token_asset_execution.py"
    assert "sha256:" + hashlib.sha256(token_bytes).hexdigest() == asset.ROUTE_SOURCE_DIGEST


@pytest.mark.parametrize("mutate,diagnostic", [
    (lambda rows: rows[0].update(proposition_digest="sha256:" + "0" * 64), "PROPOSITION_DRIFT:ASSET-1.1"),
    (lambda rows: rows[1].update(checking_mechanism="verifier.runtime.other.evaluate"), "CHECKER_DRIFT:ASSET-2.1"),
    (lambda rows: rows[2].update(tier=2), "TIER_DRIFT:ASSET-3.1"),
    (lambda rows: rows[2].update(exact_claim=rows[2]["exact_claim"].replace("real custody", "custody")),
     "CLAUSE_DRIFT:ASSET-3.1:custody"),
    (lambda rows: rows.append(dict(rows[0])), "DUPLICATED:ASSET-1.1"),
    (lambda rows: rows.pop(), "MISSING:ASSET-3.1"),
    (lambda rows: rows.append({**rows[0], "coordinate": "ASSET-4.1"}), "UNKNOWN:'ASSET-4.1'"),
    (lambda rows: rows.append("ASSET-1.1"), "ROW_SHAPE_DIFFERS"),
])
def test_route_drift_reports_each_proposition_checker_coordinate_and_clause_drift(
    mutate: Any, diagnostic: str
) -> None:
    rows = [dict(row) for row in token_routes.catalog()]
    mutate(rows)
    assert diagnostic in asset.route_drift(rows)


def test_fresh_evaluation_is_accepted_for_each_route_and_reproduces_in_model_only() -> None:
    report = asset.evaluate()
    for coordinate in ROUTES:
        assert asset.check_observations(coordinate, report) is True
        entry = report["route_correspondence"][coordinate]
        assert entry["status"] == "IN_MODEL_REPRODUCED"
        assert entry["unmatched"] == []
        assert entry["rows"] > 0
        assert entry["route_status"] == "NOT_ESTABLISHED"
        assert entry["route_proposition_digest"] == asset.ROUTE_PROPOSITION_DIGESTS[coordinate]
    assert report["status"] == "PASS"
    assert report["conformance"] == "NOT_ESTABLISHED"
    assert {entry["status"] for entry in report["route_correspondence"].values()} == {"IN_MODEL_REPRODUCED"}


def test_row_tags_are_an_exact_cover_of_every_scenario_and_reconciliation_row() -> None:
    report = asset.evaluate()
    names = [row["name"] for row in report["scenarios"] + report["reconciliations"]]
    assert len(names) == len(set(names))
    assert set(asset.ROUTE_ROW_TAGS) == set(names)
    assert {c for tags in asset.ROUTE_ROW_TAGS.values() for c in tags} == set(ROUTES)
    for tags in asset.ROUTE_ROW_TAGS.values():
        assert tags and len(tags) == len(set(tags))


def test_check_observations_rejects_unregistered_and_aliased_coordinates() -> None:
    report = asset.evaluate()
    for coordinate in ("ASSET-4.1", "asset-1.1", "ASSET-1.1 ", "ASSET-1.10", "", None):
        with pytest.raises(ValueError, match="ASSET_ROUTE_COORDINATE_UNREGISTERED"):
            asset.check_observations(coordinate, report)


def test_observation_that_is_not_a_mapping_is_refused_by_shape() -> None:
    with pytest.raises(ValueError, match="ASSET_ROUTE_OBSERVATION_SHAPE_DIFFERS"):
        asset.check_observations("ASSET-1.1", [])


def test_forged_status_words_are_rejected_at_top_level_route_row_and_boundary() -> None:
    report = asset.evaluate()
    forgeries = [
        _forged_copy(report, lambda r: r.update(status="FAIL")),
        _forged_copy(report, lambda r: r["route_correspondence"]["ASSET-3.1"].update(status="PASS")),
        _forged_copy(report, lambda r: r["route_correspondence"]["ASSET-2.1"].update(
            route_status="PASS")),
        _forged_copy(report, lambda r: r["scenarios"][8].update(observed="APPLIED")),
        _forged_copy(report, lambda r: r["scenarios"][8].update(matched=False)),
        _forged_copy(report, lambda r: r["claim_boundary"].update(backing="ESTABLISHED")),
        _forged_copy(report, lambda r: r.update(conformance="ESTABLISHED")),
    ]
    for forged in forgeries:
        for coordinate in ROUTES:
            assert asset.check_observations(coordinate, forged) is False


def test_missing_duplicate_reordered_and_truncated_observations_are_rejected() -> None:
    report = asset.evaluate()
    cases = [
        lambda r: r["scenarios"].pop(3),
        lambda r: r["scenarios"].append(copy.deepcopy(r["scenarios"][0])),
        lambda r: r["scenarios"].reverse(),
        lambda r: r["reconciliations"].reverse(),
        lambda r: r["route_correspondence"].pop("ASSET-3.1"),
        lambda r: r["reconciliations"].pop(),
    ]
    for mutate in cases:
        forged = _forged_copy(report, mutate)
        for coordinate in ROUTES:
            assert asset.check_observations(coordinate, forged) is False


def test_observation_rows_aliased_across_coordinates_are_rejected() -> None:
    report = asset.evaluate()

    def alias(r: dict[str, Any]) -> None:
        r["route_correspondence"]["ASSET-1.1"] = copy.deepcopy(r["route_correspondence"]["ASSET-2.1"])

    assert asset.check_observations("ASSET-1.1", _forged_copy(report, alias)) is False


def test_stale_observation_is_rejected_after_source_or_proposition_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    report = asset.evaluate()
    monkeypatch.setattr(asset, "source_digest", lambda: "sha256:" + "1" * 64)
    assert asset.check_observations("ASSET-2.1", report) is False
    monkeypatch.undo()
    assert asset.check_observations("ASSET-2.1", report) is True
    monkeypatch.setitem(asset.ROUTE_PROPOSITION_DIGESTS, "ASSET-3.1", "sha256:" + "2" * 64)
    assert asset.check_observations("ASSET-3.1", report) is False


def test_authority_custody_and_backing_boundaries_are_not_upgraded_by_route_correspondence() -> None:
    report = asset.evaluate()
    assert report["claim_boundary"] == asset.CLAIM_BOUNDARY
    assert set(report["claim_boundary"].values()) == {"NOT_ESTABLISHED"}
    assert report["conformance"] == "NOT_ESTABLISHED"
    assert {row["route_status"] for row in report["route_correspondence"].values()} == {"NOT_ESTABLISHED"}
    custody = next(row for row in asset.catalog() if row["field"] == "custody")
    assert custody["route_stance"] == asset.NAMED_BOUNDARY
    assert custody["field_status"] == asset.BOUNDARY_EXCLUDED
    assert asset.CLAIM_BOUNDARY["backing"] == "NOT_ESTABLISHED"


def test_field_statuses_match_central_profile() -> None:
    divergent = {}
    for obligation, fields in asset.FIELD_DECLARATIONS.items():
        for field, declared in fields.items():
            central = profiles._DECLARATION_FIELD_BINDINGS[obligation][field]["status"]
            if declared.status != central:
                divergent[(obligation, field)] = (declared.status, central)
    assert divergent == {}


@pytest.mark.parametrize("coordinate,target,build", [
    ("ASSET-1.1", "_check_quantity", _mutant_check_quantity),
    ("ASSET-2.1", "_authorize", _mutant_authorize),
    ("ASSET-3.1", "_available", _mutant_available),
])
def test_one_mutation_per_route_is_detected_by_that_route_only_on_fresh_execution(
    monkeypatch: pytest.MonkeyPatch, coordinate: str, target: str, build: Any
) -> None:
    baseline = asset.evaluate()
    assert asset.check_observations(coordinate, baseline) is True
    monkeypatch.setattr(asset, target, build(getattr(asset, target)))
    mutated = asset.evaluate()
    entry = mutated["route_correspondence"][coordinate]
    assert entry["status"] == "IN_MODEL_UNREPRODUCED"
    assert entry["unmatched"]
    assert mutated["status"] == "FAIL"
    assert asset.check_observations(coordinate, baseline) is False
    assert asset.check_observations(coordinate, mutated) is False


ASSET_OBJECT_ID = "vstd-asset-tier0-execution-verifier"
ASSET_PATH = "src/verifier/runtime/asset_execution.py"
ASSET_TEST_PATH = "tests/test_package_asset_tier0_execution.py"
ASSET_FIXTURE_GROUP = "vstd-test-runtime-execution-regressions"


def _semantic_spec(object_id: str) -> Any:
    matches = [item for item in SEMANTIC_OWNERSHIP_SPECS if item.object_id == object_id]
    assert len(matches) == 1, object_id
    return matches[0]


def test_asset_execution_is_one_distinct_primary_verifier_record() -> None:
    spec = _semantic_spec(ASSET_OBJECT_ID)
    assert spec.primary_kind == "VERIFIER"
    assert spec.owned_paths == (ASSET_PATH,)
    # Only POLICY follows from source behavior: check_observations accepts or refuses
    # caller-supplied observations against a fresh evaluation. Nothing else is inferred.
    assert spec.specializations == ("POLICY",)
    owners = [item.object_id for item in SEMANTIC_OWNERSHIP_SPECS if ASSET_PATH in item.owned_paths]
    assert owners == [ASSET_OBJECT_ID]


def test_package_worker_exchange_does_not_own_the_asset_mechanism() -> None:
    exchange = _semantic_spec("vstd-package-worker-exchange")
    assert ASSET_PATH not in exchange.owned_paths
    assert ASSET_OBJECT_ID != exchange.object_id
    assert asset.__name__.endswith("asset_execution")


def test_asset_record_is_never_an_asset_subject_or_external_backing_or_custody_proof() -> None:
    spec = _semantic_spec(ASSET_OBJECT_ID)
    assert "ASSET" not in (spec.primary_kind, *spec.specializations)
    assert not any(
        decision.kind == "ASSET" and decision.status == "APPLIES"
        for decision in spec.root_role_decisions
    )
    boundary = spec.consequence_boundary
    for phrase in ("not an ASSET", "issuer authority", "real custody", "backing"):
        assert phrase in boundary, phrase
    assert asset.CLAIM_BOUNDARY["real_custody"] == "NOT_ESTABLISHED"
    assert asset.CLAIM_BOUNDARY["backing"] == "NOT_ESTABLISHED"
    assert all(row["carried_by_route"] is False for row in asset.catalog())


def test_asset_test_is_owned_by_exactly_the_runtime_execution_fixture_group() -> None:
    owners = [item.object_id for item in TEST_FIXTURE_OWNERSHIP_SPECS if ASSET_TEST_PATH in item.owned_paths]
    assert owners == [ASSET_FIXTURE_GROUP]
