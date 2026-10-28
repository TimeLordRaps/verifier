"""Focused tests for the three new POLICY enforcement routes: isolated execution and independent oracle.

The routes are POLICY-1.3 (rule semantics), POLICY-2.3 (exceptions and declared revisions) and POLICY-3.3
(decision correspondence). Their observations come from real engine runs; their expectations come from the
oracle in ``policy_enforcement_worker``, which must not import the engine. Mutants are applied to the engine
in this process, and the oracle must reject each one. A PASS is local field evidence and never conformance.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

from verifier.runtime import manifest_gate
from verifier.runtime import policy_enforcement_execution as pe
from verifier.runtime import policy_enforcement_routes as routes
from verifier.runtime import policy_enforcement_worker as oracle

ROUTE_NAMES = (
    "POLICY-1.3-enforcement-rule-semantics",
    "POLICY-2.3-enforcement-exceptions-and-revisions",
    "POLICY-3.3-enforcement-decision-correspondence",
)


@pytest.fixture(scope="module")
def honest_report() -> dict[str, Any]:
    return routes.evaluate_routes()


@pytest.fixture(scope="module")
def honest_observations() -> list[dict[str, Any]]:
    return routes.observe_all()


def _judge(coordinate: str) -> tuple[str, list[str]]:
    observations = routes.observe_route(coordinate)
    verdicts, global_refusals = oracle.check_all(observations)
    return verdicts[coordinate][0], global_refusals + verdicts[coordinate][1]


def test_route_set_is_exactly_the_three_new_coordinates() -> None:
    assert routes.COORDINATES == ROUTE_NAMES
    assert tuple(oracle.DECLARED_STATUS) == ROUTE_NAMES
    assert routes.TIER1.startswith("POLICY-1.3-") and routes.TIER3.startswith("POLICY-3.3-")


def test_fault_patch_is_a_closed_engine_seam_and_restores_exactly() -> None:
    original = pe._decide
    replacement = lambda *args, **kwargs: None

    with pytest.raises(ValueError, match="retained engine"):
        with routes._patched(object(), "_decide", replacement):
            pass
    with pytest.raises(ValueError, match="enumerated seam"):
        with routes._patched(pe, "not_a_policy_seam", replacement):
            pass

    with routes._patched(pe, "_decide", replacement):
        assert pe._decide is replacement
    assert pe._decide is original


def test_new_routes_are_discovered_in_the_central_catalog_by_exact_binding() -> None:
    # The central row carries the short coordinate and the full route name, so a join on either alone
    # or on a prefix is the false negative this test exists to catch. Catalog presence is not conformance.
    assert {name: routes._central_registration(name) for name in ROUTE_NAMES} == {
        name: "CENTRAL_ROW_PRESENT_UNPINNED" for name in ROUTE_NAMES}


def test_isolated_report_carries_the_exact_central_binding_per_route(honest_report) -> None:
    assert [item["central_registration"] for item in honest_report["routes"]] == ["CENTRAL_ROW_PRESENT_UNPINNED"] * 3
    assert all(item["route_conformance"] == pe.NOT_ESTABLISHED for item in honest_report["routes"])


# --- Central binding: exact-key join against forged, renamed, duplicated and malformed rows --------

def _genuine(central_rows: list, route: str) -> dict:
    return next(row for row in central_rows if row["obligation_id"] == route)


def _without(central_rows: list, route: str) -> list:
    return [row for row in central_rows if row["obligation_id"] != route]


def _swap(central_rows: list, route: str, **changes: Any) -> list:
    return [{**row, **changes} if row["obligation_id"] == route else row for row in central_rows]


def _with_extra(central_rows: list, *extra: Any) -> list:
    return list(central_rows) + list(extra)


def _raise_catalog(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("catalog unreadable")


@pytest.fixture(scope="module")
def central_rows() -> list:
    return manifest_gate.obligation_catalog()


@pytest.mark.parametrize(("route", "build", "expected"), [
    pytest.param(routes.TIER1, lambda c: _without(c, routes.TIER1), "NOT_REGISTERED", id="absent-row"),
    pytest.param(routes.TIER1, lambda c: _without(c, routes.TIER1) + [
        {**_genuine(c, routes.TIER1), "coordinate": "POLICY-1.30", "obligation_id": "POLICY-1.30-enforcement-rule-semantics"}],
        "NOT_REGISTERED", id="forged-prefix-only"),
    pytest.param(routes.TIER1, lambda c: _with_extra(c,
        {**_genuine(c, routes.TIER1), "coordinate": "POLICY-1.30", "obligation_id": "POLICY-1.30-enforcement-rule-semantics"}),
        "CENTRAL_ROW_PRESENT_UNPINNED", id="genuine-with-forged-prefix-neighbour"),
    pytest.param(routes.TIER1, lambda c: _with_extra(c,
        {**_genuine(c, routes.TIER1), "coordinate": "POLICY-1.30", "obligation_id": routes.TIER1 + "-extra"}),
        "CENTRAL_ROW_PRESENT_UNPINNED", id="genuine-with-prefix-named-neighbour"),
    pytest.param(routes.TIER1, lambda c: _swap(c, routes.TIER1, obligation_id="POLICY-1.3-enforcement-rule-semantic"),
        "NOT_REGISTERED", id="wrong-name-truncated"),
    pytest.param(routes.TIER1, lambda c: _swap(c, routes.TIER1, obligation_id=routes.TIER1 + "-extra"),
        "NOT_REGISTERED", id="wrong-suffix-extended"),
    pytest.param(routes.TIER1, lambda c: _swap(c, routes.TIER1, adapter="verifier-provenance-policy-1"),
        "NOT_REGISTERED", id="wrong-adapter"),
    pytest.param(routes.TIER1, lambda c: _swap(c, routes.TIER1,
        checking_mechanism="verifier.runtime.added_kind_behavioral_routes.recheck_market_checks_certificate"),
        "NOT_REGISTERED", id="wrong-mechanism"),
    pytest.param(routes.TIER1, lambda c: _swap(c, routes.TIER1, tier=2), "NOT_REGISTERED", id="wrong-tier"),
    pytest.param(routes.TIER1, lambda c: _swap(c, routes.TIER1, object_kind="MARKET"), "NOT_REGISTERED",
                 id="wrong-object-kind"),
    pytest.param(routes.TIER1, lambda c: _swap(c, routes.TIER1, coordinate="POLICY-1.2"), "NOT_REGISTERED",
                 id="coordinate-of-another-route"),
    pytest.param(routes.TIER3, lambda c: _swap(c, routes.TIER3, adapter="verifier-retained-added-kind-behavioral-1"),
                 "NOT_REGISTERED", id="wrong-adapter-tier3"),
    pytest.param(routes.TIER1, lambda c: _with_extra(c, _genuine(c, routes.TIER1)), "UNKNOWN",
                 id="duplicate-identical-row"),
    pytest.param(routes.TIER1, lambda c: _with_extra(c,
        {**_genuine(c, routes.TIER1), "obligation_id": "POLICY-1.3-enforcement-rule-semantic"}),
        "UNKNOWN", id="same-coordinate-different-name"),
    pytest.param(routes.TIER1, lambda c: _with_extra(c,
        {**_genuine(c, routes.TIER1), "coordinate": "POLICY-1.30"}),
        "UNKNOWN", id="same-name-different-coordinate"),
    pytest.param(routes.TIER1, lambda c: _swap(c, routes.TIER1, adapter=None), "UNKNOWN", id="malformed-missing-adapter"),
    pytest.param(routes.TIER1, lambda c: _swap(c, routes.TIER1, tier="1"), "UNKNOWN", id="malformed-tier-as-string"),
    pytest.param(routes.TIER1, lambda c: _with_extra(c, "POLICY-1.3"), "UNKNOWN", id="malformed-non-mapping-row"),
    pytest.param(routes.TIER1, lambda c: None, "UNKNOWN", id="catalog-not-a-list"),
])
def test_central_binding_is_exact_and_fails_closed(monkeypatch, central_rows, route, build, expected) -> None:
    monkeypatch.setattr(manifest_gate, "obligation_catalog", lambda: build(central_rows))
    assert routes._central_registration(route) == expected


def test_unreadable_central_catalog_is_unknown_never_registered(monkeypatch) -> None:
    monkeypatch.setattr(manifest_gate, "obligation_catalog", _raise_catalog)
    assert {routes._central_registration(name) for name in ROUTE_NAMES} == {"UNKNOWN"}


def test_central_route_set_joins_provenance_and_enforcement_without_source_boundaries() -> None:
    assert pe.ROUTE_COORDINATES == (
        "POLICY-1.1", "POLICY-1.2", "POLICY-1.3",
        "POLICY-2.1", "POLICY-2.2", "POLICY-2.3",
        "POLICY-3.1", "POLICY-3.2", "POLICY-3.3",
    )
    assert set(pe.SOURCE_ROUTE_COORDINATES).isdisjoint(pe.ROUTE_COORDINATES)


@pytest.mark.parametrize("route", ROUTE_NAMES)
def test_each_enforcement_route_removal_or_forgery_fails_closed(
        monkeypatch, central_rows, route) -> None:
    with monkeypatch.context() as patch:
        patch.setattr(manifest_gate, "obligation_catalog", lambda: _without(central_rows, route))
        assert routes._central_registration(route) == "NOT_REGISTERED"
    with monkeypatch.context() as patch:
        patch.setattr(manifest_gate, "obligation_catalog", lambda: _swap(
            central_rows, route, adapter="verifier-provenance-policy-1"))
        assert routes._central_registration(route) == "NOT_REGISTERED"


def test_isolated_worker_reconciles_every_route_and_declares_no_conformance(honest_report) -> None:
    assert honest_report["auxiliary_verdict"] == oracle.PASS
    assert honest_report["case_count"] == len(routes._CASES)
    for route in honest_report["routes"]:
        assert route["auxiliary_verdict"] == oracle.PASS, route["refusals"]
        assert route["refusals"] == []
        assert route["route_conformance"] == pe.NOT_ESTABLISHED
        assert route["obligation_closure"] == pe.NOT_ESTABLISHED
    assert honest_report["route_conformance"] == pe.NOT_ESTABLISHED


def test_external_boundaries_stay_unknown_in_every_route_report(honest_report) -> None:
    boundaries = honest_report["external_boundaries"]
    assert set(boundaries.values()) == {oracle.UNKNOWN}
    for name in ("legal authority", "key custody", "signer identity", "trust-root truth",
                 "wall-clock currentness", "downstream routing", "truth of facts behind decision evidence"):
        assert name in boundaries


def test_worker_runs_with_isolated_interpreter_flags(monkeypatch) -> None:
    calls = []

    def capture(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", capture)
    assert routes.evaluate_routes()["auxiliary_verdict"] == oracle.UNKNOWN
    assert calls[0][1:4] == ["-I", "-S", "-B"]
    assert Path(calls[0][4]).name == "policy_enforcement_worker.py"


@pytest.mark.parametrize(("returncode", "stdout", "reason"), [
    (1, b"", "WORKER_FAILED"),
    (0, b"not json", "WORKER_OUTPUT_INVALID"),
    (0, json.dumps({"schema": oracle.OBSERVATION_SCHEMA, "nonce": "other", "observations": []}).encode(),
     "WORKER_OUTPUT_INVALID"),
])
def test_worker_failures_and_wrong_nonce_are_unknown_never_pass(monkeypatch, returncode, stdout, reason) -> None:
    monkeypatch.setattr(subprocess, "run",
                        lambda args, **kwargs: subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr=b""))
    report = routes.evaluate_routes()
    assert report["auxiliary_verdict"] == oracle.UNKNOWN
    assert report["reason"] == reason
    assert report["route_conformance"] == pe.NOT_ESTABLISHED


def test_source_pin_drift_between_parent_and_worker_is_unknown(monkeypatch) -> None:
    real_run = subprocess.run

    def drifted(args, **kwargs):
        completed = real_run(args, **kwargs)
        payload = json.loads(completed.stdout)
        payload["source_pins"] = {"runtime/policy_enforcement_worker.py": "sha256:" + "0" * 64}
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload).encode(), stderr=b"")

    monkeypatch.setattr(subprocess, "run", drifted)
    report = routes.evaluate_routes()
    assert report["auxiliary_verdict"] == oracle.UNKNOWN
    assert report["reason"] == "SOURCE_DRIFT"


def test_oracle_module_top_level_never_imports_the_engine() -> None:
    tree = ast.parse(Path(oracle.__file__).read_text(encoding="utf-8"))
    forbidden = ("policy_enforcement_execution", "policy_enforcement_routes", "verifier")
    for node in tree.body:
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""] + [alias.name for alias in node.names]
        for name in names:
            assert not any(part in forbidden for part in name.split(".")), name


def test_closed_form_rule_table_is_stated_independently() -> None:
    def rule(identifier, priority, effect, action="transfer", role="FINANCIAL"):
        return {"rule_id": identifier, "priority": priority, "effect": effect,
                "actions": [action], "roles": [role]}

    assert oracle.closed_form_role([], "transfer", "FINANCIAL") == ("DENY", "NO_MATCHING_RULE")
    assert oracle.closed_form_role([rule("A", 1, "ALLOW"), rule("D", 10, "DENY")], "transfer", "FINANCIAL") == (
        "DENY", "DENIED_BY_RULE:D")
    assert oracle.closed_form_role([rule("A", 10, "ALLOW"), rule("D", 1, "DENY")], "transfer", "FINANCIAL") == (
        "ALLOW", "ALLOWED_BY_RULE:A")
    assert oracle.closed_form_role([rule("A", 5, "ALLOW"), rule("D", 5, "DENY")], "transfer", "FINANCIAL") == (
        "DENY", "PRECEDENCE_CONFLICT")
    assert oracle.closed_form_role([rule("B", 5, "ALLOW"), rule("A", 5, "ALLOW")], "transfer", "FINANCIAL") == (
        "ALLOW", "ALLOWED_BY_RULE:A,B")


def test_fixture_trust_keys_are_public_constants_not_production_roots() -> None:
    assert set(oracle.FIXTURE_KEYS) == {oracle.DECIDER, oracle.EXCEPTOR, oracle.CLERK, oracle.UNUSED}
    assert all(len(key) == 32 for key in oracle.FIXTURE_KEYS.values())


# --- Falsification: each mutant must be rejected by the oracle --------------------------------

def _min_priority_role(policy, request, role, waived):
    applicable = [item for item in policy.rules
                  if request.action in item.actions and role in item.roles and item.rule_id not in waived]
    if not applicable:
        return role, pe.DENY, "NO_MATCHING_RULE"
    low = min(item.priority for item in applicable)
    deciding = [item for item in applicable if item.priority == low]
    identifiers = ",".join(sorted(item.rule_id for item in deciding))
    effects = {item.effect for item in deciding}
    if len(effects) > 1:
        return role, pe.DENY, "PRECEDENCE_CONFLICT"
    if effects == {pe.DENY}:
        return role, pe.DENY, "DENIED_BY_RULE:" + identifiers
    return role, pe.ALLOW, "ALLOWED_BY_RULE:" + identifiers


def _mixed_effects_allowed(policy, request, role, waived):
    real = pe._decide_role_real(policy, request, role, waived)
    return (role, pe.ALLOW, "ALLOWED_BY_RULE:TIE") if real[2] == "PRECEDENCE_CONFLICT" else real


def _no_rule_allowed(policy, request, role, waived):
    real = pe._decide_role_real(policy, request, role, waived)
    return (role, pe.ALLOW, "NO_MATCHING_RULE") if real[2] == "NO_MATCHING_RULE" else real


@pytest.fixture
def engine_mutant(monkeypatch):
    monkeypatch.setattr(pe, "_decide_role_real", pe._decide_role, raising=False)

    def apply(attribute: str, replacement: Any) -> None:
        monkeypatch.setattr(pe, attribute, replacement)

    return apply


@pytest.mark.parametrize("replacement", [_min_priority_role, _mixed_effects_allowed, _no_rule_allowed])
def test_rule_table_mutants_fail_policy_1_3(engine_mutant, replacement) -> None:
    engine_mutant("_decide_role", replacement)
    verdict, refusals = _judge(routes.TIER1)
    assert verdict == oracle.FAIL
    assert refusals


def test_disabled_current_revision_check_fails_policy_2_3(engine_mutant) -> None:
    engine_mutant("_current_revision_failure", lambda *args, **kwargs: None)
    verdict, refusals = _judge(routes.TIER2)
    assert verdict == oracle.FAIL
    assert "OUTCOME_MISMATCH:revisions.superseded_revision_refused" in refusals


def test_constant_trust_commitment_fails_policy_1_3(engine_mutant) -> None:
    engine_mutant("_trust_roots_digest", lambda trust_roots: "sha256:" + "0" * 64)
    verdict, refusals = _judge(routes.TIER1)
    assert verdict == oracle.FAIL
    assert any("TRUST_COMMITMENT_MISMATCH" in item for item in refusals)


def test_unchecked_decision_evidence_fails_policy_3_3(engine_mutant) -> None:
    engine_mutant("check_policy_decision", lambda evidence: True)
    verdict, refusals = _judge(routes.TIER3)
    assert verdict == oracle.FAIL
    assert any("mutated" in item for item in refusals)


def test_disabled_bypass_detection_fails_policy_3_3(engine_mutant) -> None:
    engine_mutant("detect_bypass", lambda ledger, effects: ())
    verdict, refusals = _judge(routes.TIER3)
    assert verdict == oracle.FAIL
    assert any("BYPASS_FINDINGS_MISMATCH" in item for item in refusals)


def test_forged_allowed_on_injected_faults_fails_policy_3_3(engine_mutant) -> None:
    engine_mutant("_decide", lambda *args, **kwargs: pe._Verdict(pe.ALLOWED, ("ALL_ROLES_ALLOWED",)))
    verdict, refusals = _judge(routes.TIER3)
    assert verdict == oracle.FAIL
    assert any("unavailable_behavior" in item for item in refusals)


def test_unsupplied_effects_reported_as_clean_fails_policy_3_3(engine_mutant) -> None:
    real_report = pe.build_report

    def clean(policy, ledger, effects=()):
        report = real_report(policy, ledger, effects)
        report["effect_coverage"]["unsupplied_effects"] = "NONE"
        return report

    engine_mutant("build_report", clean)
    verdict, refusals = _judge(routes.TIER3)
    assert verdict == oracle.FAIL
    assert any("UNSUPPLIED_EFFECTS_NOT_UNKNOWN" in item for item in refusals)


# --- Forged or incomplete observation sets are refused, never silently passed ---------------

def test_flipped_outcome_in_an_observation_is_refused(honest_observations) -> None:
    observations = [dict(item) for item in honest_observations]
    target = next(item for item in observations if item["case"] == "precedence.higher_priority_deny_wins")
    target["outcome"] = pe.ALLOWED
    verdicts, global_refusals = oracle.check_all(observations)
    assert verdicts[routes.TIER1][0] == oracle.FAIL
    assert "OUTCOME_MISMATCH:precedence.higher_priority_deny_wins" in verdicts[routes.TIER1][1]


def test_missing_case_fails_its_route(honest_observations) -> None:
    observations = [item for item in honest_observations if item["case"] != "revisions.superseded_revision_refused"]
    verdicts, _ = oracle.check_all(observations)
    assert verdicts[routes.TIER2][0] == oracle.FAIL
    assert "CASE_COUNT_NOT_ONE:revisions.superseded_revision_refused" in verdicts[routes.TIER2][1]


def test_duplicated_case_fails_its_route(honest_observations) -> None:
    observations = list(honest_observations) + [honest_observations[0]]
    verdicts, _ = oracle.check_all(observations)
    assert verdicts[routes.TIER1][0] == oracle.FAIL


def test_unknown_case_name_fails_every_route(honest_observations) -> None:
    observations = list(honest_observations) + [{"case": "invented.case", "coordinate": routes.TIER1}]
    verdicts, global_refusals = oracle.check_all(observations)
    assert global_refusals == ["UNKNOWN_CASE:'invented.case'"]
    assert all(verdict == oracle.FAIL for verdict, _ in verdicts.values())


def test_route_pass_requires_bound_chain_and_digests(honest_observations) -> None:
    observations = [dict(item) for item in honest_observations]
    for item in observations:
        if item["case"] == "decision_inputs.request_digest_binds_request":
            item["request_digests"] = [item["request_digests"][0], item["request_digests"][0]]
        if item["case"] == "unavailable_behavior.request_digest_fault_unavailable_and_unsealed":
            item["chain_verified"] = True
    verdicts, _ = oracle.check_all(observations)
    assert verdicts[routes.TIER1][0] == oracle.FAIL
    assert verdicts[routes.TIER3][0] == oracle.FAIL
