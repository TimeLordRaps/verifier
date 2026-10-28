"""Package integration for the three retained POLICY enforcement routes.

POLICY-1.3, POLICY-2.3 and POLICY-3.3 are a separate route family.  They are
not the provenance POLICY-1.1 through POLICY-3.2 rows, and they are not a
MARKET, ROBOT, FINBOT, or consequence role.  Expected values below are literal
so that a change to the family definition must be made deliberately here.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.runtime import added_kind_behavioral_routes as behavioral
from verifier.runtime import package_contract_coverage as coverage
from verifier.runtime import package_contract_profiles as profiles
from verifier.runtime import package_instance_evidence as package_evidence
from verifier.runtime import policy_enforcement_worker as oracle
from verifier.runtime.manifest_gate import obligation_catalog
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.self_polish_estate import bytes_digest
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest

REPO = Path(__file__).resolve().parents[1]
ENGINE = REPO / "src" / "verifier" / "runtime" / "policy_enforcement_execution.py"
ADAPTER = "verifier-retained-policy-enforcement-1"
SEMANTIC = "verifier-policy-enforcement-routes-1"
PROVENANCE_ADAPTER = "verifier-provenance-policy-1"
LEGACY_ADAPTER = "verifier-retained-added-kind-behavioral-1"
ZERO = "sha256:" + "0" * 64
ROUTES = {
    "POLICY-1.3": ("POLICY-1.3-enforcement-rule-semantics", "rule_semantics", 1),
    "POLICY-2.3": ("POLICY-2.3-enforcement-exceptions-and-revisions", "exceptions_revisions", 2),
    "POLICY-3.3": ("POLICY-3.3-enforcement-decision-correspondence", "decision_correspondence", 3),
}
PROVENANCE = ("POLICY-1.1", "POLICY-1.2", "POLICY-2.1", "POLICY-2.2", "POLICY-3.1", "POLICY-3.2")


@pytest.fixture(scope="module")
def retained() -> dict:
    """One isolated worker run; its raw observations are the retained evidence."""
    return behavioral.retained_policy_observations()


def _select(coordinate: str) -> dict:
    row = behavioral.select_package_route(semantic_version=SEMANTIC, coordinate=coordinate)
    assert row is not None, coordinate
    return dict(row)


def _policy_source_digest() -> str:
    return bytes_digest(ENGINE.read_bytes())


def _replay(route: dict, coordinate: str, retained: dict, *, observations=None,
            source_pins=None, policy=None):
    """Build one certificate from retained observations, returning its evidence too."""
    source_digest = _policy_source_digest()
    evidence = behavioral.policy_enforcement_evidence(
        subject_id="policy-route", source_digest=source_digest,
        observations=retained["observations"] if observations is None else observations,
        source_pins=retained["source_pins"] if source_pins is None else source_pins,
    )
    selected_policy = behavioral.policy_enforcement_policy() if policy is None else policy
    request = behavioral.policy_enforcement_request(
        check=ROUTES[coordinate][1], subject_id="policy-route", source_digest=source_digest,
        evidence_ref=bytes_digest(evidence), policy=selected_policy,
    )
    certificate = behavioral.build_policy_enforcement_certificate(
        request, evidence, policy=selected_policy,
    )
    return request, certificate, selected_policy, evidence


# --- Catalog, denominators and exact recognition -------------------------------------------

def test_catalog_registers_exact_short_coordinates_beside_provenance_rows() -> None:
    catalog = obligation_catalog()
    for coordinate, (obligation, check, tier) in ROUTES.items():
        rows = [row for row in catalog if row.get("coordinate") == coordinate]
        assert len(rows) == 1, coordinate
        row = rows[0]
        assert row["obligation_id"] == obligation
        assert row["object_kind"] == "POLICY"
        assert row["tier"] == tier
        assert row["adapter"] == ADAPTER
        assert row["semantic_version"] == SEMANTIC
        assert row["checking_mechanism"] == (
            "verifier.runtime.added_kind_behavioral_routes.recheck_policy_enforcement_certificate"
        )
        assert row["scope"] == "finite_retained_policy_" + check
        assert row["prerequisite_coordinates"] == [
            coordinate_ for coordinate_ in ROUTES if ROUTES[coordinate_][2] < tier
        ]
    provenance = {row["coordinate"]: row["adapter"] for row in catalog
                  if row.get("coordinate") in PROVENANCE}
    assert provenance == {coordinate: PROVENANCE_ADAPTER for coordinate in PROVENANCE}


def test_exact_denominators_after_agency_and_this_policy_slice() -> None:
    catalog = obligation_catalog()
    assert len([row for row in catalog if row["tier"] <= 3]) == 293
    assert len(behavioral.catalog()) == 21
    assert sum(1 for row in behavioral.catalog() if row["adapter"] == ADAPTER) == 3
    matrix = profiles.contract_coverage_matrix()
    assert matrix["route_denominator"] == 293
    assert matrix["defined_obligation_denominator"] == 364
    assert matrix["findings"] == []


def test_profile_denominator_is_cumulative_for_policy_enforcement() -> None:
    for tier in (1, 2, 3):
        required = set(profiles.required_coordinates("POLICY", tier) or ())
        expected = {coordinate for coordinate, (_, _, route_tier) in ROUTES.items()
                    if route_tier <= tier}
        assert expected <= required
        assert not (set(ROUTES) - expected) & required
        assert {"POLICY-1.1", "POLICY-1.2"} <= required


def test_tier_two_and_three_omit_no_prerequisite_in_source_coverage() -> None:
    kinds = SimpleNamespace(registry=namespace_registry())
    clauses = [{"coordinate": f"POLICY-{tier}.90", "closure_status": "PASS",
                "checking_mechanism": "source"} for tier in (1, 2)]
    residuals = coverage._residuals("POLICY", 2, kinds, {}, clauses)
    residual_ids = {row["source_id"] for row in residuals
                    if row["source"] == "installed-package-variant-profile"}
    assert {"POLICY-1.3", "POLICY-2.3"} <= residual_ids
    assert "POLICY-3.3" not in residual_ids
    assert all(row["status"] == "UNKNOWN" for row in residuals
               if row["source"] == "installed-package-variant-profile")


def test_select_is_exact_and_refuses_unregistered_or_foreign_families() -> None:
    for coordinate, (obligation, _, _) in ROUTES.items():
        row = _select(coordinate)
        assert row["obligation_id"] == obligation and row["adapter"] == ADAPTER
    assert behavioral.select_package_route(semantic_version=SEMANTIC, coordinate="POLICY-1.1") is None
    assert behavioral.select_package_route(semantic_version=SEMANTIC, coordinate="POLICY-1.4") is None
    assert behavioral.select_package_route(semantic_version="verifier-other-1", coordinate="POLICY-1.3") is None


@pytest.mark.parametrize("mutation", [
    {"adapter": LEGACY_ADAPTER},
    {"adapter": PROVENANCE_ADAPTER},
    {"proposition_digest": ZERO},
    {"obligation_id": "POLICY-1.3-forged"},
    {"object_kind": "MARKET"},
    {"mechanism_digest": ZERO},
    {"checking_mechanism": "verifier.runtime.policy_enforcement_worker.check_all"},
])
@pytest.mark.parametrize("coordinate", list(ROUTES))
def test_is_route_recognizes_only_the_exact_current_policy_row(
        mutation: dict, coordinate: str) -> None:
    route = _select(coordinate)
    assert behavioral.is_route(route)
    forged = {**route, **mutation}
    assert not behavioral.is_route(forged)


def test_central_policy_pin_ties_package_route_to_installed_engine_bytes() -> None:
    route = _select("POLICY-1.3")
    assert route["mechanism_digest"] == behavioral.mechanism_digest(behavioral.POLICY_SPEC)
    module = REPO / "src" / "verifier" / "runtime" / "added_kind_behavioral_routes.py"
    assert profiles._ADDED_KIND_SEMANTIC_SOURCE_DIGESTS[
        "src/verifier/runtime/added_kind_behavioral_routes.py"
    ] == "sha256:" + hashlib.sha256(module.read_bytes()).hexdigest()


# --- Source-owned replay and forgery ------------------------------------------------------

@pytest.mark.parametrize("coordinate", list(ROUTES))
def test_retained_observations_replay_through_the_installed_oracle(
        retained: dict, coordinate: str) -> None:
    route = _select(coordinate)
    request, certificate, policy, _ = _replay(route, coordinate, retained)
    replay = behavioral.recheck_package_certificate(
        route, certificate, expected_request=request, policy=policy,
    )
    assert replay["status"] == "PASS"
    assert replay["scope"] == "finite_retained_policy_" + ROUTES[coordinate][1]
    assert replay["object_profile_conformance"] == "NOT_ESTABLISHED"
    for field in ("authority", "activation", "enforcement", "external_legal_adoption",
                  "signer_key_custody", "fact_truth", "unsupplied_effects",
                  "wall_clock_currentness"):
        assert replay[field] == "NOT_ESTABLISHED"


def test_forged_retained_outcome_is_refuted_not_passed(retained: dict) -> None:
    coordinate = "POLICY-1.3"
    observations = deepcopy(retained["observations"])
    target = next(item for item in observations
                  if item["case"] == "scope.out_of_scope_refused_before_rules")
    target["outcome"] = "ALLOWED"
    route = _select(coordinate)
    request, certificate, policy, _ = _replay(route, coordinate, retained, observations=observations)
    replay = behavioral.recheck_package_certificate(
        route, certificate, expected_request=request, policy=policy,
    )
    assert replay["status"] == "FAIL"
    assert "OUTCOME_MISMATCH" in json.dumps(replay["evaluation"])


@pytest.mark.parametrize("coordinate", list(ROUTES))
def test_stale_retained_source_pin_is_refuted(retained: dict, coordinate: str) -> None:
    stale = {**retained["source_pins"], "runtime/policy_enforcement_execution.py": ZERO}
    route = _select(coordinate)
    request, certificate, policy, _ = _replay(route, coordinate, retained, source_pins=stale)
    replay = behavioral.recheck_package_certificate(
        route, certificate, expected_request=request, policy=policy,
    )
    assert replay["status"] == "FAIL"
    assert "differ" in replay["evaluation"]["reason"]


@pytest.mark.parametrize("coordinate", list(ROUTES))
def test_current_source_drift_makes_a_retained_certificate_not_reproduce(
        monkeypatch: pytest.MonkeyPatch, retained: dict, coordinate: str) -> None:
    route = _select(coordinate)
    request, certificate, policy, _ = _replay(route, coordinate, retained)
    drifted = dict(oracle.source_pins())
    drifted["runtime/policy_enforcement_execution.py"] = ZERO
    monkeypatch.setattr(oracle, "source_pins", lambda: drifted)
    with pytest.raises(ValueError, match="does not reproduce"):
        behavioral.recheck_package_certificate(
            route, certificate, expected_request=request, policy=policy,
        )


def test_omitted_prerequisite_observations_remain_unknown(retained: dict) -> None:
    coordinate = "POLICY-2.3"
    observations = [item for item in retained["observations"]
                    if item["coordinate"] != ROUTES["POLICY-1.3"][0]]
    assert len(observations) < len(retained["observations"])
    route = _select(coordinate)
    request, certificate, policy, _ = _replay(route, coordinate, retained, observations=observations)
    replay = behavioral.recheck_package_certificate(
        route, certificate, expected_request=request, policy=policy,
    )
    assert replay["status"] == "UNKNOWN"


def test_forged_certificate_result_is_refused(retained: dict) -> None:
    coordinate = "POLICY-1.3"
    route = _select(coordinate)
    request, certificate, policy, _ = _replay(route, coordinate, retained)
    value = json.loads(certificate)
    current = value["result"]["status"]
    value["result"]["status"] = "FAIL" if current != "FAIL" else "PASS"
    with pytest.raises(ValueError):
        behavioral.recheck_package_certificate(
            route, canonical_bytes(value), expected_request=request, policy=policy,
        )


@pytest.mark.parametrize("mutation", ["coordinate", "proposition", "object_kind"])
def test_request_route_substitution_is_refused(retained: dict, mutation: str) -> None:
    coordinate = "POLICY-1.3"
    route = _select(coordinate)
    request, certificate, policy, _ = _replay(route, coordinate, retained)
    if mutation == "coordinate":
        request["coordinate"] = "MARKET-1.1-order-access-lifecycle"
    elif mutation == "proposition":
        request["proposition_digest"] = ZERO
    else:
        request["object_kind"] = "MARKET"
    with pytest.raises(ValueError, match="REQUEST_ROUTE|PACKAGE_REQUEST|differs|unsupported|objective"):
        behavioral.recheck_package_certificate(
            route, certificate, expected_request=request, policy=policy,
        )


def test_trust_root_substitution_is_refused_at_policy_and_replay(retained: dict) -> None:
    with pytest.raises(ValueError):
        behavioral.policy_enforcement_policy(trust_roots=["authority:unrelated"])
    coordinate = "POLICY-1.3"
    route = _select(coordinate)
    request, certificate, policy, _ = _replay(route, coordinate, retained)
    substituted = {**policy, "trust_roots": ["authority:unrelated"]}
    with pytest.raises(ValueError):
        behavioral.recheck_package_certificate(
            route, certificate, expected_request=request, policy=substituted,
        )


# --- Package instance result --------------------------------------------------------------

def _instance(root: Path, retained: dict, coordinate: str):
    route = _select(coordinate)
    source = ENGINE.read_bytes()
    (root / "subject.py").write_bytes(source)
    source_digest = bytes_digest(source)
    request, certificate, policy, evidence = _replay(route, coordinate, retained)
    request_bytes = canonical_bytes(request)
    check = {
        "object_id": "policy-route",
        "coordinate": route["coordinate"],
        "semantic_version": route["semantic_version"],
        "proposition_digest": route["proposition_digest"],
        "reason": "This exact retained POLICY enforcement variant selects the bounded route.",
        "evidence": [{"path": "subject.py", "sha256": source_digest}],
    }
    for name, raw in (
        ("request", request_bytes),
        ("policy", canonical_bytes(policy)),
        ("certificate", certificate),
        ("evidence", evidence),
    ):
        (root / (name + ".json")).write_bytes(raw)
        if name != "evidence":
            check[name] = {"path": name + ".json", "sha256": bytes_digest(raw)}
    item = NamespaceObject.create("policy-route", "OBJECT", {})
    row = {
        **item.to_dict(), "specializations": ["POLICY"],
        "surfaces": ["file:subject.py"], "reason": "Retained POLICY enforcement fixture.",
        "classification": {}, "obligations": {},
    }
    declaration = {"objects": [row], "instance_checks": [check]}
    return item, row, declaration, check, route


def test_policy_package_instance_replays_and_names_its_own_adapter(
        tmp_path: Path, retained: dict) -> None:
    item, row, declaration, check, route = _instance(tmp_path, retained, "POLICY-1.3")
    package_evidence.validate_checks([check], declaration["objects"], namespace_registry())
    selected = package_evidence.InstanceEvidence(
        tmp_path, (item,), declaration,
    ).evaluate(item, route)
    assert selected is not None and selected["status"] == "PASS"
    assert selected["adapter_id"] == ADAPTER
    assert selected["adapter_id"] != LEGACY_ADAPTER
    assert selected["applicability_established"] is True
    assert selected["result_digest"] == value_digest({
        key: value for key, value in selected.items() if key != "result_digest"
    })


def test_policy_object_must_explicitly_declare_the_policy_role(
        tmp_path: Path, retained: dict) -> None:
    _, row, declaration, check, _ = _instance(tmp_path, retained, "POLICY-1.3")
    undeclared = {**row, "specializations": []}
    with pytest.raises(ValueError, match="ADDED_KIND_NOT_EXPLICIT"):
        package_evidence.validate_checks([check], [undeclared], namespace_registry())


def test_policy_instance_refuses_a_substituted_proposition(tmp_path: Path, retained: dict) -> None:
    _, _, declaration, check, _ = _instance(tmp_path, retained, "POLICY-1.3")
    changed = {**check, "proposition_digest": ZERO}
    with pytest.raises(ValueError, match="PROPOSITION_DIFFERS"):
        package_evidence.validate_checks([changed], declaration["objects"], namespace_registry())


def test_policy_instance_with_unowned_source_is_refused(tmp_path: Path, retained: dict) -> None:
    item, row, declaration, check, route = _instance(tmp_path, retained, "POLICY-1.3")
    row["surfaces"] = ["file:different.py"]
    result = package_evidence.InstanceEvidence(
        tmp_path, (item,), declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "FAIL"
    assert "ADDED_SOURCE_UNOWNED" in result["reason"]


# --- Central declaration-field reconciliation ---------------------------------------------

_EXPECTED_POLICY_FIELDS = {
    "POLICY-0.1-rules-and-precedence": {
        "scope": "PARTIAL", "decision_inputs": "PARTIAL", "defaults": "PARTIAL", "precedence": "PARTIAL",
    },
    "POLICY-0.2-authority-and-exceptions": {
        "exceptions": "PARTIAL", "revisions": "PARTIAL",
        "authority": "BOUNDARY_EXCLUDED", "activation": "BOUNDARY_EXCLUDED",
    },
    "POLICY-0.3-enforcement-and-decisions": {
        "decision_evidence": "PARTIAL", "enforcement_points": "BOUNDARY_EXCLUDED",
        "bypass_handling": "PARTIAL", "unavailable_behavior": "PARTIAL",
    },
}


@pytest.mark.parametrize("obligation", list(_EXPECTED_POLICY_FIELDS))
def test_central_policy_field_statuses_match_the_route_self_declaration(obligation: str) -> None:
    evidence = profiles.declaration_field_evidence(obligation)
    assert evidence is not None
    statuses = {row["field"]: row["status"] for row in evidence["field_bindings"]}
    assert statuses == _EXPECTED_POLICY_FIELDS[obligation]
    assert "MECHANIZED" not in statuses.values()
    declared = oracle.DECLARED_STATUS
    coordinates = {
        "POLICY-0.1-rules-and-precedence": "POLICY-1.3-enforcement-rule-semantics",
        "POLICY-0.2-authority-and-exceptions": "POLICY-2.3-enforcement-exceptions-and-revisions",
        "POLICY-0.3-enforcement-and-decisions": "POLICY-3.3-enforcement-decision-correspondence",
    }
    worker = {field: ("BOUNDARY_EXCLUDED" if status == "BOUNDARY" else "PARTIAL")
              for field, status in declared[coordinates[obligation]].items()}
    assert {field: statuses[field] for field in worker} == worker


def test_central_overclaim_of_a_policy_boundary_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    obligation = "POLICY-0.1-rules-and-precedence"
    bindings = profiles._expand_declaration_field_bindings()
    overclaimed = deepcopy(bindings[obligation])
    overclaimed["precedence"]["status"] = "MECHANIZED"
    monkeypatch.setitem(profiles._DECLARATION_FIELD_BINDINGS, obligation, overclaimed)
    with pytest.raises(ValueError, match="BOUNDARY_OVERCLAIMED"):
        profiles.declaration_field_evidence(obligation)


def test_central_policy_authority_cannot_be_upgraded_to_partial(
        monkeypatch: pytest.MonkeyPatch) -> None:
    obligation = "POLICY-0.2-authority-and-exceptions"
    bindings = profiles._expand_declaration_field_bindings()
    upgraded = deepcopy(bindings[obligation])
    upgraded["authority"]["status"] = "PARTIAL"
    monkeypatch.setitem(profiles._DECLARATION_FIELD_BINDINGS, obligation, upgraded)
    with pytest.raises(ValueError, match="BOUNDARY_OVERCLAIMED"):
        profiles.declaration_field_evidence(obligation)


def test_policy_engine_source_bytes_are_pinned_as_reviewed() -> None:
    """Deliberate tripwire: a change to the POLICY engine bytes must be repinned here on review."""
    pins = oracle.source_pins()
    assert pins["runtime/policy_enforcement_execution.py"] == bytes_digest(ENGINE.read_bytes())
    assert pins == {
        "data/policy.py": "sha256:49b7249262b44f1f8375e4ca15e40b138a9b1bf85eb8d676edf6816645e4e8a3",
        "runtime/policy_enforcement_execution.py": "sha256:f868d74e9c353b8a2c4b469cc0b79b72d2ab9d2439e97646890954be93a80e92",
        "runtime/policy_enforcement_routes.py": "sha256:06504a355e697833626b332aaac345d78a384f2f51ea9cdb832163070d4d9a49",
        "runtime/policy_enforcement_worker.py": "sha256:7bd79141d43403cb49c7cfd5e94c2de4bdc3874296ae7ed678cb76707bd919cd",
        "runtime/tier_zero_profile.py": "sha256:87c67b4c9b6129e15dbd7eef0f250f7316f70909878047c1202a4ebd5cde1193",
    }
