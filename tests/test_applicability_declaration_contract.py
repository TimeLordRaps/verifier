"""Canonical reason/applicability declarations for Polish 0 through 3.

Declarations identify why a proposition enters the denominator.  They are not
instance evidence and cannot themselves close an obligation.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy

import pytest

from verifier.runtime import (
    added_kind_behavioral_routes,
    core_tier_progression,
    manifest_gate,
    package_execution,
    package_source_contracts,
)
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.tier_zero_profile import (
    applicability_declaration,
    applicability_digest,
    installed_tier_zero_profile,
    validate_applicability_binding,
    validate_applicability_declaration,
)


_FIELDS = {
    "mode",
    "condition",
    "reason",
    "when_condition_met",
    "unknown_condition",
}


def _assert_declaration(value: object) -> None:
    assert isinstance(value, dict)
    assert set(value) == _FIELDS
    assert value["mode"] in {"NECESSARY", "CONDITIONAL"}
    assert value["when_condition_met"] == "NECESSARY"
    assert value["unknown_condition"] == "NOT_EXEMPT"
    assert value["condition"].strip()
    assert value["reason"].strip()
    assert not ({"status", "evidence", "applicability_established"} & set(value))
    assert validate_applicability_declaration(value) == value


def _assert_binding(value: dict[str, object]) -> None:
    _assert_declaration(value["applicability"])
    assert value["applicability_digest"] == applicability_digest(
        value["applicability"]
    )
    assert validate_applicability_binding(value) == value["applicability"]


def test_exact_polish_zero_through_three_denominators_declare_applicability() -> None:
    admission = installed_tier_zero_profile()["obligations"]
    assert len(admission) == 9
    assert all(row["applicability"]["mode"] == "NECESSARY" for row in admission)
    for row in admission:
        _assert_binding(row)

    added = [
        obligation
        for contract in namespace_registry().values()
        if contract.extends is not None
        for obligation in contract.obligations
    ]
    assert len(added) == 36
    assert all(obligation.applicability["mode"] == "NECESSARY" for obligation in added)
    for obligation in added:
        _assert_binding({"applicability": obligation.applicability,
                         "applicability_digest": obligation.applicability_digest})

    routes = [row for row in manifest_gate.obligation_catalog() if row["tier"] in (1, 2, 3)]
    assert Counter(row["tier"] for row in routes) == {1: 105, 2: 97, 3: 91}
    assert len(routes) == 293
    source = [row for row in routes if package_source_contracts.is_route(row)]
    assert len(routes) - len(source) == 179
    for route in routes:
        _assert_binding(route)


def test_route_declaration_modes_match_their_installed_trigger_classes() -> None:
    routes = [row for row in manifest_gate.obligation_catalog() if row["tier"] in (1, 2, 3)]
    # Same classification as the contract matrix: source, then package-execution
    # mechanism, then added-kind behavioral (which also holds the BOT, ROBOT,
    # FINBOT and POLICY agency/policy routes), else native.  Grouping by adapter
    # string alone would put the 12 agency/policy routes into the execution class.
    source = [row for row in routes if package_source_contracts.is_route(row)]
    executions = [row for row in routes if package_execution.route_mechanism(row) is not None]
    core = [row for row in routes if row.get("adapter") is None]
    retained_added = [row for row in routes if added_kind_behavioral_routes.is_route(row)]

    classes = [source, executions, core, retained_added]
    keys = [{(row["coordinate"], row["obligation_id"]) for row in group} for group in classes]
    assert sum(len(group) for group in classes) == len(set().union(*keys)) == 293
    assert (len(source), len(executions), len(core), len(retained_added)) == (114, 45, 113, 21)
    assert Counter(row["adapter"] for row in retained_added) == {
        "verifier-retained-added-kind-behavioral-1": 9,
        "verifier-retained-agency-surface-1": 9,
        "verifier-retained-policy-enforcement-1": 3,
    }
    assert all(row["applicability"]["mode"] == "NECESSARY" for row in source)
    universal = [row for row in core if row["coordinate"] == "OBJECT-1.1"]
    runtime_variants = [row for row in core if row["coordinate"] != "OBJECT-1.1"]
    assert [row["obligation_id"] for row in universal] == [
        "OBJECT-1.1-canonical-representation-and-address"
    ]
    assert all(row["applicability"]["mode"] == "NECESSARY" for row in universal)
    assert all(row["applicability"]["mode"] == "CONDITIONAL"
               for row in runtime_variants)
    assert all("retained runtime-domain instance" in
               row["applicability"]["condition"].lower()
               for row in runtime_variants)
    assert all(row["applicability"]["mode"] == "CONDITIONAL"
               for row in executions + retained_added)
    assert all("exact owned" in row["applicability"]["condition"].lower()
               for row in executions)


@pytest.mark.parametrize("change", [
    {"reason": " "},
    {"condition": ""},
    {"unknown_condition": "EXEMPT"},
    {"when_condition_met": "CONDITION_NOT_MET"},
    {"mode": "CONDITION_NOT_MET"},
])
def test_declaration_contract_refuses_blank_or_exempting_variants(change: dict[str, str]) -> None:
    value = applicability_declaration(
        mode="CONDITIONAL",
        condition="The exact installed implementation is owned by this object.",
        reason="The implementation-specific proposition needs fresh execution.",
    )
    with pytest.raises(ValueError, match="APPLICABILITY_DECLARATION"):
        validate_applicability_declaration({**value, **change})


def test_declaration_contract_refuses_outcome_or_evidence_fields() -> None:
    value = applicability_declaration(
        mode="NECESSARY",
        condition="Repository admission is requested.",
        reason="Admission cannot omit its canonical manifest check.",
    )
    with pytest.raises(ValueError, match="APPLICABILITY_DECLARATION_FIELDS"):
        validate_applicability_declaration({**value, "status": "PASS"})


def test_instance_route_binding_refuses_declaration_digest_contradiction() -> None:
    route = next(row for row in manifest_gate.obligation_catalog()
                 if row["coordinate"] == "TRANSACTION-1.3")
    with pytest.raises(ValueError, match="APPLICABILITY_BINDING_DIGEST"):
        validate_applicability_binding({**route, "applicability_digest": "sha256:" + "0" * 64})

    changed = dict(route["applicability"])
    changed["reason"] += " substituted"
    with pytest.raises(ValueError, match="APPLICABILITY_BINDING_DIGEST"):
        validate_applicability_binding({**route, "applicability": changed})


def test_each_instance_catalog_boundary_rejects_a_tampered_binding(
        monkeypatch: pytest.MonkeyPatch) -> None:
    execution = deepcopy(package_execution.catalog()[0])
    execution["applicability_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="PACKAGE_EXECUTION_ROUTE_BINDING_DIFFERS"):
        package_execution.route_mechanism(execution)

    source = deepcopy(package_source_contracts.catalog()[0])
    source["applicability_digest"] = "sha256:" + "0" * 64
    assert package_source_contracts.is_route(source) is False

    declarations = deepcopy(core_tier_progression.installed_core_route_declarations())
    declarations[next(iter(declarations))]["applicability_digest"] = (
        "sha256:" + "0" * 64
    )
    monkeypatch.setattr(core_tier_progression, "installed_core_route_declarations",
                        lambda: declarations)
    with pytest.raises(ValueError, match="APPLICABILITY_BINDING_DIGEST"):
        manifest_gate.obligation_catalog()
