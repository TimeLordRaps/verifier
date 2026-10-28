from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.runtime import core_obligation_union as binding
from verifier.runtime import manifest_gate
from verifier.runtime import package_execution
from verifier.runtime import package_manifest_refresh
from verifier.runtime import package_polish
from verifier.runtime import self_polish_tiers


DIGEST = "sha256:" + "a" * 64


def _route(tier: int) -> dict:
    coordinate = f"OBJECT-{tier}.1"
    return {
        "object_kind": "OBJECT",
        "tier": tier,
        "coordinate": coordinate,
        "obligation_id": f"{coordinate}-cumulative-gate-{tier}",
        "obligation_name": f"Cumulative gate {tier}",
        "semantic_version": "1.0.0",
        "proposition_digest": DIGEST,
        "checking_mechanism": "tests.synthetic.package_graph_gate",
        "scope": "selected package graph source",
        "reason": f"Package gate {tier} must pass for this exact object.",
    }


def _preflight_index(item: NamespaceObject, routes: list[dict]) -> list[dict]:
    rows = []
    for route in routes:
        identity = {
            "object_id": item.object_id,
            "object_digest": item.digest,
            "coordinate": route["coordinate"],
            "tier": route["tier"],
            "proposition_digest": route["proposition_digest"],
        }
        rows.append({
            "object_id": item.object_id,
            "object_kind": route["object_kind"],
            "coordinate": route["coordinate"],
            "tier": route["tier"],
            "instance_digest": binding.value_digest(identity),
        })
    return rows


class _Evidence:
    def __init__(self, calls: list[str], fail_at: int | None) -> None:
        self.calls = calls
        self.fail_at = fail_at

    def evaluate(self, _item, route):
        self.calls.append(route["coordinate"])
        status = "FAIL" if route["tier"] == self.fail_at else "PASS"
        return {
            "status": status,
            "reason": (
                "The exact Tier-1 package object contradicts its selected check."
                if status == "FAIL"
                else "The selected package object passed."
            ),
            "applicability_established": True,
            "applicability_reason": "This exact package object requires the route.",
            "evidence_origin": "PACKAGE_GRAPH_BOUND_FRESH_REPLAY",
        }


def _run_synthetic_instance_prefix(
    monkeypatch, requested_tier: int, *, fail_at: int | None = 1
):
    item = NamespaceObject.create("package-object", "OBJECT", {})
    verifier = NamespaceObject.create("package-verifier", "VERIFIER", {})
    routes = [_route(tier) for tier in range(1, requested_tier + 1)]
    cells = [
        {
            "object_kind": "OBJECT",
            "tier": route["tier"],
            "registered_route_memberships": [route],
        }
        for route in routes
    ]

    def preflight(tier, _objects, _kinds, coordinates):
        selected_routes = [
            route
            for route in routes
            if route["tier"] <= tier
            and (coordinates is None or route["coordinate"] in coordinates)
        ]
        selected_cells = [
            cell
            for cell in cells
            if cell["registered_route_memberships"][0] in selected_routes
        ]
        return selected_cells, _preflight_index(item, selected_routes)

    monkeypatch.setattr(
        package_polish, "_obligation_selection_preflight", preflight
    )
    monkeypatch.setattr(
        package_polish.tier_zero_reasons,
        "installed_reason_ledger",
        lambda _root: {"objectives": {}},
    )
    monkeypatch.setattr(
        package_polish, "_route_applies_to_record", lambda *_args: True
    )
    mechanism = SimpleNamespace(BOUNDARY="Synthetic package-graph route.")
    monkeypatch.setattr(
        package_execution, "route_mechanism", lambda _route: mechanism
    )
    monkeypatch.setattr(
        package_execution,
        "evaluate",
        lambda evidence, selected, route: evidence.evaluate(selected, route),
    )

    calls: list[str] = []
    commitment: dict = {}
    rows = package_polish._instance_obligations(
        requested_tier,
        (item,),
        Path("."),
        verifier,
        {"results": []},
        evidence=_Evidence(calls, fail_at),
        selection_commitment=commitment,
    )
    return rows, calls, commitment, routes


def test_package_graph_gate_prefix_is_literal_and_cumulative() -> None:
    assert package_polish._cumulative_gate_depths(1) == (0, 1)
    assert package_polish._cumulative_gate_depths(2) == (0, 1, 2)
    assert package_polish._cumulative_gate_depths(3) == (0, 1, 2, 3)
    with pytest.raises(ValueError, match="PACKAGE_TIER_UNSUPPORTED"):
        package_polish._cumulative_gate_depths(0)


@pytest.mark.parametrize(
    ("requested_tier", "expected_calls"),
    [
        (1, ["OBJECT-1.1"]),
        (2, ["OBJECT-1.1", "OBJECT-2.1"]),
        (3, ["OBJECT-1.1", "OBJECT-2.1", "OBJECT-3.1"]),
    ],
)
def test_package_instance_prefix_executes_each_selected_gate_in_order(
    monkeypatch, requested_tier, expected_calls
) -> None:
    rows, calls, commitment, _routes = _run_synthetic_instance_prefix(
        monkeypatch, requested_tier, fail_at=None
    )

    assert calls == expected_calls
    assert [row["tier"] for row in rows] == list(
        range(1, requested_tier + 1)
    )
    assert all(row["status"] == "PASS" for row in rows)
    assert commitment["status"] == "COMMITTED"


def test_lower_package_gate_failure_stops_higher_graph_execution(
    monkeypatch,
) -> None:
    rows, calls, commitment, _routes = _run_synthetic_instance_prefix(
        monkeypatch, 3
    )

    assert calls == ["OBJECT-1.1"]
    assert [row["tier"] for row in rows] == [1, 2, 3]
    assert rows[0]["status"] == "FAIL"
    for row in rows[1:]:
        assert row["checker_status"] == "NOT_RUN"
        assert row["status"] == "UNKNOWN"
        assert "PACKAGE_INSTANCE_SELECTION_UNAVAILABLE" in row["blockers"]
        assert "required package gate 1 status was FAIL" in (
            row["selected_package_check"]["reason"]
        )
    assert commitment["status"] == "COMMITTED"
    assert commitment["selected_instance_count"] == 3


def _original_kind_tier_zero_report(status: str) -> dict:
    """One sealed Tier-0 prerequisite with an exact catalog closure locus."""

    object_id = "vstd-simulation"
    classification_kind = "MODEL"
    obligation_id = "VSTD-T0.2-object-denominator-closure"
    code = (
        "PACKAGE_ORIGINAL_KIND_CATALOG_CONTRADICTION:"
        if status == "FAIL"
        else "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
    ) + object_id + ":" + classification_kind
    reason = (
        "The original-kind applicability cell for object vstd-simulation and "
        "kind MODEL is not source-closed."
    )
    next_action = (
        "Audit this exact object/kind against its owned current source, then "
        "bind the source-audited decision."
    )
    finding = {
        "scope": "object",
        "object_id": object_id,
        "object_kind": "SIM",
        "classification_kind": classification_kind,
        "coordinate": "VSTD-T0.2",
        "obligation_id": obligation_id,
        "gate_id": "object-inventory",
        "status": status,
        "code": code,
        "reason": reason,
        "explanation": reason,
        "next_action": next_action,
        "rerun_argv": [
            "vstd", "gate", "--object", object_id,
            "--obligation", obligation_id,
        ],
    }
    obligations = []
    for index in range(1, 10):
        selected_status = status if index == 2 else "PASS"
        obligations.append({
            "coordinate": f"VSTD-T0.{index}",
            "status": selected_status,
            "assessment_reason": (
                reason if index == 2 else "Synthetic prerequisite passed."
            ),
        })
    counts = {
        selected: sum(row["status"] == selected for row in obligations)
        for selected in ("PASS", "FAIL", "UNKNOWN")
    }
    body = {
        "status": status,
        "manifest_digest": DIGEST,
        "obligation_count": 9,
        "obligation_status_counts": counts,
        "obligations": obligations,
        "blockers": [code],
        "findings": [finding],
    }
    return {**body, "report_digest": binding.value_digest(body)}


@pytest.mark.parametrize("status", ["UNKNOWN", "FAIL"])
@pytest.mark.parametrize("requested_tier", [1, 2, 3])
def test_original_kind_tier_zero_nonpass_stops_exact_cumulative_prefix(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    requested_tier: int,
) -> None:
    """No numeric polish may execute above a non-PASS admission closure."""

    zero = _original_kind_tier_zero_report(status)
    monkeypatch.setattr(
        package_polish.tier_zero, "assess_tier_zero", lambda _root: zero,
    )
    monkeypatch.setattr(
        package_polish.self_polish_tiers,
        "assess_self_polish_tier",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("a higher native tier ran after Tier-0 non-PASS")
        ),
    )

    if requested_tier < 3:
        diagnostics = package_polish._run_native_diagnostics(
            requested_tier, Path("."),
        )
    else:
        blocking = {
            "tier": 0,
            "tier_name": "ADMISSION",
            "required_status": "PASS",
            "observed_status": status,
            "report_digest": zero["report_digest"],
            "blockers": zero["blockers"],
        }
        execution = {
            "0": package_polish._native_execution_record(
                0,
                execution_status="EXECUTED",
                status=status,
                reason="Fresh Tier 0 admission was executed.",
                evidence_digest=zero["report_digest"],
            ),
            **{
                str(depth): package_polish._native_execution_record(
                    depth,
                    execution_status="NOT_RUN",
                    status="UNKNOWN",
                    reason="Tier 0 did not pass.",
                    blocking_prerequisite=blocking,
                )
                for depth in range(1, 4)
            },
        }
        body = {
            "status": status,
            "prerequisites": {"0": zero},
            "tier_execution": execution,
            "complete_tier_evidence_replay": None,
            "post_replay_full_source_recapture": "UNKNOWN",
            "claim_scope": "SOURCE_NATIVE_DIAGNOSTICS_NOT_PACKAGE_INSTANCES",
        }
        diagnostics = {**body, "report_digest": binding.value_digest(body)}

    assert diagnostics["status"] == status
    assert set(diagnostics["prerequisites"]) == {"0"}
    assert diagnostics["tier_execution"]["0"]["execution_status"] == "EXECUTED"
    for depth in range(1, requested_tier + 1):
        skipped = diagnostics["tier_execution"][str(depth)]
        assert skipped["execution_status"] == "NOT_RUN"
        assert skipped["status"] == "UNKNOWN"
        assert skipped["blocking_prerequisite"]["tier"] == 0
        assert skipped["blocking_prerequisite"]["observed_status"] == status

    reference = package_polish._native_diagnostic_reference(diagnostics)
    records = reference["prerequisites"]["0"]["nonpass_records"]
    selected = next(
        row for row in records
        if row.get("path") == "$.prerequisites.0.findings[0]"
    )
    source = zero["findings"][0]
    for field in (
        "gate_id", "object_id", "object_kind", "classification_kind",
        "obligation_id", "reason", "next_action", "rerun_argv",
    ):
        assert selected[field] == source[field]

    findings = package_polish._package_findings_with_exact_native_focus({
        "status": status,
        "obligation_instances": [],
        "kind_requirements": {},
        "blockers": ["PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS"],
        "native_diagnostics": reference,
    })
    promoted = next(
        row for row in findings
        if row.get("diagnostic_path")
        == "$.prerequisites.0.findings[0]"
    )
    for field in (
        "gate_id", "object_id", "object_kind", "classification_kind",
        "obligation_id", "reason", "next_action", "rerun_argv",
    ):
        assert promoted[field] == source[field]

    assert package_polish._native_execution_prefix_complete(
        diagnostics,
        requested_tier=requested_tier,
        source_coordinate_digest=DIGEST,
        manifest_digest=DIGEST,
    )


def test_lower_gate_finding_retains_exact_focus_and_action(monkeypatch) -> None:
    rows, _calls, _commitment, routes = _run_synthetic_instance_prefix(
        monkeypatch, 3
    )
    finding = manifest_gate.instance_findings(rows[0], routes[0])[0]

    assert finding["gate_id"] == "instance-evidence"
    assert finding["object_id"] == "package-object"
    assert finding["obligation_id"] == "OBJECT-1.1-cumulative-gate-1"
    assert (
        "The exact Tier-1 package object contradicts its selected check."
        in finding["reason"]
    )
    assert finding["next_action"]
    assert finding["rerun_argv"] == [
        "vstd",
        "gate",
        "--object",
        "package-object",
        "--obligation",
        "OBJECT-1.1-cumulative-gate-1",
    ]


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_default_numeric_dispatch_selects_root_package_graph_not_native(
    monkeypatch, tmp_path, tier
) -> None:
    refresh_digest = "sha256:" + "b" * 64
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda source_root, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "CURRENT",
            "before_digest": refresh_digest,
            "after_digest": refresh_digest,
            "backup_digest": None,
            "source_census_digest": DIGEST,
            "migration_mechanism_digest": DIGEST,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )

    class DispatchObserved(Exception):
        pass

    def selected(requested_tier, source_root, *, cancelled):
        assert requested_tier == tier
        assert Path(source_root) == tmp_path
        assert cancelled is False
        raise DispatchObserved

    monkeypatch.setattr(package_polish, "assess_package_polish", selected)
    monkeypatch.setattr(
        self_polish_tiers,
        "assess_self_polish_tier",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("default numeric Polish selected native specimens")
        ),
    )

    with pytest.raises(DispatchObserved):
        self_polish_tiers.handle_self_polish_tier_argv([
            str(tier),
            "--source-root",
            str(tmp_path),
            "--manifest-refresh",
            "check",
        ])



def _blocking_rows(failures: int, unknowns: int) -> list[dict]:
    rows = [
        {"object_id": f"fixture-object-with-a-long-identifier-{index:05d}",
         "coordinate": f"OBJECT-2.{index % 7}", "status": status}
        for index, status in enumerate(
            ["FAIL"] * failures + ["UNKNOWN"] * unknowns)
    ]
    rows.append({"object_id": "passing-object", "coordinate": "OBJECT-2.1",
                 "status": "PASS"})
    return rows


def test_blocked_gate_reason_names_a_small_blocking_set_in_full() -> None:
    reason = package_polish._blocked_gate_reason(
        2, "FAIL", _blocking_rows(2, 1), 3)

    assert "Package gate 3 was not executed because required package gate 2 " \
        "status was FAIL." in reason
    for index in range(3):
        assert f"fixture-object-with-a-long-identifier-{index:05d}" in reason
    assert "passing-object" not in reason
    assert "more" not in reason


def test_blocked_gate_reason_stays_bounded_for_a_large_blocking_set() -> None:
    """Thousands of skipped rows copy this text twice, so its size is a wire cost."""
    rows = _blocking_rows(87, 1500)

    reason = package_polish._blocked_gate_reason(2, "FAIL", rows, 3)

    assert len(reason.encode("utf-8")) <= 2048
    assert "required package gate 2 status was FAIL" in reason
    # Refuting instances come first; the rest are counted and digest-bound, and
    # each one remains a full row at the blocking tier in the same report.
    assert "fixture-object-with-a-long-identifier-00000" in reason
    assert "87 FAIL" in reason and "1500 UNKNOWN" in reason
    expected = binding.value_digest([
        f"{row['object_id']}:{row['coordinate']}={row['status']}"
        for row in rows if row["status"] != "PASS"
    ])
    assert expected in reason


def test_blocked_gate_reason_is_deterministic_for_the_same_blocking_set() -> None:
    rows = _blocking_rows(30, 30)

    assert package_polish._blocked_gate_reason(1, "FAIL", rows, 2) == \
        package_polish._blocked_gate_reason(1, "FAIL", list(rows), 2)


class _CountingPath(str):
    """A diagnostic path that counts how often a lookup compares it."""

    comparisons = 0

    def __eq__(self, other):
        type(self).comparisons += 1
        return str.__eq__(self, other)

    __hash__ = str.__hash__


def _native_focus_fixture(count: int):
    findings, records = [], []
    for index in range(count):
        object_id = f"object-{index:05d}"
        path = f"$.prerequisites.0.obligations[{index}]"
        findings.append({
            "scope": "object", "diagnostic_path": path, "object_id": object_id,
            "obligation_id": "VSTD-T0.2-namespace-admission", "gate_id": "namespace-admission",
            "status": "UNKNOWN", "code": "PACKAGE_NATIVE_DIAGNOSTIC_NONPASS",
            "reason": "generic", "explanation": "generic", "next_action": "generic",
            "rerun_argv": None,
        })
        records.append({
            "path": _CountingPath(path), "object_id": object_id,
            "obligation_id": "VSTD-T0.2-namespace-admission",
            "gate_id": "namespace-admission", "coordinate": "VSTD-T0.2",
            "reason": f"exact reason {index}", "next_action": f"exact action {index}",
            "rerun_argv": ["vstd", "gate", "--object", object_id,
                           "--obligation", "VSTD-T0.2-namespace-admission"],
        })
    return findings, records


def _focused(monkeypatch, findings, records):
    monkeypatch.setattr(manifest_gate, "package_findings", lambda _report: findings)
    return package_polish._package_findings_with_exact_native_focus({
        "blockers": [], "requested_tier": 3,
        "native_diagnostics": {"prerequisites": {"0": {"nonpass_records": records}}},
    })


def test_native_focus_restores_each_findings_exact_record(monkeypatch) -> None:
    findings, records = _native_focus_fixture(40)
    focused = _focused(monkeypatch, findings, records)
    assert [row["reason"] for row in focused] == [f"exact reason {i}" for i in range(40)]
    assert [row["next_action"] for row in focused] == [f"exact action {i}" for i in range(40)]
    assert all(row["coordinate"] == "VSTD-T0.2" for row in focused)


def test_native_focus_takes_the_first_record_that_matches_every_condition(monkeypatch) -> None:
    findings, records = _native_focus_fixture(3)
    wrong_argv = {**records[1], "reason": "wrong argv", "rerun_argv": ["x"]}
    later = {**records[1], "reason": "later duplicate"}
    focused = _focused(monkeypatch, findings, [records[0], wrong_argv, records[1], later, records[2]])
    assert focused[1]["reason"] == "exact reason 1"


def test_native_focus_cost_is_linear_in_findings_and_records(monkeypatch) -> None:
    """A repository-scale report holds ~30k findings and ~16k records."""
    findings, records = _native_focus_fixture(1500)
    _CountingPath.comparisons = 0
    _focused(monkeypatch, findings, records)
    # A scan per finding compares ~n/2 record paths each: over a million comparisons.
    assert _CountingPath.comparisons < 20 * len(records)
