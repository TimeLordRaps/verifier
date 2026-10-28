"""Verifier Standard (VSTD) manifest-object gate selection regressions."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from verifier.runtime import package_manifest_refresh
from verifier.runtime import package_polish as package
from verifier.runtime import core_obligation_union as binding
from verifier.runtime.public_cli import main


ROOT = Path(__file__).resolve().parents[1]


def test_targeted_gate_missing_manifest_is_structured_unknown(tmp_path, capsys) -> None:
    assert main(["gate", "--object", "vstd-simulation", "--obligation",
                 "SIM-2.4-signed-transition-resource-records", "--source-root",
                 str(tmp_path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "UNKNOWN"
    assert result["findings"][0]["gate_id"] == "manifest-admission"
    assert result["findings"][0]["object_id"] == "vstd-simulation"
    assert result["findings"][0]["code"] == "PACKAGE_MANIFEST_MISSING"
    assert result["findings"][0]["reason"] == result["findings"][0]["explanation"]


def test_package_missing_manifest_names_the_blocking_gate(tmp_path) -> None:
    result = package.assess_package_polish(1, tmp_path)
    finding = result["findings"][0]
    assert finding["scope"] == "repository"
    assert finding["object_id"] is None  # No invented manifest object.
    assert finding["obligation_id"] == "VSTD-T0.1-canonical-manifest-admission"
    assert finding["gate_id"] == "manifest-admission"
    assert finding["status"] == "UNKNOWN"
    assert finding["reason"] == finding["explanation"]


@pytest.fixture
def selected_root(tmp_path, monkeypatch):
    manifest = package.package_manifest.retained_contract(json.loads((ROOT / "objects.vstd").read_bytes()))
    (tmp_path / "objects.vstd").write_bytes(binding.canonical_bytes(manifest) + b"\n")
    (tmp_path / "reasons.vstd").write_bytes((ROOT / "reasons.vstd").read_bytes())
    provider = tmp_path / "src/verifier/runtime/tier_zero_reasons.py"
    provider.parent.mkdir(parents=True)
    provider.write_bytes((ROOT / "src/verifier/runtime/tier_zero_reasons.py").read_bytes())
    reasons = package.tier_zero_reasons.installed_reason_ledger(ROOT)
    coordinate = {"source_head": manifest["repository"]["revision"],
                  "source_tree": "2" * 40, "source_manifest_digest": "sha256:" + "a" * 64,
                  "source_worktree_status_digest": "sha256:" + "b" * 64}
    monkeypatch.setattr(package.self_polish_estate, "_git_coordinate", lambda root: {
        "repository": manifest["repository"]["remote"], "revision": manifest["repository"]["revision"]})
    monkeypatch.setattr(package.self_polish_statics, "_capture_coordinate", lambda root: coordinate)
    monkeypatch.setattr(package.self_polish_statics, "_package_source_binding", lambda root: {"status": "PASS"})
    monkeypatch.setattr(package.self_polish_tiers, "_post_replay_source_recapture", lambda *args: {"status": "PASS"})
    monkeypatch.setattr(package.tier_zero_reasons, "installed_reason_ledger", lambda root: deepcopy(reasons))
    monkeypatch.setattr(package, "_run_native_diagnostics", lambda *args: pytest.fail("target gate must not run unrelated specimen suites"))
    return tmp_path


def test_exact_target_replays_manifest_structure_without_other_objects(selected_root, capsys) -> None:
    assert main(["gate", "--object", "vstd-simulation", "--obligation",
                 "SIM-1.1-declared-operand-facets", "--source-root", str(selected_root), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["object_id"] == "vstd-simulation"
    assert result["obligation_id"] == "SIM-1.1-declared-operand-facets"
    assert result["instance"]["checker_status"] == "PASS"
    assert result["status"] == "UNKNOWN"  # Applicability is not established by structure.
    assert result["facet_replay"]["object_count"] == 1
    assert result["facet_replay"]["results"][0]["object_id"] == "vstd-simulation"
    assert {f["gate_id"] for f in result["findings"]} == {"applicability", "semantic-fulfillment"}
    assert all(f["object_id"] == "vstd-simulation" for f in result["findings"])
    assert all(f["reason"] == f["explanation"] for f in result["findings"])
    assert result["polished"] is False


def test_missing_instance_evidence_is_not_replaced_by_native_specimens(selected_root, capsys) -> None:
    assert main(["gate", "--object", "vstd-simulation", "--obligation",
                 "SIM-2.4-signed-transition-resource-records", "--source-root", str(selected_root), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["instance"]["checker_status"] == "NOT_RUN"
    assert result["facet_replay"] is None
    assert "signed" in result["obligation_name"].lower()
    assert {f["gate_id"] for f in result["findings"]} == {"applicability", "instance-evidence"}
    assert result["rerun_argv"][:3] == ["vstd", "gate", "--object"]


@pytest.mark.parametrize("object_id,obligation,code", [
    ("not-declared", "SIM-1.1-declared-operand-facets", "PACKAGE_GATE_OBJECT_NOT_DECLARED"),
    ("vstd-data", "SIM-1.1-declared-operand-facets", "PACKAGE_GATE_OBJECT_KIND_DIFFERS"),
    ("vstd-simulation", "SIM-2.4-invented", "PACKAGE_GATE_OBLIGATION_NOT_REGISTERED"),
])
def test_gate_selection_cannot_substitute_object_or_obligation(selected_root, capsys, object_id, obligation, code) -> None:
    assert main(["gate", "--object", object_id, "--obligation", obligation,
                 "--source-root", str(selected_root), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "FAIL"
    assert result["findings"][0]["code"] == code


def test_catalog_has_readable_unique_version_bound_names() -> None:
    from collections import Counter

    from verifier.runtime.manifest_gate import obligation_catalog
    from verifier.runtime import (
        added_kind_behavioral_routes,
        core_tier_progression,
        package_execution,
        package_source_contracts,
    )
    rows = obligation_catalog()
    # Bind the readable gate denominator to its four registered producers.  A
    # literal total alone would miss a route moving between or vanishing from
    # one producer while another producer happened to replace the same count.
    producer_routes = {
        "core": [
            route
            for cell in core_tier_progression.installed_core_route_inventory()["family_cells"]
            for route in cell["registered_route_memberships"]
        ],
        "package_execution": package_execution.catalog(),
        "added_kind_behavioral": added_kind_behavioral_routes.catalog(),
        "source": package_source_contracts.catalog(),
    }
    producer_counts = {name: len(routes) for name, routes in producer_routes.items()}
    # The added-kind producer is 9 MARKET/ROBOT/FINBOT kind routes, 9 agency-surface
    # routes, and 3 POLICY routes; no coordinate may belong to two producers.
    assert producer_counts == {
        "core": 408,
        "package_execution": 45,
        "added_kind_behavioral": 21,
        "source": 114,
    }
    producer_coordinates = [
        route["coordinate"]
        for routes in producer_routes.values()
        for route in routes
    ]
    assert len(producer_coordinates) == len(set(producer_coordinates)) == 588
    assert Counter(row["semantic_version"] for row in rows) == Counter(
        route["semantic_version"]
        for routes in producer_routes.values()
        for route in routes
    )
    assert len(rows) == len({r["obligation_id"] for r in rows}) == sum(producer_counts.values()) == 588
    assert all(r["obligation_id"].startswith(r["coordinate"] + "-")
               and r["obligation_name"] and r["exact_claim"] and r["semantic_version"] for r in rows)


def test_targeted_admission_pass_is_only_the_selected_obligation(selected_root, monkeypatch, capsys) -> None:
    from verifier.runtime.manifest_gate import _admission_catalog
    name = _admission_catalog()[0]
    monkeypatch.setattr(package.tier_zero, "assess_tier_zero", lambda root: {
        "status": "UNKNOWN", "report_digest": "sha256:" + "c" * 64,
        "manifest_digest": binding.bytes_digest((root / "objects.vstd").read_bytes()),
        "obligations": [{"coordinate": name["coordinate"], "status": "PASS", "blockers": [],
                         "assessment_reason": "Exact canonical declaration admitted."}],
    })
    assert main(["gate", "--object", "vstd-package-graph", "--obligation", name["obligation_id"],
                 "--source-root", str(selected_root), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "PASS" and not report["polished"]
    assert report["admission_context"]["status"] == "UNKNOWN"
    assert report["findings"] == []


def test_native_refutation_keeps_its_exact_object_obligation_and_gate(selected_root, monkeypatch) -> None:
    from verifier.runtime.manifest_gate import assess_object_gate
    original = package.package_self_polish._native_facets_replay

    def failed(*args, **kwargs):
        result = original(*args, **kwargs)
        result["results"][0]["typed_facets"]["status"] = "FAIL"
        return result

    monkeypatch.setattr(package.package_self_polish, "_native_facets_replay", failed)
    report = assess_object_gate("vstd-simulation", "SIM-1.1-declared-operand-facets", selected_root)
    assert report["status"] == "FAIL"
    finding = next(f for f in report["findings"] if f["status"] == "FAIL")
    assert finding["gate_id"] == "native-check"
    assert finding["object_id"] == "vstd-simulation"
    assert finding["obligation_id"] == "SIM-1.1-declared-operand-facets"
    assert finding["code"] == "PACKAGE_INSTANCE_CHECK_REFUTED"


def test_target_source_drift_cannot_leave_a_passing_result(selected_root, monkeypatch) -> None:
    from verifier.runtime.manifest_gate import assess_object_gate
    monkeypatch.setattr(package.self_polish_tiers, "_post_replay_source_recapture", lambda *args: {"status": "FAIL"})
    report = assess_object_gate("vstd-simulation", "SIM-1.1-declared-operand-facets", selected_root)
    assert report["status"] == "FAIL"
    assert any(f["code"] == "PACKAGE_GATE_SOURCE_CHANGED" for f in report["findings"])


def test_focused_source_route_reuses_the_full_package_snapshot(monkeypatch) -> None:
    from verifier.runtime.manifest_gate import assess_object_gate

    created = {}
    constructor = package.package_source_contracts.SourceContractAssessment
    obligations = package._instance_obligations

    def construct(root, objects, kinds):
        assessment = constructor(root, objects, kinds)
        created.update(assessment=assessment, object_count=len(objects), kinds=kinds)
        return assessment

    def inspect(*args, **kwargs):
        assert kwargs["source_contracts"] is created["assessment"]
        assert kwargs["kinds"] is created["kinds"]
        return obligations(*args, **kwargs)

    monkeypatch.setattr(
        package.package_source_contracts, "SourceContractAssessment", construct
    )
    monkeypatch.setattr(package, "_instance_obligations", inspect)
    report = assess_object_gate(
        "vstd-harness", "TRANSACTION-1.90-source-representation-facets", ROOT
    )

    assert created["object_count"] > 1
    assert report["status"] == "PASS"
    assert report["instance"]["checker_status"] == "PASS"
    assert report["instance"]["selected_package_check"]["evidence_origin"] == (
        "INSTALLED_SOURCE_REVIEW_AND_FRESH_DISCOVERY"
    )


def test_focused_native_route_preserves_explicit_condition_not_met() -> None:
    from verifier.runtime.manifest_gate import assess_object_gate
    from verifier.runtime import package_execution

    report = assess_object_gate(
        "vstd-harness", "TRANSACTION-1.1-local-input-preconditions", ROOT
    )

    assert report["status"] == "PASS"
    assert report["instance"]["checker_status"] == "NOT_REQUIRED"
    assert report["instance"]["applicability"]["classification"] == (
        "CONDITION_NOT_MET"
    )
    selected = report["instance"]["selected_package_check"]
    route = next(
        row
        for row in package_execution.catalog()
        if row["object_kind"] == "TRANSACTION"
        and row["coordinate"] == "TRANSACTION-1.1"
    )
    assert selected["condition"] == route["applicability"]["condition"]
    assert selected["applicability_digest"] == route["applicability_digest"]
    assert selected["fulfillment_required"] is False
    assert selected["adaptation_obligation_id"] == (
        "TRANSACTION-1.90-source-representation-facets"
    )


def test_focused_execution_owner_is_not_refuted_as_a_source_variant() -> None:
    from verifier.runtime.manifest_gate import assess_object_gate

    report = assess_object_gate(
        "vstd-simulation", "MEASUREMENT-1.1-transition-resource-meaning", ROOT
    )

    assert report["status"] == "PASS"
    assert report["instance"]["checker_status"] == "PASS"
    assert report["instance"]["selected_package_check"]["status"] == "PASS"
    assert report["instance"]["applicability"]["classification"] == "NECESSARY"


def test_runtime_substitution_is_not_source_bound_evidence(selected_root, monkeypatch) -> None:
    from verifier.runtime.manifest_gate import assess_object_gate

    def substituted(root):
        raise ValueError("STATICS_INSTALLED_SOURCE_DIFFERS")

    monkeypatch.setattr(package.self_polish_statics, "_package_source_binding", substituted)
    report = assess_object_gate("vstd-simulation", "SIM-1.1-declared-operand-facets", selected_root)
    assert report["status"] == "FAIL"
    assert report["findings"][0]["gate_id"] == "source-binding"
    assert report["instance"] is None


def test_package_diagnostic_allocation_failure_preserves_refutation(monkeypatch) -> None:
    from verifier.runtime import manifest_gate

    def unavailable(report):
        raise MemoryError("private diagnostic data")

    monkeypatch.setattr(manifest_gate, "package_findings", unavailable)
    result = package.assess_package_polish(1, cancelled=True)
    result.pop("report_digest")
    result["status"] = "FAIL"
    result = package._seal(result)
    assert result["status"] == "FAIL"
    assert "PACKAGE_FINDINGS_UNAVAILABLE" in result["blockers"]
    assert "private diagnostic data" not in json.dumps(result)


def test_targeted_selectors_cannot_be_ignored_by_legacy_gate(tmp_path, capsys) -> None:
    assert main(["gate", "--object", "vstd-simulation", "--obligation", "SIM-1.1-declared-operand-facets",
                 "paths", str(tmp_path), "--json"]) == 1


def test_gate_report_schema(selected_root) -> None:
    import jsonschema
    from verifier.runtime.manifest_gate import assess_object_gate
    schema = json.loads((ROOT / "src/verifier/schemas/verifier-manifest-object-gate-1.schema.json").read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    result = assess_object_gate("vstd-simulation", "SIM-1.1-declared-operand-facets", selected_root)
    validator.validate(result)
    validator.validate(assess_object_gate("vstd-simulation", "SIM-1.1-declared-operand-facets", selected_root / "absent"))
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**result, "polished": True})
    missing_reason = deepcopy(result)
    missing_reason["findings"][0].pop("reason")
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(missing_reason)


def test_missing_selector_json_is_an_invocation_error(capsys) -> None:
    assert main(["gate", "--object", "vstd-simulation", "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "PACKAGE_GATE_SELECTORS_REQUIRED"
    assert result["status"] == "UNKNOWN"
    assert result["gate_id"] == "target-selection"
    assert result["reason"] == result["explanation"]
    assert result["next_action"].strip()
    assert result["rerun_argv"] == ["vstd", "gate", "--help"]
    assert result["findings"] == [{**result["findings"][0],
        "scope": "object",
        "object_id": "vstd-simulation",
        "obligation_id": "CLI-PREREQUISITE-complete-gate-selectors",
        "gate_id": "target-selection",
        "status": "UNKNOWN",
        "code": "PACKAGE_GATE_SELECTORS_REQUIRED",
        "reason": result["explanation"],
        "explanation": result["explanation"],
        "next_action": result["next_action"],
        "rerun_argv": ["vstd", "gate", "--help"],
    }]


@pytest.mark.parametrize(
    ("object_id", "obligation_id"),
    (
        ("x" * 257, "VSTD-T0.7-source-and-mechanism-freshness"),
        ("vstd-amd-live-sensor", "x" * 513),
        ("invalid object", "VSTD-T0.7-source-and-mechanism-freshness"),
        ("vstd-amd-live-sensor", "invalid obligation"),
    ),
)
def test_malformed_selector_is_rejected_before_tier_zero_routing(
        object_id, obligation_id, tmp_path, monkeypatch) -> None:
    from verifier.runtime import namespace_manifest
    from verifier.runtime.manifest_gate import assess_object_gate

    monkeypatch.setattr(
        namespace_manifest,
        "read_manifest",
        lambda _path: pytest.fail("malformed selectors must fail before manifest routing"),
    )

    result = assess_object_gate(object_id, obligation_id, tmp_path)

    assert result["status"] == "FAIL"
    assert result["error"] == "PACKAGE_GATE_SELECTION_INVALID"
    finding = result["findings"][0]
    assert finding["gate_id"] == "target-selection"
    assert finding["obligation_id"] == "CLI-PREREQUISITE-valid-gate-selectors"
    assert finding["reason"] == finding["explanation"]
    assert finding["next_action"].strip()
    assert finding["rerun_argv"] == ["vstd", "gate", "--help"]


def test_repository_finding_is_named_and_actionable_for_package_scope() -> None:
    from verifier.runtime.manifest_gate import repository_finding

    finding = repository_finding(
        "PACKAGE_REPORT_CAPACITY_EXHAUSTED", "UNKNOWN", tier=3,
    )

    assert finding["scope"] == "repository"
    assert finding["object_id"] is None
    assert finding["gate_id"] == "package-assessment"
    assert finding["obligation_id"] == (
        "PACKAGE-PREREQUISITE-package-report-capacity-exhausted"
    )
    assert finding["obligation_name"].strip()
    assert finding["reason"] == finding["explanation"]
    assert finding["next_action"].strip()
    assert finding["rerun_argv"] == ["vstd", "polish", "3", "--json"]


@pytest.mark.parametrize("finding", [
    {},
    {"reason": "", "explanation": "  ", "assessment_reason": None, "code": ""},
])
def test_reasoned_finding_never_emits_a_blank_fallback(finding) -> None:
    from verifier.runtime.manifest_gate import _reasoned_finding

    result = _reasoned_finding(finding)

    assert result["reason"] == "Unspecified verification failure."


@pytest.mark.parametrize(
    "status,code",
    [
        (
            "UNKNOWN",
            "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
            "vstd-simulation:MODEL",
        ),
        (
            "FAIL",
            "PACKAGE_ORIGINAL_KIND_CATALOG_CONTRADICTION:"
            "vstd-simulation:MODEL",
        ),
    ],
)
def test_original_kind_closure_finding_names_exact_focus_and_rerun(
    status, code
) -> None:
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    finding = original_kind_closure_finding(
        object_id="vstd-simulation",
        object_kind="SIM",
        classification_kind="MODEL",
        status=status,
        code=code,
    )

    assert finding["scope"] == "object"
    assert finding["object_id"] == "vstd-simulation"
    assert finding["object_kind"] == "SIM"
    assert finding["classification_kind"] == "MODEL"
    assert finding["coordinate"] == "VSTD-T0.2"
    assert finding["obligation_id"] == "VSTD-T0.2-object-denominator-closure"
    assert finding["gate_id"] == "object-inventory"
    assert finding["status"] == status
    assert finding["code"] == code
    assert "MODEL" in finding["reason"]
    assert "vstd-simulation" in finding["reason"]
    assert finding["next_action"].strip()
    assert finding["rerun_argv"] == [
        "vstd",
        "gate",
        "--object",
        "vstd-simulation",
        "--obligation",
        "VSTD-T0.2-object-denominator-closure",
    ]


_ORIGINAL_KIND_CODE = "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:vstd-simulation:MODEL"
_ORIGINAL_KIND_RERUN = [
    "vstd", "gate", "--object", "vstd-simulation",
    "--obligation", "VSTD-T0.2-object-denominator-closure",
]


@pytest.mark.parametrize("status", ["UNKNOWN", "FAIL"])
@pytest.mark.parametrize("binding_blocker,clause", [
    ("EVIDENCE_DIGEST_STALE", "differs from the current file bytes"),
    ("EVIDENCE_PATH_UNOWNED", "outside this object's current manifest-declared file surfaces"),
    ("EVIDENCE_DIGEST_MALFORMED", "not canonical sha256:<64 lowercase hex>"),
    ("SOURCE_INVENTORY_ABSENT", "no current source inventory"),
    ("EVIDENCE_PATH_NOT_IN_INVENTORY", "absent from the current source inventory"),
    ("EVIDENCE_MALFORMED", "not exactly {path, sha256}"),
    ("DECISION_UNRESOLVED", "no APPLIES or DOES_NOT_APPLY decision"),
])
def test_original_kind_binding_failure_names_its_cause_and_stays_unknown(
    status, binding_blocker, clause
) -> None:
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    finding = original_kind_closure_finding(
        object_id="vstd-simulation",
        object_kind="SIM",
        classification_kind="MODEL",
        status=status,
        code=_ORIGINAL_KIND_CODE,
        binding_blocker=binding_blocker,
    )

    assert finding["status"] == "UNKNOWN"
    assert clause in finding["reason"]
    assert "MODEL" in finding["reason"] and "vstd-simulation" in finding["reason"]
    assert finding["code"] == _ORIGINAL_KIND_CODE
    assert finding["gate_id"] == "object-inventory"
    assert finding["next_action"].strip()
    assert finding["rerun_argv"] == _ORIGINAL_KIND_RERUN


@pytest.mark.parametrize("code,clause", [
    ("PACKAGE_ORIGINAL_KIND_SOURCE_MUTATED",
     "changed between the opening and closing census"),
    ("PACKAGE_ORIGINAL_KIND_SOURCE_CLOSING_UNAVAILABLE",
     "closing source census was unavailable"),
    ("PACKAGE_ORIGINAL_KIND_SOURCE_INVENTORY_UNAVAILABLE:CANDIDATE_SOURCE_MUTATED",
     "refusal CANDIDATE_SOURCE_MUTATED"),
])
def test_source_snapshot_failure_is_unknown_even_when_reported_as_fail(code, clause) -> None:
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    finding = original_kind_closure_finding(
        object_id="vstd-simulation",
        object_kind="SIM",
        classification_kind="MODEL",
        status="FAIL",
        code=code,
    )

    assert finding["status"] == "UNKNOWN"
    assert finding["code"] == code
    assert clause in finding["reason"]
    assert finding["next_action"].strip()
    assert finding["rerun_argv"] == _ORIGINAL_KIND_RERUN


@pytest.mark.parametrize("binding_blocker", [None, "EVIDENCE_DIGEST_STALE", "SOURCE_INVENTORY_ABSENT"])
def test_catalog_contradiction_stays_fail_under_any_binding_failure(binding_blocker) -> None:
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    code = "PACKAGE_ORIGINAL_KIND_CATALOG_CONTRADICTION:vstd-simulation:MODEL"
    finding = original_kind_closure_finding(
        object_id="vstd-simulation",
        object_kind="SIM",
        classification_kind="MODEL",
        status="UNKNOWN",
        code=code,
        binding_blocker=binding_blocker,
    )

    assert finding["status"] == "FAIL"
    assert finding["code"] == code
    assert "contradicts" in finding["reason"]


def test_unknown_binding_blocker_is_refused_not_guessed() -> None:
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    with pytest.raises(ValueError, match="ORIGINAL_KIND_BINDING_BLOCKER_UNKNOWN"):
        original_kind_closure_finding(
            object_id="vstd-simulation",
            object_kind="SIM",
            classification_kind="MODEL",
            status="UNKNOWN",
            code=_ORIGINAL_KIND_CODE,
            binding_blocker="EVIDENCE_DIGEST_SOMEWHERE",
        )


_DENOMINATOR_CODES = (
    "DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE",
    "DOES_NOT_APPLY_EVIDENCE_PATH_DUPLICATED",
    "DOES_NOT_APPLY_OWNER_CLOSURE_UNKNOWN",
    "DOES_NOT_APPLY_SOURCE_DRIFT",
    "DOES_NOT_APPLY_EFFECT_BOUNDARY_UNCLOSED",
)


@pytest.mark.parametrize("denominator_blocker,clause", [
    ("DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE",
     "does not cite every file of the object's validated owned-file denominator"),
    ("DOES_NOT_APPLY_EVIDENCE_PATH_DUPLICATED",
     "cites an owned file more than once"),
    ("DOES_NOT_APPLY_OWNER_CLOSURE_UNKNOWN",
     "owned-file denominator or its source census is unavailable"),
    ("DOES_NOT_APPLY_SOURCE_DRIFT",
     "changed since their refutation was effect-audited"),
    ("DOES_NOT_APPLY_EFFECT_BOUNDARY_UNCLOSED",
     "unsupported language"),
])
def test_denominator_refusal_names_its_exact_cause_not_the_generic_decision_clause(
    denominator_blocker, clause
) -> None:
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    finding = original_kind_closure_finding(
        object_id="vstd-simulation",
        object_kind="SIM",
        classification_kind="MODEL",
        status="UNKNOWN",
        code=_ORIGINAL_KIND_CODE,
        denominator_blocker=denominator_blocker,
    )

    assert finding["status"] == "UNKNOWN"
    assert finding["code"] == _ORIGINAL_KIND_CODE
    assert clause in finding["reason"]
    assert "no APPLIES or DOES_NOT_APPLY decision" not in finding["reason"]
    assert finding["next_action"].strip()
    assert finding["rerun_argv"] == _ORIGINAL_KIND_RERUN


def test_gate_names_every_denominator_blocker_the_catalog_can_emit() -> None:
    from verifier.runtime import package_original_kind_catalog as catalog
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    assert set(catalog._DOES_NOT_APPLY_BLOCKER_ACTIONS) == set(_DENOMINATOR_CODES)
    for code, action in catalog._DOES_NOT_APPLY_BLOCKER_ACTIONS.items():
        finding = original_kind_closure_finding(
            object_id="vstd-simulation",
            object_kind="SIM",
            classification_kind="MODEL",
            status="UNKNOWN",
            code=_ORIGINAL_KIND_CODE,
            denominator_blocker=code,
        )
        assert finding["status"] == "UNKNOWN", code
        assert finding["next_action"] == action, code


def test_catalog_contradiction_stays_fail_under_denominator_blocker() -> None:
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    code = "PACKAGE_ORIGINAL_KIND_CATALOG_CONTRADICTION:vstd-simulation:MODEL"
    finding = original_kind_closure_finding(
        object_id="vstd-simulation",
        object_kind="SIM",
        classification_kind="MODEL",
        status="UNKNOWN",
        code=code,
        denominator_blocker="DOES_NOT_APPLY_SOURCE_DRIFT",
    )

    assert finding["status"] == "FAIL"
    assert "contradicts" in finding["reason"]


def test_unknown_denominator_blocker_is_refused_not_guessed() -> None:
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    with pytest.raises(ValueError, match="ORIGINAL_KIND_DENOMINATOR_BLOCKER_UNKNOWN"):
        original_kind_closure_finding(
            object_id="vstd-simulation",
            object_kind="SIM",
            classification_kind="MODEL",
            status="UNKNOWN",
            code=_ORIGINAL_KIND_CODE,
            denominator_blocker="DOES_NOT_APPLY_SOMETHING_ELSE",
        )


def test_gate_names_every_binding_blocker_the_catalog_can_emit() -> None:
    from verifier.runtime import package_original_kind_catalog as catalog
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    sha = "sha256:" + "a" * 64
    row = {"surfaces": ["file:src/a.py"]}
    cases = {
        "DECISION_UNRESOLVED": (
            {"status": "UNRESOLVED", "reason": "", "evidence": []}, {"src/a.py": sha}),
        "EVIDENCE_MALFORMED": (
            {"status": "APPLIES", "reason": "r", "evidence": [{"path": "src/a.py"}]},
            {"src/a.py": sha}),
        "EVIDENCE_DIGEST_MALFORMED": (
            {"status": "APPLIES", "reason": "r",
             "evidence": [{"path": "src/a.py", "sha256": "sha256:ABC"}]},
            {"src/a.py": sha}),
        "SOURCE_INVENTORY_ABSENT": (
            {"status": "APPLIES", "reason": "r",
             "evidence": [{"path": "src/a.py", "sha256": sha}]}, None),
        "EVIDENCE_PATH_UNOWNED": (
            {"status": "APPLIES", "reason": "r",
             "evidence": [{"path": "src/b.py", "sha256": sha}]},
            {"src/a.py": sha, "src/b.py": sha}),
        "EVIDENCE_PATH_NOT_IN_INVENTORY": (
            {"status": "APPLIES", "reason": "r",
             "evidence": [{"path": "src/a.py", "sha256": sha}]}, {}),
        "EVIDENCE_DIGEST_STALE": (
            {"status": "APPLIES", "reason": "r",
             "evidence": [{"path": "src/a.py", "sha256": sha}]},
            {"src/a.py": "sha256:" + "b" * 64}),
    }
    for expected, (decision, inventory) in cases.items():
        blocker = catalog._decision_binding_blocker(row, decision, inventory)
        assert blocker == expected
        finding = original_kind_closure_finding(
            object_id="vstd-simulation",
            object_kind="SIM",
            classification_kind="MODEL",
            status="UNKNOWN",
            code=_ORIGINAL_KIND_CODE,
            binding_blocker=blocker,
        )
        assert finding["status"] == "UNKNOWN", expected


def test_admission_json_names_its_gate_and_binds_findings(tmp_path, monkeypatch, capsys) -> None:
    manifest_digest = "sha256:" + "1" * 64
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "CURRENT",
            "before_digest": manifest_digest,
            "after_digest": manifest_digest,
            "backup_digest": None,
            "source_census_digest": "sha256:" + "2" * 64,
            "migration_mechanism_digest": "sha256:" + "3" * 64,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(package.tier_zero, "assess_tier_zero", lambda *args, **kwargs: {
        "status": "UNKNOWN", "obligations": [{"coordinate": "VSTD-T0.4", "status": "UNKNOWN",
            "blockers": ["TIER_ZERO_SURFACE_UNRESOLVED"], "assessment_reason": "Surface coverage is unresolved."}],
        "blockers": ["TIER_ZERO_SURFACE_UNRESOLVED"], "report_digest": "old",
    })
    assert main(["polish", "0", "--source-root", str(tmp_path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    finding = result["findings"][0]
    assert finding["gate_id"] == "exposed-surface-coverage"
    assert finding["coordinate"] == "VSTD-T0.4"
    assert finding["object_id"] is None
    digest = result.pop("report_digest")
    assert digest == binding.value_digest(result)


def test_aggregate_facets_failure_survives_instance_diagnostics(selected_root) -> None:
    from verifier.runtime.manifest_gate import assess_object_gate, package_findings
    target = assess_object_gate("vstd-simulation", "SIM-1.1-declared-operand-facets", selected_root)
    findings = package_findings({"status": "FAIL", "obligation_instances": [target["instance"]],
                                 "blockers": ["PACKAGE_FACET_REPLAY_FAILED"]})
    assert any(f["code"] == "PACKAGE_FACET_REPLAY_FAILED" and f["status"] == "FAIL" for f in findings)
    assert all(f["status"] == "UNKNOWN" for f in findings if f["scope"] == "object")
    assert all(f["reason"] == f["explanation"] for f in findings)


def _grouped_input(per_object: int = 10, objects: int = 6) -> list[dict]:
    """Many instance findings that share one cause, plus one distinct refutation."""
    from verifier.runtime.manifest_gate import repository_finding
    findings = []
    for index in range(objects):
        for ordinal in range(per_object):
            findings.append({
                "scope": "object", "object_id": f"object-{index:02d}", "object_kind": "SENSOR",
                "coordinate": f"SENSOR-1.{ordinal}", "obligation_id": f"SENSOR-1.{ordinal}-step",
                "obligation_name": "Step", "semantic_version": "v1", "gate_id": "applicability",
                "status": "UNKNOWN", "code": "PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED",
                "explanation": "No object-specific necessity reason is established.",
                "next_action": "Supply source-bound applicability evidence.",
                "reason": "No object-specific necessity reason is established.",
                "rerun_argv": ["vstd", "gate", "--object", f"object-{index:02d}",
                               "--obligation", f"SENSOR-1.{ordinal}-step"],
            })
    findings.append(repository_finding("PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS", "FAIL"))
    return findings


def test_group_findings_collapses_by_status_code_and_gate_worst_first() -> None:
    from verifier.runtime.manifest_gate import group_findings
    groups = group_findings(_grouped_input())

    assert [(g["status"], g["code"]) for g in groups] == [
        ("FAIL", "PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS"),
        ("UNKNOWN", "PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED"),
    ]
    applicability = groups[1]
    assert applicability["scope"] == "group"
    assert applicability["instance_count"] == 60
    assert applicability["object_count"] == 6
    assert applicability["object_id"] is None
    assert len(applicability["examples"]) == 3
    assert applicability["examples"] == sorted(
        applicability["examples"], key=lambda item: (item["object_id"], item["obligation_id"])
    )
    assert applicability["next_action"] == "Supply source-bound applicability evidence."
    assert groups[0]["instance_count"] == 1


def test_group_findings_is_deterministic_and_input_order_independent() -> None:
    from verifier.runtime.manifest_gate import group_findings
    findings = _grouped_input()
    assert group_findings(findings) == group_findings(list(reversed(findings)))


def test_grouped_finding_keeps_the_finding_contract_and_is_idempotent() -> None:
    from verifier.runtime.manifest_gate import group_findings
    groups = group_findings(_grouped_input())
    for group in groups:
        assert group["status"] in {"FAIL", "UNKNOWN"}
        assert group["reason"].strip() and group["explanation"].strip() and group["next_action"].strip()
        assert group["rerun_argv"] is None or all(type(item) is str for item in group["rerun_argv"])
        assert "obligation_id" in group and "gate_id" in group
    assert group_findings(groups) == groups


def test_group_findings_never_hides_a_refutation_inside_a_larger_unknown_group() -> None:
    from verifier.runtime.manifest_gate import group_findings
    findings = _grouped_input()
    findings.append({**findings[0], "status": "FAIL", "object_id": "object-00-refuted"})
    groups = group_findings(findings)
    assert [(g["status"], g["instance_count"]) for g in groups
            if g["code"] == "PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED"] == [
        ("FAIL", 1), ("UNKNOWN", 60)]


def test_print_finding_groups_prints_a_short_list_exactly_like_print_findings(capsys) -> None:
    from verifier.runtime.manifest_gate import print_finding_groups, print_findings
    findings = _grouped_input(per_object=2, objects=2)
    print_findings(findings)
    expected = capsys.readouterr().out
    print_finding_groups(findings)
    assert capsys.readouterr().out == expected


def test_print_finding_groups_collapses_a_long_list_into_a_short_next_action_view(capsys) -> None:
    from verifier.runtime.manifest_gate import print_finding_groups
    findings = _grouped_input(per_object=100, objects=30)   # 3000 instance findings
    print_finding_groups(findings)
    lines = capsys.readouterr().out.splitlines()

    text = "\n".join(lines)
    assert len(lines) < 40
    assert lines[0].startswith("Next actions: 2 kind(s) of finding covering 3001 item(s)")
    assert "1 FAIL" in lines[0] and "3000 UNKNOWN" in lines[0]
    # Refutations come first and every group names its count, one next step and a rerun.
    assert text.index("[FAIL]") < text.index("[UNKNOWN]")
    assert "[UNKNOWN] 3000x PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED" in text
    assert "objects=30" in text
    assert "Next: Supply source-bound applicability evidence." in text
    assert "vstd gate --object object-00 --obligation SENSOR-1.0-step" in text
    assert "--json" in lines[-1]


def test_print_finding_groups_accepts_findings_that_are_already_groups(capsys) -> None:
    from verifier.runtime.manifest_gate import group_findings, print_finding_groups
    groups = group_findings(_grouped_input())
    print_finding_groups(groups)
    output = capsys.readouterr().out
    assert "[UNKNOWN] 60x PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED" in output
    assert "<repository>" not in output.split("[UNKNOWN]")[1]
