"""Consequence-derived package requirements must survive generic labels.

Verifier Standard (VSTD) tests keep source discovery and consequence derivation
real; only expensive repository diagnostics use the shared isolated fixture.
No hardware, financial endpoint or subject process executes.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from test_package_polish import declared_package
from test_manifest_gate import selected_root
from verifier.runtime import package_polish as package
from verifier.runtime import core_obligation_union as binding
from verifier.runtime.namespace_contracts import namespace_registry, registry_document
from verifier.runtime.package_kind_requirements import KindRequirements


def prepare(root: Path, retained: dict) -> dict:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "subject.py").write_text("raise RuntimeError('subject must not execute')\n", encoding="utf-8")
    rows = [{**item.to_dict(), "specializations": [], "surfaces": [],
             "reason": "Retained role", "classification": {}, "obligations": {}}
            for item in package.tier_zero_manifest._namespace_objects(retained["objects"])]
    rows.append({"object_id": "external", "kind": "OBJECT", "specializations": [],
        "payload": {}, "operands": {}, "surfaces": ["file:subject.py", "python:subject.py:<module>"],
        "reason": "A consequential endpoint cannot hide behind a generic label.",
        "classification": {}, "obligations": {}})
    graph = next(row for row in rows if row["kind"] == "GRAPH")
    graph["operands"]["members"].append("external")
    evidence = [{"path": "subject.py", "sha256": binding.bytes_digest((root / "subject.py").read_bytes())}]
    agent = next(row["object_id"] for row in rows if row["kind"] == "AGENT")
    consequence = {"schema_version": "verifier-consequence-graph-1",
        "edges": [{"source": agent, "relation": "influences", "target": "external",
                   "reason": "An indirect external consequence.", "evidence": evidence}],
        "effects": [{"object_id": "external", "domain": domain,
                     "reason": "An externally consequential endpoint.", "evidence": evidence}
                    for domain in ("REAL_PHYSICAL", "REAL_FINANCIAL")]}
    document = {**retained, "schema_version": package.package_manifest.SCHEMA, "namespace": {
        "schema_version": "verifier-objects-manifest-2", "extensions": [],
        "registry_digest": registry_document(namespace_registry())["digest"],
        "objects": rows, "consequence_graph": consequence}}
    save(root, document)
    return document


def save(root: Path, document: dict) -> None:
    (root / "objects.vstd").write_bytes(binding.canonical_bytes(document) + b"\n")


def consequence_reason(kind: str) -> str:
    """Return the exact source-bound reason an agent-reachable consequence adds to a role."""
    return ("Declared consequence graph requires " + kind
            + "; simulation or generic labels cannot erase an external path.")


def refresh_evidence(root: Path, document: dict) -> None:
    """Rebind every consequence record to the current subject bytes it cites."""
    digest = binding.bytes_digest((root / "subject.py").read_bytes())
    graph = document["namespace"]["consequence_graph"]
    for record in [*graph["edges"], *graph["effects"]]:
        record["evidence"] = [{"path": "subject.py", "sha256": digest}]


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_polish_keeps_undeclared_consequential_roles_in_higher_tier_coverage(declared_package, tier):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    report = package.assess_package_polish(tier, root)
    bot = next(row["object_id"] for row in document["namespace"]["objects"] if row["kind"] == "BOT")
    agent = next(row["object_id"] for row in document["namespace"]["objects"] if row["kind"] == "AGENT")
    # The AGENT influence path reaches both declared external effects.  There is no
    # actuates edge, so the external process launch is not a command-to-effect ACTUATOR.
    coverage = report["refinement_coverage"]
    assert {(row["object_id"], row["kind"]) for row in coverage} == {
        (bot, "ROBOT"), (bot, "FINBOT"), (agent, "ROBOT"), (agent, "FINBOT")}
    assert all(row["status"] == "UNKNOWN"
               and row["blocker"] == "PACKAGE_REFINEMENT_HIGHER_TIER_CONTRACT_NOT_ESTABLISHED"
               and row["kind_requirement"]["necessity"] == "NECESSARY"
               and row["kind_requirement"]["reasons"] == [consequence_reason(row["kind"])]
               for row in coverage)
    assert report["kind_requirements"]["consequence_graph"]["required_kinds"] == {
        agent: ["FINBOT", "ROBOT"], bot: ["FINBOT", "ROBOT"]}
    external = next(row for row in report["kind_requirements"]["objects"] if row["object_id"] == "external")
    assert "ACTUATOR" not in external["effective_kinds"]
    assert not report["polished"]
    import jsonschema
    schema = json.loads((Path(__file__).resolve().parents[1] /
        "src/verifier/schemas/verifier-manifest-package-polish-2.schema.json").read_bytes())
    jsonschema.Draft202012Validator(schema).validate(report)
    assert any(row["object_id"] == bot and row["code"] == "NAMESPACE_LABEL_CONTRADICTS_SOURCE"
               for row in report["findings"])


def test_source_declared_native_kind_adds_routes_without_casting_generic_object(declared_package):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    document["namespace"].pop("consequence_graph")
    (root / "subject.py").write_text("__vstd_kinds__ = ['AGENT']\nraise RuntimeError('never run')\n", encoding="utf-8")
    save(root, document)
    report = package.assess_package_polish(3, root)
    selected = [row for row in report["obligation_instances"]
                if row["object_id"] == "external" and row["object_kind"] == "AGENT"]
    assert selected, "Source-declared AGENT obligations disappeared behind OBJECT"
    assert all(row["status"] == "UNKNOWN" and row["checker_status"] == "NOT_RUN" for row in selected)
    assert all("PACKAGE_INSTANCE_TYPED_REPRESENTATION_UNRESOLVED" in row["blockers"] for row in selected)
    assert all(row["declared_kind"] == "OBJECT" for row in selected)
    assert len({row["instance_digest"] for row in report["obligation_instances"]}) == len(report["obligation_instances"])


def test_focused_gate_uses_the_same_derived_native_kind_without_replaying_wrong_subject(selected_root, monkeypatch):
    from verifier.runtime.manifest_gate import assess_object_gate
    retained = json.loads((selected_root / "objects.vstd").read_bytes())
    document = prepare(selected_root, retained)
    document["namespace"].pop("consequence_graph")
    (selected_root / "subject.py").write_text("__vstd_kinds__ = ['AGENT']\n", encoding="utf-8")
    save(selected_root, document)
    monkeypatch.setattr(package.package_self_polish, "_native_facets_replay",
        lambda *args, **kwargs: pytest.fail("a derived kind must not replay the wrong typed subject"))
    report = assess_object_gate("external", "AGENT-1.1-declared-operand-facets", selected_root)
    assert report["status"] == "UNKNOWN", report["findings"]
    assert report["selection"]["object_kind"] == "AGENT"
    assert report["instance"]["checker_status"] == "NOT_RUN" and report["facet_replay"] is None
    assert report["instance"]["kind_requirement"]["declared"] is False
    assert report["instance"]["kind_requirement"]["necessity"] == "NECESSARY"
    assert any(row["gate_id"] == "typed-representation" and row["rerun_argv"] == report["rerun_argv"]
               for row in report["findings"])
    assert report["post_replay_source_recapture"] == "PASS"


def test_generic_representation_route_keeps_its_native_any_kind_semantics(selected_root):
    from verifier.runtime.manifest_gate import assess_object_gate
    retained = json.loads((selected_root / "objects.vstd").read_bytes())
    document = prepare(selected_root, retained)
    bot = next(row["object_id"] for row in document["namespace"]["objects"] if row["kind"] == "BOT")
    report = assess_object_gate(bot, "OBJECT-1.1-canonical-representation-and-address", selected_root)
    # OBJECT-1.1 is the kind-independent structural route.  A successful
    # subject-bound replay may close this one obligation for a BOT without
    # claiming that the BOT's typed obligations or the package are polished.
    assert report["status"] == "PASS"
    assert report["polished"] is False and report["release_authorized"] is False
    assert report["instance"]["checker_status"] == "PASS"
    assert "PACKAGE_INSTANCE_TYPED_REPRESENTATION_UNRESOLVED" not in report["instance"]["blockers"]
    assert report["instance"]["declared_kind"] == "BOT"


def test_unavailable_discovery_is_unknown_not_wrong_kind_or_empty_pass(selected_root, monkeypatch):
    from verifier.runtime.manifest_gate import assess_object_gate
    from verifier.runtime import namespace_discovery
    retained = json.loads((selected_root / "objects.vstd").read_bytes())
    prepare(selected_root, retained)

    def unavailable(root: Path) -> dict:
        raise ValueError("GIT_STATE_UNAVAILABLE")

    monkeypatch.setattr(namespace_discovery, "discover", unavailable)
    report = assess_object_gate("external", "AGENT-1.1-declared-operand-facets", selected_root)
    assert report["status"] == "UNKNOWN" and report["instance"] is None
    assert all(row["code"] != "PACKAGE_GATE_OBJECT_KIND_DIFFERS" for row in report["findings"])


def test_unselected_self_harness_checker_is_nested_without_affecting_kind_status(
        declared_package) -> None:
    root, retained, _ = declared_package
    declaration = prepare(root, retained)["namespace"]
    selected = KindRequirements(root, declaration)
    assert selected.report["harness_applicability"]["selection_status"] == "NOT_SELECTED"
    assert selected.report["harness_applicability"]["blockers"] == []


def test_root_reason_answers_extend_the_same_package_kind_denominator(
        declared_package, monkeypatch: pytest.MonkeyPatch) -> None:
    """Package tiers must retain the exact APPLIES answers admitted by Tier 0."""

    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    root, retained, _ = declared_package
    declaration = prepare(root, retained)["namespace"]
    external = next(
        row for row in declaration["objects"] if row["object_id"] == "external"
    )
    external["classification"]["ACTUATOR"] = {
        "status": "UNRESOLVED",
        "reason": "The fixture source-role decision remains open.",
        "evidence": [],
    }
    (root / "reasons.vstd").write_text("fixture\n", encoding="utf-8")
    monkeypatch.setattr(reason_integration, "select_root_reasons", lambda _root: object())
    monkeypatch.setattr(
        reason_integration,
        "documented_applicability_answers",
        lambda _selection, _objects: (
            {
                "object_id": "external",
                "object_kind": "ACTUATOR",
                "reason_id": "fixture-external-actuator",
                "decision": "APPLIES",
            },
        ),
    )

    selected = KindRequirements(root, declaration)

    assert "ACTUATOR" in selected.kinds("external")
    assert selected.basis("external", "ACTUATOR")["necessity"] == "NECESSARY"
    assert not any(
        row["object_id"] == "external"
        and row["code"] == "NAMESPACE_OBLIGATION_NOT_APPLICABLE_OR_REGISTERED"
        for row in selected.report["findings"]
    )


def test_prose_refutation_never_removes_a_hint_and_a_declared_consequence_still_fails(declared_package):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    document["namespace"].pop("consequence_graph")
    (root / "subject.py").write_text("def controller_documentation(): pass\n", encoding="utf-8")
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    selected = KindRequirements(root, document["namespace"])
    assert selected.basis("external", "CONTROLLER")["necessity"] == "CONDITIONAL_UNRESOLVED"
    evidence = [{"path": "subject.py", "sha256": binding.bytes_digest((root / "subject.py").read_bytes())}]
    row["classification"]["CONTROLLER"] = {"status": "DOES_NOT_APPLY",
        "reason": "This symbol describes documentation, not a controller.", "evidence": evidence}
    selected = KindRequirements(root, document["namespace"])
    # Prose and source hashes never remove a hint; CONTROLLER has no registered closure.
    assert "CONTROLLER" in selected.kinds("external")
    assert selected.basis("external", "CONTROLLER")["necessity"] == "CONDITIONAL_UNRESOLVED"
    agent = next(row["object_id"] for row in document["namespace"]["objects"] if row["kind"] == "AGENT")
    document["namespace"]["consequence_graph"] = {"schema_version": "verifier-consequence-graph-1",
        "edges": [{"source": agent, "relation": "controls", "target": "external",
                   "reason": "A declared controller path contradicts the label refutation.", "evidence": evidence}], "effects": []}
    selected = KindRequirements(root, document["namespace"])
    assert selected.basis("external", "CONTROLLER")["necessity"] == "NECESSARY"
    assert selected.report["status"] == "FAIL"


@pytest.mark.parametrize("stale", [False, True])
def test_classification_adoption_keeps_native_requirements_even_with_missing_or_stale_support(declared_package, stale):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    document["namespace"].pop("consequence_graph")
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    row["classification"]["AGENT"] = {"status": "APPLIES", "reason": "This object is declared an agent.",
        "evidence": [{"path": "subject.py", "sha256": "sha256:" + "0" * 64}] if stale else []}
    save(root, document)
    report = package.assess_package_polish(3, root)
    assert any(row["object_id"] == "external" and row["object_kind"] == "AGENT" for row in report["obligation_instances"])
    assert report["status"] == "FAIL"  # An adopted role contradicts the generic-only label.


def test_kind_discovery_is_recaptured_after_native_diagnostics(declared_package, monkeypatch):
    root, retained, _ = declared_package
    prepare(root, retained)
    original = package._run_native_diagnostics

    def change(tier: int, selected: Path) -> dict:
        result = original(tier, selected)
        (root / "subject.py").write_text("__vstd_kinds__ = ['AGENT']\n", encoding="utf-8")
        return result

    monkeypatch.setattr(package, "_run_native_diagnostics", change)
    report = package.assess_package_polish(3, root)
    assert report["status"] == "FAIL" and "PACKAGE_KIND_SOURCE_CHANGED" in report["blockers"]


def test_independent_reconciler_checks_native_kinds_without_added_admission_obligations(declared_package):
    from verifier.runtime import namespace_admission, namespace_discovery, namespace_classification
    root, retained, _ = declared_package
    document = prepare(root, retained)["namespace"]
    document.pop("consequence_graph")
    (root / "subject.py").write_text("__vstd_kinds__ = ['AGENT']\n", encoding="utf-8")
    observed = namespace_discovery.discover(root)
    registry = namespace_registry()
    classified = namespace_classification.assess_classification(document["objects"], registry, observed)
    raw = binding.canonical_bytes(document) + b"\n"
    assert namespace_admission._reconcile(raw, registry, observed, classified)["status"] == "PASS"
    row = next(row for row in classified["objects"] if row["object_id"] == "external")
    row["effective_kinds"].remove("AGENT")
    # AGENT has no extra Tier-0 declaration obligations, so merely comparing
    # required_obligation_ids would miss this native higher-tier omission.
    assert namespace_admission._reconcile(raw, registry, observed, classified)["status"] == "FAIL"


def test_all_twelve_added_kinds_survive_as_source_requirements(declared_package):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    document["namespace"].pop("consequence_graph")
    added = sorted(kind for kind, contract in namespace_registry().items() if contract.extends is not None)
    assert len(added) == 12
    (root / "subject.py").write_text("__vstd_kinds__ = " + repr(added) + "\n", encoding="utf-8")
    selected = KindRequirements(root, document["namespace"])
    coverage = [row for row in selected.refinements(3) if row["object_id"] == "external"]
    assert {row["kind"] for row in coverage} == set(added)
    assert all(row["kind_requirement"]["necessity"] == "NECESSARY" for row in coverage)
    assert "OBJECT" in selected.kinds("external")


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_wrapper_bypass_remains_blocking_in_higher_tier_package_graph(declared_package, tier):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    declaration = document["namespace"]
    bot = next(row["object_id"] for row in declaration["objects"] if row["kind"] == "BOT")
    graph = declaration["consequence_graph"]
    graph["edges"].append({**graph["edges"][0], "source": bot})
    save(root, document)
    report = package.assess_package_polish(tier, root)
    findings = [row for row in report["kind_requirements"]["findings"]
                if row["code"] == "NAMESPACE_AGENCY_EFFECT_BYPASS" and row["object_id"] == bot]
    assert {row["obligation_id"] for row in findings} == {
        "ROBOT-0.1-agent-to-actuator-binding", "FINBOT-0.1-agent-and-financial-authority"}
    assert report["status"] != "PASS" and not report["polished"]
    coverage = report["kind_requirements"]["contract_coverage"]
    assert coverage["denominator_status"] == "PASS"
    assert all(row["status"] != "PASS" for row in coverage["contracts"])


@pytest.mark.parametrize("content,non_applicability,status,code", [
    ("def ledger_summary(entry):\n    return entry\n", "DOCUMENTED", "DOCUMENTED", "DOCUMENTED_BOUNDED_ABSENCE"),
    ("def append_ledger_entry(entry):\n    return entry\n", "NOT_ESTABLISHED", "FAIL", "BOUNDARY_IDENTIFIER_REFERENCED"),
], ids=["benign-current-closure-documented", "boundary-reference-closure-refutes"])
def test_package_refutation_runs_the_same_fresh_closure_as_admission(
        declared_package, content, non_applicability, status, code):
    from verifier.runtime import namespace_admission, namespace_classification, namespace_discovery
    from verifier.runtime import namespace_refutation
    from verifier.runtime.tier_zero_profile import value_digest
    root, retained, _ = declared_package
    document = prepare(root, retained)
    document["namespace"].pop("consequence_graph")
    (root / "subject.py").write_text(content, encoding="utf-8")
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    assert "LEDGER" in KindRequirements(root, document["namespace"]).kinds("external")
    evidence = [{"path": "subject.py", "sha256": binding.bytes_digest((root / "subject.py").read_bytes())}]
    decision = {"status": "DOES_NOT_APPLY", "reason": "This source has no ledger write path.",
                "evidence": evidence}
    row["classification"]["LEDGER"] = decision
    mechanism = value_digest(namespace_admission.mechanism_binding())
    context = namespace_classification.refutation_context(
        namespace_discovery.discover(root), mechanism, root=root)
    expected = namespace_refutation.ExpectedReview(
        object_id="external", kind="LEDGER", basis=namespace_refutation.BASIS_EXECUTABLE_CLOSURE,
        review_module="subject_py", review_mechanism_digest=mechanism,
        review_row_digest=value_digest(decision))
    decision["refutation"] = namespace_refutation.build_witness(
        expected=expected, source_paths=["subject.py"], inventory=context["inventory"])
    selected = KindRequirements(root, document["namespace"])
    # No installed closure establishes non-applicability.  A clean scan over a clean owned
    # effect audit is only DOCUMENTED and a referenced boundary is a FAIL; neither removes
    # the LEDGER hint.
    assert "LEDGER" in selected.kinds("external")
    assert selected.basis("external", "LEDGER")["necessity"] == "CONDITIONAL_UNRESOLVED"
    assert selected.basis("external", "LEDGER")["reasons"] == [
        "Unrefuted source hint at python:subject.py:<module>."]
    classified = next(item for item in selected.objects["external"]["classification"] if item["kind"] == "LEDGER")
    assert classified["decision"] == "DOES_NOT_APPLY" and classified["support_status"] == "PASS"
    assert classified["non_applicability"] == non_applicability
    assert (classified["refutation_status"], classified["refutation_code"]) == (status, code)
    digest = classified["refutation_receipt_digest"]
    assert digest.startswith("sha256:")
    findings = [item for item in selected.report["findings"]
                if item["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED" and item["object_id"] == "external"]
    if status == "DOCUMENTED":
        # DOCUMENTED answers the classification question, so the claim adds no blocker.
        assert findings == []
        return
    assert len(findings) == 1 and findings[0]["status"] == status
    prefix = ("LEDGER declares DOES_NOT_APPLY, but that claim is " + status + " (" + code
              + "); its obligations remain required.")
    assert findings[0]["reason"] == prefix
    assert selected.report["status"] == status


def count_preserving_relabel(root: Path, document: dict, object_id: str, kind: str) -> None:
    """Change one existing row's label in place so the object count and identities are unchanged."""
    row = next(item for item in document["namespace"]["objects"] if item["object_id"] == object_id)
    row["kind"] = kind


def test_count_preserving_actuator_label_on_process_launch_adds_no_physical_evidence(declared_package):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    objects = document["namespace"]["objects"]
    bot = next(row["object_id"] for row in objects if row["kind"] == "BOT")
    agent = next(row["object_id"] for row in objects if row["kind"] == "AGENT")
    count = len(objects)
    count_preserving_relabel(root, document, "external", "ACTUATOR")
    # A process launch is read as source text only; the subject never runs.
    (root / "subject.py").write_text("import subprocess\nsubprocess.run(['true'])\n", encoding="utf-8")
    refresh_evidence(root, document)
    save(root, document)
    report = package.assess_package_polish(3, root)
    kinds = report["kind_requirements"]
    assert len(kinds["objects"]) == count
    external = next(row for row in kinds["objects"] if row["object_id"] == "external")
    # The label itself is only a declared UNKNOWN obligation; it adds no ROBOT or FINBOT route.
    assert external["kind_reasons"]["ACTUATOR"] == ["Manifest declares ACTUATOR."]
    assert not {"ROBOT", "FINBOT"} & set(external["effective_kinds"])
    assert kinds["consequence_graph"]["required_kinds"] == {agent: ["FINBOT", "ROBOT"], bot: ["FINBOT", "ROBOT"]}
    assert {(row["object_id"], row["kind"]) for row in report["refinement_coverage"]} == {
        (bot, "ROBOT"), (bot, "FINBOT"), (agent, "ROBOT"), (agent, "FINBOT"), ("external", "ACTUATOR")}
    external_rows = [row for row in report["refinement_coverage"] if row["object_id"] == "external"]
    assert [(row["status"], row["kind_requirement"]["reasons"]) for row in external_rows] == [
        ("UNKNOWN", ["Manifest declares ACTUATOR."])]
    assert report["status"] == "FAIL" and not report["polished"]
    assert "PACKAGE_REFINEMENT_HIGHER_TIER_CONTRACT_NOT_ESTABLISHED" in report["blockers"]


def test_count_preserving_agent_label_erasure_keeps_bot_and_agent_consequences(declared_package):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    objects = document["namespace"]["objects"]
    bot = next(row["object_id"] for row in objects if row["kind"] == "BOT")
    agent = next(row["object_id"] for row in objects if row["kind"] == "AGENT")
    count_preserving_relabel(root, document, agent, "OBJECT")
    save(root, document)
    # The package path refuses a relabeled retained object before any role is derived.
    report = package.assess_package_polish(3, root)
    assert report["status"] == "FAIL" and "PACKAGE_NAMESPACE_KIND_CHANGED" in report["blockers"]
    # The kind layer must still keep every consequential role, with no physical evidence for the external object.
    selected = KindRequirements(root, document["namespace"])
    assert selected.report["status"] == "FAIL"
    for identifier in (agent, bot):
        for kind in ("ROBOT", "FINBOT"):
            basis = selected.basis(identifier, kind)
            assert basis["necessity"] == "NECESSARY" and basis["reasons"] == [consequence_reason(kind)]
    assert selected.kinds("external") == {"OBJECT"}
