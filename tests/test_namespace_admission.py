"""Executable boundaries for extensible Verifier Standard (VSTD) admission.

These tests distinguish declaration admission from financial correctness. Source
labels and discovery hints must never become an authority to issue a safety claim.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from verifier.runtime.public_cli import main


def test_manifest_evidence_reference_bound_retains_legacy_split_input() -> None:
    from verifier.runtime import namespace_manifest

    reference = {"path": "owned.py", "sha256": "sha256:" + "0" * 64}
    legacy_binding = {
        "reason": "The legacy catchall retains exact path/digest references until migration.",
        "evidence": [dict(reference) for _ in range(1407)],
    }
    assert namespace_manifest._binding(legacy_binding)
    legacy_binding["evidence"] = [
        dict(reference)
        for _ in range(namespace_manifest.MAX_EVIDENCE_REFERENCES + 1)
    ]
    assert not namespace_manifest._binding(legacy_binding)


def test_independent_reconciler_capture_refuses_output_growth() -> None:
    from verifier.runtime import namespace_admission as admission

    result = admission._run_bounded_reconciler(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
        b"",
        output_limit=1024,
        stderr_limit=1024,
        timeout_seconds=5,
    )
    assert result == {
        "status": "UNKNOWN",
        "reason": "The independent reconciler exceeded its bounded output envelope.",
    }


def test_classification_has_one_exact_derived_item_denominator(tmp_path) -> None:
    from verifier.runtime import namespace_admission as admission
    from verifier.runtime import namespace_classification as classification
    from verifier.runtime import namespace_contracts as contracts
    from verifier.runtime import namespace_discovery as discovery

    root = repository(tmp_path, "VALUE = 1\n")
    draft = admission.build_template(root)["manifest"]
    registry = contracts.namespace_registry(draft["extensions"])
    observed = discovery.discover(root)
    baseline = classification.assess_classification(
        draft["objects"], registry, observed, derived_item_limit=10_000
    )
    used = baseline["derived_item_count"]
    assert classification.assess_classification(
        draft["objects"], registry, observed, derived_item_limit=used
    )["objects"] == baseline["objects"]
    with pytest.raises(ValueError, match="NAMESPACE_DERIVATION_CAPACITY"):
        classification.assess_classification(
            draft["objects"], registry, observed, derived_item_limit=used - 1
        )


def repository(tmp_path: Path, source: str) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "accounts.py").write_text(source, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "accounts.py"], check=True)
    return tmp_path


def save(root: Path, manifest: dict) -> None:
    from verifier.runtime.tier_zero_profile import canonical_bytes
    (root / "objects.vstd").write_bytes(canonical_bytes(manifest) + b"\n")


def test_template_command_discovers_methods_without_executing_subject(tmp_path, capsys):
    root = repository(tmp_path, "raise RuntimeError('must not execute')\nclass Ledger:\n    def post(self): pass\n")
    assert main(["template", "--source-root", str(root), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["manifest"]["schema_version"] == "verifier-objects-manifest-2"
    assert "python:accounts.py:Ledger.post" in result["manifest"]["objects"][0]["surfaces"]
    assert result["status"] == "DRAFT"
    assert not (root / "objects.vstd").exists()


def test_object_label_cannot_erase_source_declared_financial_obligations(tmp_path):
    from verifier.runtime.namespace_admission import assess, build_template
    from verifier.runtime.tier_zero_profile import value_digest
    root = repository(tmp_path, '__vstd_kinds__ = ("LEDGER", "TRANSACTION")\ndef post(): pass\n')
    manifest = build_template(root)["manifest"]
    subject = manifest["objects"][0]
    subject["kind"] = "OBJECT"
    subject["specializations"] = []
    subject["classification"] = {}
    subject["obligations"] = {}
    save(root, manifest)
    report = assess(root)
    assert report["status"] == "FAIL"
    assert any(row["code"] == "NAMESPACE_LABEL_CONTRADICTS_SOURCE" for row in report["findings"])
    assert {row["kind"] for row in report["required_obligations"]} == {"LEDGER", "TRANSACTION"}
    assert len(report["required_obligations"]) == 6
    contracts = {row["id"]: row for row in report["obligation_contracts"]}
    assert all(
        contracts[row["id"]]["reason"]
        and row["applicability_reason"]
        and row["contract_digest"] == value_digest(contracts[row["id"]])
        for row in report["required_obligations"]
    )
    assert all(
        row["detail_profile"] == "MISSING_OBLIGATION_BINDING"
        and "assessment_reason" not in row
        for row in report["required_obligations"]
    )
    obligation_findings = [
        row for row in report["findings"]
        if row["code"] == "NAMESPACE_OBLIGATION_EVIDENCE_UNRESOLVED"
    ]
    assert len(obligation_findings) == 6
    assert all(
        row["detail_profile"] == "REQUIRED_OBLIGATION_REFERENCE"
        and row["reason"]
        and row["next_action"]
        for row in obligation_findings
    )
    assert report["tier_1_plus_status"] == "NOT_ESTABLISHED"


def test_unlisted_method_fails_even_when_file_is_owned(tmp_path):
    from verifier.runtime.namespace_admission import assess, build_template
    root = repository(tmp_path, "def existing(): pass\n")
    manifest = build_template(root)["manifest"]
    save(root, manifest)
    (root / "accounts.py").write_text("def existing(): pass\ndef hidden(): pass\n", encoding="utf-8")
    report = assess(root)
    assert any(row["code"] == "NAMESPACE_SURFACE_UNCOVERED"
               and row["surface_id"] == "python:accounts.py:hidden" for row in report["findings"])


def test_heuristic_is_unknown_not_proven_mislabeling(tmp_path):
    from verifier.runtime.namespace_admission import assess, build_template
    root = repository(tmp_path, "class Ledger:\n    pass\n")
    manifest = build_template(root)["manifest"]
    save(root, manifest)
    report = assess(root)
    assert any(row["code"] == "NAMESPACE_CLASSIFICATION_UNRESOLVED" for row in report["findings"])
    assert not any(row["code"] == "NAMESPACE_LABEL_CONTRADICTS_SOURCE" for row in report["findings"])


def test_template_reviews_every_original_and_added_kind_except_generic_object(tmp_path):
    from verifier.runtime.namespace_admission import build_template
    from verifier.runtime.namespace_contracts import namespace_registry

    root = repository(tmp_path, "class Agent:\n    def plan(self): pass\n")
    draft = build_template(root)
    subject = draft["manifest"]["objects"][0]
    assert subject["kind"] == "OBJECT"
    assert set(subject["classification"]) == set(namespace_registry()) - {"OBJECT"}
    assert any(
        "AGENT" in surface["hints"]
        for surface in draft["suggestions"]
        if surface["path"] == "accounts.py"
    )


def test_original_kind_hint_needs_evidence_bound_decision_before_object_can_pass(tmp_path):
    from verifier.runtime.namespace_admission import assess, build_template

    root = repository(
        tmp_path,
        "class Agent:\n    def plan(self): return 'goal'\n    def act(self): return 'tool-call'\n",
    )
    draft = build_template(root)
    manifest = draft["manifest"]
    subject = manifest["objects"][0]
    subject["reason"] = "This record owns the bounded source definitions."
    for kind, decision in subject["classification"].items():
        decision.update(
            status="UNRESOLVED" if kind == "AGENT" else "DOES_NOT_APPLY",
            reason=(
                "Current source cues require an explicit agency decision."
                if kind == "AGENT"
                else "This installed semantic role does not apply to the bounded source representation."
            ),
            evidence=draft["source_evidence"],
        )
    save(root, manifest)

    unresolved = assess(root)
    agent = next(
        row for row in unresolved["object_assessments"][0]["classification"]
        if row["kind"] == "AGENT"
    )
    assert unresolved["status"] == "UNKNOWN"
    assert agent["hinted"] and agent["decision"] == "UNRESOLVED"
    assert "AGENT" in unresolved["object_assessments"][0]["effective_kinds"]
    assert any(
        row["code"] == "NAMESPACE_CLASSIFICATION_UNRESOLVED"
        and row["object_id"] == "accounts.py"
        and row["reason"].startswith("AGENT:")
        for row in unresolved["findings"]
    )

    subject["classification"]["AGENT"].update(
        status="DOES_NOT_APPLY",
        reason="The bounded source uses an Agent-shaped local helper name but owns no autonomous goal or action authority.",
    )
    save(root, manifest)
    # With its reason and current owned evidence, and with no stored witness, the closure
    # runs now over every owned file and the owned effect audit judges the same bytes.  Both
    # are clean, so AGENT's DOES_NOT_APPLY is admitted as DOCUMENTED, never ESTABLISHED.
    # The hint still keeps AGENT effective with all of its obligations; the object passes
    # Tier 0 only because AGENT selects no Tier-0 declaration.
    prose = assess(root)
    assert prose["status"] == "PASS"
    assert "AGENT" in prose["object_assessments"][0]["effective_kinds"]
    assert not any(row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED" for row in prose["findings"])
    assert_admitted_only_as_documented(prose)
    # A stored witness, when present, must bind the same current bytes; it admits no more.
    bind_refutations(root, manifest)
    save(root, manifest)
    documented = assess(root)
    assert documented["status"] == "PASS"
    assert "AGENT" in documented["object_assessments"][0]["effective_kinds"]
    assert_admitted_only_as_documented(documented)


def test_original_source_declaration_cannot_be_hidden_behind_object(tmp_path):
    from verifier.runtime.namespace_admission import assess, build_template

    root = repository(
        tmp_path,
        '__vstd_kinds__ = ("AGENT",)\nclass Worker:\n    def plan(self): pass\n',
    )
    draft = build_template(root)
    manifest = draft["manifest"]
    subject = manifest["objects"][0]
    assert subject["kind"] == "AGENT"
    subject["kind"] = "OBJECT"
    subject["reason"] = "This record owns the bounded source definitions."
    for decision in subject["classification"].values():
        decision.update(
            status="DOES_NOT_APPLY",
            reason="This role is asserted not to apply to the bounded source representation.",
            evidence=draft["source_evidence"],
        )
    save(root, manifest)

    report = assess(root)
    assert report["status"] == "FAIL"
    assert "AGENT" in report["object_assessments"][0]["effective_kinds"]
    assert any(
        row["code"] == "NAMESPACE_LABEL_CONTRADICTS_SOURCE"
        and row["object_id"] == "accounts.py"
        for row in report["findings"]
    )
    assert any(
        row["code"] == "NAMESPACE_REFUTATION_CONTRADICTS_DECLARATION"
        and row["object_id"] == "accounts.py"
        for row in report["findings"]
    )


def test_extension_cannot_replace_builtin_or_drop_inherited_obligations():
    from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
    custom = {"kind": "JOURNAL", "extends": "LEDGER", "version": "1",
              "reason": "Journal instances retain the ledger contract.",
              "obligations": [{"id": "JOURNAL-0.1-retention", "name": "Retention boundary",
                               "reason": "Retention changes the replay horizon.",
                               "evidence_requirement": "Bind the retention policy and source."}]}
    registry = namespace_registry([custom])
    assert len(requirements_for(registry, ["JOURNAL"])) == 4
    assert len(requirements_for(registry, ["JOURNAL", "LEDGER"])) == 4
    with pytest.raises(ValueError, match="REDEFINITION"):
        namespace_registry([{**custom, "kind": "LEDGER"}])
    with pytest.raises(ValueError, match="REASON"):
        namespace_registry([{**custom, "reason": ""}])


def assert_admitted_only_as_documented(report: dict) -> None:
    """Every DOES_NOT_APPLY of a completed fixture is DOCUMENTED, never ESTABLISHED, and nothing blocks."""
    assert [row for row in report["findings"] if row["status"] != "PASS"] == []
    decisions = [row for assessment in report["object_assessments"] for row in assessment["classification"]
                 if row["decision"] == "DOES_NOT_APPLY"]
    assert decisions
    assert all(row["non_applicability"] == row["refutation_status"] == "DOCUMENTED" for row in decisions)


def completed_manifest(root: Path, source: str, *, witness: bool = True) -> dict:
    """Bind declared reasons; this is not a financial execution fixture.

    ``witness=False`` leaves every DOES_NOT_APPLY row exactly as a reviewer wrote it,
    with no stored refutation witness.
    """
    from verifier.runtime.namespace_admission import build_template
    draft = build_template(root)
    manifest = draft["manifest"]
    for row in manifest["objects"]:
        row["reason"] = "This object owns the source definitions of the bounded test subject."
        for kind, decision in row["classification"].items():
            decision.update(status="APPLIES" if kind in source else "DOES_NOT_APPLY",
                reason="The selected source declares this role." if kind in source else
                       "The selected calculation has no authoritative history or coordinated external effects.",
                evidence=draft["source_evidence"])
        for binding in row["obligations"].values():
            binding.update(reason="This source defines the selected subject's declared boundary; implementation correctness is a later obligation.",
                           evidence=draft["source_evidence"])
            # Deliberately declarative: these specimens have no financial engine.
            # Admission must check every answer without claiming it was executed.
            binding["declaration"] = {field: "The specimen declares its " + field +
                " boundary in this test contract; no financial enforcement is asserted."
                for field in binding["declaration"]}
    if witness:
        bind_refutations(root, manifest)
    return manifest


def bind_refutations(root: Path, manifest: dict) -> None:
    """Bind a current executable witness to every DOES_NOT_APPLY decision.

    Prose alone never removes an obligation, so a passing specimen must carry
    the typed witness for each non-applicability it declares.  The expected
    identity mirrors one reviewer: this object's owned file, the installed
    mechanism, and the exact decision row.
    """
    from verifier.runtime import namespace_admission as admission
    from verifier.runtime import namespace_classification as classification
    from verifier.runtime import namespace_discovery as discovery
    from verifier.runtime import namespace_refutation as refutation
    from verifier.runtime.tier_zero_profile import value_digest

    observed = discovery.discover(root)
    mechanism = value_digest(admission.mechanism_binding())
    context = classification.refutation_context(observed, mechanism, root=root)
    surfaces = {row["surface_id"]: row["path"] for row in observed["surfaces"]}
    for row in manifest["objects"]:
        owned = sorted({surfaces[surface] for surface in row["surfaces"] if surface in surfaces})
        module = classification._review_module(set(owned))
        for kind, decision in row["classification"].items():
            if decision["status"] != "DOES_NOT_APPLY":
                continue
            expected = refutation.ExpectedReview(
                object_id=row["object_id"], kind=kind, basis=refutation.BASIS_EXECUTABLE_CLOSURE,
                review_module=module, review_mechanism_digest=mechanism,
                review_row_digest=value_digest({key: item for key, item in decision.items()
                                                if key != "refutation"}),
            )
            decision["refutation"] = refutation.build_witness(
                expected=expected, source_paths=owned, inventory=context["inventory"])


def bind_conditional_kind(manifest: dict, kind: str, evidence: list[dict[str, str]]) -> None:
    """Complete selected conditional obligations without asserting applicability."""
    from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
    subject = manifest["objects"][0]
    subject["classification"][kind].update(status="UNRESOLVED",
        reason="Current source evidence selects this role for applicability review.", evidence=evidence)
    subject["classification"][kind].pop("refutation", None)
    for obligation in requirements_for(namespace_registry(), [kind]):
        if obligation["kind"] != kind:
            continue
        subject["obligations"][obligation["id"]] = {
            "reason": "The conditional candidate retains this declaration while applicability remains unresolved.",
            "evidence": manifest["objects"][0]["classification"][kind]["evidence"],
            "declaration": {field: "The bounded specimen declares this conditional " + field + " boundary."
                            for field in obligation["declaration_fields"]},
        }


def test_evidence_bearing_unresolved_classification_retains_conditional_obligations_and_node_agrees(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    manifest = completed_manifest(root, "")
    evidence = manifest["objects"][0]["classification"]["LEDGER"]["evidence"]
    bind_conditional_kind(manifest, "LEDGER", evidence)
    save(root, manifest)
    report = assess(root)
    selected = [row for row in report["required_obligations"] if row["kind"] == "LEDGER"]
    assessment = report["object_assessments"][0]
    decision = next(row for row in assessment["classification"] if row["kind"] == "LEDGER")
    assert report["status"] == "UNKNOWN"
    assert len(selected) == 3 and all(row["necessity"] == "CONDITIONAL_UNRESOLVED" for row in selected)
    assert all("evidence-bearing unresolved applicability candidate" in row["applicability_reason"]
               for row in selected)
    assert "LEDGER" in assessment["effective_kinds"] and "LEDGER" not in assessment["necessary_kinds"]
    assert decision["decision"] == "UNRESOLVED" and decision["support_status"] == "PASS"
    assert decision["semantic_classification_status"] == "NOT_ESTABLISHED"
    assert report["independent_reconciliation"]["status"] == "PASS"


def test_documented_applies_reason_retains_obligations_without_rewriting_registry(tmp_path):
    from verifier.runtime import namespace_admission as admission
    from verifier.runtime import namespace_classification as classification
    from verifier.runtime import namespace_contracts as contracts
    from verifier.runtime import namespace_discovery as discovery
    from verifier.runtime.tier_zero_profile import canonical_bytes

    root = repository(tmp_path, "def add(a, b): return a + b\n")
    draft = admission.build_template(root)["manifest"]
    row = draft["objects"][0]
    row["reason"] = "This record owns the bounded source definitions."
    row["classification"]["LEDGER"].update(
        status="UNRESOLVED",
        reason="The compiled registry keeps this applicability question open.",
        evidence=[],
    )
    original = dict(row["classification"]["LEDGER"])
    registry = contracts.namespace_registry(draft["extensions"])
    observed = discovery.discover(root)

    answers = [{
        "reason_id": "retain-ledger",
        "object_id": row["object_id"],
        "object_kind": "LEDGER",
        "decision": "APPLIES",
    }]
    result = classification.assess_classification(
        draft["objects"],
        registry,
        observed,
        documented_applicability_answers=answers,
    )

    assessed = result["objects"][0]
    decision = next(
        item for item in assessed["classification"] if item["kind"] == "LEDGER"
    )
    assert row["classification"]["LEDGER"] == original
    assert "LEDGER" in assessed["effective_kinds"]
    assert "LEDGER" in assessed["necessary_kinds"]
    assert decision["decision"] == "UNRESOLVED"
    assert decision["reason_decision"] == "APPLIES"
    assert decision["reason_status"] == "DOCUMENTED"
    assert decision["semantic_classification_status"] == "NOT_ESTABLISHED"
    assert decision["detail_profile"] == "DOCUMENTED_APPLIES_RETENTION"
    assert {
        key: result["detail_profiles"][decision["detail_profile"]][key]
        for key in (
            "non_applicability",
            "refutation_status",
            "refutation_code",
            "refutation_receipt_digest",
        )
    } == {
        "non_applicability": "NOT_ESTABLISHED",
        "refutation_status": None,
        "refutation_code": None,
        "refutation_receipt_digest": None,
    }
    assert not any(
        finding["code"] == "NAMESPACE_CLASSIFICATION_UNRESOLVED"
        and finding["object_id"] == row["object_id"]
        and finding["explanation"].startswith("LEDGER:")
        for finding in result["findings"]
    )
    assert {
        item["id"] for item in result["required_obligations"]
        if item["object_id"] == row["object_id"] and item["kind"] == "LEDGER"
    } == {obligation.id for obligation in registry["LEDGER"].obligations}
    reconciled = admission._reconcile(
        canonical_bytes(draft) + b"\n",
        registry,
        observed,
        result,
        documented_applicability_answers=answers,
        reason_ir_digest="sha256:" + "1" * 64,
    )
    assert reconciled["status"] == "PASS"
    assert reconciled["receipt"]["documented_applicability_digest"].startswith(
        "sha256:"
    )


def test_documented_applies_supersedes_compiled_denial_conservatively(tmp_path):
    from verifier.runtime import namespace_admission as admission
    from verifier.runtime import namespace_classification as classification
    from verifier.runtime import namespace_contracts as contracts
    from verifier.runtime import namespace_discovery as discovery
    from verifier.runtime.tier_zero_profile import canonical_bytes

    root = repository(tmp_path, "def add(a, b): return a + b\n")
    draft = admission.build_template(root)["manifest"]
    row = draft["objects"][0]
    row["reason"] = "This record owns the bounded source definitions."
    row["classification"]["LEDGER"].update(
        status="DOES_NOT_APPLY",
        reason="The compiled denial remains unestablished.",
        evidence=[],
    )
    original = dict(row["classification"]["LEDGER"])
    registry = contracts.namespace_registry(draft["extensions"])
    observed = discovery.discover(root)
    answers = [{
        "reason_id": "retain-ledger-over-denial",
        "object_id": row["object_id"],
        "object_kind": "LEDGER",
        "decision": "APPLIES",
    }]

    result = classification.assess_classification(
        draft["objects"], registry, observed,
        documented_applicability_answers=answers,
    )

    assessed = result["objects"][0]
    decision = next(
        item for item in assessed["classification"] if item["kind"] == "LEDGER"
    )
    assert row["classification"]["LEDGER"] == original
    assert decision["decision"] == "DOES_NOT_APPLY"
    assert decision["reason_decision"] == "APPLIES"
    assert decision["reason_status"] == "DOCUMENTED"
    assert decision["semantic_classification_status"] == "NOT_ESTABLISHED"
    assert decision["detail_profile"] == "DOCUMENTED_APPLIES_RETENTION"
    assert result["detail_profiles"][decision["detail_profile"]][
        "non_applicability"
    ] == "NOT_ESTABLISHED"
    assert "LEDGER" in assessed["effective_kinds"]
    assert "LEDGER" in assessed["necessary_kinds"]
    assert not any(
        item["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
        and item["object_id"] == row["object_id"]
        for item in result["findings"]
    )
    assert {
        item["id"] for item in result["required_obligations"]
        if item["object_id"] == row["object_id"] and item["kind"] == "LEDGER"
    } == {obligation.id for obligation in registry["LEDGER"].obligations}
    reconciled = admission._reconcile(
        canonical_bytes(draft) + b"\n", registry, observed, result,
        documented_applicability_answers=answers,
        reason_ir_digest="sha256:" + "1" * 64,
    )
    assert reconciled["status"] == "PASS"


def test_root_reason_applies_is_consumed_by_repository_admission(tmp_path):
    from verifier.runtime import namespace_admission as admission

    root = repository(tmp_path, "def add(a, b): return a + b\n")
    manifest = admission.build_template(root)["manifest"]
    row = manifest["objects"][0]
    row["reason"] = "This record owns the bounded source definitions."
    row["classification"]["LEDGER"].update(
        status="UNRESOLVED",
        reason="The compiled registry keeps this applicability question open.",
        evidence=[],
    )
    save(root, manifest)
    (root / "reasons.vstd").write_text(
        "reason retain-ledger\n"
        f"  about    {row['object_id']}\n"
        f"  claim    applies {row['object_id']} LEDGER\n"
        "  basis    declared objects.vstd\n"
        "  note     Retain the LEDGER obligations without claiming source adoption.\n",
        encoding="utf-8",
        newline="\n",
    )

    report = admission.assess(root)

    decision = next(
        item
        for item in report["object_assessments"][0]["classification"]
        if item["kind"] == "LEDGER"
    )
    assert report["classification_reason_reconciliation"][
        "documented_applicability_answer_count"
    ] == 1
    assert decision["decision"] == "UNRESOLVED"
    assert decision["reason_decision"] == "APPLIES"
    assert decision["reason_status"] == "DOCUMENTED"
    assert any(
        item["object_id"] == row["object_id"] and item["kind"] == "LEDGER"
        for item in report["required_obligations"]
    )
    assert not any(
        finding["code"] == "NAMESPACE_CLASSIFICATION_UNRESOLVED"
        and finding["object_id"] == row["object_id"]
        and finding["explanation"].startswith("LEDGER:")
        for finding in report["findings"]
    )
    assert report["independent_reconciliation"]["status"] == "PASS"


def test_stale_unresolved_classification_evidence_keeps_denominator_and_fails_freshness(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    manifest = completed_manifest(root, "")
    current = manifest["objects"][0]["classification"]["LEDGER"]["evidence"]
    bind_conditional_kind(manifest, "LEDGER", current)
    manifest["objects"][0]["classification"]["LEDGER"]["evidence"] = [
        {"path": "accounts.py", "sha256": "sha256:" + "0" * 64}]
    save(root, manifest)
    report = assess(root)
    selected = [row for row in report["required_obligations"] if row["kind"] == "LEDGER"]
    classification_failures = [row for row in report["findings"]
        if row["code"] == "NAMESPACE_CLASSIFICATION_UNRESOLVED" and row["object_id"] == "accounts.py"
        and row["status"] == "FAIL" and row["explanation"].startswith("LEDGER:")]
    assert report["status"] == "FAIL"
    assert len(selected) == 3 and all(row["necessity"] == "CONDITIONAL_UNRESOLVED" for row in selected)
    assert len(classification_failures) == 1
    assert report["independent_reconciliation"]["status"] == "PASS"


def test_empty_unresolved_classification_does_not_expand_obligation_denominator(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    manifest = completed_manifest(root, "")
    manifest["objects"][0]["classification"]["LEDGER"].update(
        status="UNRESOLVED", reason="Applicability has not been selected.", evidence=[])
    manifest["objects"][0]["classification"]["LEDGER"].pop("refutation")
    save(root, manifest)
    report = assess(root)
    assessment = report["object_assessments"][0]
    assert report["status"] == "UNKNOWN"
    assert not any(row["kind"] == "LEDGER" for row in report["required_obligations"])
    assert "LEDGER" not in assessment["effective_kinds"]
    assert report["independent_reconciliation"]["status"] == "PASS"


def test_current_evidence_cross_root_role_accumulates_obligations_without_casting(
    tmp_path: Path,
) -> None:
    from verifier.runtime.namespace_admission import assess
    from verifier.runtime.namespace_contracts import namespace_registry, requirements_for

    root = repository(tmp_path, "def decide(value): return bool(value)\n")
    manifest = completed_manifest(root, "")
    row = manifest["objects"][0]
    evidence = row["classification"]["LEDGER"]["evidence"]
    row["classification"]["VERIFIER"] = {
        "status": "APPLIES",
        "reason": "This source computes one bounded Boolean decision over its supplied value.",
        "evidence": evidence,
    }
    for obligation in requirements_for(namespace_registry(), ["VERIFIER"]):
        row["obligations"][obligation["id"]] = {
            "reason": "The bounded decision surface requires this explicit verifier boundary.",
            "evidence": evidence,
            "declaration": {
                field: "The specimen declares this bounded " + field + " boundary."
                for field in obligation["declaration_fields"]
            },
        }
    save(root, manifest)

    report = assess(root)
    assessment = report["object_assessments"][0]
    assert report["status"] == "PASS"
    assert_admitted_only_as_documented(report)
    assert row["kind"] != "VERIFIER" and row["specializations"] == []
    assert "VERIFIER" in assessment["effective_kinds"]
    assert "VERIFIER" in assessment["necessary_kinds"]
    assert not any(
        finding["code"] == "NAMESPACE_LABEL_CONTRADICTS_SOURCE"
        and finding["object_id"] == row["object_id"]
        for finding in report["findings"]
    )
    assert report["independent_reconciliation"]["status"] == "PASS"


@pytest.mark.parametrize("damage", ("missing", "stale"))
def test_cross_root_role_without_current_owned_evidence_remains_blocking(
    tmp_path: Path,
    damage: str,
) -> None:
    from verifier.runtime.namespace_admission import assess

    root = repository(tmp_path, "def decide(value): return bool(value)\n")
    manifest = completed_manifest(root, "")
    row = manifest["objects"][0]
    evidence = (
        []
        if damage == "missing"
        else [{"path": "accounts.py", "sha256": "sha256:" + "0" * 64}]
    )
    row["classification"]["VERIFIER"] = {
        "status": "APPLIES",
        "reason": "This source computes one bounded Boolean decision.",
        "evidence": evidence,
    }
    save(root, manifest)

    report = assess(root)
    assert report["status"] in {"UNKNOWN", "FAIL"}
    assert any(
        finding["code"] == "NAMESPACE_CLASSIFICATION_UNRESOLVED"
        and finding["object_id"] == row["object_id"]
        and finding["explanation"].startswith("VERIFIER:")
        for finding in report["findings"]
    )
    assert any(
        finding["code"] == "NAMESPACE_LABEL_CONTRADICTS_SOURCE"
        and finding["object_id"] == row["object_id"]
        for finding in report["findings"]
    )


def test_real_cli_admits_documented_core_non_applicability_with_independent_node(tmp_path, capsys):
    root = repository(tmp_path, '__vstd_kinds__ = ("LEDGER", "TRANSACTION")\ndef post(): pass\n')
    manifest = completed_manifest(root, "LEDGER TRANSACTION")
    save(root, manifest)
    # The bounded financial kinds are APPLIES and the independent reconciler agrees.  Every
    # DOES_NOT_APPLY row carries a reason, current owned evidence, a fresh clean closure scan
    # and a clean owned effect audit, so each is admitted as DOCUMENTED, never ESTABLISHED.
    # Tier 0 then passes, yet no obligation's semantics, polish, release or deployment is claimed.
    # Exit 0 is the documented PASS code (docs/GATED_PUBLISH.md); exit 1 is rejection.
    assert main(["polish", "0", "--source-root", str(root), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "PASS"
    assert_admitted_only_as_documented(report)
    assert report["blockers"] == []
    assert report["obligation_count"] == 9
    assert len(report["required_obligations"]) == 6
    assert report["independent_reconciliation"]["status"] == "PASS"
    assert report["finalization"]["complete"] is True
    assert "not independently authenticated semantic proofs" in report["finalization"]["claim_boundary"]
    assert report["tier_1_plus_status"] == "NOT_ESTABLISHED"
    assert all(row["semantic_fulfillment"] == "NOT_ESTABLISHED" for row in report["required_obligations"])
    assert report["polished"] is False
    assert report["release_authorized"] is False
    assert report["deployment_authorized"] is False


def test_real_cli_admits_documented_non_applicability_without_any_stored_witness(tmp_path, capsys):
    # D1 as worded: a reason, current owned evidence, a fresh clean closure scan and a clean
    # effect audit.  No row stores a witness, and polish writes none: it scans and audits the
    # current owned census itself, so every DOES_NOT_APPLY is admitted as DOCUMENTED.
    root = repository(tmp_path, '__vstd_kinds__ = ("LEDGER", "TRANSACTION")\ndef post(): pass\n')
    manifest = completed_manifest(root, "LEDGER TRANSACTION", witness=False)
    assert not any("refutation" in decision for row in manifest["objects"]
                   for decision in row["classification"].values())
    save(root, manifest)
    before = (root / "objects.vstd").read_bytes()
    assert main(["polish", "0", "--source-root", str(root), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "PASS"
    assert_admitted_only_as_documented(report)
    assert report["blockers"] == []
    assert report["independent_reconciliation"]["status"] == "PASS"
    assert report["finalization"]["complete"] is True
    assert report["tier_1_plus_status"] == "NOT_ESTABLISHED"
    assert report["polished"] is False
    # No answer was authored and no witness was written: every reviewer row is unchanged.
    from verifier.runtime import namespace_manifest as manifests

    def classifications(raw: bytes) -> dict:
        value = json.loads(raw)
        value = value.get("namespace", value)
        return {row["object_id"]: row["classification"]
                for row in manifests.normalize_manifest(value)["objects"]}

    assert classifications((root / "objects.vstd").read_bytes()) == classifications(before)


def test_reason_and_hash_cannot_substitute_for_accounting_declarations(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, '__vstd_kinds__ = ("LEDGER",)\ndef post(): pass\n')
    manifest = completed_manifest(root, "LEDGER")
    binding = manifest["objects"][0]["obligations"]["LEDGER-0.2-accounting-invariants"]
    binding.pop("declaration", None)
    save(root, manifest)
    report = assess(root)
    assert report["status"] == "UNKNOWN"
    selected = next(row for row in report["required_obligations"] if row["id"] == "LEDGER-0.2-accounting-invariants")
    assert selected["missing_declaration_fields"] == ["units", "balance_rules", "rounding", "sources_and_sinks"]


@pytest.mark.parametrize("field,value,status", [
    ("rounding", "  ", "UNKNOWN"), ("rounding", None, "UNKNOWN"),
    ("roundng", "Round towards zero.", "FAIL"),
])
def test_accounting_declaration_reports_exact_missing_or_misspelled_field(tmp_path, field, value, status):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, '__vstd_kinds__ = ("LEDGER",)\ndef post(): pass\n')
    manifest = completed_manifest(root, "LEDGER")
    obligation_id = "LEDGER-0.2-accounting-invariants"
    fields = manifest["objects"][0]["obligations"][obligation_id]["declaration"]
    if value is None:
        fields.pop(field)
    else:
        fields[field] = value
    save(root, manifest)
    report = assess(root)
    assert report["status"] == status
    # Core-kind blockers may sort first; the accounting row must still name the field.
    finding = next(row for row in report["findings"] if row.get("obligation_id") == obligation_id)
    assert finding["object_id"] == "accounts.py"
    assert finding["status"] == status
    assert field in finding["next_action"]


def test_template_names_every_financial_question_without_filling_answers(tmp_path):
    from verifier.runtime.namespace_admission import build_template
    root = repository(tmp_path, '__vstd_kinds__ = ("LEDGER", "TRANSACTION")\n')
    obligations = build_template(root)["manifest"]["objects"][0]["obligations"]
    assert len(obligations) == 6
    assert sum(len(binding["declaration"]) for binding in obligations.values()) == 24
    assert all(not text for binding in obligations.values() for text in binding["declaration"].values())
    assert set(obligations["TRANSACTION-0.2-commit-and-failure"]["declaration"]) == {
        "commit", "abort", "finality", "partial_failure"}


@pytest.mark.parametrize("fields", [[], ["units", "units"], ["Units"], [""], [None]])
def test_local_contract_cannot_remove_or_ambiguously_name_questions(fields):
    from verifier.runtime.namespace_contracts import namespace_registry
    extension = {"kind": "JOURNAL", "extends": "LEDGER", "version": "1", "reason": "A journal retains ledger necessities.",
        "obligations": [{"id": "JOURNAL-0.1-retention", "name": "Retention", "reason": "Bound the replay horizon.",
            "evidence_requirement": "Bind retention behavior.", "declaration_fields": fields}]}
    with pytest.raises(ValueError, match="NAMESPACE_DECLARATION_FIELDS_INVALID"):
        namespace_registry([extension])


def test_local_named_questions_add_to_inherited_ledger_contract(tmp_path):
    from verifier.runtime.namespace_admission import build_template
    root = repository(tmp_path, '__vstd_kinds__ = ("JOURNAL",)\n')
    extension = {"kind": "JOURNAL", "extends": "LEDGER", "version": "1", "reason": "A journal retains ledger necessities.",
        "obligations": [{"id": "JOURNAL-0.1-retention", "name": "Retention", "reason": "Bound the replay horizon.",
            "evidence_requirement": "Bind retention behavior.", "declaration_fields": ["horizon", "pruning"]}]}
    obligations = build_template(root, extensions=[extension])["manifest"]["objects"][0]["obligations"]
    assert obligations["JOURNAL-0.1-retention"]["declaration"] == {"horizon": "", "pruning": ""}
    assert set(obligations["LEDGER-0.2-accounting-invariants"]["declaration"]) == {
        "units", "balance_rules", "rounding", "sources_and_sinks"}


@pytest.mark.parametrize("damage,code,status", [
    ("reason", "NAMESPACE_OBLIGATION_EVIDENCE_UNRESOLVED", "UNKNOWN"),
    ("evidence", "NAMESPACE_OBLIGATION_EVIDENCE_UNRESOLVED", "UNKNOWN"),
    ("stale", "NAMESPACE_OBLIGATION_EVIDENCE_UNRESOLVED", "FAIL"),
    ("escape", "NAMESPACE_OBLIGATION_EVIDENCE_UNRESOLVED", "FAIL"),
    ("refutation", "NAMESPACE_REFUTATION_CONTRADICTS_DECLARATION", "FAIL"),
    ("unregistered", "NAMESPACE_OBLIGATION_NOT_APPLICABLE_OR_REGISTERED", "FAIL"),
])
def test_binding_damage_is_never_promoted(tmp_path, damage, code, status):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, '__vstd_kinds__ = ("LEDGER",)\ndef post(): pass\n')
    manifest = completed_manifest(root, "LEDGER")
    row = manifest["objects"][0]
    binding = row["obligations"]["LEDGER-0.1-authoritative-history"]
    if damage == "reason":
        binding["reason"] = "  "
    elif damage == "evidence":
        binding["evidence"] = []
    elif damage == "stale":
        binding["evidence"] = [{"path": "accounts.py", "sha256": "sha256:" + "0" * 64}]
    elif damage == "escape":
        binding["evidence"] = [{"path": "../accounts.py", "sha256": "sha256:" + "0" * 64}]
    elif damage == "refutation":
        row["classification"]["LEDGER"]["status"] = "DOES_NOT_APPLY"
    else:
        row["obligations"]["LEDGER-0.99-invented"] = binding
    save(root, manifest)
    report = assess(root)
    assert report["status"] == status
    assert any(finding["code"] == code for finding in report["findings"])
    assert len(report["required_obligations"]) == 3
    assert report["finalization"]["complete"] is False


def test_negative_classification_needs_reason_and_current_owned_evidence(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    manifest = completed_manifest(root, "")
    save(root, manifest)
    report = assess(root)
    # Every bound witness on this benign source is a fresh clean scan over a clean owned
    # effect audit, and every decision keeps its reason and current owned evidence, so
    # each DOES_NOT_APPLY is admitted as DOCUMENTED, never ESTABLISHED.  No hint selects
    # an obligation here, so none is required.
    assert report["status"] == "PASS"
    assert report["required_obligations"] == []
    assert_admitted_only_as_documented(report)
    decisions = report["object_assessments"][0]["classification"]
    assert {row["kind"]: row["non_applicability"] for row in decisions}["LEDGER"] == "DOCUMENTED"
    added = ("TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER",
             "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT")
    assert all(row["non_applicability"] == "DOCUMENTED"
               for row in decisions if row["kind"] in added)
    assert all(row["semantic_classification_status"] == "NOT_ESTABLISHED" for row in report["object_assessments"][0]["classification"])
    manifest["objects"][0]["classification"]["LEDGER"]["reason"] = ""
    save(root, manifest)
    # Without its reason the claim is not admitted, and the bound witness no longer
    # matches the edited decision row, so the contradiction is FAIL with its exact code.
    changed = assess(root)
    assert changed["status"] == "FAIL"
    ledger = next(row for row in changed["object_assessments"][0]["classification"] if row["kind"] == "LEDGER")
    assert ledger["non_applicability"] == "NOT_ESTABLISHED"
    assert any(row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
               and row["object_id"] == "accounts.py" and "WRONG_ROW" in row["reason"]
               for row in changed["findings"])


def test_unselected_harness_applicability_is_attached_without_changing_tier_zero(
        tmp_path: Path) -> None:
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    save(root, completed_manifest(root, ""))
    report = assess(root)
    assert report["status"] == "PASS"
    assert_admitted_only_as_documented(report)
    assert report["obligation_count"] == 9
    assert report["harness_applicability"]["selection_status"] == "NOT_SELECTED"
    assert not any(code.startswith("PACKAGE_HARNESS_APPLICABILITY")
                   for code in report["blockers"])


def test_harness_source_drift_is_a_tier_zero_freshness_refutation(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.runtime import namespace_admission as admission
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    save(root, completed_manifest(root, ""))
    monkeypatch.setattr(admission.package_harness_applicability,
        "assess_selected_repository", lambda *args, **kwargs: {
            "selection_status": "SELECTED", "owner_object_id": "selected-harness",
            "status": "FAIL", "blockers": ["PACKAGE_HARNESS_APPLICABILITY_SOURCE_DRIFT"],
            "findings": [{"code": "DIRECT_LAUNCH_SOURCE_CHANGED", "launch_id": "changed"}],
        })
    report = admission.assess(root)
    selected = [row for row in report["findings"]
                if row["code"] == "PACKAGE_HARNESS_DIRECT_LAUNCH_SOURCE_CHANGED"]
    assert len(selected) == 1
    assert selected[0]["coordinate"] == "VSTD-T0.7" and selected[0]["status"] == "FAIL"
    assert selected[0]["obligation_id"] == (
        "VSTD-T0.7-source-and-mechanism-freshness"
    )
    assert selected[0]["rerun_argv"] == [
        "vstd", "gate", "--object", "selected-harness",
        "--obligation", "VSTD-T0.7-source-and-mechanism-freshness",
    ]
    assert report["obligation_count"] == 9


def test_node_missing_never_finalizes(tmp_path, monkeypatch):
    from verifier.runtime import namespace_admission as admission
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    save(root, completed_manifest(root, ""))
    original_which = admission.shutil.which
    # Only Node is absent; git discovery must keep its real executable.
    monkeypatch.setattr(admission.shutil, "which",
                        lambda name, *args, **kwargs: None if name == "node"
                        else original_which(name, *args, **kwargs))
    report = admission.assess(root)
    assert report["status"] == "UNKNOWN"
    # Every DOES_NOT_APPLY is DOCUMENTED, so Node is the only missing input and the
    # independent reconciliation coordinate is the only one left open.
    assert report["finalization"]["unclosed_coordinates"] == ["VSTD-T0.8"]


def test_source_mutation_during_reconciliation_fails(tmp_path, monkeypatch):
    from verifier.runtime import namespace_admission as admission
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    save(root, completed_manifest(root, ""))
    original = admission._reconcile
    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        (root / "accounts.py").write_text("def add(a, b): return a - b\n", encoding="utf-8")
        return result
    monkeypatch.setattr(admission, "_reconcile", mutate)
    report = admission.assess(root)
    assert report["status"] == "FAIL"
    assert "NAMESPACE_SOURCE_OR_MECHANISM_CHANGED" in report["blockers"]


def test_unsupported_language_is_not_implicitly_covered_by_file(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    (root / "Proof.lean").write_text("theorem identity (p : Prop) : p -> p := fun h => h\n", encoding="utf-8")
    save(root, completed_manifest(root, ""))
    report = assess(root)
    assert report["status"] == "UNKNOWN"
    assert "NAMESPACE_LANGUAGE_DISCOVERY_UNSUPPORTED" in report["blockers"]


def test_template_exclusive_create_preserves_existing_manifest(tmp_path, capsys):
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    assert main(["template", "--source-root", str(root)]) == 0
    capsys.readouterr()
    prior = (root / "objects.vstd").read_bytes()
    assert main(["template", "--source-root", str(root)]) == 1
    assert "no bytes changed" in capsys.readouterr().out
    assert (root / "objects.vstd").read_bytes() == prior


def test_version_one_cannot_bypass_current_classification(tmp_path, capsys):
    root = repository(tmp_path, '__vstd_kinds__ = ("LEDGER",)\n')
    save(root, {"schema_version": "verifier-objects-manifest-1"})
    assert main(["polish", "0", "--source-root", str(root), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert "NAMESPACE_VERSION_ONE_REQUIRES_MIGRATION" in result["blockers"]
    assert result["finalization"]["complete"] is False


def test_focused_gate_prints_exact_next_obligation_and_keeps_global_blockers(tmp_path, capsys):
    root = repository(tmp_path, '__vstd_kinds__ = ("TRANSACTION",)\ndef post(): pass\n')
    manifest = completed_manifest(root, "TRANSACTION")
    manifest["objects"][0]["obligations"]["TRANSACTION-0.3-retry-and-replay"]["reason"] = ""
    save(root, manifest)
    args = ["gate", "--object", "accounts.py", "--obligation", "TRANSACTION-0.3-retry-and-replay", "--source-root", str(root)]
    assert main(args) == 2
    output = capsys.readouterr().out
    assert "accounts.py" in output and "TRANSACTION-0.3-retry-and-replay" in output
    assert "Why required:" in output and "Next:" in output
    assert main(args + ["--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["selected_obligation"]["id"] == "TRANSACTION-0.3-retry-and-replay"
    assert report["package_admission_status"] == "UNKNOWN"


def test_every_retained_tier_zero_slug_is_a_selectable_focused_gate(tmp_path):
    """TIME.md T0.1: a rerun command that polish prints must select, not be refused.

    Focused diagnostics emit the retained slug identifiers registered by
    ``manifest_gate._admission_identities``; the gate has to resolve each of them
    to the retained row at the same coordinate rather than call it invalid.
    """
    from verifier.runtime import manifest_gate
    from verifier.runtime.namespace_admission import assess_gate
    root = repository(tmp_path, '__vstd_kinds__ = ("TRANSACTION",)\ndef post(): pass\n')
    save(root, completed_manifest(root, "TRANSACTION"))
    slugs = sorted(identifier for identifier, row in manifest_gate._admission_identities().items()
                   if row["gate_id"] != "namespace-admission")
    assert len(slugs) == 9
    refused = {}
    for slug in slugs:
        report = assess_gate("accounts.py", slug, root)
        if report["selection_status"] == "FAIL":
            refused[slug] = [row["code"] for row in report["findings"]]
    assert refused == {}
    # A namespace-only report never assessed the retained component, so a retained
    # selector resolves but cannot answer PASS for the retained proposition.
    report = assess_gate("accounts.py", "VSTD-T0.5-obligation-denominator-closure", root)
    assert report["status"] != "PASS" and report["selection_status"] == "UNKNOWN"
    assert [row["code"] for row in report["findings"]] == ["RETAINED_TIER_ZERO_COMPONENT_NOT_ASSESSED"]


def test_invalid_gate_selector_does_not_rewrite_package_admission(tmp_path):
    from verifier.runtime.namespace_admission import assess, assess_gate
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    save(root, completed_manifest(root, ""))
    report = assess_gate("missing-object", "VSTD-T0.2-namespace-admission", root)
    assert report["status"] == "FAIL"
    assert report["selection_status"] == "FAIL"
    # A selector error neither rewrites nor borrows the package admission: the package
    # result stays exactly what an unselected assessment reports, while the gate fails.
    assert report["package_admission_status"] == report["finalization"]["status"] == assess(root)["status"]
    assert report["package_admission_status"] == "PASS"


def test_unexecuted_admission_does_not_assert_that_a_selected_object_is_absent(tmp_path):
    from verifier.runtime.namespace_admission import assess_gate
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    save(root, {"schema_version": "verifier-objects-manifest-1"})
    report = assess_gate("accounts.py", "VSTD-T0.2-namespace-admission", root)
    assert report["status"] == report["selection_status"] == "UNKNOWN"
    assert report["findings"][0]["code"] == "NAMESPACE_GATE_SELECTION_UNAVAILABLE"


def test_package_profile_mismatch_is_a_structured_focused_gate_failure(
        tmp_path, monkeypatch, capsys):
    from verifier.runtime import namespace_admission as admission
    from verifier.runtime import package_admission, package_manifest

    monkeypatch.setattr(admission.manifests, "read_manifest", lambda _path: (
        b"{}", {"schema_version": package_manifest.PACKAGE_REPRESENTATION_SCHEMA}
    ))
    monkeypatch.setattr(package_admission, "assess", lambda _root: (
        (_ for _ in ()).throw(ValueError("TIER_ZERO_MANIFEST_PROFILE_DIFFERS"))
    ))
    (tmp_path / "objects.vstd").write_text("{}\n", encoding="utf-8")
    argv = ["gate", "--object", "vstd-graph", "--obligation",
            "VSTD-T0.1-canonical-manifest-admission", "--source-root", str(tmp_path)]

    assert main(argv + ["--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    finding = report["findings"][0]
    assert report["status"] == report["package_admission_status"] == "FAIL"
    assert report["selection_status"] == "UNKNOWN"
    assert finding == {
        **finding,
        "code": "TIER_ZERO_MANIFEST_PROFILE_DIFFERS",
        "status": "FAIL",
        "coordinate": "VSTD-T0.1",
        "gate_id": "manifest-admission",
        "object_id": "vstd-graph",
        "obligation_id": "VSTD-T0.1-canonical-manifest-admission",
        "reason": finding["explanation"],
        "rerun_argv": ["vstd", "gate", "--object", "vstd-graph", "--obligation",
                       "VSTD-T0.1-canonical-manifest-admission"],
    }
    assert finding["reason"].strip()
    assert finding["next_action"].strip()

    assert main(argv) == 1
    output = capsys.readouterr().out
    assert "gate=manifest-admission" in output
    assert "Reason:" in output and "Next:" in output
    assert "vstd gate --object vstd-graph --obligation VSTD-T0.1-canonical-manifest-admission" in output


@pytest.mark.parametrize(
    "code",
    (
        "CANDIDATE_SOURCE_MUTATED",
        "SOURCE_COORDINATE_MUTATED",
        "SOURCE_COORDINATE_DIFFERS",
    ),
)
def test_package_live_source_drift_is_a_structured_focused_gate_unknown(
        code, tmp_path, monkeypatch, capsys):
    """The installed/public command-line interface (CLI) must not flatten retryable drift to text FAIL."""

    from verifier.runtime import namespace_admission as admission
    from verifier.runtime import package_admission, package_manifest
    from verifier.runtime.self_polish_estate import EstateError

    monkeypatch.setattr(admission.manifests, "read_manifest", lambda _path: (
        b"{}", {"schema_version": package_manifest.PACKAGE_REPRESENTATION_SCHEMA}
    ))
    monkeypatch.setattr(package_admission, "assess", lambda _root: (
        (_ for _ in ()).throw(EstateError(code))
    ))
    (tmp_path / "objects.vstd").write_text("{}\n", encoding="utf-8")
    object_id = "vstd-amd-live-sensor"
    obligation_id = "VSTD-T0.7-source-and-mechanism-freshness"
    argv = ["gate", "--object", object_id, "--obligation", obligation_id,
            "--source-root", str(tmp_path), "--json"]

    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    finding = next(row for row in report["findings"] if row["code"] == code)
    assert report["status"] == report["package_admission_status"] == "UNKNOWN"
    assert finding == {
        **finding,
        "status": "UNKNOWN",
        "coordinate": "VSTD-T0.7",
        "gate_id": "source-freshness",
        "object_id": object_id,
        "obligation_id": obligation_id,
        "reason": finding["explanation"],
        "rerun_argv": ["vstd", "gate", "--object", object_id,
                       "--obligation", obligation_id],
    }
    assert finding["reason"].strip()
    assert finding["next_action"].strip()


def test_package_non_drift_value_error_remains_structured_fail(
        tmp_path, monkeypatch, capsys):
    """Only named live-source drift codes are retryable; other rejections fail."""

    from verifier.runtime import namespace_admission as admission
    from verifier.runtime import package_admission, package_manifest

    code = "SYNTHETIC_PACKAGE_CONTRACT_REJECTED"
    monkeypatch.setattr(admission.manifests, "read_manifest", lambda _path: (
        b"{}", {"schema_version": package_manifest.PACKAGE_REPRESENTATION_SCHEMA}
    ))
    monkeypatch.setattr(package_admission, "assess", lambda _root: (
        (_ for _ in ()).throw(ValueError(code))
    ))
    (tmp_path / "objects.vstd").write_text("{}\n", encoding="utf-8")
    object_id = "vstd-graph"
    obligation_id = "VSTD-T0.1-canonical-manifest-admission"

    assert main(["gate", "--object", object_id, "--obligation", obligation_id,
                 "--source-root", str(tmp_path), "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    finding = next(row for row in report["findings"] if row["code"] == code)
    assert report["status"] == "FAIL"
    assert finding["status"] == "FAIL"
    assert finding["object_id"] == object_id
    assert finding["obligation_id"] == obligation_id
    assert finding["rerun_argv"] == [
        "vstd", "gate", "--object", object_id, "--obligation", obligation_id,
    ]


def test_classification_finding_always_carries_its_nonblank_reason() -> None:
    from verifier.runtime.namespace_classification import finding

    result = finding(
        "NAMESPACE_EXAMPLE",
        "UNKNOWN",
        "VSTD-T0.2",
        "The exact classification is unresolved.",
        "Bind the selected source evidence.",
        object_id="subject",
    )

    assert result["reason"] == result["explanation"]


@pytest.mark.parametrize("source", [
    'class Wallet:\n    __vstd_kinds__ = ("LEDGER",)\n    async def post(self): pass\n',
    'def transfer():\n    __vstd_kinds__ = ("TRANSACTION",)\n    def apply(): pass\n',
])
def test_scope_inheritance_cannot_be_evaded_by_renaming_source_or_moving_ownership(tmp_path, source):
    from verifier.runtime.namespace_admission import assess, build_template
    root = repository(tmp_path, source)
    manifest = build_template(root)["manifest"]
    manifest["objects"][0]["specializations"] = []
    save(root, manifest)
    report = assess(root)
    assert "NAMESPACE_LABEL_CONTRADICTS_SOURCE" in report["blockers"]
    assert len(report["required_obligations"]) == 3


def test_manifest_schema_and_executable_reader_agree_on_draft(tmp_path):
    import jsonschema
    from verifier.runtime.namespace_admission import build_template
    from verifier.runtime.namespace_manifest import validate_manifest
    root = repository(tmp_path, "class Ledger: pass\n")
    manifest = build_template(root)["manifest"]
    schema = json.loads((Path(__file__).parents[1] / "src/verifier/schemas/verifier-objects-manifest-2.schema.json").read_bytes())
    jsonschema.Draft202012Validator(schema).validate(manifest)
    validate_manifest(manifest)


def test_manifest_schema_and_executable_reader_share_exact_execution_registry(tmp_path):
    """A selected installed mechanism must not pass one admission reader only."""
    import jsonschema
    from verifier.runtime.namespace_admission import build_template
    from verifier.runtime.namespace_manifest import validate_manifest
    from verifier.runtime.package_execution import mechanisms

    root = repository(tmp_path, "VALUE = 1\n")
    manifest = build_template(root)["manifest"]
    object_id = manifest["objects"][0]["object_id"]
    registered = mechanisms()
    manifest["execution_checks"] = [
        {
            "object_id": object_id,
            "mechanism": mechanism,
            "reason": "The exact installed package mechanism is explicitly selected.",
            "evidence": [],
        }
        for mechanism in registered
    ]
    schema = json.loads((
        Path(__file__).parents[1]
        / "src/verifier/schemas/verifier-objects-manifest-2.schema.json"
    ).read_bytes())
    schema_mechanisms = set(
        schema["$defs"]["execution_check"]["properties"]["mechanism"]["enum"]
    )
    assert schema_mechanisms == set(registered)
    jsonschema.Draft202012Validator(schema).validate(manifest)
    validate_manifest(manifest)

    manifest["execution_checks"][0]["mechanism"] = "unregistered-execution-mechanism"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(manifest)
    with pytest.raises(ValueError, match="PACKAGE_EXECUTION_MECHANISM_UNREGISTERED"):
        validate_manifest(manifest)


def test_graph_of_ledgers_cannot_accept_transaction_only_member(tmp_path):
    from verifier.runtime.namespace_contracts import namespace_registry
    from verifier.runtime.namespace_manifest import check_composition
    registry = namespace_registry()
    rows = [{"object_id": "books", "kind": "LEDGER", "specializations": [], "payload": {}, "operands": {}},
            {"object_id": "all-books", "kind": "GRAPH", "specializations": [],
             "payload": {"element_kind": "LEDGER"}, "operands": {"members": ["books"]}}]
    assert check_composition(rows, registry)["status"] == "PASS"
    rows[0]["kind"] = "TRANSACTION"
    with pytest.raises(ValueError, match="NAMESPACE_GRAPH_REFINEMENT_DIFFERS"):
        check_composition(rows, registry)


def test_conditional_marker_and_dynamic_surface_do_not_pass_silently(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, 'if condition:\n    __vstd_kinds__ = ("LEDGER",)\nexec(code)\n')
    save(root, completed_manifest(root, ""))
    report = assess(root)
    assert report["status"] == "UNKNOWN"
    assert "NAMESPACE_SOURCE_LABEL_UNRESOLVED" in report["blockers"]
    assert "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED" in report["blockers"]


@pytest.mark.parametrize("source", [
    '__vstd_kinds__, note = ("LEDGER",), None\n',
    'class Book: pass\nBook.__vstd_kinds__ = ("LEDGER",)\n',
])
def test_unsupported_marker_assignment_is_not_silently_ignored(tmp_path, source):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, source)
    save(root, completed_manifest(root, ""))
    report = assess(root)
    assert report["status"] == "UNKNOWN"
    assert "NAMESPACE_SOURCE_LABEL_UNRESOLVED" in report["blockers"]


def test_plain_type_introspection_does_not_claim_dynamic_interface_construction(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, 'def describe(value): return type(value).__name__\n')
    save(root, completed_manifest(root, ""))
    report = assess(root)
    assert report["status"] == "PASS"
    assert "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED" not in report["blockers"]
    assert_admitted_only_as_documented(report)


def test_custom_kind_is_live_in_template_cli_and_inherits_reasons(tmp_path, capsys):
    from verifier.runtime.tier_zero_profile import canonical_bytes
    root = repository(tmp_path, '__vstd_kinds__ = ("JOURNAL",)\ndef post(): pass\n')
    extension = {"kind": "JOURNAL", "extends": "LEDGER", "version": "1",
                 "reason": "A journal preserves ledger necessities and additionally declares its retention horizon.",
                 "obligations": [{"id": "JOURNAL-0.1-retention", "name": "Retention",
                     "reason": "Retention bounds what can be replayed.", "evidence_requirement": "Bind the retention contract."}]}
    path = root / "journal-kind.json"
    path.write_bytes(canonical_bytes(extension) + b"\n")
    assert main(["template", "--source-root", str(root), "--namespace-extension", str(path), "--json"]) == 0
    draft = json.loads(capsys.readouterr().out)
    subject = next(row for row in draft["manifest"]["objects"] if row["object_id"] == "accounts.py")
    assert subject["specializations"] == ["JOURNAL"]
    assert len(subject["obligations"]) == 4
    assert "LEDGER-0.2-accounting-invariants" in subject["obligations"]


@pytest.mark.parametrize("raw,code", [
    (b'{"schema_version":"first","schema_version":"second"}\n', "TIER_ZERO_MANIFEST_DUPLICATE_KEY"),
    (b'{"x":NaN}\n', "TIER_ZERO_MANIFEST_NONFINITE_NUMBER"),
    (b'{"x":1.0}\n', "NAMESPACE_NUMBER_NOT_PORTABLE"),
    (b'{"x":9007199254740992}\n', "NAMESPACE_INTEGER_NOT_PORTABLE"),
])
def test_portable_decoder_refuses_ambiguous_inputs(tmp_path, raw, code):
    from verifier.runtime.namespace_manifest import read_manifest
    path = tmp_path / "objects.vstd"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match=code):
        read_manifest(path)


def test_source_rename_does_not_make_declared_kind_optional(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, '__vstd_kinds__ = ("LEDGER",)\ndef ordinary(): pass\n')
    manifest = completed_manifest(root, "LEDGER")
    subject = manifest["objects"][0]
    subject["specializations"] = []
    subject["classification"]["LEDGER"]["status"] = "DOES_NOT_APPLY"
    save(root, manifest)
    report = assess(root)
    assert report["status"] == "FAIL"
    assert all(row["necessity"] == "NECESSARY" for row in report["required_obligations"])
    assert all("python:accounts.py:" in row["applicability_reason"] for row in report["required_obligations"])


def test_local_refinement_obligation_cannot_have_empty_reason():
    from verifier.runtime.namespace_contracts import namespace_registry
    extension = {"kind": "JOURNAL", "extends": "LEDGER", "version": "1", "reason": "A journal is a ledger.",
                 "obligations": [{"id": "JOURNAL-0.1-retention", "name": "Retention", "reason": " ",
                                  "evidence_requirement": "The retention boundary."}]}
    with pytest.raises(ValueError, match="REASON_REQUIRED"):
        namespace_registry([extension])


def test_registry_digest_prevents_silent_contract_substitution(tmp_path):
    from verifier.runtime.namespace_admission import assess
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    manifest = completed_manifest(root, "")
    manifest["registry_digest"] = "sha256:" + "0" * 64
    save(root, manifest)
    report = assess(root)
    assert report["status"] == "FAIL"
    assert "NAMESPACE_REGISTRY_DIGEST_DIFFERS" in report["blockers"]


def test_independent_interpreter_disagreement_is_refutation(tmp_path, monkeypatch):
    from verifier.runtime import namespace_admission as admission
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    save(root, completed_manifest(root, ""))
    monkeypatch.setattr(admission, "_reconcile", lambda *args, **kwargs: {"status": "FAIL", "reason": "Different obligation sets."})
    report = admission.assess(root)
    assert report["status"] == "FAIL"
    assert "NAMESPACE_RECONCILIATION_UNRESOLVED" in report["blockers"]


def test_template_works_before_first_git_add(tmp_path):
    from verifier.runtime.namespace_admission import build_template
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "first.py").write_text("def first(): pass\n", encoding="utf-8")
    draft = build_template(tmp_path)
    assert draft["manifest"]["objects"][0]["object_id"] == "first.py"


def test_formatter_preserves_meaning_and_never_repairs_evidence(tmp_path, capsys):
    root = repository(tmp_path, "def add(a, b): return a + b\n")
    manifest = completed_manifest(root, "")
    manifest["registry_digest"] = "intentionally-stale"
    path = root / "objects.vstd"
    before = json.dumps(manifest, indent=2).encode("utf-8")
    path.write_bytes(before)
    assert main(["format", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == manifest
    assert path.read_bytes() == before
    assert main(["format", str(path), "--write"]) == 0
    capsys.readouterr()
    assert json.loads(path.read_bytes()) == manifest
    assert path.read_bytes() != before
    assert not list(root.glob(".vstd-format-*"))


def test_formatter_refuses_duplicate_keys_without_overwriting(tmp_path, capsys):
    path = tmp_path / "objects.vstd"
    before = b'{"label":"OBJECT","label":"LEDGER"}'
    path.write_bytes(before)
    assert main(["format", str(path), "--write"]) != 0
    assert path.read_bytes() == before


def test_mechanism_binds_the_closed_effect_audit_that_gates_establishment():
    """The audit that refuses an open census is part of the installed mechanism that witnesses bind."""
    from verifier.runtime import namespace_admission
    from verifier.runtime.self_polish_estate import bytes_digest

    root = Path(namespace_admission.__file__).parent
    binding = namespace_admission.mechanism_binding()
    assert binding["runtime/package_original_kind_review.py"] == bytes_digest(
        (root / "package_original_kind_review.py").read_bytes())


def test_installed_namespace_registry_returns_an_independent_dict_per_call():
    """Every call returns an equal, independent dict, so one caller's edit cannot leak.

    The registry is rebuilt on each call (namespace_contracts.py keeps its audited pin), so
    this pins only the isolation a caller relies on, not how often contracts are built.
    """
    from verifier.runtime import namespace_contracts

    first = namespace_contracts.namespace_registry()
    second = namespace_contracts.namespace_registry()

    assert second == first and second is not first
    second.pop("OBJECT")
    assert "OBJECT" in namespace_contracts.namespace_registry()


def test_local_extension_never_leaks_into_the_installed_registry():
    from verifier.runtime import namespace_contracts

    extension = {
        "kind": "SCRATCHKIND", "extends": "OBJECT", "version": "1",
        "reason": "A local declaration used only by this test.",
        "obligations": [{
            "id": "SCRATCHKIND-0.1-scratch-contract", "name": "Scratch contract",
            "reason": "Scratch reason.", "evidence_requirement": "Scratch evidence.",
        }],
    }
    extended = namespace_contracts.namespace_registry([extension])
    assert "SCRATCHKIND" in extended
    assert "SCRATCHKIND" not in namespace_contracts.namespace_registry()
    assert len(namespace_contracts.namespace_registry()) == 38


def test_discovery_scope_reuses_an_identical_census_and_never_a_changed_one(
        tmp_path, monkeypatch) -> None:
    """Re-discovering unchanged bytes inside one command is a pure repeat; changed bytes never are."""
    from verifier.runtime import namespace_discovery as discovery

    root = repository(tmp_path, "VALUE = 1\n")
    parsed: list[int] = []
    real = discovery._python_surfaces

    def counting(*args, **kwargs):
        parsed.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(discovery, "_python_surfaces", counting)
    with discovery.discovery_scope():
        first = discovery.discover(root)
        parsed_once = len(parsed)
        assert parsed_once >= 1
        again = discovery.discover(root)
        assert len(parsed) == parsed_once
        assert again == first and again is not first and again["surfaces"] is not first["surfaces"]
        again["surfaces"].append({"surface_id": "tampered"})
        assert discovery.discover(root) == first

        (root / "accounts.py").write_text("VALUE = 2\nOTHER = 3\n", encoding="utf-8")
        changed = discovery.discover(root)
        assert len(parsed) > parsed_once
        assert changed["census"]["census_digest"] != first["census"]["census_digest"]
        assert changed != first

    parsed.clear()
    discovery.discover(root)
    discovery.discover(root)
    assert len(parsed) >= 2, "outside a scope every call re-parses the working bytes"


def test_parallel_python_discovery_is_byte_identical_to_sequential_discovery(
        tmp_path, monkeypatch) -> None:
    """Worker scheduling changes cost only; it cannot change discovery bytes."""
    from verifier.runtime import namespace_discovery as discovery
    from verifier.runtime.tier_zero_profile import canonical_bytes

    root = repository(tmp_path, "VALUE = 1\n")
    (root / "second.py").write_text(
        "class Ledger:\n    def post(self):\n        return None\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(root), "add", "second.py"], check=True)
    sequential = discovery.discover(root)

    monkeypatch.setattr(discovery, "_PARALLEL_PYTHON_THRESHOLD", 1)
    monkeypatch.setattr(discovery, "_MAX_PYTHON_WORKERS", 2)
    parallel = discovery.discover(root)

    assert canonical_bytes(parallel) == canonical_bytes(sequential)
