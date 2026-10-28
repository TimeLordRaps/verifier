from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from verifier.runtime import public_cli
from verifier.runtime import namespace_exports
from verifier.runtime.tier_zero_reasoning import conditional_dispatch, reasons_dsl
from verifier.runtime.tier_zero_reasoning import binding_registry, redundancy_obligations
from verifier.runtime.tier_zero_reasoning import effect_reach_prototype
from verifier.runtime.tier_zero_reasoning import integration
from verifier.runtime.tier_zero_reasoning import replace_codec_probe
from verifier.runtime.tier_zero_reasoning import reasons_check


def _reason(path: Path, line: int, column: int) -> None:
    path.write_text(
        "reason shift-stable\n"
        f"  claim    type pkg/mod.py::target:{line}:{column} `value` str\n"
        "  basis    annotation pkg/mod.py:1\n"
        "  falsify  row expect holds\n",
        encoding="utf-8",
        newline="\n",
    )


def test_public_cli_exposes_one_integrated_reasons_assessment() -> None:
    parser = public_cli.build_parser()
    args = parser.parse_args([
        "reasons", "assess", "--root", ".",
    ])
    assert args.command == "reasons"
    assert args.reasons_command == "assess"
    assert args.subject == "nontest"
    assert args.implicit == "all"
    assert args.name_rule == "off"
    assert not hasattr(args, "reason")


def test_effect_reach_language_vocabulary_is_static_and_closed() -> None:
    source_path = Path(effect_reach_prototype.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=source_path.as_posix())

    assert namespace_exports.has_dynamic_construction(tree, closed_lazy=False) is False
    assert "import importlib" not in source
    assert "import builtins" not in source
    assert len(effect_reach_prototype.STDLIB_METHODS) == 2314
    assert {"read_text", "write_text", "parse_args"} <= effect_reach_prototype.STDLIB_METHODS


def test_reason_falsifier_edits_only_reviewed_ast_fields_and_restores() -> None:
    class Code:
        invalidations = 0

        def invalidate(self) -> None:
            self.invalidations += 1

    code = Code()
    call = ast.parse("target(first, second)", mode="eval").body
    original = call.args[0]
    replacement = ast.Name(id="replacement", ctx=ast.Load())
    patches = reasons_check.Patches(code)

    patches.set(call, "args", replacement, index=0)
    assert call.args[0] is replacement
    patches.restore()
    assert call.args[0] is original
    assert code.invalidations == 2

    with pytest.raises(ValueError, match="UNREVIEWED_FALSIFIER_AST_FIELD"):
        patches.set(call, "keywords", [], index=None)


def test_public_cli_refuses_multiple_reason_inputs() -> None:
    parser = public_cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "reasons", "assess", "--root", ".",
            "--reason", "one.vstd", "--reason", "two.vstd",
        ])


def test_integrated_assessment_only_accepts_root_reasons_vstd(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / ".git").mkdir(parents=True)
    (root / "objects.vstd").write_text("{}\n", encoding="utf-8")
    (root / "reasons.vstd").write_text("", encoding="utf-8")
    other = tmp_path / "other.vstd"
    other.write_text("", encoding="utf-8")
    with pytest.raises(
        ValueError, match="TIER_ZERO_REASONING_REASONS_MUST_BE_ROOT_REASONS_VSTD"
    ):
        integration.assess(root, other, tmp_path / "out")


def test_root_reason_selector_binds_the_single_authored_input(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "objects.vstd").write_text("{}\n", encoding="utf-8", newline="\n")
    raw = (
        "reason selected-role\n"
        "  about    selected-object\n"
        "  claim    denial selected-object ACTUATOR\n"
        "  basis    declared src/verifier/runtime/selected.py\n"
        "  note     The selected object owns no command-to-effect boundary.\n"
    ).encode("utf-8")
    (root / "reasons.vstd").write_bytes(raw)

    selection = integration.select_root_reasons(root)

    assert selection.authority == {
        "schema_version": "verifier-package-root-reason-authority-1",
        "path": "reasons.vstd",
        "sha256": integration._digest(raw),
        "authored_input_count": 1,
        "objects_registry_path": "objects.vstd",
        "only_authored_reason_input": True,
    }
    assert selection.classification_decisions == ({
        "reason_id": "selected-role",
        "object_id": "selected-object",
        "object_kind": "ACTUATOR",
        "decision": "DOES_NOT_APPLY",
    },)
    assert selection.ir_digest == reasons_dsl.ir_digest(selection.ir)


def test_root_reason_selector_capacity_covers_the_compiled_obligation_ledger() -> None:
    """The finite root ledger bound retains headroom for the package denominator."""

    assert integration._MAX_ROOT_REASONS_BYTES == 32 * 1024 * 1024


def test_root_reason_selector_refuses_duplicate_object_kind_decisions(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "objects.vstd").write_text("{}\n", encoding="utf-8", newline="\n")
    (root / "reasons.vstd").write_text(
        "reason first\n"
        "  claim    applies selected-object ACTUATOR\n"
        "  basis    declared src/verifier/runtime/selected.py\n"
        "reason second\n"
        "  claim    denial selected-object ACTUATOR\n"
        "  basis    declared src/verifier/runtime/selected.py\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        ValueError, match="PACKAGE_ROOT_REASON_DECISION_DUPLICATE"
    ):
        integration.select_root_reasons(root)


def test_root_reason_selector_refuses_incomplete_classification_reason(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "objects.vstd").write_text("{}\n", encoding="utf-8", newline="\n")
    (root / "reasons.vstd").write_text(
        "reason incomplete\n"
        "  about    selected-object\n"
        "  claim    applies selected-object ACTUATOR\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        ValueError, match="PACKAGE_ROOT_CLASSIFICATION_REASON_INCOMPLETE"
    ):
        integration.select_root_reasons(root)


def test_root_reason_applicability_answers_select_only_conservative_applies(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "objects.vstd").write_text("{}\n", encoding="utf-8", newline="\n")
    (root / "reasons.vstd").write_text(
        "reason retain-actuator\n"
        "  about    selected-object\n"
        "  claim    applies selected-object ACTUATOR\n"
        "  basis    declared objects.vstd\n"
        "  note     Retain the ACTUATOR obligations without claiming source adoption.\n"
        "\n"
        "reason deny-sensor\n"
        "  about    selected-object\n"
        "  claim    denial selected-object SENSOR\n"
        "  basis    declared objects.vstd\n"
        "  note     The denial remains documented and cannot erase obligations.\n",
        encoding="utf-8",
        newline="\n",
    )
    selection = integration.select_root_reasons(root)
    rows = [{
        "object_id": "selected-object",
        "classification": {
            "ACTUATOR": {
                "status": "UNRESOLVED",
                "reason": "Applicability remains open.",
                "evidence": [],
            },
            "SENSOR": {
                "status": "UNRESOLVED",
                "reason": "Applicability remains open.",
                "evidence": [],
            },
        },
    }]

    answers = integration.documented_applicability_answers(selection, rows)

    assert answers == ({
        "reason_id": "retain-actuator",
        "object_id": "selected-object",
        "object_kind": "ACTUATOR",
        "decision": "APPLIES",
    },)


def test_documented_applies_can_conservatively_override_compiled_denial(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "objects.vstd").write_text("{}\n", encoding="utf-8", newline="\n")
    (root / "reasons.vstd").write_text(
        "reason retain-actuator\n"
        "  about    selected-object\n"
        "  claim    applies selected-object ACTUATOR\n"
        "  basis    declared objects.vstd\n"
        "  note     Retain ACTUATOR obligations over the unestablished compiled denial.\n",
        encoding="utf-8",
        newline="\n",
    )
    selection = integration.select_root_reasons(root)
    rows = [{
        "object_id": "selected-object",
        "classification": {
            "ACTUATOR": {
                "status": "DOES_NOT_APPLY",
                "reason": "The compiler carries a denial whose absence is not established.",
                "evidence": [],
            },
        },
    }]

    assert integration.documented_applicability_answers(selection, rows) == ({
        "reason_id": "retain-actuator",
        "object_id": "selected-object",
        "object_kind": "ACTUATOR",
        "decision": "APPLIES",
    },)



def test_position_free_registry_reanchors_shift_and_refuses_ambiguity(tmp_path: Path) -> None:
    root = tmp_path / "root"
    source = root / "pkg" / "mod.py"
    source.parent.mkdir(parents=True)
    original = "def target(value: str):\n    return value.strip()\n"
    source.write_text(original, encoding="utf-8", newline="\n")
    reason = tmp_path / "reason.vstd"
    _reason(reason, 2, 12)

    compiled = binding_registry.compile_registry(root, [str(reason)])
    assert compiled["problems"] == []
    source.write_text("\n" + original, encoding="utf-8", newline="\n")
    shifted = binding_registry.rewrite(root, compiled, [str(reason)], tmp_path / "shifted")
    assert shifted["resolved"] == 2
    assert shifted["stale"] == 0

    source.write_text(
        "def target(value: str):\n    value.strip()\n    return value.strip()\n",
        encoding="utf-8",
        newline="\n",
    )
    duplicate = binding_registry.rewrite(root, compiled, [str(reason)], tmp_path / "duplicate")
    assert duplicate["stale"] >= 1
    assert any(change["next_action"] for change in duplicate["changes"] if not change["resolved"])


def test_every_falsifier_normalizes_to_one_complete_observation() -> None:
    fixture = Path(__file__).parent / "fixtures" / "tier_zero_reasoning" / "q1_reasons.vstd"
    parsed = reasons_dsl.parse(fixture.read_text(encoding="utf-8"), fixture.name)
    observations = reasons_dsl.observation_ir(parsed["ir"])
    expected = sum(len(reason.get("falsify", [])) for reason in parsed["ir"]["reasons"])
    assert len(observations["observations"]) == expected
    required = {"subject", "treatment", "witness", "expectation", "independence"}
    assert all(required <= row.keys() for row in observations["observations"])


def test_runtime_witnesses_reconcile_without_promoting_external_claims() -> None:
    check = {
        "reasons": {
            "independent": {"status": "REFUTED", "detail": "static external form"},
            "self": {"status": "REFUTED", "detail": "static external form"},
            "blind": {"status": "REFUTED", "detail": "static external form"},
        },
    }
    observations = {
        "observations": [
            {
                "id": reason + ":0",
                "expectation": "holds",
                "subject": {"reason": reason},
                "witness": {"kind": kind, "locator": reason},
            }
            for reason, kind in (
                ("independent", "test"), ("self", "test"), ("blind", "observer")
            )
        ],
    }
    receipts = {
        "receipts": [
            {"id": "independent", "status": "HOLDS", "tier5_eligible": True},
            {"id": "self", "status": "HOLDS", "tier5_eligible": False},
            {"id": "blind", "status": "UNKNOWN", "tier5_eligible": False},
        ],
    }
    result = integration._reconcile_witness_documents(check, observations, receipts)
    assert result["mechanism_status"] == "PASS"
    assert result["counts"] == {
        "OBSERVED_TIER5_ELIGIBLE": 1,
        "OBSERVED_NONINDEPENDENT": 1,
        "UNKNOWN": 1,
    }
    assert {row["claim_status"] for row in result["observations"]} == {"UNKNOWN"}
    assert result["closure_recomputation"] == "NOT_ESTABLISHED"


def test_redundancy_keep_must_bite_after_competing_support_is_deleted() -> None:
    true_backup = {
        "reason": "backup", "why": "independent fallback", "delete_basis": ["primary"],
        "support_facts": {"primary": ["typed"], "backup": ["typed"]},
        "site_requirements": {"site": ["typed"]},
    }
    fake_backup = {
        **true_backup,
        "support_facts": {"primary": ["typed"], "backup": ["unrelated"]},
    }
    assert redundancy_obligations.evaluate_keep(true_backup)["status"] == "KEEP-ADMITTED"
    assert redundancy_obligations.evaluate_keep(fake_backup)["status"] == "KEEP-REFUTED"


def test_conditional_dispatch_keeps_replace_and_codec_hooks_visible(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    source.write_text(
        "import codecs\n"
        "import copy\n"
        "import dataclasses\n"
        "def run(record, encoding):\n"
        "    dataclasses.replace(record)\n"
        "    copy.replace(record)\n"
        "    'x'.encode('utf-8')\n"
        "    'x'.encode(encoding)\n"
        "    codecs.register(lambda name: None)\n",
        encoding="utf-8",
        newline="\n",
    )
    report = conditional_dispatch.scan(tmp_path)
    rows = report["calls"]
    dataclass_row = next(row for row in rows if row["target"] == "dataclasses.replace")
    copy_row = next(row for row in rows if row["target"] == "copy.replace")
    codec_rows = [row for row in rows if row["target"] == "<receiver>.encode"]
    assert "__post_init__" in dataclass_row["hidden_dispatch"]
    assert copy_row["hidden_dispatch"] == ["__replace__"]
    assert len(codec_rows) == 2
    assert all(row["status"] == "UNKNOWN" for row in codec_rows)
    assert report["registry_mutations"][0]["operation"] == "codecs.register"
    assert report["source_files_changed_during_scan"] == []


def test_replace_codec_runtime_probe_passes_and_mutant_is_killed(tmp_path: Path) -> None:
    report = replace_codec_probe.run()
    assert report["status"] == "PASS"
    assert not report["failed"]

    mutant_output = tmp_path / "mutant.json"
    environment = os.environ.copy()
    environment["VSTD_REPLACE_CODEC_MUTANT"] = "dataclasses-replace-ignores-dunder-replace"
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(Path(replace_codec_probe.__file__).resolve()),
            str(mutant_output),
        ],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    mutant = json.loads(mutant_output.read_text(encoding="utf-8"))
    assert completed.returncode == 1
    assert mutant["status"] == "FAIL"
    assert mutant["failed"] == ["dataclasses-replace-ignores-dunder-replace"]


def test_relative_witness_fixture_has_no_machine_coordinate() -> None:
    path = Path(__file__).parent / "fixtures" / "tier_zero_reasoning" / "q1_witness_specs.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert all(":" not in row["subject_path"] for row in document.values())


def _classification_checker(cell: dict) -> reasons_check.Checker:
    checker = object.__new__(reasons_check.Checker)
    checker.code = SimpleNamespace(
        object_dump={
            "vstd-example": {
                "cells": {"ACTUATOR": cell},
            },
        },
    )
    return checker


def _classification_reason(form: str, *, basis: bool = True) -> dict:
    reason = {
        "id": "example-classification",
        "about": ["vstd-example"],
        "claim": {
            "form": form,
            "object": "vstd-example",
            "kind": "ACTUATOR",
        },
    }
    if basis:
        reason["basis"] = [{"kind": "declared", "evidence": ["review-2026-10-19"]}]
    return reason


def _obligation_checker(open_obligations: list[dict]) -> reasons_check.Checker:
    checker = object.__new__(reasons_check.Checker)
    checker.code = SimpleNamespace(
        object_dump={
            "vstd-example": {
                "cells": {"ACTUATOR": {"open": True}},
            },
        },
        open_obligations=open_obligations,
    )
    return checker


def _obligation_reason(coordinate: str = "ACTUATOR-0.1-example") -> dict:
    return {
        "id": "example-obligation",
        "about": ["vstd-example"],
        "claim": {
            "form": "obligation",
            "object": "vstd-example",
            "coordinate": coordinate,
            "decision": "REQUIRED",
        },
        "basis": [{
            "kind": "declared",
            "evidence": ["objects.vstd"],
        }],
        "note": "The compiled obligation remains required and unresolved.",
    }


def test_applies_reason_answers_open_compiled_cell_without_rewriting_it() -> None:
    checker = _classification_checker({
        "applies": False,
        "dna": False,
        "declared": False,
        "source": False,
        "consequence": False,
    })
    reason = _classification_reason("applies")
    result = checker.claim_applies(reason, reason["claim"])
    assert result["status"] == "DOCUMENTED"
    assert result["compiled_agrees"] is False
    assert result["facts"]["classification"] == [{
        "object_id": "vstd-example",
        "kind": "ACTUATOR",
        "decision": "APPLIES",
    }]


def test_denial_reason_cannot_erase_compiled_or_source_applicability() -> None:
    checker = _classification_checker({
        "applies": True,
        "dna": False,
        "declared": True,
        "source": False,
        "consequence": False,
    })
    reason = _classification_reason("denial")
    result = checker.claim_denial(reason, reason["claim"])
    assert result["status"] == "REFUTED"
    assert "cannot erase" in result["detail"]


def test_applies_reason_can_retain_obligations_over_compiled_denial() -> None:
    checker = _classification_checker({
        "applies": False,
        "dna": True,
        "declared": False,
        "source": False,
        "consequence": False,
        "open": False,
    })
    reason = _classification_reason("applies")
    result = checker.claim_applies(reason, reason["claim"])
    assert result["status"] == "DOCUMENTED"
    assert result["compiled_agrees"] is False
    assert result["compiled_conflicts"] is True
    assert "obligation retention only" in result["detail"]
    assert result["facts"]["classification"] == [{
        "object_id": "vstd-example",
        "kind": "ACTUATOR",
        "decision": "APPLIES",
    }]


def test_denial_reason_can_document_a_conflict_while_compiled_cell_is_open() -> None:
    checker = _classification_checker({
        "applies": False,
        "dna": False,
        "declared": True,
        "source": False,
        "consequence": False,
        "open": True,
    })
    reason = _classification_reason("denial")
    result = checker.claim_denial(reason, reason["claim"])
    assert result["status"] == "DOCUMENTED"
    assert result["compiled_agrees"] is False
    assert result["compiled_conflicts"] is True
    assert "open compiled classification conflict" in result["detail"]
    assert result["facts"]["classification"] == [{
        "object_id": "vstd-example",
        "kind": "ACTUATOR",
        "decision": "DOES_NOT_APPLY",
    }]


def test_classification_reason_requires_declared_evidence_basis() -> None:
    checker = _classification_checker({
        "applies": False,
        "dna": False,
        "declared": False,
        "source": False,
        "consequence": False,
    })
    reason = _classification_reason("applies", basis=False)
    result = checker.claim_applies(reason, reason["claim"])
    assert result["status"] == "REFUTED"
    assert "declared evidence basis" in result["detail"]


def test_obligation_reason_is_checked_against_the_exact_compiled_row() -> None:
    row = {
        "object_id": "vstd-example",
        "kind": "ACTUATOR",
        "obligation": "ACTUATOR-0.1-example",
        "status": "UNKNOWN",
    }
    checker = _obligation_checker([row])
    reason = _obligation_reason()

    result = checker.claim_obligation(reason, reason["claim"])

    assert result["status"] == "DOCUMENTED"
    assert result["compiled_match"] is True
    assert result["facts"]["obligation"] == [{
        "object_id": "vstd-example",
        "coordinate": "ACTUATOR-0.1-example",
        "decision": "REQUIRED",
    }]


def test_obligation_reason_remains_load_bearing_as_a_denominator_reference() -> None:
    checker = _obligation_checker([])
    reason = _obligation_reason("ACTUATOR-1.1-package-route")
    checker.reasons = {reason["id"]: reason}
    checker.results = {
        reason["id"]: {
            "status": "DOCUMENTED",
            "admitted_as": "DOCUMENTED",
        },
    }
    checker.admitted = {reason["id"]: {}}

    assert checker.load(reason["id"]) == {
        "verdict": "obligation-reference",
        "used_by": [],
    }


def test_obligation_reason_reconciliation_maps_exact_open_rows() -> None:
    reason_ir = {
        "reasons": [
            {
                "id": "example-actuator-obligation",
                "claim": {
                    "form": "obligation",
                    "object": "vstd-example",
                    "coordinate": "ACTUATOR-0.1-example",
                    "decision": "REQUIRED",
                },
            },
        ],
    }
    check = {
        "reasons": {
            "example-actuator-obligation": {
                "status": "DOCUMENTED",
                "detail": "checked exact obligation",
                "compiled_match": True,
            },
        },
    }
    objects_dump = {
        "open_obligations": [
            {
                "object_id": "vstd-example",
                "kind": "ACTUATOR",
                "obligation": "ACTUATOR-0.1-example",
                "status": "UNKNOWN",
            }
        ],
    }
    report = integration._reconcile_obligation_reason_documents(
        reason_ir, check, objects_dump
    )
    assert report["mechanism_status"] == "PASS"
    assert report["coverage_status"] == "PASS"
    assert report["counts"]["reasoned_role_pairs"] == 1
    assert report["counts"]["reasoned_obligations"] == 1
    assert report["counts"]["unreasoned_obligations"] == 0
    assert report["obligation_reasons"][0]["compiled_match"] is True


def test_obligation_reason_reconciliation_keeps_unreasoned_rows_unknown() -> None:
    report = integration._reconcile_obligation_reason_documents(
        {"reasons": []},
        {"reasons": {}},
        {
            "open_obligations": [
                {
                    "object_id": "vstd-example",
                    "kind": "POLICY",
                    "obligation": "POLICY-0.1-example",
                    "status": "FAIL",
                },
            ],
        },
    )
    assert report["mechanism_status"] == "PASS"
    assert report["coverage_status"] == "UNKNOWN"
    assert report["counts"]["evidence_unresolved_obligations"] == 1
    assert report["counts"]["unreasoned_role_pairs"] == 1


def test_obligation_reason_reconciliation_refuses_duplicate_exact_decisions() -> None:
    reasons = [{
        "id": identifier,
        "claim": {
            "form": "obligation",
            "object": "vstd-example",
            "coordinate": "SENSOR-0.1-example",
            "decision": "REQUIRED",
        },
    } for identifier in ("first", "second")]
    checked = {
        identifier: {"status": "DOCUMENTED", "compiled_match": True}
        for identifier in ("first", "second")
    }
    report = integration._reconcile_obligation_reason_documents(
        {"reasons": reasons},
        {"reasons": checked},
        {
            "open_obligations": [
                {
                    "object_id": "vstd-example",
                    "kind": "SENSOR",
                    "obligation": "SENSOR-0.1-example",
                    "status": "UNKNOWN",
                },
            ],
        },
    )
    assert report["mechanism_status"] == "FAIL"
    assert report["counts"]["duplicate_obligation_keys"] == 1


def test_obligation_reason_reconciliation_refuses_contradictory_decisions() -> None:
    parsed = reasons_dsl.parse(
        "reason required\n"
        "  about    vstd-example\n"
        "  claim    obligation vstd-example SENSOR-0.1-example REQUIRED\n"
        "  basis    declared objects.vstd\n"
        "  note     The exact compiled obligation remains required.\n"
        "reason weakening\n"
        "  about    vstd-example\n"
        "  claim    obligation vstd-example SENSOR-0.1-example DOES_NOT_APPLY\n"
        "  basis    declared objects.vstd\n"
        "  note     This attempted weakening must be refused.\n",
        "reasons.vstd",
    )

    assert [row["id"] for row in parsed["ir"]["reasons"]] == ["required"]
    assert "weakening" in parsed["malformed"]
    assert "decision must be one of REQUIRED" in parsed["malformed"]["weakening"][0]


def test_obligation_reconciliation_does_not_treat_other_tier_reasons_as_corruption() -> None:
    reason = {
        "id": "later-tier-route",
        "claim": {
            "form": "obligation",
            "object": "vstd-example",
            "coordinate": "ACTUATOR-2.1-later-route",
            "decision": "REQUIRED",
        },
    }
    report = integration._reconcile_obligation_reason_documents(
        {"reasons": [reason]},
        {"reasons": {"later-tier-route": {"status": "DOCUMENTED"}}},
        {"open_obligations": []},
    )

    assert report["mechanism_status"] == "PASS"
    assert report["coverage_status"] == "PASS"
    assert report["counts"]["out_of_denominator_obligation_reasons"] == 1
