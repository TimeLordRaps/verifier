"""Admission regression for the 38-kind Verifier Standard (VSTD) namespace.

These checks establish required declarations and label preservation, not the
truth of financial or physical claims. The legacy 26-kind wire stays distinct.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from verifier.core.namespace import ObjectKind
from verifier.runtime.namespace_admission import assess, build_template
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.namespace_manifest import validate_manifest
from verifier.runtime.tier_zero_profile import canonical_bytes


ADDITIONS = (
    "LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
    "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT",
)


def subject_repo(root: Path, kinds: tuple[str, ...]) -> dict:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    # The exception proves discovery never imports the subject to obtain labels.
    (root / "subject.py").write_text(
        "__vstd_kinds__ = " + repr(kinds) + "\nraise RuntimeError('not an execution fixture')\n",
        encoding="utf-8",
    )
    return build_template(root)


def test_complete_namespace_retains_the_exact_legacy_wire_denominator():
    registry = namespace_registry()
    assert len(ObjectKind) == 26
    assert set(registry) == {kind.value for kind in ObjectKind} | set(ADDITIONS)
    assert len(registry) == 38
    assert all(registry[kind].origin == "INSTALLED" for kind in ADDITIONS)


@pytest.mark.parametrize("kind", ADDITIONS)
def test_every_added_kind_has_its_own_reasoned_named_declaration_contract(kind):
    contract = namespace_registry()[kind]
    assert contract.reason.strip() and contract.version
    assert len(contract.obligations) >= 3
    for obligation in contract.obligations:
        assert obligation.id.startswith(kind + "-0.")
        assert obligation.name.strip() and obligation.reason.strip()
        assert obligation.evidence_requirement.strip()
        assert len(obligation.declaration_fields) == len(set(obligation.declaration_fields))
        assert obligation.declaration_fields


@pytest.mark.parametrize("kind", ADDITIONS)
def test_each_kind_is_discovered_without_execution_and_cannot_be_hidden_as_object(tmp_path, kind):
    draft = subject_repo(tmp_path, (kind,))
    manifest = draft["manifest"]
    row = manifest["objects"][0]
    assert row["specializations"] == [kind]
    expected = {item.id for item in namespace_registry()[kind].obligations}
    assert set(row["obligations"]) == expected
    assert all(not text for binding in row["obligations"].values()
               for text in binding["declaration"].values())
    row["specializations"] = []
    row["classification"][kind] = {"status": "DOES_NOT_APPLY",
        "reason": "The manifest calls this OBJECT; this is deliberately not a valid refutation.",
        "evidence": draft["source_evidence"]}
    (tmp_path / "objects.vstd").write_bytes(canonical_bytes(manifest) + b"\n")
    report = assess(tmp_path)
    assert report["status"] == "FAIL"
    assert "NAMESPACE_LABEL_CONTRADICTS_SOURCE" in report["blockers"]
    assert "NAMESPACE_REFUTATION_CONTRADICTS_DECLARATION" in report["blockers"]
    assert {item["id"] for item in report["required_obligations"]} == expected
    assert all(item["necessity"] == "NECESSARY" for item in report["required_obligations"])
    assert report["independent_reconciliation"]["status"] == "PASS"


@pytest.mark.parametrize("base", [kind.value for kind in ObjectKind])
def test_generic_consequential_roles_can_accumulate_on_every_original_kind(tmp_path, base):
    draft = subject_repo(tmp_path, (base, "ROBOT", "FINBOT"))
    row = draft["manifest"]["objects"][0]
    assert row["kind"] == base
    assert row["specializations"] == ["FINBOT", "ROBOT"]
    # Shape validation is not composition or behavioral conformance. In
    # particular, this draft has not provided the original BOT/AGENT operands.
    validate_manifest(draft["manifest"])
    assert {item.split("-", 1)[0] for item in row["obligations"]} == {"ROBOT", "FINBOT"}


def test_robot_and_finbot_union_is_not_overwritten_by_simulation_role(tmp_path):
    draft = subject_repo(tmp_path, ("BOT", "ROBOT", "FINBOT"))
    registry = namespace_registry()
    expected = requirements_for(registry, ["BOT", "ROBOT", "FINBOT"])
    assert len(expected) == 6
    assert len(requirements_for(registry, ["BOT", "ROBOT", "FINBOT", "ROBOT"])) == 6
    assert set(draft["manifest"]["objects"][0]["obligations"]) == {row["id"] for row in expected}


def test_names_in_prose_do_not_manufacture_real_world_roles(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "subject.py").write_text(
        '"""ROBOT FINBOT are examples, not implemented roles."""\ndef add(a, b): return a + b\n',
        encoding="utf-8",
    )
    draft = build_template(tmp_path)
    row = draft["manifest"]["objects"][0]
    assert row["specializations"] == [] and row["obligations"] == {}
    assert set(row["classification"]) == set(namespace_registry()) - {"OBJECT"}
    assert all(item["status"] == "UNRESOLVED" for item in row["classification"].values())
    assert draft["suggestions"] == []


def test_narrower_base_specialization_still_rejects_unrelated_original_kind(tmp_path):
    draft = subject_repo(tmp_path, ("BOT",))
    extension = {"kind": "SPECIALSIM", "extends": "SIM", "version": "1",
        "reason": "A simulation-specific refinement retains simulation composition.",
        "obligations": [{"id": "SPECIALSIM-0.1-boundary", "name": "Boundary",
            "reason": "The specialized simulation needs a declared boundary.",
            "evidence_requirement": "Bind the selected simulation boundary."}]}
    from verifier.runtime.namespace_contracts import registry_document
    manifest = draft["manifest"]
    manifest["extensions"] = [extension]
    manifest["registry_digest"] = registry_document(namespace_registry([extension]))["digest"]
    manifest["objects"][0]["specializations"] = ["SPECIALSIM"]
    with pytest.raises(ValueError, match="NAMESPACE_SPECIALIZATION_BASE_DIFFERS"):
        validate_manifest(manifest)


@pytest.mark.parametrize("kind", ADDITIONS)
def test_named_kind_hint_requires_review_without_manufacturing_a_role(tmp_path, kind):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "subject.py").write_text("class " + kind.title() + ": pass\n", encoding="utf-8")
    draft = build_template(tmp_path)
    row = draft["manifest"]["objects"][0]
    assert row["kind"] == "OBJECT" and row["specializations"] == []
    assert set(row["obligations"]) == {item.id for item in namespace_registry()[kind].obligations}
    (tmp_path / "objects.vstd").write_bytes(canonical_bytes(draft["manifest"]) + b"\n")
    report = assess(tmp_path)
    assert report["status"] == "UNKNOWN"
    assert "NAMESPACE_LABEL_CONTRADICTS_SOURCE" not in report["blockers"]
    assert all(item["necessity"] == "CONDITIONAL_UNRESOLVED" for item in report["required_obligations"])
