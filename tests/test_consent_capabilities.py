"""Consent capabilities, polish bindings and slot inventory that need no signing backend.

Verifier Standard (VSTD). These checks run where the optional signing backend (the ``cryptography`` package of the ``seal``
extra) is absent. They were moved here, with their bodies unchanged, from ``test_current_consent_checks.py`` (38 test items),
``test_public_consent.py`` (4) and ``test_consent_stages.py`` (3). Every other test of those three modules signs or verifies
an Ed25519 signature and needs the backend, so each of the three is skipped as one module where the backend is absent;
without this module the base coordinate would execute none of the three. Counts are dimensionless.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from test_current_typed_facets import KINDS
from test_optional_dependency_collection import ITEM_REPORT, MODULE_REPORT, collect_without, import_time_imports, preflight
from verifier.consent import public as public_consent_module
from verifier.consent import stages as consent_stages_module
from verifier.domains.contracts import consent_checks as consent_checks_contract

# The root of the signed family: it defines the specimen fixture and the signing helper that the other signed modules import,
# and it is skipped as a whole where the backend is absent. A module that imports it is skipped with it.
FAMILY_ROOT = "test_public_consent"
KNOWN_MEMBERS = {"test_current_consent_checks.py", "test_public_consent.py", "test_consent_stages.py"}
# Its tests that sign skip one by one, so it must keep collecting where the backend is absent.
MIXED = "test_polish_capacity.py"
# Test function name -> number of items that moved here: 4 + 8 + one per object kind + 4 + 3 = 45.
MOVED = {
    "test_current_consent_capability": 4,
    "test_polish_binds_every_consent_dependency": 8,
    "test_consent_inventory_retains_six_separate_numbered_predicates": len(KINDS),
    "test_public_key_consent_capability": 4,
    "test_distinct_stage_capability": 3,
}


def signed_family(directory: Path) -> list[str]:
    """The root module and every test module of the directory that imports it while being imported, so a later member is covered too."""
    members = [FAMILY_ROOT + ".py"]
    for path in sorted(directory.glob("test_*.py")):
        if path.name != members[0] and FAMILY_ROOT in import_time_imports(ast.parse(path.read_text(encoding="utf-8"))):
            members.append(path.name)
    return members


def contract() -> Any:
    return consent_checks_contract


def public_module():
    return public_consent_module


def stages_module():
    return consent_stages_module


@pytest.mark.parametrize("name", ["consent_checks_policy", "consent_checks_request",
    "build_consent_checks_certificate", "recheck_consent_checks_certificate"])
def test_current_consent_capability(name: str) -> None:
    assert callable(getattr(contract(), name))


@pytest.mark.parametrize("name", ["public_consent_policy", "consent_signing_bytes", "evaluate_public_consent", "recheck_public_consent"])
def test_public_key_consent_capability(name):
    assert callable(getattr(public_module(), name, None)), name


@pytest.mark.parametrize("name", ["evaluate_consent_stages", "recheck_consent_stages", "mechanism_digest"])
def test_distinct_stage_capability(name):
    assert callable(getattr(stages_module(), name, None)), name


@pytest.mark.parametrize("relative", ["domains/contracts/consent_checks.py", "consent/stages.py", "consent/public.py",
    "consent/engine.py", "core/signature_keys.py", "standard/CURRENT_CONSENT_CHECKS.md", "standard/CONSENT_STAGES.md",
    "standard/CONSENT_PUBLIC_ADMISSION.md"])
def test_polish_binds_every_consent_dependency(relative: str, monkeypatch: Any) -> None:
    from verifier.runtime.polish import mechanism_digest
    before = mechanism_digest()
    original = Path.read_bytes
    target = Path(contract().__file__).parents[2] / relative
    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged dependency\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert mechanism_digest() != before


@pytest.mark.parametrize("kind", KINDS)
def test_consent_inventory_retains_six_separate_numbered_predicates(kind: str) -> None:
    from verifier.domains.inventory import slot_inventory
    row = next(row for row in slot_inventory() if row["object_kind"] == kind and row["tier"] == 7)
    assert [item["coordinate"] for item in row["registered_objectives"]] == [kind + "-7." + str(stage) for stage in range(1, 7)]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


def test_each_signed_consent_module_skips_whole_where_the_signing_backend_is_absent_and_these_checks_still_collect() -> None:
    here = Path(__file__).resolve()
    family = signed_family(here.parent)
    assert KNOWN_MEMBERS <= set(family), family
    status, output = collect_without(frozenset({"cryptography"}), *(here.parent / name for name in family), here.parent / MIXED, here,
                                     cwd=here.parents[1])
    outcomes = {Path(node).name: outcome for outcome, node in MODULE_REPORT.findall(output)}
    assert {name: outcomes.get(name) for name in family} == dict.fromkeys(family, "skipped"), outcomes
    assert outcomes.get(here.name) == "passed" and outcomes.get(MIXED) == "passed", outcomes
    assert any(Path(item.split("::", 1)[0]).name == MIXED for item in ITEM_REPORT.findall(output)), "the mixed module collected no item"
    mine = [item.split("::", 1)[1].split("[", 1)[0] for item in ITEM_REPORT.findall(output)
            if "::" in item and Path(item.split("::", 1)[0]).name == here.name]
    assert {name: mine.count(name) for name in MOVED} == MOVED, "the moved checks must all collect where the backend is absent"
    assert not [item for item in ITEM_REPORT.findall(output) if Path(item.split("::", 1)[0]).name in family], "a signed module collected items"
    assert status == 0, f"the child process exited with status {status}"
    ok, counts, unclassified = preflight.audit_test_skips(output)
    assert ok and not unclassified, unclassified
    assert counts["OPTIONAL_DEPENDENCY_ABSENT"] == len(family), counts
