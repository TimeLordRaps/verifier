"""Executable boundaries for DOES_NOT_APPLY refutation witnesses.

The oracle here is independent of the module under test: digests are recomputed
with local json/hashlib code, and every malformed document is re-signed so that
the intended defect, not a stale digest, is what the validator must report.
"""
from __future__ import annotations

import ast
import copy
import dataclasses
import hashlib
import json
from pathlib import Path
import os
import random
import subprocess
import sys
import time

import pytest

from verifier.runtime import namespace_refutation as nr


OWNER = "verifier.runtime.review_mod"
OWNED = "src/verifier/runtime/review_mod.py"
OWNED_HELPER = "src/verifier/runtime/review_mod_helper.py"
CALLEE = "src/verifier/runtime/callee_mod.py"
CALLEE_HELPER = "src/verifier/runtime/callee_helper.py"
OTHER = "src/verifier/runtime/other_mod.py"
MANIFEST = "objects.vstd"
ADDED_KINDS = (
    "LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
    "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT",
)
ORIGINAL_KINDS = (
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER",
    "HARDWARE", "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT",
    "ENV", "DATA", "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER",
    "MODEL", "HARNESS", "AGENT", "SIM", "BOT", "TOKEN",
)
ALL_KINDS = ORIGINAL_KINDS + ADDED_KINDS
# Independent oracle: a clean finite scan is bounded evidence, never establishment.
BOUNDED = "BOUNDED_ABSENCE_OBSERVED_NOT_NON_APPLICABILITY"

_SOURCES = {
    OWNED: (OWNER, b"owned source\n"),
    OWNED_HELPER: (OWNER, b"owned helper\n"),
    CALLEE: ("verifier.runtime.callee_mod", b"callee source\n"),
    CALLEE_HELPER: ("verifier.runtime.callee_helper", b"callee helper\n"),
    OTHER: ("verifier.runtime.other_mod", b"other source\n"),
    MANIFEST: ("verifier.namespace", b"{}\n"),
}


def _oracle_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _oracle_canon(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _resign(doc: dict) -> dict:
    body = {key: value for key, value in doc.items() if key != "witness_digest"}
    signed = dict(body)
    signed["witness_digest"] = _oracle_digest(_oracle_canon(body))
    return signed


def _inventory(overrides=None, unavailable=(), owners=None):
    overrides = overrides or {}
    owners = owners or {}
    inventory = {}
    for path, (owner, data) in _SOURCES.items():
        inventory[path] = {
            "owner": owners.get(path, owner),
            "sha256": _oracle_digest(overrides.get(path, data)),
            "available": path not in unavailable,
        }
    return inventory


def _expected(basis=nr.BASIS_EXECUTABLE_CLOSURE, **changes):
    # LEDGER is the one kind with a registered closure, so it is the default
    # subject for every executable-basis witness.
    fields = dict(
        object_id="vstd-example-object",
        kind="LEDGER",
        basis=basis,
        review_module=OWNER,
        review_mechanism_digest=_oracle_digest(b"review mechanism"),
        review_row_digest=_oracle_digest(b"review row"),
    )
    fields.update(changes)
    return nr.ExpectedReview(**fields)


def _witness(expected=None, source=(OWNED, OWNED_HELPER), callee=(CALLEE,), inventory=None):
    # Both files share the review module, so a complete owned census binds both.
    expected = expected or _expected()
    inventory = inventory if inventory is not None else _inventory()
    return nr.build_witness(expected=expected, source_paths=list(source),
                            callee_paths=list(callee), inventory=inventory)


def _anchor(path, inventory=None):
    inventory = inventory or _inventory()
    return {"path": path, "sha256": inventory[path]["sha256"]}


def _check(document, expected=None, inventory=None):
    return nr.validate_dne_witness(
        document,
        expected=expected if expected is not None else _expected(),
        inventory=inventory if inventory is not None else _inventory(),
    )


def _reader(overrides=None):
    """Bytes the fresh closure reads; defaults to the exact bytes the inventory digests."""
    overrides = overrides or {}

    def read(path):
        return overrides[path] if path in overrides else _SOURCES[path][1]

    return read


def _establish(document, expected=None, inventory=None, read=None):
    return nr.establish_dne_witness(
        document,
        expected=expected if expected is not None else _expected(),
        inventory=inventory if inventory is not None else _inventory(),
        read=read if read is not None else _reader(),
    )


def _assert_fail(verdict, code):
    assert verdict.status == nr.FAIL, verdict
    assert verdict.code == code, verdict
    assert not verdict.is_established


def _assert_unknown(verdict, code):
    assert verdict.status == nr.UNKNOWN, verdict
    assert verdict.code == code, verdict
    assert not verdict.is_established


def _assert_bounded(verdict):
    """A clean fresh scan: non-admissible UNKNOWN that keeps its PASS receipt."""
    assert verdict.status == nr.UNKNOWN, verdict
    assert verdict.code == BOUNDED, verdict
    assert not verdict.is_established
    assert verdict.receipt is not None and verdict.receipt["status"] == "PASS", verdict


# --- positive semantics -----------------------------------------------------

def test_executable_current_witness_binding_alone_is_not_established():
    # Bindings and currency are necessary, never sufficient: without a fresh
    # closure run the witness remains UNKNOWN and keeps its obligations.
    verdict = _check(_witness())
    assert verdict.status == nr.UNKNOWN
    assert verdict.code == "EXECUTION_NOT_RUN"
    assert not verdict.is_established


def test_fresh_closure_pass_is_bounded_absence_and_never_established():
    # A finite identifier and gate scan that finds nothing supports only a bounded
    # observation.  It can never remove an obligation, so no PASS establishes.
    verdict = _establish(_witness())
    _assert_bounded(verdict)
    assert verdict.receipt["closure_digest"] == nr.closure_digest("LEDGER")


def test_bounded_verdict_retains_the_fresh_receipt_identity():
    expected = _expected()
    verdict = _establish(_witness(expected=expected), expected=expected)
    receipt = verdict.receipt
    _assert_bounded(verdict)
    assert receipt["object_id"] == expected.object_id and receipt["kind"] == "LEDGER"
    assert receipt["closure_digest"] == nr.closure_digest("LEDGER")
    assert receipt["mechanism_digest"] == expected.review_mechanism_digest
    assert receipt["decision_row_digest"] == expected.review_row_digest
    assert receipt["census_digest"] == nr.value_digest(receipt["anchors"])
    assert receipt["receipt_digest"].startswith("sha256:")
    assert {anchor["path"] for anchor in receipt["anchors"]} == {OWNED, OWNED_HELPER, CALLEE}


def test_audited_witness_is_audited_not_established_never_established():
    expected = _expected(basis=nr.BASIS_AUDITED_SOURCE)
    verdict = _check(_witness(expected=expected), expected=expected)
    assert verdict.status == nr.AUDITED_NOT_ESTABLISHED
    assert verdict.code == "AUDITED_SOURCE_NOT_EXECUTABLE"
    assert not verdict.is_established
    assert verdict.status != nr.ESTABLISHED


def test_builder_binds_inventory_digests_and_sorts_anchors_deterministically():
    inventory = _inventory()
    first = _witness(source=(OWNED_HELPER, OWNED), callee=(CALLEE_HELPER, CALLEE), inventory=inventory)
    second = _witness(source=(OWNED, OWNED_HELPER), callee=(CALLEE, CALLEE_HELPER), inventory=inventory)
    assert first == second
    assert first["source_anchors"] == sorted([_anchor(OWNED, inventory), _anchor(OWNED_HELPER, inventory)],
                                             key=lambda row: row["path"])
    assert first["callee_anchors"] == sorted([_anchor(CALLEE, inventory), _anchor(CALLEE_HELPER, inventory)],
                                             key=lambda row: row["path"])
    assert first["decision_status"] == "DOES_NOT_APPLY"
    assert first["witness_digest"] == _resign(first)["witness_digest"]


def test_key_insertion_order_does_not_change_the_verdict():
    doc = _witness()
    reordered = {key: doc[key] for key in reversed(list(doc))}
    assert nr.canonical_bytes(reordered) == nr.canonical_bytes(doc)
    _assert_bounded(_establish(reordered))


def test_canonical_primitive_matches_existing_tier_zero_primitive():
    from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest

    # American Standard Code for Information Interchange (ASCII) output only: tier_zero_profile
    # writes Unicode Transformation Format, 8-bit (UTF-8), while this module escapes to ASCII.
    samples = [{"b": [1, "x"], "a": {"z": None, "y": True}}, [], "x", 0, {"k": "escaped"}]
    for sample in samples:
        assert nr.canonical_bytes(sample) == canonical_bytes(sample)
        assert nr.value_digest(sample) == value_digest(sample)
    assert nr.canonical_bytes({"x": 1}) == _oracle_canon({"x": 1})


# --- absence and unknown are never DNE ----------------------------------------

def test_absent_inputs_are_unknown_never_dne():
    _assert_unknown(nr.validate_dne_witness(None, expected=_expected(), inventory=_inventory()), "WITNESS_ABSENT")
    _assert_unknown(nr.validate_dne_witness(_witness(), expected=_expected(), inventory=None), "INVENTORY_ABSENT")
    _assert_unknown(nr.validate_dne_witness(_witness(), expected=None, inventory=_inventory()), "EXPECTED_ABSENT")


def test_only_established_is_admissible():
    assert nr.Verdict(nr.ESTABLISHED, "X", "").is_established
    for status in (nr.AUDITED_NOT_ESTABLISHED, nr.UNKNOWN, nr.FAIL):
        assert not nr.Verdict(status, "X", "").is_established
    assert nr.STATUSES == {nr.ESTABLISHED, nr.AUDITED_NOT_ESTABLISHED, nr.UNKNOWN, nr.FAIL}


# --- strict shape ---------------------------------------------------------------

@pytest.mark.parametrize("status", ["APPLIES", "UNRESOLVED", "does_not_apply", "DOES_NOT_APPLY ", "", None, 1])
def test_decision_status_must_be_exactly_does_not_apply(status):
    doc = _witness()
    doc["decision_status"] = status
    _assert_fail(_check(_resign(doc)), "UNKNOWN_DECISION")


@pytest.mark.parametrize("basis", ["EXECUTABLE", "executable_closure", "AUDITED", "", None, ["EXECUTABLE_CLOSURE"]])
def test_basis_must_be_a_known_enum(basis):
    doc = _witness()
    doc["basis"] = basis
    _assert_fail(_check(_resign(doc)), "UNKNOWN_BASIS")


def test_basis_substitution_fails_with_and_without_a_recomputed_digest():
    doc = _witness()
    doc["basis"] = nr.BASIS_AUDITED_SOURCE
    _assert_fail(_check(doc), "DIGEST_MISMATCH")
    _assert_fail(_check(_resign(doc)), "BASIS_MISMATCH")


def test_audited_document_presented_as_executable_is_not_established():
    audited_expected = _expected(basis=nr.BASIS_AUDITED_SOURCE)
    doc = _witness(expected=audited_expected, inventory=_inventory())
    verdict = _check(doc, expected=_expected(basis=nr.BASIS_EXECUTABLE_CLOSURE))
    _assert_fail(verdict, "BASIS_MISMATCH")


@pytest.mark.parametrize("mutation", ["missing_top", "extra_top", "missing_anchor_key", "extra_anchor_key",
                                      "extra_callee_key"])
def test_missing_and_extra_keys_fail_closed(mutation):
    doc = _witness()
    if mutation == "missing_top":
        del doc["review_row_digest"]
        code = "MISSING_KEY"
    elif mutation == "extra_top":
        doc["notes"] = "extra"
        code = "EXTRA_KEY"
    elif mutation == "missing_anchor_key":
        del doc["source_anchors"][0]["sha256"]
        code = "MALFORMED_ANCHOR"
    elif mutation == "extra_anchor_key":
        doc["source_anchors"][0]["owner"] = OWNER
        code = "MALFORMED_ANCHOR"
    else:
        doc["callee_anchors"][0]["role"] = "callee"
        code = "MALFORMED_ANCHOR"
    _assert_fail(_check(_resign(doc)), code)


def test_strict_types_reject_subclasses_and_container_substitutes():
    class DocSub(dict):
        pass

    class AnchorSub(dict):
        pass

    class StrSub(str):
        pass

    doc = _witness()
    _assert_fail(_check(DocSub(_resign(doc))), "WITNESS_MALFORMED")

    doc = _witness()
    doc["source_anchors"] = tuple(doc["source_anchors"])
    _assert_fail(_check(_resign(doc)), "MALFORMED_FIELD")

    doc = _witness()
    doc["source_anchors"][0] = AnchorSub(doc["source_anchors"][0])
    _assert_fail(_check(_resign(doc)), "MALFORMED_ANCHOR")

    doc = _witness()
    doc["object_id"] = StrSub(doc["object_id"])
    _assert_fail(_check(_resign(doc)), "MALFORMED_FIELD")

    doc = _witness()
    doc["schema"] = StrSub(nr.SCHEMA)
    _assert_fail(_check(_resign(doc)), "MALFORMED_FIELD")


@pytest.mark.parametrize("field,value", [
    ("object_id", "has space"),
    ("object_id", ""),
    ("kind", ""),
    ("kind", "1OBJECT"),
    ("review_module", "1starts.with.digit"),
    ("review_module", "verifier..runtime"),
    ("review_module", "verifier.runtime.review-mod"),
    ("review_mechanism_digest", "sha256:" + "A" * 64),
    ("review_mechanism_digest", "sha256:" + "a" * 63),
    ("review_row_digest", "md5:" + "a" * 32),
    ("review_row_digest", "sha256:" + "a" * 64 + "\n"),
    ("witness_digest", "sha256:" + "g" * 64),
])
def test_malformed_identity_and_digest_fields_fail(field, value):
    doc = _witness()
    doc[field] = value
    code = "MALFORMED_DIGEST" if "digest" in field else "MALFORMED_FIELD"
    _assert_fail(_check(_resign(doc) if field != "witness_digest" else doc), code)


@pytest.mark.parametrize("path", [
    "/abs/review_mod.py", "../review_mod.py", "src/../review_mod.py", "C:" "/review_mod.py",
    "src\\verifier\\review_mod.py", "./src/verifier/review_mod.py", "src//verifier/review_mod.py",
    "src/verifier/review_mod.py/", "src/verifier/review_mod.py.", "src/CON.py", "src/verifier/nul.txt",
    "", "src/verifier/review mod.py", "src/verifier/rev\u00e9.py", "src/verifier/\ud800.py",
    "..hidden/review_mod.py", "src/.hidden./review_mod.py",
], ids=[f"bad-path-{index:02d}" for index in range(17)])
def test_malformed_paths_fail_closed(path):
    doc = _witness()
    doc["source_anchors"][0]["path"] = path
    _assert_fail(_check(_resign(doc)), "MALFORMED_PATH")


def test_path_longer_than_bound_is_oversize():
    doc = _witness()
    long_path = "src/" + "a" * (nr.MAX_PATH_BYTES) + ".py"
    doc["source_anchors"][0]["path"] = long_path
    _assert_fail(_check(_resign(doc)), "OVERSIZE")


def test_non_string_numbers_and_floats_fail_closed_without_raising():
    for value in (float("nan"), float("inf"), 1.5, True, 0):
        doc = _witness()
        doc["object_id"] = value
        verdict = _check(doc)
        assert verdict.status == nr.FAIL
        assert not verdict.is_established


# --- aliasing, duplicates, order, self-reference, bounds -----------------------

def test_aliased_anchor_containers_fail():
    doc = _witness()
    doc["callee_anchors"] = doc["source_anchors"]
    _assert_fail(_check(_resign(doc)), "ALIASED_CONTAINER")


def test_same_anchor_object_in_two_positions_fails():
    doc = _witness()
    doc["callee_anchors"] = [doc["source_anchors"][0]]
    _assert_fail(_check(_resign(doc)), "ALIASED_CONTAINER")


def test_duplicate_source_path_fails():
    doc = _witness()
    doc["source_anchors"] = [_anchor(OWNED), _anchor(OWNED)]
    _assert_fail(_check(_resign(doc)), "DUPLICATE_ANCHOR")


def test_source_callee_duplicate_fails():
    doc = _witness()
    doc["callee_anchors"] = [_anchor(OWNED)]
    _assert_fail(_check(_resign(doc)), "DUPLICATE_ANCHOR")


def test_case_alias_anchor_duplicate_fails():
    doc = _witness()
    alias = OWNED.upper()
    doc["callee_anchors"] = [{"path": alias, "sha256": _anchor(OWNED)["sha256"]}]
    _assert_fail(_check(_resign(doc)), "DUPLICATE_ANCHOR")


def test_case_alias_inventory_keys_fail():
    inventory = _inventory()
    inventory["src/verifier/runtime/REVIEW_MOD.py"] = dict(inventory[OWNED])
    _assert_fail(_check(_witness(), inventory=inventory), "ALIASED_PATH")


def test_wrong_order_fails_for_source_and_callee():
    doc = _witness(source=(OWNED, OWNED_HELPER))
    doc["source_anchors"] = list(reversed(doc["source_anchors"]))
    _assert_fail(_check(_resign(doc)), "WRONG_ORDER")

    doc = _witness(callee=(CALLEE, CALLEE_HELPER))
    doc["callee_anchors"] = list(reversed(doc["callee_anchors"]))
    _assert_fail(_check(_resign(doc)), "WRONG_ORDER")


def test_missing_source_anchor_fails():
    doc = _witness()
    doc["source_anchors"] = []
    _assert_fail(_check(_resign(doc)), "MISSING_SOURCE_ANCHOR")


@pytest.mark.parametrize("unavailable", [False, True])
def test_self_referential_manifest_anchor_fails_regardless_of_availability(unavailable):
    inventory = _inventory(unavailable=(MANIFEST,) if unavailable else ())
    doc = _witness(inventory=inventory)
    doc["callee_anchors"] = [_anchor(MANIFEST, inventory)]
    _assert_fail(_check(_resign(doc), inventory=inventory), "SELF_REFERENTIAL_ANCHOR")


def test_manifest_as_owned_source_anchor_fails():
    inventory = _inventory()
    doc = _witness(inventory=inventory)
    doc["source_anchors"] = [_anchor(MANIFEST, inventory)]
    _assert_fail(_check(_resign(doc), inventory=inventory), "SELF_REFERENTIAL_ANCHOR")


def test_oversize_source_and_callee_counts_fail():
    doc = _witness()
    doc["source_anchors"] = [_anchor(OWNED)] * (nr.MAX_SOURCE_ANCHORS + 1)
    _assert_fail(_check(_resign(doc)), "OVERSIZE")

    doc = _witness()
    doc["callee_anchors"] = [_anchor(CALLEE)] * (nr.MAX_CALLEE_ANCHORS + 1)
    _assert_fail(_check(_resign(doc)), "OVERSIZE")


def test_oversize_byte_bound_is_enforced(monkeypatch):
    doc = _witness()
    monkeypatch.setattr(nr, "MAX_WITNESS_BYTES", 64)
    _assert_fail(_check(_resign(doc)), "OVERSIZE")


def test_maximum_declared_witness_fits_default_byte_bound():
    inventory = _inventory()
    doc = _witness(inventory=inventory)
    long_names = {}
    for index in range(nr.MAX_SOURCE_ANCHORS):
        name = f"src/verifier/runtime/owned_{index:03d}_" + "a" * 150 + ".py"
        inventory[name] = {"owner": OWNER, "sha256": _oracle_digest(name.encode()), "available": True}
        long_names[name] = None
    doc["source_anchors"] = sorted((_anchor(name, inventory) for name in long_names), key=lambda row: row["path"])
    doc = _resign(doc)
    assert len(_oracle_canon(doc)) <= nr.MAX_WITNESS_BYTES
    # The census here is synthetic and partial by construction, so this test checks
    # only that the largest declared binding fits and binds, not that it establishes.
    verdict = _check(doc, inventory=inventory)
    assert verdict.code == "EXECUTION_NOT_RUN", verdict


# --- identity mismatch -----------------------------------------------------------

@pytest.mark.parametrize("field,value,code", [
    ("object_id", "vstd-other-object", "WRONG_OBJECT"),
    ("kind", "OTHER", "WRONG_KIND"),
    ("review_module", "verifier.runtime.other_review", "WRONG_REVIEW_MODULE"),
    ("review_mechanism_digest", _oracle_digest(b"different mechanism"), "WRONG_MECHANISM"),
    ("review_row_digest", _oracle_digest(b"different row"), "WRONG_ROW"),
])
def test_wrong_identity_fails_even_with_a_recomputed_digest(field, value, code):
    doc = _witness()
    doc[field] = value
    _assert_fail(_check(_resign(doc)), code)


def test_expected_identity_with_different_row_fails():
    doc = _witness()
    other = _expected(review_row_digest=_oracle_digest(b"reviewed later"))
    _assert_fail(_check(doc, expected=other), "WRONG_ROW")


# --- forged digest and mutations -----------------------------------------------

def test_flipped_digest_bit_fails_as_forgery():
    doc = _witness()
    digest = doc["witness_digest"]
    flipped = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    doc["witness_digest"] = flipped
    _assert_fail(_check(doc), "DIGEST_MISMATCH")


def test_digest_copied_from_another_witness_fails():
    first = _witness(expected=_expected(object_id="vstd-first"))
    second = _witness(expected=_expected(object_id="vstd-second"))
    second["witness_digest"] = first["witness_digest"]
    _assert_fail(_check(second, expected=_expected(object_id="vstd-second")), "DIGEST_MISMATCH")


def test_uppercase_digest_is_malformed_not_normalized():
    doc = _witness()
    doc["witness_digest"] = doc["witness_digest"].upper().replace("SHA256", "sha256")
    _assert_fail(_check(doc), "MALFORMED_DIGEST")


def _mutation_cases():
    cases = []
    for field in ("schema", "object_id", "kind", "decision_status", "basis", "review_module",
                  "review_mechanism_digest", "review_row_digest"):
        cases.append((field, field))
    cases.append(("source path", "source_anchors.0.path"))
    cases.append(("source sha", "source_anchors.0.sha256"))
    cases.append(("callee path", "callee_anchors.0.path"))
    cases.append(("callee sha", "callee_anchors.0.sha256"))
    return cases


@pytest.mark.parametrize("label,target", _mutation_cases(), ids=[label for label, _ in _mutation_cases()])
def test_single_field_mutation_without_resign_is_never_established(label, target):
    doc = _witness()
    parts = target.split(".")
    node = doc
    for part in parts[:-1]:
        node = node[int(part)] if part.isdigit() else node[part]
    last = parts[-1]
    node[last] = "mutated" if last != "decision_status" else "APPLIES"
    if last == "basis":
        node[last] = nr.BASIS_AUDITED_SOURCE
    verdict = _check(doc)
    _assert_fail(verdict, verdict.code)
    assert verdict.code in {"DIGEST_MISMATCH", "MALFORMED_DIGEST", "MALFORMED_FIELD", "UNKNOWN_DECISION",
                            "MALFORMED_PATH"}, verdict


def test_stale_snapshot_callee_only_change_is_unknown_not_dne():
    witness = _witness()
    changed = _inventory(overrides={CALLEE: b"callee changed\n"})
    verdict = _check(witness, inventory=changed)
    _assert_unknown(verdict, "STALE_ANCHOR")
    assert CALLEE in verdict.detail
    assert OWNED not in verdict.detail


def test_owned_source_change_is_unknown_stale():
    witness = _witness()
    changed = _inventory(overrides={OWNED: b"owned source changed\n"})
    _assert_unknown(_check(witness, inventory=changed), "STALE_ANCHOR")


def test_source_change_read_from_disk_is_unknown(tmp_path):
    root = tmp_path / "repo"
    for path, (owner, data) in _SOURCES.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def disk_inventory():
        inventory = {}
        for path, (owner, _data) in _SOURCES.items():
            inventory[path] = {"owner": owner, "sha256": _oracle_digest((root / path).read_bytes()),
                               "available": True}
        return inventory

    witness = _witness(inventory=disk_inventory())
    disk_bytes = {path: (root / path).read_bytes() for path in _SOURCES}
    _assert_bounded(_establish(witness, inventory=disk_inventory(), read=_reader(disk_bytes)))
    (root / OWNED).write_bytes(b"owned source edited\n")
    _assert_unknown(_check(witness, inventory=disk_inventory()), "STALE_ANCHOR")


def test_anchor_removed_from_inventory_is_unknown():
    witness = _witness()
    inventory = _inventory()
    del inventory[CALLEE]
    _assert_unknown(_check(witness, inventory=inventory), "ANCHOR_NOT_IN_INVENTORY")


@pytest.mark.parametrize("unavailable_path", [OWNED, CALLEE])
def test_unavailable_anchor_is_unknown(unavailable_path):
    witness = _witness()
    _assert_unknown(_check(witness, inventory=_inventory(unavailable=(unavailable_path,))), "ANCHOR_UNAVAILABLE")


def test_wrong_owner_fails_in_builder_and_validator():
    inventory = _inventory(owners={OWNED: "verifier.runtime.other_mod"})
    with pytest.raises(nr.WitnessBuildError) as raised:
        nr.build_witness(expected=_expected(), source_paths=[OWNED], callee_paths=[CALLEE], inventory=inventory)
    assert raised.value.code == "WRONG_OWNER"

    witness = _witness()
    _assert_fail(_check(witness, inventory=_inventory(owners={OWNED: "verifier.runtime.other_mod"})), "WRONG_OWNER")


def test_fail_outranks_unknown_when_both_present():
    witness = _witness()
    changed = _inventory(overrides={CALLEE: b"callee changed\n"}, owners={OWNED: "verifier.runtime.other_mod"})
    _assert_fail(_check(witness, inventory=changed), "WRONG_OWNER")


# --- inventory and expected validation ------------------------------------------------

@pytest.mark.parametrize("inventory,code", [
    ([], "INVENTORY_MALFORMED"),
    ({OWNED: {"owner": OWNER, "sha256": _oracle_digest(b"x"), "available": 1}}, "INVENTORY_MALFORMED"),
    ({OWNED: {"owner": OWNER, "sha256": _oracle_digest(b"x"), "available": True, "extra": 1}}, "INVENTORY_MALFORMED"),
    ({OWNED: {"owner": "1bad", "sha256": _oracle_digest(b"x"), "available": True}}, "INVENTORY_MALFORMED"),
    ({OWNED: {"owner": OWNER, "sha256": "sha256:XYZ", "available": True}}, "INVENTORY_MALFORMED"),
    ({"/abs.py": {"owner": OWNER, "sha256": _oracle_digest(b"x"), "available": True}}, "INVENTORY_MALFORMED"),
    ({OWNED: ["not", "a", "dict"]}, "INVENTORY_MALFORMED"),
])
def test_malformed_inventory_fails_closed(inventory, code):
    _assert_fail(_check(_witness(), inventory=inventory), code)


def test_inventory_oversize_fails(monkeypatch):
    witness = _witness()
    monkeypatch.setattr(nr, "MAX_INVENTORY_ENTRIES", 3)
    _assert_fail(_check(witness), "INVENTORY_OVERSIZE")


@pytest.mark.parametrize("expected", [
    "not an expected review",
    _expected(basis="AUDITED"),
    _expected(object_id="has space"),
    _expected(review_mechanism_digest="sha256:short"),
])
def test_malformed_expected_identity_fails_closed(expected):
    _assert_fail(_check(_witness(), expected=expected), "EXPECTED_MALFORMED")


def test_expected_subclass_is_rejected():
    class ExpectedSub(nr.ExpectedReview):
        pass

    sub = ExpectedSub(**{field.name: getattr(_expected(), field.name)
                         for field in dataclasses.fields(nr.ExpectedReview)})
    _assert_fail(_check(_witness(), expected=sub), "EXPECTED_MALFORMED")


# --- builder refusals ----------------------------------------------------------------

@pytest.mark.parametrize("kwargs,code", [
    (dict(source_paths=[]), "MISSING_SOURCE_ANCHOR"),
    (dict(source_paths=[OWNED, OWNED]), "DUPLICATE_ANCHOR"),
    (dict(source_paths=[OWNED], callee_paths=[OWNED]), "DUPLICATE_ANCHOR"),
    (dict(source_paths=["../escape.py"]), "MALFORMED_PATH"),
    (dict(source_paths=["missing.py"]), "ANCHOR_NOT_IN_INVENTORY"),
    (dict(source_paths=[OWNED], callee_paths=["src/verifier/unknown.py"]), "ANCHOR_NOT_IN_INVENTORY"),
    (dict(source_paths=[MANIFEST]), "SELF_REFERENTIAL_ANCHOR"),
    (dict(source_paths=OWNED), "MALFORMED_FIELD"),
    (dict(source_paths=[OWNED], callee_paths=[CALLEE] * (nr.MAX_CALLEE_ANCHORS + 1)), "OVERSIZE"),
])
def test_builder_refuses_unestablished_inputs(kwargs, code):
    with pytest.raises(nr.WitnessBuildError) as raised:
        nr.build_witness(expected=_expected(), inventory=_inventory(), **{"callee_paths": [], **kwargs})
    assert raised.value.code == code


def test_builder_refuses_unavailable_anchor():
    with pytest.raises(nr.WitnessBuildError) as raised:
        nr.build_witness(expected=_expected(), source_paths=[OWNED], callee_paths=[CALLEE],
                         inventory=_inventory(unavailable=(CALLEE,)))
    assert raised.value.code == "ANCHOR_UNAVAILABLE"


def test_builder_output_for_audited_basis_is_never_established():
    expected = _expected(basis=nr.BASIS_AUDITED_SOURCE)
    doc = _witness(expected=expected)
    assert _check(doc, expected=expected).status == nr.AUDITED_NOT_ESTABLISHED


# --- purity, dependency and non-mutation ---------------------------------------------

def test_validator_performs_no_implicit_reads(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("implicit read attempted")

    doc = _witness()
    monkeypatch.setattr("builtins.open", refuse)
    monkeypatch.setattr(Path, "read_bytes", refuse)
    monkeypatch.setattr(Path, "read_text", refuse)
    monkeypatch.setattr(os, "getcwd", refuse)
    monkeypatch.setattr(os, "environ", {})
    verdict = _establish(doc)
    # Restore before asserting: pytest's failure report itself calls os.getcwd.
    monkeypatch.undo()
    _assert_bounded(verdict)


def test_module_is_stdlib_only_and_does_not_import_verifier():
    source = Path(nr.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    # io/tokenize provide in-memory Python lexing; unicodedata provides pure text
    # normalization. None grants filesystem, environment, network, or process access.
    allowed = {"__future__", "dataclasses", "hashlib", "io", "json", "re", "time", "tokenize",
               "typing", "unicodedata"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            imported.add((node.module or "").split(".")[0])
    assert imported <= allowed, imported
    forbidden_names = {"open", "Path", "os", "subprocess", "importlib", "eval", "exec"}
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not (names & forbidden_names), names & forbidden_names


def test_importing_module_does_not_load_namespace_modules():
    src = str(Path(nr.__file__).resolve().parents[2])
    code = ("import sys, verifier.runtime.namespace_refutation as m;"
            "print(sorted(k for k in sys.modules if k.startswith('verifier.runtime.namespace')))")
    env = dict(os.environ, PYTHONPATH=src)
    completed = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env,
                               timeout=60, check=True)
    assert completed.stdout.strip() == "['verifier.runtime.namespace_refutation']"


def test_inputs_are_not_mutated_and_validation_is_repeatable():
    doc = _witness()
    inventory = _inventory()
    expected = _expected()
    snapshot = (copy.deepcopy(doc), copy.deepcopy(inventory), copy.deepcopy(expected))
    first = nr.validate_dne_witness(doc, expected=expected, inventory=inventory)
    second = nr.validate_dne_witness(doc, expected=expected, inventory=inventory)
    assert first == second
    assert (doc, inventory, expected) == snapshot


def test_seeded_mutation_probe_never_establishes_a_changed_document():
    rng = random.Random(20261016)
    base = _witness()
    inventory = _inventory()
    expected = _expected()
    junk = [None, 0, -7, True, 1.5, "", " ", "x" * 300, "\u2028", "\ud800", [], {}, ["a"],
            {"path": "x"}, "sha256:" + "A" * 64, "DOES_NOT_APPLY", MANIFEST, OWNED, CALLEE, "EXECUTABLE"]
    top_keys = sorted(base)
    seen_changes = 0
    for _ in range(1500):
        doc = copy.deepcopy(base)
        where = rng.randrange(4)
        value = rng.choice(junk)
        if where == 0:
            doc[rng.choice(top_keys)] = value
        elif where == 1:
            doc.pop(rng.choice(top_keys))
        elif where == 2:
            anchors = doc[rng.choice(["source_anchors", "callee_anchors"])]
            if anchors:
                anchors[0][rng.choice(["path", "sha256"])] = value
        else:
            doc["callee_anchors"].append(value)
        if rng.random() < 0.5:
            doc = _resign(doc)
        if doc == base:
            continue
        seen_changes += 1
        verdict = nr.validate_dne_witness(doc, expected=expected, inventory=inventory)
        assert verdict.status in nr.STATUSES
        assert not verdict.is_established, (doc, verdict)
    assert seen_changes > 1000


# --- fresh closure execution: only a current, registered, fresh PASS establishes ---

LEDGER_BOUNDARY = b"def append_ledger_entry(entry):\n    return entry\n"
LEDGER_BENIGN = b"def ledger_summary(entry):\n    return entry\n"


def _content_reader(content):
    """Inventory and reader both use these bytes, so only the closure decides."""
    return _reader(content), _inventory(overrides=content)


def test_closure_refutes_a_boundary_reference_even_with_a_current_witness():
    read, inventory = _content_reader({OWNED: LEDGER_BOUNDARY})
    document = _witness(inventory=inventory)
    verdict = _establish(document, inventory=inventory, read=read)
    _assert_fail(verdict, "BOUNDARY_IDENTIFIER_REFERENCED")
    assert verdict.receipt["status"] == "FAIL"


def test_benign_owned_census_is_bounded_and_not_established():
    read, inventory = _content_reader({OWNED: LEDGER_BENIGN})
    verdict = _establish(_witness(inventory=inventory), inventory=inventory, read=read)
    _assert_bounded(verdict)
    assert verdict.receipt["code"] == "NO_BOUNDARY_IDENTIFIER_REFERENCED"


@pytest.mark.parametrize("kind", ["FUTURE_KIND", "UNREGISTERED_ROLE", "CUSTOM_EXTENSION"])
def test_kind_without_a_registered_closure_is_unknown_never_dne(kind):
    expected = _expected(kind=kind)
    verdict = _establish(_witness(expected=expected), expected=expected)
    _assert_unknown(verdict, "CLOSURE_UNREGISTERED")


def test_missing_reader_is_unknown_not_established():
    verdict = nr.establish_dne_witness(_witness(), expected=_expected(), inventory=_inventory(), read=None)
    _assert_unknown(verdict, "READER_ABSENT")


def test_each_establishment_runs_the_closure_again(monkeypatch):
    calls = []
    original = nr.run_closure

    def counting(**kwargs):
        calls.append(1)
        return original(**kwargs)

    monkeypatch.setattr(nr, "run_closure", counting)
    document = _witness()
    _assert_bounded(_establish(document))
    _assert_bounded(_establish(document))
    assert len(calls) == 2


def test_stale_source_bytes_after_the_witness_are_unknown():
    read = _reader({OWNED: b"changed after the witness was bound\n"})
    _assert_unknown(_establish(_witness(), read=read), "STALE_SOURCE")


def test_partial_owned_census_keeps_obligations():
    # OWNED_HELPER has the same owner as OWNED, so an anchor naming only OWNED is partial.
    _assert_unknown(_establish(_witness(source=(OWNED,))), "PARTIAL_CENSUS")


def test_undecodable_source_is_unknown_not_a_pass():
    read, inventory = _content_reader({OWNED: b"\xff\xfe\x00 not utf-8 \x80"})
    _assert_unknown(_establish(_witness(inventory=inventory), inventory=inventory, read=read),
                    "SOURCE_UNDECODABLE")


def test_oversize_anchor_and_byte_budget_are_unknown(monkeypatch):
    read, inventory = _content_reader({OWNED: LEDGER_BENIGN})
    document = _witness(inventory=inventory)
    monkeypatch.setattr(nr, "MAX_ANCHOR_BYTES", 4)
    _assert_unknown(_establish(document, inventory=inventory, read=read), "OVERSIZE")
    monkeypatch.setattr(nr, "MAX_ANCHOR_BYTES", 1024 * 1024)
    monkeypatch.setattr(nr, "MAX_CLOSURE_BYTES", 4)
    _assert_unknown(_establish(document, inventory=inventory, read=read), "BUDGET_EXCEEDED")


def test_scanner_timeout_error_and_slow_run_are_unknown(monkeypatch):
    def timed_out(*args, **kwargs):
        raise TimeoutError("budget")

    def broken(*args, **kwargs):
        raise RuntimeError("scanner fault")

    monkeypatch.setattr(nr, "_scan_boundary_references", timed_out)
    _assert_unknown(_establish(_witness()), "EXECUTION_TIMEOUT")
    monkeypatch.setattr(nr, "_scan_boundary_references", broken)
    _assert_unknown(_establish(_witness()), "EXECUTION_ERROR")

    def slow(*args, **kwargs):
        time.sleep(0.05)
        return "PASS", "NO_BOUNDARY_IDENTIFIER_REFERENCED", ""

    monkeypatch.setattr(nr, "_scan_boundary_references", slow)
    monkeypatch.setattr(nr, "MAX_CLOSURE_SECONDS", 0.01)
    _assert_unknown(_establish(_witness()), "EXECUTION_TIMEOUT")


def test_checker_swap_is_detected_by_the_pinned_closure_digest(monkeypatch):
    monkeypatch.setitem(nr._CLOSURES, "LEDGER", nr.Closure(
        closure_id="verifier.closure.swapped", kind="LEDGER",
        identifiers=frozenset({"unrelated_name"}), claim="swapped"))
    _assert_unknown(_establish(_witness()), "CLOSURE_PIN_MISMATCH")


def test_mutated_checker_semantics_cannot_pass_a_boundary_reference(monkeypatch):
    original = nr._CLOSURES["LEDGER"]
    monkeypatch.setitem(nr._CLOSURES, "LEDGER", dataclasses.replace(
        original, identifiers=original.identifiers - {"append_ledger_entry"}))
    read, inventory = _content_reader({OWNED: LEDGER_BOUNDARY})
    verdict = _establish(_witness(inventory=inventory), inventory=inventory, read=read)
    assert not verdict.is_established
    _assert_unknown(verdict, "CLOSURE_PIN_MISMATCH")


def test_pinned_closure_digest_matches_the_registered_definition():
    for kind in ALL_KINDS:
        assert nr.closure_digest(kind) == nr._PINNED_CLOSURE_DIGESTS[kind], kind
    assert nr.closure_digest("FUTURE_KIND") is None


def _receipt_for(object_id="vstd-example-object", kind="LEDGER"):
    expected = _expected(object_id=object_id, kind=kind)
    return _establish(_witness(expected=expected), expected=expected).receipt


def test_replayed_receipt_from_another_object_or_kind_is_refused(monkeypatch):
    # Build donors before patching run_closure, so their fixtures run the real closure.
    donor = _receipt_for(object_id="another-object")
    other_kind = {**_receipt_for(kind="LEDGER"), "kind": "TRANSACTION"}
    monkeypatch.setattr(nr, "run_closure", lambda **kwargs: dict(donor))
    _assert_fail(_establish(_witness()), "RECEIPT_REPLAYED")
    monkeypatch.setattr(nr, "run_closure", lambda **kwargs: dict(other_kind))
    _assert_fail(_establish(_witness()), "RECEIPT_DIGEST_MISMATCH")


def test_forged_receipt_without_recomputed_digest_is_refused(monkeypatch):
    real = _receipt_for()
    forged = {**real, "status": "PASS", "code": "NO_BOUNDARY_IDENTIFIER_REFERENCED", "anchors": []}
    monkeypatch.setattr(nr, "run_closure", lambda **kwargs: dict(forged))
    _assert_fail(_establish(_witness()), "RECEIPT_DIGEST_MISMATCH")


def test_receipt_for_a_stale_census_is_unknown(monkeypatch):
    stale = _receipt_for()
    stale = {**stale, "anchors": [{"path": OWNED, "sha256": _oracle_digest(b"earlier bytes\n")}]}
    stale = {**stale, "census_digest": value_digest_for(stale["anchors"])}
    stale = {**stale, "receipt_digest": _oracle_digest(_oracle_canon(
        {key: value for key, value in stale.items() if key != "receipt_digest"}))}
    monkeypatch.setattr(nr, "run_closure", lambda **kwargs: dict(stale))
    _assert_unknown(_establish(_witness()), "RECEIPT_STALE")


def value_digest_for(value):
    return _oracle_digest(_oracle_canon(value))


def test_receipt_keys_are_exact_and_typed():
    receipt = _receipt_for()
    assert set(receipt) == nr.RECEIPT_KEYS
    assert receipt["schema"] == nr.CLOSURE_SCHEMA
    assert receipt["object_id"] == "vstd-example-object"
    assert receipt["kind"] == "LEDGER"


# --- per-kind closures for the complete installed namespace -----------------

DYNAMIC_SNIPPETS = (
    "import importlib\n", "value = eval(text)\n", "value = getattr(obj, name)\n", "exec(code)\n",
)
EXTERNAL_SNIPPETS = (
    "import subprocess\n", "import socket\n", "os.system(command)\n", "import requests\n",
)
JS_OWNED = "src/verifier/runtime/review_mod.mjs"
UNSUPPORTED = "src/verifier/runtime/review_mod.rs"


def _resign_receipt(receipt, **changes):
    body = {key: value for key, value in {**receipt, **changes}.items() if key != "receipt_digest"}
    return {**body, "receipt_digest": _oracle_digest(_oracle_canon(body))}


def _census_with(path, data, *, overrides=None):
    """Owned census plus one extra owned file, with its own bytes and digest."""
    overrides = dict(overrides or {})
    inventory = _inventory(overrides=overrides)
    inventory[path] = {"owner": OWNER, "sha256": _oracle_digest(data), "available": True}
    return _reader({**overrides, path: data}), inventory


def _bound(kind, read, inventory, path=OWNED):
    expected = _expected(kind=kind)
    sources = (OWNED, OWNED_HELPER) if path == OWNED else (OWNED, OWNED_HELPER, path)
    document = _witness(expected=expected, source=sources, inventory=inventory)
    return _establish(document, expected=expected, inventory=inventory, read=read)


def test_each_installed_kind_has_its_own_registered_closure():
    for kind in ALL_KINDS:
        closure = nr._CLOSURES[kind]
        assert closure.kind == kind
        assert closure.closure_id == "verifier.closure." + kind.lower() + "-boundary-absence-2"
        assert len(closure.identifiers) >= 4
        assert closure.claim.strip()
        assert nr.closure_digest(kind) == nr._PINNED_CLOSURE_DIGESTS[kind]


def test_registry_holds_exactly_all_thirty_eight_installed_kinds():
    from verifier.core.namespace import ObjectKind
    from verifier.runtime import namespace_contracts

    added = {row.kind for row in namespace_contracts._ADDED_KINDS}
    original = {row.value for row in ObjectKind}
    assert set(nr._CLOSURES) == set(ALL_KINDS) == original | added
    assert set(nr._PINNED_CLOSURE_DIGESTS) == set(ALL_KINDS)
    assert len(ADDED_KINDS) == 12
    assert len(original) == 26 and len(ALL_KINDS) == 38
    for kind in ALL_KINDS:
        assert nr.closure_digest(kind) == nr._PINNED_CLOSURE_DIGESTS[kind]


def test_installed_closures_do_not_generalize_the_ledger_scan():
    ledger = nr._CLOSURES["LEDGER"].identifiers
    identifiers = {kind: nr._CLOSURES[kind].identifiers for kind in ALL_KINDS}
    assert len({frozenset(value) for value in identifiers.values()}) == len(ALL_KINDS)
    assert len({nr._CLOSURES[kind].closure_id for kind in ALL_KINDS}) == len(ALL_KINDS)
    for kind in ALL_KINDS:
        if kind != "LEDGER":
            assert identifiers[kind] != ledger


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_benign_census_is_bounded_for_each_installed_kind_and_never_established(kind):
    read, inventory = _content_reader({OWNED: b"def benign_summary(value):\n    return value\n"})
    verdict = _bound(kind, read, inventory)
    _assert_bounded(verdict)
    assert verdict.receipt["code"] == "NO_BOUNDARY_IDENTIFIER_REFERENCED"
    assert verdict.receipt["kind"] == kind
    assert verdict.receipt["closure_digest"] == nr.closure_digest(kind)
    assert verdict.receipt["limits_digest"] == nr.value_digest(nr._limits())


ALL_IDENTIFIER_CASES = [(kind, identifier) for kind in ALL_KINDS
                        for identifier in sorted(nr._CLOSURES[kind].identifiers)]


@pytest.mark.parametrize("kind,identifier", ALL_IDENTIFIER_CASES,
                         ids=[f"{kind}-{identifier}" for kind, identifier in ALL_IDENTIFIER_CASES])
def test_every_boundary_identifier_of_every_kind_refutes_that_kind(kind, identifier):
    # Not registry-first-only: each identifier of each kind is a separate contradiction.
    read, inventory = _content_reader({OWNED: ("def " + identifier + "(entry):\n    return entry\n").encode()})
    verdict = _bound(kind, read, inventory)
    _assert_fail(verdict, "BOUNDARY_IDENTIFIER_REFERENCED")
    assert verdict.receipt["status"] == "FAIL"
    assert identifier in verdict.detail


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_scanner_detects_the_last_sorted_identifier_of_each_kind(kind):
    # Drop-last mutation guard: the final alternative must still be scanned.
    last = sorted(nr._CLOSURES[kind].identifiers)[-1]
    read, inventory = _content_reader({OWNED: ("def " + last + "(entry):\n    return entry\n").encode()})
    _assert_fail(_bound(kind, read, inventory), "BOUNDARY_IDENTIFIER_REFERENCED")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_dropping_the_last_identifier_is_a_pin_mismatch_for_each_kind(kind, monkeypatch):
    closure = nr._CLOSURES[kind]
    last = sorted(closure.identifiers)[-1]
    monkeypatch.setitem(nr._CLOSURES, kind, dataclasses.replace(closure, identifiers=closure.identifiers - {last}))
    expected = _expected(kind=kind)
    _assert_unknown(_establish(_witness(expected=expected), expected=expected), "CLOSURE_PIN_MISMATCH")


def test_boundary_identifiers_refute_only_their_own_kind():
    for kind in ALL_KINDS:
        others = set().union(*(nr._CLOSURES[other].identifiers for other in ALL_KINDS if other != kind))
        unique = sorted(nr._CLOSURES[kind].identifiers - others)
        assert unique, kind
        read, inventory = _content_reader({OWNED: ("def " + unique[0] + "(entry):\n    return entry\n").encode()})
        _assert_fail(_bound(kind, read, inventory), "BOUNDARY_IDENTIFIER_REFERENCED")
        for other in ALL_KINDS:
            if other != kind:
                assert _bound(other, read, inventory).code == BOUNDED, (kind, other)


@pytest.mark.parametrize("kind", ALL_KINDS)
@pytest.mark.parametrize("snippet", DYNAMIC_SNIPPETS)
def test_dynamic_lookup_and_reflection_are_unknown_for_each_kind(kind, snippet):
    read, inventory = _content_reader({OWNED: ("def summary(value):\n    return value\n" + snippet).encode()})
    verdict = _bound(kind, read, inventory)
    _assert_unknown(verdict, "DYNAMIC_FEATURE_PRESENT")
    assert verdict.receipt["status"] == "UNKNOWN"
    assert not verdict.is_established


@pytest.mark.parametrize("kind", ALL_KINDS)
@pytest.mark.parametrize("snippet", EXTERNAL_SNIPPETS)
def test_subprocess_network_and_external_effects_are_unknown_for_each_kind(kind, snippet):
    read, inventory = _content_reader({OWNED: ("def summary(value):\n    return value\n" + snippet).encode()})
    _assert_unknown(_bound(kind, read, inventory), "EXTERNAL_EFFECT_PRESENT")


@pytest.mark.parametrize("kind", ("ACTOR", "COLLECTIVE", "HARDWARE"))
def test_python_prose_that_names_requests_is_not_an_external_effect(kind):
    source = (
        '"""The verifier accepts independently selected exact requests.\n\n'
        'No network client is imported or invoked by this module.\n"""\n'
        "def summary(value):\n    return value\n"
    )
    read, inventory = _content_reader({OWNED: source.encode()})

    _assert_bounded(_bound(kind, read, inventory))


@pytest.mark.parametrize("separator", (".", " . "))
def test_regex_compilation_is_not_dynamic_python_code(separator):
    source = "import re\npattern = re" + separator + "compile(r'[0-9a-f]{64}\\\\Z')\n"
    read, inventory = _content_reader({OWNED: source.encode()})

    _assert_bounded(_bound("ACTUATOR", read, inventory))


def test_builtin_compile_remains_a_dynamic_python_code_gate():
    read, inventory = _content_reader({OWNED: b"code = compile(source, name, 'exec')\n"})

    _assert_unknown(_bound("ACTUATOR", read, inventory), "DYNAMIC_FEATURE_PRESENT")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_unsupported_language_is_unknown_for_each_kind(kind):
    read, inventory = _census_with(UNSUPPORTED, b"fn summary() {}\n")
    verdict = _bound(kind, read, inventory, path=UNSUPPORTED)
    _assert_unknown(verdict, "UNSUPPORTED_LANGUAGE")


def test_javascript_census_is_gated_as_javascript():
    benign_read, benign_inventory = _census_with(JS_OWNED, b"export const value = 1;\n")
    _assert_bounded(_bound("ROBOT", benign_read, benign_inventory, path=JS_OWNED))
    dynamic_read, dynamic_inventory = _census_with(JS_OWNED, b"const loader = await import(name);\n")
    _assert_unknown(_bound("ROBOT", dynamic_read, dynamic_inventory, path=JS_OWNED), "DYNAMIC_FEATURE_PRESENT")
    external_read, external_inventory = _census_with(
        JS_OWNED, b'import { spawn } from "node:child_process";\n')
    _assert_unknown(_bound("ROBOT", external_read, external_inventory, path=JS_OWNED),
                    "EXTERNAL_EFFECT_PRESENT")


def test_data_files_are_scanned_for_identifiers_and_never_gated():
    read, inventory = _census_with("src/verifier/runtime/review_mod.md", b"prose mentions eval(text)\n")
    _assert_bounded(_bound("LEDGER", read, inventory, path="src/verifier/runtime/review_mod.md"))
    read, inventory = _census_with("src/verifier/runtime/review_mod.md", b"see append_ledger_entry\n")
    _assert_fail(_bound("LEDGER", read, inventory, path="src/verifier/runtime/review_mod.md"),
                 "BOUNDARY_IDENTIFIER_REFERENCED")


def test_boundary_reference_outranks_a_gate_hit_in_another_file():
    read, inventory = _content_reader({
        OWNED: b"import subprocess\n",
        OWNED_HELPER: b"def post_ledger_entry(entry):\n    return entry\n",
    })
    _assert_fail(_bound("LEDGER", read, inventory), "BOUNDARY_IDENTIFIER_REFERENCED")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_fake_executable_closure_is_never_established_without_a_run(kind):
    expected = _expected(kind=kind)
    document = _witness(expected=expected)
    _assert_unknown(nr.validate_dne_witness(document, expected=expected, inventory=_inventory()),
                    "EXECUTION_NOT_RUN")
    _assert_unknown(nr.establish_dne_witness(document, expected=expected, inventory=_inventory(), read=None),
                    "READER_ABSENT")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_manifest_supplied_pass_receipt_is_an_extra_key_for_each_kind(kind):
    expected = _expected(kind=kind)
    donor = _receipt_for(kind=kind)
    forged = {**_witness(expected=expected), "closure_receipt": donor}
    _assert_fail(_establish(forged, expected=expected), "EXTRA_KEY")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_forged_pass_without_recomputed_digest_is_refused_for_each_kind(kind, monkeypatch):
    identifier = sorted(nr._CLOSURES[kind].identifiers)[0]
    read, inventory = _content_reader({OWNED: ("def " + identifier + "(entry):\n    return entry\n").encode()})
    real = _bound(kind, read, inventory).receipt
    assert real["status"] == "FAIL"
    forged = {**real, "status": "PASS", "code": "NO_BOUNDARY_IDENTIFIER_REFERENCED", "detail": ""}
    monkeypatch.setattr(nr, "run_closure", lambda **kwargs: dict(forged))
    expected = _expected(kind=kind)
    _assert_fail(_establish(_witness(expected=expected, inventory=inventory), expected=expected,
                            inventory=inventory, read=read), "RECEIPT_DIGEST_MISMATCH")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_receipt_transplanted_from_another_kind_is_replayed(kind, monkeypatch):
    donor = _receipt_for(kind=next(other for other in ALL_KINDS if other != kind))
    monkeypatch.setattr(nr, "run_closure", lambda **kwargs: _resign_receipt(donor, kind=kind))
    _assert_fail(_establish(_witness(expected=_expected(kind=kind)), expected=_expected(kind=kind)),
                 "RECEIPT_REPLAYED")


@pytest.mark.parametrize("kind", ALL_KINDS)
@pytest.mark.parametrize("change", [
    {"object_id": "another-object"},
    {"decision_row_digest": "sha256:" + "1" * 64},
    {"mechanism_digest": "sha256:" + "2" * 64},
    {"closure_digest": "sha256:" + "3" * 64},
    {"limits_digest": "sha256:" + "4" * 64},
])
def test_receipt_replayed_for_another_object_row_mechanism_or_definition_is_refused(kind, change, monkeypatch):
    donor = _receipt_for(kind=kind)
    monkeypatch.setattr(nr, "run_closure", lambda **kwargs: _resign_receipt(donor, **change))
    _assert_fail(_establish(_witness(expected=_expected(kind=kind)), expected=_expected(kind=kind)),
                 "RECEIPT_REPLAYED")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_stale_source_after_the_run_is_unknown_for_each_kind(kind):
    read = _reader({OWNED: b"changed after the witness was bound\n"})
    _assert_unknown(_bound(kind, read, _inventory()), "STALE_SOURCE")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_reparse_point_or_escaping_read_is_unknown_for_each_kind(kind):
    def refused(path):
        raise OSError("CENSUS_PATH_REPARSE_POINT")

    _assert_unknown(_bound(kind, refused, _inventory()), "SOURCE_UNREADABLE")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_missing_checker_is_unknown_for_each_kind(kind, monkeypatch):
    monkeypatch.delitem(nr._CLOSURES, kind)
    expected = _expected(kind=kind)
    _assert_unknown(_establish(_witness(expected=expected), expected=expected), "CLOSURE_UNREGISTERED")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_swapped_definition_fails_the_pin_for_each_kind(kind, monkeypatch):
    original = nr._CLOSURES[kind]
    monkeypatch.setitem(nr._CLOSURES, kind, dataclasses.replace(
        original, identifiers=frozenset({"unrelated_name_for_pin"})))
    expected = _expected(kind=kind)
    _assert_unknown(_establish(_witness(expected=expected), expected=expected), "CLOSURE_PIN_MISMATCH")


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_timeout_and_scanner_fault_are_unknown_for_each_kind(kind, monkeypatch):
    def timed_out(*args, **kwargs):
        raise TimeoutError("budget")

    def broken(*args, **kwargs):
        raise RuntimeError("scanner fault")

    expected = _expected(kind=kind)
    monkeypatch.setattr(nr, "_scan_boundary_references", timed_out)
    _assert_unknown(_establish(_witness(expected=expected), expected=expected), "EXECUTION_TIMEOUT")
    monkeypatch.setattr(nr, "_scan_boundary_references", broken)
    _assert_unknown(_establish(_witness(expected=expected), expected=expected), "EXECUTION_ERROR")


@pytest.mark.parametrize("gate", ["_DYNAMIC_PATTERNS", "_EXTERNAL_PATTERNS"])
def test_checker_gate_mutation_fails_the_pin(gate, monkeypatch):
    original = getattr(nr, gate)
    monkeypatch.setattr(nr, gate, {name: () for name in original})
    read, inventory = _content_reader({OWNED: b"value = eval(text)\nimport subprocess\n"})
    _assert_unknown(_bound("ROBOT", read, inventory), "CLOSURE_PIN_MISMATCH")


def test_receipt_binds_the_limits_in_effect(monkeypatch):
    donor = _receipt_for()
    assert donor["limits_digest"].startswith("sha256:")
    monkeypatch.setattr(nr, "MAX_CLOSURE_SECONDS", 4.0)
    monkeypatch.setattr(nr, "run_closure", lambda **kwargs: dict(donor))
    _assert_fail(_establish(_witness()), "RECEIPT_REPLAYED")


def test_unknown_gate_outcome_receipts_bind_the_identity_and_code(monkeypatch):
    read, inventory = _content_reader({OWNED: b"value = eval(text)\n"})
    receipt = _bound("SENSOR", read, inventory).receipt
    assert receipt["status"] == "UNKNOWN"
    assert receipt["code"] == "DYNAMIC_FEATURE_PRESENT"
    assert receipt["kind"] == "SENSOR"
    assert receipt["closure_digest"] == nr.closure_digest("SENSOR")
    assert set(receipt) == nr.RECEIPT_KEYS


def test_refutation_layer_bounds_an_escaped_helper_and_never_establishes():
    """Characterization, not endorsement: the closure scans only owned and anchored bytes.

    A helper outside the census that writes the ledger is invisible at this layer, so
    the closed-effect precondition that refuses it belongs in classification.  Even a
    fully clean scan here yields only the bounded observation.
    """
    escaped = b"from review_mod_helper import persist\n\n\ndef record(entry):\n    return persist(entry)\n"
    read, inventory = _content_reader({OWNED: escaped})
    verdict = _establish(_witness(inventory=inventory), inventory=inventory, read=read)
    _assert_bounded(verdict)


# --- identifier variants: conservative contradictions, never a clean pass ---------

LEDGER_VARIANTS = {
    "camel": "appendLedgerEntry",
    "pascal": "AppendLedgerEntry",
    "upper_snake": "APPEND_LEDGER_ENTRY",
    "private": "_append_ledger_entry",
    "dunder": "__append_ledger_entry",
    "attribute": "self._append_ledger_entry",
    "nfkc_fullwidth": "ａｐｐｅｎｄ＿ｌｅｄｇｅｒ＿ｅｎｔｒｙ",
    "format_character": "append_ledger​_entry",
}


@pytest.mark.parametrize("variant", sorted(LEDGER_VARIANTS))
def test_identifier_variant_is_a_conservative_boundary_contradiction(variant):
    source = ("def " + LEDGER_VARIANTS[variant] + "(entry):\n    return entry\n").encode("utf-8")
    read, inventory = _content_reader({OWNED: source})
    _assert_fail(_establish(_witness(inventory=inventory), inventory=inventory, read=read),
                 "BOUNDARY_IDENTIFIER_REFERENCED")


def test_plural_identifier_variant_is_a_conservative_boundary_contradiction():
    read, inventory = _content_reader({OWNED: b"def issue_tokens(values):\n    return values\n"})
    _assert_fail(_bound("TOKEN", read, inventory), "BOUNDARY_IDENTIFIER_REFERENCED")


@pytest.mark.parametrize("neighbour", [
    "def unappend_ledger_entry(entry):\n    return entry\n",
    "def append_ledger_entry_count(entry):\n    return entry\n",
])
def test_non_variant_neighbours_are_not_contradictions(neighbour):
    # Distinct whole words are not variants: they stay bounded, never FAIL or PASS.
    read, inventory = _content_reader({OWNED: neighbour.encode()})
    verdict = _establish(_witness(inventory=inventory), inventory=inventory, read=read)
    _assert_bounded(verdict)


@pytest.mark.parametrize("residual", [
    # Residual forms the scan cannot see: they must stay non-establishing.
    "def append_ledger_entries(entry):\n    return entry\n",
    "def аppend_ledger_entry(entry):\n    return entry\n",
])
def test_unmatched_residual_spellings_never_establish(residual):
    read, inventory = _content_reader({OWNED: residual.encode("utf-8")})
    verdict = _establish(_witness(inventory=inventory), inventory=inventory, read=read)
    assert not verdict.is_established
    assert verdict.status in (nr.UNKNOWN, nr.FAIL)


# --- mechanism pin coverage: every matching and scanning component is pinned -------

PIN_COMPONENTS = [
    ("CLOSURE_ALGORITHM", "KIND_BOUNDARY_ABSENCE_V0"),
    ("_IDENTIFIER_PREFIX", r"(?<![A-Za-z0-9])_*"),
    ("_IDENTIFIER_SUFFIX", r"(?:e?s)?"),
    ("_IDENTIFIER_WORD_JOIN", "_"),
    ("_IDENTIFIER_NORMALIZATION", "NFC"),
    ("_IDENTIFIER_STRIPPED_CATEGORY", "Zs"),
    ("_DATA_SUFFIXES", frozenset({".md"})),
    ("_LANGUAGE_BY_SUFFIX", {".py": "python"}),
    ("_DYNAMIC_PATTERNS", {"javascript": (), "python": ()}),
    ("_EXTERNAL_PATTERNS", {"javascript": (), "python": ()}),
]


@pytest.mark.parametrize("name,value", PIN_COMPONENTS, ids=[name for name, _ in PIN_COMPONENTS])
def test_every_matching_and_scanning_component_is_covered_by_the_pin(name, value, monkeypatch):
    before = nr.closure_digest("LEDGER")
    monkeypatch.setattr(nr, name, value)
    assert nr.closure_digest("LEDGER") != before
    _assert_unknown(_establish(_witness()), "CLOSURE_PIN_MISMATCH")


@pytest.mark.parametrize("field,value", [
    ("claim", "The subject does something else."),
    ("closure_id", "verifier.closure.swapped"),
])
def test_every_closure_definition_field_is_covered_by_the_pin(field, value, monkeypatch):
    monkeypatch.setitem(nr._CLOSURES, "LEDGER", dataclasses.replace(nr._CLOSURES["LEDGER"], **{field: value}))
    _assert_unknown(_establish(_witness()), "CLOSURE_PIN_MISMATCH")


# --- census closure: a fresh run over an object's exact current owned census ---------
# No witness is stored or read.  The caller supplies the census paths and digests from
# its current source census; every byte read is checked against them, and the receipt
# binds the object, kind, decision row, mechanism, closure, limits and census.

CENSUS_ROW = _oracle_digest(b"review row")
CENSUS_MECHANISM = _oracle_digest(b"review mechanism")
NOTES = "docs/review_notes.md"


def _census(content):
    """A census of exactly these bytes and a reader that returns them."""
    census = {path: _oracle_digest(data) for path, data in content.items()}

    def read(path):
        return content[path]

    return census, read


def _judge(census, read, kind="LEDGER", **changes):
    fields = dict(object_id="vstd-example-object", kind=kind, decision_row_digest=CENSUS_ROW,
                  mechanism_digest=CENSUS_MECHANISM, census=census, read=read)
    fields.update(changes)
    return nr.judge_census_closure(**fields)


def test_census_closure_over_a_benign_census_is_bounded_and_binds_every_file():
    census, read = _census({OWNED: LEDGER_BENIGN, OTHER: b"x = 1\n", NOTES: b"# Plain notes\n"})
    verdict = _judge(census, read)
    _assert_bounded(verdict)
    receipt = verdict.receipt
    assert receipt["anchors"] == [{"path": path, "sha256": census[path]} for path in sorted(census)]
    assert receipt["census_digest"] == value_digest_for(receipt["anchors"])
    assert (receipt["object_id"], receipt["kind"]) == ("vstd-example-object", "LEDGER")
    assert (receipt["decision_row_digest"], receipt["mechanism_digest"]) == (CENSUS_ROW, CENSUS_MECHANISM)
    assert receipt["closure_digest"] == nr.closure_digest("LEDGER")
    assert receipt["limits_digest"] == nr.value_digest(nr._limits())
    assert receipt["receipt_digest"] == value_digest_for(
        {key: value for key, value in receipt.items() if key != "receipt_digest"})


def test_census_closure_sees_a_reference_in_any_owned_file_and_keeps_it_unadmitted():
    # No reviewer asserted that this census scans clean, so a mention is a reason to
    # review, not a contradiction of a bound claim: UNKNOWN, never PASS or DOCUMENTED.
    census, read = _census({OWNED: LEDGER_BENIGN, OTHER: LEDGER_BOUNDARY})
    verdict = _judge(census, read)
    _assert_unknown(verdict, "BOUNDARY_IDENTIFIER_REFERENCED")
    assert verdict.receipt["status"] == "FAIL"
    assert OTHER in verdict.detail and "append_ledger_entry" in verdict.detail


def test_census_closure_scans_data_files_for_identifiers_only():
    census, read = _census({OWNED: LEDGER_BENIGN, NOTES: b"prose mentions eval(text)\n"})
    _assert_bounded(_judge(census, read))
    census, read = _census({OWNED: LEDGER_BENIGN, NOTES: b"see append_ledger_entry\n"})
    _assert_unknown(_judge(census, read), "BOUNDARY_IDENTIFIER_REFERENCED")


@pytest.mark.parametrize(("path", "data", "code"), [
    (OTHER, b"value = eval(text)\n", "DYNAMIC_FEATURE_PRESENT"),
    (OTHER, b"import subprocess\n", "EXTERNAL_EFFECT_PRESENT"),
    (UNSUPPORTED, b"fn summary() {}\n", "UNSUPPORTED_LANGUAGE"),
    (JS_OWNED, b"const loader = await import(name);\n", "DYNAMIC_FEATURE_PRESENT"),
])
def test_census_closure_keeps_every_shared_gate(path, data, code):
    census, read = _census({OWNED: LEDGER_BENIGN, path: data})
    verdict = _judge(census, read)
    _assert_unknown(verdict, code)
    assert verdict.receipt["status"] == "UNKNOWN"


def test_census_closure_refuses_bytes_that_differ_from_the_census_digest():
    census, _ = _census({OWNED: LEDGER_BENIGN})
    _assert_unknown(_judge(census, lambda path: LEDGER_BOUNDARY), "STALE_SOURCE")


@pytest.mark.parametrize("changes", [
    {"object_id": "account ledger"}, {"kind": "not a kind"},
    {"decision_row_digest": "sha256:xyz"}, {"mechanism_digest": None},
])
def test_census_closure_with_an_unbindable_identity_is_unknown(changes):
    census, read = _census({OWNED: LEDGER_BENIGN})
    _assert_unknown(_judge(census, read, **changes), "REVIEW_IDENTITY_UNBINDABLE")


def test_census_closure_input_refusals_are_unknown_and_never_admitted():
    census, read = _census({OWNED: LEDGER_BENIGN})
    digest = census[OWNED]
    _assert_unknown(_judge(census, None), "READER_ABSENT")
    _assert_unknown(_judge({}, read), "CENSUS_EMPTY")
    _assert_unknown(_judge([OWNED], read), "CENSUS_MALFORMED")
    _assert_unknown(_judge({**census, MANIFEST: _oracle_digest(b"{}\n")}, read), "SELF_REFERENTIAL_CENSUS")
    _assert_unknown(_judge({"../escape.py": digest}, read), "CENSUS_PATH_UNBINDABLE")
    _assert_unknown(_judge({OWNED: "sha256:XYZ"}, read), "CENSUS_DIGEST_MALFORMED")
    _assert_unknown(_judge({OWNED: digest, OWNED.upper(): digest}, read), "DUPLICATE_ANCHOR")
    _assert_unknown(_judge(census, read, kind="FUTURE_KIND"), "CLOSURE_UNREGISTERED")


def test_census_closure_binds_dot_named_paths_and_still_refuses_dot_segments():
    # Census paths such as .github/... are ordinary owned files; only ".", "..", doubled
    # leading dots and trailing dots stay unbindable.
    census, read = _census({OWNED: LEDGER_BENIGN, ".github/review_notes.md": b"# Plain notes\n"})
    verdict = _judge(census, read)
    _assert_bounded(verdict)
    assert ".github/review_notes.md" in {anchor["path"] for anchor in verdict.receipt["anchors"]}
    digest = _oracle_digest(b"x = 1\n")
    for path in ("./notes.md", "../notes.md", ".github/../notes.md", "..github/notes.md",
                 ".github./notes.md", "src/.hidden./notes.md"):
        _assert_unknown(_judge({OWNED: census[OWNED], path: digest}, read), "CENSUS_PATH_UNBINDABLE")


def test_census_closure_pin_mismatch_is_unknown(monkeypatch):
    monkeypatch.setitem(nr._CLOSURES, "LEDGER", dataclasses.replace(
        nr._CLOSURES["LEDGER"], identifiers=frozenset({"unrelated_name_for_pin"})))
    census, read = _census({OWNED: LEDGER_BOUNDARY})
    _assert_unknown(_judge(census, read), "CLOSURE_PIN_MISMATCH")


def test_census_over_the_receipt_anchor_bound_is_unknown_without_reading():
    limit = nr.MAX_SOURCE_ANCHORS + nr.MAX_CALLEE_ANCHORS
    data = b"x = 1\n"
    census = {f"src/verifier/runtime/m{index:03d}.py": _oracle_digest(data) for index in range(limit + 1)}

    def refuse(path):
        raise AssertionError("an oversize census must not be read")

    _assert_unknown(_judge(census, refuse), "OVERSIZE")
    within = dict(sorted(census.items())[:limit])
    verdict = _judge(within, lambda path: data)
    _assert_bounded(verdict)
    assert len(verdict.receipt["anchors"]) == limit


def test_census_closure_timeout_and_scanner_fault_are_unknown(monkeypatch):
    def timed_out(*args, **kwargs):
        raise TimeoutError("budget")

    def broken(*args, **kwargs):
        raise RuntimeError("scanner fault")

    census, read = _census({OWNED: LEDGER_BENIGN})
    monkeypatch.setattr(nr, "_scan_boundary_references", timed_out)
    _assert_unknown(_judge(census, read), "EXECUTION_TIMEOUT")
    monkeypatch.setattr(nr, "_scan_boundary_references", broken)
    _assert_unknown(_judge(census, read), "EXECUTION_ERROR")


def test_census_memo_never_serves_text_or_gates_for_other_bytes():
    memo: dict = {}
    census, read = _census({OWNED: LEDGER_BENIGN})
    _assert_bounded(_judge(census, read, memo=memo))
    assert memo
    changed, read_changed = _census({OWNED: LEDGER_BOUNDARY})
    _assert_unknown(_judge(changed, read_changed, memo=memo), "BOUNDARY_IDENTIFIER_REFERENCED")
    gated, read_gated = _census({OWNED: b"value = eval(text)\n"})
    _assert_unknown(_judge(gated, read_gated, memo=memo), "DYNAMIC_FEATURE_PRESENT")


def test_census_memo_normalizes_and_gates_each_file_once_across_kinds(monkeypatch):
    normalized: list[str] = []
    gated: list[str] = []
    real_normalize, real_gate = nr._normalized_for_scan, nr._gate_hit
    monkeypatch.setattr(nr, "_normalized_for_scan",
                        lambda text: normalized.append(text) or real_normalize(text))
    monkeypatch.setattr(nr, "_gate_hit", lambda path, text: gated.append(path) or real_gate(path, text))
    memo: dict = {}
    census, read = _census({OWNED: LEDGER_BENIGN, OTHER: b"x = 1\n"})
    for kind in ("LEDGER", "ROBOT", "FINBOT"):
        _assert_bounded(_judge(census, read, kind=kind, memo=memo))
    assert len(normalized) == 2
    assert sorted(gated) == sorted([OWNED, OTHER])


def test_witness_path_scan_semantics_are_unchanged_by_the_census_closure():
    # Characterization: a witness still FAILs on a reference and stays bounded when clean.
    read, inventory = _content_reader({OWNED: LEDGER_BOUNDARY})
    _assert_fail(_establish(_witness(inventory=inventory), inventory=inventory, read=read),
                 "BOUNDARY_IDENTIFIER_REFERENCED")
    read, inventory = _content_reader({OWNED: LEDGER_BENIGN})
    _assert_bounded(_establish(_witness(inventory=inventory), inventory=inventory, read=read))


def test_data_path_definition_is_shared_with_the_scan():
    for path in ("a.csv", "a.json", "docs/a.md", "a.toml", "notes/a.txt"):
        assert nr.is_data_path(path) and nr._language_of(path) == "data", path
    for path in ("a.py", "a.mjs", "a.rs", "Makefile", "a.yml"):
        assert not nr.is_data_path(path), path
