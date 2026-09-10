"""Verifier Standard (VSTD) portable formation receipt resource boundaries.

JavaScript Object Notation (JSON) Schema checks structure, not reproduction,
source self-derivation, completeness or authority axiom agency preservation.
"""

from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
import pytest

from verifier.interoperability.formation_receipt import (
    build_formation_receipt, recheck_formation_receipt,
)
from verifier.interoperability.network import canonical_bytes, digest_bytes


ROOT = Path(__file__).resolve().parents[1]
NAME = "vstd-silo-formation-receipt-0.1.schema.json"
CASES = json.loads((ROOT / "tests/fixtures/formation-interoperability-corpus.json").read_bytes())["silo_cases"]


def _bytes(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _inputs(case: dict[str, Any]) -> tuple[bytes, bytes, dict[str, bytes]]:
    commit = _bytes(case["commit_bytes_base64url"])
    selection = canonical_bytes({"schema_version": "VSTD-SILO-FORMATION-SELECTION-0.1",
                                 "commit_digest": digest_bytes(commit), **case["paths"]})
    evidence = {entry["digest"]: _bytes(entry["bytes_base64url"]) for entry in case["evidence"]}
    return selection, commit, evidence


def _validator() -> Draft202012Validator:
    schema = json.loads((ROOT / "standard/schemas" / NAME).read_bytes())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.mark.parametrize("case", CASES, ids=[case["case_id"] for case in CASES])
def test_formation_receipt_schema_admits_native_corpus_without_status_promotion(case: dict[str, Any]) -> None:
    selection, commit, evidence = _inputs(case)
    receipt = build_formation_receipt(selection, commit, evidence)
    _validator().validate(json.loads(selection))
    _validator().validate(json.loads(receipt))
    assert recheck_formation_receipt(selection, commit, receipt, evidence) == case["expected_report"]


@pytest.mark.parametrize("mutation", ["receipt_extra", "selection_extra", "inspection_extra", "bad_state", "boolean_size", "missing_residual"])
def test_formation_receipt_schema_refuses_structural_substitutions(mutation: str) -> None:
    selection, commit, evidence = _inputs(CASES[0])
    item = json.loads(build_formation_receipt(selection, commit, evidence))
    if mutation == "receipt_extra":
        item["trusted"] = True
    elif mutation == "selection_extra":
        item["selection"]["graph_trust"] = "PASS"
    elif mutation == "inspection_extra":
        item["inspection"]["authority_axiom_agency"] = "PRESERVED"
    elif mutation == "bad_state":
        item["inspection"]["coordinate_binding"] = "PASS"
    elif mutation == "boolean_size":
        item["observed_evidence"][0]["size_bytes"] = True
    else:
        item["inspection"]["residual_obligations"].pop()
    assert not _validator().is_valid(item)


def test_formation_receipt_schema_pass_is_not_fresh_reproduction() -> None:
    selection, commit, evidence = _inputs(CASES[0])
    carried = json.loads(build_formation_receipt(selection, commit, evidence))
    forged = deepcopy(carried)
    forged["inspection"]["formation_report"]["observation"]["denotation_digest"] = digest_bytes(b"forged observation")
    _validator().validate(forged)
    with pytest.raises(ValueError):
        recheck_formation_receipt(selection, commit, canonical_bytes(forged), evidence)


def test_formation_receipt_resources_are_packaged_registered_and_experimental() -> None:
    from scripts.build_component_index import REVIEWED_CANDIDATE_SOURCE_PATHS
    from scripts.release_artifacts import PACKAGED_SCHEMA_NAMES

    assert NAME in PACKAGED_SCHEMA_NAMES
    assert (ROOT / "standard/schemas" / NAME).read_bytes() == (ROOT / "src/verifier/schemas" / NAME).read_bytes()
    assert (ROOT / "standard/FORMATION_RECEIPT.md").read_bytes() == (ROOT / "src/verifier/specifications/FORMATION_RECEIPT.md").read_bytes()
    identifiers = (ROOT / "standard/WIRE_IDENTIFIERS.md").read_text(encoding="utf-8")
    assert "VSTD-SILO-FORMATION-SELECTION-0.1" in identifiers
    assert "VSTD-SILO-FORMATION-RECEIPT-0.1" in identifiers
    for path in ("src/verifier/interoperability/formation_receipt.py",
                 "src/verifier/schemas/" + NAME,
                 "src/verifier/specifications/FORMATION_RECEIPT.md"):
        assert path in REVIEWED_CANDIDATE_SOURCE_PATHS
