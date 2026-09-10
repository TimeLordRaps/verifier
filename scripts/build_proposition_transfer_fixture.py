"""Portable proposition-transfer specimens, not authority or deployment evidence.

Verifier Standard (VSTD), JavaScript Object Notation (JSON), Secure Hash Algorithm
256-bit (SHA-256), and Unicode Transformation Format, 8-bit (UTF-8).
The checked-in network fixture is public synthetic test data. Added census members
are not accompanied by claims of self-derivation or complete coverage.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from typing import Any

from verifier.interoperability.network import (
    CensusEntry, ObjectRecord, SiloCommit, canonical_bytes, digest_bytes,
    _read_bounded_regular,
)
from verifier.interoperability.proposition_transfer import (
    assess_transfer, build_transfer_receipt, rule_profile_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "examples/artifact-network/canonical-wire-fixture.json"
TARGET = ROOT / "examples/artifact-network/canonical-proposition-transfer-fixture.json"
MAX_FIXTURE_BYTES = 2 * 1024 * 1024
ZERO = "sha256:" + "0" * 64


def _sorted(items: list[str]) -> list[str]:
    return sorted(items, key=lambda item: item.encode("utf-8"))


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _proposition(
    base: SiloCommit, path: str, items: list[str], allowed: list[str],
    evidence: dict[str, bytes], *, raw: bytes | None = None,
) -> dict[str, Any]:
    payload = raw if raw is not None else canonical_bytes({
        "schema_version": "VSTD-CANONICAL-FINITE-SET-0.1", "items": _sorted(items),
    })
    record = ObjectRecord.from_payload(
        payload, "application/json", "finite-set", "VSTD-CANONICAL-FINITE-SET-0.1",
    )
    commit = replace(base, census=(*base.census, CensusEntry(path, record, "DISPENSABLE")))
    commit_bytes = canonical_bytes(commit.to_dict())
    evidence[digest_bytes(commit_bytes)] = commit_bytes
    evidence[record.object_digest] = payload
    model_digest = None if commit.authority_model_path is None else next(
        entry.object_record.object_digest for entry in commit.census
        if entry.path == commit.authority_model_path
    )
    return {
        "commit_digest": digest_bytes(commit_bytes), "artifact_digest": record.object_digest,
        "artifact_path": path, "size_bytes": len(payload),
        "predicate_id": "canonical_finite_set_subset_v1", "facet": "items",
        "parameters": {"allowed_items": _sorted(allowed)},
        "context": {
            "semantic_scope": "synthetic-inventory-strings", "actor_scope": "ANY_ACTOR",
            "agency_digest": commit.authority_axiom_agency_digest,
            "authority_model_digest": model_digest, "assumptions": [], "exclusions": [],
        },
    }


def assessment_summary(assessment: dict[str, Any]) -> dict[str, Any]:
    return {
        "premise_bindings": sorted(item["evidence_binding"] for item in assessment["premises"]),
        "premise_predicates": sorted(item["predicate_result"] for item in assessment["premises"]),
        "target_binding": assessment["conclusion"]["evidence_binding"],
        "target_predicate": assessment["conclusion"]["predicate_result"],
        **{key: assessment[key] for key in (
            "context_preservation", "artifact_relation", "upper_bound_preservation",
            "residual_closure", "conclusion_support", "authority_admissibility",
        )},
    }


def build_fixture() -> dict[str, Any]:
    base_wire = json.loads(_read_bounded_regular(BASE, MAX_FIXTURE_BYTES, "public network fixture"))
    base = SiloCommit.from_dict(base_wire["records"]["silo_transfer"]["commit"])
    cases: list[dict[str, Any]] = []

    def seed(
        sources: list[tuple[list[str], list[str]]] | None = None,
        target: tuple[list[str], list[str]] | None = None,
    ) -> tuple[dict[str, Any], dict[str, bytes]]:
        evidence: dict[str, bytes] = {}
        sources = sources if sources is not None else [(["a"], ["a"]), (["b"], ["b"])]
        target = target if target is not None else (["a", "b"], ["a", "b"])
        declaration = {
            "schema_version": "VSTD-PROPOSITION-TRANSFER-0.1",
            "rule_id": "canonical_finite_set_union_v1",
            "rule_profile_digest": digest_bytes(rule_profile_bytes()),
            "premises": [
                _proposition(base, f"sets/source-{index}.json", items, allowed, evidence)
                for index, (items, allowed) in enumerate(sources)
            ],
            "conclusion": _proposition(base, "sets/target.json", *target, evidence),
            "residual_obligations": [],
        }
        return declaration, evidence

    def retain(
        case_id: str, declaration: dict[str, Any], evidence: dict[str, bytes],
        **expected_changes: Any,
    ) -> None:
        declaration = deepcopy(declaration)
        declaration["premises"].sort(key=lambda item: digest_bytes(canonical_bytes(item)))
        encoded = canonical_bytes(declaration)
        expected = {
            "premise_bindings": ["PASS"] * len(declaration["premises"]),
            "premise_predicates": ["PASS"] * len(declaration["premises"]),
            "target_binding": "PASS", "target_predicate": "PASS",
            "context_preservation": "PASS", "artifact_relation": "PASS",
            "upper_bound_preservation": "PASS", "residual_closure": "PASS",
            "conclusion_support": "SUPPORTED", "authority_admissibility": "NOT_ESTABLISHED",
            **expected_changes,
        }
        assessment = assess_transfer(encoded, evidence)
        actual = assessment_summary(assessment)
        if actual != expected:
            raise AssertionError(f"{case_id}: hand-specified oracle {expected!r}; actual {actual!r}")
        receipt = build_transfer_receipt(encoded, evidence)
        cases.append({
            "case_id": case_id, "declaration_canonical_json": encoded.decode("utf-8"),
            "declaration_digest": digest_bytes(encoded), "expected": expected,
            "objects": [
                {"digest": key, "bytes_base64url": _encode(value)}
                for key, value in sorted(evidence.items())
            ],
            "receipt_canonical_json": receipt.decode("utf-8"), "receipt_digest": digest_bytes(receipt),
        })

    retain("two_source_union", *seed())
    retain("second_transfer_of_observed_union", *seed(
        [(["a", "b"], ["a", "b"]), (["c"], ["c"])], (["a", "b", "c"], ["a", "b", "c"]),
    ))
    retain("empty_union", *seed([([], []), ([], [])], ([], [])))
    retain("unicode_utf8_order", *seed(
        [(["\ue000"], ["\ue000"]), (["\U0001f600"], ["\U0001f600"])],
        (["\ue000", "\U0001f600"], ["\ue000", "\U0001f600"]),
    ))
    retain("true_target_failed_upper_bound", *seed(
        [(["a"], ["a", "unused"]), (["b"], ["b"])],
    ), upper_bound_preservation="FAIL", conclusion_support="NOT_ESTABLISHED")
    retain("altered_target_not_union", *seed(target=(["a"], ["a", "b"])),
           artifact_relation="FAIL", conclusion_support="NOT_ESTABLISHED")
    retain("false_target_and_relation", *seed(target=(["a", "b", "z"], ["a", "b"])),
           target_predicate="FAIL", artifact_relation="FAIL", conclusion_support="NOT_ESTABLISHED")
    declaration, evidence = seed([(["a"], []), (["b"], ["b"])])
    del evidence[declaration["premises"][0]["commit_digest"]]
    retain("false_premise_missing_commit", declaration, evidence,
           premise_bindings=["PASS", "UNKNOWN"], premise_predicates=["FAIL", "PASS"],
           conclusion_support="NOT_ESTABLISHED")
    for field, value in (
        ("semantic_scope", "different-scope"), ("actor_scope", "DIFFERENT_ACTOR"),
        ("agency_digest", ZERO), ("authority_model_digest", ZERO),
    ):
        declaration, evidence = seed()
        declaration["premises"][0]["context"][field] = value
        changes: dict[str, Any] = {
            "context_preservation": "FAIL", "conclusion_support": "NOT_ESTABLISHED",
        }
        if field in {"agency_digest", "authority_model_digest"}:
            changes["premise_bindings"] = ["FAIL", "PASS"]
        retain("mismatched_" + field, declaration, evidence, **changes)
    for field, value in (("rule_id", "not_registered"), ("rule_profile_digest", ZERO)):
        declaration, evidence = seed([(["a"], []), (["b"], ["b"])])
        declaration[field] = value
        retain("unsupported_" + field, declaration, evidence,
               premise_predicates=["FAIL", "PASS"], context_preservation="UNKNOWN",
               artifact_relation="UNKNOWN", upper_bound_preservation="UNKNOWN",
               conclusion_support="NOT_ESTABLISHED")
    declaration, evidence = seed()
    declaration["premises"][0]["parameters"] = {"allowed_items": ["a", "a"]}
    retain("invalid_parameters_actual_relation_passes", declaration, evidence,
           premise_predicates=["INVALID", "PASS"], upper_bound_preservation="INVALID",
           conclusion_support="NOT_ESTABLISHED")
    declaration, evidence = seed()
    declaration["residual_obligations"] = ["unresolved-side-condition"]
    retain("open_residual", declaration, evidence,
           residual_closure="UNKNOWN", conclusion_support="NOT_ESTABLISHED")
    declaration, evidence = seed()
    declaration["premises"][0]["artifact_path"] = "sets/absent.json"
    retain("census_binding_failure", declaration, evidence,
           premise_bindings=["FAIL", "PASS"], conclusion_support="NOT_ESTABLISHED")
    declaration, evidence = seed()
    opaque = _proposition(base, "sets/opaque.bin", [], [], evidence, raw=b"opaque foreign proof bytes")
    opaque["predicate_id"] = "unregistered_opaque_proof"
    declaration["premises"][0] = opaque
    retain("opaque_unknown_predicate", declaration, evidence,
           premise_predicates=["PASS", "UNKNOWN"], context_preservation="UNKNOWN",
           artifact_relation="UNKNOWN", upper_bound_preservation="UNKNOWN",
           conclusion_support="NOT_ESTABLISHED")
    return {
        "schema_version": "VSTD-PROPOSITION-TRANSFER-FIXTURE-0.1",
        "rule_profile_canonical_json": rule_profile_bytes().decode("utf-8"),
        "rule_profile_digest": digest_bytes(rule_profile_bytes()),
        "cases": sorted(cases, key=lambda item: item["case_id"]),
        "claim_boundary": (
            "Synthetic exact-byte finite-set evidence only. Hand-specified result summaries "
            "are checked before recording canonical receipts. This is not complete adversarial "
            "coverage, self-derivation, real-world inventory completeness, authority preservation, "
            "execution identity, generic graph deduction, or hosted platform evidence."
        ),
    }


def render_fixture() -> bytes:
    encoded = (json.dumps(build_fixture(), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_FIXTURE_BYTES:
        raise ValueError("proposition transfer fixture exceeds its bound")
    return encoded


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    rendered = render_fixture()
    if args.write:
        TARGET.write_bytes(rendered)
        print(f"[PROPOSITION TRANSFER FIXTURE WRITTEN] bytes={len(rendered)} digest={digest_bytes(rendered)}")
    else:
        if _read_bounded_regular(TARGET, MAX_FIXTURE_BYTES, "proposition transfer fixture") != rendered:
            raise SystemExit("proposition transfer fixture is stale")
        print(f"[PROPOSITION TRANSFER FIXTURE OK] bytes={len(rendered)} digest={digest_bytes(rendered)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

