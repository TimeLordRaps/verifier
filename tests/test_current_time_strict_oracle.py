"""Independent exhaustive oracle for TIME-3.1 strict order over small sequences.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Instants are integer microseconds on one declared
clock; counts are dimensionless. The oracle predicates use built-in Python
only. Inputs are built here through the public TIME-2.1 and TIME-3.1 builders;
nothing is imported from the mechanism's private helpers or from the unit-test
fixtures, so a shared mistake cannot make the mechanism and the oracle agree.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
from itertools import product
import json
from typing import Any

from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import time_order


SPAN = (0, 4)
VALUES = range(0, 4)
BOUNDARY_VALUES = range(0, 5)


def encode(value: Any) -> bytes:
    """Canonical JSON written out here: sorted keys, no spaces, and escapes outside
    American Standard Code for Information Interchange (ASCII)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sequences(values: range, longest: int) -> list[tuple[int, ...]]:
    return [tuple(item) for length in range(1, longest + 1)
            for item in product(values, repeat=length)]


def child_oracle(instants: tuple[int, ...], start: int, end: int) -> bool:
    return all(start <= at < end for at in instants) and sorted(instants) == list(instants)


def parent_oracle(instants: tuple[int, ...], start: int, end: int) -> bool:
    return child_oracle(instants, start, end) and len(set(instants)) == len(instants)


class Builder:
    """Build real child and parent certificates from public builders only."""

    def __init__(self) -> None:
        self.strict = importlib.import_module("verifier.domains.contracts.time_strict")
        self.child_policy = time_order.time_order_policy(trust_roots=["oracle-clock"])
        self.parent_policy = self.strict.time_strict_policy(trust_roots=["oracle-strict"])

    def statuses(self, instants: tuple[int, ...]) -> tuple[str, str]:
        samples = [{"id": "s" + str(index), "at_us": at} for index, at in enumerate(instants)]
        subject = NamespaceObject.create("time-root", "TIME", {
            "scope": "retained-declared-clock-order", "clock": "oracle:clock",
            "unit": "microsecond", "span_start_us": SPAN[0], "span_end_us": SPAN[1],
            "samples_digest": sha(encode(samples))})
        evidence = encode({"schema_version": time_order.EVIDENCE_VERSION,
                           "objects": [subject.to_dict()], "inputs": {"samples": samples}})
        request = time_order.time_order_request(
            subject_id=subject.object_id, object_digest=subject.digest,
            collection_digest=composition_digest([subject]), evidence_ref=sha(evidence),
            policy=self.child_policy)
        certificate = time_order.build_time_order_certificate(
            request, evidence, policy=self.child_policy)
        child = time_order.recheck_time_order_certificate(
            certificate, expected_request=request, policy=self.child_policy)["status"]
        bundle = encode({"schema_version": self.strict.EVIDENCE_VERSION,
            "child_request": request, "child_policy": self.child_policy,
            "child_certificate": base64.b64encode(certificate).decode("ascii")})
        parent_request = self.strict.time_strict_request(
            subject_id=subject.object_id, object_digest=subject.digest,
            collection_digest=composition_digest([subject]),
            child_request_digest=sha(encode(request)),
            child_policy_digest=sha(encode(self.child_policy)),
            child_certificate_digest=sha(certificate), evidence_ref=sha(bundle),
            policy=self.parent_policy)
        parent_certificate = self.strict.build_time_strict_certificate(
            parent_request, bundle, policy=self.parent_policy)
        parent = self.strict.recheck_time_strict_certificate(
            parent_certificate, expected_request=parent_request,
            policy=self.parent_policy)["status"]
        return child, parent


def expected(verdict: bool) -> str:
    return "PASS" if verdict else "FAIL"


def test_enumeration_sizes_are_exact() -> None:
    assert len(sequences(VALUES, 4)) == 4 + 16 + 64 + 256 == 340
    assert len(set(sequences(VALUES, 4))) == 340
    assert len(sequences(BOUNDARY_VALUES, 2)) == 5 + 25 == 30


def test_oracle_counts_are_non_vacuous() -> None:
    cases = sequences(VALUES, 4)
    assert sum(parent_oracle(case, *SPAN) for case in cases) == 15
    assert sum(child_oracle(case, *SPAN) for case in cases) == 69
    stricter = [case for case in cases
                if child_oracle(case, *SPAN) and not parent_oracle(case, *SPAN)]
    assert len(stricter) == 54
    assert all(len(set(case)) < len(case) for case in stricter)


def test_child_agrees_with_its_oracle_on_all_340_sequences() -> None:
    policy = time_order.time_order_policy(trust_roots=["oracle-clock"])
    disagreements = []
    passed = 0
    for instants in sequences(VALUES, 4):
        samples = [{"id": "s" + str(index), "at_us": at} for index, at in enumerate(instants)]
        subject = NamespaceObject.create("time-root", "TIME", {
            "scope": "retained-declared-clock-order", "clock": "oracle:clock",
            "unit": "microsecond", "span_start_us": SPAN[0], "span_end_us": SPAN[1],
            "samples_digest": sha(encode(samples))})
        evidence = encode({"schema_version": time_order.EVIDENCE_VERSION,
                           "objects": [subject.to_dict()], "inputs": {"samples": samples}})
        request = time_order.time_order_request(
            subject_id=subject.object_id, object_digest=subject.digest,
            collection_digest=composition_digest([subject]), evidence_ref=sha(evidence),
            policy=policy)
        status = time_order.recheck_time_order_certificate(
            time_order.build_time_order_certificate(request, evidence, policy=policy),
            expected_request=request, policy=policy)["status"]
        passed += status == "PASS"
        if status != expected(child_oracle(instants, *SPAN)):
            disagreements.append((instants, status))
    print("child oracle: 340 sequences,", passed, "PASS,", len(disagreements), "disagreements")
    assert disagreements == []
    assert passed == 69


def test_parent_agrees_with_independent_oracle_on_all_340_sequences() -> None:
    builder = Builder()
    disagreements = []
    parent_passed = child_passed = stricter = 0
    for instants in sequences(VALUES, 4):
        child, parent = builder.statuses(instants)
        child_passed += child == "PASS"
        parent_passed += parent == "PASS"
        stricter += child == "PASS" and parent == "FAIL"
        if (child, parent) != (expected(child_oracle(instants, *SPAN)),
                               expected(parent_oracle(instants, *SPAN))):
            disagreements.append((instants, child, parent))
    print("parent oracle: 340 sequences,", parent_passed, "parent PASS,", child_passed,
          "child PASS,", stricter, "child PASS with parent FAIL,",
          len(disagreements), "disagreements")
    assert disagreements == []
    assert parent_passed == 15
    assert child_passed == 69 and stricter == 54


def test_parent_agrees_with_oracle_on_span_boundary_set() -> None:
    builder = Builder()
    disagreements = []
    counts = {"PASS": 0, "FAIL": 0}
    for instants in sequences(BOUNDARY_VALUES, 2):
        child, parent = builder.statuses(instants)
        counts[parent] += 1
        if (child, parent) != (expected(child_oracle(instants, *SPAN)),
                               expected(parent_oracle(instants, *SPAN))):
            disagreements.append((instants, child, parent))
    print("span boundary: 30 sequences,", counts, len(disagreements), "disagreements")
    assert disagreements == []
    assert counts == {"PASS": 10, "FAIL": 20}
    assert builder.statuses((SPAN[1],)) == ("FAIL", "FAIL")
    assert builder.statuses((SPAN[1] - 1,)) == ("PASS", "PASS")
