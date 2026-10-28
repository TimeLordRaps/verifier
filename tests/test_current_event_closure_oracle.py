"""Exhaustive small oracle and mutation checks for EVENT-4.1 log closure.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); depth-first search (DFS). Sequence numbers and
case counts are dimensionless.

For n in {1, 2, 3} events the oracle enumerates every declared prerequisite
relation (each event names any subset of the others), every sequence
assignment in {0..n}, every head, first_sequence in {0, 1}, and two log digest
arms: the correct commitment and one rotating perturbation. It computes each
head's declared cone with Warshall transitive closure over an adjacency
matrix, independent of the checker's iterative DFS, and supplies exactly that
cone as the retained payload map.

Measured cost split: the full enumeration runs at the parent ``_evaluate``
level, which still rebuilds and replays each EVENT-3.1 child, with the
installed-source digest computed once per test rather than per call. A
stratified sample runs the complete uncached build and recheck path.
"""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
from itertools import product
import json
from typing import Any, Iterator

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import event_closure, event_prerequisites


LOG_VERSION = "verifier-current-event-closure-log-1"
OPERANDS = {"time": ["clock"], "space": ["place"], "meaning": ["meaning"]}
NAMES = ("e0", "e1", "e2")
FIXED = (NamespaceObject.create("clock", "TIME", {}),
         NamespaceObject.create("place", "SPACE", {}),
         NamespaceObject.create("meaning", "OBJECT", {}))
FULL_CASES = {1: 4, 2: 144, 3: 24576}


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def warshall(parents: tuple[tuple[int, ...], ...]) -> list[list[bool]]:
    """Reachability along declared prerequisite edges, by Warshall's algorithm."""
    count = len(parents)
    reach = [[column in parents[row] for column in range(count)] for row in range(count)]
    for middle in range(count):
        for row in range(count):
            if reach[row][middle]:
                for column in range(count):
                    if reach[middle][column]:
                        reach[row][column] = True
    return reach


def relations(count: int) -> Iterator[tuple[tuple[int, ...], ...]]:
    choices = []
    for index in range(count):
        others = [other for other in range(count) if other != index]
        choices.append([tuple(other for bit, other in enumerate(others) if mask >> bit & 1)
                        for mask in range(2 ** len(others))])
    yield from product(*choices)


def oracle(parents: tuple[tuple[int, ...], ...], sequences: tuple[int, ...],
           head: int, first: int) -> tuple[set[int], str, str, str]:
    """Return the cone, child verdict, parent verdict and first failing clause."""
    reach = warshall(parents)
    cone = {head} | {other for other in range(len(parents)) if reach[head][other]}
    child_ok = all(sequences[parent] < sequences[node]
                   for node in cone for parent in parents[node])
    if not child_ok:
        return cone, "FAIL", "FAIL", "child"
    if cone != set(range(len(parents))):
        return cone, "PASS", "FAIL", "orphan"
    if sorted(sequences) != list(range(first, first + len(parents))):
        return cone, "PASS", "FAIL", "sequence"
    return cone, "PASS", "PASS", "pass"


def log_rows(records: list[NamespaceObject]) -> list[dict[str, Any]]:
    rows = [{"object_id": item.object_id, "object_digest": item.digest,
             "sequence": item.payload["sequence"]} for item in records]
    return sorted(rows, key=lambda row: (row["sequence"], row["object_id"]))


def log_digest(head: str, first: int, rows: list[dict[str, Any]]) -> str:
    return digest({"schema_version": LOG_VERSION, "head_id": head,
                   "first_sequence": first, "events": rows})


def perturbed(head: str, first: int, rows: list[dict[str, Any]], turn: int) -> str:
    changed_digest = [dict(row) for row in rows]
    changed_digest[0]["object_digest"] = "sha256:" + "1" * 64
    variants = [log_digest(head, first + 1, rows),
                log_digest(head, first, changed_digest),
                log_digest(head, first, rows[:-1])]
    if len(rows) > 1:
        variants.append(log_digest(head, first, list(reversed(rows))))
    choice = variants[turn % len(variants)]
    assert choice != log_digest(head, first, rows)
    return choice


class Unit:
    """One (relation, sequences, head) child plus its parent selections."""

    def __init__(self, parents: tuple[tuple[int, ...], ...],
                 sequences: tuple[int, ...], head: int, turn: int,
                 child_policy: dict[str, Any], parent_policy: dict[str, Any]) -> None:
        count = len(parents)
        self.parents, self.sequences, self.head, self.turn = parents, sequences, head, turn
        self.head_id = NAMES[head]
        self.records = [NamespaceObject.create(NAMES[index], "EVENT", {
            "scope": "retained-declared-prerequisites", "sequence": sequences[index],
            "prerequisites": [NAMES[parent] for parent in parents[index]],
            "payload_digest": digest({"value": index})}, OPERANDS)
            for index in range(count)]
        objects = [*FIXED, *self.records]
        cone = oracle(parents, sequences, head, 0)[0]
        evidence = canonical_bytes({
            "schema_version": event_prerequisites.EVIDENCE_VERSION,
            "objects": [item.to_dict() for item in objects],
            "inputs": {"payloads": {NAMES[index]: {"value": index} for index in cone}}})
        self.collection = composition_digest(objects)
        self.child_request = event_prerequisites.event_prerequisites_request(
            subject_id=self.head_id, object_digest=self.records[head].digest,
            collection_digest=self.collection,
            evidence_ref=digest(json.loads(evidence)), policy=child_policy)
        self.child_policy = child_policy
        self.child_certificate = event_prerequisites.build_event_prerequisites_certificate(
            self.child_request, evidence, policy=child_policy)
        self.payload_ids = {NAMES[index] for index in cone}
        self.evidence = canonical_bytes({
            "schema_version": event_closure.EVIDENCE_VERSION,
            "child_request": self.child_request, "child_policy": child_policy,
            "child_certificate": base64.b64encode(self.child_certificate).decode("ascii")})
        self.parent_policy = parent_policy
        self.rows = log_rows(self.records)

    def child_status(self) -> str:
        return json.loads(self.child_certificate)["result"]["status"]

    def selections(self) -> Iterator[tuple[int, str, dict[str, Any], str, str, str]]:
        """Yield first_sequence, arm, parent request and oracle expectations."""
        for first in (0, 1):
            _, child_expected, parent_expected, reason = oracle(
                self.parents, self.sequences, self.head, first)
            for arm in ("correct", "perturbed"):
                log = (log_digest(self.head_id, first, self.rows) if arm == "correct"
                       else perturbed(self.head_id, first, self.rows, self.turn + first))
                request = event_closure.event_closure_request(
                    subject_id=self.head_id, object_digest=self.records[self.head].digest,
                    collection_digest=self.collection,
                    child_request_digest=digest(self.child_request),
                    child_policy_digest=digest(self.child_policy),
                    child_certificate_digest="sha256:" + hashlib.sha256(
                        self.child_certificate).hexdigest(),
                    first_sequence=first, log_digest=log,
                    evidence_ref=digest(json.loads(self.evidence)),
                    policy=self.parent_policy)
                expected = parent_expected if arm == "correct" else "FAIL"
                yield first, arm, request, child_expected, expected, reason


def descriptors(count: int) -> Iterator[tuple[tuple[tuple[int, ...], ...], tuple[int, ...], int]]:
    for parents in relations(count):
        for sequences in product(range(count + 1), repeat=count):
            for head in range(count):
                yield parents, sequences, head


def policies() -> tuple[dict[str, Any], dict[str, Any]]:
    return (event_prerequisites.event_prerequisites_policy(trust_roots=["oracle-child"]),
            event_closure.event_closure_policy(trust_roots=["oracle-parent"]))


@pytest.fixture
def cached_source_digests(monkeypatch: Any) -> None:
    """Hash installed sources once; the dependency tests cover the uncached path."""
    for module in (event_prerequisites, event_closure):
        value = module.mechanism_digest()
        monkeypatch.setattr(module, "mechanism_digest", lambda value=value: value)


def evaluate(module: Any, unit: Unit, request: dict[str, Any]) -> str:
    return module._evaluate(unit.evidence, request).outcome.value


@pytest.mark.parametrize("count", [1, 2, pytest.param(3, marks=pytest.mark.timeout(300))])
def test_exhaustive_oracle_agrees_at_evaluate_level(count: int,
                                                    cached_source_digests: None) -> None:
    child_policy, parent_policy = policies()
    tally: Counter[str] = Counter()
    disagreements = []
    for turn, (parents, sequences, head) in enumerate(descriptors(count)):
        unit = Unit(parents, sequences, head, turn, child_policy, parent_policy)
        for first, arm, request, child_expected, expected, reason in unit.selections():
            tally["cases"] += 1
            tally[arm + ":" + (reason if arm == "correct" else "any")] += 1
            if first == 0 and arm == "correct" and unit.child_status() != child_expected:
                disagreements.append(("child", parents, sequences, head))
            observed = evaluate(event_closure, unit, request)
            if observed != expected:
                disagreements.append((parents, sequences, head, first, arm, observed, expected))
    print(f"\nEVENT-4.1 oracle n={count}: {dict(sorted(tally.items()))}; "
          f"disagreements={len(disagreements)}")
    assert tally["cases"] == 2 * FULL_CASES[count]
    assert tally["correct:pass"] > 0
    assert not disagreements, disagreements[:5]


def _stratified(count: int, cap: int) -> list[tuple[Any, ...]]:
    strata: dict[str, list[tuple[Any, ...]]] = {}
    for turn, (parents, sequences, head) in enumerate(descriptors(count)):
        for first in (0, 1):
            reason = oracle(parents, sequences, head, first)[3]
            strata.setdefault(reason, []).append((parents, sequences, head, turn, first))
    chosen = []
    for reason, members in sorted(strata.items()):
        stride = 1 if reason == "pass" else max(1, len(members) // cap)
        chosen.extend(members[::stride])
    return chosen


def test_stratified_sample_agrees_through_build_and_recheck() -> None:
    child_policy, parent_policy = policies()
    tally: Counter[str] = Counter()
    disagreements = []
    samples = [(parents, sequences, head, turn, first)
               for count in (1, 2)
               for turn, (parents, sequences, head) in enumerate(descriptors(count))
               for first in (0, 1)]
    samples += _stratified(3, cap=120)
    for parents, sequences, head, turn, first in samples:
        unit = Unit(parents, sequences, head, turn, child_policy, parent_policy)
        for chosen, arm, request, _, expected, reason in unit.selections():
            if chosen != first:
                continue
            certificate = event_closure.build_event_closure_certificate(
                request, unit.evidence, policy=parent_policy)
            result = event_closure.recheck_event_closure_certificate(
                certificate, expected_request=request, policy=parent_policy)
            tally["cases"] += 1
            tally[str(len(parents)) + ":" + arm + ":" + reason] += 1
            if result["status"] != expected:
                disagreements.append((parents, sequences, head, first, arm,
                                      result["status"], expected))
    print(f"\nEVENT-4.1 build+recheck sample: {dict(sorted(tally.items()))}; "
          f"disagreements={len(disagreements)}")
    assert tally["cases"] >= 2 * (FULL_CASES[1] + FULL_CASES[2])
    assert not disagreements, disagreements[:5]


MUTANTS = (
    "drop_clause_3_orphan",
    "drop_clause_4_gap",
    "drop_clause_4_uniqueness_half",
    "ignore_first_sequence_in_clause_4",
    "ignore_first_sequence_everywhere",
    "commit_in_identifier_order",
    "commit_in_descending_order",
    "drop_log_commitment_clause",
)


def mutant_outcome(name: str | None, unit: Unit, request: dict[str, Any]) -> str:
    """Static finite models of the eight source mutations above.

    Keeping each mutation as an explicit branch makes the mutation denominator
    visible to repository admission.  No generated module or executed source
    string can add an unenumerated interface.
    """
    if unit.child_status() != "PASS":
        return "FAIL"
    identifiers = [row.object_id for row in unit.records]
    if len(set(identifiers)) != len(identifiers):
        return "FAIL"
    if name != "drop_clause_3_orphan" and set(identifiers) != unit.payload_ids:
        return "FAIL"
    sequences = [row.payload["sequence"] for row in unit.records]
    first = (min(sequences) if name in {
        "ignore_first_sequence_in_clause_4", "ignore_first_sequence_everywhere"
    } else request["first_sequence"])
    if name == "drop_clause_4_uniqueness_half":
        sequence_invalid = set(sequences) != set(
            range(first, first + len(set(sequences))))
    else:
        sequence_invalid = sorted(sequences) != list(
            range(first, first + len(sequences)))
    if name != "drop_clause_4_gap" and sequence_invalid:
        return "FAIL"
    rows = [{"object_id": row.object_id, "object_digest": row.digest,
             "sequence": row.payload["sequence"]} for row in unit.records]
    if name == "commit_in_identifier_order":
        log = sorted(rows, key=lambda row: row["object_id"])
    elif name == "commit_in_descending_order":
        log = sorted(rows, key=lambda row: row["sequence"], reverse=True)
    else:
        log = sorted(rows, key=lambda row: row["sequence"])
    committed_first = first if name == "ignore_first_sequence_everywhere" else request["first_sequence"]
    commitment = digest({"schema_version": LOG_VERSION,
        "head_id": request["subject_id"], "first_sequence": committed_first,
        "events": log})
    if name != "drop_log_commitment_clause" and commitment != request["log_digest"]:
        return "FAIL"
    return "PASS"


def test_unmutated_static_mutant_model_agrees_with_oracle(cached_source_digests: None) -> None:
    """Control: the finite static mutation model introduces no disagreement."""
    child_policy, parent_policy = policies()
    checked = 0
    for count in (1, 2):
        for turn, (parents, sequences, head) in enumerate(descriptors(count)):
            unit = Unit(parents, sequences, head, turn, child_policy, parent_policy)
            for _, _, request, _, expected, _ in unit.selections():
                assert mutant_outcome(None, unit, request) == expected
                checked += 1
    for parents, sequences, head, turn, first in _stratified(3, cap=60):
        unit = Unit(parents, sequences, head, turn, child_policy, parent_policy)
        for chosen, _, request, _, expected, _ in unit.selections():
            if chosen == first:
                assert mutant_outcome(None, unit, request) == expected
                checked += 1
    print(f"\nEVENT-4.1 unmutated exec control: {checked} cases, 0 disagreements")


@pytest.mark.timeout(120)
def test_every_listed_mutant_is_killed_by_the_oracle(cached_source_digests: None) -> None:
    alive = set(MUTANTS)
    killed: dict[str, tuple[Any, ...]] = {}
    child_policy, parent_policy = policies()
    examined = 0
    for count in (1, 2, 3):
        for turn, (parents, sequences, head) in enumerate(descriptors(count)):
            if not alive:
                break
            unit = Unit(parents, sequences, head, turn, child_policy, parent_policy)
            for first, arm, request, _, expected, _ in unit.selections():
                examined += 1
                for name in list(alive):
                    observed = mutant_outcome(name, unit, request)
                    if observed != expected:
                        killed[name] = (parents, sequences, head, first, arm,
                                        observed, expected)
                        alive.remove(name)
    for name, witness in sorted(killed.items()):
        print(f"\nkilled {name}: {witness}")
    print(f"\nEVENT-4.1 mutants: {len(killed)} killed, {len(alive)} survived, "
          f"{examined} cases examined")
    assert not alive, sorted(alive)
