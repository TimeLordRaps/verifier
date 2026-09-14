"""Session snapshot tests for Verifier Standard (VSTD) exact claim binding.

Secure Hash Algorithm 256-bit (SHA-256) coordinates bind the private original
snapshot, not a caller or invocation object mutated during execution.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from copy import deepcopy
from typing import Any

import pytest

from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession, EvaluatedProposition,
)


class ControlledMechanism:
    """Run a synchronous test hook; no external side effects or inference."""

    mechanism_id = "test.session-binding-snapshot"
    mechanism_digest = "sha256:" + "a" * 64

    def __init__(self, hook: Callable[[Sequence[BoundProposition]], None]) -> None:
        self.hook = hook

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        self.hook((binding,))
        return MechanismDecision(MechanismOutcome.PASS, "controlled test decision")

    def evaluate_compound(
        self, bindings: Sequence[BoundProposition], evidence: Sequence[Sequence[bytes]],
    ) -> tuple[MechanismDecision, ...]:
        self.hook(bindings)
        return tuple(MechanismDecision(MechanismOutcome.PASS, "controlled test decision") for _ in bindings)


def _binding(store: EvidenceStore, index: int = 0) -> BoundProposition:
    return BoundProposition(
        "subject:" + str(index), "test.snapshot", {"values": [{"accepted": True}]},
        ControlledMechanism.mechanism_id, ControlledMechanism.mechanism_digest,
        (store.add(b"bounded fixture " + str(index).encode("ascii")),),
        ("test:explicit-boundary",), EvidenceBounds(1, 1000),
        {"nested": {"labels": ["original"]}},
    )


def test_session_single_result_keeps_private_original_binding_when_caller_changes() -> None:
    store = EvidenceStore()
    binding = _binding(store)
    original = binding.digest()

    def mutate_caller(_invocations: Sequence[BoundProposition]) -> None:
        binding.parameters["nested"]["labels"][0] = "caller changed"

    session = VerificationSession(store)
    session.register(ControlledMechanism(mutate_caller))
    result = session.evaluate(binding)
    assert result.outcome is MechanismOutcome.PASS
    assert binding.digest() != original
    assert result.binding_digest == original


class ResolvingHookStore(EvidenceStore):
    """Execute one test callback inside actual content-addressed resolution."""

    def __init__(self) -> None:
        super().__init__()
        self.hook: Callable[[], None] | None = None
        self.resolve_calls = 0

    def resolve(self, reference: str) -> bytes:
        self.resolve_calls += 1
        if self.hook is not None:
            callback, self.hook = self.hook, None
            callback()
        return super().resolve(reference)


def _mutate(binding: BoundProposition, field: str) -> None:
    if field == "expected":
        binding.expected["values"][0]["accepted"] = False
    else:
        binding.parameters["nested"]["labels"][0] = "changed"


def _run(
    session: VerificationSession, bindings: Sequence[BoundProposition], compound: bool,
) -> tuple[EvaluatedProposition, ...]:
    return session.evaluate_compound(bindings) if compound else (session.evaluate(bindings[0]),)


def _assert_coordinates(
    results: Sequence[EvaluatedProposition], originals: Sequence[BoundProposition],
) -> None:
    assert len(results) == len(originals)
    for result, original in zip(results, originals):
        assert result.binding_digest == original.digest()
        assert result.evidence_refs == original.evidence_refs
        assert result.mechanism_id == original.mechanism_id
        assert result.mechanism_digest == original.mechanism_digest
        assert result.trust_roots == original.trust_roots
        assert result.observed_evidence_bytes > 0


@pytest.mark.parametrize("compound", [False, True], ids=["single", "compound"])
@pytest.mark.parametrize("field", ["expected", "parameters"])
@pytest.mark.parametrize("timing", ["resolve", "evaluate"])
def test_session_caller_mutation_cannot_change_dispatched_or_returned_binding(
    compound: bool, field: str, timing: str,
) -> None:
    store = ResolvingHookStore()
    bindings = [_binding(store, index) for index in range(2 if compound else 1)]
    originals = deepcopy(bindings)
    observed: list[BoundProposition] = []
    mutations: list[str] = []

    def mutate_callers() -> None:
        for binding in bindings:
            _mutate(binding, field)
        mutations.append(timing)

    def observe_invocation(invocations: Sequence[BoundProposition]) -> None:
        if timing == "evaluate":
            mutate_callers()
        observed.extend(deepcopy(invocations))

    if timing == "resolve":
        store.hook = mutate_callers
    session = VerificationSession(store)
    session.register(ControlledMechanism(observe_invocation))
    results = _run(session, bindings, compound)
    assert mutations == [timing]
    assert store.resolve_calls == len(bindings)
    assert all(result.outcome is MechanismOutcome.PASS for result in results)
    assert [item.to_dict() for item in observed] == [item.to_dict() for item in originals]
    assert all(item.digest() != original.digest() for item, original in zip(bindings, originals))
    _assert_coordinates(results, originals)


@pytest.mark.parametrize("compound", [False, True], ids=["single", "compound"])
@pytest.mark.parametrize("field", ["expected", "parameters"])
def test_session_invocation_mutation_is_unknown_without_mutating_caller(
    compound: bool, field: str,
) -> None:
    store = EvidenceStore()
    bindings = [_binding(store, index) for index in range(2 if compound else 1)]
    originals = deepcopy(bindings)
    invoked: list[bool] = []

    def corrupt_invocation(invocations: Sequence[BoundProposition]) -> None:
        _mutate(invocations[-1], field)
        invoked.append(True)

    session = VerificationSession(store)
    session.register(ControlledMechanism(corrupt_invocation))
    results = _run(session, bindings, compound)
    assert invoked == [True]
    assert all(result.outcome is MechanismOutcome.UNKNOWN for result in results)
    assert all("binding snapshot" in result.details for result in results)
    assert [item.to_dict() for item in bindings] == [item.to_dict() for item in originals]
    _assert_coordinates(results, originals)


@pytest.mark.parametrize("target", ["caller", "invocation"])
@pytest.mark.parametrize("field", ["expected", "parameters"])
def test_session_compound_generator_mutation_cannot_retarget_after_method_returns(
    target: str, field: str,
) -> None:
    store = EvidenceStore()
    bindings = [_binding(store, index) for index in range(2)]
    originals = deepcopy(bindings)
    phases: list[str] = []

    class LazyMechanism(ControlledMechanism):
        def evaluate_compound(
            self, invocations: Sequence[BoundProposition], evidence: Sequence[Sequence[bytes]],
        ) -> Iterator[MechanismDecision]:
            phases.append("method returned iterator")

            def decisions() -> Iterator[MechanismDecision]:
                phases.append("iterator started")
                yield MechanismDecision(MechanismOutcome.PASS, "first controlled decision")
                _mutate((bindings if target == "caller" else invocations)[0], field)
                phases.append("mutated after first decision")
                yield MechanismDecision(MechanismOutcome.PASS, "second controlled decision")

            return decisions()

    session = VerificationSession(store)
    session.register(LazyMechanism(lambda _items: None))
    results = session.evaluate_compound(bindings)
    assert phases == ["method returned iterator", "iterator started", "mutated after first decision"]
    expected = MechanismOutcome.PASS if target == "caller" else MechanismOutcome.UNKNOWN
    assert all(result.outcome is expected for result in results)
    if target == "invocation":
        assert [item.to_dict() for item in bindings] == [item.to_dict() for item in originals]
    else:
        assert bindings[0].digest() != originals[0].digest()
    _assert_coordinates(results, originals)


@pytest.mark.parametrize("compound", [False, True], ids=["single", "compound"])
def test_session_snapshot_retains_canonical_value_types_without_wire_coercion(compound: bool) -> None:
    store = EvidenceStore()
    bindings = [_binding(store, index) for index in range(2 if compound else 1)]
    for binding in bindings:
        binding.expected["values"] = (None, True, 3, 2.5, {"nested": ["exact"]})
        binding.parameters["nested"]["labels"] = ("original", 2, False)
    originals = deepcopy(bindings)
    observed: list[BoundProposition] = []

    def retain(invocations: Sequence[BoundProposition]) -> None:
        observed.extend(invocations)

    session = VerificationSession(store)
    session.register(ControlledMechanism(retain))
    results = _run(session, bindings, compound)
    assert all(result.outcome is MechanismOutcome.PASS for result in results)
    for invocation, caller in zip(observed, bindings):
        assert invocation is not caller
        assert type(invocation.expected["values"]) is tuple
        assert type(invocation.parameters["nested"]) is dict
        assert type(invocation.parameters["nested"]["labels"]) is tuple
        assert invocation.expected == caller.expected
        assert invocation.parameters == caller.parameters
    _assert_coordinates(results, originals)
