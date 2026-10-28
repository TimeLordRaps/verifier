"""Bounded agent harness (HARNESS) capture and cancellation counterexamples.

Verifier Standard (VSTD); JavaScript Object Notation (JSON).
These checks establish retained-record integrity, not recorder authenticity,
instruction compliance, model correctness, or overall safety.
"""
from __future__ import annotations

from asyncio import CancelledError
from copy import deepcopy
from typing import Sequence

import pytest

from verifier import (BoundProposition, EvidenceBounds, EvidenceStore,
                      MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.evidence import BytesDigestMechanism
from test_current_harness_checks import inputs as current_inputs, replay as current_replay
from verifier.domains.common import Budget, digest, merkle_root


def specimen() -> dict:
    payloads = [("user", "chat", {"text": "read the retained file"}),
                ("tool", "tool_io", {"input": {"path": "example.txt"},
                                      "output": {"text": "retained"}})]
    records = [{"index": i, "channel": channel, "role": role,
                "payload": payload, "payload_digest": digest(payload)}
               for i, (role, channel, payload) in enumerate(payloads)]
    declaration_record = {"name": "read_file", "inputs": ["path"], "outputs": ["text"]}
    declaration = digest(declaration_record)
    bundle = {
            "artifact": {"surface": {"chat": "instrumented", "tool_io": "instrumented",
                                     "model_reasoning": "declared-gap"},
                         "tools": {"read_file": declaration},
                         "effects": {"network": "declared-gap"},
                         "record_count": len(records), "transcript_digest": digest(records),
                         "transcript_root": merkle_root(records, Budget(10000))},
            "inputs": {"records": records,
                       "invocations": [{"index": 1, "tool": "read_file",
                                        **records[1]["payload"], "declaration_digest": declaration}],
                       "effects": [], "declarations": {"read_file": declaration_record}}}
    recommit(bundle)
    return bundle


def assess(bundle: dict) -> dict:
    """Replay each named current predicate; this fixture aggregator is no profile."""
    selected = {}
    for check in ("surface", "messages", "tools", "effects", "transcript"):
        contract, request, policy, evidence = current_inputs(check,
            artifact=bundle["artifact"], retained=bundle["inputs"])
        replay = current_replay(contract, request, policy, evidence)
        native = replay["native_result"]
        assert native["object_profile_conformance"] == "NOT_ESTABLISHED"
        assert replay["replay_status"] == "REPRODUCED"
        selected[request["coordinate"]] = native
    outcomes = [row["status"] for row in selected.values()]
    return {"status": "FAIL" if "FAIL" in outcomes else "UNKNOWN" if "UNKNOWN" in outcomes else "PASS",
            "selected_checks": selected, "object_profile_conformance": "NOT_ESTABLISHED"}


def recommit(bundle: dict) -> None:
    records = bundle["inputs"]["records"]
    bundle["artifact"]["transcript_digest"] = digest(records)
    bundle["artifact"]["transcript_root"] = merkle_root(records, Budget(10000))
    bundle["artifact"]["invocations_digest"] = digest(bundle["inputs"]["invocations"])
    bundle["artifact"]["effects_digest"] = digest(bundle["inputs"]["effects"])


def test_complete_retained_tool_inventory_replays() -> None:
    result = assess(specimen())
    assert result["status"] == "PASS"
    assert set(result["selected_checks"]) == {"HARNESS-1.6", "HARNESS-2.1", "HARNESS-2.2", "HARNESS-2.3", "HARNESS-4.1"}


@pytest.mark.parametrize("mutation", ["omit", "duplicate"])
def test_tool_inventory_cannot_omit_or_duplicate_retained_tool_record(mutation: str) -> None:
    bundle = specimen()
    invocations = bundle["inputs"]["invocations"]
    if mutation == "omit":
        invocations.clear()
    else:
        invocations.append(deepcopy(invocations[0]))
    recommit(bundle)
    result = assess(bundle)
    assert result["status"] == "FAIL"
    assert result["selected_checks"]["HARNESS-2.2"]["status"] == "FAIL"
    # Current transcript proves retained commitments independently of tool pairing.
    # The independently detected tools failure still prevents aggregate PASS.
    assert result["selected_checks"]["HARNESS-4.1"]["status"] == "PASS"


@pytest.mark.parametrize("index", [False, 0.0])
def test_transcript_index_requires_exact_integer_even_after_recommit(index: object) -> None:
    bundle = specimen()
    bundle["inputs"]["records"][0]["index"] = index
    recommit(bundle)
    result = assess(bundle)
    assert result["status"] == "FAIL"
    assert result["selected_checks"]["HARNESS-2.1"]["status"] == "FAIL"


@pytest.mark.parametrize("count", [True, 1.0])
def test_record_count_requires_exact_integer(count: object) -> None:
    bundle = specimen()
    bundle["inputs"]["records"] = bundle["inputs"]["records"][:1]
    bundle["inputs"]["invocations"] = []
    bundle["artifact"]["record_count"] = count
    recommit(bundle)
    result = assess(bundle)
    assert result["status"] == "FAIL"
    assert result["selected_checks"]["HARNESS-2.1"]["status"] == "FAIL"


class InterruptedMechanism:
    mechanism_id = "test:harness-cancellation-1"
    mechanism_digest = digest("test:interrupted-mechanism")

    def __init__(self, exception: type[BaseException]) -> None:
        self.exception = exception

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        raise self.exception("mechanism interrupted")

    def evaluate_compound(self, bindings: Sequence[BoundProposition],
                          evidence: Sequence[Sequence[bytes]]) -> Sequence[MechanismDecision]:
        raise self.exception("compound mechanism interrupted")


def cancellation_session(exception: type[BaseException]) -> tuple[VerificationSession, BoundProposition]:
    store = EvidenceStore()
    reference = store.add(b"retained revision")
    mechanism = InterruptedMechanism(exception)
    session = VerificationSession(store)
    session.register(mechanism)
    binding = BoundProposition(subject_id="test:harness", predicate="test:revision-binding-1",
                               expected=True, mechanism_id=mechanism.mechanism_id,
                               mechanism_digest=mechanism.mechanism_digest, evidence_refs=(reference,),
                               trust_roots=("test:checker",), bounds=EvidenceBounds(1, 64))
    return session, binding


@pytest.mark.parametrize("compound", [False, True])
def test_mechanism_cancellation_is_unknown(compound: bool) -> None:
    session, binding = cancellation_session(CancelledError)
    evaluations = session.evaluate_compound((binding, binding)) if compound else (session.evaluate(binding),)
    assert len(evaluations) == (2 if compound else 1)
    for evaluated in evaluations:
        assert evaluated.outcome is MechanismOutcome.UNKNOWN
        assert not evaluated.passed
        assert evaluated.binding_digest == binding.digest()
        assert "CancelledError" in evaluated.details
        assert evaluated.observed_evidence_bytes == len(b"retained revision")


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("compound", [False, True])
def test_process_interrupts_still_propagate(exception: type[BaseException], compound: bool) -> None:
    session, binding = cancellation_session(exception)
    with pytest.raises(exception):
        if compound:
            session.evaluate_compound((binding,))
        else:
            session.evaluate(binding)


@pytest.mark.parametrize("revision", ["artifact", "instructions", "context", "goal"])
def test_exact_retained_revision_binding_and_portable_replay(revision: str) -> None:
    original = (revision + ":revision-1\nretained bytes").encode("utf-8")
    expected_store = EvidenceStore()
    expected = expected_store.add(original)
    mechanism = BytesDigestMechanism()
    for altered in (False, True):
        store = EvidenceStore()
        observed = store.add(original + b" substituted" if altered else original)
        binding = BoundProposition(
            subject_id="test:retained-harness", predicate="bytes.sha256", expected=expected,
            mechanism_id=mechanism.mechanism_id, mechanism_digest=mechanism.mechanism_digest,
            evidence_refs=(observed,), trust_roots=("test:externally-selected-revision",),
            bounds=EvidenceBounds(1, 128),
            parameters={"contract": "times-harness-verifier-contract-1", "revision": revision})
        session = VerificationSession(store)
        session.register(mechanism)
        evaluated = session.evaluate(binding)
        assert evaluated.outcome is (MechanismOutcome.FAIL if altered else MechanismOutcome.PASS)
        restored = EvidenceStore()
        restored.import_base64(store.export_base64(binding.evidence_refs))
        replay = VerificationSession(restored)
        replay.register(mechanism)
        assert replay.evaluate(binding).to_dict() == evaluated.to_dict()
        # A complete reference without retained bytes is unavailable, not verified.
        absent = VerificationSession(EvidenceStore())
        absent.register(mechanism)
        assert absent.evaluate(binding).outcome is MechanismOutcome.UNKNOWN


def test_missing_current_tool_declaration_remains_unknown():
    bundle = specimen()
    bundle["inputs"].pop("declarations")
    result = assess(bundle)
    assert result["selected_checks"]["HARNESS-2.2"]["status"] == "UNKNOWN"
    assert result["status"] == "UNKNOWN"
