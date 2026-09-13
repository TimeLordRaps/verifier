"""Adversarial runtime-authority correspondence tests for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) fixtures retain inert declarations and traces.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any

import pytest

from verifier.interoperability.network import (
    AUTHORITY_ACTOR_SCOPE_VERSION,
    AUTHORITY_AXIOM_AGENCY,
    AUTHORITY_AXIOM_AGENCY_VERSION,
    AuthorityModel,
    AuthorityState,
    AuthorityTransition,
    authority_actor_scope_digest,
    authority_axiom_agency_digest,
    canonical_bytes,
    digest_bytes,
)
from verifier.interoperability.runtime_authority_correspondence import (
    CLAIM_BOUNDARY,
    DECLARATION_SCHEMA,
    SUPPORTED_RUNTIME_KIND,
    TRACE_SCHEMA,
    CorrespondenceVerdict,
    CoverageCompleteness,
    DeriverExecutionEvidence,
    RuntimeCoordinate,
    build_runtime_authority_correspondence_receipt,
    recheck_runtime_authority_correspondence_receipt,
    runtime_authority_profile_digest,
)
import verifier.interoperability.runtime_authority_correspondence as runtime_module


_DERIVER_CHECKER_SOURCE_DIGEST = digest_bytes(b"test-only deriver checker source")
_REAL_DERIVER_RECHECK = runtime_module._recheck_deriver_execution


@pytest.fixture(autouse=True)
def _bounded_fake_deriver_recheck(monkeypatch: pytest.MonkeyPatch) -> None:
    def recheck(
        declaration_bytes: bytes,
        receipt_bytes: bytes,
        _executable_path: str | Path | None,
    ) -> DeriverExecutionEvidence:
        status_bytes, separator, stdout = receipt_bytes.partition(b"\n")
        if not separator:
            return DeriverExecutionEvidence(
                CorrespondenceVerdict.INVALID, None, None, None, None, ("FAKE_RECEIPT_INVALID",)
            )
        try:
            status = CorrespondenceVerdict(status_bytes.decode("ascii"))
            executable_digest, execution_coordinate_digest = declaration_bytes.decode("ascii").splitlines()
        except (UnicodeError, ValueError):
            return DeriverExecutionEvidence(
                CorrespondenceVerdict.INVALID, None, None, None, None, ("FAKE_RECEIPT_INVALID",)
            )
        return DeriverExecutionEvidence(
            status=status,
            standard_output_bytes=stdout if status is CorrespondenceVerdict.ESTABLISHED else None,
            executable_digest=executable_digest,
            runtime_coordinate_digest=execution_coordinate_digest,
            checker_source_digest=_DERIVER_CHECKER_SOURCE_DIGEST,
            reason_codes=() if status is CorrespondenceVerdict.ESTABLISHED else (f"FAKE_{status.value}",),
        )

    monkeypatch.setattr(runtime_module, "_recheck_deriver_execution", recheck)


def _composed_model_bytes() -> bytes:
    states = tuple(
        AuthorityState(state_id, AUTHORITY_AXIOM_AGENCY, ())
        for state_id in ("s00", "s01", "s10", "s11")
    )
    transitions = (
        AuthorityTransition("left-off", "s11", "s01", "ANY_ACTOR", "LEFT_OFF"),
        AuthorityTransition("left-on", "s00", "s10", "ANY_ACTOR", "LEFT_ON"),
        AuthorityTransition("right-off", "s01", "s00", "ANY_ACTOR", "RIGHT_OFF"),
        AuthorityTransition("right-on", "s10", "s11", "ANY_ACTOR", "RIGHT_ON"),
    )
    model = AuthorityModel(
        authority_axiom_agency_version=AUTHORITY_AXIOM_AGENCY_VERSION,
        authority_axiom_agency_digest=authority_axiom_agency_digest(),
        actor_scope_version=AUTHORITY_ACTOR_SCOPE_VERSION,
        actor_scope_digest=authority_actor_scope_digest(),
        initial_state_ids=("s00",),
        state_universe=("s00", "s01", "s10", "s11"),
        transition_universe=("left-off", "left-on", "right-off", "right-on"),
        states=states,
        transitions=transitions,
        closure_status="CLOSED",
        residual_obligations=(),
    )
    return canonical_bytes(model.to_dict())


def _fixture(
    *,
    platform: str = "windows-amd64",
    maximum_events: int = 16,
    executable_bytes: bytes = b"example executable bytes\x00v1",
    deployed_bytes: bytes = b"example deployed artifact bytes\x00v1",
    execution_coordinate_digest: str = digest_bytes(b"test-only execution coordinate"),
) -> tuple[dict[str, Any], dict[str, bytes]]:
    model_bytes = _composed_model_bytes()
    coordinate = RuntimeCoordinate(
        runtime_kind=SUPPORTED_RUNTIME_KIND,
        platform=platform,
        runtime_version="example-runtime-1",
        invocation_digest=digest_bytes(b"argv:--bounded-replay"),
        execution_coordinate_digest=execution_coordinate_digest,
        deployment_coordinate="example/slot-a/revision-7",
        maximum_events=maximum_events,
    )
    mappings = [
        {
            "event_type": "authority.left.off",
            "actor_scope": "ANY_ACTOR",
            "action": "LEFT_OFF",
            "authority_transition_id": "left-off",
        },
        {
            "event_type": "authority.left.on",
            "actor_scope": "ANY_ACTOR",
            "action": "LEFT_ON",
            "authority_transition_id": "left-on",
        },
        {
            "event_type": "authority.right.off",
            "actor_scope": "ANY_ACTOR",
            "action": "RIGHT_OFF",
            "authority_transition_id": "right-off",
        },
        {
            "event_type": "authority.right.on",
            "actor_scope": "ANY_ACTOR",
            "action": "RIGHT_ON",
            "authority_transition_id": "right-on",
        },
    ]
    events = [
        {"sequence": 0, "event_id": "event-0", **{key: mappings[1][key] for key in ("event_type", "actor_scope", "action")}},
        {"sequence": 1, "event_id": "event-1", **{key: mappings[3][key] for key in ("event_type", "actor_scope", "action")}},
        {"sequence": 2, "event_id": "event-2", **{key: mappings[0][key] for key in ("event_type", "actor_scope", "action")}},
        {"sequence": 3, "event_id": "event-3", **{key: mappings[2][key] for key in ("event_type", "actor_scope", "action")}},
    ]
    trace = {
        "schema_version": TRACE_SCHEMA,
        "authority_model_digest": digest_bytes(model_bytes),
        "executable_artifact_digest": digest_bytes(executable_bytes),
        "deployed_artifact_digest": digest_bytes(deployed_bytes),
        "runtime_coordinate_digest": coordinate.canonical_digest(),
        "events": events,
    }
    trace_bytes = canonical_bytes(trace)
    deriver_declaration_bytes = (
        digest_bytes(executable_bytes) + "\n" + execution_coordinate_digest
    ).encode("ascii")
    deriver_receipt_bytes = b"ESTABLISHED\n" + trace_bytes
    declaration = {
        "schema_version": DECLARATION_SCHEMA,
        "profile_digest": runtime_authority_profile_digest(),
        "authority_model_digest": digest_bytes(model_bytes),
        "executable_artifact_digest": digest_bytes(executable_bytes),
        "deployed_artifact_digest": digest_bytes(deployed_bytes),
        "trace_digest": digest_bytes(trace_bytes),
        "deriver_declaration_digest": digest_bytes(deriver_declaration_bytes),
        "deriver_receipt_digest": digest_bytes(deriver_receipt_bytes),
        "deriver_checker_source_digest": _DERIVER_CHECKER_SOURCE_DIGEST,
        "deriver_standard_output_digest": digest_bytes(trace_bytes),
        "deriver_standard_output_size_bytes": len(trace_bytes),
        "runtime_coordinate": coordinate.to_dict(),
        "initial_state_id": "s00",
        "transition_mappings": mappings,
        "coverage_transition_ids": ["left-off", "left-on", "right-off", "right-on"],
    }
    evidence = {
        digest_bytes(model_bytes): model_bytes,
        digest_bytes(executable_bytes): executable_bytes,
        digest_bytes(deployed_bytes): deployed_bytes,
        digest_bytes(trace_bytes): trace_bytes,
        digest_bytes(deriver_declaration_bytes): deriver_declaration_bytes,
        digest_bytes(deriver_receipt_bytes): deriver_receipt_bytes,
    }
    return declaration, evidence


def _assess(declaration: dict[str, Any], evidence: dict[str, bytes]):
    return build_runtime_authority_correspondence_receipt(canonical_bytes(declaration), evidence)


def _replace_trace(declaration: dict[str, Any], evidence: dict[str, bytes], trace: dict[str, Any]) -> None:
    old_digest = declaration["trace_digest"]
    payload = canonical_bytes(trace)
    declaration["trace_digest"] = digest_bytes(payload)
    declaration["deriver_standard_output_digest"] = digest_bytes(payload)
    declaration["deriver_standard_output_size_bytes"] = len(payload)
    evidence.pop(old_digest)
    evidence[declaration["trace_digest"]] = payload
    _replace_deriver_receipt(declaration, evidence, b"ESTABLISHED\n" + payload)


def _trace(declaration: dict[str, Any], evidence: dict[str, bytes]) -> dict[str, Any]:
    return json.loads(evidence[declaration["trace_digest"]])


def _replace_deriver_receipt(
    declaration: dict[str, Any], evidence: dict[str, bytes], payload: bytes
) -> None:
    evidence.pop(declaration["deriver_receipt_digest"])
    declaration["deriver_receipt_digest"] = digest_bytes(payload)
    evidence[declaration["deriver_receipt_digest"]] = payload


@pytest.mark.parametrize("platform", ("linux-x86_64", "macos-arm64", "windows-amd64"))
def test_composed_model_replay_is_portable_and_complete_for_its_finite_denominator(platform: str) -> None:
    declaration, evidence = _fixture(platform=platform)
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.ESTABLISHED
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.ESTABLISHED
    assert receipt.coverage_completeness is CoverageCompleteness.COMPLETE
    assert receipt.observed_event_count == 4
    assert receipt.covered_transition_ids == ("left-off", "left-on", "right-off", "right-on")
    assert receipt.reconstructed_state_ids == ("s00", "s10", "s11", "s01", "s00")
    assert receipt.claim_boundary == CLAIM_BOUNDARY
    assert len(receipt.retained_evidence) == 6
    assert _assess(declaration, dict(reversed(tuple(evidence.items())))).to_bytes() == receipt.to_bytes()
    recheck = recheck_runtime_authority_correspondence_receipt(receipt.to_bytes())
    assert recheck.verdict is CorrespondenceVerdict.ESTABLISHED
    assert recheck.receipt_digest == receipt.receipt_digest


def test_observed_correspondence_does_not_imply_complete_coverage() -> None:
    declaration, evidence = _fixture()
    trace = _trace(declaration, evidence)
    trace["events"] = trace["events"][:2]
    _replace_trace(declaration, evidence, trace)
    receipt = _assess(declaration, evidence)
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.ESTABLISHED
    assert receipt.coverage_completeness is CoverageCompleteness.INCOMPLETE
    assert receipt.covered_transition_ids == ("left-on", "right-on")
    assert receipt.reason_codes == ("FINITE_DENOMINATOR_INCOMPLETE",)


def test_fabricated_trace_without_reproduced_execution_stays_unknown() -> None:
    declaration, evidence = _fixture()
    evidence.pop(declaration["deriver_receipt_digest"])
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.UNKNOWN
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.UNKNOWN
    assert receipt.coverage_completeness is CoverageCompleteness.UNKNOWN
    assert receipt.reason_codes == ("SELECTED_EVIDENCE_MISSING_OR_UNTRUSTED",)


def test_established_execution_with_different_standard_output_is_invalid() -> None:
    declaration, evidence = _fixture()
    _replace_deriver_receipt(declaration, evidence, b"ESTABLISHED\nnot the retained trace")
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.ESTABLISHED
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.INVALID
    assert receipt.coverage_completeness is CoverageCompleteness.INVALID
    assert receipt.reason_codes == ("DERIVER_EXECUTION_TRACE_OR_COORDINATE_MISMATCH",)


@pytest.mark.parametrize(
    ("status", "expected"),
    (
        ("REFUTED", CorrespondenceVerdict.REFUTED),
        ("UNKNOWN", CorrespondenceVerdict.UNKNOWN),
    ),
)
def test_nonestablished_deriver_result_cannot_establish_correspondence(
    status: str, expected: CorrespondenceVerdict
) -> None:
    declaration, evidence = _fixture()
    trace_bytes = evidence[declaration["trace_digest"]]
    _replace_deriver_receipt(declaration, evidence, status.encode("ascii") + b"\n" + trace_bytes)
    receipt = _assess(declaration, evidence)
    assert receipt.observed_transition_correspondence is expected
    assert receipt.coverage_completeness is CoverageCompleteness.UNKNOWN
    assert "DERIVER_EXECUTION_NOT_ESTABLISHED" in receipt.reason_codes or "DERIVER_EXECUTION_REFUTED" in receipt.reason_codes


@pytest.mark.parametrize(
    "coordinate",
    (
        "executable_artifact_digest",
        "deployed_artifact_digest",
        "authority_model_digest",
        "deriver_receipt_digest",
    ),
)
def test_exact_artifact_substitution_is_invalid(coordinate: str) -> None:
    declaration, evidence = _fixture()
    evidence[declaration[coordinate]] = b"substituted bytes"
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.INVALID
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.INVALID
    assert receipt.coverage_completeness is CoverageCompleteness.INVALID
    assert receipt.reason_codes == ("SELECTED_EVIDENCE_SUBSTITUTED",)


def test_deriver_checker_source_substitution_is_invalid() -> None:
    declaration, evidence = _fixture()
    declaration["deriver_checker_source_digest"] = digest_bytes(b"substituted checker")
    receipt = _assess(declaration, evidence)
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.INVALID
    assert receipt.coverage_completeness is CoverageCompleteness.INVALID
    assert receipt.reason_codes == ("DERIVER_EXECUTION_TRACE_OR_COORDINATE_MISMATCH",)


def test_deriver_runtime_coordinate_substitution_is_invalid() -> None:
    declaration, evidence = _fixture()
    declaration["runtime_coordinate"]["execution_coordinate_digest"] = digest_bytes(
        b"different runtime coordinate"
    )
    receipt = _assess(declaration, evidence)
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.INVALID
    assert receipt.coverage_completeness is CoverageCompleteness.INVALID
    assert receipt.reason_codes == ("DERIVER_EXECUTION_TRACE_OR_COORDINATE_MISMATCH",)


@pytest.mark.parametrize("mutation", ("omission", "event_alias", "transition_alias"))
def test_mapping_omission_or_alias_is_invalid(mutation: str) -> None:
    declaration, evidence = _fixture()
    if mutation == "omission":
        declaration["transition_mappings"].pop()
    elif mutation == "event_alias":
        declaration["transition_mappings"][1].update(
            {
                key: declaration["transition_mappings"][0][key]
                for key in ("event_type", "actor_scope", "action")
            }
        )
    else:
        declaration["transition_mappings"][1]["authority_transition_id"] = "left-off"
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.INVALID
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.INVALID
    assert receipt.coverage_completeness is CoverageCompleteness.INVALID
    assert receipt.reason_codes == ("DECLARATION_INVALID",)


def test_impossible_transition_is_refuted_after_deterministic_state_reconstruction() -> None:
    declaration, evidence = _fixture()
    trace = _trace(declaration, evidence)
    trace["events"] = [trace["events"][1], trace["events"][0], *trace["events"][2:]]
    for sequence, event in enumerate(trace["events"]):
        event["sequence"] = sequence
    _replace_trace(declaration, evidence, trace)
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.ESTABLISHED
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.REFUTED
    assert receipt.coverage_completeness is CoverageCompleteness.UNKNOWN
    assert receipt.reason_codes == ("OBSERVED_TRANSITION_IMPOSSIBLE_FROM_RECONSTRUCTED_STATE",)


@pytest.mark.parametrize("mutation", ("mapping_actor", "event_action"))
def test_actor_or_action_mismatch_is_refuted(mutation: str) -> None:
    declaration, evidence = _fixture()
    if mutation == "mapping_actor":
        declaration["transition_mappings"][0]["actor_scope"] = "NAMED_ACTOR"
        declaration["transition_mappings"] = sorted(
            declaration["transition_mappings"],
            key=lambda item: (item["event_type"], item["actor_scope"], item["action"], item["authority_transition_id"]),
        )
    else:
        trace = _trace(declaration, evidence)
        trace["events"][0]["action"] = "UNDECLARED_ACTION"
        _replace_trace(declaration, evidence, trace)
    receipt = _assess(declaration, evidence)
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.REFUTED
    assert receipt.coverage_completeness is CoverageCompleteness.UNKNOWN
    assert receipt.reason_codes == (
        "MAPPING_ACTOR_OR_ACTION_MISMATCH" if mutation == "mapping_actor" else "OBSERVED_EVENT_HAS_NO_EXACT_MAPPING",
    )


@pytest.mark.parametrize("mutation", ("gap", "reordering"))
def test_trace_gap_or_unrenumbered_reordering_is_invalid(mutation: str) -> None:
    declaration, evidence = _fixture()
    trace = _trace(declaration, evidence)
    if mutation == "gap":
        trace["events"][1]["sequence"] = 2
    else:
        trace["events"].reverse()
    _replace_trace(declaration, evidence, trace)
    receipt = _assess(declaration, evidence)
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.INVALID
    assert receipt.coverage_completeness is CoverageCompleteness.INVALID
    assert receipt.reason_codes == ("MODEL_OR_TRACE_INVALID",)


def test_incomplete_or_untrusted_evidence_is_unknown_not_a_pass() -> None:
    declaration, evidence = _fixture()
    evidence.pop(declaration["deployed_artifact_digest"])
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.UNKNOWN
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.UNKNOWN
    assert receipt.coverage_completeness is CoverageCompleteness.UNKNOWN
    evidence[declaration["deployed_artifact_digest"]] = None  # type: ignore[assignment]
    assert _assess(declaration, evidence).coordinate_binding is CorrespondenceVerdict.UNKNOWN


def test_unsupported_runtime_is_unknown_even_when_exact_bytes_are_bound() -> None:
    declaration, evidence = _fixture()
    declaration["runtime_coordinate"]["runtime_kind"] = "UNSUPPORTED-RUNTIME-1"
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.ESTABLISHED
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.UNKNOWN
    assert receipt.coverage_completeness is CoverageCompleteness.UNKNOWN
    assert receipt.reason_codes == ("RUNTIME_KIND_UNSUPPORTED",)


def test_declared_event_budget_exhaustion_is_unknown() -> None:
    declaration, evidence = _fixture(maximum_events=2)
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.ESTABLISHED
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.UNKNOWN
    assert receipt.coverage_completeness is CoverageCompleteness.UNKNOWN
    assert receipt.observed_event_count == 4
    assert receipt.reason_codes == ("DECLARED_EVENT_BUDGET_EXHAUSTED",)


def test_decoded_node_budget_exhaustion_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    import verifier.interoperability.runtime_authority_correspondence as module

    declaration, evidence = _fixture()
    monkeypatch.setattr(module, "MAX_JSON_NODES", 2)
    receipt = _assess(declaration, evidence)
    assert receipt.coordinate_binding is CorrespondenceVerdict.UNKNOWN
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.UNKNOWN
    assert receipt.coverage_completeness is CoverageCompleteness.UNKNOWN
    assert receipt.reason_codes == ("DECLARATION_LIMIT_EXHAUSTED",)


def test_trace_coordinate_substitution_is_invalid() -> None:
    declaration, evidence = _fixture()
    trace = _trace(declaration, evidence)
    trace["deployed_artifact_digest"] = digest_bytes(b"different deployed artifact")
    _replace_trace(declaration, evidence, trace)
    receipt = _assess(declaration, evidence)
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.INVALID
    assert receipt.coverage_completeness is CoverageCompleteness.INVALID
    assert receipt.reason_codes == ("TRACE_COORDINATE_SUBSTITUTION",)


@pytest.mark.parametrize("recompute_digest", (False, True))
def test_forged_receipt_is_invalid_even_if_the_attacker_recomputes_its_digest(recompute_digest: bool) -> None:
    declaration, evidence = _fixture()
    receipt = _assess(declaration, evidence)
    forged = json.loads(receipt.to_bytes())
    forged["coverage_completeness"] = "INCOMPLETE"
    if recompute_digest:
        body = {key: value for key, value in forged.items() if key != "receipt_digest"}
        forged["receipt_digest"] = digest_bytes(canonical_bytes(body))
    recheck = recheck_runtime_authority_correspondence_receipt(canonical_bytes(forged))
    assert recheck.verdict is CorrespondenceVerdict.INVALID
    assert recheck.reason_codes == ("RECEIPT_INVALID_OR_FORGED",)


def test_receipt_digests_bind_all_retained_coordinates_without_claiming_deployment_truth() -> None:
    declaration, evidence = _fixture()
    declaration_bytes = canonical_bytes(declaration)
    receipt = build_runtime_authority_correspondence_receipt(declaration_bytes, evidence)
    assert receipt.declaration_digest == digest_bytes(declaration_bytes)
    assert receipt.runtime_coordinate_digest == digest_bytes(canonical_bytes(declaration["runtime_coordinate"]))
    assert {item.coordinate for item in receipt.retained_evidence} == {
        declaration["authority_model_digest"],
        declaration["executable_artifact_digest"],
        declaration["deployed_artifact_digest"],
        declaration["trace_digest"],
        declaration["deriver_declaration_digest"],
        declaration["deriver_receipt_digest"],
    }
    assert "does not prove" in receipt.claim_boundary
    assert "actual deployment" in receipt.claim_boundary


def test_real_local_deriver_execution_produces_and_reproduces_the_exact_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.interoperability.deriver_self_status import (
        DeriverSessionDeclaration,
        record_deriver_session,
        runtime_coordinate_for,
    )
    import verifier.interoperability.deriver_self_status as deriver_module

    monkeypatch.setattr(runtime_module, "_recheck_deriver_execution", _REAL_DERIVER_RECHECK)
    # ``uv run --with`` may expose a short-lived launcher that cannot be
    # independently re-executed. Bind the stable interpreter that launcher uses.
    executable_path = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    executable_bytes = executable_path.read_bytes()
    deriver_coordinate = runtime_coordinate_for(executable_path)
    declaration, evidence = _fixture(
        platform=sys.platform,
        executable_bytes=executable_bytes,
        deployed_bytes=executable_bytes,
        execution_coordinate_digest=digest_bytes(canonical_bytes(deriver_coordinate.to_dict())),
    )
    trace_bytes = evidence[declaration["trace_digest"]]
    source_bytes = Path(deriver_module.__file__).read_bytes()
    assert digest_bytes(source_bytes) == "sha256:50379e925911f8a0a7cd3940b62b8d39ae60bf863d9898533729e854edc86dff"
    public_environment = (
        (("SYSTEMROOT", os.environ["SystemRoot"]),) if os.name == "nt" else ()
    )
    session = DeriverSessionDeclaration(
        deriver_id="tests.runtime-authority-trace-producer.0.1",
        subject_digest=declaration["authority_model_digest"],
        runtime_coordinate=deriver_coordinate,
        arguments=(
            "-c",
            "import sys;sys.stdout.buffer.write(bytes.fromhex(" + repr(trace_bytes.hex()) + "))",
        ),
        public_environment=public_environment,
        stdin_bytes=b"",
        stdin_digest=digest_bytes(b""),
        expected_stdout_digest=digest_bytes(trace_bytes),
        expected_stderr_digest=digest_bytes(b""),
        expected_exit_code=0,
        timeout_ms=10_000,
        max_output_bytes=len(trace_bytes) + 1_024,
    )
    session_bytes = session.to_bytes()
    session_receipt_bytes = record_deriver_session(session_bytes, executable_path).to_bytes()
    evidence.pop(declaration["deriver_declaration_digest"])
    evidence.pop(declaration["deriver_receipt_digest"])
    declaration["deriver_declaration_digest"] = digest_bytes(session_bytes)
    declaration["deriver_receipt_digest"] = digest_bytes(session_receipt_bytes)
    declaration["deriver_checker_source_digest"] = digest_bytes(source_bytes)
    evidence[declaration["deriver_declaration_digest"]] = session_bytes
    evidence[declaration["deriver_receipt_digest"]] = session_receipt_bytes

    receipt = build_runtime_authority_correspondence_receipt(
        canonical_bytes(declaration), evidence, executable_path
    )
    assert receipt.coordinate_binding is CorrespondenceVerdict.ESTABLISHED
    assert receipt.observed_transition_correspondence is CorrespondenceVerdict.ESTABLISHED
    assert receipt.coverage_completeness is CoverageCompleteness.COMPLETE
    recheck = recheck_runtime_authority_correspondence_receipt(
        receipt.to_bytes(), executable_path
    )
    assert recheck.verdict is CorrespondenceVerdict.ESTABLISHED
