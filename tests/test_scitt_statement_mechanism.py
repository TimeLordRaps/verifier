"""Synthetic Supply Chain Integrity, Transparency, and Trust (SCITT) mechanism tests.

JavaScript Object Notation (JSON) output fixtures do not constitute native execution.
The mechanism identifier (ID) selects only the native acceptance predicate.
"""

from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from examples.scitt_native_interop import statement_mechanism

from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, MechanismOutcome, VerificationSession


ROOT = Path(__file__).resolve().parents[1]


def test_native_statement_mechanism_exists() -> None:
    assert statement_mechanism.STATEMENT_PREDICATE == "scitt.go.statement-native-acceptance"


def setup_host(tmp_path: Path, *, approved: bool = True) -> tuple[Any, Any, BoundProposition, tuple[bytes, bytes], Path]:
    module = statement_mechanism
    executable = tmp_path / "checker"
    executable.write_bytes(b"synthetic nonexecutable checker")
    output = tmp_path / "outputs"
    output.mkdir()
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    identity = module.mechanism_digest(executable, digest)
    evidence = (b"synthetic statement", b"synthetic public key")
    refs = tuple("sha256:" + hashlib.sha256(raw).hexdigest() for raw in evidence)
    binding = BoundProposition(refs[0], module.STATEMENT_PREDICATE, True,
        module.MECHANISM_ID, identity, refs, ("host-selected-native-runtime",),
        EvidenceBounds(2, 1024), {"algorithm": "EdDSA", "statement_ref": refs[0], "public_key_ref": refs[1]})
    mechanism = module.GoStatementAcceptanceMechanism(executable, digest, output_root=output,
        approved_bindings=(binding,) if approved else ())
    return module, mechanism, binding, evidence, output


def accepted() -> tuple[int, None, bytes, bytes]:
    return 0, None, json.dumps({"valid": True, "alg": "EdDSA", "content_type": "", "iss": "", "sub": ""}).encode(), b""


def run_session(mechanism: Any, binding: BoundProposition, evidence: tuple[bytes, ...]) -> Any:
    store = EvidenceStore()
    for item in evidence:
        store.add(item)
    session = VerificationSession(store)
    session.register(mechanism)
    return session.evaluate(binding)


def test_session_actually_invokes_pinned_checker_and_retains_portable_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    calls = []

    def invoke(name: str, arguments: list[str], cwd: Path, **limits: Any) -> tuple[int, None, bytes, bytes]:
        calls.append((arguments, limits))
        assert (cwd / "statement.cose").read_bytes() == evidence[0]
        assert (cwd / "public-key.pem").read_bytes() == evidence[1]
        return accepted()

    monkeypatch.setattr(module.runner, "_run_process", invoke)
    result = run_session(mechanism, binding, evidence)
    assert result.outcome is MechanismOutcome.PASS
    assert len(calls) == 1 and calls[0][0][1:] == list(module.ARGUMENTS)
    assert calls[0][1] == {"timeout": 20, "output_limit": 128 * 1024}
    directory, = output.iterdir()
    assert {p.name for p in directory.iterdir()} == {"statement.cose", "public-key.pem", "stdout.bin", "stderr.bin", "observation.json"}
    assert json.loads((directory / "observation.json").read_bytes()) == result.observations
    assert str(tmp_path) not in json.dumps(result.to_dict())
    assert "approved_bindings" not in json.dumps(result.observations)


@pytest.mark.parametrize("change", ["no-approval", "subject", "expected", "predicate", "key", "statement", "order", "trust", "parameter", "bounds", "bool-bound", "mechanism", "identity", "oversized", "evidence-type"])
def test_unapproved_or_malformed_request_never_invokes_or_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path, approved=change != "no-approval")
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: pytest.fail("native invocation forbidden"))
    if change == "subject": binding = replace(binding, subject_id="unrelated claim")
    elif change == "expected": binding = replace(binding, expected=1)
    elif change == "predicate": binding = replace(binding, predicate="signature-valid")
    elif change == "key": evidence = (evidence[0], b"other key")
    elif change == "statement": evidence = (b"other statement", evidence[1])
    elif change == "order": evidence = tuple(reversed(evidence))
    elif change == "trust": binding = replace(binding, trust_roots=("other host",))
    elif change == "parameter": binding.parameters["algorithm"] = "other"
    elif change == "bounds": binding = replace(binding, bounds=EvidenceBounds(2, 2048))
    elif change == "bool-bound": binding = replace(binding, bounds=EvidenceBounds(True, 1024))
    elif change == "mechanism": binding = replace(binding, mechanism_id="other")
    elif change == "identity": binding = replace(binding, mechanism_digest="sha256:" + "0" * 64)
    elif change == "oversized": evidence = (b"x" * (module.MAX_INPUT_BYTES + 1), evidence[1])
    elif change == "evidence-type": evidence = (bytearray(evidence[0]), evidence[1])
    assert mechanism.evaluate(binding, evidence).outcome is MechanismOutcome.UNKNOWN
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("code,reason,stdout,stderr,outcome", [
    (*accepted(), MechanismOutcome.PASS),
    (1, None, json.dumps({"valid": False, "alg": "EdDSA", "content_type": "", "iss": "", "sub": "", "error": "signature verification failed: verification error"}).encode(), b"", MechanismOutcome.FAIL),
    (None, "TIMEOUT", accepted()[2], b"", MechanismOutcome.UNKNOWN),
    (None, "OUTPUT_LIMIT", accepted()[2], b"", MechanismOutcome.UNKNOWN),
    (None, "LAUNCH_ERROR", b"", b"", MechanismOutcome.UNKNOWN),
    (1, None, b"malformed", b"", MechanismOutcome.UNKNOWN),
    (0, None, accepted()[2], b"operational error", MechanismOutcome.UNKNOWN),
    (1, None, b'{"valid":false,"error":"cannot read key"}', b"", MechanismOutcome.UNKNOWN),
    (True, None, accepted()[2], b"", MechanismOutcome.UNKNOWN),
    (0, None, b"x" * (128 * 1024 + 1), b"", MechanismOutcome.UNKNOWN),
], ids=["accept", "native-false", "timeout", "output-limit", "launch-error", "malformed", "stderr", "operational-false", "bool-exit", "oversized-channel"])
def test_only_recognized_native_acceptance_or_false_is_decisive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int | None, reason: str | None, stdout: bytes, stderr: bytes, outcome: MechanismOutcome) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: (code, reason, stdout, stderr))
    result = mechanism.evaluate(binding, evidence)
    assert result.outcome is outcome
    assert result.observations["native_invocation_attempted"] is True


@pytest.mark.parametrize("when,which", [(when, which) for when in ("before", "during") for which in ("executable", "helper", "runner", "decoder", "input", "binding")])
def test_pre_post_identity_and_input_drift_never_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, when: str, which: str) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    original = module.runner.read_regular
    changed = False
    count = 0
    source = {"helper": "statement_mechanism.py", "runner": "native_runner.py", "decoder": "package_comparison.py"}.get(which)

    def read(path: Path, limit: int) -> bytes:
        raw = original(path, limit)
        return raw + b"drift" if changed and path.name == source else raw

    def mutate(directory: Path | None) -> None:
        nonlocal changed
        changed = True
        if which == "executable": mechanism._go_checker.write_bytes(b"changed")
        elif which == "binding": binding.parameters["statement_ref"] = binding.evidence_refs[1]
        elif which == "input" and directory is not None: (directory / "statement.cose").write_bytes(b"changed")

    def invoke(*args: Any, **kwargs: Any) -> tuple[int, None, bytes, bytes]:
        nonlocal count
        count += 1
        mutate(args[2])
        return accepted()

    monkeypatch.setattr(module.runner, "read_regular", read)
    monkeypatch.setattr(module.runner, "_run_process", invoke)
    if when == "before":
        mutate(None)
        if which == "input": evidence = (b"changed", evidence[1])
    assert mechanism.evaluate(binding, evidence).outcome is MechanismOutcome.UNKNOWN
    assert count == (0 if when == "before" else 1)
    if when == "before": assert list(output.iterdir()) == []


def test_replay_requires_separate_host_approval_and_reruns_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    calls = []
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: (calls.append(1), accepted())[1])
    first = run_session(mechanism, binding, evidence)
    retained = tuple(base64.b64decode(first.observations["input_base64"][name]) for name in ("statement.cose", "public-key.pem"))
    denied = module.GoStatementAcceptanceMechanism(mechanism._go_checker, mechanism._coordinate["go_checker_sha256"], output_root=output)
    assert run_session(denied, binding, retained).outcome is MechanismOutcome.UNKNOWN
    replay = module.GoStatementAcceptanceMechanism(mechanism._go_checker, mechanism._coordinate["go_checker_sha256"], output_root=output, approved_bindings=(binding,))
    assert run_session(replay, binding, retained).to_dict() == first.to_dict()
    assert len(calls) == 2 and len(list(output.iterdir())) == 2


def test_session_enforces_missing_evidence_before_mechanism(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: pytest.fail("missing evidence executed"))
    assert run_session(mechanism, binding, evidence[:1]).outcome is MechanismOutcome.UNKNOWN
    assert list(output.iterdir()) == []


def test_cancellation_propagates_without_inventing_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)

    def interrupt(*args: Any, **kwargs: Any) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(module.runner, "_run_process", interrupt)
    with pytest.raises(KeyboardInterrupt): mechanism.evaluate(binding, evidence)
    directory, = output.iterdir()
    assert not (directory / "observation.json").exists()


def test_late_binding_mutation_does_not_attach_pass_to_changed_session_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The session hands the mechanism a private copy of the binding, so the late edit targets that copy.
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    original = module.runner._write_new
    evaluate = mechanism.evaluate
    invocation: list[BoundProposition] = []

    def spy(session_binding: BoundProposition, inputs: Any) -> Any:
        invocation.append(session_binding)
        return evaluate(session_binding, inputs)

    def write(path: Path, raw: bytes) -> None:
        original(path, raw)
        if path.name == "observation.json": invocation[0].parameters["algorithm"] = "changed after decoding"

    monkeypatch.setattr(mechanism, "evaluate", spy)
    monkeypatch.setattr(module.runner, "_write_new", write)
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: accepted())
    assert run_session(mechanism, binding, evidence).outcome is MechanismOutcome.UNKNOWN
    assert len(invocation) == 1 and invocation[0] is not binding


def test_caller_binding_edit_during_evaluation_stays_outside_the_bound_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Session evaluation binds a snapshot taken before evidence resolution; a later edit to the caller's
    # dictionary neither reaches the mechanism nor gives the result a different binding digest.
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    original = module.runner._write_new
    evaluated = binding.to_dict()
    evaluated_digest = binding.digest()

    def write(path: Path, raw: bytes) -> None:
        original(path, raw)
        if path.name == "observation.json": binding.parameters["algorithm"] = "changed after decoding"

    monkeypatch.setattr(module.runner, "_write_new", write)
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: accepted())
    result = run_session(mechanism, binding, evidence)
    assert binding.parameters["algorithm"] == "changed after decoding"
    assert binding.digest() != evaluated_digest
    assert result.outcome is MechanismOutcome.PASS
    assert result.binding_digest == evaluated_digest
    assert result.binding_digest != binding.digest()
    assert result.observations["binding"] == evaluated


def test_direct_call_late_binding_mutation_during_observation_retention_is_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    original = module.runner._write_new

    def write(path: Path, raw: bytes) -> None:
        original(path, raw)
        if path.name == "observation.json": binding.parameters["algorithm"] = "changed after decoding"

    monkeypatch.setattr(module.runner, "_write_new", write)
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: accepted())
    result = mechanism.evaluate(binding, evidence)
    assert result.outcome is MechanismOutcome.UNKNOWN
    assert result.observations["pre_post_identity_unchanged"] is False


def test_failed_launch_does_not_claim_native_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: (None, "LAUNCH_ERROR", b"", b""))
    result = mechanism.evaluate(binding, evidence)
    assert result.observations.get("native_execution_performed") is not True


@pytest.mark.parametrize("change", ["subject", "expected", "roles", "boolean-bound", "too-large-bound"])
def test_even_fresh_host_approval_cannot_change_fixed_predicate_contract(tmp_path: Path, change: str) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    if change == "subject": binding = replace(binding, subject_id="payload computational truth")
    elif change == "expected": binding = replace(binding, expected=1)
    elif change == "roles": binding.parameters["public_key_ref"] = binding.evidence_refs[0]
    elif change == "boolean-bound": binding = replace(binding, bounds=EvidenceBounds(2, True))
    elif change == "too-large-bound": binding = replace(binding, bounds=EvidenceBounds(2, 2 * module.MAX_INPUT_BYTES + 1))
    with pytest.raises(ValueError):
        module.GoStatementAcceptanceMechanism(mechanism._go_checker, mechanism._coordinate["go_checker_sha256"],
            output_root=output, approved_bindings=(binding,))
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("which", ["runner", "decoder"])
def test_obvious_shadowed_import_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, which: str) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    monkeypatch.setattr(getattr(module, which), "__file__", str(tmp_path / "shadowed.py"))
    assert mechanism.evaluate(binding, evidence).outcome is MechanismOutcome.UNKNOWN
    assert list(output.iterdir()) == []


def test_exact_approved_byte_ceiling_enforced_directly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    binding = replace(binding, bounds=EvidenceBounds(2, sum(map(len, evidence)) - 1))
    mechanism = module.GoStatementAcceptanceMechanism(mechanism._go_checker, mechanism._coordinate["go_checker_sha256"],
        output_root=output, approved_bindings=(binding,))
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: pytest.fail("excess evidence executed"))
    assert mechanism.evaluate(binding, evidence).outcome is MechanismOutcome.UNKNOWN
    assert list(output.iterdir()) == []


def test_extra_native_output_kept_but_never_reports_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)

    def invoke(name: str, arguments: list[str], cwd: Path, **limits: Any) -> tuple[int, None, bytes, bytes]:
        (cwd / "unexpected.txt").write_bytes(b"not admitted")
        return accepted()

    monkeypatch.setattr(module.runner, "_run_process", invoke)
    assert mechanism.evaluate(binding, evidence).outcome is MechanismOutcome.UNKNOWN
    directory, = output.iterdir()
    assert (directory / "unexpected.txt").exists()


def test_changed_native_result_on_explicit_rerun_is_not_carried_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, mechanism, binding, evidence, output = setup_host(tmp_path)
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: accepted())
    original = run_session(mechanism, binding, evidence)
    monkeypatch.setattr(module.runner, "_run_process", lambda *args, **kwargs: (None, "TIMEOUT", b"", b""))
    assert original.outcome is MechanismOutcome.PASS
    assert run_session(mechanism, binding, evidence).outcome is MechanismOutcome.UNKNOWN
