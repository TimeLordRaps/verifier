"""Actual finite host controls and hostile portable replacement substitutions.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Fixture keys and explicitly selected admission exercise bounded verification
mechanics, not real production authority, witnesses or human acceptance.
"""
from __future__ import annotations

from asyncio import CancelledError
import base64
from dataclasses import asdict
import hashlib
import json
from os import getpid
from pathlib import Path
from typing import Any, Callable

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import verifier_replacement as native
from verifier.runtime.permission_slot import (
    BoundaryResult, Census, DrainObservation, EntryObservation, Grant, GrantDecision,
    Outcome, PermissionSlot, Selection, Ticket,
)


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _private_keys() -> dict[str, Any]:
    pytest.importorskip(
        "cryptography",
        reason="OPTIONAL_DEPENDENCY_ABSENT: seal extra (cryptography); "
        "exercised by the platform-python-contracts workflow job",
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return {name: Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)
            for number, name in enumerate(("fixture:admission", "fixture:old", "fixture:new", "fixture:observer"), 1)}


def _public(key: Any) -> str:
    pytest.importorskip(
        "cryptography",
        reason="OPTIONAL_DEPENDENCY_ABSENT: seal extra (cryptography); "
        "exercised by the platform-python-contracts workflow job",
    )
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _sign(payload: dict[str, Any], key_id: str) -> dict[str, Any]:
    return {"schema_version": native.ATTESTATION_VERSION, "key_id": key_id, "payload": payload,
            "signature": _private_keys()[key_id].sign(native.verifier_replacement_signing_bytes(payload)).hex()}


class FixtureAuthority:
    def verify(self, grant: Grant, *, expected: Selection, revoked: Selection | None, epoch: int) -> GrantDecision:
        assert grant.selection == expected
        assert (grant.purpose == "successor") == (revoked is not None)
        return GrantDecision(Outcome.PASS, grant, epoch)


class FixtureObserver:
    observer_id = "fixture:observer"

    def __init__(self) -> None:
        self.observed: dict[str, tuple[int, int, int]] = {}
        self.censuses: list[Census] = []
        self.after_boundary: Callable[[], None] | None = None

    def invoke(self, ticket: Ticket, boundary: Callable[[Callable[[], None]], BoundaryResult],
               effect: Callable[[], None]) -> EntryObservation:
        entries = exits = 0

        def instrumented() -> None:
            nonlocal entries, exits
            entries += 1
            try:
                effect()
            finally:
                exits += 1

        result = boundary(instrumented)
        self.observed[ticket.invocation_id] = (1, entries, exits)
        if self.after_boundary is not None:
            self.after_boundary()
        return EntryObservation(self.observer_id, ticket, 1, entries, exits, result.status)

    def drain(self, read_census: Callable[[], Census]) -> DrainObservation:
        actual = read_census()
        self.censuses.append(actual)
        return DrainObservation(self.observer_id, actual, Outcome.PASS)


def selected_fixture(*, cancel_before_entry: bool = False, max_events: int = 512,
        pre_revocation_entry: bool = False, capture_after_exit: bool = False,
        sticky_failure: bool = False, omit_stale_attempt: bool = False,
        uncommitted_preparation: bool = False) -> tuple[dict[str, Any], dict[str, Any], bytes, list[str]]:
    """Build actual local fixture witnesses under explicitly selected fixture roots."""
    retained: dict[str, str] = {}

    def retain(raw: bytes) -> str:
        ref = digest(raw)
        retained[ref] = base64.b64encode(raw).decode("ascii")
        return ref

    tuples = []
    for generation in (1, 2):
        context = {"schema_version": native.CONTEXT_VERSION,
                   "revision_digest": retain(f"fixture:context-revision:{generation}".encode())}
        for kind in ("TIME", "TOKEN", "ENV", "HARDWARE", "SPACE"):
            context[kind] = retain(canonical_bytes({"kind": kind, "record": {"fixture_generation": generation}}))
        tuples.append(Selection(retain(f"fixture:artifact:{generation}".encode()),
                                retain(f"fixture:instruction:{generation}".encode()),
                                retain(f"fixture:policy:{generation}".encode()), retain(canonical_bytes(context)),
                                f"fixture:session:{generation}", str(getpid()), generation))
    old, successor = tuples
    observer = FixtureObserver()
    slot = PermissionSlot(old, authorities=("fixture:old", "fixture:new"), verifier=FixtureAuthority(),
                          observer=observer, observer_id=observer.observer_id, max_events=max_events)
    initial_view = retain(canonical_bytes({"fixture": "initial-view", "cutoff": 0}))
    revoked_view = retain(canonical_bytes({"fixture": "revoked-view", "cutoff": 2}))
    first = Grant(old, "fixture:old", retain(b"fixture:permission:old"), initial_view,
                  retain(b"fixture:grant-evidence:old"), "fixture:nonce:old", "initial")
    second = Grant(successor, "fixture:new", retain(b"fixture:permission:new"), revoked_view,
                   retain(b"fixture:grant-evidence:new"), "fixture:nonce:new", "successor")
    assert slot.grant(first).status == Outcome.PASS
    old_ticket = slot.queue(old, "old-stale").ticket
    assert old_ticket is not None
    effects: list[str] = []
    prior_ticket = None
    if pre_revocation_entry:
        prior_ticket = slot.queue(old, "old-entered-before-cutoff").ticket
        assert prior_ticket is not None

        def entered_before_revocation() -> None:
            effects.append("old-before-cutoff")
            assert slot.revoke(old).status == Outcome.PASS

        assert slot.invoke(prior_ticket, entered_before_revocation).status == Outcome.PASS
    else:
        assert slot.revoke(old).status == Outcome.PASS
    assert slot.drain().status == Outcome.PASS
    slot.select_successor(successor)
    cutoff = 2
    if uncommitted_preparation:
        def refresh_before_commit() -> None:
            assert slot.revoke(old).status == Outcome.PASS

        assert slot.grant(second, prepare=refresh_before_commit).status == Outcome.UNKNOWN
        assert slot.drain().status == Outcome.PASS
        cutoff = 3
        revoked_view = retain(canonical_bytes({"fixture": "revoked-view", "cutoff": cutoff}))
        second = Grant(successor, "fixture:new", second.permission_digest, revoked_view,
                       second.evidence_digest, second.nonce, second.purpose)
    assert slot.grant(second).status == Outcome.PASS
    if not omit_stale_attempt:
        assert slot.invoke(old_ticket, lambda: effects.append("forbidden-old")).status == Outcome.PASS
    new_ticket = slot.queue(successor, "new-entered").ticket
    assert new_ticket is not None
    interim: list[bytes] = []
    if capture_after_exit:
        observer.after_boundary = lambda: interim.append(slot.capture())
    if cancel_before_entry:
        def cancelled_preparation() -> None:
            raise CancelledError()

        assert slot.invoke(new_ticket, lambda: effects.append("successor"), prepare=cancelled_preparation).status == Outcome.UNKNOWN
        assert slot.assessment().status == Outcome.UNKNOWN
        assert not slot.census().inflight and not effects
    else:
        expected_status = Outcome.PASS if max_events >= 12 else Outcome.UNKNOWN
        assert slot.invoke(new_ticket, lambda: effects.append("successor")).status == expected_status
        assert slot.assessment().status == (Outcome.UNKNOWN if omit_stale_attempt else expected_status)
        assert effects == (["old-before-cutoff"] if pre_revocation_entry else []) + ["successor"]
    if sticky_failure:
        assert slot.grant(second).status == Outcome.FAIL
        assert slot.assessment().status == Outcome.FAIL
    capture_raw = interim[-1] if capture_after_exit else slot.capture()
    capture = json.loads(capture_raw)
    subject = NamespaceObject.create("fixture:verifier", "VERIFIER", {"fixture": "selected finite host"})
    subject_digest = retain(canonical_bytes(subject.to_dict()))
    collection_digest = retain(canonical_bytes({"schema_version": "verifier-object-composition-1", "objects": [subject.to_dict()]}))
    for path in native._mechanism_paths().values():
        retain(path.read_bytes())
    checker_manifest = retain(native._mechanism_bytes())
    closure = {"schema_version": native.EXECUTION_VERSION, "executor_digest": retain(Path(native.permission_slot.__file__).read_bytes()),
               "observer_digest": retain(Path(__file__).read_bytes()), "harness_digest": retain(Path(__file__).read_bytes()),
               "mechanism_digest": checker_manifest}
    closure_digest = retain(canonical_bytes(closure))
    inventory = sorted([
        {"invocation_id": old_ticket.invocation_id, "effect_id": "fixture:old-effect", "effect_digest": retain(b"fixture:effect:old"),
         "selection_digest": digest(canonical_bytes(asdict(old)))},
        {"invocation_id": new_ticket.invocation_id, "effect_id": "fixture:new-effect", "effect_digest": retain(b"fixture:effect:new"),
         "selection_digest": digest(canonical_bytes(asdict(successor)))},
    ], key=lambda row: row["invocation_id"])
    if prior_ticket is not None:
        inventory.append({"invocation_id": prior_ticket.invocation_id, "effect_id": "fixture:old-before-cutoff",
                          "effect_digest": retain(b"fixture:effect:old-before-cutoff"),
                          "selection_digest": digest(canonical_bytes(asdict(old)))})
        inventory.sort(key=lambda row: row["invocation_id"])
    keys = _private_keys()
    authority_keys = {name: _public(keys[name]) for name in ("fixture:old", "fixture:new")}
    observer_keys = {"fixture:observer": _public(keys["fixture:observer"])}
    subject_binding = {"subject_id": subject.object_id, "object_digest": subject_digest, "collection_digest": collection_digest,
                       "initial_digest": digest(canonical_bytes(asdict(old))), "successor_digest": digest(canonical_bytes(asdict(successor)))}
    base = {"operation_id": "fixture:replacement-operation", "boundary_id": "fixture:registered-callback-boundary",
            "execution_closure_digest": closure_digest, **subject_binding}
    authority_admission = _sign({"schema_version": native.ADMISSION_VERSION, **base, "purpose": "grant-and-revoke", "keys": authority_keys}, "fixture:admission")
    observer_admission = _sign({"schema_version": native.ADMISSION_VERSION, **base, "purpose": "observe-complete-effect-census", "keys": observer_keys}, "fixture:admission")
    policy = native.verifier_replacement_policy(trust_roots=["fixture:explicit-independent-admission"],
        admission_key_id="fixture:admission", admission_public_key=_public(keys["fixture:admission"]),
        authority_keys=authority_keys, observer_keys=observer_keys,
        authority_admission_digest=digest(canonical_bytes(authority_admission)),
        observer_admission_digest=digest(canonical_bytes(observer_admission)))
    capture_digest = digest(capture_raw)
    census_digest = digest(canonical_bytes(capture["result"]["census"]))
    authority_common = {"schema_version": native.AUTHORITY_VERSION, **base, "capture_digest": capture_digest}
    statements = [_sign({**authority_common, "kind": "grant", "record": row["record"]}, row["record"]["grant"]["authority"])
                  for row in capture["observations"] if row["kind"] == "GrantDecision"]
    statements.append(_sign({**authority_common, "kind": "revocation", "record": {
        "selection": asdict(old), "epoch": cutoff, "revocation_view_digest": revoked_view, "revoked_authority": "fixture:old"}}, "fixture:old"))
    effect_census = [{**row, **dict(zip(("attempts", "entries", "exits"), observer.observed[row["invocation_id"]]))}
                     for row in inventory if row["invocation_id"] in observer.observed]
    observer_statement = _sign({"schema_version": native.OBSERVER_VERSION, **base, "capture_digest": capture_digest,
        "trace_digest": capture["trace_digest"], "terminal_census_digest": census_digest,
        "effect_inventory": inventory, "effect_census": effect_census,
        "coverage_complete": not cancel_before_entry and not omit_stale_attempt and max_events >= 12}, "fixture:observer")
    evidence = canonical_bytes({"schema_version": native.EVIDENCE_VERSION, "capture_base64": base64.b64encode(capture_raw).decode("ascii"),
        "retained_payloads": retained, "authority_admission": authority_admission, "observer_admission": observer_admission,
        "authority_attestations": statements, "observer_attestation": observer_statement})
    request = native.verifier_replacement_request(subject_id=subject.object_id, object_digest=subject_digest,
        collection_digest=collection_digest, operation_id=base["operation_id"], boundary_id=base["boundary_id"],
        initial=asdict(old), successor=asdict(successor), execution_closure_digest=closure_digest,
        capture_digest=capture_digest, trace_digest=capture["trace_digest"], terminal_sequence=capture["terminal_sequence"],
        terminal_census_digest=census_digest, revocation_cutoff=cutoff, revocation_view_digest=revoked_view,
        effect_inventory=inventory, evidence_ref=digest(evidence), policy=policy)
    return request, policy, evidence, effects


def repin_evidence(request: dict[str, Any], value: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Select altered candidate bytes without rewriting independent request pins."""
    raw = canonical_bytes(value)
    return {**request, "evidence_ref": digest(raw)}, raw


def reanchor_capture(request: dict[str, Any], value: dict[str, Any], capture: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Explicit adversarial selection of altered trace/capture with fixture signatures."""
    capture["terminal_sequence"] = len(capture["events"])
    for number, event in enumerate(capture["events"], 1):
        event["sequence"] = number
    capture["trace_digest"] = digest(canonical_bytes(capture["events"]))
    raw = canonical_bytes(capture)
    selected = {**request, "capture_digest": digest(raw), "trace_digest": capture["trace_digest"],
                "terminal_sequence": capture["terminal_sequence"], "terminal_census_digest": digest(canonical_bytes(capture["result"]["census"]))}
    value["capture_base64"] = base64.b64encode(raw).decode("ascii")
    for number, row in enumerate(value["authority_attestations"]):
        value["authority_attestations"][number] = _sign({**row["payload"], "capture_digest": selected["capture_digest"]}, row["key_id"])
    if value["observer_attestation"] is not None:
        row = value["observer_attestation"]
        value["observer_attestation"] = _sign({**row["payload"], **{key: selected[key] for key in ("capture_digest", "trace_digest", "terminal_census_digest")}}, row["key_id"])
    return repin_evidence(selected, value)


def outcome(request: dict[str, Any], policy: dict[str, Any], evidence: bytes | None) -> dict[str, Any]:
    certificate = native.build_verifier_replacement_certificate(request, evidence, policy=policy)
    return native.recheck_verifier_replacement_certificate(certificate, expected_request=request, policy=policy)


def test_actual_host_capture_replays_and_does_not_repeat_effects() -> None:
    request, policy, evidence, effects = selected_fixture()
    result = outcome(request, policy, evidence)
    assert result["status"] == result["finite_replacement"] == "PASS"
    assert result["replay_status"] == "REPRODUCED"
    assert result["complete_corrigibility_admission"] == "UNKNOWN"
    assert all(result[key] == "NOT_ESTABLISHED" for key in native._EXCLUDED)
    assert effects == ["successor"]


def test_actual_host_preparation_cancellation_cleanup_remains_unknown() -> None:
    request, policy, evidence, effects = selected_fixture(cancel_before_entry=True)
    result = outcome(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    assert result["finite_replacement"] == "NOT_ESTABLISHED"
    assert effects == []


def test_actual_host_event_exhaustion_at_exit_remains_unknown() -> None:
    request, policy, evidence, effects = selected_fixture(max_events=11)
    result = outcome(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    assert result["finite_replacement"] == "NOT_ESTABLISHED"
    assert effects == ["successor"]


def test_actual_old_entry_may_finish_after_nested_revocation() -> None:
    request, policy, evidence, effects = selected_fixture(pre_revocation_entry=True)
    assert outcome(request, policy, evidence)["status"] == "PASS"
    assert effects == ["old-before-cutoff", "successor"]


def test_actual_observer_lifetime_after_effect_exit_remains_unknown() -> None:
    request, policy, evidence, effects = selected_fixture(capture_after_exit=True)
    assert outcome(request, policy, evidence)["status"] == "UNKNOWN"
    assert effects == ["successor"]


def test_actual_sticky_host_failure_survives_checking_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, effects = selected_fixture(sticky_failure=True)

    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise CancelledError()

    monkeypatch.setattr(native, "mechanism_digest", unavailable)
    monkeypatch.setattr(native, "_verify_signature", unavailable)
    assert outcome({**request, "cancelled": True}, policy, evidence)["status"] == "FAIL"
    assert effects == ["successor"]


def test_actual_missing_stale_attempt_remains_unknown() -> None:
    request, policy, evidence, effects = selected_fixture(omit_stale_attempt=True)
    assert outcome(request, policy, evidence)["status"] == "UNKNOWN"
    assert effects == ["successor"]


def test_actual_uncommitted_grant_decision_never_implies_activation() -> None:
    request, policy, evidence, effects = selected_fixture(uncommitted_preparation=True)
    assert outcome(request, policy, evidence)["status"] == "UNKNOWN"
    assert effects == ["successor"]


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest", "operation_id", "boundary_id", "execution_closure_digest"], ids=["subject", "object", "collection", "operation", "boundary", "source"])
def test_cross_subject_and_operation_substitution_fails(field: str) -> None:
    request, policy, evidence, _ = selected_fixture()
    replacement = "fixture:other" if field.endswith("id") else digest(b"fixture:other")
    assert outcome({**request, field: replacement}, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("field", ["artifact_digest", "instruction_digest", "policy_digest", "context_digest", "session_id", "process_id", "generation"])
def test_exact_successor_tuple_substitution_fails(field: str) -> None:
    request, policy, evidence, _ = selected_fixture()
    successor = dict(request["successor"])
    successor[field] = 3 if field == "generation" else "fixture:other" if field.endswith("id") else digest(b"substitution")
    assert outcome({**request, "successor": successor}, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("field", ["authority_admission", "observer_admission", "observer_attestation", "capture_base64"])
def test_missing_admitted_peer_remains_unknown(field: str) -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    value[field] = None
    request, evidence = repin_evidence(request, value)
    assert outcome(request, policy, evidence)["status"] == "UNKNOWN"


def test_partial_observer_coverage_remains_unknown() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    row = value["observer_attestation"]
    payload = {**row["payload"], "coverage_complete": False, "effect_census": row["payload"]["effect_census"][:1]}
    value["observer_attestation"] = _sign(payload, row["key_id"])
    request, evidence = repin_evidence(request, value)
    assert outcome(request, policy, evidence)["status"] == "UNKNOWN"


def test_asserted_complete_effect_census_omission_fails_without_capture() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    value["capture_base64"] = None
    row = value["observer_attestation"]
    value["observer_attestation"] = _sign({**row["payload"], "effect_census": row["payload"]["effect_census"][:1]}, row["key_id"])
    request, evidence = repin_evidence(request, value)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_invalid_signature_survives_missing_peer_and_selected_cancel() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    value["capture_base64"] = None
    value["authority_admission"] = None
    value["observer_attestation"]["signature"] = "00" * 64
    request, evidence = repin_evidence({**request, "cancelled": True}, value)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_wrong_observer_binding_survives_missing_capture() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    value["capture_base64"] = None
    row = value["observer_attestation"]
    value["observer_attestation"] = _sign({**row["payload"], "operation_id": "fixture:other"}, row["key_id"])
    request, evidence = repin_evidence(request, value)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_stale_generation_entry_fails_under_new_external_anchors() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    capture = json.loads(base64.b64decode(value["capture_base64"]))
    refusal = next(row for row in capture["events"] if row["action"] == "callback_refused")
    refusal["action"] = "callback_entry"
    request, evidence = reanchor_capture(request, value, capture)
    result = outcome(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "stale or revoked" in result["evaluation"]["details"]


def test_missing_grant_observation_cannot_hide_stale_entry() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    capture = json.loads(base64.b64decode(value["capture_base64"]))
    capture["observations"] = [row for row in capture["observations"] if row["kind"] != "GrantDecision"]
    next(row for row in capture["events"] if row["action"] == "callback_refused")["action"] = "callback_entry"
    request, evidence = reanchor_capture(request, value, capture)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_missing_grant_observation_remains_unknown() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    capture = json.loads(base64.b64decode(value["capture_base64"]))
    capture["observations"] = [row for row in capture["observations"] if row["kind"] != "GrantDecision"]
    capture["result"]["status"] = "UNKNOWN"
    request, evidence = reanchor_capture(request, value, capture)
    assert outcome(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["permission_digest", "evidence_digest", "revocation_view_digest"])
def test_missing_grant_bytes_remain_unknown(field: str) -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    capture = json.loads(base64.b64decode(value["capture_base64"]))
    first = next(row["record"] for row in capture["observations"] if row["kind"] == "GrantDecision")
    value["retained_payloads"].pop(first["grant"][field])
    request, evidence = repin_evidence(request, value)
    assert outcome(request, policy, evidence)["status"] == "UNKNOWN"


def test_retained_prior_failure_survives_cancelled_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    capture = json.loads(base64.b64decode(value["capture_base64"]))
    capture["result"]["status"] = "FAIL"
    value["observer_attestation"] = None
    value["authority_admission"] = None
    request, evidence = reanchor_capture({**request, "cancelled": True}, value, capture)

    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise CancelledError()

    monkeypatch.setattr(native, "mechanism_digest", unavailable)
    monkeypatch.setattr(native, "_verify_signature", unavailable)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_optional_crypto_outage_remains_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, _ = selected_fixture()

    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise MemoryError()

    monkeypatch.setattr(native, "_verify_signature", unavailable)
    assert outcome(request, policy, evidence)["status"] == "UNKNOWN"


def test_carried_pass_becomes_unknown_when_crypto_replay_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, _ = selected_fixture()
    certificate = native.build_verifier_replacement_certificate(request, evidence, policy=policy)
    assert json.loads(certificate)["result"]["status"] == "PASS"

    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise MemoryError()

    monkeypatch.setattr(native, "_verify_signature", unavailable)
    result = native.recheck_verifier_replacement_certificate(certificate, expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN" and result["replay_status"] == "UNAVAILABLE"


@pytest.mark.parametrize("component", ["observer", "grant"])
def test_known_signed_contradiction_survives_unrelated_context_capacity(component: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    context_bytes = base64.b64decode(value["retained_payloads"][request["initial"]["context_digest"]])
    if component == "observer":
        row = value["observer_attestation"]
        payload = row["payload"]
        census = next(item for item in payload["effect_census"] if item["invocation_id"] == "old-stale")
        census["entries"] = 1
        value["observer_attestation"] = _sign(payload, row["key_id"])
    else:
        row = next(item for item in value["authority_attestations"] if item["payload"]["kind"] == "grant")
        row["payload"]["record"]["grant"]["permission_digest"] = digest(b"wrong-signed-permission")
        row.update(_sign(row["payload"], row["key_id"]))
    request, evidence = repin_evidence(request, value)
    original = native._json

    def bounded_decoder(raw: bytes) -> Any:
        if raw == context_bytes:
            raise native.Unavailable("context decoder capacity unavailable")
        return original(raw)

    monkeypatch.setattr(native, "_json", bounded_decoder)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_selected_source_mismatch_fails_without_evidence() -> None:
    request, policy, _, _ = selected_fixture()
    policy = {**policy, "mechanism_digest": digest(b"other-installed-checker")}
    request = {**request, "policy_digest": "sha256:" + canonical_digest(policy)}
    assert outcome(request, policy, None)["status"] == "FAIL"


def test_duplicate_json_keys_are_refuted() -> None:
    request, policy, _, _ = selected_fixture()
    raw = b'{"schema_version":"one","schema_version":"two"}'
    request = {**request, "evidence_ref": digest(raw)}
    assert outcome(request, policy, raw)["status"] == "FAIL"


def test_foreign_primitive_callbacks_are_never_invoked() -> None:
    request, policy, evidence, _ = selected_fixture()
    calls: list[str] = []

    class Hostile(str):
        def __eq__(self, other: Any) -> bool:
            calls.append("equal")
            raise AssertionError("foreign equality invoked")

        def __hash__(self) -> int:
            calls.append("hash")
            raise AssertionError("foreign hash invoked")

    with pytest.raises(native.VerifierReplacementError):
        native.build_verifier_replacement_certificate({**request, "operation_id": Hostile("hostile")}, evidence, policy=policy)
    assert calls == []


def test_unadmitted_signature_key_cannot_self_select() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    value["observer_attestation"]["key_id"] = "fixture:admission"
    request, evidence = repin_evidence(request, value)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_revoked_authority_cannot_reappear_under_same_key_alias() -> None:
    request, policy, evidence, _ = selected_fixture()
    aliased = {**policy, "authority_keys": {**policy["authority_keys"], "fixture:new": policy["authority_keys"]["fixture:old"]}}
    with pytest.raises(native.VerifierReplacementError, match="signer aliases"):
        native.build_verifier_replacement_certificate(request, evidence, policy=aliased)


def test_old_revoked_authority_cannot_grant_successor() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    capture = json.loads(base64.b64decode(value["capture_base64"]))
    decision = next(row["record"] for row in capture["observations"] if row["kind"] == "GrantDecision" and row["record"]["grant"]["purpose"] == "successor")
    decision["grant"]["authority"] = "fixture:old"
    capture["result"]["census"]["authority"] = "fixture:old"
    request, evidence = reanchor_capture(request, value, capture)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_replayed_grant_nonce_fails() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    capture = json.loads(base64.b64decode(value["capture_base64"]))
    decisions = [row["record"] for row in capture["observations"] if row["kind"] == "GrantDecision"]
    decisions[1]["grant"]["nonce"] = decisions[0]["grant"]["nonce"]
    request, evidence = reanchor_capture(request, value, capture)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_stale_selected_revocation_cutoff_and_view_fail() -> None:
    request, policy, evidence, _ = selected_fixture()
    assert outcome({**request, "revocation_cutoff": request["revocation_cutoff"] + 1}, policy, evidence)["status"] == "FAIL"
    assert outcome({**request, "revocation_view_digest": digest(b"stale-view")}, policy, evidence)["status"] == "FAIL"


def test_terminal_census_substitution_fails() -> None:
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    capture = json.loads(base64.b64decode(value["capture_base64"]))
    capture["result"]["census"]["active"] = False
    request, evidence = reanchor_capture(request, value, capture)
    assert outcome(request, policy, evidence)["status"] == "FAIL"


def test_certificate_boundary_claim_substitution_is_refused() -> None:
    request, policy, evidence, _ = selected_fixture()
    raw = native.build_verifier_replacement_certificate(request, evidence, policy=policy)
    value = json.loads(raw)
    value["result"]["whole_corrigibility_conformance"] = "PASS"
    value["digest"] = "sha256:" + canonical_digest({key: item for key, item in value.items() if key != "digest"})
    with pytest.raises(native.VerifierReplacementError):
        native.recheck_verifier_replacement_certificate(canonical_bytes(value), expected_request=request, policy=policy)
