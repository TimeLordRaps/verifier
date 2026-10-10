"""Independent baseline for joining current native replay to existing signed admission."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
import pytest
from verifier.consent import ConsentContext, authenticate_consent, evaluate_consent
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.governance import evaluate_governance, policy_digest
from verifier.privacy import DisclosureBound, DisclosureSurface
from verifier.privacy.models import EmissionResult
from verifier.privacy.current_certificate_emission import evaluate_current_certificate_emission

ROOT = Path(__file__).resolve().parents[1]

def module() -> Any:
    import verifier.controlled_emission as result
    return result

def helper(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("fixture_" + name, ROOT / "tests" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(result)
    return result

def legacy() -> dict[str, Any]:
    return helper("test_controlled_emission").example.__wrapped__()

def current(kind: str, *, selected_inputs: tuple[Any, ...] | None = None) -> dict[str, Any]:
    _, request, policy, raw = (selected_inputs if selected_inputs is not None else
                              helper("test_current_certificate_emission")._current(kind))
    selected = legacy()
    action = replace(selected["action"], object_name=kind,
                     artifact_digest=hashlib.sha256(raw).hexdigest())
    consent = replace(selected["consent_policy"], artifact_bindings=((kind, action.artifact_digest),))
    payload = deepcopy(selected["consent_grants"][0]["payload"])
    payload.update(object_name=kind, artifact_digest=action.artifact_digest)
    key = next(key for key in consent.keys if key.key_id == "owner-key")
    signed_grant = authenticate_consent(payload, key)
    governance = replace(selected["governance_policy"], object_names=(kind,))
    vote = {k: v for k, v in selected["governance_decisions"][0].items() if k != "signature"}
    vote.update(policy_digest=policy_digest(governance), binding=asdict(action))
    signer = governance.principals[0]
    signed_vote = helper("test_controlled_emission").sign(vote, signer.key)
    status = {k: v for k, v in selected["governance_status"].items() if k != "signature"}
    status["policy_digest"] = policy_digest(governance)
    signed_status = helper("test_controlled_emission").sign(status, governance.status_key)
    fields = tuple(json.loads(raw))
    selected.pop("certificate")
    return {**selected, "certificate_bytes": raw, "semantic_version": request["semantic_version"],
        "objective": request["coordinate"], "represented_kind": kind, "expected_request": request,
        "certificate_policy": policy, "action": action, "consent_policy": consent,
        "consent_grants": (signed_grant,), "governance_policy": governance,
        "governance_decisions": (signed_vote,), "governance_status": signed_status,
        "privacy_surface": DisclosureSurface(kind, fields, ()),
        "privacy_bounds": tuple(DisclosureBound("bound:" + field, field,
            admitted_observers=("reader",), conditions=(("purpose", "teaching"),)) for field in fields)}

def test_existing_complete_legacy_signed_admission_is_an_independent_positive_control() -> None:
    result = module().evaluate_controlled_emission(**legacy())
    assert result["admission"] == "PASS"
    assert result["receipt"]["external_execution"] == "NOT_PERFORMED"


@pytest.mark.parametrize("kind", ["SIM", "HYPER"])
def test_existing_current_authorities_admit_the_exact_signed_action_independently(kind: str) -> None:
    inputs = current(kind)
    shared = {k: v for k, v in asdict(inputs["action"]).items() if k not in {"jurisdiction", "invocation_id"}}
    consent = evaluate_consent(ConsentContext(**shared), inputs["consent_grants"],
        policy=inputs["consent_policy"], revocation=inputs["consent_revocation"], evaluation_time=200)
    governance = evaluate_governance(inputs["action"], inputs["governance_decisions"],
        policy=inputs["governance_policy"], status=inputs["governance_status"], evaluation_time=200)
    assert consent.verdict.value == governance.verdict.value == "PASS"

@pytest.mark.parametrize("kind", ["SIM", "HYPER"])
def test_existing_current_native_and_full_disclosure_are_independently_reproduced(kind: str) -> None:
    inputs = current(kind)
    result = evaluate_current_certificate_emission(inputs["certificate_bytes"], kind=kind,
        expected_request=inputs["expected_request"], policy=inputs["certificate_policy"],
        surface=inputs["privacy_surface"], bounds=inputs["privacy_bounds"], context=inputs["privacy_context"])
    assert result.replay_status == "REPRODUCED"
    assert result.computational_status == "PASS"
    assert result.emitted_certificate_bytes == inputs["certificate_bytes"]

@pytest.mark.parametrize("kind", ["SIM", "HYPER"])
def test_current_certificate_reuses_complete_signed_controlled_admission(kind: str) -> None:
    inputs = current(kind)
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "PASS"
    assert result["emitted_certificate_bytes"] == inputs["certificate_bytes"]
    assert result["receipt"]["schema_version"] == "verifier-controlled-current-emission-1"
    assert result["receipt"]["atomic_invocation_consumption"] == "NOT_PERFORMED"
    assert result["receipt"]["normative_level_6_7_8_conformance"] == "UNKNOWN"

@pytest.mark.parametrize("mode", ["output-copy", "captured-source"])
def test_legacy_disclosure_cannot_substitute_a_numerically_equal_serialized_value(monkeypatch: Any, mode: str) -> None:
    inputs = legacy()
    original = module().EmissionEvaluator.evaluate_emission
    original_depth = inputs["certificate"]["request"]["target_depth"]
    assert type(original_depth) is int

    def real_then_change_representation(self: Any, *args: Any, **kwargs: Any) -> Any:
        result = original(self, *args, **kwargs)
        changed = deepcopy(result.emitted_certificate) if mode == "output-copy" else args[0]
        changed["request"]["target_depth"] = float(original_depth)
        assert changed == inputs["certificate"]
        assert canonical_bytes(changed) != canonical_bytes(inputs["certificate"])
        return replace(result, emitted_certificate=changed)

    monkeypatch.setattr(module().EmissionEvaluator, "evaluate_emission", real_then_change_representation)
    result = module().evaluate_controlled_emission(**inputs)
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate"] is None


@pytest.mark.parametrize("field,value", [
    ("semantic_version", "legacy"), ("objective", "SIM-4.4"),
    ("objective", "OBJECT-1.1"), ("objective", "GRAPH-9.2"),
    ("represented_kind", "GRAPH"), ("represented_kind", "HYPER"),
])
def test_current_route_is_selected_externally_without_other_route_promotion(field: str, value: str) -> None:
    inputs = current("SIM")
    result = module().evaluate_controlled_current_emission(**{**inputs, field: value})
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate_bytes"] is None


@pytest.mark.parametrize("field,value", [
    ("artifact_digest", "0" * 64), ("object_name", "BOT"),
    ("observer_id", "other"), ("purpose", "resale"),
    ("timestamp", 199), ("invocation_id", "another-invocation"),
    ("jurisdiction", "another-jurisdiction"), ("actor_id", "another-publisher"),
])
def test_current_signed_action_cannot_be_substituted(field: str, value: Any) -> None:
    inputs = current("SIM")
    inputs["action"] = replace(inputs["action"], **{field: value})
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate_bytes"] is None


@pytest.mark.parametrize("field", ["consent_policy", "consent_revocation",
                                    "governance_policy", "governance_status", "evaluation_time"])
def test_current_missing_authority_or_clock_remains_unknown(field: str) -> None:
    inputs = current("HYPER")
    result = module().evaluate_controlled_current_emission(**{**inputs, field: None})
    assert result["admission"] == "UNKNOWN"
    assert result["emitted_certificate_bytes"] is None


@pytest.mark.parametrize("field", ["consent_grant", "governance_decision", "governance_status"])
def test_current_forged_authority_is_refuted(field: str) -> None:
    inputs = current("SIM")
    target = (inputs["consent_grants"][0] if field == "consent_grant" else
              inputs["governance_decisions"][0] if field == "governance_decision" else
              inputs["governance_status"])
    target["authenticator" if field == "consent_grant" else "signature"] = "0" * 64
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate_bytes"] is None


@pytest.mark.parametrize("authority", ["consent", "governance", "consumed-invocation"])
def test_current_authentic_revocation_or_consumption_refuses(authority: str) -> None:
    inputs = current("SIM")
    if authority == "consent":
        revoked = deepcopy(inputs["consent_revocation"]["payload"])
        revoked["revoked_grant_ids"] = ["grant-1"]
        registry = next(key for key in inputs["consent_policy"].keys if key.key_id == "registry-key")
        inputs["consent_revocation"] = authenticate_consent(revoked, registry)
    else:
        status = {k: v for k, v in inputs["governance_status"].items() if k != "signature"}
        status["revoked_actors" if authority == "governance" else "consumed_invocations"] = [
            "board" if authority == "governance" else "invocation-1"]
        inputs["governance_status"] = helper("test_controlled_emission").sign(
            status, inputs["governance_policy"].status_key)
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate_bytes"] is None


@pytest.mark.parametrize("changed", ["request", "policy", "surface", "withheld", "composition"])
def test_current_native_and_disclosure_bindings_are_required(changed: str) -> None:
    inputs = current("SIM")
    if changed == "request":
        inputs["expected_request"]["subject_id"] = "another-subject"
    elif changed == "policy":
        inputs["certificate_policy"]["trust_roots"] = ["another-selected-root"]
    elif changed == "surface":
        inputs["privacy_surface"] = replace(inputs["privacy_surface"], object_name="BOT")
    elif changed == "withheld":
        inputs["privacy_surface"] = replace(inputs["privacy_surface"],
            disclosed_fields=tuple(key for key in inputs["privacy_surface"].disclosed_fields if key != "evidence_payloads"),
            withheld_fields=("evidence_payloads",))
    else:
        inputs["privacy_context"] = replace(inputs["privacy_context"], co_emitted_certificates=({"object_name": "MODEL"},))
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate_bytes"] is None


def honest_outcome(status: str) -> dict[str, Any]:
    fixture = helper("test_current_certificate_emission")
    native, request, objects, isolation, policy = fixture._sim_inputs()
    if status == "FAIL":
        escaped = fixture._sim_model()
        escaped["transitions"][0]["outcomes"][0]["effects"] = [
            {"kind": "external_export", "target": "host:network"}]
        isolation = canonical_bytes(escaped)
        objects = fixture._sim_objects(isolation)
        request = native.current_object_request(objects, sim_id="sim",
            isolation_evidence_bytes=isolation, policy=policy)
    else:
        assert status == "UNKNOWN"
        isolation = None
    raw = native.build_current_object_certificate(request, objects, isolation, policy=policy)
    independent = native.recheck_current_object_certificate(raw, expected_request=request, policy=policy)
    assert independent["status"] == status
    return current("SIM", selected_inputs=(native, request, policy, raw))


@pytest.mark.parametrize("status,expected_admission", [("FAIL", "REJECTED"), ("UNKNOWN", "UNKNOWN")])
def test_current_default_outcome_policy_does_not_promote_negative_result(status: str, expected_admission: str) -> None:
    result = module().evaluate_controlled_current_emission(**honest_outcome(status))
    assert result["admission"] == expected_admission
    assert result["receipt"]["computational_result"]["status"] == status
    assert result["receipt"]["computational_result_basis"] == "REPRODUCED"
    assert result["emitted_certificate_bytes"] is None


@pytest.mark.parametrize("status", ["FAIL", "UNKNOWN"])
def test_current_explicit_outcome_policy_can_admit_reproduced_negative_bytes(status: str) -> None:
    inputs = honest_outcome(status)
    result = module().evaluate_controlled_current_emission(**inputs,
        admitted_computational_statuses=("PASS", "FAIL", "UNKNOWN"))
    assert result["admission"] == "PASS"
    assert result["emitted_certificate_bytes"] == inputs["certificate_bytes"]
    assert result["receipt"]["computational_result"]["status"] == status
    for gate in ("consent", "governance"):
        assert result["receipt"]["checks"][gate]["computational_verdict"] == status


def test_current_exact_receipt_replays_without_transmission_or_key_disclosure() -> None:
    inputs = current("SIM")
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "PASS"
    assert result == module().evaluate_controlled_current_emission(**inputs)
    assert module().recheck_controlled_current_emission(result, **inputs)
    receipt_bytes = canonical_bytes(result["receipt"])
    for key in [key.secret for key in inputs["consent_policy"].keys]:
        assert key.hex().encode() not in receipt_bytes
    assert result["receipt"]["external_execution"] == "NOT_PERFORMED"


@pytest.mark.parametrize("changed", ["admission", "bytes", "result", "clock-type", "authority", "source"])
def test_current_rehashed_receipt_substitutions_are_not_native_evidence(changed: str) -> None:
    inputs = current("SIM")
    carried = deepcopy(module().evaluate_controlled_current_emission(**inputs))
    assert carried["admission"] == "PASS"
    if changed == "admission":
        carried["admission"] = "UNKNOWN"
    elif changed == "bytes":
        carried["emitted_certificate_bytes"] += b" "
    elif changed == "result":
        carried["receipt"]["computational_result"]["status"] = "FAIL"
    elif changed == "clock-type":
        carried["receipt"]["evaluation_time"] = 200.0
    elif changed == "authority":
        carried["receipt"]["normative_level_6_7_8_conformance"] = "PASS"
    else:
        carried["receipt"]["selection_binding"]["controlled_emission_source_sha256"] = "sha256:" + "0" * 64
    carried["receipt"].pop("receipt_digest")
    carried["receipt"]["receipt_digest"] = canonical_digest(carried["receipt"])
    assert not module().recheck_controlled_current_emission(carried, **inputs)


@pytest.mark.parametrize("changed", ["privacy-result", "selection-binding", "carried-native", "carried-binding"])
def test_current_bridge_output_is_bounded_plain_evidence_and_is_independently_replayed(monkeypatch: Any, changed: str) -> None:
    inputs = current("SIM")
    original = module().evaluate_current_certificate_emission
    callbacks = []

    class CallbackPrivacy(EmissionResult):
        def __getattribute__(self, name: str) -> Any:
            if name == "emitted_certificate":
                callbacks.append(name)
            return super().__getattribute__(name)

    class CallbackBinding(dict):
        def __getitem__(self, name: str) -> Any:
            callbacks.append(name)
            return super().__getitem__(name)

    def real_then_substitute(*args: Any, **kwargs: Any) -> Any:
        bridge = original(*args, **kwargs)
        if changed == "privacy-result":
            privacy = CallbackPrivacy(**{name: getattr(bridge.privacy_result, name)
                for name in EmissionResult.__dataclass_fields__})
            return replace(bridge, privacy_result=privacy)
        if changed == "selection-binding":
            return replace(bridge, selection_binding=CallbackBinding(bridge.selection_binding))
        if changed == "carried-native":
            native = deepcopy(bridge.native_result)
            before = native["evaluation"]["observed_evidence_bytes"]
            assert type(before) is int
            native["evaluation"]["observed_evidence_bytes"] = float(before)
            assert native == bridge.native_result
            assert canonical_bytes(native) != canonical_bytes(bridge.native_result)
            return replace(bridge, native_result=native)
        binding = dict(bridge.selection_binding, request_sha256="sha256:" + "0" * 64)
        return replace(bridge, selection_binding=binding)

    monkeypatch.setattr(module(), "evaluate_current_certificate_emission", real_then_substitute)
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate_bytes"] is None
    assert callbacks == []


@pytest.mark.parametrize("changed", ["request", "policy", "action", "outcome-policy", "consent-grant",
    "consent-revocation", "governance-policy", "governance-status", "privacy-bound", "privacy-context"])
def test_current_all_external_selections_are_captured_before_the_bridge(monkeypatch: Any, changed: str) -> None:
    inputs = current("SIM")
    original = module().evaluate_current_certificate_emission
    request_digest = "sha256:" + canonical_digest(inputs["expected_request"])
    policy_digest_before = "sha256:" + canonical_digest(inputs["certificate_policy"])

    def real_then_mutate_caller(*args: Any, **kwargs: Any) -> Any:
        bridge = original(*args, **kwargs)
        if changed == "request":
            inputs["expected_request"]["subject_id"] = "other-subject"
        elif changed == "policy":
            inputs["certificate_policy"]["trust_roots"] = ["other-root"]
        elif changed == "action":
            object.__setattr__(inputs["action"], "purpose", "resale")
        elif changed == "outcome-policy":
            inputs["admitted_computational_statuses"] = ("FAIL",)
        elif changed == "consent-grant":
            inputs["consent_grants"][0]["payload"]["purposes"] = ["resale"]
        elif changed == "consent-revocation":
            inputs["consent_revocation"]["payload"]["revoked_grant_ids"] = ["grant-1"]
        elif changed == "governance-policy":
            object.__setattr__(inputs["governance_policy"], "operations", ("resale",))
        elif changed == "governance-status":
            inputs["governance_status"]["revoked_actors"] = ["board"]
        elif changed == "privacy-bound":
            object.__setattr__(inputs["privacy_bounds"][0], "admitted_observers", ("other",))
        else:
            object.__setattr__(inputs["privacy_context"].observer, "purpose", "resale")
        return bridge

    monkeypatch.setattr(module(), "evaluate_current_certificate_emission", real_then_mutate_caller)
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "PASS"
    assert result["receipt"]["action"]["purpose"] == "teaching"
    assert result["receipt"]["selection_binding"]["request_sha256"] == request_digest
    assert result["receipt"]["selection_binding"]["policy_sha256"] == policy_digest_before
    assert result["receipt"]["checks"]["computational_outcome"]["admitted_statuses"] == ("PASS",)


def test_current_oversized_certificate_is_refused_before_hashing(monkeypatch: Any) -> None:
    inputs = current("SIM")
    inputs["certificate_bytes"] = b"x" * (16 * 1024 * 1024 + 1)
    callbacks = []

    def forbidden_hash(*args: Any, **kwargs: Any) -> Any:
        callbacks.append("hash")
        raise AssertionError("oversized bytes must be rejected before hashing")

    monkeypatch.setattr(module(), "hashlib", SimpleNamespace(sha256=forbidden_hash))
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "REJECTED"
    assert callbacks == []


def test_current_carried_receipt_is_captured_before_later_caller_mutation(monkeypatch: Any) -> None:
    inputs = current("SIM")
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "PASS"
    original = module().evaluate_current_certificate_emission

    def real_then_mutate_carried(*args: Any, **kwargs: Any) -> Any:
        bridge = original(*args, **kwargs)
        result["receipt"]["evaluation_time"] = 200.0
        return bridge

    monkeypatch.setattr(module(), "evaluate_current_certificate_emission", real_then_mutate_carried)
    assert module().recheck_controlled_current_emission(result, **inputs)
    assert type(result["receipt"]["evaluation_time"]) is float


def test_current_input_capture_never_calls_a_foreign_metaclass_equality(monkeypatch: Any) -> None:
    callbacks = []

    class CallbackType(type):
        def __eq__(self, other: Any) -> bool:
            callbacks.append("equality")
            return False

    class ForeignValue(metaclass=CallbackType):
        pass

    inputs = current("SIM")
    inputs["certificate_policy"]["foreign"] = ForeignValue()
    result = module().evaluate_controlled_current_emission(**inputs)
    assert result["admission"] == "REJECTED"
    assert result["receipt"]["checks"]["binding"] == "INPUT_CAPTURE_REJECTED"
    assert callbacks == []
