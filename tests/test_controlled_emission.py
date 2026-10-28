"""A real certificate must pass all separately bound emission controls."""
from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass, replace
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import secrets

import pytest

from verifier import build_domain_certificate, domain_policy, domain_request
from verifier.consent import ConsentKey, ConsentPolicy, authenticate_consent
from verifier.governance import GovernanceContext, GovernancePolicy, GovernancePrincipal, policy_digest
from verifier.privacy import DisclosureBound, DisclosureSurface, EmissionContext, ObserverParty


def sign(payload, key):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    return {**payload, "signature": hmac.new(key, raw, hashlib.sha256).hexdigest()}


@pytest.fixture
def example():
    path = Path(__file__).resolve().parents[1] / "examples/domain_grounding.py"
    spec = importlib.util.spec_from_file_location("controls_example", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    evidence = module.specimens()["SIM"]
    checker_policy = domain_policy(trust_roots=["local:control-test"])
    certificate = build_domain_certificate(domain_request(evidence, target_depth=4), evidence, policy=checker_policy)
    assert certificate["result"]["status"] == "PASS"
    artifact_digest = hashlib.sha256(json.dumps(certificate, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
    action = GovernanceContext("SIM", artifact_digest, "publish", "publisher", "reader", "teaching", 200, "lab", "invocation-1")
    owner = ConsentKey("owner-key", "owner", secrets.token_bytes(32))
    registry = ConsentKey("registry-key", "registry", secrets.token_bytes(32))
    consent_policy = ConsentPolicy("consent-test", "owner", (owner, registry),
        (owner.key_id,), (registry.key_id,), artifact_bindings=(("SIM", artifact_digest),))
    grant = {"schema_version": "verifier-consent-grant-1", "grant_id": "grant-1", "issuer_id": "owner",
        "actor_id": "publisher", "object_name": "SIM", "artifact_digest": artifact_digest,
        "operations": ["publish"], "observer_ids": ["reader"], "purposes": ["teaching"],
        "not_before": 100, "not_after": 300, "parent_digest": None, "allow_delegation": False, "effect": "ALLOW"}
    revocation = {"schema_version": "verifier-consent-revocations-1", "issuer_id": "registry",
        "policy_id": consent_policy.policy_id, "as_of": 195, "next_update": 220, "revoked_grant_ids": []}
    principal = GovernancePrincipal("board", "board-key", secrets.token_bytes(32))
    governance_policy = GovernancePolicy(policy_id="governance-test", revision=1, object_names=("SIM",),
        operations=("publish",), jurisdictions=("lab",), principals=(principal,), quorum=1,
        veto_actors=(), status_key_id="governance-status", status_key=secrets.token_bytes(32),
        effective_from=100, effective_until=300, max_status_age=30)
    terms = policy_digest(governance_policy)
    vote = sign({"schema": "verifier-governance-decision-1", "decision_id": "decision-1", "policy_digest": terms,
        "binding": asdict(action), "actor_id": principal.actor_id, "key_id": principal.key_id,
        "decision": "APPROVE", "issued_at": 190, "expires_at": 220}, principal.key)
    status = sign({"schema": "verifier-governance-status-1", "policy_digest": terms,
        "key_id": governance_policy.status_key_id, "observed_at": 195, "expires_at": 220,
        "revoked_decisions": [], "revoked_actors": [], "consumed_invocations": []}, governance_policy.status_key)
    return dict(certificate=certificate, action=action, certificate_policy=checker_policy,
        privacy_surface=DisclosureSurface("SIM", tuple(certificate), ()),
        privacy_bounds=tuple(DisclosureBound("bound:"+k, k, admitted_observers=("reader",),
                              conditions=(("purpose", "teaching"),)) for k in certificate),
        privacy_context=EmissionContext(ObserverParty("reader", "reader", "teaching"), "1970-01-01T00:03:20Z"),
        consent_policy=consent_policy, consent_grants=(authenticate_consent(grant, owner),),
        consent_revocation=authenticate_consent(revocation, registry), governance_policy=governance_policy,
        governance_decisions=(vote,), governance_status=status, evaluation_time=200)


def evaluate(example, **changes):
    return candidate().evaluate_controlled_emission(**{**example, **changes})


def candidate():
    import verifier.controlled_emission as module
    return module


def test_aggregate_receipt_uses_admitted_action_snapshot_after_callback_mutation(example, monkeypatch):
    module = candidate()
    original = module.EmissionEvaluator.evaluate_emission
    signed_purpose = example["action"].purpose

    def mutate_after_real_privacy(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        object.__setattr__(example["action"], "purpose", "resale")
        return result

    monkeypatch.setattr(module.EmissionEvaluator, "evaluate_emission", mutate_after_real_privacy)
    result = evaluate(example)
    assert result["admission"] == "PASS"
    assert result["receipt"]["action"]["purpose"] == signed_purpose
    assert result["receipt"]["checks"]["governance"]["binding"]["purpose"] == signed_purpose
    assert example["action"].purpose == "resale"


@pytest.mark.parametrize("changed_input", [
    "action", "consent_policy", "consent_grant", "consent_revocation",
    "governance_policy", "governance_decision", "governance_status",
    "privacy_surface", "privacy_bound", "privacy_context",
])
def test_all_admission_inputs_are_captured_before_native_callback(example, monkeypatch, changed_input):
    module = candidate()
    original = module.recheck_domain_certificate
    expected_surface_digest = hashlib.sha256(json.dumps(asdict(example["privacy_surface"]),
        sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    def after_real_native(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result["status"] == "PASS"
        if changed_input == "action":
            object.__setattr__(example["action"], "purpose", "resale")
        elif changed_input == "consent_policy":
            object.__setattr__(example["consent_policy"], "grantor_id", "other-owner")
        elif changed_input == "consent_grant":
            example["consent_grants"][0]["purposes"] = ["resale"]
        elif changed_input == "consent_revocation":
            example["consent_revocation"]["revoked_grant_ids"] = ["grant-1"]
        elif changed_input == "governance_policy":
            object.__setattr__(example["governance_policy"], "operations", ("resale",))
        elif changed_input == "governance_decision":
            example["governance_decisions"][0]["binding"]["purpose"] = "resale"
        elif changed_input == "governance_status":
            example["governance_status"]["revoked_actors"] = ["board"]
        elif changed_input == "privacy_surface":
            object.__setattr__(example["privacy_surface"], "object_name", "BOT")
        elif changed_input == "privacy_bound":
            object.__setattr__(example["privacy_bounds"][0], "conditions", (("purpose", "resale"),))
        elif changed_input == "privacy_context":
            object.__setattr__(example["privacy_context"].observer, "purpose", "resale")
        return result

    monkeypatch.setattr(module, "recheck_domain_certificate", after_real_native)
    result = evaluate(example)
    assert result["admission"] == "PASS"
    assert result["receipt"]["action"]["purpose"] == "teaching"
    assert result["receipt"]["checks"]["privacy"]["input_binding"]["surface_sha256"] == expected_surface_digest
    assert result["emitted_certificate"] == example["certificate"]


def test_checker_policy_is_captured_before_certificate_digest_callback(example, monkeypatch):
    module = candidate()
    original = module.canonical_bytes
    changed = False

    def mutate_after_digest(value):
        nonlocal changed
        encoded = original(value)
        if not changed and type(value) is dict and value.get("schema_version") == "verifier-domain-certification-1":
            example["certificate_policy"]["trust_roots"][0] = "replacement-root"
            changed = True
        return encoded

    monkeypatch.setattr(module, "canonical_bytes", mutate_after_digest)
    result = evaluate(example)
    assert changed
    assert result["admission"] == "PASS"
    assert result["receipt"]["checks"]["computational_recheck"]["status"] == "PASS"


def test_hostile_action_subclass_is_refused_before_field_callback(example):
    class HostileAction(GovernanceContext):
        def __getattribute__(self, name):
            raise AssertionError("hostile action field callback invoked")

    hostile = object.__new__(HostileAction)
    with pytest.raises(ValueError, match="plain context"):
        evaluate(example, action=hostile)


@pytest.mark.parametrize("field,replacement", [
    ("consent_grants", ({},) * 10001),
    ("certificate", {"cycle": None}),
])
def test_unbounded_or_cyclic_input_refuses_before_any_gate(example, monkeypatch, field, replacement):
    module = candidate()
    if field == "certificate":
        replacement["cycle"] = replacement

    def forbidden(*args, **kwargs):
        raise AssertionError("gate invoked before bounded input capture")

    monkeypatch.setattr(module, "recheck_domain_certificate", forbidden)
    result = evaluate(example, **{field: replacement})
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate"] is None
    assert result["receipt"]["checks"]["binding"] == "INPUT_CAPTURE_REJECTED"


def test_hostile_policy_mapping_is_refused_before_iteration(example, monkeypatch):
    module = candidate()

    class HostileMapping(dict):
        def items(self):
            raise AssertionError("hostile mapping items callback invoked")

    def forbidden(*args, **kwargs):
        raise AssertionError("gate invoked before plain input capture")

    monkeypatch.setattr(module, "recheck_domain_certificate", forbidden)
    result = evaluate(example, certificate_policy=HostileMapping(example["certificate_policy"]))
    assert result["admission"] == "REJECTED"
    assert result["receipt"]["checks"]["binding"] == "INPUT_CAPTURE_REJECTED"


def test_capture_failure_never_carries_uncaptured_hostile_clock(example, monkeypatch):
    module = candidate()

    class HostileClock(int):
        def __str__(self):
            raise AssertionError("hostile clock serialized")

    def forbidden(*args, **kwargs):
        raise AssertionError("gate invoked before clock capture")

    monkeypatch.setattr(module, "recheck_domain_certificate", forbidden)
    result = evaluate(example, evaluation_time=HostileClock(200))
    assert result["admission"] == "REJECTED"
    assert result["receipt"]["evaluation_time"] is None
    assert result["receipt"]["checks"]["binding"] == "INPUT_CAPTURE_REJECTED"


@pytest.mark.parametrize("field,replacement", [
    ("certificate", {"nonfinite": float("nan")}),
    ("certificate_policy", {"unknown": object()}),
])
def test_nonfinite_or_custom_input_refuses_before_gate(example, monkeypatch, field, replacement):
    module = candidate()

    def forbidden(*args, **kwargs):
        raise AssertionError("gate invoked before finite plain input capture")

    monkeypatch.setattr(module, "recheck_domain_certificate", forbidden)
    result = evaluate(example, **{field: replacement})
    assert result["admission"] == "REJECTED"
    assert result["receipt"]["checks"]["binding"] == "INPUT_CAPTURE_REJECTED"


def test_hostile_record_subclass_is_refused_before_field_callback(example, monkeypatch):
    module = candidate()

    class HostileSurface(DisclosureSurface):
        def __getattribute__(self, name):
            raise AssertionError("hostile surface field callback invoked")

    hostile = object.__new__(HostileSurface)

    def forbidden(*args, **kwargs):
        raise AssertionError("gate invoked before plain record capture")

    monkeypatch.setattr(module, "recheck_domain_certificate", forbidden)
    result = evaluate(example, privacy_surface=hostile)
    assert result["admission"] == "REJECTED"
    assert result["receipt"]["checks"]["binding"] == "INPUT_CAPTURE_REJECTED"


def test_one_aggregate_byte_budget_spans_action_clock_and_all_gate_inputs(example, monkeypatch):
    module = candidate()

    def literal_source_bytes(value):
        if type(value) is dict:
            return sum(len(key.encode("utf-8")) + literal_source_bytes(item)
                       for key, item in value.items())
        if type(value) in (tuple, list):
            return sum(literal_source_bytes(item) for item in value)
        if is_dataclass(value):
            return sum(literal_source_bytes(getattr(value, field.name))
                       for field in fields(value))
        if type(value) is str:
            return len(value.encode("utf-8"))
        if type(value) is bytes:
            return len(value)
        return 0

    inputs = tuple(example[field] for field in (
        "action", "evaluation_time", "certificate", "certificate_policy",
        "privacy_surface", "privacy_bounds", "privacy_context", "consent_policy",
        "consent_grants", "consent_revocation", "governance_policy",
        "governance_decisions", "governance_status"))
    exact = literal_source_bytes(inputs)
    action_bytes = literal_source_bytes(example["action"])
    remaining_bytes = exact - action_bytes
    assert 0 < action_bytes < exact and 0 < remaining_bytes < exact
    assert max(action_bytes, remaining_bytes) < exact
    monkeypatch.setattr(module, "_MAX_CAPTURE_BYTES", exact)
    assert evaluate(example)["admission"] == "PASS"
    monkeypatch.setattr(module, "_MAX_CAPTURE_BYTES", exact - 1)
    rejected = evaluate(example)
    assert rejected["admission"] == "REJECTED"
    assert rejected["receipt"]["evaluation_time"] == 200
    assert rejected["receipt"]["checks"]["binding"] == "INPUT_CAPTURE_REJECTED"


def test_real_certificate_all_controls_and_determinism(example):
    before = deepcopy(example["certificate"])
    result = evaluate(example)
    assert result["admission"] == "PASS"
    assert result["emitted_certificate"] == before == example["certificate"]
    assert result == evaluate(example)
    assert result["receipt"]["computational_result"] == before["result"]
    assert result["receipt"]["normative_level_6_7_8_conformance"] == "UNKNOWN"
    assert result["receipt"]["external_execution"] == "NOT_PERFORMED"


@pytest.mark.parametrize("field", ["consent_policy", "consent_revocation", "governance_policy", "governance_status"])
def test_missing_one_authority_cannot_be_replaced_by_other_passes(example, field):
    result = evaluate(example, **{field: None})
    assert result["admission"] == "UNKNOWN"
    assert result["emitted_certificate"] is None


def test_valid_permissions_do_not_override_privacy(example):
    surface = DisclosureSurface("SIM", tuple(k for k in example["certificate"] if k != "evidence"), ("evidence",))
    result = evaluate(example, privacy_surface=surface)
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate"] is None


@pytest.mark.parametrize("field,value", [("artifact_digest", "0"*64), ("object_name", "BOT"),
    ("observer_id", "other"), ("purpose", "resale"), ("timestamp", 199)])
def test_context_substitution_cannot_reuse_permissions(example, field, value):
    result = evaluate(example, action=replace(example["action"], **{field: value}))
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate"] is None


def test_fabricated_computational_pass_does_not_pass_native_rechecker(example):
    bad = deepcopy(example["certificate"])
    bad["result"]["domain_depth"] = 999
    # Exercise native replay, not the outer digest mismatch guard.
    digest = hashlib.sha256(json.dumps(bad, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True, allow_nan=False).encode()).hexdigest()
    result = evaluate(example, certificate=bad, action=replace(example["action"], artifact_digest=digest))
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate"] is None
    assert result["receipt"]["checks"]["computational_recheck"]["status"] != "PASS"


def test_missing_trusted_clock_is_unknown(example):
    result = evaluate(example, evaluation_time=None)
    assert result["admission"] == "UNKNOWN"
    assert result["emitted_certificate"] is None


@pytest.mark.parametrize("timestamp", [
    "1970-01-01T00:03:20.0000001Z", "1970-01-01T00:03:20.000000001Z",
    "1970-01-01T00:03:20.000001Z",
    "1970-01-01T00:03:20+00:00:00.0000001", None,
])
def test_privacy_timestamp_never_rounds_a_different_instant(example, timestamp):
    context = replace(example["privacy_context"], timestamp=timestamp)
    result = evaluate(example, privacy_context=context)
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate"] is None


@pytest.mark.parametrize("timestamp", [
    "1970-01-01T00:03:20.0000000Z", "1970-01-01T00:03:20.000000000Z",
    "1970-01-01T01:03:20+01:00",
    "1969-12-31T23:03:20-01:00",
])
def test_equivalent_integral_privacy_instants_are_admitted(example, timestamp):
    result = evaluate(example, privacy_context=replace(example["privacy_context"], timestamp=timestamp))
    assert result["admission"] == "PASS"


def test_nonmapping_certificate_is_rejected_without_emission(example):
    result = evaluate(example, certificate=[])
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate"] is None
