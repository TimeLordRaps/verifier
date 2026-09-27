"""A real certificate must pass all separately bound emission controls."""
from copy import deepcopy
from dataclasses import asdict, replace
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
    from verifier.controlled_emission import evaluate_controlled_emission
    return evaluate_controlled_emission(**{**example, **changes})


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
    "1970-01-01T00:03:20.0000001Z", "1970-01-01T00:03:20.000001Z",
    "1970-01-01T00:03:20+00:00:00.0000001", None,
])
def test_privacy_timestamp_never_rounds_a_different_instant(example, timestamp):
    context = replace(example["privacy_context"], timestamp=timestamp)
    result = evaluate(example, privacy_context=context)
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate"] is None


@pytest.mark.parametrize("timestamp", [
    "1970-01-01T00:03:20.0000000Z", "1970-01-01T01:03:20+01:00",
    "1969-12-31T23:03:20-01:00",
])
def test_equivalent_integral_privacy_instants_are_admitted(example, timestamp):
    result = evaluate(example, privacy_context=replace(example["privacy_context"], timestamp=timestamp))
    assert result["admission"] == "PASS"


def test_nonmapping_certificate_is_rejected_without_emission(example):
    result = evaluate(example, certificate=[])
    assert result["admission"] == "REJECTED"
    assert result["emitted_certificate"] is None
