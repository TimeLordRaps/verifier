"""Adversarial qualification of ACTOR domain adapter.

Terminology: application programming interface (API); JavaScript Object Notation (JSON);
Verifier Standard (VSTD).
"""
from __future__ import annotations

import pytest

from verifier.domains.actor import evaluate
from verifier.domains.common import Budget, Refuted, Unavailable, digest


def _sample_actor_bundle() -> tuple[dict, dict]:
    actor_id = "actor:principal:alice-org"
    control_keys = [
        {"key_id": "key:primary", "algorithm": "ed25519", "public_key": "aabbcc"},
        {"key_id": "key:backup", "algorithm": "ed25519", "public_key": "ddeeff"},
    ]
    decision_classes = ["code_review", "release_authorization", "policy_modification"]
    admitted_spaces = ["vstd", "graph", "domain"]
    boundary = {
        "actor": ["alice-signer", "alice-key-custody"],
        "instruments": ["cli:vstd", "ide:antigravity"],
    }
    delegation_events = [
        {
            "event": "delegation",
            "position": 0,
            "delegate": "actor:delegate:bob",
            "subset": ["code_review"],
            "interval": [1000, 2000],
        },
        {
            "event": "revocation",
            "position": 1,
            "delegate": "actor:delegate:bob",
            "subset": ["code_review"],
            "interval": [2000, 2000],
        },
    ]
    decisions = [
        {
            "decision_id": "dec:001",
            "position": 0,
            "decision_class": "code_review",
            "actor": actor_id,
            "instrument": "cli:vstd",
            "timestamp": 1200,
        },
        {
            "decision_id": "dec:002",
            "position": 1,
            "decision_class": "release_authorization",
            "actor": actor_id,
            "instrument": "cli:vstd",
            "timestamp": 1500,
        },
    ]
    witnesses = [
        {"witness_id": "witness:independent:charlie", "decision_id": "dec:001", "actor_id": actor_id},
        {"witness_id": "witness:independent:dana", "decision_id": "dec:002", "actor_id": actor_id},
    ]

    artifact = {
        "actor_id": actor_id,
        "control_surface": control_keys,
        "decision_classes": decision_classes,
        "admitted_spaces": admitted_spaces,
        "instrument_boundary": boundary,
        "delegations_digest": digest(delegation_events),
        "decisions_digest": digest(decisions),
    }
    inputs = {
        "control_keys": control_keys,
        "delegation_events": delegation_events,
        "decisions": decisions,
        "witness_attributions": witnesses,
    }
    return artifact, inputs


def test_actor_identity_check_passes_on_valid_bundle() -> None:
    artifact, inputs = _sample_actor_bundle()
    budget = Budget(10000)
    result = evaluate("identity", artifact, inputs, budget)
    assert result["actor_id"] == artifact["actor_id"]
    assert result["control_keys"] == 2
    assert "code_review" in result["decision_classes"]


def test_actor_identity_fails_on_instrument_boundary_overlap() -> None:
    artifact, inputs = _sample_actor_bundle()
    artifact["instrument_boundary"]["instruments"].append("alice-signer")
    budget = Budget(10000)
    with pytest.raises(Refuted, match="instrument boundary overlap"):
        evaluate("identity", artifact, inputs, budget)


def test_actor_delegation_replays_and_forbids_widening() -> None:
    artifact, inputs = _sample_actor_bundle()
    budget = Budget(10000)
    result = evaluate("delegation", artifact, inputs, budget)
    assert result["delegation_events"] == 2
    assert result["active_delegates"] == 0

    # Forbid widening authority beyond declared decision classes
    invalid_inputs = dict(inputs)
    invalid_events = [
        {
            "event": "delegation",
            "position": 0,
            "delegate": "actor:delegate:bob",
            "subset": ["root_access_unbounded"],
            "interval": [1000, 2000],
        }
    ]
    invalid_inputs["delegation_events"] = invalid_events
    invalid_artifact = dict(artifact)
    invalid_artifact["delegations_digest"] = digest(invalid_events)
    with pytest.raises(Refuted, match="delegation conveys authority outside"):
        evaluate("delegation", invalid_artifact, invalid_inputs, budget)


def test_actor_accountability_forbids_sole_witness() -> None:
    artifact, inputs = _sample_actor_bundle()
    budget = Budget(10000)
    result = evaluate("accountability", artifact, inputs, budget)
    assert result["witnesses_verified"] == 2

    # Sole witness violation: actor cannot self-witness
    inputs["witness_attributions"] = [
        {"witness_id": artifact["actor_id"], "decision_id": "dec:001", "actor_id": artifact["actor_id"]}
    ]
    with pytest.raises(Refuted, match="sole witness violation"):
        evaluate("accountability", artifact, inputs, budget)


def test_actor_attribution_checks_uniqueness_and_continuity() -> None:
    artifact, inputs = _sample_actor_bundle()
    budget = Budget(10000)
    result = evaluate("attribution", artifact, inputs, budget)
    assert result["decisions_attributed"] == 2
    assert result["unattributed"] == 0

    # Duplicate decision attribution rejected
    dup_decisions = [
        inputs["decisions"][0],
        dict(inputs["decisions"][0], position=1),
    ]
    dup_inputs = dict(inputs, decisions=dup_decisions)
    dup_artifact = dict(artifact, decisions_digest=digest(dup_decisions))
    with pytest.raises(Refuted, match="duplicate attribution"):
        evaluate("attribution", dup_artifact, dup_inputs, budget)


def test_actor_domain_certificate_build_and_recheck() -> None:
    import json
    from pathlib import Path
    from jsonschema import Draft202012Validator
    from verifier.domains.certification import (
        build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate
    )
    artifact, inputs = _sample_actor_bundle()
    evidence = {
        "schema_version": "verifier-domain-evidence-1",
        "domain": "ACTOR",
        "subject_id": artifact["actor_id"],
        "artifact": artifact,
        "inputs": inputs,
    }
    policy = domain_policy(trust_roots=["test:trust"])
    request = domain_request(evidence, target_depth=4)
    certificate = build_domain_certificate(request, evidence, policy=policy)

    schema_dir = Path("src/verifier/schemas")
    ev_schema = json.loads((schema_dir / "verifier-domain-evidence-1.schema.json").read_text(encoding="utf-8"))
    cert_schema = json.loads((schema_dir / "verifier-domain-certification-1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(ev_schema).validate(evidence)
    Draft202012Validator(cert_schema).validate(certificate)

    result = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert result["domain_depth"] == 4
    assert list(result["checks"].keys()) == ["ACTOR-1.1", "ACTOR-2.1", "ACTOR-3.2", "ACTOR-4.2"]
    assert all(row["established"] for row in result["checks"].values())
