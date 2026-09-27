"""Adversarial qualification of OWNER domain adapter.

Terminology: application programming interface (API); JavaScript Object Notation (JSON);
Verifier Standard (VSTD).
"""
from __future__ import annotations

import pytest

from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains.owner import evaluate


def _sample_owner_bundle() -> tuple[dict, dict]:
    holder_actor_id = "actor:principal:alice-org"
    held_coord = "DATA-1.2"
    held_digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    limbs = ["responsibility", "authority", "blame", "fault", "consent", "privacy"]
    limbs_kind = {
        "responsibility": "discharge_duty",
        "authority": "right",
        "blame": "answering_duty",
        "fault": "answering_duty",
        "consent": "right",
        "privacy": "right",
    }
    instrument = {"id": "inst:contract:001", "issuing_authority": "jurisdiction:delaware"}
    term = {"start": 1000, "end": 9000}
    chain_origin = "holding:origin:001"

    events = [
        {"event": "freeze", "position": 0, "target_limb": "responsibility", "actor_id": holder_actor_id},
        {"event": "seal", "position": 1, "target_limb": "responsibility", "actor_id": holder_actor_id},
        {"event": "thaw", "position": 2, "target_limb": "responsibility", "actor_id": holder_actor_id},
        {"event": "transfer", "position": 3, "target_limb": "authority", "actor_id": holder_actor_id},
    ]

    artifact = {
        "holder_actor_id": holder_actor_id,
        "held_object_coordinate": held_coord,
        "held_object_digest": held_digest,
        "limbs": limbs,
        "limbs_kind": limbs_kind,
        "instrument": instrument,
        "term": term,
        "chain_origin": chain_origin,
        "events_digest": digest(events),
    }

    holdings_chain = [
        {"id": chain_origin, "holder": holder_actor_id, "position": 0},
        {"id": "holding:current:002", "holder": holder_actor_id, "position": 1},
    ]

    answering_duties = {
        "responsibility": "human:person:alice-roost",
    }

    held_verdict = {
        "status": "PASS",
        "computed_digest": held_digest,
    }

    inputs = {
        "events": events,
        "holdings_chain": holdings_chain,
        "answering_duties": answering_duties,
        "held_verdict": held_verdict,
    }
    return artifact, inputs


def test_owner_limbs_validation() -> None:
    artifact, inputs = _sample_owner_bundle()
    budget = Budget(10000)
    result = evaluate("limbs", artifact, inputs, budget)
    assert result["holder_actor_id"] == artifact["holder_actor_id"]
    assert len(result["limbs"]) == 6

    # Refuse unknown consequence limb
    bad_artifact = dict(artifact, limbs=["responsibility", "unlimited_dominion"])
    with pytest.raises(Refuted, match="unknown consequence limbs"):
        evaluate("limbs", bad_artifact, inputs, budget)


def test_owner_lifecycle_freeze_seal_thaw() -> None:
    artifact, inputs = _sample_owner_bundle()
    budget = Budget(10000)
    result = evaluate("lifecycle", artifact, inputs, budget)
    assert result["events_replayed"] == 4
    assert result["frozen"] is True
    assert result["sealed"] is False  # Thaw unsealed it

    # Thaw without seal is refuted
    bad_events = [
        {"event": "thaw", "position": 0, "target_limb": "responsibility", "actor_id": artifact["holder_actor_id"]}
    ]
    bad_inputs = dict(inputs, events=bad_events)
    bad_artifact = dict(artifact, events_digest=digest(bad_events))
    with pytest.raises(Refuted, match="thaw requires previous seal"):
        evaluate("lifecycle", bad_artifact, bad_inputs, budget)


def test_owner_verdict_independence_never_alters_held_computation() -> None:
    artifact, inputs = _sample_owner_bundle()
    budget = Budget(10000)
    result = evaluate("independence", artifact, inputs, budget)
    assert result["verdict_independence_preserved"] is True
    assert result["held_verdict"] == "PASS"

    # Refute if held object digest was altered
    bad_inputs = dict(inputs, held_verdict={"status": "PASS", "computed_digest": "sha256:" + "0" * 64})
    with pytest.raises(Refuted, match="held object digest altered"):
        evaluate("independence", artifact, bad_inputs, budget)


def test_owner_accountability_floor_terminates_in_natural_person() -> None:
    artifact, inputs = _sample_owner_bundle()
    budget = Budget(10000)
    result = evaluate("accountability", artifact, inputs, budget)
    assert result["accountability_floor_satisfied"] is True
    assert result["discharge_duties"] == 1

    # Refute if answering duty does not terminate in a human / natural person
    bad_inputs = dict(inputs, answering_duties={"responsibility": "bot:automated-agent-42"})
    with pytest.raises(Refuted, match="does not terminate in a natural person"):
        evaluate("accountability", artifact, bad_inputs, budget)


def test_owner_domain_certificate_build_and_recheck() -> None:
    import json
    from pathlib import Path
    from jsonschema import Draft202012Validator
    from verifier.domains.certification import (
        build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate
    )
    artifact, inputs = _sample_owner_bundle()
    evidence = {
        "schema_version": "verifier-domain-evidence-1",
        "domain": "OWNER",
        "subject_id": artifact["holder_actor_id"],
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
    assert list(result["checks"].keys()) == ["OWNER-1.3", "OWNER-2.1", "OWNER-3.1", "OWNER-4.5"]
    assert all(row["established"] for row in result["checks"].values())
