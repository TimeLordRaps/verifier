"""Adversarial qualification of OWNER domain adapter.

Terminology: application programming interface (API); JavaScript Object Notation (JSON);
Verifier Standard (VSTD).
"""
from __future__ import annotations

import pytest

from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains.owner import evaluate


def _event(action: str, position: object, limb: str, actor_id: str) -> dict:
    """One holding event, declared with its instrument and its position (OWNER-2.1)."""
    return {"event": action, "position": position, "target_limb": limb, "actor_id": actor_id,
            "instrument": {"id": f"inst:{action}:{position}", "issuing_authority": "jurisdiction:delaware"}}


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
        _event("freeze", 0, "responsibility", holder_actor_id),
        _event("seal", 1, "responsibility", holder_actor_id),
        _event("thaw", 2, "responsibility", holder_actor_id),
        _event("transfer", 3, "authority", holder_actor_id),
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
    bad_events = [_event("thaw", 0, "responsibility", artifact["holder_actor_id"])]
    bad_inputs = dict(inputs, events=bad_events)
    bad_artifact = dict(artifact, events_digest=digest(bad_events))
    with pytest.raises(Refuted, match="thaw requires previous seal"):
        evaluate("lifecycle", bad_artifact, bad_inputs, budget)


def _replay(events: list) -> dict:
    artifact, inputs = _sample_owner_bundle()
    return evaluate("lifecycle", dict(artifact, events_digest=digest(events)),
                    dict(inputs, events=events), Budget(10000))


def test_owner_event_declared_without_its_instrument_is_refuted() -> None:
    """OWNER-2.1 declares every event that changes the holding with its instrument."""
    artifact, _ = _sample_owner_bundle()
    bare = {key: value for key, value in _event("transfer", 0, "authority", artifact["holder_actor_id"]).items()
            if key != "instrument"}
    with pytest.raises(Refuted, match="without its instrument"):
        _replay([bare])
    unbound = dict(_event("transfer", 0, "authority", artifact["holder_actor_id"]), instrument={"id": "inst:1"})
    with pytest.raises(Refuted):
        _replay([unbound])


def test_owner_lapse_is_never_an_event() -> None:
    """A term ending is the clock's doing: it declares nothing and occupies no position (OWNER-2.5)."""
    artifact, _ = _sample_owner_bundle()
    with pytest.raises(Refuted, match="lapse"):
        _replay([_event("lapse", 0, "authority", artifact["holder_actor_id"])])


def test_owner_event_position_is_an_integer_not_a_truth_value() -> None:
    """`True == 1` in Python, so a Boolean position must not pass for the second slot in the order."""
    artifact, _ = _sample_owner_bundle()
    holder = artifact["holder_actor_id"]
    with pytest.raises(Refuted, match="bounded integer"):
        _replay([_event("seal", 0, "responsibility", holder), _event("thaw", True, "responsibility", holder)])


def test_owner_delegation_is_a_holding_event() -> None:
    """Transfer, delegation and revocation are the holding's dynamics (OWNER-2).

    A delegation conveys a subset of the delegator's limbs and leaves its own holding intact
    (OWNER-2.3), so it replays like a transfer and a later transfer of the same limb stands.
    """
    artifact, _ = _sample_owner_bundle()
    holder = artifact["holder_actor_id"]
    result = _replay([_event("delegation", 0, "authority", holder), _event("transfer", 1, "authority", holder)])
    assert result["events_replayed"] == 2
    with pytest.raises(Refuted, match="cannot delegate unheld limb"):
        _replay([_event("revocation", 0, "authority", holder), _event("delegation", 1, "authority", holder)])


def test_owner_verdict_independence_is_declared_not_replayed() -> None:
    """OWNER-3.1: the holding never changes any verdict the held object's certificate reaches.

    The check reads a declared status and a declared digest, never the held object's
    certificate, so it cannot tell a verdict the holding left alone from one it moved. A
    declared verdict is a declaration, not evidence: consistent declarations leave
    independence open, and only an inconsistency the check can see is refuted.
    """
    artifact, inputs = _sample_owner_bundle()
    budget = Budget(10000)
    with pytest.raises(Unavailable, match="declared, not replayed"):
        evaluate("independence", artifact, inputs, budget)

    # Refute if held object digest was altered
    bad_inputs = dict(inputs, held_verdict={"status": "PASS", "computed_digest": "sha256:" + "0" * 64})
    with pytest.raises(Refuted, match="held object digest altered"):
        evaluate("independence", artifact, bad_inputs, budget)

    # Refute a status that is not a verdict
    bad_inputs = dict(inputs, held_verdict={"status": "ESTABLISHED",
                                            "computed_digest": artifact["held_object_digest"]})
    with pytest.raises(Refuted, match="invalid held verdict status"):
        evaluate("independence", artifact, bad_inputs, budget)


@pytest.mark.parametrize("terminal", [
    "human:person:alice-roost",
    "actor:person:alice",
    "bot:automated-agent-42",
], ids=["human-prefix", "person-prefix", "bot-prefix"])
def test_owner_accountability_floor_is_never_read_from_a_holder_label(terminal: str) -> None:
    """OWNER-4.5 ends every answering-duty chain in a natural person, and a label is not one.

    A holder label is a declaration, not evidence. Termination is reached through holdings
    to a HUMAN (HUMAN-4.4), and no adapter issues a HUMAN certificate, so the floor stays
    open whatever the label says: never PASS on a `human:` prefix, and never FAIL on a
    `bot:` one, because failing a closure condition is UNKNOWN (OWNER-4.6).
    """
    artifact, inputs = _sample_owner_bundle()
    labelled = dict(inputs, answering_duties={"responsibility": terminal})
    with pytest.raises(Unavailable, match="HUMAN certificate"):
        evaluate("accountability", artifact, labelled, Budget(10000))


def test_owner_chain_that_misses_its_declared_origin_is_open_not_failed() -> None:
    """OWNER-4.1 unmet is one of the five closure failures, which are UNKNOWN and never FAIL."""
    artifact, inputs = _sample_owner_bundle()
    chain = [dict(inputs["holdings_chain"][0], id="holding:elsewhere:009"), inputs["holdings_chain"][1]]
    with pytest.raises(Unavailable, match="declared origin"):
        evaluate("accountability", artifact, dict(inputs, holdings_chain=chain), Budget(10000))


def test_owner_discharge_without_answering_leaves_the_chain_open() -> None:
    """A chain that discharges without answering is not closed (OWNER-4.5), so it is UNKNOWN."""
    artifact, inputs = _sample_owner_bundle()
    with pytest.raises(Unavailable, match="no answering duty"):
        evaluate("accountability", artifact, dict(inputs, answering_duties={}), Budget(10000))


def test_owner_malformed_holding_is_refuted_rather_than_crashing() -> None:
    """A holding that is not an object is malformed evidence, which the adapter must refute.

    An uncaught AttributeError escapes the adapter's verdict mapping and aborts the whole
    certificate instead of failing the one check.
    """
    artifact, inputs = _sample_owner_bundle()
    with pytest.raises(Refuted):
        evaluate("accountability", artifact, dict(inputs, holdings_chain=["holding:origin:001"]),
                 Budget(10000))


def test_owner_evidence_carries_no_field_the_adapter_never_reads() -> None:
    """`accountability_witnesses` was admitted as OWNER evidence and read by nothing.

    An admitted field is a promise that the verdict considered it, so an ignored one reads
    as witnessing the floor never received. It is refused like any other unsupported field.
    """
    from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
    artifact, inputs = _sample_owner_bundle()
    evidence = {"schema_version": "verifier-domain-evidence-1", "domain": "OWNER",
                "subject_id": artifact["holder_actor_id"], "artifact": artifact,
                "inputs": dict(inputs, accountability_witnesses=["witness:independent:001"])}
    with pytest.raises(ValueError, match="unsupported domain evidence field"):
        build_domain_certificate(domain_request(evidence, target_depth=4), evidence,
                                 policy=domain_policy(trust_roots=["test:trust"]))


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
    # Verdict independence is declared rather than replayed, and the accountability floor
    # needs a HUMAN certificate no adapter issues, so an OWNER certificate stops short of
    # both rather than passing on a declaration.
    assert result["status"] == "UNKNOWN"
    assert result["domain_depth"] == 2
    assert list(result["checks"].keys()) == ["OWNER-1.3", "OWNER-2.1", "OWNER-3.1", "OWNER-4.5"]
    assert [row["established"] for row in result["checks"].values()] == [True, True, False, False]
    assert result["checks"]["OWNER-3.1"]["evaluation"]["outcome"] == "UNKNOWN"
    assert result["checks"]["OWNER-4.5"]["evaluation"]["outcome"] == "UNKNOWN"
