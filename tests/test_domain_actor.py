"""Adversarial qualification of ACTOR domain adapter.

Terminology: application programming interface (API); JavaScript Object Notation (JSON);
Verifier Standard (VSTD).
"""
from __future__ import annotations

import base64
import hashlib
from typing import Callable

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.actor import evaluate
from verifier.domains.common import Budget, Refuted, Unavailable, digest

WITNESSES = ("witness:independent:charlie", "witness:independent:dana")


def _private_key(name: str):
    """A deterministic Ed25519 key per witness, so the fixture never depends on a random draw."""
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519",
                                 reason="OPTIONAL_DEPENDENCY_ABSENT: seal signature backend")
    return crypto.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(name.encode("utf-8")).digest())


def _public_hex(name: str) -> str:
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization",
                                        reason="OPTIONAL_DEPENDENCY_ABSENT: seal signature backend")
    return _private_key(name).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _attest(artifact: dict, witness_id: str, decision_id: str, *, signer: str | None = None) -> dict:
    """A witness attribution signed over the exact decision trace it attests."""
    statement = {"attests": "ACTOR-3.4", "actor_id": artifact["actor_id"], "decision_id": decision_id,
                 "decisions_digest": artifact["decisions_digest"], "witness_id": witness_id}
    signature = _private_key(signer or witness_id).sign(canonical_bytes(statement))
    return {"witness_id": witness_id, "decision_id": decision_id, "actor_id": artifact["actor_id"],
            "signature": base64.b64encode(signature).decode("ascii")}


def _witnessed(artifact: dict, inputs: dict) -> tuple[dict, dict]:
    """The fixture with each decision attested by an independent witness the checker admits."""
    witnesses = [_attest(artifact, WITNESSES[0], "dec:001"), _attest(artifact, WITNESSES[1], "dec:002")]
    return dict(inputs, witness_attributions=witnesses), {name: _public_hex(name) for name in WITNESSES}


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
    # Unsigned: a witness identifier is a declaration. `_witnessed` signs them.
    witnesses = [
        {"witness_id": WITNESSES[0], "decision_id": "dec:001", "actor_id": actor_id, "signature": None},
        {"witness_id": WITNESSES[1], "decision_id": "dec:002", "actor_id": actor_id, "signature": None},
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


def test_actor_is_never_named_as_one_of_its_own_instruments() -> None:
    """ACTOR-1.1 names the actor as the accountable party rather than as any instrument."""
    artifact, inputs = _sample_actor_bundle()
    artifact["instrument_boundary"]["instruments"].append(artifact["actor_id"])
    with pytest.raises(Refuted, match="named as one of its own instruments"):
        evaluate("identity", artifact, inputs, Budget(10000))


def _delegations(events: list) -> dict:
    artifact, inputs = _sample_actor_bundle()
    return evaluate("delegation", dict(artifact, delegations_digest=digest(events)),
                    dict(inputs, delegation_events=events), Budget(10000))


def _delegation(position: object, delegate: str = "actor:delegate:bob", interval: object = (1000, 2000)) -> dict:
    return {"event": "delegation", "position": position, "delegate": delegate, "subset": ["code_review"],
            "interval": list(interval) if isinstance(interval, tuple) else interval}


@pytest.mark.parametrize("positions", [(0, 2), (1,), (0, True)], ids=["gap", "late-start", "boolean"])
def test_actor_delegation_positions_are_contiguous_integers(positions: tuple) -> None:
    """ACTOR-2.1 declares each delegation as an event at a stated position in the order."""
    with pytest.raises(Refuted):
        _delegations([_delegation(position) for position in positions])


def test_actor_cannot_delegate_to_itself() -> None:
    """ACTOR-2.1 conveys a subset of the actor's authority to another actor."""
    artifact, _ = _sample_actor_bundle()
    with pytest.raises(Refuted, match="another actor"):
        _delegations([_delegation(0, delegate=artifact["actor_id"])])


@pytest.mark.parametrize("interval", [None, [2000, 1000], [1000], [1000, "2000"], [True, 2000]],
                         ids=["absent", "reversed", "one-bound", "text-bound", "boolean-bound"])
def test_actor_delegation_names_its_interval(interval: object) -> None:
    """ACTOR-2.1 names the interval: a start and an end, each a bounded integer, in order."""
    with pytest.raises(Refuted):
        _delegations([_delegation(0, interval=interval)])


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


def _account(artifact: dict, inputs: dict, witness_keys: dict) -> dict:
    return evaluate("accountability", artifact, inputs, Budget(10000), witness_keys=witness_keys)


def test_actor_accountability_rests_on_independently_signed_witnesses() -> None:
    """ACTOR-3.4: every decision is attested by a witness the checker admits, over the exact trace."""
    artifact, inputs = _sample_actor_bundle()
    signed, keys = _witnessed(artifact, inputs)
    result = _account(artifact, signed, keys)
    assert result == {"witnesses_verified": 2, "decisions_witnessed": 2}


def test_actor_witness_named_independent_establishes_nothing_by_its_name() -> None:
    """A witness identifier is a declaration: an unsigned `witness:independent:*` is not independence.

    Before this was fixed, any witness whose identifier differed from the actor's passed, so an
    actor could attest its own decisions under a second name.
    """
    artifact, inputs = _sample_actor_bundle()
    _, keys = _witnessed(artifact, inputs)
    with pytest.raises(Unavailable, match="rests on no independent witness"):
        _account(artifact, inputs, {})
    with pytest.raises(Refuted, match="does not verify"):
        _account(artifact, inputs, keys)


def test_actor_self_witness_establishes_nothing() -> None:
    """An attribution resting only on the actor's own record establishes nothing, so it is UNKNOWN."""
    artifact, inputs = _sample_actor_bundle()
    signed, keys = _witnessed(artifact, inputs)
    own = dict(signed, witness_attributions=[
        _attest(artifact, artifact["actor_id"], "dec:001", signer=WITNESSES[0]),
        signed["witness_attributions"][1]])
    with pytest.raises(Unavailable, match="dec:001 rests on no independent witness"):
        _account(artifact, own, dict(keys, **{artifact["actor_id"]: keys[WITNESSES[0]]}))


def test_actor_witness_holding_an_actor_key_is_not_independent() -> None:
    """A record signed with key material the actor controls is a record the actor controls."""
    artifact, inputs = _sample_actor_bundle()
    signed, keys = _witnessed(artifact, inputs)
    captured = dict(artifact, control_surface=[
        *artifact["control_surface"],
        {"key_id": "key:custody", "algorithm": "ed25519", "public_key": keys[WITNESSES[0]]}])
    with pytest.raises(Unavailable, match="dec:001 rests on no independent witness"):
        _account(captured, signed, keys)


def test_actor_forged_or_misdirected_witness_is_refuted() -> None:
    artifact, inputs = _sample_actor_bundle()
    signed, keys = _witnessed(artifact, inputs)
    forged = dict(signed, witness_attributions=[
        _attest(artifact, WITNESSES[0], "dec:001", signer=WITNESSES[1]), signed["witness_attributions"][1]])
    with pytest.raises(Refuted, match="does not verify"):
        _account(artifact, forged, keys)
    elsewhere = dict(signed, witness_attributions=[
        dict(signed["witness_attributions"][0], actor_id="actor:other"), signed["witness_attributions"][1]])
    with pytest.raises(Refuted, match="binds another actor"):
        _account(artifact, elsewhere, keys)
    outside = dict(signed, witness_attributions=[
        *signed["witness_attributions"], _attest(artifact, WITNESSES[0], "dec:999")])
    with pytest.raises(Refuted, match="outside the bound decision trace"):
        _account(artifact, outside, keys)


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


def _attribute(decisions: list) -> dict:
    artifact, inputs = _sample_actor_bundle()
    return evaluate("attribution", dict(artifact, decisions_digest=digest(decisions)),
                    dict(inputs, decisions=decisions), Budget(10000))


def test_actor_decision_position_is_an_integer_not_a_truth_value() -> None:
    """ACTOR-4.2 enumerates decisions at stated positions; `True == 1`, so a Boolean must not pass."""
    _, inputs = _sample_actor_bundle()
    decisions = [inputs["decisions"][0], dict(inputs["decisions"][1], position=True)]
    with pytest.raises(Refuted, match="bounded integer"):
        _attribute(decisions)


@pytest.mark.parametrize("instrument", [None, "", ["cli:vstd"]], ids=["absent", "empty", "list"])
def test_actor_decision_names_its_instrument(instrument: object) -> None:
    """An instrument executes while the actor answers, so each decision names one as text."""
    _, inputs = _sample_actor_bundle()
    with pytest.raises(Refuted):
        _attribute([dict(inputs["decisions"][0], instrument=instrument), inputs["decisions"][1]])


def test_actor_domain_certificate_build_and_recheck() -> None:
    import json
    from pathlib import Path
    from jsonschema import Draft202012Validator
    from verifier.domains.certification import (
        build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate
    )
    artifact, inputs = _sample_actor_bundle()
    inputs, keys = _witnessed(artifact, inputs)
    evidence = {
        "schema_version": "verifier-domain-evidence-1",
        "domain": "ACTOR",
        "subject_id": artifact["actor_id"],
        "artifact": artifact,
        "inputs": inputs,
    }
    policy = domain_policy(trust_roots=["test:trust"], witness_keys=keys)
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
    assert list(result["checks"].keys()) == ["ACTOR-1.1", "ACTOR-2.1", "ACTOR-3.4", "ACTOR-4.2"]
    assert all(row["established"] for row in result["checks"].values())

    # Without the witnesses' keys in the checker's own policy, nothing shows they are
    # independent, so the certificate stops short of accountability rather than passing.
    unadmitted = domain_policy(trust_roots=["test:trust"])
    result = build_domain_certificate(request, evidence, policy=unadmitted)["result"]
    assert result["status"] == "UNKNOWN"
    assert result["checks"]["ACTOR-3.4"]["evaluation"]["outcome"] == "UNKNOWN"


from verifier.domains.certification import (
    build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate,
)


def _assess_control_key(control_encoding: Callable[[str], str] | None = None) -> tuple[dict, dict]:
    artifact, inputs = _sample_actor_bundle()
    inputs, keys = _witnessed(artifact, inputs)
    if control_encoding is not None:
        encoded = control_encoding(keys[WITNESSES[0]])
        assert bytes.fromhex(encoded) == bytes.fromhex(keys[WITNESSES[0]])
        artifact["control_surface"].append({"key_id": "declared-actor-witness-key",
            "algorithm": "ed25519", "public_key": encoded})
        inputs["control_keys"] = artifact["control_surface"]
    evidence = {"schema_version": "verifier-domain-evidence-1", "domain": "ACTOR",
        "subject_id": artifact["actor_id"], "artifact": artifact, "inputs": inputs}
    request = domain_request(evidence, target_depth=4)
    policy = domain_policy(trust_roots=["test:independent-checker"], witness_keys=keys)
    certificate = build_domain_certificate(request, evidence, policy=policy)
    replay = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
    print("ACTOR_RESULT", certificate["result"]["status"], replay["status"], flush=True)
    return certificate, replay


def test_distinct_admitted_witnesses_pass() -> None:
    certificate, replay = _assess_control_key()
    assert certificate["result"]["status"] == replay["status"] == "PASS"


@pytest.mark.parametrize("encode", [lambda h: h, lambda h: h.upper()], ids=["lower", "upper"])
def test_declared_actor_key_is_not_independent(encode: Callable[[str], str]) -> None:
    certificate, replay = _assess_control_key(encode)
    assert certificate["result"]["status"] == replay["status"] == "UNKNOWN"


@pytest.mark.parametrize("encode", [
    lambda h: " ".join(h[i:i+2] for i in range(0, len(h), 2)),
    lambda h: "\t" + h,
    lambda h: h + "\n",
    lambda h: h[:32] + "\r\n" + h[32:],
], ids=["byte-spaces", "leading-tab", "trailing-newline", "middle-crlf"])
def test_same_decoded_actor_key_cannot_be_an_independent_witness(encode: Callable[[str], str]) -> None:
    certificate, replay = _assess_control_key(encode)
    assert certificate["result"]["status"] != "PASS", "Actor-owned key passed via alternate hex spelling"
    assert replay["status"] != "PASS", "Recheck accepted actor-owned witness key"
