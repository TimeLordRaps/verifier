"""OBJECT-8.1 selected namespace-governance decision and adversarial replay.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Times are integer Unix seconds in Coordinated
Universal Time (UTC); all counts are dimensionless. Ephemeral signing keys
exist only in memory during these tests.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: OBJECT-8.1 governance evidence is Ed25519-signed and needs the seal extra (cryptography); the platform-python-contracts workflow job installs it")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import object_governance
from verifier.domains import common as common_module


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def key() -> tuple[Ed25519PrivateKey, str]:
    secret = Ed25519PrivateKey.generate()
    public = secret.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return secret, public


def signed(secret: Ed25519PrivateKey, role: str, key_id: str,
           payload: dict) -> dict:
    return {"schema_version": object_governance.ENVELOPE_VERSION,
            "key_id": key_id, "payload": payload,
            "signature": secret.sign(object_governance.signing_bytes(
                role, key_id, payload)).hex()}


def selected(*, votes: tuple[str, ...] = ("APPROVE", "APPROVE"),
             missing_status: bool = False, stale_status: bool = False,
             revoke_first: bool = False):
    object_record = NamespaceObject.create(
        "proposal", "OBJECT", {"namespace_name": "example",
                                "schema_digest": digest({"fields": ["value"]})})
    decision_keys = [key() for _ in range(3)]
    status_secret, status_public = key()
    policy = object_governance.governance_policy(
        namespace_id="reviewed-namespace", policy_id="policy-a", revision=7,
        decision_keys=[{"actor_id": f"actor-{i}", "key_id": f"decision-{i}",
                        "public_key": pair[1]} for i, pair in enumerate(decision_keys)],
        status_key={"key_id": "status", "public_key": status_public},
        quorum=2, valid_from=100, valid_until=300,
        max_status_age_seconds=20)
    policy_ref = digest(policy)
    record_ref = digest(object_record.to_dict())
    decisions = [
        signed(decision_keys[i][0], "decision", f"decision-{i}", {
            "schema_version": object_governance.DECISION_VERSION,
            "decision_id": f"vote-{i}", "actor_id": f"actor-{i}",
            "policy_digest": policy_ref, "record_digest": record_ref,
            "namespace_id": "reviewed-namespace", "action": "NAMESPACE_ADMIT",
            "vote": vote, "issued_at": 180, "expires_at": 220})
        for i, vote in enumerate(votes)
    ]
    status = None if missing_status else signed(status_secret, "status", "status", {
        "schema_version": object_governance.STATUS_VERSION,
        "policy_digest": policy_ref, "as_of": 160 if stale_status else 195,
        "expires_at": 220,
        "revoked_decision_ids": ["vote-0"] if revoke_first else []})
    evidence = {"schema_version": object_governance.EVIDENCE_VERSION,
                "record": object_record.to_dict(), "decisions": decisions,
                "status": status}
    evidence_bytes = canonical_bytes(evidence)
    request = object_governance.governance_request(
        object_record, namespace_id="reviewed-namespace",
        evidence_ref=digest(evidence), evaluation_time=200, policy=policy)
    return request, policy, evidence_bytes, decision_keys, status_secret


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = object_governance.build_governance_certificate(
        request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=object_governance.SEMANTIC_VERSION,
        objective=object_governance.COORDINATE, represented_kind="OBJECT",
        expected_request=request, policy=policy)
    return certificate, result


def test_exact_configured_quorum_and_fresh_status_replay_under_selected_policy():
    request, policy, evidence, _, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["native_result"]["legal_compliance"] == "NOT_ESTABLISHED"
    assert result["native_result"]["enforcement"] == "NOT_ESTABLISHED"
    assert "selected signed namespace governance" in result["claim_boundary"]
    assert "no legal compliance" in result["claim_boundary"]
    assert certificate == object_governance.build_governance_certificate(
        request, evidence, policy=policy)
    assert any(row["objective"] == object_governance.COORDINATE
               for row in routes.current_object_route_catalog())


@pytest.mark.parametrize("change", [
    "wrong-signature", "wrong-record", "duplicate-actor", "veto",
    "revoked", "wrong-status-signature", "wrong-policy",
])
def test_rehashed_false_or_unauthorized_governance_evidence_fails(change: str):
    request, policy, raw, secrets, status_secret = selected()
    evidence = json.loads(raw)
    if change == "wrong-signature":
        evidence["decisions"][0]["signature"] = "00" * 64
    elif change == "wrong-record":
        evidence["record"]["payload"]["namespace_name"] = "substituted"
    elif change == "duplicate-actor":
        evidence["decisions"][1] = deepcopy(evidence["decisions"][0])
        evidence["decisions"][1]["payload"]["decision_id"] = "vote-1"
        evidence["decisions"][1] = signed(secrets[0][0], "decision", "decision-0",
                                           evidence["decisions"][1]["payload"])
    elif change == "veto":
        payload = evidence["decisions"][0]["payload"]
        payload["vote"] = "VETO"
        evidence["decisions"][0] = signed(secrets[0][0], "decision", "decision-0", payload)
    elif change == "revoked":
        payload = evidence["status"]["payload"]
        payload["revoked_decision_ids"] = ["vote-0"]
        evidence["status"] = signed(status_secret, "status", "status", payload)
    elif change == "wrong-status-signature":
        evidence["status"]["signature"] = "00" * 64
    elif change == "wrong-policy":
        evidence["decisions"][0]["payload"]["policy_digest"] = digest({"forged": True})
        evidence["decisions"][0] = signed(secrets[0][0], "decision", "decision-0",
                                           evidence["decisions"][0]["payload"])
    raw = canonical_bytes(evidence)
    request["evidence_ref"] = digest(evidence)
    assert replay(request, policy, raw)[1]["computational_status"] == "FAIL"


@pytest.mark.parametrize("change", ["missing", "stale"])
def test_missing_or_stale_revocation_view_remains_unknown(change: str):
    request, policy, evidence, _, _ = selected(
        missing_status=change == "missing", stale_status=change == "stale")
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"


def test_external_request_policy_and_carried_verdict_substitution_are_rejected():
    request, policy, evidence, _, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    altered = deepcopy(request)
    altered["namespace_id"] = "another-namespace"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=object_governance.SEMANTIC_VERSION,
            objective=object_governance.COORDINATE, represented_kind="OBJECT",
            expected_request=altered, policy=policy)
    altered_policy = deepcopy(policy)
    altered_policy["revision"] = 8
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=object_governance.SEMANTIC_VERSION,
            objective=object_governance.COORDINATE, represented_kind="OBJECT",
            expected_request=request, policy=altered_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged["certificate_digest"] = digest({k: v for k, v in forged.items()
                                           if k != "certificate_digest"})
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            canonical_bytes(forged), semantic_version=object_governance.SEMANTIC_VERSION,
            objective=object_governance.COORDINATE, represented_kind="OBJECT",
            expected_request=request, policy=policy)


def test_wrong_represented_kind_and_unregistered_semantics_refuse_route():
    request, policy, evidence, _, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    for kind, version in (("HUMAN", object_governance.SEMANTIC_VERSION),
                          ("OBJECT", "legacy-unversioned")):
        with pytest.raises(routes.CurrentObjectRouteRefusal):
            routes.replay_current_object_certificate(
                certificate, semantic_version=version,
                objective=object_governance.COORDINATE, represented_kind=kind,
                expected_request=request, policy=policy)


def test_public_command_replays_exact_bytes_while_polish_remains_unknown(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence, _, _ = selected()
    certificate = object_governance.build_governance_certificate(
        request, evidence, policy=policy)
    paths = {name: tmp_path / (name + ".json")
             for name in ("certificate", "request", "policy")}
    for name, raw in (("certificate", certificate),
                      ("request", canonical_bytes(request)),
                      ("policy", canonical_bytes(policy))):
        paths[name].write_bytes(raw)
    before = {name: path.read_bytes() for name, path in paths.items()}
    code = main(["current-object", "check", str(paths["certificate"]),
        "--semantic-version", object_governance.SEMANTIC_VERSION,
        "--objective", object_governance.COORDINATE,
        "--represented-kind", "OBJECT",
        "--request", str(paths["request"]), "--policy", str(paths["policy"]),
        "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    assert before == {name: path.read_bytes() for name, path in paths.items()}

    subject = NamespaceObject.create("proposal", "OBJECT", {
        "namespace_name": "example", "schema_digest": digest({"fields": ["value"]})})
    certificate_ref = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": [subject.to_dict()],
              "certificates": {certificate_ref: certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "proposal", "collection_digest": composition_digest([subject]),
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "proposal", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected governance only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][7]["objectives"] = [{
        "semantic_version": object_governance.SEMANTIC_VERSION,
        "coordinate": object_governance.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": certificate_ref}]
    report = assess_polish(canonical_bytes(bundle),
                           request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["status"] == "UNKNOWN" and report["polished"] is False


def test_policy_helper_owns_selected_public_key_inputs():
    first, first_public = key()
    status_secret, status_public = key()
    keys = [{"actor_id": "actor-0", "key_id": "decision-0",
             "public_key": first_public}]
    status_key = {"key_id": "status", "public_key": status_public}
    policy = object_governance.governance_policy(
        namespace_id="reviewed-namespace", policy_id="policy-a", revision=1,
        decision_keys=keys, status_key=status_key, quorum=1,
        valid_from=100, valid_until=300)
    keys[0]["actor_id"] = "substituted"
    status_key["key_id"] = "substituted"
    assert policy["decision_keys"][0]["actor_id"] == "actor-0"
    assert policy["status_key"]["key_id"] == "status"
    assert first and status_secret


def test_shared_verdict_semantics_change_invalidates_selected_policy(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    request, policy, evidence, _, _ = selected()
    altered = tmp_path / "common.py"
    altered.write_bytes(Path(common_module.__file__).read_bytes()
                        + b"\n# simulated changed shared verdict semantics\n")
    monkeypatch.setattr(common_module, "__file__", str(altered))
    with pytest.raises(object_governance.ObjectGovernanceError,
                       match="selected policy mechanism differs"):
        object_governance.build_governance_certificate(
            request, evidence, policy=policy)


def test_direct_builder_refuses_foreign_comparison_callbacks():
    class HostileText(str):
        def __eq__(self, other):
            raise AssertionError("foreign equality callback invoked")

        def __ne__(self, other):
            raise AssertionError("foreign inequality callback invoked")

        __hash__ = str.__hash__

    request, policy, evidence, _, _ = selected()
    policy["mechanism_id"] = HostileText(object_governance.MECHANISM_ID)
    with pytest.raises(object_governance.ObjectGovernanceError):
        object_governance.build_governance_certificate(
            request, evidence, policy=policy)


def test_missing_public_signature_backend_is_unavailable_not_forgery(monkeypatch):
    request, policy, evidence, _, _ = selected()
    certificate = object_governance.build_governance_certificate(
        request, evidence, policy=policy)
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=object_governance.SEMANTIC_VERSION,
        objective=object_governance.COORDINATE, represented_kind="OBJECT",
        expected_request=request, policy=policy)
    assert result["replay_status"] == "UNAVAILABLE"
    assert result["computational_status"] == "UNKNOWN"
    assert result["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("field,value", [
    ("object_profile_conformance", "PASS"),
    ("enforcement", "PASS"),
    ("legal_compliance", "PASS"),
    ("status", "NOT_A_VERDICT"),
    ("record_digest", "sha256:" + "0" * 64),
])
def test_carried_governance_invariants_reject_without_signature_backend(
        field: str, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, _, _ = selected()
    forged = json.loads(object_governance.build_governance_certificate(
        request, evidence, policy=policy))
    forged["result"][field] = value
    forged["certificate_digest"] = digest({
        key: item for key, item in forged.items() if key != "certificate_digest"})
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)
    with pytest.raises(object_governance.ObjectGovernanceError,
                       match="certificate result invariant differs"):
        object_governance.recheck_governance_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def test_canonical_governance_certificate_refuses_retained_evidence_redaction() -> None:
    from verifier.privacy import (
        DisclosureSurface, DisclosureBound, ObserverParty, EmissionContext,
        EmissionEvaluator, EmissionRefusalError)

    request, policy, evidence, _, _ = selected()
    certificate = json.loads(object_governance.build_governance_certificate(
        request, evidence, policy=policy))
    fields = tuple(key for key in certificate if key != "evidence_payloads")
    surface = DisclosureSurface("OBJECT", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(certificate, surface, bounds,
                                              context)


@pytest.mark.parametrize('field,value',[
 ('approvals',999),('quorum',999),('policy_revision','wrong-revision'),
 ('status_as_of',True),('observations',[]),('reason',None),('details',None),
])
def test_decidable_carried_observations_cannot_hide_behind_unavailable_backend(field,value,monkeypatch):
    request,policy,evidence,_,_=selected()
    cert=json.loads(object_governance.build_governance_certificate(request,evidence,policy=policy))
    evaluation=cert['result']['evaluation']
    if field in ('observations','reason','details'):evaluation[field]=value
    else:evaluation['observations'][field]=value
    cert['certificate_digest']='sha256:'+hashlib.sha256(canonical_bytes({k:v for k,v in cert.items() if k!='certificate_digest'})).hexdigest()
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)
    with pytest.raises(object_governance.ObjectGovernanceError):
        object_governance.recheck_governance_certificate(canonical_bytes(cert),expected_request=request,policy=policy)


def _independent_signed_fixture(secret, role: str, key_id: str, payload: dict) -> dict:
    # Independently specified wire prefix and envelope; the production signing
    # serializer is not the oracle for this paired evidence lane.
    encoded = json.dumps({"schema_version": "verifier-current-object-governance-envelope-1",
        "role": role, "key_id": key_id, "payload": payload}, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    message = b"vstd-object-governance-ed25519-1\0" + encoded
    signature = secret.sign(message)
    Ed25519PublicKey.from_public_bytes(secret.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)).verify(signature, message)
    return {"schema_version": object_governance.ENVELOPE_VERSION,
            "key_id": key_id, "payload": payload, "signature": signature.hex()}


def _paired_dependency_refutation(request: dict, policy: dict, good: bytes,
                                  bad: dict, monkeypatch, mode: str = "all") -> None:
    changed = canonical_bytes(bad)
    bad_request = {**request, "evidence_ref": digest(bad)}
    bad_certificate, bad_prior = replay(bad_request, policy, changed)
    good_certificate, good_prior = replay(request, policy, good)
    assert bad_prior["computational_status"] == "FAIL"
    assert good_prior["computational_status"] == "PASS"
    if mode == "all":
        monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)
    else:
        original_verify = object_governance._verify_envelope

        def unavailable(value, *, role, key_id, public_key):
            if role == "status":
                raise object_governance._SignatureBackendUnavailable(
                    "selected production signature dependency unavailable")
            return original_verify(value, role=role, key_id=key_id, public_key=public_key)

        monkeypatch.setattr(object_governance, "_verify_envelope", unavailable)
    results = []
    for certificate, selected_request in ((bad_certificate, bad_request), (good_certificate, request)):
        results.append(routes.replay_current_object_certificate(certificate,
            semantic_version=object_governance.SEMANTIC_VERSION, objective="OBJECT-8.1", represented_kind="OBJECT",
            expected_request=selected_request, policy=policy))
    assert results[0]["computational_status"] == "FAIL"
    assert results[0]["replay_status"] == "REPRODUCED"
    assert results[1]["computational_status"] == "UNKNOWN"
    assert results[1]["replay_status"] == "UNAVAILABLE"


@pytest.mark.parametrize("position", [0, 1])
@pytest.mark.parametrize("violation", ["veto", "wrong-record", "expired", "duplicate-id",
    "wrong-actor", "future-issued", "wrong-policy", "payload-shape"])
def test_decidable_decision_constraints_survive_dependency_loss(violation, position, monkeypatch):
    request, policy, good, secrets, _ = selected()
    value = json.loads(good); bad = deepcopy(value); payload = bad["decisions"][position]["payload"]
    if violation == "veto": payload["vote"] = "VETO"
    elif violation == "wrong-record": payload["record_digest"] = "sha256:" + "0" * 64
    elif violation == "expired": payload["expires_at"] = request["evaluation_time"] - 1
    elif violation == "duplicate-id": payload["decision_id"] = value["decisions"][1 - position]["payload"]["decision_id"]
    elif violation == "wrong-actor": payload["actor_id"] = value["decisions"][1 - position]["payload"]["actor_id"]
    elif violation == "future-issued": payload["issued_at"] = request["evaluation_time"] + 1
    elif violation == "wrong-policy": payload["policy_digest"] = "sha256:" + "0" * 64
    else: payload["unsupported"] = "outside-decision-schema"
    bad["decisions"][position] = _independent_signed_fixture(secrets[position][0], "decision", f"decision-{position}", payload)
    assert bad["status"] == value["status"] and bad["decisions"][1 - position] == value["decisions"][1 - position]
    _paired_dependency_refutation(request, policy, good, bad, monkeypatch)


@pytest.mark.parametrize("mode", ["all", "status-only"])
@pytest.mark.parametrize("violation", ["wrong-policy", "schema", "future", "inverted",
    "boolean-time", "revoked-type", "revoked-duplicate", "selected-revoked"])
def test_decidable_fresh_status_constraints_survive_dependency_loss(violation, mode, monkeypatch):
    request, policy, good, _, secret = selected()
    value = json.loads(good); bad = deepcopy(value); payload = bad["status"]["payload"]
    if violation == "wrong-policy": payload["policy_digest"] = "sha256:" + "0" * 64
    elif violation == "schema": payload["unsupported"] = "outside-status-schema"
    elif violation == "future": payload["as_of"] = request["evaluation_time"] + 1
    elif violation == "inverted": payload["expires_at"] = payload["as_of"]
    elif violation == "boolean-time": payload["as_of"] = True
    elif violation == "revoked-type": payload["revoked_decision_ids"] = {}
    elif violation == "revoked-duplicate": payload["revoked_decision_ids"] = ["unselected", "unselected"]
    else: payload["revoked_decision_ids"] = [value["decisions"][0]["payload"]["decision_id"]]
    bad["status"] = _independent_signed_fixture(secret, "status", "status", payload)
    assert bad["record"] == value["record"] and bad["decisions"] == value["decisions"]
    _paired_dependency_refutation(request, policy, good, bad, monkeypatch, mode)


@pytest.mark.parametrize("mode", ["all", "status-only"])
@pytest.mark.parametrize("violation", ["wrong-key", "wrong-version", "missing-signature", "signature-shape"])
def test_status_envelope_grammar_survives_decision_dependency_loss(violation, mode, monkeypatch):
    request, policy, good, _, secret = selected()
    value = json.loads(good); bad = deepcopy(value)
    if violation == "wrong-key": bad["status"] = _independent_signed_fixture(secret, "status", "unselected", bad["status"]["payload"])
    elif violation == "wrong-version": bad["status"]["schema_version"] = "unselected-envelope"
    elif violation == "missing-signature": del bad["status"]["signature"]
    else: bad["status"]["signature"] = "NOT_HEXADECIMAL"
    assert bad["status"]["payload"] == value["status"]["payload"] and bad["decisions"] == value["decisions"]
    _paired_dependency_refutation(request, policy, good, bad, monkeypatch, mode)


@pytest.mark.parametrize("violation", ["zero-decisions", "one-decision", "duplicate-signer", "unconfigured-signer"])
def test_finite_approval_inventory_refutation_survives_dependency_loss(violation, monkeypatch):
    request, policy, good, secrets, _ = selected()
    bad = json.loads(good)
    if violation == "zero-decisions": bad["decisions"] = []
    elif violation == "one-decision": bad["decisions"] = bad["decisions"][:1]
    elif violation == "duplicate-signer": bad["decisions"][1] = deepcopy(bad["decisions"][0])
    else: bad["decisions"][1] = _independent_signed_fixture(secrets[1][0], "decision", "unconfigured", bad["decisions"][1]["payload"])
    _paired_dependency_refutation(request, policy, good, bad, monkeypatch)
