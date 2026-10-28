"""Verifier Standard (VSTD) selected simulation (SIM) shard signatures.

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
bind synthetic test records; no production private key is used.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import sim_shard_signatures as sim_shard_signatures_contract
from test_current_sim_shard_relations import selected as selected_relations
from test_current_sim_shard_coverage import selected as selected_shards
from verifier.runtime.polish import assess_polish


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def manual_message(module, request, policy, shard, index, row):
    # Independent field inventory and domain separator; no production message helper.
    return b"verifier-current-sim-shard-signature-1\x00" + canonical_bytes({
        "schema_version": "verifier-current-sim-shard-signature-message-1",
        "semantic_version": module.SEMANTIC_VERSION,
        "coordinate": "SIM-4.3", "proposition_digest": module.PROPOSITION_DIGEST,
        "subject_id": request["subject_id"], "object_digest": request["object_digest"],
        "collection_digest": request["collection_digest"],
        "relations_request_digest": request["relations_request_digest"],
        "relations_policy_digest": request["relations_policy_digest"],
        "relations_certificate_digest": request["relations_certificate_digest"],
        "policy_digest": digest(policy), "shard_id": shard, "step_index": index,
        "time": row["time"], "state": row["state"],
    })


SEAL_ABSENT = ("OPTIONAL_DEPENDENCY_ABSENT: shard signatures are Ed25519-signed and need the seal extra (cryptography); "
               "the platform-python-contracts workflow job installs it")


def selected(*, required_shards=None, signed_change=None, absent_key=None):
    module = sim_shard_signatures_contract
    Ed25519PrivateKey = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519", reason=SEAL_ABSENT).Ed25519PrivateKey
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization", reason=SEAL_ABSENT)

    relations_module, child_request, child_policy, child_evidence, _ = selected_relations()
    child = relations_module.build_sim_shard_relations_certificate(
        child_request, child_evidence, policy=child_policy)
    shard_evidence = json.loads(child_evidence)
    shard_child = json.loads(base64.b64decode(shard_evidence["shard_certificate"]))
    retained_rows = json.loads(base64.b64decode(
        shard_child["evidence_payloads"][shard_evidence["shard_request"]["evidence_ref"]]))["shard_rows"]
    required = ["left", "right"] if required_shards is None else required_shards
    private = {name: Ed25519PrivateKey.from_private_bytes(bytes([i + 1]) * 32)
               for i, name in enumerate(required)}
    keys = {name: key.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw).hex() for name, key in private.items()}
    if absent_key is not None:
        keys[absent_key] = None
    policy = module.sim_shard_signatures_policy(required_shards=required,
        public_keys=keys, trust_roots=["external-synthetic-shard-keys"])
    parameters = {"subject_id": child_request["subject_id"],
        "object_digest": child_request["object_digest"],
        "collection_digest": child_request["collection_digest"],
        "relations_request_digest": digest(child_request),
        "relations_policy_digest": digest(child_policy),
        "relations_certificate_digest": "sha256:" + hashlib.sha256(child).hexdigest()}
    signatures = {}
    for name in required:
        signatures[name] = []
        for index, row in enumerate(retained_rows[name]):
            message = manual_message(module, parameters, policy, name, index, row)
            if signed_change is not None and name == required[0] and index == 0:
                payload = json.loads(message.split(b"\x00", 1)[1])
                field, value = signed_change
                payload[field] = value
                message = b"verifier-current-sim-shard-signature-1\x00" + canonical_bytes(payload)
            signatures[name].append(private[name].sign(message).hex())
    evidence = {"schema_version": module.EVIDENCE_VERSION,
        "relations_request": child_request, "relations_policy": child_policy,
        "relations_certificate": base64.b64encode(child).decode("ascii"),
        "signatures": signatures}
    request = module.sim_shard_signatures_request(**parameters,
        evidence_ref=digest(evidence), policy=policy)
    return module, request, policy, canonical_bytes(evidence), retained_rows


def replay(module, request, policy, evidence):
    certificate = module.build_sim_shard_signatures_certificate(request, evidence, policy=policy)
    return certificate, module.recheck_sim_shard_signatures_certificate(
        certificate, expected_request=request, policy=policy)


def changed_evidence(request, evidence, mutate):
    retained = json.loads(evidence)
    mutate(retained)
    request["evidence_ref"] = digest(retained)
    return canonical_bytes(retained)


def test_exact_selected_shard_signatures_replay_without_authority_promotion():
    module, request, policy, evidence, rows = selected()
    certificate, native = replay(module, request, policy, evidence)
    public = routes.replay_current_object_certificate(certificate,
        semantic_version=module.SEMANTIC_VERSION, objective=module.COORDINATE,
        represented_kind="SIM", expected_request=request, policy=policy)
    assert native["status"] == public["computational_status"] == "PASS"
    assert native["selected_shard_signatures"] == "PASS"
    assert native["evaluation"]["observations"]["verified_signatures"] == 4
    assert native["authority"] == native["sim_tier_4_conformance"] == "NOT_ESTABLISHED"
    assert module.sim_shard_signature_message(request, policy=policy,
        shard_id="left", step_index=0, time=rows["left"][0]["time"],
        state=rows["left"][0]["state"]) == manual_message(
            module, request, policy, "left", 0, rows["left"][0])
    assert certificate == module.build_sim_shard_signatures_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("byte_index", [0, 63])
def test_single_bit_signature_tamper_fails_even_with_new_outer_hash(byte_index):
    module, request, policy, evidence, _ = selected()
    def mutate(value):
        signature = bytearray.fromhex(value["signatures"]["left"][0])
        signature[byte_index] ^= 1
        value["signatures"]["left"][0] = bytes(signature).hex()
    evidence = changed_evidence(request, evidence, mutate)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("change", [
    ("shard_id", "right"), ("step_index", 1), ("time", 1.0), ("time", 0),
    ("state", {"l": 100.0}), ("relations_certificate_digest", "sha256:" + "0" * 64),
    ("policy_digest", "sha256:" + "0" * 64),
])
def test_valid_signature_for_different_selected_message_is_refuted(change):
    module, request, policy, evidence, _ = selected(signed_change=change)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


def test_absent_selected_child_and_signature_stay_unknown():
    module, request, policy, evidence, _ = selected()
    absent_child = changed_evidence(request, evidence,
        lambda value: value.update(relations_certificate=None))
    assert replay(module, request, policy, absent_child)[1]["status"] == "UNKNOWN"
    absent_signature = changed_evidence(request, evidence,
        lambda value: value["signatures"]["left"].__setitem__(0, None))
    assert replay(module, request, policy, absent_signature)[1]["status"] == "UNKNOWN"


def test_known_missing_or_extra_signature_inventory_fails():
    for kind in ("missing", "extra", "short"):
        module, request, policy, evidence, _ = selected()
        def mutate(value):
            if kind == "missing":
                value["signatures"].pop("right")
            elif kind == "extra":
                value["signatures"]["other"] = []
            else:
                value["signatures"]["right"].pop()
        evidence = changed_evidence(request, evidence, mutate)
        assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


def test_partial_policy_only_claims_its_selected_shards():
    module, request, policy, evidence, _ = selected(required_shards=["left"])
    result = replay(module, request, policy, evidence)[1]
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["verified_signatures"] == 2
    assert result["all_shard_signatures"] == "NOT_ESTABLISHED"


def test_degenerate_key_policy_is_refused_before_optional_backend():
    module, _, policy, _, _ = selected()
    with pytest.raises(module.SimShardSignaturesError, match="inadmissible"):
        module.sim_shard_signatures_policy(required_shards=["left"],
            public_keys={"left": "00" * 32}, trust_roots=policy["trust_roots"])


def test_unavailable_signature_backend_stays_unknown(monkeypatch):
    module, request, policy, evidence, _ = selected()
    monkeypatch.setitem(sys.modules, "cryptography", None)
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_rehashed_parent_verdict_and_changed_selection_are_refused():
    module, request, policy, evidence, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    changed = deepcopy(request)
    changed["object_digest"] = "sha256:" + "0" * 64
    with pytest.raises(module.SimShardSignaturesError):
        module.recheck_sim_shard_signatures_certificate(certificate,
            expected_request=changed, policy=policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(module.SimShardSignaturesError):
        module.recheck_sim_shard_signatures_certificate(canonical_bytes(forged),
            expected_request=request, policy=policy)


def test_absent_key_stays_unknown_but_other_invalid_signature_is_not_masked():
    module, request, policy, evidence, _ = selected(absent_key="left")
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"
    evidence = changed_evidence(request, evidence,
        lambda value: value["signatures"]["right"].__setitem__(0, "00" * 64))
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("value", ["00", "FF" * 64, "gg" * 64, 1, True])
def test_malformed_present_signature_is_not_hidden_by_missing_child(value):
    module, request, policy, evidence, _ = selected()
    def mutate(retained):
        retained["relations_certificate"] = None
        retained["signatures"]["left"][0] = value
    evidence = changed_evidence(request, evidence, mutate)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


def test_absent_signature_does_not_hide_another_present_invalid_signature():
    module, request, policy, evidence, _ = selected()
    def mutate(retained):
        retained["signatures"]["left"][0] = None
        retained["signatures"]["right"][0] = "00" * 64
    evidence = changed_evidence(request, evidence, mutate)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


def test_changed_backend_version_stays_unknown(monkeypatch):
    cryptography = pytest.importorskip("cryptography", reason=SEAL_ABSENT)

    module, request, policy, evidence, _ = selected()
    monkeypatch.setattr(cryptography, "__version__", "UNQUALIFIED")
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_unsupported_backend_operation_stays_unknown(monkeypatch):
    UnsupportedAlgorithm = pytest.importorskip("cryptography.exceptions", reason=SEAL_ABSENT).UnsupportedAlgorithm
    ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519", reason=SEAL_ABSENT)

    module, request, policy, evidence, _ = selected()
    class UnavailableKey:
        @staticmethod
        def from_public_bytes(raw):
            raise UnsupportedAlgorithm("synthetic unavailable operation")
    monkeypatch.setattr(ed25519, "Ed25519PublicKey", UnavailableKey)
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_published_signature_vector_and_noncanonical_scalar_falsifier():
    # Request for Comments (RFC) 8032 section 7.1, test 1 (empty message).
    # https://www.rfc-editor.org/rfc/rfc8032.txt
    # Neither expected bytes nor expected result are generated by our signer.
    pytest.importorskip("cryptography", reason=SEAL_ABSENT)
    module = sim_shard_signatures_contract
    key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    module.signature_keys.admit_ed25519_public_key(key)
    module._verify_signature(signature, b"", key)
    with pytest.raises(module.Refuted, match="invalid"):
        module._verify_signature(signature, b"changed", key)
    # Scalar at or above the subgroup order must not verify by modular reduction.
    subgroup_order = 2**252 + 27742317777372353535851937790883648493
    altered = signature[:32] + (int.from_bytes(signature[32:], "little")
                               + subgroup_order).to_bytes(32, "little")
    with pytest.raises(module.Refuted, match="invalid"):
        module._verify_signature(altered, b"", key)


def test_forged_child_and_child_absence_verdict_are_replayed():
    module, request, policy, evidence, _ = selected()
    retained = json.loads(evidence)
    child = json.loads(base64.b64decode(retained["relations_certificate"]))
    child["result"]["status"] = "FAIL"
    child.pop("digest")
    child["digest"] = digest(child)
    raw = canonical_bytes(child)
    retained["relations_certificate"] = base64.b64encode(raw).decode("ascii")
    request["relations_certificate_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    request["evidence_ref"] = digest(retained)
    assert replay(module, request, policy, canonical_bytes(retained))[1]["status"] == "FAIL"
    from verifier.domains.contracts import sim_shard_relations
    raw = sim_shard_relations.build_sim_shard_relations_certificate(
        retained["relations_request"], None, policy=retained["relations_policy"])
    retained["relations_certificate"] = base64.b64encode(raw).decode("ascii")
    request["relations_certificate_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    request["evidence_ref"] = digest(retained)
    assert replay(module, request, policy, canonical_bytes(retained))[1]["status"] == "UNKNOWN"


def test_required_shard_outside_child_is_refuted():
    module, request, policy, evidence, _ = selected()
    retained = json.loads(evidence)
    policy = module.sim_shard_signatures_policy(required_shards=["left", "other"],
        public_keys={"left": policy["public_keys"]["left"],
                     "other": policy["public_keys"]["right"]},
        trust_roots=policy["trust_roots"])
    retained["signatures"]["other"] = retained["signatures"].pop("right")
    request["policy_digest"] = digest(policy)
    request["evidence_ref"] = digest(retained)
    assert replay(module, request, policy, canonical_bytes(retained))[1]["status"] == "FAIL"


@pytest.mark.parametrize("limits", [{"max_operations": 1}, {"max_items": 1},
                                   {"max_signatures": 1}])
def test_admitted_resource_exhaustion_stays_unknown(limits):
    module, request, policy, evidence, _ = selected()
    request["limits"].update(limits)
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_actual_canonical_certificate_refuses_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        ObserverParty, EmissionContext, EmissionEvaluator, EmissionRefusalError)

    module, request, policy, evidence, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    value = json.loads(certificate)
    fields = tuple(key for key in value if key != "evidence_payloads")
    surface = DisclosureSurface("SIM", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",)) for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/sim_shard_signatures.py", "standard/CURRENT_SIM_SHARD_SIGNATURES.md",
    "core/signature_keys.py", "domains/contracts/sim_shard_coverage.py",
])
def test_checker_or_spec_substitution_invalidates_selected_policy(monkeypatch, relative):
    module = sim_shard_signatures_contract
    before = module.mechanism_digest()
    target = (Path(module.__file__).resolve().parents[2] / relative).resolve()
    original = Path.read_bytes
    def changed(path):
        raw = original(path)
        return raw + b"\n# selected mechanism substitution\n" if path.resolve() == target else raw
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert module.mechanism_digest() != before


@pytest.mark.parametrize("relative", [
    "domains/contracts/sim_shard_signatures.py", "standard/CURRENT_SIM_SHARD_SIGNATURES.md",
])
def test_checker_or_spec_substitution_invalidates_polish_mechanism(monkeypatch, relative):
    from verifier.runtime import polish

    module = sim_shard_signatures_contract
    before = polish.mechanism_digest()
    target = (Path(module.__file__).resolve().parents[2] / relative).resolve()
    original = Path.read_bytes
    def changed(path):
        raw = original(path)
        return raw + b"\n# selected mechanism substitution\n" if path.resolve() == target else raw
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


def test_polish_keeps_unknown_aggregate_despite_selected_pass():
    module, request, policy, evidence, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    _, _, _, _, _, dynamics_evidence = selected_shards()
    objects = json.loads(dynamics_evidence)["objects"]
    certificate_digest = "sha256:" + hashlib.sha256(certificate).hexdigest()
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": objects,
              "certificates": {certificate_digest: certificate.decode("utf-8")}}
    requirements = [{"object_id": item["object_id"], "tier": tier,
                     "applicability": "REQUIRED", "rationale": "selected finite scope",
                     "objectives": []}
                    for item in objects for tier in range(1, 10)]
    next(row for row in requirements if row["object_id"] == "sim" and row["tier"] == 4)["objectives"] = [{
        "semantic_version": module.SEMANTIC_VERSION, "coordinate": module.COORDINATE,
        "request": request, "policy": policy, "certificate_digest": certificate_digest}]
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "sim", "collection_digest": request["collection_digest"],
        "bundle_digest": "sha256:" + hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
        "requirements": requirements}
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    assert report["objectives"][0]["status"] == "PASS"


def test_legacy_selector_and_wrong_kind_cannot_claim_current_signatures():
    module, request, policy, evidence, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    for semantic, kind in (("legacy-sim-domain-1", "SIM"), (module.SEMANTIC_VERSION, "BOT")):
        with pytest.raises(routes.CurrentObjectRouteRefusal):
            routes.replay_current_object_certificate(
                certificate, semantic_version=semantic, objective=module.COORDINATE,
                represented_kind=kind, expected_request=request, policy=policy)
