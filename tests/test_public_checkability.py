"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

Edwards-curve digital signature algorithm with a 255-bit field (Ed25519).
Finite public replay controls with no full-profile or authority promotion.

Positive checks use actual native certificates, actual native DAG replay and real
Ed25519 signatures. Negative-only monkeypatches fence or simulate unavailability;
none provides a successful native/authority result. Keys are ephemeral test objects.
"""
from __future__ import annotations

import asyncio
import base64
from copy import deepcopy
import hashlib
import json

import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.consent import public as consent
from verifier.consent import engine
from verifier.domains.contracts import certificate_dag as dag, object_facets, current_object_routes
from verifier.runtime import public_checkability as check


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def retained_missing_bundle_request():
    """Plain wrapper selection only; missing bundle supplies no native admission."""
    return canonical_bytes({"schema_version": check.REQUEST, "mechanism_digest": check.mechanism_digest(),
        "dependency_bundle_digest": digest(b"test:absent dependency"),
        "dependency_policy_digest": digest(b"test:absent native policy"),
        "artifact_inventory_digest": digest(b"test:absent inventory"),
        "required_nodes": [{"node_id": "test:absent", "mode": check.PUBLIC,
            "context_digest": digest(b"test:absent context"), "proof_protocol_id": None,
            "proof_statement_digest": None}],
        "disclosure_policy_terms_digest": digest(b"test:absent disclosure terms"),
        "disclosure": {"actor_id": "test:operator", "observer_id": "PUBLIC", "purpose": "PUBLIC_CHECKABILITY"}})


class Package:
    def __init__(self):
        pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: signature fixtures require the seal extra (cryptography); the platform-python-contracts workflow job installs it")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self.keys = {name: Ed25519PrivateKey.generate() for name in ("root", "status")}
        self.time = 100
        item = NamespaceObject.create("selected", "OBJECT", {"message": "public ✓"}, {})
        self.native_policy = object_facets.object_facets_policy(trust_roots=["test:independent-selection"])
        self.native_request = object_facets.object_facets_request(item, policy=self.native_policy)
        raw = object_facets.build_object_facets_certificate(self.native_request,
            canonical_bytes(item.to_dict()), policy=self.native_policy)
        replay = current_object_routes.replay_current_object_certificate(raw,
            semantic_version=object_facets.SEMANTIC_VERSION, objective=object_facets.COORDINATE,
            represented_kind=item.kind.value, expected_request=self.native_request, policy=self.native_policy)
        # Require actual native replay before using this fixture.
        assert replay["replay_status"] == "REPRODUCED" and replay["computational_status"] == "PASS"
        profile = {"schema_version": dag.PROFILE, "profile_id": "test-public-generic-only", "profile_version": "1",
            "object_kind": "OBJECT", "obligations": [{"claim_id": "generic", "semantic_version": object_facets.SEMANTIC_VERSION,
                "objective": object_facets.COORDINATE, "proposition_digest": object_facets.PROPOSITION_DIGEST,
                "scope": "generic_canonical_representation_and_address", "assumptions": [], "dependencies": []}]}
        node = {"node_id": "generic", "object_id": item.object_id, "claim_id": "generic", "certificate_path": "generic.json",
            "certificate_digest": digest(raw), "request": self.native_request, "checker_policy": self.native_policy,
            "contract_version": replay["schema_version"].rsplit("-", 1)[1],
            "artifact_bindings": [{"path": "generic.json", "digest": digest(raw)}],
            "facet_bindings": {"payload_digest": digest(item.payload_bytes), "operands_digest": digest(canonical_bytes(item.to_dict()["operands"]))}}
        self.files = {"generic.json": raw}
        self.dependency = {"schema_version": dag.BUNDLE, "profiles": [profile], "objects": [item.to_dict()], "nodes": [node], "edges": []}
        self.policy = {"schema_version": dag.POLICY, "approved_profiles": [digest(canonical_bytes(profile))],
            "required_objects": [{"object_id": item.object_id, "object_kind": "OBJECT", "record_digest": item.digest,
                                   "profile_digest": digest(canonical_bytes(profile))}],
            "required_roots": ["generic"], "nodes": deepcopy(self.dependency["nodes"]), "artifact_files_digest": dag.artifact_files_digest(self.files)}
        public_keys = [{"key_id": name, "actor_id": "holder",
            "public_key": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()} for name, key in self.keys.items()]
        self.disclosure_policy = consent.public_consent_policy(policy_id="test:disclose", grantor_id="holder", keys=public_keys,
            root_key_ids=["root"], revocation_key_ids=["status"], artifact_bindings=[], max_revocation_age_seconds=60)
        self.mode = check.PUBLIC
        self.rebind()

    def signed(self, payload, name):
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        return {"schema_version": consent.ENVELOPE_VERSION, "algorithm": "Ed25519", "key_id": name,
            "payload": payload, "payload_digest": hashlib.sha256(encoded).hexdigest(),
            "signature": self.keys[name].sign(consent.consent_signing_bytes(payload, name)).hex()}

    def rebind(self):
        """Create a NEW external test selection, including actual signed disclosure.

        This does not repair production input or prove its native predicate; a
        forged native certificate remains rejected even when its new hash is selected.
        """
        self.policy["nodes"] = deepcopy(self.dependency["nodes"])
        self.policy["artifact_files_digest"] = dag.artifact_files_digest(self.files)
        contexts = check.node_contexts(self.dependency, self.policy)
        self.request = {"schema_version": check.REQUEST, "mechanism_digest": check.mechanism_digest(),
            "dependency_bundle_digest": digest(canonical_bytes(self.dependency)), "dependency_policy_digest": digest(canonical_bytes(self.policy)),
            "artifact_inventory_digest": dag.artifact_files_digest(self.files),
            "required_nodes": [{"node_id": nid, "mode": self.mode, "context_digest": digest(canonical_bytes(context)),
                "proof_protocol_id": "uninstalled-proof-system-1" if self.mode == check.CONFIDENTIAL else None,
                "proof_statement_digest": digest(b"exact-placeholder-statement-NOT-A-PROOF") if self.mode == check.CONFIDENTIAL else None}
                for nid, context in sorted(contexts.items())],
            "disclosure_policy_terms_digest": check.disclosure_policy_terms_digest(self.disclosure_policy),
            "disclosure": {"actor_id": "operator", "observer_id": "PUBLIC", "purpose": "PUBLIC_CHECKABILITY"}}
        subject = digest(canonical_bytes(check.disclosure_subject(canonical_bytes(self.request))))[7:]
        self.disclosure_policy["artifact_bindings"] = [["OBJECT", subject]]
        grant = {"schema_version": "verifier-consent-public-grant-1", "grant_id": "test-grant", "issuer_id": "holder",
            "actor_id": "operator", "object_name": "OBJECT", "artifact_digest": subject,
            "operations": [check.OPERATION], "observer_ids": ["PUBLIC"], "purposes": ["PUBLIC_CHECKABILITY"],
            "not_before": 0, "not_after": 200, "parent_digest": None, "allow_delegation": False, "effect": "ALLOW"}
        state = {"schema_version": "verifier-consent-public-revocations-1", "issuer_id": "holder", "policy_id": "test:disclose",
            "as_of": 90, "next_update": 200, "revoked_grant_ids": []}
        self.evidence = {"grants": [self.signed(grant, "root")], "revocation": self.signed(state, "status")}

    def bundle_bytes(self):
        return canonical_bytes({"schema_version": check.BUNDLE, "dependency_bundle_base64": b64(canonical_bytes(self.dependency)),
            "dependency_policy_base64": b64(canonical_bytes(self.policy)),
            "artifact_files": [{"path": path, "base64": b64(raw)} for path, raw in sorted(self.files.items())]})

    def selection(self):
        return {"request_bytes": canonical_bytes(self.request), "disclosure_policy_bytes": canonical_bytes(self.disclosure_policy),
                "disclosure_evidence_bytes": canonical_bytes(self.evidence), "evaluation_time": self.time}

    def assess(self):
        return check.assess_public_checkability(self.bundle_bytes(), **self.selection())


def test_real_public_witness_replays_without_secret_policy_keys():
    package = Package()
    result = package.assess()
    assert result["status"] == result["nodes"][0]["status"] == "PASS"
    assert result["disclosure_status"] == "PASS" and result["dependency_assessment_digest"]
    assert result["polished_artifact"] is False and result["human_acceptance"] == "NOT_ESTABLISHED"
    assert result["public_availability"] == "NOT_ESTABLISHED" and result["publication"] == "NOT_PERFORMED"
    replay = check.recheck_public_checkability(canonical_bytes(result), package.bundle_bytes(), **package.selection())
    assert replay["status"] == "REPRODUCED" and replay["public_checkability_status"] == "PASS"
    # Unicode remains bound by the actual native and public-consent formats.
    assert "✓" in json.loads(base64.b64decode(json.loads(package.files["generic.json"])["evidence_payloads"][package.native_request["evidence_ref"]]))["payload"]["message"]


@pytest.mark.parametrize("target", ["artifact", "native-request", "node-context", "extra-file", "omitted-node"])
def test_exact_external_input_or_context_substitution_fails(target):
    package = Package()
    if target == "artifact":
        package.files["generic.json"] += b" "
    elif target == "extra-file":
        package.files["unexpected.json"] = b"{}"
    elif target == "native-request":
        package.dependency["nodes"][0]["request"]["object_id"] = "other"
    elif target == "node-context":
        package.request["required_nodes"][0]["context_digest"] = digest(b"other-context")
    else:
        package.request["required_nodes"] = []
    assert package.assess()["status"] == "FAIL"


def test_selected_forged_native_result_is_not_proof():
    package = Package()
    envelope = json.loads(package.files["generic.json"])
    envelope["result"]["execution"] = "ESTABLISHED"
    envelope["digest"] = digest(canonical_bytes({k: v for k, v in envelope.items() if k != "digest"}))
    package.files["generic.json"] = canonical_bytes(envelope)
    node = package.dependency["nodes"][0]
    node["certificate_digest"] = digest(package.files["generic.json"])
    node["artifact_bindings"][0]["digest"] = node["certificate_digest"]
    package.rebind()
    assert package.assess()["status"] == "FAIL"


@pytest.mark.parametrize("change, expected", [("signature", "FAIL"), ("revoked", "FAIL"), ("wrong-operation", "FAIL"),
    ("missing-status", "UNKNOWN"), ("stale-status", "UNKNOWN"), ("missing-time", "UNKNOWN")])
def test_actual_signed_disclosure_adverse_cases(change, expected):
    package = Package()
    if change == "signature":
        original = package.evidence["grants"][0]["signature"]
        package.evidence["grants"][0]["signature"] = ("0" if original[0] != "0" else "1") + original[1:]
    elif change == "revoked":
        state = package.evidence["revocation"]["payload"]
        state["revoked_grant_ids"] = ["test-grant"]
        package.evidence["revocation"] = package.signed(state, "status")
    elif change == "wrong-operation":
        grant = package.evidence["grants"][0]["payload"]
        grant["operations"] = ["ADMIT_SELECTED_POLISH_INVENTORY"]
        package.evidence["grants"] = [package.signed(grant, "root")]
    elif change == "missing-status":
        package.evidence["revocation"] = None
    elif change == "stale-status":
        package.time = 151
    else:
        package.time = None
    assert package.assess()["status"] == expected


def test_confidential_hashes_without_actual_verifier_are_unknown_and_fenced(monkeypatch):
    package = Package()
    package.mode = check.CONFIDENTIAL
    package.rebind()
    calls = []
    def prohibited(*args, **kwargs):
        calls.append(True)
        raise RuntimeError("native callback must remain fenced without actual proof verifier")
    monkeypatch.setattr(dag, "assess_certificate_dependencies", prohibited)
    result = package.assess()
    assert result["status"] == "UNKNOWN" and "CONFIDENTIAL_PROOF_VERIFIER_UNAVAILABLE:generic" in result["blockers"]
    assert not calls


def test_cancellation_unknown_interrupt_no_result_and_no_cached_positive(monkeypatch):
    package = Package()
    positive = package.assess()
    assert positive["status"] == "PASS"
    def cancelled(*args, **kwargs):
        raise asyncio.CancelledError()
    monkeypatch.setattr(dag, "assess_certificate_dependencies", cancelled)
    assert package.assess()["status"] == "UNKNOWN"
    replay = check.recheck_public_checkability(canonical_bytes(positive), package.bundle_bytes(), **package.selection())
    assert replay["status"] == "UNAVAILABLE" and replay["public_checkability_status"] == "UNKNOWN"
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr(dag, "assess_certificate_dependencies", interrupted)
    with pytest.raises(KeyboardInterrupt):
        package.assess()


def test_capacity_and_no_secret_witness_keys_do_not_pass(monkeypatch):
    package = Package()
    package.files.update({f"extra/{number:04d}": b"" for number in range(1024)})
    package.rebind()
    calls = []
    def prohibited(*args, **kwargs):
        calls.append(True)
        raise RuntimeError("capacity must fence native callbacks")
    with monkeypatch.context() as fence:
        fence.setattr(dag, "assess_certificate_dependencies", prohibited)
        assert package.assess()["status"] == "UNKNOWN"
    assert not calls
    package = Package()
    package.dependency["nodes"][0]["checker_policy"]["witness_keys"] = {"forbidden": "DO-NOT-EXPORT"}
    package.rebind()
    result = package.assess()
    assert result["status"] == "FAIL" and "DO-NOT-EXPORT" not in json.dumps(result)


def test_missing_retained_witness_and_duplicate_key_do_not_pass():
    package = Package()
    envelope = json.loads(package.files["generic.json"])
    envelope["evidence_payloads"] = {}
    envelope["digest"] = digest(canonical_bytes({k: v for k, v in envelope.items() if k != "digest"}))
    package.files["generic.json"] = canonical_bytes(envelope)
    node = package.dependency["nodes"][0]
    node["certificate_digest"] = digest(package.files["generic.json"])
    node["artifact_bindings"][0]["digest"] = node["certificate_digest"]
    package.rebind()
    assert package.assess()["status"] == "UNKNOWN"
    package = Package()
    raw = canonical_bytes(package.request)
    duplicate = b'{"schema_version":"duplicate",' + raw[1:]
    selection = package.selection()
    selection["request_bytes"] = duplicate
    assert check.assess_public_checkability(package.bundle_bytes(), **selection)["status"] == "FAIL"


def test_missing_crypto_backend_and_reproduced_unknown_never_pass(monkeypatch):
    package = Package()
    def unavailable(*args, **kwargs):
        raise engine._Unknown("backend unavailable")
    monkeypatch.setattr(consent, "_verify_signature", unavailable)
    result = package.assess()
    assert result["status"] == "UNKNOWN"
    replay = check.recheck_public_checkability(canonical_bytes(result), package.bundle_bytes(), **package.selection())
    assert replay["status"] == "REPRODUCED" and replay["public_checkability_status"] == "UNKNOWN"


def test_transport_caps_precede_all_submitted_input_hashes_without_crypto(monkeypatch):
    bundle, request, evidence = b'{"b":1}', b'{"r":2}', b'{"e":3}'
    overbound = b" " * (check.MIB + 1)
    values = (bundle, request, evidence, overbound)
    events = []
    original_capture = check._capture_inputs
    original_hash = check.hashlib.sha256
    def captured(selected):
        events.append("capture-start")
        result = original_capture(selected)
        events.append("capture-finished")
        return result
    def tracked(raw=b"", *args, **kwargs):
        if any(raw is value for value in values):
            assert "capture-finished" in events
            assert raw is not overbound
            events.append("bounded-input-hash")
        return original_hash(raw, *args, **kwargs)
    monkeypatch.setattr(check, "_capture_inputs", captured)
    monkeypatch.setattr(check.hashlib, "sha256", tracked)
    result = check.assess_public_checkability(bundle, request_bytes=request,
        disclosure_policy_bytes=overbound, disclosure_evidence_bytes=evidence, evaluation_time=100)
    assert result["status"] == "UNKNOWN" and result["input_capture"] == "INCOMPLETE_BOUND"
    assert result["input_digests"]["disclosure_policy"] is None
    assert events[:2] == ["capture-start", "capture-finished"]
    assert "bounded-input-hash" in events


def test_foreign_transport_refuses_before_length_or_submitted_input_hash_without_crypto(monkeypatch):
    callbacks, hashes = [], []
    class Foreign(bytes):
        def __len__(self):
            callbacks.append(True)
            raise RuntimeError("foreign length must not run")
    invalid = Foreign(b"{}")
    siblings = (b'{"r":1}', b'{"p":2}', b'{"e":3}')
    original_hash = check.hashlib.sha256
    def tracked(raw=b"", *args, **kwargs):
        if raw is invalid or any(raw is item for item in siblings):
            hashes.append(True)
        return original_hash(raw, *args, **kwargs)
    monkeypatch.setattr(check.hashlib, "sha256", tracked)
    result = check.assess_public_checkability(invalid, request_bytes=siblings[0],
        disclosure_policy_bytes=siblings[1], disclosure_evidence_bytes=siblings[2], evaluation_time=100)
    assert result["status"] == "FAIL" and not callbacks and not hashes


def test_known_input_contradiction_precedes_missing_bundle_and_overbound_sibling_without_crypto(monkeypatch):
    selection = {"request_bytes": retained_missing_bundle_request(), "disclosure_policy_bytes": None,
                 "disclosure_evidence_bytes": None, "evaluation_time": 100}
    stored = check.assess_public_checkability(None, **selection)
    assert stored["status"] == "UNKNOWN" and stored["input_capture"] == "BOUNDED_CAPTURED"
    changed = {**selection, "request_bytes": b'{"changed":true}', "disclosure_policy_bytes": b" " * (check.MIB + 1)}
    calls = []
    def prohibited(*args, **kwargs):
        calls.append(True)
        raise RuntimeError("known contradiction must precede dispatch")
    monkeypatch.setattr(check, "assess_public_checkability", prohibited)
    replay = check.recheck_public_checkability(canonical_bytes(stored), None, **changed)
    assert replay["status"] == "FAIL" and not calls


def test_never_retained_overbound_bytes_cannot_claim_exact_reproduction_without_crypto():
    selection = {"request_bytes": b"{}", "disclosure_policy_bytes": b" " * (check.MIB + 1),
                 "disclosure_evidence_bytes": None, "evaluation_time": 100}
    stored = check.assess_public_checkability(b"{}", **selection)
    assert stored["status"] == "UNKNOWN" and stored["input_capture"] == "INCOMPLETE_BOUND"
    replay = check.recheck_public_checkability(canonical_bytes(stored), b"{}", **selection)
    assert replay["status"] == "UNAVAILABLE" and replay["public_checkability_status"] == "UNKNOWN"


def test_known_changed_valid_package_precedes_new_unknown_proof_mode(monkeypatch):
    package = Package()
    positive = package.assess()
    assert positive["status"] == "PASS"
    package.mode = check.CONFIDENTIAL
    package.rebind()
    assert package.assess()["status"] == "UNKNOWN"
    calls = []
    def prohibited(*args, **kwargs):
        calls.append(True)
        raise RuntimeError("changed exact package must fail before new assessment")
    monkeypatch.setattr(check, "assess_public_checkability", prohibited)
    replay = check.recheck_public_checkability(canonical_bytes(positive), package.bundle_bytes(), **package.selection())
    assert replay["status"] == "FAIL" and not calls


def test_rehashed_forged_runtime_attestation_is_rejected_without_crypto():
    selection = {"request_bytes": retained_missing_bundle_request(), "disclosure_policy_bytes": None,
                 "disclosure_evidence_bytes": None, "evaluation_time": 100}
    stored = check.assess_public_checkability(None, **selection)
    assert stored["runtime_provenance"] == "TRUSTED_FIXED_HOST_PROCESS_REQUIRED;NOT_ATTESTED_BY_SOURCE_HASH"
    forged = {**stored, "runtime_provenance": "MACHINE_ATTESTED"}
    forged["assessment_digest"] = digest(canonical_bytes({k: v for k, v in forged.items() if k != "assessment_digest"}))
    replay = check.recheck_public_checkability(canonical_bytes(forged), None, **selection)
    assert replay["status"] == "FAIL"
