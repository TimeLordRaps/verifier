"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

Edwards-curve digital signature algorithm with a 255-bit field (Ed25519).
Finite native, signature and local-ledger fixture with no full-profile promotion.

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
from verifier.runtime import finite_record_issuance as issuer
from verifier.runtime import polish_public_authority as authority, polish_invocation_ledger as ledger
from verifier.core.namespace import composition_digest
from pathlib import Path


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


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


class FinitePackage:
    """Real finite native/signature/SQLite fixture; no full positive is supplied."""
    def __init__(self, tmp_path):
        pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: signature fixtures require the seal extra (cryptography); the platform-python-contracts workflow job installs it")
        import cryptography
        assert cryptography.__version__ == "50.0.0", "signature qualification needs exact cryptography==50.0.0"
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.public = Package()
        self.keys = {name: Ed25519PrivateKey.generate() for name in ("a", "b", "veto", "status")}
        self.ledger = ledger.IssuerLedgerSelection(str(tmp_path / "finite.sqlite"), "fixture:finite-ledger", "fixture:finite-domain", 1)
        ledger.provision_issuance_ledger(self.ledger)
        self.refresh()

    def refresh(self):
        p = self.public
        record = p.dependency["objects"][0]
        item = NamespaceObject.create(record["object_id"], record["kind"], record["payload"], record["operands"])
        self.source = canonical_bytes({"schema_version": "fixture:retained-source-scope-1", "source": record})
        self.docs = {"source_scope": self.source, "native_bundle": canonical_bytes(p.dependency),
            "native_policy": canonical_bytes(p.policy), "public_bundle": p.bundle_bytes(),
            "public_request": canonical_bytes(p.request), "disclosure_policy": canonical_bytes(p.disclosure_policy),
            "disclosure_evidence": canonical_bytes(p.evidence)}
        self.action = {"operation": authority.FINITE_OPERATION, "application_id": "fixture:finite-record",
            "profile_digest": digest(canonical_bytes(p.dependency["profiles"][0])), "source_scope_digest": digest(self.source),
            "collection_digest": composition_digest([item]), "actor_id": "fixture:submitter", "observer_id": "PUBLIC",
            "purpose": "FINITE_OBJECT_RECORD_ISSUANCE", "jurisdiction": "fixture:only", "timestamp": p.time,
            "invocation_id": "fixture:one", "ledger_id": self.ledger.ledger_id,
            "policy_domain": self.ledger.policy_domain, "policy_epoch": self.ledger.policy_epoch}
        scope = {name: self.action[name] for name in authority._SCOPE_FIELDS}
        self.authority_policy = {"schema_version": authority.POLICY, "mechanism_digest": authority.mechanism_digest(),
            "policy_id": "fixture:independent-operator", "revision": 1,
            "keys": [{"key_id": name, "actor_id": "actor:" + name, "public_key": key.public_key().public_bytes_raw().hex()}
                     for name, key in self.keys.items()], "voting_key_ids": ["a", "b", "veto"], "status_key_id": "status",
            "quorum": 2, "veto_actor_ids": ["actor:veto"], "scopes": [scope],
            "effective_from": 0, "effective_until": 300, "max_status_age_seconds": 60}
        # Actual finite fixture bytes are committed. These labels do not represent
        # a qualified production tree/wheel, import attestation or trusted humans.
        source_bytes = Path(object_facets.__file__).read_bytes()
        self.policy = {"schema_version": issuer.POLICY, "mode": issuer.FINITE,
            "mechanism_digest": issuer.mechanism_digest(), "source_commitments": {
                "source_tree_digest": digest(source_bytes), "wheel_digest": digest(b"fixture:local-unreleased-wheel-capsule"),
                "namespace_digest": digest(canonical_bytes(record))},
            "input_digests": {name: digest(raw) for name, raw in self.docs.items()},
            "artifact_inventory_digest": dag.artifact_files_digest(p.files), "action": self.action, "postcommit_key_id": "status"}
        self.host = issuer.FiniteIssuerHostSelection(canonical_bytes(self.policy), digest(canonical_bytes(self.policy)),
            canonical_bytes(self.authority_policy), digest(canonical_bytes(self.authority_policy)), self.ledger)
        self.bundle = canonical_bytes({"schema_version": issuer.BUNDLE,
            "documents": [{"name": name, "base64": b64(raw)} for name, raw in sorted(self.docs.items())],
            "artifact_files": [{"path": path, "base64": b64(raw)} for path, raw in sorted(p.files.items())]})
        self.request = canonical_bytes({"schema_version": issuer.REQUEST, "mode": issuer.FINITE,
            "bundle_digest": digest(self.bundle), "host_policy_digest": self.host.expected_policy_digest, "action": self.action})
        self.evidence = None

    def envelope(self, payload, key_id):
        encoded = canonical_bytes(payload)
        return {"schema_version": authority.ENVELOPE, "algorithm": "Ed25519", "key_id": key_id,
            "payload": payload, "payload_digest": digest(encoded),
            "signature": self.keys[key_id].sign(authority.authority_signing_bytes(encoded, key_id=key_id)).hex()}

    def assess(self):
        return issuer.assess_finite_record_issuance(self.bundle, request_bytes=self.request,
            issue_evidence_bytes=None if self.evidence is None else canonical_bytes(self.evidence),
            host_selection=self.host, evaluation_time=self.public.time)

    def decision(self, name, decision="APPROVE"):
        return self.envelope({"schema_version": authority.DECISION, "decision_id": "decision:" + name,
            "actor_id": "actor:" + name, "context_digest": digest(canonical_bytes(self.context)),
            "policy_digest": self.host.expected_authority_policy_digest,
            "issued_at": 90, "expires_at": 200, "decision": decision}, name)

    def authorize(self):
        initial = self.assess()
        assert initial["status"] == "UNKNOWN" and initial["polished"] is False
        self.context = initial["authority_context"]
        status = {"schema_version": authority.STATUS, "policy_digest": self.host.expected_authority_policy_digest,
            "ledger_id": self.ledger.ledger_id, "policy_domain": self.ledger.policy_domain, "policy_epoch": self.ledger.policy_epoch,
            "observed_at": 90, "expires_at": 200, "revoked_decisions": [], "revoked_actors": [], "consumed_invocations": []}
        self.evidence = {"decisions": [self.decision("a"), self.decision("b")], "status": self.envelope(status, "status")}
        self.ready = self.assess()
        assert self.ready["status"] == "PASS" and self.ready["polished"] is False
        self.proposal = issuer.finite_precommit_proposal(self.ready)
        return self.ready

    def commit(self):
        return issuer.commit_finite_record_issuance(self.proposal, bundle_bytes=self.bundle, request_bytes=self.request,
            issue_evidence_bytes=canonical_bytes(self.evidence), host_selection=self.host, commit_time=self.public.time)

    def postcommit(self, receipt):
        payload = {"schema_version": issuer.COMMIT_PAYLOAD, "operation": issuer.COMMIT_OPERATION,
            "subject_digest": digest(canonical_bytes(self.ready["subject"])), "proposal_digest": digest(self.proposal),
            "receipt_digest": receipt["receipt_digest"], "authority_policy_digest": self.host.expected_authority_policy_digest,
            "authority_status_digest": self.ready["authority_status_digest"],
            **{name: receipt[name] for name in ("ledger_id", "policy_domain", "policy_epoch", "invocation_id", "commit_sequence", "commit_time")},
            "observed_at": self.public.time, "expires_at": 200, "revoked_subjects": []}
        self.public_commit = self.commit_envelope(payload)
        return self.public_commit

    def commit_envelope(self, payload, wrong_domain=False):
        encoded = canonical_bytes(payload)
        message = authority.authority_signing_bytes(encoded, key_id="status") if wrong_domain else issuer.finite_commit_signing_bytes(encoded, key_id="status")
        return canonical_bytes({"schema_version": issuer.COMMIT_ENVELOPE, "algorithm": "Ed25519", "key_id": "status",
            "payload": payload, "payload_digest": digest(encoded), "signature": self.keys["status"].sign(message).hex()})

    def final_selection(self, receipt):
        return {"receipt_bytes": canonical_bytes(receipt), "public_commit_bytes": self.public_commit,
            "bundle_bytes": self.bundle, "request_bytes": self.request, "issue_evidence_bytes": canonical_bytes(self.evidence),
            "host_selection": self.host, "evaluation_time": self.public.time}
