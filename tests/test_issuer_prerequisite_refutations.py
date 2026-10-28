"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

adverse test proposal: never imported, parsed, compiled or executed here.

ROOT must independently select/integrate/qualify the reviewed proposal before use.
These tests supply no successful native certificate, signature, ledger commit,
public proof, full inventory, loaded-code attestation or issuance fixture. The
small context fixture exercises wrapper structural preflight only; its named
confidential verifier is unavailable and its native callback is always fenced.
Every carried PASS marker in the ledger test is an adversarial untrusted record.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.runtime import polish_invocation_ledger as ledger
from verifier.runtime import public_checkability as check


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encoded(raw):
    return base64.b64encode(raw).decode("ascii")


@pytest.mark.parametrize("contradiction", ["purpose", "observer", "native-bundle-pin", "native-policy-pin", "inventory-pin", "context-pin"])
@pytest.mark.parametrize("capacity_error", [OSError, RecursionError, OverflowError])
def test_available_local_request_refutation_precedes_source_unavailability(monkeypatch, contradiction, capacity_error):
    bundle, request_bytes = unavailable_confidential_context_selection()
    request = json.loads(request_bytes)
    if contradiction in ("purpose", "observer"):
        request["disclosure"]["purpose" if contradiction == "purpose" else "observer_id"] = "other"
    elif contradiction == "inventory-pin":
        request["artifact_inventory_digest"] = digest(b"different complete artifact inventory")
    elif contradiction == "context-pin":
        request["required_nodes"][0]["context_digest"] = digest(b"different selected node context")
    else:
        request["dependency_bundle_digest" if contradiction == "native-bundle-pin"
                else "dependency_policy_digest"] = digest(b"different exact native input")
    calls = []
    def source_unavailable():
        calls.append("source")
        raise capacity_error("test selected source bytes unavailable")
    def native_forbidden(*args, **kwargs):
        pytest.fail("independent local contradiction must refuse before native work")
    monkeypatch.setattr(check, "mechanism_digest", source_unavailable)
    monkeypatch.setattr(check.certificate_dag, "assess_certificate_dependencies", native_forbidden)
    result = check.assess_public_checkability(bundle, request_bytes=canonical_bytes(request),
        disclosure_policy_bytes=None, disclosure_evidence_bytes=None, evaluation_time=100)
    assert result["status"] == "FAIL"
    assert result["polished_artifact"] is False
    assert not calls


def unavailable_confidential_context_selection():
    """Wrapper formatting context only; no valid native or confidential proof."""
    profile = {"obligations": [{"claim_id": "test:unsupported-claim"}]}
    node = {"node_id": "test:node", "object_id": "test:object", "claim_id": "test:unsupported-claim"}
    dependency = {"schema_version": check.certificate_dag.BUNDLE, "profiles": [profile],
        "objects": [{"object_id": "test:object"}], "nodes": [node], "edges": []}
    inventory = check.certificate_dag.artifact_files_digest({})
    policy = {"schema_version": check.certificate_dag.POLICY, "approved_profiles": [digest(canonical_bytes(profile))],
        "required_objects": [{"object_id": "test:object", "profile_digest": digest(canonical_bytes(profile))}],
        "required_roots": ["test:node"], "nodes": [node], "artifact_files_digest": inventory}
    contexts = check.node_contexts(dependency, policy)  # Formatting supplies no admission.
    request = {"schema_version": check.REQUEST, "mechanism_digest": check.mechanism_digest(),
        "dependency_bundle_digest": digest(canonical_bytes(dependency)),
        "dependency_policy_digest": digest(canonical_bytes(policy)), "artifact_inventory_digest": inventory,
        "required_nodes": [{"node_id": "test:node", "mode": check.CONFIDENTIAL,
            "context_digest": digest(canonical_bytes(contexts["test:node"])),
            "proof_protocol_id": "test:uninstalled-protocol", "proof_statement_digest": digest(b"not a proof")}],
        "disclosure_policy_terms_digest": digest(b"independently selected terms"),
        "disclosure": {"actor_id": "test:operator", "observer_id": "PUBLIC", "purpose": "PUBLIC_CHECKABILITY"}}
    bundle = canonical_bytes({"schema_version": check.BUNDLE,
        "dependency_bundle_base64": encoded(canonical_bytes(dependency)),
        "dependency_policy_base64": encoded(canonical_bytes(policy)), "artifact_files": []})
    return bundle, canonical_bytes(request)


@pytest.mark.parametrize("present", ["malformed-policy", "malformed-evidence"])
def test_present_disclosure_grammar_refutation_precedes_missing_companion(monkeypatch, present):
    bundle, request = unavailable_confidential_context_selection()
    def forbidden(*args, **kwargs):
        pytest.fail("missing disclosure companion must fence authentication/native callbacks")
    monkeypatch.setattr(check.public_consent, "evaluate_public_consent", forbidden)
    monkeypatch.setattr(check.certificate_dag, "assess_certificate_dependencies", forbidden)
    policy = canonical_bytes({}) if present == "malformed-policy" else None
    evidence = canonical_bytes({"grants": "not a plain list", "revocation": None}) if present == "malformed-evidence" else None
    result = check.assess_public_checkability(bundle, request_bytes=request,
        disclosure_policy_bytes=policy, disclosure_evidence_bytes=evidence, evaluation_time=100)
    assert result["status"] == "FAIL"
    assert result["polished_artifact"] is False


def local_disclosure_policy():
    """Wrapper-shape record only, not an authenticated or admissible policy fixture."""
    return {"schema_version": "verifier-consent-public-policy-1",
        "mechanism_digest": digest(b"test:unverified configured consent mechanism"),
        "policy_id": "test:unverified-policy", "grantor_id": "test:unverified-grantor",
        "keys": [], "root_key_ids": [], "revocation_key_ids": [], "artifact_bindings": [],
        "max_revocation_age_seconds": 60, "minimum_revocation_as_of": 0, "max_chain_length": 4}


@pytest.mark.parametrize("contradiction", ["terms", "subject"])
def test_selected_disclosure_pin_refutation_precedes_missing_evidence_and_source(monkeypatch, contradiction):
    bundle, request_bytes = unavailable_confidential_context_selection()
    request = json.loads(request_bytes)
    policy = local_disclosure_policy()
    terms = check.disclosure_policy_terms_digest(policy)
    request["disclosure_policy_terms_digest"] = terms if contradiction == "subject" else digest(b"different independently selected terms")
    request_bytes = canonical_bytes(request)
    subject = digest(canonical_bytes(check.disclosure_subject(request_bytes)))[7:]
    policy["artifact_bindings"] = [["OBJECT", subject if contradiction == "terms" else digest(b"another subject")[7:]]]
    calls = []
    def source_unavailable():
        calls.append("source")
        raise OSError("test source unavailable")
    def forbidden(*args, **kwargs):
        pytest.fail("local policy pin refusal must precede authentication/native callbacks")
    monkeypatch.setattr(check, "mechanism_digest", source_unavailable)
    monkeypatch.setattr(check.public_consent, "evaluate_public_consent", forbidden)
    monkeypatch.setattr(check.certificate_dag, "assess_certificate_dependencies", forbidden)
    result = check.assess_public_checkability(bundle, request_bytes=request_bytes,
        disclosure_policy_bytes=canonical_bytes(policy), disclosure_evidence_bytes=None, evaluation_time=100)
    assert result["status"] == "FAIL" and result["disclosure_status"] == "UNKNOWN"
    assert not calls


@pytest.mark.parametrize("capacity_error", [OSError, RecursionError, OverflowError])
def test_source_unavailable_without_local_refutation_stays_unknown(monkeypatch, capacity_error):
    bundle, request = unavailable_confidential_context_selection()
    calls = []
    def unavailable():
        calls.append("source")
        raise capacity_error("test source unavailable")
    def forbidden(*args, **kwargs):
        pytest.fail("source unavailability must fence authentication/native callbacks")
    monkeypatch.setattr(check, "mechanism_digest", unavailable)
    monkeypatch.setattr(check.public_consent, "evaluate_public_consent", forbidden)
    monkeypatch.setattr(check.certificate_dag, "assess_certificate_dependencies", forbidden)
    result = check.assess_public_checkability(bundle, request_bytes=request,
        disclosure_policy_bytes=None, disclosure_evidence_bytes=None, evaluation_time=100)
    assert result["status"] == "UNKNOWN" and result["disclosure_status"] == "UNKNOWN"
    assert result["polished_artifact"] is False and calls == ["source"]


def test_missing_disclosure_without_known_local_refutation_stays_unknown(monkeypatch):
    bundle, request = unavailable_confidential_context_selection()
    def forbidden(*args, **kwargs):
        pytest.fail("missing disclosure must fence authentication/native callbacks")
    monkeypatch.setattr(check.public_consent, "evaluate_public_consent", forbidden)
    monkeypatch.setattr(check.certificate_dag, "assess_certificate_dependencies", forbidden)
    result = check.assess_public_checkability(bundle, request_bytes=request,
        disclosure_policy_bytes=None, disclosure_evidence_bytes=None, evaluation_time=100)
    assert result["status"] == "UNKNOWN" and result["disclosure_status"] == "UNKNOWN"
    assert result["polished_artifact"] is False


def test_wrong_fixed_ledger_claim_boundary_refuses_before_storage(monkeypatch, tmp_path):
    selected = ledger.IssuerLedgerSelection(str(tmp_path / "never-created.sqlite"), "test:ledger", "test:domain", 1)
    proposal = canonical_bytes({"schema_version": "test:untrusted-proposal"})
    carried = {"schema_version": ledger.RECEIPT, "status": "PASS", "polished": False,
        "invocation_consumption": "CONSUMED_EXACT_LOCAL_LEDGER", "ledger_id": selected.ledger_id,
        "policy_domain": selected.policy_domain, "policy_epoch": selected.policy_epoch,
        "invocation_id": "test:untrusted-invocation", "commit_sequence": 1,
        "proposal_digest": digest(proposal), "authority_status_digest": digest(b"untrusted status label"),
        "commit_time": 100, "mechanism_digest": digest(b"untrusted current source label"),
        "public_consumption_authentication": "NOT_ESTABLISHED",
        "claim_boundary": "WORLDWIDE_UNIQUENESS_ESTABLISHED"}
    carried["receipt_digest"] = digest(canonical_bytes(carried))
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(True)
        raise OSError("test storage unavailable")
    monkeypatch.setattr(ledger, "_connect", unavailable)
    result = ledger.recheck_issuance_commit(canonical_bytes(carried), proposal_bytes=proposal,
        expected_proposal_digest=digest(proposal), selection=selected)
    assert result["status"] == "FAIL" and result["replay_status"] == "REJECTED"
    assert not calls
    assert not (tmp_path / "never-created.sqlite").exists()
