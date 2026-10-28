"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

exact finite OBJECT-1.1 record issuance mechanics.

This separate finite wire never issues the existing polished-artifact claim.
Every result keeps polished=False and full_application_status=UNKNOWN. No
transport, publication, human acceptance or production promotion is performed.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.core.signature_keys import admit_ed25519_public_key
from verifier.domains.contracts import certificate_dag as codec, object_facets
from verifier.runtime import polish_public_authority as authority
from verifier.runtime import polish_invocation_ledger as ledger
from verifier.runtime import public_checkability as public

BUNDLE = "verifier-finite-record-issuance-bundle-1"
REQUEST = "verifier-finite-record-issuance-request-1"
POLICY = "verifier-finite-record-issuer-policy-1"
SUBJECT = "verifier-finite-record-issuance-subject-1"
ASSESSMENT = "verifier-finite-record-issuance-assessment-1"
PROPOSAL = "verifier-finite-record-precommit-proposal-1"
ISSUED = "verifier-finite-record-issued-attestation-1"
REPLAY = "verifier-finite-record-issuance-replay-1"
COMMIT_PAYLOAD = "verifier-finite-record-public-commit-1"
COMMIT_ENVELOPE = "verifier-finite-record-public-commit-envelope-1"
COMMIT_OPERATION = "ATTEST_FINITE_OBJECT_RECORD_COMMIT"
COMMIT_PREFIX = b"vstd-finite-object-record-commit-ed25519-1\0"
FINITE = "FINITE_OBJECT_1_1_RECORD"
FULL = "FULL_APPLICATION"
SCOPE = "exact-single-generic-object-record-and-address-1"
MAX_BYTES = 1024**2
MAX_BUNDLE_BYTES = 8 * MAX_BYTES
DOCUMENTS = {"source_scope", "native_bundle", "native_policy", "public_bundle",
             "public_request", "disclosure_policy", "disclosure_evidence"}
ACTION = {"operation", "application_id", "profile_digest", "source_scope_digest",
          "collection_digest", "actor_id", "observer_id", "purpose", "jurisdiction",
          "timestamp", "invocation_id", "ledger_id", "policy_domain", "policy_epoch"}
BOUNDARY = ("Exact finite OBJECT-1.1 record/address, configured-key authorization and one "
            "local atomic invocation only. Full application, all 234 slots, semantic families, "
            "applicability, consumer census, human acceptance and production polish remain UNKNOWN.")


class Unavailable(RuntimeError):
    """Exact required evidence or a fixed installed mechanism is unavailable."""


@dataclass(frozen=True)
class FiniteIssuerHostSelection:
    """Authenticated operator selection, never decoded from a candidate bundle."""
    policy_bytes: bytes
    expected_policy_digest: str
    authority_policy_bytes: bytes
    expected_authority_policy_digest: str
    ledger_selection: ledger.IssuerLedgerSelection


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _bytes(raw: Any, cap: int = MAX_BYTES) -> bytes:
    if raw is None:
        raise Unavailable("required exact finite transport absent")
    if type(raw) is not bytes:
        raise ValueError("plain immutable finite transport required")
    if len(raw) > cap:
        raise Unavailable("finite transport bound exhausted")
    return raw


def _load(raw: bytes, cap: int = MAX_BYTES) -> dict:
    return codec._parse(_bytes(raw, cap))


def _decode(value: Any) -> bytes:
    if type(value) is not str:
        raise ValueError("plain canonical base64 required")
    if len(value) > 4 * ((MAX_BYTES + 2) // 3):
        raise Unavailable("encoded finite document capacity")
    raw = base64.b64decode(value, validate=True)
    if len(raw) > MAX_BYTES:
        raise Unavailable("decoded finite document capacity")
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("canonical base64 required")
    return raw


def mechanism_digest() -> str:
    root = Path(__file__).parents[1]
    paths = ("runtime/finite_record_issuance.py", "standard/FINITE_RECORD_ISSUANCE.md",
             "domains/contracts/certificate_dag.py", "core/namespace.py",
             "core/certificate.py", "core/receipt.py", "core/signature_keys.py")
    return _digest(canonical_bytes({"sources": {p: _digest((root / p).read_bytes()) for p in paths},
        "native": object_facets.mechanism_digest(), "authority": authority.mechanism_digest(),
        "public": public.mechanism_digest(), "ledger": ledger.mechanism_digest(),
        "signature_backend": "cryptography-50.0.0"}))


def _report(schema: str, status: str = "UNKNOWN", **fields: Any) -> dict:
    return {"schema_version": schema, "status": status, "polished": False,
        "full_application_status": "UNKNOWN", "objective_inventory_closure": "NOT_ESTABLISHED",
        "human_acceptance": "NOT_ESTABLISHED", "promotion": "NOT_PERFORMED",
        "publication": "NOT_PERFORMED", "claim_boundary": BOUNDARY, **fields}


def _finish(report: dict) -> dict:
    try:
        encoded = canonical_bytes(report)
        # Reserve the final digest field on ALL paths, including errors.
        if len(encoded) + 96 > MAX_BYTES:
            report = _report(report["schema_version"], "FAIL" if report["status"] == "FAIL" else "UNKNOWN",
                reason="FINITE_OUTPUT_CAPACITY_EXHAUSTED", replayable=False)
            if report["schema_version"] == REPLAY:
                report["replay_status"] = "REJECTED" if report["status"] == "FAIL" else "UNAVAILABLE"
            encoded = canonical_bytes(report)
        report["assessment_digest"] = _digest(encoded)
        return report
    except (codec._Exhausted, RecursionError, OverflowError, asyncio.CancelledError):
        # Fixed plain diagnostic still retains known FAIL if output work itself
        # is cancelled. No digest/reproduction is invented when formatting fails.
        diagnostic = _report(report["schema_version"], "FAIL" if report["status"] == "FAIL" else "UNKNOWN",
            reason="FINITE_OUTPUT_UNAVAILABLE", replayable=False)
        if diagnostic["schema_version"] == REPLAY:
            diagnostic["replay_status"] = "REJECTED" if diagnostic["status"] == "FAIL" else "UNAVAILABLE"
        return diagnostic


def _capture(bundle_bytes: bytes, request_bytes: bytes, evidence_bytes: bytes | None,
             host: FiniteIssuerHostSelection | None) -> tuple[dict, dict, dict, dict]:
    # Admit every externally supplied transport before decode/hash/source callbacks.
    _bytes(bundle_bytes, MAX_BUNDLE_BYTES)
    _bytes(request_bytes)
    if evidence_bytes is not None:
        _bytes(evidence_bytes)
    if host is not None:
        if type(host) is not FiniteIssuerHostSelection:
            raise ValueError("native fixed host selection required")
        _bytes(host.policy_bytes)
        _bytes(host.authority_policy_bytes)
    bundle = codec._record(_load(bundle_bytes, MAX_BUNDLE_BYTES), {"schema_version", "documents", "artifact_files"})
    request = codec._record(_load(request_bytes), {"schema_version", "mode", "bundle_digest", "host_policy_digest", "action"})
    if bundle["schema_version"] != BUNDLE or request["schema_version"] != REQUEST:
        raise ValueError("finite issuance contract differs")
    if request["mode"] not in (FINITE, FULL):
        raise ValueError("unsupported issuance mode")
    action = codec._record(request["action"], ACTION)
    for name, value in action.items():
        if name in ("timestamp", "policy_epoch"):
            if authority._time(value) < (1 if name == "policy_epoch" else 0):
                raise ValueError("positive policy epoch required")
        else:
            (codec._hash if name.endswith("_digest") else codec._text)(value)
    if action["operation"] != authority.FINITE_OPERATION:
        raise ValueError("exact authority operation required")
    if type(bundle["documents"]) is not list or len(bundle["documents"]) != len(DOCUMENTS):
        raise ValueError("closed finite documents required")
    docs, previous = {}, ""
    for row in bundle["documents"]:
        codec._record(row, {"name", "base64"})
        name = codec._text(row["name"])
        if name not in DOCUMENTS or name <= previous:
            raise ValueError("sorted exact document denominator required")
        docs[name], previous = _decode(row["base64"]), name
    if set(docs) != DOCUMENTS:
        raise ValueError("finite document omitted")
    if type(bundle["artifact_files"]) is not list or len(bundle["artifact_files"]) != 1:
        raise ValueError("exact one retained public certificate required")
    row = codec._record(bundle["artifact_files"][0], {"path", "base64"})
    files = {codec._path(row["path"]): _decode(row["base64"])}
    # All embedded decoded-byte bounds precede the first candidate digest.
    if codec._hash(request["bundle_digest"]) != _digest(bundle_bytes):
        raise ValueError("exact candidate bundle selection differs")
    codec._hash(request["host_policy_digest"])
    return bundle, request, docs, files


def _host(host: FiniteIssuerHostSelection | None, request: dict, docs: dict, files: dict) -> dict | None:
    if host is None:
        return None  # Independent declared contradictions can still be screened.
    selected, _ = ledger._selection(host.ledger_selection)  # No database open.
    policy = codec._record(_load(host.policy_bytes), {"schema_version", "mode", "mechanism_digest",
        "source_commitments", "input_digests", "artifact_inventory_digest", "action", "postcommit_key_id"})
    if (policy["schema_version"] != POLICY or policy["mode"] != request["mode"]
            or codec._hash(host.expected_policy_digest) != _digest(host.policy_bytes)
            or request["host_policy_digest"] != host.expected_policy_digest
            or codec._hash(host.expected_authority_policy_digest) != _digest(host.authority_policy_bytes)):
        raise ValueError("independent exact operator policy selection differs")
    if policy["action"] != request["action"]:
        raise ValueError("exact operator action scope differs")
    action = request["action"]
    if any(action[name] != getattr(selected, name) for name in ("ledger_id", "policy_domain", "policy_epoch")):
        raise ValueError("configured ledger identity or policy generation differs")
    pins = codec._record(policy["input_digests"], DOCUMENTS)
    if any(codec._hash(pins[name]) != _digest(raw) for name, raw in docs.items()):
        raise ValueError("independently selected finite input differs")
    if codec._hash(policy["artifact_inventory_digest"]) != codec.artifact_files_digest(files):
        raise ValueError("complete certificate byte inventory differs")
    source = codec._record(policy["source_commitments"], {"source_tree_digest", "wheel_digest", "namespace_digest"})
    for pin in source.values():
        codec._hash(pin)
    codec._text(policy["postcommit_key_id"])
    codec._hash(policy["mechanism_digest"])  # No source read or positive admission.
    declared_authority = authority._policy(host.authority_policy_bytes, check_mechanism=False)
    if ({name: action[name] for name in authority._SCOPE_FIELDS} not in declared_authority["scopes"]
            or not declared_authority["effective_from"] <= action["timestamp"] < declared_authority["effective_until"]
            or policy["postcommit_key_id"] != declared_authority["status_key_id"]):
        raise ValueError("declared finite authority scope/time/status role differs")
    return policy


def _denominator(request: dict, docs: dict, files: dict) -> tuple[dict, dict, dict]:
    if request["mode"] == FULL:
        raise Unavailable("FULL_APPLICATION_SEMANTIC_APPLICABILITY_CONSUMER_PUBLIC_CLOSURE_UNAVAILABLE")
    native = codec._record(_load(docs["native_bundle"]), {"schema_version", "profiles", "objects", "nodes", "edges"})
    policy = codec._record(_load(docs["native_policy"]), {"schema_version", "approved_profiles", "required_objects", "required_roots", "nodes", "artifact_files_digest"})
    if any(type(native[name]) is not list or len(native[name]) != 1 for name in ("profiles", "objects", "nodes")) or native["edges"] != []:
        raise ValueError("exact one-object one-claim finite denominator required")
    profile = native["profiles"][0]
    codec._record(profile, {"schema_version", "profile_id", "profile_version", "object_kind", "obligations"})
    if profile["object_kind"] != "OBJECT" or type(profile["obligations"]) is not list or len(profile["obligations"]) != 1:
        raise ValueError("exact generic OBJECT profile required")
    claim = codec._record(profile["obligations"][0], {"claim_id", "semantic_version", "objective", "proposition_digest", "scope", "assumptions", "dependencies"})
    if claim["semantic_version"] != object_facets.SEMANTIC_VERSION or claim["objective"] != object_facets.COORDINATE:
        raise Unavailable("native/public adapter outside exact finite OBJECT-1.1 capability")
    if (claim["proposition_digest"] != object_facets.PROPOSITION_DIGEST
            or claim["scope"] != object_facets.REGISTRATION["scope"]
            or claim["assumptions"] != [] or claim["dependencies"] != []):
        raise ValueError("finite scope cannot promote another proposition or requirement")
    record = codec._record(native["objects"][0], {"object_id", "kind", "payload", "operands"})
    if record["kind"] != "OBJECT" or record["operands"] != {}:
        raise ValueError("finite scope excludes operands and typed subject obligations")
    item = NamespaceObject.create(record["object_id"], record["kind"], record["payload"], record["operands"])
    node = native["nodes"][0]
    if (node["object_id"] != item.object_id or node["claim_id"] != claim["claim_id"]
            or policy["approved_profiles"] != [_digest(canonical_bytes(profile))]
            or policy["required_objects"] != [{"object_id": item.object_id, "object_kind": "OBJECT",
                "record_digest": item.digest, "profile_digest": _digest(canonical_bytes(profile))}]
            or policy["required_roots"] != [node["node_id"]] or policy["nodes"] != native["nodes"]
            or set(files) != {node["certificate_path"]}
            or node["artifact_bindings"] != [{"path": node["certificate_path"], "digest": node["certificate_digest"]}]
            or _digest(files[node["certificate_path"]]) != node["certificate_digest"]):
        raise ValueError("exact retained claim/certificate denominator differs")
    action = request["action"]
    if (action["profile_digest"] != _digest(canonical_bytes(profile))
            or action["source_scope_digest"] != _digest(docs["source_scope"])
            or action["collection_digest"] != composition_digest([item])):
        raise ValueError("exact profile/source/collection authority scope differs")
    carried = codec._record(_load(docs["public_bundle"]), {"schema_version", "dependency_bundle_base64", "dependency_policy_base64", "artifact_files"})
    if (_decode(carried["dependency_bundle_base64"]) != docs["native_bundle"]
            or _decode(carried["dependency_policy_base64"]) != docs["native_policy"]
            or carried["artifact_files"] != [{"path": p, "base64": base64.b64encode(raw).decode("ascii")} for p, raw in sorted(files.items())]):
        raise ValueError("public replay must consume SAME full certificate and native inputs")
    public_request = _load(docs["public_request"])
    required = public_request["required_nodes"]
    if type(required) is not list or len(required) != 1 or required[0]["node_id"] != node["node_id"]:
        raise ValueError("public node denominator differs")
    if required[0]["mode"] != public.PUBLIC:
        raise Unavailable("named confidential proof or public adapter unavailable")
    return native, policy, node


def assess_finite_record_issuance(bundle_bytes: bytes, *, request_bytes: bytes,
        issue_evidence_bytes: bytes | None, host_selection: FiniteIssuerHostSelection | None,
        evaluation_time: int | None) -> dict:
    report = _report(ASSESSMENT, replayable=False, finite_scope=SCOPE)
    failures, unknown = [], []
    try:
        if evaluation_time is not None:
            authority._time(evaluation_time)
        _, request, docs, files = _capture(bundle_bytes, request_bytes, issue_evidence_bytes, host_selection)
        report["input_digests"] = {"bundle": _digest(bundle_bytes), "request": _digest(request_bytes),
            "issue_evidence": None if issue_evidence_bytes is None else _digest(issue_evidence_bytes)}
        report["evaluation_time"] = evaluation_time
        host = _host(host_selection, request, docs, files)
        # Fixed denominator is checked before native/public outcomes. It is never
        # inferred from a successful replay or the route catalogue.
        _denominator(request, docs, files)
        if evaluation_time is None:
            unknown.append("TRUSTED_CLOCK_UNAVAILABLE")
        elif request["action"]["timestamp"] != evaluation_time:
            failures.append("EXACT_ACTION_CLOCK_MISMATCH")
        if host is None:
            raise Unavailable("authenticated operator host selection absent")
        if host["mechanism_digest"] != mechanism_digest():
            raise ValueError("independently admitted installed finite mechanism differs")
        report.update(mechanism_digest=host["mechanism_digest"], replayable=True)
        native = codec.assess_certificate_dependencies(docs["native_bundle"], expected_policy_bytes=docs["native_policy"], artifact_files=files)
        report["native_assessment_digest"] = native["assessment_digest"]
        if native["status"] == "FAIL":
            failures.append("NATIVE_RECORD_REFUTED")
        elif native["status"] != "PASS":
            unknown.append("NATIVE_RECORD_UNAVAILABLE")
        checked = public.assess_public_checkability(docs["public_bundle"], request_bytes=docs["public_request"],
            disclosure_policy_bytes=docs["disclosure_policy"], disclosure_evidence_bytes=docs["disclosure_evidence"], evaluation_time=evaluation_time)
        replay = public.recheck_public_checkability(canonical_bytes(checked), docs["public_bundle"], request_bytes=docs["public_request"],
            disclosure_policy_bytes=docs["disclosure_policy"], disclosure_evidence_bytes=docs["disclosure_evidence"], evaluation_time=evaluation_time)
        report["public_assessment_digest"] = checked["assessment_digest"]
        if checked["status"] == "FAIL" or replay["status"] == "FAIL":
            failures.append("PUBLIC_RECORD_REFUTED")
        elif checked["status"] != "PASS" or replay["status"] != "REPRODUCED" or replay["public_checkability_status"] != "PASS":
            unknown.append("PUBLIC_RECORD_UNAVAILABLE")
        if not failures and not unknown:
            action = request["action"]
            # Votes and status signatures are external to bundle/request/subject.
            subject = {"schema_version": SUBJECT, **action, "finite_scope": SCOPE,
                "full_application_status": "UNKNOWN", "polished": False,
                "bundle_digest": _digest(bundle_bytes), "request_digest": _digest(request_bytes),
                "host_policy_digest": host_selection.expected_policy_digest,
                "authority_policy_digest": host_selection.expected_authority_policy_digest,
                "source_commitments": host["source_commitments"], "mechanism_digest": host["mechanism_digest"],
                "native_assessment_digest": native["assessment_digest"], "public_assessment_digest": checked["assessment_digest"]}
            context = {"schema_version": authority.CONTEXT, "mechanism_digest": authority.mechanism_digest(),
                "subject_digest": _digest(canonical_bytes(subject)), "policy_digest": host_selection.expected_authority_policy_digest, **action}
            report.update(subject=subject, authority_context=context)
            admitted = authority.assess_polish_authority(canonical_bytes(subject), context_bytes=canonical_bytes(context),
                evidence_bytes=issue_evidence_bytes, trusted_policy_bytes=host_selection.authority_policy_bytes,
                expected_trusted_policy_digest=host_selection.expected_authority_policy_digest, evaluation_time=evaluation_time)
            report["authority_assessment_digest"] = admitted.get("assessment_digest")
            if admitted["status"] == "FAIL":
                failures.append("CONFIGURED_AUTHORITY_REFUSED")
                if admitted.get("replayable") is not True:
                    report["replayable"] = False
            elif admitted.get("replayable") is not True:
                unknown.append("CONFIGURED_AUTHORITY_UNAVAILABLE")
                report["replayable"] = False
            else:
                replay = authority.recheck_polish_authority(canonical_bytes(admitted), subject_bytes=canonical_bytes(subject), context_bytes=canonical_bytes(context),
                    evidence_bytes=issue_evidence_bytes, trusted_policy_bytes=host_selection.authority_policy_bytes,
                    expected_trusted_policy_digest=host_selection.expected_authority_policy_digest, evaluation_time=evaluation_time)
                if replay["status"] == "FAIL":
                    failures.append("CONFIGURED_AUTHORITY_REFUSED")
                elif admitted["status"] != "PASS" or replay["status"] != "PASS" or replay["replay_status"] != "REPRODUCED":
                    unknown.append("CONFIGURED_AUTHORITY_UNAVAILABLE")
                else:
                    evidence = _load(issue_evidence_bytes)
                    report["authority_status_digest"] = _digest(canonical_bytes(evidence["status"]))
                    report["finite_issuance_state"] = "READY_FOR_LOCAL_ATOMIC_COMMIT"
    except (Unavailable, codec._Exhausted, RecursionError, OverflowError, OSError, ImportError, asyncio.CancelledError):
        unknown.append("FINITE_INPUT_OR_MECHANISM_UNAVAILABLE")
        report["replayable"] = False
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
        failures.append("FINITE_CONTRACT_OR_SELECTION_REFUSED")
    report.update(status="FAIL" if failures else "UNKNOWN" if unknown else "PASS", checks=sorted(set(failures + unknown)))
    return _finish(report)


def finite_precommit_proposal(assessment: dict) -> bytes:
    """Format exact precommit bytes. This helper admits no stored PASS."""
    result = canonical_bytes({"schema_version": PROPOSAL, "assessment": assessment})
    _bytes(result, ledger.MAX_PROPOSAL_BYTES)
    return result


def _ready(stored: dict, host_selection: FiniteIssuerHostSelection | None = None) -> None:
    """Closed retained proposal validation before source/backend admission."""
    base = _report(ASSESSMENT)
    fields = set(base) | {"replayable", "finite_scope", "input_digests", "evaluation_time",
        "mechanism_digest", "native_assessment_digest", "public_assessment_digest", "subject",
        "authority_context", "authority_assessment_digest", "authority_status_digest",
        "finite_issuance_state", "checks", "assessment_digest"}
    codec._record(stored, fields)
    if (stored["status"] != "PASS" or stored["replayable"] is not True or stored["finite_scope"] != SCOPE
            or stored["finite_issuance_state"] != "READY_FOR_LOCAL_ATOMIC_COMMIT" or stored["checks"] != []
            or any(stored[name] != value for name, value in base.items() if name != "status")
            or codec._hash(stored["assessment_digest"]) != _digest(canonical_bytes(
                {k: v for k, v in stored.items() if k != "assessment_digest"}))):
        raise ValueError("retained ready proposal or claim boundary differs")
    authority._time(stored["evaluation_time"])
    pins = codec._record(stored["input_digests"], {"bundle", "request", "issue_evidence"})
    for pin in pins.values():
        codec._hash(pin)
    for name in ("mechanism_digest", "native_assessment_digest", "public_assessment_digest",
                 "authority_assessment_digest", "authority_status_digest"):
        codec._hash(stored[name])
    codec._record(stored["authority_context"], authority._CONTEXT_FIELDS)
    subject = codec._record(stored["subject"], ACTION | {"schema_version", "finite_scope", "full_application_status", "polished",
        "bundle_digest", "request_digest", "host_policy_digest", "authority_policy_digest", "source_commitments",
        "mechanism_digest", "native_assessment_digest", "public_assessment_digest"})
    for name in ACTION:
        if name in ("timestamp", "policy_epoch"):
            if authority._time(subject[name]) < (1 if name == "policy_epoch" else 0):
                raise ValueError("plain retained action time/positive epoch required")
        else:
            (codec._hash if name.endswith("_digest") else codec._text)(subject[name])
    for name in ("host_policy_digest", "authority_policy_digest"):
        codec._hash(subject[name])
    source = codec._record(subject["source_commitments"], {"source_tree_digest", "wheel_digest", "namespace_digest"})
    for pin in source.values():
        codec._hash(pin)
    context = stored["authority_context"]
    for name, value in context.items():
        if name in ("timestamp", "policy_epoch"):
            if authority._time(value) < (1 if name == "policy_epoch" else 0):
                raise ValueError("plain retained context time/positive epoch required")
        else:
            (codec._hash if name.endswith("_digest") else codec._text)(value)
    if (subject["schema_version"] != SUBJECT or subject["finite_scope"] != SCOPE
            or subject["polished"] is not False or subject["full_application_status"] != "UNKNOWN"
            or subject["operation"] != authority.FINITE_OPERATION
            or subject["bundle_digest"] != pins["bundle"] or subject["request_digest"] != pins["request"]
            or subject["timestamp"] != stored["evaluation_time"]
            or any(subject[name] != stored[name] for name in
                ("mechanism_digest", "native_assessment_digest", "public_assessment_digest"))
            or context["schema_version"] != authority.CONTEXT
            or any(context[name] != subject[name] for name in ACTION)
            or context["policy_digest"] != subject["authority_policy_digest"]
            or context["subject_digest"] != _digest(canonical_bytes(subject))):
        raise ValueError("retained finite subject binding differs")
    if host_selection is not None:
        if (subject["host_policy_digest"] != host_selection.expected_policy_digest
                or subject["authority_policy_digest"] != host_selection.expected_authority_policy_digest
                or _digest(host_selection.policy_bytes) != subject["host_policy_digest"]
                or _digest(host_selection.authority_policy_bytes) != subject["authority_policy_digest"]):
            raise ValueError("retained finite independently selected policy differs")
        declared = authority._policy(host_selection.authority_policy_bytes, check_mechanism=False)
        if context["mechanism_digest"] != codec._hash(declared["mechanism_digest"]):
            raise ValueError("retained authority context/policy mechanism differs")
        if ({name: subject[name] for name in authority._SCOPE_FIELDS} not in declared["scopes"]
                or not declared["effective_from"] <= subject["timestamp"] < declared["effective_until"]):
            raise ValueError("retained declared authority scope/time differs")
        finite_policy = codec._record(_load(host_selection.policy_bytes), {"schema_version", "mode", "mechanism_digest",
            "source_commitments", "input_digests", "artifact_inventory_digest", "action", "postcommit_key_id"})
        for pin in codec._record(finite_policy["input_digests"], DOCUMENTS).values():
            codec._hash(pin)
        codec._hash(finite_policy["artifact_inventory_digest"])
        codec._text(finite_policy["postcommit_key_id"])
        if (finite_policy["schema_version"] != POLICY or finite_policy["mode"] != FINITE
                or finite_policy["postcommit_key_id"] != declared["status_key_id"]
                or stored["mechanism_digest"] != codec._hash(finite_policy["mechanism_digest"])
                or subject["source_commitments"] != finite_policy["source_commitments"]
                or {name: subject[name] for name in ACTION} != finite_policy["action"]):
            raise ValueError("retained subject/operator action or source mechanism differs")
        selected, _ = ledger._selection(host_selection.ledger_selection)  # No source/database access.
        if any(subject[name] != getattr(selected, name) for name in ("ledger_id", "policy_domain", "policy_epoch")):
            raise ValueError("retained action/current selected ledger generation differs")


def _retained_receipt(raw: bytes, proposal_bytes: bytes, stored: dict) -> dict:
    """Pure bounded SAME-receipt/action guards, granting no commit admission."""
    receipt = codec._record(_load(raw, ledger.MAX_RECEIPT_BYTES), {"schema_version", "status", "polished",
        "invocation_consumption", "ledger_id", "policy_domain", "policy_epoch", "invocation_id", "commit_sequence",
        "proposal_digest", "authority_status_digest", "commit_time", "mechanism_digest",
        "public_consumption_authentication", "claim_boundary", "receipt_digest"})
    for name in ("ledger_id", "policy_domain", "invocation_id", "claim_boundary"):
        codec._text(receipt[name])
    for name in ("proposal_digest", "authority_status_digest", "mechanism_digest", "receipt_digest"):
        codec._hash(receipt[name])
    for name in ("policy_epoch", "commit_sequence", "commit_time"):
        if authority._time(receipt[name]) < (0 if name == "commit_time" else 1):
            raise ValueError("positive plain receipt sequence/epoch required")
    if (receipt["schema_version"] != ledger.RECEIPT or receipt["status"] != "PASS" or receipt["polished"] is not False
            or receipt["invocation_consumption"] != "CONSUMED_EXACT_LOCAL_LEDGER"
            or receipt["public_consumption_authentication"] != "NOT_ESTABLISHED"
            or receipt["claim_boundary"] != ledger._CLAIM_BOUNDARY
            or receipt["proposal_digest"] != _digest(proposal_bytes)
            or receipt["authority_status_digest"] != stored["authority_status_digest"]
            or any(receipt[name] != stored["subject"][name] for name in
                ("invocation_id", "ledger_id", "policy_domain", "policy_epoch"))
            or receipt["commit_time"] != stored["evaluation_time"]
            or receipt["commit_time"] != stored["subject"]["timestamp"]
            or receipt["receipt_digest"] != _digest(canonical_bytes({k: v for k, v in receipt.items() if k != "receipt_digest"}))):
        raise ValueError("retained receipt differs from exact authorized action")
    return receipt


def commit_finite_record_issuance(proposal_bytes: bytes, *, bundle_bytes: bytes, request_bytes: bytes,
        issue_evidence_bytes: bytes, host_selection: FiniteIssuerHostSelection, commit_time: int) -> dict:
    report = _report("verifier-finite-record-local-commit-result-1")
    try:
        authority._time(commit_time)
        _bytes(proposal_bytes, ledger.MAX_PROPOSAL_BYTES)
        for raw, cap in ((bundle_bytes, MAX_BUNDLE_BYTES), (request_bytes, MAX_BYTES), (issue_evidence_bytes, MAX_BYTES)):
            if raw is not None:
                _bytes(raw, cap)
        if host_selection is not None:
            if type(host_selection) is not FiniteIssuerHostSelection:
                raise ValueError("exact fixed finite host selection required")
            _bytes(host_selection.policy_bytes)
            _bytes(host_selection.authority_policy_bytes)
        proposal = codec._record(_load(proposal_bytes, ledger.MAX_PROPOSAL_BYTES), {"schema_version", "assessment"})
        if proposal["schema_version"] != PROPOSAL:
            raise ValueError("finite proposal contract differs")
        _ready(proposal["assessment"], host_selection)
        for name, raw in (("bundle", bundle_bytes), ("request", request_bytes), ("issue_evidence", issue_evidence_bytes)):
            if raw is not None and _digest(raw) != proposal["assessment"]["input_digests"][name]:
                raise ValueError("known precommit original input differs")
        if commit_time != proposal["assessment"]["evaluation_time"]:
            raise ValueError("exact precommit evaluation clock differs")
        if any(raw is None for raw in (bundle_bytes, request_bytes, issue_evidence_bytes)):
            raise Unavailable("original retained finite commit input absent")
        _capture(bundle_bytes, request_bytes, issue_evidence_bytes, host_selection)
        actual = assess_finite_record_issuance(bundle_bytes, request_bytes=request_bytes,
            issue_evidence_bytes=issue_evidence_bytes, host_selection=host_selection, evaluation_time=commit_time)
        if actual["status"] != "PASS":
            return _finish(_report(report["schema_version"], actual["status"], reason="CURRENT_FINITE_PREREQUISITES_NOT_ADMITTED"))
        if proposal_bytes != finite_precommit_proposal(actual):
            raise ValueError("complete current precommit proposal bytes differ")
        receipt = ledger.commit_issuance(proposal_bytes, expected_proposal_digest=_digest(proposal_bytes),
            invocation_id=actual["subject"]["invocation_id"], authority_status_digest=actual["authority_status_digest"],
            commit_time=commit_time, selection=host_selection.ledger_selection)
        report.update(status=receipt["status"], local_commit=receipt,
            finite_issuance_state="AWAITING_DISTINCT_SIGNED_POSTCOMMIT" if receipt["status"] == "PASS" else "NOT_ESTABLISHED")
    except (Unavailable, codec._Exhausted, OSError, ImportError, RecursionError, OverflowError, asyncio.CancelledError):
        report["reason"] = "LOCAL_FINITE_COMMIT_UNAVAILABLE_OR_UNCERTAIN"
    except (ValueError, TypeError, KeyError, UnicodeError):
        report.update(status="FAIL", reason="LOCAL_FINITE_COMMIT_REFUSED")
    return _finish(report)


def finite_commit_signing_bytes(payload_bytes: bytes, *, key_id: str) -> bytes:
    """Format distinct postcommit signing bytes; no signing key is read."""
    body = {"schema_version": COMMIT_ENVELOPE, "algorithm": "Ed25519", "key_id": codec._text(key_id),
            "payload": _load(payload_bytes), "payload_digest": _digest(payload_bytes)}
    return COMMIT_PREFIX + canonical_bytes(body)


def _postcommit(raw: bytes, actual: dict, proposal_bytes: bytes, receipt: dict,
                host_selection: FiniteIssuerHostSelection, now: int) -> None:
    envelope = codec._record(_load(raw), {"schema_version", "algorithm", "key_id", "payload", "payload_digest", "signature"})
    payload = codec._record(envelope["payload"], {"schema_version", "operation", "subject_digest", "proposal_digest", "receipt_digest",
        "authority_policy_digest", "authority_status_digest", "ledger_id", "policy_domain", "policy_epoch", "invocation_id",
        "commit_sequence", "commit_time", "observed_at", "expires_at", "revoked_subjects"})
    for name, value in payload.items():
        if name in ("policy_epoch", "commit_sequence", "commit_time", "observed_at", "expires_at"):
            if authority._time(value) < (1 if name in ("policy_epoch", "commit_sequence") else 0):
                raise ValueError("positive plain postcommit sequence/generation required")
        elif name.endswith("_digest"):
            codec._hash(value)
        elif name != "revoked_subjects":
            codec._text(value)
    policy = authority._policy(host_selection.authority_policy_bytes, check_mechanism=False)
    selected = _load(host_selection.policy_bytes)
    key_id = codec._text(envelope["key_id"])
    if (envelope["schema_version"] != COMMIT_ENVELOPE or envelope["algorithm"] != "Ed25519"
            or key_id != selected["postcommit_key_id"] or key_id != policy["status_key_id"]
            or payload["schema_version"] != COMMIT_PAYLOAD or payload["operation"] != COMMIT_OPERATION
            or codec._hash(envelope["payload_digest"]) != _digest(canonical_bytes(payload))
            or payload["subject_digest"] != _digest(canonical_bytes(actual["subject"]))
            or payload["proposal_digest"] != _digest(proposal_bytes)
            or payload["receipt_digest"] != receipt["receipt_digest"]
            or payload["authority_policy_digest"] != host_selection.expected_authority_policy_digest
            or payload["authority_status_digest"] != actual["authority_status_digest"]
            or any(payload[name] != receipt[name] for name in ("ledger_id", "policy_domain", "policy_epoch", "invocation_id", "commit_sequence", "commit_time"))):
        raise ValueError("distinct exact postcommit scope differs")
    signature = authority._hex(envelope["signature"], 64)
    start, end = authority._time(payload["observed_at"]), authority._time(payload["expires_at"])
    revoked = authority._names(payload["revoked_subjects"])
    for pin in revoked:
        codec._hash(pin)
    # Known role/domain/scope/interval contradictions precede optional backend.
    if (end <= start or start < receipt["commit_time"] or now < receipt["commit_time"]
            or not policy["effective_from"] <= now < policy["effective_until"]):
        raise ValueError("postcommit policy or observation interval differs")
    stale = not start <= now < end or now - start > policy["max_status_age_seconds"]
    if policy["mechanism_digest"] != authority.mechanism_digest():
        raise ValueError("fresh postcommit authority mechanism differs")
    row = next(row for row in policy["keys"] if row["key_id"] == key_id)
    try:
        import cryptography
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise Unavailable("postcommit signature backend absent") from error
    if getattr(cryptography, "__version__", None) != "50.0.0":
        raise Unavailable("exact postcommit signature backend version absent")
    try:
        Ed25519PublicKey.from_public_bytes(admit_ed25519_public_key(authority._hex(row["public_key"], 32))).verify(signature,
            finite_commit_signing_bytes(canonical_bytes(payload), key_id=key_id))
    except UnsupportedAlgorithm as error:
        raise Unavailable("postcommit signature algorithm unavailable") from error
    except (InvalidSignature, ValueError, TypeError) as error:
        raise ValueError("postcommit signature refused") from error
    if payload["subject_digest"] in revoked:
        raise ValueError("authenticated finite subject revocation")
    if stale:
        raise Unavailable("postcommit signed observation not current")


def finalize_finite_record_issuance(proposal_bytes: bytes, *, receipt_bytes: bytes, public_commit_bytes: bytes | None,
        bundle_bytes: bytes, request_bytes: bytes, issue_evidence_bytes: bytes,
        host_selection: FiniteIssuerHostSelection, evaluation_time: int | None) -> dict:
    report = _report(ISSUED, replayable=False, finite_issuance_state="NOT_ESTABLISHED")
    try:
        # All explicit transports, including host inputs, admitted before hashes.
        _bytes(proposal_bytes, ledger.MAX_PROPOSAL_BYTES)
        for raw, cap in ((receipt_bytes, ledger.MAX_RECEIPT_BYTES), (public_commit_bytes, MAX_BYTES),
                         (bundle_bytes, MAX_BUNDLE_BYTES), (request_bytes, MAX_BYTES), (issue_evidence_bytes, MAX_BYTES)):
            if raw is not None:
                _bytes(raw, cap)
        if host_selection is not None:
            if type(host_selection) is not FiniteIssuerHostSelection:
                raise ValueError("exact fixed finite host selection required")
            _bytes(host_selection.policy_bytes)
            _bytes(host_selection.authority_policy_bytes)
        if evaluation_time is not None:
            authority._time(evaluation_time)
        proposal = codec._record(_load(proposal_bytes, ledger.MAX_PROPOSAL_BYTES), {"schema_version", "assessment"})
        stored = proposal["assessment"]
        if proposal["schema_version"] != PROPOSAL:
            raise ValueError("finite precommit schema differs")
        _ready(stored, host_selection)
        # Known substitutions remain FAIL even when later native/source/backend
        # reconstruction is unavailable. These checks authenticate no execution.
        for name, raw in (("bundle", bundle_bytes), ("request", request_bytes), ("issue_evidence", issue_evidence_bytes)):
            if raw is not None and _digest(raw) != stored["input_digests"][name]:
                raise ValueError("known original finite input differs")
        if host_selection is not None and (stored["subject"]["host_policy_digest"] != host_selection.expected_policy_digest
                or stored["subject"]["authority_policy_digest"] != host_selection.expected_authority_policy_digest):
            raise ValueError("known independent finite policy selection differs")
        if receipt_bytes is not None:
            receipt = _retained_receipt(receipt_bytes, proposal_bytes, stored)
        if any(raw is None for raw in (receipt_bytes, bundle_bytes, request_bytes, issue_evidence_bytes)):
            raise Unavailable("original retained finite commit/input absent")
        _capture(bundle_bytes, request_bytes, issue_evidence_bytes, host_selection)
        historical = authority._time(stored["evaluation_time"])
        actual = assess_finite_record_issuance(bundle_bytes, request_bytes=request_bytes, issue_evidence_bytes=issue_evidence_bytes,
            host_selection=host_selection, evaluation_time=historical)
        if actual["status"] == "FAIL":
            raise ValueError("current exact retained finite prerequisites refuted")
        if actual["status"] != "PASS":
            raise Unavailable("retained finite prerequisite reconstruction unavailable")
        if proposal["schema_version"] != PROPOSAL or finite_precommit_proposal(actual) != proposal_bytes:
            raise ValueError("exact precommit reconstruction differs")
        replay = ledger.recheck_issuance_commit(receipt_bytes, proposal_bytes=proposal_bytes,
            expected_proposal_digest=_digest(proposal_bytes), selection=host_selection.ledger_selection)
        if replay["status"] == "FAIL":
            raise ValueError("SAME committed local invocation refuted")
        if replay["status"] != "PASS" or replay["replay_status"] != "REPRODUCED":
            raise Unavailable("SAME committed local invocation unavailable")
        if public_commit_bytes is None or evaluation_time is None:
            raise Unavailable("distinct signed postcommit or independent current clock absent")
        _postcommit(public_commit_bytes, actual, proposal_bytes, receipt, host_selection, evaluation_time)
        report.update(status="PASS", replayable=True, finite_issuance_state="EXACT_FINITE_RECORD_ISSUED",
            finite_scope=SCOPE, evaluation_time=evaluation_time, historical_evaluation_time=historical,
            subject_digest=_digest(canonical_bytes(actual["subject"])), proposal_digest=_digest(proposal_bytes),
            receipt_digest=_digest(receipt_bytes), public_commit_digest=_digest(public_commit_bytes),
            input_digests={"bundle": _digest(bundle_bytes), "request": _digest(request_bytes), "issue_evidence": _digest(issue_evidence_bytes)},
            host_policy_digest=host_selection.expected_policy_digest, authority_policy_digest=host_selection.expected_authority_policy_digest,
            mechanism_digest=actual["mechanism_digest"], local_replay_digest=_digest(canonical_bytes(replay)))
    except (Unavailable, codec._Exhausted, OSError, ImportError, RecursionError, OverflowError, asyncio.CancelledError):
        report["reason"] = "FINITE_FINALIZATION_UNAVAILABLE"
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
        report.update(status="FAIL", reason="FINITE_FINALIZATION_REFUSED")
    return _finish(report)


def recheck_finite_record_issuance(attestation_bytes: bytes, proposal_bytes: bytes, **external_selection: Any) -> dict:
    """Read-only exact replay; never consumes again or carries a prior PASS."""
    report = _report(REPLAY, "FAIL", replay_status="REJECTED")
    try:
        _bytes(attestation_bytes)
        _bytes(proposal_bytes, ledger.MAX_PROPOSAL_BYTES)
        for name, cap in (("receipt_bytes", ledger.MAX_RECEIPT_BYTES), ("public_commit_bytes", MAX_BYTES),
                          ("bundle_bytes", MAX_BUNDLE_BYTES), ("request_bytes", MAX_BYTES), ("issue_evidence_bytes", MAX_BYTES)):
            raw = external_selection[name]
            if raw is not None:
                _bytes(raw, cap)
        host = external_selection["host_selection"]
        if host is not None:
            if type(host) is not FiniteIssuerHostSelection:
                raise ValueError("exact fixed finite host selection required")
            _bytes(host.policy_bytes)
            _bytes(host.authority_policy_bytes)
        stored = codec._record(_load(attestation_bytes), set(_report(ISSUED)) | {
            "replayable", "finite_issuance_state", "finite_scope", "evaluation_time", "historical_evaluation_time",
            "subject_digest", "proposal_digest", "receipt_digest", "public_commit_digest", "input_digests",
            "host_policy_digest", "authority_policy_digest", "mechanism_digest", "local_replay_digest", "assessment_digest"})
        if (stored["schema_version"] != ISSUED or stored["status"] != "PASS" or stored["polished"] is not False
                or stored["full_application_status"] != "UNKNOWN" or stored["finite_scope"] != SCOPE
                or stored["replayable"] is not True or stored["finite_issuance_state"] != "EXACT_FINITE_RECORD_ISSUED"
                or any(stored[name] != value for name, value in _report(ISSUED).items() if name != "status")
                or stored["assessment_digest"] != _digest(canonical_bytes({k: v for k, v in stored.items() if k != "assessment_digest"}))):
            raise ValueError("retained finite attestation differs")
        for name in ("subject_digest", "proposal_digest", "receipt_digest", "public_commit_digest", "host_policy_digest",
                     "authority_policy_digest", "mechanism_digest", "local_replay_digest", "assessment_digest"):
            codec._hash(stored[name])
        authority._time(stored["evaluation_time"])
        authority._time(stored["historical_evaluation_time"])
        codec._record(stored["input_digests"], {"bundle", "request", "issue_evidence"})
        for pin in stored["input_digests"].values():
            codec._hash(pin)
        proposal = codec._record(_load(proposal_bytes, ledger.MAX_PROPOSAL_BYTES), {"schema_version", "assessment"})
        if proposal["schema_version"] != PROPOSAL:
            raise ValueError("retained finite precommit schema differs")
        _ready(proposal["assessment"], host)
        ready = proposal["assessment"]
        if (stored["historical_evaluation_time"] != ready["evaluation_time"]
                or stored["subject_digest"] != _digest(canonical_bytes(ready["subject"]))
                or stored["mechanism_digest"] != ready["mechanism_digest"]
                or stored["input_digests"] != ready["input_digests"]
                or stored["host_policy_digest"] != ready["subject"]["host_policy_digest"]
                or stored["authority_policy_digest"] != ready["subject"]["authority_policy_digest"]):
            raise ValueError("retained finite attestation/precommit binding differs")
        if _digest(proposal_bytes) != stored["proposal_digest"]:
            raise ValueError("known precommit bytes differ")
        for name in ("receipt", "public_commit"):
            raw = external_selection[name + "_bytes"]
            if raw is not None and _digest(raw) != stored[name + "_digest"]:
                raise ValueError("known retained commit bytes differ")
        for name in ("bundle", "request", "issue_evidence"):
            raw = external_selection[name + "_bytes"]
            if raw is not None and _digest(raw) != stored["input_digests"][name]:
                raise ValueError("known retained finite input differs")
        now = external_selection["evaluation_time"]
        if now is not None and authority._time(now) != stored["evaluation_time"]:
            raise ValueError("known exact finite replay clock differs")
        if host is not None and (stored["host_policy_digest"] != host.expected_policy_digest
                or stored["authority_policy_digest"] != host.expected_authority_policy_digest):
            raise ValueError("known retained finite host policy differs")
        if external_selection["receipt_bytes"] is not None:
            _retained_receipt(external_selection["receipt_bytes"], proposal_bytes, ready)
        if any(external_selection[name] is None for name in ("receipt_bytes", "public_commit_bytes", "bundle_bytes", "request_bytes", "issue_evidence_bytes")):
            raise Unavailable("exact retained finite replay input absent")
        actual = finalize_finite_record_issuance(proposal_bytes, **external_selection)
        if actual["status"] == "PASS" and canonical_bytes(actual) == attestation_bytes:
            report.update(status="PASS", replay_status="REPRODUCED", attestation_digest=stored["assessment_digest"])
        elif actual["status"] == "UNKNOWN":
            report.update(status="UNKNOWN", replay_status="UNAVAILABLE")
    except (Unavailable, codec._Exhausted, OSError, ImportError, RecursionError, OverflowError, asyncio.CancelledError):
        report.update(status="UNKNOWN", replay_status="UNAVAILABLE")
    except (ValueError, TypeError, KeyError, UnicodeError):
        pass
    return _finish(report)
