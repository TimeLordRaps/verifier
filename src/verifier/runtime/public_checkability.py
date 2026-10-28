"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

Experimental bounded public checkability, version 1.

Retained native witnesses require exact public disclosure admission and replay.
Full polished issuance and publication remain separate.
The initial secret-free native adapter is OBJECT-1.1 only. Other adapters and
all confidential proof protocols are unavailable rather than producer selected.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
from typing import Any

from verifier.core import certificate, signature_keys
from verifier.consent import engine, public as public_consent
from verifier.domains.contracts import certificate_dag, current_object_routes, object_facets

VERSION = "1"
BUNDLE = "verifier-public-checkability-bundle-1"
REQUEST = "verifier-public-checkability-request-1"
ASSESSMENT = "verifier-public-checkability-assessment-1"
CONTEXT = "verifier-public-checkability-node-context-1"
SUBJECT = "verifier-public-checkability-disclosure-subject-1"
OPERATION = "DISCLOSE_PUBLIC_CHECKABILITY_WITNESS"
MECHANISM_ID = "verifier.public-checkability.retained-native.1"
PUBLIC = "PUBLIC_RETAINED_NATIVE_REPLAY"
CONFIDENTIAL = "CONFIDENTIAL_NAMED_PROOF"
MIB = 1024 * 1024
_INPUT_CAPS = {"bundle": 112 * MIB, "request": 8 * MIB,
               "disclosure_policy": MIB, "disclosure_evidence": MIB}
_RUNTIME_SCOPE = "TRUSTED_FIXED_HOST_PROCESS_REQUIRED;NOT_ATTESTED_BY_SOURCE_HASH"
_ASSESSMENT_FIELDS = {"schema_version", "status", "nodes", "blockers", "evaluation_time",
    "input_digests", "input_capture", "runtime_provenance", "disclosure_status",
    "disclosure_subject_digest", "disclosure_receipt_digest", "disclosure_replay_digest",
    "dependency_assessment_digest", "public_checkability_scope", "polished_artifact",
    "inventory_completeness", "human_acceptance", "public_availability", "publication",
    "claim_correctness", "overall_safety", "assessment_digest"}
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_POLICY_FIELDS = {"schema_version", "mechanism_digest", "policy_id", "grantor_id", "keys",
                  "root_key_ids", "revocation_key_ids", "artifact_bindings",
                  "max_revocation_age_seconds", "minimum_revocation_as_of", "max_chain_length"}


class _Unavailable(ValueError):
    pass


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return certificate.canonical_bytes(value)


def _fields(value: Any, names: set[str]) -> dict:
    if type(value) is not dict or set(value) != names:
        raise ValueError("fields differ")
    return value


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError("digest differs")
    return value


def _plain_text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value.encode("utf-8")) > 256:
        raise ValueError("bounded text required")
    return value


def _capture_inputs(values: dict) -> tuple[dict, dict]:
    """Inspect ALL transport bounds before hashing any submitted input.

    None is captured absence, not byte evidence. Overbound bytes are not retained
    or hashed; already admitted bounded sibling inputs can still establish an
    exact historical contradiction before UNKNOWN. Foreign built-ins are refused
    before their length/callbacks. No producer status is accepted.
    """
    admitted, states = {}, {}
    for name, cap in _INPUT_CAPS.items():
        raw = values[name]
        if raw is None:
            admitted[name], states[name] = None, "ABSENT"
        elif type(raw) is not bytes:
            raise ValueError("immutable plain input bytes required")
        elif len(raw) > cap:
            admitted[name], states[name] = None, "OVERBOUND"
        else:
            admitted[name], states[name] = raw, "PRESENT"
    return admitted, states


def _json(raw: bytes, cap: int) -> dict:
    if type(raw) is not bytes:
        raise ValueError("immutable bytes required")
    if len(raw) > cap:
        raise _Unavailable("byte capacity")
    # Fence nesting and long numeric tokens before allocating decoded JSON trees.
    quoted = escaped = False
    depth = digits = 0
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
            continue
        if byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 48:
                raise _Unavailable("nesting capacity")
        elif byte in (93, 125):
            depth -= 1
        digits = digits + 1 if 48 <= byte <= 57 else 0
        if digits > 1234:
            raise _Unavailable("numeric capacity")

    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def finite(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("non-finite number")
        return result

    def reject(_):
        raise ValueError("non-finite constant")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_float=finite, parse_constant=reject)
    work = 0

    def visit(item):
        nonlocal work
        work += 1
        if work > 100000:
            raise _Unavailable("structural capacity")
        if type(item) is dict:
            for key, child in item.items():
                visit(key)
                visit(child)
        elif type(item) is list:
            for child in item:
                visit(child)
        elif type(item) is int and item.bit_length() > 4096:
            raise _Unavailable("integer capacity")

    visit(value)
    if type(value) is not dict or _canonical(value) != raw:
        raise ValueError("canonical object required")
    return value


def _decode(text: Any, cap: int) -> bytes:
    if type(text) is not str:
        raise ValueError("base64 text required")
    if len(text) > 4 * ((cap + 2) // 3):
        raise _Unavailable("encoded byte capacity")
    raw = base64.b64decode(text, validate=True)
    if len(raw) > cap:
        raise _Unavailable("decoded byte capacity")
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("noncanonical base64")
    return raw


def mechanism_digest() -> str:
    """Proposed adapter/source pin; exact native route pins remain separate.

    No authentication of the installed machine or cryptographic backend follows.
    ROOT must independently admit the installed digest after integration/testing.
    """
    paths = {"public_checkability.py": Path(__file__),
             "PUBLIC_CHECKABILITY.md": Path(__file__).parents[1] / "standard" / "PUBLIC_CHECKABILITY.md"}
    for module in (certificate, signature_keys, engine, public_consent,
                   certificate_dag, current_object_routes, object_facets):
        paths[module.__name__] = Path(module.__file__)
    return _digest(_canonical({name: _digest(path.read_bytes()) for name, path in sorted(paths.items())}))


def node_contexts(dependency: dict, policy: dict) -> dict[str, dict]:
    """Format context from exact inputs; this helper supplies no admission."""
    profiles = {_digest(_canonical(p)): p for p in dependency["profiles"]}
    objects = {row["object_id"]: row for row in dependency["objects"]}
    selected = {row["object_id"]: row for row in policy["required_objects"]}
    if (len(profiles) != len(dependency["profiles"]) or len(objects) != len(dependency["objects"])
            or len(selected) != len(policy["required_objects"])):
        raise ValueError("duplicate selected context")
    edges = sorted(dependency["edges"], key=_canonical)
    policy_digest = _digest(_canonical(policy))
    result = {}
    for node in dependency["nodes"]:
        nid, oid = node["node_id"], node["object_id"]
        if nid in result:
            raise ValueError("duplicate node")
        selection = selected[oid]
        if selection["profile_digest"] not in profiles or oid not in objects:
            raise _Unavailable("selected profile or object absent")
        profile = profiles[selection["profile_digest"]]
        claims = [c for c in profile["obligations"] if c["claim_id"] == node["claim_id"]]
        if not claims:
            raise _Unavailable("selected claim absent")
        if len(claims) != 1:
            raise ValueError("unique selected claim required")
        result[nid] = {"schema_version": CONTEXT, "node": node,
                       "selected_object": selection, "object": objects[oid],
                       "profile": profile, "claim": claims[0],
                       "declared_edges": edges,
                       "dependency_policy_digest": policy_digest}
    return result


def disclosure_policy_terms_digest(policy: dict) -> str:
    _fields(policy, _POLICY_FIELDS)
    return _digest(_canonical({key: value for key, value in policy.items() if key != "artifact_bindings"}))


def disclosure_subject(request_bytes: bytes) -> dict:
    request = _json(request_bytes, 8 * MIB)
    return {"schema_version": SUBJECT, "operation": OPERATION,
            "request_digest": _digest(request_bytes),
            "dependency_bundle_digest": request["dependency_bundle_digest"],
            "dependency_policy_digest": request["dependency_policy_digest"],
            "artifact_inventory_digest": request["artifact_inventory_digest"],
            "mechanism_digest": request["mechanism_digest"],
            "disclosure_policy_terms_digest": request["disclosure_policy_terms_digest"],
            "artifact_binding_rule": "EXACT_SINGLE_OBJECT_DERIVED_SUBJECT"}


def _screen_request(request_bytes: bytes) -> dict:
    """Owned retained grammar and bindings only; no source or authority credit."""
    request = _fields(_json(request_bytes, 8 * MIB),
        {"schema_version", "mechanism_digest", "dependency_bundle_digest", "dependency_policy_digest",
         "artifact_inventory_digest", "required_nodes", "disclosure_policy_terms_digest", "disclosure"})
    if request["schema_version"] != REQUEST:
        raise ValueError("request version differs")
    for name in ("mechanism_digest", "dependency_bundle_digest", "dependency_policy_digest",
                 "artifact_inventory_digest", "disclosure_policy_terms_digest"):
        _hash(request[name])
    disclosure = _fields(request["disclosure"], {"actor_id", "observer_id", "purpose"})
    _plain_text(disclosure["actor_id"])
    if disclosure["observer_id"] != "PUBLIC" or disclosure["purpose"] != "PUBLIC_CHECKABILITY":
        raise ValueError("public audience and exact purpose required")
    required = request["required_nodes"]
    if type(required) is not list or not 1 <= len(required) <= 512:
        raise ValueError("nonempty exact required nodes needed")
    identifiers = []
    for row in required:
        _fields(row, {"node_id", "mode", "context_digest", "proof_protocol_id", "proof_statement_digest"})
        identifiers.append(_plain_text(row["node_id"]))
        _hash(row["context_digest"])
        if row["mode"] not in (PUBLIC, CONFIDENTIAL):
            raise ValueError("unsupported evidence mode")
        if row["mode"] == PUBLIC:
            if row["proof_protocol_id"] is not None or row["proof_statement_digest"] is not None:
                raise ValueError("public native mode cannot carry a proof assertion")
        else:
            _plain_text(row["proof_protocol_id"])
            _hash(row["proof_statement_digest"])
    if identifiers != sorted(set(identifiers)):
        raise ValueError("sorted unique required node identifiers needed")
    return request


def _screen_disclosure(request: dict | None, request_bytes: bytes | None,
                       policy_bytes: bytes | None, evidence_bytes: bytes | None) -> tuple:
    """Refute present local inputs without supplying missing disclosure support."""
    selected, signed, subject_digest = None, None, None
    if policy_bytes is not None:
        selected = _fields(_json(policy_bytes, MIB), _POLICY_FIELDS)
        if request is not None:
            if disclosure_policy_terms_digest(selected) != request["disclosure_policy_terms_digest"]:
                raise ValueError("disclosure authority terms substituted")
            subject_digest = _digest(_canonical(disclosure_subject(request_bytes)))
            if selected["artifact_bindings"] != [["OBJECT", subject_digest[7:]]]:
                raise ValueError("exact singleton disclosure artifact binding required")
    if evidence_bytes is not None:
        signed = _fields(_json(evidence_bytes, MIB), {"grants", "revocation"})
        if type(signed["grants"]) is not list:
            raise ValueError("plain signed grant chain required")
    return selected, signed, subject_digest


def _retained_adapter(context: dict, files: dict[str, bytes]) -> bool:
    claim, node = context["claim"], context["node"]
    if (claim["semantic_version"] != object_facets.SEMANTIC_VERSION
            or claim["objective"] != object_facets.COORDINATE):
        return False
    # Source-grounded public policy shape, not a heuristic secret-field blacklist.
    _fields(node["checker_policy"], {"schema_version", "mechanism_id", "mechanism_digest",
                                    "trust_roots", "max_certificate_bytes"})
    certificate_bytes = files.get(node["certificate_path"])
    if certificate_bytes is None:
        raise _Unavailable("retained certificate absent")
    envelope = _json(certificate_bytes, 8 * MIB)
    payloads = envelope["evidence_payloads"]
    reference = node["request"]["evidence_ref"]
    if type(payloads) is not dict or set(payloads) != {reference}:
        # Missing material is UNKNOWN; unexpected retained material is a refusal.
        if type(payloads) is dict and not payloads:
            raise _Unavailable("retained witness absent")
        raise ValueError("unexpected retained witness")
    _hash(reference)
    raw = _decode(payloads[reference], 4 * MIB)
    if _digest(raw) != reference:
        raise ValueError("retained witness substituted")
    return True


def assess_public_checkability(bundle_bytes: bytes | None, *, request_bytes: bytes | None,
                              disclosure_policy_bytes: bytes | None,
                              disclosure_evidence_bytes: bytes | None,
                              evaluation_time: int | None) -> dict:
    """Assess an independently selected finite package, never issue or publish.

    The caller must retain immutable inputs. No path/module/callback, secret policy
    key or proof-verifier selection is accepted from a producer. Native callbacks
    are fenced until disclosure is admitted and every node has an installed adapter.
    """
    result = {"schema_version": ASSESSMENT, "status": "UNKNOWN", "nodes": [],
              "blockers": [], "evaluation_time": evaluation_time if type(evaluation_time) is int and 0 <= evaluation_time <= 2**53 - 1 else None,
              "input_digests": {name: None for name in _INPUT_CAPS},
              "input_capture": "NOT_CAPTURED", "runtime_provenance": _RUNTIME_SCOPE,
              "disclosure_status": "UNKNOWN", "disclosure_subject_digest": None,
              "disclosure_receipt_digest": None, "disclosure_replay_digest": None,
              "dependency_assessment_digest": None,
              "public_checkability_scope": "EXACT_FINITE_SELECTED_NODE_CONTEXTS",
              "polished_artifact": False, "inventory_completeness": "NOT_ESTABLISHED",
              "human_acceptance": "NOT_ESTABLISHED", "public_availability": "NOT_ESTABLISHED",
              "publication": "NOT_PERFORMED", "claim_correctness": "NOT_ESTABLISHED",
              "overall_safety": "NOT_ESTABLISHED"}
    try:
        if evaluation_time is not None and (type(evaluation_time) is not int or not 0 <= evaluation_time <= 2**53 - 1):
            raise ValueError("externally selected time invalid")
        admitted, states = _capture_inputs({"bundle": bundle_bytes, "request": request_bytes,
            "disclosure_policy": disclosure_policy_bytes, "disclosure_evidence": disclosure_evidence_bytes})
        result["input_capture"] = "INCOMPLETE_BOUND" if "OVERBOUND" in states.values() else "BOUNDED_CAPTURED"
        result["input_digests"] = {name: _digest(raw) if raw is not None else None for name, raw in admitted.items()}
        if "OVERBOUND" in states.values():
            raise _Unavailable("input transport capacity")
        request = None if admitted["request"] is None else _screen_request(admitted["request"])
        selected_disclosure, signed, subject_digest = _screen_disclosure(request, admitted["request"],
            admitted["disclosure_policy"], admitted["disclosure_evidence"])
        result["disclosure_subject_digest"] = subject_digest
        if admitted["bundle"] is None or request is None:
            raise _Unavailable("external public bundle or request absent")
        disclosure = request["disclosure"]
        carried = _fields(_json(bundle_bytes, 112 * MIB),
            {"schema_version", "dependency_bundle_base64", "dependency_policy_base64", "artifact_files"})
        if carried["schema_version"] != BUNDLE:
            raise ValueError("bundle version differs")
        dependency_bytes = _decode(carried["dependency_bundle_base64"], 8 * MIB)
        policy_bytes = _decode(carried["dependency_policy_base64"], 8 * MIB)
        if (_digest(dependency_bytes) != _hash(request["dependency_bundle_digest"])
                or _digest(policy_bytes) != _hash(request["dependency_policy_digest"])):
            raise ValueError("native input substituted")
        rows = carried["artifact_files"]
        if type(rows) is not list or len(rows) > 1024:
            raise _Unavailable("artifact count capacity")
        files, total, previous = {}, 0, ""
        for row in rows:
            _fields(row, {"path", "base64"})
            path = _plain_text(row["path"])
            parsed = PurePosixPath(path)
            if (path <= previous or "\\" in path or ":" in path or any(ord(c) < 32 for c in path) or parsed.is_absolute()
                    or str(parsed) != path or any(p in (".", "..") for p in parsed.parts)):
                raise ValueError("sorted unique snapshot-relative paths required")
            raw = _decode(row["base64"], 64 * MIB - total)
            files[path], previous = raw, path
            total += len(raw)
        if certificate_dag.artifact_files_digest(files) != _hash(request["artifact_inventory_digest"]):
            raise ValueError("complete public inventory substituted")
        dependency = _fields(_json(dependency_bytes, 8 * MIB),
                             {"schema_version", "profiles", "objects", "nodes", "edges"})
        policy = _fields(_json(policy_bytes, 8 * MIB),
                        {"schema_version", "approved_profiles", "required_objects", "required_roots", "nodes", "artifact_files_digest"})
        if dependency["nodes"] != policy["nodes"] or policy["artifact_files_digest"] != request["artifact_inventory_digest"]:
            raise ValueError("selected native policy differs")
        for name in ("profiles", "objects", "nodes", "edges"):
            if type(dependency[name]) is not list:
                raise ValueError("bounded native lists required")
        if len(dependency["nodes"]) > 512 or len(dependency["edges"]) > 4096:
            raise _Unavailable("native context capacity")
        contexts = node_contexts(dependency, policy)
        required = request["required_nodes"]
        if [row["node_id"] for row in required] != sorted(contexts):
            raise ValueError("required node inventory omitted, duplicated, reordered or expanded")
        pending = []
        context_bytes = 0
        for row in required:
            encoded_context = _canonical(contexts[row["node_id"]])
            context_bytes += len(encoded_context)
            if context_bytes > 64 * MIB:
                raise _Unavailable("cumulative context canonical byte capacity")
            if _hash(row["context_digest"]) != _digest(encoded_context):
                raise ValueError("required exact node context differs")
            if row["mode"] == CONFIDENTIAL:
                pending.append("CONFIDENTIAL_PROOF_VERIFIER_UNAVAILABLE:" + row["node_id"])
            else:
                try:
                    if not _retained_adapter(contexts[row["node_id"]], files):
                        pending.append("PUBLIC_NATIVE_ADAPTER_UNAVAILABLE:" + row["node_id"])
                except _Unavailable:
                    pending.append("PUBLIC_WITNESS_UNAVAILABLE:" + row["node_id"])
            result["nodes"].append({"node_id": row["node_id"], "mode": row["mode"],
                                    "context_digest": row["context_digest"], "status": "UNKNOWN"})
        # Every available retained local screen precedes current source availability.
        # Source equality still fences admission; it cannot authenticate loaded code.
        if request["mechanism_digest"] != mechanism_digest():
            raise ValueError("installed adapter differs")
        if selected_disclosure is None or signed is None:
            raise _Unavailable("disclosure selection or signed evidence missing")
        context = engine.ConsentContext("OBJECT", subject_digest[7:], OPERATION,
            disclosure["actor_id"], "PUBLIC", "PUBLIC_CHECKABILITY", evaluation_time or 0)
        consent = public_consent.evaluate_public_consent(context, tuple(signed["grants"]),
            policy=selected_disclosure, revocation=signed["revocation"], evaluation_time=evaluation_time)
        replay = public_consent.recheck_public_consent(consent.receipt, context, tuple(signed["grants"]),
            policy=selected_disclosure, revocation=signed["revocation"], evaluation_time=evaluation_time)
        result["disclosure_status"] = consent.verdict.value
        result["disclosure_receipt_digest"] = "sha256:" + consent.receipt["receipt_digest"]
        result["disclosure_replay_digest"] = _digest(_canonical(replay))
        if consent.verdict.value == "REJECTED":
            raise ValueError("authenticated disclosure rejected")
        if consent.verdict.value != "PASS" or replay.get("admission_status") != "PASS" or replay.get("replay_status") != "REPRODUCED":
            raise _Unavailable("current public disclosure admission unavailable")
        if pending:
            result["blockers"] = sorted(pending)
        else:
            native = certificate_dag.assess_certificate_dependencies(dependency_bytes,
                expected_policy_bytes=policy_bytes, artifact_files=files)
            result["dependency_assessment_digest"] = native["assessment_digest"]
            by_id = {row["node_id"]: row for row in native["nodes"]}
            for node in result["nodes"]:
                row = by_id.get(node["node_id"])
                if row is not None:
                    node["status"] = row["qualified_status"]
                    node["native_replay_digest"] = row["replay_digest"]
            if native["status"] == "FAIL":
                result["status"], result["blockers"] = "FAIL", ["NATIVE_DEPENDENCY_REFUTED"]
            elif native["status"] == "PASS" and all(n["status"] == "PASS" for n in result["nodes"]):
                result["status"] = "PASS"
            else:
                result["blockers"] = ["NATIVE_DEPENDENCY_UNAVAILABLE"]
    except asyncio.CancelledError:
        result["blockers"] = ["ASSESSMENT_CANCELLED"]
    except (_Unavailable, RecursionError, OverflowError, ImportError, OSError):
        result["blockers"] = ["CHECKABILITY_OR_RESOURCE_UNAVAILABLE"]
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
        result["status"], result["blockers"] = "FAIL", ["PUBLIC_CHECKABILITY_CONTRACT_REJECTED"]
    except Exception:
        result["blockers"] = ["CHECKABILITY_IMPLEMENTATION_UNAVAILABLE"]
    # Never retain exception text, raw witnesses, secret keys or producer explanations.
    result["assessment_digest"] = _digest(_canonical(result))
    return result


def recheck_public_checkability(assessment_bytes: bytes, bundle_bytes: bytes, **external_selection) -> dict:
    """Exact historical replay with all external inputs/time reselected.

    REPRODUCED UNKNOWN/FAIL remains UNKNOWN/FAIL. Fresh-time admission is a new
    assessment, and an interrupted process has no result. No cached PASS fallback.
    """
    try:
        if type(assessment_bytes) is not bytes:
            raise ValueError("plain retained assessment bytes required")
        if len(assessment_bytes) > 2 * MIB:
            raise _Unavailable("retained assessment byte capacity")
        _fields(external_selection, {"request_bytes", "disclosure_policy_bytes", "disclosure_evidence_bytes", "evaluation_time"})
        now = external_selection["evaluation_time"]
        if now is not None and (type(now) is not int or not 0 <= now <= 2**53 - 1):
            raise ValueError("plain historical clock required")
        admitted, states = _capture_inputs({"bundle": bundle_bytes,
            "request": external_selection["request_bytes"],
            "disclosure_policy": external_selection["disclosure_policy_bytes"],
            "disclosure_evidence": external_selection["disclosure_evidence_bytes"]})
        recorded = _fields(_json(assessment_bytes, 2 * MIB), _ASSESSMENT_FIELDS)
        if (recorded.get("schema_version") != ASSESSMENT or recorded.get("assessment_digest") !=
                _digest(_canonical({k: v for k, v in recorded.items() if k != "assessment_digest"}))):
            raise ValueError("assessment binding differs")
        if recorded["status"] not in ("PASS", "FAIL", "UNKNOWN") or recorded["input_capture"] not in (
                "NOT_CAPTURED", "INCOMPLETE_BOUND", "BOUNDED_CAPTURED"):
            raise ValueError("retained outcome or capture marker differs")
        if (recorded["polished_artifact"] is not False or recorded["runtime_provenance"] != _RUNTIME_SCOPE
                or recorded["public_checkability_scope"] != "EXACT_FINITE_SELECTED_NODE_CONTEXTS"
                or recorded["publication"] != "NOT_PERFORMED"
                or any(recorded[name] != "NOT_ESTABLISHED" for name in
                    ("inventory_completeness", "human_acceptance", "public_availability", "claim_correctness", "overall_safety"))):
            raise ValueError("retained claim boundary differs")
        selected_pins = _fields(recorded["input_digests"], set(_INPUT_CAPS))
        if recorded["status"] == "PASS" and (recorded["input_capture"] != "BOUNDED_CAPTURED"
                or any(pin is None for pin in selected_pins.values())
                or recorded["disclosure_status"] != "PASS"
                or type(recorded["nodes"]) is not list or not recorded["nodes"]
                or any(type(node) is not dict or node.get("status") != "PASS" for node in recorded["nodes"])
                or recorded["evaluation_time"] is None):
            raise ValueError("positive retained prerequisites absent")
        for name, pin in selected_pins.items():
            if pin is not None:
                _hash(pin)
            if states[name] == "PRESENT":
                # All transport admissions above precede hashing. A known changed
                # retained byte selection dominates a later unavailable checker.
                current_pin = _digest(admitted[name])
                if (pin is not None and current_pin != pin
                        or pin is None and recorded["input_capture"] == "BOUNDED_CAPTURED"):
                    raise ValueError("exact retained historical input selection differs")
        historical_time = recorded["evaluation_time"]
        if historical_time is not None and (type(historical_time) is not int or not 0 <= historical_time <= 2**53 - 1):
            raise ValueError("retained historical clock invalid")
        if now is not None and now != historical_time:
            raise ValueError("exact historical clock selection differs")
        if ("OVERBOUND" in states.values() or recorded["input_capture"] != "BOUNDED_CAPTURED"
                or any(states[name] == "ABSENT" and selected_pins[name] is not None for name in _INPUT_CAPS)):
            raise _Unavailable("exact retained input unavailable or never fully captured")
        rebuilt = assess_public_checkability(bundle_bytes, **external_selection)
        if _canonical(rebuilt) != assessment_bytes:
            return {"schema_version": "verifier-public-checkability-replay-1",
                    "status": "UNAVAILABLE" if rebuilt["status"] == "UNKNOWN" else "FAIL",
                    "public_checkability_status": "UNKNOWN"}
        return {"schema_version": "verifier-public-checkability-replay-1", "status": "REPRODUCED",
                "public_checkability_status": rebuilt["status"], "assessment_digest": rebuilt["assessment_digest"]}
    except (_Unavailable, RecursionError, OverflowError):
        return {"schema_version": "verifier-public-checkability-replay-1",
                "status": "UNAVAILABLE", "public_checkability_status": "UNKNOWN"}
    except (ValueError, TypeError, UnicodeError):
        return {"schema_version": "verifier-public-checkability-replay-1",
                "status": "FAIL", "public_checkability_status": "UNKNOWN"}


__all__ = ["assess_public_checkability", "recheck_public_checkability", "node_contexts",
           "disclosure_subject", "disclosure_policy_terms_digest", "mechanism_digest"]
