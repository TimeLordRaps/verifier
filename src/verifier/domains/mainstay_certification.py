"""Request-bound mainstay assessments, separate from domain certification depth.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256). These certificates establish only the selected bounded checks.
They do not establish a complete domain tier, object profile, native-format
conformance, observation authenticity or an external trust root. Evidence and
operation sizes are bytes and dimensionless counts, respectively. Numerical
tolerance has the output units of the supplied model contract.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
from typing import Any, Sequence

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads
from .carriers import SUPPORTED
from .common import Budget, Refuted, Unavailable, digest, inspect_structure, integer, number, obj, same, text
from .mainstays import CHECKS, MAINSTAYS, evaluate, mainstay_catalog, mainstay_digest

MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EVIDENCE_FIELDS = {"schema_version", "object_name", "subject_id", "artifact", "inputs"}
_REQUEST_FIELDS = {"schema_version", "object_name", "subject_id", "artifact_digest", "evidence_ref", "checks"}
_POLICY_FIELDS = {"schema_version", "mechanism_digest", "trust_roots", "max_operations", "max_items",
                  "max_evidence_bytes", "max_tolerance"}
_ARTIFACT_FIELDS = {"mainstay", "mapping", "transcript_digest", "model", "samples_digest", "residual"}
_INPUT_FIELDS = {"carrier", "inventory", "transcript", "samples"}


def _snapshot(value: Any) -> Any:
    pending, nodes, characters = [(value, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 64 or nodes > 250000:
            raise ValueError("mainstay document structure bound exceeded")
        if type(item) is dict:
            if any(type(k) is not str for k in item):
                raise ValueError("mainstay object keys must be strings")
            characters += sum(len(k) for k in item)
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            characters += len(item)
        elif type(item) in (int, float):
            number(item)
        elif type(item) not in (bool, type(None)):
            raise ValueError("mainstay document requires plain JSON values")
        if characters > MAX_DOCUMENT_BYTES:
            raise ValueError("mainstay document byte bound exceeded")
    encoded = canonical_bytes(value)
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise ValueError("mainstay document byte bound exceeded")
    return strict_json_loads(encoded.decode("utf-8"))


def _hash(value: Any) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        raise ValueError("canonical SHA-256 reference required")
    return value


def mainstay_implementation_digest() -> str:
    """Pin this envelope, transitive carrier mechanisms and interpreter version."""
    return digest({"mainstay": mainstay_digest(),
                   "envelope": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "runtime": [sys.implementation.name, *sys.version_info[:3]]})


def mainstay_runtime_catalog() -> dict:
    result = mainstay_catalog()
    result["mechanism_digest"] = mainstay_implementation_digest()
    result["runtime_support"] = {
        "HARNESS": {"har": {"versions": list(SUPPORTED["har"]), "checks": ["binding", "layout", "roundtrip", "residual"]}},
        "MODEL": {"safetensors": {"versions": list(SUPPORTED["safetensors"]), "checks": ["binding", "schema", "roundtrip", "residual"]}},
    }
    result["scope"] = "selected bounded checks; registry membership alone does not establish support"
    return result


def _policy(value: Any) -> dict:
    value = obj(_snapshot(value), _POLICY_FIELDS)
    same(value["schema_version"], "verifier-mainstay-policy-1", "unsupported mainstay policy")
    _hash(value["mechanism_digest"])
    roots = value["trust_roots"]
    if type(roots) is not list or not roots or any(type(r) is not str or not r.strip() for r in roots):
        raise ValueError("explicit checker-selected trust roots required")
    if len(set(roots)) != len(roots):
        raise ValueError("distinct checker-selected trust roots required")
    integer(value["max_operations"], 1, 10000000)
    integer(value["max_items"], 1, 100000)
    integer(value["max_evidence_bytes"], 1, MAX_DOCUMENT_BYTES)
    if not 0 <= number(value["max_tolerance"]) <= 1e-8:
        raise ValueError("checker tolerance outside the supported mainstay range")
    return value


def mainstay_policy(*, trust_roots: list[str], max_operations: int = 1000000,
                    max_items: int = 4096, max_evidence_bytes: int = 8 * 1024 * 1024,
                    max_tolerance: float = 1e-8) -> dict:
    return _policy({"schema_version": "verifier-mainstay-policy-1",
                    "mechanism_digest": mainstay_implementation_digest(), "trust_roots": trust_roots,
                    "max_operations": max_operations, "max_items": max_items,
                    "max_evidence_bytes": max_evidence_bytes, "max_tolerance": max_tolerance})


def _bundle(value: Any) -> dict:
    value = obj(_snapshot(value), _EVIDENCE_FIELDS)
    same(value["schema_version"], "verifier-mainstay-evidence-1", "unsupported mainstay evidence")
    if text(value["object_name"]) not in MAINSTAYS:
        raise ValueError("unknown mainstay object")
    text(value["subject_id"])
    if set(obj(value["artifact"])) - _ARTIFACT_FIELDS or set(obj(value["inputs"])) - _INPUT_FIELDS:
        raise ValueError("unsupported mainstay evidence field")
    return value


def _request(value: Any) -> dict:
    value = obj(_snapshot(value), _REQUEST_FIELDS)
    same(value["schema_version"], "verifier-mainstay-request-1", "unsupported mainstay request")
    if text(value["object_name"]) not in MAINSTAYS:
        raise ValueError("unknown mainstay object")
    text(value["subject_id"])
    _hash(value["artifact_digest"])
    _hash(value["evidence_ref"])
    checks = value["checks"]
    if type(checks) is not list or not checks or any(type(c) is not str or c not in CHECKS for c in checks):
        raise ValueError("nonempty supported check names required")
    if len(set(checks)) != len(checks):
        raise ValueError("duplicate requested mainstay check")
    return value


def mainstay_request(evidence: dict, *, checks: Sequence[str]) -> dict:
    bundle = _bundle(evidence)
    return _request({"schema_version": "verifier-mainstay-request-1",
                     "object_name": bundle["object_name"], "subject_id": bundle["subject_id"],
                     "artifact_digest": digest(bundle["artifact"]), "evidence_ref": digest(bundle),
                     "checks": list(checks)})


def build_mainstay_certificate(request: dict, evidence: dict, *, policy: dict) -> dict:
    """Run the exact selected checks under one shared checker-controlled budget."""
    request, bundle, policy = _request(request), _bundle(evidence), _policy(policy)
    same(mainstay_request(bundle, checks=request["checks"]), request, "evidence differs from intended mainstay request")
    same(policy["mechanism_digest"], mainstay_implementation_digest(), "mainstay mechanism not admitted by checker")
    evidence_bytes = len(canonical_bytes(bundle))
    budget = Budget(policy["max_operations"], policy["max_items"])
    rows = {}
    for check in request["checks"]:
        before = budget.used
        observations = {}
        try:
            if evidence_bytes > policy["max_evidence_bytes"]:
                raise Unavailable("mainstay evidence exceeds checker byte bound")
            inspect_structure(bundle, budget)
            model = bundle["artifact"].get("model")
            if check == "roundtrip" and request["object_name"] == "MODEL" and isinstance(model, dict) and "tolerance" in model:
                tolerance = number(model["tolerance"])
                if tolerance < 0:
                    raise Refuted("negative numerical tolerance")
                if tolerance > policy["max_tolerance"]:
                    raise Unavailable("requested numerical tolerance exceeds checker policy")
            observations = evaluate(request["object_name"], check, bundle["artifact"], bundle["inputs"], budget)
            outcome, details = "PASS", "selected bounded mainstay computation reproduced"
        except Unavailable as exc:
            outcome, details = "UNKNOWN", str(exc)
        except (Refuted, ValueError, TypeError, KeyError, IndexError, ArithmeticError, UnicodeError) as exc:
            outcome, details = "FAIL", str(exc)
        rows[check] = {"status": outcome, "details": details, "observations": observations,
                       "operations": budget.used - before}
    outcomes = [row["status"] for row in rows.values()]
    status = "FAIL" if "FAIL" in outcomes else "UNKNOWN" if "UNKNOWN" in outcomes else "PASS"
    result = {"status": status, "checks": rows, "operations": budget.used,
              "scope": "selected bounded checks on retained carriers",
              "object_profile_conformance": "NOT_ESTABLISHED",
              "domain_tier_5_conformance": "NOT_ESTABLISHED",
              "native_format_conformance": "NOT_ESTABLISHED", "authentication": "NOT_ESTABLISHED"}
    certificate = {"schema_version": "verifier-mainstay-certification-1", "request": request, "evidence": bundle,
                   "policy_digest": digest(policy), "mechanism_digest": policy["mechanism_digest"], "result": result}
    certificate["certificate_digest"] = digest(certificate)
    return _snapshot(certificate)


def recheck_mainstay_certificate(certificate: dict, *, expected_request: dict, policy: dict) -> dict:
    """Replay exact external intent and policy; never promote a retained verdict."""
    try:
        certificate = obj(_snapshot(certificate), {"schema_version", "request", "evidence", "policy_digest",
                                                  "mechanism_digest", "result", "certificate_digest"})
        same(certificate["request"], _request(expected_request), "mainstay request differs from consumer intent")
        reproduced = build_mainstay_certificate(expected_request, certificate["evidence"], policy=policy)
        same(certificate, reproduced, "mainstay certificate does not reproduce under checker policy")
        return reproduced["result"]
    except (ValueError, TypeError, KeyError, ArithmeticError, RecursionError) as exc:
        return {"status": "REJECTED", "reason": str(exc), "object_profile_conformance": "NOT_ESTABLISHED",
                "domain_tier_5_conformance": "NOT_ESTABLISHED", "authentication": "NOT_ESTABLISHED"}
