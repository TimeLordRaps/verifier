"""Verifier Standard (VSTD) domain certificates bound to external requests and policy.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Domain depth is a dimensionless consecutive prerequisite count, never an object
or Graph numbered-profile verdict. Portable results are recomputed, not trusted.
"""
from __future__ import annotations

import hashlib
from importlib import import_module, metadata, resources
import re
import sys
from typing import Any, Sequence

from verifier.core.certificate import canonical_bytes
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from .catalog import CHECKS, SCOPES, domain_specification_digest
from .common import Budget, Refuted, Unavailable, digest, inspect_structure, integer, need, number, obj, same, text

MAX_BYTES = 16 * 1024 * 1024
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ARTIFACT_FIELDS = {
    "DATA": "shards fields shard_fields transforms source_shards splits final_shards identity_field overlap",
    "ENV": "scope files configuration ceilings execution execution_ids",
    "BENCH": "problems minimum_score",
    "HYPER": "configuration architecture checkpoint_digests steps_digest start_step tolerance",
    "MODEL": "architecture_digest weights_digest dependencies tolerance samples_digest metric metric_bounds challenges",
    "HARNESS": "surface transcript_digest transcript_root tools effects record_count",
    "AGENT": "harness_certificate_digest harness_subject_id required_channels steps_digest actions_digest outcomes claims",
    "BOT": "agent_certificate_digest sim_certificate_digest agent_environment_certificate_digest sim_environment_certificate_digest step_map exogenous_transitions initial_observation_record separation",
    "SIM": "transition trajectory_digest entropy_digest times_digest initial_state invariants finite_state_set finite_entropy_set projection macro_digest tolerance observation action_bounds shards",
}
_INPUT_FIELDS = {
    "DATA": "shards", "ENV": "files configuration measurements executions",
    "BENCH": "runs score", "HYPER": "checkpoints steps batches",
    "MODEL": "architecture weights dependencies samples metric_value",
    "SIM": "states entropy times macro_states observations actions shards",
    "HARNESS": "records invocations effects",
    "AGENT": "harness_certificate steps actions outcomes",
    "BOT": "agent_certificate sim_certificate agent_environment_certificate sim_environment_certificate",
}


def _snapshot(value: Any) -> Any:
    """Reject non-JSON, excessive nesting and ambiguous scalar types before hashing."""
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 64 or nodes > 250000:
            raise ValueError("domain document structure bound exceeded")
        if type(item) is dict:
            if any(type(k) is not str for k in item):
                raise ValueError("domain object keys must be strings")
            pending.extend((v, depth+1) for v in item.values())
        elif type(item) is list:
            pending.extend((v, depth+1) for v in item)
        elif type(item) not in (str, int, float, bool, type(None)):
            raise ValueError("domain document must contain plain JSON values")
        elif type(item) in (int, float):
            number(item)
    encoded = canonical_bytes(value)
    if len(encoded) > MAX_BYTES:
        raise ValueError("domain document byte bound exceeded")
    return strict_json_loads(encoded.decode("utf-8"))


def _hash(value: Any) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError("canonical SHA-256 reference required")
    return value


def implementation_digest() -> str:
    dependencies = {}
    for package, names in (("verifier.domains", ("__init__", "catalog", "common", "certification", "data", "env", "bench", "numerical", "hyper", "model", "sim", "harness", "agent", "bot")),
                           ("verifier.core", ("certificate", "evidence", "receipt"))):
        for name in names:
            dependencies[package+"."+name] = hashlib.sha256(resources.files(package).joinpath(name+".py").read_bytes()).hexdigest()
    try:
        crypto = metadata.version("cryptography")
    except metadata.PackageNotFoundError:
        crypto = "absent"
    return digest({"sources": dependencies, "runtime": [sys.implementation.name, sys.version_info.major, sys.version_info.minor],
                   "cryptography": crypto, "specification": domain_specification_digest()})


def domain_policy(*, trust_roots: list[str], witness_keys: dict | None = None,
                  max_operations: int = 1000000, max_items: int = 4096,
                  max_evidence_bytes: int = 4*1024*1024, max_tolerance: float = 1e-8) -> dict:
    """Create a checker-selected policy; never derive roots from a certificate."""
    return _policy({"schema_version": "VSTD-DOMAIN-POLICY-1", "mechanism_digest": implementation_digest(),
        "trust_roots": trust_roots, "witness_keys": {} if witness_keys is None else witness_keys, "max_operations": max_operations,
        "max_items": max_items, "max_evidence_bytes": max_evidence_bytes, "max_tolerance": max_tolerance})


def _policy(value: Any) -> dict:
    value = obj(_snapshot(value), {"schema_version", "mechanism_digest", "trust_roots", "witness_keys",
                                  "max_operations", "max_items", "max_evidence_bytes", "max_tolerance"})
    same(value["schema_version"], "VSTD-DOMAIN-POLICY-1", "unsupported domain policy")
    _hash(value["mechanism_digest"])
    roots = value["trust_roots"]
    if type(roots) is not list or not roots or any(not isinstance(r,str) or not r.strip() for r in roots) or len(set(roots)) != len(roots):
        raise ValueError("distinct explicit trust roots required")
    integer(value["max_operations"], 1, 10000000)
    integer(value["max_items"], 1, 100000)
    integer(value["max_evidence_bytes"], 1, MAX_BYTES//2)
    if not 0 <= number(value["max_tolerance"]) <= 1e-4:
        raise ValueError("checker numerical tolerance outside supported range")
    for key, encoded in obj(value["witness_keys"]).items():
        text(key)
        if not isinstance(encoded,str) or not re.fullmatch(r"[0-9a-f]{64}", encoded):
            raise ValueError("witness public key must contain 32 hex-encoded bytes")
    return value


def domain_request(evidence: dict, *, target_depth: int | None = None) -> dict:
    """Bind a consumer-selected subject, artifact and complete evidence inventory."""
    bundle = _bundle(evidence)
    domain = bundle["domain"]
    return _request({"schema_version": "VSTD-DOMAIN-REQUEST-1", "domain": domain,
        "subject_id": bundle["subject_id"], "artifact_digest": digest(bundle["artifact"]),
        "evidence_ref": digest(bundle), "target_depth": len(CHECKS[domain]) if target_depth is None else target_depth})


def _request(value: Any) -> dict:
    value = obj(_snapshot(value), {"schema_version", "domain", "subject_id", "artifact_digest", "evidence_ref", "target_depth"})
    same(value["schema_version"], "VSTD-DOMAIN-REQUEST-1", "unsupported domain request")
    if value["domain"] not in CHECKS:
        raise ValueError("unknown domain")
    text(value["subject_id"])
    _hash(value["artifact_digest"])
    _hash(value["evidence_ref"])
    integer(value["target_depth"], 1, len(CHECKS[value["domain"]]))
    return value


def _bundle(value: Any) -> dict:
    value = obj(_snapshot(value), {"schema_version", "domain", "subject_id", "artifact", "inputs"})
    same(value["schema_version"], "VSTD-DOMAIN-EVIDENCE-1", "unsupported domain evidence")
    if value["domain"] not in CHECKS:
        raise ValueError("unknown domain")
    text(value["subject_id"])
    for field, allowed in (("artifact", _ARTIFACT_FIELDS), ("inputs", _INPUT_FIELDS)):
        if set(obj(value[field])) - set(allowed[value["domain"]].split()):
            raise ValueError("unsupported domain evidence field")
    return value


class NativeDomainAdapter:
    """Executable mechanism for one domain; registration supplies no implicit authority."""

    def __init__(self, domain: str, policy: dict) -> None:
        if domain not in CHECKS:
            raise ValueError("unknown domain")
        self.domain = domain
        self.policy = _policy(policy)
        self.mechanism_id = "vstd.native-domain."+domain.lower()+".1"
        self.mechanism_digest = implementation_digest()

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        try:
            if len(evidence) != 1 or binding.expected is not True:
                raise Refuted("one retained bundle and the exact positive proposition required")
            same(list(binding.trust_roots), sorted(self.policy["trust_roots"]), "trust roots differ")
            same(self.policy["mechanism_digest"], self.mechanism_digest, "mechanism not admitted by policy")
            bundle = _bundle(strict_json_loads(evidence[0].decode("utf-8")))
            same(bundle["subject_id"], binding.subject_id, "subject differs")
            same(bundle["domain"], self.domain, "domain differs")
            same(digest(bundle["artifact"]), binding.parameters["artifact_digest"], "artifact differs")
            same(digest(self.policy), binding.parameters["policy_digest"], "checker policy differs")
            names = dict((f"{self.domain}.{i}", c[0]) for i,c in enumerate(CHECKS[self.domain],1))
            if binding.predicate not in names:
                raise Unavailable("unsupported domain predicate")
            budget = Budget(self.policy["max_operations"], self.policy["max_items"])
            inspect_structure(bundle, budget)
            artifact = bundle["artifact"]
            numerical_contracts = [artifact] if self.domain in ("HYPER", "MODEL", "SIM") else []
            if self.domain == "BENCH":
                numerical_contracts = [p.get("specification", {}) for p in artifact.get("problems", [])
                                       if isinstance(p,dict) and p.get("kind") == "linear-system"]
            for contract in numerical_contracts:
                if "tolerance" in contract:
                    tolerance = number(contract["tolerance"])
                    if tolerance < 0:
                        raise Refuted("negative numerical tolerance")
                    if tolerance > self.policy["max_tolerance"]:
                        raise Unavailable("requested numerical tolerance exceeds checker policy")
            module = import_module("verifier.domains."+self.domain.lower())
            kwargs = {"witness_keys": self.policy["witness_keys"]} if self.domain == "SIM" else {}
            if self.domain in ("AGENT", "BOT"):
                kwargs = {"mechanism_digest": self.mechanism_digest}
            observed = module.evaluate(names[binding.predicate], artifact, bundle["inputs"], budget, **kwargs)
            observed["operations"] = budget.used
            return MechanismDecision(MechanismOutcome.PASS, "bound domain computation reproduced", observed)
        except Unavailable as exc:
            return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
        except (Refuted, ValueError, TypeError, KeyError, IndexError, ArithmeticError, UnicodeError) as exc:
            return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def build_domain_certificate(request: dict, evidence: dict, *, policy: dict) -> dict:
    """Execute every requested prerequisite with content-addressed evidence."""
    request, bundle, policy = _request(request), _bundle(evidence), _policy(policy)
    same(domain_request(bundle, target_depth=request["target_depth"]), request, "evidence does not match intended request")
    same(policy["mechanism_digest"], implementation_digest(), "checker implementation not admitted")
    payload = canonical_bytes(bundle)
    store = EvidenceStore()
    ref = store.add(payload)
    session = VerificationSession(store)
    adapter = NativeDomainAdapter(request["domain"], policy)
    session.register(adapter)
    rows, depth, holds = {}, 0, set()
    for i, (name, statement, depends) in enumerate(CHECKS[request["domain"]][:request["target_depth"]], 1):
        coordinate = f"{request['domain']}.{i}"
        proposition = BoundProposition(subject_id=request["subject_id"], predicate=coordinate, expected=True,
            mechanism_id=adapter.mechanism_id, mechanism_digest=adapter.mechanism_digest, evidence_refs=(ref,),
            trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, policy["max_evidence_bytes"]),
            parameters={"artifact_digest": request["artifact_digest"], "policy_digest": digest(policy), "request_digest": digest(request)})
        evaluated = session.evaluate(proposition).to_dict()
        blocked = [f"{request['domain']}.{d}" for d in depends if d not in holds]
        established = not blocked and evaluated["outcome"] == "PASS"
        if established:
            holds.add(i)
            if depth == i-1:
                depth = i
        rows[coordinate] = {"name": name, "proposition": statement, "established": established,
                            "blocked_by": blocked, "evaluation": evaluated}
    outcomes = [r["evaluation"]["outcome"] for r in rows.values()]
    status = "FAIL" if "FAIL" in outcomes else "UNKNOWN" if "UNKNOWN" in outcomes else "PASS"
    result = {"status": status, "domain_depth": depth, "scope": SCOPES[request["domain"]],
              "object_profile_conformance": "NOT_ESTABLISHED", "checks": rows}
    certificate = {"schema_version": "VSTD-DOMAIN-CERTIFICATION-1", "request": request, "evidence": bundle,
                   "policy_digest": digest(policy), "mechanism_digest": adapter.mechanism_digest,
                   "specification_digest": "sha256:"+domain_specification_digest(), "result": result}
    certificate["certificate_digest"] = digest(certificate)
    return _snapshot(certificate)


def recheck_domain_certificate(certificate: dict, *, expected_request: dict, policy: dict) -> dict:
    """Replay against external intent; return REJECTED for substitution or forged output."""
    try:
        certificate = obj(_snapshot(certificate), {"schema_version", "request", "evidence", "policy_digest",
            "mechanism_digest", "specification_digest", "result", "certificate_digest"})
        same(certificate["request"], _request(expected_request), "certificate request differs from consumer intent")
        reproduced = build_domain_certificate(expected_request, certificate["evidence"], policy=policy)
        same(certificate, reproduced, "certificate does not reproduce under checker policy")
        return reproduced["result"]
    except (ValueError, TypeError, KeyError, ArithmeticError, RecursionError) as exc:
        return {"status": "REJECTED", "reason": str(exc), "domain_depth": 0, "object_profile_conformance": "NOT_ESTABLISHED"}
