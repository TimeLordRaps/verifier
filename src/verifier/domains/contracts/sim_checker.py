"""Current VERIFIER dynamics: bounded native Simulation (SIM) checker correspondence.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8). Counts are
dimensionless, byte limits count encoded bytes, and model quantities retain their
declared units. Finite outcome correspondence is not class-wide checker soundness.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import Path
import re
import sys
from typing import Any, Sequence

from verifier.core import signature_keys
from verifier.core import certificate as certificate_module, evidence as evidence_module, receipt as receipt_module, namespace as namespace_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession
from verifier.core.receipt import strict_json_loads
from verifier.domains import common, sim
from verifier.domains.common import Budget, Refuted, Unavailable


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "VERIFIER-2.1"
REQUEST_VERSION = "verifier-current-sim-checker-request-1"
POLICY_VERSION = "verifier-current-sim-checker-policy-1"
EVIDENCE_VERSION = "verifier-current-sim-checker-cases-1"
CERTIFICATE_VERSION = "verifier-current-sim-checker-certificate-1"
MECHANISM_ID = "verifier.current-object.native-sim-checker-dynamics.1"
CHECKER = "verifier.domains.sim.evaluate"
CHECKS = ("replay", "invariants", "refinement", "channels", "shards")
PROPOSITION = (
    "For the independently selected installed native simulation checker, exact finite "
    "input cases, check names, expected outcomes and resource bounds, every selected "
    "invocation reproduces its selected positive result or explicit refutation."
)
REGISTRATION = {
    "schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
    "coordinate": COORDINATE, "subject_kind": "VERIFIER", "proposition": PROPOSITION,
    "scope": "finite_native_sim_checker_outcome_correspondence",
    "prerequisites": ["independently selected exact inputs and expected outcomes", "admitted installed checker and runtime"],
    "exclusions": ["class-wide soundness", "arbitrary checker execution", "historical execution",
                   "effect confinement", "public checkability", "whole tier or object profile conformance"],
}
PROPOSITION_DIGEST = "sha256:" + canonical_digest(REGISTRATION)
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_BYTES = 4 * 1024 * 1024
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
DEFAULT_LIMITS = {"max_evidence_bytes": _MAX_BYTES, "max_total_operations": 1_000_000,
                  "max_items": 4096, "max_capture_nodes": 100_000, "max_expectations": 128}


class SimCheckerError(ValueError):
    """External selection is malformed, incompatible or substituted."""


def _capture(value: Any, *, nodes: int = 100_000, byte_limit: int = _MAX_BYTES) -> Any:
    """Capture only bounded plain values without invoking user-defined copy hooks."""
    count = size = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> Any:
        nonlocal count, size
        count += 1
        if count > nodes or depth > 48:
            raise Unavailable("capture structural bound exhausted")
        kind = type(item)
        if item is None or kind is bool:
            return item
        if kind is int:
            if item.bit_length() > 4096:
                raise Unavailable("capture integer bound exhausted")
            return item
        if kind is float:
            if not math.isfinite(item):
                raise SimCheckerError("nonfinite selection or evidence")
            return item
        if kind is str:
            if len(item) > byte_limit - size:
                raise Unavailable("capture text bound exhausted")
            size += len(item.encode("utf-8"))
            if size > byte_limit:
                raise Unavailable("capture text bound exhausted")
            return item
        if kind not in (dict, list) or id(item) in active:
            raise SimCheckerError("bounded acyclic plain JSON values required")
        if len(item) > 4096:
            raise Unavailable("capture collection bound exhausted")
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            if any(type(key) is not str for key in item):
                raise SimCheckerError("plain text keys required")
            return {visit(key, depth + 1): visit(child, depth + 1) for key, child in item.items()}
        finally:
            active.remove(id(item))

    return visit(value, 0)


def _shape(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise SimCheckerError(label + " fields differ")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value.encode("utf-8")) > 256:
        raise SimCheckerError("bounded nonblank plain text required")
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        raise SimCheckerError("canonical SHA-256 digest required")
    return value


def _integer(value: Any, ceiling: int) -> int:
    if type(value) is not int or not 1 <= value <= ceiling:
        raise SimCheckerError("positive integer exceeds checker limit")
    return value


def mechanism_digest() -> str:
    """Bind installed code, specification and the selected interpreter version."""
    modules = (common, sim, certificate_module, evidence_module, receipt_module, namespace_module, signature_keys)
    files = {module.__name__: Path(module.__file__) for module in modules}
    files[__name__] = Path(__file__)
    files["CURRENT_SIM_CHECKER.md"] = Path(__file__).parents[2]/"standard/CURRENT_SIM_CHECKER.md"
    return common.digest({"sources": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                                      for name, path in sorted(files.items())},
                          "runtime": {"implementation": sys.implementation.name,
                                      "version": list(sys.version_info[:3]), "byteorder": sys.byteorder}})


def _policy(value: Any) -> dict:
    selected = _shape(value, {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "policy")
    if selected["schema_version"] != POLICY_VERSION or selected["mechanism_id"] != MECHANISM_ID:
        raise SimCheckerError("unsupported checker policy")
    roots = selected["trust_roots"]
    if type(roots) is not list or not 1 <= len(roots) <= 16:
        raise SimCheckerError("bounded trust-root list required")
    for root in roots:
        _text(root)
    if roots != sorted(set(roots)):
        raise SimCheckerError("trust roots must be sorted and unique")
    _integer(selected["max_certificate_bytes"], _MAX_CERTIFICATE_BYTES)
    if _digest(selected["mechanism_digest"]) != mechanism_digest():
        raise SimCheckerError("policy does not admit the installed checker mechanism")
    return selected


def sim_checker_policy(*, trust_roots: Sequence[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict:
    """Format local policy; root labels do not authenticate their issuer."""
    if type(trust_roots) not in (list, tuple) or not 1 <= len(trust_roots) <= 16:
        raise SimCheckerError("bounded plain trust-root sequence required")
    selected = _capture({"trust_roots": list(trust_roots), "max_certificate_bytes": max_certificate_bytes})
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
                    "mechanism_digest": mechanism_digest(), **selected})


def _request(value: Any) -> dict:
    selected = _shape(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "object_id",
        "object_digest", "checker", "evidence_digest", "expectations", "policy_digest", "limits"}, "request")
    for key, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                          ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST), ("checker", CHECKER)):
        if type(selected[key]) is not str or selected[key] != expected:
            raise SimCheckerError("unsupported selected checker proposition")
    _text(selected["object_id"])
    _digest(selected["object_digest"])
    _digest(selected["evidence_digest"])
    _digest(selected["policy_digest"])
    limits = _shape(selected["limits"], set(DEFAULT_LIMITS), "limits")
    for name, ceiling in DEFAULT_LIMITS.items():
        _integer(limits[name], ceiling)
    rows = selected["expectations"]
    if type(rows) is not list or not 1 <= len(rows) <= 128:
        raise SimCheckerError("nonempty bounded expected invocation list required")
    seen: set[tuple[str, str]] = set()
    for row in rows:
        _shape(row, {"case_id", "check", "input_digest", "expected", "max_operations"}, "expectation")
        _text(row["case_id"])
        if type(row["check"]) is not str or row["check"] not in CHECKS:
            raise SimCheckerError("unsupported native simulation check")
        pair = (row["case_id"], row["check"])
        if pair in seen:
            raise SimCheckerError("duplicate expected invocation")
        seen.add(pair)
        _digest(row["input_digest"])
        _integer(row["max_operations"], 1_000_000)
        outcome = row["expected"]
        if type(outcome) is not dict:
            raise SimCheckerError("expected outcome object required")
        if outcome.get("status") == "PASS":
            _shape(outcome, {"status", "result"}, "expected positive outcome")
            result = _shape(outcome["result"], {"states", "transitions"}, "expected native result")
            for count in result.values():
                _integer(count, 4096)
        elif outcome.get("status") == "FAIL":
            _shape(outcome, {"status", "reason"}, "expected refutation")
            _text(outcome["reason"])
        else:
            raise SimCheckerError("expected outcomes require a positive result or explicit refutation")
    return selected


def sim_checker_request(*, object_id: str, object_digest: str, evidence_digest: str, expectations: list[dict],
                        policy: dict, limits: dict | None = None) -> dict:
    """Bind independently supplied expectations; never derive them by running cases."""
    captured = _capture({"object_id": object_id, "object_digest": object_digest, "evidence_digest": evidence_digest,
                         "expectations": expectations, "policy": policy,
                         "limits": DEFAULT_LIMITS if limits is None else limits})
    admitted = _policy(captured.pop("policy"))
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST, "checker": CHECKER,
        "policy_digest": common.digest(admitted), **captured})


def _selection(request: dict, policy: dict) -> tuple[dict, dict]:
    captured = _capture({"request": request, "policy": policy})
    selected = _request(captured["request"])
    admitted = _policy(captured["policy"])
    if selected["policy_digest"] != common.digest(admitted):
        raise SimCheckerError("request does not bind the independently selected policy")
    return selected, admitted


def _binding(request: dict, policy: dict) -> BoundProposition:
    return BoundProposition(subject_id=request["object_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_digest"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": common.digest(request), "proposition_digest": PROPOSITION_DIGEST})


class _SimCheckerMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict, policy: dict) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        observations: list[dict] = []
        try:
            request, limits = self.request, self.request["limits"]
            if canonical_bytes(binding.to_dict()) != canonical_bytes(_binding(request, self.policy).to_dict()):
                raise Refuted("selected checker proposition differs")
            if len(evidence) != 1:
                raise Unavailable("one exact finite checker case set is required")
            raw = evidence[0]
            suite = _capture(strict_json_loads(raw.decode("utf-8")), nodes=limits["max_capture_nodes"])
            _shape(suite, {"schema_version", "checker_object", "cases"}, "case set")
            if suite["schema_version"] != EVIDENCE_VERSION or canonical_bytes(suite) != raw:
                raise Refuted("case set version or canonical bytes differ")
            record = _shape(suite["checker_object"], {"object_id", "kind", "payload", "operands"}, "checker object")
            item = namespace_module.NamespaceObject.create(**record)
            if (canonical_bytes(item.to_dict()) != canonical_bytes(record)
                    or item.object_id != request["object_id"] or item.digest != request["object_digest"]):
                raise Refuted("checker object differs from independently selected record")
            if (record["kind"] != "VERIFIER" or record["operands"] != {}
                    or record["payload"] != {"checker_kind": "CHECKER", "checker": CHECKER,
                                             "mechanism_digest": self.policy["mechanism_digest"]}):
                raise Refuted("checker object does not describe the selected installed mechanism")
            cases = suite["cases"]
            if type(cases) is not dict or set(cases) != {row["case_id"] for row in request["expectations"]}:
                raise Refuted("retained case inventory differs from selected invocations")
            if len(request["expectations"]) > limits["max_expectations"]:
                raise Unavailable("selected invocation count bound exhausted")
            for row in request["expectations"]:
                case = _shape(cases[row["case_id"]], {"artifact", "inputs"}, "native input")
                if type(case["artifact"]) is not dict or type(case["inputs"]) is not dict:
                    raise Refuted("native input requires artifact and inputs objects")
                if common.digest(case) != row["input_digest"]:
                    raise Refuted("native case differs from independently selected input")
            remaining = limits["max_total_operations"]
            status = MechanismOutcome.PASS
            for row in request["expectations"]:
                if remaining <= 0:
                    if status is MechanismOutcome.PASS:
                        status = MechanismOutcome.UNKNOWN
                    break
                case = cases[row["case_id"]]
                budget = Budget(min(row["max_operations"], remaining), max_items=limits["max_items"])
                try:
                    native = sim.evaluate(row["check"], case["artifact"], case["inputs"], budget, witness_keys={})
                    if type(native) is not dict or set(native) != {"states", "transitions"}:
                        raise Unavailable("native checker returned an unsupported result")
                    if any(type(v) is not int or v < 1 for v in native.values()):
                        raise Unavailable("native checker returned invalid counts")
                    outcome = {"status": "PASS", "result": native}
                except Refuted as exc:
                    outcome = {"status": "FAIL", "reason": str(exc)}
                except (Unavailable, ArithmeticError, ValueError, KeyError, TypeError, RecursionError) as exc:
                    outcome = {"status": "UNKNOWN", "reason": str(exc)}
                remaining -= budget.used
                observations.append({"case_id": row["case_id"], "check": row["check"],
                    "input_digest": row["input_digest"], "outcome": outcome, "operations_used": budget.used})
                if outcome["status"] == "UNKNOWN":
                    if status is MechanismOutcome.PASS:
                        status = MechanismOutcome.UNKNOWN
                elif canonical_bytes(outcome) != canonical_bytes(row["expected"]):
                    status = MechanismOutcome.FAIL
            return MechanismDecision(status, "finite selected native checker outcomes compared", {"cases": observations})
        except Unavailable as exc:
            return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc), {"cases": observations})
        except (ValueError, KeyError, TypeError, UnicodeError, RecursionError) as exc:
            return MechanismDecision(MechanismOutcome.FAIL, str(exc), {"cases": observations})


def _build(request: dict, policy: dict, store: EvidenceStore) -> bytes:
    session = VerificationSession(store)
    session.register(_SimCheckerMechanism(request, policy))
    evaluation = session.evaluate(_binding(request, policy))
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_id": request["object_id"], "object_digest": request["object_digest"], "checker": CHECKER,
        "scope": REGISTRATION["scope"], "observations": evaluation.observations.get("cases", []),
        "evaluation": evaluation.to_dict(),
        **{name: "NOT_ESTABLISHED" for name in ("class_wide_soundness", "historical_execution",
           "effect_confinement", "public_checkability", "object_profile_conformance", "authority")}}
    refs = [request["evidence_digest"]] if request["evidence_digest"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_digest"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = common.digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise SimCheckerError("certificate byte bound exhausted")
    return encoded


def build_sim_checker_certificate(request: dict, evidence_bytes: bytes | None, *, policy: dict) -> bytes:
    """Execute installed native code against the selected finite expected outcomes."""
    selected, admitted = _selection(request, policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _MAX_BYTES:
            raise SimCheckerError("immutable evidence bytes exceed transport bounds")
        if store.add(evidence_bytes) != selected["evidence_digest"]:
            raise SimCheckerError("retained evidence differs from external selection")
    return _build(selected, admitted, store)


def recheck_sim_checker_certificate(certificate_bytes: bytes, *, expected_request: dict, policy: dict) -> dict:
    """Rerun every selected invocation; a rehashed carried result is insufficient."""
    selected, admitted = _selection(expected_request, policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise SimCheckerError("certificate exceeds selected byte bound")
    try:
        value = _capture(strict_json_loads(certificate_bytes.decode("utf-8")), byte_limit=_MAX_CERTIFICATE_BYTES)
        envelope = _shape(value, {"schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(envelope) != certificate_bytes or envelope["schema_version"] != CERTIFICATE_VERSION:
            raise SimCheckerError("certificate version or canonical bytes differ")
        if envelope["digest"] != common.digest({k: v for k, v in envelope.items() if k != "digest"}):
            raise SimCheckerError("certificate digest differs")
        if canonical_bytes(envelope["request"]) != canonical_bytes(selected):
            raise SimCheckerError("certificate differs from independently selected request")
        if (envelope["policy_digest"] != common.digest(admitted)
                or envelope["mechanism_digest"] != admitted["mechanism_digest"]
                or envelope["proposition_digest"] != PROPOSITION_DIGEST
                or envelope["evidence_refs"] != [selected["evidence_digest"]]):
            raise SimCheckerError("certificate mechanism, policy or evidence binding differs")
        payloads = envelope["evidence_payloads"]
        if type(payloads) is not dict or set(payloads) - {selected["evidence_digest"]}:
            raise SimCheckerError("certificate payload inventory differs")
        if any(type(value) is not str for value in payloads.values()):
            raise SimCheckerError("certificate payload requires encoded text")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimCheckerError("selected native checker certificate did not reproduce")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, SimCheckerError):
            raise
        raise SimCheckerError("invalid native checker certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "PROPOSITION", "PROPOSITION_DIGEST", "sim_checker_policy",
           "sim_checker_request", "build_sim_checker_certificate", "recheck_sim_checker_certificate", "SimCheckerError"]
