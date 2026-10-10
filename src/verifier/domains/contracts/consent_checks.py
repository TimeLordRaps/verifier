"""Current exact-object, selected-holder consent certificates and replay.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Coordinated Universal Time (UTC). Times are integer
UTC Unix seconds. Byte limits count encoded bytes; other counts are dimensionless.
Configured authority is not real-world ownership, voluntary consent or enforcement.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any

from verifier.consent import engine, public, stages
from verifier.core import certificate as certificate_module, namespace, receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains import common
from verifier.domains.contracts import retained_selection

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-consent-checks-request-1"
POLICY_VERSION = "verifier-current-consent-checks-policy-1"
EVIDENCE_VERSION = "verifier-current-consent-checks-evidence-1"
CERTIFICATE_VERSION = "verifier-current-consent-checks-certificate-1"
MECHANISM_ID = "verifier.current-object.selected-holder-consent.1"
_CEILINGS = {"max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_holder_evaluations": 16,
    "max_evidence_bytes": 4 * 1024 * 1024, "max_payload_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_CLAIMS = {1: "authenticated terminal action scope", 2: "configured holder and statement authority",
    3: "trusted-time validity and authorized revocation", 4: "nonwidening delegation with authority and validity",
    5: "exact retained stage reproduction without admission promotion",
    6: "consent independence from the five computational verdict inputs"}


class ConsentChecksError(ValueError):
    """Malformed selection, unsupported contract or known certificate substitution."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, ConsentChecksError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, ConsentChecksError)


def _digest(value: Any) -> str:
    return "sha256:" + canonical_digest(value)


def coordinate(kind: str, stage: int) -> str:
    if type(kind) is not str or kind not in {item.value for item in ObjectKind}:
        raise ConsentChecksError("admitted exact object kind required")
    if type(stage) is not int or stage not in _CLAIMS:
        raise ConsentChecksError("consent stage must be one through six")
    return kind + "-7." + str(stage)


def registration(kind: str, stage: int) -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": coordinate(kind, stage),
        "subject_kind": kind, "scope": "selected_holder_consent_7_" + str(stage),
        "proposition": "For every independently selected required holder of the exact " + kind
            + " record in the selected typed collection, check " + _CLAIMS[stage] + ".",
        "prerequisites": ["selected full subject and collection", "selected holder set, policies, action, time and evidence"],
        "exclusions": ["holder-set completeness or real-world authority", "voluntary human consent or legal rights",
            "clock or registry authenticity", "execution or emission permission", "whole-tier or object-profile conformance"]}


@dataclass(frozen=True)
class ConsentDescriptor:
    """Immutable kind and stage selection for native public routing."""
    kind: str
    stage: int
    CERTIFICATE_VERSION = CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return _digest(registration(self.kind, self.stage))


def mechanism_digest() -> str:
    modules = (certificate_module, namespace, receipt_module, common, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_CONSENT_CHECKS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return _digest({"sources": {name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())}, "native_stages": stages.mechanism_digest()})


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(engine._capture_plain(value), {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes", "required_holders"}, "policy")
    base = {key: item for key, item in selected.items() if key != "required_holders"}
    retained_selection.policy(base, error_type=ConsentChecksError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)
    holders = selected["required_holders"]
    if type(holders) is not list or not 1 <= len(holders) <= 16:
        raise ConsentChecksError("nonempty bounded independently selected holders required")
    names = []
    for row in holders:
        holder = _record(row, {"holder_id", "public_policy"}, "holder")
        names.append(engine._text(holder["holder_id"]))
        admitted, _ = public._capture_policy(holder["public_policy"])
        if admitted is None or admitted.grantor_id != holder["holder_id"]:
            raise ConsentChecksError("holder differs from independently selected public policy")
    if names != sorted(set(names)):
        raise ConsentChecksError("required holders must be sorted and unique")
    return selected


def consent_checks_policy(*, trust_roots: list[str], required_holders: list[dict[str, Any]],
                          max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes, "required_holders": required_holders})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(engine._capture_plain(value), {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "stage", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "action", "evaluation_time", "computational_verdict",
        "historical_receipts", "limits"}, "request")
    kind, stage = selected["object_kind"], selected["stage"]
    expected = {"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(kind, stage), "proposition_digest": _digest(registration(kind, stage))}
    if any(type(selected[key]) is not str or selected[key] != item for key, item in expected.items()):
        raise ConsentChecksError("selected consent objective differs")
    for key in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(selected[key])
    engine._text(selected["subject_id"])
    action = _record(selected["action"], {"operation", "actor_id", "observer_id", "purpose", "timestamp"}, "action")
    for key in ("operation", "actor_id", "observer_id", "purpose"):
        engine._text(action[key])
    engine._time(action["timestamp"])
    if selected["evaluation_time"] is not None:
        engine._time(selected["evaluation_time"])
    if type(selected["computational_verdict"]) is not str or selected["computational_verdict"] not in stages._VERDICTS:
        raise ConsentChecksError("unsupported computational verdict")
    history = selected["historical_receipts"]
    if type(history) is not dict or len(history) > 16:
        raise ConsentChecksError("bounded historical receipt selection required")
    for name, commitment in history.items():
        engine._text(name); _hash(commitment)
    if stage != 5 and history:
        raise ConsentChecksError("historical receipt selection belongs to reproduction only")
    selected["limits"] = retained_selection.limits(selected["limits"], _CEILINGS, ConsentChecksError)
    return selected


def consent_checks_request(*, object_kind: str, stage: int, subject_id: str, object_digest: str,
                           collection_digest: str, evidence_ref: str, action: dict[str, Any],
                           evaluation_time: int | None, computational_verdict: str,
                           historical_receipts: dict[str, str], policy: dict[str, Any],
                           limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise ConsentChecksError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(object_kind, stage), "proposition_digest": _digest(registration(object_kind, stage)),
        "object_kind": object_kind, "stage": stage, "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "evidence_ref": evidence_ref, "policy_digest": _digest(admitted),
        "action": action, "evaluation_time": evaluation_time, "computational_verdict": computational_verdict,
        "historical_receipts": historical_receipts, "limits": {**_CEILINGS, **(limits or {})}})


def _context(request: dict[str, Any]) -> engine.ConsentContext:
    return engine.ConsentContext(object_name=request["subject_id"], artifact_digest=request["object_digest"][7:],
        **request["action"])


def _inputs(row: dict[str, Any] | None, request: dict[str, Any], holder: dict[str, Any]) -> dict[str, Any]:
    return {"context": _context(request), "grants": tuple(row["grants"]) if row is not None else (),
        "policy": holder["public_policy"], "revocation": row["revocation"] if row is not None else None,
        "evaluation_time": request["evaluation_time"], "computational_verdict": request["computational_verdict"]}


def _combine(values: list[str]) -> str:
    return "FAIL" if "FAIL" in values else "UNKNOWN" if not values or "UNKNOWN" in values else "PASS"


def _result(request: dict[str, Any], holders: dict[str, Any], *, status: str | None = None,
            reason: str = "selected holder predicates evaluated") -> dict[str, Any]:
    values = [row["retained_replay"] if request["stage"] == 5 else
        row["receipt"]["stages"]["7." + str(request["stage"])]["status"] for row in holders.values()]
    return {"status": status or _combine(values), "reason": reason,
        "semantic_version": SEMANTIC_VERSION, "coordinate": request["coordinate"],
        "object_kind": request["object_kind"], "scope": registration(request["object_kind"], request["stage"])["scope"],
        "holder_results": holders, "admission_status": _combine([row["receipt"]["admission_status"] for row in holders.values()]),
        "selected_computational_verdict": request["computational_verdict"],
        "object_profile_conformance": "NOT_ESTABLISHED", "enforcement": "NOT_ESTABLISHED",
        "holder_set_completeness": "NOT_ESTABLISHED", "real_world_authority": "NOT_ESTABLISHED"}


def _evaluate(data: bytes | None, request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    limits = request["limits"]
    try:
        if data is None:
            raise common.Unavailable("retained consent evidence absent")
        if len(data) > limits["max_evidence_bytes"]:
            raise common.Unavailable("selected evidence byte bound exhausted")
        value = _record(strict_json_loads(data.decode("utf-8")), {"schema_version", "objects", "holders"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise ConsentChecksError("canonical evidence version differs")
        budget = common.Budget(limits["max_operations"])
        common.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise ConsentChecksError("retained namespace collection required")
        if len(rows) > limits["max_objects"]:
            raise common.Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            item = NamespaceObject.create(**_record(row, {"object_id", "kind", "payload", "operands"}, "namespace record"))
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise ConsentChecksError("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [item for item in objects if item.object_id == request["subject_id"]]
        if len(matches) != 1 or matches[0].kind.value != request["object_kind"] or matches[0].digest != request["object_digest"]:
            raise ConsentChecksError("selected exact namespace subject differs")
        composition = namespace.assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_reference_bytes=limits["max_reference_bytes"], max_payload_bytes=limits["max_payload_bytes"])
        if composition.verdict.value != "PASS":
            return _result(request, {}, status=composition.verdict.value, reason=composition.reason)
        selected = policy["required_holders"]
        if len(selected) > limits["max_holder_evaluations"]:
            raise common.Unavailable("selected holder evaluation bound exhausted")
        retained = value["holders"]
        names = {row["holder_id"] for row in selected}
        if type(retained) is not dict or any(type(key) is not str for key in retained) or set(retained) - names:
            raise ConsentChecksError("retained holder inventory differs from independent selection")
        if request["stage"] == 5 and set(request["historical_receipts"]) != names:
            raise ConsentChecksError("historical receipt selection must cover all selected holders")
        results = {}
        for holder in selected:
            budget.tick()
            name = holder["holder_id"]
            row = retained.get(name)
            if row is not None:
                row = _record(row, {"grants", "revocation", "receipt"}, "holder evidence")
                if type(row["grants"]) is not list or len(row["grants"]) > 16:
                    raise ConsentChecksError("bounded ordered grant list required")
                if request["stage"] != 5 and row["receipt"] is not None:
                    raise ConsentChecksError("historical receipt supplied to a different objective")
            chosen = _inputs(row, request, holder)
            evaluation = stages.evaluate_consent_stages(**chosen)
            reproduction = None
            if request["stage"] == 5:
                historical = row["receipt"] if row is not None else None
                if historical is None:
                    reproduction = "UNKNOWN"
                elif _digest(historical) != request["historical_receipts"][name]:
                    reproduction = "FAIL"
                else:
                    reproduction = stages.recheck_consent_stages(historical, **chosen)["reproduction_status"]
            results[name] = {"receipt": evaluation, "retained_replay": reproduction}
        return _result(request, results)
    except common.Unavailable as exc:
        return _result(request, {}, status="UNKNOWN", reason=str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return _result(request, {}, status="FAIL", reason=str(exc))


def _selection(request: Any, policy: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    selected, admitted = _request(request), _policy(policy)
    if selected["policy_digest"] != _digest(admitted):
        raise ConsentChecksError("selected policy differs from request")
    return selected, admitted


def _envelope(request: dict[str, Any], policy: dict[str, Any], data: bytes | None) -> dict[str, Any]:
    if data is not None and "sha256:" + hashlib.sha256(data).hexdigest() != request["evidence_ref"]:
        raise ConsentChecksError("retained evidence differs from selected commitment")
    value = {"schema_version": CERTIFICATE_VERSION, "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"], "proposition_digest": request["proposition_digest"],
        "evidence": data.decode("utf-8") if data is not None else None, "result": _evaluate(data, request, policy)}
    value["digest"] = _digest(value)
    return value


def build_consent_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                     *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _selection(request, policy)
    if evidence_bytes is not None and (type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
        raise ConsentChecksError("bounded immutable evidence required")
    encoded = canonical_bytes(_envelope(selected, admitted, evidence_bytes))
    if len(encoded) > admitted["max_certificate_bytes"]:
        raise ConsentChecksError("selected certificate byte bound exhausted")
    return encoded


def recheck_consent_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _selection(expected_request, policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ConsentChecksError("bounded immutable certificate required")
    value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest",
        "mechanism_digest", "proposition_digest", "evidence", "result", "digest"}, "certificate")
    if canonical_bytes(value) != certificate_bytes or value["digest"] != _digest({key: item for key, item in value.items() if key != "digest"}):
        raise ConsentChecksError("canonical certificate digest differs")
    if canonical_bytes(value["request"]) != canonical_bytes(selected):
        raise ConsentChecksError("certificate differs from independently selected request")
    data = value["evidence"]
    if data is not None and (type(data) is not str or len(data.encode("utf-8")) > _CEILINGS["max_evidence_bytes"]):
        raise ConsentChecksError("retained evidence must be bounded exact text")
    rebuilt = _envelope(selected, admitted, data.encode("utf-8") if data is not None else None)
    if canonical_bytes(rebuilt) == certificate_bytes:
        return {**rebuilt["result"], "certificate_replay_status": "REPRODUCED"}
    # Availability cannot excuse a changed subject, policy, evidence or envelope.
    ignored = {"result", "digest"}
    if canonical_bytes({k: v for k, v in value.items() if k not in ignored}) != canonical_bytes({k: v for k, v in rebuilt.items() if k not in ignored}):
        raise ConsentChecksError("certificate identity differs")
    carried, current = value["result"], rebuilt["result"]
    if type(carried) is not dict or set(carried) != set(current) or not current["holder_results"]:
        raise ConsentChecksError("certificate result does not reproduce")
    rows = carried["holder_results"]
    if type(rows) is not dict or set(rows) != set(current["holder_results"]):
        raise ConsentChecksError("carried holder coverage differs")
    if canonical_bytes(carried) != canonical_bytes(_result(selected, rows)):
        raise ConsentChecksError("carried result does not match its distinct predicates")
    evidence = strict_json_loads(data)["holders"]
    unavailable = False
    for holder in admitted["required_holders"]:
        name = holder["holder_id"]
        row = _record(rows[name], {"receipt", "retained_replay"}, "carried holder")
        chosen = _inputs(evidence.get(name), selected, holder)
        checked = stages.recheck_consent_stages(row["receipt"], **chosen)
        if checked["replay_status"] == "REJECTED":
            raise ConsentChecksError("carried holder stage result is substituted")
        unavailable |= checked["replay_status"] == "UNAVAILABLE"
        if selected["stage"] != 5:
            if row["retained_replay"] is not None:
                raise ConsentChecksError("unexpected retained reproduction status")
        elif row["retained_replay"] != current["holder_results"][name]["retained_replay"]:
            historical = evidence.get(name, {}).get("receipt")
            if (row["retained_replay"] not in ("PASS", "FAIL", "UNKNOWN") or historical is None
                    or _digest(historical) != selected["historical_receipts"][name]
                    or stages.recheck_consent_stages(historical, **chosen)["replay_status"] != "UNAVAILABLE"):
                raise ConsentChecksError("historical reproduction result differs")
            unavailable = True
    if not unavailable:
        raise ConsentChecksError("certificate does not reproduce exactly")
    return {**current, "status": "UNKNOWN", "certificate_replay_status": "UNAVAILABLE"}
