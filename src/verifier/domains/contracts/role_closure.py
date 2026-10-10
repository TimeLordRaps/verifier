"""Current ROLE-4.1 exact selected decision/occupancy closure.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Declared clock microseconds are selected units, not observed physical timing.
This module changes no historical ROLE reader or whole-closure verdict.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, role_constraints, role_lifecycle
from verifier.domains.contracts import identity_occupancy

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "ROLE-4.1"
REQUEST_VERSION = "verifier-current-role-closure-request-1"
POLICY_VERSION = "verifier-current-role-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-role-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-role-closure-evidence-1"
MECHANISM_ID = "verifier.current-role.selected-decision-closure.1"
SCOPE = "finite_selected_role_point_decision_occupancy_closure"
_CEILINGS = {"max_decisions": 4096, "max_items": 4096, "max_operations": 1000000,
    "max_relation_steps": 100000, "max_child_operations": 9700000,
    "max_child_certificate_bytes": 16 * 1024 * 1024,
    "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024

class RoleClosureError(ValueError):
    """Malformed independent selection or nonreproducing carried certificate."""

class RoleClosureUnavailable(OSError):
    """Bounded recheck work unavailable; existing public route reports UNKNOWN."""

def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "ROLE", "scope": SCOPE,
        "proposition": "The complete independently selected finite timed occupancy/event and "
            "point-in-role decision inventories replay over one declared half-open clock period. "
            "Exact freshly rechecked ROLE-2.1 and inline ROLE-3.1 snapshots form a gapless "
            "nonempty occupancy-set partition; each exact inventoried decision belongs to one "
            "selected actor/identity in its interval, admitted scope and literal permission class.",
        "prerequisites": ["independent exact current ROLE/collection/clock/period selection",
            "fresh exact ROLE-2.1 replay including all selected inline ROLE-3.1 endpoint witnesses",
            "complete externally committed timed event and decision inventories",
            "installed policy/source/specification bytes and finite checker limits"],
        "exclusions": ["actual occurrence, real history completeness, physical clock or live occupancy",
            "authenticated authority, legal permission, human authenticity or actor independence",
            "delegation, personal acts or asynchronous decisions in flight across handover",
            "legacy ROLE closure, whole tier/profile conformance and other applicable .m objectives",
            "privacy, consent, governance, security or publication admission"]}

PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())

@dataclass(frozen=True)
class RoleClosureDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST

def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, RoleClosureError)

def _hash(value: Any) -> str:
    return retained_selection.commitment(value, RoleClosureError)

def _owned(value: Any, remaining: list[int] | None = None, depth: int = 0) -> Any:
    if remaining is None:
        remaining = [200000]
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 96:
        raise RoleClosureError("independent selection capture bound exhausted")
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise RoleClosureError("plain independent selection keys required")
        return {key:_owned(item, remaining, depth + 1) for key,item in value.items()}
    if type(value) is list:
        return [_owned(item, remaining, depth + 1) for item in value]
    if type(value) in (str, int, bool, type(None)):
        return value
    raise RoleClosureError("plain independent selection values required")

def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module, common_module,
        retained_selection, role_constraints, role_lifecycle, identity_occupancy)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["CURRENT_ROLE_DECISION_CLOSURE.md"] = Path(__file__).parents[2] / "standard" / "CURRENT_ROLE_DECISION_CLOSURE.md"
    paths["role_closure_evidence.json"] = Path(__file__).parents[2] / "schemas" / "role_closure_evidence.json"
    return "sha256:" + canonical_digest({"sources": {name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())}, "lifecycle_mechanism_digest": role_lifecycle.mechanism_digest()})

def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(_owned(value), error_type=RoleClosureError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)

def role_closure_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    trust_roots = _owned(trust_roots)
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})

def _instant(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise RoleClosureError("declared microsecond instant requires a bounded plain integer")
    return value

def _request(value: Any) -> dict[str, Any]:
    selected = _owned(_record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest", "collective_id",
        "clock_id", "clock_unit", "period_us", "endpoint_times_us", "lifecycle_request", "lifecycle_policy",
        "lifecycle_certificate_digest", "events_digest", "decisions_digest", "evidence_ref", "policy_digest", "limits"}, "request"))
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "ROLE"), ("proposition_digest", PROPOSITION_DIGEST),
        ("clock_unit", "microseconds")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise RoleClosureError("selected ROLE closure protocol differs")
    for field in ("subject_id", "collective_id", "clock_id"):
        role_constraints._text(selected[field])
    for field in ("object_digest", "collection_digest", "lifecycle_certificate_digest", "events_digest", "decisions_digest", "evidence_ref", "policy_digest"):
        _hash(selected[field])
    selected["limits"] = retained_selection.limits(selected["limits"], _CEILINGS, RoleClosureError)
    period = selected["period_us"]
    if type(period) is not list or len(period) != 2 or not _instant(period[0]) < _instant(period[1]):
        raise RoleClosureError("one nonempty selected half-open period required")
    selected["period_us"] = list(period)
    period = selected["period_us"]
    times = selected["endpoint_times_us"]
    if type(times) is not list or not 2 <= len(times) <= 16:
        raise RoleClosureError("two to sixteen independently selected endpoint times required")
    checked = [_instant(t) for t in times]
    if checked[0] != period[0] or checked[-1] >= period[1] or any(a >= b for a, b in zip(checked, checked[1:])):
        raise RoleClosureError("selected endpoint times do not partition the selected period")
    selected["endpoint_times_us"] = checked
    child = role_lifecycle._request(selected["lifecycle_request"])
    child_policy_input = _record(selected["lifecycle_policy"], {"schema_version", "mechanism_id",
        "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "lifecycle policy")
    if type(child_policy_input["trust_roots"]) is not list:
        raise RoleClosureError("plain selected child trust-root labels required")
    child_policy_input["trust_roots"] = list(child_policy_input["trust_roots"])
    child_policy = role_lifecycle._policy(child_policy_input)
    if (child["subject_id"] != selected["subject_id"] or child["object_digest"] != selected["object_digest"]
            or child["collection_digest"] != selected["collection_digest"]
            or child["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise RoleClosureError("lifecycle prerequisite differs from independently selected terminal ROLE")
    if len(checked) != len(child["endpoint_selections"]):
        raise RoleClosureError("one independently selected time per lifecycle endpoint required")
    selected["lifecycle_request"], selected["lifecycle_policy"] = child, child_policy
    return selected

def role_closure_request(*, subject_id: str, object_digest: str, collection_digest: str,
        collective_id: str, clock_id: str, period_us: list[int], endpoint_times_us: list[int],
        lifecycle_request: dict[str, Any], lifecycle_policy: dict[str, Any], lifecycle_certificate_digest: str,
        events_digest: str, decisions_digest: str, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    (subject_id, object_digest, collection_digest, collective_id, clock_id, period_us,
     endpoint_times_us, lifecycle_request, lifecycle_policy, lifecycle_certificate_digest,
     events_digest, decisions_digest, evidence_ref, policy, limits) = _owned([
        subject_id, object_digest, collection_digest, collective_id, clock_id, period_us,
        endpoint_times_us, lifecycle_request, lifecycle_policy, lifecycle_certificate_digest,
        events_digest, decisions_digest, evidence_ref, policy, limits])
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict or set(limits) - set(_CEILINGS)):
        raise RoleClosureError("unsupported ROLE closure limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST, "object_kind": "ROLE",
        "subject_id": subject_id, "object_digest": object_digest, "collection_digest": collection_digest,
        "collective_id": collective_id, "clock_id": clock_id, "clock_unit": "microseconds",
        "period_us": period_us, "endpoint_times_us": endpoint_times_us,
        "lifecycle_request": lifecycle_request, "lifecycle_policy": lifecycle_policy,
        "lifecycle_certificate_digest": lifecycle_certificate_digest,
        "events_digest": events_digest, "decisions_digest": decisions_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})

def _component(value: Any, expected: str, label: str) -> Any:
    if value is not None and "sha256:" + canonical_digest(value) != expected:
        raise Refuted(label + " differs from independently selected complete inventory")
    return value

def _names(value: Any, budget: common_module.Budget) -> list[str]:
    return role_constraints._strings(value, budget)

def _native_boundary(result: Any, module: Any, label: str) -> str:
    if (type(result) is not dict or type(result.get("status")) is not str
            or result["status"] not in ("PASS", "FAIL", "UNKNOWN")
            or result.get("object_kind") != "ROLE" or result.get("coordinate") != module.COORDINATE
            or result.get("semantic_version") != module.SEMANTIC_VERSION or result.get("scope") != module.SCOPE
            or any(result.get(key) != "NOT_ESTABLISHED" for key in
                ("object_profile_conformance", "whole_tier_conformance", "authority", "actual_execution"))):
        raise Refuted(label + " native result exceeds its exact selected proposition boundary")
    return result["status"]

def _child_data(raw: bytes, child_request: dict[str, Any]) -> dict[str, Any] | None:
    role_constraints._preflight_depth(raw)
    envelope = _record(strict_json_loads(raw.decode("utf-8")), {
        "schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
        "evidence_refs", "evidence_payloads", "result", "digest"}, "child certificate")
    payloads = envelope["evidence_payloads"]
    if (canonical_bytes(envelope) != raw or envelope["request"] != child_request
            or envelope["evidence_refs"] != [child_request["evidence_ref"]]
            or type(payloads) is not dict or set(payloads) - {child_request["evidence_ref"]}
            or any(type(key) is not str or type(item) is not str for key,item in payloads.items())):
        raise Refuted("child retained envelope differs from exact selected plain binding")
    encoded = payloads.get(child_request["evidence_ref"])
    if encoded is None:
        return None
    data = role_lifecycle._decode(encoded, child_request["limits"]["max_evidence_bytes"])
    role_constraints._preflight_depth(data)
    retained = strict_json_loads(data.decode("utf-8"))
    if type(retained) is not dict or any(type(key) is not str for key in retained):
        raise Refuted("plain retained child evidence record required")
    return retained

def _snapshots(raw: bytes, request: dict[str, Any], budget: common_module.Budget) -> tuple[list[Any], list[str]]:
    child_request = request["lifecycle_request"]
    retained = _child_data(raw, child_request)
    # Fence inherited depth-error wrappers before invoking native child readers.
    if retained is not None and type(retained.get("endpoints")) is list:
        for endpoint in retained["endpoints"]:
            budget.tick()
            if type(endpoint) is dict and endpoint.get("child_certificate") is not None:
                static_raw = role_lifecycle._decode(endpoint["child_certificate"], child_request["limits"]["max_child_certificate_bytes"])
                role_constraints._preflight_depth(static_raw)
                if type(endpoint.get("child_request")) is dict:
                    _child_data(static_raw, role_constraints._request(endpoint["child_request"]))
    result = role_lifecycle.recheck_role_lifecycle_certificate(raw,
        expected_request=child_request, policy=request["lifecycle_policy"])
    status = _native_boundary(result, role_lifecycle, "lifecycle")
    if status == "FAIL":
        raise Refuted("freshly replayed lifecycle prerequisite is FAIL")
    missing = [] if status == "PASS" else ["freshly replayed lifecycle prerequisite remains UNKNOWN"]
    selections = child_request["endpoint_selections"]
    snapshots = [None] * len(selections)
    if retained is None or retained.get("schema_version") != role_lifecycle.EVIDENCE_VERSION or retained.get("endpoints") is None:
        return snapshots, missing + ["supported retained endpoint witness inventory absent"]
    endpoints = retained["endpoints"]
    if type(endpoints) is not list or len(endpoints) > len(selections):
        raise Refuted("retained endpoint inventory differs from independent selection")
    if len(endpoints) < len(selections):
        missing.append("selected endpoint witnesses absent")
    relation_remaining = [request["limits"]["max_relation_steps"]]
    reserve = child_request["limits"]["max_operations"] + child_request["limits"]["max_child_operations"]
    for position, endpoint in enumerate(endpoints):
        budget.tick()
        try:
            endpoint = _record(endpoint, {"child_request", "child_policy", "child_certificate"}, "endpoint")
            selection = selections[position]
            selected, selected_policy = endpoint["child_request"], endpoint["child_policy"]
            for value, expected, label in ((selected, selection["child_request_digest"], "request"),
                    (selected_policy, selection["child_policy_digest"], "policy")):
                if value is not None and "sha256:" + canonical_digest(value) != expected:
                    raise Refuted("endpoint " + label + " differs from independent exact selection")
            static_raw = None
            if endpoint["child_certificate"] is not None:
                static_raw = role_lifecycle._decode(endpoint["child_certificate"], child_request["limits"]["max_child_certificate_bytes"])
                if "sha256:" + hashlib.sha256(static_raw).hexdigest() != selection["child_certificate_digest"]:
                    raise Refuted("endpoint certificate differs from independent exact selection")
            if selected is None or selected_policy is None or static_raw is None:
                raise Unavailable("independently selected endpoint witness absent")
            selected, selected_policy = role_constraints._request(selected), role_constraints._policy(selected_policy)
            if (selected["subject_id"] != request["subject_id"] or selected["object_digest"] != selection["object_digest"]
                    or selected["collection_digest"] != selection["collection_digest"]):
                raise Refuted("local endpoint is not the independently selected ROLE record and collection")
            bound = _child_data(static_raw, selected)
            if status != "PASS":
                reserve += sum(selected["limits"][key] for key in
                    ("max_operations", "max_composition_operations", "max_relation_steps"))
                if reserve > request["limits"]["max_child_operations"]:
                    raise Unavailable("additional local static replay reserve exhausted")
                local = role_constraints.recheck_role_constraints_certificate(static_raw,
                    expected_request=selected, policy=selected_policy)
                local_status = _native_boundary(local, role_constraints, "endpoint")
                if local_status == "FAIL":
                    raise Refuted("freshly replayed local static prerequisite is FAIL")
                if local_status != "PASS":
                    raise Unavailable("freshly replayed local static prerequisite remains UNKNOWN")
            if bound is None:
                raise Unavailable("replayed local static evidence absent")
            matrix = bound["inputs"]["matrix"]
            if matrix["collective_id"] != request["collective_id"]:
                raise Refuted("endpoint occupancy is selected under another COLLECTIVE")
            index = {row["object_id"]: NamespaceObject.create(**row) for row in bound["objects"]}
            budget.tick(len(index) + len(matrix["occupancies"]))
            role = index[request["subject_id"]]
            if role.digest != selection["object_digest"]:
                raise Refuted("replayed local ROLE record differs from independent selection")
            rows = [row for row in matrix["occupancies"] if row["role_id"] == request["subject_id"]]
            identities = {}
            for row in rows:
                roots = identity_occupancy._leaves(index, index[row["actor_id"]], "root_human", relation_remaining)
                if roots is None:
                    raise Unavailable("aggregate selected identity relation reserve exhausted")
                if len(roots) != 1:
                    raise Refuted("declared accountable actor lacks one exact HUMAN root")
                identities[row["identity_id"]] = {**row, "root_human_id": roots[0].object_id}
            snapshots[position] = {"actors": sorted({row["actor_id"] for row in rows}),
                "identities": identities, "permissions": role.payload["permissions"], "scopes": role.payload["admitted_scopes"]}
        except (Unavailable, OSError, ImportError) as exc:
            missing.append(str(exc))
    return snapshots, missing

def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    try:
        role_constraints._preflight_depth(data)
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "lifecycle_certificate", "events", "decisions"}, "closure evidence")
        if value["schema_version"] != EVIDENCE_VERSION:
            raise Unavailable("ROLE closure evidence version unsupported")
        if canonical_bytes(value) != data:
            raise Refuted("retained ROLE closure evidence is not canonical")
        limits = request["limits"]
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        missing = []
        events = _component(value["events"], request["events_digest"], "timed events")
        decisions = _component(value["decisions"], request["decisions_digest"], "decisions")
        times = request["endpoint_times_us"]
        if events is None:
            missing.append("complete timed event inventory absent")
        else:
            if type(events) is not list or len(events) != len(times) - 1:
                raise Refuted("timed event inventory does not cover selected endpoint transitions")
            for position, event in enumerate(events, 1):
                budget.tick()
                row = _record(event, {"position", "time_us", "action", "taking", "leaving"}, "timed event")
                if type(row["position"]) is not int or row["position"] != position or _instant(row["time_us"]) != times[position]:
                    raise Refuted("timed event position/clock does not match selected endpoint")
                taking, leaving = _names(row["taking"], budget), _names(row["leaving"], budget)
                if set(taking) & set(leaving):
                    raise Refuted("atomic event takes and leaves the same actor")
                action = row["action"]
                legal = ((action == "TAKE" and taking and not leaving)
                    or (action == "LEAVE" and leaving and not taking)
                    or (action == "HANDOVER" and len(taking) == len(leaving) == 1)
                    or (action == "CHECKPOINT" and not taking and not leaving))
                if not legal:
                    raise Refuted("event is not an exact take/leave/paired handover/checkpoint")
        if decisions is None:
            missing.append("complete selected decision inventory absent")
        else:
            if type(decisions) is not list:
                raise Refuted("plain complete decision array required")
            if len(decisions) > limits["max_decisions"]:
                raise Unavailable("selected decision bound exhausted")
            seen, previous = set(), -1
            for position, decision in enumerate(decisions):
                budget.tick()
                row = _record(decision, {"position", "decision_id", "time_us", "actor_id", "identity_id",
                    "scope", "decision_class", "content_digest"}, "point-in-role decision")
                if type(row["position"]) is not int or row["position"] != position:
                    raise Refuted("decision positions are not complete and contiguous")
                for key in ("decision_id", "actor_id", "identity_id", "scope", "decision_class"):
                    role_constraints._text(row[key])
                _hash(row["content_digest"])
                instant = _instant(row["time_us"])
                if row["decision_id"] in seen or instant < previous or not request["period_us"][0] <= instant < request["period_us"][1]:
                    raise Refuted("duplicate, reordered or out-of-period decision")
                seen.add(row["decision_id"]); previous = instant
        snapshots = None
        if value["lifecycle_certificate"] is None:
            missing.append("exact selected lifecycle prerequisite bytes absent")
        else:
            raw = role_lifecycle._decode(value["lifecycle_certificate"], limits["max_child_certificate_bytes"])
            if "sha256:" + hashlib.sha256(raw).hexdigest() != request["lifecycle_certificate_digest"]:
                raise Refuted("lifecycle certificate differs from independent exact selection")
            child_limits = request["lifecycle_request"]["limits"]
            if child_limits["max_operations"] + child_limits["max_child_operations"] > limits["max_child_operations"]:
                raise Unavailable("aggregate selected child operation reserve exhausted")
            try:
                snapshots, unavailable = _snapshots(raw, request, budget)
                missing.extend(unavailable)
            except (Unavailable, OSError, ImportError) as exc:
                missing.append(str(exc))
        cells, attributions = [], []
        if snapshots is not None:
            if len(snapshots) != len(times):
                raise Refuted("replayed lifecycle endpoint inventory differs")
            for position, snapshot in enumerate(snapshots):
                budget.tick()
                if snapshot is not None and not snapshot["actors"]:
                    raise Refuted("selected period contains an empty occupancy cell")
                end = times[position + 1] if position + 1 < len(times) else request["period_us"][1]
                cells.append({"start_us": times[position], "end_us": end, "actors": snapshot["actors"] if snapshot is not None else None})
                if events is not None and position and snapshot is not None and snapshots[position - 1] is not None:
                    before, event = snapshots[position - 1], events[position - 1]
                    if (set(event["taking"]) != set(snapshot["actors"]) - set(before["actors"])
                            or set(event["leaving"]) != set(before["actors"]) - set(snapshot["actors"])):
                        raise Refuted("timed complete history differs from freshly replayed occupancy delta")
            if decisions is not None:
                for row in decisions:
                    budget.tick(len(times))
                    position = next(i for i, cell in enumerate(cells) if cell["start_us"] <= row["time_us"] < cell["end_us"])
                    snapshot = snapshots[position]
                    if snapshot is None:
                        continue
                    binding = snapshot["identities"].get(row["identity_id"])
                    if (binding is None or binding["actor_id"] != row["actor_id"] or binding["scope"] != row["scope"]
                            or row["actor_id"] not in snapshot["actors"] or row["scope"] not in snapshot["scopes"]
                            or row["decision_class"] not in snapshot["permissions"]):
                        raise Refuted("decision bearer/identity/scope/permission is not exact occupied ROLE authority token")
                    attributions.append({**row, "role_id": request["subject_id"], "root_human_id": binding["root_human_id"]})
        if missing:
            raise Unavailable("; ".join(sorted(set(missing))))
        return MechanismDecision(MechanismOutcome.PASS, "complete selected point-decision and occupancy inventories reproduced",
            {"intervals": cells, "attributed_decisions": attributions, "operations": budget.used,
             "actual_occurrence": "NOT_ESTABLISHED", "inventory_real_world_completeness": "NOT_ESTABLISHED"})
    except (Unavailable, OSError, ImportError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, IndexError, StopIteration) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))

def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _RoleClosureMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound ROLE closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one selected closure bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise RoleClosureError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_RoleClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ROLE", "scope": SCOPE,
        "evaluation": evaluation.to_dict(), **{field: "NOT_ESTABLISHED" for field in (
            "object_profile_conformance", "whole_tier_conformance", "authority", "actual_execution",
            "historical_occurrence", "enforcement", "actual_occupancy")}}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise RoleClosureError("certificate byte bound exhausted")
    return encoded


def build_role_closure_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                    *, policy: dict[str, Any]) -> bytes:
    request, policy = _owned(request), _owned(policy)
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise RoleClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise RoleClosureError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_role_closure_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    expected_request, policy = _owned(expected_request), _owned(policy)
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes:
        raise RoleClosureError("immutable closure certificate bytes required")
    if len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise RoleClosureUnavailable("selected closure certificate byte checking bound exhausted")
    try:
        role_constraints._preflight_depth(certificate_bytes)
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
            "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise RoleClosureError("selected canonical closure certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise RoleClosureError("retained closure evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise RoleClosureError("closure certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (Unavailable, RecursionError, OverflowError) as exc:
        raise RoleClosureUnavailable("bounded native closure recheck unavailable") from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, RoleClosureError):
            raise
        raise RoleClosureError("invalid retained closure certificate") from exc

__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "SCOPE", "RoleClosureDescriptor", "RoleClosureError", "RoleClosureUnavailable", "registration", "mechanism_digest",
    "role_closure_policy", "role_closure_request", "build_role_closure_certificate", "recheck_role_closure_certificate"]
