"""Current COLLECTIVE-3.1 retained static membership and quorum constraints.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8).
Replay binds one exact typed collection and externally selected ROLE records,
rehashes retained nonblank charter bytes and checks integer quorum feasibility.
Counts are dimensionless; byte bounds count encoded bytes. A feasible declared
quorum establishes no vote, occupancy, actual authority or whole-tier conformance.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "COLLECTIVE-3.1"
REQUEST_VERSION = "verifier-current-collective-constraints-request-1"
POLICY_VERSION = "verifier-current-collective-constraints-policy-1"
CERTIFICATE_VERSION = "verifier-current-collective-constraints-certificate-1"
EVIDENCE_VERSION = "verifier-current-collective-constraints-evidence-1"
CONSTRAINTS_VERSION = "verifier-current-collective-static-constraints-1"
MECHANISM_ID = "verifier.current-collective.static-constraints.1"
SCOPE = "finite_selected_collective_membership_charter_quorum_constraints"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
    "max_depth": 64, "max_charter_bytes": 65536,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class CollectiveConstraintsError(ValueError):
    """Malformed external selection or substituted retained certificate."""


class CollectiveConstraintsUnavailable(OSError):
    """Retained checking capacity is unavailable; no semantic refusal."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "COLLECTIVE", "scope": SCOPE,
        "proposition": (
            "The externally selected exact COLLECTIVE occurs in the selected finite "
            "typed collection; its complete declared roles operand equals the externally "
            "selected sorted distinct ROLE records; the retained membership and nonblank "
            "UTF-8 charter rehash to the selected commitments; and its selected integer "
            "quorum lies between one and that declared role count, inclusive."
        ),
        "prerequisites": [
            "externally selected exact subject, full finite collection, ROLE records, "
            "charter byte commitment, declared quorum, retained evidence, installed "
            "checker policy and finite resource limits"
        ],
        "exclusions": [
            "complete real membership or an exhaustive charter and obligation catalogue",
            "living persons, independent occupants or live ROLE occupancy",
            "charter meaning, legal validity, role authority or governance admission",
            "actual votes, a collective decision, signature validity or enforcement",
            "actual execution, complete statics tier or object-profile conformance",
            "privacy, consent, independence, governance or security conformance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class CollectiveConstraintsDescriptor:
    """Native metadata for this finite declared static invariant."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != fields):
        raise CollectiveConstraintsError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise CollectiveConstraintsError("canonical SHA-256 commitment required")
    return value


def _name(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise CollectiveConstraintsError("bounded nonempty role or subject identifier required")
    return value


def _members(value: Any) -> list[dict[str, str]]:
    if type(value) is not list or len(value) > 4096:
        raise CollectiveConstraintsError("bounded selected ROLE membership required")
    rows = []
    for raw in value:
        row = _record(raw, {"role_id", "role_digest"}, "member")
        rows.append({"role_id": _name(row["role_id"]), "role_digest": _hash(row["role_digest"])})
    ids = [row["role_id"] for row in rows]
    if ids != sorted(set(ids)):
        raise CollectiveConstraintsError("sorted distinct ROLE membership required")
    return rows


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    # Resolve the namespace specification beside the actual imported dependency.
    # This also permits a coordinator to replay an additive module against a
    # selected existing checkout without replacing its namespace implementation.
    paths["NAMESPACE_OBJECTS.md"] = Path(namespace_module.__file__).parents[1] / "standard" / "NAMESPACE_OBJECTS.md"
    paths["CURRENT_COLLECTIVE_CONSTRAINTS.md"] = Path(__file__).parents[2] / "standard" / "CURRENT_COLLECTIVE_CONSTRAINTS.md"
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {
        "schema_version", "mechanism_id", "mechanism_digest", "trust_roots",
        "max_certificate_bytes", "selected_members", "charter_digest", "quorum",
    }, "policy")
    if (policy["schema_version"] != POLICY_VERSION or policy["mechanism_id"] != MECHANISM_ID
            or _hash(policy["mechanism_digest"]) != mechanism_digest()):
        raise CollectiveConstraintsError("policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise CollectiveConstraintsError("bounded sorted unique trust-root labels required")
    size = policy["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise CollectiveConstraintsError("certificate byte bound unsupported")
    # Admit finite false selections so replay can refute quorum feasibility.
    if type(policy["quorum"]) is not int or not -4096 <= policy["quorum"] <= 4096:
        raise CollectiveConstraintsError("bounded integer quorum selection required")
    policy["selected_members"] = _members(policy["selected_members"])
    policy["charter_digest"] = _hash(policy["charter_digest"])
    policy["trust_roots"] = list(roots)
    return policy


def collective_constraints_policy(*, trust_roots: list[str],
                                  selected_members: list[dict[str, str]],
                                  charter_digest: str, quorum: int,
                                  max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                                  ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
        "selected_members": selected_members, "charter_digest": charter_digest,
        "quorum": quorum,
    })


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "COLLECTIVE"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise CollectiveConstraintsError("selected COLLECTIVE static objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    _name(request["subject_id"])
    limits = _record(request["limits"], set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling
           for key, ceiling in _CEILINGS.items()):
        raise CollectiveConstraintsError("finite checker limit unsupported")
    request["limits"] = limits
    return request


def collective_constraints_request(*, subject_id: str, object_digest: str,
                                   collection_digest: str, evidence_ref: str,
                                   policy: dict[str, Any],
                                   limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise CollectiveConstraintsError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "COLLECTIVE", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _depth(data: bytes, maximum: int) -> None:
    """Bound JSON nesting before a recursive parser, ignoring quoted brackets."""
    depth = 0
    quoted = escaped = False
    for value in data:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in (91, 123):
            depth += 1
            if depth > maximum:
                raise Unavailable("selected JSON depth bound exhausted")
        elif value in (93, 125):
            depth -= 1


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        _depth(data, limits["max_depth"])
        value = strict_json_loads(data.decode("utf-8"))
        if (type(value) is not dict or set(value) - {"schema_version", "objects", "inputs"}
                or not {"schema_version", "objects"} <= set(value)
                or value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data):
            raise Refuted("retained evidence version, shape or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            selected = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            if type(selected["operands"]) is not dict:
                raise Refuted("namespace operands must be an exact mapping")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "COLLECTIVE"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained COLLECTIVE differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        subject = matches[0]
        constraints = subject.payload.get("static_constraints")
        if constraints is None:
            raise Unavailable("selected COLLECTIVE static constraints absent")
        constraints = _record(constraints, {
            "schema_version", "charter_digest", "membership_digest", "quorum",
        }, "static constraints")
        if constraints["schema_version"] != CONSTRAINTS_VERSION:
            raise Unavailable("unsupported COLLECTIVE static constraint semantics")
        members = policy["selected_members"]
        ids = [member["role_id"] for member in members]
        by_id = {obj.object_id: obj for obj in objects}
        # Composition has already validated graph kinds and acyclicity. Expand
        # only declared role leaves, charging every visited reference; overlapping
        # graph paths cannot count the same role as multiple quorum seats.
        pending = list(dict(subject.operands).get("roles", ()))
        visited_graphs: set[str] = set()
        role_ids: set[str] = set()
        while pending:
            budget.tick()
            identifier = pending.pop()
            item = by_id[identifier]
            if item.kind.value == "GRAPH":
                if identifier not in visited_graphs:
                    visited_graphs.add(identifier)
                    pending.extend(dict(item.operands)["members"])
            elif item.kind.value == "ROLE":
                role_ids.add(identifier)
            else:
                raise Refuted("declared membership leaf is not a ROLE")
        if sorted(role_ids) != ids:
            raise Refuted("complete declared roles operand differs from selected membership")
        for member in members:
            budget.tick()
            role = by_id.get(member["role_id"])
            if role is None or role.kind.value != "ROLE" or role.digest != member["role_digest"]:
                raise Refuted("selected member is not the exact retained ROLE record")
        if (constraints["membership_digest"] != "sha256:" + canonical_digest(members)
                or constraints["charter_digest"] != policy["charter_digest"]
                or type(constraints["quorum"]) is not int
                or constraints["quorum"] != policy["quorum"]):
            raise Refuted("selected charter, membership or quorum commitment differs")
        if not 1 <= policy["quorum"] <= len(members):
            raise Refuted("declared integer quorum is outside selected ROLE cardinality")
        retained = value.get("inputs")
        if retained is None:
            raise Unavailable("retained membership, charter and quorum evidence absent")
        if type(retained) is not dict or set(retained) - {"membership", "charter", "quorum"}:
            raise Refuted("retained static inputs differ")
        missing = []
        charter_size = 0
        # Inspect every present input before reporting absence: a missing charter
        # cannot conceal a contradictory membership or declared quorum.
        for field in ("membership", "quorum", "charter"):
            if retained.get(field) is None:
                missing.append(field)
                continue
            if field == "membership":
                actual = _members(retained[field])
                budget.tick(len(actual))
                if actual != members:
                    raise Refuted("retained membership differs from external selection")
            elif field == "quorum":
                budget.tick()
                if type(retained[field]) is not int or retained[field] != policy["quorum"]:
                    raise Refuted("retained quorum differs from external selection")
            else:
                row = _record(retained[field], {"sha256", "base64"}, "retained charter")
                if type(row["base64"]) is not str:
                    raise Refuted("retained charter encoding differs")
                charter = base64.b64decode(row["base64"], validate=True)
                charter_size = len(charter)
                if charter_size > limits["max_charter_bytes"]:
                    raise Unavailable("selected charter byte bound exhausted")
                budget.tick(charter_size)
                observed = "sha256:" + hashlib.sha256(charter).hexdigest()
                if row["sha256"] != observed or observed != policy["charter_digest"]:
                    raise Refuted("retained charter bytes differ from selected commitment")
                if not charter.decode("utf-8").strip():
                    raise Refuted("retained charter must be nonblank UTF-8 text")
        if missing:
            raise Unavailable("required retained static evidence absent: " + ", ".join(missing))
        return MechanismDecision(MechanismOutcome.PASS,
            "selected retained COLLECTIVE static constraints reproduced",
            {"selected_roles": len(members), "quorum": policy["quorum"],
             "charter_bytes": charter_size, "operations": budget.used})
    except (Unavailable, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **{key: request[key] for key in (
            "semantic_version", "proposition_digest", "object_kind", "object_digest",
            "collection_digest", "policy_digest",
        )}, "limits_digest": "sha256:" + canonical_digest(request["limits"]),
    }


class _CollectiveConstraintsMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound COLLECTIVE proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained COLLECTIVE bundle required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise CollectiveConstraintsError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_CollectiveConstraintsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "COLLECTIVE", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED", "whole_tier_conformance": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "actual_execution": "NOT_ESTABLISHED",
        "membership_completeness": "NOT_ESTABLISHED", "role_occupancy": "NOT_ESTABLISHED",
        "charter_authority": "NOT_ESTABLISHED", "actual_quorum_decision": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise CollectiveConstraintsError("certificate byte bound exhausted")
    return encoded


def build_collective_constraints_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                              *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise CollectiveConstraintsError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise CollectiveConstraintsError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_collective_constraints_certificate(certificate_bytes: bytes, *,
                                               expected_request: dict[str, Any],
                                               policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise CollectiveConstraintsError("bounded immutable certificate bytes required")
    try:
        _depth(certificate_bytes, 128)
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
            "evidence_refs", "evidence_payloads", "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise CollectiveConstraintsError("canonical certificate version differs")
        if value["request"] != selected:
            raise CollectiveConstraintsError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise CollectiveConstraintsError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise CollectiveConstraintsError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (Unavailable, RecursionError, OverflowError) as exc:
        raise CollectiveConstraintsUnavailable("retained certificate checking capacity unavailable") from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, CollectiveConstraintsError):
            raise
        raise CollectiveConstraintsError("invalid retained COLLECTIVE certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "CONSTRAINTS_VERSION", "PROPOSITION_DIGEST", "CollectiveConstraintsDescriptor",
    "CollectiveConstraintsError", "CollectiveConstraintsUnavailable", "registration", "mechanism_digest",
    "collective_constraints_policy", "collective_constraints_request",
    "build_collective_constraints_certificate", "recheck_collective_constraints_certificate",
]
