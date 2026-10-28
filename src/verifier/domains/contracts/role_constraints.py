"""Current ROLE-3.1 finite declared occupancy and permission constraints.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). One externally pinned finite matrix is checked
against exact typed namespace bytes. Counts and budgets are dimensionless;
byte limits measure retained input. No actual authority or enforcement claim.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
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
from verifier.domains.contracts import identity_occupancy, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "ROLE-3.1"
REQUEST_VERSION = "verifier-current-role-constraints-request-1"
POLICY_VERSION = "verifier-current-role-constraints-policy-1"
CERTIFICATE_VERSION = "verifier-current-role-constraints-certificate-1"
EVIDENCE_VERSION = "verifier-current-role-constraints-evidence-1"
MATRIX_VERSION = "verifier-current-role-constraints-matrix-1"
MECHANISM_ID = "verifier.current-role.finite-constraints.1"
SCOPE = "finite_declared_role_occupancy_permission_constraints"
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_relation_steps": 100000,
    "max_items": 4096, "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_MAX_DEPTH = 64


class RoleConstraintsError(ValueError):
    """Malformed external selection or a certificate that cannot reproduce."""


class RoleConstraintsUnavailable(OSError):
    """Retained checking capacity is unavailable; no semantic refusal."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "ROLE", "scope": SCOPE,
        "proposition": (
            "The exact externally selected ROLE record and complete finite typed "
            "collection agree with an externally committed matrix covering every "
            "retained ROLE, ACTOR and IDENTITY. The selected COLLECTIVE contains "
            "exactly those roles; declared permissions and scopes satisfy selected "
            "bounds; every identity equals one selected actor-role-scope cell; "
            "distinct declared occupancy counts satisfy each selected interval; "
            "and selected mutually exclusive roles have neither a shared ACTOR "
            "nor a shared declared responsible HUMAN."
        ),
        "prerequisites": [
            "independently selected exact ROLE and full typed collection commitments",
            "independently selected finite matrix commitment and retained canonical bytes",
            "installed source/specification policy and finite checker limits",
        ],
        "exclusions": [
            "real-world authority, permission issuance or actual enforcement",
            "human authenticity, actor independence, actual occupancy or liveness",
            "out-of-collection role, actor, identity or permission completeness",
            "unselected constraints, permission meaning, law or ethical adequacy",
            "complete ROLE statics tier or object-profile conformance",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class RoleConstraintsDescriptor:
    """Metadata for the one finite matrix proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, RoleConstraintsError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, RoleConstraintsError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection, identity_occupancy)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "IDENTITY_OCCUPANCY.md"):
        paths[name] = Path(namespace_module.__file__).parents[1] / "standard" / name
    paths["CURRENT_ROLE_CONSTRAINTS.md"] = Path(__file__).parents[2] / "standard" / "CURRENT_ROLE_CONSTRAINTS.md"
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=RoleConstraintsError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def role_constraints_policy(*, trust_roots: list[str],
                            max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "matrix_digest", "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "ROLE"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise RoleConstraintsError("selected role objective differs")
    for field in ("object_digest", "collection_digest", "matrix_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise RoleConstraintsError("bounded subject identifier required")
    request["limits"] = retained_selection.limits(request["limits"], _CEILINGS, RoleConstraintsError)
    return request


def role_constraints_request(*, subject_id: str, object_digest: str,
                             collection_digest: str, matrix_digest: str,
                             evidence_ref: str, policy: dict[str, Any],
                             limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise RoleConstraintsError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "ROLE", "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "matrix_digest": matrix_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise Refuted("bounded nonblank identifier or permission required")
    return value


def _strings(value: Any, budget: common_module.Budget, *, nonempty: bool = False) -> list[str]:
    if type(value) is not list:
        raise Refuted("plain sorted string array required")
    if len(value) > budget.max_items:
        raise Unavailable("selected string-array bound exhausted")
    budget.tick(len(value))
    values = [_text(item) for item in value]
    if values != sorted(set(values)):
        raise Refuted("sorted unique strings required")
    if nonempty and not values:
        raise Unavailable("nonempty selected inventory required")
    return values


def _rows(value: Any, fields: set[str], key: str,
          budget: common_module.Budget) -> dict[str, dict[str, Any]]:
    if type(value) is not list:
        raise Refuted("matrix rows must be a plain array")
    if len(value) > budget.max_items:
        raise Unavailable("selected matrix-row bound exhausted")
    budget.tick(len(value))
    result: dict[str, dict[str, Any]] = {}
    order = []
    for row in value:
        captured = _record(row, fields, "matrix row")
        identifier = _text(captured[key])
        if identifier in result:
            raise Refuted("duplicate selected matrix identifier")
        result[identifier] = captured
        order.append(identifier)
    if order != sorted(order):
        raise Refuted("matrix identifiers must be sorted")
    return result


def _preflight_depth(data: bytes) -> None:
    """Bound nesting before calling recursive JSON parsing or serialization."""
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > _MAX_DEPTH:
                raise Unavailable("retained JSON nesting bound exhausted")
        elif byte in (93, 125):
            depth -= 1


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        _preflight_depth(data)
        evidence = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "objects", "inputs"}, "evidence")
        if evidence["schema_version"] != EVIDENCE_VERSION:
            raise Unavailable("retained role evidence version unsupported")
        if canonical_bytes(evidence) != data:
            raise Refuted("retained evidence is not canonical")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(evidence, budget)
        rows = evidence["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            captured = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**captured)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "ROLE"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained ROLE subject differs from external selection")
        composition = namespace_module.assess_composition(objects,
            expected_digest=request["collection_digest"], max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        if evidence["inputs"] is None:
            raise Unavailable("retained selected matrix absent")
        inputs = _record(evidence["inputs"], {"matrix"}, "inputs")
        if inputs["matrix"] is None:
            raise Unavailable("retained selected matrix absent")
        matrix = _record(inputs["matrix"], {
            "schema_version", "collective_id", "roles", "actors", "occupancies", "exclusive_role_sets",
        }, "matrix")
        if "sha256:" + canonical_digest(matrix) != request["matrix_digest"]:
            raise Refuted("retained matrix differs from independent selection")
        if matrix["schema_version"] != MATRIX_VERSION:
            raise Unavailable("retained matrix version unsupported")
        role_rows = _rows(matrix["roles"], {"role_id", "allowed_permissions", "allowed_scopes",
            "min_occupants", "max_occupants"}, "role_id", budget)
        actor_rows = _rows(matrix["actors"], {"actor_id", "allowed_roles"}, "actor_id", budget)
        occupancy_rows = _rows(matrix["occupancies"], {
            "identity_id", "actor_id", "role_id", "scope"}, "identity_id", budget)
        index = {obj.object_id: obj for obj in objects}
        for kind, selected in (("ROLE", role_rows), ("ACTOR", actor_rows), ("IDENTITY", occupancy_rows)):
            if set(selected) != {obj.object_id for obj in objects if obj.kind.value == kind}:
                raise Refuted("selected matrix does not cover exact retained " + kind + " inventory")
        collective = index.get(_text(matrix["collective_id"]))
        if collective is None or collective.kind.value != "COLLECTIVE":
            raise Refuted("selected COLLECTIVE is not retained")
        remaining = [limits["max_relation_steps"]]

        def leaves(item: NamespaceObject, name: str) -> list[NamespaceObject]:
            expanded = identity_occupancy._leaves(index, item, name, remaining)
            if expanded is None:
                raise Unavailable("selected typed relation expansion bound exhausted")
            return expanded

        if {item.object_id for item in leaves(collective, "roles")} != set(role_rows):
            raise Refuted("selected collective roles differ from complete matrix")
        roles: dict[str, tuple[set[str], int, int]] = {}
        for identifier, constraint in role_rows.items():
            budget.tick()
            allowed_permissions = set(_strings(constraint["allowed_permissions"], budget))
            allowed_scopes = set(_strings(constraint["allowed_scopes"], budget))
            minimum, maximum = constraint["min_occupants"], constraint["max_occupants"]
            if (type(minimum) is not int or type(maximum) is not int
                    or not 0 <= minimum <= maximum <= _CEILINGS["max_items"]):
                raise Refuted("finite occupancy interval required")
            payload = index[identifier].payload
            if "permissions" not in payload or "admitted_scopes" not in payload:
                raise Unavailable("retained ROLE permissions or scopes absent")
            declared_permissions = set(_strings(payload["permissions"], budget))
            declared_scopes = set(_strings(payload["admitted_scopes"], budget))
            if not declared_permissions <= allowed_permissions or not declared_scopes <= allowed_scopes:
                raise Refuted("declared ROLE permissions or scopes exceed selected bounds")
            roles[identifier] = (declared_scopes, minimum, maximum)
        allowed_roles: dict[str, set[str]] = {}
        roots: dict[str, str] = {}
        for identifier, constraint in actor_rows.items():
            budget.tick()
            allowed = set(_strings(constraint["allowed_roles"], budget))
            if not allowed <= set(role_rows):
                raise Refuted("actor matrix references an unselected role")
            allowed_roles[identifier] = allowed
            humans = leaves(index[identifier], "root_human")
            if len(humans) != 1 or humans[0].kind.value != "HUMAN":
                raise Refuted("declared actor root is not exactly one HUMAN")
            roots[identifier] = humans[0].object_id
        occupants: dict[str, set[str]] = {identifier: set() for identifier in roles}
        cells: set[tuple[str, str]] = set()
        for identifier, selected in occupancy_rows.items():
            budget.tick()
            identity = index[identifier]
            actors, identity_roles = leaves(identity, "actor"), leaves(identity, "role")
            if len(actors) != 1 or len(identity_roles) != 1:
                raise Refuted("IDENTITY must declare exactly one actor and one role")
            actor_id, role_id = actors[0].object_id, identity_roles[0].object_id
            if "scope" not in identity.payload:
                raise Unavailable("retained IDENTITY scope absent")
            scope = _text(identity.payload["scope"])
            actual = {"identity_id": identifier, "actor_id": actor_id, "role_id": role_id, "scope": scope}
            if canonical_bytes(actual) != canonical_bytes(selected):
                raise Refuted("retained IDENTITY differs from selected matrix cell")
            if role_id not in allowed_roles[actor_id] or scope not in roles[role_id][0]:
                raise Refuted("declared occupancy exceeds actor permission or role scope")
            if (actor_id, role_id) in cells:
                raise Refuted("duplicate declared actor-role occupancy")
            cells.add((actor_id, role_id))
            occupants[role_id].add(actor_id)
        for identifier, (_, minimum, maximum) in roles.items():
            budget.tick()
            if not minimum <= len(occupants[identifier]) <= maximum:
                raise Refuted("declared occupancy count violates selected interval")
        groups = matrix["exclusive_role_sets"]
        if type(groups) is not list:
            raise Refuted("exclusive role sets must be an array")
        if len(groups) > budget.max_items:
            raise Unavailable("selected exclusion-group bound exhausted")
        group_keys = []
        for group in groups:
            names = _strings(group, budget)
            if len(names) < 2 or not set(names) <= set(roles):
                raise Refuted("exclusive set requires at least two selected roles")
            group_keys.append(canonical_bytes(names))
            used_actors: set[str] = set()
            used_humans: set[str] = set()
            for name in names:
                budget.tick(1 + len(occupants[name]))
                actors = occupants[name]
                humans = {roots[actor] for actor in actors}
                if used_actors & actors or used_humans & humans:
                    raise Refuted("selected mutually exclusive roles share actor or responsible HUMAN")
                used_actors.update(actors)
                used_humans.update(humans)
        if group_keys != sorted(set(group_keys)):
            raise Refuted("exclusive role sets must be sorted and unique")
        return MechanismDecision(MechanismOutcome.PASS,
            "selected finite ROLE constraints reproduced", {
                "roles": len(roles), "actors": len(actor_rows), "identities": len(occupancy_rows),
                "exclusive_sets": len(groups), "operations": budget.used,
                "relation_steps": limits["max_relation_steps"] - remaining[0],
            })
    except (Unavailable, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**retained_selection.parameters(request), "matrix_digest": request["matrix_digest"]}


class _RoleConstraintsMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound role proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained role evidence bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise RoleConstraintsError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_RoleConstraintsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ROLE", "scope": SCOPE,
        "evaluation": evaluation.to_dict(),
        **{field: "NOT_ESTABLISHED" for field in (
            "object_profile_conformance", "statics_tier_conformance", "whole_tier_conformance",
            "authority", "actual_execution", "actual_occupancy", "enforcement", "human_authenticity")}}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise RoleConstraintsError("certificate byte bound exhausted")
    return encoded


def build_role_constraints_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                       *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise RoleConstraintsError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise RoleConstraintsError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_role_constraints_certificate(certificate_bytes: bytes, *,
                                         expected_request: dict[str, Any],
                                         policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise RoleConstraintsError("bounded immutable certificate bytes required")
    try:
        _preflight_depth(certificate_bytes)
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise RoleConstraintsError("canonical certificate version differs")
        if value["request"] != selected:
            raise RoleConstraintsError("certificate differs from selected external request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise RoleConstraintsError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise RoleConstraintsError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (Unavailable, RecursionError, OverflowError) as exc:
        raise RoleConstraintsUnavailable("retained certificate checking capacity unavailable") from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, RoleConstraintsError):
            raise
        raise RoleConstraintsError("invalid retained role certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "MATRIX_VERSION", "PROPOSITION_DIGEST", "SCOPE", "RoleConstraintsDescriptor",
    "RoleConstraintsError", "RoleConstraintsUnavailable", "registration", "mechanism_digest", "role_constraints_policy",
    "role_constraints_request", "build_role_constraints_certificate",
    "recheck_role_constraints_certificate"]
