"""Current SPACE-2.1: length-preserving partition migration between two layouts.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Offsets, lengths and extents are bytes; counts and
resource budgets are dimensionless. This proves no physical data movement.
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
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, space_layout


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SPACE-2.1"
REQUEST_VERSION = "verifier-current-space-migration-request-1"
POLICY_VERSION = "verifier-current-space-migration-policy-1"
CERTIFICATE_VERSION = "verifier-current-space-migration-certificate-1"
EVIDENCE_VERSION = "verifier-current-space-migration-evidence-1"
MECHANISM_ID = "verifier.current-space.retained-partition-migration.1"
SCOPE = "selected_length_preserving_partition_migration"
_SIDES = ("before", "after")
_MAX_SAFE_INTEGER = 2**53 - 1
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class SpaceMigrationError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SPACE", "scope": SCOPE,
        "proposition": (
            "The independently selected exact before and after SPACE-3.1 "
            "children for the same SPACE subject both replay PASS, and the "
            "retained finite migration map is a bijection from the before "
            "layout's logical byte partitions onto the after layout's "
            "partitions in which every mapped after partition starts at the "
            "map's declared byte offset and has the same byte length as its "
            "before partition."),
        "prerequisites": [
            "exact separately selected before and after SPACE-3.1 requests, "
            "policies and retained certificates; both child replays PASS; "
            "retained migration map; finite checker limits"],
        "exclusions": [
            "actual host, device or storage allocation, copying or data movement",
            "routing tables, address translation hardware or physical containment",
            "isolation, non-leakage or retention of partition contents",
            "whole SPACE dynamics tier or object-profile conformance",
            "privacy, consent, governance, security, spending or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SpaceMigrationDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SpaceMigrationError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, SpaceMigrationError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               common_module, retained_selection, space_layout)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SPACE_LAYOUT.md",
                 "CURRENT_SPACE_MIGRATION.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=SpaceMigrationError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def space_migration_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


_CHILD_FIELDS = tuple(side + "_" + item for side in _SIDES
                      for item in ("request_digest", "policy_digest",
                                   "certificate_digest"))


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", *_CHILD_FIELDS,
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "SPACE")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SpaceMigrationError("selected SPACE migration objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise SpaceMigrationError("bounded SPACE subject required")
    for field in ("object_digest", "collection_digest", *_CHILD_FIELDS,
                  "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SpaceMigrationError)
    return selected


def space_migration_request(*, subject_id: str, object_digest: str,
        collection_digest: str, before_request_digest: str,
        before_policy_digest: str, before_certificate_digest: str,
        after_request_digest: str, after_policy_digest: str,
        after_certificate_digest: str, evidence_ref: str,
        policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise SpaceMigrationError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "SPACE",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "before_request_digest": before_request_digest,
        "before_policy_digest": before_policy_digest,
        "before_certificate_digest": before_certificate_digest,
        "after_request_digest": after_request_digest,
        "after_policy_digest": after_policy_digest,
        "after_certificate_digest": after_certificate_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_b64(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise Refuted(label + " must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted(label + " is noncanonical base64")
    return decoded


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _child(side: str, value: Any, request: dict[str, Any]) -> tuple[str, list[Any]]:
    """Recheck one selected SPACE-3.1 child; return its status and partitions."""
    child = _record(value, {"request", "policy", "certificate"}, side + " child")
    child_request, child_policy = child["request"], child["policy"]
    if ("sha256:" + canonical_digest(child_request) != request[side + "_request_digest"]
            or "sha256:" + canonical_digest(child_policy) != request[side + "_policy_digest"]):
        raise Refuted("selected " + side + " child request or policy differs")
    if (type(child_request) is not dict
            or child_request.get("subject_id") != request["subject_id"]
            or child_request.get("semantic_version") != space_layout.SEMANTIC_VERSION
            or child_request.get("coordinate") != space_layout.COORDINATE
            or child_request.get("object_kind") != "SPACE"):
        raise Refuted(side + " child is not the selected SPACE-3.1 subject")
    if side == "after" and (
            child_request.get("object_digest") != request["object_digest"]
            or child_request.get("collection_digest") != request["collection_digest"]):
        raise Refuted("after child is not the selected SPACE record")
    certificate = _decode_b64(child["certificate"], side + " child certificate")
    if len(certificate) > space_layout._MAX_CERTIFICATE_BYTES:
        raise Unavailable(side + " child certificate bound exhausted")
    if ("sha256:" + hashlib.sha256(certificate).hexdigest()
            != request[side + "_certificate_digest"]):
        raise Refuted("selected " + side + " child certificate differs")
    try:
        result = space_layout.recheck_space_layout_certificate(
            certificate, expected_request=child_request, policy=child_policy)
    except space_layout.SpaceLayoutError as exc:
        raise Refuted("selected " + side + " SPACE-3.1 child does not replay") from exc
    if result["status"] != "PASS":
        return result["status"], []
    retained_certificate = strict_json_loads(certificate.decode("utf-8"))
    data = _decode_b64(
        retained_certificate["evidence_payloads"][child_request["evidence_ref"]],
        side + " child retained evidence")
    return "PASS", strict_json_loads(data.decode("utf-8"))["inputs"]["partitions"]


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise Refuted(label + " must be a nonnegative safe integer byte offset")
    return value


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "before", "after", "migration"},
                        "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained migration evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        checked: dict[str, tuple[str, list[Any]]] = {}
        for side in _SIDES:
            # Both children are decided before the parent: a child FAIL
            # outranks the other child's UNKNOWN in either order.
            try:
                checked[side] = _child(side, value[side], request)
            except Unavailable:
                checked[side] = ("UNKNOWN", [])
        statuses = {status for status, _ in checked.values()}
        if statuses - {"PASS", "UNKNOWN"}:
            raise Refuted("selected SPACE-3.1 child did not pass")
        if "UNKNOWN" in statuses:
            raise Unavailable("selected SPACE-3.1 child remains UNKNOWN")
        before = {row["id"]: row for row in checked["before"][1]}
        after = {row["id"]: row for row in checked["after"][1]}
        budget.tick(len(before) + len(after))
        migration = value["migration"]
        if type(migration) is not list:
            raise Refuted("retained migration map must be a sequence")
        if len(migration) > limits["max_items"]:
            raise Unavailable("retained migration map bound exhausted")
        sources: set[str] = set()
        targets: set[str] = set()
        for row in migration:
            budget.tick()
            entry = _record(row, {"from", "to", "start_byte"}, "migration entry")
            source, target = entry["from"], entry["to"]
            if type(source) is not str or source not in before:
                raise Refuted("migration source is not a retained before partition")
            if type(target) is not str or target not in after:
                raise Refuted("migration target is not a retained after partition")
            if source in sources:
                raise Refuted("migration map assigns one before partition twice")
            if target in targets:
                raise Refuted("migration map is not injective")
            sources.add(source)
            targets.add(target)
            old, new = before[source], after[target]
            if new["start_byte"] != _integer(entry["start_byte"], "declared offset"):
                raise Refuted("after partition offset differs from the declared remap")
            if new["end_byte"] - new["start_byte"] != old["end_byte"] - old["start_byte"]:
                raise Refuted("migration does not preserve partition byte length")
        if sources != set(before):
            raise Refuted("migration map omits a before partition")
        if targets != set(after):
            raise Refuted("after layout has a partition outside the migration map")
        return MechanismDecision(MechanismOutcome.PASS,
            "selected length-preserving partition migration reproduced",
            {"partitions": len(before), "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SpaceMigrationMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound SPACE migration proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected migration bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SpaceMigrationError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_SpaceMigrationMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "SPACE", "scope": SCOPE,
        "partition_migration": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "host_allocation": "NOT_ESTABLISHED",
        "data_movement": "NOT_ESTABLISHED",
        "physical_non_leakage": "NOT_ESTABLISHED",
        "whole_space_dynamics": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise SpaceMigrationError("certificate byte bound exhausted")
    return encoded


def build_space_migration_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise SpaceMigrationError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SpaceMigrationError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_space_migration_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise SpaceMigrationError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise SpaceMigrationError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SpaceMigrationError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SpaceMigrationError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, SpaceMigrationError):
            raise
        raise SpaceMigrationError("invalid retained SPACE migration certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SpaceMigrationDescriptor",
           "SpaceMigrationError", "registration", "space_migration_policy",
           "space_migration_request", "build_space_migration_certificate",
           "recheck_space_migration_certificate"]
