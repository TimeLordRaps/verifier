"""Explicit version 2 capacity for Verifier Standard (VSTD) assessments.

JavaScript Object Notation (JSON); Unicode Transformation Format, 8-bit (UTF-8).
This transport preserves exact native certificate bytes, not native authority.
Counts are dimensionless; byte quantities count the stated encoded workload.
It discharges no numbered profile and never issues a polished artifact.
"""
from __future__ import annotations

import base64
import binascii
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectCoordinate, assess_composition
from verifier.runtime import polish


CEILINGS = {
    "bundle_bytes": 64 * 1024 * 1024, "request_bytes": 8 * 1024 * 1024,
    "objects": 4096, "requirements": 36864, "objectives": 8192,
    "certificates": 8192, "evidence_bytes": 64 * 1024 * 1024,
    "certificate_bytes": 64 * 1024 * 1024, "replay_bytes": 256 * 1024 * 1024,
    "composition_operations": 1000000, "composition_payload_bytes": 64 * 1024 * 1024,
    "composition_reference_bytes": 16 * 1024 * 1024, "output_bytes": 32 * 1024 * 1024,
}


class CapacityExceeded(ValueError):
    """A named independently selected budget cannot discharge the workload."""

    def __init__(self, resource: str) -> None:
        super().__init__("selected resource exhausted")
        self.resource = resource


class Budget:
    """Per-operation captured limits; never changes version 1 module globals."""

    def __init__(self, limits: Any) -> None:
        polish._keys(limits, " ".join(CEILINGS))
        if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling
               for key, ceiling in CEILINGS.items()) or limits["output_bytes"] < 4096:
            raise ValueError("invalid resource contract")
        self.limits = dict(limits)
        self.usage = {key: 0 for key in CEILINGS}

    def charge(self, resource: str, count: int) -> None:
        if count > self.limits[resource] - self.usage[resource]:
            raise CapacityExceeded(resource)
        self.usage[resource] += count


def _certificates(bundle: dict[str, Any], budget: Budget) -> dict[str, bytes]:
    packed, shared = bundle["certificates"], bundle["evidence_payloads"]
    if type(packed) is not dict or type(shared) is not dict:
        raise ValueError("certificate and shared payload maps required")
    budget.charge("certificates", len(packed))
    decoded = {}
    for digest, encoded in shared.items():
        polish._hash(digest)
        if type(encoded) is not str or not encoded.isascii() or len(encoded) % 4:
            raise ValueError("canonical base64 required")
        # Preflight decoded allocation; validation still checks alphabet and pad bits.
        size = len(encoded) // 4 * 3 - (len(encoded) - len(encoded.rstrip("=")))
        if size < 0:
            raise ValueError("invalid base64 size")
        budget.charge("evidence_bytes", size)
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded or polish._digest(raw) != digest:
            raise ValueError("shared evidence differs from exact commitment")
        decoded[digest] = raw
    captured, used = {}, set()
    for digest, packed_certificate in packed.items():
        polish._hash(digest)
        if type(packed_certificate) is not dict:
            raise ValueError("explicit certificate encoding required")
        encoding = packed_certificate.get("encoding")
        if encoding == "utf8":
            polish._keys(packed_certificate, "encoding text")
            text = packed_certificate["text"]
            if type(text) is not str:
                raise ValueError("exact certificate text required")
            raw = text.encode("utf-8")
            budget.charge("certificate_bytes", len(raw))
        elif encoding in ("shared-canonical-json", "shared-text-json"):
            field = "evidence_refs" if encoding == "shared-canonical-json" else "evidence_ref"
            polish._keys(packed_certificate, "encoding envelope " + field)
            envelope = packed_certificate["envelope"]
            if type(envelope) is not dict:
                raise ValueError("canonical certificate envelope required")
            refs = packed_certificate[field]
            if field == "evidence_ref":
                refs = [polish._hash(refs)]
                key = "evidence"
            else:
                if type(refs) is not list or any(type(ref) is not str for ref in refs):
                    raise ValueError("sorted unique payload references required")
                if refs != sorted(set(refs)):
                    raise ValueError("sorted unique payload references required")
                for ref in refs:
                    polish._hash(ref)
                key = "evidence_payloads"
            if key in envelope or any(ref not in decoded for ref in refs):
                raise ValueError("ambiguous or missing retained payload")
            # Count the exact reconstructed encoding before copying shared payloads.
            envelope_size = len(canonical_bytes(envelope))
            if key == "evidence":
                value: Any = decoded[refs[0]].decode("utf-8")
                value_size = len(canonical_bytes(value))
            else:
                value_size = 2 + sum(len(canonical_bytes(ref)) + 1 + len(shared[ref]) + 2
                                     for ref in refs) + max(0, len(refs) - 1)
                value = None
            size = envelope_size + len(canonical_bytes(key)) + 1 + value_size + bool(envelope)
            budget.charge("certificate_bytes", size)
            if key == "evidence_payloads":
                value = {ref: shared[ref] for ref in refs}
            raw = canonical_bytes({**envelope, key: value})
            if len(raw) != size:
                raise ValueError("reconstruction accounting differs")
            used.update(refs)
        else:
            raise ValueError("unsupported certificate encoding")
        if polish._digest(raw) != digest:
            raise ValueError("reconstructed certificate differs from selected digest")
        captured[digest] = raw
    if used != set(shared):
        raise ValueError("unreferenced shared evidence")
    return captured


def _prepare(bundle: dict[str, Any], request: dict[str, Any], budget: Budget) -> dict[str, Any]:
    records = bundle["objects"]
    if type(records) is not list or not records:
        raise ValueError("nonempty object inventory required")
    budget.charge("objects", len(records))
    objects = {}
    for record in records:
        polish._keys(record, "object_id kind payload operands")
        if type(record["operands"]) is not dict:
            raise ValueError("operand map required")
        item = NamespaceObject.create(record["object_id"], record["kind"],
                                      record["payload"], record["operands"])
        if item.object_id in objects:
            raise ValueError("duplicate object identity")
        objects[item.object_id] = item
    if polish._text(request["root_id"]) not in objects:
        raise ValueError("selected root absent")
    collection_digest = polish._hash(request["collection_digest"])
    requirements = request["requirements"]
    if type(requirements) is not list:
        raise ValueError("applicability inventory required")
    budget.charge("requirements", len(requirements))
    seen, selections, applicability = set(), [], []
    for row in requirements:
        polish._keys(row, "object_id tier applicability rationale objectives")
        object_id = polish._text(row["object_id"])
        tier = row["tier"]
        if (object_id not in objects or type(tier) is not int or not 1 <= tier <= 9
                or (object_id, tier) in seen):
            raise ValueError("unknown or duplicate applicability coordinate")
        seen.add((object_id, tier))
        if row["applicability"] not in ("REQUIRED", "NOT_APPLICABLE", "UNKNOWN"):
            raise ValueError("unknown applicability declaration")
        polish._text(row["rationale"])
        objectives = row["objectives"]
        if type(objectives) is not list or (row["applicability"] != "REQUIRED" and objectives):
            raise ValueError("invalid selected objectives")
        budget.charge("objectives", len(objectives))
        applicability.append(row["applicability"])
        unique = set()
        for selected in objectives:
            polish._keys(selected, "semantic_version coordinate request policy certificate_digest")
            semantic = polish._text(selected["semantic_version"])
            if semantic == "verifier-current-ten-tier-object-obligations-1":
                raise ValueError("historical nine-tier polish semantic version differs")
            address = ObjectCoordinate.parse(polish._text(selected["coordinate"]))
            if (address.tier.value != tier or address.object_kind.value not in
                    ("OBJECT", objects[object_id].kind.value) or (semantic, str(address)) in unique):
                raise ValueError("objective differs from declared coordinate")
            unique.add((semantic, str(address)))
            polish._hash(selected["certificate_digest"])
            if type(selected["request"]) is not dict or type(selected["policy"]) is not dict:
                raise ValueError("independent native request and policy required")
            selections.append((selected, objects[object_id]))
    captured = _certificates(bundle, budget)
    for selected, _ in selections:
        budget.charge("replay_bytes", len(captured.get(selected["certificate_digest"], b"")))
    budget.charge("composition_payload_bytes", sum(len(item.payload_bytes) for item in objects.values()))
    references = sum(len(canonical_bytes(item.object_id)) + sum(
        len(canonical_bytes(role)) + sum(len(canonical_bytes(ref)) for ref in targets)
        for role, targets in item.operands) for item in objects.values())
    budget.charge("composition_reference_bytes", references)
    # Composition owns its operation counter. Reserve the selected allowance and
    # finish its bounded traversal before any native objective invocation.
    budget.charge("composition_operations", budget.limits["composition_operations"])
    composition = assess_composition(tuple(objects.values()), expected_digest=collection_digest,
        max_objects=budget.limits["objects"], max_operations=budget.limits["composition_operations"],
        max_payload_bytes=budget.limits["composition_payload_bytes"],
        max_reference_bytes=budget.limits["composition_reference_bytes"])
    if composition.verdict.value == "UNKNOWN":
        raise CapacityExceeded("composition_operations")
    missing = [{"object_id": object_id, "tier": tier} for object_id in sorted(objects)
               for tier in range(1, 10) if (object_id, tier) not in seen]
    # Reserve bounded output before replay, including worst-case route metadata.
    reservation = 4096 + len(canonical_bytes(missing)) + sum(1024 + len(canonical_bytes({
        "object_id": item.object_id, "coordinate": selected["coordinate"],
        "semantic_version": selected["semantic_version"],
        "certificate_digest": selected["certificate_digest"]})) for selected, item in selections)
    budget.charge("output_bytes", reservation)
    return {"objects": objects, "selections": selections, "certificates": captured,
            "composition": composition, "missing": missing, "applicability": applicability}


def assess(bundle_bytes: bytes, request_bytes: bytes) -> dict[str, Any]:
    """Assess selected version 2 work; exhausted capacity never becomes a pass."""
    report = {"schema_version": "verifier-polish-assessment-2", "polished": False,
        "objective_inventory_closure": "NOT_ESTABLISHED", "claim_boundary": polish.BOUNDARY,
        "mechanism_digest": polish.mechanism_digest()}
    budget = None
    try:
        request = polish._load(request_bytes, CEILINGS["request_bytes"])
        polish._keys(request, "schema_version root_id collection_digest bundle_digest requirements limits")
        if request["schema_version"] != "verifier-polish-request-2":
            raise ValueError("version 2 request required")
        budget = Budget(request["limits"])
        if type(bundle_bytes) is not bytes or polish._hash(request["bundle_digest"]) != polish._digest(bundle_bytes):
            raise ValueError("externally selected bundle commitment differs")
        report.update(bundle_digest=polish._digest(bundle_bytes), request_digest=polish._digest(request_bytes))
        budget.charge("request_bytes", len(request_bytes))
        budget.charge("bundle_bytes", len(bundle_bytes))
        bundle = polish._load(bundle_bytes, CEILINGS["bundle_bytes"])
        polish._keys(bundle, "schema_version objects certificates evidence_payloads")
        if bundle["schema_version"] != "verifier-polish-bundle-2":
            raise ValueError("version 2 bundle required")
        prepared = _prepare(bundle, request, budget)
        results = [polish._objective(selected, item, prepared["certificates"], request["collection_digest"])
                   for selected, item in prepared["selections"]]
        composition_status = prepared["composition"].verdict.value
        status = "FAIL" if composition_status == "FAIL" or any(row["status"] == "FAIL" for row in results) else "UNKNOWN"
        report.update(status=status, composition_status=composition_status,
            root_id=request["root_id"], collection_digest=request["collection_digest"],
            tier_inventory_status="UNKNOWN" if prepared["missing"] else "PASS",
            applicability_status="PASS" if not prepared["missing"] and all(
                value == "REQUIRED" for value in prepared["applicability"]) else "UNKNOWN",
            missing_tiers=prepared["missing"], objectives=results, resource_usage=budget.usage,
            remaining_gates=["APPLICABLE_OBJECTIVE_INVENTORY_CLOSURE",
                "PUBLIC_CHECKABILITY_FOR_EVERY_REQUIRED_OBJECTIVE",
                "AUTHENTICATED_AUTHORITY_AND_INAPPLICABILITY"])
    except CapacityExceeded as exc:
        report.update(status="UNKNOWN", reason="RESOURCE_LIMIT_EXCEEDED", exhausted_resource=exc.resource)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError, binascii.Error):
        report.update(status="FAIL", reason="INVALID_OR_SUBSTITUTED_INPUT")
    report["assessment_digest"] = polish._digest(canonical_bytes(report))
    # Output reservation includes this digest and the complete resource report.
    if budget is not None and len(canonical_bytes(report)) > budget.limits["output_bytes"]:
        raise RuntimeError("assessment output exceeded its preflight reservation")
    return report
