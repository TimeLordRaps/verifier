"""Reproduce the source-bound Tier-6 privacy native specimen payload."""
from __future__ import annotations

import base64
import json
import zlib
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import privacy_checks
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression


KINDS = tuple(
    "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT "
    "GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL "
    "HARNESS AGENT SIM BOT TOKEN".split()
)
FIELDS = ("kind", "object_id", "operands", "payload")


def _collection() -> list[NamespaceObject]:
    make = NamespaceObject.create
    primitive = (
        "HUMAN ROLE HARDWARE OBJECT SPACE TIME ENV DATA VERIFIER ARCH "
        "HARNESS TOKEN"
    ).split()
    objects = [
        make(kind.lower(), kind, {"fixture": kind}) for kind in primitive
    ]
    operands = {
        "ACTOR": {"representation": ["human"], "root_human": ["human"]},
        "COLLECTIVE": {"roles": ["role"]},
        "IDENTITY": {"actor": ["actor"], "role": ["role"]},
        "OWNER": {"actor": ["actor"], "object": ["object"]},
        "RECEIPT": {"subject": ["object"], "hardware": ["hardware"]},
        "EVENT": {
            "time": ["time"], "space": ["space"], "meaning": ["object"],
        },
        "BENCH": {"verifier": ["verifier"], "data": ["data"]},
        "TRAIN": {
            "data": ["data"], "events": ["event"],
            "bench": ["bench"], "arch": ["arch"],
        },
        "MODEL": {
            "train": ["train"], "data": ["data"],
            "events": ["event"], "bench": ["bench"],
            "arch": ["arch"], "env": ["env"],
            "hardware": ["hardware"],
        },
        "AGENT": {
            "model": ["model"], "harness": ["harness"], "env": ["env"],
        },
        "SIM": {
            "data": ["data"], "verifier": ["verifier"],
            "objects": ["object"], "env": ["env"],
        },
        "BOT": {"agent": ["agent"], "sim": ["sim"], "env": ["env"]},
        "HYPER": {"model": ["model"], "identity": ["identity"]},
    }
    objects.extend(
        make(kind.lower(), kind, {"fixture": kind}, value)
        for kind, value in operands.items()
    )
    objects.append(
        make("graph", "GRAPH", {"element_kind": "ENV"}, {"members": ["env"]})
    )
    if {item.kind.value for item in objects} != set(KINDS):
        raise RuntimeError("fixture collection does not cover current kinds")
    return objects


def _policy_inputs() -> dict[str, Any]:
    return {
        "trust_roots": ["selected-finite-disclosure-specimen"],
        "observer": {
            "actor_id": "reader",
            "role": "auditor",
            "purpose": "inspect",
            "credentials": ["declared-review"],
        },
        "disclosed_fields": list(FIELDS),
        "withheld_fields": [],
        "bounds": [
            {
                "bound_id": "admit:" + field,
                "field_name": field,
                "admitted_observers": ["reader"],
                "admitted_roles": [],
                "conditions": [
                    ["purpose", "inspect"],
                    ["credential", "declared-review"],
                ],
            }
            for field in FIELDS
        ],
        "co_emitted_ids": [],
        "extra_join_rules": [],
    }


def _generate(kind: str) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    objects = _collection()
    subject = next(item for item in objects if item.object_id == kind.lower())
    evidence_value = {
        "schema_version": privacy_checks.EVIDENCE_VERSION,
        "objects": [
            item.to_dict()
            for item in sorted(objects, key=lambda item: item.object_id)
        ],
    }
    evidence = canonical_bytes(evidence_value)
    policy = privacy_checks.privacy_checks_policy(**_policy_inputs())
    request = privacy_checks.privacy_checks_request(
        object_kind=kind,
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(evidence_value),
        timestamp="2026-09-28T13:00:00Z",
        policy=policy,
    )
    return request, policy, evidence


def build_payload() -> tuple[bytes, bytes]:
    inventory = core_tier_progression.installed_core_route_inventory()
    memberships = sorted(
        [
            {
                "obligation_id": (
                    f"{cell['object_kind']}:{route['coordinate']}"
                ),
                "object_kind": cell["object_kind"],
                **route,
            }
            for cell in inventory["family_cells"]
            if cell["tier"] == 6
            for route in cell["registered_route_memberships"]
        ],
        key=lambda row: row["obligation_id"],
    )
    if len(memberships) != 26:
        raise RuntimeError("Tier-6 route denominator differs")
    payload = {}
    for membership in memberships:
        request, policy, evidence = _generate(membership["object_kind"])
        if (
            request["coordinate"] != membership["coordinate"]
            or request["semantic_version"] != membership["semantic_version"]
            or request["proposition_digest"]
                != membership["proposition_digest"]
            or request["policy_digest"]
                != core_obligation_union.value_digest(policy)
        ):
            raise RuntimeError("Tier-6 generated route binding differs")
        payload[membership["obligation_id"]] = {
            "builder_adapter": "BOUNDED_EVIDENCE_BYTES",
            "checking_mechanism": membership["checking_mechanism"],
            "evidence_base64": base64.b64encode(evidence).decode("ascii"),
            "negative_adapter": "MALFORMED_EVIDENCE_REBIND",
            "policy": policy,
            "request": request,
            "unknown_adapter": "ABSENT_EVIDENCE",
        }
    raw = core_obligation_union.canonical_bytes(payload)
    return raw, base64.b85encode(zlib.compress(raw, 9))


def main() -> int:
    raw, encoded = build_payload()
    print(json.dumps({
        "entry_count": 26,
        "raw_bytes": len(raw),
        "encoded_bytes": len(encoded),
        "registry_digest": core_obligation_union.bytes_digest(raw),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
