"""Reproduce the source-bound Tier-5 native specimen payload."""
from __future__ import annotations

import base64
import hashlib
import json
import zlib
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import independence_checks
from verifier.domains.contracts import object_grounding
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression


SIM_INPUT_SCHEMA = "verifier-self-polish-native-object-grounding-input-1"


def _independence_collection() -> list[NamespaceObject]:
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
            "data": ["data"], "events": ["event"], "bench": ["bench"],
            "arch": ["arch"],
        },
        "MODEL": {
            "train": ["train"], "data": ["data"], "events": ["event"],
            "bench": ["bench"], "arch": ["arch"], "env": ["env"],
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
    return objects


def _independence_facets(
        objects: list[NamespaceObject], kind: str,
        ) -> dict[str, Any]:
    by_id = {item.object_id: item for item in objects}
    subject = by_id[kind.lower()]
    result: dict[str, Any] = {
        "subject_record": subject.digest,
        "payload": digest(subject.payload),
        "operands": {},
        "dependencies": {},
    }
    pending = []
    for role, refs in subject.operands:
        result["operands"][role] = {}
        for ref in refs:
            result["operands"][role][ref] = by_id[ref].digest
            pending.append(ref)
    seen = set()
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        seen.add(ref)
        result["dependencies"][ref] = by_id[ref].digest
        pending.extend(
            target
            for _role, refs in by_id[ref].operands
            for target in refs
        )
    return result


def _independence_case(
        kind: str,
        ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    objects = _independence_collection()
    subject = next(item for item in objects if item.object_id == kind.lower())
    collection_digest = composition_digest(objects)
    artifacts = {}

    def retain(data: bytes) -> str:
        ref = "sha256:" + hashlib.sha256(data).hexdigest()
        artifacts[ref] = base64.b64encode(data).decode("ascii")
        return ref

    sources = {}
    for role in ("producer", "checker"):
        support = retain(
            ("Retained " + role + " implementation artifact\n").encode()
        )
        trace = retain(canonical_bytes({
            "schema_version": independence_checks.TRACE_VERSION,
            "role": role,
            "object_kind": kind,
            "subject_id": subject.object_id,
            "object_digest": subject.digest,
            "collection_digest": collection_digest,
            "facets": _independence_facets(objects, kind),
        }))
        sources[role + "-support"] = {
            "artifact_ref": support, "parents": [],
        }
        sources[role] = {
            "artifact_ref": trace, "parents": [role + "-support"],
        }
    evidence_value = {
        "schema_version": independence_checks.EVIDENCE_VERSION,
        "collection": {
            "schema_version": independence_checks.COLLECTION_VERSION,
            "objects": [
                item.to_dict()
                for item in sorted(objects, key=lambda item: item.object_id)
            ],
        },
        "sources": sources,
        "artifacts": artifacts,
    }
    evidence = canonical_bytes(evidence_value)
    policy = independence_checks.independence_checks_policy(
        trust_roots=["selected-finite-documentary-source-model"],
        source_roots={"producer": ["producer"], "checker": ["checker"]},
        graph_digest=digest(sources),
        required_dimensions=["retained_provenance"],
    )
    request = independence_checks.independence_checks_request(
        object_kind=kind,
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=collection_digest,
        evidence_ref=digest(evidence_value),
        policy=policy,
    )
    return request, policy, evidence


def _sim_model() -> dict[str, Any]:
    return {
        "schema_version": "verifier-sim-isolation-evidence-1",
        "sim_id": "sim",
        "initial_state": "idle",
        "virtual_hardware": [
            {"id": "cpu", "kind": "compute"},
            {"id": "disk", "kind": "storage"},
        ],
        "states": [
            {
                "id": "idle", "partition": "inside",
                "capabilities": ["cpu", "disk"],
            },
            {
                "id": "busy", "partition": "inside",
                "capabilities": ["cpu", "disk"],
            },
            {
                "id": "outside", "partition": "outside",
                "capabilities": ["host:network"],
            },
        ],
        "actions": ["step"],
        "transitions": [
            {
                "source": "idle", "action": "step", "outcomes": [
                    {
                        "target": "busy", "effects": [
                            {"kind": "internal_write", "target": "cpu"},
                        ],
                    },
                    {"target": "idle", "effects": []},
                ],
            },
            {
                "source": "busy", "action": "step", "outcomes": [
                    {
                        "target": "idle", "effects": [
                            {"kind": "receipt_record", "target": "disk"},
                        ],
                    },
                ],
            },
        ],
    }


def _sim_objects(isolation: bytes) -> list[NamespaceObject]:
    make = NamespaceObject.create
    objects = [
        make("data", "DATA", {}),
        make("verifier", "VERIFIER", {}),
        make("room", "OBJECT", {}),
        make("env", "ENV", {}),
    ]
    objects.append(make(
        "sim",
        "SIM",
        {
            "isolation_evidence_digest": (
                "sha256:" + hashlib.sha256(isolation).hexdigest()
            ),
        },
        {
            "data": ["data"], "verifier": ["verifier"],
            "objects": ["room"], "env": ["env"],
        },
    ))
    return objects


def _sim_case() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    isolation = canonical_bytes(_sim_model())
    objects = _sim_objects(isolation)
    policy = object_grounding.current_object_policy(
        trust_roots=["checker-selected-local-fixture"]
    )
    request = object_grounding.current_object_request(
        objects,
        sim_id="sim",
        isolation_evidence_bytes=isolation,
        policy=policy,
    )
    collection = {
        "schema_version": object_grounding.COLLECTION_VERSION,
        "objects": [
            item.to_dict()
            for item in sorted(objects, key=lambda item: item.object_id)
        ],
    }
    replay_input = canonical_bytes({
        "schema_version": SIM_INPUT_SCHEMA,
        "collection": collection,
        "isolation_evidence_base64": base64.b64encode(isolation).decode(
            "ascii"
        ),
    })
    return request, policy, replay_input


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
            if cell["tier"] == 5
            for route in cell["registered_route_memberships"]
        ],
        key=lambda row: row["obligation_id"],
    )
    if len(memberships) != 26:
        raise RuntimeError("Tier-5 route denominator differs")
    payload = {}
    for membership in memberships:
        is_sim = membership["obligation_id"] == "SIM:SIM-5.1"
        if is_sim:
            request, policy, evidence = _sim_case()
        else:
            request, policy, evidence = _independence_case(
                membership["object_kind"]
            )
        if (
            request["coordinate"] != membership["coordinate"]
            or request["semantic_version"] != membership["semantic_version"]
            or request["proposition_digest"]
                != membership["proposition_digest"]
            or request["policy_digest"]
                != core_obligation_union.value_digest(policy)
            or (
                not is_sim
                and request["object_kind"] != membership["object_kind"]
            )
        ):
            raise RuntimeError("Tier-5 generated route binding differs")
        payload[membership["obligation_id"]] = {
            "builder_adapter": (
                "SIM_OBJECT_GROUNDING"
                if is_sim else "BOUNDED_EVIDENCE_BYTES"
            ),
            "checking_mechanism": membership["checking_mechanism"],
            "evidence_base64": base64.b64encode(evidence).decode("ascii"),
            "negative_adapter": (
                "SIM_ISOLATION_MALFORMED_REBIND"
                if is_sim else "MALFORMED_EVIDENCE_REBIND"
            ),
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
