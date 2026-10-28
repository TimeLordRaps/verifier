"""Reproduce the source-bound Tier-7 consent native specimen payload."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import zlib
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from verifier.consent import public, stages
from verifier.consent.engine import ConsentContext
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import consent_checks
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression


KINDS = tuple(
    "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT "
    "GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL "
    "HARNESS AGENT SIM BOT TOKEN".split()
)


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


def _sign(
        payload: dict[str, Any], key_id: str,
        private: dict[str, ed25519.Ed25519PrivateKey],
        ) -> dict[str, Any]:
    captured = deepcopy(payload)
    body = {
        "schema_version": "verifier-consent-public-envelope-1",
        "algorithm": "Ed25519",
        "key_id": key_id,
        "payload": captured,
        "payload_digest": hashlib.sha256(canonical_bytes(captured)).hexdigest(),
    }
    signature = private[key_id].sign(
        public.consent_signing_bytes(captured, key_id)
    )
    return {**body, "signature": signature.hex()}


def _generate(
        kind: str, stage: int,
        ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    objects = _collection()
    subject = next(item for item in objects if item.object_id == kind.lower())
    context = ConsentContext(
        subject.object_id,
        subject.digest.removeprefix("sha256:"),
        "inspect", "operator", "reader", "review", 100,
    )
    selected = []
    retained = {}
    historical = {}
    for index in range(2):
        holder = f"holder-{index}"
        private = {
            "root": ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes([1 + index * 2]) * 32
            ),
            "status": ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes([2 + index * 2]) * 32
            ),
        }
        keys = [
            {
                "key_id": name,
                "actor_id": holder if name == "root" else "registry-" + holder,
                "public_key": key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                ).hex(),
            }
            for name, key in private.items()
        ]
        holder_policy = public.public_consent_policy(
            policy_id="policy-" + holder,
            grantor_id=holder,
            keys=keys,
            root_key_ids=["root"],
            revocation_key_ids=["status"],
            artifact_bindings=[[subject.object_id, context.artifact_digest]],
            max_revocation_age_seconds=30,
        )
        grant = {
            "schema_version": "verifier-consent-public-grant-1",
            "grant_id": "grant-" + holder,
            "issuer_id": holder,
            "actor_id": "operator",
            "object_name": subject.object_id,
            "artifact_digest": context.artifact_digest,
            "operations": ["inspect"],
            "observer_ids": ["reader"],
            "purposes": ["review"],
            "not_before": 90,
            "not_after": 110,
            "effect": "ALLOW",
            "allow_delegation": False,
            "parent_digest": None,
        }
        status = {
            "schema_version": "verifier-consent-public-revocations-1",
            "issuer_id": "registry-" + holder,
            "policy_id": "policy-" + holder,
            "as_of": 95,
            "next_update": 105,
            "revoked_grant_ids": [],
        }
        selected.append({"holder_id": holder, "public_policy": holder_policy})
        row = {
            "grants": [_sign(grant, "root", private)],
            "revocation": _sign(status, "status", private),
            "receipt": None,
        }
        if stage == 5:
            row["receipt"] = stages.evaluate_consent_stages(
                context,
                tuple(row["grants"]),
                policy=holder_policy,
                revocation=row["revocation"],
                evaluation_time=100,
                computational_verdict="FAIL",
            )
            historical[holder] = "sha256:" + canonical_digest(row["receipt"])
        retained[holder] = row
    policy = consent_checks.consent_checks_policy(
        trust_roots=["selected-finite-consent-specimen"],
        required_holders=selected,
    )
    evidence_value = {
        "schema_version": consent_checks.EVIDENCE_VERSION,
        "objects": [
            item.to_dict()
            for item in sorted(objects, key=lambda item: item.object_id)
        ],
        "holders": retained,
    }
    evidence = canonical_bytes(evidence_value)
    request = consent_checks.consent_checks_request(
        object_kind=kind,
        stage=stage,
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref="sha256:" + canonical_digest(evidence_value),
        action={
            "operation": "inspect",
            "actor_id": "operator",
            "observer_id": "reader",
            "purpose": "review",
            "timestamp": 100,
        },
        evaluation_time=100,
        computational_verdict="FAIL",
        historical_receipts=historical,
        policy=policy,
    )
    return request, policy, evidence


def build_payload() -> tuple[bytes, bytes]:
    inventory = core_tier_progression.installed_core_route_inventory()
    memberships = sorted(
        [
            {
                "obligation_id": f"{cell['object_kind']}:{route['coordinate']}",
                "object_kind": cell["object_kind"],
                **route,
            }
            for cell in inventory["family_cells"]
            if cell["tier"] == 7
            for route in cell["registered_route_memberships"]
        ],
        key=lambda row: row["obligation_id"],
    )
    if len(memberships) != 156:
        raise RuntimeError("Tier-7 route denominator differs")
    payload = {}
    for membership in memberships:
        stage = int(membership["coordinate"].rsplit(".", 1)[1])
        request, policy, evidence = _generate(
            membership["object_kind"], stage
        )
        if (
            request["coordinate"] != membership["coordinate"]
            or request["semantic_version"] != membership["semantic_version"]
            or request["proposition_digest"]
                != membership["proposition_digest"]
            or request["policy_digest"]
                != core_obligation_union.value_digest(policy)
        ):
            raise RuntimeError("Tier-7 generated route binding differs")
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
        "entry_count": 156,
        "raw_bytes": len(raw),
        "encoded_bytes": len(encoded),
        "registry_digest": core_obligation_union.bytes_digest(raw),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
