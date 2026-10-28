"""Reproduce the source-bound Tier-8 governance native specimen payload."""
from __future__ import annotations

import base64
import json
import zlib
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import object_governance
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression


KINDS = tuple(
    "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT "
    "GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL "
    "HARNESS AGENT SIM BOT TOKEN".split()
)


def _digest(value: Any) -> str:
    return "sha256:" + canonical_digest(value)


def _signed(
        secret: ed25519.Ed25519PrivateKey, role: str, key_id: str,
        payload: dict[str, Any],
        ) -> dict[str, Any]:
    return {
        "schema_version": object_governance.ENVELOPE_VERSION,
        "key_id": key_id,
        "payload": payload,
        "signature": secret.sign(
            object_governance.signing_bytes(role, key_id, payload)
        ).hex(),
    }


def _generate(kind: str) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    item = NamespaceObject.create(
        "selected-subject", kind, {"declared": "value"}
    )
    keys = [
        ed25519.Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
        for index in range(1, 4)
    ]
    public_keys = [
        key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()
        for key in keys
    ]
    policy = object_governance.governance_policy(
        namespace_id="selected-namespace",
        policy_id="selected-policy",
        revision=4,
        decision_keys=[
            {
                "actor_id": f"actor-{index}",
                "key_id": f"vote-{index}",
                "public_key": public_keys[index],
            }
            for index in range(2)
        ],
        status_key={"key_id": "status", "public_key": public_keys[2]},
        quorum=2,
        valid_from=100,
        valid_until=300,
        max_status_age_seconds=20,
    )
    decisions = [
        _signed(
            keys[index],
            "decision",
            f"vote-{index}",
            {
                "schema_version": object_governance.DECISION_VERSION,
                "decision_id": f"decision-{index}",
                "actor_id": f"actor-{index}",
                "policy_digest": _digest(policy),
                "record_digest": _digest(item.to_dict()),
                "namespace_id": "selected-namespace",
                "action": "NAMESPACE_ADMIT",
                "vote": "APPROVE",
                "issued_at": 180,
                "expires_at": 220,
            },
        )
        for index in range(2)
    ]
    status = _signed(
        keys[2],
        "status",
        "status",
        {
            "schema_version": object_governance.STATUS_VERSION,
            "policy_digest": _digest(policy),
            "as_of": 195,
            "expires_at": 220,
            "revoked_decision_ids": [],
        },
    )
    evidence_value = {
        "schema_version": object_governance.EVIDENCE_VERSION,
        "record": item.to_dict(),
        "decisions": decisions,
        "status": status,
    }
    evidence = canonical_bytes(evidence_value)
    request = object_governance.governance_request(
        item,
        namespace_id="selected-namespace",
        evidence_ref=_digest(evidence_value),
        evaluation_time=200,
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
            if cell["tier"] == 8
            for route in cell["registered_route_memberships"]
        ],
        key=lambda row: row["obligation_id"],
    )
    if len(memberships) != 26:
        raise RuntimeError("Tier-8 route denominator differs")
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
            raise RuntimeError("Tier-8 generated route binding differs")
        payload[membership["obligation_id"]] = {
            "builder_adapter": "BOUNDED_EVIDENCE_BYTES",
            "checking_mechanism": membership["checking_mechanism"],
            "evidence_base64": base64.b64encode(evidence).decode("ascii"),
            "negative_adapter": "GOVERNANCE_INVALID_SIGNATURE",
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
