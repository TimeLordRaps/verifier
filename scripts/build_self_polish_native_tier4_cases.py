"""Reproduce and live-validate the source-bound Tier-4 specimen payload.

The non-HYPER semantic seed bytes were reviewed at the pinned digest below.
They are data only: this builder imports no test module, reconstructs every
source-derived policy, request, and prerequisite certificate through current
public contract application programming interfaces (APIs), reconstructs HYPER
directly, binds every request to the live route inventory, and replays every
PASS/FAIL/UNKNOWN triad before emitting a payload.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any
import zlib

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import hyper_closure
from verifier.domains.contracts import current_object_routes
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import self_polish_native_adapters as adapters

try:
    from scripts import render_self_polish_native_case_module as source_rebinding
except ImportError:  # Direct ``python scripts/...`` execution.
    import render_self_polish_native_case_module as source_rebinding


SEED_PATH = (
    Path(__file__).resolve().parent
    / "fixtures" / "self_polish_native_tier4_seed.json"
)
SEED_DIGEST = (
    "sha256:66a9bfb3d4950e85d06ed0e6e617fbe7f50e545cdf5c6931a926e68cca1c5b68"
)
SEED_ENTRY_COUNT = 32
_SEED_ENTRY_KEYS = {
    "checking_mechanism", "evidence_base64", "policy", "request",
}


def _memberships() -> list[dict[str, Any]]:
    inventory = core_tier_progression.installed_core_route_inventory()
    if inventory.get("status") != "PASS":
        raise RuntimeError("Tier-4 route inventory is not PASS")
    rows = sorted(
        [
            {
                "obligation_id": (
                    f"{cell['object_kind']}:{route['coordinate']}"
                ),
                "object_kind": cell["object_kind"],
                **route,
            }
            for cell in inventory.get("family_cells", [])
            if type(cell) is dict and cell.get("tier") == 4
            for route in cell.get("registered_route_memberships", [])
            if type(route) is dict
        ],
        key=lambda row: row["obligation_id"],
    )
    if (
        len(rows) != SEED_ENTRY_COUNT
        or len({row["obligation_id"] for row in rows})
            != SEED_ENTRY_COUNT
    ):
        raise RuntimeError("Tier-4 route denominator differs")
    return rows


def _load_seed() -> dict[str, dict[str, Any]]:
    raw = SEED_PATH.read_bytes()
    if core_obligation_union.bytes_digest(raw) != SEED_DIGEST:
        raise RuntimeError("Tier-4 reviewed seed digest differs")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise RuntimeError("Tier-4 reviewed seed is invalid") from exc
    if (
        type(value) is not dict
        or len(value) != SEED_ENTRY_COUNT
        or canonical_bytes(value) != raw
        or not all(
            type(identifier) is str
            and type(case) is dict
            and set(case) == _SEED_ENTRY_KEYS
            and type(case["checking_mechanism"]) is str
            and type(case["request"]) is dict
            and type(case["policy"]) is dict
            and type(case["evidence_base64"]) is str
            for identifier, case in value.items()
        )
    ):
        raise RuntimeError("Tier-4 reviewed seed is invalid")
    return value


def _hyper_case() -> dict[str, Any]:
    make = NamespaceObject.create
    objects = [
        make("t", "TIME", {}),
        make("s", "SPACE", {}),
        make("meaning", "OBJECT", {}),
        make("d", "DATA", {}),
        make(
            "e", "EVENT", {},
            {"time": ["t"], "space": ["s"], "meaning": ["meaning"]},
        ),
        make("h", "HYPER", {}, {"event": ["e"], "input": ["d"]}),
    ]
    policy = hyper_closure.hyper_closure_policy(
        trust_roots=["independent-local-policy"]
    )
    request = hyper_closure.hyper_closure_request(
        objects, hyper_id="h", policy=policy
    )
    evidence = canonical_bytes({
        "schema_version": hyper_closure.COLLECTION_VERSION,
        "objects": [
            item.to_dict()
            for item in sorted(objects, key=lambda item: item.object_id)
        ],
    })
    return {
        "checking_mechanism": (
            "verifier.domains.contracts.hyper_closure."
            "recheck_hyper_closure_certificate"
        ),
        "request": request,
        "policy": policy,
        "evidence_base64": base64.b64encode(evidence).decode("ascii"),
    }


def _byte_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _private_key(octet: int) -> Any:
    """Return one public, deterministic fixture-only Ed25519 private key."""

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Tier-4 signed fixture regeneration requires the seal extra"
        ) from exc
    return Ed25519PrivateKey.from_private_bytes(bytes([octet]) * 32)


def _public_key_hex(private_key: Any) -> str:
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Tier-4 signed fixture regeneration requires the seal extra"
        ) from exc
    return private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()


def _identity_case(
        seed: dict[str, Any],
        rebinder: source_rebinding.SourceCaseRebinder,
        ) -> dict[str, Any]:
    """Re-sign the reviewed identity selection after child source rebinding."""

    from verifier.domains.contracts import identity_presentation

    case = rebinder.refresh_case(seed)
    evidence = json.loads(base64.b64decode(
        case["evidence_base64"], validate=True
    ))
    request = case["request"]
    policy = case["policy"]
    child_request = evidence["identity_lifecycle_certificate"]["request"]
    keys = {
        "a": _private_key(17),
        "b": _private_key(34),
        "holder": _private_key(51),
    }
    public_keys = {
        name: _public_key_hex(key) for name, key in keys.items()
    }
    sources = {row["source_id"]: row for row in policy["sources"]}
    if (
        sources["configured-source-a"]["public_key"] != public_keys["a"]
        or sources["configured-source-b"]["public_key"] != public_keys["b"]
        or policy["holder_public_key"] != public_keys["holder"]
    ):
        raise RuntimeError("Tier-4 identity fixture key selection differs")

    selection = identity_presentation.claim_selection_digest(request)
    probe = {
        key: value
        for key, value in evidence["exit_probe"].items()
        if key != "signature"
    }
    probe.update({
        "selection_digest": selection,
        "binding_digest": request["binding_digest"],
        "head_digest": child_request["selected_head_digest"],
    })
    probe["signature"] = keys["holder"].sign(
        identity_presentation.probe_signing_bytes(probe)
    ).hex()
    probe_ref = core_obligation_union.value_digest(probe)

    supports: dict[str, Any] = {}
    for requirement_id, retained in evidence["supports"].items():
        envelope = dict(retained)
        payload = dict(envelope["payload"])
        witness = dict(payload["witness"])
        payload.update({
            "selection_digest": selection,
            "binding_digest": request["binding_digest"],
            "subject_id": request["subject_id"],
            "object_digest": request["object_digest"],
        })
        if requirement_id == "assurance":
            witness["native_identity_scope_certificate_ref"] = request[
                "identity_scope_certificate_ref"
            ]
        elif requirement_id == "exit":
            witness.update({
                "holder_id": policy["holder_id"],
                "holder_public_key": policy["holder_public_key"],
                "probe_ref": probe_ref,
            })
        elif requirement_id == "status":
            witness.update({
                "head_digest": child_request["selected_head_digest"],
                "event_count": child_request["selected_event_count"],
            })
        payload["witness"] = witness
        envelope["payload"] = payload
        signing_key = (
            keys["b"] if payload["purpose"] == "attribute" else keys["a"]
        )
        envelope["signature"] = signing_key.sign(
            identity_presentation.support_signing_bytes(
                envelope["source_id"], envelope["key_id"], payload
            )
        ).hex()
        supports[requirement_id] = envelope

    evidence.update({"exit_probe": probe, "supports": supports})
    raw = canonical_bytes(evidence)
    request = source_rebinding._invoke_from_seed(
        identity_presentation.identity_presentation_request,
        request,
        overrides={
            "identity_lifecycle_request": child_request,
            "identity_lifecycle_certificate_ref": (
                core_obligation_union.value_digest(
                    evidence["identity_lifecycle_certificate"]
                )
            ),
            "exit_probe_ref": probe_ref,
            "support_refs": {
                identifier: core_obligation_union.value_digest(value)
                for identifier, value in supports.items()
            },
            "evidence_ref": core_obligation_union.value_digest(evidence),
            "policy": policy,
        },
    )
    if identity_presentation.claim_selection_digest(request) != selection:
        raise RuntimeError("Tier-4 identity selection changed during signing")
    case.update({
        "request": request,
        "evidence_base64": base64.b64encode(raw).decode("ascii"),
    })
    return case


def _certificate_evidence(certificate: dict[str, Any]) -> dict[str, Any]:
    reference = certificate["request"]["evidence_ref"]
    return json.loads(base64.b64decode(
        certificate["evidence_payloads"][reference], validate=True
    ))


def _sim_signatures_case(
        seed: dict[str, Any],
        rebinder: source_rebinding.SourceCaseRebinder,
        ) -> dict[str, Any]:
    """Re-sign the exact reviewed shard rows after child source rebinding."""

    from verifier.domains.contracts import sim_shard_signatures

    case = rebinder.refresh_case(seed)
    evidence = json.loads(base64.b64decode(
        case["evidence_base64"], validate=True
    ))
    request, policy = case["request"], case["policy"]
    relations_certificate = json.loads(base64.b64decode(
        evidence["relations_certificate"], validate=True
    ))
    relations_evidence = _certificate_evidence(relations_certificate)
    shard_certificate = json.loads(base64.b64decode(
        relations_evidence["shard_certificate"], validate=True
    ))
    rows = _certificate_evidence(shard_certificate)["shard_rows"]
    signatures: dict[str, list[str]] = {}
    for index, shard_id in enumerate(policy["required_shards"]):
        private = _private_key(index + 1)
        if _public_key_hex(private) != policy["public_keys"][shard_id]:
            raise RuntimeError("Tier-4 shard fixture key selection differs")
        signatures[shard_id] = [
            private.sign(sim_shard_signatures.sim_shard_signature_message(
                request, policy=policy, shard_id=shard_id,
                step_index=step_index, time=row["time"],
                state=row["state"],
            )).hex()
            for step_index, row in enumerate(rows[shard_id])
        ]
    evidence["signatures"] = signatures
    raw = canonical_bytes(evidence)
    request = source_rebinding._invoke_from_seed(
        sim_shard_signatures.sim_shard_signatures_request,
        request,
        overrides={
            "evidence_ref": _byte_digest(raw),
            "policy": policy,
        },
    )
    case.update({
        "request": request,
        "evidence_base64": base64.b64encode(raw).decode("ascii"),
    })
    return case


def _sim_surface_case(
        seed: dict[str, Any],
        rebinder: source_rebinding.SourceCaseRebinder,
        ) -> dict[str, Any]:
    """Bind SIM-4.4 to the freshly regenerated signed SIM-4.3 child."""

    from verifier.domains.contracts import sim_shard_signatures
    from verifier.domains.contracts import sim_surface_partition

    retained_evidence = json.loads(base64.b64decode(
        seed["evidence_base64"], validate=True
    ))
    retained_certificate = json.loads(base64.b64decode(
        retained_evidence["signatures_certificate"], validate=True
    ))
    retained_child_evidence = _certificate_evidence(retained_certificate)
    signatures_case = _sim_signatures_case({
        "checking_mechanism": (
            "verifier.domains.contracts.sim_shard_signatures."
            "recheck_sim_shard_signatures_certificate"
        ),
        "request": retained_evidence["signatures_request"],
        "policy": retained_evidence["signatures_policy"],
        "evidence_base64": base64.b64encode(
            canonical_bytes(retained_child_evidence)
        ).decode("ascii"),
    }, rebinder)
    child_request = signatures_case["request"]
    child_policy = signatures_case["policy"]
    child_evidence = base64.b64decode(
        signatures_case["evidence_base64"], validate=True
    )
    child_certificate = (
        sim_shard_signatures.build_sim_shard_signatures_certificate(
            child_request, child_evidence, policy=child_policy
        )
    )
    policy = rebinder.refresh_policy(seed["policy"])
    evidence = retained_evidence
    evidence.update({
        "signatures_request": child_request,
        "signatures_policy": child_policy,
        "signatures_certificate": base64.b64encode(
            child_certificate
        ).decode("ascii"),
    })
    raw = canonical_bytes(evidence)
    request = source_rebinding._invoke_from_seed(
        sim_surface_partition.sim_surface_partition_request,
        seed["request"],
        overrides={
            "signatures_request_digest": (
                core_obligation_union.value_digest(child_request)
            ),
            "signatures_policy_digest": (
                core_obligation_union.value_digest(child_policy)
            ),
            "signatures_certificate_digest": _byte_digest(
                child_certificate
            ),
            "evidence_ref": _byte_digest(raw),
            "policy": policy,
        },
    )
    case = dict(seed)
    case.update({
        "policy": policy,
        "request": request,
        "evidence_base64": base64.b64encode(raw).decode("ascii"),
    })
    return case


def _validate_binding(
        identifier: str, case: dict[str, Any], row: dict[str, Any],
        ) -> None:
    request = case["request"]
    try:
        evidence = base64.b64decode(
            case["evidence_base64"], validate=True
        )
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Tier-4 evidence encoding differs") from exc
    if (
        not evidence
        or case["checking_mechanism"] != row["checking_mechanism"]
        or request.get("coordinate") != row["coordinate"]
        or request.get("semantic_version") != row["semantic_version"]
        or request.get("proposition_digest") != row["proposition_digest"]
        or request.get("policy_digest")
            != core_obligation_union.value_digest(case["policy"])
        or identifier != row["obligation_id"]
    ):
        raise RuntimeError("Tier-4 generated route binding differs")


def _validate_triad(case: dict[str, Any]) -> None:
    _, recheck_symbol = case["checking_mechanism"].rsplit(".", 1)
    module = current_object_routes.registered_mechanism_module(
        case["checking_mechanism"]
    )
    rechecker = getattr(module, recheck_symbol)
    builder = getattr(
        module, recheck_symbol.replace("recheck_", "build_", 1)
    )
    request = case["request"]
    policy = case["policy"]
    replay_input = base64.b64decode(
        case["evidence_base64"], validate=True
    )
    negative_request, negative_input = adapters.negative_case(
        case["negative_adapter"], request, replay_input, policy=policy
    )
    unknown_request, unknown_input = adapters.unknown_case(
        case["unknown_adapter"], request, replay_input, policy=policy
    )
    selected = {
        "PASS": (request, replay_input, "POSITIVE"),
        "FAIL": (negative_request, negative_input, "NEGATIVE"),
        "UNKNOWN": (
            unknown_request, unknown_input, case["unknown_adapter"],
        ),
    }
    for expected, (selected_request, selected_input, case_kind) \
            in selected.items():
        certificate = adapters.build_certificate(
            case["builder_adapter"], case_kind, builder,
            selected_request, selected_input, policy,
        )
        result = rechecker(
            certificate,
            expected_request=selected_request,
            policy=policy,
        )
        if result.get("status") != expected:
            raise RuntimeError("Tier-4 native triad status differs")


def build_cases() -> dict[str, dict[str, Any]]:
    seed = _load_seed()
    rebinder = source_rebinding.SourceCaseRebinder(seed)
    regenerated = {
        identifier: rebinder.refresh_case(case)
        for identifier, case in seed.items()
        if identifier not in {
            "HYPER:HYPER-4.1", "IDENTITY:IDENTITY-4.1",
            "SIM:SIM-4.3", "SIM:SIM-4.4",
        }
    }
    regenerated["HYPER:HYPER-4.1"] = _hyper_case()
    regenerated["IDENTITY:IDENTITY-4.1"] = _identity_case(
        seed["IDENTITY:IDENTITY-4.1"], rebinder
    )
    regenerated["SIM:SIM-4.3"] = _sim_signatures_case(
        seed["SIM:SIM-4.3"], rebinder
    )
    regenerated["SIM:SIM-4.4"] = _sim_surface_case(
        seed["SIM:SIM-4.4"], rebinder
    )

    rows = _memberships()
    expected = {row["obligation_id"]: row for row in rows}
    if set(regenerated) != set(seed) or set(regenerated) != set(expected):
        raise RuntimeError("Tier-4 seed denominator differs")

    payload: dict[str, dict[str, Any]] = {}
    for identifier in sorted(regenerated):
        case = dict(regenerated[identifier])
        if identifier == "HYPER:HYPER-4.1":
            case.update({
                "builder_adapter": "HYPER_OBJECT_COLLECTION",
                "negative_adapter": "HYPER_UNRELATED_OBJECT_COLLECTION",
                "unknown_adapter": "HYPER_CLOSURE_OPERATION_BUDGET",
            })
        else:
            case.update({
                "builder_adapter": "BOUNDED_EVIDENCE_BYTES",
                "negative_adapter": "MALFORMED_EVIDENCE_REBIND",
                "unknown_adapter": "ABSENT_EVIDENCE",
            })
        _validate_binding(identifier, case, expected[identifier])
        _validate_triad(case)
        payload[identifier] = case
    return payload


def build_payload() -> tuple[bytes, bytes]:
    raw = canonical_bytes(build_cases())
    return raw, base64.b85encode(zlib.compress(raw, level=9))


def main() -> int:
    raw, encoded = build_payload()
    print(f"raw_bytes={len(raw)}")
    print(f"encoded_bytes={len(encoded)}")
    print(f"digest={core_obligation_union.bytes_digest(raw)}")
    print(f"encoded_sha256={hashlib.sha256(encoded).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
