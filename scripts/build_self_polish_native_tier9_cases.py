"""Reproduce the source-bound Tier-9 native specimen payload."""
from __future__ import annotations

import base64
import hashlib
import json
import zlib
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import graph_lineage, graph_statics
from verifier.domains.contracts import receipt_authenticity, receipt_chain
from verifier.domains.contracts import subject_security
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression


def _bytes_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _subject_case(
        kind: str,
        ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    subject = {
        "object_id": "selected-subject",
        "kind": kind,
        "payload": {"declared": "finite retained record"},
        "operands": {},
    }
    subject_digest = _bytes_digest(canonical_bytes(subject))
    chain_policy = receipt_chain.receipt_chain_policy(
        trust_roots=["selected-finite-chain-anchor"]
    )
    policy = subject_security.subject_security_policy(
        object_kind=kind,
        chain_policy=chain_policy,
        trust_roots=["selected-finite-subject-context"],
    )
    message = {
        "schema_version": "verifier-current-subject-security-message-1",
        "semantic_version": subject_security.SEMANTIC_VERSION,
        "coordinate": subject_security.coordinate(kind),
        "proposition_digest": (
            subject_security.SubjectSecurityDescriptor(kind)
            .PROPOSITION_DIGEST
        ),
        "object_kind": kind,
        "subject_id": "selected-subject",
        "object_digest": subject_digest,
        "receipt_object_id": "selected-chain",
        "chain_domain": "selected-subject-association",
        "chain_genesis_digest": "sha256:" + "a" * 64,
        "chain_first_sequence": 7,
        "chain_sequence": 8,
        "context_digest": "sha256:" + "b" * 64,
        "policy_digest": "sha256:" + canonical_digest(policy),
    }
    entries = [b"uninterpreted neighboring receipt", canonical_bytes(message)]
    previous = "sha256:" + "a" * 64
    for offset, raw in enumerate(entries):
        previous = "sha256:" + canonical_digest({
            "schema_version": "verifier-receipt-chain-link-1",
            "domain": "selected-subject-association",
            "sequence": 7 + offset,
            "previous": previous,
            "receipt_digest": _bytes_digest(raw),
        })
    receipt = {
        "object_id": "selected-chain",
        "kind": "RECEIPT",
        "payload": {
            "chain_domain": "selected-subject-association",
            "chain_genesis_digest": "sha256:" + "a" * 64,
            "chain_first_sequence": 7,
            "chain_tip_digest": previous,
        },
        "operands": {
            "subject": ["selected-subject"],
            "hardware": ["retained-device"],
        },
    }
    chain_evidence = canonical_bytes({
        "schema_version": receipt_chain.EVIDENCE_VERSION,
        "domain": "selected-subject-association",
        "receipt_object": receipt,
        "entries": [
            {
                "sequence": 7 + index,
                "receipt_base64": base64.b64encode(raw).decode("ascii"),
            }
            for index, raw in enumerate(entries)
        ],
    })
    chain_request = receipt_chain.receipt_chain_request(
        receipt_object_id="selected-chain",
        receipt_object_digest=_bytes_digest(canonical_bytes(receipt)),
        domain="selected-subject-association",
        genesis_digest="sha256:" + "a" * 64,
        first_sequence=7,
        tip_digest=previous,
        evidence_ref=_bytes_digest(chain_evidence),
        policy=chain_policy,
    )
    child = receipt_chain.build_receipt_chain_certificate(
        chain_request, chain_evidence, policy=chain_policy
    )
    evidence = canonical_bytes({
        "schema_version": subject_security.EVIDENCE_VERSION,
        "subject": subject,
        "chain_certificate": child.decode("utf-8"),
    })
    request = subject_security.subject_security_request(
        object_kind=kind,
        subject_id="selected-subject",
        object_digest=subject_digest,
        context_digest="sha256:" + "b" * 64,
        chain_request=chain_request,
        chain_certificate_digest=_bytes_digest(child),
        chain_sequence=8,
        evidence_ref=_bytes_digest(evidence),
        policy=policy,
    )
    return request, policy, evidence


def _receipt_object(
        tip: str, *, domain: str, genesis: str, first: int,
        ) -> NamespaceObject:
    return NamespaceObject.create("selected-chain", "RECEIPT", {
        "chain_domain": domain,
        "chain_genesis_digest": genesis,
        "chain_first_sequence": first,
        "chain_tip_digest": tip,
    })


def _receipt_evidence(
        receipts: tuple[bytes, ...], *,
        domain: str = "selected-receipt-chain",
        genesis: str = "sha256:" + "0" * 64,
        first: int = 7,
        ) -> tuple[bytes, str]:
    entries = []
    previous = genesis
    for index, payload in enumerate(receipts):
        sequence = first + index
        entries.append({
            "sequence": sequence,
            "receipt_base64": base64.b64encode(payload).decode("ascii"),
        })
        previous = "sha256:" + canonical_digest({
            "schema_version": "verifier-receipt-chain-link-1",
            "domain": domain,
            "sequence": sequence,
            "previous": previous,
            "receipt_digest": _bytes_digest(payload),
        })
    record = _receipt_object(
        previous, domain=domain, genesis=genesis, first=first
    )
    evidence = canonical_bytes({
        "schema_version": receipt_chain.EVIDENCE_VERSION,
        "domain": domain,
        "receipt_object": record.to_dict(),
        "entries": entries,
    })
    return evidence, previous


def _receipt_selection(
        evidence: bytes, tip: str, policy: dict[str, Any], *,
        domain: str = "selected-receipt-chain",
        genesis: str = "sha256:" + "0" * 64,
        first: int = 7,
        ) -> dict[str, Any]:
    record = _receipt_object(
        tip, domain=domain, genesis=genesis, first=first
    )
    return receipt_chain.receipt_chain_request(
        domain=domain,
        genesis_digest=genesis,
        first_sequence=first,
        tip_digest=tip,
        evidence_ref=_bytes_digest(evidence),
        receipt_object_id=record.object_id,
        receipt_object_digest=record.digest,
        policy=policy,
    )


def _receipt_chain_case(
        ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    policy = receipt_chain.receipt_chain_policy(
        trust_roots=["selected-finite-tip-register"]
    )
    evidence, tip = _receipt_evidence((b"first", b"second"))
    return _receipt_selection(evidence, tip, policy), policy, evidence


def _receipt_authenticity_case(
        ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    # Deterministic fixture key only; it is not an authority or credential.
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32)
    public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    chain_policy = receipt_chain.receipt_chain_policy(
        trust_roots=["selected-finite-chain-anchor"]
    )
    chain_evidence, tip = _receipt_evidence((b"first", b"second"))
    chain_request = _receipt_selection(chain_evidence, tip, chain_policy)
    child = receipt_chain.build_receipt_chain_certificate(
        chain_request, chain_evidence, policy=chain_policy
    )
    policy = receipt_authenticity.receipt_authenticity_policy(
        issuer_key_id="selected-issuer-key",
        issuer_public_key=public_key,
        chain_policy=chain_policy,
        trust_roots=["selected-finite-issuer-key"],
        max_validity_seconds=100,
    )
    request = receipt_authenticity.receipt_authenticity_request(
        chain_request=chain_request,
        chain_certificate_digest=_bytes_digest(child),
        challenge="12" * 32,
        evaluation_time=100,
        evidence_ref="sha256:" + "0" * 64,
        policy=policy,
    )
    payload = receipt_authenticity.receipt_authenticity_payload(
        request, policy=policy, issued_at=100, expires_at=200
    )
    signature = key.sign(
        receipt_authenticity.receipt_authenticity_signing_bytes(payload)
    )
    evidence = canonical_bytes({
        "schema_version": receipt_authenticity.EVIDENCE_VERSION,
        "chain_certificate": child.decode("utf-8"),
        "attestation": {
            "schema_version": receipt_authenticity.ATTESTATION_VERSION,
            "key_id": policy["issuer_key_id"],
            "payload": payload,
            "signature": signature.hex(),
        },
    })
    request["evidence_ref"] = _bytes_digest(evidence)
    return request, policy, evidence


def _graph_lineage_case(
        ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    nodes = ["a", "b", "c"]
    edges = [
        {"source": "a", "target": "b"},
        {"source": "b", "target": "c"},
    ]
    roles = {
        "a": {"link": ["b"]},
        "b": {"link": ["c"]},
        "c": {},
    }
    members = [
        NamespaceObject.create(
            name, "HYPER" if roles[name] else "OBJECT", {}, roles[name]
        )
        for name in nodes
    ]
    graph = NamespaceObject.create("g", "GRAPH", {
        "element_kind": "OBJECT",
        "scope": "retained_directed_graph",
        "nodes_digest": digest(nodes),
        "edges_digest": digest(edges),
    }, {"members": nodes})
    objects = [*members, graph]
    child_evidence = canonical_bytes({
        "schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": nodes, "edges": edges},
    })
    child_policy = graph_statics.graph_statics_policy(
        trust_roots=["selected-finite-graph-root"]
    )
    child_request = graph_statics.graph_statics_request(
        subject_id="g",
        object_digest=graph.digest,
        collection_digest=composition_digest(objects),
        nodes_digest=digest(nodes),
        edges_digest=digest(edges),
        evidence_ref=digest(json.loads(child_evidence)),
        policy=child_policy,
    )
    child_certificate = graph_statics.build_graph_statics_certificate(
        child_request, child_evidence, policy=child_policy
    )
    index = {item.object_id: item for item in objects}
    contents = [
        {
            **edge,
            "source_digest": index[edge["source"]].digest,
            "target_digest": index[edge["target"]].digest,
        }
        for edge in edges
    ]
    evidence_value = {
        "schema_version": graph_lineage.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": nodes, "edges": edges},
        "edge_contents": contents,
        "child_certificate": base64.b64encode(
            child_certificate
        ).decode("ascii"),
    }
    evidence = canonical_bytes(evidence_value)
    policy = graph_lineage.graph_lineage_policy(
        trust_roots=["selected-finite-lineage-root"]
    )
    request = graph_lineage.graph_lineage_request(
        subject_id="g",
        object_digest=graph.digest,
        collection_digest=composition_digest(objects),
        nodes_digest=digest(nodes),
        edges_digest=digest(edges),
        edge_contents_digest=digest(contents),
        evidence_ref=digest(evidence_value),
        child_request=child_request,
        child_policy=child_policy,
        child_certificate_digest=_bytes_digest(child_certificate),
        policy=policy,
    )
    return request, policy, evidence


SPECIAL_GENERATORS: dict[
    str, Callable[[], tuple[dict[str, Any], dict[str, Any], bytes]]
] = {
    "GRAPH:GRAPH-9.2": _graph_lineage_case,
    "RECEIPT:RECEIPT-9.1": _receipt_chain_case,
    "RECEIPT:RECEIPT-9.2": _receipt_authenticity_case,
}

SPECIAL_NEGATIVE_ADAPTERS = {
    "GRAPH:GRAPH-9.2": "GRAPH_EDGE_CONTENT_SUBSTITUTION",
    "RECEIPT:RECEIPT-9.1": "RECEIPT_CHAIN_ENTRY_SUBSTITUTION",
    "RECEIPT:RECEIPT-9.2": "RECEIPT_ATTESTATION_SIGNATURE_BIT_FLIP",
}


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
            if cell["tier"] == 9
            for route in cell["registered_route_memberships"]
        ],
        key=lambda row: row["obligation_id"],
    )
    if len(memberships) != 29:
        raise RuntimeError("Tier-9 route denominator differs")
    payload = {}
    for membership in memberships:
        identifier = membership["obligation_id"]
        generator = SPECIAL_GENERATORS.get(identifier)
        if generator is None:
            request, policy, evidence = _subject_case(
                membership["object_kind"]
            )
            negative_adapter = "SUBJECT_SECURITY_VALID_TRANSPLANT"
        else:
            request, policy, evidence = generator()
            negative_adapter = SPECIAL_NEGATIVE_ADAPTERS[identifier]
        if (
            request["coordinate"] != membership["coordinate"]
            or request["semantic_version"] != membership["semantic_version"]
            or request["proposition_digest"]
                != membership["proposition_digest"]
            or request["policy_digest"]
                != core_obligation_union.value_digest(policy)
        ):
            raise RuntimeError("Tier-9 generated route binding differs")
        payload[identifier] = {
            "builder_adapter": "BOUNDED_EVIDENCE_BYTES",
            "checking_mechanism": membership["checking_mechanism"],
            "evidence_base64": base64.b64encode(evidence).decode("ascii"),
            "negative_adapter": negative_adapter,
            "policy": policy,
            "request": request,
            "unknown_adapter": "ABSENT_EVIDENCE",
        }
    raw = core_obligation_union.canonical_bytes(payload)
    return raw, base64.b85encode(zlib.compress(raw, 9))


def main() -> int:
    raw, encoded = build_payload()
    print(json.dumps({
        "entry_count": 29,
        "raw_bytes": len(raw),
        "encoded_bytes": len(encoded),
        "registry_digest": core_obligation_union.bytes_digest(raw),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
