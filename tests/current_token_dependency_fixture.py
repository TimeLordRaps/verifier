"""Retained finite TOKEN dependency fixtures; no production qualification."""
from __future__ import annotations
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import object_facets
from verifier.domains.contracts.current_object_routes import current_object_route_catalog
from verifier.runtime.artifact_snapshot import digest

def obligation(claim_id: str, objective: str, dependencies: list | None = None) -> dict:
    route = next(r for r in current_object_route_catalog() if r["objective"] == objective)
    return {"claim_id": claim_id, "semantic_version": route["semantic_version"],
        "objective": objective, "proposition_digest": route["proposition_digest"],
        "scope": route["scope"], "assumptions": [],
        "dependencies": dependencies or []}

def node(item: NamespaceObject, claim_id: str, request: dict, checker_policy: dict,
         raw: bytes, files: dict, *, version: str = "1") -> dict:
    identity = item.object_id + ":" + claim_id
    path = identity.replace(":", "-") + ".json"
    files[path] = raw
    return {"node_id": identity, "object_id": item.object_id, "claim_id": claim_id,
        "certificate_path": path, "certificate_digest": digest(raw), "request": request,
        "checker_policy": checker_policy, "contract_version": version,
        "artifact_bindings": [{"path": path, "digest": digest(raw)}],
        "facet_bindings": {"payload_digest": digest(item.payload_bytes),
            "operands_digest": digest(canonical_bytes(item.to_dict()["operands"]))}}

def facet(item: NamespaceObject, claim_id: str, files: dict, *, missing: bool = False) -> dict:
    policy = object_facets.object_facets_policy(trust_roots=["test:independent-selector"])
    request = object_facets.object_facets_request(item, policy=policy)
    raw = object_facets.build_object_facets_certificate(request,
        None if missing else canonical_bytes(item.to_dict()), policy=policy)
    return node(item, claim_id, request, policy, raw, files)
