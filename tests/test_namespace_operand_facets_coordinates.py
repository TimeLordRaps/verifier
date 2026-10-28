"""Coordinate-level adversaries for four namespace operand-facet routes.

Verifier Standard (VSTD); JavaScript Object Notation (JSON).  These checks use
the installed public route and its native certificate replay.  Merely finding
the coordinate text in a catalog would not establish that the declared operand
contract is executed.
"""
from __future__ import annotations

import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import typed_facets
from verifier.domains.contracts.current_object_routes import (
    current_object_route_catalog,
    replay_current_object_certificate,
)


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
CASES = (
    ("COLLECTIVE", "COLLECTIVE-1.1"),
    ("IDENTITY", "IDENTITY-1.1"),
    ("GRAPH", "GRAPH-1.1"),
    ("TIME", "TIME-1.1"),
)


def _objects(kind: str, *, broken: bool) -> list[NamespaceObject]:
    """Build the smallest closed graph that distinguishes each contract."""
    make = NamespaceObject.create
    if kind == "COLLECTIVE":
        objects = [make("role", "ROLE", {}), make("object", "OBJECT", {})]
        selected = make(
            "collective",
            "COLLECTIVE",
            {},
            {"roles": ["object" if broken else "role"]},
        )
    elif kind == "IDENTITY":
        objects = [
            make("human", "HUMAN", {}),
            make("role", "ROLE", {}),
            make("object", "OBJECT", {}),
            make(
                "actor",
                "ACTOR",
                {},
                {"representation": ["human"], "root_human": ["human"]},
            ),
        ]
        selected = make(
            "identity",
            "IDENTITY",
            {},
            {"actor": ["object" if broken else "actor"], "role": ["role"]},
        )
    elif kind == "GRAPH":
        objects = [make("env", "ENV", {}), make("time", "TIME", {})]
        selected = make(
            "graph",
            "GRAPH",
            {"element_kind": "ENV"},
            {"members": ["time" if broken else "env"]},
        )
    else:
        objects = [make("object", "OBJECT", {})]
        selected = make(
            "time",
            "TIME",
            {},
            {"undeclared": ["object"]} if broken else None,
        )
    return [*objects, selected]


def _replay(kind: str, *, broken: bool) -> dict:
    objects = _objects(kind, broken=broken)
    selected = next(item for item in objects if item.object_id == kind.lower())
    evidence = canonical_bytes(
        {
            "schema_version": typed_facets.COLLECTION_VERSION,
            "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.object_id)],
        }
    )
    policy = typed_facets.typed_facets_policy(trust_roots=["coordinate-adversary"])
    request = typed_facets.typed_facets_request(
        object_kind=kind,
        subject_id=selected.object_id,
        object_digest=selected.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)),
        policy=policy,
    )
    certificate = typed_facets.build_typed_facets_certificate(
        request, evidence, policy=policy
    )
    return replay_current_object_certificate(
        certificate,
        semantic_version=SEMANTIC_VERSION,
        objective=request["coordinate"],
        represented_kind=kind,
        expected_request=request,
        policy=policy,
    )


@pytest.mark.parametrize("kind,coordinate", CASES)
def test_coordinate_selects_the_exact_installed_typed_facets_mechanism(
    kind: str, coordinate: str
) -> None:
    rows = {
        row["objective"]: row for row in current_object_route_catalog()
    }
    row = rows[coordinate]
    assert row == {
        "semantic_version": SEMANTIC_VERSION,
        "objective": coordinate,
        "certificate_schema_version": typed_facets.CERTIFICATE_VERSION,
        "proposition_digest": typed_facets.FacetDescriptor(kind).PROPOSITION_DIGEST,
        "represented_kind_rule": kind,
        "scope": typed_facets.SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
    }
    result = _replay(kind, broken=False)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["coordinate"] == coordinate
    assert result["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("kind,coordinate", CASES)
def test_coordinate_refutes_its_kind_specific_operand_violation(
    kind: str, coordinate: str
) -> None:
    result = _replay(kind, broken=True)
    assert result["computational_status"] == "FAIL"
    assert result["native_result"]["coordinate"] == coordinate
    assert result["native_result"]["status"] == "FAIL"

