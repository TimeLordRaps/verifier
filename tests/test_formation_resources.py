"""Packaged experimental Verifier Standard (VSTD) formation resources.

JavaScript Object Notation (JSON) Schema admission is tested separately from
canonical byte and semantic checking. No schema pass establishes grounding.
An integer identifier (ID) selects a node; the ID tag constructs an identity path.
"""

from __future__ import annotations

from copy import deepcopy
import importlib.resources
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
import pytest

from verifier.interoperability.formation_checker import check_formation
from verifier.interoperability.formation_producer import produce_formation_certificate
from verifier.interoperability.formation_wire import (
    canonical_bytes, digest_bytes, profile_bytes, profile_digest,
)


ROOT = Path(__file__).resolve().parents[1]


def _subject() -> dict[str, Any]:
    return {
        "schema_version": "VSTD-TYPED-FORMATION-0.1",
        "profile_digest": profile_digest(),
        "context": {
            "ground_artifact_digest": digest_bytes(b"declared ground"),
            "authority_axiom_agency_digest": digest_bytes(b"declared agency"),
        },
        "nodes": [
            {"tag": "ATOM", "payload_digest": digest_bytes(b"opaque symbol")},
            {"tag": "APPLY", "argument": 0},
            {"tag": "APPLY_STEP", "source": 0, "target": 1},
            {"tag": "ID", "at": 0},
            {"tag": "COMPOSE", "left": 3, "right": 2},
            {"tag": "QUOTE", "value": 4},
            {"tag": "READ", "code": 5},
        ],
        "root": 6,
    }


def _validator() -> Draft202012Validator:
    data = (ROOT / "standard/schemas/vstd-typed-formation-0.1.schema.json").read_bytes()
    schema = json.loads(data)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_formation_profile_is_exact_inert_installed_resource() -> None:
    retained = importlib.resources.files("verifier").joinpath("profiles/typed-formation-0.1.json")
    assert retained.read_bytes() == profile_bytes()
    assert digest_bytes(retained.read_bytes()) == profile_digest()
    assert json.loads(retained.read_bytes())["context_meaning"] == (
        "declared byte coordinates only; no grounding or agency proof"
    )


def test_formation_schema_covers_every_constructor_and_produced_certificate() -> None:
    subject = _subject()
    validator = _validator()
    validator.validate(subject)
    encoded = canonical_bytes(subject)
    certificate = produce_formation_certificate(encoded)
    validator.validate(json.loads(certificate))
    report = check_formation(encoded, certificate)
    assert report["status"] == "CHECKED"
    assert report["observation"]["quote_origins"] == [5]
    assert "SELF_STATUS_NOT_ESTABLISHED" in report["residual_obligations"]


@pytest.mark.parametrize("field", ["status", "self_derivation", "complete", "agency"])
def test_formation_schema_refuses_extra_verdict_fields(field: str) -> None:
    subject = _subject()
    subject[field] = "PASS"
    assert not _validator().is_valid(subject)
    certificate = json.loads(produce_formation_certificate(canonical_bytes(_subject())))
    certificate[field] = "PASS"
    assert not _validator().is_valid(certificate)


def test_formation_schema_pass_is_not_reference_or_type_checking() -> None:
    subject = _subject()
    certificate = produce_formation_certificate(canonical_bytes(subject))
    forward = deepcopy(subject)
    forward["nodes"][1]["argument"] = 1
    _validator().validate(forward)
    assert check_formation(canonical_bytes(forward), certificate)["status"] == "INVALID"
    ill_typed = deepcopy(subject)
    ill_typed["nodes"][1] = {"tag": "READ", "code": 0}
    _validator().validate(ill_typed)
    with pytest.raises(ValueError):
        produce_formation_certificate(canonical_bytes(ill_typed))


def test_formation_resources_are_explicitly_packaged_and_experimental() -> None:
    from scripts.release_artifacts import PACKAGED_SCHEMA_NAMES

    assert "vstd-typed-formation-0.1.schema.json" in PACKAGED_SCHEMA_NAMES
    specification = ROOT / "standard/TYPED_FORMATION.md"
    assert specification.read_bytes() == (
        ROOT / "src/verifier/specifications/TYPED_FORMATION.md"
    ).read_bytes()
    assert "Experimental typed formation" in specification.read_text(encoding="utf-8")
    assert "COMPLETENESS_NOT_ESTABLISHED" in specification.read_text(encoding="utf-8")
