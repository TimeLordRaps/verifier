"""Portable positive and negative silo-composition fixture tests.

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256),
and Verifier Standard (VSTD) terms are expanded here for fixture readers.
"""

from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

from scripts.build_silo_composition_fixture import build_fixture
from verifier.interoperability.network import (
    ContentAddressedStore,
    NetworkError,
    ObjectRecord,
    SiloCommit,
    SiloComposition,
    SiloCompositionAssessmentReceipt,
    build_silo_composition_assessment_receipt,
    canonical_bytes,
    digest_bytes,
    recheck_silo_composition_assessment_receipt,
    silo_composition_mechanism_bytes,
)


FIXTURE = Path("examples/artifact-network/canonical-silo-composition-fixture.json")


def _load() -> dict[str, Any]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _reconstruct_silo(
    root: Path,
    value: dict[str, Any],
) -> tuple[SiloCommit, ContentAddressedStore]:
    commit = SiloCommit.from_dict(value["commit"])
    assert canonical_bytes(commit.to_dict()).decode("utf-8") == value["commit_canonical_json"]
    assert commit.canonical_digest() == value["commit_digest"]
    assert [item["object"]["object_digest"] for item in value["objects"]] == sorted(
        item["object"]["object_digest"] for item in value["objects"]
    )
    store = ContentAddressedStore(root)
    for item in value["objects"]:
        expected = ObjectRecord.from_dict(item["object"])
        actual = store.add_object(
            _decode(item["bytes_base64url"]),
            expected.media_type,
            expected.artifact_kind,
            expected.declared_schema_id,
        )
        assert actual == expected
    assert {item.object_record.object_digest for item in commit.census} == {
        item["object"]["object_digest"] for item in value["objects"]
    }
    return commit, store


def _apply_pointer(value: dict[str, Any], pointer: str, replacement: Any) -> dict[str, Any]:
    result = deepcopy(value)
    segments = pointer.removeprefix("/").split("/")
    target: Any = result
    for segment in segments[:-1]:
        target = target[int(segment)] if isinstance(target, list) else target[segment]
    final = segments[-1]
    if isinstance(target, list):
        target[int(final)] = replacement
    else:
        target[final] = replacement
    return result


def _resolved(tmp_path: Path, fixture: dict[str, Any]) -> tuple[
    SiloComposition,
    list[tuple[SiloCommit, ContentAddressedStore]],
    tuple[SiloCommit, ContentAddressedStore],
]:
    declaration = SiloComposition.from_dict(fixture["declaration"])
    members = [
        _reconstruct_silo(tmp_path / f"member-{index}", member)
        for index, member in enumerate(fixture["members"])
    ]
    composite = _reconstruct_silo(tmp_path / "composite", fixture["composite"])
    return declaration, members, composite


def test_checked_in_fixture_is_canonical() -> None:
    checked_in = _load()
    assert checked_in["schema_version"] == "VSTD-SILO-COMPOSITION-WIRE-FIXTURE-0.1"
    assert [case["case_id"] for case in checked_in["negative_cases"]] == sorted(
        case["case_id"] for case in checked_in["negative_cases"]
    )


def test_checked_in_fixture_matches_cryptographic_regeneration() -> None:
    pytest.importorskip("cryptography", reason="fixture freshness regenerates Ed25519 keys and signatures")
    assert _load() == build_fixture()


def test_fixture_reconstructs_exact_bytes_and_recomputes_receipt(tmp_path: Path) -> None:
    fixture = _load()
    declaration, members, composite = _resolved(tmp_path, fixture)
    expected = fixture["expected"]
    mechanism = fixture["composition_mechanism"]
    mechanism_bytes = _decode(mechanism["bytes_base64url"])
    assert mechanism_bytes == silo_composition_mechanism_bytes()
    assert mechanism_bytes.decode("utf-8") == mechanism["canonical_json_utf8"]
    assert digest_bytes(mechanism_bytes) == mechanism["digest"] == expected["composition_mechanism_digest"]
    assert canonical_bytes(declaration.to_dict()).decode("utf-8") == expected["declaration_canonical_json"]
    assert declaration.canonical_digest() == expected["declaration_digest"]

    supplied = SiloCompositionAssessmentReceipt.from_dict(fixture["composition_assessment_receipt"])
    recomputed = build_silo_composition_assessment_receipt(declaration, tuple(reversed(members)), composite)
    assert recomputed == supplied
    assert supplied.assessment.result == expected["result"] == "ADMISSIBLE"
    assert canonical_bytes(supplied.assessment.to_dict()).decode("utf-8") == expected["composition_assessment_canonical_json"]
    assert digest_bytes(canonical_bytes(supplied.assessment.to_dict())) == expected["composition_assessment_digest"]
    assert canonical_bytes(supplied.to_dict()).decode("utf-8") == expected["composition_assessment_receipt_canonical_json"]
    assert supplied.canonical_digest() == expected["composition_assessment_receipt_digest"]
    recheck_silo_composition_assessment_receipt(declaration, supplied, members, composite)


@pytest.mark.parametrize("case_id", [
    "composite-receipt-substitution",
    "declaration-substitution",
    "mechanism-substitution",
    "member-receipt-substitution",
    "result-substitution",
])
def test_fixture_adversarial_substitution_is_rejected(tmp_path: Path, case_id: str) -> None:
    fixture = _load()
    declaration, members, composite = _resolved(tmp_path, fixture)
    case = next(item for item in fixture["negative_cases"] if item["case_id"] == case_id)
    assert case["expected_result"] == "REJECT"
    if case["target"] == "DECLARATION":
        mutated = _apply_pointer(fixture["declaration"], case["json_pointer"], case["replacement"])
        substituted = SiloComposition.from_dict(mutated)
        with pytest.raises(NetworkError):
            recheck_silo_composition_assessment_receipt(
                substituted,
                fixture["composition_assessment_receipt"],
                members,
                composite,
            )
        return
    assert case["target"] == "RECEIPT"
    mutated = _apply_pointer(
        fixture["composition_assessment_receipt"],
        case["json_pointer"],
        case["replacement"],
    )
    with pytest.raises(NetworkError):
        recheck_silo_composition_assessment_receipt(declaration, mutated, members, composite)
