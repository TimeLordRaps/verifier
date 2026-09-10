"""Build the portable Verifier Standard (VSTD) silo-composition fixture.

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256),
and unpadded base64url are used as exact wire encodings.  The specimen is
deterministic test data, not evidence about a deployed service or artifact
truth.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import replace
import json
from pathlib import Path
import tempfile
from typing import Any

if __package__:
    from scripts.build_artifact_network_fixture import build_fixture as build_network_fixture
else:  # Direct ``python scripts/...`` execution.
    from build_artifact_network_fixture import build_fixture as build_network_fixture
from verifier.interoperability.network import (
    ArtifactRelation,
    AuthorityModel,
    CensusEntry,
    ContentAddressedStore,
    DerivationEdge,
    SiloCommit,
    SiloComposition,
    build_silo_composition_assessment_receipt,
    canonical_bytes,
    census_boundary_members,
    digest_bytes,
    silo_composition_mechanism_bytes,
    _read_bounded_regular,
)


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples" / "artifact-network" / "canonical-silo-composition-fixture.json"
SCHEMA = "VSTD-SILO-COMPOSITION-WIRE-FIXTURE-0.1"
MAX_FIXTURE_BYTES = 2 * 1024 * 1024
ZERO_DIGEST = "sha256:" + "0" * 64


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _base_transfer() -> dict[str, Any]:
    fixture = build_network_fixture()
    records = fixture["records"]
    if not isinstance(records, dict) or not isinstance(records.get("silo_transfer"), dict):
        raise ValueError("canonical artifact-network fixture lacks its silo transfer")
    return records["silo_transfer"]


def _materialize_base(root: Path) -> tuple[SiloCommit, ContentAddressedStore]:
    transfer = _base_transfer()
    commit = SiloCommit.from_dict(transfer["commit"])
    encoded_by_digest = {
        item["digest"]: item["bytes_base64url"]
        for item in transfer["objects"]
    }
    store = ContentAddressedStore(root)
    for entry in commit.census:
        record = entry.object_record
        rebuilt = store.add_object(
            _decode(encoded_by_digest[record.object_digest]),
            record.media_type,
            record.artifact_kind,
            record.declared_schema_id,
        )
        if rebuilt != record:
            raise ValueError("canonical transfer object does not reproduce its census record")
    return commit, store


def _authority_model(commit: SiloCommit, store: ContentAddressedStore) -> AuthorityModel | None:
    if commit.authority_model_path is None:
        return None
    entry = next(item for item in commit.census if item.path == commit.authority_model_path)
    value = json.loads(store.read_object(entry.object_record))
    return AuthorityModel.from_dict(value)


def _coverage(commit: SiloCommit, store: ContentAddressedStore) -> tuple[str, ...]:
    return census_boundary_members(
        commit.census,
        commit.ground_paths,
        commit.derivations,
        commit.relations,
        commit.authority_axiom_agency,
        commit.residual_obligations,
        commit.exclusions,
        publisher_id=commit.publisher_id,
        parents=commit.parents,
        completeness_kind=commit.completeness_kind,
        authority_version=commit.authority_axiom_agency_version,
        authority_digest=commit.authority_axiom_agency_digest,
        self_derivation_record=commit.self_derivation_record,
        created_at=commit.created_at,
        authority_model_path=commit.authority_model_path,
        authority_model=_authority_model(commit, store),
    )


def _variant_member(commit: SiloCommit, store: ContentAddressedStore) -> SiloCommit:
    variant = replace(commit, created_at="2026-09-08T00:00:01Z")
    return replace(variant, coverage_universe=_coverage(variant, store))


def _composite(
    root: Path,
    members: tuple[SiloCommit, SiloCommit],
) -> tuple[SiloCommit, ContentAddressedStore]:
    base, store = _materialize_base(root)
    extras = (
        ("members/first.json", canonical_bytes(members[0].to_dict()), "member-commit", "VSTD-SILO-COMMIT-0.1"),
        ("members/second.json", canonical_bytes(members[1].to_dict()), "member-commit", "VSTD-SILO-COMMIT-0.1"),
        ("adapter.bin", b"canonical composition adapter", "composition-adapter", "COMPOSITION-ADAPTER-1"),
        ("policy.json", b"canonical additive policy", "composition-policy", "COMPOSITION-POLICY-1"),
        ("bridge.json", b"canonical bridge relation", "composition-relation", "COMPOSITION-RELATION-1"),
    )
    added = tuple(
        CensusEntry(
            path,
            store.add_object(payload, "application/json", kind, schema),
            "NECESSARY",
        )
        for path, payload, kind, schema in extras
    )
    derivations = (
        *base.derivations,
        *(DerivationEdge(item.path, ("ground.txt",), "mechanism.bin") for item in added),
    )
    relations = (
        ArtifactRelation(
            "CHECKS",
            "members/first.json",
            "members/second.json",
            "adapter.bin",
            "member-compatibility",
        ),
    )
    composite = replace(base, census=(*base.census, *added), derivations=derivations, relations=relations)
    return replace(composite, coverage_universe=_coverage(composite, store)), store


def _portable_silo(commit: SiloCommit, store: ContentAddressedStore) -> dict[str, Any]:
    objects: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in commit.census:
        record = entry.object_record
        if record.object_digest in seen:
            continue
        seen.add(record.object_digest)
        objects.append({
            "object": record.to_dict(),
            "bytes_base64url": _encode(store.read_object(record)),
        })
    objects.sort(key=lambda item: item["object"]["object_digest"])
    encoded_commit = canonical_bytes(commit.to_dict())
    return {
        "commit": commit.to_dict(),
        "commit_canonical_json": encoded_commit.decode("utf-8"),
        "commit_digest": commit.canonical_digest(),
        "objects": objects,
    }


def _negative_cases() -> list[dict[str, Any]]:
    cases = [
        {
            "case_id": "composite-receipt-substitution",
            "target": "RECEIPT",
            "json_pointer": "/composite_assessment_receipt/commit_digest",
            "replacement": ZERO_DIGEST,
            "expected_result": "REJECT",
        },
        {
            "case_id": "declaration-substitution",
            "target": "DECLARATION",
            "json_pointer": "/member_commit_digests/0",
            "replacement": ZERO_DIGEST,
            "expected_result": "REJECT",
        },
        {
            "case_id": "mechanism-substitution",
            "target": "RECEIPT",
            "json_pointer": "/composition_mechanism_digest",
            "replacement": ZERO_DIGEST,
            "expected_result": "REJECT",
        },
        {
            "case_id": "member-receipt-substitution",
            "target": "RECEIPT",
            "json_pointer": "/member_assessment_receipts/0/mechanism_digest",
            "replacement": ZERO_DIGEST,
            "expected_result": "REJECT",
        },
        {
            "case_id": "result-substitution",
            "target": "RECEIPT",
            "json_pointer": "/assessment/result",
            "replacement": "NOT_ADMISSIBLE",
            "expected_result": "REJECT",
        },
    ]
    return sorted(cases, key=lambda item: item["case_id"])


def build_fixture() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        first, first_store = _materialize_base(root / "first")
        second_base, second_store = _materialize_base(root / "second")
        second = _variant_member(second_base, second_store)
        composite, composite_store = _composite(root / "composite", (first, second))
        declaration = SiloComposition(
            (first.canonical_digest(), second.canonical_digest()),
            composite.canonical_digest(),
        )
        receipt = build_silo_composition_assessment_receipt(
            declaration,
            ((second, second_store), (first, first_store)),
            (composite, composite_store),
        )
        declaration_bytes = canonical_bytes(declaration.to_dict())
        mechanism_bytes = silo_composition_mechanism_bytes()
        receipt_bytes = canonical_bytes(receipt.to_dict())
        return {
            "schema_version": SCHEMA,
            "encoding": {
                "json": "Unicode Transformation Format, 8-bit (UTF-8); sorted keys; no whitespace; NFC strings; nonnegative integers <= 2^53-1; no floats",
                "binary": "unpadded Request for Comments (RFC) 4648 base64url",
                "digest": "sha256:<64 lowercase hexadecimal characters>",
            },
            "declaration": declaration.to_dict(),
            "composition_mechanism": {
                "bytes_base64url": _encode(mechanism_bytes),
                "canonical_json_utf8": mechanism_bytes.decode("utf-8"),
                "digest": digest_bytes(mechanism_bytes),
            },
            "members": [
                _portable_silo(commit, store)
                for commit, store in sorted(
                    ((first, first_store), (second, second_store)),
                    key=lambda item: item[0].canonical_digest(),
                )
            ],
            "composite": _portable_silo(composite, composite_store),
            "composition_assessment_receipt": receipt.to_dict(),
            "expected": {
                "declaration_canonical_json": declaration_bytes.decode("utf-8"),
                "declaration_digest": declaration.canonical_digest(),
                "composition_mechanism_digest": digest_bytes(mechanism_bytes),
                "composition_assessment_canonical_json": canonical_bytes(receipt.assessment.to_dict()).decode("utf-8"),
                "composition_assessment_digest": digest_bytes(canonical_bytes(receipt.assessment.to_dict())),
                "composition_assessment_receipt_canonical_json": receipt_bytes.decode("utf-8"),
                "composition_assessment_receipt_digest": receipt.canonical_digest(),
                "result": "ADMISSIBLE",
            },
            "negative_cases": _negative_cases(),
            "claim_boundary": (
                "This fixture establishes deterministic encoding, retained-byte reconstruction, and independent "
                "recomputation for one finite reference composition only. It does not establish completeness of "
                "adversarial coverage, artifact truth, publisher identity, arbitrary graph-edge compatibility, "
                "cross-runtime parity until another runtime reproduces it, or deployed service behavior."
            ),
        }


def _read_bounded(path: Path) -> bytes:
    value = _read_bounded_regular(path, MAX_FIXTURE_BYTES, "silo composition fixture")
    if len(value) > MAX_FIXTURE_BYTES:
        raise SystemExit("silo composition fixture exceeds its byte bound")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fixture = build_fixture()
    rendered = (json.dumps(fixture, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    if len(rendered) > MAX_FIXTURE_BYTES:
        raise SystemExit("silo composition fixture exceeds its byte bound")
    if args.write:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_bytes(rendered)
        print(
            "[SILO COMPOSITION FIXTURE WRITTEN] "
            f"members={len(fixture['members'])} cases={len(fixture['negative_cases'])} bytes={len(rendered)}"
        )
        return 0
    if not TARGET.is_file() or _read_bounded(TARGET) != rendered:
        raise SystemExit("silo composition fixture is stale; run with --write")
    print(
        "[SILO COMPOSITION FIXTURE OK] "
        f"members={len(fixture['members'])} cases={len(fixture['negative_cases'])} bytes={len(rendered)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
