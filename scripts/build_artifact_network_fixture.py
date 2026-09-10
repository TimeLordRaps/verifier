"""Build the cross-runtime Verifier Standard (VSTD) network wire fixture.

Terminology: American Standard Code for Information Interchange (ASCII);
JavaScript Object Notation (JSON); Privacy-Enhanced Mail (PEM); Request for
Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation
Format, 8-bit (UTF-8). The fixed private seed exists only to
make this public test specimen reproducible and MUST NOT be used for identity.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifier.interoperability.network import (
    AUTHORITY_AXIOM_AGENCY,
    AUTHORITY_AXIOM_AGENCY_VERSION,
    AUTHORITY_ACTOR_SCOPE_VERSION,
    AUTHORITY_MODEL_SCHEMA,
    AuthorityModel,
    AuthorityState,
    AuthorityTransition,
    authority_actor_scope_digest,
    CensusEntry,
    ContentAddressedStore,
    DerivationEdge,
    MAX_RECORD_BYTES,
    SelfDerivationRecord,
    SiloCommit,
    assess_silo,
    authority_axiom_agency_digest,
    build_silo_assessment_receipt,
    build_silo_transfer,
    census_boundary_members,
    canonical_bytes,
    digest_bytes,
    publisher_from_private_key,
    sign_head,
    self_derivation_mechanism_bytes,
    _read_bounded_regular,
)


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples" / "artifact-network" / "canonical-wire-fixture.json"


def build_fixture() -> dict[str, object]:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = Path(temporary)
        key_path = temporary_root / "fixture.pem"
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        publisher = publisher_from_private_key(
            key_path, "VSTD wire specimen", "Deterministic test identity; not a real publisher."
        )
        store = ContentAddressedStore(temporary_root / "silo")
        ground = store.add_object(b"ground", "text/plain", "ground", "GROUND-1")
        mechanism = store.add_object(self_derivation_mechanism_bytes(), "application/json", "derivation-mechanism", "VSTD-SELF-DERIVATION-MECHANISM-0.1")
        status = store.add_object(b"self-derived", "text/plain", "self-derivation-status", "STATUS-1")
        evidence_paths = (
            "evidence/ground-self.json", "evidence/derivation-reflexivity.json",
            "evidence/reflexion-identity.json", "evidence/deriver-cycle-closed.json",
        )
        predicates = ("ground_self", "derivation_reflexivity", "reflexion_identity", "deriver_cycle_closed")
        evidence = tuple(store.add_object(canonical_bytes({
            "schema_version": "VSTD-SELF-DERIVATION-EVIDENCE-0.1",
            "predicate": predicate, "subject_path": "status.txt",
            "mechanism_digest": mechanism.object_digest,
        }), "application/json", "self-derivation-evidence", "VSTD-SELF-DERIVATION-EVIDENCE-0.1") for predicate in predicates)
        census = (
            CensusEntry("ground.txt", ground, "NECESSARY"),
            CensusEntry("mechanism.bin", mechanism, "NECESSARY"),
            CensusEntry("status.txt", status, "NECESSARY"),
            *(CensusEntry(path, record, "NECESSARY") for path, record in zip(evidence_paths, evidence)),
        )
        derivations = (
            *(DerivationEdge(path, ("ground.txt",), "mechanism.bin") for path in evidence_paths),
            DerivationEdge("status.txt", ("ground.txt", *evidence_paths), "mechanism.bin"),
        )
        self_record = SelfDerivationRecord(
            "status.txt", ("ground.txt",), "mechanism.bin",
            ("ground.txt", "mechanism.bin", *evidence_paths, "status.txt"),
            "DERIVES", True, True, True, True, *evidence_paths, (),
        )
        agency_digest = authority_axiom_agency_digest()
        authority_model = AuthorityModel(
            authority_axiom_agency_version=AUTHORITY_AXIOM_AGENCY_VERSION,
            authority_axiom_agency_digest=agency_digest,
            actor_scope_version=AUTHORITY_ACTOR_SCOPE_VERSION,
            actor_scope_digest=authority_actor_scope_digest(),
            initial_state_ids=("initial",), state_universe=("initial", "steady"),
            transition_universe=("settle",),
            states=(
                AuthorityState("initial", AUTHORITY_AXIOM_AGENCY, ()),
                AuthorityState("steady", AUTHORITY_AXIOM_AGENCY, ()),
            ),
            transitions=(AuthorityTransition("settle", "initial", "steady", "ANY_ACTOR", "SETTLE"),),
            closure_status="CLOSED", residual_obligations=(),
        )
        authority_record = store.add_object(
            canonical_bytes(authority_model.to_dict()), "application/json",
            "authority-model", AUTHORITY_MODEL_SCHEMA,
        )
        census = (*census, CensusEntry("authority/model.json", authority_record, "NECESSARY"))
        derivations = (*derivations, DerivationEdge("authority/model.json", ("ground.txt",), "mechanism.bin"))
        created_at = "2026-09-08T00:00:00Z"
        coverage_universe = census_boundary_members(
            census, ("ground.txt", "mechanism.bin"), derivations, (),
            AUTHORITY_AXIOM_AGENCY, (), (),
            publisher_id=publisher.publisher_id, parents=(),
            completeness_kind="SILO_CENSUS",
            authority_version=AUTHORITY_AXIOM_AGENCY_VERSION,
            authority_digest=agency_digest,
            self_derivation_record=self_record, created_at=created_at,
            authority_model_path="authority/model.json", authority_model=authority_model,
        )
        commit = SiloCommit(
            publisher_id=publisher.publisher_id, parents=(), census=census,
            ground_paths=("ground.txt", "mechanism.bin"), derivations=derivations,
            relations=(), residual_obligations=(), exclusions=(), completeness_kind="SILO_CENSUS",
            coverage_universe=coverage_universe,
            authority_axiom_agency=AUTHORITY_AXIOM_AGENCY,
            authority_axiom_agency_version=AUTHORITY_AXIOM_AGENCY_VERSION,
            authority_axiom_agency_digest=agency_digest,
            authority_model_path="authority/model.json",
            self_derivation_record=self_record,
            created_at=created_at,
        )
        head = sign_head(commit, key_path, 0, None, "2026-09-08T00:00:00Z")
        records = {
            "object": ground.to_dict(), "publisher": publisher.to_dict(),
            "commit": commit.to_dict(), "signed_head": head.to_dict(),
            "assessment": assess_silo(commit, store).to_dict(),
            "assessment_receipt": build_silo_assessment_receipt(commit, store).to_dict(),
        }
        records["silo_transfer"] = build_silo_transfer(commit, head, publisher, store)
        return {
            "schema_version": "VSTD-ARTIFACT-NETWORK-WIRE-FIXTURE-0.1",
            "encoding": {
                "json": "UTF-8; lowercase ASCII snake_case keys; sorted keys; no whitespace; NFC strings; nonnegative integers <= 2^53-1; no floats",
                "binary": "unpadded RFC 4648 base64url",
                "digest": "sha256:<64 lowercase hexadecimal characters>",
                "signature": "Ed25519 over signed_head_signing_bytes_utf8",
            },
            "records": records,
            "expected": {
                "object_canonical_json": canonical_bytes(records["object"]).decode("utf-8"),
                "object_record_digest": digest_bytes(canonical_bytes(records["object"])),
                "commit_canonical_json": canonical_bytes(records["commit"]).decode("utf-8"),
                "commit_digest": commit.canonical_digest(),
                "assessment_receipt_canonical_json": canonical_bytes(records["assessment_receipt"]).decode("utf-8"),
                "assessment_receipt_digest": digest_bytes(canonical_bytes(records["assessment_receipt"])),
                "signed_head_signing_bytes_utf8": canonical_bytes(head.signing_dict()).decode("utf-8"),
                "signed_head_digest": head.canonical_digest(),
                "silo_transfer_canonical_json": canonical_bytes(records["silo_transfer"]).decode("utf-8"),
                "silo_transfer_digest": digest_bytes(canonical_bytes(records["silo_transfer"])),
            },
            "claim_boundary": "This fixture checks cross-runtime encoding and signature interoperability only; it does not establish artifact correctness, publisher identity, completeness outside the declared census kind, or deployed service compatibility.",
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(build_fixture(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if args.write:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_text(rendered, encoding="utf-8", newline="\n")
        return 0
    expected = rendered.encode("utf-8")
    if not TARGET.is_file():
        raise SystemExit("artifact-network canonical wire fixture is stale; run with --write")
    observed = _read_bounded_regular(TARGET, MAX_RECORD_BYTES, "canonical wire fixture")
    if observed != expected:
        raise SystemExit("artifact-network canonical wire fixture is stale or oversized; run with --write")
    print("[ARTIFACT NETWORK FIXTURE OK]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
