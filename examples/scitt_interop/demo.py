"""Terminology: Concise Binary Object Representation (CBOR);
CBOR Object Signing and Encryption (COSE); CBOR Web Token (CWT);
grounded decision certificate (GDC); Request for Comments (RFC);
Supply Chain Integrity, Transparency, and Trust (SCITT); Secure Hash Algorithm 256-bit (SHA-256);
verifiable data structure (VDS); Verifier Standard (VSTD).

Deterministic cryptographic VSTD/SCITT interoperability specimen.

The optional ``scitt`` extra supplies COSE and RFC 9162 receipt primitives.  A
one-entry local test log is used so the example is self-contained.  This is a
real signed statement, signed inclusion receipt, and independent verification;
it is not a production Transparency Service, public anchoring, or endorsement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from verifier.core.certificate import (
    CertificateHeader,
    ClaimBinding,
    ClaimCoordinate,
    ClauseGrounding,
    CostTier,
    DecisionBlock,
    DecisionCertificate,
    EncodingRule,
    GroundedFact,
    Grounding,
    ResourceBounds,
    VariableGrounding,
    Verdict,
    VerifierDescriptor,
    canonical_bytes,
    canonical_digest,
    certificate_from_dict,
)
from verifier.core.kernel import KernelOutcome, check, reference_descriptor
from verifier.interoperability.scitt import (
    EXPERIMENTAL_CONTENT_TYPE,
    EXPERIMENTAL_PROFILE,
    ScittEvidenceState,
    ScittVerificationEvidence,
    VstdCoordinates,
    VstdScittPayload,
    VstdVerificationEvidence,
    VstdVerificationState,
    compose_results,
    consume_scitt_evidence,
    create_scitt_registration_template,
)


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE / "artifact.txt"
ISSUER = "https://issuer.example/vstd-scitt-demo"
LOCAL_LOG = "urn:example:vstd-scitt-local-test-log"
POLICY = "urn:example:vstd-scitt-registration-policy:v1"


def _crypto():
    try:
        import cbor2
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from scitt_cose import (
            attach_receipts,
            build_receipt,
            build_signed_statement,
            extract_receipts,
            merkle_root,
            parse_signed_statement,
            sign_sign1,
            verify_receipt,
        )
    except ImportError as exc:  # pragma: no cover - exercised in base environment
        raise SystemExit(
            "Install the pinned optional dependencies with: "
            "python -m pip install -e '.[scitt]'"
        ) from exc
    return {
        "cbor2": cbor2,
        "serialization": serialization,
        "ed25519": ed25519,
        "attach_receipts": attach_receipts,
        "build_receipt": build_receipt,
        "build_signed_statement": build_signed_statement,
        "extract_receipts": extract_receipts,
        "merkle_root": merkle_root,
        "parse_signed_statement": parse_signed_statement,
        "sign_sign1": sign_sign1,
        "verify_receipt": verify_receipt,
    }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _public_key_pair():
    crypto = _crypto()
    serialization = crypto["serialization"]
    key = crypto["ed25519"].Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _claim_binding_from_dict(value: dict[str, Any]) -> ClaimBinding:
    """Reconstruct the exact receipt binding for independent kernel checking."""

    coordinate = value["coordinate"]
    bounds = value["bounds"]
    verifier = value["verifier"]
    return ClaimBinding(
        claim=value["claim"],
        coordinate=ClaimCoordinate(
            coordinate["subject"],
            coordinate["predicate"],
            dict(coordinate["parameters"]),
        ),
        policy_root=value["policy_root"],
        evidence_root=value["evidence_root"],
        verifier=VerifierDescriptor(
            specification_hash=verifier["specification_hash"],
            implementation_hash=verifier["implementation_hash"],
            parser_hash=verifier["parser_hash"],
            certificate_format=verifier["certificate_format"],
            format_fragment=verifier["format_fragment"],
            dependencies=tuple(verifier["dependencies"]),
            deterministic=verifier["deterministic"],
        ),
        bounds=ResourceBounds(
            bounds["verification_cost_bound"],
            bounds["memory_bound"],
            bounds["certificate_size_bound"],
        ),
        prior_commitment=value["prior_commitment"],
    )


def _apply_local_registration_policy(
    parsed: dict[str, Any], coordinates: VstdCoordinates
) -> None:
    """Minimal explicit policy applied before the local log issues a receipt."""

    if parsed.get("signature_verified") is not True:
        raise RuntimeError("registration policy rejected an unverified statement")
    if parsed.get("issuer") != ISSUER:
        raise RuntimeError("registration policy rejected the issuer")
    if parsed.get("subject") != coordinates.subject:
        raise RuntimeError("registration policy rejected the subject")
    if parsed.get("content_type") != EXPERIMENTAL_CONTENT_TYPE:
        raise RuntimeError("registration policy rejected the payload content type")
    if parsed.get("claims", {}).get("vstd_profile") != EXPERIMENTAL_PROFILE:
        raise RuntimeError("registration policy rejected the VSTD profile")


def build_vstd_receipt() -> tuple[dict[str, Any], VstdCoordinates]:
    artifact_digest = _sha256(ARTIFACT.read_bytes())
    subject = f"artifact:sha256:{artifact_digest}"
    predicate = "content_digest_matches"
    formula = ((1,),)
    rule = EncodingRule("RULE:ASSERT_DIGEST_MATCH", ("artifact",), ((1, "artifact"),))
    grounding = Grounding(
        variables=(
            VariableGrounding(
                1, GroundedFact(subject, predicate, "MATCH")
            ),
        ),
        clauses=(
            ClauseGrounding(0, rule.rule_id, {"artifact": 1}, {"artifact": subject}),
        ),
        rules=(rule,),
    )
    binding = ClaimBinding(
        claim="the named artifact bytes have the declared SHA-256 digest",
        coordinate=ClaimCoordinate(
            subject, predicate, {"algorithm": "sha-256", "digest": artifact_digest}
        ),
        policy_root=canonical_digest(
            {"algorithm": "sha-256", "predicate": predicate}
        ),
        evidence_root=artifact_digest,
        verifier=reference_descriptor(),
        bounds=ResourceBounds(100, 10, 20000),
    )
    certificate = DecisionCertificate(
        CertificateHeader(
            Verdict.PASS,
            CostTier.UP,
            n_vars=1,
            clause_count=1,
            literal_count=1,
            step_count=0,
            binding=binding.digest(),
        ),
        formula,
        grounding,
        DecisionBlock(model={1: True}),
    )
    result = check(certificate, budget=100, binding=binding)
    if result.outcome is not KernelOutcome.ACCEPTED or result.verdict is not Verdict.PASS:
        raise RuntimeError(f"VSTD kernel did not accept demo certificate: {result}")

    receipt = {
        "schema_version": "VSTD-4",
        "receipt_id": "VFY-4-scitt-interop-demo",
        "claim_id": "SCITT-INTEROP-DEMO-DIGEST",
        "binding": binding.to_dict(),
        "vstd4_depth": 14,
        "rung_evidence": {
            f"4.{index}": f"decision_certificate:{certificate.digest()}#4.{index}"
            for index in range(1, 15)
        },
        "witness": certificate.to_dict(),
        "ceiling_refutation": None,
        "blocking_rungs": [],
        "status": "VALID",
        "refutation_surface": {
            "admissible_refutations": [
                "artifact bytes hash to a value other than the bound digest",
                "the VSTD decision certificate fails independent checking",
            ],
            "excluded_claims": [
                "artifact safety",
                "issuer authorization",
                "truth outside the bounded digest predicate",
            ],
        },
    }
    receipt_digest = _sha256(canonical_bytes(receipt))
    coordinates = VstdCoordinates(
        receipt_id=receipt["receipt_id"],
        schema_version=receipt["schema_version"],
        claim_id=receipt["claim_id"],
        subject=subject,
        predicate=predicate,
        parameters={"algorithm": "sha-256", "digest": artifact_digest},
        native_result=result.verdict.value,
        native_canonical_digest=receipt_digest,
        evidence_bounds=binding.bounds.to_dict(),
        artifact_digests={"primary": artifact_digest},
        provenance_references=("urn:example:vstd-scitt-demo:artifact",),
    )
    return receipt, coordinates


def produce(
    output: Path, *, vstd_binding_tamper: bool = False
) -> dict[str, Any]:
    crypto = _crypto()
    receipt, coordinates = build_vstd_receipt()
    if vstd_binding_tamper:
        receipt["witness"]["header"]["binding"] = "0" * 64
        coordinates = replace(
            coordinates,
            native_canonical_digest=_sha256(canonical_bytes(receipt)),
        )
    template = create_scitt_registration_template(
        receipt, coordinates, issuer=ISSUER, subject=coordinates.subject
    )
    payload_bytes = template.payload.to_bytes()

    # Generate fresh, memory-only private keys.  The public keys are emitted
    # as explicit trust coordinates; private key material is never committed
    # or written to the output directory.
    issuer_private, issuer_public = _public_key_pair()
    log_private, log_public = _public_key_pair()
    issuer_kid = hashlib.sha256(issuer_public).digest()
    log_kid = hashlib.sha256(log_public).digest()
    statement = crypto["build_signed_statement"](
        payload_bytes,
        alg="EdDSA",
        private_key_pem=issuer_private,
        issuer=ISSUER,
        subject=coordinates.subject,
        content_type=EXPERIMENTAL_CONTENT_TYPE,
        extra_cwt_claims={"vstd_profile": EXPERIMENTAL_PROFILE},
        kid=issuer_kid,
    )
    _apply_local_registration_policy(
        crypto["parse_signed_statement"](
            statement, public_key_pem=issuer_public
        ),
        coordinates,
    )
    tree_entries = [statement.hex()]
    base_receipt = crypto["build_receipt"](
        leaf_entry_hex=statement.hex(),
        leaf_index=0,
        tree_entries_hex=tree_entries,
        alg="EdDSA",
        log_private_key_pem=log_private,
    )
    # The generic RFC 9942 builder supplies the VDS proof. Re-sign the same
    # detached root with RFC 9943's mandatory protected CWT issuer/subject
    # claims so this specimen is also a SCITT Receipt, not only a COSE Receipt.
    decoded_base = crypto["cbor2"].loads(base_receipt)
    root = bytes.fromhex(crypto["merkle_root"](tree_entries))
    scitt_receipt = crypto["sign_sign1"](
        root,
        alg="EdDSA",
        private_key_pem=log_private,
        protected={
            4: log_kid,
            15: {1: LOCAL_LOG, 2: coordinates.subject},
            395: 1,
        },
        unprotected=decoded_base.value[1],
        detached=True,
    )
    transparent = crypto["attach_receipts"](statement, [scitt_receipt])

    output.mkdir(parents=True, exist_ok=True)
    (output / "vstd_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "vstd_scitt_payload.json").write_bytes(payload_bytes + b"\n")
    (output / "registration_template.json").write_text(
        json.dumps(template.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "signed_statement.cose").write_bytes(statement)
    (output / "receipt.cose").write_bytes(scitt_receipt)
    (output / "transparent_statement.cose").write_bytes(transparent)
    (output / "issuer_public.pem").write_bytes(issuer_public)
    (output / "log_public.pem").write_bytes(log_public)
    return verify(output)


def verify(output: Path, *, vstd_budget: int = 100) -> dict[str, Any]:
    crypto = _crypto()
    payload_bytes = (output / "vstd_scitt_payload.json").read_bytes().rstrip(b"\n")
    payload = VstdScittPayload.from_bytes(payload_bytes)
    statement = (output / "signed_statement.cose").read_bytes()
    scitt_receipt = (output / "receipt.cose").read_bytes()
    transparent = (output / "transparent_statement.cose").read_bytes()
    issuer_public = (output / "issuer_public.pem").read_bytes()
    log_public = (output / "log_public.pem").read_bytes()

    try:
        parsed = crypto["parse_signed_statement"](
            statement, public_key_pem=issuer_public
        )
        statement_structure = crypto["cbor2"].loads(statement)
        statement_protected = crypto["cbor2"].loads(statement_structure.value[0])
    except Exception as exc:
        raise RuntimeError("malformed SCITT Signed Statement") from exc
    receipt_result = crypto["verify_receipt"](
        scitt_receipt,
        leaf_entry_hex=statement.hex(),
        log_public_key_pem=log_public,
    )
    attached = crypto["extract_receipts"](transparent)
    receipt_structure = crypto["cbor2"].loads(scitt_receipt)
    receipt_protected = crypto["cbor2"].loads(receipt_structure.value[0])
    if parsed["signature_verified"] is not True:
        raise RuntimeError("SCITT Signed Statement signature did not verify")
    _apply_local_registration_policy(parsed, payload.coordinates)
    if parsed["payload"] != payload_bytes:
        raise RuntimeError("SCITT Signed Statement payload changed")
    if parsed["issuer"] != ISSUER or parsed["subject"] != payload.coordinates.subject:
        raise RuntimeError("SCITT Signed Statement identity coordinates changed")
    if parsed["content_type"] != EXPERIMENTAL_CONTENT_TYPE:
        raise RuntimeError("SCITT Signed Statement content type changed")
    if statement_protected.get(4) != hashlib.sha256(issuer_public).digest():
        raise RuntimeError("SCITT Signed Statement key identifier changed")
    if not receipt_result.ok:
        raise RuntimeError(f"COSE Receipt failed: {receipt_result.errors}")
    if receipt_protected.get(15) != {
        1: LOCAL_LOG,
        2: payload.coordinates.subject,
    }:
        raise RuntimeError("SCITT Receipt issuer/subject claims changed")
    if receipt_protected.get(4) != hashlib.sha256(log_public).digest():
        raise RuntimeError("SCITT Receipt key identifier changed")
    if attached != [scitt_receipt]:
        raise RuntimeError("Transparent Statement did not preserve its receipt")

    native_receipt = json.loads((output / "vstd_receipt.json").read_text())
    certificate = certificate_from_dict(native_receipt["witness"])
    binding = _claim_binding_from_dict(native_receipt["binding"])
    vstd_result = check(certificate, budget=vstd_budget, binding=binding)
    if vstd_result.outcome is KernelOutcome.ACCEPTED:
        vstd_state = VstdVerificationState.VERIFIED
        if vstd_result.verdict is None:
            raise RuntimeError("independent VSTD checker returned no native verdict")
        native_vstd_result = vstd_result.verdict.value
    elif vstd_result.outcome is KernelOutcome.REFUSED:
        vstd_state = VstdVerificationState.INDETERMINATE
        native_vstd_result = "UNKNOWN"
    else:
        vstd_state = VstdVerificationState.REJECTED
        native_vstd_result = "REJECTED"

    vstd_observation = VstdVerificationEvidence(
        state=vstd_state,
        receipt_sha256=_sha256(canonical_bytes(native_receipt)),
        native_result=native_vstd_result,
        checker="verifier.core.kernel.check",
        verification_profile="VSTD4-GDC-1/reference-kernel",
        reason=vstd_result.details,
    )

    observation = ScittVerificationEvidence(
        state=ScittEvidenceState.REGISTERED,
        statement_sha256=_sha256(statement),
        payload_sha256=_sha256(payload_bytes),
        issuer=parsed["issuer"],
        subject=parsed["subject"],
        signed_statement_verified=True,
        receipt_verified=True,
        verification_profile="RFC9943+RFC9942/RFC9162_SHA256",
        registration_policy=POLICY,
        transparency_service=LOCAL_LOG,
        vds="RFC9162_SHA256",
        native_result="SIGNED_STATEMENT_AND_INCLUSION_RECEIPT_VERIFIED",
        reason=(
            "local one-entry test log; cryptographic inclusion verified, "
            "without public anchoring or production-service claims"
        ),
        registered_at="2026-08-23T00:00:00Z",
    )
    composition = compose_results(
        payload,
        vstd_observation,
        observation,
        artifact_digests={"primary": _sha256(ARTIFACT.read_bytes())},
        accepted_issuers=[ISSUER],
    )
    expected_composition = {
        KernelOutcome.ACCEPTED: "PASS",
        KernelOutcome.REFUSED: "UNKNOWN",
        KernelOutcome.REJECTED: "FAIL",
    }[vstd_result.outcome]
    if composition.status.value != expected_composition:
        raise RuntimeError(f"composition failed: {composition}")

    scitt_as_vstd_evidence = consume_scitt_evidence(
        observation,
        expected_payload_sha256=payload.payload_sha256(),
        expected_subject=payload.coordinates.subject,
        accepted_issuers=[ISSUER],
    )

    result = {
        "vstd_kernel": vstd_result.to_dict(),
        "vstd_observation": vstd_observation.to_dict(),
        "scitt_observation": observation.to_dict(),
        "scitt_as_vstd_evidence": scitt_as_vstd_evidence,
        "composition": composition.to_dict(),
        "artifact_sha256": _sha256(ARTIFACT.read_bytes()),
        "payload_sha256": _sha256(payload_bytes),
        "statement_sha256": _sha256(statement),
        "receipt_sha256": _sha256(scitt_receipt),
        "transparent_statement_sha256": _sha256(transparent),
    }
    (output / "verification_result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("produce", "verify"))
    parser.add_argument("--output", type=Path, default=HERE / "generated")
    parser.add_argument("--vstd-budget", type=int, default=100)
    args = parser.parse_args()
    result = (
        produce(args.output)
        if args.command == "produce"
        else verify(args.output, vstd_budget=args.vstd_budget)
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
