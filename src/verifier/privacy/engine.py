"""Emission-time disclosure and transparency evaluation engine (obligations 6.1 - 6.6).

Acronyms:
    JavaScript Object Notation (JSON);
    Secure Hash Algorithm 256-bit (SHA-256);
    Verifier Standard (VSTD).
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any

from .adapters import SelectiveMerkleDisclosure
from .composition import CompositionDeltaEvaluator
from .independence import assert_verdict_independence
from .models import (
    DisclosureBound,
    DisclosureSurface,
    EmissionContext,
    EmissionResult,
    ObserverParty,
    TransparencyCommitment,
)


class EmissionRefusalError(ValueError):
    """Raised when an emission violates disclosure bounds or composition limits."""


class EmissionEvaluator:
    """Dynamic emission-time evaluator for Level 6 disclosure bounds.

    Bounds are evaluated at every emission of the certificate rather than once
    when the certificate was certified (obligation 6.4).
    """

    def __init__(
        self,
        composition_evaluator: CompositionDeltaEvaluator | None = None,
    ) -> None:
        self.composition_evaluator = (
            CompositionDeltaEvaluator()
            if composition_evaluator is None
            else composition_evaluator
        )

    def evaluate_emission(
        self,
        certificate: dict[str, Any],
        surface: DisclosureSurface,
        bounds: tuple[DisclosureBound, ...],
        context: EmissionContext,
    ) -> EmissionResult:
        """Evaluate emission of a certificate against declared bounds and observer context.

        Executes:
        - Obligation 6.1: Disclosure surface partitioning and non-omission commitments.
        - Obligation 6.2: Disclosure bound declaration and admission testing.
        - Obligation 6.3: Observer identification as an accountable party.
        - Obligation 6.4: Emission-time dynamic evaluation.
        - Obligation 6.5: Composition delta join analysis against co-emitted certificates.
        - Obligation 6.6: Strict verdict independence validation.
        """
        # Obligation 6.3: Observer identification (party rather than channel)
        if not context.observer.actor_id or not context.observer.role:
            raise EmissionRefusalError(
                "Observer must be identified as an accountable party (actor_id and role required), "
                "not an anonymous or relayable channel (obligation 6.3)"
            )

        # Obligation 6.5: Composition delta evaluation across co-emitted certificates
        admissible, join_reason, join_meta = self.composition_evaluator.evaluate_composition_delta(
            primary_cert=certificate,
            co_emitted=context.co_emitted_certificates,
            observer=context.observer,
        )
        if not admissible:
            raise EmissionRefusalError(f"Composition delta violation (obligation 6.5): {join_reason}")

        # Index bounds by field_name
        bounds_by_field: dict[str, list[DisclosureBound]] = {}
        for b in bounds:
            bounds_by_field.setdefault(b.field_name, []).append(b)

        # Obligation 6.1 & 6.2: Determine which fields are permitted to this observer
        disclosed_payload: dict[str, Any] = {}
        redacted_fields: list[str] = []
        commitments: list[TransparencyCommitment] = list(surface.commitments)

        for key, val in certificate.items():
            # Tiers 1-5 structural and verdict fields must always be present to preserve verification
            if key in {
                "schema_version", "object_name", "domain", "verdict",
                "result", "request", "certificate_digest", "specification_digest",
                "policy_digest", "mechanism_digest",
                "tier_1", "tier_2", "tier_3", "tier_4", "tier_5",
                "tier_1_verdict", "tier_2_verdict", "tier_3_verdict",
                "tier_4_verdict", "tier_5_verdict", "results",
            }:
                disclosed_payload[key] = deepcopy(val)
                continue

            # If field is declared in surface withheld_fields, withhold it immediately
            if key in surface.withheld_fields:
                redacted_fields.append(key)
                leaf_hash = SelectiveMerkleDisclosure._leaf_hash(key, val)
                commitments.append(
                    TransparencyCommitment(
                        field_name=key,
                        schema_type=type(val).__name__,
                        commitment_digest=leaf_hash,
                    )
                )
                continue

            # Obligation 6.2: A field emitted without a bound is not admissible
            field_bounds = bounds_by_field.get(key, [])
            if not field_bounds:
                # Field lacks an explicit bound: fail closed by withholding
                redacted_fields.append(key)
                leaf_hash = SelectiveMerkleDisclosure._leaf_hash(key, val)
                commitments.append(
                    TransparencyCommitment(
                        field_name=key,
                        schema_type=type(val).__name__,
                        commitment_digest=leaf_hash,
                    )
                )
                continue

            # Evaluate bounds against observer
            if any(b.permits(context.observer) for b in field_bounds):
                disclosed_payload[key] = deepcopy(val)
            else:
                redacted_fields.append(key)
                leaf_hash = SelectiveMerkleDisclosure._leaf_hash(key, val)
                commitments.append(
                    TransparencyCommitment(
                        field_name=key,
                        schema_type=type(val).__name__,
                        commitment_digest=leaf_hash,
                    )
                )

        # Attach transparent negative-space commitments to emitted certificate
        disclosed_payload["transparency_commitments"] = [c.to_dict() for c in commitments]

        # Obligation 6.6: Verdict independence check
        assert_verdict_independence(certificate, disclosed_payload)

        # Generate verifier-privacy-assessment-receipt-1
        receipt_payload = {
            "schema_version": "verifier-privacy-assessment-receipt-1",
            "object_name": surface.object_name,
            "observer": context.observer.to_dict(),
            "emission_timestamp": context.timestamp,
            "disclosed_fields_count": len(disclosed_payload),
            "redacted_fields": redacted_fields,
            "commitments_count": len(commitments),
            "composition_join_check": "PASS" if admissible else "FAIL",
            "verdict_independence": "PASS",
        }
        receipt_bytes = json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        receipt_payload["receipt_digest"] = hashlib.sha256(receipt_bytes).hexdigest()

        return EmissionResult(
            emitted_certificate=disclosed_payload,
            redacted_fields=tuple(redacted_fields),
            transparency_commitments=tuple(commitments),
            receipt=receipt_payload,
        )
