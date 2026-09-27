"""Local emission-time disclosure helper, not normative level 6 conformance.

Acronyms:
    JavaScript Object Notation (JSON);
    Secure Hash Algorithm 256-bit (SHA-256);
    Verifier Standard (VSTD).
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, fields
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from .adapters import SelectiveMerkleDisclosure
from .composition import CompositionDeltaEvaluator
from .independence import MalformedRedactionError, assert_verdict_independence
from .models import (
    DisclosureBound,
    DisclosureSurface,
    EmissionContext,
    EmissionResult,
    ObserverParty,
    TransparencyCommitment,
    _string_sequence,
)


class EmissionRefusalError(ValueError):
    """Raised when an emission violates disclosure bounds or composition limits."""


def _snapshot(value: Any) -> Any:
    """Copy exact plain values and bundled records without user copy hooks."""
    record_types = (DisclosureBound, DisclosureSurface, EmissionContext,
                    EmissionResult, ObserverParty, TransparencyCommitment)

    def copy_plain(item: Any) -> Any:
        kind = type(item)
        if item is None or kind in (str, bool, int):
            return item
        if kind is float and math.isfinite(item):
            return item
        if kind is dict:
            if any(type(key) is not str for key in item):
                raise EmissionRefusalError("JSON object keys must be strings")
            return {key: copy_plain(child) for key, child in item.items()}
        if kind in (list, tuple):
            return kind(copy_plain(child) for child in item)
        if kind in record_types:
            return kind(**{field.name: copy_plain(getattr(item, field.name))
                           for field in fields(kind)})
        raise EmissionRefusalError("Disclosure inputs require finite JSON values and bundled records")

    try:
        return copy_plain(value)
    except RecursionError as exc:
        raise EmissionRefusalError("Disclosure inputs must be finite acyclic JSON values") from exc


def _canonical_bytes(value: Any) -> bytes:
    """Encode finite JSON values without coercing mapping keys or custom objects."""
    def validate(item: Any) -> None:
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("JSON object keys must be strings")
            for child in item.values():
                validate(child)
        elif type(item) in (list, tuple):
            for child in item:
                validate(child)
        elif item is not None and type(item) not in (str, bool, int, float):
            raise ValueError("Unsupported JSON value")

    try:
        validate(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as exc:
        raise EmissionRefusalError("Disclosure inputs must be finite JSON values") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _mechanism_digest() -> str:
    """Bind shipped helper source bytes; this digest does not authenticate them."""
    names = ("engine.py", "models.py", "composition.py", "independence.py", "adapters.py")
    return _digest({name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                    for name in names})


def _input_binding(
    certificate: dict[str, Any], surface: DisclosureSurface,
    bounds: tuple[DisclosureBound, ...], context: EmissionContext,
    join_rules: tuple[tuple[str, str, str], ...],
) -> dict[str, str]:
    """Bind full records without collapsing repeated conjunctive conditions."""
    certificate, surface, bounds, context, join_rules = _snapshot(
        (certificate, surface, bounds, context, join_rules)
    )
    return {
        "certificate_sha256": _digest(certificate),
        "surface_sha256": _digest(asdict(surface)),
        "bounds_sha256": _digest([asdict(bound) for bound in bounds]),
        "context_sha256": _digest(asdict(context)),
        "composition_rules_sha256": _digest(join_rules),
        "mechanism_sha256": _mechanism_digest(),
    }


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

    def recheck_emission(
        self,
        result: EmissionResult,
        certificate: dict[str, Any],
        surface: DisclosureSurface,
        bounds: tuple[DisclosureBound, ...],
        context: EmissionContext,
    ) -> bool:
        """Replay under externally selected inputs and compare the complete result.

        The caller supplies the expected certificate, policy, observer and context;
        none is accepted from the receipt as its own authority. Unbound old receipts,
        substitutions and changed mechanism bytes fail comparison. This reproduces
        the local helper only: it does not authenticate observer declarations,
        validate native certificates or establish normative privacy conformance.
        """
        try:
            if (type(result) is not EmissionResult
                    or not _string_sequence(result.redacted_fields)
                    or type(result.transparency_commitments) not in (tuple, list)
                    or any(type(commitment) is not TransparencyCommitment
                           for commitment in result.transparency_commitments)):
                return False
            result = _snapshot(result)
            expected = self.evaluate_emission(certificate, surface, bounds, context)
            return _canonical_bytes(result.to_dict()) == _canonical_bytes(expected.to_dict())
        except (ValueError, TypeError, AttributeError, RecursionError, OSError):
            return False

    def evaluate_emission(
        self,
        certificate: dict[str, Any],
        surface: DisclosureSurface,
        bounds: tuple[DisclosureBound, ...],
        context: EmissionContext,
    ) -> EmissionResult:
        """Evaluate emission of a certificate against declared bounds and observer context.

        Every emitted top-level field (including structural containers) needs both
        enumeration and a permitting bound. Bounds cover the entire field value;
        nested-path policy is unsupported. Canonical domain certificates must be
        emitted unchanged or refused, because no selective-proof mechanism is
        implemented. Caller-established observer facts are assumed, not verified.
        The result preserves existing verdicts without independently validating them.
        """
        if (type(surface) is not DisclosureSurface or type(context) is not EmissionContext
                or type(context.observer) is not ObserverParty):
            raise EmissionRefusalError("Only bundled disclosure and observer records are supported")
        if type(bounds) not in (tuple, list) or any(type(bound) is not DisclosureBound for bound in bounds):
            raise EmissionRefusalError("Only bundled declarative disclosure bounds are supported")
        if type(surface.commitments) not in (tuple, list) or any(
            type(commitment) is not TransparencyCommitment for commitment in surface.commitments
        ):
            raise EmissionRefusalError("Only bundled commitment records are supported")
        if type(self.composition_evaluator) is not CompositionDeltaEvaluator:
            raise EmissionRefusalError("Only the bundled composition evaluator is supported")
        join_rules = self.composition_evaluator.join_rules
        if type(join_rules) not in (tuple, list) or any(
            not _string_sequence(rule) or len(rule) != 3 for rule in join_rules
        ):
            raise EmissionRefusalError("Composition rules must be sequences of three strings")
        if not all(_string_sequence(value) for value in (
            surface.disclosed_fields, surface.withheld_fields, context.observer.credentials,
        )):
            raise EmissionRefusalError("Disclosure and credential fields must be string sequences")
        if not all(type(value) is str for value in (
            context.observer.actor_id, context.observer.role, context.observer.purpose,
        )):
            raise EmissionRefusalError("Observer declarations must be strings")
        # Private snapshots prevent a composition screen from rewriting the caller's
        # authority inputs. Rebinding after the screen also detects local mutation.
        certificate, surface, bounds, context, join_rules = _snapshot(
            (certificate, surface, bounds, context, join_rules)
        )
        input_binding = _input_binding(certificate, surface, bounds, context, join_rules)
        if set(surface.disclosed_fields) & set(surface.withheld_fields):
            raise EmissionRefusalError("Disclosure surface has disclosed/withheld overlap")
        # Obligation 6.3: Observer identification (party rather than channel)
        if not context.observer.actor_id.strip() or not context.observer.role.strip():
            raise EmissionRefusalError(
                "Observer must be identified as an accountable party (actor_id and role required), "
                "not an anonymous or relayable channel (obligation 6.3)"
            )

        # Obligation 6.5: Composition delta evaluation across co-emitted certificates
        admissible, join_reason, join_meta = CompositionDeltaEvaluator(join_rules).evaluate_composition_delta(
            primary_cert=certificate,
            co_emitted=context.co_emitted_certificates,
            observer=context.observer,
        )
        if type(admissible) is not bool:
            raise EmissionRefusalError("Composition admission must be Boolean")
        if _input_binding(certificate, surface, bounds, context, join_rules) != input_binding:
            raise EmissionRefusalError("Composition evaluation changed disclosure inputs")
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
            field_bounds = bounds_by_field.get(key, [])
            permitted = (key in surface.disclosed_fields
                         and key not in surface.withheld_fields
                         and any(b.permits(context.observer) for b in field_bounds))
            if permitted:
                disclosed_payload[key] = deepcopy(val)
                continue
            redacted_fields.append(key)
            commitments.append(TransparencyCommitment(
                field_name=key, schema_type=type(val).__name__,
                commitment_digest=SelectiveMerkleDisclosure._leaf_hash(key, val),
            ))

        if certificate.get("schema_version") == "verifier-domain-certification-1" and redacted_fields:
            raise EmissionRefusalError(
                "Disclosure would invalidate the canonical certificate; no selective-proof mechanism is available"
            )

        # Obligation 6.6: Verdict independence check
        try:
            assert_verdict_independence(certificate, disclosed_payload)
        except MalformedRedactionError as exc:
            raise EmissionRefusalError("Disclosure would move a computational verdict") from exc

        # Generate verifier-privacy-assessment-receipt-1
        receipt_payload = {
            "schema_version": "verifier-privacy-assessment-receipt-1",
            "object_name": surface.object_name,
            "observer": context.observer.to_dict(),
            "emission_timestamp": context.timestamp,
            "disclosed_fields_count": len(disclosed_payload),
            "redacted_fields": redacted_fields,
            "commitments_count": len(commitments),
            "composition_join_check": "UNKNOWN",
            "composition_rule_screen": "PASS",
            "verdict_independence": "PASS",
            "level_6_conformance": "UNKNOWN",
            "observer_authentication": "NOT_CHECKED",
            "certificate_validation": "NOT_CHECKED",
            "commitment_privacy": "NOT_ESTABLISHED",
            "transparency_commitments": [c.to_dict() for c in commitments],
            "input_binding": input_binding,
        }
        receipt_payload["receipt_digest"] = _digest(receipt_payload)

        return EmissionResult(
            emitted_certificate=disclosed_payload,
            redacted_fields=tuple(redacted_fields),
            transparency_commitments=tuple(commitments),
            receipt=receipt_payload,
        )
