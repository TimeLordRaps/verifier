"""Installed Tier-0 repository-admission obligations for Verifier Standard
(VSTD) self-polish.

Terms used below include application programming interface (API), abstract
syntax tree (AST), command-line interface (CLI), identifier (ID), and
JavaScript Object Notation (JSON).

Tier zero is not a ``MetaTier`` and does not establish any numbered object
obligation.  It answers the prior question: is the repository declaration
complete enough, current enough, and independently checkable enough to begin
semantic self-polish without silently omitting objects, surfaces, obligations,
reasons, adaptations, or source drift?
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


PROFILE_SCHEMA = "verifier-tier-zero-repository-admission-profile-1"
PROFILE_ID = "vstd-tier-zero-repository-admission-1"
MANIFEST_SCHEMA = "verifier-objects-manifest-1"
OBJECT_KIND_COUNT = 26
CORE_SLOT_COUNT = 234
CORE_ROUTE_COUNT = 408


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def value_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


_FIELDS = {
    "coordinate", "name", "question", "rationale", "required_evidence",
    "pass_condition", "unknown_condition", "failure_condition",
    "claim_boundary", "applicability", "applicability_digest",
}
_APPLICABILITY_FIELDS = {
    "mode", "condition", "reason", "when_condition_met", "unknown_condition",
}


def validate_applicability_declaration(value: Any) -> dict[str, str]:
    """Validate the outcome-free applicability contract shared by route producers.

    The declaration explains why a proposition belongs in a denominator.  It
    deliberately has no status or evidence field: only an instance assessment
    may establish that a condition triggered or that an obligation passed.
    """
    if type(value) is not dict or set(value) != _APPLICABILITY_FIELDS:
        raise ValueError("APPLICABILITY_DECLARATION_FIELDS")
    if value["mode"] not in {"NECESSARY", "CONDITIONAL"}:
        raise ValueError("APPLICABILITY_DECLARATION_MODE")
    for field in ("condition", "reason"):
        text = value[field]
        if type(text) is not str or not text.strip() or len(text) > 8192:
            raise ValueError("APPLICABILITY_DECLARATION_" + field.upper())
    if value["when_condition_met"] != "NECESSARY":
        raise ValueError("APPLICABILITY_DECLARATION_TRIGGER")
    if value["unknown_condition"] != "NOT_EXEMPT":
        raise ValueError("APPLICABILITY_DECLARATION_UNKNOWN")
    return {field: value[field] for field in (
        "mode", "condition", "when_condition_met", "unknown_condition", "reason",
    )}


def applicability_declaration(*, mode: str, condition: str, reason: str) -> dict[str, str]:
    """Construct one canonical necessary-or-conditional declaration."""
    return validate_applicability_declaration({
        "mode": mode,
        "condition": condition,
        "when_condition_met": "NECESSARY",
        "unknown_condition": "NOT_EXEMPT",
        "reason": reason,
    })


def applicability_digest(value: Any) -> str:
    """Digest exactly one validated outcome-free applicability declaration."""
    return value_digest(validate_applicability_declaration(value))


def validate_applicability_binding(value: Any) -> dict[str, str]:
    """Reject a route/obligation whose declaration and dedicated digest differ."""
    if type(value) is not dict:
        raise ValueError("APPLICABILITY_BINDING_FIELDS")
    declaration = validate_applicability_declaration(value.get("applicability"))
    if value.get("applicability_digest") != applicability_digest(declaration):
        raise ValueError("APPLICABILITY_BINDING_DIGEST")
    return declaration


def _obligation(
        coordinate: str, name: str, question: str, rationale: str,
        required_evidence: tuple[str, ...], pass_condition: str,
        unknown_condition: str, failure_condition: str,
        claim_boundary: str,
        ) -> dict[str, Any]:
    applicability = applicability_declaration(
        mode="NECESSARY",
        condition=(
            "Repository admission is requested for the exact selected repository "
            "declaration and source coordinate."
        ),
        reason=rationale,
    )
    return {
        "coordinate": coordinate,
        "name": name,
        "question": question,
        "rationale": rationale,
        "required_evidence": list(required_evidence),
        "pass_condition": pass_condition,
        "unknown_condition": unknown_condition,
        "failure_condition": failure_condition,
        "claim_boundary": claim_boundary,
        "applicability": applicability,
        "applicability_digest": applicability_digest(applicability),
    }


_OBLIGATIONS = (
    _obligation(
        "VSTD-T0.1", "Canonical manifest admission",
        "Are the selected objects.vstd bytes strict canonical JSON under the installed schema and profile?",
        "A repository declaration cannot be replayed across implementations when duplicate keys, non-finite values, encoding ambiguity, or schema drift can change its meaning.",
        ("exact objects.vstd bytes", "installed JSON Schema", "installed Tier-0 profile digest"),
        "Strict decoding, schema validation, canonical re-encoding, and profile binding all reproduce exactly.",
        "Selected bytes or an independent decoder are unavailable.",
        "Malformed, duplicate-key, non-finite, non-canonical, oversized, or wrong-profile bytes are observed.",
        "PASS establishes only canonical admission of one exact declaration.",
    ),
    _obligation(
        "VSTD-T0.2", "Object denominator closure",
        "Does the manifest declare exactly one stable record for every installed VSTD object kind?",
        "Whole-package claims are unsound when an admitted kind can be omitted, duplicated, aliased, or replaced without changing the declared denominator.",
        ("installed ObjectKind inventory", "26 manifest object records", "unique object identifiers"),
        "The manifest and installed namespace contain the same 26 kinds exactly once with unique identifiers.",
        "The installed namespace cannot be observed.",
        "A kind or identifier is missing, extra, duplicated, substituted, or inconsistent.",
        "PASS establishes the object census, not the truth of any object payload.",
    ),
    _obligation(
        "VSTD-T0.3", "Typed relation closure",
        "Do all declared object edges resolve and reproduce the installed typed package graph?",
        "A list of objects is not a package graph; dangling, mistyped, omitted, or extra relations can hide the interactions later tiers must assess.",
        ("typed edge declarations", "installed relation template", "canonical graph round trip", "composition assessment"),
        "Every edge resolves to a declared object, the exact typed edge set matches the installed template, and canonical composition passes.",
        "Composition resources or an installed relation definition are unavailable.",
        "An edge is dangling, mistyped, duplicated, omitted, extra, or composition is refuted.",
        "PASS establishes finite typed composition only.",
    ),
    _obligation(
        "VSTD-T0.4", "Exposed-surface closure",
        "Does independent discovery account for every exposed repository surface in the installed census categories?",
        "A repository can appear covered while unlisted files, CLI routes, APIs, schemas, plugins, receipts, mechanisms, or compatibility surfaces remain outside the assessment.",
        ("opening and closing source census", "installed discovery category set", "all discovered surface identities", "ownership or explicit exclusion for each identity"),
        "The complete discovered candidate set is unchanged and every identity has one declared disposition without silent residual surfaces.",
        "A surface is observable but its applicability or ownership evidence is unavailable.",
        "Discovery changes during assessment or a surface is missing, extra, multiply disposed, falsely excluded, or contradicts the manifest.",
        "PASS establishes bounded census and disposition closure, not semantic correctness of a surface.",
    ),
    _obligation(
        "VSTD-T0.5", "Obligation denominator closure",
        "Does the declaration bind the exact installed 234-slot and 408-route obligation denominator?",
        "Surface coverage is not standards coverage: every installed object-tier slot and route must remain visible before higher-tier results can be interpreted as complete.",
        ("installed route inventory", "234 slot identities", "408 route identities", "semantic and proposition digests"),
        "The declared slot and route identity sets and their current semantic digests exactly match the installed inventory.",
        "The installed inventory or a selected denominator attachment is unavailable.",
        "Any slot, route, semantic version, proposition, certificate schema, scope, or checking mechanism differs.",
        "PASS establishes denominator identity only; no route verdict is promoted.",
    ),
    _obligation(
        "VSTD-T0.6", "Reason and realization closure",
        "Does every obligation have both its standard rationale and a repository-specific realization or adaptation annotation?",
        "An obligation name alone does not explain why it exists or why exact repository mechanisms satisfy, specialize, translate, condition, exclude, or fail to realize it.",
        ("standard rationale for every slot and route", "repository realization class", "semantic digest", "discovered surface IDs", "mechanism-byte bindings", "evidence requirements", "preserved and unpreserved semantics", "residual obligations", "falsifiers", "decision authority"),
        "Every annotation is present, well formed, current-byte bound, and independently reconciled; adaptations state why they are necessary and cannot erase semantic loss.",
        "A valid annotation is present but its semantic support or decision authority is not established.",
        "An annotation is missing, malformed, stale, contradictory, falsely claims direct realization, or hides lost semantics.",
        "PASS establishes the bounded annotation and its reconciled support, not the original obligation beyond that evidence.",
    ),
    _obligation(
        "VSTD-T0.7", "Source and mechanism freshness",
        "Are the manifest, discovered surfaces, checking mechanisms, and receipts bound to one unchanged source coordinate?",
        "A correct declaration for old or changing bytes cannot admit the repository currently being polished.",
        ("source head and tree", "tracked and nonignored-untracked byte census", "opening and closing source capture", "mechanism source digests"),
        "All selected and discovered evidence binds the same coordinate and the closing recapture equals the opening capture.",
        "A required source observation cannot be completed.",
        "Any selected digest, path, mechanism byte sequence, or source coordinate differs or mutates during assessment.",
        "PASS establishes freshness at the bounded assessment coordinate, not historical continuity.",
    ),
    _obligation(
        "VSTD-T0.8", "Independent implementation agreement",
        "Do strict Python and Node reconcilers independently admit the same canonical declaration, object graph, declared obligation denominator, and selected attachment bytes?",
        "A language-neutral manifest is not independently checkable when one implementation defines both its grammar and the only accepted interpretation.",
        ("Python reconciliation receipt", "Node reconciliation receipt", "shared adversarial corpus", "golden canonical digests", "source-bound attachment digests", "differential result comparison"),
        "Both source-bound implementations pass the same parser fixtures and independently emit equal manifest, object, graph, declared-denominator, attachment, and result digests.",
        "Either implementation or a required runtime is unavailable.",
        "The implementations disagree, accept a forbidden input, reject a required valid input, or bind different declaration, graph, denominator, or attachment bytes.",
        "PASS establishes bounded cross-runtime manifest agreement, not duplicate full-language AST discovery or universal parser equivalence.",
    ),
    _obligation(
        "VSTD-T0.9", "Conservative verdict and authority boundary",
        "Does Tier zero preserve FAIL, UNKNOWN, lifecycle, and authority distinctions without granting higher-tier credit?",
        "Admission becomes unsafe if missing support is coerced to PASS or if structural coverage is relabeled as semantic correctness, owner adoption, polish, release, or deployment authority.",
        ("per-obligation outcomes", "explicit residual blockers", "decision-authority fields", "claim boundary", "polished and release flags"),
        "Contradictions remain FAIL, unavailable or unsupported claims remain UNKNOWN, and a Tier-0 PASS leaves every Tier-1-plus, polished, release, and deployment claim unestablished.",
        "A required independent authority decision is absent without contradiction.",
        "A weaker lifecycle state is promoted, a blocker is suppressed, or Tier zero grants semantic, polished, release, or deployment authority.",
        "PASS closes only the nine installed Tier-0 repository-admission obligations.",
    ),
)

_CLOSURE_DIMENSIONS = (
    "encoding_and_schema", "object_denominator", "typed_relations",
    "exposed_surfaces", "obligation_denominator", "reasons_and_realization",
    "source_freshness", "independent_reconciliation", "epistemic_boundary",
)


def installed_tier_zero_profile() -> dict[str, Any]:
    """Return the fixed installed Tier-0 denominator and its reasons."""
    obligations = [dict(row) for row in _OBLIGATIONS]
    if len(obligations) != 9 or any(set(row) != _FIELDS for row in obligations):
        raise RuntimeError("TIER_ZERO_PROFILE_INTERNAL_FIELDS")
    coordinates = [row["coordinate"] for row in obligations]
    if len(set(coordinates)) != len(coordinates):
        raise RuntimeError("TIER_ZERO_PROFILE_DUPLICATE_COORDINATE")
    body = {
        "schema_version": PROFILE_SCHEMA,
        "profile_id": PROFILE_ID,
        "manifest_schema_version": MANIFEST_SCHEMA,
        "object_kind_count": OBJECT_KIND_COUNT,
        "core_slot_count": CORE_SLOT_COUNT,
        "core_route_count": CORE_ROUTE_COUNT,
        "obligation_count": len(obligations),
        "obligations": obligations,
        "closure_dimensions": list(_CLOSURE_DIMENSIONS),
        "finalization_rule": (
            "This version is complete for repository admission only because its "
            "denominator covers encoding, objects, relations, exposed surfaces, "
            "installed obligations, two-layer reasons, source freshness, independent "
            "reconciliation, and conservative authority boundaries. Adding, removing, "
            "or changing an obligation requires a new profile version and digest."
        ),
        "claim_boundary": (
            "Tier-0 PASS admits one exact repository declaration at one source "
            "coordinate. It does not establish a Tier-1-plus obligation, full package "
            "polish, release authority, publication, or deployment."
        ),
    }
    return {**body, "profile_digest": value_digest(body)}


def mechanism_digest(module_bytes: bytes, specification_bytes: bytes) -> str:
    """Digest the exact module and specification bytes that the caller read.

    The orchestrator reads both packaged resources and passes them here, so this
    owner constructs no path and performs no file access.  Only exact ``bytes``
    are admitted; any other value fails closed instead of being coerced.
    """
    if type(module_bytes) is not bytes or type(specification_bytes) is not bytes:
        raise ValueError("TIER_ZERO_PROFILE_MECHANISM_BYTES_INVALID")
    return value_digest({
        "schema_version": "verifier-tier-zero-profile-mechanism-1",
        "module_digest": "sha256:" + hashlib.sha256(module_bytes).hexdigest(),
        "specification_digest": "sha256:" + hashlib.sha256(
            specification_bytes
        ).hexdigest(),
        "profile_digest": installed_tier_zero_profile()["profile_digest"],
    })


__all__ = [
    "CORE_ROUTE_COUNT", "CORE_SLOT_COUNT", "MANIFEST_SCHEMA",
    "OBJECT_KIND_COUNT", "PROFILE_ID", "PROFILE_SCHEMA", "canonical_bytes",
    "applicability_declaration", "applicability_digest", "installed_tier_zero_profile",
    "mechanism_digest", "validate_applicability_binding",
    "validate_applicability_declaration", "value_digest",
]
