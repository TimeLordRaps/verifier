"""Tier-0 semantic reviews for seven original people/identity package objects.

Terminology: JavaScript Object Notation (JSON); trusted computing base (TCB);
abstract syntax tree (AST).

The reviewed denominator follows the package migration's explicit ownership
rule: one domain implementation (where present) plus every current file below
``domains/contracts`` whose stem names the kind, at any depth and with any
suffix (case-insensitive; caches excluded).  RECEIPT has no domain implementation
and therefore owns only its same-prefix contracts.  The census is re-observed at
opening, after conflict analysis, and before return, so adding or removing a
source changes that denominator and makes application fail closed.

A DOES_NOT_APPLY basis is kept only when the exact owned code names no mechanism
of that kind (AST identifiers, attributes, definitions, and single-token string
literals; docstrings excluded).  A kind whose mechanism words appear in owned code
but whose role was not positively refuted is UNRESOLVED, never DOES_NOT_APPLY.
Application re-checks this against the current bytes and fails closed on drift.

These are current-source declarations, not mechanism proofs.  In particular,
retained event replay is not a live ledger or transaction, signature validity is
not real-world authenticity, declared authority is not external authority, and
the configured IDENTITY exit controller affects only an ephemeral replay.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.package_semantic_ownership_domains_agency_collective import (
    OBLIGATION_RETENTION_APPLIES as _AGENCY_OBLIGATION_RETENTION_APPLIES,
    obligation_retention_reason as _obligation_retention_reason,
)


REVIEW_KINDS = (
    "LEDGER",
    "TRANSACTION",
    "ASSET",
    "MARKET",
    "MEASUREMENT",
    "SENSOR",
    "CONTROLLER",
    "ACTUATOR",
    "PROTOCOL",
    "POLICY",
    "ROBOT",
    "FINBOT",
)

PEOPLE_OBJECT_IDS = (
    "vstd-actor",
    "vstd-collective",
    "vstd-human",
    "vstd-identity",
    "vstd-owner",
    "vstd-receipt",
    "vstd-role",
)

CLAIM_BOUNDARY = (
    "Exact-source Tier-0 applicability and declaration review for these seven "
    "original package objects only. Mechanism truth, Tier-1-plus conformance, "
    "real-world authenticity or authority, live effects, physical confinement, "
    "financial authority, full package coverage, release, and deployment remain "
    "unestablished."
)

_MIGRATION_REASON = (
    "Migration retains this applicability question. Static ownership alone "
    "cannot refute a {kind} role."
)


def _canonical_migration_question(kind: str) -> dict[str, Any]:
    """Return the sole unreviewed value permitted outside this catalog's scope."""
    return {
        "status": "UNRESOLVED",
        "reason": _MIGRATION_REASON.format(kind=kind),
        "evidence": [],
    }


def _has_complete_foreign_questions(
    classification: Any, registered_questions: set[str]
) -> bool:
    """Keep the 37-question denominator without claiming authority over 25 kinds.

    A question outside this catalog may already be decided by its own audited
    catalog (the original-kind reviews fill it before or after this stage), so it
    may carry any well-formed decision.  This stage only passes it through.
    """
    owned = set(REVIEW_KINDS)
    return (
        type(classification) is dict
        and set(classification) == registered_questions
        and all(
            _well_formed_question(classification[kind])
            for kind in registered_questions - owned
        )
    )


def _well_formed_question(cell: Any) -> bool:
    """Return whether a cell has the exact question shape, whatever its decision."""
    return (
        type(cell) is dict
        and set(cell) == {"status", "reason", "evidence"}
        and cell["status"] in {"UNRESOLVED", "APPLIES", "DOES_NOT_APPLY"}
        and type(cell["reason"]) is str
        and bool(cell["reason"].strip())
        and type(cell["evidence"]) is list
        and all(
            type(item) is dict
            and set(item) == {"path", "sha256"}
            and type(item["path"]) is str
            and type(item["sha256"]) is str
            for item in cell["evidence"]
        )
    )


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


# Mechanism words name a role's concrete code surface. They are checked against
# exact owned code (not prose), so a DOES_NOT_APPLY basis cannot survive a source
# that names the role. The list is a fail-closed trigger, not a semantic proof.
_MECHANISM_WORDS: dict[str, frozenset[str]] = {
    "LEDGER": frozenset({"ledger", "ledgers", "journal", "accounting", "balance", "balances", "reconcile", "reconciliation"}),
    "TRANSACTION": frozenset({"transaction", "transactions", "rollback", "atomicity", "settle", "settlement", "compensate", "compensation", "idempotent", "idempotency", "retry", "retries"}),
    "ASSET": frozenset({"asset", "assets", "custody", "redeem", "redemption", "redemptions", "issuance", "backing", "encumbrance", "encumbrances"}),
    "MARKET": frozenset({"market", "markets", "orderbook", "price", "prices", "trade", "trades", "trading", "bid", "bids", "ask", "asks"}),
    "MEASUREMENT": frozenset({"measurement", "measurements", "measured", "uncertainty", "calibration", "phenomenon", "phenomena"}),
    "SENSOR": frozenset({"sensor", "sensors", "sampling", "latency", "drift", "acquisition"}),
    "CONTROLLER": frozenset({"controller", "controllers", "feedback", "setpoint", "stability", "arbitration"}),
    "ACTUATOR": frozenset({"actuator", "actuators", "actuation", "actuate", "actuated", "interlock", "interlocks"}),
    "PROTOCOL": frozenset({"protocol", "protocols", "participant", "participants", "handshake", "consensus", "message", "messages"}),
    "POLICY": frozenset({"policy", "policies", "precedence", "exception", "exceptions", "enforce", "enforcement"}),
    "ROBOT": frozenset({"robot", "robots", "robotic", "embodied", "actuator", "actuators", "actuation"}),
    "FINBOT": frozenset({"financial", "finance", "money", "payment", "payments", "currency", "monetary", "wallet", "exposure", "exposures", "trading"}),
}
_TOKEN_LITERAL = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")


def _code_words(text: str) -> set[str]:
    """Return lowercase words from exact code names and single-token literals.

    Docstrings and prose literals are excluded; a claim boundary written in prose
    neither triggers nor clears a mechanism word.
    """
    tree = ast.parse(text)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and type(node.body[0].value.value) is str
    }
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, ast.arg):
            names.append(node.arg)
        elif isinstance(node, ast.alias):
            names.append(node.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
        elif (
            isinstance(node, ast.Constant)
            and type(node.value) is str
            and id(node) not in docstrings
            and _TOKEN_LITERAL.fullmatch(node.value) is not None
        ):
            names.append(node.value)
    words: set[str] = set()
    for name in names:
        spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
        words.update(word for word in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if word)
    return words


def _mechanism_words(root: Path, object_id: str, paths: tuple[str, ...]) -> set[str]:
    words: set[str] = set()
    for path in paths:
        try:
            words |= _code_words((root / path).read_text(encoding="utf-8"))
        except (SyntaxError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_SOURCE_UNPARSEABLE:"
                + object_id
                + ":"
                + path
            ) from exc
    return words


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    prefix: str
    implementation: str | None
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    refuted: tuple[str, ...]
    reasons: Mapping[str, str]
    declarations: Mapping[str, Mapping[str, str]]


_PATHS = {
    "vstd-human": (
        "src/verifier/domains/human.py",
        "src/verifier/domains/contracts/human_no_composition.py",
        "src/verifier/domains/contracts/human_population_declaration.py",
        "src/verifier/domains/contracts/human_template_irreversibility.py",
    ),
    "vstd-actor": (
        "src/verifier/domains/actor.py",
        "src/verifier/domains/contracts/actor_closure.py",
        "src/verifier/domains/contracts/actor_decision_record.py",
        "src/verifier/domains/contracts/actor_replay.py",
    ),
    "vstd-collective": (
        "src/verifier/domains/collective.py",
        "src/verifier/domains/contracts/collective_closure.py",
        "src/verifier/domains/contracts/collective_constraints.py",
        "src/verifier/domains/contracts/collective_lifecycle.py",
    ),
    "vstd-role": (
        "src/verifier/domains/role.py",
        "src/verifier/domains/contracts/role_closure.py",
        "src/verifier/domains/contracts/role_constraints.py",
        "src/verifier/domains/contracts/role_lifecycle.py",
    ),
    "vstd-identity": (
        "src/verifier/domains/identity.py",
        "src/verifier/domains/contracts/identity_lifecycle.py",
        "src/verifier/domains/contracts/identity_lifecycle_replay.py",
        "src/verifier/domains/contracts/identity_occupancy.py",
        "src/verifier/domains/contracts/identity_presentation.py",
        "src/verifier/domains/contracts/identity_scope.py",
    ),
    "vstd-owner": (
        "src/verifier/domains/owner.py",
        "src/verifier/domains/contracts/owner_eligibility.py",
        "src/verifier/domains/contracts/owner_forks.py",
        "src/verifier/domains/contracts/owner_replay.py",
    ),
    "vstd-receipt": (
        "src/verifier/domains/contracts/receipt_authenticity.py",
        "src/verifier/domains/contracts/receipt_chain.py",
        "src/verifier/domains/contracts/receipt_prerequisite_closure.py",
        "src/verifier/domains/contracts/receipt_statics.py",
        "src/verifier/domains/contracts/receipt_validation_replay.py",
    ),
}


def _requirements(kind: str) -> list[dict[str, Any]]:
    return [
        row
        for row in requirements_for(namespace_registry(), (kind,))
        if row["kind"] == kind
    ]


def _declarations(kind: str, fields: Mapping[str, str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    expected: set[str] = set()
    for obligation in _requirements(kind):
        names = tuple(obligation["declaration_fields"])
        expected.update(names)
        result[obligation["id"]] = {name: fields[name] for name in names}
    if set(fields) != expected:
        raise AssertionError(kind + " declaration fields differ from live registry")
    if any(not value.strip() for row in result.values() for value in row.values()):
        raise AssertionError(kind + " contains a blank declaration")
    return result


def _open_effect_declarations(
    kind: str, subject: str
) -> dict[str, dict[str, str]]:
    """Retain every live field without fabricating an unobserved mechanism value."""
    fields = {
        field
        for obligation in _requirements(kind)
        for field in obligation["declaration_fields"]
    }
    return _declarations(
        kind,
        {
            field: (
                f"{subject} retains {kind}.{field} as a Tier-0 obligation because "
                "the sole authored reasons.vstd selects conservative APPLIES while "
                "its owned closed-effect boundary is open. The concrete mechanism "
                "value and any external occurrence remain NOT_ESTABLISHED."
            )
            for field in sorted(fields)
        },
    )


def _merge(*groups: Mapping[str, Mapping[str, str]]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for group in groups:
        overlap = set(result).intersection(group)
        if overlap:
            raise AssertionError("duplicate obligation ids: " + ", ".join(sorted(overlap)))
        result.update({name: dict(fields) for name, fields in group.items()})
    return result


def _protocol(
    subject: str,
    *,
    participants: str,
    states: str,
    transitions: str,
    authority: str,
    ordering: str,
    compatibility: str,
    safety: str,
    liveness: str,
    recovery: str,
) -> dict[str, dict[str, str]]:
    return _declarations(
        "PROTOCOL",
        {
            "participants": participants,
            "roles": f"{subject} assigns bounded declarant, subject, supporting-record, verifier, and transition roles; those labels do not authenticate real participants.",
            "states": states,
            "transitions": transitions,
            "message_authority": authority,
            "ordering": ordering,
            "replay": f"{subject} replays exact retained bytes and commitments; replay establishes consistency only and never repeats or proves a live-world event.",
            "compatibility": compatibility,
            "failure_assumptions": f"{subject} assumes retained inputs may be absent, malformed, stale, contradictory, unauthenticated, incomplete, or beyond finite checking bounds.",
            "safety": safety,
            "liveness": liveness,
            "recovery": recovery,
        },
    )


def _policy(
    subject: str,
    *,
    scope: str,
    inputs: str,
    precedence: str,
    authority: str,
    exceptions: str,
    revisions: str,
    enforcement: str,
    evidence: str,
) -> dict[str, dict[str, str]]:
    return _declarations(
        "POLICY",
        {
            "scope": scope,
            "decision_inputs": inputs,
            "precedence": precedence,
            "defaults": f"{subject} fails closed to UNKNOWN or FAIL when necessary selected evidence, support, compatibility, or bounded checking capacity is absent; it never infers approval from silence.",
            "authority": authority,
            "exceptions": exceptions,
            "revisions": revisions,
            "activation": "The policy is activated only for one exact request, mechanism digest, trust-root selection, retained evidence coordinate, and finite limits; no ambient deployment is inferred.",
            "enforcement_points": enforcement,
            "decision_evidence": evidence,
            "bypass_handling": "Generic labels, declarations without selected support, stale bytes, foreign children, unregistered exceptions, and exhausted checks cannot be promoted to PASS.",
            "unavailable_behavior": f"{subject} preserves UNKNOWN for missing support or checking capacity and FAIL for retained contradictions; neither result authorizes downstream action.",
        },
    )


def _refutations(subject: str, *, physical: str, financial: str) -> dict[str, str]:
    return {
        "LEDGER": subject + " verifies externally supplied retained records but owns no authoritative append, account state, durable history, correction log, or global replay authority.",
        "TRANSACTION": subject + " computes and returns assessments or certificate bytes without committing a live state change or external effect with atomicity, finality, compensation, or retry semantics.",
        "ASSET": subject + " represents no quantity-bearing right with issuance, redemption, custody, encumbrance, backing, or supply reconciliation.",
        "MARKET": subject + " exposes no order lifecycle, participant market access, matching, price formation, allocation, manipulation control, or settlement.",
        "MEASUREMENT": subject + " does not itself declare a phenomenon observation with units, source, time, uncertainty, validity, missingness, and provenance semantics.",
        "SENSOR": subject + " acquires no live observation from a deployed source and provides no calibration, sampling, latency, drift, or sensor-fault mechanism.",
        "CONTROLLER": subject + " implements no feedback objective, command selection, stability envelope, arbitration, intervention, or controller failure behavior.",
        "ACTUATOR": subject + " exposes no command-to-effect target, response limit, feedback, interlock, or recovery surface and performs no live-world actuation.",
        "PROTOCOL": subject + " implements no participant state machine with transitions, ordering, replay, compatibility, safety, liveness, and recovery boundaries.",
        "POLICY": subject + " selects no scoped rule set, authority, precedence, exception, revision, enforcement point, or fail-closed decision behavior.",
        "ROBOT": physical,
        "FINBOT": financial,
    }


def _review(
    object_id: str,
    primary_kind: str,
    applicable_reasons: Mapping[str, str],
    declarations: Mapping[str, Mapping[str, str]],
    *,
    refuted: tuple[str, ...],
    physical: str,
    financial: str,
    refutation_overrides: Mapping[str, str] | None = None,
) -> _Review:
    prefix = object_id.removeprefix("vstd-")
    implementation = None if prefix == "receipt" else f"src/verifier/domains/{prefix}.py"
    reasons = _refutations(
        f"The {primary_kind} implementation and same-prefix contracts",
        physical=physical.format(primary=primary_kind),
        financial=financial.format(primary=primary_kind),
    )
    if refutation_overrides:
        reasons.update(refutation_overrides)
    reasons.update(applicable_reasons)
    return _Review(
        primary_kind=primary_kind,
        prefix=prefix,
        implementation=implementation,
        owned_paths=tuple(_PATHS[object_id]),
        applicable=tuple(sorted(applicable_reasons)),
        refuted=refuted,
        reasons=reasons,
        declarations={name: dict(fields) for name, fields in declarations.items()},
    )


_NO_PHYSICAL = (
    "The {primary} sources expose no AGENT-to-HARNESS-to-CONTROLLER-to-physical-"
    "ACTUATOR path and establish no external confinement. A later physical "
    "endpoint would separately require ROBOT consequences and evidence."
)
_NO_FINANCIAL = (
    "The {primary} sources give no agent live-money decision or transfer authority, "
    "name no payment or settlement rail, and enforce no financial exposure. A "
    "later real-money endpoint would separately require FINBOT."
)


def _basis(review: _Review, kind: str) -> str:
    if kind in review.applicable:
        return "APPLIES"
    if kind in review.refuted:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _obligation_reason(review: _Review, kind: str) -> str:
    return (
        review.reasons[kind]
        + " This exact-source Tier-0 declaration states the boundary; "
        "mechanism truth and Tier-1-plus fulfillment remain unestablished."
    )


_HUMAN_PROTOCOL = _protocol(
    "The HUMAN lifecycle and template checks",
    participants="Represented participants are the declared subject, evidence/witness records, assertion or template declarant, and verifier; none is authenticated as a living person by these checks.",
    states="Declared states include unenrolled, active, withdrawn, dead, template-enrolled, compromised, and revoked, plus arrangement states that must never manufacture HUMAN.",
    transitions="Enrollment, reverification, compromise, revocation, death, and permanent template-breach rules define the admitted retained transitions.",
    authority="Record digests, optional admitted witness keys, trust-root labels, and declared instruments bind selected statements but do not establish personhood, consent, or issuer authority.",
    ordering="Event positions are contiguous or strictly increasing as specified, declared time cannot move backward, enrollment begins validity, and terminal/template-breach rules constrain later events.",
    compatibility="Installed semantic, request, policy, evidence, and certificate versions plus exact HUMAN typed records and finite vocabularies define compatibility.",
    safety="No-composition rules reject manufactured HUMAN outputs, event replay rejects invalid lifecycle changes, and permanent template breach cannot be silently restored.",
    liveness="No enrollment, reverification, revocation, death, witness, or availability progress is guaranteed; missing support remains UNKNOWN.",
    recovery="Recovery is exact certificate/evidence replay. Historical events remain retained, but no live identity, biometric template, or real-world state is restored.",
)
_HUMAN_POLICY = _policy(
    "The HUMAN checkers",
    scope="Policy covers exact declared evidence classes, operating-point/population fields, unasserted identity attributes, validity/event vocabulary, no-composition, and permanent template-breach rules.",
    inputs="Inputs are typed HUMAN records, selected collections, retained evidence/arrangement/event bytes, mechanism pins, trust-root labels, finite limits, and exact request commitments.",
    precedence="Typed-kind and commitment contradictions fail before missing support; global uniqueness claims are refused, required unasserted attributes remain excluded, and permanent compromise forbids restoration.",
    authority="The caller selects policy, trust-root labels, evidence, population, and clocks; neither labels nor signatures establish voluntary consent, personhood, witness independence, or institutional authority.",
    exceptions="Only exact admitted evidence classes, vocabulary, finite bounds, and declared exclusions are accepted; no label, arrangement strength, or restorative event overrides HUMAN boundaries.",
    revisions="Changed mechanism bytes, policy/request version, trust roots, HUMAN record, population, operating point, event log, or collection produces a different digest-bound selection.",
    enforcement="evaluate and native certificate recheck paths reject malformed or contradictory declarations and keep unavailable personhood/liveness/closure claims at UNKNOWN.",
    evidence="Certificates bind exact requests, policies, mechanism/proposition digests, retained payload references, bounded evaluation, and explicit NOT_ESTABLISHED exclusions.",
)
_HUMAN_RETENTION_KINDS = tuple(
    kind
    for kind in _AGENCY_OBLIGATION_RETENTION_APPLIES["vstd-human"]
    if kind not in {"PROTOCOL", "POLICY"}
)
_HUMAN_RETENTION_REASONS = {
    kind: _obligation_retention_reason("vstd-human", kind)
    for kind in _HUMAN_RETENTION_KINDS
}
_HUMAN_RETENTION_DECLARATIONS = _merge(
    *(
        _open_effect_declarations(kind, "The HUMAN verifier")
        for kind in _HUMAN_RETENTION_KINDS
    )
)
_HUMAN = _review(
    "vstd-human",
    "HUMAN",
    {
        **_HUMAN_RETENTION_REASONS,
        "PROTOCOL": "The sources implement retained assertion and template lifecycle state machines with enrollment, compromise, revocation, death, ordering, replay, and recovery boundaries.",
        "POLICY": "They enforce exact evidence-class, population, unasserted-attribute, no-composition, template-irreversibility, trust-root, and fail-closed admission rules.",
    },
    _merge(_HUMAN_RETENTION_DECLARATIONS, _HUMAN_PROTOCOL, _HUMAN_POLICY),
    refuted=(),
    physical=_NO_PHYSICAL,
    financial=_NO_FINANCIAL,
    refutation_overrides={
        "MEASUREMENT": "The HUMAN sources validate retained declared population counts, operating-point rates, evidence classes, and lifecycle records; they do not acquire or represent a phenomenon observation with units, time, uncertainty, missingness, and provenance.",
        "SENSOR": "The HUMAN sources consume caller-supplied retained declarations and evidence references only; they perform no live biometric or person observation and expose no calibration, sampling, drift, latency, or sensor-fault mechanism.",
    },
)


_ACTOR_PROTOCOL = _protocol(
    "The ACTOR decision and accountability checks",
    participants="Participants represented are the accountable actor, delegates, successors, instruments, independent witness-key holders, and verifier; actor and witness identities remain declared.",
    states="States include active actor/key/decision-class sets, live or revoked delegations, membership, rotated keys, dissolved actors, succession pairs, and retained decision attribution/closure.",
    transitions="Delegation, revocation, key rotation, membership entry/leave, dissolution, succession, decision attribution, and witness attestation define retained transitions.",
    authority="Admitted Ed25519 witness keys can bind exact decision statements and control-surface keys delimit declared actor control; neither proves real-world identity or independent custody.",
    ordering="Event and decision positions are contiguous or strictly increasing, delegation intervals are ordered, succession ending/beginning pair at one position, and earlier decision records cannot be rewritten.",
    compatibility="Exact ACTOR typed records, control/instrument boundaries, decision-class vocabularies, semantic versions, canonical bytes, and installed mechanism digests define compatibility.",
    safety="The checks reject self-delegation, out-of-class authority, instrument/actor overlap, conflicting succession, unattributed decisions, and witness keys within the actor's declared control surface.",
    liveness="No delegate, witness, successor, decision, or accountability response is guaranteed to appear; missing independent support remains UNKNOWN.",
    recovery="Recovery is deterministic replay of the selected base state, ordered events, retained decisions/attributions, and exact certificates; it performs no live authority restoration.",
)
_ACTOR_POLICY = _policy(
    "The ACTOR checkers",
    scope="Policy covers declared control surfaces, instrument separation, admitted decision classes/spaces, delegation subsets and intervals, witness-key admission, succession, dissolution, and closure inventory.",
    inputs="Inputs are the exact ACTOR record/collection, control keys, decision and event inventories, attributions, independent witness records/keys, mechanism pins, trust roots, and finite limits.",
    precedence="Typed and commitment contradictions fail first; an actor cannot delegate to itself or beyond its classes, controlled/self witnesses do not establish accountability, and every selected decision must be attributed.",
    authority="The checker admits configured witness keys and caller-selected ACTOR records; signatures prove key use only, not actor personhood, witness independence, legal authority, or consent.",
    exceptions="Only exact declared delegation subsets, intervals, admitted spaces, event kinds, and independently admitted witness keys are considered; no implicit authority expansion is allowed.",
    revisions="Changed control surface, decision class, admitted space, key set, event/decision record, policy, trust root, or mechanism bytes is a new digest-bound decision coordinate.",
    enforcement="Actor evaluate, closure, retention, replay, and recheck paths refuse invalid delegation/attribution/order and preserve unavailable independence or real-world completeness as UNKNOWN.",
    evidence="Results bind exact ACTOR/collection bytes, selected decision/event/attribution inventories, witness signatures where available, requests, policies, and explicit NOT_ESTABLISHED boundaries.",
)
_ACTOR_ACTUATOR = _declarations(
    "ACTUATOR",
    {
        "commands": "No physical command is established. ACTUATOR remains applicable as a verification obligation because the owned actor graph invokes imported cryptographic helpers and caller-supplied budget/store interfaces whose complete effect closure is not established.",
        "targets": "UNKNOWN beyond the retained actor, decision, witness-key, certificate and caller-supplied interface surfaces; no physical target or occurrence is asserted.",
        "effect_domains": "The directly observed domain is retained decision and certificate verification. Imported and injected call effects remain open, so downstream actuation cannot be refuted from this finite owned census.",
        "authority": "The caller selects records, keys, stores and budgets. Signature verification proves key use only and grants no physical or external-effect authority.",
        "units_and_frames": "Commands and responses are framed as typed records, canonical bytes, digests, event positions, finite counts and signatures; no physical unit or coordinate frame is established.",
        "response": "Observed responses are PASS, FAIL, UNKNOWN, certificate bytes and retained records. They do not prove or disprove an external effect through an unresolved imported or injected target.",
        "limits": "Finite item, operation, certificate and replay limits bound the local checks; they do not close imported dependency or caller-supplied callback effects.",
        "saturation": "Bound exhaustion yields unavailable or refusal states. No physical saturation behavior is represented or inferred.",
        "effect_feedback": "Only retained checker outcomes and exact replay evidence are observed; external-effect feedback is NOT_ESTABLISHED.",
        "interlocks": "Schema, digest, ordering, witness-key, control-surface and finite-budget checks interlock retained-result admission, not a physical safe state.",
        "failure_states": "Malformed, contradictory, stale, unsupported, over-limit, signature-failing or open-effect inputs remain FAIL or UNKNOWN; external target state remains UNKNOWN.",
        "recovery": "A corrected immutable input may be checked by a fresh bounded replay. No external rollback, compensation or actuator safe-state recovery is claimed.",
    },
)
_ACTOR_OPEN_EFFECT_KINDS = (
    "ASSET",
    "CONTROLLER",
    "FINBOT",
    "LEDGER",
    "MARKET",
    "MEASUREMENT",
    "ROBOT",
    "SENSOR",
    "TRANSACTION",
)
_ACTOR_OPEN_EFFECT_REASONS = {
    kind: (
        "The owned actor graph has unresolved imported and caller-supplied call "
        f"targets. {kind} is conservatively applicable as an obligation until that "
        "effect boundary is closed; this records no external mechanism, authority, "
        "result, or occurrence."
    )
    for kind in _ACTOR_OPEN_EFFECT_KINDS
}
_ACTOR_OPEN_EFFECT_DECLARATIONS = _merge(*(
    _open_effect_declarations(kind, "The ACTOR verifier")
    for kind in _ACTOR_OPEN_EFFECT_KINDS
))
_ACTOR = _review(
    "vstd-actor",
    "ACTOR",
    {
        **_ACTOR_OPEN_EFFECT_REASONS,
        "ACTUATOR": "The owned actor graph has unresolved imported and caller-supplied call targets. ACTUATOR is conservatively applicable as an obligation until that effect boundary is closed; this records no physical command, target, authority, response, or occurrence.",
        "PROTOCOL": "ACTOR sources define delegation, revocation, rotation, membership, dissolution, succession, decision-retention, attribution, and witness state/ordering replay.",
        "POLICY": "They enforce control-surface separation, decision classes, delegation scope, witness independence/key admission, attribution completeness, and fail-closed closure rules.",
    },
    _merge(
        _ACTOR_OPEN_EFFECT_DECLARATIONS,
        _ACTOR_ACTUATOR,
        _ACTOR_PROTOCOL,
        _ACTOR_POLICY,
    ),
    refuted=(),
    physical=_NO_PHYSICAL,
    financial=(
        "ACTOR decision classes are generic declarations. These sources bind no "
        "AGENT/HARNESS with live-money authority, asset parties, settlement route, or "
        "exposure enforcement; a financial agent would separately require FINBOT."
    ),
)

# Open imported/caller-supplied targets retain these obligations but do not
# establish that the ACTOR verifier itself instantiates the selected roles.
OBLIGATION_RETENTION_APPLIES: dict[str, tuple[str, ...]] = {
    "vstd-actor": ("ACTUATOR", *_ACTOR_OPEN_EFFECT_KINDS),
}


def obligation_retention_reason(object_id: str, kind: str) -> str:
    """Return one exact people-review demand-only reason."""

    if kind not in OBLIGATION_RETENTION_APPLIES.get(object_id, ()):
        raise ValueError("PEOPLE_REVIEW_OBLIGATION_RETENTION_UNDECLARED")
    return _REVIEWS[object_id].reasons[kind]


_COLLECTIVE_PROTOCOL = _protocol(
    "The COLLECTIVE membership and point-decision checks",
    participants="Participants represented are one collective, its selected ROLE members, role bearers/actors through child records, countersign roles, charter declarant, and verifier.",
    states="States include fixed or changing ROLE membership, admitted/departed members, frozen charter/quorum coordinates, role decisions, and assembled collective point decisions.",
    transitions="ROLE admission and departure move between exact endpoint collections; retained role decisions assemble a collective decision only when quorum, required roles, and countersign edges are satisfied.",
    authority="Typed ROLE children, retained charter/quorum commitments, and selected child certificates bind declarations; they do not establish live membership, natural-person separation, or legal collective authority.",
    ordering="Membership events have unique contiguous positions and declared chronology; role/collective decision positions are complete, unique, and constrained to the selected point/period.",
    compatibility="Exact COLLECTIVE/ROLE namespace records, selected protocol and charter versions, child request/policy/certificate bytes, mechanism pins, and finite limits define compatibility.",
    safety="The checks reject undeclared roles, duplicate/reused components, infeasible quorum, missing required/countersign roles, changed frozen terms, and transitions that modify unrelated records.",
    liveness="No member admission, departure, quorum assembly, countersignature, or collective decision progress is guaranteed; incomplete support remains UNKNOWN.",
    recovery="Recovery replays exact endpoint certificates, role decisions, and collective assemblies from retained bytes; it does not restore live membership or execute a collective decision.",
)
_COLLECTIVE_POLICY = _policy(
    "The COLLECTIVE checkers",
    scope="Policy covers selected membership, role graph, charter, quorum, assembly requirements, required/countersign roles, separation flags, decision classes, and admission/departure rules.",
    inputs="Inputs are exact COLLECTIVE and ROLE records, membership/charter/quorum commitments, endpoint certificates, decision inventories, assembly protocol, mechanism/trust selections, and bounds.",
    precedence="Membership and frozen charter/quorum consistency precede assembly; distinct selected members must meet feasible quorum and every decision-class requirement/countersign edge.",
    authority="The caller selects charter, membership, quorum, roles, and child evidence; no source establishes legal existence, actual role occupancy, consent, or authority of the collective.",
    exceptions="Only explicit selected separation flags, required roles, countersign edges, and admitted lifecycle actions are accepted; undeclared components cannot inflate quorum.",
    revisions="Any changed member, charter, quorum, decision class, assembly rule, lifecycle endpoint, mechanism, or trust selection requires a new bound policy coordinate.",
    enforcement="Graph, decision, static-constraint, lifecycle, and closure evaluators reject inconsistent membership/assembly and keep absent real-world membership or actual decision execution unestablished.",
    evidence="Certificates bind exact selected collections, membership/charter/quorum bytes, child replays, role and collective decision inventories, and explicit excluded claims.",
)
_COLLECTIVE_RETENTION_KINDS = tuple(
    kind
    for kind in _AGENCY_OBLIGATION_RETENTION_APPLIES["vstd-collective"]
    if kind not in {"PROTOCOL", "POLICY"}
)
_COLLECTIVE_RETENTION_REASONS = {
    kind: _obligation_retention_reason("vstd-collective", kind)
    for kind in _COLLECTIVE_RETENTION_KINDS
}
_COLLECTIVE_RETENTION_DECLARATIONS = _merge(
    *(
        _open_effect_declarations(kind, "The COLLECTIVE verifier")
        for kind in _COLLECTIVE_RETENTION_KINDS
    )
)
_COLLECTIVE_LEDGER = _declarations(
    "LEDGER",
    {
        "history": "collective_closure.py replays the exact retained ROLE decision inventory as one finite declared history; it does not establish a live or externally authoritative ledger.",
        "state": "State is the retained set of decision identifiers, instants, decision classes, ROLE references and selected point or period; no account, asset or external system state is asserted.",
        "ordering": "Decision identifiers are unique, instants are nondecreasing, and every instant must lie inside the selected point or period before the declared ledger is accepted.",
        "authority": "The caller selects the retained ROLE inventory and COLLECTIVE evidence. Successful replay establishes internal consistency only, not legal, financial, operational or external ledger authority.",
        "units": "The replay uses finite decision records, identifiers, positions and declared instants. It defines no monetary unit, quantity scale or independently calibrated clock.",
        "balance_rules": "No debit, credit, conservation or account-balance equation is present; completeness and reference matching are the only retained-history invariants checked here.",
        "rounding": "No quantity arithmetic or rounding is performed. Exact retained identifiers, integer positions and declared instants are compared without an inferred tolerance.",
        "sources_and_sinks": "The selected ROLE decision inventory is the sole bounded source of ledger entries. The verifier neither creates decisions nor observes an external source or sink.",
        "corrections": "A changed decision record requires a newly selected evidence coordinate and complete replay; the verifier does not mutate or silently amend retained history.",
        "replay": "Replay rebuilds the declared ledger from exact retained ROLE decisions and rejects duplicate identifiers, decreasing instants and out-of-period entries.",
        "reconciliation": "COLLECTIVE component references are matched against the complete replayed ROLE inventory; no external ledger, account or real-world occurrence is reconciled.",
        "recovery": "Recovery consists of supplying a corrected complete retained inventory and rerunning the bounded closure checks. No live rollback, compensation or external restoration is performed.",
    },
)
_COLLECTIVE = _review(
    "vstd-collective",
    "COLLECTIVE",
    {
        **_COLLECTIVE_RETENTION_REASONS,
        "LEDGER": "collective_closure.py replays a complete finite declared ledger of retained ROLE decision identifiers, instants and references, rejecting duplicates, decreasing order and out-of-period entries without claiming external authority.",
        "PROTOCOL": "COLLECTIVE sources implement finite ROLE admission/departure and point-decision assembly protocols with explicit membership, quorum, countersign, ordering, replay, and recovery boundaries.",
        "POLICY": "They enforce charter, membership, quorum, required-role, countersign, separation, assembly, and fail-closed decision rules.",
    },
    _merge(
        _COLLECTIVE_RETENTION_DECLARATIONS,
        _COLLECTIVE_LEDGER,
        _COLLECTIVE_PROTOCOL,
        _COLLECTIVE_POLICY,
    ),
    refuted=(),
    physical=_NO_PHYSICAL,
    financial=_NO_FINANCIAL,
)


_ROLE_PROTOCOL = _protocol(
    "The ROLE lifecycle and occupancy checks",
    participants="Participants represented are one ROLE class/seat, HUMAN or BOT bearers, responsible ACTOR/HUMAN roots through selected identity relations, a COLLECTIVE, and verifier.",
    states="States include selected lifecycle state, empty or bounded occupied bearer set, taking/leaving/handover endpoints, permissions/scopes, and retained point decisions.",
    transitions="Configured lifecycle state pairs govern permitted permission/scope changes and taking/leaving; take, leave, paired handover, and checkpoint events reproduce exact endpoint occupancy.",
    authority="Selected IDENTITY/ACTOR/HUMAN relationships and ROLE permissions bind declared authority tokens; live bearer authenticity, occupancy, consent, and institutional authority remain unestablished.",
    ordering="Occupancy and decision positions are contiguous, clocks and endpoints follow the selected order, handover is paired, and simultaneous bearer limits/exclusive groups constrain states.",
    compatibility="Exact ROLE/COLLECTIVE/IDENTITY/ACTOR typed records, lifecycle protocol/matrix versions, child request/policy/certificate bytes, and finite bounds define compatibility.",
    safety="The checks reject inadmissible bearer classes, over-capacity occupancy, illegal state transitions, out-of-scope permissions, duplicate actor-role cells, and mutually exclusive shared occupancy.",
    liveness="No bearer takes/leaves a seat and no decision occurs merely because a retained protocol is valid; missing endpoint or identity support remains UNKNOWN.",
    recovery="Recovery is exact endpoint, occupancy-event, identity-relation, and decision replay; it cannot restore a live bearer or real authority.",
)
_ROLE_POLICY = _policy(
    "The ROLE checkers",
    scope="Policy covers ROLE class facets, admitted bearer classes, bearer limits, lifecycle states/transitions, permission/scope matrices, occupancy intervals, exclusive sets, and decision authority tokens.",
    inputs="Inputs are exact ROLE and related typed records, selected matrices/protocols, endpoint certificates, occupancy/decision inventories, trust/mechanism pins, and finite limits.",
    precedence="Typed relation and static constraints precede lifecycle/closure; bearer admission, scope/permission ceilings, lifecycle transition rules, limits, and mutual exclusion must all hold.",
    authority="The caller selects policies and child evidence; replayed relationships bind declared tokens only and do not establish live occupancy, personhood, role legitimacy, or consent.",
    exceptions="Only explicitly admitted bearer classes, transition pairs, permission/scope changes, occupancy intervals, and selected exclusion groups are recognized.",
    revisions="Changed ROLE facets, bearer limits, lifecycle protocol, matrix, permissions, scopes, endpoints, mechanism, or trust roots require a distinct bound evaluation.",
    enforcement="ROLE facet, constraint, lifecycle, and closure paths reject invalid occupancy/authority declarations and keep actual occurrence, live occupancy, and real-world completeness NOT_ESTABLISHED.",
    evidence="Results bind exact ROLE/collection bytes, selected matrices/protocols, child replays, timed occupancy and decision inventories, requests, policies, and exclusions.",
)
_ROLE = _review(
    "vstd-role",
    "ROLE",
    {
        "PROTOCOL": "ROLE sources implement finite lifecycle, take/leave/handover occupancy, endpoint, and point-decision replay with explicit states, order, safety, and recovery.",
        "POLICY": "They enforce bearer-class, simultaneous-limit, permission, scope, lifecycle-transition, exclusivity, and decision-authority rules.",
    },
    _merge(_ROLE_PROTOCOL, _ROLE_POLICY),
    refuted=("LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "ROBOT", "FINBOT"),
    physical=_NO_PHYSICAL,
    financial=_NO_FINANCIAL,
)


_IDENTITY_PROTOCOL = _protocol(
    "The IDENTITY occupancy, lifecycle, and presentation checks",
    participants="Participants represented are one HUMAN or BOT bearer, one ROLE seat, declared issuers/authorities, presentation verifiers, a selected SIM for BOT occupancy, and the checker; their real identities and authority remain unestablished.",
    states="States include enrolled, active, renewed, revoked, expired, terminated, compromised, and successor states for one immutable bearer-to-ROLE binding, plus retained presentations.",
    transitions="Enrollment, renewal, revocation, expiry, termination, compromise, successor enrollment, and presentation association are the finite retained transitions; HUMAN and BOT scope restrictions remain distinct.",
    authority="Selected authority evidence references, issuer labels, admitted keys, child certificates, and presentation signatures bind retained statements only; they do not establish issuer custody, personhood, consent, or external role authority.",
    ordering="Event positions are contiguous, commitments form the selected chain, time is nondecreasing, enrollment begins the lifecycle, terminal events are prospective, and presentations bind eligible prior events under the declared clock.",
    compatibility="Exact IDENTITY/HUMAN/BOT/ROLE/SIM records, lifecycle and presentation schema versions, declared algorithms, trust-root selections, mechanism digests, and finite bounds define compatibility.",
    safety="The checks reject bare AGENT bearers, HUMAN simulation scope, cross-bearer or cross-role substitution, invalid lifecycle order, post-terminal renewal/presentation, and inconsistent scope or occupancy.",
    liveness="No enrollment, renewal, revocation, termination, presentation, issuer response, or live eligibility progress is guaranteed; missing selected support remains UNKNOWN.",
    recovery="Recovery is deterministic replay of exact retained binding, event, presentation, child-certificate, and commitment bytes. It restores no live identity, role occupancy, or authority.",
)
_IDENTITY_POLICY = _policy(
    "The IDENTITY checkers",
    scope="Policy covers bearer class, ROLE binding, occupancy interval, assurance and disclosure, attribute scope, HUMAN/BOT and SIM restrictions, lifecycle vocabulary, presentation prerequisites, and finite replay limits.",
    inputs="Inputs are exact IDENTITY and related typed records, retained binding/event/presentation inventories, selected child certificates, declared issuer/key/trust information, policy/mechanism pins, clocks, and finite limits.",
    precedence="Typed bearer/ROLE/scope contradictions fail before unavailable support; lifecycle order and terminal-state rules precede presentation admission, and no generic label can substitute for selected child replay.",
    authority="The caller selects issuer/trust labels, policy, clocks, child evidence, and retained records; signature verification demonstrates key use only, not issuer authenticity, legal authority, consent, or current occupancy.",
    exceptions="Only exact admitted bearer classes, lifecycle events, presentation algorithms, scope relations, successor rules, and finite vocabularies are recognized; no implicit transfer or privilege widening is accepted.",
    revisions="Changed bearer, ROLE, scope, assurance, issuer/key, lifecycle or presentation bytes, child certificate, trust roots, clock, policy, or mechanism creates a distinct digest-bound coordinate.",
    enforcement="Occupancy, scope, lifecycle, presentation, and certificate recheck paths reject malformed or contradictory retained relations. The exit probe appends only to an ephemeral local event copy and reports actual enforcement NOT_ESTABLISHED.",
    evidence="Results bind exact selected records, commitments, event and presentation inventories, signatures/children where selected, requests, policies, finite bounds, and explicit NOT_ESTABLISHED exclusions.",
)
_IDENTITY = _review(
    "vstd-identity",
    "IDENTITY",
    {
        "PROTOCOL": "IDENTITY sources implement finite bearer-to-ROLE occupancy, lifecycle, successor, presentation, ordering, signature-check, and retained replay state machines.",
        "POLICY": "They enforce bearer-class, ROLE/scope, assurance/disclosure, HUMAN/BOT/SIM separation, lifecycle, presentation, trust-selection, and fail-closed admission rules.",
    },
    _merge(_IDENTITY_PROTOCOL, _IDENTITY_POLICY),
    # CONTROLLER is UNRESOLVED: identity_presentation.py names a controller_id
    # binding and a terminal controller whose installation the sources report as
    # missing, so the role is neither refuted nor established.
    refuted=("LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR", "ACTUATOR", "ROBOT", "FINBOT"),
    physical=_NO_PHYSICAL,
    financial=_NO_FINANCIAL,
    refutation_overrides={
        "ACTUATOR": "The exit probe only validates a signature and appends one event to an ephemeral local list for replay, explicitly leaving actual enforcement NOT_ESTABLISHED; no command-to-effect target is invoked.",
    },
)


_OWNER_ASSET = _declarations(
    "ASSET",
    {
        "identity": "The selected artifact_id and exact OWNER subject/record identify one declared holding of artifact rights and duties; this is a repository record, not proof of legal title or the external artifact's existence.",
        "rights": "Declared capability, consequence, and duty limbs identify the bounded rights and obligations attributed to the OWNER; labels and retained instruments do not grant real authority or prove enforceability.",
        "units": "Units are discrete named capability/consequence/duty limbs, ownership intervals, delegates, instruments, and fork coordinates, never currency, fungible quantity, or physical inventory.",
        "precision": "Identity is exact text/digest equality, positions and interval endpoints are exact integers, and limb inventories are finite sorted sets; no valuation, fractional title, or measurement precision is asserted.",
        "issuance_authority": "The selected genesis OWNER/instrument and replay policy declare who may originate or change the holding, but legal issuer authority, instrument custody, consent, and enforceability remain unestablished.",
        "supply_changes": "Transfer, delegation, revocation, freeze, seal, thaw, succession, and fork events change the retained rights/duties state; they do not create or destroy an external asset or monetary supply.",
        "redemption": "No cash, token, commodity, service, or external claim redemption is implemented. Termination or transfer only changes the retained OWNER relation under the declared protocol.",
        "backing_claims": "Artifact, instrument, and consequence references are declared support coordinates only. Existence, custody, legal title, economic backing, liens, and real-world control remain NOT_ESTABLISHED.",
        "custody": "The sources retain OWNER, artifact, instrument, delegate, and event references but do not observe possession, key custody, physical custody, beneficial ownership, or third-party custody.",
        "control": "Capability limbs and delegates delimit declared control claims; replay consistency does not prove that any command, artifact, account, or institution will honor them.",
        "encumbrances": "Duties, consequence limbs, revocations, freezes, seals, terms, and forks are checked as declared constraints; external liens, competing claims, security interests, and undisclosed encumbrances remain unestablished.",
        "reconciliation": "Exact base/end states, ordered events, instruments, and fork evidence are replayed for finite consistency. No authoritative registry, counterparty confirmation, accounting ledger, or external settlement is reconciled.",
    },
)
_OWNER_PROTOCOL = _protocol(
    "The OWNER holding and lifecycle checks",
    participants="Participants represented are an OWNER subject, artifact, declared issuers/instruments, delegates, successor owners, fork claimants, and verifier; legal identity, consent, and authority remain declared.",
    states="States include active, frozen, sealed, thawed, transferred, delegated, revoked, expired/terminated, succeeded, and forked holdings with bounded capability, consequence, and duty limbs.",
    transitions="Freeze, seal, thaw, transfer, delegation, revocation, succession, term-end, and fork evidence define finite retained changes to the OWNER relation.",
    authority="Selected instruments, issuer labels, signatures or evidence references, and child records bind declared transition authority; they do not prove legal title, key custody, consent, or external enforceability.",
    ordering="Lifecycle events use exact unique positions and time/interval constraints, transfer/succession must preserve the declared relation, and fork comparison binds a common selected base.",
    compatibility="Exact OWNER/artifact/instrument schemas, rights/duties vocabularies, lifecycle and fork versions, policy/mechanism pins, canonical bytes, and finite limits define compatibility.",
    safety="The checks reject ineligible hardware holdings, rights/duties outside declared limbs, invalid transfer/delegation/revocation order, incompatible instruments, and contradictory fork histories.",
    liveness="No owner, delegate, issuer, registry, court, custodian, or artifact is guaranteed to respond or honor the relation; unavailable external support remains UNKNOWN.",
    recovery="Recovery replays exact retained base state, events, instruments, endpoints, and forks. It cannot restore possession, legal title, authority, or an external artifact.",
)
_OWNER_POLICY = _policy(
    "The OWNER checkers",
    scope="Policy covers artifact identity, capability/consequence/duty limbs, ownership eligibility, instruments, delegation/transfer/revocation, freeze/seal/thaw, term and succession, replay, and forks.",
    inputs="Inputs are exact OWNER and artifact records, selected instruments, lifecycle/fork inventories, base/end states, eligibility evidence, mechanism/trust pins, clocks, and finite limits.",
    precedence="Typed identity and selected-base contradictions fail first; eligibility and instrument constraints precede lifecycle changes, and no event may widen rights or erase duties outside the declared limbs.",
    authority="The caller selects holdings, instruments, issuer/trust labels, evidence, and policies; these sources do not establish legal ownership, jurisdiction, consent, issuer authority, or external registry precedence.",
    exceptions="Only explicit lifecycle kinds, admitted instruments, bounded delegates, term conditions, hardware eligibility predicates, and selected fork relations are recognized; no implied waiver or authority is accepted.",
    revisions="Changed OWNER/artifact bytes, rights/duties, instrument, delegate, event/fork history, clock, trust root, policy, or mechanism creates a different digest-bound decision.",
    enforcement="Eligibility, holding replay, fork, and certificate recheck paths reject malformed or contradictory retained ownership relations while leaving possession, title, liens, custody, and external execution unestablished.",
    evidence="Results bind exact selected records, instruments, histories, endpoint/fork commitments, requests, policies, child evidence where selected, and explicit external-authority exclusions.",
)
_OWNER = _review(
    "vstd-owner",
    "OWNER",
    {
        "ASSET": "OWNER sources explicitly represent one artifact's bounded rights, duties, control limbs, instruments, custody claims, transfer/delegation/revocation history, terms, and forks, so ASSET questions cannot be escaped even though external title and backing are unestablished.",
        "PROTOCOL": "They implement finite holding lifecycle, delegation, transfer, revocation, succession, eligibility, replay, and fork protocols with explicit states, order, failures, and recovery boundaries.",
        "POLICY": "They enforce eligibility, instruments, capability/consequence/duty limbs, delegates, terms, lifecycle transitions, forks, and fail-closed authority boundaries.",
    },
    _merge(_OWNER_ASSET, _OWNER_PROTOCOL, _OWNER_POLICY),
    refuted=("LEDGER", "TRANSACTION", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "ROBOT", "FINBOT"),
    physical=_NO_PHYSICAL,
    financial=(
        "OWNER represents nonmonetary artifact and hardware holding claims, not an "
        "AGENT/HARNESS authorized to make live-money decisions or transfers. No "
        "payment, trading, custody, settlement, or exposure endpoint is invoked; a "
        "later real-money endpoint would separately require FINBOT."
    ),
    refutation_overrides={
        "TRANSACTION": "OWNER replays declared transfer, delegation, revocation, and fork records but neither commits those events to an authoritative external registry nor performs an atomic live effect, settlement, compensation, or retry.",
        "MARKET": "OWNER asset semantics cover a declared artifact holding only; there is no order lifecycle, participant market access, matching, price formation, allocation, manipulation control, or settlement.",
    },
)


_RECEIPT_PROTOCOL = _protocol(
    "The RECEIPT statics, replay, chain, authenticity, and closure checks",
    participants="Participants represented are one receipt subject, retained issuer/key labels, prerequisite receipt subjects, an audit producer, trust-root selector, and verifier; their real identity and authority remain unestablished.",
    states="States include canonical or malformed receipt bytes, audit replay PASS/FAIL/UNKNOWN, prerequisite cone closure, chain genesis/tip continuity, signature-valid/invalid, and unsupported or unavailable evidence.",
    transitions="The checks decode canonical statics, replay one retained audit, close selected prerequisites, advance a bounded hash chain, and validate an admitted issuer-key signature without generating or publishing a receipt.",
    authority="Externally selected issuer ids, admitted public keys, trust-root labels, receipt signatures, and child certificates bind exact retained bytes only; key custody, issuer authenticity, governance, and authorization remain unestablished.",
    ordering="Prerequisite edges must form the selected acyclic cone, receipt sequences are contiguous from the selected genesis, previous digests reach the exact tip, and audit replay binds one exact retained coordinate.",
    compatibility="VSTD-1 receipt models, canonical JSON/base64, certificate/request/policy schema versions, admitted signature algorithms, installed trusted-computing-base digest, mechanism pins, and finite bounds define compatibility.",
    safety="The checks reject noncanonical bytes, digest substitution, prerequisite cycles or omissions, chain discontinuity, foreign children, signature mismatch, and replay disagreement within the selected bounds.",
    liveness="No receipt generation, issuer response, revocation publication, ledger registration, prerequisite availability, chain extension, or target rerun is guaranteed; unavailable evidence remains UNKNOWN.",
    recovery="Recovery rechecks exact retained receipt, audit, child-certificate, chain, and signature bytes. It does not regenerate an event, establish claim truth, reverse an action, or restore issuer authority.",
)
_RECEIPT_POLICY = _policy(
    "The RECEIPT checkers",
    scope="Policy covers canonical VSTD-1 statics, selected audit replay, prerequisite closure, finite hash-chain continuity, admitted issuer-key signature checks, trust roots, and bounded evidence/certificate sizes.",
    inputs="Inputs are exact RECEIPT records and bytes, retained independent-audit fields, selected child certificates, prerequisite graph, chain anchors/items, issuer/key/signature selections, mechanism pins, and finite limits.",
    precedence="Canonical statics and digest commitments precede dependent replay; prerequisite and chain contradictions fail, signature validity cannot substitute for claim truth, and unavailable capacity or authority remains UNKNOWN.",
    authority="The caller selects receipt bytes, issuer/key and trust-root labels, prerequisite children, chain anchors, and policy. Cryptographic validity proves use of an admitted key only, not authentic issuer identity, custody, governance, or authorization.",
    exceptions="Only exact admitted schema versions, algorithms, trust-root selections, bounded child/cone/chain inventories, and canonical encodings are recognized; no label or successful replay promotes excluded claims.",
    revisions="Changed receipt/audit bytes, prerequisite graph, chain anchor/tip, issuer/key/signature, installed checker TCB, trust roots, policy, or mechanism creates a distinct digest-bound decision.",
    enforcement="Statics, validation replay, prerequisite closure, chain, authenticity, build, and native recheck paths reject malformed or contradictory retained evidence and preserve explicit NOT_ESTABLISHED fields.",
    evidence="Certificates bind exact selected records/bytes, request and policy digests, mechanism/TCB coordinates, retained children, chain/signature inputs, bounded outcomes, and exclusions.",
)
_RECEIPT = _review(
    "vstd-receipt",
    "RECEIPT",
    {
        "PROTOCOL": "RECEIPT contracts implement canonical statics, deterministic audit replay, prerequisite-cone closure, bounded hash-chain ordering, issuer-key signature checking, and exact recovery/recheck protocols.",
        "POLICY": "They enforce canonical encoding, digest and child selection, prerequisite/chain closure, admitted key/trust-root and signature rules, finite limits, and fail-closed exclusions.",
    },
    _merge(_RECEIPT_PROTOCOL, _RECEIPT_POLICY),
    # LEDGER is UNRESOLVED: receipt_validation_replay.py names a ledger_registration
    # capability, reported NOT_ESTABLISHED; a named ledger step is not refuted.
    refuted=("TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "ROBOT", "FINBOT"),
    physical=_NO_PHYSICAL,
    financial=(
        "These RECEIPT contracts validate generic retained claim mechanics and do "
        "not give an AGENT/HARNESS live-money authority or invoke payment, trading, "
        "asset custody, or settlement. A later financial receipt endpoint would "
        "separately require FINBOT."
    ),
    refutation_overrides={
        "TRANSACTION": "RECEIPT build and recheck paths produce deterministic assessments and certificate bytes only; they do not execute the represented claim, audit target, transfer, payment, or another live effect with atomicity/finality semantics.",
        "ASSET": "A RECEIPT may mention arbitrary claims, but these contracts represent no quantity-bearing right with issuance, redemption, backing, custody, encumbrance, or supply reconciliation.",
    },
)


_REVIEWS = dict(
    sorted(
        {
            "vstd-actor": _ACTOR,
            "vstd-collective": _COLLECTIVE,
            "vstd-human": _HUMAN,
            "vstd-identity": _IDENTITY,
            "vstd-owner": _OWNER,
            "vstd-receipt": _RECEIPT,
            "vstd-role": _ROLE,
        }.items()
    )
)


def _catalog_check() -> None:
    registry = namespace_registry()
    if tuple(_REVIEWS) != PEOPLE_OBJECT_IDS:
        raise AssertionError("people review object denominator differs")
    if any(kind not in registry for kind in REVIEW_KINDS):
        raise AssertionError("people review kind missing from live namespace registry")
    owned: dict[str, str] = {}
    for object_id, review in _REVIEWS.items():
        if review.primary_kind not in registry:
            raise AssertionError(object_id + " primary kind missing from registry")
        expected_implementation = (
            None
            if review.prefix == "receipt"
            else "src/verifier/domains/" + review.prefix + ".py"
        )
        if review.implementation != expected_implementation:
            raise AssertionError(object_id + " implementation rule differs")
        if review.implementation is not None and review.implementation not in review.owned_paths:
            raise AssertionError(object_id + " implementation is not owned")
        if set(review.reasons) != set(REVIEW_KINDS):
            raise AssertionError(object_id + " does not decide all twelve added kinds")
        if len(review.refuted) != len(set(review.refuted)):
            raise AssertionError(object_id + " repeats a refuted kind")
        if not set(review.refuted) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " refutes an unsupported kind")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " applies and refutes one kind")
        if any(
            type(reason) is not str or not reason.strip()
            for reason in review.reasons.values()
        ):
            raise AssertionError(object_id + " contains a blank applicability reason")
        expected: dict[str, tuple[str, ...]] = {}
        for kind in review.applicable:
            for obligation in _requirements(kind):
                expected[obligation["id"]] = tuple(obligation["declaration_fields"])
        if set(review.declarations) != set(expected):
            raise AssertionError(object_id + " declaration denominator differs")
        for obligation_id, fields in expected.items():
            declaration = review.declarations[obligation_id]
            if set(declaration) != set(fields) or any(
                type(value) is not str or not value.strip()
                for value in declaration.values()
            ):
                raise AssertionError(object_id + " incomplete " + obligation_id)
        for path in review.owned_paths:
            candidate = Path(path)
            if (
                type(path) is not str
                or not path
                or candidate.is_absolute()
                or "\\" in path
                or ".." in candidate.parts
                or candidate.as_posix() != path
            ):
                raise AssertionError(object_id + " owns a nonportable path")
            prior = owned.setdefault(path, object_id)
            if prior != object_id:
                raise AssertionError(
                    path + " owned by both " + prior + " and " + object_id
                )


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return the deterministic exact-source review for the seven objects."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: {
                    "status": _basis(review, kind),
                    "reason": (
                        _MIGRATION_REASON.format(kind=kind)
                        if _basis(review, kind) == "UNRESOLVED"
                        else review.reasons[kind]
                    ),
                    "evidence_paths": (
                        []
                        if _basis(review, kind) == "UNRESOLVED"
                        else list(review.owned_paths)
                    ),
                }
                for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(review.declarations),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for object_id, review in _REVIEWS.items()
    }


def _owned_file_paths(row: Mapping[str, Any]) -> set[str]:
    surfaces = row.get("surfaces")
    if type(surfaces) is not list or any(
        type(surface) is not str for surface in surfaces
    ):
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_PEOPLE_SURFACES_INVALID")
    paths = [
        surface.removeprefix("file:")
        for surface in surfaces
        if surface.startswith("file:")
    ]
    if len(paths) != len(set(paths)):
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_PEOPLE_SURFACES_DUPLICATED")
    return set(paths)


def _live_migration_paths(root: Path) -> set[str]:
    """Observe every file below ``domains/contracts`` plus owned domain implementations.

    Caches are excluded because they are not source; every other file, at any
    depth and with any suffix, is a candidate for the migration owner rule.
    """
    contracts = root / "src/verifier/domains/contracts"
    census = {
        path.relative_to(root).as_posix()
        for path in contracts.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    for object_id in PEOPLE_OBJECT_IDS:
        implementation = _REVIEWS[object_id].implementation
        if implementation is not None and (root / implementation).is_file():
            census.add(implementation)
    return census


def _migration_owned_paths(paths: set[str], review: _Review) -> set[str]:
    """Select this object's paths with the migration's owner rule.

    A contract belongs to the kind named by the stem segment before its first
    underscore, compared case-insensitively. The domain implementation is an
    explicit reviewed owner when it is present in the census.
    """
    contract_prefix = "src/verifier/domains/contracts/"
    current = {
        path
        for path in paths
        if path.startswith(contract_prefix)
        and Path(path).stem.split("_", 1)[0].upper() == review.primary_kind
    }
    if review.implementation is not None and review.implementation in paths:
        current.add(review.implementation)
    return current


def _source_snapshot(
    root: Path,
    paths: tuple[str, ...],
    *,
    object_id: str,
) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    for path in paths:
        try:
            target = (root / path).resolve(strict=True)
            target.relative_to(root)
            if not target.is_file():
                raise OSError("not a regular file")
            digest = _digest(target.read_bytes())
        except (OSError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_SOURCE_UNAVAILABLE:"
                + object_id
                + ":"
                + path
            ) from exc
        evidence.append({"path": path, "sha256": digest})
    return evidence


def _current_evidence(
    root: Path,
    paths: tuple[str, ...],
    files: Mapping[str, str],
    *,
    object_id: str,
) -> list[dict[str, str]]:
    evidence = _source_snapshot(root, paths, object_id=object_id)
    for reference in evidence:
        if files.get(reference["path"]) != reference["sha256"]:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_SOURCE_DIFFERS:"
                + object_id
                + ":"
                + reference["path"]
            )
    return evidence


def _validate_evidence(
    evidence: Any,
    files: Mapping[str, str],
    owned: set[str],
    *,
    allow_empty: bool,
    code: str,
) -> None:
    if type(evidence) is not list or (not allow_empty and not evidence):
        raise ValueError(code)
    seen: set[str] = set()
    for reference in evidence:
        if (
            type(reference) is not dict
            or set(reference) != {"path", "sha256"}
            or type(reference["path"]) is not str
            or type(reference["sha256"]) is not str
            or reference["path"] not in owned
            or reference["path"] in seen
            or files.get(reference["path"]) != reference["sha256"]
        ):
            raise ValueError(code)
        seen.add(reference["path"])


def _preserve_decision(
    decision: Any,
    expected: Mapping[str, Any] | None,
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    kind: str,
) -> bool:
    code = "PACKAGE_ORIGINAL_REVIEW_PEOPLE_DECISION_CONFLICT:" + object_id + ":" + kind
    if type(decision) is not dict or set(decision) != {"status", "reason", "evidence"}:
        raise ValueError(code)
    if decision["status"] == "UNRESOLVED":
        if decision["reason"] != _MIGRATION_REASON.format(kind=kind):
            raise ValueError(code)
        _validate_evidence(
            decision["evidence"], files, owned, allow_empty=True, code=code
        )
        return False
    if expected is None or decision != expected:
        raise ValueError(code)
    return True


def _blank_candidate(
    binding: Any,
    fields: tuple[str, ...],
    files: Mapping[str, str],
    owned: set[str],
    *,
    code: str,
) -> bool:
    if type(binding) is not dict or set(binding) != {
        "reason",
        "evidence",
        "declaration",
    }:
        return False
    declaration = binding["declaration"]
    if (
        binding["reason"] != ""
        or type(declaration) is not dict
        or set(declaration) != set(fields)
        or any(value != "" for value in declaration.values())
    ):
        return False
    try:
        _validate_evidence(
            binding["evidence"], files, owned, allow_empty=True, code=code
        )
    except ValueError:
        raise
    return True


def _preserve_obligation(
    binding: Any,
    fields: tuple[str, ...],
    expected_reason: str,
    expected_evidence: list[dict[str, str]],
    expected_declaration: Mapping[str, str],
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    obligation_id: str,
) -> bool:
    if binding is None:
        return False
    code = (
        "PACKAGE_ORIGINAL_REVIEW_PEOPLE_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id
    )
    if _blank_candidate(binding, fields, files, owned, code=code):
        return False
    if type(binding) is not dict or set(binding) != {
        "reason",
        "evidence",
        "declaration",
    }:
        raise ValueError(code)
    # Compatibility is exact: a non-blank declaration that differs from the
    # reviewed Tier-0 text is a conflicting binding, not a preserved review.
    if (
        binding["reason"] != expected_reason
        or binding["evidence"] != expected_evidence
        or type(binding["declaration"]) is not dict
        or binding["declaration"] != expected_declaration
    ):
        raise ValueError(code)
    return True


def _ensure_denominator(census: set[str], object_id: str, review: _Review) -> None:
    if _migration_owned_paths(census, review) != set(review.owned_paths):
        raise ValueError(
            "PACKAGE_ORIGINAL_REVIEW_PEOPLE_MIGRATION_DENOMINATOR_CHANGED:"
            + object_id
        )


def apply_package_original_review_people(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply the complete seven-object review atomically to a deep copy.

    Only the exact current migration's unresolved decision and blank obligation
    templates may be filled. Complete compatible current-byte reviews are
    preserved. Any partial, conflicting, stale, unowned, or source-drifted
    binding fails before a result is returned.
    """
    selected_root = Path(root).resolve(strict=True)
    if not selected_root.is_dir():
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_PEOPLE_ROOT_INVALID")
    if type(rows) is not dict:
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_PEOPLE_ROWS_INVALID")
    if type(files) is not dict or any(
        type(path) is not str or type(digest) is not str
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_PEOPLE_FILES_INVALID")

    registered_questions = set(namespace_registry()) - {"OBJECT"}
    registered: dict[str, dict[str, tuple[str, ...]]] = {}
    all_review_obligations: set[str] = set()
    for kind in REVIEW_KINDS:
        registered[kind] = {
            obligation["id"]: tuple(obligation["declaration_fields"])
            for obligation in _requirements(kind)
        }
        all_review_obligations.update(registered[kind])

    opening_census = _live_migration_paths(selected_root)
    plans: dict[str, dict[str, Any]] = {}
    for object_id, review in _REVIEWS.items():
        _ensure_denominator(opening_census, object_id, review)
        row = rows.get(object_id)
        if type(row) is not dict:
            raise ValueError("PACKAGE_ORIGINAL_REVIEW_PEOPLE_OBJECT_MISSING:" + object_id)
        if row.get("object_id") != object_id or row.get("kind") != review.primary_kind:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_PRIMARY_KIND_DIFFERS:" + object_id
            )
        owned = _owned_file_paths(row)
        if owned != set(review.owned_paths):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_OWNERSHIP_DIFFERS:" + object_id
            )
        evidence = _current_evidence(
            selected_root, review.owned_paths, files, object_id=object_id
        )
        evidence_by_path = {item["path"]: item for item in evidence}
        classification = row.get("classification")
        obligations = row.get("obligations")
        specializations = row.get("specializations")
        if not _has_complete_foreign_questions(
            classification, registered_questions
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_CLASSIFICATION_INVALID:" + object_id
            )
        if type(obligations) is not dict:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_OBLIGATIONS_INVALID:" + object_id
            )
        if type(specializations) is not list or any(
            type(kind) is not str for kind in specializations
        ) or len(specializations) != len(set(specializations)):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_SPECIALIZATIONS_INVALID:" + object_id
            )
        # OBJECT is the general base that every role can attach to; it is never a
        # reviewed label, so it cannot stand in for an unreviewed role.
        if any(
            kind == "OBJECT" or kind not in registered_questions
            for kind in specializations
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_SPECIALIZATION_UNREGISTERED:"
                + object_id
            )

        stale = {
            obligation_id
            for obligation_id in obligations
            if any(
                obligation_id.startswith(kind + "-") for kind in REVIEW_KINDS
            )
            and obligation_id not in all_review_obligations
        }
        if stale:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_STALE_OBLIGATION:"
                + object_id
                + ":"
                + sorted(stale)[0]
            )

        preserve_decisions: set[str] = set()
        preserve_obligations: set[str] = set()
        remove_obligations: set[str] = set()
        owned_words = _mechanism_words(selected_root, object_id, review.owned_paths)
        for kind in REVIEW_KINDS:
            basis = _basis(review, kind)
            if basis != "APPLIES" and (row["kind"] == kind or kind in specializations):
                raise ValueError(
                    "PACKAGE_ORIGINAL_REVIEW_PEOPLE_LABEL_CONFLICT:"
                    + object_id
                    + ":"
                    + kind
                )
            if basis == "DOES_NOT_APPLY" and owned_words & _MECHANISM_WORDS[kind]:
                raise ValueError(
                    "PACKAGE_ORIGINAL_REVIEW_PEOPLE_MECHANISM_CONTRADICTS_REFUTATION:"
                    + object_id
                    + ":"
                    + kind
                )
            expected_decision = None
            if basis != "UNRESOLVED":
                expected_decision = {
                    "status": basis,
                    "reason": review.reasons[kind],
                    "evidence": [
                        deepcopy(evidence_by_path[path]) for path in review.owned_paths
                    ],
                }
            if _preserve_decision(
                classification[kind],
                expected_decision,
                files,
                owned,
                object_id=object_id,
                kind=kind,
            ):
                preserve_decisions.add(kind)
            for obligation_id, fields in registered[kind].items():
                binding = obligations.get(obligation_id)
                if basis == "APPLIES":
                    expected_evidence = [
                        deepcopy(evidence_by_path[path]) for path in review.owned_paths
                    ]
                    if _preserve_obligation(
                        binding,
                        fields,
                        _obligation_reason(review, kind),
                        expected_evidence,
                        dict(review.declarations[obligation_id]),
                        files,
                        owned,
                        object_id=object_id,
                        obligation_id=obligation_id,
                    ):
                        preserve_obligations.add(obligation_id)
                elif binding is not None:
                    prefix = (
                        "PACKAGE_ORIGINAL_REVIEW_PEOPLE_REFUTED_DECLARATION_CONFLICT:"
                        if basis == "DOES_NOT_APPLY"
                        else "PACKAGE_ORIGINAL_REVIEW_PEOPLE_UNLISTED_DECLARATION_CONFLICT:"
                    )
                    code = prefix + object_id + ":" + obligation_id
                    if not _blank_candidate(binding, fields, files, owned, code=code):
                        raise ValueError(code)
                    remove_obligations.add(obligation_id)
        plans[object_id] = {
            "evidence_by_path": evidence_by_path,
            "preserve_decisions": preserve_decisions,
            "preserve_obligations": preserve_obligations,
            "remove_obligations": remove_obligations,
        }

    closing_census = _live_migration_paths(selected_root)
    for object_id, review in _REVIEWS.items():
        _ensure_denominator(closing_census, object_id, review)
        closing = _source_snapshot(
            selected_root, review.owned_paths, object_id=object_id
        )
        if {item["path"]: item for item in closing} != plans[object_id][
            "evidence_by_path"
        ]:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_SOURCE_CHANGED:" + object_id
            )

    result = deepcopy(rows)
    for object_id, review in _REVIEWS.items():
        row = result[object_id]
        plan = plans[object_id]
        for kind in REVIEW_KINDS:
            if kind in plan["preserve_decisions"]:
                continue
            basis = _basis(review, kind)
            if basis == "UNRESOLVED":
                row["classification"][kind] = _canonical_migration_question(kind)
            else:
                row["classification"][kind] = {
                    "status": basis,
                    "reason": review.reasons[kind],
                    "evidence": [
                        deepcopy(plan["evidence_by_path"][path])
                        for path in review.owned_paths
                    ],
                }
        for obligation_id in plan["remove_obligations"]:
            row["obligations"].pop(obligation_id, None)
        for obligation_id, declaration in review.declarations.items():
            if obligation_id in plan["preserve_obligations"]:
                continue
            kind = obligation_id.split("-", 1)[0]
            row["obligations"][obligation_id] = {
                "reason": _obligation_reason(review, kind),
                "evidence": [
                    deepcopy(plan["evidence_by_path"][path])
                    for path in review.owned_paths
                ],
                "declaration": dict(declaration),
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)

    final_census = _live_migration_paths(selected_root)
    for object_id, review in _REVIEWS.items():
        _ensure_denominator(final_census, object_id, review)
        final = _source_snapshot(
            selected_root, review.owned_paths, object_id=object_id
        )
        if {item["path"]: item for item in final} != plans[object_id][
            "evidence_by_path"
        ]:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PEOPLE_SOURCE_CHANGED:" + object_id
            )
    return result
