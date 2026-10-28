"""Current-source Tier-0 review for seven retained computation objects.

Terminology: abstract syntax tree (AST); central processing unit (CPU);
JavaScript Object Notation (JSON).

The seven objects predate the additive consequence namespace.  This module
answers the new applicability questions against their current source owners:
each explicit domain implementation plus every contract assigned by the
migration's same-prefix ownership rule.  It records declarations, not proof of
their truth.  Mechanism execution, Tier-1-plus conformance, physical reach,
financial authority, publication, release, and deployment remain unestablished.

Application is pure and atomic.  The complete 30-file denominator is read at
opening, after conflict analysis, and again before return.  Only canonical
migration candidates or complete compatible current reviews are accepted;
partial, stale, unowned, conflicting, or concurrently changed state fails.
Each DOES_NOT_APPLY basis is also checked against its exact owned source by an
AST lexicon audit; source that names the refuted role fails closed.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.package_semantic_ownership_domains_agency_collective import (
    OBLIGATION_RETENTION_APPLIES as _AGENCY_OBLIGATION_RETENTION_APPLIES,
    obligation_retention_reason as _obligation_retention_reason,
)
from verifier.runtime.self_polish_estate import (
    EstateError,
    _git_tracked_paths,
    _git_untracked_paths,
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

ORIGINAL_OBJECT_IDS = (
    "vstd-architecture",
    "vstd-training",
    "vstd-hypergraph",
    "vstd-model",
    "vstd-agent",
    "vstd-bot",
    "vstd-token",
)

CLAIM_BOUNDARY = (
    "Exact-current-source Tier-0 applicability and declaration review for these "
    "seven retained objects only. Mechanism truth, Tier-1-plus conformance, "
    "physical or financial authority, full package coverage, release, and "
    "deployment remain unestablished."
)


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    refuted: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    reasons: Mapping[str, str]
    declarations: Mapping[str, Mapping[str, str]]


# These are the migration's current ownership results, written explicitly so a
# new same-prefix contract changes the row's owned file set and fails closed.
# ARCH and HYPER have no domain implementation file; the other five do.
_ARCH_PATHS = (
    "src/verifier/domains/contracts/arch_resolution.py",
    "src/verifier/domains/contracts/arch_schedule.py",
    "src/verifier/domains/contracts/arch_shapes.py",
)
_TRAIN_PATHS = (
    "src/verifier/domains/train.py",
    "src/verifier/domains/contracts/train_accumulation.py",
    "src/verifier/domains/contracts/train_checks.py",
    "src/verifier/domains/contracts/train_data_bridge.py",
)
_HYPER_PATHS = (
    "src/verifier/domains/contracts/hyper_closure.py",
    "src/verifier/domains/contracts/hyper_composed_ceiling.py",
    "src/verifier/domains/contracts/hyper_unknown_absorption.py",
)
_MODEL_PATHS = (
    "src/verifier/domains/model.py",
    "src/verifier/domains/contracts/model_artifact_bytes.py",
    "src/verifier/domains/contracts/model_checks.py",
    "src/verifier/domains/contracts/model_data_citation.py",
    "src/verifier/domains/contracts/model_data_lineage.py",
    "src/verifier/domains/contracts/model_hardware_observation.py",
    "src/verifier/domains/contracts/model_quantization.py",
    "src/verifier/domains/contracts/model_train_citation.py",
)
# The corrigibility contract joined the MODEL row by the same stem rule.  It is
# owned here, but the role evidence above predates it and is not widened to cite it.
_MODEL_OWNED_PATHS = tuple(
    sorted(
        _MODEL_PATHS
        + (
            "src/verifier/domains/contracts/model_corrigibility.py",
            "src/verifier/domains/contracts/model_corrigibility_worker.py",
        )
    )
)
_AGENT_PATHS = (
    "src/verifier/domains/agent.py",
    "src/verifier/domains/contracts/agent_ceiling_fixity.py",
    "src/verifier/domains/contracts/agent_checks.py",
)
_BOT_PATHS = (
    "src/verifier/domains/bot.py",
    "src/verifier/domains/contracts/bot_checks.py",
    "src/verifier/domains/contracts/bot_inherited_ceiling.py",
)
_TOKEN_PATHS = (
    "src/verifier/domains/token.py",
    "src/verifier/domains/contracts/token_checks.py",
    "src/verifier/domains/contracts/token_checks_projection.py",
    "src/verifier/domains/contracts/token_facets.py",
)

_MODEL_HARDWARE = ("src/verifier/domains/contracts/model_hardware_observation.py",)
_MODEL_MEASUREMENT_PATHS = (
    "src/verifier/domains/model.py",
    "src/verifier/domains/contracts/model_checks.py",
    "src/verifier/domains/contracts/model_hardware_observation.py",
)
_BOT_LOOP = (
    "src/verifier/domains/bot.py",
    "src/verifier/domains/contracts/bot_checks.py",
    "src/verifier/domains/contracts/bot_inherited_ceiling.py",
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
    # A simulated ACTUATOR is still an ACTUATOR, but it is not a ROBOT carrier.
    # ROBOT begins only at an embodied/physical or explicit sim-to-real path.
    "ROBOT": frozenset({
        "robot", "robots", "robotic", "embodied", "physical", "motor",
        "__physical_control_endpoint__",
    }),
    "FINBOT": frozenset({
        "financial", "finance", "money", "payment", "payments", "currency",
        "monetary", "wallet", "exposure", "exposures", "trading",
        "__real_financial_endpoint__",
    }),
}
_TOKEN_LITERAL = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")

# These names are not proof of physical reach. They are fail-closed evidence
# that a source cannot retain a ROBOT DOES_NOT_APPLY decision without a fresh
# human/source review. Pairing a hardware family with an effectful endpoint
# term avoids treating a data mention of ``GPIO`` or a generic ``output`` as a
# robot. Reference and explicit simulation vocabulary is excluded unless the
# same construct also names a real/external crossing.
_PHYSICAL_CONTROL_ALIASES = frozenset({
    "can", "cnc", "gpio", "i2c", "modbus", "plc", "pwm", "relay", "ros",
    "scada", "serial", "servo", "solenoid", "spi", "uart",
})
_PHYSICAL_EFFECT_CONTEXT = frozenset({
    "actuate", "actuated", "actuation", "command", "commands", "configure",
    "control", "controller", "controllers", "controls", "drive", "drives",
    "driving", "endpoint", "endpoints", "output", "outputs", "publish",
    "send", "set", "write", "writes",
})
_REAL_CROSSING_CONTEXT = frozenset({
    "device", "external", "hardware", "live", "physical", "real", "world",
})
_REFERENCE_ONLY_CONTEXT = frozenset({
    "check", "checker", "checks", "doc", "docs", "documentation", "example",
    "examples", "expected", "fixture", "label", "labels", "metadata",
    "reference", "references", "report", "reports", "sample", "samples",
    "schema", "schemas", "specimen", "test", "tests", "vocabulary",
})
_FINANCIAL_ENDPOINT_ALIASES = frozenset({
    "ach", "bank", "broker", "brokerage", "card", "crypto", "fiat", "iban",
    "sepa", "swift", "wire",
})
_FINANCIAL_EFFECT_CONTEXT = frozenset({
    "account", "buy", "decision", "deposit", "endpoint", "execute", "order",
    "pay", "payment", "sell", "send", "settle", "settlement", "trade",
    "transfer", "withdraw", "write",
})


def _symbol_words(value: str) -> set[str]:
    """Split one code-shaped symbol without interpreting prose."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return {
        word
        for word in re.split(r"[^A-Za-z0-9]+", spaced.lower())
        if word
    }


def _bounded_static_symbol(node: ast.AST) -> str | None:
    """Fold a tiny string-only expression used as an endpoint or member name."""
    if isinstance(node, ast.Constant) and type(node.value) is str:
        value = node.value
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _bounded_static_symbol(node.left)
        right = _bounded_static_symbol(node.right)
        if left is None or right is None:
            return None
        value = left + right
    else:
        return None
    if not value or len(value) > 128 or any(character.isspace() for character in value):
        return None
    return value


def _lexical_words(node: ast.AST, docstrings: set[int]) -> set[str]:
    """Collect code identifiers and short symbol-like values from one construct."""
    words: set[str] = set()
    folded = _bounded_static_symbol(node)
    if folded is not None:
        words |= _symbol_words(folded)
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            words |= _symbol_words(child.id)
        elif isinstance(child, ast.Attribute):
            words |= _symbol_words(child.attr)
        elif isinstance(child, ast.arg):
            words |= _symbol_words(child.arg)
        elif isinstance(child, ast.alias):
            words |= _symbol_words(child.name)
            if child.asname:
                words |= _symbol_words(child.asname)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            words |= _symbol_words(child.name)
        elif (
            isinstance(child, ast.Constant)
            and type(child.value) is str
            and id(child) not in docstrings
        ):
            value = _bounded_static_symbol(child)
            if value is not None:
                words |= _symbol_words(value)
    return words


def _consequence_alias_words(
    text: str,
    aliases: frozenset[str],
    effect_context: frozenset[str],
) -> bool:
    """Detect one consequence endpoint alias inside one related AST construct."""
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

    def selected(words: set[str]) -> bool:
        if not words & aliases:
            return False
        if not words & effect_context:
            return False
        crosses = bool(words & _REAL_CROSSING_CONTEXT)
        if words & _REFERENCE_ONLY_CONTEXT and not crosses:
            return False
        if (
            ("simulated" in words or "simulation" in words)
            and not crosses
        ):
            return False
        return True

    # Individual identifiers catch GPIO_COMMAND, rosCommand and imported
    # constants without combining unrelated statements elsewhere in the file.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and selected(_symbol_words(node.id)):
            return True
        if isinstance(node, ast.Attribute) and selected(_symbol_words(node.attr)):
            return True
        if isinstance(node, ast.alias):
            words = _symbol_words(node.name)
            if node.asname:
                words |= _symbol_words(node.asname)
            if selected(words):
                return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if selected(_symbol_words(node.name)):
                return True

    # Bind a target/callee to its own value or argument, but never join two
    # independent statements. This catches endpoint='g'+'pio' and
    # getattr(board, 'gpio_'+'write') while leaving detached vocabulary alone.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            binding = set().union(*(
                _lexical_words(target, docstrings) for target in targets
            ))
            value = getattr(node, "value", None)
            if value is not None and selected(
                binding | _lexical_words(value, docstrings)
            ):
                return True
        elif isinstance(node, ast.Call):
            callee = _lexical_words(node.func, docstrings)
            for argument in [*node.args, *(item.value for item in node.keywords)]:
                if selected(callee | _lexical_words(argument, docstrings)):
                    return True
    return False


def _physical_control_alias_words(text: str) -> bool:
    """Detect a physical-control alias only in one effect-bearing construct."""
    return _consequence_alias_words(
        text, _PHYSICAL_CONTROL_ALIASES, _PHYSICAL_EFFECT_CONTEXT
    )


def _financial_endpoint_alias_words(text: str) -> bool:
    """Detect a real-financial endpoint alias without treating simulation as reach."""
    return _consequence_alias_words(
        text, _FINANCIAL_ENDPOINT_ALIASES, _FINANCIAL_EFFECT_CONTEXT
    )


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
            text = (root / path).read_text(encoding="utf-8")
            words |= _code_words(text)
            if _physical_control_alias_words(text):
                words.add("__physical_control_endpoint__")
            if _financial_endpoint_alias_words(text):
                words.add("__real_financial_endpoint__")
        except (SyntaxError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SOURCE_UNPARSEABLE:"
                + object_id
                + ":"
                + path
            ) from exc
    return words


def _requirements(kind: str) -> list[dict[str, Any]]:
    return [
        row
        for row in requirements_for(namespace_registry(), (kind,))
        if row["kind"] == kind
    ]


def _declarations(kind: str, fields: Mapping[str, str]) -> dict[str, dict[str, str]]:
    """Bind a readable field map to the live obligation denominator."""
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
    """Retain live fields while leaving every concrete mechanism value open."""
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
                "the owned closed-effect boundary is open. The concrete mechanism "
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
            raise AssertionError(
                "duplicate declaration ids: " + ", ".join(sorted(overlap))
            )
        result.update({name: dict(fields) for name, fields in group.items()})
    return result


def _base_reasons(subject: str) -> dict[str, str]:
    """Repository-bound defaults; each applicable or unusual role is overridden."""
    return {
        "LEDGER": subject
        + " owns no authoritative ordered history, account state, posting rules, reconciliation, correction history, or duplicate-application authority.",
        "TRANSACTION": subject
        + " performs deterministic checking and owns no externally visible state-changing effect with commit, abort, finality, compensation, and retry semantics.",
        "ASSET": subject
        + " represents no owned right or quantity with issuance, redemption, custody, encumbrance, and backing semantics.",
        "MARKET": subject
        + " has no participants, orders, matching, price formation, allocation, manipulation control, or settlement mechanism.",
        "MEASUREMENT": subject
        + " validates retained values but declares no observation of a phenomenon with acquisition time, uncertainty, missingness, and provenance semantics.",
        "SENSOR": subject
        + " performs no fresh acquisition from a deployed source and has no calibration, sampling, latency, drift, or sensor-fault boundary.",
        "CONTROLLER": subject
        + " implements no feedback objective, adaptive command selection, stability assumption, arbitration, intervention, or controller failure state.",
        "ACTUATOR": subject
        + " exposes no command-to-effect interface with a target, response envelope, interlock, effect feedback, or actuator recovery state.",
        "PROTOCOL": subject
        + " defines no participant message state machine with authority, ordering, replay, compatibility, safety, liveness, and recovery semantics.",
        "POLICY": subject
        + " has no installed rule-selection, authority, exception, revision, enforcement, or fail-closed decision boundary.",
        "ROBOT": subject
        + " exposes no AGENT-to-HARNESS-to-CONTROLLER-to-physical-ACTUATOR path. No physical reach or sim-to-real crossing is inferred.",
        "FINBOT": subject
        + " gives no agent live-money decision or transfer authority, financial assets or parties, settlement dependency, or exposure limit.",
    }


def _review(
    primary_kind: str,
    owned_paths: tuple[str, ...],
    role_paths: Mapping[str, tuple[str, ...]],
    reason_overrides: Mapping[str, str],
    declarations: Mapping[str, Mapping[str, str]],
    *,
    subject: str,
    refuted: tuple[str, ...],
) -> _Review:
    reasons = _base_reasons(subject)
    reasons.update(reason_overrides)
    applicable = tuple(role_paths)
    return _Review(
        primary_kind=primary_kind,
        owned_paths=owned_paths,
        applicable=applicable,
        refuted=refuted,
        role_paths={kind: tuple(paths) for kind, paths in role_paths.items()},
        reasons=reasons,
        declarations={name: dict(fields) for name, fields in declarations.items()},
    )


def _policy(
    *,
    scope: str,
    decision_inputs: str,
    precedence: str,
    defaults: str,
    authority: str,
    exceptions: str,
    revisions: str,
    activation: str,
    enforcement_points: str,
    decision_evidence: str,
    bypass_handling: str,
    unavailable_behavior: str,
) -> dict[str, dict[str, str]]:
    return _declarations(
        "POLICY",
        {
            "scope": scope,
            "decision_inputs": decision_inputs,
            "precedence": precedence,
            "defaults": defaults,
            "authority": authority,
            "exceptions": exceptions,
            "revisions": revisions,
            "activation": activation,
            "enforcement_points": enforcement_points,
            "decision_evidence": decision_evidence,
            "bypass_handling": bypass_handling,
            "unavailable_behavior": unavailable_behavior,
        },
    )


_ARCH_POLICY = _policy(
    scope="Admission of exact finite ARCH tensor graphs, retained execution schedules, and selected operator-definition and library-byte closure.",
    decision_inputs="Exact request, policy, mechanism, source and evidence digests; selected shapes, graph edges, schedule, definitions, libraries, references, and finite limits.",
    precedence="Canonical binding and finite-bound failures are handled before graph semantics; reproduced contradictions FAIL, while missing selected closure remains UNKNOWN.",
    defaults="No execution equivalence, operator truth, complete submodules, fusion, routing, or runtime behavior is inferred from a static ARCH record.",
    authority="An external selector chooses the subject, policy and trust-root labels; these checkers validate that selection without authenticating the real authority behind it.",
    exceptions="No exception bypasses substituted digests, malformed shapes, graph cycles, missing definitions, schedule disagreement, or exhausted finite bounds.",
    revisions="Schema, semantic, policy, mechanism and installed source digests bind the active rules; changed bytes or versions require a new selection.",
    activation="The selected policy applies to one bounded build or recheck of the named ARCH proposition and grants no execution or deployment authority.",
    enforcement_points="Request and policy parsing, source and mechanism binding, graph and shape validation, schedule replay, catalog closure, cycle/depth checks, and certificate reproduction.",
    decision_evidence="Canonical certificates bind exact retained bytes, selected coordinates, limits, dependencies and the bounded PASS, FAIL, or UNKNOWN result.",
    bypass_handling="Unknown fields, stale bindings, duplicate nodes, unsupported references, cycles, malformed orders and over-limit inputs cannot silently reach PASS.",
    unavailable_behavior="Absent selected definitions, incomplete closure, unsupported interpretation, or exhausted bounds remains UNKNOWN rather than being treated as empty or successful.",
)

_TRAIN_POLICY = _policy(
    scope="Admission of exact retained TRAIN configurations, checkpoints, step traces, batch views, binary64 reductions, optimizer updates, and DATA bridge bindings.",
    decision_inputs="Selected TRAIN and DATA identities, exact artifact and evidence digests, configurations, checkpoints, batches, steps, reduction trees, child certificates, tolerances, and limits.",
    precedence="Source and selection binding precede numerical replay; exact contradictions FAIL and unsupported arithmetic, missing children, or exhausted bounds remain UNKNOWN.",
    defaults="Retained records do not establish that historical training occurred, that live hardware was observed, or that a weight update commanded any deployed system.",
    authority="An external selector supplies the policy and trust roots for one TRAIN proposition; the checker does not authenticate training ownership or publication authority.",
    exceptions="No bypass permits substituted checkpoints, unreferenced batches, noncontiguous steps, mismatched gradients, unsupported arithmetic, or a changed DATA child.",
    revisions="Exact schema, semantic, mechanism, runtime-identity and source digests bind the rules; another runtime or source is a different selection.",
    activation="The selected policy governs one bounded retained replay and grants no authority to start, resume, stop, or deploy a training process.",
    enforcement_points="Request and policy parsing, checkpoint and trace commitments, configuration validation, DATA child replay, binary64 host self-check, reduction replay, loss and update comparisons, and certificate reproduction.",
    decision_evidence="The certificate retains selected bytes and reports only the bounded replay outcome, runtime identity, exclusions, and exact prerequisite bindings.",
    bypass_handling="Missing records, altered digests, unsupported numeric conditions, tolerance violations, unused batches, and exhausted limits cannot become PASS by omission.",
    unavailable_behavior="Unsupported arithmetic, absent child evidence, incomplete records, and bounded-resource exhaustion remain UNKNOWN; they do not prove training absence or correctness.",
)

_HYPER_POLICY = _policy(
    scope="Admission of one finite HYPER operand closure, direct-child UNKNOWN absorption result, and weakest-operand composed tier ceiling.",
    decision_inputs="Exact HYPER root and operand records, selected child certificates and routes, policy and mechanism digests, collection digest, tier coordinates, and finite limits.",
    precedence="All operand identities and selections bind before replay; direct UNKNOWN absorbs composition, contradictions FAIL, and unavailable routes remain UNKNOWN.",
    defaults="Composition grants no new authority, privacy, consent, security, semantic truth, or tier strength beyond the weakest replayed operand.",
    authority="The external selector chooses the root, children, routes, policy and trust-root labels; the HYPER checkers cannot create authority by composition.",
    exceptions="No exception drops a direct operand, substitutes a child, treats UNKNOWN as PASS, or lets the composed declaration raise its own ceiling.",
    revisions="Installed registry, route, policy, mechanism and source digests bind the current composition rules; changed dependencies require re-selection.",
    activation="The policy applies to one bounded closure or child-replay certificate and does not activate the composed objects or their effects.",
    enforcement_points="Canonical parsing, root and collection binding, finite cone construction, direct-operand matching, route selection, child replay, UNKNOWN absorption, ceiling computation, and exact recheck.",
    decision_evidence="Certificates retain the selected collection and child certificate bytes and bind each result to its target, coordinate, tier, status, and current route.",
    bypass_handling="Missing, duplicate, indirect, substituted, over-limit, unknown, or incompatible operands cannot be omitted or promoted to PASS.",
    unavailable_behavior="Unavailable child routes, evidence, policies, or bounded replay remains UNKNOWN and limits the composed result rather than being assumed absent.",
)

_AGENT_POLICY = _policy(
    scope="Admission of one retained AGENT trajectory, action inventory, outcomes and claims under the observation ceiling of its bound HARNESS certificate.",
    decision_inputs="Exact AGENT and HARNESS selections, current child policy, required and instrumented channels, retained records and invocations, steps, actions, outcomes, claims, and finite bounds.",
    precedence="The HARNESS observation ceiling binds first; records outside required instrumented channels remain UNKNOWN, while exact trajectory or invocation contradictions FAIL.",
    defaults="No undeclared channel, live execution, physical isolation, action effect, corrigibility, objective fulfillment, or historical child-policy reproduction is assumed.",
    authority="An external selector supplies policy and trust roots; a retained AGENT decision or tool name does not itself grant execution, physical, or financial authority.",
    exceptions="No exception reconstructs unobserved channels, accepts noncontiguous steps, invents missing invocations, or treats an empty outcome contract as established.",
    revisions="Current mechanism, policy, source and child-certificate digests bind the replay; historical policies are explicitly not reproduced by default.",
    activation="The policy governs one bounded replay of retained AGENT evidence and neither runs the agent nor authorizes a later action.",
    enforcement_points="Request and policy parsing, HARNESS certificate replay, observation-ceiling derivation, record witnessing, step ordering, action-to-invocation matching, outcome comparison, claim support, and exact recheck.",
    decision_evidence="A certificate binds the exact selected records and reports only bounded observation channels, step and action counts, child-policy limits, and the resulting status.",
    bypass_handling="Uninstrumented channels, unbound records, missing tool invocations, substituted digests, unsupported checks, and over-limit evidence cannot silently pass.",
    unavailable_behavior="A claim outside the observation ceiling, an empty contract, missing evidence, or unavailable child replay remains UNKNOWN rather than being inferred from surrounding records.",
)

_MODEL_POLICY = _policy(
    scope="Admission of exact MODEL architecture and weight bytes, finite inference and metric replay, DATA and TRAIN citations, quantization records, and one fresh local hardware bracket observation.",
    decision_inputs="Selected MODEL, HARDWARE, DATA and TRAIN records; exact request, policy, mechanism, source, artifact and child-certificate digests; finite inputs, outputs, caps, trials, tolerances and limits.",
    precedence="Canonical and source binding precede computation; reproduced output, metric or cap contradictions FAIL, while unsupported formats, platforms, children, or bounded execution remain UNKNOWN.",
    defaults="No historical training, weight derivation, universal memory minimum, cross-runtime behavior, physical device authenticity, model safety, disclosure authority, or deployment fitness is inferred.",
    authority="An external selector chooses the model proposition, child policies, trust roots and local resource bracket; the checker grants no model-use, disclosure, deployment, physical, or financial authority.",
    exceptions="No exception bypasses raw-byte commitments, child selection, shape and numeric checks, Job Object enforcement, exact expected output, cap ordering, or finite limits.",
    revisions="Schema, semantic, policy, mechanism, dependency and installed source digests plus the current runtime identity bind the rules; changed bytes or runtime require new evidence.",
    activation="The policy applies to one bounded replay or fresh hardware observation and does not activate an inference service, agent, controller, or deployed model.",
    enforcement_points="Request and policy parsing, object composition, raw artifact and child replay, quantization validation, inference and metric comparison, platform binding, pre-resume Job Object limits, child result validation, and certificate reproduction.",
    decision_evidence="Certificates bind exact selected bytes and report finite replay values or the current local low-cap exhaustion and high-cap completion observations with explicit exclusions.",
    bypass_handling="Substituted artifacts, unsupported formats, stale children, wrong outputs, unverified job limits, ambiguous child exits, and exhausted bounds cannot become PASS.",
    unavailable_behavior="Missing children, unsupported Windows runtime, unavailable enforcement, ambiguous child results, absent inputs, or unbounded claims remain UNKNOWN rather than being estimated.",
)

_BOT_POLICY = _policy(
    scope="Admission of one retained BOT closed-loop binding among an AGENT, its HARNESS evidence, one SIM, and distinct declared AGENT and SIM environments.",
    decision_inputs="Exact AGENT, SIM, ENV and retained HARNESS certificates; current child policies; observation ceiling, records, invocations, transition attribution, simulated observations and actions, separation declaration, and finite limits.",
    precedence="Every child and environment binds before alignment; exact mismatches FAIL, while absent attributed transitions, fused environments, or unobserved channels remain UNKNOWN.",
    defaults="No live execution, physical isolation, stability, task success, corrigibility, real-world actuation, sim-to-real crossing, or historical child-policy reproduction is assumed.",
    authority="External selection and current child policies authorize only this retained replay. The BOT record grants no physical, financial, deployment, or live-agent authority.",
    exceptions="No exception invents an unattributed step, widens the AGENT ceiling, merges distinct environments, or substitutes a SIM observation or action.",
    revisions="Current mechanism, source, policy and child-certificate digests bind the loop; a changed AGENT, SIM, HARNESS or ENV selection is a different BOT.",
    activation="The policy applies to one bounded retained BOT replay and does not start the AGENT, advance a live SIM, or authorize any external action.",
    enforcement_points="Request and policy parsing, child replay, HARNESS digest binding, transition attribution, strict record order, observation and action equality, environment separation, inherited ceiling, and exact recheck.",
    decision_evidence="The certificate binds every selected child and reports only attributed and exogenous transitions, observation ceiling, declared environment separation, and bounded outcome.",
    bypass_handling="Missing invocations, unbound transitions, out-of-ceiling channels, substituted children, fused environments, and exhausted limits cannot silently pass.",
    unavailable_behavior="A loop with no attributed transition, unavailable child, fused environment, or unobserved channel remains UNKNOWN rather than being treated as contained or controlled.",
)

_TOKEN_POLICY = _policy(
    scope="Admission of one retained capability-token holding: identity, tenure fold, delegation attenuation, signatures, audiences, time windows, caveats, status freshness, and replay relations.",
    decision_inputs="Exact token records, issuing keys admitted by checker policy, accepted algorithms, birth commitment, epoch and status traces, root scopes, audiences, clock and skew, caveats, windows, replay identifiers, and finite limits.",
    precedence="Inventory shape and unique identifiers bind first; signature and delegation contradictions FAIL, while missing keys, unsupported algorithms, stale statuses, clock ambiguity, or incomplete tenure remain UNKNOWN.",
    defaults="A signature binds bytes to an admitted key but is never an authority grant; possession, scope text, status, or a TOKEN label grants no legal, financial, physical, or application authority by default.",
    authority="The external checker policy admits exact public keys, algorithms and witness mappings; the token bundle cannot admit its own issuer or prove the issuer's real authority.",
    exceptions="No exception permits unsigned algorithms, key confusion, scope widening, dropped caveats, re-delegated soulbound leases, stale status, replay-id collision, or out-of-window use.",
    revisions="Current source, mechanism, policy, admitted key set, accepted algorithms and selected clock/status inputs bind the rules; changed policy or observations require fresh review.",
    activation="The policy evaluates one retained holding and grants no invocation, redemption, transfer, spending, settlement, or application access by itself.",
    enforcement_points="Canonical inventory parsing, unique token and replay ids, epoch folding, delegation graph and attenuation, key and signature checks, audience and window closure, status freshness, native projection, and exact recheck.",
    decision_evidence="Certificates bind exact retained token and status bytes, admitted policy and mechanism digests, and the bounded tenure, lease, signature, closure, or projection result.",
    bypass_handling="Unspecified issuers, unsupported algorithms, absent or stale statuses, delegation gaps, clock ambiguity, malformed signatures, and exhausted limits cannot silently become authorized.",
    unavailable_behavior="Missing authority evidence, unsupported verification, incomplete epochs, stale status, uncertain window phase, or absent lease closure remains UNKNOWN rather than being treated as valid or revoked.",
)


_MODEL_TRANSACTION = _declarations(
    "TRANSACTION",
    {
        "effects": "Launch the fixed installed Windows CPython dense-model worker under selected Job Object memory caps, consume local process and memory resources, collect its bounded result, and construct one local certificate.",
        "preconditions": "Exact MODEL and HARDWARE selections, current raw architecture and weight bytes, finite input and expected output, supported Windows CPython backend, increasing caps, wall bound, trials, policy, and source bindings must validate before admission.",
        "authorization": "The external local invocation and operating-system process permissions authorize this bounded checker worker only; no model deployment, external inference, physical-device, or financial authority is established.",
        "resources": "One fixed-source child process per cap observation, a Windows Job Object, committed memory, anonymous standard-input/output/error pipes, bounded parent time, and in-memory certificate bytes.",
        "commit": "The bounded observation is accepted only after the lower cap exhausts, the upper cap completes with the selected output, limits were verified before child resume, cleanup is observed, and the certificate is canonically built.",
        "abort": "Timeout, output exhaustion, unavailable enforcement, ambiguous exit, unexpected output, failed cleanup, or any binding error prevents admission; this is process cleanup, not rollback of an external transaction.",
        "finality": "The result is final only for this local invocation and exact source/runtime coordinate. It is not a universal memory minimum, durable deployment result, or external transaction finality.",
        "partial_failure": "A child may be created, resumed, allocate memory, or exit before the parent rejects a result or certificate construction fails; no external compensation beyond bounded process cleanup is claimed.",
        "duplicate_detection": "Exact request, evidence, object, collection, policy and mechanism digests distinguish the selected invocation; no cross-invocation external duplicate ledger exists.",
        "idempotency": "Repetition reruns local child processes and resource consumption. The fixed computation is intended to be source-deterministic, but process effects and current runtime observations are not claimed idempotent.",
        "retry_limits": "The request permits one to three explicit trials and each child wait is bounded to at most five seconds; no hidden automatic retry promotes an unavailable result.",
        "replay": "Certificate recheck reconstructs the exact selection and freshly evaluates the current local worker; retained prior PASS is not accepted as a current hardware observation.",
    },
)

_MODEL_MEASUREMENT = _declarations(
    "MEASUREMENT",
    {
        "phenomenon": "Finite MODEL outputs and evaluation metrics under exact retained architecture and weights, plus lower-cap exhaustion and upper-cap completion for one selected workload on the current Windows CPU runtime.",
        "method": "Replay dense-model arithmetic and metrics, then launch the fixed worker under each selected committed-memory cap for every trial and compare its bounded output with the selected expected vector.",
        "source": "Exact retained model artifacts, finite samples or workload, parent-observed Job Object configuration, child exit and bounded stdout/stderr, current machine and Python identity, and installed source digests.",
        "observation_vs_estimate": "Metric values are deterministic source-bound computations; the hardware bracket is a fresh local parent-interface observation. Neither is an estimate of universal model quality or intrinsic minimum memory.",
        "units": "Committed-memory caps count bytes; trials, operations, layers and samples are dimensionless; dense outputs and supported metrics use ordered Python binary64 values in the selected contract frame.",
        "reference_frame": "Values are relative to the exact MODEL bytes, input or sample set, tolerance, current machine, Windows CPython version, execution backend, selected caps, and installed checker source.",
        "observation_time": "Fresh child observations occur in invocation order during certificate evaluation; no authenticated wall-clock instant or device-internal sample time is retained.",
        "arrival_time": "Each status arrives when the parent observes the bounded child completion and captures its exit and streams; child-internal event timing is not reconstructed.",
        "uncertainty": "No physical calibration, resident-memory value, hardware authenticity, cross-runtime interval, universal minimum, or statistical quality confidence is established; those remain explicit exclusions.",
        "validity": "Validity requires exact artifacts and expected output, supported numeric forms, verified Job Object limits before resume, bounded clean child completion, expected lower/high statuses, current bindings, and all finite checks.",
        "missingness": "Absent inputs, unsupported platform or format, unavailable enforcement, ambiguous exit, unverified cleanup, missing child evidence, and exhausted bounds remain UNKNOWN rather than zero or PASS.",
        "freshness": "The hardware bracket is fresh for this evaluation and current runtime only; retained model metrics are fresh only to the selected bytes and no claim survives source, runtime, input, or policy change.",
        "provenance": "Canonical certificates bind the request, MODEL/HARDWARE and child references, artifact and collection digests, mechanism and policy source, limits, machine/Python/backend identity, and exact bounded outcome.",
    },
)

_MODEL_SENSOR = _declarations(
    "SENSOR",
    {
        "acquisition": "For each selected trial the parent freshly launches a fixed worker twice, verifies the Windows Job Object committed-memory cap before resume, and captures bounded child status, exit, stdout, stderr, and cleanup state.",
        "phenomena": "Parent-visible resource exhaustion under the selected lower cap and successful exact dense-model output under the selected higher cap on the current software and processor runtime.",
        "measurements": "RESOURCE_EXHAUSTED or PASS status, selected cap in bytes, exact output vector, bounded operation count, trial order, machine, Python version, and execution backend.",
        "deployment": "The deployed acquisition boundary is the current local Windows CPython parent, its Job Object backend, and the fixed installed child source; it is not a physical transducer or remote telemetry service.",
        "calibration_applicability": "Physical calibration is not applicable to this software process-bound observation. Applicability is limited to verified operating-system job-limit configuration and exact source/runtime compatibility.",
        "calibration_evidence": "Applied Job Object flags and byte cap are verified before resume and the fixed worker output is checked, but this is enforcement evidence rather than metrological calibration or device authentication.",
        "operating_range": "Selected committed-memory caps are finite increasing values from 8 MiB through 64 MiB, with one to three trials, one-to-five-second child bounds, finite payloads, and bounded native operations.",
        "drift": "Windows, CPython, machine, execution backend, installed numerical/checker source, model bytes, input, and operating-system behavior can drift and require a new observation.",
        "sampling": "Each trial performs one lower-cap observation followed by one upper-cap observation; there is no periodic cadence, aggregation population, or cross-host synchronization.",
        "latency": "Parent waiting is bounded by the selected wall seconds per child, but launch, scheduling, allocation and observation latency are not separately measured or guaranteed.",
        "fault_detection": "Unsupported platform, launch error, timeout, output exhaustion, nonzero exit, stderr, malformed response, wrong output, unverified limits, nonempty owned job, and cleanup ambiguity prevent a valid observation.",
        "recovery": "The backend bounds and cleans the selected child where observable; after environmental repair the only supported recovery is a fresh invocation, never promotion of cached status.",
    },
)

_MODEL_ACTUATOR = _declarations(
    "ACTUATOR",
    {
        "commands": "Create the fixed installed CPython worker, assign it to the owned Windows Job Object, apply the selected committed-memory cap and time/output bounds, resume it, and supply the exact canonical workload.",
        "targets": "The owned local child process and its Job Object only; the command does not target a physical actuator, external model service, user workload, or arbitrary caller-supplied code.",
        "effect_domains": "SOFTWARE_PROCESS_ONLY: local process creation, scheduling, committed-memory enforcement, pipe input/output, termination, and cleanup on the selected Windows host.",
        "authority": "Explicit local checker invocation plus operating-system process permissions authorize only the fixed worker and selected limits; no authority over external systems or model deployment is inferred.",
        "units_and_frames": "Committed-memory limits are bytes, wall bounds are seconds, operations and trials are dimensionless, and all effects are framed to the owned Job Object and exact child process.",
        "response": "The parent observes applied limits before resume, timeout/output flags, child exit, stdout/stderr, owned-job cleanup, and either a bounded RESOURCE_EXHAUSTED or exact PASS record.",
        "limits": "Caps, payload and certificate bytes, operations, trials, wall time, output, evidence objects and composition work are finite and selected under installed ceilings.",
        "saturation": "Lower-cap memory saturation must appear as the exact bounded RESOURCE_EXHAUSTED record; upper-cap saturation, ambiguous failure, or any other status cannot be interpreted as success.",
        "effect_feedback": "Parent-side backend metadata, exit state and captured streams report the selected process effect boundary; they do not observe physical hardware state or undeclared operating-system effects.",
        "interlocks": "The child remains suspended until Job Object ownership and limits are verified; fixed source, isolated interpreter flags, bounded pipes, timeout, expected output and empty owned job are required.",
        "failure_states": "Launch or enforcement unavailable, timeout, output exhaustion, nonzero exit, stderr, malformed response, wrong output, cap mismatch, remaining owned process, or cleanup ambiguity yields UNKNOWN or FAIL.",
        "recovery": "The backend attempts bounded ownership and cleanup; no external rollback is claimed, and another observation requires a fresh process under a freshly validated selection.",
    },
)

_MODEL_PROTOCOL = _declarations(
    "PROTOCOL",
    {
        "participants": "External selector/caller, MODEL checker, Windows execution backend, one fixed installed child worker per cap, and the certificate rechecker.",
        "roles": "The caller selects immutable intent, the checker validates prerequisites and payload, the backend applies bounds and transports bytes, the worker computes one dense output, and the checker validates and records the response.",
        "states": "Selected, prerequisites-replayed, payload-bound, child-created-suspended, limits-verified, resumed, exited-or-bounded, response-validated, trial-complete, and certificate-built or refused.",
        "transitions": "Only exact validation advances selection to launch; verified pre-resume limits advance to running; bounded exit and response parsing advance to accepted observation; any mismatch terminates that path without PASS.",
        "message_authority": "Request, policy, evidence, mechanism and object digests authorize interpretation of canonical stdin/stdout bytes only; child output grants no broader authority.",
        "ordering": "Raw artifact prerequisite precedes native work; within each trial the lower-cap child precedes the upper-cap child; limit verification precedes resume; complete response validation precedes certificate publication.",
        "replay": "Recheck validates the exact request and policy and rebuilds the outcome through current fresh worker execution; replay is bounded and cannot substitute another model or runtime.",
        "compatibility": "Exact schema and semantic versions, Windows CPython, installed execution backend, canonical JSON dense-model format, mechanism digest, source dependencies and finite request shape must match.",
        "failure_assumptions": "The boundary assumes only parent-visible operating-system Job Object and process results; power loss, kernel compromise, physical authenticity, hidden platform effects and external time truth are outside evidence.",
        "safety": "Fixed source, exact payload, verified cap before resume, bounded time and output, owned-job cleanup, strict response fields and expected-output equality prevent unsupported results from becoming PASS.",
        "liveness": "Each child wait is finite, but no guarantee says the platform is available or either selected cap will yield the desired status; bounded nonprogress becomes UNKNOWN.",
        "recovery": "A failed or unavailable exchange produces no accepted observation; cleanup is bounded to the owned job and later recovery is a fresh complete exchange after the cause is addressed.",
    },
)


_BOT_CONTROLLER = _declarations(
    "CONTROLLER",
    {
        "objectives": "Establish the selected simulated closed-loop correspondence: every attributed SIM transition is linked to the retained AGENT/HARNESS interaction, while declared exogenous transitions remain separate. No task-optimality objective is inferred.",
        "feedback": "SIM projections are compared with the AGENT's retained HARNESS invocation outputs on channels inside the inherited observation ceiling.",
        "commands": "The AGENT's retained HARNESS invocation inputs are bound exactly to the selected SIM action sequence for attributed transitions.",
        "authority": "External selection and current AGENT, HARNESS, SIM and ENV certificates authorize retained replay only; the BOT checker neither runs an agent nor commands a live environment.",
        "timing": "Control order is the strict dimensionless SIM transition and HARNESS record order. No wall-clock rate, deadline, latency, simultaneity, or real-time schedule is established.",
        "stability_assumptions": "No convergence, robustness, bounded-state, reward, controllability, observability, or closed-loop stability theorem is checked; correspondence alone cannot supply one.",
        "operating_envelope": "The envelope is the exact selected SIM, attributed transition set, inherited AGENT observation ceiling, retained HARNESS records and invocations, current child policies, and declared distinct environments.",
        "saturation": "No command magnitude or actuator saturation model is present. A missing invocation, out-of-ceiling channel, absent attribution, or unsupported child remains FAIL or UNKNOWN rather than clipped control.",
        "feedback_loss": "A missing or mismatched retained observation, uninstrumented channel, unavailable child, fused environment, or incomplete step map prevents establishment of the loop.",
        "arbitration": "The selected step map and explicit exogenous-transition list divide responsibility between the AGENT and simulation inputs; no multi-controller priority or conflict resolver is claimed.",
        "intervention": "The checker can refuse a retained BOT claim. It has no live pause, override, shutdown, human intervention, or command-replacement channel.",
        "failure_behavior": "Contradictory bindings FAIL and missing evidence or unestablished separation remains UNKNOWN; no live safe state, continuity guarantee, or corrective action follows from a certificate.",
    },
)

_BOT_ACTUATOR = _declarations(
    "ACTUATOR",
    {
        "commands": "Retained AGENT invocation input values that are mapped one-for-one to the SIM action at each attributed transition.",
        "targets": "The selected SIM transition and simulated model state only, as represented by the retained SIM action sequence; no physical endpoint is selected.",
        "effect_domains": "SIMULATED_ONLY: exact retained action-to-transition correspondence inside the selected SIM and BOT evidence graph; no sim-to-real effect is established.",
        "authority": "The bound AGENT, HARNESS and SIM certificates plus external selection authorize only replay of the declared simulated action correspondence.",
        "units_and_frames": "Transition and HARNESS record indices are dimensionless and action payloads retain the SIM contract's selected frame; no physical unit or coordinate is inferred.",
        "response": "The next retained SIM projection is compared with the corresponding HARNESS invocation output for the attributed transition.",
        "limits": "Only finite retained transitions, records, invocations, actions, observation channels, child certificate bytes and checker operations are admitted.",
        "saturation": "No simulated actuator saturation, rate limit or magnitude clamp is modeled by these BOT sources; absent semantics remain unestablished rather than assumed safe.",
        "effect_feedback": "Retained SIM observations and HARNESS invocation outputs provide equality evidence for the simulated loop, not proof of a live effect or whole-SIM truth.",
        "interlocks": "Exact child binding, strict step order, attributed/exogenous partition, observation ceiling, invocation existence and optional distinct-environment checks gate the simulated action correspondence.",
        "failure_states": "Mismatched action or observation, missing invocation, invalid step mapping, out-of-ceiling channel, unavailable child, or fused environment yields FAIL or UNKNOWN.",
        "recovery": "Recovery requires corrected immutable evidence and a fresh bounded replay; the checker cannot undo a simulated transition or intervene in a running system.",
    },
)

_BOT_PROTOCOL = _declarations(
    "PROTOCOL",
    {
        "participants": "Externally selected AGENT, its retained HARNESS interaction, selected SIM, AGENT ENV, SIM ENV, BOT checker and certificate rechecker.",
        "roles": "The AGENT supplies retained decisions and invocations, HARNESS supplies witnessed records, SIM supplies transitions/actions/projections, ENV records support separation, and BOT binds their correspondence.",
        "states": "Children-bound, transitions-partitioned, step-map-aligned, initial-observation-bound, action-and-observation-compared, environment-separation-checked, and certificate accepted, failed or unavailable.",
        "transitions": "Exact child replay permits alignment; strict retained record order permits each attributed transition comparison; optional containment advances only when declared distinct environments remain separately evidenced.",
        "message_authority": "Current child certificates, object and evidence digests, external policy and trust-root selections authorize interpretation of retained interaction bytes only.",
        "ordering": "SIM transitions preserve their sequence, attributed HARNESS record indices must strictly increase, the initial observation precedes attributed steps, and child binding precedes every comparison.",
        "replay": "Build and recheck replay exact retained child certificates and interaction evidence under current policies; historical child-policy reproduction is explicitly not established.",
        "compatibility": "Exact AGENT, SIM, HARNESS and ENV kinds, subject ids, digests, current route versions, action and observation shapes, channel names, and finite bounds must agree.",
        "failure_assumptions": "Only retained child and parent-interface evidence is observed; live scheduling, hidden environment channels, physical isolation, sim-to-real effects and external side effects remain outside the protocol claim.",
        "safety": "No unattributed transition is silently assigned to the AGENT, no uninstrumented channel supports the loop, and action or observation disagreement cannot pass.",
        "liveness": "Finite replay terminates under checker bounds, but no claim says an AGENT acts, a SIM advances, the loop remains available, or a task eventually succeeds.",
        "recovery": "Unavailable or contradictory exchanges require corrected selections or evidence and a complete fresh replay; there is no live reconnect, retry, compensation, or system reset.",
    },
)


_TOKEN_ASSET = _declarations(
    "ASSET",
    {
        "identity": "Each retained capability claim has an exact token identifier, replay identifier, kind, issuing-key identifier, signature and canonical preimage within one selected holding.",
        "rights": "Scopes, audiences, windows and caveats are a recorded capability claim, not an authority grant, legal right, financial instrument, ownership proof, or evidence that an application will honor it.",
        "units": "Tokens and invocations are dimensionless counts; epochs are dimensionless; issued-at, windows, status publication and skew are integers on the one declared microsecond clock.",
        "precision": "Identifiers, commitments, signatures and digests compare exactly; counters and instants are exact bounded integers, with clock-skew boundaries reported as undetermined rather than rounded.",
        "issuance_authority": "A verified signature identifies an admitted issuing key for the canonical bytes. The checker policy admits keys, but neither key possession nor signature authenticates the issuer's real authority.",
        "supply_changes": "Retained birth, aging and lifetime records describe issuance and delegation, while epoch/status traces describe suspension or revocation; the checker itself creates, transfers, redeems or destroys no token.",
        "redemption": "No redemption, invocation, application access, money conversion, settlement, or consumption occurs. Downstream use requires separate current application authority and effect evidence.",
        "backing_claims": "Cryptographic binding, attenuation and freshness checks back only the exact recorded relationships. Legal, organizational, application, physical and financial backing remain unestablished.",
        "custody": "The checker temporarily holds selected immutable token bytes. Byte possession is not custody of an underlying right, secret key, account, asset, or application authority.",
        "control": "Delegate keys, confirmation keys, soulbound flags, scopes and caveats constrain the recorded capability path but do not prove exclusive control or prevent use outside this checker.",
        "encumbrances": "Parent scopes, time windows, invocation ceilings, caveats, soulbound restrictions, audience, suspension, revocation, key retirement and status freshness are explicit recorded encumbrances.",
        "reconciliation": "Reconciliation is exact replay of identifiers, parent paths, epoch accumulator, signatures, audiences, windows and latest bounded statuses under the current selected policy; no external authority system is reconciled.",
    },
)

_TOKEN_PROTOCOL = _declarations(
    "PROTOCOL",
    {
        "participants": "Recorded issuer keys, birth issuer, delegating and delegate keys, token holders, named audiences, status publishers, external policy selector, TOKEN checker and certificate rechecker.",
        "roles": "Issuers sign canonical records, parents attenuate leases, delegates receive constrained claims, status publishers report state, policy admits keys/algorithms, and the checker replays the bounded relations.",
        "states": "Birth, aging and lifetime token forms; pending, open, ended or clock-undetermined windows; ACTIVE, SUSPENDED or REVOKED epoch/status states; and verified, unavailable or refuted replay outcomes.",
        "transitions": "Issuance follows birth, delegation follows an existing parent grant with attenuation, epoch folding advances contiguously, revocation cannot resume, key retirement bounds later issuance, and fresh status updates supersede older ones.",
        "message_authority": "Canonical signatures under policy-admitted exact public keys authorize only attribution of token bytes to that key; they do not prove application or financial authority.",
        "ordering": "Issued-at and parent ordering, contiguous epochs, delegation depth, time windows, key retirement, status publication and freshness are compared on the declared clock with explicit skew.",
        "replay": "Replay identifiers must be unique in the holding, exact retained bytes rebuild each result, and recheck cannot silently substitute a token, key, status, clock, policy or native projection.",
        "compatibility": "Exact schema and semantic versions, token kinds and fields, supported signature algorithms, key encoding, clock declaration, policy/mechanism digests, native projection mapping and finite bounds must match.",
        "failure_assumptions": "The protocol sees retained records and policy-admitted keys only; issuer identity, secret-key custody, application enforcement, network delivery, global revocation service and wall-clock truth remain outside evidence.",
        "safety": "Delegation cannot widen scope/window/invocation bounds, drop or rewrite inherited caveats, re-delegate a soulbound lease, use a retired key, collide replay ids, or hide stale/missing status behind PASS.",
        "liveness": "No issuance, delivery, status publication, application acceptance, or eventual recovery is guaranteed; missing or stale necessary evidence remains UNKNOWN.",
        "recovery": "A corrected current holding, key policy, epoch trace or status set must be selected and replayed afresh; the checker performs no revocation broadcast, key rotation, reissue, or application rollback.",
    },
)


def _retention_profile(
    object_id: str,
    owned_paths: tuple[str, ...],
    established: tuple[str, ...],
) -> tuple[
    dict[str, tuple[str, ...]],
    dict[str, str],
    dict[str, dict[str, str]],
]:
    retained = tuple(
        kind
        for kind in _AGENCY_OBLIGATION_RETENTION_APPLIES[object_id]
        if kind not in established
    )
    return (
        {kind: owned_paths for kind in retained},
        {kind: _obligation_retention_reason(object_id, kind) for kind in retained},
        _merge(
            *(
                _open_effect_declarations(kind, "The " + object_id + " verifier")
                for kind in retained
            )
        ),
    )


(
    _ARCH_RETENTION_PATHS,
    _ARCH_RETENTION_REASONS,
    _ARCH_RETENTION_DECLARATIONS,
) = _retention_profile("vstd-architecture", _ARCH_PATHS, ("POLICY",))
(
    _AGENT_RETENTION_PATHS,
    _AGENT_RETENTION_REASONS,
    _AGENT_RETENTION_DECLARATIONS,
) = _retention_profile("vstd-agent", _AGENT_PATHS, ("POLICY",))
(
    _BOT_RETENTION_PATHS,
    _BOT_RETENTION_REASONS,
    _BOT_RETENTION_DECLARATIONS,
) = _retention_profile(
    "vstd-bot", _BOT_PATHS, ("CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY")
)


_REVIEWS = {
    "vstd-architecture": _review(
        "ARCH",
        _ARCH_PATHS,
        {**_ARCH_RETENTION_PATHS, "POLICY": _ARCH_PATHS},
        {
            "POLICY": "The ARCH sources implement externally selected, versioned and digest-bound rules for shape graphs, schedules and finite operator/library closure, with explicit precedence and fail-closed outcomes.",
            "PROTOCOL": "ARCH graph nodes, schedules and operator references are retained computation structure, not participants exchanging authoritative messages or a liveness-bearing protocol.",
            **_ARCH_RETENTION_REASONS,
        },
        _merge(_ARCH_RETENTION_DECLARATIONS, _ARCH_POLICY),
        subject="The exact ARCH shape, schedule and resolution sources",
        refuted=(),
    ),
    "vstd-training": _review(
        "TRAIN",
        _TRAIN_PATHS,
        {"POLICY": _TRAIN_PATHS},
        {
            "TRANSACTION": "The TRAIN sources replay immutable checkpoints, steps, batches and DATA views in memory; they do not run or commit a live training job, publish weights, roll back effects, or establish finality.",
            "SENSOR": "The TRAIN sources read selected retained bytes and never acquire a live hardware, process or training-system signal; their runtime-identity record is compatibility context, not sensor telemetry.",
            "CONTROLLER": "Optimizer equations are replayed over retained checkpoints, but these sources do not operate a live feedback loop, choose training commands, assert stability, or intervene in a running trainer.",
            "ACTUATOR": "Retained weight updates describe a claimed training trace. The checker does not command a trainer, mutate model weights, allocate an accelerator, publish a checkpoint, or expose a command-to-effect interface.",
            "POLICY": "The TRAIN contracts select exact source, runtime, child DATA, arithmetic, tolerance and finite-limit rules and enforce contradictions or unavailability without promoting either to PASS.",
        },
        _TRAIN_POLICY,
        subject="The exact TRAIN replay and DATA-bridge sources",
        refuted=("LEDGER", "TRANSACTION", "ASSET", "MARKET", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"),
    ),
    "vstd-hypergraph": _review(
        "HYPER",
        _HYPER_PATHS,
        {"POLICY": _HYPER_PATHS},
        {
            "POLICY": "The HYPER sources install exact operand selection, closure, UNKNOWN absorption and weakest-ceiling rules with current route and child replay enforcement.",
            "PROTOCOL": "HYPER operands and replayed child certificates form a finite composition graph, not communicating participants or a message-delivery state machine with liveness semantics.",
        },
        _HYPER_POLICY,
        subject="The exact HYPER closure and composed-ceiling sources",
        refuted=("LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"),
    ),
    "vstd-model": _review(
        "MODEL",
        _MODEL_OWNED_PATHS,
        {
            "TRANSACTION": _MODEL_HARDWARE,
            "MEASUREMENT": _MODEL_MEASUREMENT_PATHS,
            "SENSOR": _MODEL_HARDWARE,
            "ACTUATOR": _MODEL_HARDWARE,
            "PROTOCOL": _MODEL_HARDWARE,
            "POLICY": _MODEL_PATHS,
        },
        {
            "TRANSACTION": "MODEL-3.2 freshly creates fixed local child processes under selected memory and time bounds. Process creation, resource consumption, response publication and partial failure require an explicit transaction boundary even though no external model effect is committed.",
            "MEASUREMENT": "The MODEL implementation recomputes finite outputs and metrics and, at MODEL-3.2, freshly observes a selected lower/upper committed-memory execution bracket on the current Windows CPU runtime.",
            "SENSOR": "MODEL-3.2 is a fresh parent-side acquisition route: it applies and verifies Job Object limits before child resume, then captures bounded child status, exit and streams. It is a software sensor, not calibrated physical telemetry.",
            "CONTROLLER": "The MODEL sources evaluate fixed selected inputs and cap trials but do not choose commands from feedback, adapt caps, assert stability, arbitrate controllers, or intervene in a deployed system.",
            "ACTUATOR": "MODEL-3.2 commands a fixed local child process and Job Object under selected caps. Its effect domain is the owned software process only, not a physical actuator or deployed model endpoint.",
            "PROTOCOL": "MODEL-3.2 defines a bounded parent/backend/fixed-worker request and response state machine with pre-resume limit ordering, exact compatibility, timeout and replay rules.",
            "POLICY": "The MODEL sources enforce exact artifacts, child citations, numeric and quantization forms, local runtime selection, hardware caps, expected output and current source bindings under externally selected policies.",
            "ROBOT": "No MODEL source supplies an AGENT, operational HARNESS, adaptive CONTROLLER or physical ACTUATOR chain. Launching the fixed measurement worker is not a sim-to-real or robot pathway.",
            "FINBOT": "The MODEL sources expose no agent, trading or payment decision scope, live-money authority, financial asset or party, settlement path, or exposure limit.",
        },
        _merge(
            _MODEL_TRANSACTION,
            _MODEL_MEASUREMENT,
            _MODEL_SENSOR,
            _MODEL_ACTUATOR,
            _MODEL_PROTOCOL,
            _MODEL_POLICY,
        ),
        subject="The exact MODEL replay, citation, quantization and hardware-observation sources",
        refuted=("LEDGER", "ASSET", "MARKET", "CONTROLLER", "ROBOT", "FINBOT"),
    ),
    "vstd-agent": _review(
        "AGENT",
        _AGENT_PATHS,
        {**_AGENT_RETENTION_PATHS, "POLICY": _AGENT_PATHS},
        {
            "TRANSACTION": "The AGENT sources replay retained decisions, actions, outcomes and claims. They do not execute a tool, mutate external state, establish action commit or finality, compensate effects, or retry an operation.",
            "CONTROLLER": "A retained trajectory contains decisions and observations, but this AGENT object has no bound environment-response loop, control objective, timing model, stability assumption, arbitration or intervention surface; BOT or ROBOT composition supplies materially different consequences.",
            "ACTUATOR": "The AGENT action check confirms that a declared action names a witnessed HARNESS invocation record. It neither establishes the invocation's target or effect nor exposes an owned command-to-effect interface.",
            "PROTOCOL": "AGENT-to-HARNESS certificate binding and transcript order are evidence composition, not an executing participant message protocol with delivery, liveness or recovery semantics.",
            "POLICY": "The AGENT sources derive and enforce a current HARNESS observation ceiling, exact record witnessing, trajectory order, action-to-invocation correspondence, claim support and fail-closed gaps.",
            "ROBOT": "This AGENT review binds no real-world target, CONTROLLER, physical ACTUATOR or sim-to-real crossing. A later HARNESS-to-physical composition would require a distinct ROBOT classification.",
            "FINBOT": "This AGENT review binds no financial assets, parties, market or payment tool, live-money decision authority, settlement effect, or exposure limit. A later financial endpoint would require FINBOT review.",
            **_AGENT_RETENTION_REASONS,
        },
        _merge(_AGENT_RETENTION_DECLARATIONS, _AGENT_POLICY),
        subject="The exact retained AGENT trajectory and ceiling sources",
        refuted=(),
    ),
    "vstd-bot": _review(
        "BOT",
        _BOT_PATHS,
        {
            **_BOT_RETENTION_PATHS,
            "CONTROLLER": _BOT_LOOP,
            "ACTUATOR": _BOT_LOOP,
            "PROTOCOL": _BOT_LOOP,
            "POLICY": _BOT_PATHS,
        },
        {
            "TRANSACTION": "The BOT sources replay immutable AGENT, HARNESS, SIM and ENV records and do not advance a live simulation, commit external state, publish an effect, compensate failure, or assert finality.",
            "MEASUREMENT": "BOT observations are retained SIM projections compared with retained HARNESS outputs. The sources do not freshly acquire a phenomenon or attach observation time, empirical uncertainty and missing-sample semantics.",
            "CONTROLLER": "The BOT object is the selected closed loop that binds simulated feedback to AGENT commands across attributed transitions, so its objectives, envelope, timing, stability exclusions and failure behavior require declaration.",
            "ACTUATOR": "The BOT actuation check binds each retained AGENT invocation input to a SIM action. This is a simulated-only command-to-transition boundary and cannot establish a physical effect.",
            "PROTOCOL": "The BOT sources define participant roles, strict transition/record ordering, replay compatibility and failure handling across AGENT, HARNESS, SIM and ENV certificates.",
            "POLICY": "The BOT sources enforce child identity, transition attribution, observation ceiling, action/observation equality, environment separation and bounded current-policy replay.",
            "ROBOT": "The exact owned BOT sources bind commands only to retained SIM transitions and expose no source-reachable REAL_PHYSICAL endpoint, physical ACTUATOR, or sim-to-real crossing. A SIMULATED_ONLY label alone is never absence evidence; any reachable real endpoint invalidates this refutation.",
            "FINBOT": "The exact owned BOT sources expose no source-reachable REAL_FINANCIAL endpoint, financial asset or party, live trading/payment authority, settlement dependency, or exposure limit. A simulated label alone is never absence evidence; any reachable real-financial path invalidates this refutation.",
            **_BOT_RETENTION_REASONS,
        },
        _merge(
            _BOT_RETENTION_DECLARATIONS,
            _BOT_CONTROLLER,
            _BOT_ACTUATOR,
            _BOT_PROTOCOL,
            _BOT_POLICY,
        ),
        subject="The exact retained BOT closed-loop and inherited-ceiling sources",
        refuted=(),
    ),
    "vstd-token": _review(
        "TOKEN",
        _TOKEN_PATHS,
        {
            "ASSET": _TOKEN_PATHS,
            "PROTOCOL": _TOKEN_PATHS,
            "POLICY": _TOKEN_PATHS,
        },
        {
            "TRANSACTION": "The checker neither issues, delegates, redeems, revokes, transfers nor consumes a token and commits no application effect; it only replays immutable selected records.",
            "ASSET": "A TOKEN records a claimed scoped capability with identity, issuance, delegation, windows, caveats, revocation and backing questions. ASSET applies to that nonfinancial claim while the declaration explicitly denies inferred authority or ownership.",
            "MARKET": "Capability scopes and delegation are not orders, prices, matching, participant market access, allocation, manipulation control or trade settlement.",
            "MEASUREMENT": "Epoch, clock, window, skew and status integers are supplied retained protocol records checked for consistency, not fresh measurements of an external phenomenon.",
            "SENSOR": "The TOKEN sources acquire no live key, status service, clock or application observation; absent or stale retained status remains UNKNOWN rather than sensor output.",
            "CONTROLLER": "Scope attenuation, caveats and revocation are protocol constraints, not a feedback controller choosing commands or asserting stability and intervention behavior.",
            "ACTUATOR": "No token is invoked or redeemed and no application command or effect target is reached; checking a capability claim is not actuation.",
            "PROTOCOL": "TOKEN birth, aging, lease delegation, signature, audience, window and status records define participant roles, ordered state transitions, replay resistance, compatibility and fail-closed progress boundaries.",
            "POLICY": "The TOKEN sources apply externally selected keys, algorithms, trust roots, scope attenuation, caveats, windows, replay ids, clock skew, status freshness and finite limits without turning a signature into authority.",
            "ROBOT": "No TOKEN source binds an AGENT, HARNESS, CONTROLLER or physical ACTUATOR. A capability string or signature creates no physical reach or sim-to-real crossing.",
            "FINBOT": "These are nonfinancial capability claims. No token denotes money or a financial asset, no agent receives trading or transfer authority, and no settlement or exposure path is present.",
        },
        _merge(_TOKEN_ASSET, _TOKEN_PROTOCOL, _TOKEN_POLICY),
        subject="The exact retained capability-TOKEN replay and projection sources",
        refuted=("TRANSACTION", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "ROBOT", "FINBOT"),
    ),
}


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


def _catalog_check() -> None:
    if tuple(_REVIEWS) != ORIGINAL_OBJECT_IDS:
        raise AssertionError("original review object order differs")
    owned: dict[str, str] = {}
    for object_id, review in _REVIEWS.items():
        if set(review.reasons) != set(REVIEW_KINDS):
            raise AssertionError(object_id + " does not decide all twelve added kinds")
        if len(review.refuted) != len(set(review.refuted)):
            raise AssertionError(object_id + " repeats a refuted kind")
        if not set(review.refuted) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " refutes an unsupported kind")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " applies and refutes one kind")
        if any(not reason.strip() for reason in review.reasons.values()):
            raise AssertionError(object_id + " contains a blank applicability reason")
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if any(
            not paths or not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence is outside owned source")
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
            prior = owned.setdefault(path, object_id)
            if prior != object_id:
                raise AssertionError(
                    path + " owned by both " + prior + " and " + object_id
                )
    if len(owned) != 30:
        raise AssertionError("original review must own exactly 30 current paths")


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return the deterministic human-inspectable seven-object review."""
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
                    "evidence_paths": list(
                        review.role_paths[kind]
                        if _basis(review, kind) == "APPLIES"
                        else review.owned_paths
                        if _basis(review, kind) == "DOES_NOT_APPLY"
                        else ()
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
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SURFACES_INVALID")
    file_surfaces = [surface for surface in surfaces if surface.startswith("file:")]
    if len(file_surfaces) != len(set(file_surfaces)):
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SURFACES_INVALID")
    return {surface.removeprefix("file:") for surface in file_surfaces}


def _migration_owned_paths(paths: set[str], review: _Review) -> set[str]:
    """Select this object's paths with the migration's exact owner rule.

    Domain implementations are explicit reviewed owners.  Every candidate
    census file below ``domains/contracts`` is owned from the stem segment
    before its first underscore, independent of suffix or nesting.
    """
    contract_prefix = "src/verifier/domains/contracts/"
    current = {
        path
        for path in paths
        if path.startswith(contract_prefix)
        and Path(path).stem.split("_", 1)[0].upper() == review.primary_kind
    }
    current.update(
        path
        for path in review.owned_paths
        if path.startswith("src/verifier/domains/")
        and not path.startswith("src/verifier/domains/contracts/")
        and path in paths
    )
    return current


def _live_migration_paths(root: Path) -> set[str]:
    """Observe the migration's Git-tracked plus nonignored-untracked paths.

    Synthetic isolated tests need no Git repository, so their complete regular
    file tree is the equivalent source census.  The production route uses the
    same Git selectors as repository discovery and therefore excludes ignored
    caches rather than mistaking ``__pycache__`` entries for owned contracts.
    """
    try:
        return set(_git_tracked_paths(root, allow_empty=True)) | set(
            _git_untracked_paths(root)
        )
    except EstateError:
        return {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        }


def _ensure_migration_denominator(
    candidate_paths: set[str],
    live_paths: set[str],
    object_id: str,
    review: _Review,
) -> None:
    expected = set(review.owned_paths)
    if (
        _migration_owned_paths(candidate_paths, review) != expected
        or _migration_owned_paths(live_paths, review) != expected
    ):
        raise ValueError(
            "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_MIGRATION_DENOMINATOR_CHANGED:"
            + object_id
        )


def _source_snapshot(
    root: Path,
    paths: tuple[str, ...],
    *,
    object_id: str,
) -> list[dict[str, str]]:
    """Read every ordinary owned file at one explicit evidence coordinate."""
    evidence: list[dict[str, str]] = []
    for path in paths:
        try:
            candidate = root / Path(path)
            selected = root
            for part in Path(path).parts:
                selected /= part
                information = selected.lstat()
                if selected.is_symlink() or (
                    getattr(information, "st_file_attributes", 0) & 0x400
                ):
                    raise OSError("symbolic or reparse source path")
            target = candidate.resolve(strict=True)
            target.relative_to(root)
            if not stat.S_ISREG(target.stat().st_mode):
                raise OSError("source path is not a regular file")
            digest = _digest(target.read_bytes())
        except (OSError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SOURCE_UNAVAILABLE:"
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
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SOURCE_DIFFERS:"
                + object_id
                + ":"
                + reference["path"]
            )
    return evidence


def _validate_candidate_evidence(
    evidence: Any,
    files: Mapping[str, str],
    owned: set[str],
    *,
    code: str,
) -> None:
    """Accept only current owned references on an exact blank migration row."""
    if type(evidence) is not list:
        raise ValueError(code)
    seen: set[str] = set()
    for reference in evidence:
        if (
            type(reference) is not dict
            or set(reference) != {"path", "sha256"}
            or type(reference["path"]) is not str
            or type(reference["sha256"]) is not str
            or reference["path"] in seen
            or reference["path"] not in owned
            or files.get(reference["path"]) != reference["sha256"]
        ):
            raise ValueError(code)
        seen.add(reference["path"])


def _validate_complete_evidence(
    evidence: Any,
    files: Mapping[str, str],
    expected_paths: tuple[str, ...],
    *,
    code: str,
) -> None:
    """A preserved answer must cover its complete reviewed denominator."""
    if type(evidence) is not list or len(evidence) != len(expected_paths):
        raise ValueError(code)
    by_path: dict[str, str] = {}
    for reference in evidence:
        if (
            type(reference) is not dict
            or set(reference) != {"path", "sha256"}
            or type(reference["path"]) is not str
            or type(reference["sha256"]) is not str
            or reference["path"] in by_path
        ):
            raise ValueError(code)
        by_path[reference["path"]] = reference["sha256"]
    if set(by_path) != set(expected_paths) or any(
        files.get(path) != digest for path, digest in by_path.items()
    ):
        raise ValueError(code)


def _preserve_decision(
    decision: Any,
    expected: Mapping[str, Any] | None,
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    kind: str,
) -> bool:
    code = (
        "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_DECISION_CONFLICT:"
        + object_id
        + ":"
        + kind
    )
    if type(decision) is not dict or set(decision) != {"status", "reason", "evidence"}:
        raise ValueError(code)
    if decision["status"] == "UNRESOLVED":
        expected_reason = (
            "Migration retains this applicability question. Static ownership "
            "alone cannot refute a " + kind + " role."
        )
        if decision["reason"] != expected_reason:
            raise ValueError(code)
        _validate_candidate_evidence(decision["evidence"], files, owned, code=code)
        return False
    if expected is None or decision != expected:
        raise ValueError(code)
    return True


def _blank_candidate(
    binding: Mapping[str, Any],
    fields: tuple[str, ...],
    files: Mapping[str, str],
    owned: set[str],
    *,
    code: str,
) -> bool:
    declaration = binding.get("declaration")
    blank = (
        set(binding) == {"reason", "evidence", "declaration"}
        and binding.get("reason") == ""
        and type(binding.get("evidence")) is list
        and type(declaration) is dict
        and set(declaration) == set(fields)
        and all(value == "" for value in declaration.values())
    )
    if blank:
        _validate_candidate_evidence(binding["evidence"], files, owned, code=code)
    return blank


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
        "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id
    )
    if type(binding) is not dict:
        raise ValueError(code)
    if _blank_candidate(binding, fields, files, owned, code=code):
        return False
    if set(binding) != {"reason", "evidence", "declaration"}:
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


def apply_package_original_review_computation(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
    *,
    record_gaps: bool = False,
    gaps: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Apply all seven current-source reviews to a deep copy or change nothing.

    A refutation whose kind the owned code names cannot stand.  By default that
    aborts.  With ``record_gaps`` the refutation is reopened as the canonical open
    question instead (never as an exemption) and reported in ``gaps``; only the
    catalog's own generated refutation may be replaced that way.
    """
    selected_root = Path(root).resolve(strict=True)
    if type(rows) is not dict:
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_COMPUTATION_ROWS_INVALID")
    if type(files) is not dict or any(
        type(path) is not str or type(digest) is not str
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_COMPUTATION_FILES_INVALID")

    registered_questions = set(namespace_registry()) - {"OBJECT"}
    known_obligations = {
        obligation["id"] for kind in REVIEW_KINDS for obligation in _requirements(kind)
    }
    candidate_paths = set(files)
    opening_paths = _live_migration_paths(selected_root)
    plans: dict[str, dict[str, Any]] = {}
    for object_id, review in _REVIEWS.items():
        row = rows.get(object_id)
        if type(row) is not dict:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_OBJECT_MISSING:" + object_id
            )
        if row.get("object_id") != object_id or row.get("kind") != review.primary_kind:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_PRIMARY_KIND_DIFFERS:" + object_id
            )
        _ensure_migration_denominator(candidate_paths, opening_paths, object_id, review)
        owned = _owned_file_paths(row)
        if owned != set(review.owned_paths):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_OWNERSHIP_DIFFERS:" + object_id
            )
        owned_words = _mechanism_words(selected_root, object_id, review.owned_paths)
        evidence = _current_evidence(
            selected_root, review.owned_paths, files, object_id=object_id
        )
        evidence_by_path = {item["path"]: item for item in evidence}
        classification = row.get("classification")
        obligations = row.get("obligations")
        specializations = row.get("specializations")
        if (
            not _has_complete_foreign_questions(
                classification, registered_questions
            )
            or type(obligations) is not dict
            or not set(obligations) <= known_obligations
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_BINDINGS_INVALID:" + object_id
            )
        if (
            type(specializations) is not list
            or any(type(kind) is not str for kind in specializations)
            or len(specializations) != len(set(specializations))
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SPECIALIZATIONS_INVALID:"
                + object_id
            )
        if any(
            kind == "OBJECT" or kind not in registered_questions
            for kind in specializations
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SPECIALIZATION_UNREGISTERED:"
                + object_id
            )

        preserve_decisions: set[str] = set()
        preserve_obligations: set[str] = set()
        remove_obligations: set[str] = set()
        reopened: dict[str, list[str]] = {}
        for kind in REVIEW_KINDS:
            basis = _basis(review, kind)
            if basis == "DOES_NOT_APPLY" and owned_words & _MECHANISM_WORDS[kind]:
                if not record_gaps:
                    raise ValueError(
                        "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_MECHANISM_CONTRADICTS_REFUTATION:"
                        + object_id
                        + ":"
                        + kind
                    )
                reopened[kind] = sorted(owned_words & _MECHANISM_WORDS[kind])
                basis = "UNRESOLVED"
            if basis != "APPLIES" and (row["kind"] == kind or kind in specializations):
                raise ValueError(
                    "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_LABEL_CONFLICT:"
                    + object_id
                    + ":"
                    + kind
                )
            decision_paths = (
                review.role_paths[kind]
                if basis == "APPLIES"
                else review.owned_paths
            )
            expected_decision = None
            if basis != "UNRESOLVED":
                expected_decision = {
                    "status": basis,
                    "reason": review.reasons[kind],
                    "evidence": [
                        deepcopy(evidence_by_path[path]) for path in decision_paths
                    ],
                }
            generated_refutation = {
                "status": "DOES_NOT_APPLY",
                "reason": review.reasons.get(kind),
                "evidence": [
                    deepcopy(evidence_by_path[path]) for path in review.owned_paths
                ],
            }
            if kind in reopened and classification[kind] == generated_refutation:
                pass
            elif _preserve_decision(
                classification[kind],
                expected_decision,
                files,
                owned,
                object_id=object_id,
                kind=kind,
            ):
                preserve_decisions.add(kind)
            for obligation in _requirements(kind):
                obligation_id = obligation["id"]
                fields = tuple(obligation["declaration_fields"])
                binding = obligations.get(obligation_id)
                if basis == "APPLIES":
                    expected_evidence = [
                        deepcopy(evidence_by_path[path])
                        for path in review.role_paths[kind]
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
                        "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_REFUTED_DECLARATION_CONFLICT:"
                        if basis == "DOES_NOT_APPLY"
                        else "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_UNLISTED_DECLARATION_CONFLICT:"
                    )
                    code = prefix + object_id + ":" + obligation_id
                    if type(binding) is not dict or not _blank_candidate(
                        binding, fields, files, owned, code=code
                    ):
                        raise ValueError(code)
                    remove_obligations.add(obligation_id)
        plans[object_id] = {
            "evidence_by_path": evidence_by_path,
            "preserve_decisions": preserve_decisions,
            "preserve_obligations": preserve_obligations,
            "remove_obligations": remove_obligations,
            "reopened": reopened,
        }

    # Conflict analysis can be nontrivial. Re-read the entire denominator before
    # copying so a concurrent edit or newly owned contract cannot inherit the
    # opening coordinate while escaping the evidence census.
    closing_paths = _live_migration_paths(selected_root)
    for object_id, review in _REVIEWS.items():
        _ensure_migration_denominator(candidate_paths, closing_paths, object_id, review)
        closing = _source_snapshot(
            selected_root, review.owned_paths, object_id=object_id
        )
        if {item["path"]: item for item in closing} != plans[object_id][
            "evidence_by_path"
        ]:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SOURCE_CHANGED:" + object_id
            )

    result = deepcopy(rows)
    for object_id, review in _REVIEWS.items():
        row = result[object_id]
        plan = plans[object_id]
        for kind in REVIEW_KINDS:
            if kind in plan["preserve_decisions"]:
                continue
            basis = "UNRESOLVED" if kind in plan["reopened"] else _basis(review, kind)
            if basis == "UNRESOLVED":
                row["classification"][kind] = _canonical_migration_question(kind)
                if kind in plan["reopened"] and gaps is not None:
                    gaps.append(
                        {
                            "stage": "computation",
                            "object_id": object_id,
                            "kind": kind,
                            "gap": "REFUTATION_REOPENED_MECHANISM_WORD",
                            "words": list(plan["reopened"][kind]),
                        }
                    )
            else:
                paths = (
                    review.role_paths[kind]
                    if basis == "APPLIES"
                    else review.owned_paths
                )
                row["classification"][kind] = {
                    "status": basis,
                    "reason": review.reasons[kind],
                    "evidence": [
                        deepcopy(plan["evidence_by_path"][path]) for path in paths
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
                    for path in review.role_paths[kind]
                ],
                "declaration": dict(declaration),
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)

    # Copy construction is not instantaneous. Bind the return value to a final
    # complete denominator and byte reread as well as the opening and
    # post-preflight snapshots.
    final_paths = _live_migration_paths(selected_root)
    for object_id, review in _REVIEWS.items():
        _ensure_migration_denominator(candidate_paths, final_paths, object_id, review)
        final = _source_snapshot(selected_root, review.owned_paths, object_id=object_id)
        if {item["path"]: item for item in final} != plans[object_id][
            "evidence_by_path"
        ]:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SOURCE_CHANGED:" + object_id
            )
    return result


__all__ = [
    "REVIEW_KINDS",
    "ORIGINAL_OBJECT_IDS",
    "CLAIM_BOUNDARY",
    "review_document",
    "apply_package_original_review_computation",
]
