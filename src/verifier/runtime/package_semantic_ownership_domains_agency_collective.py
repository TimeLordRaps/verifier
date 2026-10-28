"""Audited original-domain ownership for seven retained primary kinds: ACTOR, AGENT, BOT, COLLECTIVE, BENCH, HUMAN and ARCH.

Terminology: identifier (ID).

Terminology: Verifier Standard (VSTD); computational model architecture (ARCH); abstract
syntax tree (AST); Secure Hash Algorithm 256-bit (SHA-256). Primary kinds are preserved
exactly as declared by their owning source. Accumulated consequence roles are decided only
from executable mechanisms in the owned source bytes; a file name, a docstring, a label
constant, a checker policy parameter, a closed key schema, or a primary kind is never
evidence for a role.

This data-first module declares exactly 25 source paths: ``domains/actor.py``,
``domains/agent.py``, ``domains/bot.py``, ``domains/collective.py``, ``domains/bench.py``,
``domains/human.py`` and the contract files of those kinds plus the three ARCH contracts.
It imports only the path-independent model constructors and never imports the aggregate
catalog or a sibling ownership batch, so it can be aggregated later without cycles.

Every (object, accumulating role) cell is exactly one of two things. A ``SourceRoleDecision``
records APPLIES or DOES_NOT_APPLY, and each carries an applicability mode, cited spans, a
reason, a next action and an executable checker. A ``SourceRoleUnresolved`` record marks the
cell UNKNOWN; it carries the same fields and an optional integration blocker. Silence,
an unread field, a label constant, a primary kind, or a closed exact-key schema never decides
a cell. APPLIES for ACTUATOR needs an effect-bearing refutation, APPLIES for PROTOCOL needs a
failure or liveness refutation, and DOES_NOT_APPLY needs an executable refutation of the role's
defining consequence. A closed key set bounds which keys a row carries, not which values are
permitted, so it decides nothing. An invocation comparison or a replayed action list is not an
effect endpoint. TRANSACTION needs atomicity, retry, partial failure, compensation and finality
source-established before it is decided at all.

The shared ``RootRoleDecision`` type cannot encode UNKNOWN. Root applicability is therefore the
exact batch-local mapping ``ROOT_APPLICABILITY``; a root that is not source-established is mapped
UNKNOWN and exported with no root decision. ``OBJECT`` is never a fallback.

The sole authored ``reasons.vstd`` may separately choose conservative APPLIES to retain an
obligation without asserting that the owned source establishes that consequence. Those choices
are recorded in ``OBLIGATION_RETENTION_APPLIES`` and become declared specializations, but they do
not masquerade as ``SourceRoleDecision`` mechanism evidence. They are therefore excluded from
the UNKNOWN denominator while remaining distinguishable from source-established roles.

Typed operand slots required by the namespace layout (ACTOR, AGENT, BOT, BENCH and
COLLECTIVE) are bound to the unique retained registry objects of their required kinds.
Those exact identifiers are recorded in ``_OPERAND_TARGETS`` and are revalidated by the
aggregate catalog; no placeholder target or inferred identifier is accepted.

Claim boundary: ownership and role-applicability data for the named source bytes only. It
establishes neither mechanism truth, obligation fulfillment, admission into the package
graph, physical or financial effect, authority, release, nor deployment. A simulation label
exempts no real physical or financial consequence; ROBOT and FINBOT stay UNKNOWN for BOT.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Literal, Mapping, cast

from verifier.runtime.package_semantic_ownership_model import (
    RootRoleDecision,
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


PRIMARY_KINDS = ("ACTOR", "AGENT", "ARCH", "BENCH", "BOT", "COLLECTIVE", "HUMAN")

# The twelve registered specializations of OBJECT.  Every decision row names one of
# these or the VERIFIER root; any other role is rejected rather than inferred.
ACCUMULATING_ROLES = (
    "ACTUATOR",
    "ASSET",
    "CONTROLLER",
    "FINBOT",
    "LEDGER",
    "MARKET",
    "MEASUREMENT",
    "POLICY",
    "PROTOCOL",
    "ROBOT",
    "SENSOR",
    "TRANSACTION",
)
# Obligation-retention applicability chosen in the sole authored reasons.vstd.
# This is deliberately distinct from SOURCE_ROLE_DECISIONS: it retains every added-kind
# obligation for the open-ended AGENT boundary while claiming no actuator, financial,
# physical, protocol, policy, or other external effect.
OBLIGATION_RETENTION_APPLIES: dict[str, tuple[str, ...]] = {
    "vstd-actor": tuple(role for role in ACCUMULATING_ROLES if role != "POLICY"),
    "vstd-agent": ACCUMULATING_ROLES,
    "vstd-architecture": ACCUMULATING_ROLES,
    "vstd-benchmark": tuple(role for role in ACCUMULATING_ROLES if role != "MEASUREMENT"),
    "vstd-bot": ACCUMULATING_ROLES,
    "vstd-collective": tuple(role for role in ACCUMULATING_ROLES if role not in {"LEDGER", "POLICY"}),
    "vstd-human": ACCUMULATING_ROLES,
}


def obligation_retention_reason(object_id: str, kind: str) -> str:
    """Return the exact non-mechanism rationale for one retained obligation kind."""
    if kind not in OBLIGATION_RETENTION_APPLIES.get(object_id, ()):
        raise ValueError("BATCH_OBLIGATION_RETENTION_UNDECLARED")
    return (
        "The sole authored reasons.vstd conservatively selects APPLIES for "
        + object_id
        + " as "
        + kind
        + " so every "
        + kind
        + " obligation remains required while the owned closed-effect boundary "
        "is open. This obligation-retention decision is distinct from source-role "
        "evidence and establishes neither a concrete mechanism, authority, external "
        "effect, occurrence, checker PASS, nor Tier-1-plus fulfillment."
    )
ROOT_ROLE = "VERIFIER"
DECIDED_ROLES = (*ACCUMULATING_ROLES, ROOT_ROLE)
STATUSES = ("APPLIES", "DOES_NOT_APPLY")
UNKNOWN = "UNKNOWN"

_OBJECT_ID = re.compile(r"[a-z][a-z0-9-]{2,95}")
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PATH_PREFIX = "src/verifier/"
_D = "src/verifier/domains/"
_C = "src/verifier/domains/contracts/"
_RECHECK = "none in this batch; re-audit the cited span if its source digest changes"


@dataclass(frozen=True)
class SourceEvidence:
    """One executable source span, with a marker that must occur inside it."""

    path: str
    symbol: str
    start_line: int
    end_line: int
    marker: str


@dataclass(frozen=True)
class SourceRoleDecision:
    """APPLIES or DOES_NOT_APPLY for one role of one object, with evidence.

    ``applicability`` is ``UNCONDITIONAL`` or ``CONDITIONAL: <dispatch condition>``, naming the
    check branch in which the cited span executes.
    """

    object_id: str
    role: str
    status: Literal["APPLIES", "DOES_NOT_APPLY"]
    evidence: tuple[SourceEvidence, ...]
    reason: str
    applicability: str
    next_action: str
    checker: str


@dataclass(frozen=True)
class SourceRoleUnresolved:
    """UNKNOWN for one role of one object.

    ``evidence`` holds the spans that were examined and do not establish or refute the role.
    ``blocker`` names an explicit integration blocker when one applies; empty means unaudited.
    """

    object_id: str
    role: str
    applicability: Literal["UNKNOWN"]
    evidence: tuple[SourceEvidence, ...]
    reason: str
    blocker: str
    next_action: str
    checker: str


# Root reasons cite the executable condition token that refutes, never a Refuted message.
_ROOT_REASONS = {
    "vstd-actor": "actor.py evaluate, under check == 'identity', refutes an overlapping boundary through the executable test `actor_components & instrument_components` and a self-instrument declaration through `actor_id in instrument_components`, so the identity check is a native verifier of its boundary.",
    "vstd-agent": "agent.py evaluate, under check == 'actions', refutes a declared action through the executable membership test `(text(action['tool']), action['record']) not in invocations` over the bound harness invocations, so the actions check is a native verifier.",
    "vstd-bot": "bot.py containment refutes an invalid separation through `separation not in SEPARATIONS`, and bot.py loop refutes an observation or action the simulation projection does not reproduce through `observations[transition + 1]` and `actions[transition]`; both are native verifier checks.",
    "vstd-benchmark": "bench.py evaluate, under check in ('oracles', 'coverage'), refutes a recomputed weighted score through the executable comparison `score < expected` against the declared minimum_score, so the oracle replay is the native verifier of the score.",
    "vstd-collective": "collective.py _decisions, under check in ('decisions', 'quorum'), refutes a collective decision through `component_roles != required[decision_class]`, so the decision replay is a native verifier of the declared assembly policy.",
    "vstd-human": "human.py _assertion refutes only the enumerated population denylist through the membership test `population.lower() in {'global', 'worldwide', 'all-humans', 'all humans'}` over four literal declarations; it establishes no population uniqueness beyond that denylist.",
    "vstd-architecture": "arch_schedule.py _evaluate refutes a schedule that does not cover the retained graph nodes through `len(position) != len(nodes)`, so the execution-order replay is a native verifier.",
}

# Root applicability: an exact batch-local mapping over every owned object.  The shared root type
# cannot encode UNKNOWN, so an UNKNOWN root is exported with no root decision.
ROOT_APPLICABILITY: dict[str, str] = {
    "vstd-actor": "APPLIES",
    "vstd-agent": "APPLIES",
    "vstd-bot": "APPLIES",
    "vstd-collective": "APPLIES",
    "vstd-benchmark": "APPLIES",
    "vstd-human": "APPLIES",
    "vstd-architecture": "APPLIES",
}
_ROOT_STATUSES = (*STATUSES, UNKNOWN)


def _ev(path: str, symbol: str, start: int, end: int, marker: str) -> SourceEvidence:
    return SourceEvidence(path=path, symbol=symbol, start_line=start, end_line=end, marker=marker)


def _applies(
    object_id: str,
    role: str,
    reason: str,
    applicability: str,
    checker: str,
    *evidence: SourceEvidence,
    next_action: str = _RECHECK,
) -> SourceRoleDecision:
    return SourceRoleDecision(
        object_id, role, "APPLIES", tuple(evidence), reason, applicability, next_action, checker,
    )


def _verifier(object_id: str, applicability: str, *evidence: SourceEvidence) -> SourceRoleDecision:
    return _applies(
        object_id, ROOT_ROLE, _ROOT_REASONS[object_id], applicability,
        "test_root_role_decision_must_match_the_decision_table", *evidence,
    )


_GOLDEN = "test_decision_table_is_golden_and_specializations_follow_applies_only"

# Each row decides only the roles its source supports; all other roles are UNKNOWN.
SOURCE_ROLE_DECISIONS: tuple[SourceRoleDecision, ...] = tuple(sorted((
    # ACTOR: accountable party.  Instruments stay outside the actor; no actuator is decided here.
    _verifier("vstd-actor", "CONDITIONAL: check == 'identity'",
              _ev(_D + "actor.py", "evaluate", 35, 36, "actor_components & instrument_components"),
              _ev(_D + "actor.py", "evaluate", 37, 37, "actor_id in instrument_components")),
    _applies(
        "vstd-actor", "POLICY",
        "actor.py evaluate enforces delegation and revocation events: a delegated subset must lie inside the declared decision classes (set(subset) <= set(decision_classes), line 62), and each event kind changes the active delegation set (lines 64-71).",
        "CONDITIONAL: check == 'delegation'", _GOLDEN,
        _ev(_D + "actor.py", "evaluate", 62, 63, "set(subset) <= set(decision_classes)"),
        _ev(_D + "actor.py", "evaluate", 64, 71, "active_delegations[delegate] = subset"),
    ),

    # AGENT: open-ended trajectory.  The invocation match is the only actuation-shaped mechanism;
    # it is not an effect endpoint, so ACTUATOR is UNKNOWN rather than APPLIES.
    _verifier("vstd-agent", "CONDITIONAL: check == 'actions'",
              _ev(_D + "agent.py", "evaluate", 64, 65, "not in invocations")),

    # BOT: simulation-situated closed loop.  Its consequence domain is not decided here.
    _verifier("vstd-bot", "CONDITIONAL: check in ('containment', 'observation', 'actuation')",
              _ev(_D + "bot.py", "containment", 109, 110, "separation not in SEPARATIONS"),
              _ev(_D + "bot.py", "loop", 98, 100, "observations[transition + 1]"),
              _ev(_D + "bot.py", "loop", 102, 103, "actions[transition]")),

    # COLLECTIVE: assembled decisions over ROLE components.
    _verifier("vstd-collective", "CONDITIONAL: check in ('decisions', 'quorum')",
              _ev(_D + "collective.py", "_decisions", 111, 112, "component_roles != required[decision_class]")),
    _applies(
        "vstd-collective", "LEDGER",
        "collective_closure.py _declared_ledger refutes a duplicate decision identifier, an instant earlier than its predecessor, or an out-of-period instant in the retained ROLE inventory (instant < previous), and returns the one complete ordered ledger that component references are matched against. It is reached only when the freshly replayed ROLE closure status is neither PASS nor FAIL (collective_closure.py _evaluate, lines 420-424).",
        "CONDITIONAL: the freshly replayed ROLE closure status is neither PASS nor FAIL (collective_closure.py _evaluate lines 420-424) and a retained selected ROLE inventory of the current evidence version is present; _declared_ledger returns None otherwise",
        _GOLDEN,
        _ev(_C + "collective_closure.py", "_declared_ledger", 304, 305, "instant < previous"),
        _ev(_C + "collective_closure.py", "_evaluate", 422, 424, 'status != "PASS"'),
    ),
    _applies(
        "vstd-collective", "POLICY",
        "collective.py _decisions enforces the assembly policy: set(policy) != decision_classes refutes a policy that does not cover every declared decision class (line 60), and component_roles != required[decision_class] refutes each collective decision that departs from its declared required roles (line 111); both run under check in ('decisions', 'quorum').",
        "CONDITIONAL: check in ('decisions', 'quorum')", _GOLDEN,
        _ev(_D + "collective.py", "_decisions", 59, 61, "set(policy) != decision_classes"),
        _ev(_D + "collective.py", "_decisions", 111, 112, "component_roles != required[decision_class]"),
    ),

    # ARCH: static computational graph declarations.  Its SCOPE label decides no role.
    _verifier("vstd-architecture",
              "CONDITIONAL: schedule entries validated before node coverage (arch_schedule.py _evaluate 242-248)",
              _ev(_C + "arch_schedule.py", "_evaluate", 249, 250, "len(position) != len(nodes)")),

    # BENCH: specification graph with finite oracles and retained resource observations.
    _verifier("vstd-benchmark", "CONDITIONAL: check in ('oracles', 'coverage')",
              _ev(_D + "bench.py", "evaluate", 99, 100, "score < expected")),
    _applies(
        "vstd-benchmark", "MEASUREMENT",
        "bench.py evaluate, under check == 'budgets', compares retained execution_ms and peak_memory_bytes observations with declared timeout and memory bounds (line 88), so the retained resource observations are consequential under that check. Uncertainty and method are not declared here.",
        "CONDITIONAL: check == 'budgets'", "test_bench_measurement_is_conditional_on_the_budgets_check",
        _ev(_D + "bench.py", "evaluate", 88, 89, "not 0 <= run[field] <= problem[bound]"),
    ),

    # HUMAN: retained assertion metadata; no declaration authenticates a person.
    _verifier("vstd-human", "UNCONDITIONAL: _assertion runs before every human check",
              _ev(_D + "human.py", "_assertion", 30, 31, "population.lower() in")),
), key=lambda row: (row.object_id, row.role)))


# Explicit UNKNOWN records.  Each names the spans it examined, why they decide nothing, the
# blocker or audit step, and the checker that pins the cell.  Keys must be undecided cells.
_UNKNOWN_CHECKER_CONTROLLER = "test_bot_controller_is_unknown_not_applies_by_runtime_limits_or_routing"
_UNKNOWN_CHECKER_ARCH = "test_arch_roles_are_unknown_and_never_inherit_from_the_scope_label"
_UNKNOWN_CHECKER_TRANSACTION = "test_transaction_is_never_dna_by_absence_of_commit_or_retry_fields"
_UNKNOWN_CHECKER_HUMAN = "test_human_absence_of_controller_actuator_robot_finbot_is_unknown_not_silence_based_dna"
_UNKNOWN_CHECKER_AGENT_ACTUATOR = "test_mutant_1_agent_actuator_applies_is_unknown_not_invocation_match"
_UNKNOWN_CHECKER_BOT_ACTUATOR = "test_mutant_2_bot_actuator_applies_is_unknown_not_replayed_action_list"
_UNKNOWN_CHECKER_PROTOCOL = "test_mutant_3_collective_protocol_applies_is_unknown_without_failure_or_liveness"
_UNKNOWN_CHECKER_HUMAN_CONTROLLER = "test_mutant_4_human_controller_dne_is_unknown_without_feedback_law_refutation"
_UNKNOWN_CHECKER_ACTOR_ACTUATOR = "test_mutant_5_actor_actuator_dne_is_unknown_not_boundary_overlap"
_UNKNOWN_CHECKER_COLLECTIVE_SCHEMA = "test_mutant_6_collective_closed_schema_dne_is_unknown"
_UNKNOWN_CHECKER_BENCH_SCHEMA = "test_mutant_7_bench_closed_schema_dne_is_unknown"
_TRANSACTION_NEXT = (
    "Source-establish or refute atomicity, retry, partial failure, compensation and finality "
    "for this object; a closed row schema alone does not decide TRANSACTION."
)


def _unknown(
    object_id: str,
    role: str,
    reason: str,
    next_action: str,
    checker: str,
    *evidence: SourceEvidence,
    blocker: str = "",
) -> SourceRoleUnresolved:
    return SourceRoleUnresolved(object_id, role, UNKNOWN, tuple(evidence), reason, blocker, next_action, checker)


_ARCH_SCOPE_LABEL = _ev(_C + "arch_schedule.py", "SCOPE", 37, 37, "selected_static_graph_execution_order")
_ARCH_REPLAY = _ev(_C + "arch_schedule.py", "_evaluate", 244, 245, "name not in names")

_EXPLICIT_UNKNOWN: dict[tuple[str, str], SourceRoleUnresolved] = {
    ("vstd-bot", "ACTUATOR"): _unknown(
        "vstd-bot", "ACTUATOR",
        "bot.py loop under check == 'actuation' (lines 92, 101-103) compares each retained invocation input with the simulation's recorded action list. Comparing two retained lists is neither real actuation nor an executed transition, and establishes no effect on the simulation or any environment, so ACTUATOR is UNKNOWN.",
        "Bind an executed simulation transition and a real effect endpoint for each replayed action with an executable check; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_BOT_ACTUATOR,
        _ev(_D + "bot.py", "loop", 92, 92, 'need(world, "actions")'),
        _ev(_D + "bot.py", "loop", 101, 103, "actions[transition]"),
        blocker="BOT-ACTUATOR-EXECUTED-TRANSITION",
    ),
    ("vstd-bot", "CONTROLLER"): _unknown(
        "vstd-bot", "CONTROLLER",
        "bot.py loop under the observation check (lines 98-100) equates each retained observation with the simulation projection after a transition. That is correspondence, not control: the batch finds no feedback law or error signal that selects an action, no declared control authority, no timing or stability bound, and no intervention semantics. Runtime limits and routing in the bound ceilings do not establish CONTROLLER. No refutation exists.",
        "Obtain a source that declares feedback, control authority, timing and stability bounds and intervention semantics for the loop, with an executable check; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_CONTROLLER,
        _ev(_D + "bot.py", "loop", 98, 100, "observations[transition + 1]"),
        blocker="BOT-CONTROLLER-SEMANTICS",
    ),
    ("vstd-actor", "ACTUATOR"): _unknown(
        "vstd-actor", "ACTUATOR",
        "actor.py attribution check (lines 151-152) refutes an instrument that is also an actor component. That bounds the boundary overlap; it does not refute that an instrument executes or effects an action, and no effect-bearing refutation exists in the actor sources, so this batch leaves ACTUATOR undecided rather than declaring DOES_NOT_APPLY.",
        "Establish or refute an instrument's effect endpoint with an executable effect-bearing check; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_ACTOR_ACTUATOR,
        _ev(_D + "actor.py", "evaluate", 151, 152, "in actor_components"),
        blocker="ACTOR-ACTUATOR-EFFECT-ENDPOINT",
    ),
    ("vstd-actor", "TRANSACTION"): _unknown(
        "vstd-actor", "TRANSACTION",
        "actor.py evaluate attribution rows are a closed exact-key schema (line 139) with no effect, commit or retry field. Closure of the row schema does not decide TRANSACTION: atomic multi-decision commit, retry, partial failure, compensation and finality are neither established nor refuted anywhere in the owned source.",
        _TRANSACTION_NEXT, _UNKNOWN_CHECKER_TRANSACTION,
        _ev(_D + "actor.py", "evaluate", 139, 139, "decision_class"),
    ),
    ("vstd-collective", "PROTOCOL"): _unknown(
        "vstd-collective", "PROTOCOL",
        "collective_closure.py _evaluate applies participant membership (line 366), order and time (line 355), quorum (lines 369-370) and class-membership (lines 371-374) refutations. None models participant failure, timeout, recovery or progress, and no executable liveness refutation exists in the collective sources, so an assembly rule is not a participant protocol. PROTOCOL is UNKNOWN.",
        "Source-establish participant failure, timeout, recovery and progress semantics with an executable refutation; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_PROTOCOL,
        _ev(_C + "collective_closure.py", "_evaluate", 355, 355, "instant < previous"),
        _ev(_C + "collective_closure.py", "_evaluate", 366, 366, "not in members"),
        _ev(_C + "collective_closure.py", "_evaluate", 369, 370, "len(component_roles) < quorum"),
        _ev(_C + "collective_closure.py", "_evaluate", 371, 374, "classes is not None"),
        blocker="COLLECTIVE-PROTOCOL-FAILURE-LIVENESS",
    ),
    ("vstd-collective", "ROBOT"): _unknown(
        "vstd-collective", "ROBOT",
        "collective.py _decisions role-decision rows are a closed exact-key schema (line 78) carrying position, identifiers, class and bearer only. A closed key set bounds which keys a row carries, not which values are permitted, so no agent, harness, controller or actuator consequence is bounded. No refuting check on a consequence field exists, so ROBOT is UNKNOWN.",
        "Declare an executable refutation over a robot consequence field of the replayed rows; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_COLLECTIVE_SCHEMA,
        _ev(_D + "collective.py", "_decisions", 78, 78, "bearer_id"),
    ),
    ("vstd-collective", "FINBOT"): _unknown(
        "vstd-collective", "FINBOT",
        "collective.py _decisions role-decision rows are a closed exact-key schema (line 78) with no amount, account or settlement field in the permitted values. A closed key set bounds which keys a row carries, not which values are permitted, so no financial consequence is bounded. No refuting check exists, so FINBOT is UNKNOWN.",
        "Declare an executable refutation over a financial consequence field of the replayed rows; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_COLLECTIVE_SCHEMA,
        _ev(_D + "collective.py", "_decisions", 78, 78, "bearer_id"),
    ),
    ("vstd-collective", "ACTUATOR"): _unknown(
        "vstd-collective", "ACTUATOR",
        "collective.py _decisions collective-decision rows are a closed exact-key schema (line 94) carrying identifier, class and component identifiers only. A closed key set bounds which keys a row carries, not which command, target or effect values are permitted, so no actuator consequence is bounded. No refuting check exists, so ACTUATOR is UNKNOWN.",
        "Declare an executable effect-bearing refutation over the collective decision rows; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_COLLECTIVE_SCHEMA,
        _ev(_D + "collective.py", "_decisions", 94, 94, "component_decision_ids"),
    ),
    ("vstd-benchmark", "ACTUATOR"): _unknown(
        "vstd-benchmark", "ACTUATOR",
        "bench.py evaluate run rows are a closed exact-key schema (line 78) carrying identifier, problem digest, answer and observed resources. A closed key set bounds which keys a run carries, not which command, target or effect values are permitted, so no actuator consequence is bounded. No refuting check exists, so ACTUATOR is UNKNOWN.",
        "Declare an executable effect-bearing refutation over the run rows; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_BENCH_SCHEMA,
        _ev(_D + "bench.py", "evaluate", 78, 78, "peak_memory_bytes"),
    ),
    ("vstd-benchmark", "ROBOT"): _unknown(
        "vstd-benchmark", "ROBOT",
        "bench.py evaluate run rows are a closed exact-key schema (line 78) that binds no agent, harness or physical target; the only observed fields are execution time and peak memory. A closed key set bounds keys, not permitted values, so no robot consequence is bounded. No refuting check exists, so ROBOT is UNKNOWN.",
        "Declare an executable refutation over a robot consequence field of the run rows; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_BENCH_SCHEMA,
        _ev(_D + "bench.py", "evaluate", 78, 78, "peak_memory_bytes"),
    ),
    ("vstd-benchmark", "FINBOT"): _unknown(
        "vstd-benchmark", "FINBOT",
        "bench.py evaluate run rows are a closed exact-key schema (line 78) with no financial amount, account or order field in the permitted values. A closed key set bounds keys, not permitted values, so no financial consequence is bounded. No refuting check exists, so FINBOT is UNKNOWN.",
        "Declare an executable refutation over a financial consequence field of the run rows; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_BENCH_SCHEMA,
        _ev(_D + "bench.py", "evaluate", 78, 78, "peak_memory_bytes"),
    ),
    ("vstd-benchmark", "TRANSACTION"): _unknown(
        "vstd-benchmark", "TRANSACTION",
        "bench.py evaluate checks coverage and identity equalities over the replayed rows (line 71) and returns a score. No atomicity, retry, partial failure, compensation or finality mechanism is present, and no refutation exists, so TRANSACTION stays UNKNOWN.",
        _TRANSACTION_NEXT, _UNKNOWN_CHECKER_TRANSACTION,
        _ev(_D + "bench.py", "evaluate", 71, 72, "set(runs) - set(problems)"),
    ),
    ("vstd-human", "CONTROLLER"): _unknown(
        "vstd-human", "CONTROLLER",
        "human.py evaluate closes the lifecycle row schema (line 73) and enumerates five event transitions (lines 88-109). The enumeration bounds which event kinds are accepted; it carries no feedback, error, setpoint or control-signal field and refutes no control law, so CONTROLLER is UNKNOWN rather than DOES_NOT_APPLY.",
        "Declare an executable feedback-law refutation over a control signal for the lifecycle rows; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_HUMAN_CONTROLLER,
        _ev(_D + "human.py", "evaluate", 73, 73, '"evidence_id", "instrument"'),
        _ev(_D + "human.py", "evaluate", 88, 90, 'if kind == "enrollment"'),
        blocker="HUMAN-CONTROLLER-FEEDBACK-LAW",
    ),
    ("vstd-human", "TRANSACTION"): _unknown(
        "vstd-human", "TRANSACTION",
        "human.py evaluate lifecycle transitions (lines 88-90) are per-event state checks. Each transition is validated alone; no atomic multi-record commit, retry, partial failure, compensation or finality semantics are established or refuted.",
        _TRANSACTION_NEXT, _UNKNOWN_CHECKER_TRANSACTION,
        _ev(_D + "human.py", "evaluate", 88, 90, 'if kind == "enrollment"'),
    ),
    ("vstd-human", "ACTUATOR"): _unknown(
        "vstd-human", "ACTUATOR",
        "human.py _assertion reads its metadata through need() (line 20), and the artifact is an open object: unread fields are silence, not refutation. The closed schema at line 43 constrains retained evidence records only. No refuting check exists.",
        "Declare a closed assertion schema or a refuting check for actuator fields; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_HUMAN,
        _ev(_D + "human.py", "_assertion", 20, 20, 'need(artifact, "subject_ref")'),
        _ev(_D + "human.py", "_assertion", 43, 43, "obj(record"),
    ),
    ("vstd-human", "ROBOT"): _unknown(
        "vstd-human", "ROBOT",
        "human.py _assertion reads its metadata through need() (line 20) and binds no agent field, but the artifact is an open object, so unread fields are silence rather than refutation. No refuting check exists.",
        "Declare a closed assertion schema or a refuting check for agent and harness fields; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_HUMAN,
        _ev(_D + "human.py", "_assertion", 20, 20, 'need(artifact, "subject_ref")'),
    ),
    ("vstd-human", "FINBOT"): _unknown(
        "vstd-human", "FINBOT",
        "human.py _assertion reads its metadata through need() (line 20) and declares no financial field, but the artifact is an open object, so unread fields are silence rather than refutation. No refuting check exists.",
        "Declare a closed assertion schema or a refuting check for financial fields; otherwise keep UNKNOWN.",
        _UNKNOWN_CHECKER_HUMAN,
        _ev(_D + "human.py", "_assertion", 20, 20, 'need(artifact, "subject_ref")'),
    ),
}
_EXPLICIT_UNKNOWN.update({
    ("vstd-architecture", role): _unknown(
        "vstd-architecture", role,
        f"arch_schedule.py SCOPE is the label constant 'selected_static_graph_execution_order'. A label is not a mechanism: the replay (_evaluate, lines 244-245) checks node names and order only and reads no command, target, effect, feedback or physical field. Neither establishing nor refuting evidence exists for {role}, so the cell is UNKNOWN rather than DOES_NOT_APPLY.",
        f"Audit ARCH for an executable {role} check or refutation; a static graph label never decides the cell.",
        _UNKNOWN_CHECKER_ARCH,
        _ARCH_SCOPE_LABEL,
        _ARCH_REPLAY,
    )
    for role in ("ACTUATOR", "CONTROLLER", "FINBOT", "ROBOT")
})
# ARCH MEASUREMENT and SENSOR have no decision; the generated record below covers them.


def _generated_unknown(object_id: str, role: str) -> SourceRoleUnresolved:
    return _unknown(
        object_id, role,
        f"UNKNOWN: no decision records {role} for {object_id}; no owned-source span establishes or refutes it, and the primary kind {_PRIMARY_BY_OBJECT[object_id]} is not evidence for it.",
        f"Audit the {len(_OWNED_PATHS[object_id])} owned paths of {object_id} for a {role} mechanism; record APPLIES only with an executable span and DOES_NOT_APPLY only with a refutation span, otherwise keep UNKNOWN.",
        "test_every_unknown_cell_has_a_record_with_reason_next_action_and_checker",
    )


def unresolved_records(
    decisions: tuple[SourceRoleDecision, ...] = SOURCE_ROLE_DECISIONS,
) -> tuple[SourceRoleUnresolved, ...]:
    """One UNKNOWN record per accumulating (object, role) cell that no decision row decides."""
    decided = {(row.object_id, row.role) for row in decisions}
    decided.update(
        (object_id, role)
        for object_id, roles in OBLIGATION_RETENTION_APPLIES.items()
        for role in roles
    )
    return tuple(
        _EXPLICIT_UNKNOWN.get((object_id, role)) or _generated_unknown(object_id, role)
        for object_id in sorted(_OWNED_PATHS)
        for role in ACCUMULATING_ROLES
        if (object_id, role) not in decided
    )


# Full-file SHA-256 of each owned path, computed from the bytes audited for these rows.
# Drift is a failure: a changed file must be re-audited before its rows change.
SOURCE_DIGESTS: dict[str, str] = {
    "src/verifier/domains/actor.py": "sha256:cea3c698ed0d62e11ceb4ef478b61f1c42911c09ab7f76072a362abc4d482117",
    "src/verifier/domains/agent.py": "sha256:0a793d1dc210a7ffb6d143c6ff227dd112fe11f41b5cfdff856037cb588d0f50",
    "src/verifier/domains/bot.py": "sha256:4f2e5d0bdc203c60a6efeb37a3e8e8dd2f64cde7ceedfe831855ccedde1e409c",
    "src/verifier/domains/collective.py": "sha256:9015e91474773797455bc8c52546bc4dd37d7f5ec5ff361ffd9f726b70147ede",
    "src/verifier/domains/bench.py": "sha256:924a122aa24d34927ee679c24a98fac81e5f4201fa5025fa712dc575f25dc4db",
    "src/verifier/domains/human.py": "sha256:d1fc9d70d65552fe64d37d8e3c86bae71a68ad8f74ac36e1bcc85916cdca0fb3",
    "src/verifier/domains/contracts/actor_closure.py": "sha256:d14f86637a2479fe33ff2edc170b109aead09e27416bd1410d120e0cec61ce21",
    "src/verifier/domains/contracts/actor_decision_record.py": "sha256:f4c19aebfb5a66f2fb88f513a726e753c6ce48a04b6962f0aa37fb91d9ac51bd",
    "src/verifier/domains/contracts/actor_replay.py": "sha256:564d890c5bfb48cd4a5622361d0ea50c874f19af8dc9bc7743f50c22b0f41438",
    "src/verifier/domains/contracts/agent_ceiling_fixity.py": "sha256:7b107e458dd8a947d365089b1aacaef46f2408e61270f9645a289e62c03453cc",
    "src/verifier/domains/contracts/agent_checks.py": "sha256:3dad2c6ec04e3a6dce548c4dfd114684369778300db853876f7f13052e256708",
    "src/verifier/domains/contracts/bot_checks.py": "sha256:3e18c90aa7583243c90585770abd90ab44384352110c4bdf1ef1cb7805408661",
    "src/verifier/domains/contracts/bot_inherited_ceiling.py": "sha256:29477927b30750028f6201cf67948695b74bbf15db2f7ec0f8203c490e27d6e3",
    "src/verifier/domains/contracts/collective_closure.py": "sha256:bb148e92c0c8151d42796ee957ef280061db6e64e16ac681d6f1e668af726673",
    "src/verifier/domains/contracts/collective_constraints.py": "sha256:72d0f38838b65268acf0a539262e5161b18b5209ede7145bbf61f514c8c691b9",
    "src/verifier/domains/contracts/collective_lifecycle.py": "sha256:73085730c3176295ed294bc2345048cb05c518113f95db1fb59b385859ef2495",
    "src/verifier/domains/contracts/bench_attempts.py": "sha256:040defe90c721f33a41e75510bf562dfd564c9f32b62009ed43efd14ece47176",
    "src/verifier/domains/contracts/bench_checks.py": "sha256:3826e27fba32889349b989be5e6362bcc5a04ddce8aa897e1243b31bc13a4e5a",
    "src/verifier/domains/contracts/bench_checks_projection.py": "sha256:6d642695777878a8e437e07bb7e68bf282975f14dd04daeef3a6e67dfa726cb6",
    "src/verifier/domains/contracts/human_no_composition.py": "sha256:22dc7a5a736671c0ae2d3082df9e24864633854c052e811ae8ea85991326a816",
    "src/verifier/domains/contracts/human_population_declaration.py": "sha256:5e1fdde605ca886b670c0744ea7e3e4497750a770bfdff373633fe5579ff4e85",
    "src/verifier/domains/contracts/human_template_irreversibility.py": "sha256:a45f84bf6cf8f02d3937124e57b18ff404df1b9d6fe39b10e2581607a97dab75",
    "src/verifier/domains/contracts/arch_resolution.py": "sha256:fe080259b172572d883d154e094f22fa8c4eddfecebdfe8ab03c62a8702a4c8c",
    "src/verifier/domains/contracts/arch_schedule.py": "sha256:ebf5c39f9f90f525b7a3e40f467324c6f70d27a2d87080f5fd3266202ab1a764",
    "src/verifier/domains/contracts/arch_shapes.py": "sha256:9c47e5d33d7c3934460e268fb52f7150cc30e603cdc4600672db575fe712b391",
}
PATH_CENSUS: tuple[str, ...] = tuple(sorted(SOURCE_DIGESTS))

_OWNED_PATHS: dict[str, tuple[str, ...]] = {
    "vstd-actor": (_D + "actor.py", _C + "actor_closure.py", _C + "actor_decision_record.py", _C + "actor_replay.py"),
    "vstd-agent": (_D + "agent.py", _C + "agent_ceiling_fixity.py", _C + "agent_checks.py"),
    "vstd-bot": (_D + "bot.py", _C + "bot_checks.py", _C + "bot_inherited_ceiling.py"),
    "vstd-collective": (_D + "collective.py", _C + "collective_closure.py", _C + "collective_constraints.py", _C + "collective_lifecycle.py"),
    "vstd-benchmark": (_D + "bench.py", _C + "bench_attempts.py", _C + "bench_checks.py", _C + "bench_checks_projection.py"),
    "vstd-human": (_D + "human.py", _C + "human_no_composition.py", _C + "human_population_declaration.py", _C + "human_template_irreversibility.py"),
    "vstd-architecture": (_C + "arch_resolution.py", _C + "arch_schedule.py", _C + "arch_shapes.py"),
}
_PRIMARY_BY_OBJECT: dict[str, str] = {
    "vstd-actor": "ACTOR",
    "vstd-agent": "AGENT",
    "vstd-bot": "BOT",
    "vstd-collective": "COLLECTIVE",
    "vstd-benchmark": "BENCH",
    "vstd-human": "HUMAN",
    "vstd-architecture": "ARCH",
}
_REPRESENTATION: dict[str, tuple[str, str, str]] = {
    "vstd-actor": (
        "accountable party whose attributed decisions are bound to one actor identifier",
        "Identity, delegation, witness accountability, attribution and retention are checked over four owned sources.",
        "Attribution and witness admission only; decision truth, personhood, non-transferable accountability and instrument execution are not claimed.",
    ),
    "vstd-agent": (
        "open-ended trajectory of observations, decisions and tool invocations bounded by a bound harness ceiling",
        "The agent module and its contracts bind every trajectory, action and claim to records the bound harness retained.",
        "Observation ceiling and retained-record binding only; live execution, physical isolation and real effects are not established.",
    ),
    "vstd-bot": (
        "simulation-situated closed loop between one agent and one simulation",
        "The BOT module and its contracts bind an agent certificate and a simulation certificate; neither alone establishes the loop.",
        "Simulation-situated loop only; no real physical or financial effect is established. ROBOT, FINBOT, ACTUATOR and CONTROLLER are UNKNOWN: the simulation label exempts neither real physical nor financial consequence.",
    ),
    "vstd-collective": (
        "fixed-membership collective assembled from ROLE components under declared decision classes",
        "The collective module and its contracts replay role graphs, membership lifecycle, quorum constraints and decision assembly.",
        "Declaration and assembly replay only; votes, occupancy, personhood, authority and participant failure or liveness are not established.",
    ),
    "vstd-benchmark": (
        "benchmark specification graph with finite problem oracles and retained run observations",
        "The benchmark module and its contracts recompute oracle answers, scores, resource bounds and attempt policies.",
        "Finite oracle and retained-observation checks only; live measurement authenticity and oracle correctness beyond built-in predicates are excluded.",
    ),
    "vstd-human": (
        "retained humanness assertion with declared evidence, lifecycle and enrollment population",
        "The human module and its contracts bind assertion metadata, evidence records, lifecycle events and population declarations.",
        "Assertion metadata and declared event order only; personhood, uniqueness, witness independence and physical liveness are NOT_ESTABLISHED.",
    ),
    "vstd-architecture": (
        "computational model architecture given as tensor shapes, operator definitions and static execution order",
        "The architecture contracts replay operator closure, static graph order and tensor shapes from retained declarations.",
        "Static declarations only; execution equivalence, operator truth, fusion and runtime behaviour are not established.",
    ),
}
_BLOCKER_REASON = (
    "Typed operand slot is unbound: ownership rows name source files, and no owner row in this batch "
    "supplies a namespace object instance of the required kind."
)
# Typed slots from the namespace composition layout, with the target kinds each slot requires.
_TYPED_SLOTS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "vstd-actor": (("representation", ("AGENT", "BOT", "HUMAN")), ("root_human", ("HUMAN",))),
    "vstd-agent": (("env", ("ENV",)), ("harness", ("HARNESS",)), ("model", ("MODEL",))),
    "vstd-bot": (("agent", ("AGENT",)), ("env", ("ENV",)), ("sim", ("SIM",))),
    "vstd-collective": (("roles", ("ROLE",)),),
    "vstd-benchmark": (("data", ("DATA",)), ("verifier", ("VERIFIER",))),
}
_OPERAND_TARGETS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "vstd-actor": (("representation", ("vstd-human",)), ("root_human", ("vstd-human",))),
    "vstd-agent": (("env", ("vstd-environment",)), ("harness", ("vstd-harness",)), ("model", ("vstd-model",))),
    "vstd-bot": (("agent", ("vstd-agent",)), ("env", ("vstd-environment",)), ("sim", ("vstd-simulation",))),
    "vstd-collective": (("roles", ("vstd-role",)),),
    "vstd-benchmark": (("data", ("vstd-data",)), ("verifier", ("verifier-core-self",))),
}


def _row(object_id: str) -> SemanticOwnershipSpec:
    applies = tuple(sorted({
        row.role for row in SOURCE_ROLE_DECISIONS
        if row.object_id == object_id and row.status == "APPLIES" and row.role != ROOT_ROLE
    } | set(OBLIGATION_RETENTION_APPLIES.get(object_id, ()))))
    representation, necessity, boundary = _REPRESENTATION[object_id]
    roots: tuple[RootRoleDecision, ...] = ()
    if ROOT_APPLICABILITY[object_id] != UNKNOWN:
        status = cast(Literal["APPLIES", "DOES_NOT_APPLY"], ROOT_APPLICABILITY[object_id])
        roots = (root_role_decision(ROOT_ROLE, status, _ROOT_REASONS[object_id]),)
    return ownership_spec(
        object_id,
        _PRIMARY_BY_OBJECT[object_id],
        _OWNED_PATHS[object_id],
        representation,
        necessity,
        boundary,
        *applies,
        operands=_OPERAND_TARGETS.get(object_id, ()),
        root_role_decisions=roots,
    )


# Export for later aggregation.  Operands bind the exact installed registry IDs;
# central aggregation independently checks those IDs and kinds against the
# compiled graph declaration.
SEMANTIC_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = tuple(
    _row(object_id) for object_id in sorted(_OWNED_PATHS)
)


def integration_blockers() -> tuple[tuple[str, str, tuple[str, ...], str], ...]:
    """Typed operand slots not yet bound to exact registry IDs."""
    return tuple(
        (object_id, slot, targets, _BLOCKER_REASON)
        for object_id in sorted(_TYPED_SLOTS)
        for slot, targets in _TYPED_SLOTS[object_id]
        if not dict(_OPERAND_TARGETS.get(object_id, ())).get(slot)
    )


def unresolved_roles(
    decisions: tuple[SourceRoleDecision, ...] = SOURCE_ROLE_DECISIONS,
) -> dict[str, tuple[str, ...]]:
    """Accumulating roles with no recorded decision.  UNKNOWN, never an exemption."""
    records = unresolved_records(decisions)
    return {
        object_id: tuple(record.role for record in records if record.object_id == object_id)
        for object_id in sorted(_OWNED_PATHS)
    }


def aggregation_ready() -> bool:
    """True only when every typed operand slot has an exact registry binding."""
    return not integration_blockers()


def _source_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def source_digest(path: str | Path) -> str:
    """Return the raw-byte digest of one file, as pinned in the census."""
    return _source_digest(Path(path).read_bytes())


def _portable(path: str) -> PurePosixPath:
    if type(path) is not str or not path or "\\" in path:
        raise ValueError("BATCH_PATH_NOT_PORTABLE")
    portable = PurePosixPath(path)
    if (
        portable.is_absolute()
        or portable.as_posix() != path
        or any(part in {"", ".", ".."} for part in portable.parts)
        or re.match(r"^[A-Za-z]:", path)
    ):
        raise ValueError("BATCH_PATH_NOT_PORTABLE")
    return portable


def _valid_applicability(value: object) -> bool:
    if type(value) is not str:
        return False
    if value == "UNCONDITIONAL":
        return True
    return any(value.startswith(prefix) and value[len(prefix):].strip() for prefix in (
        "UNCONDITIONAL: ", "CONDITIONAL: ",
    ))


def validate_batch(
    specs: tuple[SemanticOwnershipSpec, ...],
    decisions: tuple[SourceRoleDecision, ...],
    census: tuple[str, ...],
    digests: Mapping[str, str],
) -> tuple[SemanticOwnershipSpec, ...]:
    """Validate rows, decisions, UNKNOWN records, census and digests with no filesystem access.

    Raises ``ValueError`` with a stable code on the first violation.  Source byte
    drift, evidence spans and source markers are checked by the functions below
    against a repository root.
    """
    if census != PATH_CENSUS:
        raise ValueError("BATCH_CENSUS_NOT_EXACT")
    for path in census:
        _portable(path)
        if not path.startswith(_PATH_PREFIX):
            raise ValueError("BATCH_CENSUS_PREFIX_INVALID")
    if set(digests) != set(census):
        raise ValueError("BATCH_DIGEST_COVERAGE_INVALID")
    if any(_DIGEST.fullmatch(value) is None for value in digests.values()):
        raise ValueError("BATCH_DIGEST_INVALID")
    if set(ROOT_APPLICABILITY) != set(_OWNED_PATHS) or any(
        value not in _ROOT_STATUSES for value in ROOT_APPLICABILITY.values()
    ):
        raise ValueError("BATCH_ROOT_APPLICABILITY_INVALID")
    if (
        set(OBLIGATION_RETENTION_APPLIES) - set(_OWNED_PATHS)
        or any(
            roles != tuple(dict.fromkeys(roles))
            or not set(roles) <= set(ACCUMULATING_ROLES)
            for roles in OBLIGATION_RETENTION_APPLIES.values()
        )
    ):
        raise ValueError("BATCH_OBLIGATION_RETENTION_INVALID")
    if type(specs) is not tuple or type(decisions) is not tuple:
        raise ValueError("BATCH_TABLE_INVALID")

    ids = [item.object_id for item in specs]
    if len(ids) != len(set(ids)):
        raise ValueError("BATCH_ID_DUPLICATED")
    if sorted(ids) != sorted(_OWNED_PATHS):
        raise ValueError("BATCH_OBJECT_SET_INVALID")
    owner_of: dict[str, str] = {}
    for item in specs:
        if type(item) is not SemanticOwnershipSpec:
            raise ValueError("BATCH_SPEC_INVALID")
        if _OBJECT_ID.fullmatch(item.object_id) is None:
            raise ValueError("BATCH_ID_INVALID")
        if item.primary_kind not in PRIMARY_KINDS:
            raise ValueError("BATCH_PRIMARY_KIND_INVALID")
        if item.specializations != tuple(sorted(set(item.specializations))) or not set(
            item.specializations
        ) <= set(ACCUMULATING_ROLES):
            raise ValueError("BATCH_SPECIALIZATION_INVALID")
        if item.primary_kind in item.specializations:
            raise ValueError("BATCH_SPECIALIZATION_INVALID")
        if item.owned_paths != tuple(sorted(set(item.owned_paths))) or not item.owned_paths:
            raise ValueError("BATCH_PATHS_INVALID")
        for value in (item.representation_role, item.necessity_reason, item.consequence_boundary):
            if type(value) is not str or not value.strip():
                raise ValueError("BATCH_REASON_REQUIRED")
        for path in item.owned_paths:
            _portable(path)
            if path not in census:
                raise ValueError("BATCH_PATH_NOT_IN_CENSUS")
            if owner_of.setdefault(path, item.object_id) != item.object_id:
                raise ValueError("BATCH_PATH_DUPLICATED")
        if item.operands != tuple(sorted(_OPERAND_TARGETS.get(item.object_id, ()))):
            raise ValueError("BATCH_OPERAND_BINDING_INVALID")
        _validate_root_roles(item)
        _validate_row_decisions(item, [row for row in decisions if row.object_id == item.object_id])

    if set(owner_of) != set(census):
        raise ValueError("BATCH_CENSUS_COVERAGE_INVALID")
    if {row.object_id for row in decisions} - set(ids):
        raise ValueError("BATCH_DECISION_OBJECT_UNKNOWN")
    _validate_unknown_partition(specs, decisions)
    return tuple(sorted(specs, key=lambda item: item.object_id))


def _validate_root_roles(item: SemanticOwnershipSpec) -> None:
    """The exported root decision is exactly the ROOT_APPLICABILITY mapping for this object."""
    status = ROOT_APPLICABILITY[item.object_id]
    roots = item.root_role_decisions
    if status == UNKNOWN:
        if roots:
            raise ValueError("BATCH_ROOT_ROLE_INVALID")
        return
    if len(roots) != 1 or type(roots[0]) is not RootRoleDecision:
        raise ValueError("BATCH_ROOT_ROLE_INVALID")
    if roots[0].kind != ROOT_ROLE or roots[0].status != status or not roots[0].reason.strip():
        raise ValueError("BATCH_ROOT_ROLE_INVALID")


def _validate_row_decisions(item: SemanticOwnershipSpec, rows: list[SourceRoleDecision]) -> None:
    seen: set[str] = set()
    for row in rows:
        if type(row) is not SourceRoleDecision:
            raise ValueError("BATCH_DECISION_INVALID")
        if row.role not in DECIDED_ROLES:
            raise ValueError("BATCH_DECISION_ROLE_INVALID")
        if row.role in seen:
            raise ValueError("BATCH_DECISION_DUPLICATED")
        seen.add(row.role)
        if row.status not in STATUSES:
            raise ValueError("BATCH_DECISION_STATUS_INVALID")
        if type(row.reason) is not str or not row.reason.strip():
            raise ValueError("BATCH_DECISION_REASON_REQUIRED")
        if not row.evidence:
            raise ValueError("BATCH_DECISION_EVIDENCE_REQUIRED")
        if not _valid_applicability(row.applicability):
            raise ValueError("BATCH_APPLICABILITY_INVALID")
        if type(row.next_action) is not str or not row.next_action.strip():
            raise ValueError("BATCH_DECISION_CONTRACT_INCOMPLETE")
        if type(row.checker) is not str or not row.checker.strip():
            raise ValueError("BATCH_DECISION_CONTRACT_INCOMPLETE")
        for span in row.evidence:
            if (
                type(span) is not SourceEvidence
                or span.path not in item.owned_paths
                or _SYMBOL.fullmatch(span.symbol) is None
                or type(span.start_line) is not int
                or type(span.end_line) is not int
                or not 1 <= span.start_line <= span.end_line
                or type(span.marker) is not str
                or not span.marker.strip()
            ):
                raise ValueError("BATCH_EVIDENCE_INVALID")
        # The reason must name a file in its own evidence, so prose cannot stand in for source.
        if not any(PurePosixPath(span.path).name in row.reason for span in row.evidence):
            raise ValueError("BATCH_DECISION_REASON_UNBOUND")
    applies = {row.role for row in rows if row.status == "APPLIES" and row.role != ROOT_ROLE}
    applies.update(OBLIGATION_RETENTION_APPLIES.get(item.object_id, ()))
    if applies != set(item.specializations):
        raise ValueError("BATCH_ROLE_PROMOTION_MISMATCH")
    root = [row for row in rows if row.role == ROOT_ROLE]
    if ROOT_APPLICABILITY[item.object_id] == UNKNOWN:
        if root:
            raise ValueError("BATCH_ROOT_ROLE_UNDECIDED")
        return
    declared = item.root_role_decisions[0]
    if len(root) != 1 or root[0].status != declared.status or root[0].reason != declared.reason:
        raise ValueError("BATCH_ROOT_ROLE_UNDECIDED")


def _validate_unknown_partition(
    specs: tuple[SemanticOwnershipSpec, ...],
    decisions: tuple[SourceRoleDecision, ...],
) -> None:
    """Every accumulating cell is decided or UNKNOWN exactly once; UNKNOWN records are complete."""
    source_decided = {
        (row.object_id, row.role) for row in decisions if row.role != ROOT_ROLE
    }
    # Explicit UNKNOWN evidence becomes inactive when the sole reasons ledger
    # conservatively retains an obligation.  It is stale only if a source audit
    # later claims the same cell; retention deliberately makes no such source
    # mechanism claim.
    if source_decided & set(_EXPLICIT_UNKNOWN):
        raise ValueError("BATCH_UNKNOWN_STALE")
    decided = set(source_decided)
    decided.update(
        (object_id, role)
        for object_id, roles in OBLIGATION_RETENTION_APPLIES.items()
        for role in roles
    )
    owned = {item.object_id: set(item.owned_paths) for item in specs}
    records = unresolved_records(decisions)
    keys = [(record.object_id, record.role) for record in records]
    grid = {(object_id, role) for object_id in _OWNED_PATHS for role in ACCUMULATING_ROLES}
    if len(keys) != len(set(keys)) or decided & set(keys) or decided | set(keys) != grid:
        raise ValueError("BATCH_UNKNOWN_PARTITION_INVALID")
    for record in records:
        if record.applicability != UNKNOWN or type(record.blocker) is not str:
            raise ValueError("BATCH_UNKNOWN_RECORD_INVALID")
        if not record.reason.strip() or not record.next_action.strip() or not record.checker.strip():
            raise ValueError("BATCH_UNKNOWN_RECORD_INCOMPLETE")
        if any(span.path not in owned[record.object_id] for span in record.evidence):
            raise ValueError("BATCH_UNKNOWN_RECORD_INVALID")


def _docstring_lines(tree: ast.Module) -> set[int]:
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                lines.update(range(body[0].lineno, (body[0].end_lineno or body[0].lineno) + 1))
    return lines


def _symbol_span(tree: ast.Module, symbol: str) -> tuple[int, int] | None:
    """Line span of a dotted top-level or nested symbol."""
    scope: list[ast.stmt] = tree.body
    found: ast.stmt | None = None
    for part in symbol.split("."):
        found = None
        for node in scope:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                matched = node.name == part
            elif isinstance(node, ast.Assign):
                matched = any(
                    isinstance(target, ast.Name) and target.id == part for target in node.targets
                )
            elif isinstance(node, ast.AnnAssign):
                matched = isinstance(node.target, ast.Name) and node.target.id == part
            else:
                matched = False
            if matched:
                found = node
                break
        if found is None:
            return None
        scope = list(getattr(found, "body", []))
    if found is None:
        return None
    return found.lineno, found.end_lineno or found.lineno


def evidence_failures(
    root: str | Path,
    decisions: tuple[SourceRoleDecision | SourceRoleUnresolved, ...],
) -> tuple[str, ...]:
    """Return one failure per evidence span not supported by its current source.

    Each span must name an existing symbol, cite lines within it, and cite no docstring
    or comment-only line.  Decisions and UNKNOWN records are both checked.
    """
    base = Path(root).resolve(strict=True)
    failures: list[str] = []
    cache: dict[str, tuple[ast.Module, list[str], set[int]] | None] = {}
    for row in decisions:
        for span in row.evidence:
            label = f"{row.object_id} {row.role} {span.path}:{span.symbol}:{span.start_line}-{span.end_line}"
            if span.path not in cache:
                target = base.joinpath(*PurePosixPath(span.path).parts).resolve(strict=False)
                if not target.is_relative_to(base) or not target.is_file():
                    cache[span.path] = None
                else:
                    source = target.read_text(encoding="utf-8")
                    tree = ast.parse(source, filename=span.path)
                    cache[span.path] = (tree, source.splitlines(), _docstring_lines(tree))
            loaded = cache[span.path]
            if loaded is None:
                failures.append(f"EVIDENCE_PATH_INVALID {label}")
                continue
            tree, lines, doc_lines = loaded
            bounds = _symbol_span(tree, span.symbol)
            if bounds is None:
                failures.append(f"EVIDENCE_SYMBOL_MISSING {label}")
            elif not bounds[0] <= span.start_line <= span.end_line <= bounds[1]:
                failures.append(f"EVIDENCE_OUTSIDE_SYMBOL {label}")
            elif any(line in doc_lines for line in range(span.start_line, span.end_line + 1)):
                failures.append(f"EVIDENCE_IS_DOCSTRING {label}")
            elif lines[span.start_line - 1].strip().startswith("#"):
                failures.append(f"EVIDENCE_IS_COMMENT {label}")
    return tuple(failures)


def marker_failures(
    root: str | Path,
    decisions: tuple[SourceRoleDecision | SourceRoleUnresolved, ...],
) -> tuple[str, ...]:
    """Return one failure per evidence span whose cited lines lack its source marker."""
    base = Path(root).resolve(strict=True)
    failures: list[str] = []
    for row in decisions:
        for span in row.evidence:
            label = f"{row.object_id} {row.role} {span.path}:{span.start_line}-{span.end_line}"
            target = base.joinpath(*PurePosixPath(span.path).parts).resolve(strict=False)
            if not target.is_relative_to(base) or not target.is_file():
                failures.append(f"EVIDENCE_PATH_INVALID {label}")
                continue
            lines = target.read_text(encoding="utf-8").splitlines()
            window = "\n".join(lines[span.start_line - 1:span.end_line])
            if span.marker not in window:
                failures.append(f"EVIDENCE_MARKER_MISSING {label} {span.marker!r}")
    return tuple(failures)


def source_drift_failures(
    root: str | Path,
    census: tuple[str, ...],
    digests: Mapping[str, str],
) -> tuple[str, ...]:
    """Return missing or byte-drifted census files under one repository root."""
    base = Path(root).resolve(strict=True)
    failures: list[str] = []
    for path in census:
        candidate = base.joinpath(*PurePosixPath(path).parts).resolve(strict=False)
        if not candidate.is_relative_to(base) or not candidate.is_file():
            failures.append(f"SOURCE_MISSING {path}")
            continue
        observed = _source_digest(candidate.read_bytes())
        if observed != digests[path]:
            failures.append(f"SOURCE_DRIFT {path} expected {digests[path]} observed {observed}")
    return tuple(failures)


__all__ = [
    "ACCUMULATING_ROLES",
    "DECIDED_ROLES",
    "OBLIGATION_RETENTION_APPLIES",
    "obligation_retention_reason",
    "PATH_CENSUS",
    "PRIMARY_KINDS",
    "ROOT_APPLICABILITY",
    "ROOT_ROLE",
    "SEMANTIC_OWNERSHIP_SPECS",
    "SOURCE_DIGESTS",
    "SOURCE_ROLE_DECISIONS",
    "UNKNOWN",
    "SourceEvidence",
    "SourceRoleDecision",
    "SourceRoleUnresolved",
    "aggregation_ready",
    "evidence_failures",
    "integration_blockers",
    "marker_failures",
    "source_digest",
    "source_drift_failures",
    "unresolved_records",
    "unresolved_roles",
    "validate_batch",
]
