"""Additive kind contracts for Verifier Standard (VSTD) repository admission.

Boundary: these contracts require inspectable declarations, not proof that money
is conserved, a simulation is confined, or physical actuation is safe.
Tier-1-plus evidence remains separate.
The legacy ObjectKind enum is deliberately untouched: old receipts keep their
original denominator. New kinds refine a registered base instead of replacing it.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Iterable, Mapping

from verifier.core.namespace import ObjectKind
from verifier.runtime.tier_zero_profile import (
    applicability_declaration,
    applicability_digest,
    validate_applicability_declaration,
    value_digest,
)


KIND_DENOMINATOR_SCHEMA = "verifier-kind-denominators-1"
OBJECT_KIND_DENOMINATOR_SCOPE = "RETAINED_NATIVE_WIRE"
OBJECT_KIND_COUNT = 26
INSTALLED_NAMESPACE_KIND_COUNT = 38


@dataclass(frozen=True)
class AdmissionObligation:
    """One necessary declaration once its owning kind is applicable."""

    id: str
    name: str
    reason: str
    evidence_requirement: str
    declaration_fields: tuple[str, ...] = ("contract",)
    applicability: dict[str, str] | None = None
    applicability_digest: str | None = None

    def __post_init__(self) -> None:
        kind = self.id.split("-", 1)[0]
        declaration = self.applicability
        if declaration is None:
            declaration = applicability_declaration(
                mode="NECESSARY",
                condition=(
                    f"The admitted object carries the {kind} kind or accumulated "
                    f"{kind} role governed by this installed contract."
                ),
                reason=(
                    self.reason
                    + " Once that kind or role is carried, this declaration obligation "
                      "cannot be omitted; unresolved role applicability is not an exemption."
                ),
            )
        else:
            declaration = validate_applicability_declaration(declaration)
        object.__setattr__(self, "applicability", declaration)
        digest = applicability_digest(declaration)
        if self.applicability_digest not in (None, digest):
            raise ValueError("APPLICABILITY_BINDING_DIGEST")
        object.__setattr__(self, "applicability_digest", digest)


@dataclass(frozen=True)
class KindContract:
    """An immutable, versioned refinement; inheritance only adds obligations."""

    kind: str
    extends: str | None
    version: str
    reason: str
    obligations: tuple[AdmissionObligation, ...]
    origin: str = "INSTALLED"


# Each named kind is first-class in current admission. OBJECT inheritance reuses
# its general representation; it neither collapses the kind nor supplies the
# missing higher-tier specialized mechanisms. Existing wire kinds stay frozen.
_ADDED_KINDS = (
    KindContract("LEDGER", "OBJECT", "1",
        "Authoritative histories need explicit accounting and recovery boundaries, not just valid data bytes.", (
        AdmissionObligation("LEDGER-0.1-authoritative-history", "Authoritative history",
            "A reader must know which records and state constitute the authoritative ledger.",
            "Bind source and a declaration identifying the history, state, ordering and authority boundary.",
            ("history", "state", "ordering", "authority")),
        AdmissionObligation("LEDGER-0.2-accounting-invariants", "Accounting invariants",
            "Structurally valid entries can still violate units, balance rules or authorized issuance.",
            "Bind the declared units, balance equations, rounding and permitted sources and sinks; do not claim they were executed.",
            ("units", "balance_rules", "rounding", "sources_and_sinks")),
        AdmissionObligation("LEDGER-0.3-correction-and-recovery", "Correction and recovery",
            "Corrections, replay and recovery can silently change previously relied-upon balances.",
            "Bind the correction, replay, reconciliation and recovery contract and its implementation surfaces.",
            ("corrections", "replay", "reconciliation", "recovery")),
    )),
    KindContract("TRANSACTION", "OBJECT", "1",
        "Coordinated effects require explicit authorization, failure and retry semantics.", (
        AdmissionObligation("TRANSACTION-0.1-effects-and-authority", "Effects and authority",
            "A valid request must not conceal affected resources or the authority needed to change them.",
            "Bind the effect set, preconditions, authorization checks and participating resources.",
            ("effects", "preconditions", "authorization", "resources")),
        AdmissionObligation("TRANSACTION-0.2-commit-and-failure", "Commit and failure",
            "Partial failure can leave a system in a state that a successful-path test never observes.",
            "Bind commit, abort, finality and partial-failure semantics, including compensation where atomicity is not claimed.",
            ("commit", "abort", "finality", "partial_failure")),
        AdmissionObligation("TRANSACTION-0.3-retry-and-replay", "Retry and replay",
            "Retries and duplicate delivery can apply the same external effect more than once.",
            "Bind duplicate detection, idempotency or explicit non-idempotency, retry limits and replay behavior.",
            ("duplicate_detection", "idempotency", "retry_limits", "replay")),
    )),
    KindContract("ASSET", "OBJECT", "1",
        "A recorded holding must identify the right, quantity and custody claim rather than imply actual backing.", (
        AdmissionObligation("ASSET-0.1-identity-and-quantity", "Identity and quantity",
            "Identical numbers can denote different assets, rights or units and must not be interchangeable.",
            "Bind the asset identity, represented rights, quantity units and precision rules.",
            ("identity", "rights", "units", "precision")),
        AdmissionObligation("ASSET-0.2-issuance-and-redemption", "Issuance and redemption",
            "Creating or extinguishing a recorded claim must not imply authorized issuance or promised redemption.",
            "Bind issuance authority, supply changes, redemption terms and the evidence needed for any backing claim.",
            ("issuance_authority", "supply_changes", "redemption", "backing_claims")),
        AdmissionObligation("ASSET-0.3-custody-and-encumbrance", "Custody and encumbrance",
            "A recorded owner may lack access to a pledged, segregated or externally held asset.",
            "Bind custody, control, encumbrances and reconciliation with the actual claimed holdings.",
            ("custody", "control", "encumbrances", "reconciliation")),
    )),
    KindContract("MARKET", "OBJECT", "1",
        "Valid individual trades do not establish valid order admission, matching, allocation or settlement rules.", (
        AdmissionObligation("MARKET-0.1-orders-and-access", "Orders and participant access",
            "Unspecified admission and cancellation rules conceal who can trade and which orders remain active.",
            "Bind participant access, order states, validation and cancellation rules.",
            ("participant_access", "order_states", "validation", "cancellation")),
        AdmissionObligation("MARKET-0.2-matching-and-allocation", "Matching and allocation",
            "Authorized orders can still receive incorrect prices, priority or allocation.",
            "Bind matching, price formation, allocation and conflict or manipulation controls.",
            ("matching", "price_formation", "allocation", "manipulation_controls")),
        AdmissionObligation("MARKET-0.3-settlement-and-disruption", "Settlement and disruption",
            "A matched order is not a settled transfer, especially during defaults or outages.",
            "Bind settlement dependencies, finality, participant failure and disruption handling.",
            ("settlement_dependencies", "finality", "participant_failure", "disruption")),
    )),
    KindContract("MEASUREMENT", "OBJECT", "1",
        "An observed value needs a phenomenon, method and uncertainty boundary; valid data bytes are insufficient.", (
        AdmissionObligation("MEASUREMENT-0.1-phenomenon-and-method", "Phenomenon and method",
            "An observation must not be confused with an estimate, command or unrelated physical quantity.",
            "Bind the phenomenon, observation method, source and distinction from model-derived values.",
            ("phenomenon", "method", "source", "observation_vs_estimate")),
        AdmissionObligation("MEASUREMENT-0.2-units-time-and-uncertainty", "Units, time and uncertainty",
            "Units, reference frames, age and uncertainty determine whether a value supports a decision.",
            "Bind units, reference frame, observation and arrival times, and uncertainty interpretation.",
            ("units", "reference_frame", "observation_time", "arrival_time", "uncertainty")),
        AdmissionObligation("MEASUREMENT-0.3-validity-and-missingness", "Validity and missing observations",
            "Missing or invalid observations must not silently become precise current measurements.",
            "Bind validity conditions, missing-data handling, freshness limits and provenance.",
            ("validity", "missingness", "freshness", "provenance")),
    )),
    KindContract("SENSOR", "OBJECT", "1",
        "The mechanism producing observations has calibration, range and fault conditions distinct from its output data.", (
        AdmissionObligation("SENSOR-0.1-acquisition-and-observations", "Acquisition and observations",
            "A sensor declaration must identify how inputs become observations rather than merely name a data feed.",
            "Bind the acquisition mechanism, observed phenomena, output measurements and deployment boundary.",
            ("acquisition", "phenomena", "measurements", "deployment")),
        AdmissionObligation("SENSOR-0.2-calibration-and-envelope", "Calibration and operating envelope",
            "A producer can return well-formed values outside the conditions where its readings are meaningful.",
            "Bind calibration applicability, calibration evidence, operating range and drift treatment.",
            ("calibration_applicability", "calibration_evidence", "operating_range", "drift")),
        AdmissionObligation("SENSOR-0.3-sampling-and-faults", "Sampling and faults",
            "Sampling delay and undetected sensor faults can invalidate downstream decisions.",
            "Bind sampling, latency, fault detection and recovery or replacement behavior.",
            ("sampling", "latency", "fault_detection", "recovery")),
    )),
    KindContract("CONTROLLER", "OBJECT", "1",
        "Feedback-directed actions need explicit timing, operating limits and failure semantics independently of agent labels.", (
        AdmissionObligation("CONTROLLER-0.1-feedback-and-authority", "Feedback and command authority",
            "A controller must identify its observations, objectives and allowed commands before its behavior can be checked.",
            "Bind objectives, feedback inputs, command outputs and control authority.",
            ("objectives", "feedback", "commands", "authority")),
        AdmissionObligation("CONTROLLER-0.2-timing-and-stability", "Timing and stability assumptions",
            "A locally valid command may destabilize a loop when feedback is delayed or operating assumptions fail.",
            "Bind timing constraints, stability assumptions, operating envelope and saturation handling.",
            ("timing", "stability_assumptions", "operating_envelope", "saturation")),
        AdmissionObligation("CONTROLLER-0.3-intervention-and-failure", "Intervention and failure behavior",
            "Loss of feedback, conflicting commands and intervention can require different safe responses.",
            "Bind feedback-loss handling, controller arbitration, intervention and justified failure behavior.",
            ("feedback_loss", "arbitration", "intervention", "failure_behavior")),
    )),
    KindContract("ACTUATOR", "OBJECT", "1",
        "A command acceptance record is not proof of its effect; actuation has separate targets, limits and failure modes.", (
        AdmissionObligation("ACTUATOR-0.1-command-to-effect", "Command-to-effect boundary",
            "The same command shape can address simulated or real targets with different consequences.",
            "Bind accepted commands, effect targets, effect domains and authority boundaries.",
            ("commands", "targets", "effect_domains", "authority")),
        AdmissionObligation("ACTUATOR-0.2-response-and-limits", "Response and limits",
            "Actuation delay, saturation and unit mismatches can violate the intended operating envelope.",
            "Bind command units and frames, response assumptions, limits and saturation behavior.",
            ("units_and_frames", "response", "limits", "saturation")),
        AdmissionObligation("ACTUATOR-0.3-feedback-and-interlocks", "Feedback and interlocks",
            "Successful submission does not establish execution, and failure may require an interlocked safe state.",
            "Bind effect feedback, interlocks, failure states and recovery requirements.",
            ("effect_feedback", "interlocks", "failure_states", "recovery")),
    )),
    KindContract("PROTOCOL", "OBJECT", "1",
        "Participant-local correctness does not establish agreement, safe message handling or progress across participants.", (
        AdmissionObligation("PROTOCOL-0.1-participants-and-states", "Participants and states",
            "Coordination cannot be assessed without participants, roles and allowed state transitions.",
            "Bind participants, roles, state machines and permitted transitions.",
            ("participants", "roles", "states", "transitions")),
        AdmissionObligation("PROTOCOL-0.2-ordering-and-replay", "Ordering and replay",
            "Reordered, duplicated or unauthenticated messages can invalidate an otherwise correct local operation.",
            "Bind message authority, ordering, replay handling and compatibility negotiation.",
            ("message_authority", "ordering", "replay", "compatibility")),
        AdmissionObligation("PROTOCOL-0.3-failures-and-progress", "Failures and progress",
            "Safety and liveness depend on explicit network, participant and recovery assumptions.",
            "Bind failure assumptions, safety invariants, progress guarantees and recovery.",
            ("failure_assumptions", "safety", "liveness", "recovery")),
    )),
    KindContract("POLICY", "OBJECT", "1",
        "A declared rule is not an enforced decision; precedence, exceptions and policy changes have their own semantics.", (
        AdmissionObligation("POLICY-0.1-rules-and-precedence", "Rules and precedence",
            "Conflicting or incomplete rules need explicit resolution rather than accidental implementation order.",
            "Bind rule scope, decision inputs, precedence and default outcomes.",
            ("scope", "decision_inputs", "precedence", "defaults")),
        AdmissionObligation("POLICY-0.2-authority-and-exceptions", "Authority and exceptions",
            "An exception or policy update can change permissible effects without changing the subject's code.",
            "Bind policy authority, exception authority, revision rules and activation boundaries.",
            ("authority", "exceptions", "revisions", "activation")),
        AdmissionObligation("POLICY-0.3-enforcement-and-decisions", "Enforcement and decision correspondence",
            "A valid policy document does not show that every consequential execution used it.",
            "Bind enforcement points, decision evidence, bypass handling and policy-unavailable behavior.",
            ("enforcement_points", "decision_evidence", "bypass_handling", "unavailable_behavior")),
    )),
    KindContract("ROBOT", "OBJECT", "1",
        "An agent reaching physical actuators acquires physical consequences even when upstream execution is simulated.", (
        AdmissionObligation("ROBOT-0.1-agent-to-actuator-binding", "Agent-to-actuator binding",
            "The actual agent, governing harness, controllers and actuators must be bound as one effect path.",
            "Bind the agent, its actual governing harness, controllers and physical actuator targets.",
            ("agent", "harness", "controllers", "actuators")),
        AdmissionObligation("ROBOT-0.2-physical-reach-and-observation", "Physical reach and observation",
            "A simulation label cannot exclude real effects or make simulated feedback evidence of physical response.",
            "Bind physical reach, observation sources, effect-domain crossings and evidence required for confinement claims.",
            ("physical_reach", "observations", "domain_crossings", "confinement_evidence")),
        AdmissionObligation("ROBOT-0.3-consequences-and-intervention", "Consequences and intervention",
            "Physical actions need justified operating limits and failure responses; immediate shutdown is not universally safe.",
            "Bind consequential hazards, operating limits, intervention and safe-state or continuity requirements.",
            ("hazards", "operating_limits", "intervention", "safe_state_or_continuity")),
    )),
    KindContract("FINBOT", "OBJECT", "1",
        "An agent responsible for real financial decisions or effects needs financial consequence checks, not only agent or simulation checks.", (
        AdmissionObligation("FINBOT-0.1-agent-and-financial-authority", "Agent and financial authority",
            "A financial decision needs an identified agent, governing harness, decision scope and authority boundary.",
            "Bind the agent, its actual harness, consequential financial decisions and permitted authority.",
            ("agent", "harness", "decision_scope", "financial_authority")),
        AdmissionObligation("FINBOT-0.2-financial-exposure-and-dependencies", "Financial exposure and dependencies",
            "Real financial consequences can arise through advice or delegated execution, including from inside a simulation.",
            "Bind affected assets and parties, financial object dependencies, real-world decision or effect paths and exposure limits.",
            ("assets_and_parties", "financial_dependencies", "real_world_paths", "exposure_limits")),
        AdmissionObligation("FINBOT-0.3-decisions-effects-and-recovery", "Decisions, effects and recovery",
            "An accepted decision is not proof of authorized settlement, and retries or interventions may duplicate exposure.",
            "Bind decision-to-effect evidence, independent limit enforcement where required, intervention and reconciliation or recovery.",
            ("decision_effect_evidence", "limit_enforcement", "intervention", "reconciliation_and_recovery")),
    )),
)


def _nonblank(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 8192:
        raise ValueError(code)
    return value


def namespace_registry(extensions: Iterable[dict[str, Any]] = ()) -> dict[str, KindContract]:
    """Build a fresh registry without importing any repository-authored code.

    Local extensions are declarations, not endorsements by the standard. They
    cannot replace installed contracts, remove ancestors, or invent PASS results.
    Requiring parents first makes cycles impossible without a separate graph pass.
    """
    registry = {kind.value: KindContract(kind.value, None, "1",
        "Preserve the installed " + kind.value + " typed-composition contract.", ()) for kind in ObjectKind}
    registry.update((contract.kind, contract) for contract in _ADDED_KINDS)
    for index, document in enumerate(extensions):
        if index >= 128:
            raise ValueError("NAMESPACE_EXTENSION_CAPACITY")
        if type(document) is not dict or set(document) != {"kind", "extends", "version", "reason", "obligations"}:
            raise ValueError("NAMESPACE_EXTENSION_FIELDS")
        kind = _nonblank(document["kind"], "NAMESPACE_KIND_INVALID")
        if re.fullmatch(r"[A-Z][A-Z0-9]{0,63}", kind) is None:
            raise ValueError("NAMESPACE_KIND_INVALID")
        if kind in registry:
            raise ValueError("NAMESPACE_KIND_REDEFINITION")
        parent = document["extends"]
        if not isinstance(parent, str) or parent not in registry:
            raise ValueError("NAMESPACE_PARENT_UNAVAILABLE")
        version = _nonblank(document["version"], "NAMESPACE_VERSION_REQUIRED")
        reason = _nonblank(document["reason"], "NAMESPACE_KIND_REASON_REQUIRED")
        rows = document["obligations"]
        if type(rows) is not list or not 1 <= len(rows) <= 64:
            raise ValueError("NAMESPACE_OBLIGATION_DENOMINATOR_REQUIRED")
        obligations = []
        for row in rows:
            required = {"id", "name", "reason", "evidence_requirement"}
            if type(row) is not dict or not required <= set(row) <= required | {"declaration_fields"}:
                raise ValueError("NAMESPACE_OBLIGATION_FIELDS")
            for key in sorted(required):
                _nonblank(row[key], "NAMESPACE_OBLIGATION_" + key.upper() + "_REQUIRED")
            if re.fullmatch(re.escape(kind) + r"-0\.[1-9][0-9]*-[a-z][a-z0-9-]*", row["id"]) is None:
                raise ValueError("NAMESPACE_OBLIGATION_ID_INVALID")
            # Even the shortest local contract requires a declaration. Authors
            # can name precise questions, but cannot choose an empty denominator.
            fields = row.get("declaration_fields", ["contract"])
            if (type(fields) is not list or not 1 <= len(fields) <= 32
                    or any(not isinstance(field, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", field) is None for field in fields)
                    or len(fields) != len(set(fields))):
                raise ValueError("NAMESPACE_DECLARATION_FIELDS_INVALID")
            obligations.append(AdmissionObligation(**{key: row[key] for key in required},
                                                   declaration_fields=tuple(fields)))
        if len({row.id for row in obligations}) != len(obligations):
            raise ValueError("NAMESPACE_OBLIGATION_DUPLICATED")
        registry[kind] = KindContract(kind, parent, version, reason, tuple(obligations), "LOCAL_DECLARATION")
    return registry


def validate_kind_denominators(record: Any) -> dict[str, Any]:
    """Validate the distinct native-wire and installed-namespace counts.

    Python booleans are integers for ordinary arithmetic, so every numeric
    check uses exact types.  The 26-kind value is the frozen ``ObjectKind``
    denominator used by the native 26-by-9 grid and its 408 registered route
    memberships.  The 38-kind value is the installed extensible namespace;
    it must never replace the native denominator or create a 38-by-9 grid.
    """

    required = {
        "schema_version",
        "object_kind_count",
        "object_kind_denominator_scope",
        "installed_namespace_kind_count",
    }
    if type(record) is not dict or set(record) != required:
        raise ValueError("PACKAGE_KIND_DENOMINATORS_FIELDS_INVALID")
    if record["schema_version"] != KIND_DENOMINATOR_SCHEMA:
        raise ValueError("PACKAGE_KIND_DENOMINATOR_SCHEMA_INVALID")
    if (
        type(record["object_kind_count"]) is not int
        or record["object_kind_count"] != OBJECT_KIND_COUNT
    ):
        raise ValueError("PACKAGE_OBJECT_KIND_COUNT_INVALID")
    if record["object_kind_denominator_scope"] != OBJECT_KIND_DENOMINATOR_SCOPE:
        raise ValueError("PACKAGE_OBJECT_KIND_DENOMINATOR_SCOPE_INVALID")
    if (
        type(record["installed_namespace_kind_count"]) is not int
        or record["installed_namespace_kind_count"]
        != INSTALLED_NAMESPACE_KIND_COUNT
    ):
        raise ValueError("PACKAGE_INSTALLED_NAMESPACE_KIND_COUNT_INVALID")
    return dict(record)


def kind_denominators() -> dict[str, Any]:
    """Derive and return the one installed 26/38 denominator record."""

    native_count = len(tuple(ObjectKind))
    if type(native_count) is not int or native_count != OBJECT_KIND_COUNT:
        raise ValueError("PACKAGE_OBJECT_KIND_COUNT_INVALID")
    installed_count = len(namespace_registry())
    if (
        type(installed_count) is not int
        or installed_count != INSTALLED_NAMESPACE_KIND_COUNT
    ):
        raise ValueError("PACKAGE_INSTALLED_NAMESPACE_KIND_COUNT_INVALID")
    return validate_kind_denominators({
        "schema_version": KIND_DENOMINATOR_SCHEMA,
        "object_kind_count": native_count,
        "object_kind_denominator_scope": OBJECT_KIND_DENOMINATOR_SCOPE,
        "installed_namespace_kind_count": installed_count,
    })


def ancestors(registry: Mapping[str, KindContract], kind: str) -> tuple[str, ...]:
    """Return the kind and all parents; unknown spelling never falls back to OBJECT."""
    result = []
    while kind is not None:
        if kind not in registry or kind in result:
            raise ValueError("NAMESPACE_KIND_UNREGISTERED_OR_CYCLIC")
        result.append(kind)
        kind = registry[kind].extends
    return tuple(result)


def compatible_specialization(registry: Mapping[str, KindContract], primary: str, role: str) -> bool:
    """Allow general-object roles on any kind without changing its base operands.

    OBJECT is already the general subject type in the legacy composition model.
    Consequently a BOT can also have physical or financial roles. A refinement of
    a narrower base (for example SIM) cannot be attached to an unrelated base.
    Compatibility only admits labels; it establishes no role's behavior or shape.
    """
    base = ancestors(registry, role)[-1]
    return registry[role].extends is not None and (base == "OBJECT" or base == ancestors(registry, primary)[-1])


def requirements_for(registry: Mapping[str, KindContract], kinds: Iterable[str]) -> list[dict[str, Any]]:
    """Union requirements by exact identifier, preserving inheritance and reasons."""
    selected = {ancestor for kind in kinds for ancestor in ancestors(registry, kind)}
    return [{**asdict(row), "kind": kind, "version": registry[kind].version,
             "origin": registry[kind].origin}
            for kind in sorted(selected) for row in registry[kind].obligations]


def registry_document(registry: Mapping[str, KindContract]) -> dict[str, Any]:
    contracts = [asdict(registry[kind]) for kind in sorted(registry)]
    return {"schema_version": "verifier-extensible-namespace-1", "contracts": contracts,
            "digest": value_digest(contracts)}
