"""Reviewed Tier-0 namespace answers for selected Verifier package objects.

Terminology: application programming interface (API); command-line interface
(CLI); central processing unit (CPU); JavaScript Object Notation (JSON); Secure
Hash Algorithm 256-bit (SHA-256).

This module is deliberately narrower than package migration.  It records one
current-source semantic review, binds that review to the complete owned file
boundary, and returns a copy of the supplied object mapping.  It does not infer
roles from filenames, execute subject code, establish higher-tier behavior, or
turn a Tier-0 declaration into proof that its prose is true.

Every complete decision has a literal per-object basis.  ``applicable`` names
APPLIES roles, ``refuted`` names the few DOES_NOT_APPLY roles whose source audit
found an affirmative exclusion (an explicit declaration or an enforced refusal of
the role's defining operand or effect class), and a kind in neither set remains
canonical UNRESOLVED.  Absence of role vocabulary or an import/call inventory
alone is not a refutation, so it stays UNRESOLVED.  Tuple absence alone never
creates a refutation.  A refutation cites exactly the owned files whose current
bytes carry its literal anchors; a self-description such as "not the actor" does
not exclude a role that the installed contract binds to the object, and a checker
that reasons only over a declared model is not an exclusion of the real effect.

The strict owned-file equality is intentional.  Adding or moving a file changes
the semantic review denominator and must fail closed until that source is read.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime import package_protocol_dependency_relation as protocol_relation


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


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    reasons: Mapping[str, str]
    declarations: Mapping[str, Mapping[str, str]]
    refuted: tuple[str, ...] = ()
    # Each refuted kind cites exactly the owned files carrying its exclusion,
    # with exact literal anchors that must be present in those current bytes.
    refutation_anchors: Mapping[str, Mapping[str, tuple[str, ...]]] = field(
        default_factory=dict
    )
    # A dependency operand records an edge to another package object without
    # transferring that object's source into this review's ownership boundary.
    dependency_operands: Mapping[str, "_DependencyOperand"] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class _DependencyOperand:
    targets: tuple[str, ...]
    reason: str
    local_endpoint_paths: tuple[str, ...]
    target_evidence_paths: tuple[str, ...]
    # Literal anchors make the dependency executable as a current-source
    # precondition instead of leaving it as unverified graph prose.
    anchors: Mapping[str, tuple[str, ...]]


_HARDWARE_PATHS = (
    "src/verifier/domains/hardware.py",
    "src/verifier/domains/contracts/hardware_capacity.py",
    "src/verifier/domains/contracts/hardware_inventory.py",
    "src/verifier/domains/contracts/hardware_inventory_closure.py",
    "src/verifier/domains/contracts/hardware_measurements.py",
    "src/verifier/domains/contracts/hardware_substrate_observations.py",
    "src/verifier/domains/contracts/hardware_topology.py",
)

_SIM_PATHS = (
    "src/verifier/domains/sim.py",
    "src/verifier/domains/contracts/sim_checker.py",
    "src/verifier/domains/contracts/sim_dynamics.py",
    "src/verifier/domains/contracts/sim_external_law.py",
    "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
    "src/verifier/domains/contracts/sim_fresh_worker.py",
    "src/verifier/domains/contracts/sim_internal_core.py",
    "src/verifier/domains/contracts/sim_internal_state.py",
    "src/verifier/domains/contracts/sim_isolation.py",
    "src/verifier/domains/contracts/sim_perspective.py",
    "src/verifier/domains/contracts/sim_resource.py",
    "src/verifier/domains/contracts/sim_resource_fresh.py",
    "src/verifier/domains/contracts/sim_resource_worker.py",
    "src/verifier/domains/contracts/sim_response.py",
    "src/verifier/domains/contracts/sim_shard_coverage.py",
    "src/verifier/domains/contracts/sim_shard_relations.py",
    "src/verifier/domains/contracts/sim_shard_signatures.py",
    "src/verifier/domains/contracts/sim_surface_partition.py",
)

_HARNESS_PATHS = (
    "extensions/languages/pyproject.toml",
    "extensions/languages/src/vstd_languages/__init__.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
    "src/verifier/core/owned_process.py",
    "src/verifier/core/run.py",
    "src/verifier/core/run_impact.py",
    "src/verifier/core/run_inspection.py",
    "src/verifier/core/run_planning.py",
    "src/verifier/core/run_process_observation.py",
    "src/verifier/core/run_reproduction.py",
    "src/verifier/core/run_support.py",
    "src/verifier/core/run_validation.py",
    "src/verifier/domains/harness.py",
    "src/verifier/domains/contracts/harness_checks.py",
    "src/verifier/domains/contracts/harness_gap_boundary.py",
    "src/verifier/runtime/language_runners.py",
    "src/verifier/runtime/package_harness_applicability.py",
)

_LEDGER_PATHS = (
    "src/verifier/runtime/polish_invocation_ledger.py",
    "src/verifier/runtime/local_ledger_controls.py",
    "src/verifier/runtime/local_ledger_control_checks.py",
    "src/verifier/runtime/local_ledger_execution.py",
    "src/verifier/runtime/local_ledger_worker.py",
)
_MANIFEST_PATHS = (
    "src/verifier/runtime/namespace_cli.py",
    "src/verifier/runtime/manifest_write_execution.py",
    "src/verifier/runtime/manifest_write_worker.py",
)
_OPENSHELL_PATHS = (
    "extensions/openshell/pyproject.toml",
    "extensions/openshell/src/vstd_openshell/__init__.py",
    "extensions/openshell/src/vstd_openshell/environment.py",
    "extensions/openshell/src/vstd_openshell/live.py",
)
_PURE_VERIFIER_PATHS = (
    "src/verifier/core/certificate.py",
    "src/verifier/core/checker.py",
    "src/verifier/core/contextual_namespace.py",
    "src/verifier/core/geometry.py",
    "src/verifier/core/geometry_io.py",
    "src/verifier/core/grounding.py",
    "src/verifier/core/kernel.py",
    "src/verifier/core/namespace.py",
    "src/verifier/core/platform_comparison.py",
    "src/verifier/core/refutation.py",
    "src/verifier/core/reproducibility.py",
    "src/verifier/core/signature_keys.py",
)


_HARDWARE_REASONS = {
    "ASSET": "Named device records, typed capacities, and retained reservations are nonmonetary resource claims with identity, quantity, control, and backing boundaries, so ASSET declarations apply without implying ownership or physical availability.",
    "MEASUREMENT": "The HARDWARE measurement and substrate contracts validate retained quantities and observations at declared coordinates; they must distinguish supplied records from live or physically calibrated measurements.",
    "POLICY": "Installed mechanism pins, trust-root labels, finite ceilings, and fail-closed verdict rules govern which retained HARDWARE claims these checkers will admit.",
}

_SIM_REASONS = {
    "TRANSACTION": "The fresh resource-verification path launches a bounded worker and validates its response, which creates process and response-publication failure boundaries. Pure SIM replay and model-state transition are not themselves classified as transactions.",
    "MEASUREMENT": "The fresh SIM resource path directly samples executing-thread CPU intervals and traced Python allocation peaks for each selected transition, with an explicitly bounded software-only interpretation.",
    "SENSOR": "The fresh SIM worker is the acquisition mechanism for those software-counter observations; it is not a physical sensor and claims no external calibration.",
    "ACTUATOR": "The SIM channel check accepts only retained simulated actions bounded by the model contract. Its targets are model state and simulated channels, never physical actuators.",
    "PROTOCOL": "The closed bootstrap, fresh worker, bounded response, and optional shard-signature exchange form explicit local participant, ordering, compatibility, failure, and replay boundaries.",
    "POLICY": "Each SIM checker admits only exact request, mechanism, source, trust-root, and finite-limit selections and maps unavailable or contradictory evidence through installed fail-closed rules.",
}

_HARNESS_REASONS = {
    "LEDGER": "All 18 exact owned HARNESS paths are executable review inputs: their positive module-boundary anchors and content digests close the current source denominator around process launch, observation, receipt, validation, applicability, and native-adapter mechanics. That closed surface exposes no authoritative posting history, balance state, issuance or destruction authority, reconciliation, correction history, or duplicate-application ledger; HARNESS receipts remain non-authoritative observations, so LEDGER does not apply. Changed ownership, bytes, or anchors fail closed instead of preserving this refutation.",
    "TRANSACTION": "The HARNESS launches and can relaunch arbitrary subjects and sequentially publishes receipts, requiring explicit effect, authority, partial-failure, and replay boundaries; process exit is not transaction commit or finality.",
    "MEASUREMENT": "Parent-side capture records launch state, return code, stream lengths and digests, and declared gaps; those are bounded process-interface observations, not whole-subject truth.",
    "SENSOR": "The parent subprocess interface is the acquisition mechanism for HARNESS process observations and explicitly enumerates descendants, network, undeclared filesystem, and external effects as unobserved.",
    "ACTUATOR": "The HARNESS submits a command to a local process interface. This ACTUATOR role ends at launch submission and parent-visible process state; it does not establish any subject or external effect.",
    "PROTOCOL": "Core run, rerun, language-extension, and receipt exchange define local caller, runner, subject, and response states with exact compatibility and failure boundaries.",
    "POLICY": "Manifest validation, runner selection, object-role controls, timeouts, and observation requirements are installed decision rules enforced before and after launch.",
}

# LEDGER is refuted only over the complete, retained HARNESS ownership boundary.
# These positive anchors make every one of the 18 reviewed source files an
# executable input; content digests bind the rest of each file.  They do not
# infer that a launched subject has no ledger effects—the review is limited to
# effects and authority implemented by the HARNESS-owned source itself.
_HARNESS_LEDGER_REFUTATION_ANCHORS = {
    "extensions/languages/pyproject.toml": (
        'description = "Explicit native language process adapters for Verifier Standard"',
    ),
    "extensions/languages/src/vstd_languages/__init__.py": (
        "Native-language process adapters; no verification obligation is discharged.",
    ),
    "extensions/languages/src/vstd_languages/extended_batch_two.py": (
        "Batch-two native adapters: COBOL, Object Pascal, Ada, Objective-C and Assembly.",
    ),
    "extensions/languages/src/vstd_languages/extended_batch_three.py": (
        "Batch-three native adapters: Visual Basic (.NET), Scratch, MATLAB, SAS and Classic Visual Basic.",
    ),
    "src/verifier/core/owned_process.py": (
        "Bounded, stdlib-only ownership for one subprocess tree.",
        "This is a process-lifetime and stream-retention boundary.",
    ),
    "src/verifier/core/run.py": (
        "Generic computational run receipt capture for VSTD-1.",
        "External Evaluation Evidence (explicit, non-authoritative slot)",
    ),
    "src/verifier/core/run_impact.py": (
        "Recorded-ancestry impact analysis for generic-run receipts.",
    ),
    "src/verifier/core/run_inspection.py": (
        "Human-readable inspection of structurally valid generic-run receipts.",
    ),
    "src/verifier/core/run_planning.py": (
        "Side-effect-free generic-run manifest loading and execution-plan description.",
    ),
    "src/verifier/core/run_process_observation.py": (
        "Bounded parent-side process observation for Verifier Standard (VSTD) runs.",
        "A digest is not actor authentication",
    ),
    "src/verifier/core/run_reproduction.py": (
        "Opt-in rerun and side-effect-free artifact-rehash reproduction assessment.",
    ),
    "src/verifier/core/run_support.py": (
        "Shared internal coordinates for the Verifier Standard (VSTD) generic-run profile.",
    ),
    "src/verifier/core/run_validation.py": (
        "Fail-closed structural and canonical-digest validation for generic-run receipts.",
    ),
    "src/verifier/domains/harness.py": (
        "Agent harness (HARNESS): the instrumented observation surface, not the actor.",
    ),
    "src/verifier/domains/contracts/harness_checks.py": (
        "Current agent harness (HARNESS) native check certificates.",
        "Retained observations do not establish live execution or physical isolation.",
    ),
    "src/verifier/domains/contracts/harness_gap_boundary.py": (
        "Current HARNESS-3.1 named gaps bounded by retained instrument placements certificate.",
    ),
    "src/verifier/runtime/language_runners.py": (
        "Language-neutral Verifier Standard (VSTD) runner selection and process capture.",
        "The built-in trusted-local process runner is NOT a security sandbox.",
    ),
    "src/verifier/runtime/package_harness_applicability.py": (
        "Verifier-self launch denominator for bounded HARNESS applicability.",
        "The mechanism reads Python source and its one declared embedded worker;",
        "imports subject modules or starts a process.",
    ),
}

_LEDGER_REASONS = {
    "LEDGER": "The owned source implements the local LEDGER boundary described by the named declarations.",
    "TRANSACTION": "The owned source implements the local TRANSACTION boundary described by the named declarations.",
    "PROTOCOL": "The source-bound execution adapter and fixed worker exchange one versioned bounded JSON request and response across a parent/child process boundary; that protocol needs exact participants, ordering, replay, compatibility and failure limits.",
    "POLICY": "Host-selected ledger identity, policy domain and epoch plus fixed capacity and replay rules govern which local issuance can commit.",
    "FINBOT": "The owned source declares its boundary as not monetary accounting (local_ledger_execution.py) and the invocation ledger as not a monetary or global ledger (polish_invocation_ledger.py), so a real-money decision or effect is outside this object.",
}

_MANIFEST_REASONS = {
    "TRANSACTION": "The owned source implements the local TRANSACTION boundary described by the named declarations.",
    "PROTOCOL": "The owned manifest adapter and fixed worker are local endpoints of a versioned bounded request/reply exchange delegated to the uniquely owned package worker protocol; participant, ordering, replay, compatibility, failure, and progress boundaries therefore apply without transferring dispatcher ownership.",
}

_PACKAGE_WORKER_EXECUTION = "src/verifier/runtime/package_execution.py"


def _protocol_dependency(
    object_id: str, local_endpoint: str
) -> dict[str, _DependencyOperand]:
    if object_id not in protocol_relation.DEPENDENT_OBJECT_IDS:
        raise AssertionError("unregistered package protocol dependent: " + object_id)
    return {
        "protocol_exchange": _DependencyOperand(
            targets=protocol_relation.PROTOCOL_EXCHANGE_OBJECT_IDS,
            reason=protocol_relation.PARTICIPANT_DEPENDENCY_REASON,
            local_endpoint_paths=(local_endpoint,),
            target_evidence_paths=(
                _PACKAGE_WORKER_EXECUTION,
                protocol_relation.SOURCE_PATH,
            ),
            anchors={
                local_endpoint: (
                    "from verifier.runtime.package_execution import execute_bound",
                ),
                _PACKAGE_WORKER_EXECUTION: ("def execute_bound(",),
                protocol_relation.SOURCE_PATH: protocol_relation.SOURCE_ANCHORS,
            },
        )
    }

_OPENSHELL_REASONS = {
    "LEDGER": "The adapter requires the ephemeral-stop-contained lifecycle (vstd_openshell/__init__.py) and deletes its owned sandbox after execution, so it keeps no persistent authoritative history; retained command records are evidence, not ledger state.",
    "TRANSACTION": "Create, stage, execute, inspect, stop, and delete form a bounded remote lifecycle with explicit preconditions, authority, partial-failure, retry, cleanup, and finality boundaries.",
    "MEASUREMENT": "The adapter observes bounded CLI streams, exit state, elapsed host time, gateway and sandbox records, source digests, policy bindings, probes, and cleanup state with explicit gaps.",
    "SENSOR": "The OpenShell CLI and in-sandbox probes actively acquire those software-environment observations; they are not physical sensors and make no physical calibration claim.",
    "CONTROLLER": "The adapter sequences lifecycle commands, checks feedback after each stage, refuses binding drift, and drives cleanup under fixed resource and time limits.",
    "ACTUATOR": "The adapter submits OpenShell create, upload, execute, stop, and delete commands whose targets are computational sandbox resources and processes, not physical actuators.",
    "PROTOCOL": "Runner, CLI, gateway, sandbox, probe, and subject exchange through ordered versioned commands and bounded responses with named failure and recovery states.",
    "POLICY": "Exact config, image pin, resource limits, filesystem and network rules, ownership labels, negative probes, and fail-closed result mapping govern backend admission and execution.",
}


def _merge(*groups: Mapping[str, Mapping[str, str]]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for group in groups:
        overlap = set(result).intersection(group)
        if overlap:
            raise AssertionError(
                "duplicated review obligation: " + ", ".join(sorted(overlap))
            )
        result.update({name: dict(fields) for name, fields in group.items()})
    return result


_HARDWARE_ASSET = {
    "ASSET-0.1-identity-and-quantity": {
        "identity": "Each retained resource is identified by a bounded device id, supported device kind, and named capacity unit within the selected HARDWARE record.",
        "rights": "The record represents only a claimed capacity or reservation coordinate; ownership, exclusivity, delivered compute, physical availability, and credit authority are not established.",
        "units": "MEMORY_BYTE and STORAGE_BYTE count bytes; COMPUTE_SLOT and SAMPLE_SLOT are dimensionless per-device reservation counts.",
        "precision": "Quantities and microsecond coordinates are exact bounded integers; cross-device performance equivalence is explicitly excluded.",
    },
    "ASSET-0.2-issuance-and-redemption": {
        "issuance_authority": "No resource asset is issued by this checker; external evidence selection supplies the claimed device inventory and capacities.",
        "supply_changes": "A different retained inventory or capacity commitment is a different claim; this implementation does not mutate live supply.",
        "redemption": "No redemption, allocation enforcement, workload delivery, or conversion right is promised.",
        "backing_claims": "Physical device authenticity, availability, ownership, and credit backing require evidence outside this retained-record validator.",
    },
    "ASSET-0.3-custody-and-encumbrance": {
        "custody": "No physical or legal custody is asserted; the checker holds only selected evidence bytes during verification.",
        "control": "Accepted reservations demonstrate finite retained occupancy arithmetic, not exclusive control of a device.",
        "encumbrances": "Overlapping retained reservations are checked against capacity, but external reservations, liens, quotas, and competing schedulers are unobserved.",
        "reconciliation": "Reconciliation is limited to exact selected inventory, reservation, topology, measurement, and substrate commitments; no live hardware reconciliation occurs.",
    },
}

_HARDWARE_MEASUREMENT = {
    "MEASUREMENT-0.1-phenomenon-and-method": {
        "phenomenon": "A selected retained quantity for a named device and unit, or a bounded substrate observation named by the selected HARDWARE evidence.",
        "method": "Deterministic parsing, commitment checking, unit/range checking, and finite relation replay over externally supplied canonical records.",
        "source": "The selected retained HARDWARE evidence bytes and their exact request, policy, object, and collection commitments.",
        "observation_vs_estimate": "The checker validates a retained observation claim; it does not acquire a live reading or convert the supplied number into physical truth.",
    },
    "MEASUREMENT-0.2-units-time-and-uncertainty": {
        "units": "Supported capacity units are bytes or dimensionless slots; contract-specific observed quantities retain their declared typed interpretation.",
        "reference_frame": "Each value is relative to its named device, unit, declared clock, and selected evidence coordinate.",
        "observation_time": "Retained hardware measurement times are bounded integer microseconds on the evidence-declared clock, not trusted wall time.",
        "arrival_time": "The checker receives a complete selected evidence artifact; acquisition latency and original arrival time are not observed.",
        "uncertainty": "Physical accuracy, calibration, sampling error, clock truth, and device authenticity remain NOT_ESTABLISHED rather than being assigned zero uncertainty.",
    },
    "MEASUREMENT-0.3-validity-and-missingness": {
        "validity": "Canonical shape, exact commitments, supported identifiers and units, finite integer ranges, and contract-specific relations must all hold.",
        "missingness": "Absent required evidence or unsupported interpretation yields UNKNOWN or refusal; missing values are never filled with zero.",
        "freshness": "Freshness means current selected source and evidence commitments for this verification, not current physical-device state.",
        "provenance": "The certificate binds checker, request, policy, source, object, collection, and retained evidence digests without asserting who originally measured the value.",
    },
}

_HARDWARE_POLICY = {
    "POLICY-0.1-rules-and-precedence": {
        "scope": "Admission of exact finite retained HARDWARE inventory, capacity, topology, measurement, and substrate claims.",
        "decision_inputs": "Exact request, policy, mechanism and evidence digests, selected object/collection, trust-root labels, and finite ceilings.",
        "precedence": "Malformed or substituted bindings refuse before domain evaluation; bounded unavailability stays UNKNOWN; a reproduced contradiction is FAIL.",
        "defaults": "Nothing is physically authenticated by default, and absent required evidence never becomes a passing empty record.",
    },
    "POLICY-0.2-authority-and-exceptions": {
        "authority": "The external caller selects policy and trust-root labels; this checker validates the selection but does not authenticate the real authority behind a label.",
        "exceptions": "No bypass converts unsupported device kinds, units, bounds, or missing evidence into PASS.",
        "revisions": "Installed mechanism and source digests bind the active rules; changed source or policy is a different selection.",
        "activation": "The selected policy is activated for one verification call only and grants no allocation, spending, or physical-device authority.",
    },
    "POLICY-0.3-enforcement-and-decisions": {
        "enforcement_points": "Request and policy parsing, mechanism/source binding, evidence bounds, namespace composition, and each domain relation check.",
        "decision_evidence": "A bounded certificate records the selected proposition, bindings, outcome, and reproduced observations within the stated exclusions.",
        "bypass_handling": "Unknown fields, stale digests, malformed records, and exhausted finite limits cannot silently reach the PASS path.",
        "unavailable_behavior": "Unavailable physical truth, dependencies, or evidence remains UNKNOWN; the policy never treats it as absence or success.",
    },
}


_SIM_TRANSACTION = {
    "TRANSACTION-0.1-effects-and-authority": {
        "effects": "Launch one fresh bounded resource worker and return its local response/certificate bytes; the enclosed pure model transition is subject computation, not itself a transactional effect.",
        "preconditions": "Exact request, policy, resource mechanism, scenario, interpreter, and closed bootstrap/worker source bindings plus finite limits must validate before a response is admitted.",
        "authorization": "The local caller authorizes this fresh resource-verification invocation only; no physical, financial, network, or undeclared filesystem effect authority is established.",
        "resources": "The fresh local interpreter process, supplied finite scenario, traced Python allocations, thread clock, and parent/worker response channel.",
    },
    "TRANSACTION-0.2-commit-and-failure": {
        "commit": "A validated worker response commits no external transaction; it records one completed fresh resource-verification observation around selected model computation.",
        "abort": "Validation failure, worker error, malformed response, or timeout refuses the result, but does not prove rollback of unobserved host effects.",
        "finality": "Process exit and certificate creation are not physical, financial, distributed, or persistent-state finality.",
        "partial_failure": "A worker may finish computation before response parsing or parent validation fails; the capture is then unadmitted and no external compensation is claimed.",
    },
    "TRANSACTION-0.3-retry-and-replay": {
        "duplicate_detection": "Request, source, challenge, scenario and response commitments distinguish captures; they do not create a global duplicate-execution ledger.",
        "idempotency": "The enclosed selected transition replay is deterministic, but fresh process invocation, observation, and arbitrary host effects are not declared idempotent.",
        "retry_limits": "The mechanism performs no hidden automatic retry and bounds each worker invocation by its finite timeout and resource limits.",
        "replay": "A recheck starts a fresh process against current bound source; historical signatures or process exit cannot substitute for fresh execution.",
    },
}

# The resource declarations deliberately match the already-reviewed fresh SIM
# mechanism.  They describe software counters and never claim physical metrology.
_SIM_MEASUREMENT = {
    "MEASUREMENT-0.1-phenomenon-and-method": {
        "phenomenon": "Resource use within each selected finite interpreter transition, not validation or process startup.",
        "method": "CPython thread_time_ns differences and per-transition tracemalloc peak readings.",
        "source": "Fresh source-loaded sim_fresh_worker validated by sim_resource_fresh and its closed bootstrap.",
        "observation_vs_estimate": "Direct local instrument readings, not budget counters or extrapolated physical-device usage.",
    },
    "MEASUREMENT-0.2-units-time-and-uncertainty": {
        "units": "Thread CPU nanoseconds and peak traced Python allocation bytes; no total resident memory or whole-device claim.",
        "reference_frame": "The isolated worker's executing thread and Python allocation tracer, indexed by trajectory step.",
        "observation_time": "Each transition interval; elapsed thread time is not a wall-clock timestamp.",
        "arrival_time": "Parent receives the bounded completed-process response; no absolute arrival timestamp or latency guarantee is exported.",
        "uncertainty": "Instrument resolution, tracer overhead, host honesty, and calibration are not established; no zero-error physical accuracy claim.",
    },
    "MEASUREMENT-0.3-validity-and-missingness": {
        "validity": "Exact method/interpreter, source bindings, step coverage, and state digests; non-Boolean integer metrics in the declared bounds.",
        "missingness": "Unavailable execution yields UNKNOWN in certificate recheck; malformed captures refute and never fill missing metrics with zero.",
        "freshness": "New challenge and execution per invocation; no historical-record correspondence or wall-age guarantee.",
        "provenance": "Closed checked source bytes compile in the worker; the parent rechecks loaded manifest and current sources, not a collector signature.",
    },
}

_SIM_SENSOR = {
    "SENSOR-0.1-acquisition-and-observations": {
        "acquisition": "Isolated CPython transition execution with per-step thread-clock and allocation-tracer acquisition.",
        "phenomena": "Executing-thread CPU interval and traced Python allocation peak within that transition.",
        "measurements": "Indexed input/output state digests, thread_cpu_ns, and traced_peak_bytes, with run identity.",
        "deployment": "Local source-loaded subprocess under the invoking host; not hostile-host isolation or an external physical transducer.",
    },
    "SENSOR-0.2-calibration-and-envelope": {
        "calibration_applicability": "Physical metrology calibration is outside the software-counter interpretation claim; accuracy or external-phenomenon claims need additional evidence.",
        "calibration_evidence": "Controlled instrument inputs check software arithmetic and interval placement, not operating-system clock accuracy or tracer completeness.",
        "operating_range": "CPython finite replay bounds: at most 100000 operations and 4096 items; accepted nonnegative metrics through 2**63-1.",
        "drift": "Exact implementation and interpreter bindings detect changed selections; numerical clock drift is neither measured nor certified.",
    },
    "SENSOR-0.3-sampling-and-faults": {
        "sampling": "One before/after thread-clock pair and allocation peak per transition; replay validation precedes tracing.",
        "latency": "The selected subprocess timeout is 15 seconds; no real-time delivery guarantee is made.",
        "fault_detection": "Clock, transition, tracer, process, and binding failures cannot produce a validated complete capture.",
        "recovery": "Tracing is stopped after started acquisition; another recheck starts a new process. No in-place repair or failover is claimed.",
    },
}

_SIM_ACTUATOR = {
    "ACTUATOR-0.1-command-to-effect": {
        "commands": "Selected entropy values and retained action records admitted by the SIM transition/channel contracts.",
        "targets": "Only the selected model state and simulated action channels inside the finite SIM representation.",
        "effect_domains": "SIMULATED_MODEL_ONLY; no physical actuator, real-money transfer, external service, or sim-to-real route is declared.",
        "authority": "The caller's selected SIM request authorizes model evaluation only and grants no authority over an external target.",
    },
    "ACTUATOR-0.2-response-and-limits": {
        "units_and_frames": "Action values use the supplied model contract's numeric variables, bounds, and causal-step coordinate.",
        "response": "The deterministic transition function maps selected state and entropy to the next simulated state; retained channels are compared exactly.",
        "limits": "Finite state, item, operation, action-bound, trajectory, and subprocess ceilings constrain the check.",
        "saturation": "Out-of-bound retained actions refute; the implementation does not silently clamp or claim a physical saturation response.",
    },
    "ACTUATOR-0.3-feedback-and-interlocks": {
        "effect_feedback": "Subsequent simulated state and declared observation projections are model feedback, not evidence of a real-world effect.",
        "interlocks": "Exact source/request/policy bindings, finite bounds, channel coverage, and worker validation interlock admission of the model result.",
        "failure_states": "Malformed, out-of-bound, inconsistent, unavailable, or timed-out simulation inputs cannot yield an admitted effect claim.",
        "recovery": "A caller may perform a fresh bounded replay; no physical safe state, rollback, or external compensation is claimed.",
    },
}

_SIM_PROTOCOL = {
    "PROTOCOL-0.1-participants-and-states": {
        "participants": "The parent verifier, closed bootstrap, fresh SIM worker, selected scenario, and optional named shard witnesses.",
        "roles": "Parent binds inputs and validates output; bootstrap loads closed source; worker executes; shard witnesses sign only their retained coordinates.",
        "states": "Captured request, source validation, worker launch, transition replay, response construction, parent validation, and refusal/unknown terminal states.",
        "transitions": "Only exact schema, source, challenge, request, scenario, step, and response correspondence permits an admitted terminal result.",
    },
    "PROTOCOL-0.2-ordering-and-replay": {
        "message_authority": "Local source selection and configured witness keys are explicit trust assumptions; a digest or shard signature is not independent authority.",
        "ordering": "One bounded request and terminal response frame each run; trajectory and shard rows are indexed in causal-step order.",
        "replay": "Fresh challenges and current-source commitments reject substituted responses; a new run deliberately recomputes the selected scenario.",
        "compatibility": "Exact installed request, response, certificate, and shard schemas are required; no implicit version negotiation occurs.",
    },
    "PROTOCOL-0.3-failures-and-progress": {
        "failure_assumptions": "The host interpreter, filesystem, subprocess transport, and selected witness keys are trusted only within the stated local boundary.",
        "safety": "Malformed, stale, reordered, omitted, substituted, or invalidly signed coordinates cannot supply a validated response.",
        "liveness": "Finite process timeouts bound waiting but do not guarantee host scheduling, worker success, or distributed progress.",
        "recovery": "Failure yields FAIL or UNKNOWN as typed; recovery is a newly bound run, never automatic acceptance or hidden retry.",
    },
}

_SIM_POLICY = {
    "POLICY-0.1-rules-and-precedence": {
        "scope": "Exact finite SIM trajectory, dynamics, channels, shards, response, isolation, and fresh software-resource propositions selected by the caller.",
        "decision_inputs": "Request, policy, mechanism/source digests, scenario and collection commitments, witness keys where selected, and finite limits.",
        "precedence": "Structural and binding checks precede execution; contradictions are FAIL; unavailable dependencies or unsupported claims remain UNKNOWN.",
        "defaults": "No physical fidelity, confinement, witness independence, sim-to-real safety, or external effect absence is inferred by default.",
    },
    "POLICY-0.2-authority-and-exceptions": {
        "authority": "The local caller selects the proposition and policy; the checker verifies its exact form but does not authenticate external scientific or operational authority.",
        "exceptions": "No exception bypasses source, scenario, signature, finite-bound, or model-replay checks.",
        "revisions": "Policy and installed mechanism/source digests define each active revision; changed bytes require a new selection and run.",
        "activation": "The policy applies to one selected SIM check and grants no continuing process, physical actuator, or financial authority.",
    },
    "POLICY-0.3-enforcement-and-decisions": {
        "enforcement_points": "Parent request admission, closed source loading, worker execution, response validation, and certificate recheck.",
        "decision_evidence": "Bounded response and certificate fields retain exact selected commitments, typed outcome, reproduced state/resource observations, and exclusions.",
        "bypass_handling": "Unknown fields, missing steps, stale source, invalid signatures, mismatched responses, and exhausted bounds cannot reach PASS.",
        "unavailable_behavior": "Unavailable execution, dependency, calibration, or external truth remains UNKNOWN rather than being coerced into a simulated success.",
    },
}


_HARNESS_TRANSACTION = {
    "TRANSACTION-0.1-effects-and-authority": {
        "effects": "Launch or relaunch the selected subject and sequentially publish its receipt bundle; undeclared subject effects remain explicitly unobserved.",
        "preconditions": "Validate command, working directory, declared inputs, selected runner or backend, timeout, and source bindings before launch; subject-side preconditions are not established.",
        "authorization": "Explicit local operator invocation and configured backend selection authorize the HARNESS call only; authority over undeclared filesystem, network, descendant, or external subject effects is not established.",
        "resources": "Selected child working directory and declared paths, receipt directory, and temporary compiler artifacts; inherited environment and input, descendants, network, undeclared filesystem, and external effects remain unobserved.",
    },
    "TRANSACTION-0.2-commit-and-failure": {
        "commit": "A child exit and parent receipt are observations, not transactional commit; receipt files are written sequentially rather than as one atomic publication.",
        "abort": "Prelaunch validation can refuse launch, and timeout or launch errors bound the parent call; none rolls back, compensates, or proves absence of subject effects already produced.",
        "finality": "No subject or global finality is claimed. A completed child remains completed when output hashing or later receipt processing fails.",
        "partial_failure": "A subject can change undeclared resources before nonzero exit, timeout, or post-processing failure, and sequential receipt writes can remain partial; no general compensation mechanism is present.",
    },
    "TRANSACTION-0.3-retry-and-replay": {
        "duplicate_detection": "There is no cross-invocation duplicate guard; caller-selected or default receipt identifiers and output overwrites do not prevent repeating subject effects.",
        "idempotency": "Idempotency is not assumed. Repeated run, explicit rerun, backend, or language-extension invocation can repeat arbitrary subject effects and overwrite declared artifacts.",
        "retry_limits": "Core capture performs no automatic subject retry and bounds each parent wait by the declared timeout; fresh operator invocations and explicit rerun remain possible.",
        "replay": "The rerun path deliberately executes the stored command again; the read-only rehash path does not execute, and neither path proves subject idempotency.",
    },
}

_HARNESS_MEASUREMENT = {
    "MEASUREMENT-0.1-phenomenon-and-method": {
        "phenomenon": "Parent-visible subprocess-interface state: launch attempt, known process start, return code, captured stream bytes, and stream completeness.",
        "method": "Create a parent-owned launch identity immediately around subprocess invocation, capture the completed/timeout/error interface, hash complete observed bytes, and recheck canonical structure.",
        "source": "The local parent subprocess API and the exact captured stdout/stderr/error values returned to the HARNESS.",
        "observation_vs_estimate": "Fields record what the parent interface observed; descendants, network, undeclared filesystem, inherited input/environment, and external effects are not estimated as absent.",
    },
    "MEASUREMENT-0.2-units-time-and-uncertainty": {
        "units": "Stream lengths and retention limits are bytes; timeout is seconds; return code is an operating-system process-interface integer.",
        "reference_frame": "One parent launch identity, resolved working-directory digest, declared command, and parent-visible process interface.",
        "observation_time": "Launch and terminal interface phases are ordered, but no trusted wall-clock observation timestamp is claimed.",
        "arrival_time": "Streams and terminal state arrive when the parent subprocess call returns or raises; no real-time latency guarantee is exported.",
        "uncertainty": "Tri-state and completeness fields retain UNKNOWN, PARTIAL, and UNOBSERVED rather than assigning certainty outside the interface.",
    },
    "MEASUREMENT-0.3-validity-and-missingness": {
        "validity": "Exact canonical fields, launch binding, state combinations, stream digest/length, retention semantics, and inner digest must recheck.",
        "missingness": "Unobserved streams or effects remain explicit null/UNOBSERVED/UNKNOWN values; they are never replaced by empty bytes or NO.",
        "freshness": "Each execution receives a fresh parent-generated launch identity; a prior receipt cannot prove a current launch.",
        "provenance": "The observation binds exact parent-captured values and source bytes but provides integrity, not subject identity authentication or whole-HARNESS truth.",
    },
}

_HARNESS_SENSOR = {
    "SENSOR-0.1-acquisition-and-observations": {
        "acquisition": "The parent subprocess interface captures launch outcome, return code, stdout, stderr, timeout fragments, and exception phase around one invocation.",
        "phenomena": "Only parent-visible process-interface events and bytes, not descendant behavior or external effects.",
        "measurements": "Launch/process tri-states, return code, stream availability/completeness, byte counts, digests, and bounded retained prefixes.",
        "deployment": "Local HARNESS parent and selected runner/backend; no hostile-host isolation, process-tree ownership, or remote sensor claim.",
    },
    "SENSOR-0.2-calibration-and-envelope": {
        "calibration_applicability": "Physical calibration is inapplicable to this software interface; semantic completeness is bounded by documented observable and unobserved channels.",
        "calibration_evidence": "Controlled completed, nonzero, timeout, launch-error, post-processing-error, truncation, and malformed-record cases test interface-state correspondence.",
        "operating_range": "Positive bounded timeouts, nonnegative retention limits, canonical bounded records, and the selected runner's declared language/runtime surface.",
        "drift": "Current source digests and schema validation detect implementation drift; operating-system or runtime semantic drift is not certified away.",
    },
    "SENSOR-0.3-sampling-and-faults": {
        "sampling": "One acquisition per parent invocation, with complete terminal streams when available and explicitly partial fragments on timeout.",
        "latency": "The caller-selected positive timeout bounds the wait; no scheduling or real-time response guarantee is made.",
        "fault_detection": "Impossible state combinations, digest/length mismatches, missing required fields, and substituted launch bindings refute the record.",
        "recovery": "A failed capture stays typed as failure or uncertainty; a new invocation gets a new identity and does not repair or authenticate the prior one.",
    },
}

_HARNESS_ACTUATOR = {
    "ACTUATOR-0.1-command-to-effect": {
        "commands": "The validated argv, declared working directory, runner/compiler selection, and language-extension arguments submitted by the HARNESS.",
        "targets": "The selected local process-launch interface only; the child, descendants, network, files, hardware, money, and services are not established effect targets.",
        "effect_domains": "LAUNCH_SUBMISSION_AND_PARENT_PROCESS_INTERFACE_ONLY; no subject or real-world effect is inferred from acceptance or exit.",
        "authority": "Explicit operator invocation and local host permissions authorize submission, not the command's ultimate external consequences.",
    },
    "ACTUATOR-0.2-response-and-limits": {
        "units_and_frames": "Arguments are strings, cwd is declared and digest-bound, timeout is seconds, and retained output limits are bytes.",
        "response": "The parent receives launch error, timeout, nonzero exit, or completed-process interface state; response does not prove child semantic success.",
        "limits": "Manifest validation, portable path checks where required, finite timeout, bounded output retention, and extension-specific compiler/runtime selection.",
        "saturation": "Timeout or retention truncation is explicit; the HARNESS does not reinterpret truncated output or a killed wait as a safe external state.",
    },
    "ACTUATOR-0.3-feedback-and-interlocks": {
        "effect_feedback": "Only parent-visible process state and streams feed the receipt; external-effect feedback remains unobserved.",
        "interlocks": "Prelaunch validation, selected runner policy, source binding, cwd checks, timeout, and observation recheck gate receipt admission.",
        "failure_states": "Prelaunch refusal, launch error, nonzero exit, timeout, partial streams, and post-processing error remain distinct.",
        "recovery": "The operator may explicitly rerun; no automatic retry, rollback, compensation, physical safe state, or guaranteed child termination is claimed.",
    },
}

_HARNESS_PROTOCOL = {
    "PROTOCOL-0.1-participants-and-states": {
        "participants": "Local caller, HARNESS, selected language runner/backend, subject process, and receipt/reproduction consumer.",
        "roles": "Caller selects; HARNESS validates and observes; runner translates the launch; subject executes; receipt consumer rechecks or explicitly reruns.",
        "states": "Draft validation, launch prepared, launch attempted, process start known/unknown, terminal interface outcome, receipt publication, rehash, and explicit rerun.",
        "transitions": "Only validated inputs reach launch; typed outcomes reach receipt construction; rehash reads while rerun deliberately creates a fresh launch.",
    },
    "PROTOCOL-0.2-ordering-and-replay": {
        "message_authority": "Local configuration and installed runner selection are trust assumptions; stream bytes and digests do not authenticate the subject actor.",
        "ordering": "One launch observation precedes its receipt; sequential receipt files have no atomic group ordering or distributed consensus claim.",
        "replay": "Rehash never executes; explicit rerun repeats the stored command with a fresh launch identity and can repeat subject effects.",
        "compatibility": "Exact manifest, receipt, process-observation, runner, and extension schema/version checks replace implicit negotiation.",
    },
    "PROTOCOL-0.3-failures-and-progress": {
        "failure_assumptions": "The host, selected interpreter/compiler, subprocess API, filesystem, and optional backend remain explicit dependencies.",
        "safety": "Malformed input, stale binding, invalid observation, missing output, or incompatible runner cannot silently yield a conforming receipt.",
        "liveness": "Timeout bounds the parent wait but does not prove descendant termination, backend availability, or whole-subject progress.",
        "recovery": "Failures remain typed and inspectable; only an explicit new invocation retries, and partial receipt publication may require operator repair.",
    },
}

_HARNESS_POLICY = {
    "POLICY-0.1-rules-and-precedence": {
        "scope": "Local command admission, language/backend selection, object-role controls, timeout/output bounds, process observation, and receipt/reproduction behavior.",
        "decision_inputs": "Manifest command/cwd/inputs/outputs/resources, selected language and optional backend, object role, source bindings, and captured outcome.",
        "precedence": "Schema/source/precondition failures refuse before launch; typed launch/runtime failures precede receipt claims; unobserved channels never default to safe.",
        "defaults": "Python is the default language runner, optional backends require explicit selection, and absence of evidence does not establish confinement or external-effect absence.",
    },
    "POLICY-0.2-authority-and-exceptions": {
        "authority": "The local operator and host configuration choose the command and runner; this policy grants no authority over subject-owned external resources.",
        "exceptions": "Object-role controls and required bindings cannot be bypassed by relabeling; optional backend absence stays explicit.",
        "revisions": "Installed runner, extension, observation, and validation source define the active revision and are bound by current-source review.",
        "activation": "Rules activate per invocation and receipt; no persistent approval, deployment, publication, or release authority follows.",
    },
    "POLICY-0.3-enforcement-and-decisions": {
        "enforcement_points": "Manifest validation, runner resolution, prelaunch checks, subprocess capture, output validation, receipt construction, rehash, and rerun selection.",
        "decision_evidence": "Receipts retain selected inputs, source and output digests, parent process observation, declared refutation surface, and typed outcome.",
        "bypass_handling": "Unknown fields, invalid paths, missing inputs, unavailable runner, stale source, malformed observation, and mismatched outputs cannot silently pass.",
        "unavailable_behavior": "Unavailable backend, compiler, interpreter, or evidence remains a typed failure/UNKNOWN boundary and never proves the subject safe.",
    },
}


_LEDGER_DECLARATIONS = {
    "LEDGER-0.1-authoritative-history": {
        "history": "SQLite issuance rows retain each consumed invocation and exact proposal bytes.",
        "state": "ledger_meta selects ledger_id, policy_domain and current policy_epoch; issuance retains consumption.",
        "ordering": "The local AUTOINCREMENT sequence orders accepted entries; host timestamps are observations, not time truth.",
        "authority": "IssuerLedgerSelection is provisioned by the authenticated host, not decoded from candidate input.",
    },
    "LEDGER-0.2-accounting-invariants": {
        "units": "Integer invocation counts, retained-byte counts, sequences and policy epochs; no monetary units are represented.",
        "balance_rules": "Unique invocation_id consumption; MAX_INVOCATIONS and MAX_RETAINED_BYTES bound admitted state.",
        "rounding": "No rounding: integer bounds and exact proposal-byte digests are compared.",
        "sources_and_sinks": "Explicit provisioning creates the ledger; commit_issuance inserts once; policy epochs strictly advance. No deletion API is declared.",
    },
    "LEDGER-0.3-correction-and-recovery": {
        "corrections": "Advance the policy epoch to invalidate old selections; in-place correction of issuance records is not an offered operation.",
        "replay": "recheck_issuance_commit reads the same row; repeated consumption is refused.",
        "reconciliation": "Compare exact proposal, receipt, configured identity, epoch and mechanism digests with retained bytes.",
        "recovery": "Storage unavailability or uncertain commit returns UNKNOWN. Backup restoration and global uniqueness are not established.",
    },
}

_LEDGER_TRANSACTION = {
    "TRANSACTION-0.1-effects-and-authority": {
        "effects": "Provision tables, insert one issuance, or advance the configured epoch in one local database.",
        "preconditions": "Validate host selection, exact proposal digest, epoch, uniqueness and resource bounds before commit.",
        "authorization": "Host provisioning and external issuer checks are prerequisites; this primitive does not authenticate an external authority channel.",
        "resources": "One configured local SQLite database and its journal; no network or distributed transaction.",
    },
    "TRANSACTION-0.2-commit-and-failure": {
        "commit": "BEGIN IMMEDIATE followed by COMMIT, with synchronous=FULL; construct the bounded receipt before commit.",
        "abort": "ROLLBACK the active transaction on an exception or known replay.",
        "finality": "A returned local commit receipt is not worldwide finality or public historical execution.",
        "partial_failure": "Cancellation, storage errors and uncertain commit remain UNKNOWN; the caller must recheck, not infer non-consumption.",
    },
    "TRANSACTION-0.3-retry-and-replay": {
        "duplicate_detection": "UNIQUE invocation_id plus an explicit existing-row check within the transaction.",
        "idempotency": "Repeated consumption is rejected, not issued again; read-only recheck is separate.",
        "retry_limits": "No automatic consumption retry; SQLite busy waiting is bounded by MAX_BUSY_SECONDS.",
        "replay": "Exact local row replay only, with current selection, policy epoch and mechanism binding.",
    },
}

_LEDGER_POLICY = {
    "POLICY-0.1-rules-and-precedence": {
        "scope": "One host-provisioned local invocation-consumption ledger, its identity/domain/epoch, and bounded issuance rows.",
        "decision_inputs": "IssuerLedgerSelection, exact proposal and status digests, invocation id, commit time, current database state, and fixed capacity ceilings.",
        "precedence": "Selection/proposal validation precedes BEGIN IMMEDIATE; known replay is FAIL; capacity or uncertain storage/commit is UNKNOWN.",
        "defaults": "Candidates cannot choose the ledger path or epoch, and no public authority, worldwide uniqueness, or monetary meaning is assumed.",
    },
    "POLICY-0.2-authority-and-exceptions": {
        "authority": "An authenticated host provisions the absolute non-UNC path, ledger identity, policy domain, and current epoch outside candidate input.",
        "exceptions": "No override bypasses proposal digest, epoch, identity, uniqueness, retained-capacity, or mechanism checks.",
        "revisions": "advance_policy_epoch must strictly increase the stored epoch and invalidates old selections without rewriting issuance history.",
        "activation": "The exact selected ledger metadata is checked inside each writable or read-only database operation.",
    },
    "POLICY-0.3-enforcement-and-decisions": {
        "enforcement_points": "Selection validation, SQLite metadata check, transactional uniqueness/capacity check, precommit receipt construction, COMMIT, and read-only recheck.",
        "decision_evidence": "A bounded local receipt binds ledger/domain/epoch, invocation, sequence, proposal/status/time/mechanism digests, and exact retained proposal.",
        "bypass_handling": "Candidate-selected paths, stale epochs, malformed proposals, known replay, mismatched receipts, and changed mechanisms cannot yield PASS.",
        "unavailable_behavior": "Cancellation, storage failure, exhausted bounds, and uncertain commit remain UNKNOWN and require recheck rather than inferred non-consumption.",
    },
}

_LEDGER_PROTOCOL = {
    "PROTOCOL-0.1-participants-and-states": {
        "participants": "One installed Verifier parent and the fixed local_ledger_worker child selected by verifier-local-invocation-ledger-1; neither participant is an authenticated external authority.",
        "roles": "The parent binds a nonce plus exact object and collection digests, submits the canonical request, captures the process boundary, and checks the response; the child validates the closed request, runs fresh temporary-ledger experiments, and emits observations only.",
        "states": "The ledger-specific exchange advances from a selected source-bound adapter to one validated request, one fresh worker experiment, and either one bound observation response or a rejected, unavailable, nonzero, timed-out, malformed, oversized, or source-changed outcome.",
        "transitions": "Only the installed adapter can select the fixed worker and exact request/response schema versions; caller-supplied commands, database paths, money, subjects, and authority channels are not protocol inputs.",
    },
    "PROTOCOL-0.2-ordering-and-replay": {
        "message_authority": "Current source pins, the selected mechanism, a fresh nonce, and exact object and collection digests bind the exchange; JSON, SHA-256 digests, and the nonce authenticate no actor, host, or external authority.",
        "ordering": "The parent submits one bounded canonical JSON request on standard input; the worker captures source pins before and after its fresh experiments and emits one bounded JSON observation response on standard output for parent-side binding checks.",
        "replay": "A fresh nonce and current object, collection, selection, and source bindings distinguish each execution. A retained response is evidence of only its captured exchange and is never accepted as fresh execution; the protocol performs no automatic retry.",
        "compatibility": "Exact verifier-local-ledger-execution-request-1 and verifier-local-ledger-execution-observations-1 versions, closed field sets, echoed request equality, and unchanged source pins are required; no negotiation or permissive fallback is implemented.",
    },
    "PROTOCOL-0.3-failures-and-progress": {
        "failure_assumptions": "The interpreter and host are trusted dependencies. Missing or changed source, launch failure, nonzero exit, timeout, malformed or oversized output, incomplete capture, and request or source-pin mismatch cannot produce accepted observations.",
        "safety": "The fixed worker accepts no caller command, operator database path, money, subject, or authority channel and can issue no package PASS. This is a source-bound process interface, not a sandbox, delivery proof, child-internal observation, or external-effect confinement claim.",
        "liveness": "No completion or availability guarantee is claimed. The parent timeout only bounds how long one attempt waits; there is no automatic retry, delivery guarantee, worker progress proof, or service-uptime claim.",
        "recovery": "A failed or unavailable exchange remains failed or UNKNOWN for that attempt and requires a separately authorized fresh invocation. Temporary worker resources are scoped to that run; no durable protocol checkpoint or response replay is treated as recovery.",
    },
}

_MANIFEST_TRANSACTION = {
    "TRANSACTION-0.1-effects-and-authority": {
        "effects": "Template exclusive-create or explicit formatter replacement of the selected manifest file.",
        "preconditions": "Template refuses an existing target; formatter requires strict portable JSON and unchanged original bytes.",
        "authorization": "Explicit CLI invocation and local filesystem permissions; no publication or semantic admission authority.",
        "resources": "Selected manifest and same-directory unpublished temporary file.",
    },
    "TRANSACTION-0.2-commit-and-failure": {
        "commit": "Template writes through exclusive creation; formatter publishes via os.replace after a source-byte recheck.",
        "abort": "Exceptions propagate; formatter removes only its own unpublished temporary file.",
        "finality": "Filesystem publication only; no power-loss durability, cross-process lock or global atomicity guarantee is claimed.",
        "partial_failure": "Template write failure can leave a partial new file; a writer racing after the formatter recheck is not excluded by a lock.",
    },
    "TRANSACTION-0.3-retry-and-replay": {
        "duplicate_detection": "Exclusive create rejects duplicate template publication; formatting checks original bytes before replacement.",
        "idempotency": "Canonical formatting is content-idempotent; template creation is intentionally not repeated over an existing target.",
        "retry_limits": "No automatic retries or background replay.",
        "replay": "A fresh command rereads current input; prior success does not supply current admission evidence.",
    },
}

_MANIFEST_PROTOCOL = {
    "PROTOCOL-0.1-participants-and-states": {
        "participants": "One installed Verifier parent and the fixed manifest_write_worker child selected by verifier-manifest-publication-1; neither endpoint is an authenticated external authority.",
        "roles": "The owned adapter selects the closed request and response versions and delegates transport to the package worker exchange; the fixed child validates the request, runs private-file publication experiments, and emits observations only.",
        "states": "The manifest-specific exchange advances from a source-bound selected adapter to one validated request, one fresh private worker experiment, and either one bound observation response or a rejected, unavailable, nonzero, timed-out, malformed, oversized, or source-changed outcome.",
        "transitions": "Only the installed adapter can select the fixed worker and manifest request/response schemas; caller commands, operator manifests, subject imports, and publication authority are not protocol inputs.",
    },
    "PROTOCOL-0.2-ordering-and-replay": {
        "message_authority": "Current source pins, the selected mechanism, a fresh nonce, and exact object and collection digests bind the exchange; JSON and SHA-256 identify bytes but authenticate no actor, host, or external authority.",
        "ordering": "The package worker exchange submits one bounded canonical request before the child runs private-file experiments; the child captures source pins before and after execution and returns one bounded response for parent-side request and source binding checks.",
        "replay": "A fresh nonce plus current object, collection, selection, and source bindings distinguish each execution. Retained observations describe only their captured exchange and are never accepted as a fresh run; no automatic retry is performed.",
        "compatibility": "Exact verifier-manifest-publication-request-1 and verifier-manifest-publication-observations-1 versions, closed field sets, echoed request equality, and unchanged source pins are required; no negotiation or permissive fallback is implemented.",
    },
    "PROTOCOL-0.3-failures-and-progress": {
        "failure_assumptions": "The interpreter, host, and delegated package worker transport are trusted dependencies. Missing or changed source, launch failure, nonzero exit, timeout, malformed or oversized output, incomplete capture, and request or source-pin mismatch cannot produce accepted observations.",
        "safety": "The fixed child accepts no caller command, operator manifest, or subject module and can issue no package PASS. This is a source-bound process interface, not a sandbox, application-authority proof, power-loss durability claim, or external-effect confinement claim.",
        "liveness": "No completion or availability guarantee is claimed. The parent timeout bounds one attempt only; there is no automatic retry, delivery guarantee, child-progress proof, or service-uptime claim.",
        "recovery": "A failed or unavailable exchange remains failed or UNKNOWN for that attempt and requires a separately authorized fresh invocation. Private worker resources are scoped to that run; no retained response is treated as a recovery checkpoint.",
    },
}

_OPENSHELL_TRANSACTION = {
    "TRANSACTION-0.1-effects-and-authority": {
        "effects": "Creates one uniquely labelled sandbox, stages exact selected source bytes, launches the selected subject, then stops and deletes only that owned sandbox.",
        "preconditions": "Explicit OpenShell selection, a canonical bounded config, a digest-pinned image, the pinned CLI and healthy gateway, exact input paths, and passing policy probes are required before subject launch.",
        "authorization": "The invoking user and configured gateway credentials authorize the CLI operations; Verifier adds an ownership token but claims no wider gateway, subject, publication, physical, or financial authority.",
        "resources": "One named gateway and workspace, one fresh sandbox, bounded CPU and memory, selected source files, one subject process, and bounded command streams.",
    },
    "TRANSACTION-0.2-commit-and-failure": {
        "commit": "Subject completion is recorded only after exact-byte staging and pre-execution controls; cleanup completes only when the owned sandbox is observed absent after stop and delete.",
        "abort": "Any malformed input, incompatible response, denied probe, source mismatch, timeout, output overflow, binding drift, or command failure prevents a successful result and enters owned cleanup when creation may have occurred.",
        "finality": "A PASS is final only for the captured subject process and named probes in that fresh sandbox; remote durability, descendant effects, service continuity, and whole-object conformance are not established.",
        "partial_failure": "Transport uncertainty can leave execution or cleanup UNKNOWN; creation ownership is recorded before the create call so later cleanup never assumes noncreation from a client timeout.",
    },
    "TRANSACTION-0.3-retry-and-replay": {
        "duplicate_detection": "A fresh random ownership token and unique sandbox name distinguish each invocation, and cleanup rechecks the exact ownership label before mutation.",
        "idempotency": "Source inspection and policy probes are repeatable over the same bytes; create and subject execution are not treated as idempotent or silently replayed.",
        "retry_limits": "Commands have fixed timeouts, deletion observation has five bounded polls, and there is no automatic subject or create retry.",
        "replay": "A later run creates a new sandbox, reacquires gateway and policy observations, restages and rehashes source, and cannot reuse a prior PASS as current evidence.",
    },
}

_OPENSHELL_MEASUREMENT = {
    "MEASUREMENT-0.1-phenomenon-and-method": {
        "phenomenon": "Selected gateway health and version, sandbox identity and phase, admitted policy binding, exact staged bytes, named isolation probes, subject process result, and cleanup state.",
        "method": "Bounded subprocess capture of pinned OpenShell commands plus deterministic in-sandbox Python probes, canonical JSON parsing, source hashing, and before/after binding comparison.",
        "source": "CLI response bytes, gateway and sandbox JSON, probe stdout, process exit state, local monotonic elapsed time, and exact selected file bytes.",
        "observation_vs_estimate": "The fields are interface observations from one run; they are not independent attestation, complete host or image inventory, physical measurement, or an estimate of unobserved effects.",
    },
    "MEASUREMENT-0.2-units-time-and-uncertainty": {
        "units": "Streams are bytes, elapsed duration is seconds, timeouts are integer seconds, resources are CPU count and enumerated MiB, and probe results are booleans or exact identifiers.",
        "reference_frame": "Every observation is scoped to the selected gateway, workspace, unique sandbox generation, ownership token, config, source digests, and command record.",
        "observation_time": "Host monotonic elapsed duration bounds each CLI interaction; no trusted remote wall-clock or cross-host clock synchronization is claimed.",
        "arrival_time": "Responses are captured after their ordered CLI commands with bounded stream collection; remote production time and network transit decomposition are unobserved.",
        "uncertainty": "Timeout, truncation, incomplete streams, transport ambiguity, unsupported response shape, or cleanup ambiguity remain UNKNOWN rather than being assigned zero uncertainty.",
    },
    "MEASUREMENT-0.3-validity-and-missingness": {
        "validity": "Pinned version, canonical response shapes, exact ownership and workspace, unchanged generation and policy, source-digest equality, named probe truth, and bounded complete capture are required.",
        "missingness": "A missing CLI, gateway, response field, probe, binding, execution result, or cleanup confirmation is explicit failure or UNKNOWN; no absent value is synthesized.",
        "freshness": "Gateway, sandbox, source, policy, probe, execution, and cleanup observations are reacquired during each fresh invocation and expire with that bounded run.",
        "provenance": "The result retains command argv, exit state, bounded streams and digests, adapter and CLI digests, source digests, config, gateway record, before/after bindings, and cleanup status.",
    },
}

_OPENSHELL_SENSOR = {
    "SENSOR-0.1-acquisition-and-observations": {
        "acquisition": "The host launches pinned OpenShell CLI queries and sandbox commands; controlled Python probes acquire filesystem, identity, network, source, and subject-process observations.",
        "phenomena": "Software-visible gateway state, sandbox policy and lifecycle state, staged-byte identity, named containment controls, process output and exit, and owned-resource disappearance.",
        "measurements": "The acquired values feed the OpenShell MEASUREMENT declarations and retain raw bounded command evidence rather than only a derived verdict.",
        "deployment": "Optional host-side adapter to a selected OpenShell 0.1.3 gateway and one fresh remote or local gateway-managed sandbox; no physical transducer is deployed.",
    },
    "SENSOR-0.2-calibration-and-envelope": {
        "calibration_applicability": "Physical calibration is inapplicable; software interpretation instead requires exact CLI version, adapter bytes, schemas, policy shape, and named probe semantics.",
        "calibration_evidence": "CLI and adapter SHA-256 digests, exact version output, canonical gateway and sandbox records, requested policy digest, admitted policy binding, and deterministic probe code are retained.",
        "operating_range": "At most 256 selected files and 8 MiB total input, 1 MiB per output stream, 1 to 8 CPUs, enumerated 256 to 4096 MiB memory, and bounded command timeouts.",
        "drift": "Gateway version, sandbox generation, workspace, labels, policy, source bytes, and before/after binding are rechecked; any observed drift prevents PASS.",
    },
    "SENSOR-0.3-sampling-and-faults": {
        "sampling": "One ordered acquisition sequence per fresh run: gateway preflight, sandbox binding, negative probes, source check before and after execution, process result, and cleanup observation.",
        "latency": "Each command has an explicit timeout and host-monotonic elapsed record; no claim is made about subcommand or remote scheduling latency.",
        "fault_detection": "Nonzero exit, timeout, overflow, incomplete stream, malformed JSON, wrong version, missing target, failed probe, changed binding, source mutation, and cleanup ambiguity are named.",
        "recovery": "The adapter attempts stop and delete only after revalidating its ownership label; inability to prove cleanup downgrades a prior PASS to UNKNOWN.",
    },
}

_OPENSHELL_CONTROLLER = {
    "CONTROLLER-0.1-feedback-and-authority": {
        "objectives": "Admit only the selected bounded environment, preserve exact source and sandbox bindings through execution, and remove the owned sandbox afterward.",
        "feedback": "Every stage consumes bounded CLI exit and response evidence, probe results, source hashes, sandbox binding state, and final listing state before selecting the next command.",
        "commands": "Gateway queries, sandbox create, get, exec, upload, source check, stop, delete, and ownership-filtered list operations.",
        "authority": "Control is limited to the explicitly selected gateway/workspace and the one fresh sandbox bearing the invocation's random ownership label.",
    },
    "CONTROLLER-0.2-timing-and-stability": {
        "timing": "Sequential fixed command deadlines, a bounded subject timeout, bounded stream joins, and five short cleanup observations constrain waiting.",
        "stability_assumptions": "The gateway and CLI must remain compatible and the sandbox binding must remain identical before and after execution; no continuous-system stability theorem is claimed.",
        "operating_envelope": "Digest-pinned image, finite source and stream sizes, fixed CPU and memory choices, denied ambient network, restricted filesystem, nonroot process, and one subject invocation.",
        "saturation": "Input, stream, timeout, CPU, memory, name, and response-shape limits terminate or refuse the run rather than widening silently.",
    },
    "CONTROLLER-0.3-intervention-and-failure": {
        "feedback_loss": "Timeout, incomplete capture, malformed response, unavailable gateway, or ambiguous remote state yields failure or UNKNOWN and never an inferred successful transition.",
        "arbitration": "A unique ownership label selects the only mutable sandbox; the adapter does not arbitrate unrelated sandboxes, global capacity, or concurrent gateway policy.",
        "intervention": "Local CLI processes can be killed on timeout or overflow, and an owned sandbox can be stopped and deleted; subject-level corrigibility and service availability remain unestablished.",
        "failure_behavior": "Subject launch is withheld until controls pass, binding drift prevents PASS, and uncertain cleanup downgrades successful execution to UNKNOWN.",
    },
}

_OPENSHELL_ACTUATOR = {
    "ACTUATOR-0.1-command-to-effect": {
        "commands": "OpenShell create, upload, sandbox exec, stop, and delete requests plus process kill of the local CLI on bounded capture failure.",
        "targets": "The uniquely labelled sandbox resource, its staged files, its selected process, and the local CLI process; no physical target is selected.",
        "effect_domains": "Gateway-managed computational resource lifecycle, sandbox filesystem staging, and process execution only; external subject effects remain outside the observation boundary.",
        "authority": "The explicit caller's configured gateway permissions plus exact workspace, ownership label, and selected sandbox name bound command authority.",
    },
    "ACTUATOR-0.2-response-and-limits": {
        "units_and_frames": "Commands use exact sandbox names, POSIX in-sandbox paths, CPU counts, enumerated MiB, seconds, and selected host paths scoped to the repository root.",
        "response": "Bounded exit code and streams, canonical JSON state, source hash comparison, before/after binding equality, and owned-resource absence report command response.",
        "limits": "No host mount, port forward, credential attachment, automatic provider, login shell, unrestricted network rule, image tag without digest, or mutation of an unowned sandbox is admitted.",
        "saturation": "Timeout or output capacity kills the local CLI, records incomplete execution when necessary, and prevents a successful actuator result.",
    },
    "ACTUATOR-0.3-feedback-and-interlocks": {
        "effect_feedback": "Sandbox get/list responses, named policy probes, exact source checks, subject process capture, and cleanup observation are the bounded computational feedback surface.",
        "interlocks": "Strict config validation, pinned CLI and image, healthy gateway, ownership label, nonroot policy, denied direct network and selected filesystem access, and unchanged binding gate effects.",
        "failure_states": "Rejected commands, transport uncertainty, subject failure, binding drift, source mutation, inability to stop, or inability to prove deletion are retained distinctly.",
        "recovery": "Only a sandbox whose exact random ownership label is reobserved may be stopped or deleted; cleanup failure is surfaced and never broadened to unrelated resources.",
    },
}

_OPENSHELL_PROTOCOL = {
    "PROTOCOL-0.1-participants-and-states": {
        "participants": "Verifier runner, optional adapter, pinned OpenShell CLI, selected gateway/workspace, uniquely labelled sandbox, in-sandbox probes, and selected subject process.",
        "roles": "Verifier validates and sequences; the CLI transports commands; the gateway manages sandbox state; probes observe named controls; the subject supplies only its selected process behavior.",
        "states": "Unselected, config-validated, gateway-observed, creation-uncertain or created, bound, probed, staged, executed, rechecked, stopped, deleted, failed, or UNKNOWN.",
        "transitions": "Each ordered CLI result and validation permits exactly the next lifecycle step; failures divert to owned cleanup and a fail-closed final status.",
    },
    "PROTOCOL-0.2-ordering-and-replay": {
        "message_authority": "Only the pinned CLI invoked with the selected gateway/workspace and canonical responses bound to the random ownership label supplies backend state evidence.",
        "ordering": "Version and gateway preflight precede create; binding and probes precede upload; source check precedes and follows subject execution; ownership recheck precedes stop/delete.",
        "replay": "Every invocation uses a fresh token and sandbox, reacquires state, and refuses to treat a prior receipt or same-named external resource as current participation.",
        "compatibility": "Adapter result schema, config schema, OpenShell 0.1.3 version, canonical JSON shapes, pinned image digest, policy fields, and profile constraints must agree.",
    },
    "PROTOCOL-0.3-failures-and-progress": {
        "failure_assumptions": "CLI or network calls can fail, time out, truncate, return malformed data, create after client uncertainty, change bindings, or leave cleanup ambiguous.",
        "safety": "No local fallback, unpinned image, inherited OpenShell override, login shell, ambient network grant, unowned cleanup, source mutation, or inferred success is allowed.",
        "liveness": "Per-command timeouts, bounded output readers, finite source set, one subject call, and finite cleanup polling bound client waiting but do not promise gateway availability.",
        "recovery": "The adapter records creation ownership before the call, rechecks the label, attempts stop/delete, and returns failure or UNKNOWN when safe completion cannot be established.",
    },
}

_OPENSHELL_POLICY = {
    "POLICY-0.1-rules-and-precedence": {
        "scope": "Admission and bounded execution of an explicitly selected optional OpenShell environment for one runner invocation.",
        "decision_inputs": "Exact config and profile, digest-pinned image, CPU and memory bounds, adapter and CLI versions, gateway/workspace, source paths and digests, effective policy, probes, bindings, execution, and cleanup evidence.",
        "precedence": "Malformed or incompatible input refuses before effects; controls and exact binding precede subject launch; known contradiction is FAIL; transport or cleanup ambiguity is UNKNOWN.",
        "defaults": "OpenShell is not selected by the basic runner, network has no grants, filesystem access is enumerated, execution is nonroot, availability is not claimed, and no obligation is discharged by backend success alone.",
    },
    "POLICY-0.2-authority-and-exceptions": {
        "authority": "The caller explicitly selects the backend and config while existing gateway credentials authorize service operations; the adapter only narrows targets to its owned sandbox.",
        "exceptions": "No override permits unpinned images, broader resources, host mounts, network grants, login shells, automatic providers, alternate lifecycle, unowned cleanup, or a local fallback.",
        "revisions": "Config and result schemas, pinned OpenShell version, adapter and environment-projection digests, and effective policy bytes identify the selected policy revision.",
        "activation": "Policy activates only for an explicit --sandbox openshell invocation after config validation and is rechecked through returned binding and probe evidence.",
    },
    "POLICY-0.3-enforcement-and-decisions": {
        "enforcement_points": "Config parsing, executable/version check, gateway preflight, create parameters, binding validation, negative probes, source staging checks, execution capture, post-binding check, and ownership-checked cleanup.",
        "decision_evidence": "The retained result binds config, code and CLI digests, command records, gateway state, requested and effective controls, exact sources, process result, before/after bindings, environment projection, and cleanup.",
        "bypass_handling": "Unknown fields, environment overrides, custom image tags, expanded resource values, policy drift, failed probes, source escape, binding drift, and cleanup ownership mismatch prevent PASS.",
        "unavailable_behavior": "Missing CLI or gateway and ambiguous transport, execution, capture, or cleanup remain explicit UNKNOWN unless a validated local contradiction warrants FAIL.",
    },
}


_REVIEWS = {
    "vstd-core-pure-verifier": _Review(
        "VERIFIER",
        _PURE_VERIFIER_PATHS,
        (),
        {},
        {},
        {},
    ),
    "vstd-hardware": _Review(
        "HARDWARE",
        _HARDWARE_PATHS,
        ("ASSET", "MEASUREMENT", "POLICY"),
        {
            "ASSET": (
                "src/verifier/domains/hardware.py",
                "src/verifier/domains/contracts/hardware_capacity.py",
                "src/verifier/domains/contracts/hardware_inventory.py",
                "src/verifier/domains/contracts/hardware_inventory_closure.py",
            ),
            "MEASUREMENT": (
                "src/verifier/domains/hardware.py",
                "src/verifier/domains/contracts/hardware_measurements.py",
                "src/verifier/domains/contracts/hardware_substrate_observations.py",
            ),
            "POLICY": _HARDWARE_PATHS,
        },
        _HARDWARE_REASONS,
        _merge(_HARDWARE_ASSET, _HARDWARE_MEASUREMENT, _HARDWARE_POLICY),
    ),
    "vstd-simulation": _Review(
        "SIM",
        _SIM_PATHS,
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL", "POLICY"),
        {
            "TRANSACTION": (
                "src/verifier/domains/contracts/sim_resource_fresh.py",
                "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
                "src/verifier/domains/contracts/sim_fresh_worker.py",
            ),
            "MEASUREMENT": (
                "src/verifier/domains/contracts/sim_resource_fresh.py",
                "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
                "src/verifier/domains/contracts/sim_fresh_worker.py",
            ),
            "SENSOR": (
                "src/verifier/domains/contracts/sim_resource_fresh.py",
                "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
                "src/verifier/domains/contracts/sim_fresh_worker.py",
            ),
            "ACTUATOR": (
                "src/verifier/domains/sim.py",
                "src/verifier/domains/contracts/sim_response.py",
            ),
            "PROTOCOL": (
                "src/verifier/domains/contracts/sim_resource_fresh.py",
                "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
                "src/verifier/domains/contracts/sim_fresh_worker.py",
                "src/verifier/domains/contracts/sim_response.py",
                "src/verifier/domains/contracts/sim_shard_signatures.py",
            ),
            "POLICY": (
                "src/verifier/domains/contracts/sim_resource_fresh.py",
                "src/verifier/domains/contracts/sim_response.py",
                "src/verifier/domains/contracts/sim_shard_signatures.py",
            ),
        },
        _SIM_REASONS,
        _merge(
            _SIM_TRANSACTION,
            _SIM_MEASUREMENT,
            _SIM_SENSOR,
            _SIM_ACTUATOR,
            _SIM_PROTOCOL,
            _SIM_POLICY,
        ),
    ),
    "vstd-harness": _Review(
        "HARNESS",
        _HARNESS_PATHS,
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL", "POLICY"),
        {
            "TRANSACTION": (
                "src/verifier/core/run.py",
                "src/verifier/core/run_reproduction.py",
                "src/verifier/core/run_process_observation.py",
                "src/verifier/core/owned_process.py",
                "src/verifier/runtime/language_runners.py",
                "extensions/languages/src/vstd_languages/__init__.py",
                "extensions/languages/src/vstd_languages/extended_batch_two.py",
                "extensions/languages/src/vstd_languages/extended_batch_three.py",
            ),
            "MEASUREMENT": (
                "src/verifier/core/run.py",
                "src/verifier/core/run_process_observation.py",
                "src/verifier/core/owned_process.py",
                "src/verifier/runtime/language_runners.py",
                "extensions/languages/src/vstd_languages/__init__.py",
                "extensions/languages/src/vstd_languages/extended_batch_two.py",
                "extensions/languages/src/vstd_languages/extended_batch_three.py",
            ),
            "SENSOR": (
                "src/verifier/core/run.py",
                "src/verifier/core/run_process_observation.py",
                "src/verifier/core/owned_process.py",
                "src/verifier/runtime/language_runners.py",
                "extensions/languages/src/vstd_languages/__init__.py",
                "extensions/languages/src/vstd_languages/extended_batch_two.py",
                "extensions/languages/src/vstd_languages/extended_batch_three.py",
            ),
            "ACTUATOR": (
                "src/verifier/core/run.py",
                "src/verifier/core/owned_process.py",
                "src/verifier/runtime/language_runners.py",
                "extensions/languages/src/vstd_languages/__init__.py",
                "extensions/languages/src/vstd_languages/extended_batch_two.py",
                "extensions/languages/src/vstd_languages/extended_batch_three.py",
            ),
            "PROTOCOL": (
                "src/verifier/core/run.py",
                "src/verifier/core/run_reproduction.py",
                "src/verifier/core/owned_process.py",
                "src/verifier/runtime/language_runners.py",
                "extensions/languages/src/vstd_languages/__init__.py",
                "extensions/languages/src/vstd_languages/extended_batch_two.py",
                "extensions/languages/src/vstd_languages/extended_batch_three.py",
            ),
            "POLICY": (
                "src/verifier/core/run.py",
                "src/verifier/core/run_validation.py",
                "src/verifier/core/owned_process.py",
                "src/verifier/runtime/language_runners.py",
                "extensions/languages/src/vstd_languages/__init__.py",
                "extensions/languages/src/vstd_languages/extended_batch_two.py",
                "extensions/languages/src/vstd_languages/extended_batch_three.py",
            ),
        },
        _HARNESS_REASONS,
        _merge(
            _HARNESS_TRANSACTION,
            _HARNESS_MEASUREMENT,
            _HARNESS_SENSOR,
            _HARNESS_ACTUATOR,
            _HARNESS_PROTOCOL,
            _HARNESS_POLICY,
        ),
        refuted=("LEDGER",),
        refutation_anchors={"LEDGER": _HARNESS_LEDGER_REFUTATION_ANCHORS},
    ),
    "vstd-invocation-ledger": _Review(
        "LEDGER",
        _LEDGER_PATHS,
        ("LEDGER", "TRANSACTION", "PROTOCOL", "POLICY"),
        {
            "LEDGER": _LEDGER_PATHS,
            "TRANSACTION": _LEDGER_PATHS,
            "PROTOCOL": (
                "src/verifier/runtime/local_ledger_execution.py",
                "src/verifier/runtime/local_ledger_worker.py",
            ),
            "POLICY": _LEDGER_PATHS,
        },
        _LEDGER_REASONS,
        _merge(
            _LEDGER_DECLARATIONS,
            _LEDGER_TRANSACTION,
            _LEDGER_PROTOCOL,
            _LEDGER_POLICY,
        ),
        refuted=("FINBOT",),
        refutation_anchors={
            "FINBOT": {
                "src/verifier/runtime/local_ledger_execution.py": (
                    "monetary accounting",
                ),
                "src/verifier/runtime/polish_invocation_ledger.py": (
                    "not a monetary or global ledger",
                ),
            },
        },
        dependency_operands=_protocol_dependency(
            "vstd-invocation-ledger",
            "src/verifier/runtime/local_ledger_execution.py"
        ),
    ),
    "vstd-manifest-write": _Review(
        "TRANSACTION",
        _MANIFEST_PATHS,
        ("TRANSACTION", "PROTOCOL"),
        {
            "TRANSACTION": _MANIFEST_PATHS,
            "PROTOCOL": (
                "src/verifier/runtime/manifest_write_execution.py",
                "src/verifier/runtime/manifest_write_worker.py",
            ),
        },
        _MANIFEST_REASONS,
        _merge(_MANIFEST_TRANSACTION, _MANIFEST_PROTOCOL),
        dependency_operands=_protocol_dependency(
            "vstd-manifest-write",
            "src/verifier/runtime/manifest_write_execution.py"
        ),
    ),
    protocol_relation.OBJECT_ID: _Review(
        protocol_relation.PRIMARY_KIND,
        protocol_relation.OWNED_PATHS,
        (),
        {},
        {},
        {},
    ),
    "vstd-openshell-environment": _Review(
        "ENV",
        _OPENSHELL_PATHS,
        (
            "TRANSACTION",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "POLICY",
        ),
        {
            "TRANSACTION": _OPENSHELL_PATHS,
            "MEASUREMENT": (
                "extensions/openshell/src/vstd_openshell/__init__.py",
                "extensions/openshell/src/vstd_openshell/environment.py",
            ),
            "SENSOR": (
                "extensions/openshell/src/vstd_openshell/__init__.py",
                "extensions/openshell/src/vstd_openshell/environment.py",
            ),
            "CONTROLLER": (
                "extensions/openshell/src/vstd_openshell/__init__.py",
                "extensions/openshell/src/vstd_openshell/live.py",
            ),
            "ACTUATOR": (
                "extensions/openshell/src/vstd_openshell/__init__.py",
                "extensions/openshell/src/vstd_openshell/live.py",
            ),
            "PROTOCOL": (
                "extensions/openshell/pyproject.toml",
                "extensions/openshell/src/vstd_openshell/__init__.py",
                "extensions/openshell/src/vstd_openshell/live.py",
            ),
            "POLICY": (
                "extensions/openshell/src/vstd_openshell/__init__.py",
                "extensions/openshell/src/vstd_openshell/environment.py",
                "extensions/openshell/src/vstd_openshell/live.py",
            ),
        },
        _OPENSHELL_REASONS,
        _merge(
            _OPENSHELL_TRANSACTION,
            _OPENSHELL_MEASUREMENT,
            _OPENSHELL_SENSOR,
            _OPENSHELL_CONTROLLER,
            _OPENSHELL_ACTUATOR,
            _OPENSHELL_PROTOCOL,
            _OPENSHELL_POLICY,
        ),
        refuted=("LEDGER",),
        refutation_anchors={
            "LEDGER": {
                "extensions/openshell/src/vstd_openshell/__init__.py": (
                    "ephemeral-stop-contained",
                    "RUNNER_SANDBOX_CONTINUITY_NOT_IMPLEMENTED",
                ),
            },
        },
    ),
}


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _contract_rows(kind: str) -> list[dict[str, Any]]:
    return requirements_for(namespace_registry(), (kind,))


def _unresolved_reason(kind: str) -> str:
    return (
        "Migration retains this applicability question. Exact source ownership "
        "alone cannot establish or refute a " + kind + " role."
    )


def _basis(review: _Review, kind: str) -> str:
    """Return the literal catalog basis, never a complement inference."""
    if kind in review.applicable:
        return "APPLIES"
    if kind in review.refuted:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _decision_reason(review: _Review, kind: str) -> str:
    if _basis(review, kind) == "UNRESOLVED":
        return _unresolved_reason(kind)
    return review.reasons[kind]


def _classification_document(review: _Review, kind: str) -> dict[str, Any]:
    basis = _basis(review, kind)
    if basis == "UNRESOLVED":
        paths: tuple[str, ...] = ()
    elif basis == "APPLIES":
        paths = review.role_paths[kind]
    else:
        paths = tuple(review.refutation_anchors[kind])
    return {
        "status": basis,
        "reason": _decision_reason(review, kind),
        "evidence_paths": list(paths),
    }


def _explicit_decision(
    review: _Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
) -> dict[str, Any]:
    basis = _basis(review, kind)
    if basis == "APPLIES":
        paths = review.role_paths[kind]
    elif basis == "DOES_NOT_APPLY":
        paths = tuple(review.refutation_anchors[kind])
    else:
        raise AssertionError("explicit decision requested for unlisted " + kind)
    return {
        "status": basis,
        "reason": _decision_reason(review, kind),
        "evidence": [deepcopy(evidence_by_path[path]) for path in paths],
    }


def _obligation_reason(review: _Review, kind: str) -> str:
    return (
        review.reasons[kind]
        + " This Tier-0 declaration names the boundary only; mechanism "
        "execution and higher-tier semantic fulfillment remain unestablished."
    )


def _catalog_check() -> None:
    for object_id, review in _REVIEWS.items():
        if len(review.applicable) != len(set(review.applicable)):
            raise AssertionError(object_id + " repeats an applicable kind")
        if len(review.refuted) != len(set(review.refuted)):
            raise AssertionError(object_id + " repeats a refuted kind")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " has contradictory role bases")
        if set(review.refutation_anchors) != set(review.refuted):
            raise AssertionError(object_id + " refutation citation denominator differs")
        for kind in review.refuted:
            cited = review.refutation_anchors[kind]
            if not cited or not set(cited) <= set(review.owned_paths) or any(
                not anchor.strip() for anchors in cited.values() for anchor in anchors
            ):
                raise AssertionError(
                    object_id + " refutation for " + kind + " lacks an owned citation"
                )
        explicit = set(review.applicable) | set(review.refuted)
        if not explicit <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " has an unsupported role basis")
        if set(review.reasons) != explicit:
            raise AssertionError(
                object_id + " reason denominator differs from explicit role bases"
            )
        if any(not reason.strip() for reason in review.reasons.values()):
            raise AssertionError(object_id + " review contains a blank reason")
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if any(
            not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(
                object_id + " role evidence is outside its owned source"
            )
        for role, dependency in review.dependency_operands.items():
            local = set(dependency.local_endpoint_paths)
            target = set(dependency.target_evidence_paths)
            if (
                not role.strip()
                or not dependency.targets
                or any(not item.strip() for item in dependency.targets)
                or not dependency.reason.strip()
                or not local
                or not local <= set(review.owned_paths)
                or not target
                or target & set(review.owned_paths)
                or set(dependency.anchors) != local | target
                or any(
                    not anchor.strip()
                    for anchors in dependency.anchors.values()
                    for anchor in anchors
                )
            ):
                raise AssertionError(
                    object_id + " has an invalid dependency operand: " + role
                )
        expected: dict[str, tuple[str, ...]] = {}
        for kind in review.applicable:
            for obligation in _contract_rows(kind):
                if obligation["kind"] == kind:
                    expected[obligation["id"]] = tuple(obligation["declaration_fields"])
        if set(review.declarations) != set(expected):
            raise AssertionError(object_id + " declaration denominator differs")
        for name, fields in expected.items():
            selected = review.declarations[name]
            if set(selected) != set(fields) or any(
                not value.strip() for value in selected.values()
            ):
                raise AssertionError(
                    object_id + " has an incomplete declaration for " + name
                )


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return the complete human-inspectable review without source digests."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: _classification_document(review, kind)
                for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(review.declarations),
            "dependency_operands": {
                role: {
                    "targets": list(dependency.targets),
                    "reason": dependency.reason,
                    "local_endpoint_paths": list(dependency.local_endpoint_paths),
                    "target_evidence_paths": list(dependency.target_evidence_paths),
                }
                for role, dependency in review.dependency_operands.items()
            },
            "claim_boundary": (
                "Source-bound Tier-0 applicability and declaration review only; "
                "mechanism execution, semantic truth, and Tier-1-plus conformance "
                "remain separately required."
            ),
        }
        for object_id, review in _REVIEWS.items()
    }


def _owned_file_paths(row: Mapping[str, Any]) -> set[str]:
    surfaces = row.get("surfaces")
    if type(surfaces) is not list or any(
        type(surface) is not str for surface in surfaces
    ):
        raise ValueError("PACKAGE_NAMESPACE_REVIEW_SURFACES_INVALID")
    return {
        surface.removeprefix("file:")
        for surface in surfaces
        if surface.startswith("file:")
    }


def _current_evidence(
    root: Path,
    paths: tuple[str, ...],
    files: Mapping[str, str],
    *,
    object_id: str,
) -> list[dict[str, str]]:
    evidence = _source_evidence(root, paths, object_id=object_id)
    for reference in evidence:
        path = reference["path"]
        if files.get(path) != reference["sha256"]:
            raise ValueError(
                "PACKAGE_NAMESPACE_REVIEW_SOURCE_DIFFERS:" + object_id + ":" + path
            )
    return evidence


def _read_source(root: Path, path: str, *, object_id: str) -> bytes:
    candidate = root.joinpath(*path.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        if (
            candidate.is_symlink()
            or not resolved.is_relative_to(root)
            or not resolved.is_file()
        ):
            raise OSError("source is not an in-root ordinary file")
        return resolved.read_bytes()
    except OSError as exc:
        raise ValueError(
            "PACKAGE_NAMESPACE_REVIEW_SOURCE_UNAVAILABLE:" + object_id + ":" + path
        ) from exc


def _source_evidence(
    root: Path,
    paths: tuple[str, ...],
    *,
    object_id: str,
) -> list[dict[str, str]]:
    return [
        {
            "path": path,
            "sha256": _digest(_read_source(root, path, object_id=object_id)),
        }
        for path in paths
    ]


def _require_refutation_anchors(
    root: Path,
    review: _Review,
    *,
    object_id: str,
) -> None:
    """Fail closed unless each refutation's cited current source carries its anchor."""
    for kind in review.refuted:
        for path, anchors in review.refutation_anchors[kind].items():
            text = _read_source(root, path, object_id=object_id).decode(
                "utf-8", errors="replace"
            )
            if any(anchor not in text for anchor in anchors):
                raise ValueError(
                    "PACKAGE_NAMESPACE_REVIEW_REFUTATION_ANCHOR_MISSING:"
                    + object_id
                    + ":"
                    + kind
                )


def _require_dependency_evidence(
    root: Path,
    review: _Review,
    files: Mapping[str, str],
    *,
    object_id: str,
) -> None:
    """Bind every cross-owner dependency edge to current endpoint and target bytes."""
    for role, dependency in review.dependency_operands.items():
        for path, anchors in dependency.anchors.items():
            raw = _read_source(root, path, object_id=object_id)
            if files.get(path) != _digest(raw):
                raise ValueError(
                    "PACKAGE_NAMESPACE_REVIEW_DEPENDENCY_SOURCE_DIFFERS:"
                    + object_id
                    + ":"
                    + role
                    + ":"
                    + path
                )
            text = raw.decode("utf-8", errors="replace")
            if any(anchor not in text for anchor in anchors):
                raise ValueError(
                    "PACKAGE_NAMESPACE_REVIEW_DEPENDENCY_ANCHOR_MISSING:"
                    + object_id
                    + ":"
                    + role
                    + ":"
                    + path
                )


def _validate_existing_evidence(
    evidence: Any,
    files: Mapping[str, str],
    owned: set[str],
    *,
    code: str,
) -> None:
    if type(evidence) is not list or not evidence:
        raise ValueError(code)
    paths: list[str] = []
    for reference in evidence:
        if (
            type(reference) is not dict
            or set(reference) != {"path", "sha256"}
            or type(reference["path"]) is not str
            or type(reference["sha256"]) is not str
            or reference["path"] not in owned
            or files.get(reference["path"]) != reference["sha256"]
        ):
            raise ValueError(code)
        paths.append(reference["path"])
    if len(paths) != len(set(paths)):
        raise ValueError(code)


def _blank_obligation(
    binding: Any,
    expected_fields: tuple[str, ...],
    files: Mapping[str, str],
    owned: set[str],
    *,
    code: str,
) -> bool:
    if binding is None:
        return True
    if type(binding) is not dict or set(binding) != {
        "reason",
        "evidence",
        "declaration",
    }:
        raise ValueError(code)
    declaration = binding["declaration"]
    blank = (
        binding["reason"] == ""
        and type(binding["evidence"]) is list
        and type(declaration) is dict
        and set(declaration) == set(expected_fields)
        and all(value == "" for value in declaration.values())
    )
    if blank and binding["evidence"]:
        _validate_existing_evidence(
            binding["evidence"], files, owned, code=code
        )
    return blank


def _validate_unresolved_decision(
    decision: Any,
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    kind: str,
) -> list[dict[str, str]] | None:
    """Accept only a bounded unresolved candidate; reject invented decisions."""
    if decision is None:
        return None
    code = "PACKAGE_NAMESPACE_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
    if (
        type(decision) is not dict
        or set(decision) != {"status", "reason", "evidence"}
        or decision.get("status") != "UNRESOLVED"
        or type(decision.get("reason")) is not str
        or not decision["reason"].strip()
        or type(decision.get("evidence")) is not list
    ):
        raise ValueError(code)
    if decision["evidence"]:
        if decision["reason"] != _unresolved_reason(kind):
            raise ValueError(code)
        _validate_existing_evidence(decision["evidence"], files, owned, code=code)
        return deepcopy(decision["evidence"])
    return []


def _validate_existing_decision(
    decision: Any,
    expected: Mapping[str, Any],
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    kind: str,
) -> bool:
    """Preserve a decided answer only when reason and evidence are exact."""
    if decision is None:
        return False
    code = "PACKAGE_NAMESPACE_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
    if type(decision) is dict and decision.get("status") == "UNRESOLVED":
        _validate_unresolved_decision(
            decision, files, owned, object_id=object_id, kind=kind
        )
        return False
    if (
        type(decision) is not dict
        or set(decision) != {"status", "reason", "evidence"}
        or decision != expected
    ):
        raise ValueError(code)
    return True


def _validate_existing_obligation(
    binding: Any,
    expected_fields: tuple[str, ...],
    expected_reason: str,
    expected_evidence: list[dict[str, str]],
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    obligation_id: str,
) -> bool:
    """Return True for complete reviewed prose; blank candidate rows may be filled."""
    code = (
        "PACKAGE_NAMESPACE_REVIEW_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id
    )
    if _blank_obligation(binding, expected_fields, files, owned, code=code):
        return False
    declaration = binding["declaration"]
    if (
        binding["reason"] != expected_reason
        or binding["evidence"] != expected_evidence
        or type(declaration) is not dict
        or set(declaration) != set(expected_fields)
        or any(
            type(value) is not str or not value.strip()
            for value in declaration.values()
        )
    ):
        raise ValueError(code)
    return True


def _derived_text_only_differs(
    binding: Any,
    expected_fields: tuple[str, ...],
    expected_reason: str,
    expected_evidence: list[dict[str, str]],
) -> bool:
    """True when only the generated reason or evidence order differs.

    The declaration must be complete and the cited (path, digest) pairs must equal
    the current sources exactly, so the authored wording was bound to these bytes.
    """
    if type(binding) is not dict or set(binding) != {"reason", "evidence", "declaration"}:
        return False
    declaration = binding["declaration"]
    evidence = binding["evidence"]
    if (
        type(binding["reason"]) is not str
        or type(declaration) is not dict
        or set(declaration) != set(expected_fields)
        or any(
            type(value) is not str or not value.strip()
            for value in declaration.values()
        )
        or type(evidence) is not list
        or any(
            type(item) is not dict or set(item) != {"path", "sha256"}
            for item in evidence
        )
    ):
        return False
    stored = sorted((item["path"], item["sha256"]) for item in evidence)
    current = sorted((item["path"], item["sha256"]) for item in expected_evidence)
    return stored == current and len(stored) == len(set(stored))


def apply_package_namespace_review(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
    *,
    record_gaps: bool = False,
) -> dict[str, dict[str, Any]]:
    """Apply all seven reviews atomically to a copied object mapping.

    Existing decisions survive only when status, reason, and exact ordered
    current-source evidence equal their literal catalog basis. Unresolved
    decisions and wholly blank obligation candidates may be filled. Any
    contradiction, partially answered declaration, stale/unowned evidence,
    ownership drift, or missing source aborts before caller-visible mutation.

    ``record_gaps`` lets regeneration continue past one kind of drift: a complete
    obligation whose cited sources are unchanged but whose generated reason or
    evidence order trails the catalog is re-derived, keeping its authored
    declaration.  Source drift and partial declarations still abort.
    """
    selected_root = Path(root).resolve(strict=True)
    if not selected_root.is_dir():
        raise ValueError("PACKAGE_NAMESPACE_REVIEW_ROOT_INVALID")
    if type(rows) is not dict:
        raise ValueError("PACKAGE_NAMESPACE_REVIEW_ROWS_INVALID")
    if type(files) is not dict or any(
        type(path) is not str
        or type(digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_NAMESPACE_REVIEW_FILES_INVALID")

    # Preflight the full five-object denominator and build immutable plans first.
    plans: dict[str, dict[str, Any]] = {}
    for object_id, review in _REVIEWS.items():
        row = rows.get(object_id)
        if type(row) is not dict:
            raise ValueError("PACKAGE_NAMESPACE_REVIEW_OBJECT_MISSING:" + object_id)
        if row.get("object_id") != object_id or row.get("kind") != review.primary_kind:
            raise ValueError(
                "PACKAGE_NAMESPACE_REVIEW_PRIMARY_KIND_DIFFERS:" + object_id
            )
        owned = _owned_file_paths(row)
        if owned != set(review.owned_paths):
            raise ValueError("PACKAGE_NAMESPACE_REVIEW_OWNERSHIP_DIFFERS:" + object_id)
        complete_evidence = _current_evidence(
            selected_root, review.owned_paths, files, object_id=object_id
        )
        _require_refutation_anchors(selected_root, review, object_id=object_id)
        _require_dependency_evidence(
            selected_root, review, files, object_id=object_id
        )
        evidence_by_path = {item["path"]: item for item in complete_evidence}
        classification = row.get("classification")
        obligations = row.get("obligations")
        specializations = row.get("specializations")
        if type(classification) is not dict or type(obligations) is not dict:
            raise ValueError("PACKAGE_NAMESPACE_REVIEW_BINDINGS_INVALID:" + object_id)
        if type(specializations) is not list or any(
            type(kind) is not str for kind in specializations
        ) or len(specializations) != len(set(specializations)):
            raise ValueError(
                "PACKAGE_NAMESPACE_REVIEW_SPECIALIZATIONS_INVALID:" + object_id
            )

        preserve_decisions: set[str] = set()
        preserve_obligations: set[str] = set()
        rederive_obligations: set[str] = set()
        remove_obligations: set[str] = set()
        unresolved_candidates: dict[str, list[dict[str, str]]] = {}
        known_obligations = {
            obligation["id"]
            for selected_kind in REVIEW_KINDS
            for obligation in _contract_rows(selected_kind)
            if obligation["kind"] == selected_kind
        }
        for name in obligations:
            if type(name) is not str or name not in known_obligations:
                raise ValueError(
                    "PACKAGE_NAMESPACE_REVIEW_OBLIGATION_UNKNOWN:"
                    + object_id
                    + ":"
                    + str(name)
                )
        for kind in REVIEW_KINDS:
            basis = _basis(review, kind)
            if basis != "APPLIES" and (
                row["kind"] == kind or kind in specializations
            ):
                raise ValueError(
                    "PACKAGE_NAMESPACE_REVIEW_LABEL_CONFLICT:" + object_id + ":" + kind
                )
            decision = classification.get(kind)
            if basis == "UNRESOLVED":
                candidate = _validate_unresolved_decision(
                    decision,
                    files,
                    owned,
                    object_id=object_id,
                    kind=kind,
                )
                if candidate:
                    unresolved_candidates[kind] = [
                        deepcopy(evidence_by_path[item["path"]])
                        for item in candidate
                    ]
            elif _validate_existing_decision(
                decision,
                _explicit_decision(review, kind, evidence_by_path),
                files,
                owned,
                object_id=object_id,
                kind=kind,
            ):
                preserve_decisions.add(kind)

            for obligation in _contract_rows(kind):
                if obligation["kind"] != kind:
                    continue
                name = obligation["id"]
                binding = obligations.get(name)
                fields = tuple(obligation["declaration_fields"])
                if basis == "APPLIES":
                    expected_evidence = [
                        deepcopy(evidence_by_path[path])
                        for path in review.role_paths[kind]
                    ]
                    try:
                        kept = _validate_existing_obligation(
                            binding,
                            fields,
                            _obligation_reason(review, kind),
                            expected_evidence,
                            files,
                            owned,
                            object_id=object_id,
                            obligation_id=name,
                        )
                    except ValueError:
                        if not (
                            record_gaps
                            and _derived_text_only_differs(
                                binding,
                                fields,
                                _obligation_reason(review, kind),
                                expected_evidence,
                            )
                        ):
                            raise
                        rederive_obligations.add(name)
                        continue
                    if kept:
                        preserve_obligations.add(name)
                elif binding is not None:
                    prefix = (
                        "PACKAGE_NAMESPACE_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                        if basis == "DOES_NOT_APPLY"
                        else "PACKAGE_NAMESPACE_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
                    )
                    code = prefix + object_id + ":" + name
                    if not _blank_obligation(
                        binding, fields, files, owned, code=code
                    ):
                        raise ValueError(
                            code
                        )
                    remove_obligations.add(name)
        plans[object_id] = {
            "owned": owned,
            "evidence_by_path": evidence_by_path,
            "preserve_decisions": preserve_decisions,
            "preserve_obligations": preserve_obligations,
            "rederive_obligations": rederive_obligations,
            "remove_obligations": remove_obligations,
            "unresolved_candidates": unresolved_candidates,
            "opening_evidence": complete_evidence,
        }

    # Re-read the complete denominator after semantic preflight.  A file that
    # changes while this function is considering conflicts must not leave a
    # freshly generated binding that was already stale at return time.
    for object_id, review in _REVIEWS.items():
        closing = _source_evidence(
            selected_root, review.owned_paths, object_id=object_id
        )
        if closing != plans[object_id]["opening_evidence"]:
            raise ValueError("PACKAGE_NAMESPACE_REVIEW_SOURCE_CHANGED:" + object_id)

    result = deepcopy(rows)
    for object_id, review in _REVIEWS.items():
        row = result[object_id]
        plan = plans[object_id]
        for kind in REVIEW_KINDS:
            if kind in plan["preserve_decisions"]:
                continue
            if _basis(review, kind) == "UNRESOLVED":
                row["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": _unresolved_reason(kind),
                    "evidence": deepcopy(
                        plan["unresolved_candidates"].get(kind, [])
                    ),
                }
            else:
                row["classification"][kind] = _explicit_decision(
                    review, kind, plan["evidence_by_path"]
                )
        for name in plan["remove_obligations"]:
            row["obligations"].pop(name, None)
        for name, declaration in review.declarations.items():
            if name in plan["preserve_obligations"]:
                continue
            kind = name.split("-", 1)[0]
            paths = review.role_paths[kind]
            kept_declaration = (
                dict(row["obligations"][name]["declaration"])
                if name in plan["rederive_obligations"]
                else dict(declaration)
            )
            row["obligations"][name] = {
                "reason": _obligation_reason(review, kind),
                "evidence": [
                    deepcopy(plan["evidence_by_path"][path]) for path in paths
                ],
                "declaration": kept_declaration,
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)
    return result
