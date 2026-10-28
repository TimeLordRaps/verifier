"""Current-source Tier-0 semantic review for seven retained system objects.

Terminology: application programming interface (API); identifier (ID);
JavaScript Object Notation (JSON); operating system (OS); abstract syntax tree
(AST).

This module answers one bounded repository-admission question for GRAPH, SPACE,
TIME, EVENT, ENV, DATA, and BENCH: which of the twelve added namespace kinds
are actually implicated by the currently owned source?  It deliberately keeps
declared timestamps distinct from measurements, retained records distinct from
sensors, dispatch vocabulary distinct from a live protocol, and graph members
distinct from market participants.

The apply operation is pure and fail closed.  It binds every answer to exact
owned source bytes, validates the entire seven-object denominator before making
a copied change, and rereads the sources before publication.  The denominator
is re-derived from the live source census (any file below domains/contracts
whose stem names the kind, at any depth and suffix), so a new same-prefix source
fails closed rather than escaping review.  Tier-0 declaration
presence is all it establishes; mechanism execution, declaration truth, and
Tier-1-plus conformance remain separate questions.
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

CLAIM_BOUNDARY = (
    "Current-source Tier-0 applicability and declaration review only; "
    "mechanism execution, truth of the declarations, external authority, "
    "and Tier-1-plus conformance remain unestablished."
)


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    name: str
    source_summary: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    refuted: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    applicable_reasons: Mapping[str, str]
    distinctions: Mapping[str, str]
    declarations: Mapping[str, Mapping[str, str]]


def _policy_declarations(
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
    return {
        "POLICY-0.1-rules-and-precedence": {
            "scope": scope,
            "decision_inputs": decision_inputs,
            "precedence": precedence,
            "defaults": defaults,
        },
        "POLICY-0.2-authority-and-exceptions": {
            "authority": authority,
            "exceptions": exceptions,
            "revisions": revisions,
            "activation": activation,
        },
        "POLICY-0.3-enforcement-and-decisions": {
            "enforcement_points": enforcement_points,
            "decision_evidence": decision_evidence,
            "bypass_handling": bypass_handling,
            "unavailable_behavior": unavailable_behavior,
        },
    }


def _measurement_declarations(
    *,
    phenomenon: str,
    method: str,
    source: str,
    observation_vs_estimate: str,
    units: str,
    reference_frame: str,
    observation_time: str,
    arrival_time: str,
    uncertainty: str,
    validity: str,
    missingness: str,
    freshness: str,
    provenance: str,
) -> dict[str, dict[str, str]]:
    return {
        "MEASUREMENT-0.1-phenomenon-and-method": {
            "phenomenon": phenomenon,
            "method": method,
            "source": source,
            "observation_vs_estimate": observation_vs_estimate,
        },
        "MEASUREMENT-0.2-units-time-and-uncertainty": {
            "units": units,
            "reference_frame": reference_frame,
            "observation_time": observation_time,
            "arrival_time": arrival_time,
            "uncertainty": uncertainty,
        },
        "MEASUREMENT-0.3-validity-and-missingness": {
            "validity": validity,
            "missingness": missingness,
            "freshness": freshness,
            "provenance": provenance,
        },
    }


def _sensor_declarations(
    *,
    acquisition: str,
    phenomena: str,
    measurements: str,
    deployment: str,
    calibration_applicability: str,
    calibration_evidence: str,
    operating_range: str,
    drift: str,
    sampling: str,
    latency: str,
    fault_detection: str,
    recovery: str,
) -> dict[str, dict[str, str]]:
    return {
        "SENSOR-0.1-acquisition-and-observations": {
            "acquisition": acquisition,
            "phenomena": phenomena,
            "measurements": measurements,
            "deployment": deployment,
        },
        "SENSOR-0.2-calibration-and-envelope": {
            "calibration_applicability": calibration_applicability,
            "calibration_evidence": calibration_evidence,
            "operating_range": operating_range,
            "drift": drift,
        },
        "SENSOR-0.3-sampling-and-faults": {
            "sampling": sampling,
            "latency": latency,
            "fault_detection": fault_detection,
            "recovery": recovery,
        },
    }


def _merge(*parts: Mapping[str, Mapping[str, str]]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for part in parts:
        overlap = set(result).intersection(part)
        if overlap:
            raise AssertionError("duplicate declaration: " + sorted(overlap)[0])
        result.update({name: dict(fields) for name, fields in part.items()})
    return result


def _open_effect_declarations(
    kind: str, subject: str
) -> dict[str, dict[str, str]]:
    """Retain live fields while leaving every concrete mechanism value open."""
    return {
        obligation["id"]: {
            field: (
                f"{subject} retains {kind}.{field} as a Tier-0 obligation because "
                "the sole authored reasons.vstd selects conservative APPLIES while "
                "the owned closed-effect boundary is open. The concrete mechanism "
                "value and any external occurrence remain NOT_ESTABLISHED."
            )
            for field in obligation["declaration_fields"]
        }
        for obligation in requirements_for(namespace_registry(), (kind,))
        if obligation["kind"] == kind
    }


_GRAPH_PATHS = (
    "src/verifier/domains/contracts/graph_closure.py",
    "src/verifier/domains/contracts/graph_lineage.py",
    "src/verifier/domains/contracts/graph_order.py",
    "src/verifier/domains/contracts/graph_statics.py",
)

_SPACE_PATHS = (
    "src/verifier/domains/contracts/space_closure.py",
    "src/verifier/domains/contracts/space_layout.py",
    "src/verifier/domains/contracts/space_migration.py",
)

_TIME_PATHS = (
    "src/verifier/domains/contracts/time_closure.py",
    "src/verifier/domains/contracts/time_order.py",
    "src/verifier/domains/contracts/time_strict.py",
)

_EVENT_PATHS = (
    "src/verifier/domains/contracts/event_closure.py",
    "src/verifier/domains/contracts/event_dispatch.py",
    "src/verifier/domains/contracts/event_prerequisites.py",
)

_ENV_PATHS = (
    "src/verifier/domains/env.py",
    "src/verifier/domains/contracts/env_checks_projection.py",
    "src/verifier/domains/contracts/env_checks.py",
    "src/verifier/domains/contracts/env_configuration_surface.py",
    "src/verifier/domains/contracts/env_executable.py",
    "src/verifier/domains/contracts/env_pin_closure.py",
)

_DATA_PATHS = (
    "src/verifier/domains/data.py",
    "src/verifier/domains/contracts/data_checks_projection.py",
    "src/verifier/domains/contracts/data_checks.py",
    "src/verifier/domains/contracts/data_distribution.py",
)

_BENCH_PATHS = (
    "src/verifier/domains/bench.py",
    "src/verifier/domains/contracts/bench_attempts.py",
    "src/verifier/domains/contracts/bench_checks_projection.py",
    "src/verifier/domains/contracts/bench_checks.py",
)

_ENV_MEASUREMENT_PATHS = (
    "src/verifier/domains/env.py",
    "src/verifier/domains/contracts/env_checks.py",
)
_ENV_SENSOR_PATHS = ("src/verifier/domains/env.py",)
_DATA_MEASUREMENT_PATHS = (
    "src/verifier/domains/data.py",
    "src/verifier/domains/contracts/data_distribution.py",
)
_BENCH_MEASUREMENT_PATHS = (
    "src/verifier/domains/bench.py",
    "src/verifier/domains/contracts/bench_checks.py",
)


_GRAPH_POLICY = _policy_declarations(
    scope=(
        "Admission of exact retained GRAPH node/edge statics, least order, "
        "reachability closure, and direct operand-content lineage propositions."
    ),
    decision_inputs=(
        "The selected GRAPH and collection, retained node/edge/order/closure bytes, "
        "endpoint commitments, child certificates, mechanism pins, and finite limits."
    ),
    precedence=(
        "Exact request and installed-policy checks precede evidence evaluation; "
        "order, closure, and lineage replay their selected GRAPH-3.1 child first."
    ),
    defaults=(
        "Malformed, substituted, over-limit, unavailable, or contradictory input "
        "cannot default to PASS."
    ),
    authority=(
        "The caller selects evidence and trust-root labels; the installed checker "
        "decides only its finite GRAPH proposition, not causal or lineage truth."
    ),
    exceptions=(
        "No implicit exception bypasses exact subject, collection, digest, child, "
        "or finite-limit equality."
    ),
    revisions=(
        "Schema, semantic, coordinate, mechanism, and source digests bind a revision; "
        "changed installed bytes require a new current mechanism digest."
    ),
    activation=(
        "A policy activates only when its exact version, mechanism identifier, current "
        "mechanism digest, trust roots, and certificate-byte ceiling are accepted."
    ),
    enforcement_points=(
        "Each graph_*._policy(), request parser, bounded evaluator, certificate builder, "
        "and native recheck enforce the selected rule surface."
    ),
    decision_evidence=(
        "Exact request, policy, retained evidence, child certificates, current source "
        "digest, and deterministic computed graph relations support the local verdict."
    ),
    bypass_handling=(
        "Undeclared edges, unsupported shapes, digest substitution, and skipped child "
        "replay are outside PASS rather than alternate admission paths."
    ),
    unavailable_behavior=(
        "Unavailable evidence or exhausted bounded work remains unavailable or UNKNOWN; "
        "it is never promoted to a positive graph claim."
    ),
)

_SPACE_POLICY = _policy_declarations(
    scope=(
        "Admission of exact retained SPACE logical byte layouts, complete extent "
        "coverage, and declared length-preserving partition migrations."
    ),
    decision_inputs=(
        "The selected SPACE and collection, byte partitions/extents/alignment, before "
        "and after child certificates, migration map, mechanism pins, and finite limits."
    ),
    precedence=(
        "Exact request and current policy bind first; closure and migration replay the "
        "selected SPACE-3.1 layout children before evaluating added conditions."
    ),
    defaults=(
        "A malformed, missing, overlapping, unaligned, substituted, or unavailable "
        "logical layout does not default to PASS."
    ),
    authority=(
        "The caller selects retained logical layout evidence; the checker has no host, "
        "device, allocator, storage, isolation, or data-movement authority."
    ),
    exceptions=(
        "There is no implicit exception to exact interval, extent, bijection, digest, "
        "child-replay, or finite-bound requirements."
    ),
    revisions=(
        "Version and installed source/mechanism digests identify the active checker; "
        "changed bytes require a newly bound policy."
    ),
    activation=(
        "Only an exact current mechanism digest, accepted trust roots, and supported "
        "certificate-byte ceiling activate a SPACE checker policy."
    ),
    enforcement_points=(
        "space_layout, space_closure, and space_migration policy parsers, request "
        "parsers, evaluators, builders, and rechecks enforce these rules."
    ),
    decision_evidence=(
        "Exact retained partition bytes, selected child certificates, migration rows, "
        "and current mechanism bytes support only the named logical proposition."
    ),
    bypass_handling=(
        "Unsupported or over-limit coordinates and child mismatches remain refusal or "
        "unavailability; they cannot be treated as physical allocation evidence."
    ),
    unavailable_behavior=(
        "Unavailable retained evidence remains UNKNOWN/unavailable and supplies no "
        "claim of allocation, copying, containment, isolation, or non-leakage."
    ),
)

_TIME_POLICY = _policy_declarations(
    scope=(
        "Admission of exact retained TIME sample ordering, strictness, and selected "
        "declared-clock inventory closure."
    ),
    decision_inputs=(
        "The selected TIME and collection, sample identifiers and integer microsecond "
        "values, declared clock/span/cutoff, child certificate, pins, and finite limits."
    ),
    precedence=(
        "Exact policy/request binding precedes checking; strict order and closure first "
        "replay the exact selected TIME-2.1 order child."
    ),
    defaults=(
        "Malformed, unordered, duplicate, incomplete selected, substituted, or "
        "unavailable retained samples cannot default to PASS."
    ),
    authority=(
        "The caller selects the declared clock and retained inventory; the checker has "
        "no physical clock, calibration, scheduling, causality, or termination authority."
    ),
    exceptions=(
        "No implicit exception weakens exact clock/span, ordering, strictness, inventory, "
        "digest, child-replay, or finite-limit equality."
    ),
    revisions=(
        "Coordinate and mechanism/source digests bind the active semantics; changing "
        "installed bytes requires a new current policy binding."
    ),
    activation=(
        "The policy activates only for its exact current mechanism identifier/digest, "
        "accepted trust roots, and supported certificate-byte bound."
    ),
    enforcement_points=(
        "time_order, time_strict, and time_closure policy/request parsers, evaluators, "
        "builders, and native rechecks enforce the retained-time rules."
    ),
    decision_evidence=(
        "Exact selected sample rows, declared clock metadata, child certificate, policy, "
        "and current checker bytes support only the retained ordering proposition."
    ),
    bypass_handling=(
        "A timestamp label, missing child replay, unsupported clock relation, or stale "
        "digest cannot bypass the exact retained proposition."
    ),
    unavailable_behavior=(
        "Unavailable capacity or evidence remains UNKNOWN/unavailable and never becomes "
        "physical-clock truth, event causality, or actual termination."
    ),
)

_EVENT_POLICY = _policy_declarations(
    scope=(
        "Admission of exact retained EVENT prerequisite/payload relations, declared "
        "dispatch/acknowledgment logs, and one-head finite event-log closure."
    ),
    decision_inputs=(
        "The selected EVENT and collection, payloads, handler declarations, retained "
        "log/state, prerequisite cone, first sequence, child certificate, and limits."
    ),
    precedence=(
        "Exact policy/request checks precede retained replay; EVENT-4.1 first replays the "
        "selected EVENT-3.1 prerequisite child before log-closure checks."
    ),
    defaults=(
        "Malformed, substituted, orphaned, gapped, duplicate, out-of-order, or unavailable "
        "retained declarations cannot default to PASS."
    ),
    authority=(
        "The caller selects the retained declaration; the checker has no authority over "
        "actual emitters, transport, handlers, history, causality, or external effects."
    ),
    exceptions=(
        "No implicit exception weakens exact handler subscription, log ordering, state "
        "replay, prerequisite, sequence, digest, or finite-limit requirements."
    ),
    revisions=(
        "Schema/coordinate and installed mechanism/source digests bind the active rules; "
        "changed source requires a newly bound policy."
    ),
    activation=(
        "Only an exact current mechanism digest, accepted trust roots, and supported "
        "certificate-byte ceiling activate each EVENT checker policy."
    ),
    enforcement_points=(
        "event_dispatch, event_prerequisites, and event_closure policy/request parsers, "
        "evaluators, builders, and native rechecks enforce these rules."
    ),
    decision_evidence=(
        "Exact retained declarations/log bytes, child certificate, recomputed state/log "
        "commitments, and current checker bytes support only the named proposition."
    ),
    bypass_handling=(
        "A dispatch-shaped row, acknowledgment label, stale digest, or skipped replay "
        "cannot bypass exact retained checks or imply handler execution."
    ),
    unavailable_behavior=(
        "Unavailable evidence remains UNKNOWN/unavailable and supplies no historical "
        "occurrence, observer authenticity, transport, delivery, or causal claim."
    ),
)

_ENV_POLICY = _policy_declarations(
    scope=(
        "Admission of exact retained ENV software, selected configuration domains, "
        "executable pins, resource ceilings, reproduction rows, and pin closure."
    ),
    decision_inputs=(
        "Selected ENV/collection records, file and executable digests, configuration, "
        "retained executions/measurements, resolver trace, child selections, and limits."
    ),
    precedence=(
        "Exact mechanism/request binding and inventory checks precede configuration, "
        "resource, reproduction, executable, or pin-closure decisions."
    ),
    defaults=(
        "Missing, substituted, out-of-domain, over-ceiling, nonzero-exit, unresolved, "
        "or unavailable retained data cannot default to PASS."
    ),
    authority=(
        "The caller selects the retained environment and trust roots; these sources have "
        "no host-provisioning, physical-isolation, external-issuer, or execution authority."
    ),
    exceptions=(
        "Only explicitly selected finite domains and checks apply; there is no implicit "
        "exception to exact inventory, configuration, executable, or pin equality."
    ),
    revisions=(
        "Schema/coordinate and installed source/mechanism digests bind each rule revision; "
        "a source change requires a newly selected current policy."
    ),
    activation=(
        "The exact current mechanism digest, accepted trust-root labels, supported byte "
        "bounds, and selected check activate a bounded ENV policy."
    ),
    enforcement_points=(
        "env.evaluate(), contract _policy()/request parsers, selected evaluators, builders, "
        "and rechecks enforce the retained environment decision surface."
    ),
    decision_evidence=(
        "Exact retained files/configuration/execution/resource/pin rows and current source "
        "bytes support the local verdict; live authenticity remains excluded."
    ),
    bypass_handling=(
        "Unselected host state, stale pins, unsupported configuration, and physical claims "
        "cannot bypass the exact retained-process-observations scope."
    ),
    unavailable_behavior=(
        "Unavailable or incomplete retained evidence remains UNKNOWN/unavailable; it never "
        "becomes live execution, independent rerun, or physical confinement."
    ),
)

_DATA_POLICY = _policy_declarations(
    scope=(
        "Admission of exact retained DATA shard inventory, schema, deterministic lineage, "
        "split/overlap constraints, and selected value-distribution statistics."
    ),
    decision_inputs=(
        "Selected DATA/collection records, shard bytes and commitments, schema/transforms, "
        "splits/overlap contract, distribution fields, tolerance, pins, and finite limits."
    ),
    precedence=(
        "Inventory integrity is checked before schema, lineage, split, overlap, or "
        "distribution conclusions; exact policy/request binding precedes evaluation."
    ),
    defaults=(
        "Missing, substituted, unsupported, overlapping, inconsistent, over-tolerance, "
        "or unavailable retained data cannot default to PASS."
    ),
    authority=(
        "The caller selects retained data and trust-root labels; the checker has no rights, "
        "external-origin, population, collection, or sensor authority."
    ),
    exceptions=(
        "Only the explicit supported transformations/types and selected finite tolerances "
        "apply; no implicit exception bypasses exact shard and record equality."
    ),
    revisions=(
        "Coordinate, semantic, and current source/mechanism digests bind a rule revision; "
        "changed installed bytes require a new policy binding."
    ),
    activation=(
        "An exact current mechanism digest, accepted trust roots, supported certificate "
        "bound, selected check, and distribution tolerance activate the policy."
    ),
    enforcement_points=(
        "data.evaluate(), data.distribution(), contract _policy()/request parsers, builders, "
        "and native rechecks enforce the finite retained-data rules."
    ),
    decision_evidence=(
        "Exact shard/record bytes and digests, recomputed transformations/statistics, "
        "selected policy, and current source bytes support the bounded verdict."
    ),
    bypass_handling=(
        "Unretained rows, unsupported transforms, absent fields, stale digests, or external "
        "claims cannot bypass exact retained checks."
    ),
    unavailable_behavior=(
        "Unavailable or incomplete retained data remains UNKNOWN/unavailable and supplies "
        "no population, rights, external-origin, acquisition, or authority claim."
    ),
)

_BENCH_POLICY = _policy_declarations(
    scope=(
        "Admission of exact retained BENCH problem/run coverage, native oracle outcomes, "
        "resource ceilings, and bounded best-of-N attempt selection."
    ),
    decision_inputs=(
        "Selected BENCH/collection records, problem specifications, retained runs/answers, "
        "attempt bounds/metrics/selections, resource observations, pins, and limits."
    ),
    precedence=(
        "Exact problem/run binding precedes oracle, resource, score, or coverage decisions; "
        "attempt selection recomputes scores before earliest-retained tie breaking."
    ),
    defaults=(
        "Missing coverage, unsupported oracle/metric, duplicate attempt, over-bound resource, "
        "incorrect answer, or unavailable evidence cannot default to PASS."
    ),
    authority=(
        "The caller selects retained benchmark evidence and trust roots; the checker has no "
        "candidate-execution, authorship, hardware, ranking, or release authority."
    ),
    exceptions=(
        "Only named built-in oracles/metrics and exact selected bounds apply; no implicit "
        "exception bypasses problem, run, attempt, score, or limit equality."
    ),
    revisions=(
        "Coordinate and current source/mechanism digests bind the active checker revision; "
        "changed source requires a newly selected policy."
    ),
    activation=(
        "Exact current mechanism/source pins, accepted trust roots, supported certificate "
        "bound, and selected check activate the finite BENCH policy."
    ),
    enforcement_points=(
        "bench.evaluate(), bench.oracle(), bench_attempts selection, contract _policy()/request "
        "parsers, builders, and rechecks enforce the retained benchmark rules."
    ),
    decision_evidence=(
        "Exact problem/run/attempt bytes, recomputed oracle and score results, resource rows, "
        "selected policy, and current checker bytes support the local verdict."
    ),
    bypass_handling=(
        "Unretained attempts, unsupported metrics, stale digests, or reported score alone "
        "cannot bypass recomputation and exact selected bounds."
    ),
    unavailable_behavior=(
        "Unavailable or incomplete retained evidence remains UNKNOWN/unavailable and supplies "
        "no live execution, authorship, physical isolation, or generalization claim."
    ),
)

_ENV_MEASUREMENT = _measurement_declarations(
    phenomenon=(
        "Named retained process-environment configuration and per-execution wall time, "
        "memory use, and thread-count observations."
    ),
    method=(
        "env.collect_configuration() reads Python platform/sys values; "
        'env.evaluate(check="resources") validates caller-supplied retained rows against '
        "selected ceilings."
    ),
    source=(
        "Configuration may come from the local collector, while resource rows are selected "
        "retained inputs bound to exact execution identifiers; their producer is not observed."
    ),
    observation_vs_estimate=(
        "The checker treats exact supplied values as retained observations, not estimates; "
        "it does not establish live collection, observer authenticity, or physical attestation."
    ),
    units="Wall time is seconds, memory is bytes, and thread count is dimensionless.",
    reference_frame=(
        "The exact selected retained-process-observations ENV, software/configuration digest, "
        "and named execution identity."
    ),
    observation_time=(
        "Neither collect_configuration() nor retained resource rows record an observation "
        "timestamp; temporal correspondence therefore remains unestablished."
    ),
    arrival_time=(
        "The checker observes values when called but records no independent acquisition or "
        "arrival timestamp."
    ),
    uncertainty=(
        "No numerical uncertainty model or measurement calibration is supplied; exact-number "
        "comparison cannot establish resource-observer accuracy."
    ),
    validity=(
        "Exact software/configuration binding, distinct selected execution IDs, complete row "
        "coverage, supported numeric types, and positive ceilings are required."
    ),
    missingness=(
        "Missing execution coverage, fewer than two identities, absent fields, or unavailable "
        "scope remains explicit failure/unavailability rather than an imputed value."
    ),
    freshness=(
        "No freshness window exists; retained configuration/resource values must not be "
        "presented as current host state without a fresh qualified acquisition."
    ),
    provenance=(
        "Tier-0 binds env.py and env_checks.py bytes plus retained request/evidence digests; "
        "this is not independent producer or host authenticity."
    ),
)

_ENV_SENSOR = _sensor_declarations(
    acquisition=(
        "env.collect_configuration() synchronously calls platform.system(), release(), "
        "machine(), python_implementation(), python_version(), and reads sys.byteorder."
    ),
    phenomena=(
        "The calling Python process's reported OS family/release, machine label, Python "
        "implementation/version, and byte order."
    ),
    measurements=(
        "One mapping of named categorical strings; this SENSOR role does not cover the "
        "separately supplied retained resource rows."
    ),
    deployment=(
        "The Python process and standard-library platform interface on the host where the "
        "function is invoked; external host identity and physical confinement are excluded."
    ),
    calibration_applicability=(
        "Physical metrological calibration is not applicable to categorical runtime API "
        "labels; API compatibility and host-report authenticity are separate concerns."
    ),
    calibration_evidence=(
        "The exact env.py calls are bound, but no independent host attestation or comparison "
        "against an authoritative platform inventory is performed."
    ),
    operating_range=(
        "The function relies on the Python platform/sys APIs and itself declares no string "
        "length, supported-platform, privilege, or sampling-rate envelope."
    ),
    drift=(
        "No baseline, clock, repeated sample, or drift detector is retained; values can change "
        "between calls without this function detecting the transition."
    ),
    sampling="One synchronous function call produces one un-timestamped configuration snapshot.",
    latency=(
        "No acquisition deadline or latency observation is implemented by "
        "collect_configuration()."
    ),
    fault_detection=(
        "The function provides no independent empty-value, spoofing, staleness, or host-identity "
        "check; raised platform-call errors propagate to its caller."
    ),
    recovery=(
        "A caller may explicitly acquire a new snapshot or use a qualified external attestor; "
        "the prior snapshot is not silently reused as current evidence."
    ),
)

_DATA_MEASUREMENT = _measurement_declarations(
    phenomenon=(
        "The exact canonical-value distribution of each selected field over the exact retained "
        "shard inventory."
    ),
    method=(
        "data.distribution() rehashes shards, counts canonical value bytes, recomputes "
        "cardinality/classes, and derives Shannon entropy with a selected bounded tolerance."
    ),
    source=(
        "Exact caller-selected retained shard/record bytes bound to the DATA inventory; no live "
        "population or sensor acquisition is performed."
    ),
    observation_vs_estimate=(
        "Counts and entropy are an exact census of selected retained rows, not an estimate of "
        "population prevalence, representativeness, or sampling-frame completeness."
    ),
    units=(
        "Class counts/cardinality and balance numerators/denominators are dimensionless; entropy "
        "and its tolerance are bits per retained observation."
    ),
    reference_frame=(
        "The exact selected DATA object, complete retained shard inventory, sorted field name, "
        "and canonical JSON value representation."
    ),
    observation_time=(
        "The retained records carry no required observation timestamp in this mechanism; source "
        "or real-world observation time remains unestablished."
    ),
    arrival_time=(
        "The checker reads retained evidence during evaluation but records no acquisition or "
        "arrival time for the underlying records."
    ),
    uncertainty=(
        "Selected counts are exact for retained bytes; entropy comparison allows only the "
        "explicit 0 through 1e-9 bit tolerance and models no sampling uncertainty."
    ),
    validity=(
        "Shard commitments, record inventory, selected field presence, exact class counts, "
        "cardinality, finite tolerance, and recomputed entropy must all agree."
    ),
    missingness=(
        "No retained records or distribution fields is unavailable; a selected field absent "
        "from any retained record is refuted, never imputed."
    ),
    freshness=(
        "No freshness claim or temporal window exists; the result describes only the bound "
        "retained bytes."
    ),
    provenance=(
        "Tier-0 binds data.py/data_distribution.py and exact shard/evidence digests; external "
        "origin, rights, collection authenticity, and sensor calibration remain excluded."
    ),
)

_BENCH_MEASUREMENT = _measurement_declarations(
    phenomenon=(
        "Retained per-problem execution duration and peak memory plus recomputed native-oracle "
        "outcomes and exact weighted solved fraction."
    ),
    method=(
        'bench.evaluate(check="budgets") compares execution_ms and peak_memory_bytes with '
        "declared ceilings; oracle/coverage checks recompute outcomes and weighted scores."
    ),
    source=(
        "Caller-selected retained run rows bound to exact problem digests and answers; the "
        "checker does not execute or observe the candidate system."
    ),
    observation_vs_estimate=(
        "Resource values are retained claimed observations and scores are checker-derived; "
        "neither proves live execution, answer authorship, or population capability."
    ),
    units=(
        "Execution time is milliseconds, peak memory is bytes, oracle work/counts are "
        "dimensionless, and score is an exact rational with a dimensionless display."
    ),
    reference_frame=(
        "The exact selected BENCH problem/run inventory, problem digest, native oracle, weight, "
        "timeout, memory ceiling, and minimum score."
    ),
    observation_time=(
        "Retained runs include duration but no acquisition timestamp; when or where a candidate "
        "ran is not established."
    ),
    arrival_time=(
        "The checker reads the retained rows during evaluation and retains no independent "
        "arrival timestamp."
    ),
    uncertainty=(
        "Resource claims have no authenticity/error model; rational scoring is exact and only "
        "reported-score agreement uses the fixed 1e-12 parsed-value tolerance."
    ),
    validity=(
        "Exact problem/run coverage and digest binding, supported oracle, positive weights and "
        "ceilings, finite values, resource bounds, and minimum score are required."
    ),
    missingness=(
        "Incomplete suite coverage or unsupported oracle is unavailable; unbound runs, invalid "
        "answers, and over-ceiling observations are explicit refutations, not imputations."
    ),
    freshness=(
        "No freshness window exists; a retained run remains a historical claim and cannot be "
        "treated as a current live execution observation."
    ),
    provenance=(
        "Tier-0 binds bench.py/bench_checks.py plus exact problem/run/evidence digests; candidate "
        "execution, authorship, hardware enforcement, and physical isolation remain excluded."
    ),
)


_DEFAULT_REFUTATIONS = {
    "LEDGER": (
        "It establishes no authoritative account/history state, posting or balance invariant, "
        "reconciliation authority, append-only guarantee, or correction history."
    ),
    "TRANSACTION": (
        "Its bounded validation/certificate work does not coordinate a live state change with "
        "effect authority, commit/abort, partial-failure compensation, or effect retry."
    ),
    "ASSET": (
        "Its identifiers and retained bytes do not represent owned rights, issued quantity, "
        "redemption or backing, custody, control, or encumbrance."
    ),
    "MARKET": (
        "It implements no participant admission, order lifecycle, matching or price formation, "
        "allocation/manipulation control, settlement, or market disruption path."
    ),
    "MEASUREMENT": (
        "Its retained scalar fields and checker limits are declared inputs or structural values, "
        "not an acquired or derived observation of a named phenomenon."
    ),
    "SENSOR": (
        "It performs no acquisition that maps a process, device, or external phenomenon into "
        "observations with a sampling and fault boundary."
    ),
    "CONTROLLER": (
        "It implements no feedback-directed objective, command output, timing/stability loop, "
        "arbitration, intervention, or controller failure behavior."
    ),
    "ACTUATOR": (
        "It accepts no operational command to a simulated or physical target and establishes no "
        "command-to-effect, response, interlock, or effect-feedback path."
    ),
    "PROTOCOL": (
        "Its certificate request/response API is a local checker interface, not a participant "
        "message state machine with authority, replay, safety, liveness, and recovery semantics."
    ),
    "ROBOT": (
        "It contains no AGENT/HARNESS/CONTROLLER chain to a physical ACTUATOR, makes no physical "
        "reach or confinement claim, and exercises no physical intervention authority."
    ),
    "FINBOT": (
        "It contains no agent responsible for live-money decisions/effects, financial authority, "
        "assets/parties, settlement dependency, exposure limit, or monetary recovery path."
    ),
}


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
                "PACKAGE_ORIGINAL_REVIEW_SOURCE_UNPARSEABLE:" + object_id + ":" + path
            ) from exc
    return words


def _review(
    *,
    primary_kind: str,
    name: str,
    source_summary: str,
    owned_paths: tuple[str, ...],
    applicable: tuple[str, ...],
    refuted: tuple[str, ...],
    role_paths: Mapping[str, tuple[str, ...]],
    applicable_reasons: Mapping[str, str],
    declarations: Mapping[str, Mapping[str, str]],
    distinctions: Mapping[str, str] | None = None,
) -> _Review:
    return _Review(
        primary_kind=primary_kind,
        name=name,
        source_summary=source_summary,
        owned_paths=owned_paths,
        applicable=applicable,
        refuted=refuted,
        role_paths=dict(role_paths),
        applicable_reasons=dict(applicable_reasons),
        distinctions={} if distinctions is None else dict(distinctions),
        declarations={name: dict(fields) for name, fields in declarations.items()},
    )


_BENCH_RETENTION_KINDS = tuple(
    kind
    for kind in _AGENCY_OBLIGATION_RETENTION_APPLIES["vstd-benchmark"]
    if kind not in {"MEASUREMENT", "POLICY"}
)
_BENCH_RETENTION_REASONS = {
    kind: _obligation_retention_reason("vstd-benchmark", kind)
    for kind in _BENCH_RETENTION_KINDS
}
_BENCH_RETENTION_DECLARATIONS = _merge(
    *(
        _open_effect_declarations(kind, "The BENCH verifier")
        for kind in _BENCH_RETENTION_KINDS
    )
)


_REVIEWS = {
    "vstd-package-graph": _review(
        primary_kind="GRAPH",
        name="package GRAPH",
        source_summary=(
            "validate exact retained finite node/edge structure, least topological order, "
            "reachability closure, and direct operand-content lineage"
        ),
        owned_paths=_GRAPH_PATHS,
        applicable=("POLICY",),
        refuted=("LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"),
        role_paths={"POLICY": _GRAPH_PATHS},
        applicable_reasons={
            "POLICY": (
                "The package GRAPH graph_statics/order/closure/lineage _policy(), request, "
                "evaluation, build, and recheck paths enforce current mechanism pins, trust "
                "roots, finite bounds, child replay, and fail-closed retained-graph decisions."
            )
        },
        declarations=_GRAPH_POLICY,
        distinctions={
            "MARKET": (
                "Package GRAPH members and directed dependency/operand edges are structural "
                "relations, not market participants, orders, matches, prices, or settlements."
            ),
            "MEASUREMENT": (
                "Node/edge/closure counts, digests, and resource ceilings are declared graph "
                "structure or checker bounds, not observations of an acquired phenomenon."
            ),
        },
    ),
    "vstd-space": _review(
        primary_kind="SPACE",
        name="SPACE object",
        source_summary=(
            "validate retained logical byte partitions, complete declared extent coverage, "
            "and a length-preserving before/after partition map"
        ),
        owned_paths=_SPACE_PATHS,
        applicable=("POLICY",),
        refuted=("LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"),
        role_paths={"POLICY": _SPACE_PATHS},
        applicable_reasons={
            "POLICY": (
                "SPACE layout/closure/migration _policy(), request, evaluation, build, and "
                "recheck paths enforce exact logical extents, child replay, current mechanism "
                "pins, trust roots, finite limits, and fail-closed outcomes."
            )
        },
        declarations=_SPACE_POLICY,
        distinctions={
            "TRANSACTION": (
                "The before/after migration map proves only a retained length-preserving logical "
                "bijection; it performs no allocation, copy, commit, rollback, or data movement."
            ),
            "MEASUREMENT": (
                "Byte offsets, lengths, alignment, and extents are selected logical layout "
                "coordinates, not observed physical storage or memory measurements."
            ),
            "ACTUATOR": (
                "The migration checker issues no allocator/device command and explicitly proves "
                "no physical data movement or containment effect."
            ),
        },
    ),
    "vstd-time": _review(
        primary_kind="TIME",
        name="TIME object",
        source_summary=(
            "validate externally selected retained sample order, strictness, and inventory "
            "closure on one declared microsecond clock"
        ),
        owned_paths=_TIME_PATHS,
        applicable=("POLICY",),
        refuted=("LEDGER", "TRANSACTION", "ASSET", "MARKET", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"),
        role_paths={"POLICY": _TIME_PATHS},
        applicable_reasons={
            "POLICY": (
                "TIME order/strict/closure _policy(), request, evaluation, build, and recheck "
                "paths enforce exact declared-clock spans, sample ordering, child replay, "
                "mechanism pins, trust roots, finite bounds, and fail-closed outcomes."
            )
        },
        declarations=_TIME_POLICY,
        distinctions={
            "SENSOR": (
                "No owned TIME source samples a clock; each checker only validates supplied rows "
                "and therefore exposes no acquisition, calibration, cadence, latency, or fault path."
            ),
            "PROTOCOL": (
                "Sample sequence and child-certificate replay are checker ordering constraints, "
                "not messages exchanged among participants or a progress protocol."
            ),
        },
    ),
    "vstd-event": _review(
        primary_kind="EVENT",
        name="EVENT object",
        source_summary=(
            "validate retained prerequisite/payload relations, one declared dispatch/ack log, "
            "replayed final state, and finite one-head log closure"
        ),
        owned_paths=_EVENT_PATHS,
        applicable=("POLICY",),
        refuted=("LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"),
        role_paths={"POLICY": _EVENT_PATHS},
        applicable_reasons={
            "POLICY": (
                "EVENT dispatch/prerequisite/closure _policy(), request, evaluation, build, and "
                "recheck paths enforce exact retained handlers/logs/state, sequence/child rules, "
                "current mechanism pins, trust roots, finite bounds, and fail-closed outcomes."
            )
        },
        declarations=_EVENT_POLICY,
        distinctions={
            "LEDGER": (
                "The finite selected log has no historical occurrence or observer authenticity, "
                "no outside-inventory completeness, and no append-only or immutability guarantee; "
                "it is not an authoritative LEDGER history."
            ),
            "TRANSACTION": (
                "Recomputing a retained final-state mapping from acknowledged declared writes "
                "does not execute effects or establish commit, abort, compensation, or retry."
            ),
            "MEASUREMENT": (
                "Sequence numbers, payloads, log rows, and acknowledgments are retained declarations, "
                "not authenticated observations of historical or physical events."
            ),
            "SENSOR": (
                "The owned sources contain no event observer or acquisition path and explicitly "
                "exclude observer authenticity and historical occurrence."
            ),
            "PROTOCOL": (
                "event_dispatch.py validates a supplied emit/dispatch/ack declaration but performs "
                "no actual emission, transport, delivery, handler execution, message authority, "
                "failure recovery, or progress protocol."
            ),
        },
    ),
    "vstd-environment": _review(
        primary_kind="ENV",
        name="ENV object",
        source_summary=(
            "acquire a bounded named process-configuration snapshot and validate retained software, "
            "configuration, resources, reproduction, executable, and dependency-pin records"
        ),
        owned_paths=_ENV_PATHS,
        applicable=("MEASUREMENT", "SENSOR", "POLICY"),
        refuted=("TRANSACTION", "ASSET", "MARKET", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"),
        role_paths={
            "MEASUREMENT": _ENV_MEASUREMENT_PATHS,
            "SENSOR": _ENV_SENSOR_PATHS,
            "POLICY": _ENV_PATHS,
        },
        applicable_reasons={
            "MEASUREMENT": (
                'env.evaluate(check="resources") validates retained wall_seconds, memory_bytes, '
                "and thread observations for exact execution IDs against declared ceilings; the "
                "declaration preserves missing timestamps, authenticity, and physical-enforcement gaps."
            ),
            "SENSOR": (
                "env.collect_configuration() is an actual digital acquisition path: it calls "
                "platform/system runtime APIs and sys.byteorder to produce named observations, while "
                "explicitly disclaiming independent evidence and physical attestation."
            ),
            "POLICY": (
                "ENV evaluate and contract _policy()/request/recheck paths enforce exact software, "
                "configuration domains, executable/pin bindings, resource ceilings, current mechanism "
                "pins, trust roots, and fail-closed retained-process decisions."
            ),
        },
        declarations=_merge(_ENV_MEASUREMENT, _ENV_SENSOR, _ENV_POLICY),
        distinctions={
            "TRANSACTION": (
                "The ENV sources read/validate configuration and retained executions but do not "
                "provision a host, launch the retained program, commit effects, or compensate failure."
            ),
            "ACTUATOR": (
                "Reading platform values and validating retained records issues no host provisioning, "
                "container, device, process, or physical command."
            ),
        },
    ),
    "vstd-data": _review(
        primary_kind="DATA",
        name="DATA object",
        source_summary=(
            "validate retained shard integrity/schema/lineage/splits/overlap and derive an exact "
            "selected-field distribution over those bytes"
        ),
        owned_paths=_DATA_PATHS,
        applicable=("MEASUREMENT", "POLICY"),
        refuted=("TRANSACTION", "ASSET", "MARKET", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"),
        role_paths={
            "MEASUREMENT": _DATA_MEASUREMENT_PATHS,
            "POLICY": _DATA_PATHS,
        },
        applicable_reasons={
            "MEASUREMENT": (
                "data.distribution() derives exact canonical classes, counts, cardinality, and "
                "entropy_bits from the bound retained shard inventory under a selected 0..1e-9 bit "
                "tolerance, while excluding population, external-origin, and sensor claims."
            ),
            "POLICY": (
                "DATA evaluate/distribution and contract _policy()/request/recheck paths enforce exact "
                "inventory, supported schema/transforms, split/overlap/distribution rules, current "
                "mechanism pins, trust roots, finite bounds, and fail-closed decisions."
            ),
        },
        declarations=_merge(_DATA_MEASUREMENT, _DATA_POLICY),
        distinctions={
            "ASSET": (
                "Retained dataset bytes and identities establish no represented right, issuance, "
                "redemption, backing, custody, access control, or encumbrance."
            ),
            "SENSOR": (
                "data.distribution() derives statistics from already retained bytes; no DATA-owned "
                "function acquires a phenomenon, and sensor calibration/external origin are excluded."
            ),
        },
    ),
    "vstd-benchmark": _review(
        primary_kind="BENCH",
        name="BENCH object",
        source_summary=(
            "validate retained problem/run/oracle/resource/coverage records and bounded best-of-N "
            "attempt selection"
        ),
        owned_paths=_BENCH_PATHS,
        applicable=(*_BENCH_RETENTION_KINDS, "MEASUREMENT", "POLICY"),
        refuted=(),
        role_paths={
            **{kind: _BENCH_PATHS for kind in _BENCH_RETENTION_KINDS},
            "MEASUREMENT": _BENCH_MEASUREMENT_PATHS,
            "POLICY": _BENCH_PATHS,
        },
        applicable_reasons={
            **_BENCH_RETENTION_REASONS,
            "MEASUREMENT": (
                'bench.evaluate(check="budgets") validates retained execution_ms and '
                "peak_memory_bytes against declared bounds, while oracle/coverage derives exact "
                "weighted scores; live execution and measurement authenticity remain excluded."
            ),
            "POLICY": (
                "BENCH evaluate/oracle, bench_attempts best-of-N/metric/tie-break rules, and contract "
                "_policy()/request/recheck paths enforce exact current pins, trust roots, finite "
                "bounds, and fail-closed retained benchmark decisions."
            ),
        },
        declarations=_merge(
            _BENCH_RETENTION_DECLARATIONS,
            _BENCH_MEASUREMENT,
            _BENCH_POLICY,
        ),
        distinctions={
            "TRANSACTION": (
                "Oracle evaluation and attempt selection do not execute a candidate or coordinate "
                "external effects with commit, abort, compensation, or retry."
            ),
            "SENSOR": (
                "BENCH reads caller-supplied run observations and derives scores; it contains no "
                "timer, memory sampler, candidate-execution observer, or acquisition mechanism."
            ),
        },
    ),
}

ORIGINAL_SYSTEM_OBJECT_IDS = tuple(_REVIEWS)


def _contract_rows(kind: str) -> list[dict[str, Any]]:
    return [
        row
        for row in requirements_for(namespace_registry(), (kind,))
        if row["kind"] == kind
    ]


def _reason(review: _Review, kind: str) -> str:
    if kind in review.applicable:
        return review.applicable_reasons[kind]
    if kind not in review.refuted:
        return _MIGRATION_REASON.format(kind=kind)
    distinction = review.distinctions.get(kind, _DEFAULT_REFUTATIONS[kind])
    return (
        "The owned sources for the "
        + review.name
        + " "
        + review.source_summary
        + ". "
        + distinction
    )


def _basis(review: _Review, kind: str) -> str:
    if kind in review.applicable:
        return "APPLIES"
    if kind in review.refuted:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _obligation_reason(review: _Review, kind: str) -> str:
    return (
        _reason(review, kind)
        + " This declaration records the reviewed Tier-0 boundary only; "
        "mechanism execution and Tier-1-plus fulfillment remain unestablished."
    )


def _catalog_check() -> None:
    for object_id, review in _REVIEWS.items():
        if len(review.owned_paths) != len(set(review.owned_paths)):
            raise AssertionError(object_id + " repeats an owned path")
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if set(review.applicable_reasons) != set(review.applicable):
            raise AssertionError(object_id + " applicable reason denominator differs")
        if len(review.refuted) != len(set(review.refuted)):
            raise AssertionError(object_id + " repeats a refuted kind")
        if not set(review.refuted) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " refutes an unsupported kind")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " applies and refutes one kind")
        if any(
            not paths or not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence leaves owned source")
        reasons = {_reason(review, kind) for kind in REVIEW_KINDS}
        if len(reasons) != len(REVIEW_KINDS) or any(
            not value.strip() for value in reasons
        ):
            raise AssertionError(object_id + " reasons are incomplete or ambiguous")
        expected = {
            row["id"]: set(row["declaration_fields"])
            for kind in review.applicable
            for row in _contract_rows(kind)
        }
        if set(review.declarations) != set(expected):
            raise AssertionError(object_id + " declaration denominator differs")
        for obligation_id, declaration in review.declarations.items():
            if set(declaration) != expected[obligation_id] or any(
                type(value) is not str or not value.strip()
                for value in declaration.values()
            ):
                raise AssertionError(object_id + " declaration fields differ")


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return a defensive, deterministic, digest-free review document."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: {
                    "status": _basis(review, kind),
                    "reason": _reason(review, kind),
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
    if type(surfaces) is not list or any(type(item) is not str for item in surfaces):
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_SURFACES_INVALID")
    paths = [
        item.removeprefix("file:") for item in surfaces if item.startswith("file:")
    ]
    if any(not path for path in paths) or len(paths) != len(set(paths)):
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_SURFACES_INVALID")
    return set(paths)


def _live_migration_paths(root: Path) -> set[str]:
    """Observe every file below ``domains/contracts`` plus owned domain implementations.

    Caches are excluded because they are not source; every other file, at any
    depth and with any suffix, is a candidate for the migration owner rule.
    """
    census = {
        path.relative_to(root).as_posix()
        for path in (root / "src/verifier/domains/contracts").rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    for review in _REVIEWS.values():
        for path in review.owned_paths:
            if (
                path.startswith("src/verifier/domains/")
                and not path.startswith("src/verifier/domains/contracts/")
                and (root / path).is_file()
            ):
                census.add(path)
    return census


def _migration_owned_paths(census: set[str], review: _Review) -> set[str]:
    """Select this object's paths with the migration's owner rule.

    A contract belongs to the kind named by the stem segment before its first
    underscore, compared case-insensitively. A domain implementation is an
    explicit reviewed owner when it is present in the census.
    """
    contract_prefix = "src/verifier/domains/contracts/"
    current = {
        path
        for path in census
        if path.startswith(contract_prefix)
        and Path(path).stem.split("_", 1)[0].upper() == review.primary_kind
    }
    current.update(
        path
        for path in review.owned_paths
        if path.startswith("src/verifier/domains/")
        and not path.startswith(contract_prefix)
        and path in census
    )
    return current


def _ensure_migration_denominator(
    census: set[str], object_id: str, review: _Review
) -> None:
    if _migration_owned_paths(census, review) != set(review.owned_paths):
        raise ValueError(
            "PACKAGE_ORIGINAL_REVIEW_MIGRATION_DENOMINATOR_CHANGED:" + object_id
        )


def _read_digest(root: Path, path: str) -> str:
    candidate = root.joinpath(*path.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        if (
            candidate.is_symlink()
            or not resolved.is_relative_to(root)
            or not resolved.is_file()
        ):
            raise OSError("source is not an in-root ordinary file")
        raw = resolved.read_bytes()
    except OSError as exc:
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_SOURCE_UNAVAILABLE:" + path) from exc
    return "sha256:" + sha256(raw).hexdigest()


def _source_evidence(root: Path, paths: tuple[str, ...]) -> list[dict[str, str]]:
    return [{"path": path, "sha256": _read_digest(root, path)} for path in paths]


def _current_evidence(
    root: Path,
    paths: tuple[str, ...],
    files: Mapping[str, str],
    *,
    object_id: str,
) -> list[dict[str, str]]:
    evidence = _source_evidence(root, paths)
    for reference in evidence:
        if files.get(reference["path"]) != reference["sha256"]:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_SOURCE_DIFFERS:"
                + object_id
                + ":"
                + reference["path"]
            )
    return evidence


def _validate_evidence(
    evidence: Any,
    files: Mapping[str, str],
    allowed: set[str],
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
            or reference["path"] not in allowed
            or files.get(reference["path"]) != reference["sha256"]
        ):
            raise ValueError(code)
        paths.append(reference["path"])
    if len(paths) != len(set(paths)):
        raise ValueError(code)


def _is_canonical_unresolved(
    decision: Any,
    files: Mapping[str, str],
    owned: set[str],
    *,
    kind: str,
    code: str,
) -> bool:
    if type(decision) is not dict or decision.get("status") != "UNRESOLVED":
        return False
    expected_reason = (
        "Migration retains this applicability question. Static ownership alone cannot "
        "refute a " + kind + " role."
    )
    if (
        set(decision) != {"status", "reason", "evidence"}
        or decision.get("reason") != expected_reason
        or type(decision.get("evidence")) is not list
    ):
        raise ValueError(code)
    if decision["evidence"]:
        _validate_evidence(decision["evidence"], files, owned, code=code)
    return True


def _preserve_decision(
    decision: Any,
    expected: Mapping[str, Any] | None,
    files: Mapping[str, str],
    allowed: set[str],
    owned: set[str],
    *,
    object_id: str,
    kind: str,
) -> bool:
    code = "PACKAGE_ORIGINAL_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
    if _is_canonical_unresolved(decision, files, owned, kind=kind, code=code):
        return False
    if expected is None or decision != expected:
        raise ValueError(code)
    return True


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
    if not blank:
        return False
    if binding["evidence"]:
        _validate_evidence(binding["evidence"], files, owned, code=code)
    return True


def _preserve_obligation(
    binding: Any,
    expected_fields: tuple[str, ...],
    expected_reason: str,
    expected_evidence: list[dict[str, str]],
    expected_declaration: Mapping[str, str],
    files: Mapping[str, str],
    allowed: set[str],
    owned: set[str],
    *,
    object_id: str,
    obligation_id: str,
) -> bool:
    code = (
        "PACKAGE_ORIGINAL_REVIEW_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id
    )
    if _blank_obligation(binding, expected_fields, files, owned, code=code):
        return False
    if type(binding) is not dict:
        raise ValueError(code)
    declaration = binding.get("declaration")
    # Compatibility is exact: a non-blank declaration that differs from the
    # reviewed Tier-0 text is a conflicting binding, not a preserved review.
    if (
        set(binding) != {"reason", "evidence", "declaration"}
        or binding.get("reason") != expected_reason
        or binding.get("evidence") != expected_evidence
        or type(declaration) is not dict
        or declaration != expected_declaration
    ):
        raise ValueError(code)
    return True


def apply_package_original_review_systems(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Atomically apply all seven current-source reviews to a deep copy.

    The complete installed question denominator is required. Only canonical
    migration-UNRESOLVED owned decisions and absent/wholly blank obligation
    candidates are filled. Compatible complete same-status
    reviews are preserved byte-for-byte.  Contradiction, stale/unowned evidence,
    partial declarations, ownership mismatch, source drift, or a refuted role
    attached as a label/declaration aborts before any copied mutation is returned.
    """
    selected_root = Path(root).resolve(strict=True)
    if not selected_root.is_dir():
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_ROOT_INVALID")
    if type(rows) is not dict:
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_ROWS_INVALID")
    if type(files) is not dict or any(
        type(path) is not str
        or type(digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_ORIGINAL_REVIEW_FILES_INVALID")

    registered_questions = set(namespace_registry()) - {"OBJECT"}
    live_obligations = {
        kind: {
            row["id"]: tuple(row["declaration_fields"]) for row in _contract_rows(kind)
        }
        for kind in REVIEW_KINDS
    }
    known_obligations = {
        name for obligations in live_obligations.values() for name in obligations
    }
    opening_census = _live_migration_paths(selected_root)
    plans: dict[str, dict[str, Any]] = {}

    for object_id, review in _REVIEWS.items():
        row = rows.get(object_id)
        if type(row) is not dict:
            raise ValueError("PACKAGE_ORIGINAL_REVIEW_OBJECT_MISSING:" + object_id)
        if row.get("object_id") != object_id or row.get("kind") != review.primary_kind:
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_PRIMARY_KIND_DIFFERS:" + object_id
            )
        owned = _owned_file_paths(row)
        if owned != set(review.owned_paths):
            raise ValueError("PACKAGE_ORIGINAL_REVIEW_OWNERSHIP_DIFFERS:" + object_id)
        opening = _current_evidence(
            selected_root, review.owned_paths, files, object_id=object_id
        )
        _ensure_migration_denominator(opening_census, object_id, review)
        by_path = {item["path"]: item for item in opening}

        classification = row.get("classification")
        obligations = row.get("obligations")
        specializations = row.get("specializations")
        if (
            not _has_complete_foreign_questions(
                classification, registered_questions
            )
            or type(obligations) is not dict
        ):
            raise ValueError("PACKAGE_ORIGINAL_REVIEW_BINDINGS_INVALID:" + object_id)
        if (
            type(specializations) is not list
            or any(type(kind) is not str for kind in specializations)
            or len(specializations) != len(set(specializations))
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_SPECIALIZATIONS_INVALID:" + object_id
            )
        # OBJECT is the general base every role can attach to; it is never a
        # reviewed label, so it cannot stand in for an unreviewed role.
        if any(
            kind == "OBJECT" or kind not in registered_questions
            for kind in specializations
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_REVIEW_SPECIALIZATION_UNREGISTERED:" + object_id
            )
        for kind in REVIEW_KINDS:
            if _basis(review, kind) != "APPLIES" and (
                row["kind"] == kind or kind in specializations
            ):
                raise ValueError(
                    "PACKAGE_ORIGINAL_REVIEW_LABEL_CONFLICT:" + object_id + ":" + kind
                )
        for obligation_id in obligations:
            if (
                type(obligation_id) is not str
                or obligation_id.split("-", 1)[0] in REVIEW_KINDS
                and obligation_id not in known_obligations
            ):
                raise ValueError(
                    "PACKAGE_ORIGINAL_REVIEW_OBLIGATION_UNKNOWN:"
                    + object_id
                    + ":"
                    + str(obligation_id)
                )

        preserve_decisions: set[str] = set()
        preserve_obligations: set[str] = set()
        remove_obligations: set[str] = set()
        owned_words = _mechanism_words(selected_root, object_id, review.owned_paths)
        for kind in REVIEW_KINDS:
            basis = _basis(review, kind)
            if basis == "DOES_NOT_APPLY" and owned_words & _MECHANISM_WORDS[kind]:
                raise ValueError(
                    "PACKAGE_ORIGINAL_REVIEW_MECHANISM_CONTRADICTS_REFUTATION:"
                    + object_id
                    + ":"
                    + kind
                )
            paths = (
                review.role_paths[kind]
                if basis == "APPLIES"
                else review.owned_paths
            )
            expected_decision = None
            if basis != "UNRESOLVED":
                expected_decision = {
                    "status": basis,
                    "reason": _reason(review, kind),
                    "evidence": [deepcopy(by_path[path]) for path in paths],
                }
            if _preserve_decision(
                classification.get(kind),
                expected_decision,
                files,
                set(paths),
                owned,
                object_id=object_id,
                kind=kind,
            ):
                preserve_decisions.add(kind)
            for obligation_id, fields in live_obligations[kind].items():
                binding = obligations.get(obligation_id)
                if basis == "APPLIES":
                    expected_evidence = [
                        deepcopy(by_path[path]) for path in review.role_paths[kind]
                    ]
                    if _preserve_obligation(
                        binding,
                        fields,
                        _obligation_reason(review, kind),
                        expected_evidence,
                        dict(review.declarations[obligation_id]),
                        files,
                        set(review.role_paths[kind]),
                        owned,
                        object_id=object_id,
                        obligation_id=obligation_id,
                    ):
                        preserve_obligations.add(obligation_id)
                elif binding is not None:
                    prefix = (
                        "PACKAGE_ORIGINAL_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                        if basis == "DOES_NOT_APPLY"
                        else "PACKAGE_ORIGINAL_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
                    )
                    code = prefix + object_id + ":" + obligation_id
                    if not _blank_obligation(binding, fields, files, owned, code=code):
                        raise ValueError(code)
                    remove_obligations.add(obligation_id)

        plans[object_id] = {
            "opening": opening,
            "by_path": by_path,
            "preserve_decisions": preserve_decisions,
            "preserve_obligations": preserve_obligations,
            "remove_obligations": remove_obligations,
        }

    # Reread only after every semantic conflict has validated.  A concurrent
    # writer therefore cannot produce a partially current published review.
    closing_census = _live_migration_paths(selected_root)
    for object_id, review in _REVIEWS.items():
        if (
            _source_evidence(selected_root, review.owned_paths)
            != plans[object_id]["opening"]
        ):
            raise ValueError("PACKAGE_ORIGINAL_REVIEW_SOURCE_CHANGED:" + object_id)
        _ensure_migration_denominator(closing_census, object_id, review)

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
                paths = (
                    review.role_paths[kind]
                    if basis == "APPLIES"
                    else review.owned_paths
                )
                row["classification"][kind] = {
                    "status": basis,
                    "reason": _reason(review, kind),
                    "evidence": [deepcopy(plan["by_path"][path]) for path in paths],
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
                    deepcopy(plan["by_path"][path]) for path in review.role_paths[kind]
                ],
                "declaration": dict(declaration),
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)

    # Copy construction is not instantaneous. Bind the returned copy to a final
    # complete denominator and byte reread as well as the opening coordinate.
    final_census = _live_migration_paths(selected_root)
    for object_id, review in _REVIEWS.items():
        if (
            _source_evidence(selected_root, review.owned_paths)
            != plans[object_id]["opening"]
        ):
            raise ValueError("PACKAGE_ORIGINAL_REVIEW_SOURCE_CHANGED:" + object_id)
        _ensure_migration_denominator(final_census, object_id, review)
    return result


__all__ = [
    "CLAIM_BOUNDARY",
    "ORIGINAL_SYSTEM_OBJECT_IDS",
    "REVIEW_KINDS",
    "apply_package_original_review_systems",
    "review_document",
]
