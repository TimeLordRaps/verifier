"""Current-source Tier-0 reviews for thirteen package record mechanisms.

Terminology: Advanced Micro Devices (AMD); application programming interface
(API); abstract syntax tree (AST); command-line interface (CLI); central
processing unit (CPU); comma-separated values (CSV); graphics processing unit
(GPU); hash-based message authentication code (HMAC); Hypertext Transfer
Protocol Secure (HTTPS); JavaScript Object Notation (JSON); JSON Lines (JSONL);
NVIDIA Management Library (NVML); operating system (OS); Peripheral Component
Interconnect (PCI); Boolean satisfiability problem (SAT); Coordinated Universal
Time (UTC); universally unique identifier (UUID).

The ownership catalog says which source bytes belong to an object.  This module
answers the separate semantic question for one audited group: which of the
twelve additive namespace kinds apply to those exact bytes, which are literally
refuted for that object, and what every applicable Tier-0 declaration says.
Each kind is exactly one of APPLIES, DOES_NOT_APPLY, or UNRESOLVED.  Both decided
states come only from explicit per-object catalog entries with object-specific
reasons, bound to the exact current owned bytes.  A kind absent from the catalog
is UNRESOLVED, never refuted by absence, complement, or a neighboring object's
review.  The answers are declarations, not proof of mechanism behavior.  Tier-1-plus conformance, external authority, physical
calibration, confinement, and real-money effects remain unestablished.

A DOES_NOT_APPLY refutation of any kind is recorded only with a CLOSED live screen
over its owned closure.  Process (fixed or not), network, device, dynamic-code,
reflection, injected-callable, and unresolved-import sites reachable through owned
imports or calls keep every kind UNRESOLVED, because positive roles accumulate across
helpers, subprocesses, and remote endpoints.  A filesystem write also keeps the state
kinds (LEDGER, TRANSACTION) UNRESOLVED.  A lexical absence of agent, money, or write
terms is not a closed surface, and the screen does not read owned text for absence.

Application is deliberately strict and atomic.  Exact file ownership and the
caller's current digest census are checked before any copied row is changed;
complete compatible reviews are retained, while conflicting, stale, unowned,
or partially answered bindings abort the whole thirteen-object operation.
"""

from __future__ import annotations

import ast
from collections import deque
from copy import deepcopy
from dataclasses import dataclass, replace
from functools import lru_cache
from hashlib import sha256
import re
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping

from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS


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

EXTERNAL_EFFECT_KINDS = frozenset(
    {"ACTUATOR", "ASSET", "CONTROLLER", "FINBOT", "MARKET", "PROTOCOL", "ROBOT", "SENSOR"}
)

RECORD_OBJECT_IDS = (
    "vstd-amd-live-sensor",
    "vstd-anchor-history-ledger",
    "vstd-artifact-network-history",
    "vstd-assurance-event-ledger",
    "vstd-challenge-record-ledger",
    "vstd-consent-policy",
    "vstd-dataset-provenance-policy",
    "vstd-firmware-emulator-accounting",
    "vstd-governance-policy",
    "vstd-nvidia-live-sensor",
    "vstd-precommitment-ledger",
    "vstd-retention-policy",
    "vstd-sim-resource-measurement",
)

CLAIM_BOUNDARY = (
    "Exact-source Tier-0 applicability and declaration review for this bounded "
    "thirteen-object group only. It does not establish mechanism truth, Tier-1-plus "
    "conformance, physical calibration or confinement, real-money authority or "
    "effects, full package coverage, publication, release, or deployment."
)


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    reasons: Mapping[str, str]
    refuted: Mapping[str, str]
    declarations: Mapping[str, Mapping[str, str]]
    demoted: frozenset[str] = frozenset()


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _requirements(kind: str) -> list[dict[str, Any]]:
    return [
        row
        for row in requirements_for(namespace_registry(), (kind,))
        if row["kind"] == kind
    ]


def _declarations(kind: str, fields: Mapping[str, str]) -> dict[str, dict[str, str]]:
    """Bind a flat, readable field map to the live registered obligation ids."""
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


def _review(
    object_id: str,
    applicable_reasons: Mapping[str, str],
    declarations: Mapping[str, Mapping[str, str]],
    refuted: Mapping[str, str],
) -> _Review:
    """Bind one object's literal APPLIES and DOES_NOT_APPLY catalog entries.

    Kinds named in neither mapping are UNRESOLVED.  Nothing is inferred from the
    complement of the applicable set or from an absent refutation.
    """
    specs = {spec.object_id: spec for spec in SEMANTIC_OWNERSHIP_SPECS}
    spec = specs[object_id]
    return _Review(
        primary_kind=spec.primary_kind,
        owned_paths=spec.owned_paths,
        applicable=tuple(sorted(applicable_reasons)),
        reasons=dict(applicable_reasons),
        refuted=dict(refuted),
        declarations={name: dict(fields) for name, fields in declarations.items()},
    )


def _sensor_review(
    object_id: str,
    vendor: str,
    acquisition: str,
    overrides: Mapping[str, str],
    refuted: Mapping[str, str],
) -> _Review:
    """Build one vendor live-sensor review; overrides replace only exact vendor facts."""
    subject = f"The {vendor} adapter"
    reasons = {
        "MEASUREMENT": f"{subject} normalizes live host-visible accelerator observations with explicit timestamps, units, missingness, and source diagnostics; this does not establish physical truth.",
        "SENSOR": f"{subject} actively acquires {acquisition} output from the current host, so acquisition, calibration-applicability, sampling, latency, and fault declarations are necessary.",
    }
    measurement_fields = {
        "phenomenon": f"Host-visible {vendor} accelerator identity, inventory, memory, software, and health fields returned by {acquisition}.",
        "method": f"Launch the read-only {acquisition}, parse its vendor response, and normalize supported fields into AdapterResult records.",
        "source": f"The current host's {acquisition} executable and its captured stdout, stderr, return code, and adapter observation timestamp.",
        "observation_vs_estimate": "Values are host-interface observations. Physical identity, available capacity under load, performance, and completeness are not inferred or estimated.",
        "units": "Byte-valued memory fields are normalized as integer bytes where available; identifiers, versions, modes, and health states remain typed strings or explicit missing values.",
        "reference_frame": f"Each observation is relative to the host-visible {vendor} device identifier and the vendor tool's current namespace.",
        "observation_time": "The adapter records a UTC time after the query; it does not claim a hardware sampling instant for every returned field.",
        "arrival_time": "Arrival is the parent process's receipt of the completed vendor response; transport and device-internal latency are not measured.",
        "uncertainty": "No physical calibration, accuracy interval, drift bound, device authenticity, or inventory completeness is established; those uncertainties remain explicit.",
        "validity": "Success requires an available executable, accepted response shape, successful return code, bounded parsing, and supported value normalization.",
        "missingness": "Unavailable tools, failed queries, malformed rows, and absent fields remain failures or explicit missing observations; they are never silently replaced with zero.",
        "freshness": "Freshness is bounded to this invocation and its recorded UTC time; no claim is made about state before or after the query.",
        "provenance": f"The result records the adapter, selected {acquisition} route, raw diagnostics, and observation time; it does not authenticate the physical device.",
    }
    sensor_fields = {
        "acquisition": f"The adapter directly launches {acquisition} and captures the current host-visible response without commanding accelerator work.",
        "phenomena": f"Phenomena are the {vendor} management interface's reported inventory, memory, version, mode, and health fields, not direct physical transduction.",
        "measurements": "Normalized AdapterResult observations retain explicit success, failure, raw evidence, values, and observation time.",
        "deployment": "Deployment is the local host process with the vendor management executable available; container, permission, virtualization, and device mapping affect visibility.",
        "calibration_applicability": "Physical calibration is not performed. Applicability is limited to vendor-interface metadata acquisition and software normalization.",
        "calibration_evidence": "No calibration certificate or traceable physical reference is present; parser fixtures and vendor output are not calibration evidence.",
        "operating_range": "The supported range is the bounded response and field formats accepted by this adapter on a host where the vendor query completes.",
        "drift": "Driver, firmware, vendor-tool, virtualization, and parser-format drift are not quantified and can invalidate or reduce observations.",
        "sampling": "One adapter call performs one vendor query; it defines no periodic cadence, aggregation window, or cross-call synchronization.",
        "latency": "Query completion is bounded by the adapter subprocess behavior, but device-internal observation latency is not measured or guaranteed.",
        "fault_detection": "Missing executables, nonzero exits, malformed payloads, unsupported values, and parsing exceptions are reported as bounded acquisition failures.",
        "recovery": "Recovery is a later fresh query after the operator fixes availability or compatibility; cached values are not promoted as current observations.",
    }
    for name, text in overrides.items():
        if name in measurement_fields:
            measurement_fields[name] = text
        elif name in sensor_fields:
            sensor_fields[name] = text
        else:
            raise AssertionError(object_id + " overrides unknown field " + name)
    return _review(
        object_id,
        reasons,
        _merge(
            _declarations("MEASUREMENT", measurement_fields),
            _declarations("SENSOR", sensor_fields),
        ),
        refuted,
    )


_AMD = _sensor_review(
    "vstd-amd-live-sensor",
    "AMD",
    "amd-smi static query",
    {
        "method": "Launch one read-only amd-smi static --json query (hardware/adapters/amd.py:95-101) through subprocess.run with timeout=_DISCOVERY_TIMEOUT_SECONDS and stdout written to a tempfile.TemporaryFile (hardware/adapters/amd.py:93-110), parse the captured response (hardware/adapters/amd.py:118-121), and normalize supported fields through a helper imported from the NVIDIA adapter module (hardware/adapters/amd.py:20), which is outside this object's owned paths.",
        "source": "The current host's amd-smi executable and its file-captured stdout (hardware/adapters/amd.py:93-110) and return code (hardware/adapters/amd.py:111-117); stderr is discarded to DEVNULL (hardware/adapters/amd.py:98), and the adapter observation timestamp is recorded after parsing (hardware/adapters/amd.py:148).",
        "missingness": "Absent model and UUID fields are replaced with placeholder values (\"unknown AMD accelerator\" at hardware/adapters/amd.py:129; the device key at hardware/adapters/amd.py:130), so a placeholder is not an observation of the field it replaces.",
        "latency": "The amd-smi subprocess.run call is bounded by timeout=_DISCOVERY_TIMEOUT_SECONDS, 30 seconds (hardware/adapters/amd.py:23, hardware/adapters/amd.py:100), over the call at hardware/adapters/amd.py:95-101; expiry returns an unsupported result (hardware/adapters/amd.py:102-108). This declaration claims no stronger termination guarantee for helper processes, and device-internal observation latency is not measured.",
    },
    {
        "TRANSACTION": "The adapter issues one fixed read-only amd-smi static --json query with no set, reset, or write argument (hardware/adapters/amd.py:95-101) and writes no accelerator or external state. Its filesystem effects are the captured-stdout tempfile.TemporaryFile (hardware/adapters/amd.py:93-110) and, on both the live and fixture paths, the unowned in-memory normalization helper defined in the NVIDIA adapter module and imported at hardware/adapters/amd.py:20, invoked at hardware/adapters/amd.py:67-72 and hardware/adapters/amd.py:152-157, which writes a TemporaryDirectory fixture removed on exit.",
        "CONTROLLER": "hardware/adapters/amd.py has one discover() path (hardware/adapters/amd.py:43-157) with no control or feedback loop, feedback input, or command selection; its only subprocess call reads static inventory (hardware/adapters/amd.py:95-101). The parse loop at hardware/adapters/amd.py:126 iterates over returned records and is not a control loop.",
        "ACTUATOR": "hardware/adapters/amd.py:95-101 passes only the static and --json arguments (hardware/adapters/amd.py:96), with no device, power, clock, or reset argument, so the adapter commands no target and has no command-to-effect path.",
        "ROBOT": "hardware/adapters/amd.py contains no agent, harness, controller, or actuator identifier; its only process effect is the read-only amd-smi query at hardware/adapters/amd.py:95-101.",
        "FINBOT": "hardware/adapters/amd.py contains no price, order, balance, transfer, payment, settlement, or currency term and no agent identifier; its outputs are device inventory records (hardware/adapters/amd.py:124-157).",
        "MARKET": "AmdAdapter.discover (hardware/adapters/amd.py:43-157) takes a fixture or a fixed host query and returns one inventory result; it accepts no order, quote, counterparty, price, or settlement input (hardware/adapters/amd.py:39-41, hardware/adapters/amd.py:43).",
    },
)
_NVIDIA = _sensor_review(
    "vstd-nvidia-live-sensor",
    "NVIDIA",
    "nvidia-smi --query-gpu",
    {
        "phenomenon": "Host-visible NVIDIA device identity, namely UUID, name, and PCI bus id, plus driver and VBIOS version strings returned by nvidia-smi --query-gpu (hardware/adapters/nvidia.py:61-71, 94-108).",
        "method": "Launch one read-only nvidia-smi --query-gpu CSV query (hardware/adapters/nvidia.py:61-71) through subprocess.run with timeout=_DISCOVERY_TIMEOUT_SECONDS and stdout written to a tempfile.TemporaryFile (hardware/adapters/nvidia.py:59-80), parse its rows (hardware/adapters/nvidia.py:88-94), and normalize the returned identity and version fields into AdapterResult records (hardware/adapters/nvidia.py:104-122).",
        "source": "The current host's nvidia-smi executable and its file-captured stdout (hardware/adapters/nvidia.py:59-80) and return code (hardware/adapters/nvidia.py:81-87); stderr is discarded to DEVNULL (hardware/adapters/nvidia.py:68), and the adapter observation timestamp is recorded after parsing (hardware/adapters/nvidia.py:118).",
        "units": "Identifiers, names, PCI bus identifiers, and version strings remain typed strings; no memory, power, thermal, or health quantity is normalized (hardware/adapters/nvidia.py:94-108).",
        "phenomena": "Phenomena are the device identity and version fields named in the query (hardware/adapters/nvidia.py:64), not memory, power, thermal, or health readings.",
        "latency": "The nvidia-smi subprocess.run call is bounded by timeout=_DISCOVERY_TIMEOUT_SECONDS, 30 seconds (hardware/adapters/nvidia.py:24, hardware/adapters/nvidia.py:70), over the call at hardware/adapters/nvidia.py:61-71; expiry returns an unsupported result (hardware/adapters/nvidia.py:72-78). This declaration claims no stronger termination guarantee for helper processes, and device-internal observation latency is not measured.",
    },
    {
        "TRANSACTION": "hardware/adapters/nvidia.py:61-71 issues one read-only --query-gpu CSV query with no set or reset flag (hardware/adapters/nvidia.py:62-66). Its filesystem effects are the captured-stdout tempfile.TemporaryFile (hardware/adapters/nvidia.py:59-80) and, during normalization on both the live and fixture paths, a TemporaryDirectory fixture written and removed on exit (hardware/adapters/nvidia.py:186-189).",
        "CONTROLLER": "hardware/adapters/nvidia.py has one discover() path (hardware/adapters/nvidia.py:45-122) and one subprocess.run call (hardware/adapters/nvidia.py:61-71) with no control or feedback loop, feedback input, or command selection; the parse loop at hardware/adapters/nvidia.py:91 iterates over returned rows and is not a control loop. It returns inventory rows.",
        "ACTUATOR": "hardware/adapters/nvidia.py:61-71 passes only the --query-gpu and --format arguments (hardware/adapters/nvidia.py:62-66); no power, clock, reset, or compute-mode setting is invoked.",
        "ROBOT": "hardware/adapters/nvidia.py contains no agent, harness, controller, or actuator identifier; its only process effect is the read-only nvidia-smi query at hardware/adapters/nvidia.py:61-71.",
        "FINBOT": "hardware/adapters/nvidia.py contains no price, order, balance, transfer, payment, settlement, or currency term and no agent identifier; its outputs are GPU identity and version attributes (hardware/adapters/nvidia.py:96-121).",
        "MARKET": "NvidiaAdapter.discover (hardware/adapters/nvidia.py:45-122) runs one read-only identity query and returns GPU identity records; it accepts no order, quote, counterparty, price, or settlement input (hardware/adapters/nvidia.py:39-43, hardware/adapters/nvidia.py:45).",
    },
)


_RESOURCE_MEASUREMENT = _declarations(
    "MEASUREMENT",
    {
        "phenomenon": "Per selected simulated transition, the observed phenomena are CPython current-thread CPU elapsed time and peak Python allocation traced during that transition.",
        "method": "A fresh source-loaded worker validates the trajectory, starts tracemalloc, brackets the actual transition with time.thread_time_ns, reads traced peak allocation, and stops tracing for every selected step.",
        "source": "The source is the current invocation's fresh CPython worker and the exact loaded SIM transition and resource-measurement source manifests; retained readings and native specimens are not accepted.",
        "observation_vs_estimate": "thread_cpu_ns and traced_peak_bytes are direct software-instrument observations for the selected interval. They are not estimates of wall time, process-wide memory, device use, energy, or physical resource consumption.",
        "units": "thread_cpu_ns is a nonnegative integer number of nanoseconds; traced_peak_bytes is a nonnegative integer number of bytes. Both are bounded at 2^63-1.",
        "reference_frame": "Every row is relative to one fresh run_id and process_id, its exact workload digest, ordered step index, and input/output state digests on the selected CPython version.",
        "observation_time": "The CPU clock is sampled immediately before and after each actual transition. No UTC or historical occurrence time is claimed.",
        "arrival_time": "The parent receives the complete bounded worker response after the fresh subprocess exits; internal pipe and scheduler latency are not separately measured.",
        "uncertainty": "CPython clock and tracer semantics, interpreter overhead, scheduling, allocator behavior, and the host operating system remain trusted and unquantified; no physical calibration or statistical interval is asserted.",
        "validity": "Validity requires current selected and loaded source manifests, fresh challenge and run identity, exact workload and state correspondence, complete ordered step coverage, correct types, and bounded nonnegative values.",
        "missingness": "Unavailable or timed-out transport, acquisition exceptions, malformed or missing steps, invalid metrics, and source drift yield no successful capture or an explicit refusal; missing observations are never replaced with zero.",
        "freshness": "Two independent acquisitions must use distinct fresh challenges and run identifiers. Each observation is current only for its invocation and cannot be replayed as a later measurement.",
        "provenance": "Each result binds selected and loaded source manifests, bootstrap digest, challenge, workload digest, method, CPython target, run/process identity, step indexes, and state digests.",
    },
)
_RESOURCE_SENSOR = _declarations(
    "SENSOR",
    {
        "acquisition": "A fresh isolated Python worker directly calls time.thread_time_ns and tracemalloc around actual source-loaded SIM transitions and returns a bounded typed response.",
        "phenomena": "The acquired software phenomena are current-thread CPU elapsed nanoseconds and peak traced Python allocation bytes for each selected transition interval.",
        "measurements": "Measurements are complete ordered step rows bound to exact input/output state digests, with nonnegative integer thread_cpu_ns and traced_peak_bytes values.",
        "deployment": "Deployment is the newly launched local CPython worker selected by the current Verifier invocation; it is not a physical sensor, device monitor, hostile-host attestor, or sandbox.",
        "calibration_applicability": "Physical calibration is inapplicable to this software-only route. Applicability is limited to the pinned semantics of CPython's thread CPU clock and allocation tracer.",
        "calibration_evidence": "Exact controlled clocks and tracers check interval arithmetic, peak selection, cleanup, and typing, but do not constitute physical calibration or operating-system accuracy evidence.",
        "operating_range": "The accepted range is a finite selected trajectory with complete steps and integer metrics from zero through 2^63-1 under the current CPython target and bounded worker response.",
        "drift": "Interpreter version and source bytes are recaptured and compared. Scheduler, operating-system, allocator, clock, and tracer behavioral drift are not quantified.",
        "sampling": "For each validated step the route performs start tracer, sample CPU clock, execute transition, sample CPU clock, read peak allocation, and stop tracer; validation occurs outside the measured interval.",
        "latency": "The parent bounds the fresh subprocess by the selected timeout, but makes no guarantee about scheduler latency, internal sampling delay, or real-time response.",
        "fault_detection": "Injected clock-start, clock-end, transition, allocation-read, invalid-trajectory, malformed-record, source-drift, unavailable, and timeout cases must refuse rather than return a complete observation.",
        "recovery": "Tracing is stopped in a finally boundary after acquisition faults. Recovery requires a separate fresh source-bound run; an unavailable reading remains unknown and cached values are not promoted.",
    },
)
_RESOURCE = _review(
    "vstd-sim-resource-measurement",
    {
        "MEASUREMENT": "The route directly observes bounded current-thread CPU time and peak traced Python allocation for every selected SIM transition, so measurement meaning, units, correspondence, missingness, freshness, and provenance must be declared.",
        "SENSOR": "The fresh worker actively acquires those observations through CPython clock and tracer interfaces, so acquisition, applicability of calibration, sampling, drift, latency, fault, and cleanup boundaries are necessary.",
    },
    _merge(_RESOURCE_MEASUREMENT, _RESOURCE_SENSOR),
    {
        "MARKET": "The owned resource evaluator and worker (runtime/resource_measurement_execution.py:162; runtime/resource_measurement_worker.py:29-206) record per-step CPU nanoseconds and peak bytes; they accept no order, quote, counterparty, price, or settlement input (runtime/resource_measurement_worker.py:29-206).",
    },
    # ROBOT and FINBOT are deliberately UNRESOLVED: the owned execution module calls
    # package_execution.execute_bound (runtime/resource_measurement_execution.py:159,
    # 164), which launches the worker through subprocess.run (runtime/package_execution.py:302).
    # The worker's own absence of a process launch does not close the owned surface.
)


_ANCHOR_LEDGER = _declarations(
    "LEDGER",
    {
        "history": "LocalAnchorProvider owns the current in-memory anchor map; FileAnchorProvider additionally owns its append-only JSONL anchor record sequence.",
        "state": "State is the exact ContinuityAnchor selected by anchor_id, including content identity, epoch, sequence, root, provider, time, and HMAC signature.",
        "ordering": "Epoch and sequence are retained in each record; file order is append order, while duplicate anchor identifiers must reproduce the same complete record.",
        "authority": "Authority is only the caller-configured provider_id, key_id, and local HMAC key; no external witness or institutional authority is established.",
        "units": "Accounting units are discrete anchor records keyed by anchor_id; epoch and sequence are bounded integer coordinates, not money or physical quantities.",
        "balance_rules": "An anchor_id may denote one exact record; a differing reuse is a fork and is rejected rather than balanced or netted.",
        "rounding": "No numeric rounding occurs; digests, identifiers, epochs, and sequences are compared exactly.",
        "sources_and_sinks": "Records enter only through anchor_content or validated JSONL loading; there is no delete, redemption, or compaction path.",
        "corrections": "Existing records are immutable. A correction requires a separately identified later anchor; same-id disagreement is rejected as a fork.",
        "replay": "JSONL loading deterministically reconstructs the anchor map and rejects malformed rows and conflicting duplicates.",
        "reconciliation": "Reconciliation compares exact anchor identity and record equality plus local HMAC verification; it does not consult an external witness.",
        "recovery": "Recovery is bounded to reopening and validating the retained JSONL file; truncation, interrupted final writes, fsync durability, and external backup are not solved here.",
    },
)
_ANCHOR_TRANSACTION = _declarations(
    "TRANSACTION",
    {
        "effects": "anchor_content mutates the in-memory anchor map and FileAnchorProvider may append one canonical JSONL record to its configured path.",
        "preconditions": "Content identity, digest, epoch, sequence, time, provider configuration, same-id equality, readable existing lines, and parent-directory access are required.",
        "authorization": "The direct caller and locally configured provider/HMAC key authorize record construction; this is not external anchor or signer authority.",
        "resources": "Resources are the provider's process memory, signing key, configured JSONL path, parent directory, and one canonical serialized record.",
        "commit": "The in-memory effect occurs when the map assignment completes; the file effect occurs when the append write returns. No fsync or cross-resource atomic commit is claimed.",
        "abort": "Forks and parse or filesystem errors raise AnchorError or the underlying I/O error; no new file row is intentionally appended after a precondition failure.",
        "finality": "Finality is local same-id immutability within retained memory or JSONL bytes, not witnessed external finality or crash-durable storage.",
        "partial_failure": "The in-memory map is updated before directory creation and file append, so a later filesystem failure can leave memory ahead of the file; no rollback is implemented.",
        "duplicate_detection": "The exact anchor_id is checked in memory and existing JSONL lines; an equal duplicate is idempotent and a differing duplicate is rejected.",
        "idempotency": "Repeating the same complete anchor request preserves one map entry and at most one JSONL row when the existing file remains readable.",
        "retry_limits": "No retry loop or backoff is provided; the caller must inspect failure and retained file state before retrying.",
        "replay": "A retry or reload must reproduce the exact record for an existing anchor_id; external effects beyond the local map and file are absent.",
    },
)
_ANCHOR = _review(
    "vstd-anchor-history-ledger",
    {
        "LEDGER": "The anchor providers own authoritative local anchor-id history with append ordering, fork rejection, replay, and recovery boundaries.",
        "TRANSACTION": "Creating an anchor mutates memory and may append a JSONL record, with a material memory-before-file partial-failure boundary and duplicate retry rules.",
    },
    _merge(_ANCHOR_LEDGER, _ANCHOR_TRANSACTION),
    {
        "ASSET": "The anchor records (hardware/anchors.py:70-82) carry only anchor_id, content identity, epoch, sequence, rolling root, time, provider, and signature fields, with no holder, quantity, or custody field.",
        "ROBOT": "hardware/anchors.py imports no actuator, device, network, or agent module (hardware/anchors.py:7-14); its only external effect is the append-mode JSONL write at hardware/anchors.py:141.",
        "FINBOT": "hardware/anchors.py contains no price, order, balance, transfer, payment, settlement, or currency term and no agent identifier; its records are HMAC-signed continuity records (hardware/anchors.py:70-82).",
        "MARKET": "AnchorProvider and its local and file implementations (hardware/anchors.py:21-141) bind anchor identities to content digests and HMAC signatures; their public operations accept no order, quote, counterparty, price, or settlement input (hardware/anchors.py:21-141).",
    },
)


_NETWORK_LEDGER = _declarations(
    "LEDGER",
    {
        "history": "The artifact network owns content-addressed objects and records, silo commits, signed publisher heads, key-continuity records, and signed directory snapshots.",
        "state": "Current state is the exact selected commit/head/directory and its reachable immutable object and record digests under one store root.",
        "ordering": "Publisher head sequences, previous-head links, key transitions, commit ancestry, and canonical directory entries define explicit finite order.",
        "authority": "Authority is bounded to caller-selected publisher keys, signed records, explicit authority-model roots, and local store ownership; real-world identity is not established.",
        "units": "Units are exact bytes, digests, sequence numbers, finite record/member counts, and declared actions; there are no monetary balances.",
        "balance_rules": "Content digests must match bytes, signed chains must link exactly, finite censuses must close, and duplicate identities must not disagree.",
        "rounding": "Canonical JSON permits JavaScript-safe integers and exact byte/digest comparison; no floating-point or monetary rounding is admitted.",
        "sources_and_sinks": "Objects and records enter through bounded content-addressed writes and verified transfer/materialization; the module never deletes or garbage-collects stored objects or records, and its only removals are partial export or rebuild destinations on exception (interoperability/network.py:2336-2338, 2525-2527) and CLI unlink calls (runtime/network_cli.py:293, 301).",
        "corrections": "Published history is corrected by a new linked commit, head, directory, or key-continuity record; retained content is not silently overwritten under the same digest.",
        "replay": "Export, transfer, clone, rebuild, and assessment re-read canonical bytes and revalidate digests, signatures, ancestry, census, and authority-model closure.",
        "reconciliation": "Reconciliation is exact comparison of commit inventories, publisher/key continuity, directory entries, and rebuilt store contents at selected coordinates.",
        "recovery": "Recovery can rebuild or reclone verified retained bytes; remote availability, private-key recovery, concurrent writers, and storage durability remain external.",
    },
)
_NETWORK_TRANSACTION = _declarations(
    "TRANSACTION",
    {
        "effects": "Store writes, exports, downloads, transfer materialization, clone, and rebuild create bounded local filesystem objects and metadata; the Claim Garden register path POSTs to its endpoint unconditionally and writes the returned bearer token to a local file (runtime/network_cli.py:361-404).",
        "preconditions": "Canonical shape, byte limits, digest/signature validity, chain continuity, safe relative paths, allowed inventories, and destination conditions must hold.",
        "authorization": "The direct caller selects source, destination, opener, and keys; signed publisher material authenticates bounded records but grants no execution permission.",
        "resources": "Resources include bounded payloads, HTTPS responses, source/export/store directories, private-key files, temporary local paths, and finite inventories.",
        "commit": "Each operation commits only at its documented local file/directory write or verified materialized tree; there is no distributed atomic commit across peers.",
        "abort": "Validation, size, redirect, transport, signature, digest, path, inventory, and filesystem failures raise NetworkError or an I/O error and stop the selected operation.",
        "finality": "Content-addressed bytes are locally final under their digest and signed sequence records are immutable inputs; remote publication or execution finality is not established.",
        "partial_failure": "Multi-file export, clone, and rebuild can fail after earlier local writes; export and rebuild remove their partial destination on exception (interoperability/network.py:2336-2338, 2525-2527), but a process interruption can still leave an incomplete destination that the caller must not treat as a committed silo.",
        "duplicate_detection": "Digest-addressed paths, signed sequence/link checks, exact inventories, and destination validation identify equal repeats and conflicting retained state.",
        "idempotency": "Only digest-addressed object writes are byte-idempotent (interoperability/network.py:1421-1427); composite export, materialization, and rebuild refuse an existing destination (interoperability/network.py:2180-2181, 2318-2319, 2458-2459) rather than repeating silently.",
        "retry_limits": "Network redirects, bytes, entries, and records are bounded; general operator retry count and backoff are not provided by this module.",
        "replay": "Replay must revalidate the same signed/digested transfer and safe destination inventory; retained bytes confer no permission to execute them.",
    },
)
_NETWORK_PROTOCOL = _declarations(
    "PROTOCOL",
    {
        "participants": "Participants are publisher/key holders, signed directory providers, source stores or HTTPS endpoints, local consumers/materializers, and the Claim Garden enrollment endpoint (runtime/network_cli.py:361-404).",
        "roles": "Publishers sign heads and continuity; directories enumerate publishers; sources serve bounded transfers; consumers verify before retaining local bytes.",
        "states": "States include absent, content-addressed, committed, head-linked, directory-listed, transferred, materialized, assessed, and rejected.",
        "transitions": "Canonical object insertion, commit formation, head/key signing, directory signing, transfer construction, download, verification, and materialization define transitions.",
        "message_authority": "Ed25519 signatures and exact key identifiers bind selected messages; caller trust roots and real-world publisher identity remain external selections.",
        "ordering": "Head sequences and previous digests, key-continuity links, commit ancestry, and transfer record dependencies are checked exactly.",
        "replay": "Equal signed content may be replayed safely only under the same digest and sequence; conflicting sequence, key, ancestry, or bytes are rejected.",
        "compatibility": "Schema constants, canonical JSON, finite limits, media/artifact kinds, and declared authority-model versions define compatibility.",
        "failure_assumptions": "Peers, storage, DNS/TLS, redirects, signed data, and local files may be absent, malformed, stale, hostile, truncated, or inconsistent.",
        "safety": "Bounded reads, safe paths, canonical forms, digest/signature checks, closed inventories, and verify-before-accept rules prevent silent substitution within scope.",
        "liveness": "No remote availability or progress guarantee is made; bounded operations either return one verified result or fail.",
        "recovery": "Recovery uses a fresh verified transfer, clone, export, or rebuild from retained valid records; automatic distributed repair is not claimed.",
    },
)
_NETWORK_POLICY = _declarations(
    "POLICY",
    {
        "scope": "Policy covers exact allowable-action authority models, ground agency, actor-scoped local additions, finite reachable states, and composition admission for one selected silo.",
        "decision_inputs": "Inputs are the selected authority-model record, ground action and actor-scope digests, transitions, local additions, commit census, composition members, adapters, relations, and policies.",
        "precedence": "Ground agency is a required floor; local additions remain actor-scoped and cannot revoke ground actions; composition obligations do not disappear through member intersection.",
        "defaults": "Missing, malformed, ungrounded, incompatible, incomplete, or unclosed authority evidence fails closed rather than inferring permission.",
        "authority": "The caller selects trust roots and records; signed publishers bind bytes, but the module does not establish real-world actors or permission to execute artifacts.",
        "exceptions": "Only explicit finite local additions and declared composition adapters/relations are considered; undeclared exceptions are not inferred.",
        "revisions": "A changed authority model, action set, actor scope, transition graph, mechanism bytes, or composition produces a different digest-bound policy coordinate.",
        "activation": "Activation is assessment of one exact selected commit/composition and its current inputs; no global deployment or time-based enforcement is implied.",
        "enforcement_points": "The assess_silo and assess_composition paths refuse to report grounded/complete outcomes when registered authority and closure checks fail.",
        "decision_evidence": "Assessment and receipt records bind exact commits, mechanism bytes, finite inputs, results, and reasons for the selected evaluation.",
        "bypass_handling": "Missing census members, authority roots, bridges, adapters, policies, or residual obligations remain failed or incomplete; generic object labels cannot bypass them.",
        "unavailable_behavior": "Unavailable cryptography, files, keys, records, or required closure yields an error or non-passing assessment, never inferred allowability.",
    },
)
_NETWORK = _review(
    "vstd-artifact-network-history",
    {
        "LEDGER": "Content-addressed records, signed heads, key continuity, commit ancestry, and directory snapshots form an authoritative bounded artifact history.",
        "TRANSACTION": "Export, transfer, clone, materialization, and rebuild create local filesystem effects with validation, partial-failure, finality, and retry boundaries.",
        "PROTOCOL": "Publishers, directories, stores, HTTPS sources, and consumers follow signed, ordered, replay-checked transfer and reconstruction states.",
        "POLICY": "The source implements explicit authority-model and silo-composition admission rules over allowable actions, local additions, and closure evidence.",
    },
    _merge(_NETWORK_LEDGER, _NETWORK_TRANSACTION, _NETWORK_PROTOCOL, _NETWORK_POLICY),
    {
        "ASSET": "Network records carry no asset identity, quantity, issuance, redemption, custody, or backing field (interoperability/network.py); the only rights-like content is the nine declared actions of AUTHORITY_AXIOM_AGENCY (interoperability/network.py:86-96), which are operation permissions, not holdings.",
        "MARKET": "The network's public operations (interoperability/network.py:134-304) are canonical encoding, digest, record-construction, and verification functions, with bounded transfer download at interoperability/network.py:2220-2264; none accepts an order, quote, counterparty, price, or settlement term (interoperability/network.py:134-2264).",
    },
    # ROBOT and FINBOT are deliberately UNRESOLVED here: the owned CLI posts a claim
    # to a remote Claim Garden publication endpoint (runtime/network_cli.py:361-404;
    # interoperability/claim_garden.py:79-80, 468) and transfers reach remote peers
    # (interoperability/network.py:2228-2229).  Remote consequences are outside the
    # closed surface, so no physical or financial endpoint is refuted.
)


_ASSURANCE_LEDGER = _declarations(
    "LEDGER",
    {
        "history": "AssuranceLedger owns an append-only sequence of assurance events plus retained conflict resolutions over one immutable provenance graph coordinate.",
        "state": "Current artifact, transformation, trust, applicability, violation, and diagnostic state is derived from the exact retained event prefix; responsibility and guilt are not materialized into the current graph (data/assurance.py:658-677).",
        "ordering": "Each event carries a sequence, previous digest, and canonical digest; projections and grouped guilt components preserve explicit prerequisite order.",
        "authority": "Authority is local to the selected AssuranceLedger instance, immutable graph, and caller-supplied mechanisms and recorded evidence; external adjudicative authority is not established.",
        "units": "Units are discrete events, artifacts, transformations, conflicts, obligations, and graph relations; counts are diagnostic and nonmonetary.",
        "balance_rules": "Hash-chain continuity, immutable historical graph identity, admissible conflict resolution, prerequisite closure, and additive current-state rules are enforced.",
        "rounding": "Event identity and status are exact; no numeric ratio is computed, so no rounding applies and no balance, payment, or precision guarantee is created.",
        "sources_and_sinks": "Events enter only through typed record methods and are never edited or removed; current state is a projection rather than a destructive sink.",
        "corrections": "Contradictions remain retained and can receive explicit conflict resolutions or later additive events; historical events are not rewritten.",
        "replay": "recheck_assurance_log reconstructs typed events, validates their chain and graph coordinate, and compares the recomputed current state.",
        "reconciliation": "Serialized history is reconciled against the exact immutable provenance graph and recomputed current-state materialization, not an external execution system.",
        "recovery": "Recovery is deterministic reconstruction from a complete valid serialized log and the matching graph; durability, backup, and concurrent-writer recovery are external.",
    },
)
_ASSURANCE_TRANSACTION = _declarations(
    "TRANSACTION",
    {
        "effects": "Record methods append one event or a staged related group and may append one conflict resolution to in-process AssuranceLedger state.",
        "preconditions": "The historical graph must remain unchanged and referenced subjects, mechanisms, evidence, prerequisites, conflicts, and current-state relations must be admissible.",
        "authorization": "The direct caller invokes mutation and supplies actors or mechanisms; recorded identities and evidence do not independently authenticate real-world authority.",
        "resources": "Resources are one ledger instance, its immutable graph snapshot, current event/resolution lists, and bounded caller-supplied evidence payloads.",
        "commit": "A single record commits when its event is appended. Grouped guilt establishment stages all payloads before appending its required event group.",
        "abort": "Invalid graph state, references, conflicts, prerequisites, mechanism results, or evidence export raises before the corresponding retained event append where the method specifies.",
        "finality": "Committed events are append-only for that in-memory ledger prefix; this is not durable, externally witnessed, or globally authoritative finality.",
        "partial_failure": "Caller-supplied evidence exporters may have effects before the staged ledger append; the source explicitly avoids an unreplayable partial event prefix but cannot roll back exporter effects.",
        "duplicate_detection": "Event digests, existing current state, conflict identities, and prerequisite relations detect some repeats; not every record method promises request-id idempotency.",
        "idempotency": "Replay validation is deterministic, but mutation calls must be retried only after inspecting retained state because a completed append is not generically deduplicated by invocation id.",
        "retry_limits": "The module supplies no automatic retry or backoff. The caller must bound evidence mechanisms and stop on an ambiguous exporter or append outcome.",
        "replay": "A serialized valid prefix can be replayed to the same current state; replay re-executes the caller-supplied mechanisms (data/assurance.py:1816-1821), does not repeat caller exporter effects, and does not prove recorded mechanism observations true.",
    },
)
_ASSURANCE = _review(
    "vstd-assurance-event-ledger",
    {
        "LEDGER": "AssuranceLedger is the authoritative local append-only event and conflict-resolution history from which current assurance graph state is derived.",
        "TRANSACTION": "Its record methods mutate the retained prefix, and grouped guilt recording explicitly stages related evidence to avoid partial ledger commit while detecting exporter-induced graph mutation before the group append.",
    },
    _merge(_ASSURANCE_LEDGER, _ASSURANCE_TRANSACTION),
    {
        "ASSET": "data/assurance.py contains no asset, balance, payment, settlement, price, money, custody, or currency term; its events and resolutions are kept only as lists (data/assurance.py:391-393), so they represent no owned right or quantity.",
        "ROBOT": "data/assurance.py contains no agent, harness, controller, actuator, motor, or hardware term, and its imports (data/assurance.py:22-47) include no hardware package; its effects are appends to in-memory event and resolution lists (data/assurance.py:409-468).",
        "FINBOT": "data/assurance.py contains no agent, money, payment, settlement, price, balance, or exposure term; its records are event and resolution lists (data/assurance.py:391-393), so no financial agent-authority obligation has a referent.",
        "MARKET": "AssuranceLedger's record methods (data/assurance.py:726-1030) append typed status, conflict, trust, and diagnostic projections; the owned event and obligation types (data/assurance.py:50-342) carry no order, quote, counterparty, price, allocation, or settlement field.",
    },
)


_CHALLENGE_LEDGER = _declarations(
    "LEDGER",
    {
        "history": "ChallengeLedger owns one append-only sequence of filed challenge and final adjudication records for claim identifiers.",
        "state": "ClaimStatus is derived from the complete applicable record set; status is never a mutable field sealed into an earlier record.",
        "ordering": "Record sequence is append order, challenge identity is unique, a challenge must precede its adjudication, and each challenge has at most one final adjudication.",
        "authority": "The local ledger enforces shape and transition rules while retaining challenger and adjudicator identifiers; it does not authenticate those actors or confer external enforcement authority.",
        "units": "Units are discrete challenges, adjudications, claims, surfaces, exclusions, and artifact-status values; there are no financial balances.",
        "balance_rules": "Duplicate challenge ids, missing challenges, and second adjudications are rejected; inadmissible filings are recorded as REFUSED (layer4/challenge.py:239-243), and claim status is the most degraded derived status.",
        "rounding": "No rounding occurs; identifiers, enumerated outcomes, digests, timestamps, and statuses are compared exactly.",
        "sources_and_sinks": "Records enter through file or adjudicate and are never edited or removed; projections consume the full retained prefix without deleting history.",
        "corrections": "A final adjudication cannot be overwritten. A genuinely different issue requires a separately identified challenge and remains visible in history.",
        "replay": "Serializing and replaying the same ordered record set reproduces derived claim status when the same refutation surface is selected.",
        "reconciliation": "records and status reconcile by recomputing each claim from its filed and adjudicated entries; external sanctions or claim publication are outside scope.",
        "recovery": "Recovery requires the complete valid append-only record set; this in-memory implementation provides no durable store, backup, or concurrent-writer recovery.",
    },
)
_CHALLENGE_TRANSACTION = _declarations(
    "TRANSACTION",
    {
        "effects": "file and adjudicate append one ChallengeRecord to local ledger state and thereby change the derived current claim status.",
        "preconditions": "Filing requires admissibility against the selected refutation surface; adjudication requires an existing filed challenge and no prior final adjudication.",
        "authorization": "The direct caller supplies challenger and adjudicator identifiers; the ledger records them but performs no identity authentication or external authorization check.",
        "resources": "Resources are the in-memory record list, challenge-id index implied by that list, one selected refutation surface, and typed input records.",
        "commit": "Commit is an in-process list append; two dict writes precede it (layer4/challenge.py:237-238), and derived status observes the new complete prefix immediately afterward.",
        "abort": "Duplicate ids, absent challenges, and repeated adjudications raise ChallengeError before a new record is appended; inadmissible filings are recorded as REFUSED rather than raised (layer4/challenge.py:232-244).",
        "finality": "An adjudication is final inside this retained record set; no appeal execution, external enforcement, persistence, or distributed finality is claimed.",
        "partial_failure": "Each mutation performs validation before one list append and has no declared external effect, but process interruption and caller effects are outside its atomic boundary.",
        "duplicate_detection": "Challenge ids detect repeated filing and the existing adjudication record detects repeated finalization.",
        "idempotency": "A repeated successful filing or adjudication is rejected rather than returned as an idempotent success; callers must inspect current records before retry.",
        "retry_limits": "No retry loop is supplied; the caller must stop or issue a distinct valid challenge after a deterministic rejection.",
        "replay": "Replay must preserve exact record order and identities; it reconstructs local status but does not replay any external remedy or sanction.",
    },
)
_CHALLENGE_POLICY = _declarations(
    "POLICY",
    {
        "scope": "Policy covers whether a challenge is admissible against a selected claim refutation surface and how terminal outcomes degrade derived claim status.",
        "decision_inputs": "Inputs are challenge kind and target, surface categories and exclusions with reasons, filed records, terminal adjudications, and current artifact statuses.",
        "precedence": "Explicit surface exclusions refuse filing; otherwise supported categories admit it, and the most degraded applicable derived status governs the claim projection.",
        "defaults": "A category outside the admitted surface or explicitly excluded is refused; missing adjudication remains an unresolved filed challenge rather than an invented favorable result.",
        "authority": "The caller supplies the surface and adjudication records; the module records no declarant or adjudicator identity (layer4/challenge.py:69-80, 99-104).",
        "exceptions": "Only exact documented RefutationSurface exclusions with their reasons are honored; no implicit exception or generic label escape is inferred.",
        "revisions": "A changed surface, exclusion set, challenge record, or adjudication is different retained input; earlier records are not revised in place.",
        "activation": "The selected surface governs filing at call time and appended records affect local derived status immediately; no external policy deployment is claimed.",
        "enforcement_points": "admissibility refuses excluded filings, file enforces admission and uniqueness, adjudicate enforces terminality, and status applies degradation rules.",
        "decision_evidence": "Admission details, complete append-only records, typed outcomes, actor assertions, and derived ClaimStatus provide the local decision trace.",
        "bypass_handling": "Direct mutation is not exposed; excluded filings are recorded as REFUSED, and conflicting terminal records raise rather than silently entering current state.",
        "unavailable_behavior": "Missing surfaces, missing predecessor records, malformed values, or absent adjudication cannot be promoted into a favorable terminal claim.",
    },
)
_CHALLENGE = _review(
    "vstd-challenge-record-ledger",
    {
        "LEDGER": "The source owns append-only filing and adjudication history from which current claim status is derived without rewriting prior records.",
        "TRANSACTION": "Filing and final adjudication are validated local state mutations with duplicate, abort, commit, finality, and retry semantics.",
        "POLICY": "admissibility, exact exclusions, terminal outcome interpretation, and most-degraded status projection are explicit local decision rules.",
    },
    _merge(
        _CHALLENGE_LEDGER,
        _CHALLENGE_TRANSACTION,
        _CHALLENGE_POLICY,
    ),
    {
        "ASSET": "layer4/challenge.py contains no financial, asset, or money term; its units are challenge records and enumerated outcomes (layer4/challenge.py:56-63, 133-148), so it represents no owned right or quantity.",
        "ROBOT": "layer4/challenge.py contains no agent, controller, actuator, or hardware term and imports only core, data, and layer4 modules (layer4/challenge.py:41-49); its only effect is appending in-memory ChallengeRecord entries (layer4/challenge.py:265-268).",
        "FINBOT": "layer4/challenge.py contains no agent, money, payment, price, balance, or exposure term; its records classify refutation status of claim identifiers only (layer4/challenge.py:56-63).",
        "MARKET": "ChallengeLedger.file, adjudicate, records, and status (layer4/challenge.py:232-277) admit, finalize, and classify refutation records for claim identifiers; the owned types (layer4/challenge.py:52-222) carry no order, quote, counterparty, price, or settlement field.",
    },
)


_CONSENT_POLICY = _declarations(
    "POLICY",
    {
        "scope": "Consent evaluation is limited to the exact principal, delegate chain, context, operation, data scope, purpose, constraints, and invocation selected by the trusted caller.",
        "decision_inputs": "Inputs are captured trusted policy terms, shared-key or Ed25519 grant/revocation statements, status material, evaluation time, and the exact requested binding.",
        "precedence": "Exact binding and scope checks precede delegation; explicit revocation, expiry, status uncertainty, and malformed or conflicting statements prevent an allow decision.",
        "defaults": "Missing trusted policy, keys, grants, current status, evaluation time, or exact scope is UNKNOWN or rejected; consent is never inferred from silence.",
        "authority": "The trusted caller selects principals, keys, policy, time, and status roots; cryptographic validity binds statements but does not prove voluntary human consent or legal authority.",
        "exceptions": "Only explicitly signed and scope-narrowing delegation or constraints are considered; wildcard authority and implicit expansion are not inferred.",
        "revisions": "Changed policy terms, keys, grants, revocations, status roots, contexts, or scopes are distinct captured inputs and must be reevaluated.",
        "activation": "A policy is active only within its declared time/status and exact binding under the caller-supplied evaluation coordinate; no ambient global activation exists.",
        "enforcement_points": "The shared-key and public-key evaluators return bounded verdicts before a cooperating caller acts; they do not intercept or control outside execution.",
        "decision_evidence": "The evaluation records exact captured inputs, verified statement relationships, checks, verdict, and reasons for the selected invocation.",
        "bypass_handling": "Malformed, untrusted, scope-expanding, expired, revoked, or status-uncertain paths do not yield ALLOW; direct noncooperating execution remains outside this module.",
        "unavailable_behavior": "Absent keys, status, time, policy, or complete chain fails closed to UNKNOWN or rejection rather than fabricating consent.",
    },
)
_CONSENT = _review(
    "vstd-consent-policy",
    {
        "POLICY": "The engine and public-key variant implement exact consent scope, delegation, revocation, status, precedence, authority-selection, and fail-closed decision rules.",
    },
    _CONSENT_POLICY,
    {
        "ROBOT": "Consent evaluation returns a ConsentEvaluation receipt with enforcement NOT_ESTABLISHED (consent/engine.py:490; consent/public.py:228) and performs no operation (consent/public.py:199); the consent sources contain no actuator, hardware, agent, harness, controller, network, or write term.",
        "FINBOT": "The consent sources contain no money, price, payment, transfer, settlement, balance, asset, or exposure term (the only 'small-order' text is a cryptographic key term, consent/public.py:80); evaluation returns a receipt with enforcement NOT_ESTABLISHED (consent/engine.py:490).",
        "MARKET": "evaluate_consent (consent/engine.py:448) and evaluate_public_consent (consent/public.py:191) return a ConsentEvaluation verdict for one exact binding and perform no order, quote, counterparty, price, or settlement operation (consent/public.py:199).",
    },
)


_DATASET_POLICY = _declarations(
    "POLICY",
    {
        "scope": "Three distinct predicates over the selected target's recorded ancestor closure, including the target itself.",
        "decision_inputs": "ProvenanceHypergraph, target identifier, recorded statuses and rights, and optional approved license identifiers.",
        "precedence": "Structural validity precedes decision. Grounded encoding is authoritative; solver/direct disagreements raise rather than choosing a preferred answer.",
        "defaults": "No-revoked differs from all-valid; missing target and rootless license evidence are indeterminate. Missing rights do not satisfy approval; explicit empty license selection stays empty.",
        "authority": "The caller selects the graph, predicate, and license list; authenticity of metadata and legal authority are outside this implementation.",
        "exceptions": "No override argument bypasses structural or encoding checks; selecting a different predicate is a different named claim.",
        "revisions": "Installed source defines each rule. Explicit per-call license selections replace that call's default list; there is no persistent revision service.",
        "activation": "Each invocation reads its supplied graph and configuration; no cached approval or external enforcement activation is promised.",
        "enforcement_points": "All three public verification methods validate structure and certify their emitted encoding before a determined result.",
        "decision_evidence": "Results carry policy and target identifiers, verdict, clauses, and variable map. Encoding errors may retain a kernel-checkable certificate; normal result records do not export it.",
        "bypass_handling": "Malformed lineage and contradictory or incomplete encodings refuse; downstream callers remain responsible for enforcing these decisions.",
        "unavailable_behavior": "An absent target or rootless source-license question is INDETERMINATE, not successful compliance. Unsupported external truth is not inferred.",
    },
)
_DATASET = _review(
    "vstd-dataset-provenance-policy",
    {
        "POLICY": "The installed provenance-policy engine decides three recorded-lineage predicates over status, rights, and approved source licenses; it establishes neither provenance truth nor legal or downstream enforcement authority.",
    },
    _DATASET_POLICY,
    {
        "MARKET": "ProvenancePolicyVerifier's three verify methods (data/policy.py:338-556) return recorded-lineage verdicts over statuses, rights, and license identifiers; no order, quote, counterparty, price, allocation, or settlement input exists (data/policy.py:268-556).",
    },
    # ROBOT and FINBOT are deliberately UNRESOLVED: the owned execution module calls
    # package_execution.execute_bound (runtime/provenance_policy_execution.py:146,
    # 151), which launches sys.executable with a selected worker through subprocess.run
    # (runtime/package_execution.py:302).  The launched target's closure and the
    # reachable verifier-run subprocess surface (verifier/core/run.py) are not closed.
)


_GOVERNANCE_POLICY = _declarations(
    "POLICY",
    {
        "scope": "GovernancePolicy applies to exact object names, operations, jurisdictions, effective interval, principals, quorum, veto actors, status root, and selected invocation binding.",
        "decision_inputs": "Inputs are the captured trusted policy, exact context binding, signed actor decisions, signed current status, evaluation time, and prior invocation identity.",
        "precedence": "Scope and effective-time checks precede vote counting; valid veto or denial prevents approval, quorum is necessary, and current revocation or consumption status is authoritative within the selected root.",
        "defaults": "Missing or malformed trusted policy, status, time, decisions, keys, signatures, quorum, or exact scope yields UNKNOWN or rejection rather than inferred approval.",
        "authority": "The trusted caller selects policy, principal keys, status key, time, and jurisdiction; signatures bind records but do not prove personhood, legal authority, or jurisdictional truth.",
        "exceptions": "Only exact policy-scoped principals, veto terms, and retained status exceptions are recognized; undeclared actors and scopes are not admitted.",
        "revisions": "Policy revision and digest change with retained terms; changed principals, scopes, keys, quorum, veto, interval require a distinct evaluation coordinate.",
        "activation": "The policy is active only inside its effective interval and for the exact caller-selected binding and current signed status.",
        "enforcement_points": "evaluate_governance and recheck_governance return bounded verdicts to cooperating callers; they do not execute, permit, or block the downstream operation themselves.",
        "decision_evidence": "GovernanceEvaluation retains checks, captured binding, time, policy identity/revision/digest, approvals, vetoes, and status facts.",
        "bypass_handling": "Out-of-scope, unsigned, unknown-key, expired, revoked, consumed, duplicate, denied, vetoed, or insufficient-quorum records cannot produce approval.",
        "unavailable_behavior": "Unavailable trusted policy, evaluation time, status, keys, or adequate valid decisions leaves governance approval unestablished.",
    },
)
_GOVERNANCE = _review(
    "vstd-governance-policy",
    {
        "POLICY": "Governance evaluation implements scoped rules, effective intervals, principal authority, quorum, veto, revocation, consumption, and fail-closed verdicts.",
    },
    _GOVERNANCE_POLICY,
    {
        "ROBOT": "evaluate_governance returns a GovernanceEvaluation receipt with enforcement UNKNOWN (governance/__init__.py:295) and states that a passing receipt is not an execution permit (governance/__init__.py:258-260); the file contains no actuator, hardware, agent, harness, or controller term.",
        "FINBOT": "governance/__init__.py contains no money, price, payment, transfer, settlement, balance, asset, or exposure term; evaluate_governance returns a receipt with enforcement UNKNOWN (governance/__init__.py:295) and performs no financial effect.",
        "MARKET": "evaluate_governance (governance/__init__.py:246) and recheck_governance (governance/__init__.py:398) return approval verdicts for one exact invocation binding; the owned policy and receipt types (governance/__init__.py:24-245) carry no order, quote, counterparty, price, or settlement term.",
    },
)


_EMULATOR_LEDGER = _declarations(
    "LEDGER",
    {
        "history": "VirtualVSTDAccelerator owns an append-only in-memory sequence of boot, partition, execution, observation, completion, anchor, and reset accounting events.",
        "state": "Current simulated device epoch, rolling root, sequence, partitions, challenges, attestations, executions, observations, anchors, resets, and receipts derive from retained fields and events.",
        "ordering": "Each accounting event carries epoch, monotone sequence, previous root, and rolling root; execution starts precede observations and completion within the emulator lifecycle.",
        "authority": "Authority is local to the direct caller, emulator instance, test HMAC key, and optional selected AnchorProvider; no physical firmware or hardware root is established.",
        "units": "Units include discrete events/executions/partitions, byte and count quantities, caller-supplied timestamps, and digest identities; no monetary unit is present.",
        "balance_rules": "Rolling-root continuity, epoch/sequence order, partition-capacity limits, unique lifecycle records, and execution/accounting relationships constrain state.",
        "rounding": "Integer capacities and quantities and exact digests are retained without rounding; the emulator establishes no physical performance precision.",
        "sources_and_sinks": "State enters through explicit emulator commands and remains in memory for receipt/topology construction; no delete or durable compaction path exists.",
        "corrections": "Prior events are not edited. reset advances epoch and records a reset boundary; later records cannot silently rewrite an earlier rolling root.",
        "replay": "Retained events and roots expose continuity for deterministic inspection, but this module does not provide a durable full command replay engine.",
        "reconciliation": "Receipts, continuity records, topology, anchors, and accounting state reconcile against the emulator's exact in-memory prefix and test trust root.",
        "recovery": "A reset records a new simulated epoch; process loss destroys unpersisted state, and physical firmware recovery, durable replay, and external backup are not claimed.",
    },
)
_EMULATOR_TRANSACTION = _declarations(
    "TRANSACTION",
    {
        "effects": "Configuration, boot, challenge, attestation, execution submission/observation/completion, anchor, and reset mutate bounded in-memory simulated device state.",
        "preconditions": "Device lifecycle state, capacity, unique identities, matching executions/challenges, valid quantities, event continuity, and selected provider conditions must hold.",
        "authorization": "The direct Python caller invokes every mutation; the test HMAC key and provider bind simulated evidence but do not authenticate a physical operator.",
        "resources": "Resources are one emulator instance, finite partitions and record lists, simulated capacity, test keys, caller values, and an optional anchor provider.",
        "commit": "Each method commits when its validated state fields and corresponding accounting event/list entries have been updated and the method returns.",
        "abort": "FirmwareContractError rejects invalid state, capacity, identity, order, or continuity; no external physical effect is initiated.",
        "finality": "Committed state is final only for the current in-memory simulated prefix and epoch; it is neither crash-durable nor externally witnessed unless a separate anchor is successfully retained.",
        "partial_failure": "Methods make multiple in-memory updates and anchor may call an external provider; Python exceptions or provider failures can require inspection of retained state because no general rollback transaction exists.",
        "duplicate_detection": "Execution, challenge, partition, boot, sequence, and lifecycle identities plus current lists and roots detect bounded conflicts; duplicate semantics vary by command.",
        "idempotency": "Commands are not generically idempotent. A caller must inspect sequence, epoch, ids, and retained records before retrying after an ambiguous failure.",
        "retry_limits": "No automatic retry or backoff is implemented; capacity and lifecycle rules bound admissible attempts, and the caller owns retry count.",
        "replay": "A retry must respect current epoch/sequence and exact ids. Receipt or accounting replay demonstrates simulated continuity, not repetition of physical work.",
    },
)
_EMULATOR_CONTROLLER = _declarations(
    "CONTROLLER",
    {
        "objectives": "Maintain a valid simulated accelerator lifecycle, partition capacity, execution ordering, accounting continuity, and reset/anchor state under explicit caller commands.",
        "feedback": "Control decisions read the emulator's current boot, epoch, partition, challenge, execution, event, and rolling-root state; no external physical feedback is consumed.",
        "commands": "configure_partitions, boot, issue_challenge, attest, submit_execution, observe_execution, complete_execution, anchor, and reset are the bounded control surface.",
        "authority": "The direct caller has software control of the virtual instance; test keys and anchors do not confer physical-device command authority.",
        "timing": "Ordering uses caller-supplied timestamps and synchronous method order; there is no real-time deadline, scheduler guarantee, or clock authentication.",
        "stability_assumptions": "Stability means invariant-preserving finite simulated state transitions, not closed-loop control stability or plant dynamics.",
        "operating_envelope": "The envelope is the configured virtual capacity, supported partition and execution shapes, current lifecycle state, and finite in-memory package types.",
        "saturation": "Partition requests beyond simulated physical capacity and invalid quantities are refused; no command is clipped into an apparently successful physical value.",
        "feedback_loss": "Missing lifecycle state or referenced execution/challenge is treated as a contract error; no stale physical observation is substituted.",
        "arbitration": "Calls are serialized only by ordinary Python execution and explicit state checks; no concurrent multi-controller arbitration is established.",
        "intervention": "A cooperating caller can stop issuing commands or invoke reset when permitted; no emergency physical stop or independent supervisor exists.",
        "failure_behavior": "Invalid transitions raise FirmwareContractError and preserve a bounded software failure; general multi-step rollback and crash recovery are not guaranteed.",
    },
)
_EMULATOR_ACTUATOR = _declarations(
    "ACTUATOR",
    {
        "commands": "The emulator accepts explicit configuration, boot, challenge, attestation, execution, observation, completion, anchor, and reset method calls.",
        "targets": "Targets are only VirtualVSTDAccelerator in-memory state, simulated partitions/executions, accounting events, receipts, and an explicitly supplied anchor provider.",
        "effect_domains": "SIMULATED_ACCELERATOR_ONLY; no physical accelerator, motor, network service, money rail, or external workload is commanded by these exact sources.",
        "authority": "The direct caller controls the simulated instance. The source claims no physical firmware privilege, host isolation, or external-effect authority.",
        "units_and_frames": "Effects are framed by virtual device/execution ids, epoch, sequence, integer capacities/quantities, caller time strings, and exact digests.",
        "response": "Successful calls return typed simulated records after local state updates; no physical response time, motion, power, or delivered compute is represented.",
        "limits": "Configured capacity, lifecycle prerequisites, unique identities, valid quantities, and event continuity limit accepted commands.",
        "saturation": "Over-capacity partitioning and invalid state are rejected with FirmwareContractError rather than silently saturating a physical target.",
        "effect_feedback": "Returned events, observations, roots, continuity records, topology, and receipts expose local simulated effects only.",
        "interlocks": "Boot, current epoch, capacity, predecessor, identity, and rolling-root checks interlock state-changing methods.",
        "failure_states": "Contract exceptions, provider failures, invalid order, exhausted capacity, and process interruption can leave no physical effect but may require inspection of in-memory partial state.",
        "recovery": "Recovery is bounded to caller inspection, a valid later command, or simulated reset/new instance; no physical safe-state guarantee is made.",
    },
)
_EMULATOR_PROTOCOL = _declarations(
    "PROTOCOL",
    {
        "participants": "Participants are the direct caller, one VirtualVSTDAccelerator instance, optional AnchorProvider, and later receipt/continuity verifier.",
        "roles": "The caller supplies commands and observations, the emulator validates and records simulated transitions, the anchor provider retains a selected root, and verifiers inspect artifacts.",
        "states": "States include configured, booted by epoch, partitioned, challenged, attested, execution-started, observed, completed, anchored, and reset.",
        "transitions": "Typed methods move the in-memory state only after lifecycle, identity, capacity, and chain checks and append corresponding accounting records.",
        "message_authority": "Direct calls identify the caller only by process access; HMAC evidence is a test trust root and an external AnchorProvider is separately selected.",
        "ordering": "Epoch and sequence increase monotonically, rolling roots link events, and challenge/execution predecessors constrain later records.",
        "replay": "Duplicate or out-of-order identities are bounded by current state; there is no generic exactly-once remote transport or physical-command replay guarantee.",
        "compatibility": "Package dataclasses, schema/version constants, supported state methods, canonical hashes, and receipt types define local compatibility.",
        "failure_assumptions": "Caller values, order, quantities, keys, provider behavior, and process lifetime may fail; physical correspondence and durable storage are not assumed.",
        "safety": "Invariant checks and hash-linked events prevent accepted simulated transitions from silently bypassing current lifecycle and accounting state.",
        "liveness": "No command, provider, execution, or verifier progress guarantee exists; a protocol state may remain incomplete indefinitely.",
        "recovery": "A caller may inspect records, reset the simulated epoch, or rebuild a new instance from external retained inputs; full durable replay is outside this source.",
    },
)
_EMULATOR = _review(
    "vstd-firmware-emulator-accounting",
    {
        "LEDGER": "The virtual accelerator owns hash-linked append-only firmware-accounting history and derived epoch, execution, anchor, and receipt state.",
        "TRANSACTION": "Its commands mutate multi-part in-memory state and sometimes an anchor provider, requiring explicit precondition, commit, partial-failure, retry, and replay boundaries.",
        "CONTROLLER": "The virtual device validates and sequences commands using current simulated lifecycle feedback, capacity limits, interlocks, and failure states.",
        "ACTUATOR": "Its command-to-effect surface changes only simulated/emulated accelerator state and an explicitly supplied local anchor target.",
        "PROTOCOL": "Caller, emulator, anchor provider, and verifier participate in an ordered boot/challenge/attestation/execution/accounting state machine.",
    },
    _merge(
        _EMULATOR_LEDGER,
        _EMULATOR_TRANSACTION,
        _EMULATOR_CONTROLLER,
        _EMULATOR_ACTUATOR,
        _EMULATOR_PROTOCOL,
    ),
    {
        "SENSOR": "emulator.py imports only compute-side modules with no clock, OS, device, or network module (hardware/emulator.py:7-20), and its firmware values are deterministic derivations from configuration (hardware/emulator.py:233-236).",
        "ASSET": "emulator.py has no holder, owner, transfer, redemption, or custody term; its quantities are caller-supplied per execution (hardware/emulator.py:340-358) and partition fractions are virtual configuration (hardware/emulator.py:167-190), so it asserts no owned right.",
        "ROBOT": "emulator.py has no agent, harness, or I/O import or call (hardware/emulator.py:7-20); its descriptor is vendor EMULATED (hardware/emulator.py:126-137), and all effects mutate in-memory state (hardware/emulator.py:314-459).",
        "FINBOT": "emulator.py contains no price, order, balance, transfer, payment, settlement, or currency term and no agent identifier; its accounting events are caller-supplied quantities bound to virtual device ids (hardware/emulator.py:337-371).",
        "MARKET": "VirtualVSTDAccelerator (hardware/emulator.py:75-459) configures simulated partitions and records boot, challenge, execution, observation, anchor, and reset events; it provides no market order, quote, counterparty, price, or settlement operation (hardware/emulator.py:75-459).",
    },
)


_PRECOMMIT_LEDGER = _declarations(
    "LEDGER",
    {
        "history": "PrecommitmentLedger owns one immutable envelope per envelope_id, each committing the verdict-material degrees of freedom before selected evidence is observed.",
        "state": "State is the exact retained PrecommitmentEnvelope, its commitments, content digest, and optional continuity anchor; audit selections are supplied per call and are not retained by the ledger.",
        "ordering": "Each commitment carries committed_at; audit compares selection and commitment times to evidence_observed_at, while same-id envelopes cannot fork.",
        "authority": "The declarant and caller supply commitments and times; an optional selected AnchorProvider binds content but does not establish external identity or honest clocks.",
        "units": "Units are discrete envelope ids, degree-of-freedom names, canonical values, timestamps, digests, and violation records; no monetary balance exists.",
        "balance_rules": "Same-id content is immutable and anchors bind the content digest; the required-degree check runs in audit_selections, not in record(), which admits any envelope whose id is new (layer4/precommit.py:334-339), and used selections must match timely commitments.",
        "rounding": "Values, digests, and timestamp strings are compared exactly; no floating-point or monetary rounding is involved.",
        "sources_and_sinks": "Validated envelopes enter through record and remain in the in-memory map; there is no deletion, replacement, or compaction method.",
        "corrections": "A retained envelope cannot be corrected in place. A changed commitment needs a different envelope identity and remains distinguishable from the earlier record.",
        "replay": "The same envelope and observed selections reproduce validation and audit violations, subject to the same exact timestamps and optional anchor record.",
        "reconciliation": "Envelope content reconciles against all required degrees, selected values/times, evidence observation times, and the optional exact anchor digest.",
        "recovery": "Recovery requires externally retaining and re-recording the complete envelope and anchor; this in-memory map provides no durable persistence or distributed recovery.",
    },
)
_PRECOMMIT_TRANSACTION = _declarations(
    "TRANSACTION",
    {
        "effects": "PrecommitmentLedger.record inserts one validated immutable envelope into the local in-memory envelope map.",
        "preconditions": "The envelope id must be new or bound to exactly equal content, and any separately checked anchor must match its digest; record() does not run the required-degree validator (layer4/precommit.py:334-339).",
        "authorization": "The direct caller selects and records the envelope; declarant strings and optional anchor signatures are retained assertions, not authenticated external authority here.",
        "resources": "Resources are one ledger map, one bounded typed envelope and its commitment tuple, and any independently selected AnchorProvider result.",
        "commit": "Commit is the single map assignment after the fork check; a returned envelope is present in the current process ledger.",
        "abort": "Same-id forks with differing content raise PrecommitmentError before the differing envelope can replace retained state (layer4/precommit.py:336-337).",
        "finality": "The same envelope_id is immutable inside that ledger instance; durable, globally witnessed, or externally enforced precommitment finality is not established.",
        "partial_failure": "The local record mutation is one map assignment with no declared external effect; optional anchoring is a separate operation and is not atomically committed with this map.",
        "duplicate_detection": "An existing envelope_id is compared for exact equality; equal replay returns the argument and differing replay is rejected as a fork (layer4/precommit.py:339).",
        "idempotency": "Recording the exact same envelope is idempotent within one retained ledger instance.",
        "retry_limits": "No automatic retry is performed; callers may repeat only the exact same envelope after inspecting any separate anchor outcome.",
        "replay": "Replay must preserve exact envelope id and content; audit replay compares selections without executing the committed evaluation or disclosure policy.",
    },
)
_PRECOMMIT = _review(
    "vstd-precommitment-ledger",
    {
        "LEDGER": "PrecommitmentLedger is the authoritative local immutable map of verdict-material envelopes, with fork rejection and deterministic audit reconciliation.",
        "TRANSACTION": "Recording an envelope is a fork-checked local map assignment with exact duplicate idempotency, fork abort, local finality, and a separate-anchor boundary.",
    },
    _merge(_PRECOMMIT_LEDGER, _PRECOMMIT_TRANSACTION),
    {
        "ASSET": "Precommitment envelopes are frozen commitment records with no financial or asset term (layer4/precommit.py:69-99), so the ledger represents no owned right or quantity.",
        "ROBOT": "layer4/precommit.py contains no agent, controller, actuator, or motor term; its one hardware-package import (layer4/precommit.py:39-40) is the AnchorProvider and ContinuityAnchor witness interface, with no physical-effect path.",
        "FINBOT": "layer4/precommit.py contains no agent, money, payment, settlement, or exposure term; its DegreeOfFreedom values (layer4/precommit.py:47-59) are evaluation, evidence, and disclosure choices.",
        "MARKET": "PrecommitmentLedger.record (layer4/precommit.py:334) stores one immutable envelope by identity, and audit_selections (layer4/precommit.py:248-321) compares observed selections with commitments; neither accepts an order, quote, counterparty, price, or settlement input (layer4/precommit.py:248-334).",
    },
)


_RETENTION_MEASUREMENT = _declarations(
    "MEASUREMENT",
    {
        "phenomenon": "The assessed phenomenon is whether exact artifact bytes supplied as a RetrievalObservation match a declared content address and locator under a declared retention commitment.",
        "method": "ArtifactAvailability.assess deterministically compares the supplied observation, content digest, locator, policy validity, and declared level, then assess_bundle takes the weakest critical result.",
        "source": "Sources are caller-supplied artifact declarations, RetentionPolicy terms, and RetrievalObservation bytes, time, observer, locator, and artifact id; this module fetches nothing itself.",
        "observation_vs_estimate": "Byte equality is evaluated from a retained observation; future retrievability and retention duration are declarations, not measured guarantees or estimates promoted to fact.",
        "units": "Artifact bytes are counted and hashed exactly; policy duration/end coordinates are retained ISO-8601 text, and availability is an ordered categorical level.",
        "reference_frame": "Each result is relative to one artifact_id, declared locator, content address, policy declarant, and caller-supplied observation coordinate.",
        "observation_time": "observed_at is caller-supplied nonempty text and is retained, not authenticated or sampled by this module.",
        "arrival_time": "No acquisition occurs here; the supplied RetrievalObservation is already present at evaluation, so network arrival latency remains unobserved.",
        "uncertainty": "Content equality is exact for supplied bytes, but observer identity, clock truth, locator reachability outside the observation, and future retention reliability remain unestablished.",
        "validity": "Validity requires exact artifact id, locator, content-address match, nonempty observation metadata, valid policy terms, and consistent declared-versus-derived level.",
        "missingness": "An absent or mismatching observation cannot establish current retrievability; missing critical artifacts lower the bundle outcome rather than being filled with success.",
        "freshness": "Freshness is limited to the caller-supplied observation coordinate; the source makes no live re-fetch or continuing-availability assertion.",
        "provenance": "The assessment binds artifact declaration, policy, supplied observer and time, locator, retrieved-byte digest, and derived reason without authenticating the observer.",
    },
)
_RETENTION_POLICY = _declarations(
    "POLICY",
    {
        "scope": "Policy records the declared retention horizon, responsible party, locator, content address, criticality, and minimum availability level for selected artifacts; the horizon is checked only as nonblank (layer4/availability.py:88-89) and is not evaluated.",
        "decision_inputs": "Inputs are ArtifactAvailability declarations, valid RetentionPolicy terms, optional exact RetrievalObservation records, and bundle criticality/required level.",
        "precedence": "Exact observed-byte mismatch or an overstated declaration fails; bundle assessment uses the weakest critical artifact and does not let stronger noncritical artifacts mask it.",
        "defaults": "Missing observations establish at most weaker identified/declared states; invalid policy or overstated level is not treated as available.",
        "authority": "The policy records who declares retention, but this module does not verify identity, legal duty, storage control, or future performance.",
        "exceptions": "Only artifacts explicitly marked noncritical are excluded from the critical floor; no missing critical artifact is silently waived.",
        "revisions": "Changed bytes, address, locator, retention terms, declarant, criticality, required level, or observation constitute a new assessment input.",
        "activation": "A policy contributes to one explicit assessment when its fields are valid; the module does not activate storage services or schedule retention work.",
        "enforcement_points": "ArtifactAvailability.assess derives per-artifact level and overstatement; assess_bundle enforces the critical-artifact floor and reports failures.",
        "decision_evidence": "AvailabilityAssessment retains artifact declarations, matching supplied observations, derived levels, required level, overstated ids, and reasons.",
        "bypass_handling": "A declared high level, nonmatching bytes, invalid policy, missing observation, or omitted critical artifact cannot be converted to successful availability by prose alone.",
        "unavailable_behavior": "Without a valid matching observation and policy, live retrievability or retained availability remains unestablished and the derived level stays bounded accordingly.",
    },
)
_RETENTION = _review(
    "vstd-retention-policy",
    {
        "MEASUREMENT": "The source evaluates exact supplied retrieval bytes, content identity, locator, observation coordinates, missingness, and derived availability levels; it does not acquire them.",
        "POLICY": "RetentionPolicy and bundle assessment implement declared responsibility, duration, criticality, minimum-level, overstatement, and fail-closed availability rules.",
    },
    _merge(_RETENTION_MEASUREMENT, _RETENTION_POLICY),
    {
        "SENSOR": "The availability module acquires no observations: it imports only hashlib, dataclasses, enum, and typing (layer4/availability.py:30-33), contains no open, socket, urllib, subprocess, or fetch call, and takes byte content from its caller (layer4/availability.py:118).",
        "ASSET": "RetentionPolicy.custodian (layer4/availability.py:81-82) names the party committed to byte retrieval, and the module has no quantity, rights, denomination, issuance, redemption, backing, or monetary field.",
        "ROBOT": "layer4/availability.py contains no agent, harness, controller, actuator, or hardware term and imports only hashlib, dataclasses, enum, and typing (layer4/availability.py:30-33); no physical-effect path exists in this source.",
        "FINBOT": "layer4/availability.py contains no agent, money, payment, or exposure term; its assessment compares retrieved byte identity and availability level only (layer4/availability.py:163-185).",
        "MARKET": "ArtifactAvailability.assess (layer4/availability.py:163-185) and assess_bundle (layer4/availability.py:237) compare retrieved bytes with declared retention terms; the owned declarations (layer4/availability.py:75-237) carry no order, quote, counterparty, price, or settlement term.",
    },
)


_REVIEWS = dict(
    sorted(
        {
            "vstd-amd-live-sensor": _AMD,
            "vstd-anchor-history-ledger": _ANCHOR,
            "vstd-artifact-network-history": _NETWORK,
            "vstd-assurance-event-ledger": _ASSURANCE,
            "vstd-challenge-record-ledger": _CHALLENGE,
            "vstd-consent-policy": _CONSENT,
            "vstd-dataset-provenance-policy": _DATASET,
            "vstd-firmware-emulator-accounting": _EMULATOR,
            "vstd-governance-policy": _GOVERNANCE,
            "vstd-nvidia-live-sensor": _NVIDIA,
            "vstd-precommitment-ledger": _PRECOMMIT,
            "vstd-retention-policy": _RETENTION,
            "vstd-sim-resource-measurement": _RESOURCE,
        }.items()
    )
)

_STATIC_DEMOTIONS: dict[str, frozenset[str]] = {
    "vstd-amd-live-sensor": frozenset({"ACTUATOR", "CONTROLLER", "FINBOT", "MARKET", "ROBOT", "TRANSACTION"}),
    "vstd-anchor-history-ledger": frozenset({"ASSET", "FINBOT", "MARKET", "ROBOT"}),
    "vstd-artifact-network-history": frozenset({"ASSET", "MARKET"}),
    "vstd-assurance-event-ledger": frozenset({"ASSET", "FINBOT", "MARKET", "ROBOT"}),
    "vstd-challenge-record-ledger": frozenset({"ASSET", "FINBOT", "MARKET", "ROBOT"}),
    "vstd-consent-policy": frozenset({"FINBOT", "MARKET", "ROBOT"}),
    "vstd-dataset-provenance-policy": frozenset({"MARKET"}),
    "vstd-firmware-emulator-accounting": frozenset({"ASSET", "FINBOT", "MARKET", "ROBOT", "SENSOR"}),
    "vstd-governance-policy": frozenset({"FINBOT", "MARKET", "ROBOT"}),
    "vstd-nvidia-live-sensor": frozenset({"ACTUATOR", "CONTROLLER", "FINBOT", "MARKET", "ROBOT", "TRANSACTION"}),
    "vstd-precommitment-ledger": frozenset({"ASSET", "FINBOT", "MARKET", "ROBOT"}),
    "vstd-retention-policy": frozenset({"ASSET", "FINBOT", "MARKET", "ROBOT", "SENSOR"}),
    "vstd-sim-resource-measurement": frozenset({"MARKET"}),
}
_REVIEWS = {
    object_id: replace(review, demoted=_STATIC_DEMOTIONS[object_id])
    for object_id, review in _REVIEWS.items()
}


def _catalog_check() -> None:
    registry = namespace_registry()
    specs = {spec.object_id: spec for spec in SEMANTIC_OWNERSHIP_SPECS}
    if tuple(_REVIEWS) != RECORD_OBJECT_IDS:
        raise AssertionError("record review object denominator differs")
    if any(kind not in registry for kind in REVIEW_KINDS):
        raise AssertionError("record review kind missing from live namespace registry")
    owned: dict[str, str] = {}
    refuted_cells: dict[str, str] = {}
    for object_id, review in _REVIEWS.items():
        spec = specs.get(object_id)
        if spec is None:
            raise AssertionError(object_id + " missing from semantic ownership catalog")
        if (
            review.primary_kind != spec.primary_kind
            or review.owned_paths != spec.owned_paths
        ):
            raise AssertionError(object_id + " ownership or primary-kind drift")
        required_roles = {spec.primary_kind, *spec.specializations}
        if not required_roles <= set(review.applicable):
            raise AssertionError(
                object_id + " dropped an owned primary/specialized role"
            )
        if set(review.reasons) != set(review.applicable) or not set(
            review.refuted
        ) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " decision denominator differs")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " both applies and is refuted")
        if not set(review.demoted) <= set(review.refuted):
            raise AssertionError(object_id + " withholds a kind it does not refute")
        if any(
            not reason.strip()
            for reason in (*review.reasons.values(), *review.refuted.values())
        ):
            raise AssertionError(object_id + " contains a blank decision reason")
        for kind, reason in review.refuted.items():
            cell = object_id + ":" + kind
            if refuted_cells.setdefault(reason, cell) != cell:
                raise AssertionError(
                    "refutation reason is shared by "
                    + refuted_cells[reason]
                    + " and "
                    + cell
                )
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


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return the deterministic, human-inspectable thirteen-object review."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: _classification_document(review, kind) for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(review.declarations),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for object_id, review in _REVIEWS.items()
    }


_BOUNDARY_SUFFIX = (
    " This source-bound Tier-0 declaration states the boundary; "
    "mechanism truth and Tier-1-plus fulfillment remain unestablished."
)


def _basis(review: _Review, kind: str) -> str:
    """Return the only decided status for one kind: literal catalog or UNRESOLVED.

    Absence from both literal catalogs is UNRESOLVED, never DOES_NOT_APPLY.
    """
    if kind in review.applicable:
        return "APPLIES"
    if kind in review.refuted and kind not in review.demoted:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _classification_document(review: _Review, kind: str) -> dict[str, Any]:
    basis = _basis(review, kind)
    if basis == "UNRESOLVED":
        return {
            "status": basis,
            "reason": _shared._unresolved_reason(kind),
            "evidence_paths": [],
        }
    reason = review.reasons[kind] if basis == "APPLIES" else review.refuted[kind]
    return {
        "status": basis,
        "reason": reason,
        "evidence_paths": list(review.owned_paths),
    }


def _expected_decision(
    review: _Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
) -> dict[str, Any]:
    """Return the canonical row decision for one explicitly catalogued kind."""
    basis = _basis(review, kind)
    if basis == "UNRESOLVED":
        raise AssertionError("explicit decision requested for unlisted " + kind)
    reason = review.reasons[kind] if basis == "APPLIES" else review.refuted[kind]
    return {
        "status": basis,
        "reason": reason,
        "evidence": [deepcopy(evidence_by_path[path]) for path in review.owned_paths],
    }


def _owned_file_paths(row: Mapping[str, Any]) -> set[str]:
    surfaces = row.get("surfaces")
    if type(surfaces) is not list or any(
        type(surface) is not str for surface in surfaces
    ):
        raise ValueError("PACKAGE_SEMANTIC_RECORD_REVIEW_SURFACES_INVALID")
    paths = [
        surface.removeprefix("file:")
        for surface in surfaces
        if surface.startswith("file:")
    ]
    # Duplicate or empty file surfaces make the owned denominator ambiguous; the
    # subject module rejects them too, so both review families fail identically.
    if any(not path for path in paths) or len(paths) != len(set(paths)):
        raise ValueError("PACKAGE_SEMANTIC_RECORD_REVIEW_SURFACES_INVALID")
    return set(paths)


_LAZY_LOADER = "src/verifier/__init__.py"
_LAZY_LOADER_FUNCTIONS = frozenset({"__dir__", "__getattr__"})
_STDLIB_MODULES = frozenset(sys.stdlib_module_names)
_LAUNCHERS = frozenset(
    {
        "_posixsubprocess.fork_exec",
        "_winapi.CreateProcess",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "os.fork",
        "os.forkpty",
        "os.kill",
        "os.popen",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.startfile",
        "os.system",
        "pty.spawn",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "subprocess.run",
        "webbrowser.get",
        "webbrowser.open",
        "webbrowser.open_new",
        "webbrowser.open_new_tab",
    }
)
_LAUNCHER_PREFIXES = (
    "concurrent.futures.process.",
    "concurrent.futures.ProcessPoolExecutor",
    "multiprocessing.",
    "os.exec",
    "os.spawn",
)
_NETWORK_PREFIXES = (
    "aiohttp.",
    "asyncio.create_connection",
    "asyncio.create_datagram_endpoint",
    "asyncio.create_server",
    "asyncio.open_connection",
    "asyncio.open_unix_connection",
    "asyncio.start_server",
    "asyncio.start_unix_server",
    "ftplib.",
    "http.client.",
    "http.server.",
    "httpx.",
    "imaplib.",
    "nntplib.",
    "poplib.",
    "requests.",
    "smtplib.",
    "socket.",
    "socketserver.",
    "ssl.",
    "telnetlib.",
    "urllib.request.",
    "websocket.",
    "wsgiref.",
    "xmlrpc.client.",
    "xmlrpc.server.",
)
_FFI_NAMES = frozenset({"ctypes.CDLL", "ctypes.OleDLL", "ctypes.PyDLL", "ctypes.WinDLL"})
_FFI_PREFIXES = ("ctypes.cdll.", "ctypes.oledll.", "ctypes.pydll.", "ctypes.windll.")
_DEVICE_PREFIXES = ("RPi.", "gpiozero.", "periphery.", "serial.", "smbus", "usb.")
_DYNAMIC_CALLS = frozenset(
    {
        "__import__",
        "compile",
        "eval",
        "exec",
        "importlib.__import__",
        "importlib.import_module",
        "importlib.util.module_from_spec",
        "importlib.util.spec_from_file_location",
        "marshal.load",
        "marshal.loads",
        "pickle.load",
        "pickle.loads",
        "runpy.run_module",
        "runpy.run_path",
        "shelve.open",
    }
)
_DYNAMIC_PREFIXES = ("importlib.machinery.",)
# Reflection resolves names chosen at run time, so it can reach any launcher or
# writer above.  It is an open site rather than a lexical miss.
_REFLECTION_CALLS = frozenset(
    {"delattr", "getattr", "globals", "locals", "setattr", "vars"}
)
# Filesystem and database writes change state.  They block only the state kinds
# (LEDGER, TRANSACTION): a write does not by itself establish an effect-kind role.
_STATE_KINDS = frozenset({"LEDGER", "TRANSACTION"})
_WRITE_FUNCTIONS = frozenset(
    {
        "codecs.open",
        "io.open",
        "json.dump",
        "marshal.dump",
        "open",
        "os.chmod",
        "os.chown",
        "os.fdopen",
        "os.fsync",
        "os.ftruncate",
        "os.lchmod",
        "os.link",
        "os.makedirs",
        "os.mkdir",
        "os.open",
        "os.remove",
        "os.removedirs",
        "os.rename",
        "os.renames",
        "os.replace",
        "os.rmdir",
        "os.symlink",
        "os.truncate",
        "os.unlink",
        "os.utime",
        "os.write",
        "pickle.dump",
        "sqlite3.connect",
    }
)
_WRITE_PREFIXES = ("shutil.", "tempfile.")
# shutil lookups and queries read state only; every other shutil call may write.
_READ_ONLY_SHUTIL = frozenset(
    {
        "shutil.disk_usage",
        "shutil.get_archive_formats",
        "shutil.get_terminal_size",
        "shutil.get_unpack_formats",
        "shutil.which",
    }
)
# Method names that are unambiguous writers on any receiver.  str.replace, list.remove,
# and similar common names are deliberately absent; their receiver type is not known
# to this syntactic screen, so Path.replace and friends are a residual gap.
_WRITE_METHODS = frozenset(
    {
        "chmod",
        "copy2",
        "copyfile",
        "copytree",
        "dump",
        "flush",
        "fsync",
        "hardlink_to",
        "makedirs",
        "mkdir",
        "mkdtemp",
        "mkstemp",
        "move",
        "NamedTemporaryFile",
        "rename",
        "rmdir",
        "rmtree",
        "SpooledTemporaryFile",
        "symlink_to",
        "TemporaryDirectory",
        "TemporaryFile",
        "touch",
        "truncate",
        "unlink",
        "write",
        "write_bytes",
        "write_text",
        "writelines",
    }
)
_WRITE_MODE_CHARS = frozenset("wax+")
_PRIVATE_CALLABLE_NAMES = frozenset({"cls", "self"})
# Identifier vocabulary is a review trigger, read from code identifiers only
# (never strings or comments); a hit blocks only its own kind.
_VOCABULARY = {
    "ACTUATOR": frozenset({"actuate", "actuator", "actuators", "gpio", "motor", "motors", "servo"}),
    "ASSET": frozenset({"custody", "holder", "holders", "ownership", "quantities", "quantity", "redeem", "redemption"}),
    "CONTROLLER": frozenset({"feedback", "setpoint"}),
    "FINBOT": frozenset({
        "balance", "balances", "billing", "cash", "currencies", "currency", "deposit", "deposits",
        "eur", "exposure", "funds", "invoice", "invoices", "money", "pay", "payee", "payer",
        "payment", "payments", "payout", "payouts", "usd", "wallet", "withdraw", "withdrawal",
    }),
    "MARKET": frozenset({
        "ask", "asks", "bid", "bids", "broker", "brokerage", "buy", "counterparty", "counterparties",
        "market", "markets", "price", "prices", "quote", "quotes", "sell", "settle", "settlement",
        "trade", "trades", "trading",
    }),
    "PROTOCOL": frozenset({"handshake", "recv", "recvfrom", "sendall", "socket", "sockets", "urlopen"}),
    "ROBOT": frozenset({
        "actuate", "actuator", "actuators", "agent", "agents", "autonomous", "drone", "gpio",
        "harness", "motor", "motors", "robot", "robotic", "robots", "servo",
    }),
    "SENSOR": frozenset({"probe", "probes", "sensor", "sensors"}),
}
_ORDER_TOKENS = frozenset({"order", "orders"})
_ORDER_CONTEXT = frozenset({"book", "buy", "cancel", "fill", "limit", "market", "place", "sell", "submit"})
_TOKEN_PATTERN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


@dataclass(frozen=True)
class SurfaceScreen:
    """Source-bound closed-surface screen for one owned object.

    CLOSED means every import-time and function-level project import was followed
    (TYPE_CHECKING excluded, package __init__ files included) and no open effect
    site, injected callable, external dependency, lazy-export escape, or unreadable
    source was found.  Vocabulary hits block only their own kind.  Nothing here
    infers a semantic kind.
    """

    status: str
    closure: tuple[tuple[str, str], ...]
    open_sites: tuple[tuple[str, int, str, str], ...]
    write_sites: tuple[tuple[str, int, str, str], ...]
    enumerated_sites: tuple[tuple[str, int, str, str], ...]
    vocabulary_hits: tuple[tuple[str, str, str, int], ...]
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class _Facts:
    imports: tuple[tuple[int, str, tuple[str, ...], int], ...]
    refs: tuple[tuple[str, int], ...]
    idents: tuple[tuple[str, int], ...]
    open_sites: tuple[tuple[int, str, str], ...]
    write_sites: tuple[tuple[int, str, str], ...]
    enumerated_sites: tuple[tuple[int, str, str], ...]


_FACT_CACHE: dict[tuple[str, str], _Facts] = {}


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _is_type_checking(test: ast.AST) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _fixed_argv(call: ast.Call, which_names: frozenset[str]) -> bool:
    """Literal argv tail; head is a literal program or a shutil.which(<literal>) binding."""
    if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)) or not call.args[0].elts:
        return False
    head, *tail = call.args[0].elts
    head_fixed = (isinstance(head, ast.Name) and head.id in which_names) or (
        isinstance(head, ast.Constant) and type(head.value) is str
    )
    return head_fixed and all(
        isinstance(item, ast.Constant) and type(item.value) is str for item in tail
    )


def _shell_enabled(call: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False)
        for keyword in call.keywords
    )


def _writes_mode(call: ast.Call, position: int) -> bool:
    """Return True unless the call's open mode is a constant without a write flag."""
    mode: ast.AST | None = None
    if len(call.args) > position:
        mode = call.args[position]
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if mode is None:
        return False
    if isinstance(mode, ast.Constant) and type(mode.value) is str:
        return bool(_WRITE_MODE_CHARS & set(mode.value))
    return True


def _classify_call(
    resolved: str, call: ast.Call, rel: str, function: str, which_names: frozenset[str]
) -> tuple[str, str] | None:
    """Return (bucket, site class) for one resolved call, else None.

    Buckets: "open" blocks every DOES_NOT_APPLY; "write" blocks state kinds only;
    "enumerated" is a bounded site that blocks nothing.  Fixed-argument process
    launches are open: a launched process is an effect whatever its argv.
    """
    lazy_loader = rel == _LAZY_LOADER and function in _LAZY_LOADER_FUNCTIONS
    if resolved in _DYNAMIC_CALLS or resolved.startswith(_DYNAMIC_PREFIXES):
        if resolved == "importlib.import_module" and lazy_loader:
            return ("enumerated", "bounded_lazy_loader")
        return ("open", "dynamic_code")
    if resolved in _REFLECTION_CALLS:
        # The package lazy loader reflects only over its own finite export table.
        return ("enumerated", "bounded_lazy_loader") if lazy_loader else ("open", "reflection")
    if resolved in _LAUNCHERS or resolved.startswith(_LAUNCHER_PREFIXES):
        fixed = resolved.startswith(("subprocess.", "asyncio.")) and _fixed_argv(call, which_names) and not _shell_enabled(call)
        return ("open", "fixed_process_argv" if fixed else "unfixed_process")
    if resolved in _FFI_NAMES or resolved.startswith(_FFI_PREFIXES):
        return ("open", "native_ffi")
    if resolved.startswith(_NETWORK_PREFIXES):
        return ("open", "network")
    if resolved.startswith(_DEVICE_PREFIXES):
        return ("open", "device")
    if resolved in {"open", "io.open", "codecs.open", "os.fdopen"}:
        return ("write", "filesystem_write") if _writes_mode(call, 1) else None
    if resolved in _READ_ONLY_SHUTIL:
        return None
    if resolved in _WRITE_FUNCTIONS or resolved.startswith(_WRITE_PREFIXES):
        return ("write", "filesystem_write")
    last = resolved.rpartition(".")[2]
    if last == "open" and "." in resolved:
        # pathlib-style method open: the mode is the first positional argument.
        return ("write", "filesystem_write") if _writes_mode(call, 0) else None
    if last in _WRITE_METHODS:
        return ("write", "filesystem_write")
    return None


def _scan(rel: str, raw: bytes) -> _Facts:
    tree = ast.parse(raw, filename=rel)
    aliases: dict[str, str] = {}
    which_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    aliases[head] = head
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                aliases[alias.asname or alias.name] = node.module + "." + alias.name
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            which = _dotted(node.value.func)
            if (
                which is not None
                and which.partition(".")[2] == "which"
                and node.value.args
                and isinstance(node.value.args[0], ast.Constant)
                and type(node.value.args[0].value) is str
            ):
                which_names.update(t.id for t in node.targets if isinstance(t, ast.Name))

    def resolve(dotted: str) -> str:
        head, _, rest = dotted.partition(".")
        if head in aliases:
            return aliases[head] + ("." + rest if rest else "")
        return dotted

    # A caller-supplied callable stored on self and later invoked is an injected
    # callable too; collect the attribute names before visiting any call site.
    stored_callables: set[str] = set()
    for function_node in ast.walk(tree):
        if not isinstance(function_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parameters = {arg.arg for arg in function_node.args.args} - _PRIVATE_CALLABLE_NAMES
        for assignment in ast.walk(function_node):
            if (
                isinstance(assignment, ast.Assign)
                and isinstance(assignment.value, ast.Name)
                and assignment.value.id in parameters
            ):
                for target in assignment.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                    ):
                        stored_callables.add(target.attr)

    imports: list[tuple[int, str, tuple[str, ...], int]] = []
    refs: list[tuple[str, int]] = []
    idents: list[tuple[str, int]] = []
    open_sites: list[tuple[int, str, str]] = []
    writes: list[tuple[int, str, str]] = []
    enumerated: list[tuple[int, str, str]] = []

    def visit(node: ast.AST, params: frozenset[str], function: str) -> None:
        if isinstance(node, ast.If) and _is_type_checking(node.test):
            for child in node.orelse:
                visit(child, params, function)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                idents.append((node.name, node.lineno))
            arguments = node.args
            names = {arg.arg for arg in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)}
            if arguments.vararg:
                names.add(arguments.vararg.arg)
            if arguments.kwarg:
                names.add(arguments.kwarg.arg)
            inner = function if isinstance(node, ast.Lambda) else node.name
            for child in ast.iter_child_nodes(node):
                visit(child, params | frozenset(names), inner)
            return
        if isinstance(node, ast.ClassDef):
            idents.append((node.name, node.lineno))
        elif isinstance(node, ast.Name):
            idents.append((node.id, node.lineno))
        elif isinstance(node, ast.Attribute):
            idents.append((node.attr, node.lineno))
            if isinstance(node.value, ast.Name) and node.value.id == "verifier":
                refs.append((node.attr, node.lineno))
        elif isinstance(node, ast.arg):
            idents.append((node.arg, node.lineno))
        elif isinstance(node, ast.Import):
            imports.extend((0, alias.name, (), node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append((node.level, node.module or "", tuple(a.name for a in node.names), node.lineno))
            if node.level == 0 and node.module == "verifier":
                refs.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            if dotted is not None:
                resolved = resolve(dotted)
            elif isinstance(node.func, ast.Attribute):
                # A method on an expression receiver, such as Path(p).write_text, has no
                # dotted name; its method name still decides the write and open rules.
                resolved = "<expr>." + node.func.attr
            else:
                resolved = None
            if resolved is not None:
                verdict = _classify_call(resolved, node, rel, function, frozenset(which_names))
                if verdict is not None:
                    bucket = {"open": open_sites, "write": writes}.get(verdict[0], enumerated)
                    bucket.append((node.lineno, verdict[1], resolved))
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "print"
                and any(keyword.arg == "file" for keyword in node.keywords)
            ):
                writes.append((node.lineno, "filesystem_write", "print(file=)"))
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in params
                and node.func.id not in _PRIVATE_CALLABLE_NAMES
            ):
                open_sites.append((node.lineno, "injected_callable", node.func.id))
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self"
                and node.func.attr in stored_callables
            ):
                open_sites.append((node.lineno, "injected_callable", "self." + node.func.attr))
        for child in ast.iter_child_nodes(node):
            visit(child, params, function)

    for statement in tree.body:
        visit(statement, frozenset(), "<module>")
    return _Facts(
        imports=tuple(imports),
        refs=tuple(refs),
        idents=tuple(idents),
        open_sites=tuple(open_sites),
        write_sites=tuple(writes),
        enumerated_sites=tuple(enumerated),
    )


def _facts(rel: str, raw: bytes) -> _Facts:
    key = (rel, _digest(raw))
    if key not in _FACT_CACHE:
        _FACT_CACHE[key] = _scan(rel, raw)
    return _FACT_CACHE[key]


def _read_in_root(root: Path, rel: str) -> bytes:
    candidate = root.joinpath(*rel.split("/"))
    if candidate.is_symlink():
        raise OSError("symlinked source is not followed: " + rel)
    target = candidate.resolve(strict=True)
    if not target.is_relative_to(root) or not target.is_file():
        raise OSError("source is not an in-root ordinary file: " + rel)
    return target.read_bytes()


def _module_rel(root: Path, dotted: str) -> str | None:
    base = root.joinpath("src", *dotted.split("."))
    for candidate in (base.with_name(base.name + ".py"), base / "__init__.py"):
        if candidate.is_file():
            return candidate.relative_to(root).as_posix()
    return None


def _package_dir(root: Path, dotted: str) -> bool:
    return root.joinpath("src", *dotted.split(".")).is_dir()


def _init_rels(root: Path, dotted: str) -> list[str]:
    parts = dotted.split(".")
    found = []
    for index in range(1, len(parts)):
        candidate = root.joinpath("src", *parts[:index], "__init__.py")
        if candidate.is_file():
            found.append(candidate.relative_to(root).as_posix())
    return found


def _dotted_of_rel(rel: str) -> str | None:
    if not rel.startswith("src/") or not rel.endswith(".py"):
        return None
    parts = rel[len("src/"):-len(".py")].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _relative_target(rel: str, level: int, module: str) -> str | None:
    package = rel[len("src/"):-len(".py")].split("/")[:-1]
    if level > len(package) + 1:
        return None
    base = package[: len(package) - (level - 1)]
    parts = base + ([module] if module else [])
    return ".".join(parts) if parts else None


def _lazy_export_names(root: Path) -> frozenset[str]:
    try:
        tree = ast.parse(_read_in_root(root, _LAZY_LOADER))
    except (OSError, SyntaxError):
        return frozenset()
    for statement in tree.body:
        if (
            isinstance(statement, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_LAZY_EXPORTS" for t in statement.targets)
            and isinstance(statement.value, ast.Dict)
        ):
            return frozenset(
                key.value
                for key in statement.value.keys
                if isinstance(key, ast.Constant) and type(key.value) is str
            )
    return frozenset()


@lru_cache(maxsize=65536)
def _tokens(identifier: str) -> frozenset[str]:
    found: set[str] = set()
    for part in re.split(r"[_\W]+", identifier):
        found.update(match.lower() for match in _TOKEN_PATTERN.findall(part))
    return frozenset(found)


@lru_cache(maxsize=65536)
def _vocabulary_kinds(identifier: str) -> frozenset[str]:
    """Return exact review-trigger kinds for an identifier, independent of source state."""
    tokens = _tokens(identifier)
    found = {kind for kind, terms in _VOCABULARY.items() if tokens & terms}
    if tokens & _ORDER_TOKENS and tokens & _ORDER_CONTEXT:
        found.add("MARKET")
    return frozenset(found)


def closed_surface_screen(root: str | Path, owned_paths: Iterable[str]) -> SurfaceScreen:
    """Screen the conservative import closure of owned_paths against current bytes."""
    selected = Path(root).resolve(strict=True)
    lazy = _lazy_export_names(selected)
    blockers: set[str] = set()
    queue: deque[str] = deque()
    queued: set[str] = set()
    closure: dict[str, str | None] = {}
    open_sites: set[tuple[str, int, str, str]] = set()
    write_sites: set[tuple[str, int, str, str]] = set()
    enumerated: set[tuple[str, int, str, str]] = set()
    vocabulary: dict[tuple[str, str, str], int] = {}

    def push(rel: str) -> None:
        if rel not in queued:
            queued.add(rel)
            queue.append(rel)

    for path in owned_paths:
        if path.endswith(".json"):
            push(path)
            continue
        if not path.endswith(".py"):
            blockers.add("UNSUPPORTED_LANGUAGE:" + path)
            continue
        push(path)
        dotted = _dotted_of_rel(path)
        for init in _init_rels(selected, dotted) if dotted else []:
            push(init)

    while queue:
        rel = queue.popleft()
        try:
            raw = _read_in_root(selected, rel)
        except OSError:
            blockers.add("SOURCE_UNAVAILABLE:" + rel)
            closure[rel] = None
            continue
        closure[rel] = _digest(raw)
        if not rel.endswith(".py"):
            continue
        try:
            facts = _facts(rel, raw)
        except SyntaxError:
            blockers.add("PYTHON_SYNTAX_ERROR:" + rel)
            continue
        open_sites.update((rel, line, klass, target) for line, klass, target in facts.open_sites)
        write_sites.update((rel, line, klass, target) for line, klass, target in facts.write_sites)
        enumerated.update((rel, line, klass, target) for line, klass, target in facts.enumerated_sites)
        for level, module, names, line in facts.imports:
            target_name = _relative_target(rel, level, module) if level else module
            if not target_name:
                blockers.add("IMPORT_ESCAPES_ROOT:" + rel + ":" + str(line))
                continue
            if target_name.split(".")[0] != "verifier":
                if target_name.split(".")[0] not in _STDLIB_MODULES:
                    open_sites.add((rel, line, "external_dependency", target_name))
                continue
            target_module = _module_rel(selected, target_name)
            if target_module is None and not _package_dir(selected, target_name):
                # Neither a .py module, a package, nor a namespace directory: a compiled
                # extension or a missing file cannot be silently treated as closed.
                blockers.add("UNRESOLVED_PROJECT_IMPORT:" + rel + ":" + str(line))
                continue
            if target_module:
                push(target_module)
            for init in _init_rels(selected, target_name):
                push(init)
            for name in names:
                if name == "*":
                    continue
                candidate = target_name + "." + name
                found = _module_rel(selected, candidate)
                if found:
                    push(found)
                    for init in _init_rels(selected, candidate):
                        push(init)
                elif target_module is None and not _package_dir(selected, candidate):
                    # A namespace package has no __init__ attributes, so every imported
                    # name there must be a module or directory that the screen can read.
                    blockers.add("UNRESOLVED_PROJECT_IMPORT:" + rel + ":" + str(line))
        for name, line in facts.refs:
            if name in lazy:
                open_sites.add((rel, line, "lazy_export_escape", name))
        for identifier, line in facts.idents:
            for kind in _vocabulary_kinds(identifier):
                vocabulary.setdefault((kind, rel, identifier), line)

    return SurfaceScreen(
        status="OPEN" if open_sites or blockers else "CLOSED",
        closure=tuple(sorted((rel, digest) for rel, digest in closure.items() if digest)),
        open_sites=tuple(sorted(open_sites)),
        write_sites=tuple(sorted(write_sites)),
        enumerated_sites=tuple(sorted(enumerated)),
        vocabulary_hits=tuple(
            sorted((kind, rel, identifier, line) for (kind, rel, identifier), line in vocabulary.items())
        ),
        blockers=tuple(sorted(blockers)),
    )


def screen_blocks(screen: SurfaceScreen, kind: str) -> bool:
    """Return True when the live screen withholds a DOES_NOT_APPLY for this kind.

    Every kind needs a CLOSED screen: an open effect site, unresolved import, or
    unreadable source keeps any refutation UNRESOLVED.  State kinds are also blocked
    by any filesystem write in the closure, and effect kinds by a vocabulary hit.
    """
    if screen.status != "CLOSED":
        return True
    if kind in _STATE_KINDS and screen.write_sites:
        return True
    if kind in EXTERNAL_EFFECT_KINDS:
        return any(hit[0] == kind for hit in screen.vocabulary_hits)
    return False


def _source_snapshot(
    root: Path,
    paths: tuple[str, ...],
    *,
    object_id: str,
) -> list[dict[str, str]]:
    """Digest exact in-root ordinary files; symlinks and escapes are unavailable."""
    evidence: list[dict[str, str]] = []
    for path in paths:
        try:
            candidate = root.joinpath(*path.split("/"))
            target = candidate.resolve(strict=True)
            if (
                candidate.is_symlink()
                or not target.is_relative_to(root)
                or not target.is_file()
            ):
                raise OSError("owned source is not an in-root ordinary file")
            digest = _digest(target.read_bytes())
        except (OSError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_UNAVAILABLE:"
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
                "PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_DIFFERS:"
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
    code: str,
) -> None:
    if type(evidence) is not list or not evidence:
        raise ValueError(code)
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


def _unresolved_candidate(
    decision: Any,
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    kind: str,
) -> bool:
    """Return True for an absent or unreviewed UNRESOLVED template.

    An UNRESOLVED row may keep evidence only with the canonical migration reason
    and only for current owned bytes.  Any other status is not a template.
    """
    code = "PACKAGE_SEMANTIC_RECORD_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
    if decision is None:
        return True
    if type(decision) is not dict or decision.get("status") != "UNRESOLVED":
        return False
    if (
        set(decision) != {"status", "reason", "evidence"}
        or type(decision["reason"]) is not str
        or not decision["reason"].strip()
        or type(decision["evidence"]) is not list
    ):
        raise ValueError(code)
    if decision["evidence"]:
        if decision["reason"] != _shared._unresolved_reason(kind):
            raise ValueError(code)
        _validate_evidence(decision["evidence"], files, owned, code=code)
    return True


def _preserve_exact(
    decision: Any,
    expected: Mapping[str, Any],
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    kind: str,
) -> bool:
    """Keep a decided row only when it equals its literal basis exactly.

    Same-status reason rewrites, evidence substitution, and status flips are
    rejected rather than erased.  An absent or validated UNRESOLVED template is
    replaced by the literal basis, so the function returns False for a fill.
    """
    if _unresolved_candidate(decision, files, owned, object_id=object_id, kind=kind):
        return False
    if decision != expected:
        raise ValueError(
            "PACKAGE_SEMANTIC_RECORD_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
        )
    return True


def _blank_binding(
    binding: Any,
    fields: tuple[str, ...],
    files: Mapping[str, str],
    owned: set[str],
    *,
    code: str,
) -> bool:
    """Return True for an absent or wholly unanswered declaration candidate."""
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
        and set(declaration) == set(fields)
        and all(value == "" for value in declaration.values())
    )
    if blank and binding["evidence"]:
        _validate_evidence(binding["evidence"], files, owned, code=code)
    return blank


def _preserve_obligation(
    binding: Any,
    fields: tuple[str, ...],
    expected_reason: str,
    expected_evidence: list[dict[str, str]],
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    obligation_id: str,
) -> bool:
    """Keep a complete declaration only when its reason and evidence are exact.

    The declaration text is reviewed content and may differ, but it must name
    exactly the declared fields with nonblank values.
    """
    code = (
        "PACKAGE_SEMANTIC_RECORD_REVIEW_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id
    )
    if _blank_binding(binding, fields, files, owned, code=code):
        return False
    declaration = binding["declaration"]
    if (
        binding["reason"] != expected_reason
        or binding["evidence"] != expected_evidence
        or type(declaration) is not dict
        or set(declaration) != set(fields)
        or any(
            type(value) is not str or not value.strip() for value in declaration.values()
        )
    ):
        raise ValueError(code)
    return True


def _screened_review(review: _Review, screen: SurfaceScreen) -> _Review:
    """Withhold every external DOES_NOT_APPLY that the live screen cannot close."""
    withheld = {kind for kind in review.refuted if screen_blocks(screen, kind)}
    return replace(review, demoted=frozenset(review.demoted | withheld))


def _prior_refutation(
    decision: Any,
    kind: str,
    historic: _Review,
    evidence_by_path: Mapping[str, dict[str, str]],
    object_id: str,
) -> bool:
    """Accept only the exact historic refutation that the live screen now withholds.

    Any other DOES_NOT_APPLY row for a withheld kind is forged or stale and aborts.
    """
    if type(decision) is not dict or decision.get("status") != "DOES_NOT_APPLY":
        return False
    if kind not in historic.refuted:
        return False
    expected = {
        "status": "DOES_NOT_APPLY",
        "reason": historic.refuted[kind],
        "evidence": [deepcopy(evidence_by_path[path]) for path in historic.owned_paths],
    }
    if decision != expected:
        raise ValueError(
            "PACKAGE_SEMANTIC_RECORD_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
        )
    return True


def apply_package_semantic_review_records(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply the complete thirteen-object review to a deep copy, or change nothing.

    Every kind is APPLIES, DOES_NOT_APPLY, or UNRESOLVED.  APPLIES and
    DOES_NOT_APPLY come only from the literal per-object catalog and must match it
    exactly; any other kind is canonical UNRESOLVED.  A conventional unresolved
    template or wholly blank obligation candidate may be filled.  Exact canonical
    migration candidates may retain current owned evidence after reownership.
    Forged, unlisted, reason-substituted, or partially answered decisions abort.
    """
    selected_root = Path(root).resolve(strict=True)
    if type(rows) is not dict:
        raise ValueError("PACKAGE_SEMANTIC_RECORD_REVIEW_ROWS_INVALID")
    if type(files) is not dict or any(
        type(path) is not str or type(digest) is not str
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_SEMANTIC_RECORD_REVIEW_FILES_INVALID")

    known = {row["id"] for kind in REVIEW_KINDS for row in _requirements(kind)}
    plans: dict[str, dict[str, Any]] = {}
    for object_id, review in _REVIEWS.items():
        row = rows.get(object_id)
        if type(row) is not dict:
            raise ValueError(
                "PACKAGE_SEMANTIC_RECORD_REVIEW_OBJECT_MISSING:" + object_id
            )
        if row.get("object_id") != object_id or row.get("kind") != review.primary_kind:
            raise ValueError(
                "PACKAGE_SEMANTIC_RECORD_REVIEW_PRIMARY_KIND_DIFFERS:" + object_id
            )
        owned = _owned_file_paths(row)
        if owned != set(review.owned_paths):
            raise ValueError(
                "PACKAGE_SEMANTIC_RECORD_REVIEW_OWNERSHIP_DIFFERS:" + object_id
            )
        evidence = _current_evidence(
            selected_root,
            review.owned_paths,
            files,
            object_id=object_id,
        )
        evidence_by_path = {item["path"]: item for item in evidence}
        historic = review
        screen = closed_surface_screen(selected_root, review.owned_paths)
        review = _screened_review(review, screen)
        classification = row.get("classification")
        obligations = row.get("obligations")
        specializations = row.get("specializations")
        if type(classification) is not dict or type(obligations) is not dict:
            raise ValueError(
                "PACKAGE_SEMANTIC_RECORD_REVIEW_BINDINGS_INVALID:" + object_id
            )
        if type(specializations) is not list or any(
            type(kind) is not str for kind in specializations
        ):
            raise ValueError(
                "PACKAGE_SEMANTIC_RECORD_REVIEW_SPECIALIZATIONS_INVALID:" + object_id
            )

        for name in obligations:
            if type(name) is not str or (
                name.split("-", 1)[0] in REVIEW_KINDS and name not in known
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_RECORD_REVIEW_OBLIGATION_UNKNOWN:"
                    + object_id
                    + ":"
                    + str(name)
                )

        preserve_decisions: set[str] = set()
        unlisted_evidence: dict[str, list[dict[str, str]]] = {}
        preserve_obligations: set[str] = set()
        remove_obligations: set[str] = set()
        for kind in REVIEW_KINDS:
            basis = _basis(review, kind)
            if basis != "APPLIES" and (row["kind"] == kind or kind in specializations):
                raise ValueError(
                    "PACKAGE_SEMANTIC_RECORD_REVIEW_LABEL_CONFLICT:"
                    + object_id
                    + ":"
                    + kind
                )
            decision = classification.get(kind)
            if basis == "UNRESOLVED":
                if _prior_refutation(decision, kind, historic, evidence_by_path, object_id):
                    pass
                elif not _unresolved_candidate(
                    decision, files, owned, object_id=object_id, kind=kind
                ):
                    raise ValueError(
                        "PACKAGE_SEMANTIC_RECORD_REVIEW_DECISION_CONFLICT:"
                        + object_id
                        + ":"
                        + kind
                    )
                if (
                    decision is not None
                    and decision.get("status") == "UNRESOLVED"
                    and decision["evidence"]
                ):
                    unlisted_evidence[kind] = [
                        deepcopy(evidence_by_path[reference["path"]])
                        for reference in decision["evidence"]
                    ]
            elif _preserve_exact(
                decision,
                _expected_decision(review, kind, evidence_by_path),
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
                    if _preserve_obligation(
                        binding,
                        fields,
                        review.reasons[kind] + _BOUNDARY_SUFFIX,
                        [deepcopy(evidence_by_path[path]) for path in review.owned_paths],
                        files,
                        owned,
                        object_id=object_id,
                        obligation_id=obligation_id,
                    ):
                        preserve_obligations.add(obligation_id)
                elif binding is not None:
                    code = (
                        "PACKAGE_SEMANTIC_RECORD_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                        if basis == "DOES_NOT_APPLY"
                        else "PACKAGE_SEMANTIC_RECORD_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
                    ) + object_id + ":" + obligation_id
                    if not _blank_binding(binding, fields, files, owned, code=code):
                        raise ValueError(code)
                    remove_obligations.add(obligation_id)
        plans[object_id] = {
            "evidence_by_path": evidence_by_path,
            "review": review,
            "screen": screen,
            "preserve_decisions": preserve_decisions,
            "unlisted_evidence": unlisted_evidence,
            "preserve_obligations": preserve_obligations,
            "remove_obligations": remove_obligations,
        }

    # Conflict checking can be nontrivial. Re-read every owned byte before
    # constructing the copy so a concurrent edit cannot silently inherit the
    # opening census coordinate.
    for object_id, review in _REVIEWS.items():
        closing = _source_snapshot(
            selected_root, review.owned_paths, object_id=object_id
        )
        if {item["path"]: item for item in closing} != plans[object_id][
            "evidence_by_path"
        ]:
            raise ValueError(
                "PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_CHANGED:" + object_id
            )

    for object_id, review in _REVIEWS.items():
        if closed_surface_screen(selected_root, review.owned_paths) != plans[object_id]["screen"]:
            raise ValueError("PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_CHANGED:" + object_id)

    result = deepcopy(rows)
    for object_id in _REVIEWS:
        row = result[object_id]
        plan = plans[object_id]
        review = plan["review"]
        for kind in REVIEW_KINDS:
            if kind in plan["preserve_decisions"]:
                continue
            if _basis(review, kind) == "UNRESOLVED":
                row["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": _shared._unresolved_reason(kind),
                    "evidence": deepcopy(plan["unlisted_evidence"].get(kind, [])),
                }
            else:
                row["classification"][kind] = _expected_decision(
                    review, kind, plan["evidence_by_path"]
                )
        for obligation_id in plan["remove_obligations"]:
            row["obligations"].pop(obligation_id, None)
        for obligation_id, declaration in review.declarations.items():
            if obligation_id in plan["preserve_obligations"]:
                continue
            kind = obligation_id.split("-", 1)[0]
            row["obligations"][obligation_id] = {
                "reason": review.reasons[kind] + _BOUNDARY_SUFFIX,
                "evidence": [
                    deepcopy(plan["evidence_by_path"][path])
                    for path in review.owned_paths
                ],
                "declaration": dict(declaration),
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)

    # Return-time binding is checked after copy construction too. The caller
    # receives no generated current-byte claim if source drifted while we built it.
    for object_id, review in _REVIEWS.items():
        final = _source_snapshot(selected_root, review.owned_paths, object_id=object_id)
        if {item["path"]: item for item in final} != plans[object_id][
            "evidence_by_path"
        ]:
            raise ValueError(
                "PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_CHANGED:" + object_id
            )
    for object_id, review in _REVIEWS.items():
        if closed_surface_screen(selected_root, review.owned_paths) != plans[object_id]["screen"]:
            raise ValueError("PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_CHANGED:" + object_id)
    return result
