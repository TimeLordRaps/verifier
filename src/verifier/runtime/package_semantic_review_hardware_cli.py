"""Tier-0 source review for five hardware command-line interface (CLI) owners.

Terminology: Advanced Micro Devices (AMD); application programming interface
(API); abstract syntax tree (AST); hash-based message authentication code
(HMAC); International Organization for Standardization (ISO); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).

The review classifies exact current source for the public Verifier Standard
(VSTD) 3 command facade, installed-profile reader, discovery command, virtual
probe harness, and stored-receipt assessor. The discovery command retains all
twelve added roles because its caller-selected adapter can delegate through a
PATH-resolved vendor executable whose downstream effect envelope is not
established closed. It records every applicable declaration without treating
source review as mechanism execution, hardware truth, physical attestation,
sandboxing, financial effect, external authority, release, or higher-tier
conformance.

Application is pure, atomic, idempotent, and fail closed.  Every owned source
is recaptured before and after semantic preflight, and compatible current
bindings are preserved byte for byte.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


REVIEW_KINDS = _shared.REVIEW_KINDS

HARDWARE_CLI_OBJECT_IDS = (
    "vstd-hardware-cli-protocol",
    "vstd-accelerator-profile-reader",
    "vstd-accelerator-discovery-command",
    "vstd-virtual-firmware-probe-harness",
    "vstd-hardware-receipt-assessor",
)

CLAIM_BOUNDARY = (
    "Current-source Tier-0 applicability and declaration review for five exact "
    "hardware CLI owners only. No review executes a command or establishes "
    "hardware truth, physical attestation, sandboxing, financial effect, external "
    "authority, publication, release, deployment, or Tier-1-plus conformance."
)


@dataclass(frozen=True)
class _Review:
    """One owner's audited catalog.

    ``refutations`` maps each refuted kind to its own object-specific, source-cited
    incompatibility.  It is never derived as the complement of ``applicable``: a kind
    with neither an application nor a refutation is UNRESOLVED.
    """

    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    profile: _shared._Profile
    refutations: Mapping[str, str]
    reach: Mapping[str, str]


def _unresolved_reason(kind: str) -> str:
    """Return the canonical answer when this review has no explicit basis."""
    return (
        "Migration retains this applicability question. Static ownership "
        "alone cannot refute a " + kind + " role."
    )


def _basis(review: _Review, kind: str, closure: "_Closure | None" = None) -> str:
    """Select a literal application, or a refutation whose closure witness holds.

    A refutation is only a candidate.  It becomes DOES_NOT_APPLY when the owner's
    source-bound execution closure is CLOSED and reaches none of the effects the
    refuted role forbids.  Without a closure, a refutation stays UNRESOLVED.
    """
    if kind in review.applicable:
        return "APPLIES"
    if kind in review.refutations and closure is not None and _dne_allowed(kind, closure):
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _profile(
    *,
    name: str,
    scope: str,
    mechanism: str,
    participants: str,
    inputs: str,
    authority: str,
    states: str,
    ordering: str,
    commands: str,
    targets: str,
    effect_domains: str,
    effects: str,
    commit: str,
    retry: str,
    timing: str,
    limits: str,
    observations: str,
    units: str,
    failure: str,
    recovery: str,
    boundary: str,
) -> _shared._Profile:
    return _shared._Profile(
        name=name,
        scope=scope,
        mechanism=mechanism,
        participants=participants,
        inputs=inputs,
        authority=authority,
        states=states,
        ordering=ordering,
        commands=commands,
        targets=targets,
        effect_domains=effect_domains,
        effects=effects,
        commit=commit,
        retry=retry,
        timing=timing,
        limits=limits,
        observations=observations,
        units=units,
        failure=failure,
        recovery=recovery,
        boundary=boundary,
    )


_CLI_PROTOCOL = _profile(
    name="The VSTD 3 hardware CLI protocol facade",
    scope="Parse the stable VSTD 3 command families, decode bounded caller values, dispatch one selected in-process command mechanism, frame its output, and map status to an exit code.",
    mechanism="Argparse grammar and fixed dispatch tables select installed handlers; shared helpers decode verification keys and timestamps, frame deterministic JSON or text, and map PASS, FAIL, or other status to fixed exits.",
    participants="The caller, argument parser, facade dispatcher, shared parsing/framing support, one selected installed handler, standard output, and the process exit consumer.",
    inputs="One caller-supplied argument vector, optional test-only key encodings, timestamps, selected local paths, installed handler code, and handler result payload.",
    authority="The caller selects a command and local inputs; installed code selects the handler. Parsing, test-key possession, output framing, and exit status grant no caller identity, hardware, publication, release, or external authority.",
    states="Unparsed, parsed, handler selected, dispatched, handler returned, output emitted, rejected, or exited with PASS, FAIL, or UNKNOWN-family status.",
    ordering="Parser construction fixes command order; hardware dispatch eagerly loads the registry, then selects registry, discovery, receipt, or probe handling; framing precedes exit return.",
    commands="Dispatch exactly one selected installed in-process command handler and emit its returned payload; the facade itself addresses no physical device endpoint.",
    targets="The in-process parser, installed handler, standard output, and process exit status only; handler-owned files and endpoints retain their separate object consequences.",
    effect_domains="LOCAL_PROCESS_DISPATCH_AND_OUTPUT_ONLY; no facade-owned physical, financial, remote, publication, release, deployment, or sandbox boundary is represented.",
    effects="Invoke one installed handler, print its payload, and return a process exit code; any file or device-shaped operation belongs to the selected separately reviewed mechanism.",
    commit="Commit is the selected handler call plus emitted payload and returned exit code; there is no atomic cross-handler commit, durable history, or external finality.",
    retry="A repeat reparses current arguments and invokes current installed code; no request identity, duplicate ledger, rollback, or general handler idempotency is supplied.",
    timing="Parsing, dispatch, and output occur during one process call without a deadline, stable repository snapshot, device event-time proof, or liveness guarantee.",
    limits="The fixed parser grammar, installed command table, exact key/timestamp syntax, and handler-specific bounds limit the facade; handler effects are not widened by dispatch.",
    observations="Caller arguments, parsed selections, bounded decoded values, handler payload fields, status labels, and emitted output only.",
    units="Arguments, command identifiers, exact decoded bytes, timestamps, JSON fields, output lines, and process exit codes.",
    failure="Malformed values raise, unsupported or failed handlers retain their status, and output or handler exceptions abort the call without proving rollback of handler-owned effects.",
    recovery="Correct the exact arguments or selected handler condition and start a fresh invocation; inspect any handler-owned state through that mechanism's recovery contract.",
    boundary="The facade is a software command protocol, not a sandbox, hardware sensor, physical controller, attestation root, durable ledger, or authority to publish or release.",
)


_PROFILE_READER = _profile(
    name="The caller-supplied accelerator-profile reader",
    scope="List or inspect profile-shaped values by invoking one registry object supplied to the public handler, optionally filtering returned values by vendor.",
    mechanism="The public Python handler invokes registry.list or registry.get, reads attributes from returned objects, may invoke to_dict, and emits a PASS-labeled payload; annotations do not seal those runtime method targets.",
    participants="The caller, caller-supplied registry object, objects returned by its methods, argument selector, output formatter, and report consumer.",
    inputs="A list or inspect selector, optional vendor text or profile identifier, and an arbitrary runtime object passed in the registry parameter.",
    authority="The caller selects both the operation and registry object; a type annotation and PASS label grant no caller identity, device, owner, physical, financial, publication, release, or external authority.",
    states="Registry supplied, dynamic method selected, method executing, values returned, filtered or projected, missing value or exception, payload emitted, or completed.",
    ordering="Selection precedes registry.list or registry.get; returned-object attribute access and optional to_dict precede payload emission, but downstream method effects are not ordered or closed by this source.",
    commands="Invoke list, get, and returned-object methods on a caller-supplied Python object, then emit their projected result.",
    targets="The runtime registry and returned objects selected by the caller, standard output, and any downstream targets their unsealed methods can reach.",
    effect_domains="CALLER_SUPPLIED_PYTHON_DISPATCH_AND_OUTPUT; downstream physical, financial, filesystem, network, process, and other effects are not established absent.",
    effects="Invoke caller-controlled method implementations, read returned values, filter or project them, and emit one payload; applicability does not assert that any downstream consequence occurred.",
    commit="The direct commit is payload emission, while caller-supplied methods may have separate commit, partial-failure, or finality behavior that this handler does not establish.",
    retry="A repeat reinvokes current caller-supplied methods with no stable registry identity, duplicate guard, rollback, or downstream idempotency proof.",
    timing="Dynamic calls and projection occur during one invocation without a method deadline, stable registry snapshot, device time, or downstream liveness guarantee.",
    limits="The parser choices and projected field names are finite, but Python runtime dispatch does not bound what the supplied methods execute.",
    observations="Selector values, returned attributes, registry_version, profile-shaped fields, exceptions, emitted payload, and process result only.",
    units="Runtime objects, method calls, profiles, strings, model rows, registry versions, output fields, and process exits.",
    failure="Supplied methods, attribute access, filtering, conversion, or emission can fail after earlier downstream effects; this source supplies no rollback proof.",
    recovery="Inspect the exact supplied implementation and any downstream state, correct the selector or object, and perform a fresh bounded invocation.",
    boundary="All consequence roles remain applicable because runtime dispatch is unsealed; that retains obligations without asserting any effect occurred or granting device, physical, financial, publication, release, or external authority.",
)


_DISCOVERY_COMMAND = _profile(
    name="The accelerator discovery command",
    scope="Select one generic, NVIDIA, AMD, or Intel adapter, acquire its bounded device-shaped result, and optionally write normalized result JSON to one caller-selected local path.",
    mechanism="A fixed adapter map invokes one installed adapter; the generic route requires a fixture, vendor routes may use a fixture or their adapter acquisition, and normalized descriptors determine PASS versus UNSUPPORTED.",
    participants="The caller, selected installed adapter, optional fixture or vendor interface, normalized AdapterResult, optional local output writer, formatter, and consumer.",
    inputs="One fixed adapter identifier, optional fixture path, optional output path, installed adapter code, and the bytes or host-interface values acquired by that adapter.",
    authority="The caller selects adapter and paths; adapter output has no device identity, ownership, custody, calibration, attestation, publication, release, or external authorization authority.",
    states="Adapter selected, fixture required, acquiring, normalized, descriptors present or absent, local output writing or written, rejected, and report emitted.",
    ordering="Selection and required-fixture checks precede one adapter acquisition; normalization and status selection precede optional directory creation/write and output emission.",
    commands="Invoke one adapter and, when requested, create parent directories and replace the selected local JSON output file.",
    targets="The selected fixture or vendor acquisition surface, in-memory normalized result, optional local output path, standard output, and process exit.",
    effect_domains="BOUNDED_ADAPTER_ACQUISITION_AND_OPTIONAL_LOCAL_FILE_WRITE; no physical actuation, financial endpoint, publication, release, deployment, or sandbox is represented.",
    effects="Acquire one adapter result and optionally create directories and overwrite one normalized local JSON file.",
    commit="Observation commits when the adapter returns; optional output commits through one direct text write and is not exclusive, atomic, fsynced, locked, or crash-durable.",
    retry="Retry reacquires current adapter or fixture state and can repeat or replace the local write; there is no transaction identifier, duplicate guard, or stable device snapshot.",
    timing="Values are sampled during adapter execution, but the command supplies no synchronized device time, stable host snapshot, bounded acquisition latency, or freshness proof.",
    limits="The fixed adapter set, each adapter's parser and command bounds, normalized schema, caller paths, and one optional result file bound the command.",
    observations="Adapter name, normalized descriptors, evidence-source fields, acquisition errors or absences, selected status, and written result identity only.",
    units="Devices, descriptors, adapter records, exact strings and numbers supplied by adapters, bytes, JSON fields, paths, and process exits.",
    failure="Missing generic fixture or adapter failure raises; zero descriptors remains UNSUPPORTED; a failed or interrupted write can leave prior or partial local filesystem state.",
    recovery="Inspect the selected adapter and output path, correct fixture, tool, permission, or device availability, then perform a fresh discovery and explicitly reconcile any file.",
    boundary="Device-shaped adapter output is not physical attestation, calibrated completeness, device identity, custody, ownership, safe operation, or a durable transaction receipt.",
)


_VIRTUAL_PROBE = _profile(
    name="The deterministic virtual firmware probe harness",
    scope="Drive one in-process virtual accelerator through a fixed boot, challenge, attestation, execution, accounting, completion, receipt-write, and receipt-validation sequence.",
    mechanism="Validate caller time and test key, construct VirtualVSTDAccelerator, derive a deterministic nonce, execute the fixed emulator lifecycle, save its receipt, and validate it with the same supplied test key.",
    participants="The caller, deterministic virtual accelerator, fixed virtual verifier and workload identities, receipt writer, in-process receipt validator, output formatter, and consumer.",
    inputs="Caller-selected output path, timezone-aware created-at, virtual device and firmware identifiers, key identifier, and at least sixteen bytes of test-only HMAC key material.",
    authority="The caller selects virtual identifiers, time, output, and test key; the same-process test key and emulator grant no physical device, independent verifier, commodity attestation, publication, release, or external authority.",
    states="Arguments checked, virtual device constructed, partitions configured, booted, challenged, virtually attested, execution submitted, observed, completed, receipt built, locally saved, validated, reported, or failed.",
    ordering="The fixed virtual lifecycle is sequential and timestamped from created-at; receipt construction and local save precede in-process validation and report emission.",
    commands="Issue fixed in-process emulator state-transition commands, save one selected local receipt, validate it, and emit the bounded result.",
    targets="The in-memory reference emulator, its fixed logical partition and execution, one caller-selected local receipt path, standard output, and process exit only.",
    effect_domains="REFERENCE_EMULATOR_AND_LOCAL_RECEIPT_ONLY; no commodity hardware, physical actuator, financial endpoint, remote service, publication, release, deployment, or sandbox is represented.",
    effects="Mutate one ephemeral emulator through the fixed lifecycle and create or replace one local receipt file; no external hardware effect is claimed.",
    commit="Each emulator transition commits in memory; receipt saving commits through the receipt writer and is not claimed atomic or crash-durable; validation commits only a returned assessment.",
    retry="The deterministic inputs can recreate equivalent virtual evidence, but retry is a new emulator and file write with no duplicate ledger, rollback, external finality, or stable environment identity.",
    timing="Caller created-at derives fixed relative virtual timestamps; they are synthetic inputs, not observed device clocks, wall-clock freshness, real-time deadlines, or uptime evidence.",
    limits="One reference emulator, empty partition configuration, one fixed challenge and execution, one exact accounting quantity, bounded receipt schema, local write, and test-only key path are admitted.",
    observations="In-process emulator states, deterministic nonce and digests, one virtual accounting quantity, saved receipt identity, validation status, errors, and declared limitations.",
    units="Virtual state transitions, synthetic timestamps, bytes, SHA-256 and HMAC-SHA256 values, operations, receipts, paths, and process exits.",
    failure="Malformed time or key rejects before construction; emulator, write, or validation failure remains explicit and no rollback of an already written file is inferred.",
    recovery="Treat the result as virtual test evidence, inspect or remove any local receipt only under separate authority, correct exact inputs, and start a fresh emulator lifecycle.",
    boundary="This is a test-only virtual control loop and receipt harness, not physical attestation, complete mediation outside the emulator API, a ROBOT, a FINBOT, a sandbox, or durable uptime evidence.",
)


_RECEIPT_ASSESSOR = _profile(
    name="The stored hardware-receipt assessor",
    scope="Load one selected stored VSTD 3 receipt and perform selected validation, conformance, continuity, fleet, evidence, claim evaluation, or static claim explanation.",
    mechanism="Bounded receipt loading and installed validators recompute selected signatures, continuity, fleet comparison, claim evidence, or conformance projections using caller-supplied test verification keys when required.",
    participants="The caller, selected local receipt, optional test-key resolver, installed receipt and claim validators, deterministic projector, output formatter, and result consumer.",
    inputs="One selected receipt path for assessment routes, optional key-id/hex bindings, or one fixed claim kind for static explanation, plus installed validation policy.",
    authority="The caller selects bytes and optional keys; a valid stored receipt binds only its mechanism claims and grants no distinct actor, physical completeness, owner, custodian, publication, release, or external authority.",
    states="Selected, loaded, decoded, signature or continuity checked, fleet compared, claim or profile evaluated, PASS, FAIL, UNKNOWN, UNSUPPORTED, rejected, explained, or emitted.",
    ordering="Receipt decode and base validation precede dependent profile, evidence, or claim projection; continuity and fleet iterate stored records in their bounded collection order.",
    commands="Read selected local bytes, execute installed in-process assessment mechanisms, and emit their result without invoking the original producer or changing the receipt.",
    targets="The selected stored receipt, supplied test-key map, installed validators, in-memory result, standard output, and process exit only.",
    effect_domains="READ_ONLY_STORED_RECEIPT_ASSESSMENT; no source mechanism replay, physical device operation, financial action, publication, release, deployment, or sandbox effect occurs.",
    effects="Return bounded validation and projection results without mutating receipt, device, fleet, claim source, or external state.",
    commit="Commit is only emission of an assessment over selected stored bytes and installed code; it does not commit original execution truth or external finality.",
    retry="Retry reloads current selected bytes and current installed policy; no stable file lock, retained run identity, duplicate detection, or producer replay exists.",
    timing="The assessor runs at command time, distinct from receipt event times; it supplies no source freshness, uninterrupted continuity outside stored records, or current hardware observation.",
    limits="Receipt schema, selected command, supplied keys, installed validators, finite stored collections, and fixed conformance or claim enumerations bound the assessment.",
    observations="Selected receipt fields, recomputed validator results, stored evidence and claim rows, continuity gaps, fleet membership comparisons, statuses, errors, and warnings only.",
    units="Receipt bytes, records, profiles, claims, members, evidence sources, digests, signatures, status labels, errors, warnings, and process exits.",
    failure="Malformed or invalid input fails; missing keys, evidence, continuity, or support remains FAIL, UNKNOWN, or UNSUPPORTED under the selected mechanism and is never promoted.",
    recovery="Correct or replace the exact selected receipt or key map and reassess; separately rerun the admitted producer when fresh source evidence is required.",
    boundary="Stored receipt assessment is not direct source provenance, physical attestation or independent physical replay, device or fleet completeness, durable ledger authority, asset custody, sandboxing, or release permission.",
)


_PROFILE_READER_NECESSITY = {
    "LEDGER": "Caller-supplied list, get, or returned-object methods can read or mutate ordered state whose authority, replay, correction, and recovery boundaries this handler does not seal.",
    "TRANSACTION": "Dynamic registry and returned-object calls can cross commit boundaries with partial failure, retry, duplication, or finality behavior not bounded by this handler.",
    "ASSET": "The delegated methods and returned values are not established to exclude rights, quantities, issuance, custody, control, or reconciliation behavior.",
    "MARKET": "The delegated methods are not established to exclude order, price, allocation, settlement, participant, or disruption behavior.",
    "MEASUREMENT": "Returned profile-shaped values require an explicit observed-versus-declared, method, units, uncertainty, validity, and missingness boundary.",
    "SENSOR": "Caller-supplied methods can acquire values from unsealed sources, so acquisition, calibration, sampling, latency, fault, and recovery obligations remain live.",
    "CONTROLLER": "Dynamic method dispatch can couple observations, decisions, and commands through a feedback path whose authority, timing, stability, intervention, and failure behavior are not closed here.",
    "ACTUATOR": "Invoking caller-supplied methods crosses an effect boundary whose targets, authority, response, limits, feedback, interlocks, and recovery are not established.",
    "PROTOCOL": "The list or inspect grammar, method ordering, runtime participants, state transitions, replay behavior, failures, and progress form a bounded protocol surface.",
    "POLICY": "Operation selection, exact lookup, optional filtering, PASS labeling, exception behavior, and emission are explicit bounded policy decisions.",
    "ROBOT": "The delegated methods are not established to exclude an agent-to-controller-to-actuator path; retaining the role asserts no physical action or authority.",
    "FINBOT": "The delegated methods are not established to exclude financial decisions or effects; retaining the role asserts no financial action or authority.",
}


def _reason(review: _Review, kind: str, closure: "_Closure | None" = None) -> str:
    """State the source-bound decision for one kind of one owner.

    Applications state the role's necessity.  Refutations use the owner's own
    cited incompatibility and never the shared generic exclusion text, and they
    also name the closure fingerprint that witnessed them.  A kind with no basis
    returns the canonical unresolved reason.
    """
    profile = review.profile
    basis = _basis(review, kind, closure)
    if basis == "UNRESOLVED":
        return _unresolved_reason(kind)
    if basis == "DOES_NOT_APPLY":
        assert closure is not None
        return (
            profile.name
            + " does not apply as "
            + kind
            + ". "
            + review.refutations[kind]
            + " Reviewed boundary: "
            + profile.boundary
            + " "
            + _closure_clause(kind, closure)
        )
    necessity = (_PROFILE_READER_NECESSITY if profile is _PROFILE_READER else {
        "LEDGER": "Its acquired descriptor record, selected status, optional retained output, overwrite semantics, and fresh-run ordering require an explicit evidence-history boundary.",
        "TRANSACTION": "Its optional local write or virtual receipt publication has explicit preconditions, commit, partial-failure, retry, and finality boundaries.",
        "ASSET": "Its normalized descriptor and optional output file are digestible digital artifacts with explicit selection, retention, replacement, and non-property boundaries.",
        "MARKET": "Its delegated adapter boundary can reach a PATH-resolved vendor executable whose downstream market effects are not established absent; applicability retains obligations without asserting a market or trading authority.",
        "MEASUREMENT": "Its bounded software-interface values must distinguish observed fields from physical facts, completeness, and other unobserved state.",
        "SENSOR": "Its digital acquisition path has explicit source, range, sampling, missingness, latency, and fault behavior.",
        "CONTROLLER": "Its caller-selected adapter dispatch, acquired descriptor feedback, status decision, timing, limits, and recovery require a bounded software-control boundary without claiming physical control.",
        "ACTUATOR": "It invokes a selected software mechanism or writes a named local file while explicitly withholding downstream physical and external effect claims.",
        "PROTOCOL": "Its parser or virtual participants, ordered states, message authority, compatibility, replay, and failures require a protocol boundary.",
        "POLICY": "Its command or rule selection, precedence, authority, defaults, exceptions, and enforcement points determine the bounded result.",
        "ROBOT": "Its delegated adapter boundary can reach a PATH-resolved vendor executable whose downstream device effects are not established absent; applicability retains obligations without asserting physical actuation or authority.",
        "FINBOT": "Its delegated adapter boundary can reach a PATH-resolved vendor executable whose downstream financial effects are not established absent; applicability retains obligations without asserting a financial action or authority.",
    })[kind]
    reach = review.reach.get(kind, "")
    return (
        profile.name
        + " applies as "
        + kind
        + ". "
        + necessity
        + (" " + reach if reach else "")
        + " Reviewed boundary: "
        + profile.boundary
    )


def _obligation_reason(review: _Review, kind: str) -> str:
    return (
        _reason(review, kind)
        + " This Tier-0 declaration names only the exact reviewed source "
        "boundary; execution and Tier-1-plus fulfillment remain unestablished."
    )


def _review(
    primary_kind: str,
    paths: tuple[str, ...],
    applicable: tuple[str, ...],
    profile: _shared._Profile,
    *,
    refutations: Mapping[str, str],
    role_paths: Mapping[str, tuple[str, ...]] | None = None,
    reach: Mapping[str, str] | None = None,
) -> _Review:
    return _Review(
        primary_kind=primary_kind,
        owned_paths=paths,
        applicable=applicable,
        role_paths=(
            {kind: paths for kind in applicable}
            if role_paths is None
            else dict(role_paths)
        ),
        profile=profile,
        refutations=dict(refutations),
        reach=dict(reach or {}),
    )


_CLI_PATHS = (
    "src/verifier/runtime/hardware_cli.py",
    "src/verifier/runtime/hardware_cli_support.py",
)
_CLI_FACADE_PATHS = ("src/verifier/runtime/hardware_cli.py",)

# Each refutation states what the owned source does instead of the refuted role.
# Absence of a token is not enough: every entry names a concrete function or
# effect in an owned file, and no two owners share a refutation text.
_CLI_REFUTATIONS = {
    "LEDGER": (
        "hardware_cli.py builds its parser and loads the registry on every call, and "
        "hardware_cli_support.py only prints and decodes, so the facade keeps no state between "
        "invocations; the reached handlers are also one-shot, since the probe constructs a fresh "
        "emulator per call and saves one caller-selected receipt by overwrite, and discovery's "
        "optional --output is a whole-file overwrite, so no ordered history spans invocations."
    ),
    "ASSET": (
        "The reached values are argv strings, verification-key bytes, ISO timestamps, integer "
        "exit codes PASS_EXIT, FAIL_EXIT, and UNKNOWN_EXIT in hardware_cli_support.py, and the "
        "probe's fixed count of virtual operations; none is a right, balance, or quantity that "
        "can be held, issued, or redeemed, and the reached hardware package has no balance, "
        "issuance, redemption, or custody term."
    ),
    "MARKET": (
        "hardware_cli.py and hardware_cli_support.py contain no participant, order, price, "
        "trade, matching, or settlement value, and the reached hardware package contains no "
        "order, price, trade, matching, or settlement logic; the facade emits handler payloads "
        "and a process exit code only."
    ),
    "CONTROLLER": (
        "hardware_cli.py selects one handler from the parsed command name in "
        "_handle_hardware_command and never reads an observed value back to choose another "
        "command; each invocation performs exactly one dispatch."
    ),
    "ROBOT": (
        "hardware_cli.py dispatches only to in-process handlers; the only device contact they "
        "reach is fixed read-only host query argv (adapters/nvidia.py runs nvidia-smi "
        "--query-gpu, adapters/amd.py runs amd-smi static --json) with no control or write call "
        "to a device, so no agent-to-physical-actuator path is reached."
    ),
    "FINBOT": (
        "hardware_cli.py and hardware_cli_support.py contain no payment, account, transfer, or "
        "financial endpoint, and the reached handlers contain none either; the reached effects "
        "are host queries, local receipt or result files, and stdout, so they form no real-money "
        "decision or effect."
    ),
}

_DISCOVERY_REFUTATIONS = {
    "LEDGER": (
        "hardware_discovery_cli.py's only persisted effect is one whole-file overwrite of --output "
        "(write_text with no append, sequence, or prior-state read), so it cannot be an ordered "
        "authoritative history."
    ),
    "ASSET": (
        "The descriptors are device-shaped adapter records and the optional file is one normalized "
        "snapshot; hardware_discovery_cli.py represents no right, balance, quantity, or custody."
    ),
    "MARKET": (
        "hardware_discovery_cli.py contains no participant, order, price, trade, or settlement "
        "logic; its outputs are device descriptors and PASS or UNSUPPORTED labels."
    ),
    "CONTROLLER": (
        "hardware_discovery_cli.py makes one discover() call per invocation and maps the descriptors "
        "to a status once; no observed value feeds back into a subsequent command."
    ),
    "ROBOT": (
        "hardware_discovery_cli.py calls only the discover() method of one fixed adapter; the reached "
        "adapters issue no actuation: adapters/nvidia.py and adapters/amd.py run only fixed read-only "
        "argv against PATH-resolved vendor query tools, the Intel and fixture paths read bytes only, "
        "and the NVIDIA and AMD fixture shims write only an ephemeral temporary file, so no "
        "agent-to-physical-actuator path is reached."
    ),
    "FINBOT": (
        "hardware_discovery_cli.py has no payment, account, or financial endpoint; its effects are one "
        "adapter read, an optional local JSON file, and standard output."
    ),
}

_VIRTUAL_PROBE_REFUTATIONS = {
    "LEDGER": (
        "hardware_probe_cli.py constructs a fresh VirtualVSTDAccelerator on every call, so its "
        "accounting chain is a new in-memory sequence per invocation; that chain is persisted only "
        "inside one receipt which save_vstd3_receipt overwrites with write_bytes, with no append "
        "and no read of a prior receipt, so the owned file keeps no ordered history across "
        "invocations."
    ),
    "ASSET": (
        "The accounting quantity is a hard-coded constant (virtual_probe_operations with value \"1\") "
        "inside an in-process emulator; hardware_probe_cli.py represents no right, balance, issuance, "
        "or custody."
    ),
    "MARKET": (
        "hardware_probe_cli.py contains no participant, order, price, trade, or settlement mechanism; "
        "it drives one in-process VirtualVSTDAccelerator lifecycle."
    ),
    "CONTROLLER": (
        "hardware_probe_cli.py runs a fixed, open-loop sequence (boot, issue_challenge, attest, "
        "submit_execution, observe_execution, complete_execution); the validation result is reported "
        "and never fed back into a command."
    ),
    "SENSOR": (
        "hardware_probe_cli.py has no acquisition producer: observe_execution receives a hard-coded "
        "AccountingQuantity, and no device, clock, or external source is read."
    ),
    "ROBOT": (
        "hardware_probe_cli.py operates only the in-process VirtualVSTDAccelerator emulator and writes one "
        "local receipt; it has no physical endpoint or actuator path."
    ),
    "FINBOT": (
        "hardware_probe_cli.py has no financial endpoint; its only effects are emulator state, one local "
        "receipt file, and standard output."
    ),
}

_RECEIPT_REFUTATIONS = {
    "LEDGER": (
        "hardware_receipt_cli.py only loads a selected receipt and reads the continuity and fleet records "
        "already in it; it writes nothing, so it owns no ordered history."
    ),
    "TRANSACTION": (
        "hardware_receipt_cli.py performs no write, commit, or rollback: every command is a read-only load, "
        "validation, and emit."
    ),
    "ASSET": (
        "The receipt, claim, fleet, and evidence rows are mechanism records and digests; "
        "hardware_receipt_cli.py represents no right, balance, quantity, or custody."
    ),
    "MARKET": (
        "hardware_receipt_cli.py contains no participant, order, price, trade, or settlement logic; its "
        "outputs are validation, claim, and fleet status records."
    ),
    "CONTROLLER": (
        "hardware_receipt_cli.py performs one bounded assessment of a stored receipt per invocation and never "
        "feeds an assessed result back into a command."
    ),
    "ACTUATOR": (
        "hardware_receipt_cli.py invokes no submission boundary and writes no file; it loads stored bytes and "
        "emits a read-only report."
    ),
    "SENSOR": (
        "hardware_receipt_cli.py acquires no observation from a device, clock, or external source; it evaluates "
        "the records already in one stored receipt."
    ),
    "ROBOT": (
        "hardware_receipt_cli.py reads one stored file and emits a report; it contains no device, actuator, or "
        "endpoint call."
    ),
    "FINBOT": (
        "hardware_receipt_cli.py contains no payment, account, or financial endpoint; its only effects are reads "
        "and standard output."
    ),
}

_REVIEWS = {
    "vstd-hardware-cli-protocol": _review(
        "PROTOCOL",
        _CLI_PATHS,
        REVIEW_KINDS,
        _CLI_PROTOCOL,
        refutations={},
        role_paths={
            "ACTUATOR": _CLI_FACADE_PATHS,
            "ASSET": _CLI_FACADE_PATHS,
            "CONTROLLER": _CLI_FACADE_PATHS,
            "FINBOT": _CLI_FACADE_PATHS,
            "LEDGER": _CLI_FACADE_PATHS,
            "MARKET": _CLI_FACADE_PATHS,
            "MEASUREMENT": _CLI_FACADE_PATHS,
            "POLICY": _CLI_PATHS,
            "PROTOCOL": _CLI_PATHS,
            "ROBOT": _CLI_FACADE_PATHS,
            "SENSOR": _CLI_FACADE_PATHS,
            "TRANSACTION": _CLI_FACADE_PATHS,
        },
        # Dispatch-reached positives accumulate into the facade; the facade's own
        # lines are only the dispatch table, so each note names what it reaches.
        reach={
            "LEDGER": (
                "Dispatch reaches discovery result files and probe receipts whose ordering, "
                "replacement, and reconciliation boundaries remain part of the facade contract."
            ),
            "ASSET": (
                "Dispatch reaches normalized descriptor files and receipt artifacts whose exact "
                "identity and retention boundaries remain part of the facade contract."
            ),
            "MARKET": (
                "Dispatch reaches caller-selected adapters and PATH-resolved vendor executables "
                "whose downstream market effects are not established absent."
            ),
            "MEASUREMENT": (
                "Dispatch reaches hardware_discovery_cli.py's normalized device descriptors and "
                "hardware_receipt_cli.py's conformance, continuity, and fleet results, which the "
                "facade emits as observed fields."
            ),
            "SENSOR": (
                "Dispatch reaches hardware_discovery_cli.py, whose adapters run host-device query "
                "subprocesses and read clocks for observed_at, so the reached acquisition path has "
                "source, timing, and fault boundaries."
            ),
            "TRANSACTION": (
                "Dispatch reaches hardware_probe_cli.py's save-then-validate receipt write and "
                "hardware_discovery_cli.py's optional --output write, so each reached handler's "
                "commit and partial-failure boundary is part of this facade's dispatch."
            ),
            "CONTROLLER": (
                "Dispatch selects one command mechanism and returns its acquired status; the "
                "selected adapter's downstream control envelope is not established closed."
            ),
            "ROBOT": (
                "Dispatch reaches caller-selected adapters and PATH-resolved vendor executables "
                "whose downstream device effects are not established absent."
            ),
            "FINBOT": (
                "Dispatch reaches caller-selected adapters and PATH-resolved vendor executables "
                "whose downstream financial effects are not established absent."
            ),
        },
    ),
    "vstd-accelerator-profile-reader": _review(
        "VERIFIER",
        ("src/verifier/runtime/hardware_registry_cli.py",),
        REVIEW_KINDS,
        _PROFILE_READER,
        refutations={},
    ),
    "vstd-accelerator-discovery-command": _review(
        "SENSOR",
        ("src/verifier/runtime/hardware_discovery_cli.py",),
        REVIEW_KINDS,
        _DISCOVERY_COMMAND,
        refutations={},
    ),
    "vstd-virtual-firmware-probe-harness": _review(
        "HARNESS",
        ("src/verifier/runtime/hardware_probe_cli.py",),
        ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "TRANSACTION"),
        _VIRTUAL_PROBE,
        refutations=_VIRTUAL_PROBE_REFUTATIONS,
        reach={
            "MEASUREMENT": (
                "observe_execution records one AccountingQuantity with method FIRMWARE_COUNTER and "
                "exactness EXACT_FOR_DECLARED_SCOPE, a software-interface observation whose value is "
                "fixed in source and is not a physical measurement."
            ),
        },
    ),
    "vstd-hardware-receipt-assessor": _review(
        "VERIFIER",
        ("src/verifier/runtime/hardware_receipt_cli.py",),
        ("MEASUREMENT", "POLICY"),
        _RECEIPT_ASSESSOR,
        refutations=_RECEIPT_REFUTATIONS,
    ),
}

# These decisions keep consequence obligations live because an unsealed
# delegated boundary is not proved absent.  They do not establish that the
# object itself is a market actor, ROBOT, or FINBOT.  Directly implemented
# acquisition, protocol, policy, controller, actuator, artifact, and local
# write roles remain structural and are intentionally absent from this map.
OBLIGATION_RETENTION_APPLIES: dict[str, tuple[str, ...]] = {
    "vstd-hardware-cli-protocol": ("FINBOT", "MARKET", "ROBOT"),
    "vstd-accelerator-profile-reader": (
        "ASSET",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "ROBOT",
        "TRANSACTION",
    ),
    "vstd-accelerator-discovery-command": ("FINBOT", "MARKET", "ROBOT"),
}


def obligation_retention_reason(object_id: str, kind: str) -> str:
    """Return one exact source-reviewed demand-only applicability reason."""

    if kind not in OBLIGATION_RETENTION_APPLIES.get(object_id, ()):
        raise ValueError("HARDWARE_CLI_OBLIGATION_RETENTION_UNDECLARED")
    return _reason(_REVIEWS[object_id], kind)


_DECLARATION_BUILDERS = dict(_shared._DECLARATION_BUILDERS)


def _contract_rows(kind: str) -> list[dict[str, Any]]:
    return [
        row
        for row in requirements_for(namespace_registry(), (kind,))
        if row["kind"] == kind
    ]


def _declarations(review: _Review) -> dict[str, dict[str, str]]:
    declarations: dict[str, dict[str, str]] = {}
    for kind in review.applicable:
        try:
            selected = _DECLARATION_BUILDERS[kind](review.profile)
        except KeyError as exc:
            raise AssertionError("missing declaration builder for " + kind) from exc
        overlap = set(declarations).intersection(selected)
        if overlap:
            raise AssertionError("duplicate declaration ids: " + ", ".join(overlap))
        declarations.update(selected)
    return declarations


def _catalog_check() -> None:
    if tuple(_REVIEWS) != HARDWARE_CLI_OBJECT_IDS:
        raise AssertionError("hardware CLI review order differs from object order")
    owned_paths: set[str] = set()
    for object_id, review in _REVIEWS.items():
        if (
            review.primary_kind in REVIEW_KINDS
            and review.primary_kind not in review.applicable
        ):
            raise AssertionError(object_id + " primary kind is not applicable")
        if len(review.owned_paths) != len(set(review.owned_paths)):
            raise AssertionError(object_id + " repeats an owned path")
        overlap = owned_paths.intersection(review.owned_paths)
        if overlap:
            raise AssertionError(
                "hardware CLI ownership overlaps: " + ", ".join(sorted(overlap))
            )
        owned_paths.update(review.owned_paths)
        if len(review.applicable) != len(set(review.applicable)):
            raise AssertionError(object_id + " repeats an applicable kind")
        if not set(review.applicable) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " has an unsupported review kind")
        if not set(review.refutations) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " refutes an unsupported review kind")
        if set(review.applicable) & set(review.refutations):
            raise AssertionError(object_id + " applies and refutes one kind")
        for kind, text in review.refutations.items():
            # A refutation must name the exact owned source it audited, so an
            # unsourced or copied token cannot stand in for source evidence.
            if type(text) is not str or not text.strip():
                raise AssertionError(object_id + " refutation is empty: " + kind)
            if not any(Path(path).name in text for path in review.owned_paths):
                raise AssertionError(
                    object_id + " refutation cites no owned source: " + kind
                )
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if any(
            not paths or not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence leaves owned source")
        reasons = {kind: _reason(review, kind) for kind in REVIEW_KINDS}
        if set(reasons) != set(REVIEW_KINDS) or any(
            not value.strip() for value in reasons.values()
        ):
            raise AssertionError(object_id + " classification matrix is incomplete")
        refutation_texts = [
            text for item in _REVIEWS.values() for text in item.refutations.values()
        ]
        if len(refutation_texts) != len(set(refutation_texts)):
            raise AssertionError("hardware CLI refutations repeat a reason")
        expected = {
            row["id"]: set(row["declaration_fields"])
            for kind in review.applicable
            for row in _contract_rows(kind)
        }
        declarations = _declarations(review)
        if set(declarations) != set(expected):
            raise AssertionError(object_id + " declaration denominator differs")
        for obligation_id, fields in declarations.items():
            if set(fields) != expected[obligation_id] or any(
                type(value) is not str or not value.strip() for value in fields.values()
            ):
                raise AssertionError(object_id + " declaration fields differ")


_catalog_check()


def review_document(root: str | Path | None = None) -> dict[str, Any]:
    """Return a defensive deterministic review of all five exact owners.

    The root supplies each owner's source-bound closure that witnesses its
    DOES_NOT_APPLY roles.  Without a readable root every such role is UNRESOLVED.
    """
    selected_root = _default_root() if root is None else Path(root).resolve()
    closures = {
        object_id: _owner_closure(selected_root, review.owned_paths)
        for object_id, review in _REVIEWS.items()
    }
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: {
                    "status": _basis(review, kind, closures[object_id]),
                    "reason": _reason(review, kind, closures[object_id]),
                    "evidence_paths": list(
                        review.role_paths[kind]
                        if _basis(review, kind, closures[object_id]) == "APPLIES"
                        else review.owned_paths
                        if _basis(review, kind, closures[object_id]) == "DOES_NOT_APPLY"
                        else ()
                    ),
                }
                for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(_declarations(review)),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for object_id, review in _REVIEWS.items()
    }


def _read_digest(root: Path, path: str) -> str:
    """Read one exact in-root ordinary source without following an escape."""
    candidate = root.joinpath(*path.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        if (
            candidate.is_symlink()
            or not resolved.is_relative_to(root)
            or not resolved.is_file()
        ):
            raise OSError("owned source is not an in-root ordinary file")
        raw = resolved.read_bytes()
    except OSError as exc:
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE:" + path) from exc
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
        path = reference["path"]
        if files.get(path) != reference["sha256"]:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:" + object_id + ":" + path
            )
    return evidence


# Source-bound execution closure.  A DOES_NOT_APPLY basis is a candidate only: it holds
# when the owner's static closure is CLOSED and reaches none of the effect categories the
# refuted role forbids.  The scan is over-approximate (every attribute call matches each
# same-named callable in the closure, every executed package __init__ is included) and
# fail-closed (dynamic, external, or unresolvable sites leave the closure OPEN).  It is
# evidence of absence within the scanned source only, not of runtime behavior.

_ACQUISITION = frozenset({"CLOCK", "HARDWARE", "NETWORK", "PROCESS", "PROCESS_QUERY"})
_ACTUATION = frozenset({"FS_WRITE", "HARDWARE", "NETWORK", "PROCESS"})
_FORBIDDEN_BY_ROLE = {
    "ROBOT": frozenset({"HARDWARE", "NETWORK", "PROCESS", "TRACE"}),
    "FINBOT": frozenset({"HARDWARE", "NETWORK", "PROCESS", "TRACE"}),
    "ACTUATOR": frozenset(
        {"FS_WRITE", "FS_TEMP", "HARDWARE", "NETWORK", "PROCESS", "PROCESS_QUERY", "TRACE"}
    ),
    "TRANSACTION": frozenset({"FS_WRITE", "FS_TEMP", "HARDWARE", "NETWORK", "PROCESS", "TRACE"}),
    "SENSOR": _ACQUISITION | {"TRACE"},
    "MEASUREMENT": _ACQUISITION | {"TRACE"},
    "LEDGER": frozenset({"FS_APPEND", "FS_UNKNOWN", "GLOBAL_STATE", "TRACE"}),
    "ASSET": frozenset(
        {"FS_APPEND", "FS_UNKNOWN", "GLOBAL_STATE", "HARDWARE", "NETWORK", "PROCESS", "TRACE"}
    ),
    "MARKET": frozenset({"HARDWARE", "NETWORK", "PROCESS", "TRACE"}),
}
_WITNESS_TEXT = {
    kind: "no " + ", ".join(sorted(forbidden)) + " effect is reached"
    for kind, forbidden in _FORBIDDEN_BY_ROLE.items()
}
_WITNESS_TEXT["CONTROLLER"] = (
    "the reached closure lacks an acquisition or an actuation channel, so no closed "
    "observation-to-actuation loop is reachable"
)
# Only the exact read-only host-query argv literals admitted by the owned adapters.
_QUERY_TOOLS = frozenset({"nvidia-smi", "amd-smi"})
_READONLY_ARGV_TAILS = frozenset(
    {
        (
            "--query-gpu=uuid,name,pci.bus_id,driver_version,vbios_version",
            "--format=csv,noheader,nounits",
        ),
        ("static", "--json"),
    }
)
_EFFECT_PATTERNS = tuple(
    (re.compile(r"(?:" + pattern + r")(?:\.|$)"), category)
    for pattern, category in (
        (r"subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)", "PROCESS"),
        (
            r"multiprocessing|pty|asyncio\.create_subprocess_(?:exec|shell)"
            r"|os\.(?:system|popen|startfile|(?:posix_)?spawn[a-z]*|exec[a-z]*)",
            "PROCESS",
        ),
        (
            r"socket|socketserver|ssl|urllib\.request|http\.(?:client|server)|ftplib|smtplib"
            r"|poplib|imaplib|telnetlib|xmlrpc\.(?:client|server)|requests|httpx|aiohttp"
            r"|webbrowser|asyncio\.(?:open_connection|start_server|create_connection"
            r"|create_datagram_endpoint|open_unix_connection|start_unix_server)",
            "NETWORK",
        ),
        (r"ctypes|mmap|serial|usb|pyudev|pynvml|hid|smbus|fcntl|termios|msvcrt|winreg", "HARDWARE"),
        (
            r"pdb|bdb|trace|cProfile|profile|faulthandler"
            r"|sys\.(?:settrace|setprofile|breakpointhook|monitoring|call_tracing)",
            "TRACE",
        ),
        (
            r"importlib(?!\.resources(?:\.|$))|runpy|pickle|marshal|shelve|code|codeop|builtins"
            r"|sys\.modules|sys\._getframe|inspect\.(?:currentframe|stack)",
            "DYNAMIC",
        ),
        (
            r"shutil(?!\.which(?:\.|$))"
            r"|os\.(?:remove|unlink|rename|renames|replace|mkdir|makedirs|rmdir|removedirs"
            r"|chmod|chown|lchown|link|symlink|truncate|utime|mkfifo|mknod|write|ftruncate)",
            "FS_WRITE",
        ),
        (r"os\.open", "FS_UNKNOWN"),
        (r"tempfile", "FS_TEMP"),
        (r"os\.(?:listdir|scandir|stat|lstat|walk)|glob", "FS_READ"),
        (
            r"datetime\.(?:datetime\.(?:now|utcnow|today)|date\.today)"
            r"|time\.(?:time|time_ns|monotonic|monotonic_ns|perf_counter|perf_counter_ns"
            r"|process_time|clock_gettime|clock_gettime_ns)",
            "CLOCK",
        ),
    )
)
# Attribute names that carry an effect on a receiver that is not an import alias.
_ATTRIBUTE_EFFECTS = {
    "write_text": "FS_WRITE",
    "write_bytes": "FS_WRITE",
    "unlink": "FS_WRITE",
    "rmdir": "FS_WRITE",
    "mkdir": "FS_WRITE",
    "touch": "FS_WRITE",
    "rename": "FS_WRITE",
    "symlink_to": "FS_WRITE",
    "hardlink_to": "FS_WRITE",
    "chmod": "FS_WRITE",
    "lchmod": "FS_WRITE",
    "read_text": "FS_READ",
    "read_bytes": "FS_READ",
    "iterdir": "FS_READ",
    "glob": "FS_READ",
    "rglob": "FS_READ",
    "TemporaryFile": "FS_TEMP",
    "NamedTemporaryFile": "FS_TEMP",
    "TemporaryDirectory": "FS_TEMP",
    "SpooledTemporaryFile": "FS_TEMP",
    "mkstemp": "FS_TEMP",
    "mkdtemp": "FS_TEMP",
    "Popen": "PROCESS",
    "system": "PROCESS",
    "popen": "PROCESS",
    "urlopen": "NETWORK",
    "getresponse": "NETWORK",
    "create_connection": "NETWORK",
    "connect": "NETWORK",
    "bind": "NETWORK",
    "listen": "NETWORK",
    "accept": "NETWORK",
    "send": "NETWORK",
    "sendall": "NETWORK",
    "sendto": "NETWORK",
    "recv": "NETWORK",
    "recvfrom": "NETWORK",
    "utcnow": "CLOCK",
    "today": "CLOCK",
    "now": "CLOCK",
    "monotonic": "CLOCK",
    "perf_counter": "CLOCK",
    "set_trace": "TRACE",
    "settrace": "TRACE",
    "setprofile": "TRACE",
    "import_module": "DYNAMIC",
    "CDLL": "HARDWARE",
    "WinDLL": "HARDWARE",
    "PyDLL": "HARDWARE",
    "ioctl": "HARDWARE",
}
_PROCESS_RUNNERS = frozenset({"run", "call", "check_call", "check_output", "Popen"})
_BUILTIN_DYNAMIC = frozenset({"eval", "exec", "compile", "__import__", "globals", "locals", "vars"})
_CONTAINER_BUILDERS = frozenset(
    {"dict", "list", "set", "defaultdict", "OrderedDict", "Counter", "deque"}
)
_MUTATORS = frozenset(
    {
        "append",
        "extend",
        "insert",
        "add",
        "update",
        "pop",
        "popitem",
        "remove",
        "discard",
        "clear",
        "setdefault",
        "sort",
        "reverse",
    }
)
_STDLIB = frozenset(sys.stdlib_module_names)
_TREE_CACHE: dict[tuple[str, str], ast.Module] = {}


@dataclass(frozen=True)
class _Closure:
    """One owner's static execution closure; status is CLOSED only without open sites.

    ``files`` pins every source and data digest the scan read.  ``absent`` lists the
    candidate paths the scan probed and found missing, so a later appearance of one of
    them invalidates the closure too.
    """

    status: str
    fingerprint: str
    effects: frozenset[str]
    sites: tuple[str, ...]
    open_reasons: tuple[str, ...]
    files: tuple[tuple[str, str], ...]
    absent: tuple[str, ...]


def _dne_allowed(kind: str, closure: _Closure) -> bool:
    """Whether the closure witnesses the absence that DOES_NOT_APPLY for kind requires."""
    if closure.status != "CLOSED":
        return False
    if kind == "CONTROLLER":
        return (not (closure.effects & _ACQUISITION)) or (not (closure.effects & _ACTUATION))
    forbidden = _FORBIDDEN_BY_ROLE.get(kind)
    return forbidden is not None and not (closure.effects & forbidden)


def _closure_clause(kind: str, closure: _Closure) -> str:
    reached = ", ".join(sorted(closure.effects)) or "no effect categories"
    return (
        "Source-bound execution closure "
        + closure.fingerprint
        + " is CLOSED and reaches "
        + reached
        + "; "
        + _WITNESS_TEXT[kind]
        + "."
    )


def _dotted(rel: str) -> str:
    """Return the import name of one repository-relative source file."""
    stem = rel.removeprefix("src/").removesuffix("/__init__.py").removesuffix(".py")
    return stem.replace("/", ".")


def _ordinary_file(root: Path, rel: str) -> Path | None:
    """Resolve one in-root regular file; symlinks and escapes are never followed."""
    candidate = root.joinpath(*rel.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if candidate.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
        return None
    return resolved


def _module_rel(root: Path, dotted: str, absent: set[str]) -> str | None:
    base = "src/" + "/".join(dotted.split("."))
    for rel in (base + ".py", base + "/__init__.py"):
        if _ordinary_file(root, rel) is not None:
            return rel
        absent.add(rel)
    return None


def _arg_names(node: ast.AST) -> set[str]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return set()
    args = node.args
    names = [item.arg for item in args.posonlyargs + args.args + args.kwonlyargs]
    for extra in (args.vararg, args.kwarg):
        if extra is not None:
            names.append(extra.arg)
    return set(names)


def _bindable(nodes: list[ast.AST]) -> frozenset[str]:
    """Names a call may legitimately target from inside the scanned scope."""
    names: set[str] = set()
    for node in nodes:
        names |= _arg_names(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return frozenset(names)


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _executed_nodes(tree: ast.Module) -> list[ast.AST]:
    """Nodes that execute at import time, skipping function bodies and TYPE_CHECKING blocks.

    Decorators, default values, class bodies, and class bases run at definition time;
    function and lambda bodies run only when called, so the scan reaches them there.
    """
    nodes: list[ast.AST] = []
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        nodes.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.extend(node.decorator_list + node.args.defaults)
            stack.extend(d for d in node.args.kw_defaults if d is not None)
            if node.returns is not None:
                stack.append(node.returns)
        elif isinstance(node, ast.Lambda):
            stack.extend(node.args.defaults)
            stack.extend(d for d in node.args.kw_defaults if d is not None)
        elif isinstance(node, ast.If) and _is_type_checking(node.test):
            stack.extend(node.orelse)
        else:
            stack.extend(ast.iter_child_nodes(node))
    return nodes


def _import_nodes(tree: ast.Module) -> list[ast.AST]:
    """Import statements of one module, excluding TYPE_CHECKING-only blocks."""
    nodes: list[ast.AST] = []
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            nodes.append(node)
            continue
        if isinstance(node, ast.If) and _is_type_checking(node.test):
            stack.extend(node.orelse)
            continue
        stack.extend(ast.iter_child_nodes(node))
    return nodes


def _mode_category(mode: ast.expr | None) -> str:
    if mode is None:
        return "FS_READ"
    if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
        return "FS_UNKNOWN"
    if "a" in mode.value:
        return "FS_APPEND"
    if any(flag in mode.value for flag in "wx+"):
        return "FS_WRITE"
    return "FS_READ"


class _ClosureScan:
    """Fail-closed static execution scan of one owner's owned sources."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.trees: dict[str, ast.Module] = {}
        self.digests: dict[str, str] = {}
        self.imports: dict[str, dict[str, str]] = {}
        self.modules: dict[str, str] = {}
        self.toplevel: dict[str, dict[str, ast.AST]] = {}
        self.by_name: dict[str, list[tuple[str, ast.AST]]] = {}
        self.hooks: dict[str, ast.AST] = {}
        self.entry_ids: set[int] = set()
        self.visited: set[tuple[str, int]] = set()
        self.queue: list[tuple[str, ast.AST | None]] = []
        self.data: dict[str, str] = {}
        self.effects: set[str] = set()
        self.open: set[str] = set()
        self.sites: set[str] = set()
        self.scope: list[ast.AST] = []
        self.absent: set[str] = set()
        self.owner: dict[int, tuple[str, ast.ClassDef]] = {}
        self.instantiated: set[tuple[str, str]] = set()

    # -- loading -----------------------------------------------------------------

    def _load(self, pending: list[str]) -> None:
        while pending:
            rel = pending.pop()
            if rel in self.trees:
                continue
            path = _ordinary_file(self.root, rel)
            if path is None:
                self.open.add("unreadable source " + rel)
                continue
            try:
                raw = path.read_bytes()
                digest = "sha256:" + sha256(raw).hexdigest()
                key = (rel, digest)
                if key not in _TREE_CACHE:
                    _TREE_CACHE[key] = ast.parse(raw.decode("utf-8"), filename=rel)
            except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
                self.open.add("unparseable source " + rel)
                continue
            self.trees[rel] = _TREE_CACHE[key]
            self.digests[rel] = digest
            self.imports[rel] = {}
            pending.extend(self._bind_imports(rel))

    def _bind_imports(self, rel: str) -> list[str]:
        """Record aliases and return the closure sources this module's imports need."""
        found: list[str] = []
        aliases = self.imports[rel]
        for node in _import_nodes(self.trees[rel]):
            if isinstance(node, ast.Import):
                for item in node.names:
                    if item.asname:
                        aliases[item.asname] = item.name
                    else:
                        top = item.name.split(".")[0]
                        aliases[top] = top
                    found.extend(self._resolve_import(rel, item.name, strict=True))
            elif isinstance(node, ast.ImportFrom):
                base = self._absolute(rel, node)
                if base is None:
                    self.open.add("relative import outside package in " + rel)
                    continue
                found.extend(self._resolve_import(rel, base, strict=True))
                for item in node.names:
                    if item.name == "*":
                        self.open.add("star import of " + base + " in " + rel)
                        continue
                    aliases[item.asname or item.name] = (
                        base + "." + item.name if base else item.name
                    )
                    found.extend(self._resolve_import(rel, base + "." + item.name, strict=False)
                                 if base else [])
        self._bind_assigned_aliases(rel)
        return found

    def _bind_assigned_aliases(self, rel: str) -> None:
        """Bind a name assigned from an import-rooted expression to that expression.

        ``module = subprocess`` makes ``module.run`` a subprocess call.  The binding is
        flow-insensitive and never overwrites an import, so it can only add effects.
        """
        aliases = self.imports[rel]
        changed = True
        while changed:
            changed = False
            for node in ast.walk(self.trees[rel]):
                if (
                    isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id not in aliases
                ):
                    dotted = self._qual(rel, node.value)
                    if dotted is not None:
                        aliases[node.targets[0].id] = dotted
                        changed = True

    def _absolute(self, rel: str, node: ast.ImportFrom) -> str | None:
        if node.level == 0:
            return node.module or ""
        parts = _dotted(rel).split(".")
        package = parts if rel.endswith("__init__.py") else parts[:-1]
        up = node.level - 1
        if up > len(package):
            return None
        base = ".".join(package[: len(package) - up] + ([node.module] if node.module else []))
        return base

    def _resolve_import(self, rel: str, dotted: str, *, strict: bool) -> list[str]:
        if not dotted:
            return []
        top = dotted.split(".")[0]
        if top != "verifier":
            if top not in _STDLIB:
                self.open.add("external import " + dotted + " in " + rel)
            return []
        found: list[str] = []
        parts = dotted.split(".")
        for index in range(1, len(parts) + 1):
            prefix_rel = _module_rel(self.root, ".".join(parts[:index]), self.absent)
            if prefix_rel is None:
                if index == len(parts) and strict:
                    self.open.add("unresolved import " + dotted + " in " + rel)
                continue
            found.append(prefix_rel)
        return found

    def load_closure(self, owned: tuple[str, ...]) -> None:
        pending: list[str] = []
        for rel in owned:
            pending.append(rel)
            parts = _dotted(rel).split(".")
            for index in range(1, len(parts)):
                ancestor = _module_rel(self.root, ".".join(parts[:index]), self.absent)
                if ancestor is not None:
                    pending.append(ancestor)
        self._load(pending)
        self._index()

    def _index(self) -> None:
        for rel, tree in self.trees.items():
            dotted = _dotted(rel)
            self.modules[dotted] = rel
            top: dict[str, ast.AST] = {}
            for stmt in tree.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    top[stmt.name] = stmt
                    if isinstance(stmt, ast.FunctionDef) and stmt.name == "__getattr__":
                        self.hooks[rel] = stmt
                    if isinstance(stmt, ast.ClassDef):
                        for member in stmt.body:
                            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                self.owner[id(member)] = (rel, stmt)
                    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.by_name.setdefault(stmt.name, []).append((rel, stmt))
            self.toplevel[rel] = top

    # -- reachability -----------------------------------------------------------

    def _enqueue(self, rel: str, node: ast.AST) -> None:
        if id(node) in self.owner:
            # A method runs only on an instance, so its class is instantiated.
            owner_rel, owner_class = self.owner[id(node)]
            self._mark_class(owner_rel, owner_class)
            return
        key = (rel, id(node))
        if key not in self.visited:
            self.visited.add(key)
            self.queue.append((rel, node))

    def _mark_class(self, rel: str, cls: ast.ClassDef) -> None:
        """Mark a class instantiated: its methods and closure bases become reachable."""
        key = (rel, cls.name)
        if key in self.instantiated:
            return
        self.instantiated.add(key)
        for base in cls.bases:
            dotted = self._qual(rel, base) if isinstance(base, ast.Attribute) else None
            if isinstance(base, ast.Name):
                local = self.toplevel[rel].get(base.id)
                if isinstance(local, ast.ClassDef):
                    self._mark_class(rel, local)
                    continue
                dotted = self.imports[rel].get(base.id)
            found = self._resolve(dotted) if dotted else None
            if found is not None and found[0] == "def" and isinstance(found[2], ast.ClassDef):
                self._mark_class(found[1], found[2])
        for member in cls.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key_member = (rel, id(member))
                if key_member not in self.visited:
                    self.visited.add(key_member)
                    self.queue.append((rel, member))

    def _enqueue_module_named(self, name: str) -> None:
        """Module-level functions named by a literal getattr; methods need an instance."""
        for rel, node in self.by_name.get(name, []):
            if id(node) not in self.owner:
                self._enqueue(rel, node)

    def _resolve(self, dotted: str) -> tuple[str, str, ast.AST | None] | None:
        """Resolve a dotted name to (kind, rel, node) inside the loaded closure."""
        parts = dotted.split(".")
        for index in range(len(parts), 0, -1):
            prefix = ".".join(parts[:index])
            rel = self.modules.get(prefix)
            if rel is None:
                continue
            rest = parts[index:]
            if not rest:
                return ("module", rel, None)
            node = self.toplevel[rel].get(rest[0])
            if node is None:
                return ("hook", rel, self.hooks.get(rel)) if len(rest) == 1 and rel in self.hooks else None
            if len(rest) == 1:
                return ("def", rel, node)
            if isinstance(node, ast.ClassDef) and len(rest) == 2:
                for member in node.body:
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name == rest[1]:
                        return ("def", rel, member)
            return None
        return None

    def _enqueue_resolved(self, dotted: str) -> None:
        found = self._resolve(dotted)
        if found is None:
            return
        kind, rel, node = found
        if kind == "def" and isinstance(node, ast.ClassDef):
            self._mark_class(rel, node)
        elif kind == "def" and node is not None:
            self._enqueue(rel, node)
        elif kind == "hook" and node is not None:
            self._enqueue(rel, node)

    def _site(self, rel: str, node: ast.AST, category: str) -> None:
        location = rel + ":" + str(getattr(node, "lineno", 0))
        self.sites.add(category + " " + location)
        if category == "DYNAMIC":
            self.open.add("dynamic site in " + location)
        else:
            self.effects.add(category)

    def _qual(self, rel: str, node: ast.expr) -> str | None:
        """Dotted name rooted at an import alias, or None for any other receiver."""
        if isinstance(node, ast.Name):
            return self.imports[rel].get(node.id)
        if isinstance(node, ast.Attribute):
            base = self._qual(rel, node.value)
            return None if base is None else base + "." + node.attr
        return None

    def _pattern_category(self, dotted: str) -> str | None:
        for pattern, category in _EFFECT_PATTERNS:
            if pattern.match(dotted):
                return category
        return None

    def _subprocess_category(self, rel: str, call: ast.Call) -> str:
        if any(
            item.arg == "shell" and isinstance(item.value, ast.Constant) and item.value.value is True
            for item in call.keywords
        ):
            return "PROCESS"
        if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
            return "PROCESS"
        argv = call.args[0].elts
        if not argv or not isinstance(argv[0], ast.Name) or not self._query_tool(rel, argv[0].id):
            return "PROCESS"
        tail = argv[1:]
        literals = [item.value for item in tail if isinstance(item, ast.Constant) and isinstance(item.value, str)]
        if len(literals) != len(tail):
            return "PROCESS"
        values = tuple(literals)
        return "PROCESS_QUERY" if values in _READONLY_ARGV_TAILS else "PROCESS"

    def _query_tool(self, rel: str, name: str) -> bool:
        """Whether name is bound to shutil.which of an admitted read-only query tool."""
        for node in ast.walk(self.trees[rel]):
            if (
                isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
                and isinstance(node.value, ast.Call)
                and self._qual(rel, node.value.func) == "shutil.which"
                and node.value.args
                and isinstance(node.value.args[0], ast.Constant)
                and node.value.args[0].value in _QUERY_TOOLS
            ):
                return True
        return False

    def _dotted_effect(self, rel: str, node: ast.AST, dotted: str, call: ast.Call | None) -> bool:
        """Record the effect of an import-rooted name; True when one was recorded."""
        if dotted.startswith("subprocess.") and call is not None and dotted.rsplit(".", 1)[-1] in _PROCESS_RUNNERS:
            self._site(rel, node, self._subprocess_category(rel, call))
            return True
        category = self._pattern_category(dotted)
        if category is not None:
            self._site(rel, node, category)
            return True
        return False

    def _attribute(self, rel: str, func: ast.Attribute, call: ast.Call | None) -> None:
        """Effects of an attribute access; closure callees follow from instantiation."""
        dotted = self._qual(rel, func)
        if dotted is not None:
            self._enqueue_resolved(dotted)
            if self._dotted_effect(rel, func, dotted, call):
                return
        category = _ATTRIBUTE_EFFECTS.get(func.attr)
        if func.attr == "replace" and call is not None and len(call.args) == 1:
            category = "FS_WRITE"
        if func.attr == "open" and call is not None and dotted is None:
            mode = call.args[0] if call.args else next(
                (item.value for item in call.keywords if item.arg == "mode"), None
            )
            category = _mode_category(mode)
        if category is not None:
            self._site(rel, func, category)

    def _bounded_names(self, node: ast.expr) -> list[str] | None:
        """Attribute names a getattr argument can take, or None when unbounded.

        A literal string is one name.  A loop variable over a literal tuple or list of
        strings is that finite set.  A dataclass field read, `field.name` for `field` in
        `fields(...)`, takes data-only names that no effect site depends on.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Name):
            return self._loop_literals(node.id)
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "name"
            and isinstance(node.value, ast.Name)
            and self._loop_over_fields(node.value.id)
        ):
            return []
        return None

    def _loop_literals(self, name: str) -> list[str] | None:
        values: set[str] = set()
        found = False
        for item in self.scope:
            if isinstance(item, (ast.For, ast.comprehension)) and isinstance(item.target, ast.Name) and item.target.id == name:
                if not isinstance(item.iter, (ast.Tuple, ast.List)):
                    return None
                literals = [
                    e.value for e in item.iter.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
                if len(literals) != len(item.iter.elts):
                    return None
                values.update(literals)
                found = True
        return sorted(values) if found else None

    def _loop_over_fields(self, name: str) -> bool:
        for item in self.scope:
            if (
                isinstance(item, (ast.For, ast.comprehension))
                and isinstance(item.target, ast.Name)
                and item.target.id == name
                and isinstance(item.iter, ast.Call)
                and isinstance(item.iter.func, ast.Name)
                and item.iter.func.id == "fields"
            ):
                return True
        return False

    def _builtin(self, rel: str, call: ast.Call, name: str) -> None:
        if name == "open":
            mode = call.args[1] if len(call.args) > 1 else next(
                (item.value for item in call.keywords if item.arg == "mode"), None
            )
            self._site(rel, call, _mode_category(mode))
        elif name == "breakpoint":
            self._site(rel, call, "TRACE")
        elif name in _BUILTIN_DYNAMIC:
            self._site(rel, call, "DYNAMIC")
        elif name in {"getattr", "setattr", "delattr"}:
            if len(call.args) < 2:
                self._site(rel, call, "DYNAMIC")
                return
            names = self._bounded_names(call.args[1])
            if names is None:
                self._site(rel, call, "DYNAMIC")
            else:
                for attribute in names:
                    self._enqueue_module_named(attribute)

    def _call(
        self,
        rel: str,
        call: ast.Call,
        entry_params: set[str],
        bindable: frozenset[str],
        dicts: dict[str, ast.Dict],
    ) -> None:
        func = call.func
        if (
            isinstance(func, ast.Call)
            and isinstance(func.func, ast.Name)
            and func.func.id == "type"
            and len(func.args) == 1
        ):
            # type(instance)(...) constructs the class of an instance that reached code
            # already holds, so that class is instantiated and its methods are reached.
            return
        if isinstance(func, ast.Name):
            name = func.id
            if name in entry_params:
                self._site(rel, call, "DYNAMIC")
            elif name in bindable:
                return
            elif name in self.imports[rel]:
                dotted = self.imports[rel][name]
                self._enqueue_resolved(dotted)
                self._dotted_effect(rel, call, dotted, call)
                if dotted.split(".")[0] == "verifier" and self._resolve(dotted) is None:
                    self.open.add("unresolved internal callee " + dotted + " in " + rel)
            elif name in self.toplevel[rel]:
                self._enqueue_resolved(_dotted(rel) + "." + name)
            elif name in _shared.STATIC_BUILTIN_NAMES:
                self._builtin(rel, call, name)
            else:
                self.open.add("unresolved callee " + name + " in " + rel)
        elif isinstance(func, ast.Attribute):
            self._attribute(rel, func, call)
        elif isinstance(func, ast.Lambda):
            return
        elif (
            isinstance(func, ast.Subscript)
            and isinstance(func.value, ast.Name)
            and func.value.id in dicts
            and all(isinstance(item, (ast.Lambda, ast.Name)) for item in dicts[func.value.id].values)
        ):
            # A call through a local dict literal reaches only its own lambdas or names,
            # which the surrounding scope scan already walks and references.
            return
        else:
            self.open.add("computed callee in " + rel + ":" + str(getattr(call, "lineno", 0)))

    def _reference(self, rel: str, node: ast.expr) -> None:
        if isinstance(node, ast.Attribute):
            self._attribute(rel, node, None)
        elif isinstance(node, ast.Name):
            dotted = self.imports[rel].get(node.id)
            if dotted is not None:
                self._enqueue_resolved(dotted)
                self._dotted_effect(rel, node, dotted, None)
            elif node.id in self.toplevel[rel]:
                self._enqueue_resolved(_dotted(rel) + "." + node.id)
            elif node.id in _BUILTIN_DYNAMIC:
                self._site(rel, node, "DYNAMIC")

    def _data_file(self, rel: str, files_call: ast.Call, joined: ast.Call) -> None:
        """Bind one files(package).joinpath(literal) resource read to its data digest."""
        package = files_call.args[0] if files_call.args else None
        parts = list(joined.args)
        if not (
            isinstance(package, ast.Constant)
            and isinstance(package.value, str)
            and parts
            and all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in parts)
        ):
            self.open.add("dynamic resource in " + rel)
            return
        package_name = package.value if isinstance(package, ast.Constant) and isinstance(package.value, str) else ""
        names = [item.value for item in parts if isinstance(item, ast.Constant) and isinstance(item.value, str)]
        data_rel = "src/" + "/".join(package_name.split(".")) + "/" + "/".join(names)
        path = _ordinary_file(self.root, data_rel)
        if path is None:
            self.absent.add(data_rel)
            self.open.add("unreadable data " + data_rel)
            return
        self.data[data_rel] = "sha256:" + sha256(path.read_bytes()).hexdigest()
        self.effects.add("FS_READ")

    def _process(self, rel: str, nodes: list[ast.AST], entry_params: set[str], bindable: frozenset[str]) -> None:
        calls = [node for node in nodes if isinstance(node, ast.Call)]
        call_positions = {id(call.func) for call in calls}
        dicts: dict[str, ast.Dict] = {}
        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Dict):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        dicts[target.id] = node.value
        handled: set[int] = set()
        self.scope = nodes
        for call in calls:
            if isinstance(call.func, ast.Attribute) and call.func.attr == "joinpath":
                inner = call.func.value
                if isinstance(inner, ast.Call) and self._qual(rel, inner.func) == "importlib.resources.files":
                    handled.add(id(inner))
                    self._data_file(rel, inner, call)
        for call in calls:
            if id(call) in handled:
                continue
            if self._qual(rel, call.func) == "importlib.resources.files":
                self.open.add("dynamic resource in " + rel)
                continue
            self._call(rel, call, entry_params, bindable, dicts)
        for node in nodes:
            if isinstance(node, ast.Global):
                self.effects.add("GLOBAL_STATE")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.startswith("/dev/") or node.value.startswith("\\\\.\\"):
                    self._site(rel, node, "HARDWARE")
            elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
                if id(node) not in call_positions:
                    self._reference(rel, node)

    def drain(self, entries: list[tuple[str, ast.AST | None]]) -> None:
        for rel, node in entries:
            if node is None:
                self.visited.add((rel, 0))
                self.queue.append((rel, None))
            else:
                self._enqueue(rel, node)
        while self.queue:
            rel, node = self.queue.pop()
            if node is None:
                nodes = _executed_nodes(self.trees[rel])
                entry_params: set[str] = set()
            else:
                nodes = list(ast.walk(node))
                entry_params = _arg_names(node) if id(node) in self.entry_ids else set()
            bindable = _bindable(nodes)
            self._process(rel, nodes, entry_params, bindable)

    def finish(self) -> _Closure:
        for tree in self.trees.values():
            containers: set[str] = set()
            for stmt in tree.body:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, (ast.Dict, ast.List, ast.Set)):
                    containers.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
                elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                    if isinstance(stmt.value.func, ast.Name) and stmt.value.func.id in _CONTAINER_BUILDERS:
                        containers.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
            if not containers:
                continue
            # Import-time initialization runs once per process; only mutation inside
            # function bodies can accumulate state across invocations.
            initialization = {id(node) for node in _executed_nodes(tree)}
            for node in ast.walk(tree):
                if id(node) in initialization:
                    continue
                if isinstance(node, (ast.Assign, ast.AugAssign, ast.Delete)):
                    targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
                    for target in targets:
                        base = target.value if isinstance(target, ast.Subscript) else target
                        if isinstance(base, ast.Name) and base.id in containers:
                            self.effects.add("GLOBAL_STATE")
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    base = node.func.value
                    if node.func.attr in _MUTATORS and isinstance(base, ast.Name) and base.id in containers:
                        self.effects.add("GLOBAL_STATE")
        files = {**self.digests, **self.data}
        status = "OPEN" if self.open else "CLOSED"
        payload = {
            "status": status,
            "files": sorted(files.items()),
            "effects": sorted(self.effects),
            "open": sorted(self.open),
        }
        fingerprint = "sha256:" + sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return _Closure(
            status=status,
            fingerprint=fingerprint,
            effects=frozenset(self.effects),
            sites=tuple(sorted(self.sites)),
            open_reasons=tuple(sorted(self.open)),
            files=tuple(sorted(files.items())),
            absent=tuple(sorted(self.absent)),
        )


# Recent closures per owned-path tuple.  A candidate is reused only after every digest and
# probed absence it pins is revalidated against the root being reviewed, so the memo is
# keyed by content, not by location.
_CLOSURE_MEMO: dict[tuple[str, ...], list[_Closure]] = {}
_MEMO_DEPTH = 8


def _closure_is_current(root: Path, closure: _Closure) -> bool:
    """Whether every digest and absence a closure depends on still holds."""
    for rel, digest in closure.files:
        path = _ordinary_file(root, rel)
        if path is None:
            return False
        if "sha256:" + sha256(path.read_bytes()).hexdigest() != digest:
            return False
    return all(_ordinary_file(root, rel) is None for rel in closure.absent)


def _owner_closure(root: Path, owned: tuple[str, ...]) -> _Closure:
    """Scan one owner's execution closure from its owned sources, failing closed.

    Entries are module-level code of every loaded module (it runs at import), the owned
    module's top-level functions (called by the CLI with argparse data), and the owned
    classes, which are instantiated so that their methods are reached.  A memoized
    closure is reused only while every file digest and probed absence still holds.
    """
    for candidate in _CLOSURE_MEMO.get(owned, []):
        if _closure_is_current(root, candidate):
            return candidate
    scan = _ClosureScan(root)
    scan.load_closure(owned)
    entries: list[tuple[str, ast.AST | None]] = []
    classes: list[tuple[str, ast.ClassDef]] = []
    owned_set = set(owned)
    for rel, tree in scan.trees.items():
        entries.append((rel, None))
        if rel not in owned_set:
            continue
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scan.entry_ids.add(id(stmt))
                entries.append((rel, stmt))
            elif isinstance(stmt, ast.ClassDef):
                scan.entry_ids.update(
                    id(member)
                    for member in stmt.body
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                )
                classes.append((rel, stmt))
    for rel, cls in classes:
        scan._mark_class(rel, cls)
    scan.drain(entries)
    closure = scan.finish()
    # Only a CLOSED scan pins every owned source.  An OPEN scan of an unreadable source
    # pins nothing, so it would validate against any root and poison later reviews.
    if closure.status == "CLOSED":
        recent = _CLOSURE_MEMO.setdefault(owned, [])
        recent.insert(0, closure)
        del recent[_MEMO_DEPTH:]
    return closure


def _default_root() -> Path:
    """Repository root that contains this module's sources (src/verifier/runtime)."""
    return Path(__file__).resolve().parents[3]


def apply_package_semantic_review_hardware_cli(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply all five current-source reviews atomically to a deep copy."""
    selected_root = Path(root).resolve(strict=True)
    if not selected_root.is_dir():
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_ROOT_INVALID")
    if type(rows) is not dict:
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_ROWS_INVALID")
    if type(files) is not dict or any(
        type(path) is not str
        or type(digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_FILES_INVALID")

    live_obligations = {
        kind: {
            row["id"]: tuple(row["declaration_fields"])
            for row in _contract_rows(kind)
        }
        for kind in REVIEW_KINDS
    }
    known_obligations = {
        name for values in live_obligations.values() for name in values
    }
    closures = {
        object_id: _owner_closure(selected_root, review.owned_paths)
        for object_id, review in _REVIEWS.items()
    }
    plans: dict[str, dict[str, Any]] = {}
    for object_id, review in _REVIEWS.items():
        row = rows.get(object_id)
        if type(row) is not dict:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_OBJECT_MISSING:" + object_id)
        if row.get("object_id") != object_id or row.get("kind") != review.primary_kind:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_PRIMARY_KIND_DIFFERS:" + object_id
            )
        owned = _shared._owned_file_paths(row)
        if owned != set(review.owned_paths):
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_OWNERSHIP_DIFFERS:" + object_id)
        current = _current_evidence(
            selected_root, review.owned_paths, files, object_id=object_id
        )
        evidence_by_path = {item["path"]: item for item in current}

        classification = row.get("classification")
        obligations = row.get("obligations")
        specializations = row.get("specializations")
        if type(classification) is not dict or type(obligations) is not dict:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + object_id)
        if (
            type(specializations) is not list
            or any(type(kind) is not str for kind in specializations)
            or len(specializations) != len(set(specializations))
        ):
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID:" + object_id
            )
        for kind in REVIEW_KINDS:
            if _basis(review, kind, closures[object_id]) != "APPLIES" and (
                row["kind"] == kind or kind in specializations
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id + ":" + kind
                )
        for name in obligations:
            if (
                type(name) is not str
                or name.split("-", 1)[0] in REVIEW_KINDS
                and name not in known_obligations
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN:"
                    + object_id
                    + ":"
                    + str(name)
                )

        preserve_decisions: set[str] = set()
        preserve_obligations: set[str] = set()
        remove_obligations: set[str] = set()
        unresolved_candidates: dict[str, list[dict[str, str]]] = {}
        for kind in REVIEW_KINDS:
            basis = _basis(review, kind, closures[object_id])
            decision = classification.get(kind)
            if basis == "UNRESOLVED":
                code = (
                    "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:"
                    + object_id
                    + ":"
                    + kind
                )
                # A complete APPLIES or DOES_NOT_APPLY row that this catalog no
                # longer establishes is stale or forged; it is never erased into
                # UNRESOLVED without an operator clearing it.
                if decision is not None and not _shared._unresolved_decision(
                    decision,
                    files,
                    owned,
                    kind=kind,
                    code=code,
                ):
                    raise ValueError(code)
                if (
                    _shared._unresolved_decision(
                        decision,
                        files,
                        owned,
                        kind=kind,
                        code=code,
                    )
                    and decision is not None
                    and decision["evidence"]
                ):
                    unresolved_candidates[kind] = [
                        deepcopy(evidence_by_path[item["path"]])
                        for item in decision["evidence"]
                    ]
            else:
                paths = (
                    review.role_paths[kind]
                    if basis == "APPLIES"
                    else review.owned_paths
                )
                expected_decision = {
                    "status": basis,
                    "reason": _reason(review, kind, closures[object_id]),
                    "evidence": [
                        deepcopy(evidence_by_path[path]) for path in paths
                    ],
                }
                if _shared._preserve_explicit_decision(
                    decision,
                    expected_decision,
                    files,
                    owned,
                    object_id=object_id,
                    kind=kind,
                ):
                    preserve_decisions.add(kind)
            for obligation_id, fields in live_obligations[kind].items():
                binding = obligations.get(obligation_id)
                if basis == "APPLIES":
                    expected_evidence = [
                        deepcopy(evidence_by_path[path])
                        for path in review.role_paths[kind]
                    ]
                    if _shared._preserve_explicit_obligation(
                        binding,
                        fields,
                        _obligation_reason(review, kind),
                        expected_evidence,
                        files,
                        owned,
                        object_id=object_id,
                        obligation_id=obligation_id,
                    ):
                        preserve_obligations.add(obligation_id)
                elif binding is not None:
                    prefix = (
                        "PACKAGE_SEMANTIC_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                        if basis == "DOES_NOT_APPLY"
                        else "PACKAGE_SEMANTIC_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
                    )
                    code = prefix + object_id + ":" + obligation_id
                    if not _shared._blank_obligation(
                        binding,
                        fields,
                        files,
                        owned,
                        code=code,
                    ):
                        raise ValueError(code)
                    remove_obligations.add(obligation_id)

        plans[object_id] = {
            "opening_evidence": current,
            "evidence_by_path": evidence_by_path,
            "preserve_decisions": preserve_decisions,
            "preserve_obligations": preserve_obligations,
            "remove_obligations": remove_obligations,
            "unresolved_candidates": unresolved_candidates,
        }

    # Re-read the whole six-path denominator only after all semantic checks pass.
    # Concurrent source drift can therefore never yield a partly current review.
    for object_id, review in _REVIEWS.items():
        closing = _source_evidence(selected_root, review.owned_paths)
        if closing != plans[object_id]["opening_evidence"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)
        # The closure reads modules outside the owned census, so its fingerprint is
        # rechecked too: a drifted import or data file fails the whole application.
        if not _closure_is_current(selected_root, closures[object_id]):
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)

    result = deepcopy(rows)
    for object_id, review in _REVIEWS.items():
        row = result[object_id]
        plan = plans[object_id]
        closure = closures[object_id]
        declarations = _declarations(review)
        for kind in REVIEW_KINDS:
            if kind in plan["preserve_decisions"]:
                continue
            basis = _basis(review, kind, closure)
            if basis == "UNRESOLVED":
                row["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": _unresolved_reason(kind),
                    "evidence": deepcopy(
                        plan["unresolved_candidates"].get(kind, [])
                    ),
                }
            else:
                paths = (
                    review.role_paths[kind]
                    if basis == "APPLIES"
                    else review.owned_paths
                )
                row["classification"][kind] = {
                    "status": basis,
                    "reason": _reason(review, kind, closure),
                    "evidence": [
                        deepcopy(plan["evidence_by_path"][path]) for path in paths
                    ],
                }
        for name in plan["remove_obligations"]:
            row["obligations"].pop(name, None)
        for name, declaration in declarations.items():
            if name in plan["preserve_obligations"]:
                continue
            kind = name.split("-", 1)[0]
            row["obligations"][name] = {
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
    return result


__all__ = [
    "CLAIM_BOUNDARY",
    "HARDWARE_CLI_OBJECT_IDS",
    "OBLIGATION_RETENTION_APPLIES",
    "REVIEW_KINDS",
    "apply_package_semantic_review_hardware_cli",
    "obligation_retention_reason",
    "review_document",
]
