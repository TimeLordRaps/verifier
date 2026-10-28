"""Current-source Tier-0 reviews for nine consequential subject mechanisms.

Terminology: Concise Binary Object Representation (CBOR); CBOR Object Signing
and Encryption (COSE); central processing unit (CPU); JavaScript Object Notation
(JSON); Supply Chain Integrity, Transparency, and Trust (SCITT); Secure Hash
Algorithm 256-bit (SHA-256); Secure Hash Algorithm 3 256-bit (SHA3-256); Verifier
Standard (VSTD).

These reviews close one repository-admission question for exact path-owned
objects: which of the twelve consequential namespace kinds apply, which are
literally refuted, which remain UNRESOLVED, and which current source bytes support
each Tier-0 declaration.  APPLIES and DOES_NOT_APPLY come only from explicit
per-object catalog entries; a kind absent from both is UNRESOLVED, never refuted
by absence or complement.  These reviews do not execute the mechanisms, establish
application-wide correctness, prove physical confinement, authorize real-money
effects, or establish Tier-1-plus conformance.  A DOES_NOT_APPLY refutation of any
kind requires a CLOSED live screen over the owned closure: a subprocess, network,
device, reflection, dynamic-code, or filesystem-write site reachable through owned
imports or calls keeps that cell UNRESOLVED.  The screen is shared with the records
review, and no refutation is decided from lexical absence alone.

Application is pure, atomic, and fail closed.  The complete source denominator
is checked against the caller's digest census before and after semantic
preflight.  Compatible complete reviews are preserved; stale, contradictory,
partially filled, mislabeled, or unowned bindings abort the entire operation.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS
from verifier.runtime.package_semantic_review_records import (
    EXTERNAL_EFFECT_KINDS as EXTERNAL_EFFECT_KINDS,  # public test contract
    SurfaceScreen,
    closed_surface_screen,
    screen_blocks,
)


REVIEW_KINDS = _shared.REVIEW_KINDS

SUBJECT_OBJECT_IDS = (
    "vstd-artifact-control-lifecycle",
    "vstd-privacy-emission-policy",
    "vstd-logit-constraint-controller",
    "vstd-hardware-resource-accounting",
    "vstd-software-diode-effect",
    "vstd-component-package-storage",
    "vstd-hardware-receipt-publication",
    "vstd-deriver-process-exchange",
    "vstd-scitt-evidence-protocol",
)

CLAIM_BOUNDARY = (
    "Current-source Tier-0 applicability and declaration review for these nine "
    "path-owned objects only. It does not establish mechanism execution or truth, "
    "application-wide correctness or polish, physical confinement, real-money "
    "authority or effects, Tier-1-plus conformance, publication, release, or deployment."
)


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    profile: _shared._Profile
    refuted: Mapping[str, str]
    demoted: frozenset[str] = frozenset()


def _ledger(profile: _shared._Profile) -> dict[str, dict[str, str]]:
    """Declare the privacy accountant's live state without inventing a journal."""
    return {
        "LEDGER-0.1-authoritative-history": {
            "history": (
                "One DifferentialPrivacyBudget instance retains only current cumulative "
                "epsilon, delta, and successful-emission count; it retains no per-entry "
                "journal or durable history."
            ),
            "state": profile.states,
            "ordering": profile.ordering,
            "authority": profile.authority,
        },
        "LEDGER-0.2-accounting-invariants": {
            "units": profile.units,
            "balance_rules": (
                "Every value must be finite and nonnegative, delta must remain within "
                "[0, 1], prior state must already be valid, and a consume call may not "
                "raise either cumulative value above its configured maximum."
            ),
            "rounding": (
                "The implementation uses Python floating-point addition and max; it "
                "defines no decimal rounding, tolerance, or cross-runtime exactness."
            ),
            "sources_and_sinks": (
                "A successful consume call adds caller-supplied epsilon and delta and "
                "increments the count. There is no decrement, redemption, transfer, "
                "or correction operation on the instance."
            ),
        },
        "LEDGER-0.3-correction-and-recovery": {
            "corrections": (
                "No correction history exists. Replacing or resetting a mutable budget "
                "is caller action and cannot be represented as a reconciled correction."
            ),
            "replay": profile.retry,
            "reconciliation": (
                "Returned remaining values are recomputed from current counters and "
                "configured maxima; no durable or concurrent external record is reconciled."
            ),
            "recovery": profile.recovery,
        },
    }


def _transaction(profile: _shared._Profile) -> dict[str, dict[str, str]]:
    return {
        "TRANSACTION-0.1-effects-and-authority": {
            "effects": profile.effects,
            "preconditions": profile.inputs,
            "authorization": profile.authority,
            "resources": profile.targets,
        },
        "TRANSACTION-0.2-commit-and-failure": {
            "commit": profile.commit,
            "abort": profile.failure,
            "finality": (
                profile.commit
                + " Finality is limited to the named local state and grants no "
                "application-wide correctness, publication, physical, or financial authority."
            ),
            "partial_failure": profile.failure,
        },
        "TRANSACTION-0.3-retry-and-replay": {
            "duplicate_detection": profile.retry,
            "idempotency": (
                profile.retry
                + " These are the exact retry semantics; no broader idempotency is inferred."
            ),
            "retry_limits": profile.limits,
            "replay": profile.recovery,
        },
    }


def _asset(profile: _shared._Profile) -> dict[str, dict[str, str]]:
    """Declare the bounded resource claim without implying legal ownership."""
    return {
        "ASSET-0.1-identity-and-quantity": {
            "identity": profile.targets,
            "rights": profile.authority,
            "units": profile.units,
            "precision": profile.limits,
        },
        "ASSET-0.2-issuance-and-redemption": {
            "issuance_authority": (
                "No issuance authority is implemented. The supplied fleet manifest is "
                "only the local comparison authority for declared computational capacity."
            ),
            "supply_changes": (
                "This pure function neither issues nor destroys capacity; a different "
                "supplied manifest or identity set is a new input, not a supply event."
            ),
            "redemption": (
                "No redemption operation exists; correcting supplied records and rerunning "
                "does not restore or transfer a real resource right."
            ),
            "backing_claims": profile.boundary,
        },
        "ASSET-0.3-custody-and-encumbrance": {
            "custody": profile.states,
            "control": profile.commands,
            "encumbrances": profile.failure,
            "reconciliation": profile.observations,
        },
    }


def _measurement(profile: _shared._Profile) -> dict[str, dict[str, str]]:
    return {
        "MEASUREMENT-0.1-phenomenon-and-method": {
            "phenomenon": profile.observations,
            "method": profile.mechanism,
            "source": profile.inputs,
            "observation_vs_estimate": profile.boundary,
        },
        "MEASUREMENT-0.2-units-time-and-uncertainty": {
            "units": profile.units,
            "reference_frame": profile.targets,
            "observation_time": profile.timing,
            "arrival_time": profile.timing,
            "uncertainty": profile.boundary,
        },
        "MEASUREMENT-0.3-validity-and-missingness": {
            "validity": profile.limits,
            "missingness": profile.failure,
            "freshness": profile.timing,
            "provenance": profile.mechanism,
        },
    }


def _sensor(profile: _shared._Profile) -> dict[str, dict[str, str]]:
    return {
        "SENSOR-0.1-acquisition-and-observations": {
            "acquisition": profile.mechanism,
            "phenomena": profile.observations,
            "measurements": profile.units,
            "deployment": profile.targets,
        },
        "SENSOR-0.2-calibration-and-envelope": {
            "calibration_applicability": (
                "Physical calibration is not applicable to this software-interface "
                "acquisition; source and dependency identities are compatibility bindings."
            ),
            "calibration_evidence": (
                "No physical calibration evidence is present. The bounded mechanism is: "
                + profile.mechanism
            ),
            "operating_range": profile.limits,
            "drift": profile.timing,
        },
        "SENSOR-0.3-sampling-and-faults": {
            "sampling": profile.observations,
            "latency": profile.timing,
            "fault_detection": profile.failure,
            "recovery": profile.recovery,
        },
    }


def _policy(profile: _shared._Profile) -> dict[str, dict[str, str]]:
    return {
        "POLICY-0.1-rules-and-precedence": {
            "scope": profile.scope,
            "decision_inputs": profile.inputs,
            "precedence": profile.ordering,
            "defaults": profile.failure,
        },
        "POLICY-0.2-authority-and-exceptions": {
            "authority": profile.authority,
            "exceptions": profile.limits,
            "revisions": (
                profile.mechanism
                + " Current shipped source and explicit configuration define this "
                "revision; no implicit or remote revision authority is inferred."
            ),
            "activation": profile.states,
        },
        "POLICY-0.3-enforcement-and-decisions": {
            "enforcement_points": profile.mechanism,
            "decision_evidence": profile.observations,
            "bypass_handling": profile.limits,
            "unavailable_behavior": profile.failure,
        },
    }


_DECLARATION_BUILDERS = dict(_shared._DECLARATION_BUILDERS)
_DECLARATION_BUILDERS.update(
    {
        "LEDGER": _ledger,
        "TRANSACTION": _transaction,
        "ASSET": _asset,
        "MEASUREMENT": _measurement,
        "SENSOR": _sensor,
        "POLICY": _policy,
    }
)


def _review(
    primary_kind: str,
    owned_paths: tuple[str, ...],
    applicable: tuple[str, ...],
    profile: _shared._Profile,
    role_paths: Mapping[str, tuple[str, ...]] | None = None,
    *,
    refuted: Mapping[str, str],
) -> _Review:
    """Bind one object's literal APPLIES and DOES_NOT_APPLY catalog entries.

    Kinds named in neither mapping are UNRESOLVED.  Nothing is inferred from the
    complement of the applicable set or from an absent refutation.
    """
    return _Review(
        primary_kind=primary_kind,
        owned_paths=owned_paths,
        applicable=applicable,
        role_paths=(
            {kind: owned_paths for kind in applicable}
            if role_paths is None
            else dict(role_paths)
        ),
        profile=profile,
        refuted=dict(refuted),
    )


def _reason(profile: _shared._Profile, kind: str, applies: bool) -> str:
    """Return the literal APPLIES reason; refutations are never generated here."""
    if applies:
        necessity = {
            "LEDGER": (
                "Its mutable cumulative epsilon, delta, and count state needs explicit "
                "accounting and recovery semantics even though it retains no journal, "
                "is not durable, and is not concurrency-safe."
            ),
            "TRANSACTION": (
                "Its named local change, response-dependent finality, retry behavior, "
                "and partial-failure state require an explicit transaction boundary."
            ),
            "ASSET": (
                "Its supplied capacity identities and quantities need explicit units, "
                "allocation, backing, and reconciliation boundaries; this is a "
                "computational resource claim, not legal title or live custody."
            ),
            "MEASUREMENT": (
                "Its returned values distinguish exact software-interface observations "
                "from physical, child-internal, or external state that was not observed."
            ),
            "SENSOR": (
                "Its software-interface acquisition produces bounded digital observations "
                "with distinct applicability, range, latency, and fault semantics."
            ),
            "CONTROLLER": (
                "Its state, feedback, admission decisions, commands, timing, and "
                "intervention behavior form a bounded software control loop."
            ),
            "ACTUATOR": (
                "It accepts a command and changes the named local target while keeping "
                "downstream, physical, and external effects explicitly separate."
            ),
            "PROTOCOL": (
                "Its named participants, ordered states and transitions, compatibility, "
                "replay, failure, progress, and recovery form a protocol boundary; a "
                "network or cross-process exchange is not inferred unless declared."
            ),
            "POLICY": (
                "Its rule selection, authority, defaults, exceptions, and enforcement "
                "points decide whether the bounded consequential operation may proceed."
            ),
        }[kind]
        return profile.name + " applies as " + kind + ". " + necessity
    raise AssertionError(kind + " has no literal APPLIES reason")


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


_ARTIFACT_CONTROL = _profile(
    name="The artifact freeze/seal/thaw lifecycle",
    scope="Local preservation of exact file or directory bytes through freeze, optional Ed25519 seal, verification, and copy-on-write thaw operations.",
    mechanism="Canonical JSON, SHA-256 and SHA3-256 identities, exclusive staging/rename, portable read-only guards, and finite Ed25519 seal records implement the local lifecycle.",
    participants="A local caller, the selected source and destination filesystem paths, configured Ed25519 key material, and the verification routine in the same module participate.",
    inputs="Exact source bytes, normalized relative paths, freeze/seal records, local filesystem metadata, and explicitly supplied key bytes are preconditions.",
    authority="Authority is limited to the local caller's path access and explicitly supplied signing key; a valid seal establishes neither ownership nor authorization.",
    states="The represented states are source selected, freeze staged, frozen, verified, sealed, thawed descendant, or refused with retained parent unchanged.",
    ordering="Freeze must complete before verification or sealing; seals close one verified freeze; thaw creates a new descendant and never mutates the frozen parent.",
    commands="Freeze, seal, verify, and thaw commands select one bounded local lifecycle transition.",
    targets="Targets are the exact selected source, frozen bundle, seal directory, thaw destination, and sidecar records on the local filesystem.",
    effect_domains="LOCAL_FILESYSTEM_ARTIFACT_LIFECYCLE_ONLY",
    effects="A successful operation creates a frozen bundle, an exclusive seal record, or a separate mutable descendant; it does not alter the frozen parent's content.",
    commit="Freeze commits when the complete staging directory is renamed to an absent destination; seal and thaw sidecar records use exclusive creation, but the operations are not one application-wide transaction.",
    retry="Existing destinations and conflicting seal identities refuse rather than overwrite; a retry is a fresh verification and explicitly selected new operation.",
    timing="The implementation records declared lifecycle times but establishes no freshness, distributed ordering, or real-time completion guarantee.",
    limits="Paths, ordinary-file rules, canonical records, digest equality, read-only guards, key form, and absent destinations bound accepted operations.",
    observations="Verification recomputes artifact bytes, guards, manifests, seal signatures, identities, and thaw-descendant status at the selected local paths.",
    units="Units are exact bytes, file entries, canonical records, digest identities, and discrete lifecycle operations; no physical or monetary unit is represented.",
    failure="Malformed records, path escape, special files, source drift, digest or signature mismatch, guard failure, collision, or write error refuses the selected transition.",
    recovery="Recovery requires correcting the local source, key, record, guard, or destination and starting a new operation; accepted history is not silently rewritten.",
    boundary="Identity and local lifecycle closure are represented; correctness, freshness, ownership, external anchoring, crash durability, authorization, physical isolation, and application polish are not established.",
)


_PRIVACY_EMISSION = _profile(
    name="The bounded privacy-emission evaluator",
    scope="Local admission of certificate fields and co-emissions against declared disclosure bounds, observer context, contextual norms, differential-privacy budget, consent, and governance inputs.",
    mechanism="The evaluator snapshots finite plain inputs, applies field bounds and composition screens, consumes an in-memory budget when requested, and emits digest-bound local decisions and receipts.",
    participants="The local caller supplies a certificate, disclosure surface, observer, bounds, policy inputs, and optional co-emissions to the in-process evaluators.",
    inputs="Finite captured certificate bytes, explicit disclosure bounds, observer context, join rules, consent/governance facts, and any mutable budget state are the decision inputs.",
    authority="Only caller-supplied policy, consent, observer, governance, and in-memory budget configuration authorizes a local decision; the receipt is not its own authority.",
    states="States include uncaptured, captured, admitted, refused, budget available/exhausted, receipt emitted, and replay matched or rejected.",
    ordering="Input capture precedes evaluation; composition and field checks precede emission; budget consumption advances cumulative epsilon, delta, and count in call order.",
    commands="Evaluate, consume budget, redact, admit, refuse, emit a local certificate projection, or recheck a prior bounded result.",
    targets="Targets are in-memory certificate projections, privacy budget counters, and returned local decision/receipt records; no network recipient is contacted.",
    effect_domains="IN_PROCESS_DISCLOSURE_DECISION_AND_MEMORY_ONLY",
    effects="Evaluation can mutate the supplied in-memory budget counters and return admitted/redacted bytes plus a receipt; it performs no publication, network call, or atomic invocation consumption.",
    commit="A successful call returns one bound local result after all configured checks and any budget consumption; no durable, concurrent, or cross-process commit is provided.",
    retry="A repeated call is a new evaluation and may consume a mutable budget again; callers must coordinate shared state and cannot infer idempotency from matching inputs.",
    timing="Evaluation uses the supplied context and optional selected time; it establishes neither external observation time nor cross-thread serialization.",
    limits="Finite JSON shape/bytes, exact bound coverage, allowed observers, composition screens, nonnegative finite epsilon/delta, and configured maxima bound admission.",
    observations="The returned decision records selected fields, redactions, bound identifiers, composition-screen outcomes, budget totals, digests, and explicit refusal reasons.",
    units="Disclosure accounting uses dimensionless epsilon and delta plus discrete emission and byte/field counts; it does not establish that a mechanism is differentially private.",
    failure="Missing bounds, observer mismatch, unsafe composition, malformed input, budget exhaustion, concurrent mutation, or replay mismatch fails closed without external emission.",
    recovery="Recovery requires corrected current inputs or an explicitly coordinated fresh budget/evaluation; callers may not treat a reset mutable object as reconciled history.",
    boundary="This is local in-memory decision and accounting logic. It does not transmit data, prove recipient behavior, provide durable or concurrent accounting, establish differential privacy, or promote application conformance.",
)


_LOGIT_CONSTRAINT = _profile(
    name="The native logit-constraint controller",
    scope="One in-process constrained-decoding session binds a native constraint, tokenizer, per-step token mask, accepted-token transitions, and optional post-validation trace.",
    mechanism="The selected llguidance backend compiles JSON Schema, regex, or Lark source, reads matcher state, masks one logits row, consumes selected token identifiers, and records a canonical trace.",
    participants="The caller, native constraint compiler/matcher, bound tokenizer, mutable logits tensor, selected token stream, and optional post-validator participate.",
    inputs="Constraint source, tokenizer identity/digest, current matcher state, logits shape, sampled token identifiers, accepted output bytes, and validator result drive transitions.",
    authority="Authority is the caller's explicit backend, tokenizer, constraint, and validator selection; trace identity does not prove compiler fidelity or model safety.",
    states="States include source selected, compiled, matcher active, mask observed, token accepted/rejected, accepting/stopped, post-validated, and failed closed.",
    ordering="Compile precedes session creation; each mask observation precedes its sample; accepted tokens advance matcher state in strict step order; optional validation follows output formation.",
    commands="Compile constraint, query mask, replace disallowed logits with negative infinity, consume a token, stop, and post-validate output.",
    targets="Targets are the selected native matcher state, one supplied logits row, accepted-token prefix, and the resulting bounded trace.",
    effect_domains="IN_PROCESS_LOGIT_TENSOR_AND_MATCHER_STATE_ONLY",
    effects="Masking mutates supplied logits in place and token acceptance advances the native matcher; no model weights, sampler, process, physical device, or external service is controlled.",
    commit="A token transition commits only when the matcher accepts it and the observation is appended; the trace outcome is local and not an application transaction.",
    retry="Compilation or a session may be restarted from the same bound source; matcher state is not silently rewound and trace identity does not make sampling idempotent.",
    timing="Steps have deterministic ordinal indexes but no wall-clock deadline, real-time stability, or external event-time guarantee.",
    limits="Supported constraint kinds, exact vocabulary shape, one logits row, finite token identifiers, matcher status, mask length, and optional validator binding bound operation.",
    observations="The controller records packed-mask digest and cardinality, prefix length, accepting/stopped flags, token acceptance, outcome, output digest, and validator result.",
    units="Units are token identifiers, vocabulary and allowed-token counts, step indexes, packed-mask bytes, logits positions, and SHA-256 digests.",
    failure="Compiler warnings/errors, mask mismatch, tensor shape mismatch, rejected token, matcher error, incomplete mask coverage, or failed post-validation fails closed.",
    recovery="Recovery starts a fresh compiled session or corrects the exact source/tokenizer/output; rejected transitions are not reclassified as accepted.",
    boundary="The seam constrains one local decoding path. It does not prove source-to-grammar fidelity, sampler behavior, model correctness, sandboxing, physical actuation, or whole-application policy enforcement.",
)


_HARDWARE_ACCOUNTING = _profile(
    name="The supplied hardware fleet and partition accountant",
    scope="Pure validation and aggregation of caller-supplied fleet membership, logical-device capacity fractions, and compute quantity records.",
    mechanism="Set comparison checks manifest membership while Decimal aggregation maps logical scopes to physical parents and rejects mixed or over-allocated accounting.",
    participants="The caller supplies fleet manifests, fleet observations, logical identities, and compute-accounting observations to pure in-process functions.",
    inputs="Already supplied typed records, member identifiers, parent-device identifiers, capacity fractions, quantity names, values, and units are the complete inputs.",
    authority="The supplied manifest is the local comparison authority only; the module authenticates neither its issuer nor physical devices, ownership, custody, or allocation rights.",
    states="Results are valid or invalid fleet comparison and aggregated totals with explicit errors; no durable fleet or asset state is owned.",
    ordering="Input iteration and sorted result projection provide deterministic aggregation; no temporal observation sequence or posting history is represented.",
    commands="Compare expected and observed members, map logical scopes, sum like-unit quantities, and refuse overlapping logical/physical accounting.",
    targets="Targets are supplied member and device identities plus per-parent, quantity-name, and unit total keys in the returned result.",
    effect_domains="PURE_SUPPLIED_RECORD_VALIDATION_ONLY",
    effects="The functions return validation errors and aggregate totals without querying hardware, reserving capacity, issuing rights, moving custody, or persisting state.",
    commit="There is no external commit; one pure result is complete only for the supplied finite records.",
    retry="Re-evaluation is deterministic for equivalent supplied records and creates no duplicate external effect.",
    timing="The records contain no acquisition performed here and the module establishes no observation time, freshness, sampling cadence, or latency.",
    limits="Unique identifiers, exact manifest binding, disjoint logical/physical scopes, capacity fractions no greater than one million parts per million, and like-unit keys bound aggregation.",
    observations="The module observes only supplied record contents and returns expected, observed, missing, unexpected, total, and error projections.",
    units="Capacity is parts per million; resource totals retain each supplied quantity name and unit with Decimal precision and are never converted across units.",
    failure="Duplicate identifiers, mismatched membership, unregistered devices, overallocated parents, or mixed physical/logical scope yields explicit errors rather than an accepted aggregate.",
    recovery="Correct or independently reacquire the supplied records and rerun; this module cannot reconcile a physical fleet or restore capacity rights.",
    boundary="This is pure supplied-record accounting. It is not a live SENSOR, does not calibrate or authenticate hardware, and does not establish legal title, custody, backing, durable ledger state, or physical allocation.",
)


_SOFTWARE_DIODE = _profile(
    name="The software one-way-diode emulator",
    scope="Development-only rehearsal of push, flush, close, refused reverse reads, counters, and an explicitly degraded software attestation receipt.",
    mechanism="An in-memory BytesIO sink accepts pushed bytes, counts writes, refuses read/recv/peek, and emits a receipt fixed to software-emulation and TIER_1_LOCAL markers.",
    participants="A local caller, one SoftwareOneWayDataDiodeEmulator instance, its in-memory sink, and optional test inspection code participate.",
    inputs="An emulator identifier and caller-supplied byte strings drive the push-only software interface.",
    authority="Only the holder of the local Python object may invoke it; the generated receipt is not hardware, isolation, confinement, or tier-promotion authority.",
    states="The emulator is open or closed with byte and message counters; each call is pushed, refused, inspected out-of-band, or represented by a degraded receipt.",
    ordering="Accepted pushes append in call order; close prevents later pushes; every reverse-channel method refuses unconditionally.",
    commands="Push bytes, flush the in-memory sink, close the object, attempt a prohibited read, inspect test contents, or emit a degraded receipt.",
    targets="The only effect target is the emulator's process-local BytesIO sink and counters on shared host memory.",
    effect_domains="SOFTWARE_BYTESIO_REHEARSAL_ONLY_NOT_PHYSICAL_ISOLATION",
    effects="A push appends bytes to shared process memory and advances counters; no optical, electromagnetic, kernel, process, or hardware channel is severed.",
    commit="A push is recorded after the sink write and flush return; there is no durable or atomic external delivery commitment.",
    retry="Repeating a push appends duplicate bytes and increments the count; no duplicate identity or idempotency guarantee exists.",
    timing="Call order is observable in one object, but no latency, throughput, persistence, or delivery deadline is guaranteed.",
    limits="The object accepts bytes while open, always refuses reverse reads, and forces software-emulation, invalid-hardware-attestation, and TIER_1_LOCAL receipt markers.",
    observations="Returned write length, counters, closed-state refusals, test-only sink contents, and the degraded receipt are process-local observations.",
    units="Units are bytes written and discrete push messages in one process-local emulator instance.",
    failure="Closed pushes and all read/recv/peek attempts raise explicit containment errors; receipt fields that imply hardware or a higher tier are rejected.",
    recovery="Create or explicitly manage a fresh emulator and resend selected bytes; no external delivery, isolation, or hardware recovery is represented.",
    boundary="The code explicitly runs on shared silicon, caches, memory buses, and kernel space. It provides no physical diode, hostile-kernel confinement, side-channel severance, sandbox, or Tier-3 evidence.",
)


_COMPONENT_STORAGE = _profile(
    name="The component-package storage envelope",
    scope="Canonical local capture, validation, exclusive persistence, and loading of one bounded component registry with retained artifact bytes and declared dependency bindings.",
    mechanism="Strict typed records, canonical JSON, SHA-256 identities, portable-path checks, bounded ordinary-file loading, and exclusive-create saving implement storage.",
    participants="A local caller, one StoredComponentPackage, its retained artifact and registry records, and a selected ordinary filesystem path participate.",
    inputs="A complete typed registry, captured immutable artifact bytes, implementation/dependency declarations, optional independent expected digest, and an absent output path are required.",
    authority="Local filesystem permission and an optional independently selected digest authorize only this storage operation; publisher, license, dependency, and implementation declarations remain untrusted.",
    states="A package is constructed, canonicalized, saved to an absent path, loaded and validated, inspected, or rejected without overwriting an existing destination.",
    ordering="All structural and byte checks precede construction; exclusive creation precedes a successful save; loading reads one bounded ordinary file before canonical validation.",
    commands="Construct, canonicalize, hash, save exclusively, load, validate exact bindings, and inspect without rendering artifact contents.",
    targets="Targets are one absent local package file and the in-memory retained registry, artifact, implementation, and dependency records.",
    effect_domains="LOCAL_COMPONENT_PACKAGE_FILE_ONLY",
    effects="Saving creates one new canonical local file; loading and inspection return bounded records without executing artifacts, installing dependencies, or publishing a package.",
    commit="Save commits when the exclusive file write succeeds; it never overwrites, but it is not fsync-backed or coordinated with another application state change.",
    retry="An existing destination refuses duplicate saving; a retry requires a deliberately selected absent path, while loading may be repeated from current bytes.",
    timing="No occurrence, freshness, durability, or distributed ordering time is established by the package record or local write.",
    limits="Package, content, item, path, schema, canonical JSON, ordinary-file, duplicate-key, digest, and exact-reference bounds constrain acceptance.",
    observations="Inspection reports byte integrity, counts, canonical digest, and explicit NOT_ESTABLISHED native qualification and dependency completeness.",
    units="Units are package/artifact bytes, component and dependency counts, portable paths, and SHA-256 identities.",
    failure="Malformed schemas, missing or duplicate bindings, path collisions, digest mismatch, special/link files, excessive bounds, or an existing/unwritable destination refuses.",
    recovery="Correct the complete package or select an absent destination and retry; an existing stored package is never silently replaced or repaired.",
    boundary="Storage proves bounded structural and byte identity only. It does not authenticate publisher/license authority, establish dependency completeness or executable reachability, execute content, publish remotely, or promote application conformance.",
)


_HARDWARE_RECEIPT = _profile(
    name="The VSTD-3 receipt file helper",
    scope="Local serialization, directory creation, writing, loading, strict decoding, and canonical-digest checking of one VSTD-3 receipt file.",
    mechanism="The helper computes the receipt digest, serializes canonical JSON plus newline, writes a selected path, and later strictly decodes and verifies that digest.",
    participants="A local caller, one mutable VSTD3Receipt value, one selected local file or directory path, and the filesystem participate.",
    inputs="A VSTD3Receipt and selected output path drive saving; current file bytes drive loading and validation.",
    authority="Local path permission is the only write authority; receipt content and canonical digest do not authorize publication or authenticate an issuer.",
    states="The local receipt is absent, parent directory created, bytes written, loaded and digest-valid, or rejected.",
    ordering="Digest computation precedes serialization and write; loading reads before strict decode and digest verification.",
    commands="Create parent directories, compute/set digest, write receipt.json or a selected JSON path, read, decode, and check digest integrity.",
    targets="The selected local receipt path, its parent directories, and the caller-supplied mutable receipt digest field are targets.",
    effect_domains="LOCAL_TRUNCATING_RECEIPT_FILE_WRITE_ONLY",
    effects="Saving mutates the receipt's digest field, creates directories, and writes or truncates one local receipt file; it performs no remote publication.",
    commit="The helper reports success after path.write_bytes returns; the write may replace existing bytes and is not atomic, exclusive, fsync-backed, or externally witnessed.",
    retry="A repeated save can overwrite the same path; no duplicate detection, compare-and-swap, idempotency key, or retained correction history is provided.",
    timing="No durable occurrence time, write-order guarantee across processes, or receipt freshness is established.",
    limits="Strict VSTD-3 decoding and canonical digest equality bound accepted loads; filesystem size and hostile-input bounds are not added by this helper.",
    observations="A load observes current local JSON bytes and returns a typed receipt only when strict decoding and digest integrity succeed.",
    units="Units are one receipt file, canonical JSON bytes, directory/path entries, and one canonical digest.",
    failure="Filesystem errors, non-object JSON, strict-decode failure, or digest mismatch raises VSTD3ReceiptError; a failed truncating write may leave filesystem state unknown.",
    recovery="Recovery requires independently inspecting or replacing the local file and retrying; the helper owns no journal, rollback, reconciliation, or correction history.",
    boundary="This is a convenience file writer/reader. It does not provide atomic or exclusive persistence, crash durability, append-only history, external witness, hardware truth, publication, or application-wide receipt validity.",
)


_DERIVER_EXCHANGE = _profile(
    name="The bounded deriver subprocess exchange",
    scope="One declared executable invocation and one independent rerun at the same runtime coordinate, with exact arguments, public environment, input, outputs, exit state, and bounded receipt comparison.",
    mechanism="The parent validates executable bytes and declarations, launches a subprocess in a fresh empty directory, writes bounded stdin, drains stdout/stderr, enforces timeout/output bounds, terminates on failure, and reruns independently.",
    participants="The parent checker, one exact local executable, two child process invocations, pipe-reader/writer threads, temporary directories, and the caller-supplied declaration participate.",
    inputs="Executable path and bytes, runtime coordinate, arguments, public non-secret environment, stdin bytes, timeout, output bound, declaration, and optional receipt are preconditions.",
    authority="The caller explicitly selects the executable and public invocation declaration; neither process output nor receipt authorizes source meaning, safety, or broader execution.",
    states="States include NOT_RUN, START_FAILED, COMPLETED, TIMED_OUT, OUTPUT_LIMIT_EXCEEDED, CAPTURE_FAILED, and final ESTABLISHED, REFUTED, UNKNOWN, or INVALID assessment.",
    ordering="Declaration validation and coordinate capture precede launch; stdin and concurrent output capture precede wait/termination; the second run follows receipt validation and must match exact results.",
    commands="Launch exact executable bytes, send bounded stdin, capture streams, wait, terminate/kill on bounds, record receipt, rerun, and compare transcripts.",
    targets="Targets are two local child processes, their fresh temporary working directories, pipes, and the returned canonical declaration/receipt/assessment records.",
    effect_domains="LOCAL_SUBPROCESS_LAUNCH_AND_PIPE_EXCHANGE_NOT_SANDBOXED",
    effects="The parent starts, communicates with, waits for, and may terminate local child processes; unobserved child effects outside the fresh directory are not confined or measured.",
    commit="A receipt records one bounded observed disposition; ESTABLISHED requires a second exact transcript match but is not an atomic commit or semantic correctness claim.",
    retry="The independent recheck is an intentional fresh launch with exact declared inputs; arbitrary child side effects can repeat and no general idempotency is inferred.",
    timing="Parent elapsed timeout is bounded to at most 60 seconds per invocation; scheduler latency, child-internal time, processor use, and memory use are not bounded.",
    limits="Executable/input/output/declaration/receipt bytes, argument/environment counts, public environment names, platforms, timeout, fresh cwd, and exact coordinate/digest equality bound the route.",
    observations="The parent observes launch disposition, exit code or signal, exact stdout/stderr bytes, runtime coordinate, receipt bindings, and equality of the independent rerun.",
    units="Units are bytes, arguments, environment entries, milliseconds, exit codes/signals, process invocations, and SHA-256 identities.",
    failure="Unavailable or changed executable, start/capture failure, timeout, output excess, malformed binding, noncompleted run, or transcript difference remains explicit and non-ESTABLISHED.",
    recovery="Fix the exact declaration/runtime/executable and perform a new bounded pair; timeout handling terminates/kills observed children but proves no cleanup of their descendants or external effects.",
    boundary="The runner is not a sandbox and does not bound CPU, memory, network, descendants, or arbitrary child side effects. It establishes transcript reproducibility only, not source semantics, safety, authorization, or application conformance.",
)


_SCITT_PROTOCOL = _profile(
    name="The experimental SCITT evidence mapper for VSTD receipts",
    scope="Deterministic mapping among bounded VSTD receipt coordinates, pinned experimental SCITT templates/evidence vocabularies, derived-subject values, and monotone composed result states.",
    mechanism="Canonical JSON and SHA-256 bind mapping records; pinned draft algorithms derive subjects; strict adapters validate normalized caller-supplied native VSTD and SCITT verifier evidence without implementing signing or transport.",
    participants="A caller, VSTD receipt/result records, a registration-template consumer, separately operated native VSTD and SCITT verifiers, relying-party policy inputs, and derived-subject/profile adapters participate.",
    inputs="Exact receipts, claim coordinates, evidence bounds, subject inputs, accepted issuers, pinned profile/draft values, and normalized native verifier results are required.",
    authority="Only explicit relying-party issuer/profile selections and separately supplied native verifier outcomes authorize a local mapping decision; embedded PASS text and templates are never self-authorizing.",
    states="States include template prepared, native verification not evaluated/verified/rejected, SCITT missing/pending/registered/invalid, derived subject match/no-match/not-established, and composed pass/fail/unknown.",
    ordering="Create and bind the VSTD payload before external SCITT production; consume native evidence before composition; composition never upgrades either input's epistemic strength.",
    commands="Canonicalize coordinates, create a registration template, derive/compare subjects, normalize pinned evidence results, consume native SCITT evidence, and compose with native VSTD evidence.",
    targets="Targets are deterministic in-memory mapping, template, evidence, derived-subject, and composition records; no transparency service or signer is contacted.",
    effect_domains="IN_PROCESS_INTEROPERABILITY_MAPPING_ONLY_NO_SIGNING_OR_TRANSPORT",
    effects="Functions return canonical mapping inputs and bounded result projections; they do not create CBOR/COSE signatures, submit, register, fetch, verify cryptography, or mutate a transparency ledger.",
    commit="A local composition result is complete only for the exact supplied payload and verifier evidence; it is not a SCITT registration or external state commit.",
    retry="Re-mapping exact inputs is deterministic; replay acceptance, service registration, and receipt freshness remain responsibilities of the external native protocols.",
    timing="Only supplied registration/profile window fields are represented; no network occurrence, service availability, freshness acquisition, or liveness is performed here.",
    limits="Pinned draft revisions/profiles, exact fields, canonical JSON, bounded identifier/input lengths, SHA-256 equality, accepted issuer sets, and monotone state tables bound mapping.",
    observations="The mapper observes only supplied canonical records and normalized native results, retaining issuer, service, profile, digest, subject, status, limitations, and NOT_EVALUATED states.",
    units="Units are canonical bytes, identifier counts, unsigned lengths, SHA-256 identities, and discrete protocol/result states.",
    failure="Malformed or ambiguous mappings, digest/subject/issuer mismatch, unsupported revisions/states, absent native verification, or noncanonical derived inputs fail or remain explicitly unknown.",
    recovery="Obtain current native VSTD and SCITT verification evidence for the exact payload or correct the pinned mapping inputs, then compose afresh without upgrading retained unknowns.",
    boundary="This code is a deterministic adapter, not SCITT/COSE signing, transport, registration, ledger acquisition, or native cryptographic verification. It does not establish application correctness, publication, or financial/physical authority.",
)


_ARTIFACT_PATHS = (
    "src/verifier/artifact_control/__init__.py",
    "src/verifier/artifact_control/artifact-control-1.schema.json",
    "src/verifier/schemas/artifact-control-1.schema.json",
)
_PRIVACY_PATHS = (
    "src/verifier/controlled_emission.py",
    "src/verifier/privacy/__init__.py",
    "src/verifier/privacy/adapters.py",
    "src/verifier/privacy/composition.py",
    "src/verifier/privacy/current_certificate_emission.py",
    "src/verifier/privacy/engine.py",
    "src/verifier/privacy/independence.py",
    "src/verifier/privacy/models.py",
)
_LOGIT_PATHS = (
    "src/verifier/constraints/__init__.py",
    "src/verifier/constraints/kernel.py",
    "src/verifier/constraints/llguidance_backend.py",
    "src/verifier/constraints/postvalidate.py",
    "src/verifier/constraints/torch_mask.py",
)
_COMPONENT_PATHS = (
    "src/verifier/interoperability/storage.py",
    "src/verifier/schemas/verifier-component-package-1.schema.json",
    "src/verifier/schemas/verifier-component-package-2.schema.json",
)
_SCITT_PATHS = (
    "src/verifier/interoperability/scitt/__init__.py",
    "src/verifier/interoperability/scitt/adapter.py",
    "src/verifier/interoperability/scitt/derived_subjects.py",
    "src/verifier/interoperability/scitt/evidence_profiles.py",
)


_REVIEWS = {
    "vstd-artifact-control-lifecycle": _review(
        "TRANSACTION",
        _ARTIFACT_PATHS,
        ("TRANSACTION", "PROTOCOL"),
        _ARTIFACT_CONTROL,
        refuted={
            "ASSET": "The artifact lifecycle copies only local source bytes into a bundle (artifact_control/__init__.py:614-687); the module and its schemas contain no quantity, right, price, or custody field.",
            "FINBOT": "No price, money, currency, balance, order, transfer, or settlement term appears in the artifact-control module or its schemas; its effects are local copy, rename, and exclusive-create operations (artifact_control/__init__.py:674-687, 1000-1001).",
            "ROBOT": "Imports are standard-library modules, verifier.core.signature_keys, and lazily loaded cryptography (artifact_control/__init__.py:18-30, 555-557); no process, network, or device call exists, and writes stay local to a staging sibling (artifact_control/__init__.py:674) and a thaw record sibling (artifact_control/__init__.py:980).",
            "MARKET": "freeze_artifact, seal_artifact, verify_frozen_artifact, thaw_artifact, and thawed_artifact_status (artifact_control/__init__.py:614-1034) copy, sign, verify, or thaw local bytes; none accepts an order, quote, counterparty, price, or settlement input (artifact_control/__init__.py:614-1034).",
        },
    ),
    "vstd-privacy-emission-policy": _review(
        "POLICY",
        _PRIVACY_PATHS,
        ("LEDGER", "TRANSACTION", "POLICY"),
        _PRIVACY_EMISSION,
        {
            "LEDGER": ("src/verifier/privacy/adapters.py",),
            "TRANSACTION": (
                "src/verifier/controlled_emission.py",
                "src/verifier/privacy/adapters.py",
                "src/verifier/privacy/current_certificate_emission.py",
                "src/verifier/privacy/engine.py",
            ),
            "POLICY": _PRIVACY_PATHS,
        },
        # PROTOCOL, ROBOT, and FINBOT are deliberately UNRESOLVED.  controlled_emission.py
        # imports and calls verifier.domains.certification.recheck_domain_certificate
        # (controlled_emission.py:22), whose import closure reaches subprocess, ctypes,
        # and urllib publication sites (domains/verifier_execution.py; interoperability/
        # gated_publish.py:253-254), so no closed effect surface is established.
        refuted={
            "ASSET": "The budget holds only dimensionless epsilon, delta, and an emission count (privacy/adapters.py:26-38), with no holder, right, custody, or redemption field; it accumulates declared expenditure.",
            "MARKET": "evaluate_controlled_emission and evaluate_controlled_current_emission (controlled_emission.py:143-177) return an admission or refusal for one certificate disclosure; they match no counterparty and perform no order, quote, price, allocation, or settlement (controlled_emission.py:143-411).",
        },
    ),
    "vstd-logit-constraint-controller": _review(
        "CONTROLLER",
        _LOGIT_PATHS,
        (
            "TRANSACTION",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "POLICY",
        ),
        _LOGIT_CONSTRAINT,
        {
            "TRANSACTION": (
                "src/verifier/constraints/llguidance_backend.py",
                "src/verifier/constraints/torch_mask.py",
            ),
            "MEASUREMENT": (
                "src/verifier/constraints/kernel.py",
                "src/verifier/constraints/llguidance_backend.py",
            ),
            "SENSOR": (
                "src/verifier/constraints/kernel.py",
                "src/verifier/constraints/llguidance_backend.py",
            ),
            "CONTROLLER": _LOGIT_PATHS,
            "ACTUATOR": (
                "src/verifier/constraints/llguidance_backend.py",
                "src/verifier/constraints/torch_mask.py",
            ),
            "PROTOCOL": (
                "src/verifier/constraints/kernel.py",
                "src/verifier/constraints/llguidance_backend.py",
            ),
            "POLICY": (
                "src/verifier/constraints/kernel.py",
                "src/verifier/constraints/llguidance_backend.py",
                "src/verifier/constraints/postvalidate.py",
            ),
        },
        refuted={
            "ASSET": "The seam writes only the caller's in-process logits row and native matcher state (constraints/torch_mask.py:55; constraints/llguidance_backend.py:180-218); its quantities are token counts and digests (constraints/kernel.py:111-150), and it has no holder, right, custody, or redemption field.",
            "FINBOT": "No owned constraint file contains price, money, order, transfer, settlement, or balance terms; its only effects are masking logits and advancing a native grammar matcher (constraints/torch_mask.py:55; constraints/llguidance_backend.py:203-218).",
            "ROBOT": "No owned constraint file imports a device, process, network, or actuator library; torch device arguments only place tensors (constraints/torch_mask.py:20-21), and the only write target is the caller's logits row (constraints/torch_mask.py:55).",
            "MARKET": "LLGuidanceConstraintSession.mask_logits and accept_token (constraints/llguidance_backend.py:180-220) mask one logits row and advance a grammar matcher; the owned constraint types (constraints/kernel.py:24-173) describe grammar kinds, observations, and traces, with no order, quote, counterparty, price, or settlement term.",
        },
    ),
    "vstd-hardware-resource-accounting": _review(
        "MEASUREMENT",
        ("src/verifier/hardware/fleet.py",),
        ("ASSET", "MEASUREMENT", "POLICY"),
        _HARDWARE_ACCOUNTING,
        refuted={
            "SENSOR": "The inputs are prebuilt fleet records (hardware/fleet.py:29-33, 75-78), and the module contains no acquisition or calibration code.",
            "TRANSACTION": "fleet.py performs no write, send, or persistence call; both public functions return frozen results (hardware/fleet.py:21-24, 69-72) built from local containers (hardware/fleet.py:81-84), so no state change occurs.",
            "ROBOT": "fleet.py imports only collections, dataclasses, decimal, typing, and sibling models (hardware/fleet.py:7-18); it contains no device, process, or command call and no agent or control loop.",
            "FINBOT": "fleet.py contains no money, price, currency, payment, transfer, or settlement term; totals are keyed by quantity name and unit and never converted (hardware/fleet.py:101, 110).",
            "MARKET": "verify_fleet_observation (hardware/fleet.py:29) compares member sets and aggregate_partition_accounting (hardware/fleet.py:75-110) sums declared capacity by unit; this is accounting of supplied quantities, not a market order, quote, price, counterparty trade, or settlement (hardware/fleet.py:22-110).",
        },
    ),
    "vstd-software-diode-effect": _review(
        "ACTUATOR",
        ("src/verifier/hardware/diode_emulator.py",),
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL"),
        _SOFTWARE_DIODE,
        refuted={
            "ASSET": "diode_emulator.py has no asset, right, balance, custody, or value term; its only numeric state is a process-local byte and message counter (hardware/diode_emulator.py:103-104, 129-130), which counts writes rather than holdings.",
            "FINBOT": "diode_emulator.py has no payment, price, order, transfer, or settlement term; push() (hardware/diode_emulator.py:123-131) forwards caller bytes to its sink and returns a byte count.",
            "ROBOT": "diode_emulator.py imports only dataclasses, hashlib, io, json, and typing (hardware/diode_emulator.py:7-11) and defines no agent, controller, or physical endpoint; its one command is push() to an in-memory BytesIO sink (hardware/diode_emulator.py:94-131), so no agent-to-actuator binding or physical reach exists in this source.",
            "MARKET": "The emulator's public class (hardware/diode_emulator.py:94-131) exposes push and the refused read, recv, and peek methods over one in-memory sink; it has no order, quote, counterparty, price, allocation, or settlement operation (hardware/diode_emulator.py:94-131).",
        },
    ),
    "vstd-component-package-storage": _review(
        "DATA",
        _COMPONENT_PATHS,
        ("TRANSACTION",),
        _COMPONENT_STORAGE,
        {"TRANSACTION": ("src/verifier/interoperability/storage.py",)},
        refuted={
            "FINBOT": "storage.py has no payment, price, order, transfer, or settlement term; its only write is one exclusive creation of canonical package bytes (interoperability/storage.py:470).",
            "PROTOCOL": "storage.py imports no network or process module (interoperability/storage.py:12-21), performs one bounded local read (interoperability/storage.py:440-446) and one exclusive local write (interoperability/storage.py:470), and sends no message.",
            "ROBOT": "storage.py imports no process, device, or network module (interoperability/storage.py:12-21); its docstring states that loading never imports an entry point (interoperability/storage.py:6-7), and its only file effects are one read (interoperability/storage.py:440-446) and one exclusive write (interoperability/storage.py:470).",
            "MARKET": "save_component_package and load_component_package (interoperability/storage.py:418-470) write and read one canonical package file; the stored package types (interoperability/storage.py:138-254) describe artifacts, implementations, and dependencies, with no order, quote, counterparty, price, or settlement term.",
        },
    ),
    "vstd-hardware-receipt-publication": _review(
        "RECEIPT",
        ("src/verifier/hardware/receipt.py",),
        ("TRANSACTION",),
        _HARDWARE_RECEIPT,
        refuted={
            "LEDGER": "receipt.py performs one truncating path.write_bytes (hardware/receipt.py:26) on a selected path and has no append mode, so it keeps no history.",
            "PROTOCOL": "receipt.py imports only json, pathlib, typing, and sibling modules (hardware/receipt.py:7-12); its only I/O is read_text (hardware/receipt.py:33) and write_bytes (hardware/receipt.py:26), so it exchanges no messages.",
            "ROBOT": "receipt.py imports no device, process, or network module (hardware/receipt.py:7-12); its only effect is one caller-selected write (hardware/receipt.py:26), and it has no command-selection or agent logic.",
            "FINBOT": "receipt.py has no payment, price, order, transfer, or settlement term; its sole effect is the local write of canonical receipt bytes (hardware/receipt.py:26).",
            "MARKET": "save_vstd3_receipt, load_vstd3_receipt, and is_vstd3_receipt (hardware/receipt.py:19-47) serialize, read, and classify one receipt file; they expose no order, quote, counterparty, price, allocation, or settlement operation (hardware/receipt.py:15-47).",
        },
    ),
    "vstd-deriver-process-exchange": _review(
        "PROTOCOL",
        ("src/verifier/interoperability/deriver_self_status.py",),
        (
            "TRANSACTION",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
        ),
        _DERIVER_EXCHANGE,
        # ROBOT and FINBOT stay UNRESOLVED: the owned module launches arbitrary local
        # executables with subprocess.Popen (interoperability/deriver_self_status.py:449,
        # 573) and its import closure reaches network transfer sites (interoperability/
        # network.py:2228-2229).
        refuted={
            "MARKET": "The owned deriver module (interoperability/deriver_self_status.py:75-698) defines self-status declarations and receipts for one declared executable run; it accepts no order, quote, counterparty, price, allocation, or settlement input (interoperability/deriver_self_status.py:75-698).",
        },
    ),
    "vstd-scitt-evidence-protocol": _review(
        "PROTOCOL",
        _SCITT_PATHS,
        ("PROTOCOL", "POLICY"),
        _SCITT_PROTOCOL,
        refuted={
            "LEDGER": "scitt/ performs no file, network, or persistence call (interoperability/scitt/adapter.py:25-33; interoperability/scitt/derived_subjects.py:19-28; interoperability/scitt/evidence_profiles.py:13-20), and each call returns a fresh record (interoperability/scitt/adapter.py:725-741, 819-828) and retains no history.",
            "TRANSACTION": "compose_results (interoperability/scitt/adapter.py:744-828) maps supplied payload and evidence to a frozen CompositionResult, and no registration, write, or network call exists under scitt/.",
            "ROBOT": "scitt/ imports only standard-library encoding and typing modules, sibling modules, and optional cbor2 (interoperability/scitt/adapter.py:25-33; interoperability/scitt/derived_subjects.py:19-28, 297-304) and contains no device, process, or command call.",
            "FINBOT": "scitt/ has no payment, price, asset, transfer, or settlement term; its outputs are normalized states with computational_verdict NOT_EVALUATED (interoperability/scitt/adapter.py:436-446, 730).",
            "MARKET": "VstdScittPayload, ScittRegistrationTemplate, and compose_results (interoperability/scitt/adapter.py:243-828) map VSTD receipt coordinates to registration and composed result states; no order, quote, counterparty, price, allocation, or settlement operation exists in the owned SCITT modules (interoperability/scitt/adapter.py:243-828).",
        },
    ),
}


def _contract_rows(kind: str) -> list[dict[str, Any]]:
    return [
        row
        for row in requirements_for(namespace_registry(), (kind,))
        if row["kind"] == kind
    ]


def _declarations(review: _Review) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for kind in review.applicable:
        try:
            selected = _DECLARATION_BUILDERS[kind](review.profile)
        except KeyError as exc:
            raise AssertionError("missing declaration builder for " + kind) from exc
        overlap = set(rows).intersection(selected)
        if overlap:
            raise AssertionError("duplicate declaration ids: " + ", ".join(overlap))
        rows.update(selected)
    return rows


# Static demotions: every DOES_NOT_APPLY that the live closed-surface screen cannot
# close is withheld as UNRESOLVED.  Lookup is strict so a missing entry fails at import.
_STATIC_DEMOTIONS: dict[str, frozenset[str]] = {
    "vstd-artifact-control-lifecycle": frozenset({"ASSET", "FINBOT", "MARKET", "ROBOT"}),
    "vstd-privacy-emission-policy": frozenset({"ASSET", "MARKET"}),
    "vstd-logit-constraint-controller": frozenset({"ASSET", "FINBOT", "MARKET", "ROBOT"}),
    "vstd-hardware-resource-accounting": frozenset({"FINBOT", "MARKET", "ROBOT", "SENSOR", "TRANSACTION"}),
    "vstd-software-diode-effect": frozenset({"ASSET", "FINBOT", "MARKET", "ROBOT"}),
    "vstd-component-package-storage": frozenset({"FINBOT", "MARKET", "PROTOCOL", "ROBOT"}),
    "vstd-hardware-receipt-publication": frozenset({"FINBOT", "LEDGER", "MARKET", "PROTOCOL", "ROBOT"}),
    "vstd-deriver-process-exchange": frozenset({"MARKET"}),
    "vstd-scitt-evidence-protocol": frozenset({"FINBOT", "LEDGER", "MARKET", "ROBOT", "TRANSACTION"}),
}
_REVIEWS = {
    object_id: replace(review, demoted=_STATIC_DEMOTIONS[object_id])
    for object_id, review in _REVIEWS.items()
}


def _catalog_check() -> None:
    if tuple(_REVIEWS) != SUBJECT_OBJECT_IDS:
        raise AssertionError("subject review order differs from public object order")
    specs = {spec.object_id: spec for spec in SEMANTIC_OWNERSHIP_SPECS}
    for object_id, review in _REVIEWS.items():
        spec = specs.get(object_id)
        if spec is None:
            raise AssertionError(object_id + " missing from semantic ownership catalog")
        catalogued = {spec.primary_kind, *spec.specializations} & set(REVIEW_KINDS)
        if not catalogued <= set(review.applicable):
            raise AssertionError(
                object_id + " demotes a catalogued primary or specialized role"
            )
    owned_paths: set[str] = set()
    refuted_cells: dict[str, str] = {}
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
                "subject ownership overlaps: " + ", ".join(sorted(overlap))
            )
        owned_paths.update(review.owned_paths)
        if len(review.applicable) != len(set(review.applicable)):
            raise AssertionError(object_id + " repeats an applicable kind")
        if not set(review.applicable) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " has an unsupported review kind")
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if any(
            not paths or not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence leaves owned source")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " both applies and is refuted")
        if not set(review.demoted) <= set(review.refuted):
            raise AssertionError(object_id + " withholds a kind it does not refute")
        if not set(review.refuted) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " has an unsupported refuted kind")
        for kind, reason in review.refuted.items():
            cell = object_id + ":" + kind
            if refuted_cells.setdefault(reason, cell) != cell:
                raise AssertionError(
                    "refutation reason is shared by "
                    + refuted_cells[reason]
                    + " and "
                    + cell
                )
        if any(not reason.strip() for reason in review.refuted.values()) or any(
            not _reason(review.profile, kind, True).strip()
            for kind in review.applicable
        ):
            raise AssertionError(object_id + " contains a blank decision reason")
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


def review_document() -> dict[str, Any]:
    """Return a defensive, deterministic review of all nine exact owners."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: _classification_document(review, kind) for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(_declarations(review)),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for object_id, review in _REVIEWS.items()
    }


_OBLIGATION_SUFFIX = (
    " This Tier-0 declaration names the reviewed boundary only; "
    "mechanism execution and Tier-1-plus fulfillment remain unestablished."
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
    if basis == "APPLIES":
        return {
            "status": basis,
            "reason": _reason(review.profile, kind, True),
            "evidence_paths": list(review.role_paths[kind]),
        }
    return {
        "status": basis,
        "reason": review.refuted[kind],
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
    if basis == "APPLIES":
        paths = review.role_paths[kind]
        reason = _reason(review.profile, kind, True)
    else:
        paths = review.owned_paths
        reason = review.refuted[kind]
    return {
        "status": basis,
        "reason": reason,
        "evidence": [deepcopy(evidence_by_path[path]) for path in paths],
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
            "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
        )
    return True


def apply_package_semantic_review_subjects(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply all nine reviews atomically to a deep copy of package rows."""
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
            row["id"]: tuple(row["declaration_fields"]) for row in _contract_rows(kind)
        }
        for kind in REVIEW_KINDS
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
        historic = review
        screen = closed_surface_screen(selected_root, review.owned_paths)
        review = _screened_review(review, screen)

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
            if kind not in review.applicable and (
                row["kind"] == kind or kind in specializations
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id + ":" + kind
                )

        known_obligations = {
            name for values in live_obligations.values() for name in values
        }
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
        unlisted_evidence: dict[str, list[dict[str, str]]] = {}
        preserve_obligations: set[str] = set()
        remove_obligations: set[str] = set()
        for kind in REVIEW_KINDS:
            basis = _basis(review, kind)
            decision = classification.get(kind)
            code = "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
            if basis == "UNRESOLVED":
                if _prior_refutation(decision, kind, historic, evidence_by_path, object_id):
                    pass
                elif not _shared._unresolved_decision(
                    decision, files, owned, kind=kind, code=code
                ):
                    raise ValueError(code)
                if (
                    decision is not None
                    and decision.get("status") == "UNRESOLVED"
                    and decision["evidence"]
                ):
                    unlisted_evidence[kind] = [
                        deepcopy(evidence_by_path[reference["path"]])
                        for reference in decision["evidence"]
                    ]
            elif _shared._preserve_explicit_decision(
                decision,
                _expected_decision(review, kind, evidence_by_path),
                files,
                owned,
                object_id=object_id,
                kind=kind,
            ):
                preserve_decisions.add(kind)
            for obligation_id, fields in live_obligations[kind].items():
                binding = obligations.get(obligation_id)
                if basis == "APPLIES":
                    if _shared._preserve_explicit_obligation(
                        binding,
                        fields,
                        _reason(review.profile, kind, True) + _OBLIGATION_SUFFIX,
                        [
                            deepcopy(evidence_by_path[path])
                            for path in review.role_paths[kind]
                        ],
                        files,
                        owned,
                        object_id=object_id,
                        obligation_id=obligation_id,
                    ):
                        preserve_obligations.add(obligation_id)
                elif binding is not None:
                    code = (
                        "PACKAGE_SEMANTIC_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                        if basis == "DOES_NOT_APPLY"
                        else "PACKAGE_SEMANTIC_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
                    ) + object_id + ":" + obligation_id
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
            "review": review,
            "screen": screen,
            "preserve_decisions": preserve_decisions,
            "unlisted_evidence": unlisted_evidence,
            "preserve_obligations": preserve_obligations,
            "remove_obligations": remove_obligations,
        }

    # Re-read every owned byte only after all semantic conflicts have passed.
    # A concurrent writer therefore cannot produce a partly current review set.
    for object_id, review in _REVIEWS.items():
        closing = _source_evidence(selected_root, review.owned_paths)
        if closing != plans[object_id]["opening_evidence"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)

    for object_id, review in _REVIEWS.items():
        if closed_surface_screen(selected_root, review.owned_paths) != plans[object_id]["screen"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)

    result = deepcopy(rows)
    for object_id in _REVIEWS:
        row = result[object_id]
        plan = plans[object_id]
        review = plan["review"]
        declarations = _declarations(review)
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
        for name in plan["remove_obligations"]:
            row["obligations"].pop(name, None)
        for name, declaration in declarations.items():
            if name in plan["preserve_obligations"]:
                continue
            kind = name.split("-", 1)[0]
            row["obligations"][name] = {
                "reason": _reason(review.profile, kind, True) + _OBLIGATION_SUFFIX,
                "evidence": [
                    deepcopy(plan["evidence_by_path"][path])
                    for path in review.role_paths[kind]
                ],
                "declaration": dict(declaration),
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)
    for object_id, review in _REVIEWS.items():
        if closed_surface_screen(selected_root, review.owned_paths) != plans[object_id]["screen"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)
    return result


__all__ = [
    "CLAIM_BOUNDARY",
    "REVIEW_KINDS",
    "SUBJECT_OBJECT_IDS",
    "apply_package_semantic_review_subjects",
    "review_document",
]
