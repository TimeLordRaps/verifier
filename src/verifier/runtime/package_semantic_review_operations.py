"""Current-source Tier-0 semantic review for nineteen operational objects.

Terminology: hash-based message authentication code (HMAC).

Terminology: application programming interface (API); abstract syntax tree
(AST); directed acyclic graph (DAG); Hypertext Transfer Protocol (HTTP);
Hypertext Transfer Protocol Secure (HTTPS); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); Coordinated Universal Time (UTC);
Unicode Transformation Format, 8-bit (UTF-8); Verifier Standard (VSTD); YAML
Ain't Markup Language (YAML).

The catalog in this module is a bounded answer to one repository-admission
question: which of the twelve added namespace kinds apply to each audited
path-owned object, and what does each applicable Tier-0 declaration mean here?
It does not execute a mechanism, prove the declaration prose, establish a
higher polish tier, or infer that an external callback is physically or
financially confined.

Applying the review is deliberately pure and fail-closed.  Every owned source
must still have the caller-supplied current digest, every existing reviewed
answer must be compatible and complete, and the whole nineteen-object
denominator is validated before a copied row is changed.

Each added kind has exactly one explicit basis per object: a literal entry in
``applicable`` (APPLIES) or in ``refuted`` (DOES_NOT_APPLY).  A kind named in
neither is not inferred from absence; it is the canonical migration UNRESOLVED
with no evidence, or with only an already-validated owned candidate.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


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

# Static language vocabulary, not a runtime reflection result.  A Python upgrade
# may add a builtin, but it does not silently expand a reviewed callable surface;
# that requires an explicit source update and fresh semantic review.
STATIC_BUILTIN_NAMES = frozenset({
    "ArithmeticError", "AssertionError", "AttributeError", "BaseException",
    "BaseExceptionGroup", "BlockingIOError", "BrokenPipeError", "BufferError",
    "BytesWarning", "ChildProcessError", "ConnectionAbortedError",
    "ConnectionError", "ConnectionRefusedError", "ConnectionResetError",
    "DeprecationWarning", "EOFError", "Ellipsis", "EncodingWarning",
    "EnvironmentError", "Exception", "ExceptionGroup", "False",
    "FileExistsError", "FileNotFoundError", "FloatingPointError",
    "FutureWarning", "GeneratorExit", "IOError", "ImportError",
    "ImportWarning", "IndentationError", "IndexError", "InterruptedError",
    "IsADirectoryError", "KeyError", "KeyboardInterrupt", "LookupError",
    "MemoryError", "ModuleNotFoundError", "NameError", "None",
    "NotADirectoryError", "NotImplemented", "NotImplementedError", "OSError",
    "OverflowError", "PendingDeprecationWarning", "PermissionError",
    "ProcessLookupError", "RecursionError", "ReferenceError", "ResourceWarning",
    "RuntimeError", "RuntimeWarning", "StopAsyncIteration", "StopIteration",
    "SyntaxError", "SyntaxWarning", "SystemError", "SystemExit", "TabError",
    "TimeoutError", "True", "TypeError", "UnboundLocalError",
    "UnicodeDecodeError", "UnicodeEncodeError", "UnicodeError",
    "UnicodeTranslateError", "UnicodeWarning", "UserWarning", "ValueError",
    "Warning", "WindowsError", "ZeroDivisionError", "__build_class__",
    "__debug__", "__doc__", "__import__", "__loader__", "__name__",
    "__package__", "__spec__", "abs", "aiter", "all", "anext", "any",
    "ascii", "bin", "bool", "breakpoint", "bytearray", "bytes", "callable",
    "chr", "classmethod", "compile", "complex", "copyright", "credits",
    "delattr", "dict", "dir", "divmod", "enumerate", "eval", "exec", "exit",
    "filter", "float", "format", "frozenset", "getattr", "globals", "hasattr",
    "hash", "help", "hex", "id", "input", "int", "isinstance", "issubclass",
    "iter", "len", "license", "list", "locals", "map", "max", "memoryview",
    "min", "next", "object", "oct", "open", "ord", "pow", "print",
    "property", "quit", "range", "repr", "reversed", "round", "set",
    "setattr", "slice", "sorted", "staticmethod", "str", "sum", "super",
    "tuple", "type", "vars", "zip",
})

CLAIM_BOUNDARY = (
    "Current-source Tier-0 applicability and declaration review only; "
    "mechanism execution, truth of the declarations, endpoint consequences, "
    "and Tier-1-plus conformance remain separately unestablished."
)


@dataclass(frozen=True)
class _Profile:
    """Repository-specific vocabulary used to fill exact contract fields."""

    name: str
    scope: str
    mechanism: str
    participants: str
    inputs: str
    authority: str
    states: str
    ordering: str
    commands: str
    targets: str
    effect_domains: str
    effects: str
    commit: str
    retry: str
    timing: str
    limits: str
    observations: str
    units: str
    failure: str
    recovery: str
    boundary: str
    protocol_transitions: str | None = None


@dataclass(frozen=True)
class _ActuatorBasis:
    """Owned command-to-effect endpoint and its observation boundary."""

    endpoint_path: str
    command_to_effect: str
    feedback: str
    failure_surface: str


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    profile: _Profile
    refuted: tuple[str, ...] = ()
    actuator_basis: _ActuatorBasis | None = None


def _label_kind(label: str) -> str:
    """Return the leading uppercase letter run a label would name after normalizing.

    Case, whitespace, and separator variants (``robot``, `` ROBOT``, ``ROBOT_0.1``)
    therefore resolve to the same kind as the canonical label; any such variant
    that is not itself canonical is refused rather than retained as an escape.
    """
    return re.split(r"[^A-Z]", label.strip().upper(), maxsplit=1)[0]


def _names_kind(label: str) -> bool:
    """Return whether any alphabetic token of a non-canonical label is a kind.

    A prefixed spelling such as ``REAL_ROBOT`` or ``REAL_FINBOT`` would otherwise
    lead with a non-kind token and survive as an unchecked label that a reader
    could take for a physical or financial role.  Such labels are refused.
    """
    return _label_kind(label) in REVIEW_KINDS or any(
        token in REVIEW_KINDS for token in re.split(r"[^A-Z]+", label.strip().upper())
    )


def _unresolved_reason(kind: str) -> str:
    """Return the canonical migration reason for a kind with no explicit basis."""
    return (
        "Migration retains this applicability question. Static ownership "
        "alone cannot refute a " + kind + " role."
    )


def _basis(review: _Review, kind: str) -> str:
    """Return the only explicit catalog basis for one kind of one object.

    Absence from both literal tuples is UNRESOLVED, never DOES_NOT_APPLY.
    """
    if kind in review.applicable:
        return "APPLIES"
    if kind in review.refuted:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _obligation_reason(profile: _Profile, kind: str) -> str:
    """Return the canonical reason for one applicable kind's Tier-0 declaration."""
    return (
        _reason(profile, kind, True)
        + " This Tier-0 declaration names the reviewed boundary only; "
        "mechanism execution and Tier-1-plus fulfillment remain unestablished."
    )


def _ledger(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "LEDGER-0.1-authoritative-history": {
            "history": profile.observations,
            "state": profile.states,
            "ordering": profile.ordering,
            "authority": profile.authority,
        },
        "LEDGER-0.2-accounting-invariants": {
            "units": profile.units,
            "balance_rules": (
                profile.name
                + " is an ordered event/accounting ledger, not a fungible "
                "balance sheet. Its invariant is the exact authorized and ordered "
                "commit contract: "
                + profile.commit
            ),
            "rounding": (
                profile.name
                + " records exact discrete events and byte digests; it defines no "
                "numeric rounding convention or financial balance."
            ),
            "sources_and_sinks": profile.effects,
        },
        "LEDGER-0.3-correction-and-recovery": {
            "corrections": (
                profile.name
                + " does not rewrite an accepted history entry; later action is a "
                "new ordered event or a separately retained recovery operation."
            ),
            "replay": profile.retry,
            "reconciliation": profile.observations,
            "recovery": profile.recovery,
        },
    }


def _transaction(profile: _Profile) -> dict[str, dict[str, str]]:
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
                + " This finality is limited to the named local or remote state; "
                "it grants no broader correctness or publication authority."
            ),
            "partial_failure": profile.failure,
        },
        "TRANSACTION-0.3-retry-and-replay": {
            "duplicate_detection": profile.retry,
            "idempotency": (
                profile.name
                + " treats only the explicitly named digest, request, or invocation "
                "identity as duplicate evidence; no unstated idempotency is assumed."
            ),
            "retry_limits": profile.retry,
            "replay": profile.recovery,
        },
    }


def _asset(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "ASSET-0.1-identity-and-quantity": {
            "identity": profile.inputs,
            "rights": profile.authority,
            "units": profile.units,
            "precision": profile.limits,
        },
        "ASSET-0.2-issuance-and-redemption": {
            "issuance_authority": profile.authority,
            "supply_changes": profile.effects,
            "redemption": profile.recovery,
            "backing_claims": profile.boundary,
        },
        "ASSET-0.3-custody-and-encumbrance": {
            "custody": profile.targets,
            "control": profile.commands,
            "encumbrances": profile.failure,
            "reconciliation": profile.observations,
        },
    }


def _market(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "MARKET-0.1-orders-and-access": {
            "participant_access": profile.authority,
            "order_states": profile.states,
            "validation": profile.mechanism,
            "cancellation": profile.recovery,
        },
        "MARKET-0.2-matching-and-allocation": {
            "matching": profile.commands,
            "price_formation": profile.units,
            "allocation": profile.effects,
            "manipulation_controls": profile.limits,
        },
        "MARKET-0.3-settlement-and-disruption": {
            "settlement_dependencies": profile.targets,
            "finality": profile.commit,
            "participant_failure": profile.failure,
            "disruption": profile.recovery,
        },
    }


def _measurement(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "MEASUREMENT-0.1-phenomenon-and-method": {
            "phenomenon": profile.observations,
            "method": profile.mechanism,
            "source": profile.inputs,
            "observation_vs_estimate": (
                profile.name
                + " reports only the parent-boundary observations named here. "
                + profile.boundary
            ),
        },
        "MEASUREMENT-0.2-units-time-and-uncertainty": {
            "units": profile.units,
            "reference_frame": profile.targets,
            "observation_time": profile.timing,
            "arrival_time": (
                profile.name
                + " records parent receipt/completion ordering; it does not reconstruct "
                "an unobserved child or external event time."
            ),
            "uncertainty": profile.boundary,
        },
        "MEASUREMENT-0.3-validity-and-missingness": {
            "validity": profile.limits,
            "missingness": profile.failure,
            "freshness": profile.timing,
            "provenance": profile.mechanism,
        },
    }


def _sensor(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "SENSOR-0.1-acquisition-and-observations": {
            "acquisition": profile.mechanism,
            "phenomena": profile.observations,
            "measurements": profile.units,
            "deployment": profile.targets,
        },
        "SENSOR-0.2-calibration-and-envelope": {
            "calibration_applicability": (
                "Physical calibration is not applicable to "
                + profile.name
                + "'s digital parent-interface acquisition; parser and source pins are "
                "compatibility bindings, not metrological calibration."
            ),
            "calibration_evidence": profile.mechanism,
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


def _controller(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "CONTROLLER-0.1-feedback-and-authority": {
            "objectives": profile.scope,
            "feedback": profile.observations,
            "commands": profile.commands,
            "authority": profile.authority,
        },
        "CONTROLLER-0.2-timing-and-stability": {
            "timing": profile.timing,
            "stability_assumptions": (
                profile.name
                + " controls a bounded software lifecycle, not a proved dynamical "
                "plant; safe downstream stability remains outside this Tier-0 claim."
            ),
            "operating_envelope": profile.limits,
            "saturation": profile.failure,
        },
        "CONTROLLER-0.3-intervention-and-failure": {
            "feedback_loss": profile.failure,
            "arbitration": profile.ordering,
            "intervention": profile.commands,
            "failure_behavior": profile.recovery,
        },
    }


def _actuator(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "ACTUATOR-0.1-command-to-effect": {
            "commands": profile.commands,
            "targets": profile.targets,
            "effect_domains": profile.effect_domains,
            "authority": profile.authority,
        },
        "ACTUATOR-0.2-response-and-limits": {
            "units_and_frames": profile.units,
            "response": profile.observations,
            "limits": profile.limits,
            "saturation": profile.failure,
        },
        "ACTUATOR-0.3-feedback-and-interlocks": {
            "effect_feedback": profile.observations,
            "interlocks": profile.ordering,
            "failure_states": profile.failure,
            "recovery": profile.recovery,
        },
    }


def _protocol(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "PROTOCOL-0.1-participants-and-states": {
            "participants": profile.participants,
            "roles": profile.scope,
            "states": profile.states,
            "transitions": profile.protocol_transitions or profile.ordering,
        },
        "PROTOCOL-0.2-ordering-and-replay": {
            "message_authority": profile.authority,
            "ordering": profile.ordering,
            "replay": profile.retry,
            "compatibility": profile.mechanism,
        },
        "PROTOCOL-0.3-failures-and-progress": {
            "failure_assumptions": profile.failure,
            "safety": profile.limits,
            "liveness": profile.timing,
            "recovery": profile.recovery,
        },
    }


def _policy(profile: _Profile) -> dict[str, dict[str, str]]:
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
            "revisions": profile.mechanism,
            "activation": profile.states,
        },
        "POLICY-0.3-enforcement-and-decisions": {
            "enforcement_points": profile.mechanism,
            "decision_evidence": profile.observations,
            "bypass_handling": profile.limits,
            "unavailable_behavior": profile.failure,
        },
    }


def _robot(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "ROBOT-0.1-agent-to-actuator-binding": {
            "agent": profile.participants,
            "harness": profile.mechanism,
            "controllers": profile.commands,
            "actuators": profile.targets,
        },
        "ROBOT-0.2-physical-reach-and-observation": {
            "physical_reach": profile.effect_domains,
            "observations": profile.observations,
            "domain_crossings": profile.effects,
            "confinement_evidence": profile.limits,
        },
        "ROBOT-0.3-consequences-and-intervention": {
            "hazards": profile.failure,
            "operating_limits": profile.limits,
            "intervention": profile.commands,
            "safe_state_or_continuity": profile.recovery,
        },
    }


def _finbot(profile: _Profile) -> dict[str, dict[str, str]]:
    return {
        "FINBOT-0.1-agent-and-financial-authority": {
            "agent": profile.participants,
            "harness": profile.mechanism,
            "decision_scope": profile.scope,
            "financial_authority": profile.authority,
        },
        "FINBOT-0.2-financial-exposure-and-dependencies": {
            "assets_and_parties": profile.targets,
            "financial_dependencies": profile.effect_domains,
            "real_world_paths": profile.effects,
            "exposure_limits": profile.limits,
        },
        "FINBOT-0.3-decisions-effects-and-recovery": {
            "decision_effect_evidence": profile.observations,
            "limit_enforcement": profile.mechanism,
            "intervention": profile.commands,
            "reconciliation_and_recovery": profile.recovery,
        },
    }


_DECLARATION_BUILDERS = {
    "LEDGER": _ledger,
    "TRANSACTION": _transaction,
    "ASSET": _asset,
    "MARKET": _market,
    "MEASUREMENT": _measurement,
    "SENSOR": _sensor,
    "CONTROLLER": _controller,
    "ACTUATOR": _actuator,
    "PROTOCOL": _protocol,
    "POLICY": _policy,
    "ROBOT": _robot,
    "FINBOT": _finbot,
}


_CLAIM_GARDEN = _Profile(
    name="Claim Garden lifecycle",
    scope=(
        "Register one publisher, open one push, upload content-addressed objects, "
        "finalize the push, and submit one claim candidate through the explicit "
        "Claim Garden client states."
    ),
    mechanism=(
        "Canonical finite JSON over exact HTTPS origins with redirects disabled, "
        "bounded response reads, exact response fields, and source-level state checks."
    ),
    participants=(
        "The local client, a caller-selected publisher identity, its bearer "
        "credential, and the selected Claim Garden HTTPS endpoint."
    ),
    inputs=(
        "Exact endpoint, publisher/head coordinates, credential, object bytes, "
        "push manifest, claim bytes, and bounded expected response documents."
    ),
    authority=(
        "The caller explicitly selects the endpoint and operation; the endpoint "
        "accepts a registered bearer credential. Neither establishes legal, "
        "moderation, publication, or financial authority."
    ),
    states=(
        "Registration, open push, unique object storage, finalized push, and "
        "claim-candidate PENDING_REVIEW states are distinct and exact."
    ),
    ordering=(
        "Registration precedes authenticated work; a push is opened before object "
        "upload and finalized after uploads; claim submission follows its exact "
        "head and object bindings."
    ),
    commands=(
        "Create a credential file exclusively and issue the exact bounded HTTPS "
        "requests for registration, upload, finalization, and claim submission."
    ),
    targets=(
        "One exclusive local credential path and the explicitly selected Claim "
        "Garden registration, push, object, and claim endpoints."
    ),
    effect_domains=(
        "LOCAL_CREDENTIAL_AND_REMOTE_REVIEW_STATE_ONLY; public release, moderation "
        "outcome, physical effects, and payment are outside the represented target."
    ),
    effects=(
        "Create one local credential and request remote publisher, object, push, "
        "and claim-candidate records; transport may have occurred even when its "
        "response is unavailable."
    ),
    commit=(
        "Commit is only the exact accepted response for the named phase, including "
        "stored digests and PENDING_REVIEW where required."
    ),
    retry=(
        "The client performs no automatic retry after a transport attempt; exact "
        "content identities and server deduplication fields are checked where the "
        "protocol exposes them."
    ),
    timing=(
        "Each request has a finite timeout; no eventual remote progress, review "
        "completion, or publication deadline is promised."
    ),
    limits=(
        "HTTPS origin, JSON shape, byte counts, object counts, identifiers, digests, "
        "content types, and response states are bounded and fail closed."
    ),
    observations=(
        "The client observes bounded HTTP status, exact JSON response bytes, "
        "content digests, and declared remote lifecycle state only."
    ),
    units="Exact bytes, object counts, request phases, and SHA-256 identities.",
    failure=(
        "Pre-transport refusal is REJECTED; once a request may have reached the "
        "endpoint, an unavailable or inconsistent response remains INDETERMINATE "
        "or UNKNOWN and later phases are not assumed."
    ),
    recovery=(
        "Inspect the separately authenticated remote state before any manual retry; "
        "the client never treats a missing response as an abort or replays it "
        "automatically."
    ),
    boundary=(
        "Path-level phases are compound; bounded remote storage or PENDING_REVIEW "
        "does not establish publication, moderation, real-money transfer, or FINBOT "
        "responsibility."
    ),
)


_CORE_EXECUTOR = _Profile(
    name="core mechanism executor",
    scope=(
        "Select and evaluate caller-registered or built-in VERIFIER mechanisms "
        "against exact artifacts, evidence, propositions, profiles and bounds."
    ),
    mechanism=(
        "Core certification, evidence-session, witness, depth, translation and "
        "profile-obligation code validates selections, invokes admitted in-process "
        "mechanism callbacks, and retains typed decisions."
    ),
    participants=(
        "The trusted host caller, core VERIFIER evaluator, selected policy/profile, "
        "registered mechanism callbacks, and consumers of the returned decision."
    ),
    inputs=(
        "Exact artifact and evidence values, proposition bindings, profile and "
        "policy selections, registered mechanisms, thresholds, limits and probes."
    ),
    authority=(
        "The trusted host registers and selects mechanism code and policy. Core "
        "admission grants only in-process evaluation authority, not authority over "
        "any physical, financial, network or filesystem endpoint used by a callback."
    ),
    states=(
        "Unselected, admitted, evaluating, satisfied, refuted, unknown, unavailable, "
        "exceptional and retained-decision states."
    ),
    ordering=(
        "Input and policy validation precede callback entry; applicable mechanisms "
        "run under their declared composition order; results are checked before "
        "aggregation or certification."
    ),
    commands=(
        "Invoke the exact selected in-process verification, witness, differential-"
        "probe or certification mechanism with the admitted artifacts and evidence."
    ),
    targets=(
        "Caller-registered Python callback entry points and the selected in-memory "
        "artifact, evidence and decision structures."
    ),
    effect_domains=(
        "TRUSTED_IN_PROCESS_CALLBACK_EXECUTION; callback code runs with host-process "
        "authority and may have undeclared effects outside the represented decision."
    ),
    effects=(
        "Execute the admitted callback and construct a bounded VERIFIER decision, "
        "witness, probe result or certificate projection from its return or failure."
    ),
    commit=(
        "Commit is only retention or return of the typed core decision after its "
        "declared checks; callback return is not proof of downstream correctness."
    ),
    retry=(
        "No general callback idempotency or duplicate guard is assumed. A repeated "
        "evaluation is new execution and can repeat undeclared callback effects."
    ),
    timing=(
        "The core path declares no general callback timeout, preemption or real-time "
        "guarantee; a nonreturning callback can prevent progress."
    ),
    limits=(
        "Declared evidence, proposition and profile bounds constrain core data, but "
        "caller callback resources and side effects are not sandboxed by this path."
    ),
    observations=(
        "The core observes selected inputs, callback return values or exceptions, "
        "mechanism decisions, witness/probe outcomes and aggregate status only."
    ),
    units=(
        "Discrete mechanism calls, evidence items, profile depths, finite thresholds "
        "and exact artifact/proposition identities."
    ),
    failure=(
        "Invalid selection and known refutation fail closed; missing applicability, "
        "unavailable mechanism or unestablished evidence remains UNKNOWN. Callback "
        "side effects and interruption cannot be rolled back here."
    ),
    recovery=(
        "Inspect external state after callback uncertainty, correct the exact "
        "selection or mechanism, and explicitly start a new evaluation; never infer "
        "that an exception erased callback effects."
    ),
    boundary=(
        "Trusted in-process execution is not confinement. Successful return proves "
        "neither absence of side effects nor external correctness; physical or "
        "financial endpoints accumulate ROBOT or FINBOT and all applicable roles."
    ),
)


_CORE_PROVENANCE = _Profile(
    name="core provenance acquisition",
    scope=(
        "Acquire the current selected repository's Git coordinate and dirtiness, "
        "runtime-platform metadata, masked host identity, UTC capture time and exact "
        "hashes of caller-selected files."
    ),
    mechanism=(
        "Read selected files and Python platform APIs, sample the UTC clock, and run "
        "fixed Git rev-parse, config and status commands with captured text responses."
    ),
    participants=(
        "The caller, provenance collector, local filesystem and platform APIs, fixed "
        "Git child processes, selected repository and returned ProvenanceRecord."
    ),
    inputs=(
        "Caller-selected repository root, target and portable identifiers, declared "
        "command text and a finite sequence of selected key-file paths."
    ),
    authority=(
        "The caller selects readable local paths and permits fixed read-only Git "
        "queries; returned Git or platform text has no external attestation authority."
    ),
    states=(
        "Missing root, non-Git root, current Git/runtime capture, partial Git error, "
        "selected-file missing, complete record and fresh-retry states."
    ),
    ordering=(
        "Repository existence and Git membership are checked before fixed coordinate, "
        "remote and status queries; runtime/time and selected-file hashes are then "
        "assembled into one returned record."
    ),
    commands=(
        "Read selected files and platform values and launch only the fixed Git "
        "metadata/status argument vectors in the selected repository."
    ),
    targets=(
        "The selected local repository, selected key files, current Python process "
        "and operating-system-visible runtime and host metadata."
    ),
    effect_domains=(
        "READ_ONLY_LOCAL_SOFTWARE_OBSERVATION; Git process launch is an effect, but "
        "no repository mutation, physical actuation or remote request is intended."
    ),
    effects=(
        "Read local bytes and metadata, create fixed Git child processes, and return "
        "one in-memory provenance record."
    ),
    commit="Commit is return of the assembled record; no durable history is written.",
    retry=(
        "Every call reacquires current state. A prior record is historical data and "
        "cannot be replayed as a current capture."
    ),
    timing=(
        "captured_at_utc is sampled during record construction, not at every Git or "
        "file observation; Git calls have no explicit timeout in this mechanism."
    ),
    limits=(
        "Fixed Git argument vectors and caller-selected finite key files bound intent, "
        "but repository size, Git response size and command duration are not explicitly bounded."
    ),
    observations=(
        "Commit, branch, dirty and untracked paths, redacted remote, Python/platform "
        "identity, masked hostname, UTC timestamp and selected SHA-256 file hashes."
    ),
    units=(
        "Exact UTF-8 Git text, Boolean dirtiness, discrete paths, byte-oriented "
        "SHA-256 identities and an ISO-8601 UTC timestamp."
    ),
    failure=(
        "Missing/non-Git roots and Git errors become explicit sentinel values; "
        "missing key files are omitted. Exceptions are not evidence of a clean tree "
        "or complete observation."
    ),
    recovery=(
        "Correct repository/tool/file availability and perform a new capture; do not "
        "promote sentinel, omitted or stale fields to current observations."
    ),
    boundary=(
        "This is host-visible software acquisition, not hostile-host attestation, "
        "physical calibration, confinement or proof that a represented command ran."
    ),
)


_CORE_RECEIPT = _Profile(
    name="core receipt publication",
    scope=(
        "Serialize one in-memory VSTD receipt and publish its receipt, claim, manifest, "
        "optional execution log and Markdown report under a caller-selected directory."
    ),
    mechanism=(
        "Compute canonical payload and SHA-256 identities, create directories, and "
        "perform ordered pathlib text writes for each derived file."
    ),
    participants=(
        "The direct caller, mutable VstdReceipt, local filesystem, selected output "
        "directory and later local receipt consumer."
    ),
    inputs=(
        "One validated receipt object, its claim/evidence/audit/provenance metadata, "
        "optional execution metadata and caller-selected output path."
    ),
    authority=(
        "The direct caller plus local filesystem permissions authorize writes to the "
        "selected path; receipt content grants no publication or external authority."
    ),
    states=(
        "In-memory, directory-created, receipt-written, claim-written, manifest-"
        "written, optional-log-written, report-written, partial-failure and complete."
    ),
    ordering=(
        "Digest computation precedes receipt and claim writes; their current bytes "
        "feed the manifest; optional log and report follow."
    ),
    commands="Create selected directories and write the fixed derived file set.",
    targets="The caller-selected local output directory and its fixed child paths.",
    effect_domains=(
        "LOCAL_MULTI_FILE_PUBLICATION_ONLY; no remote publication, physical effect, "
        "real-money effect or external witness is represented."
    ),
    effects=(
        "Create or replace several local files and directories containing the "
        "receipt projection and human-readable report."
    ),
    commit=(
        "Each write commits separately when pathlib returns; the method returns only "
        "after the final report write, but there is no atomic group commit or fsync."
    ),
    retry=(
        "No duplicate guard or exclusive-create rule is present. Retrying can replace "
        "earlier files and can mix with files retained by a partial prior attempt."
    ),
    timing="No deadline, lock, crash-durability or concurrent-writer exclusion is declared.",
    limits=(
        "The fixed filenames bound layout, but total serialized size, output-root "
        "ownership, free space and pre-existing child content are not bounded here."
    ),
    observations=(
        "The method observes local write success and rereads receipt/claim bytes for "
        "manifest hashes; it does not revalidate all final files after completion."
    ),
    units="Exact UTF-8/JSON/Markdown bytes, fixed file names and SHA-256 identities.",
    failure=(
        "Any filesystem or serialization exception stops later writes while earlier "
        "files and directories can remain; no automatic rollback or compensation occurs."
    ),
    recovery=(
        "Inspect every selected path and its hashes, preserve unrelated later edits, "
        "and explicitly rebuild into a safely selected directory; no retained journal "
        "proves rollback."
    ),
    boundary=(
        "Local files are not an atomic, crash-durable or externally witnessed receipt, "
        "and they do not prove that represented verification actually occurred."
    ),
)


_CONTROLLED_EMISSION = _Profile(
    name="controlled emission session",
    scope=(
        "Admit a bounded caller-supplied callback only while an in-process session "
        "is accepting, below capacity, unspent, and not permanently stop-latched."
    ),
    mechanism=(
        "An RLock-protected session rechecks stop, capacity, and one-use invocation "
        "identity immediately before releasing the lock to call the callback."
    ),
    participants=(
        "The trusted host caller, controlled-operation session, optional authenticated "
        "stop evaluator, and caller-supplied in-process callback."
    ),
    inputs=(
        "One invocation identifier, callback, configured capacity, and any selected "
        "authenticated stop request/policy."
    ),
    authority=(
        "The host supplies callback authority and stop policy; the session grants "
        "only one in-process callback admission and cannot confer downstream endpoint "
        "authority."
    ),
    states="Accepting, active, permanently stopped, spent, completed, and unavailable states.",
    ordering=(
        "Stop/capacity/replay checks and reservation are atomic under the lock; the "
        "callback runs outside the lock; completion decrements the active count."
    ),
    commands="Latch STOP or submit one already-authorized callback invocation.",
    targets=(
        "The supplied in-process callback entry point; its downstream physical, "
        "financial, network, and filesystem endpoints are not represented here."
    ),
    effect_domains=(
        "CALLBACK_SUBMISSION_ONLY; callback return is not proof of any downstream "
        "effect and external endpoint roles must be represented separately."
    ),
    effects=(
        "Reserve a one-use invocation, increment/decrement active admission state, "
        "and call the supplied callback once after the final admission check."
    ),
    commit="Commit means that this session called the callback and observed its return value.",
    retry=(
        "A spent invocation identifier is refused; callback exception or interruption "
        "does not make an automatic retry safe."
    ),
    timing=(
        "Stop waiting uses a bounded monotonic deadline; an active callback is "
        "cooperative and cannot be preempted by this session."
    ),
    limits="Configured active capacity and one-use identifiers bound admission.",
    observations=(
        "The session observes its lock-protected state, active count, stop decision, "
        "callback return, and callback exception only."
    ),
    units="Discrete callback admissions, active-count slots, and monotonic timeout seconds.",
    failure=(
        "Stopped, duplicate, or over-capacity admission fails closed; unavailable "
        "stop/clock behavior remains UNKNOWN; active callbacks may continue."
    ),
    recovery=(
        "A stop latch is permanent for the session. Restart or downstream effect "
        "reconciliation requires a separately authorized mechanism."
    ),
    boundary=(
        "Only cooperating in-process calls are mediated. Callback submission is not "
        "downstream effect proof; physical or financial endpoints accumulate ROBOT "
        "or FINBOT and all other applicable roles."
    ),
)


_DIGEST_VALIDATION = _Profile(
    name="digest validation loop",
    scope=(
        "Authorize and execute one exact ordered, bounded list of host-selected "
        "validation targets under a canonical request and policy decision."
    ),
    mechanism=(
        "Canonical request bytes, exact target digests, a finite step/resource "
        "budget, and deterministic target dispatch bind each local validation step."
    ),
    participants="The trusted host selector, validation-loop controller, and fixed validation mechanism.",
    inputs=(
        "Exact canonical request, target identifiers and digests, maximum steps, "
        "reserved bytes, and the host policy's approval of those exact bytes."
    ),
    authority=(
        "Only the host policy may approve the exact request; approval is local "
        "validation authority, not permission for arbitrary subject execution."
    ),
    states="Requested, policy-refused, target-active, exhausted, PASS, FAIL, and UNKNOWN states.",
    ordering="Targets execute once in their declared deterministic order until a bounded stop condition.",
    commands="Dispatch the fixed validation mechanism for the next exact digest target or stop.",
    targets="The finite declared target list and local fixed validation mechanism.",
    effect_domains="LOCAL_VALIDATION_DECISION_ONLY; subject execution and external effects are excluded.",
    effects="Produce bounded local target decisions and a replayable aggregate validation response.",
    commit="Commit means all declared local target steps completed under the exact request and bounds.",
    retry="Replay reconstructs the same declared target sequence; it adds no omitted targets or semantic truth.",
    timing="Finite step and byte budgets bound work; no wall-clock or external progress guarantee is made.",
    limits="Target count, ordering, identifiers, digests, steps, and reserved bytes are explicit and finite.",
    observations="Per-target local outcomes, evidence, stop reason, and exact aggregate response.",
    units="Discrete validation steps, reserved bytes, and SHA-256 target identities.",
    failure="Policy refusal, exhausted bounds, target failure, or unavailable evaluation cannot become PASS.",
    recovery="Correct the exact request/policy/evidence and start a new bounded loop; replay is not an override.",
    boundary=(
        "Digest equality and declared-target exhaustion do not establish semantic "
        "correctness, geometry closure, sandboxing, or an undeclared target set."
    ),
)


_FINITE_RECORD = _Profile(
    name="finite OBJECT record issuance",
    scope=(
        "Assess exactly one generic OBJECT-1.1 record, bind authenticated host and "
        "public-checkability evidence, precommit its exact bytes, consume one local "
        "invocation, verify a distinct signed postcommit, and replay the final attestation."
    ),
    mechanism=(
        "Canonical bounded records, exact source/input/mechanism digests, configured "
        "authority and Ed25519 status checks, one invocation-ledger commit, and "
        "independent reconstruction bind every issuance phase."
    ),
    participants=(
        "The trusted operator host selection, finite issuer, authority evaluator, "
        "public-checkability evaluator, local invocation ledger, postcommit status "
        "signer and later replay verifier."
    ),
    inputs=(
        "Exact finite bundle, request, issuance evidence, native/public policies and "
        "certificate, authenticated host policies and ledger selection, trusted "
        "times, local commit receipt and distinct signed postcommit bytes."
    ),
    authority=(
        "The host-selected authority policy, exact action scope, current status role, "
        "configured ledger identity/generation and distinct postcommit public key "
        "authorize only this finite local issuance."
    ),
    states=(
        "Captured, denominator-refused, assessed PASS/FAIL/UNKNOWN, precommitted, "
        "ready-for-local-commit, locally committed, postcommit-unavailable/refuted, "
        "issued, replayed and full-application-UNKNOWN states."
    ),
    ordering=(
        "Bounded input capture and exact finite denominator precede native/public and "
        "authority assessment; identical precommit reconstruction precedes one ledger "
        "commit; a distinct current signed postcommit precedes finalization and replay."
    ),
    commands=(
        "Assess the fixed finite record, consume one exact invocation through the "
        "selected local ledger, validate a separately supplied signed postcommit, and "
        "recheck the retained attestation."
    ),
    targets=(
        "One exact generic OBJECT record/certificate, one configured local invocation "
        "ledger coordinate and one separately signed finite-commit status statement."
    ),
    effect_domains=(
        "LOCAL_FINITE_RECORD_ISSUANCE_ONLY; full package polish, transport, publication, "
        "human acceptance, physical actuation and real-money effects are excluded."
    ),
    effects=(
        "Consume one invocation in the selected local ledger and return bounded "
        "precommit, local-commit, issued-attestation and replay records."
    ),
    commit=(
        "Commit is the invocation ledger's atomic exact-proposal consumption at the "
        "selected time. Final issuance additionally requires the SAME receipt and a "
        "distinct current signed postcommit; no full-application claim is committed."
    ),
    retry=(
        "The invocation identifier and ledger uniqueness reject duplicate consumption; "
        "assessment/replay are pure rechecks, while commit is never automatically retried."
    ),
    timing=(
        "Trusted assessment/commit time must equal the exact action time and signed "
        "postcommit validity/current-observation windows; no external progress or "
        "publication deadline is represented."
    ),
    limits=(
        "Closed schemas, one object/node/certificate, exact document denominator, "
        "bounded byte transports, canonical encodings, source/input pins and one "
        "finite action scope fail closed."
    ),
    observations=(
        "Exact assessment, authority, native/public, ledger receipt and signed-status "
        "digests plus explicit FAIL/UNKNOWN reasons and replay correspondence."
    ),
    units=(
        "Exact bytes and SHA-256 identities, one discrete invocation/record, integer "
        "policy epochs and commit sequences, and trusted integer timestamps."
    ),
    failure=(
        "Known contract, selection, authority, signature or replay contradiction is "
        "FAIL; absent host/input/clock/backend/status evidence is UNKNOWN; neither can "
        "be promoted to polished or full-application PASS."
    ),
    recovery=(
        "Retain the exact precommit and ledger receipt, reacquire missing independent "
        "status/time/input evidence, and replay the SAME bytes. A new commit requires "
        "a new authorized invocation rather than inferred rollback."
    ),
    boundary=(
        "Every output keeps full_application_status UNKNOWN and polished false. The "
        "route performs no transport, publication, human acceptance, physical action "
        "or real-money decision."
    ),
)


_GATE_PIPELINE = _Profile(
    name="gate pipeline",
    scope=(
        "Schedule a manifest-declared dependency DAG, launch each bounded command "
        "when its prerequisites pass, and retain one aggregate receipt."
    ),
    mechanism=(
        "The runner binds manifest, selected input, executable, and implementation "
        "digests; launches without a shell; bounds streams and time; and rechecks "
        "inputs before retaining the receipt."
    ),
    participants="The caller, gate-pipeline parent, declared command processes, and receipt consumer.",
    inputs=(
        "Exact manifest DAG, root, selected input bytes, executable identities, "
        "arguments, result contracts, timeouts, and output bounds."
    ),
    authority=(
        "The caller-selected manifest is command-launch authority for arbitrary local "
        "executables named by argv; it is not a closed command set, subject sandbox "
        "or endpoint authority."
    ),
    states="Planned, blocked, running, PASS, FAIL, UNKNOWN, timeout, output-limit, and cleaned-up states.",
    ordering="A topological dependency order admits a step only after all named prerequisites pass.",
    commands=(
        "Launch the caller-selected argv[0] executable (manifest-relative or PATH-resolved, "
        "never a shell or .bat/.cmd) with up to 127 caller-selected arguments, then "
        "signal the owned process group/tree during cleanup."
    ),
    targets="Declared local executables/process groups and one exclusive aggregate receipt path.",
    effect_domains=(
        "PROCESS_LAUNCH_AND_RECEIPT_ONLY; command submission does not establish child "
        "or downstream external effects and is not a sandbox."
    ),
    effects="Start declared processes, capture bounded streams, terminate owned process groups, and create one receipt.",
    commit=(
        "Commit means the exclusive receipt was retained after current-input and "
        "implementation rechecks; process exit is not transactional commit of child effects."
    ),
    retry="The pipeline performs no implicit command retry; a new run creates a distinct observation.",
    timing="Each step has a finite timeout and bounded cleanup interval; no child progress beyond that boundary is promised.",
    limits="At most 64 DAG steps with finite input, output, argument, path, process, and timeout bounds.",
    observations="Parent-observed exit, result contract, bounded stdout/stderr, cleanup disposition, and input equality.",
    units="Discrete DAG steps, process exit codes, bytes, and monotonic timeout seconds.",
    failure="Dependency failure blocks dependents; timeout/output excess/error remains explicit; cleanup may remain UNKNOWN.",
    recovery="Inspect the receipt and external child state, correct inputs, and explicitly start a new run; no effect rollback is claimed.",
    boundary=(
        "Process-command submission is not proof of downstream effect or confinement; "
        "physical or financial endpoints accumulate ROBOT or FINBOT and all other roles."
    ),
)


_GATED_PUBLICATION = _Profile(
    name="gated private-review submission",
    scope=(
        "Prepare exact gate-bound evidence locally, inspect one authenticated account "
        "coordinate, and optionally submit once for private human review."
    ),
    mechanism=(
        "Exact gate receipt projection, native certificate replay, bounded disclosure "
        "scan, authenticated HTTPS account preflight, and strict stored-response binding."
    ),
    participants="The local preparer, registered publisher, and selected Claim Garden private-review endpoint.",
    inputs=(
        "Exact artifact, request, certificate, gate receipt, policy, publisher identity, "
        "credential, endpoint, private-retention consent, and optional checker coordinate."
    ),
    authority=(
        "The caller must provide explicit private-review retention consent and a "
        "linked publisher credential; this grants neither public release nor payment authority."
    ),
    states="Locally PREPARED, account-preflighted, STORED/PENDING_REVIEW, rejected, or response-UNKNOWN.",
    ordering="Local preparation precedes credential access; account preflight precedes the one POST submission.",
    commands="Read the account coordinate or issue one consent-marked private-review submission.",
    targets="Exact local input paths and the selected Claim Garden account/submission endpoints.",
    effect_domains="PRIVATE_REMOTE_REVIEW_STORAGE_ONLY; preparation sends nothing and public release is excluded.",
    effects="Optionally create a local prepared file and request one charged private-review remote submission record.",
    commit="Commit is the exact STORED/PENDING_REVIEW response bound to payload, coordinate, quota charge, and deduplication state.",
    retry="There is no automatic POST retry; response uncertainty remains UNKNOWN and requires remote inspection.",
    timing="One bounded account read and one bounded submission request; human review progress has no promised deadline.",
    limits="Exact selected roots, bytes, digests, JSON fields, disclosure scan, quota, HTTPS origin, and response bounds.",
    observations="Account linkage/quota/coordinate and the exact stored or negative bounded response.",
    units="Exact UTF-8 bytes, quota bytes, request count, and SHA-256 identities.",
    failure="Local refusal sends nothing; after POST is attempted, unavailable or inconsistent response remains UNKNOWN.",
    recovery="Inspect authenticated remote submission state before any new explicit submission; never infer abort from silence.",
    boundary=(
        "Preparation sends nothing; remote PENDING_REVIEW does not establish public "
        "release, review outcome, payment, moderation, or financial authority."
    ),
)


_JAVASCRIPT_PARSER = _Profile(
    name="JavaScript parser exchange",
    scope=(
        "Send exact JavaScript/TypeScript source bytes to the fixed isolated parser "
        "worker and return a bounded static syntax-surface census."
    ),
    mechanism=(
        "A fixed Python -I -B worker binds its own digest and pinned tree-sitter "
        "distribution bytes before and after parsing."
    ),
    participants="The parent discovery adapter and fixed isolated JavaScript parser worker.",
    inputs="Ordered path/source-byte pairs, exact language selection, protocol version, and finite capacity bounds.",
    authority="Only the parent may submit the exact parser request; neither side receives authority to run subject code.",
    states="Request admitted, parsed with surfaces/gaps, parser unavailable, capacity-exhausted, or protocol-refused.",
    ordering="Response rows must correspond one-for-one and in order to the submitted source rows.",
    commands="Parse supplied bytes using pinned grammars and return static surface and gap records.",
    targets="The fixed worker process and the supplied in-memory source bytes only.",
    effect_domains="STATIC_PARSE_ONLY; subject import, execution, reachability, and runtime effect are excluded.",
    effects="Create one child parser process and return its bounded response; no subject program is executed.",
    commit="Commit is a well-formed response bound to every exact input source and parser byte identity.",
    retry="A new parse may repeat the same pure request; previous response prose is never authority for changed bytes.",
    timing="The parent enforces a finite worker timeout; parser completion beyond it is unavailable.",
    limits="Input/output bytes, AST node count, path identity, response fields, and parser versions are finite and exact.",
    observations="Static declarations, exports, role markers, source digests, unresolved gaps, and parser mechanism bytes.",
    units="Exact source bytes, AST node counts, source line numbers, and SHA-256 identities.",
    failure="Parser absence, syntax gaps, dynamic exports, timeout, or response mismatch remains an explicit gap/refusal.",
    recovery="Install the pinned optional parser or provide corrected exact source and rerun; never execute subject code for discovery.",
    boundary="Static syntax parsing proves neither runtime reachability nor any subject or external effect.",
)


_PACKAGE_WORKER = _Profile(
    name="package worker exchange",
    scope=(
        "Dispatcher captures source and request; worker returns observations; parent "
        "checks correspondence before route predicates."
    ),
    mechanism=(
        "Exact registered request and response versions; no implicit version negotiation."
    ),
    participants="Installed dispatcher and one selected fixed local worker process.",
    inputs="Exact checker identifier, request bytes, owned source pins, implementation digest, nonce, and finite subprocess bounds.",
    authority="Closed installed worker selection and host interpreter are trust assumptions; no external authentication claim.",
    states="Source capture, launch, reply parsing, request/source validation, return or refusal.",
    ordering="One request and one captured terminal response per invocation; no multiplexed or distributed ordering claim.",
    commands="Launch the fixed worker for one selected checker and decode one bounded response.",
    targets="One fresh local child process and the parent-side stdin/stdout/stderr/return-code boundary.",
    effect_domains="PARENT_WORKER_INTERFACE_ONLY; child internals, descendants, external effects, and confinement are unobserved.",
    effects="Start one fixed checker child and acquire its parent-visible process response without arbitrary command dispatch.",
    commit="Commit is one complete, source-bound checker response plus parent-boundary observation, not the truth of child claims.",
    retry="Fresh nonce plus exact object and collection commitments; failed launches do not automatically retry.",
    timing="A 30-second subprocess timeout bounds waiting under the host contract; output is bounded after capture, not streaming memory.",
    limits="Malformed, substituted, stale or oversized replies cannot supply a validated exchange.",
    observations=(
        "Return code; stdout/stderr byte counts, retained prefixes, SHA-256 digests, "
        "truncation/completeness; and whether a decodable response arrived."
    ),
    units="Process exit code, exact bytes, byte counts, completeness flags, and SHA-256 digests.",
    failure="Trusted host interpreter, filesystem and subprocess transport; injected faults are finite controls, not arbitrary-host safety.",
    recovery="Unavailable execution remains UNKNOWN; invalid response remains FAIL at evaluation; neither authorizes automatic retry.",
    boundary=(
        "Only the parent interface is observed. Child internals, descendants, "
        "external effects, and confinement remain UNOBSERVED and NOT_ESTABLISHED."
    ),
    protocol_transitions=(
        "Only zero exit, bounded strict output, exact request and recaptured "
        "source pins permit return."
    ),
)


_PERMISSION_SLOT = _Profile(
    name="permission-slot lifecycle",
    scope=(
        "Verify one grant, register one invocation, support revoke/cancel/drain, "
        "admit at most one callback entry, and optionally admit one separately "
        "verified successor."
    ),
    mechanism=(
        "A lock-protected state machine combines external grant verification and "
        "entry observation with a bounded hash-linked local event trace and optional "
        "exact external trace anchor."
    ),
    participants="Grant verifier, permission-slot controller, caller, entry observer, callback, and optional successor verifier.",
    inputs="Exact grant/ticket/restart identities, verifier decisions, entry observation, callback, and optional trace anchor.",
    authority="External verifiers establish the named grant/successor admission; the slot cannot mint endpoint authority.",
    states="Empty, granted, registered, entering, active, revoked, cancelled, drained, completed, and successor-admitted states.",
    ordering="Grant precedes registration; revoke/cancel races are rechecked at callback entry; drain precedes successor admission.",
    commands="Grant, register, cancel, revoke, drain, invoke one callback, or admit one separately verified successor.",
    targets="One in-process callback entry and the local permission-slot lifecycle/trace state.",
    effect_domains="CALLBACK_ENTRY_AND_LOCAL_TRACE_ONLY; downstream endpoint execution and effect replay are excluded.",
    effects="Mutate local lifecycle state, append bounded events, and submit one admitted callback invocation.",
    commit="Commit means one callback entry was admitted and its local completion event retained; no downstream effect commit is claimed.",
    retry="Ticket and entry identities are one-use; stale/cancelled/revoked entry and duplicate successor attempts are refused.",
    timing="Revocation, entry, drain, and successor races are serialized at the lock; callbacks are not preempted.",
    limits="One slot, one registered invocation, one successor, bounded event trace, exact identifiers, and verifier decisions.",
    observations="Local lifecycle events, callback entry/completion, revoke/cancel/drain, verifier outcomes, and optional anchor equality.",
    units="Discrete lifecycle events, invocation count, successor count, and SHA-256 chain identities; no financial unit.",
    failure="Refused or unavailable verification blocks entry; active callbacks may finish; trace/anchor mismatch remains explicit.",
    recovery="Drain/cancel/revoke and separately verify a successor; local trace cannot reconstruct downstream effects.",
    boundary=(
        "The bounded trace is local in-memory history with an optional exact anchor, "
        "not durable global or financial accounting. Callback admission is not effect "
        "proof; endpoint roles accumulate separately."
    ),
)


_POLISH_WORKFLOW = _Profile(
    name="polish preparation workflow",
    scope=(
        "Admit one explicitly selected preparation command, run policy-selected "
        "stages over exact source bytes, retain an immutable bundle and append-only "
        "local journal, and optionally apply a compare-before-replace recovery plan."
    ),
    mechanism=(
        "Fail-closed command-option compatibility, canonical policy and source "
        "inventories, fixed stage DAG, implementation pins, hash-chained journal "
        "events, immutable retained bundles and per-file compare-before-replace mutations."
    ),
    participants="The caller, workflow command handler, selected local stage mechanisms, retained bundle/journal, and source workspace.",
    inputs="Exact policy, selected source paths/bytes/modes, mechanism pins, optional definitions/quality/requirements, and apply authority.",
    authority="The caller selects policy and must explicitly request apply with an external retained journal directory.",
    states="Check-only, preparation-started, stage outcomes, bundle-retained, pending-commit, apply-started, rolled-back, or recovery-required.",
    ordering="Command compatibility precedes workflow dispatch; the fixed stage DAG runs dependencies first, and source and implementations are rechecked before bundle retention or apply.",
    commands="Route one admitted preparation, recovery or association command, dispatch selected stages, retain journal/bundle, and optionally replace each changed file under an exact plan.",
    targets="Selected workspace files and an external retention directory containing immutable bundles, attempts, events, and apply plans.",
    effect_domains="LOCAL_PREPARATION_AND_PER_FILE_APPLY; polish, publication, and multi-file atomicity are expressly excluded.",
    effects="Retain local artifacts/journal and, only on explicit apply, replace selected files one at a time with recovery data.",
    commit="Commit is a verified per-file replacement under the retained plan; the operation is not atomic across files and does not confer polish.",
    retry="Resume never trusts carried PASS and reruns all selected dispatchers; recovery accepts only exact before/after bytes.",
    timing="Stage order is deterministic, but no wall-clock completion, exclusive filesystem ownership, or concurrent-writer exclusion is promised.",
    limits="Selected paths, files, bytes, stages, records, traversal, retained payload, and plain data are all finitely bounded.",
    observations="Source inventories/modes, stage outcomes, findings, implementation pins, journal chain, bundle and apply-plan digests.",
    units="Exact bytes, file modes, stage/event counts, and SHA-256 identities; no financial balance.",
    failure="Incompatible command selectors or required stage failure block work; changed source or partial apply retains explicit rollback/recovery state.",
    recovery="Use the retained apply plan to finish or roll back only files still matching exact before/after bytes; preserve later edits.",
    boundary=(
        "The journal is unwitnessed local chronology, not external authority or "
        "financial accounting. Preparation/apply is not multi-file atomic and "
        "establishes no polish tier, publication, or exclusive filesystem ownership."
    ),
)


_SIM_PUBLICATION = _Profile(
    name="SIM artifact submission",
    scope=(
        "Validate and transmit one exact SIM artifact/certificate/request envelope "
        "to the selected Claim Garden artifact endpoint and verify its quarantined state."
    ),
    mechanism=(
        "Exact canonical JSON bytes, source digest, native certificate replay, model "
        "transition and initial-state checks, authenticated bounded HTTPS, and strict response fields."
    ),
    participants="The local SIM verifier client, registered publisher credential, and selected Claim Garden artifact endpoint.",
    inputs="Exact SIM artifact, request, certificate, policy, publisher identity, credential, endpoint, and expected byte/digest bindings.",
    authority="The caller and bearer credential authorize one remote artifact submission, not publication, payment, or physical execution.",
    states="Locally validated, transport-attempted, STORED/QUARANTINED, rejected, INDETERMINATE, or UNKNOWN.",
    ordering="Local exact-byte and native replay checks precede one authenticated artifact POST.",
    commands="Issue one exact-byte authenticated SIM artifact upload after all local checks pass.",
    targets="The selected Claim Garden SIM artifact endpoint and its quarantined remote record.",
    effect_domains="REMOTE_QUARANTINED_STORAGE_ONLY; public, physical, monetary, and scientific-validity effects are excluded.",
    effects="Request creation of one remote quarantined artifact record; transport may have occurred without an available response.",
    commit="Commit is the exact STORED/QUARANTINED response bound to artifact, request, certificate, publisher, and retrieval path.",
    retry="No automatic retry follows a transport attempt; response uncertainty requires separate remote inspection.",
    timing="One bounded HTTPS request with finite timeout; quarantine review/publication progress has no guarantee.",
    limits="Canonical shape, exact digests, SIM/native bindings, model transition, endpoint, response bytes, and fields are bounded.",
    observations="Local validation result and bounded HTTP status/body establishing only the declared quarantined storage state.",
    units="Exact artifact/request/certificate bytes, request count, and SHA-256 identities.",
    failure="Pre-transport mismatch refuses; after transport, missing or inconsistent response remains INDETERMINATE/UNKNOWN.",
    recovery="Inspect authenticated remote artifact state before an explicit new attempt; never infer remote abort or publication.",
    boundary=(
        "Remote quarantined storage does not establish scientific validity, public "
        "release, physical effects, payment, or publication authority."
    ),
)


_SYSTEMS_PARSER = _Profile(
    name="Rust/Bash parser exchange",
    scope=(
        "Send exact Rust or Bash source bytes to the fixed isolated worker and "
        "return a static syntax census with explicit expansion/dynamic gaps."
    ),
    mechanism=(
        "A fixed Python -I -B worker binds pinned tree-sitter core/grammar distribution "
        "bytes and source digests before returning ordered surface/gap rows."
    ),
    participants="The parent systems adapter and fixed isolated Rust/Bash parser worker.",
    inputs="Ordered exact source bytes, selected Rust/Bash language, protocol version, and finite capacities.",
    authority="The parent authorizes parsing only; no Cargo, macro expansion, shell sourcing, or command evaluation is authorized.",
    states="Requested, parsed, explicit syntax/dynamic gap, parser unavailable, capacity exhausted, or protocol refused.",
    ordering="Each language is parsed under its own pinned mechanism and response rows preserve submitted file order.",
    commands="Parse bytes with the selected pinned grammar and return static declarations, hints, role markers, and gaps.",
    targets="The fixed parser worker and supplied in-memory Rust/Bash bytes only.",
    effect_domains="STATIC_PARSE_ONLY; macro expansion, sourced shell state, command execution, reachability, and effects are excluded.",
    effects="Create one parser child per selected language and return bounded static rows; no subject build or shell runs.",
    commit="Commit is a source- and parser-byte-bound response for every submitted file of that language.",
    retry="A repeat parse is a new current-byte check; prior parser output cannot cover changed sources or unresolved expansions.",
    timing="The parent enforces a finite worker timeout; no subject runtime progress is involved.",
    limits="Input/output bytes, nodes, paths, fields, parser versions, languages, and syntax rows are finite and exact.",
    observations="Static Rust/Bash definitions, exports/commands, source role markers, source digests, and unresolved gaps.",
    units="Exact source bytes, AST node counts, line numbers, and SHA-256 identities.",
    failure="Unavailable grammar, syntax error, macro/module/export gap, dialect ambiguity, or dynamic shell dispatch remains explicit.",
    recovery="Install the pinned grammar or bind missing source/expansion/dialect evidence and rerun without executing subject code.",
    boundary="Static parsing expands no macro, sources no shell, and proves neither runtime reachability nor effects.",
)


_TRAIN_CONTROL = _Profile(
    name="TRAIN control session",
    scope=(
        "Mediate one authenticated TRAIN action against exact plan, policy, current "
        "capability, stop, attribution, target, and bounded session-event state."
    ),
    mechanism=(
        "A lock-protected session checks canonical Ed25519 operation bytes, native "
        "TOKEN authority, revocation/status freshness, one-use request identity, "
        "current plan endpoints, and the final live boundary before callback entry."
    ),
    participants="Trusted host, configured root/executor principals, TRAIN session, capability authority provider, stop policy, and host callback.",
    inputs="Exact plan/policy/session/action/target/change digests, signed operation, capability snapshot, trusted clock, and optional checkpoint/fork bytes.",
    authority="Configured host root/executor keys and current native TOKEN grants authorize the exact operation; MODEL-origin proposals are denied.",
    states="Preflight, admitted, active, stopped, spent, revoked/suspended, PASS, FAIL, UNKNOWN, and retained-event states.",
    ordering="All authority/stop/replay checks and reservation occur under the lock before one callback runs outside it and completion is recorded.",
    commands=(
        "Latch authenticated STOP or submit one exact protected TRAIN action callback, "
        "including binding mutation, activation, launch, fork, delegation, model/evaluator "
        "change, or checkpoint write only when the selected plan permits it."
    ),
    targets="One declared TRAIN/target revision and caller-supplied trusted-host callback entry.",
    effect_domains="TRAIN_CALLBACK_SUBMISSION_ONLY; downstream training, hardware, physical, and financial effects remain separate.",
    effects="Spend one request/capability use, call the host effect once, and append one bounded local EVENT outcome.",
    commit=(
        "Commit means the host callback returned or raised and the session attempted "
        "to retain its completion EVENT; retention is not guaranteed when the plan "
        "context cannot be resolved, and downstream checkpoint/training truth is not established."
    ),
    retry="Request identifiers and capability invocation ceilings prevent replay; callback uncertainty is not automatically retried.",
    timing="Trusted clock freshness and grant windows are rechecked at the final boundary; active callbacks are not preempted.",
    limits="Finite keys, principals, scopes, evidence bytes, events, status age, invocation ceilings, and exact plan targets.",
    observations="Current authority generation/digest, clock, local stop/revocation/use state, callback return/exception, and retained EVENT chain.",
    units="Discrete capability uses/events, integer trusted-clock observations, exact bytes, and SHA-256 identities.",
    failure="Malformed/refuted authority fails; unavailable clock/provider/backend remains UNKNOWN; STOP prevents new admission but not active preemption.",
    recovery="Use a new root-authorized session/current authority view; retained denial replay proves only its bounded historical predicate.",
    boundary=(
        "Trusted-host mediation is not a sandbox, and callback submission is not "
        "downstream effect proof. Physical or financial endpoints accumulate ROBOT "
        "or FINBOT and every other applicable role."
    ),
)


_WORKFLOW_PARSER = _Profile(
    name="workflow parser exchange",
    scope=(
        "Send exact YAML workflow/action bytes and selected local reference digests "
        "to the fixed worker, then return static node, command, reference, and gap rows."
    ),
    mechanism=(
        "A fixed Python -I -B worker pins PyYAML bytes, uses BaseLoader composition, "
        "rejects aliases/tags/directives/duplicate keys, and rebinds source digests."
    ),
    participants="The parent workflow adapter and fixed isolated YAML workflow parser worker.",
    inputs="Ordered exact workflow/action source bytes, selected local path/digest map, protocol version, and finite capacities.",
    authority="The parent authorizes static parsing only; no referenced action download or workflow command execution is authorized.",
    states="Requested, parsed with rows/gaps, parser unavailable, malformed workflow, capacity exhausted, or protocol refused.",
    ordering="Response files preserve request order; workflow/job/step/reference ordering follows the composed YAML declaration.",
    commands="Compose YAML nodes and decode command/reference declarations without running or downloading them.",
    targets="The fixed parser worker and supplied in-memory YAML/local-reference bytes only.",
    effect_domains="STATIC_DECLARATION_PARSE_ONLY; action download, expression evaluation, and workflow execution are excluded.",
    effects="Create one parser child and return bounded static rows; no workflow step or action is executed.",
    commit="Commit is a source- and PyYAML-byte-bound response for each exact submitted document.",
    retry="A repeat parse is a new current-byte census; unresolved references/expressions remain gaps rather than cached success.",
    timing="The parent enforces a finite worker timeout; no runner or workflow liveness is claimed.",
    limits="Input/output bytes, YAML tokens/nodes/depth, files, paths, keys, references, and parser version are bounded.",
    observations="Static YAML nodes, workflow jobs/steps, decoded run scalars, local references, source digests, and explicit gaps.",
    units="Exact YAML/command bytes, token/node counts, source lines, and SHA-256 identities.",
    failure="Parser absence, malformed/recursive YAML, unresolved expression/reference/runtime, or shape ambiguity remains explicit.",
    recovery="Install pinned PyYAML or bind the missing interpreter/reference/evaluation inputs and rerun without executing the workflow.",
    boundary="Discovery parses declarations only; it downloads no action and executes no workflow command.",
)


def _reason(profile: _Profile, kind: str, applies: bool) -> str:
    """State one repository-specific role decision without making effect claims."""
    if applies:
        necessity = {
            "LEDGER": (
                "Its locally authoritative ordered history and recovery behavior "
                "would be hidden by a generic object label."
            ),
            "TRANSACTION": (
                "Its named changes, response-dependent finality, duplicate handling, "
                "and partial-failure state require an explicit transaction boundary."
            ),
            "ASSET": (
                "Its retained identity, quantity, rights, backing, custody, and "
                "encumbrance references require explicit asset boundaries even though "
                "external asset truth remains unestablished."
            ),
            "MARKET": (
                "Its retained participant, order, matching, allocation, settlement, and "
                "disruption records require explicit market boundaries even though live "
                "venue access, price formation, finality, and external effects remain "
                "NOT_ESTABLISHED."
            ),
            "FINBOT": (
                "Its applicable ASSET boundary is reached by the same source-bound "
                "certificate route, so effect-first classification retains FINBOT "
                "obligations while actual agency, authority, endpoints, exposure, "
                "financial effects, and reconciliation remain NOT_ESTABLISHED."
            ),
            "MEASUREMENT": (
                "Its retained parent-boundary values distinguish what was observed "
                "from child or external state that was not observed."
            ),
            "SENSOR": (
                "Its acquisition mechanism produces those bounded digital observations "
                "and has distinct range, latency, and fault semantics."
            ),
            "CONTROLLER": (
                "Its state, feedback, admission decisions, commands, timing, and "
                "intervention behavior form a bounded software control loop."
            ),
            "ACTUATOR": (
                "Its owned source connects an accepted command to a represented real "
                "or simulated effect endpoint and exposes effect feedback plus an "
                "explicit failure surface. Submission, dispatch, replay, callback "
                "entry, or child-process launch alone is insufficient."
            ),
            "PROTOCOL": (
                "Its participants exchange ordered requests/responses across a process "
                "or remote boundary with explicit compatibility and failure states."
            ),
            "POLICY": (
                "Its rule selection, authority, defaults, and enforcement points decide "
                "whether a consequential operation may proceed."
            ),
            "ROBOT": (
                "Its retained agent, harness, controller, actuator, crossing, hazard, and "
                "intervention records require explicit robot boundaries even though an "
                "actual physical effect path and safety remain NOT_ESTABLISHED."
            ),
        }[kind]
        return profile.name + " applies as " + kind + ". " + necessity

    if kind == "ROBOT":
        return (
            profile.name
            + " does not itself represent an agent-to-physical-actuator path or a "
            "declared physical endpoint. Its reviewed consequence boundary is: "
            + profile.boundary
            + " This decision does not infer confinement or absence of downstream "
            "effects: any external physical endpoint must be a separately represented "
            "ROBOT with its accumulated roles."
        )
    if kind == "FINBOT":
        return (
            profile.name
            + " does not itself represent an agent responsible for a real-money "
            "decision/effect path or a declared financial endpoint. Its reviewed "
            "consequence boundary is: "
            + profile.boundary
            + " This decision does not infer absence of downstream financial effects: "
            "any real financial endpoint must be a separately represented FINBOT with "
            "its accumulated roles."
        )
    exclusion = {
        "LEDGER": (
            "Any response, event, or digest it retains is evidence for the named role, "
            "not a separately owned authoritative accounting/history state."
        ),
        "TRANSACTION": (
            "Its current role has no separately owned coordinated effect/commit unit; "
            "process setup or response production is infrastructure for the named role."
        ),
        "ASSET": (
            "It represents no right, quantity, issuance/redemption, custody, or backing "
            "claim; bytes and quota counts are not assets."
        ),
        "MARKET": (
            "It provides no participant trading access, order lifecycle, matching, "
            "allocation, price formation, or settlement mechanism."
        ),
        "MEASUREMENT": (
            "Its outputs are commands, decisions, declarations, or lifecycle records, "
            "not a separately owned observation of a phenomenon with uncertainty."
        ),
        "SENSOR": (
            "It has no separately owned acquisition producer with calibration/range "
            "semantics; reading supplied bytes or callback state is not enough."
        ),
        "CONTROLLER": (
            "It does not use observed feedback to select commands for a represented "
            "target; validation or message handling alone is not control."
        ),
        "ACTUATOR": (
            "It has no separately owned command-to-target actuation role; any process "
            "or remote change is already bounded by its protocol/transaction role."
        ),
        "PROTOCOL": (
            "Its in-process decision surface has no separately owned serialized "
            "participant exchange, compatibility negotiation, or message recovery role."
        ),
        "POLICY": (
            "Its current inputs configure operation rather than define a separately "
            "owned authority/precedence/exception policy decision surface."
        ),
    }[kind]
    return (
        profile.name
        + " does not apply as "
        + kind
        + ". "
        + exclusion
        + " Reviewed boundary: "
        + profile.boundary
    )


_POLICY_ENFORCEMENT = _Profile(
    name="policy enforcement engine",
    scope=(
        "Evaluate one caller-supplied enforcement request against one versioned policy "
        "under verified decision authority and append exactly one hash-chained receipt; "
        "separately run fixed route cases in an isolated worker and judge its "
        "observations against an independent oracle."
    ),
    mechanism=(
        "Closed-field policy, grant, exception, current-revision and request records; "
        "keyed HMAC authority over exact canonical policy digests; per-role evaluation "
        "by applicable rules with deny by default; UNAVAILABLE on any evaluation "
        "exception; a hash-chained receipt ledger; and a nonce and source-pin exchange "
        "with one fixed worker."
    ),
    participants=(
        "The caller, the enforcement engine, the decision authority named by a verified "
        "grant, and for route checks the parent evaluator and one fixed isolated worker."
    ),
    inputs=(
        "Exact policy version, enforcement request with point, action, target and "
        "consequence roles, trust roots by authority, decision evidence, optional "
        "exceptions and current-revision pointer; for routes a fresh nonce and source pins."
    ),
    authority=(
        "A decision needs a grant verified by a keyed hash under a caller-supplied trust "
        "root; the engine does not establish key custody, signer identity, or that a "
        "revision is published or current."
    ),
    states="ALLOWED, REFUSED or UNAVAILABLE per decision, chained from a genesis digest; route status PASS, FAIL or UNKNOWN.",
    ordering=(
        "Each enforce call appends one receipt after the previous digest; every consequence "
        "role is decided independently and must be allowed; the ledger is a new tuple per decision."
    ),
    commands=(
        "Evaluate one request with enforce, replay a sequence, detect bypass against "
        "recorded effects, and evaluate the fixed route cases in an isolated worker."
    ),
    targets=(
        "The caller's in-memory policy, request and ledger values, one fresh worker "
        "process, and one read-only git status query of a bound source file."
    ),
    effect_domains="IN_MEMORY_DECISION_AND_RECEIPT_ONLY; downstream execution, financial transfer and physical motion are neither performed nor observed.",
    effects=(
        "Return a decision and an extended ledger tuple; the route evaluator starts one "
        "fixed interpreter child and reads its observations; no other state changes."
    ),
    commit="A decision commits when its receipt is appended to the returned ledger; a refused or unavailable decision cannot partially mutate earlier receipts.",
    retry="No automatic retry: an exception yields UNAVAILABLE, never ALLOWED, and the caller must issue a new request.",
    timing=(
        "Policy and exception windows compare caller-supplied logical times; the worker "
        "call is bounded by a subprocess timeout, with no wall-clock freshness claim."
    ),
    limits="Closed field sets, finite enforcement points and consequence roles, bounded text and integers, and a bounded worker timeout.",
    observations=(
        "Receipts with policy, request, authority, trust-root commitment and chain "
        "digests; bypass findings against recorded effects; worker observations with the "
        "echoed nonce and source pins."
    ),
    units="Exact bytes, SHA-256 digests, integer priorities and revisions, and logical times; no monetary units.",
    failure=(
        "Malformed input, unverified authority, expired or revoked evidence, or an "
        "unmatched action yields REFUSED or UNAVAILABLE; worker failure or a mismatched "
        "nonce or pins yields UNKNOWN."
    ),
    recovery="Re-evaluate with corrected input; a broken chain or replay mismatch stays FAIL; decisions mutate no external state, so nothing is rolled back.",
    boundary=(
        "The engine observes only calls made through enforce. It does not execute "
        "downstream effects, prove key custody or signer identity, establish publication "
        "or currentness of revisions, or establish the truth of facts behind decision "
        "evidence. Receipts are hash-chained, not signed, and a route PASS is local field "
        "evidence in an isolated interpreter, not route conformance or sandboxing."
    ),
    protocol_transitions=(
        "The parent sends one nonce request, the worker checks its own source pins before "
        "and after and echoes the nonce, and only an exact echo with matching pins lets "
        "the parent judge the worker's observations."
    ),
)


_TRANSACTION_COORDINATOR = _Profile(
    name="in-memory transaction coordinator",
    scope=(
        "Run one declared two-resource transaction through prepare, commit, abort and "
        "compensate over in-memory resources with a hash-chained journal, and reconcile "
        "intended against applied effects."
    ),
    mechanism=(
        "Closed request and receipt schemas, keyed authorization tags over canonical "
        "request bodies, precondition snapshots, operation identity with replay "
        "detection, bounded retry, injected-crash checkpoints, idempotent compensation, "
        "and state derived fresh from the journal and observed resource values."
    ),
    participants="The caller, one coordinator, two in-memory resources, and a named authorizer whose key is held in process.",
    inputs="Exact request with operation identity, authorizer, preconditions, a retry limit and a bounded list of effects, plus an authorization tag.",
    authority="A keyed tag from a named authorizer over the canonical request body; the key registry is in process, so real authorizer identity is not established.",
    states="Prepared, committed, aborted, compensated or refused, with committed, aborted and compensated terminal; every state is derived from the journal, never stored.",
    ordering="Journal entries are append-only and hash-chained from a genesis digest, and phases follow prepare, then commit, abort or compensate.",
    commands="Prepare, commit, abort, compensate and reconcile one operation.",
    targets="resource_a and resource_b, the in-memory resource dictionaries.",
    effect_domains="IN_MEMORY_RESOURCES_ONLY; no durable store, network, external settlement or physical effect.",
    effects="Apply or reverse bounded effects on the two in-memory resources and append journal entries.",
    commit="Commit is the boundary at which all declared effects are applied and recorded in the journal; a refused form leaves the resources unchanged.",
    retry="A declared bounded retry limit; a replayed operation identity returns its recorded outcome and is not applied twice.",
    timing="Phases are deterministic and ordered by the journal; no wall-clock timing, deadline or concurrency claim is made.",
    limits="A fixed maximum number of effects and retries, two named resources, and closed field sets.",
    observations="Receipts derived from the journal and the observed resource values, journal chain intactness, and the reconciliation of intended against applied effects.",
    units="Exact scalar resource values and SHA-256 digests; no monetary units.",
    failure="An invalid form is refused without partial mutation; a simulated crash at a checkpoint leaves a journal from which state is derived; divergence is reported, not hidden.",
    recovery="Compensation is idempotent and reconcile reports intended against applied effects; durability across process loss is NOT_ESTABLISHED.",
    boundary=(
        "Mutates only in-memory resources. Durability, concurrent writers, external "
        "settlement, external atomicity, real authorizer identity and any finality beyond "
        "the local final record are NOT_ESTABLISHED; the coordinator performs no external "
        "actuation and never reads local ledger state."
    ),
    protocol_transitions=(
        "Phases follow the closed prepare, commit, abort and compensate state machine, "
        "and a replayed operation identity returns its recorded receipt."
    ),
)


def _review(
    primary_kind: str,
    paths: tuple[str, ...],
    applicable: tuple[str, ...],
    profile: _Profile,
    role_paths: Mapping[str, tuple[str, ...]] | None = None,
    *,
    refuted: tuple[str, ...] = (),
    actuator_basis: _ActuatorBasis | None = None,
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
        refuted=refuted,
        actuator_basis=actuator_basis,
    )


_PACKAGE_WORKER_PATHS = (
    "src/verifier/runtime/emulator_control_execution.py",
    "src/verifier/runtime/emulator_control_worker.py",
    "src/verifier/runtime/package_checker_worker.py",
    "src/verifier/runtime/package_execution.py",
    "src/verifier/runtime/package_execution_observation.py",
    "src/verifier/runtime/token_asset_execution.py",
    "src/verifier/runtime/token_asset_worker.py",
    "src/verifier/runtime/worker_protocol_execution.py",
    "src/verifier/runtime/worker_protocol_worker.py",
)
_CORE_EXECUTOR_PATHS = (
    "src/verifier/core/certification_mechanisms.py",
    "src/verifier/core/depth.py",
    "src/verifier/core/evidence.py",
    "src/verifier/core/grounded_certification.py",
    "src/verifier/core/profile_obligations.py",
    "src/verifier/core/translation.py",
    "src/verifier/core/witness.py",
)

_REVIEWS = {
    "vstd-claim-garden-lifecycle": _review(
        "PROTOCOL",
        ("src/verifier/interoperability/claim_garden.py",),
        ("PROTOCOL", "TRANSACTION"),
        _CLAIM_GARDEN,
        # Unlisted, not refuted: ACTUATOR (remote POST/PUT creating records) and POLICY
        # (hard-coded publish gates) were audited UNKNOWN; UNKNOWN cannot exempt.
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-controlled-emission-controller": _review(
        "CONTROLLER",
        ("src/verifier/corrigibility/controlled_operation.py",),
        ("CONTROLLER", "POLICY", "TRANSACTION"),
        _CONTROLLED_EMISSION,
        # CONTROLLER stays APPLIES (primary, agreed by ownership): each invocation's
        # admission depends on the session's own STOP latch, spent-invocation set and
        # capacity, and the latch is an intervention on that loop. The active count is
        # observed for quiescence only and does not itself refuse admission.
        # Unlisted, not refuted: PROTOCOL is UNKNOWN; the signed stop request is
        # decoded by the reachable operator_stop module this file calls.
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-core-mechanism-executor": _review(
        "VERIFIER",
        _CORE_EXECUTOR_PATHS,
        ("TRANSACTION", "POLICY"),
        _CORE_EXECUTOR,
        # Unlisted, not refuted: PROTOCOL is UNKNOWN; versioned request, policy and
        # certificate formats are replayed by recheck functions in the owned files.
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-core-provenance-sensor": _review(
        "SENSOR",
        ("src/verifier/core/provenance.py",),
        ("MEASUREMENT", "SENSOR", "PROTOCOL"),
        _CORE_PROVENANCE,
        # TRANSACTION does not apply: fixed read-only Git queries return one in-memory
        # record and create no coordinated durable effect, commit or replay unit.
        # ACTUATOR remains UNRESOLVED: fixed Git process submission is not an owned
        # command-to-effect endpoint. PROTOCOL still applies to the exchange.
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "POLICY",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-core-receipt-transaction": _review(
        "TRANSACTION",
        ("src/verifier/core/receipt.py",),
        ("TRANSACTION",),
        _CORE_RECEIPT,
        # TRANSACTION stays APPLIES: one publication call writes several durable files
        # and returns as its completion claim, so partial-failure and replay states need
        # a boundary declaration. Non-atomicity is that declaration (TRANSACTION-0.2),
        # not an exemption. External note: ownership says "sequential exclusive writes",
        # but receipt.py uses write_text without exclusive create.
        # Unlisted, not refuted: ACTUATOR (writes caller-selected local paths) and
        # PROTOCOL (canonical serialization gate) were audited UNKNOWN.
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "POLICY",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-digest-validation-policy": _review(
        "POLICY",
        (
            "examples/selected_validation/demo.py",
            "src/verifier/interoperability/validation_loop.py",
        ),
        ("POLICY", "CONTROLLER", "PROTOCOL"),
        _DIGEST_VALIDATION,
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "ACTUATOR",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-finite-record-issuance": _review(
        "TRANSACTION",
        ("src/verifier/runtime/finite_record_issuance.py",),
        ("LEDGER", "TRANSACTION", "PROTOCOL", "POLICY"),
        _FINITE_RECORD,
        # The selected invocation ledger is an accumulated role, not incidental
        # storage: the route atomically commits an issuance and independently
        # rechecks the stored receipt, ledger identity, generation, sequence and
        # invocation identifier before finality.  The source ownership declaration
        # therefore names LEDGER explicitly so this review cannot outrun it.
        refuted=(
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-gate-pipeline-controller": _review(
        "CONTROLLER",
        (
            "src/verifier/runtime/gate_pipeline.py",
            "src/verifier/runtime/prdel_evidence.py",
            "src/verifier/runtime/quality_checks.py",
            "src/verifier/runtime/secret_gate.py",
            "src/verifier/runtime/self_polish_evidence.py",
        ),
        (
            "TRANSACTION",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "PROTOCOL",
            "POLICY",
        ),
        _GATE_PIPELINE,
        # ROBOT/FINBOT are refuted on implementation identity: the gate is an executor
        # that invokes caller-selected argv (arbitrary local executables), not itself a
        # physical or financial endpoint. Any real endpoint it reaches must be a
        # separately represented object. Process submission does not transfer an
        # ACTUATOR role from any endpoint a selected command may reach.
        refuted=("LEDGER", "ASSET", "MARKET", "ROBOT", "FINBOT"),
    ),
    "vstd-gated-publication": _review(
        "PROTOCOL",
        ("src/verifier/interoperability/gated_publish.py",),
        ("PROTOCOL", "TRANSACTION"),
        _GATED_PUBLICATION,
        # Unlisted, not refuted: ACTUATOR (authenticated POST that creates a remote record
        # and charges quota) and POLICY (owned consent, digest and disclosure gates)
        # were audited UNKNOWN; UNKNOWN cannot exempt.
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-javascript-parser-protocol": _review(
        "PROTOCOL",
        (
            "src/verifier/runtime/namespace_javascript.py",
            "src/verifier/runtime/namespace_javascript_worker.py",
        ),
        ("PROTOCOL",),
        _JAVASCRIPT_PARSER,
        {
            "PROTOCOL": (
                "src/verifier/runtime/namespace_javascript.py",
                "src/verifier/runtime/namespace_javascript_worker.py",
            ),
        },
        # The parent submits a fixed child-process request, but parsing owns no
        # command-to-effect endpoint. The exchange remains PROTOCOL evidence only.
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "POLICY",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-package-worker-exchange": _review(
        "PROTOCOL",
        _PACKAGE_WORKER_PATHS,
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL"),
        _PACKAGE_WORKER,
        # emulator_control_execution declares itself a simulated ACTUATOR check and its
        # worker submits and observes device commands in the child process that
        # package_execution launches, so it is evidence for both ACTUATOR and MEASUREMENT.
        {
            "TRANSACTION": ("src/verifier/runtime/package_execution.py",),
            "ACTUATOR": (
                "src/verifier/runtime/package_execution.py",
                "src/verifier/runtime/emulator_control_execution.py",
                "src/verifier/runtime/emulator_control_worker.py",
            ),
            "PROTOCOL": _PACKAGE_WORKER_PATHS,
            "MEASUREMENT": (
                "src/verifier/runtime/package_execution_observation.py",
                "src/verifier/runtime/emulator_control_execution.py",
                "src/verifier/runtime/emulator_control_worker.py",
            ),
            "SENSOR": ("src/verifier/runtime/package_execution_observation.py",),
        },
        actuator_basis=_ActuatorBasis(
            endpoint_path="src/verifier/runtime/emulator_control_worker.py",
            command_to_effect=(
                "The owned emulator worker applies admitted device commands to its "
                "owned simulated device state."
            ),
            feedback=(
                "The worker returns raw command/effect events, unchanged-state controls, "
                "and the parent validates the bounded response."
            ),
            failure_surface=(
                "Invalid commands, saturation, interlock refusal, worker failure, timeout, "
                "or malformed response remain explicit non-PASS outcomes."
            ),
        ),
        # Unlisted, not refuted. token_asset_execution declares ASSET-* checks and
        # emulator_control_execution declares CONTROLLER-*, so those refutations are
        # contradicted by owned source. LEDGER and POLICY have UNKNOWN verdicts.
        refuted=(
            "MARKET",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-permission-slot-controller": _review(
        "CONTROLLER",
        ("src/verifier/runtime/permission_slot.py",),
        ("CONTROLLER", "LEDGER", "POLICY", "PROTOCOL", "TRANSACTION"),
        _PERMISSION_SLOT,
        # Unlisted, not refuted: ASSET (grant quota/permission digests) and MEASUREMENT
        # (census counters) were audited UNKNOWN.
        refuted=("MARKET", "SENSOR", "ROBOT", "FINBOT"),
    ),
    # Roles come from the standalone current-source audit.  Every other added kind is
    # unlisted, not refuted: omission never becomes DOES_NOT_APPLY, so those cells stay
    # UNRESOLVED until a source-cited refutation is reviewed.
    "vstd-policy-enforcement-engine": _review(
        "POLICY",
        (
            "src/verifier/runtime/policy_enforcement_execution.py",
            "src/verifier/runtime/policy_enforcement_routes.py",
            "src/verifier/runtime/policy_enforcement_worker.py",
        ),
        ("POLICY", "PROTOCOL"),
        _POLICY_ENFORCEMENT,
        {
            "POLICY": ("src/verifier/runtime/policy_enforcement_execution.py",),
            "PROTOCOL": (
                "src/verifier/runtime/policy_enforcement_routes.py",
                "src/verifier/runtime/policy_enforcement_worker.py",
            ),
        },
        # Explicitly empty: no kind is refuted here, so every other added kind stays the
        # canonical UNRESOLVED instead of becoming a complement-derived exemption.
        refuted=(),
    ),
    "vstd-polish-workflow-transaction": _review(
        "TRANSACTION",
        (
            "src/verifier/runtime/polish_prepare.py",
            "src/verifier/runtime/polish_workflow.py",
            "src/verifier/runtime/polish_workflow_cli.py",
            "src/verifier/runtime/polish_workflow_replay.py",
        ),
        ("TRANSACTION", "CONTROLLER", "LEDGER", "POLICY", "PROTOCOL"),
        _POLISH_WORKFLOW,
        # Unlisted, not refuted: ACTUATOR (apply writes the workspace; quality stage
        # launches external tools) and MEASUREMENT (quality observation) are UNKNOWN.
        refuted=(
            "ASSET",
            "MARKET",
            "SENSOR",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-sim-artifact-publication": _review(
        "PROTOCOL",
        ("src/verifier/interoperability/artifact_publish.py",),
        ("PROTOCOL", "TRANSACTION"),
        _SIM_PUBLICATION,
        # Unlisted, not refuted: ACTUATOR (authenticated POST across a submission
        # boundary with indeterminate completion) was audited leaning CONTRADICTED.
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "POLICY",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-systems-parser-protocol": _review(
        "PROTOCOL",
        (
            "src/verifier/runtime/namespace_rust_expansions.py",
            "src/verifier/runtime/namespace_systems.py",
            "src/verifier/runtime/namespace_systems_worker.py",
        ),
        ("PROTOCOL",),
        _SYSTEMS_PARSER,
        {
            "PROTOCOL": (
                "src/verifier/runtime/namespace_rust_expansions.py",
                "src/verifier/runtime/namespace_systems.py",
                "src/verifier/runtime/namespace_systems_worker.py",
            ),
        },
        # The parent fixed-child launch owns no parsed command-to-effect endpoint;
        # the expansion helper and worker remain PROTOCOL evidence only.
        # Unlisted, not refuted: SENSOR (installed-distribution digests) was audited UNKNOWN.
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "CONTROLLER",
            "POLICY",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-train-control-session": _review(
        "CONTROLLER",
        ("src/verifier/corrigibility/train_control.py",),
        ("CONTROLLER", "LEDGER", "POLICY", "TRANSACTION"),
        _TRAIN_CONTROL,
        # LEDGER applies because the lock-protected, hash-linked EVENT chain is the only
        # locally authoritative bounded history of admitted outcomes, gates admission
        # at capacity and anchors denial replay. Its non-durability, absent reconciliation
        # and the callback path that can run when _record returns None are explicit
        # LEDGER boundaries rather than exemptions, matching permission-slot treatment.
        # ROBOT stays UNRESOLVED: every retained EVENT requires a declared HARDWARE
        # context object, which contradicts a "no declared physical endpoint" refutation.
        # Unlisted, not refuted: PROTOCOL is contested; the owned source has a versioned,
        # signed operation wire with one-use request replay rejection.
        refuted=(
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "FINBOT",
        ),
    ),
    "vstd-transaction-execution-coordinator": _review(
        "TRANSACTION",
        ("src/verifier/runtime/transaction_execution.py",),
        ("TRANSACTION", "POLICY", "PROTOCOL"),
        _TRANSACTION_COORDINATOR,
        # Explicitly empty, as for the policy-enforcement engine: nothing is refuted.
        refuted=(),
    ),
    "vstd-workflow-parser-protocol": _review(
        "PROTOCOL",
        (
            "src/verifier/runtime/namespace_workflow_worker.py",
            "src/verifier/runtime/namespace_workflows.py",
        ),
        ("PROTOCOL",),
        _WORKFLOW_PARSER,
        {
            "PROTOCOL": (
                "src/verifier/runtime/namespace_workflow_worker.py",
                "src/verifier/runtime/namespace_workflows.py",
            ),
        },
        # Fixed-worker launch is not an owned workflow command-to-effect endpoint.
        # Parsed commands are declarations and are not executed.
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "POLICY",
            "ROBOT",
            "FINBOT",
        ),
    ),
}

OPERATIONS_OBJECT_IDS = tuple(_REVIEWS)
_EMPTY_UNRESOLVED_CELLS = frozenset(
    {
        ("vstd-controlled-emission-controller", "ACTUATOR"),
        ("vstd-core-mechanism-executor", "ACTUATOR"),
        ("vstd-core-provenance-sensor", "ACTUATOR"),
        ("vstd-gate-pipeline-controller", "ACTUATOR"),
        ("vstd-javascript-parser-protocol", "ACTUATOR"),
        ("vstd-permission-slot-controller", "ACTUATOR"),
        ("vstd-systems-parser-protocol", "ACTUATOR"),
        ("vstd-train-control-session", "ACTUATOR"),
        ("vstd-workflow-parser-protocol", "ACTUATOR"),
    }
)


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
        rows.update(selected)
    return rows


def _catalog_check() -> None:
    if len(_REVIEWS) != 19:
        raise AssertionError("operations catalog must cover nineteen objects")
    for object_id, review in _REVIEWS.items():
        if (
            review.primary_kind in REVIEW_KINDS
            and review.primary_kind not in review.applicable
        ):
            raise AssertionError(object_id + " primary kind is not applicable")
        if len(review.applicable) != len(set(review.applicable)):
            raise AssertionError(object_id + " repeats an applicable kind")
        if any(kind not in REVIEW_KINDS for kind in review.applicable):
            raise AssertionError(object_id + " applies an unregistered kind")
        if len(review.refuted) != len(set(review.refuted)):
            raise AssertionError(object_id + " repeats a refuted kind")
        if any(kind not in REVIEW_KINDS for kind in review.refuted):
            raise AssertionError(object_id + " refutes an unregistered kind")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " applies and refutes one kind")
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if any(
            not paths or not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence leaves owned source")
        actuator_basis = review.actuator_basis
        if "ACTUATOR" in review.applicable:
            if (
                type(actuator_basis) is not _ActuatorBasis
                or actuator_basis.endpoint_path not in review.owned_paths
                or actuator_basis.endpoint_path not in review.role_paths["ACTUATOR"]
                or any(
                    type(value) is not str or not value.strip()
                    for value in (
                        actuator_basis.command_to_effect,
                        actuator_basis.feedback,
                        actuator_basis.failure_surface,
                    )
                )
            ):
                raise AssertionError(object_id + " ACTUATOR basis is incomplete or unowned")
        elif actuator_basis is not None:
            raise AssertionError(object_id + " has ACTUATOR basis without applicability")
        reasons = {
            kind: _reason(review.profile, kind, kind in review.applicable)
            for kind in REVIEW_KINDS
        }
        if set(reasons) != set(REVIEW_KINDS) or any(
            not value.strip() for value in reasons.values()
        ):
            raise AssertionError(object_id + " classification matrix is incomplete")
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


def _classification_document(review: _Review, kind: str) -> dict[str, Any]:
    basis = _basis(review, kind)
    if basis == "UNRESOLVED":
        return {
            "status": basis,
            "reason": _unresolved_reason(kind),
            "evidence_paths": [],
        }
    paths = review.role_paths[kind] if basis == "APPLIES" else review.owned_paths
    return {
        "status": basis,
        "reason": _reason(review.profile, kind, basis == "APPLIES"),
        "evidence_paths": list(paths),
    }


def _explicit_decision(
    review: _Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
) -> dict[str, Any]:
    """Return the canonical row decision for one explicitly catalogued kind."""
    basis = _basis(review, kind)
    if basis == "APPLIES":
        paths = review.role_paths[kind]
    elif basis == "DOES_NOT_APPLY":
        paths = review.owned_paths
    else:
        raise AssertionError("explicit decision requested for unlisted " + kind)
    return {
        "status": basis,
        "reason": _reason(review.profile, kind, basis == "APPLIES"),
        "evidence": [deepcopy(evidence_by_path[path]) for path in paths],
    }


def review_document() -> dict[str, Any]:
    """Return the deterministic, digest-free human review document."""
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


def _owned_file_paths(row: Mapping[str, Any]) -> set[str]:
    surfaces = row.get("surfaces")
    if type(surfaces) is not list or any(type(item) is not str for item in surfaces):
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_SURFACES_INVALID")
    file_surfaces = [
        item.removeprefix("file:") for item in surfaces if item.startswith("file:")
    ]
    if any(not path for path in file_surfaces) or len(file_surfaces) != len(
        set(file_surfaces)
    ):
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_SURFACES_INVALID")
    return set(file_surfaces)


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
        digest = reference["sha256"]
        if files.get(path) != digest:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:" + object_id + ":" + path
            )
    return evidence


def _source_evidence(root: Path, paths: tuple[str, ...]) -> list[dict[str, str]]:
    return [{"path": path, "sha256": _read_digest(root, path)} for path in paths]


def _validate_evidence(
    evidence: Any,
    files: Mapping[str, str],
    allowed: set[str],
    *,
    code: str,
) -> None:
    if type(evidence) is not list or not evidence:
        raise ValueError(code)
    paths = []
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


def _unresolved_decision(
    decision: Any,
    files: Mapping[str, str],
    allowed: set[str],
    *,
    kind: str,
    code: str,
) -> bool:
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
        if decision["reason"] != _unresolved_reason(kind):
            raise ValueError(code)
        _validate_evidence(decision["evidence"], files, allowed, code=code)
    return True


def _blank_obligation(
    binding: Any,
    expected_fields: tuple[str, ...],
    files: Mapping[str, str],
    allowed: set[str],
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
    if blank:
        if binding["evidence"]:
            _validate_evidence(binding["evidence"], files, allowed, code=code)
        return True
    return False


def _preserve_explicit_decision(
    decision: Any,
    expected: Mapping[str, Any],
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
    kind: str,
) -> bool:
    """Keep a complete decision only when it equals its explicit basis exactly.

    Same-status rewrites, reasons that differ, partial, duplicate, stale, or
    unowned evidence are conflicts.  An absent or validated UNRESOLVED candidate
    is replaced by the explicit basis, so returns False for a fill.
    """
    code = "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
    if _unresolved_decision(decision, files, owned, kind=kind, code=code):
        return False
    if decision != expected:
        raise ValueError(code)
    return True


def _preserve_explicit_obligation(
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
    """Keep a complete declaration only when its reason and evidence are exact.

    The declaration text is reviewed content and may differ, but it must name
    exactly the declared fields with nonblank values.
    """
    code = (
        "PACKAGE_SEMANTIC_REVIEW_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id
    )
    if _blank_obligation(binding, expected_fields, files, owned, code=code):
        return False
    if (
        type(binding) is not dict
        or set(binding) != {"reason", "evidence", "declaration"}
        or binding["reason"] != expected_reason
        or binding["evidence"] != expected_evidence
        or type(binding["declaration"]) is not dict
        or set(binding["declaration"]) != set(expected_fields)
        or any(
            type(value) is not str or not value.strip()
            for value in binding["declaration"].values()
        )
    ):
        raise ValueError(code)
    return True


def apply_package_semantic_review_operations(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply all nineteen source-bound reviews atomically to a deep copy.

    A complete decision is kept only when it equals its explicit basis exactly:
    same status, same canonical reason, and exactly the current owned evidence
    for that basis.  Unresolved decisions and absent or wholly blank obligation
    candidates may be filled.  A kind with no explicit basis becomes the
    canonical migration UNRESOLVED; it is never DOES_NOT_APPLY by absence, and
    only a validated owned candidate's evidence is retained.  A contradiction,
    stale, partial, duplicate, or unowned reference, partial declaration, wrong
    path owner, missing source, or concurrent source change aborts before the
    caller's mapping can be changed. Command-only ACTUATOR candidates are
    normalized to empty-evidence UNRESOLVED because submission evidence cannot
    establish the missing owned command-to-effect endpoint.
    """
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
        owned = _owned_file_paths(row)
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
            or any(
                kind not in REVIEW_KINDS and _names_kind(kind)
                for kind in specializations
            )
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
        for label in classification:
            if type(label) is not str or (
                label not in REVIEW_KINDS and _names_kind(label)
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:"
                    + object_id
                    + ":"
                    + str(label)
                )

        known_obligations = {
            name for values in live_obligations.values() for name in values
        }
        for name in obligations:
            if type(name) is not str or (
                name not in known_obligations and _names_kind(name)
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
        unlisted_candidates: dict[str, list[dict[str, str]]] = {}
        for kind in REVIEW_KINDS:
            basis = _basis(review, kind)
            decision = classification.get(kind)
            if basis == "UNRESOLVED":
                # No explicit basis: only a validated owned candidate survives
                # as UNRESOLVED evidence; complete APPLIES/DOES_NOT_APPLY text
                # for this kind was never backed and is not retained.
                code = (
                    "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:"
                    + object_id
                    + ":"
                    + kind
                )
                is_unresolved = _unresolved_decision(
                    decision, files, owned, kind=kind, code=code
                )
                if not is_unresolved:
                    raise ValueError(code)
                if (
                    (object_id, kind) not in _EMPTY_UNRESOLVED_CELLS
                    and decision is not None
                    and decision["evidence"]
                ):
                    unlisted_candidates[kind] = [
                        deepcopy(evidence_by_path[reference["path"]])
                        for reference in decision["evidence"]
                    ]
            elif _preserve_explicit_decision(
                decision,
                _explicit_decision(review, kind, evidence_by_path),
                files,
                owned,
                object_id=object_id,
                kind=kind,
            ):
                preserve_decisions.add(kind)
            for obligation_id, fields in live_obligations[kind].items():
                binding = obligations.get(obligation_id)
                if basis == "APPLIES":
                    if _preserve_explicit_obligation(
                        binding,
                        fields,
                        _obligation_reason(review.profile, kind),
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
                    if basis == "DOES_NOT_APPLY":
                        code = (
                            "PACKAGE_SEMANTIC_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                        )
                    else:
                        code = (
                            "PACKAGE_SEMANTIC_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
                        )
                    code = code + object_id + ":" + obligation_id
                    if not _blank_obligation(
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
            "unlisted_candidates": unlisted_candidates,
        }

    # The complete source denominator is read again only after every semantic
    # conflict check. A concurrent writer therefore cannot leave a partially
    # current set of newly generated bindings.
    for object_id, review in _REVIEWS.items():
        closing = _source_evidence(selected_root, review.owned_paths)
        if closing != plans[object_id]["opening_evidence"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)

    result = deepcopy(rows)
    for object_id, review in _REVIEWS.items():
        row = result[object_id]
        plan = plans[object_id]
        declarations = _declarations(review)
        for kind in REVIEW_KINDS:
            if kind in plan["preserve_decisions"]:
                continue
            if _basis(review, kind) == "UNRESOLVED":
                row["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": _unresolved_reason(kind),
                    "evidence": deepcopy(plan["unlisted_candidates"].get(kind, [])),
                }
            else:
                row["classification"][kind] = _explicit_decision(
                    review, kind, plan["evidence_by_path"]
                )
        for name in plan["remove_obligations"]:
            row["obligations"].pop(name, None)
        for name, declaration in declarations.items():
            if name in plan["preserve_obligations"]:
                continue
            kind = name.split("-", 1)[0]
            row["obligations"][name] = {
                "reason": _obligation_reason(review.profile, kind),
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
    "OPERATIONS_OBJECT_IDS",
    "REVIEW_KINDS",
    "apply_package_semantic_review_operations",
    "review_document",
]
