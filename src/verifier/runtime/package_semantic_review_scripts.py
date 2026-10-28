"""Current-source Tier-0 reviews for six repository script objects.

Terminology: application programming interface (API); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation
Format, 8-bit (UTF-8).

The ownership catalog identifies the source bytes assigned to an object.  This
module answers the separate admission question for twenty-three audited script
paths: which of the twelve consequential kinds apply and why, and what the
applicable Tier-0 declarations mean for those exact bytes.  Every other kind is
canonical UNRESOLVED; this module emits no complement-based or absence-based
DOES_NOT_APPLY decision.  The declarations are not evidence that a script was
executed or that its generated artifact is correct.

Application is pure, atomic, and fail closed.  Every owned source is checked
against the caller's digest census before and after semantic preflight.  An
existing decision is preserved only when it equals its explicit basis exactly;
stale, conflicting, partial, forged, unbacked, unowned, mislabeled, aliased, or
subclassed bindings abort the whole six-object operation.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


REVIEW_KINDS = _shared.REVIEW_KINDS

SCRIPT_OBJECT_IDS = (
    "vstd-selected-source-admission",
    "vstd-network-fixture-corpus",
    "vstd-self-polish-native-case-corpus",
    "vstd-self-polish-case-materializer",
    "vstd-self-polish-full-candidate-capture",
    "vstd-tier1-evidence-ledger",
)

CLAIM_BOUNDARY = (
    "Current-source Tier-0 applicability and declaration review for these six "
    "script objects only. It establishes neither script execution nor generated-"
    "artifact truth, complete repository or 38-kind coverage, application polish, "
    "physical confinement, real-money authority or effects, Tier-1-plus "
    "conformance, publication, release, or deployment."
)


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    profile: _shared._Profile


def _profile(**fields: str) -> _shared._Profile:
    return _shared._Profile(**fields)


def _review(
    primary_kind: str,
    paths: tuple[str, ...],
    applicable: tuple[str, ...],
    profile: _shared._Profile,
    role_paths: Mapping[str, tuple[str, ...]] | None = None,
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
    )


# Roles kept by the ownership catalog whose exact source supplies no basis.  They
# remain APPLIES (the ownership spec is the upstream authority for this partition)
# but their text says so instead of repeating the unsupported acquisition claim.
_RESIDUAL_ROLES = {
    "The self-polish native case corpus": ("MEASUREMENT", "SENSOR"),
}


def _reason(profile: _shared._Profile, kind: str) -> str:
    """Explain why one applicable kind applies, bound to this object's profile.

    Only applicable kinds carry a reason.  Every other kind is canonical
    UNRESOLVED and has no complement-based refutation text.
    """
    if kind in _RESIDUAL_ROLES.get(profile.name, ()):
        return (
            profile.name
            + " keeps "
            + kind
            + " only as a residual ownership-spec role: no owned source performs the "
            "live acquisition or measurement that this role describes, so its basis "
            "is unestablished. Exact source-specific basis: "
            + profile.observations
        )
    necessity = {
        "LEDGER": (
            "Its represented ordered records, invariants, replay, correction, "
            "and recovery boundary would be hidden by a generic fixture label."
        ),
        "TRANSACTION": (
            "Its bounded state or file effect has preconditions, commit, partial-"
            "failure, retry, and replay consequences that must be explicit."
        ),
        "MEASUREMENT": (
            "It captures host or repository values, so direct observations must "
            "be distinguished from inferred completeness and semantic truth."
        ),
        "SENSOR": (
            "It actively acquires those digital observations and therefore needs "
            "an explicit source, range, drift, latency, and fault boundary."
        ),
        "CONTROLLER": (
            "It selects and sequences consequential acquisition, checking, replay, "
            "or output commands using bounded feedback and stop states."
        ),
        "ACTUATOR": (
            "It issues a process or filesystem command with a named target while "
            "keeping successful submission separate from downstream truth."
        ),
        "PROTOCOL": (
            "Its participants, ordered records or exchanges, compatibility, replay, "
            "failure, and progress semantics form a distinct protocol boundary."
        ),
        "POLICY": (
            "Its admission or case-selection rules, precedence, defaults, "
            "exceptions, and enforcement decide what may be accepted or emitted."
        ),
    }[kind]
    basis = {
        "LEDGER": profile.observations,
        "TRANSACTION": profile.effects,
        "MEASUREMENT": profile.observations,
        "SENSOR": profile.mechanism,
        "CONTROLLER": profile.scope,
        "ACTUATOR": profile.commands,
        "PROTOCOL": profile.participants,
        "POLICY": profile.scope,
    }[kind]
    return (
        profile.name
        + " applies as "
        + kind
        + ". "
        + necessity
        + " Exact source-specific basis: "
        + basis
    )


def _basis(review: _Review, kind: str) -> str:
    """Return the only basis for one kind; absence is UNRESOLVED, never refuted."""
    return "APPLIES" if kind in review.applicable else "UNRESOLVED"


def _obligation_reason(profile: _shared._Profile, kind: str) -> str:
    return (
        _reason(profile, kind)
        + " This Tier-0 declaration names the reviewed boundary only; "
        "execution and Tier-1-plus fulfillment remain unestablished."
    )


def _role_evidence(
    review: _Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
) -> list[dict[str, str]]:
    """Return the exact current evidence for one applicable role, in role order."""
    return [deepcopy(evidence_by_path[path]) for path in review.role_paths[kind]]


def _label_variant(label: Any) -> bool:
    """True for a non-canonical label that would normalize to a review kind.

    ``robot``, `` ROBOT`` and ``ROBOT_0.1`` must not survive as an unchecked
    second spelling of ``ROBOT``.  Labels outside the twelve review kinds pass.
    """
    return (
        type(label) is str
        and label not in REVIEW_KINDS
        and _shared._label_kind(label) in REVIEW_KINDS
    )


def _assert_plain_tree(value: Any, *, code: str) -> None:
    """Accept only exact JSON-like values: no subclass, no callback, no cycle."""
    if value is None or type(value) in (bool, int, float, str):
        return
    if type(value) is dict:
        children = list(value.values())
        if any(type(key) is not str for key in value):
            raise ValueError(code)
    elif type(value) is list:
        children = value
    else:
        raise ValueError(code)
    for child in children:
        _assert_plain_tree(child, code=code)


def _assert_unaliased(rows: Mapping[str, Any], *, code: str) -> None:
    """Reject any dict or list reachable twice, including from an unowned row.

    A shared mutable container lets one object's review edit change another
    object, and a cycle makes a copied row self-referential.  Tuples are
    immutable and are walked only for the containers they hold.
    """
    seen: set[int] = set()
    stack: list[Any] = list(rows.values())
    while stack:
        item = stack.pop()
        if type(item) is tuple:
            stack.extend(item)
            continue
        if type(item) not in (dict, list):
            continue
        if id(item) in seen:
            raise ValueError(code)
        seen.add(id(item))
        stack.extend(item.values() if type(item) is dict else item)


def _unresolved_candidate(
    decision: Any,
    files: Mapping[str, str],
    owned: set[str],
    *,
    kind: str,
    code: str,
) -> bool:
    """Validate an UNRESOLVED candidate; evidence-free text must be canonical.

    With no evidence the reason is the only carried claim, so negative or
    exemption text there would present a refutation as migration state.
    """
    if (
        type(decision) is dict
        and decision.get("status") == "UNRESOLVED"
        and not decision.get("evidence")
        and decision.get("reason") != _shared._unresolved_reason(kind)
    ):
        raise ValueError(code)
    return _shared._unresolved_decision(decision, files, owned, kind=kind, code=code)


def _explicit_decision(
    review: _Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
) -> dict[str, Any]:
    return {
        "status": "APPLIES",
        "reason": _reason(review.profile, kind),
        "evidence": _role_evidence(review, kind, evidence_by_path),
    }


def _classification_document(review: _Review, kind: str) -> dict[str, Any]:
    if _basis(review, kind) == "UNRESOLVED":
        return {
            "status": "UNRESOLVED",
            "reason": _shared._unresolved_reason(kind),
            "evidence_paths": [],
        }
    return {
        "status": "APPLIES",
        "reason": _reason(review.profile, kind),
        "evidence_paths": list(review.role_paths[kind]),
    }


_SELECTED_SOURCE_PATHS = (
    "scripts/admitted_root_binding.py",
    "scripts/exact_materialized_member.py",
    "scripts/exact_source_scope.py",
    "scripts/windows_anchored_member.py",
)
_NETWORK_FIXTURE_PATHS = (
    "scripts/build_artifact_network_fixture.py",
    "scripts/build_artifact_network_negative_corpus.py",
    "scripts/build_formation_corpus.py",
    "scripts/build_formation_receipt_corpus.py",
    "scripts/build_proposition_transfer_fixture.py",
    "scripts/build_silo_composition_fixture.py",
)
_NATIVE_CASE_PATHS = (
    "scripts/build_self_polish_native_tier3_cases.py",
    "scripts/build_self_polish_native_tier4_cases.py",
    "scripts/build_self_polish_native_tier5_cases.py",
    "scripts/build_self_polish_native_tier6_cases.py",
    "scripts/build_self_polish_native_tier7_cases.py",
    "scripts/build_self_polish_native_tier8_cases.py",
    "scripts/build_self_polish_native_tier9_cases.py",
    "scripts/fixtures/self_polish_native_tier4_seed.json",
)
_TIER3_CASE_PATH = ("scripts/build_self_polish_native_tier3_cases.py",)
_CASE_MATERIALIZER_PATHS = (
    "scripts/build_self_polish_native_cases.py",
    "scripts/build_self_polish_sim_case_patch.py",
    "scripts/render_self_polish_native_case_module.py",
)
_FULL_CANDIDATE_PATHS = ("scripts/build_self_polish_native_full_candidate.py",)
_TIER1_LEDGER_PATHS = ("scripts/build_self_polish_tier1_ledger.py",)


_SELECTED_SOURCE = _profile(
    name="The selected-source admission mechanism",
    scope=(
        "Admit one externally bound repository root and read only the regular members "
        "named by its exact manifest, source coordinate, generation, and byte bounds."
    ),
    mechanism=(
        "Strict manifest parsing, SHA-256 and size checks, canonical relative paths, "
        "Windows handle-relative no-follow traversal, before/open/after identity "
        "snapshots, cancellation checks, and deterministic handle cleanup."
    ),
    participants=(
        "The caller, its RootAdmission and consumed-admission set, a borrowed trusted "
        "root handle, the local filesystem, exact member readers, and the returned scope."
    ),
    inputs=(
        "Exact manifest bytes and digest, source and materialization coordinates, root "
        "volume/file identity, current generation, admission id, byte bounds, trusted "
        "handle, and optional cancellation predicate."
    ),
    authority=(
        "The caller must supply both the external admission record and trusted root "
        "capability. Acceptance grants bounded local reads only and does not establish "
        "content correctness, repository completeness, or release authority."
    ),
    states=(
        "Unvalidated, refused, bound-and-consumed, exact-member-reading, scope-loaded, "
        "cancelled, cleanup-failed, and returned-observation states are distinct."
    ),
    ordering=(
        "Validate the admission, manifest, coordinate and root identity before spending "
        "the admission; duplicate and revalidate the root before each anchored read; "
        "close every owned handle before returning or propagating failure."
    ),
    commands=(
        "Bind the admitted root, duplicate/inspect/close handles, open one declared "
        "member relative to that root, read bounded bytes, and load the selected scope."
    ),
    targets=(
        "The caller-owned consumed-admission set, borrowed root capability, duplicated "
        "handles, and exact manifest-listed regular files under the selected root."
    ),
    effect_domains="LOCAL_ADMISSION_STATE_AND_BOUNDED_FILESYSTEM_READS_ONLY",
    effects=(
        "A successful bind adds one admission id to the caller-owned set; reads open and "
        "close local handles and return exact bytes without writing member content."
    ),
    commit=(
        "Binding commits only after all admission and root checks, when the id is added "
        "and the bounded view is returned. Each member read commits only as a checked "
        "observation; this is not package-wide repository admission."
    ),
    retry=(
        "A consumed admission id is refused. Failed pre-commit binding leaves the set "
        "unchanged; a repeated member read is a fresh observation and may see drift."
    ),
    timing=(
        "Cancellation is checked at traversal and read boundaries, but there is no "
        "deadline, freshness age, atomic repository snapshot, or real-time guarantee."
    ),
    limits=(
        "Canonical path components, regular-file and no-reparse rules, generation and "
        "root identity, per-member and total bytes, declared sizes/digests, and exact "
        "source coordinate fail closed."
    ),
    observations=(
        "The mechanism observes manifest identity, root volume/file identity, path and "
        "handle metadata snapshots, cancellation state, exact member bytes, sizes, and "
        "SHA-256 correspondence."
    ),
    units=(
        "Exact bytes, member counts and paths, SHA-256 identities, volume/file indexes, "
        "generation integers, admission ids, and discrete handle operations."
    ),
    failure=(
        "Malformed, stale, reused, mismatched, escaped, linked, nonregular, oversized, "
        "changed, cancelled, unreadable, or incompletely cleaned inputs fail closed; "
        "cleanup uncertainty is retained rather than hidden."
    ),
    recovery=(
        "Correct the external admission, manifest, handle, source materialization, "
        "bounds, or cancellation condition and begin a new admission/read; never infer "
        "that a failed or cancelled read spent or rolled back external state."
    ),
    boundary=(
        "This is exact selected-source admission and observation, not proof that every "
        "repository interface was selected, semantically labeled, or globally polished."
    ),
)


_NETWORK_FIXTURE = _profile(
    name="The artifact-network fixture corpus builder",
    scope=(
        "Construct bounded positive and negative reference records for signed heads, "
        "silo histories and composition, formation and receipts, and proposition transfer."
    ),
    mechanism=(
        "Deterministic Python builders, canonical encodings, fixed synthetic key and "
        "digest material, bounded source reads, and explicit output JSON schemas create "
        "the checked-in interoperability corpus."
    ),
    participants=(
        "The local fixture builder, fixed synthetic publishers/signers, artifact-network "
        "record types, corpus consumers, selected source fixtures, and output paths."
    ),
    inputs=(
        "Pinned builder source, bounded existing fixtures where selected, deterministic "
        "synthetic records, schema versions, case limits, and explicit output paths."
    ),
    authority=(
        "Authority is only the repository's designation of these bytes as synthetic "
        "fixtures. Fixed test keys and valid signatures confer no publisher identity, "
        "ownership, network authority, or production trust."
    ),
    states=(
        "Base, derived, composed, transferred, accepted-reference, intentionally invalid, "
        "rendered, written, and refused corpus states are explicitly represented."
    ),
    ordering=(
        "Base content and heads precede derived histories, transfers, composition and "
        "negative mutations; canonical sorting and record sequence determine fixture order."
    ),
    commands=(
        "Build the selected finite corpus, encode it canonically, and write its named "
        "repository fixture output when the command-line entry point is invoked."
    ),
    targets=(
        "Only the named example and test fixture JSON files and in-memory synthetic "
        "artifact-network records; no live registry, publisher, or network is targeted."
    ),
    effect_domains="SYNTHETIC_FIXTURE_FILES_ONLY",
    effects=(
        "The scripts replace or create named local fixture files. Generated signed "
        "records model protocol and ledger effects but perform no live publication or transfer."
    ),
    commit=(
        "Commit is a complete bounded canonical fixture byte string written to the "
        "selected path; direct file writes are not crash-atomic or a multi-file transaction."
    ),
    retry=(
        "Deterministic inputs should reproduce the same bytes; a retry may overwrite a "
        "prior output and does not reconcile a concurrent writer or partial filesystem effect."
    ),
    timing=(
        "Fixture timestamps are deterministic test data, not observations of occurrence "
        "time; builders provide no deadline, liveness, or real-network progress guarantee."
    ),
    limits=(
        "Schemas, exact record fields, case counts, corpus byte caps, canonical ordering, "
        "digest/signature checks, and bounded source fixture reads constrain generation."
    ),
    observations=(
        "The corpus records ordered synthetic heads, commits, transfers, derivations, "
        "receipts, expected acceptance/rejection, and exact canonical digests."
    ),
    units=(
        "Discrete synthetic records and cases, exact bytes and paths, sequence values, "
        "SHA-256 identities, and fixed test signatures; no monetary unit is represented."
    ),
    failure=(
        "Missing or oversized source fixtures, malformed records, count/shape violations, "
        "encoding errors, or output I/O failures abort generation; a direct write can leave "
        "a partial or replaced file."
    ),
    recovery=(
        "Restore valid pinned inputs, inspect any output after write uncertainty, and "
        "regenerate deterministically; fixture regeneration does not repair live history."
    ),
    boundary=(
        "These are synthetic protocol and ledger fixtures. They establish no live "
        "authority, durable journal, identity, asset backing, settlement, or publication."
    ),
)


_NATIVE_CASE_CORPUS = _profile(
    name="The self-polish native case corpus",
    scope=(
        "Declare deterministic positive, negative, and boundary case inputs for the "
        "native Tier-3 through Tier-9 checker surfaces and the pinned Tier-4 seed."
    ),
    mechanism=(
        "Tier-specific builders bind checker symbols, policies, requests, evidence, "
        "expected outcomes, limits and canonical digests; the Tier-3 builder pins "
        "host-identity literals and hard-coded provenance rather than observing the host."
    ),
    participants=(
        "The repository case builders, native checker APIs, pinned Tier-4 seed, and "
        "later test consumers; the Tier-3 host-identity fields are asserted values."
    ),
    inputs=(
        "Pinned source modules, case seeds, checker routes, policies, requests, fixture "
        "objects, expected statuses, and bounded canonical encoding rules."
    ),
    authority=(
        "Repository source selects the reference cases and expectations; a generated "
        "case is a test policy input, not independent authority for checker correctness "
        "or polish-tier attainment."
    ),
    states=(
        "Unbuilt, built, canonicalized, digest-bound, expected PASS/FAIL/UNKNOWN, seeded, "
        "and rejected case states are represented without promoting expected to observed."
    ),
    ordering=(
        "Each tier's finite generator order and canonical key order determine the corpus; "
        "the Tier-4 builder validates the exact seed before derived cases are rendered."
    ),
    commands=(
        "Build and canonically render the selected case corpus from pinned values; no "
        "owned case builder queries the live host."
    ),
    targets=(
        "In-memory native case records and their named generated fixture outputs; the "
        "Tier-3 host-identity literal 'AMD64' is asserted, not observed."
    ),
    effect_domains="REFERENCE_CASE_CORPUS_AND_ASSERTED_HOST_IDENTITY",
    effects=(
        "Builders produce reference case bytes and may write generated corpus files; "
        "they do not execute the full represented mechanisms or establish tier closure."
    ),
    commit=(
        "A builder result is only a complete canonical case payload with its digest; it "
        "does not commit a verifier decision, application status, or current repository polish."
    ),
    retry=(
        "Pinned inputs should reproduce case bytes except for explicitly captured host "
        "fields. Rebuilding is not independent replay and does not authenticate expectations."
    ),
    timing=(
        "Static case timestamps and asserted host-identity literals are fixtures; no owned "
        "case builder acquires a live host value at invocation time, and no cadence is defined."
    ),
    limits=(
        "Finite tier routes, case counts, schema and field shapes, canonical byte caps, "
        "pinned seed digest/count, exact expected labels, and checker-specific bounds apply."
    ),
    observations=(
        "No owned case builder observes host or device state at run time; the Tier-3 "
        "machine literal and provenance values are declared fixture inputs."
    ),
    units=(
        "Discrete cases, tiers, routes, objects, operations, exact bytes and SHA-256 "
        "digests; the asserted machine identity is an uncalibrated categorical string."
    ),
    failure=(
        "Seed drift, malformed case structure, mismatched checker bindings or digests, "
        "limit violations, unsupported inputs, or encoding/write errors must abort generation."
    ),
    recovery=(
        "Correct the exact seed, builder, checker contract, or environment and regenerate; "
        "do not relabel a generated expectation as an observed verifier result."
    ),
    boundary=(
        "This is policy-owned reference case generation with asserted host-identity "
        "literals. No case corpus proves its checker or any polish tier, and the residual "
        "MEASUREMENT and SENSOR roles have no live acquisition in this source."
    ),
)


_CASE_MATERIALIZER = _profile(
    name="The self-polish case materializer",
    scope=(
        "Refresh a bounded SIM case patch or render a validated native case registry into "
        "one importable Python module at an explicitly selected output path."
    ),
    mechanism=(
        "Strict source module loading, bounded decoding/decompression, exact schema/count/"
        "digest validation, selected checker rebuilds, canonical serialization, and direct "
        "UTF-8 or byte output writes."
    ),
    participants=(
        "The local caller, selected source registry/module, referenced native checker "
        "builders, SIM patch targets, renderer, and explicit output filesystem path."
    ),
    inputs=(
        "Exact source module and registry bytes, tier and schema identifiers, entry and "
        "byte limits, checker symbols, expected outcomes, patch targets, and output path."
    ),
    authority=(
        "Only explicit command-line selection authorizes local materialization; source "
        "case metadata is policy input, not authority to claim checker correctness or polish."
    ),
    states=(
        "Unloaded, validated, refreshed, rendered, output-opened, written, and failed or "
        "partially written states are distinct."
    ),
    ordering=(
        "Load and validate before rebuilding, validate refreshed entries before rendering, "
        "and render the complete payload before opening the selected output for replacement."
    ),
    commands=(
        "Invoke exact native builders/recheckers for selected cases and write one generated "
        "patch or module to the caller-selected filesystem target."
    ),
    targets=(
        "The selected generated Python module or patch file and bounded in-memory case "
        "payload; no package installation, import activation, or publication target."
    ),
    effect_domains="LOCAL_GENERATED_CASE_FILE_ONLY",
    effects=(
        "A successful invocation creates or replaces one local generated case file; "
        "checker calls may run trusted in-process code while preparing its bytes."
    ),
    commit=(
        "Commit is only return from the direct write of complete rendered bytes. The write "
        "is not temp-file/rename atomic and does not install or validate the generated module."
    ),
    retry=(
        "A retry rebuilds and may replace the same output again; matching content digests "
        "support comparison but do not make a failed or interrupted write idempotent."
    ),
    timing=(
        "There is no subprocess isolation, timeout, concurrent-writer lock, or real-time "
        "guarantee for checker execution or output materialization."
    ),
    limits=(
        "Schema, tier, entry counts, byte/decompression bounds, digest bindings, exact "
        "checker names and expected outcomes bound accepted materialization."
    ),
    observations=(
        "The materializer observes selected source bytes, schema/count/digest checks, "
        "checker rebuild correspondence, rendered byte length, and output write success."
    ),
    units="Discrete cases and entries, exact UTF-8 bytes, byte caps, and SHA-256 digests.",
    failure=(
        "Import, schema, count, digest, decompression, checker correspondence, rendering, "
        "or I/O failure aborts; direct output replacement can leave prior loss or partial bytes."
    ),
    recovery=(
        "Inspect the selected output after uncertainty, repair the exact source/checker or "
        "destination, and perform a fresh bounded render; never infer installation from a write."
    ),
    boundary=(
        "This materializes local reference case code only. It proves neither generated "
        "module importability nor checker correctness, package coverage, or polish status."
    ),
)


_FULL_CANDIDATE = _profile(
    name="The full native self-polish candidate capture",
    scope=(
        "Capture one selected repository source coordinate and census, replay the full "
        "native candidate against that coordinate digest, and serialize one candidate artifact."
    ),
    mechanism=(
        "The script resolves the selected root, invokes source capture and full-candidate "
        "replay APIs, derives canonical coordinate/candidate digests, and writes canonical bytes."
    ),
    participants=(
        "The local caller, selected repository and Git/filesystem observers, self-polish "
        "source-capture and replay mechanisms, candidate artifact, and output path."
    ),
    inputs=(
        "An explicit existing repository root and output path plus current tracked/untracked "
        "source state, Git coordinate, source manifests, native cases, and replay policies."
    ),
    authority=(
        "The caller selects root and output; internal policies select admitted replay routes. "
        "A locally captured candidate has no independent release or application authority."
    ),
    states=(
        "Root-selected, source-observed, coordinate-bound, replaying, candidate-returned, "
        "artifact-rendered, written, refused, and indeterminate states are distinct."
    ),
    ordering=(
        "Resolve root, capture current source, derive its coordinate digest, replay against "
        "that exact digest, bind evidence and candidate, then render and write the artifact."
    ),
    commands=(
        "Acquire repository/Git state, invoke the bounded full-native replay controller, "
        "and write canonical candidate bytes to the explicit output path."
    ),
    targets=(
        "The selected local repository observation/replay interfaces and one local output "
        "artifact; no deployment, publication, physical endpoint, or financial endpoint."
    ),
    effect_domains="LOCAL_SOURCE_ACQUISITION_REPLAY_AND_CANDIDATE_FILE_ONLY",
    effects=(
        "The route reads current repository state, runs trusted replay mechanisms, and "
        "creates or replaces one candidate artifact file."
    ),
    commit=(
        "Commit is return from writing one canonical artifact that binds the observed "
        "coordinate and returned candidate. It is not atomic across source drift or output I/O."
    ),
    retry=(
        "Every retry recaptures current source and reruns mechanisms; it is a new observation "
        "and execution, not idempotent replay of an earlier coordinate."
    ),
    timing=(
        "Capture and replay are invocation-bounded but have no repository freeze, global "
        "concurrent-writer exclusion, hard deadline, or cross-mechanism real-time guarantee."
    ),
    limits=(
        "Resolved-root checks, exact source manifests/census, native policy bounds, canonical "
        "digests and output encoding constrain the route; trusted mechanisms are not sandboxed."
    ),
    observations=(
        "It observes Git head/tree/status digest, source manifests and census counts/bytes, "
        "native replay decisions, candidate status, and output serialization."
    ),
    units=(
        "Exact paths and bytes, tracked/untracked and source-file counts, SHA-256 coordinate "
        "and artifact identities, and discrete replay routes/results."
    ),
    failure=(
        "Unavailable or drifting source, invalid replay input, mechanism failure, malformed "
        "candidate, or output I/O prevents a complete artifact; prior external effects are "
        "not rolled back by an exception."
    ),
    recovery=(
        "Inspect the repository and output at their exact coordinates, correct the bounded "
        "failure, and start a fresh capture; never transplant status from an older artifact."
    ),
    boundary=(
        "The artifact is candidate evidence bound to one observed source coordinate. It is "
        "not independent verification, complete application polish, confinement, or release."
    ),
)


_TIER1_LEDGER = _profile(
    name="The legacy Tier-1 evidence ledger builder",
    scope=(
        "Build and optionally replay an external FACETS evidence template for the pinned "
        "legacy inventory of 26 object kinds, 45 Tier-1 memberships, and 135 mapped cases."
    ),
    mechanism=(
        "The script validates pinned inventory identities and source mappings, acquires Git "
        "coordinates and file digests, launches bounded pytest collection, builds UNKNOWN "
        "ledger entries, validates replay receipts, and writes selected JSON artifacts."
    ),
    participants=(
        "The local caller, legacy installed-route inventory, source/test files, Git and "
        "pytest child processes, evidence/replay records, and selected output paths."
    ),
    inputs=(
        "Exact legacy constants (26 kinds, 234 global cells, 408 memberships, 45 Tier-1 "
        "memberships and 135 cases), source coordinate, current file bytes, inventory, "
        "optional replay receipt, limits, and output paths."
    ),
    authority=(
        "Repository source selects the legacy mapping and the caller selects execution and "
        "outputs. Provider labels and replay receipts remain unauthenticated candidate evidence "
        "and cannot authorize PASS or current 38-kind completeness."
    ),
    states=(
        "Unmapped, mapping-validated, source-observed, collection-complete, UNKNOWN template, "
        "candidate replayed, refused, output-written, and externally unqualified states."
    ),
    ordering=(
        "Validate pinned inventory and mappings before collection; bind current repository/"
        "revision and file digests before building entries; validate a receipt before deriving "
        "candidate disposition; write only the selected completed document."
    ),
    commands=(
        "Run fixed Git queries and bounded pytest collection, read selected source/test bytes, "
        "validate optional replay evidence, and write ledger, manifest, or candidate JSON."
    ),
    targets=(
        "Local Git/pytest child processes, current repository files, in-memory legacy evidence "
        "records, and caller-selected local JSON outputs."
    ),
    effect_domains="LOCAL_LEGACY_EVIDENCE_COLLECTION_AND_JSON_OUTPUTS_ONLY",
    effects=(
        "It launches read-oriented child processes and creates or replaces selected local "
        "JSON files; it does not alter verifier source, authenticate a provider, or grant tier PASS."
    ),
    commit=(
        "Commit is only completion of one direct JSON output write after validation. Each "
        "ledger entry remains UNKNOWN until separately qualified, and the legacy denominator "
        "cannot claim current 38-kind completeness."
    ),
    retry=(
        "A retry recollects current files, Git and pytest nodes and may replace outputs; source "
        "drift changes the evidence coordinate, and no child or file effect is rolled back."
    ),
    timing=(
        "Git calls use ten-second and pytest collection sixty-second timeouts; captured source "
        "is not locked, and no freshness beyond the invocation or provider liveness is promised."
    ),
    limits=(
        "Strict JSON, one- and sixteen-mebibyte input caps, fixed source/test mapping, exactly "
        "three cases per legacy membership, pinned counts/digests, and child timeouts fail closed."
    ),
    observations=(
        "It observes current Git repository/revision, file digests, pytest collection results, "
        "legacy inventory/mapping correspondence, replay receipt structure, and local writes."
    ),
    units=(
        "Legacy object kinds, cells, memberships and case nodes; exact file bytes and paths; "
        "SHA-256 identities; child return codes; timeout seconds; and JSON records."
    ),
    failure=(
        "Any legacy count/digest/mapping drift, absent collection node, Git/pytest failure, "
        "malformed or inconsistent receipt, or I/O error refuses output or leaves status UNKNOWN."
    ),
    recovery=(
        "Inspect child and output state, update the mechanism and independently reviewed "
        "mappings for the current namespace, then perform a fresh source-bound collection; "
        "never reuse the legacy PASS denominator for 38 kinds."
    ),
    boundary=(
        "The implementation hard-codes a legacy 26-kind/45-membership denominator. It "
        "cannot claim present 38-kind namespace completeness, package polish, authenticated "
        "provider review, release, deployment, or real-world validation."
    ),
)


_REVIEWS = {
    "vstd-selected-source-admission": _review(
        "POLICY",
        _SELECTED_SOURCE_PATHS,
        ("POLICY", "CONTROLLER", "MEASUREMENT", "SENSOR", "PROTOCOL", "TRANSACTION"),
        _SELECTED_SOURCE,
    ),
    "vstd-network-fixture-corpus": _review(
        "LEDGER",
        _NETWORK_FIXTURE_PATHS,
        ("LEDGER", "PROTOCOL", "TRANSACTION"),
        _NETWORK_FIXTURE,
    ),
    "vstd-self-polish-native-case-corpus": _review(
        "POLICY",
        _NATIVE_CASE_PATHS,
        ("POLICY", "MEASUREMENT", "SENSOR"),
        _NATIVE_CASE_CORPUS,
        {
            "POLICY": _NATIVE_CASE_PATHS,
            "MEASUREMENT": _TIER3_CASE_PATH,
            "SENSOR": _TIER3_CASE_PATH,
        },
    ),
    "vstd-self-polish-case-materializer": _review(
        "TRANSACTION",
        _CASE_MATERIALIZER_PATHS,
        ("TRANSACTION", "ACTUATOR", "POLICY"),
        _CASE_MATERIALIZER,
    ),
    "vstd-self-polish-full-candidate-capture": _review(
        "CONTROLLER",
        _FULL_CANDIDATE_PATHS,
        (
            "CONTROLLER",
            "ACTUATOR",
            "MEASUREMENT",
            "SENSOR",
            "PROTOCOL",
            "POLICY",
            "TRANSACTION",
        ),
        _FULL_CANDIDATE,
    ),
    "vstd-tier1-evidence-ledger": _review(
        "LEDGER",
        _TIER1_LEDGER_PATHS,
        (
            "LEDGER",
            "ACTUATOR",
            "CONTROLLER",
            "MEASUREMENT",
            "SENSOR",
            "PROTOCOL",
            "POLICY",
            "TRANSACTION",
        ),
        _TIER1_LEDGER,
    ),
}


def _contract_rows(kind: str) -> list[dict[str, Any]]:
    return [
        row
        for row in requirements_for(namespace_registry(), (kind,))
        if row["kind"] == kind
    ]


def _declarations(review: _Review) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for kind in review.applicable:
        try:
            selected = _shared._DECLARATION_BUILDERS[kind](review.profile)
        except KeyError as exc:
            raise AssertionError("missing declaration builder for " + kind) from exc
        overlap = set(result).intersection(selected)
        if overlap:
            raise AssertionError("duplicate declaration ids: " + ", ".join(overlap))
        result.update(selected)
    return result


def _catalog_check() -> None:
    if tuple(_REVIEWS) != SCRIPT_OBJECT_IDS:
        raise AssertionError("script review order differs from public object order")
    owned_paths: set[str] = set()
    for object_id, review in _REVIEWS.items():
        if review.primary_kind not in review.applicable:
            raise AssertionError(object_id + " primary kind is not applicable")
        if len(review.owned_paths) != len(set(review.owned_paths)):
            raise AssertionError(object_id + " repeats an owned path")
        overlap = owned_paths.intersection(review.owned_paths)
        if overlap:
            raise AssertionError(
                "script ownership overlaps: " + ", ".join(sorted(overlap))
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
        if any(
            not _reason(review.profile, kind).strip() for kind in review.applicable
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
    if len(owned_paths) != 23:
        raise AssertionError("script review source denominator differs")


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return a defensive, deterministic review of the six exact owners."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: _classification_document(review, kind)
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


def _preserve_classification(
    decision: Any,
    review: _Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
) -> bool:
    """Return True only for a complete decision equal to its explicit basis.

    Absence of a literal basis is never a refutation.  A kind without an APPLIES
    basis may hold only a validated UNRESOLVED candidate; any complete APPLIES or
    DOES_NOT_APPLY decision there is rejected as unbacked, not erased.
    """
    code = "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
    if _basis(review, kind) == "APPLIES":
        return _shared._preserve_explicit_decision(
            decision,
            _explicit_decision(review, kind, evidence_by_path),
            files,
            owned,
            object_id=object_id,
            kind=kind,
        )
    if _unresolved_candidate(decision, files, owned, kind=kind, code=code):
        return type(decision) is dict and bool(decision["evidence"])
    if type(decision) is dict and decision.get("status") in {
        "APPLIES",
        "DOES_NOT_APPLY",
    }:
        raise ValueError(
            "PACKAGE_SEMANTIC_REVIEW_UNBACKED_DECISION:" + object_id + ":" + kind
        )
    raise ValueError(code)


def apply_package_semantic_review_scripts(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply all six exact-source reviews atomically to a deep copy."""
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

    _assert_unaliased(rows, code="PACKAGE_SEMANTIC_REVIEW_ALIASED_ROWS")
    for object_id in _REVIEWS:
        row = rows.get(object_id)
        if type(row) is dict:
            for part in ("classification", "obligations", "specializations"):
                _assert_plain_tree(
                    row.get(part),
                    code="PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + object_id,
                )

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
        for label in [*classification, *specializations]:
            if _label_variant(label):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:"
                    + object_id
                    + ":"
                    + label
                )

        known_obligations = {
            name for values in live_obligations.values() for name in values
        }
        for name in obligations:
            if type(name) is not str or (
                name not in known_obligations
                and _shared._label_kind(name) in REVIEW_KINDS
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
        for kind in REVIEW_KINDS:
            applies = _basis(review, kind) == "APPLIES"
            if _preserve_classification(
                classification.get(kind),
                review,
                kind,
                evidence_by_path,
                files,
                owned,
                object_id=object_id,
            ):
                preserve_decisions.add(kind)
            for obligation_id, fields in live_obligations[kind].items():
                binding = obligations.get(obligation_id)
                if applies:
                    if _shared._preserve_explicit_obligation(
                        binding,
                        fields,
                        _obligation_reason(review.profile, kind),
                        _role_evidence(review, kind, evidence_by_path),
                        files,
                        owned,
                        object_id=object_id,
                        obligation_id=obligation_id,
                    ):
                        preserve_obligations.add(obligation_id)
                elif binding is not None:
                    code = (
                        "PACKAGE_SEMANTIC_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                        + object_id
                        + ":"
                        + obligation_id
                    )
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
        }

    # Re-read the whole twenty-three-path denominator after semantic preflight.
    # Concurrent source changes therefore cannot yield a partly current review.
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
            if _basis(review, kind) == "APPLIES":
                row["classification"][kind] = _explicit_decision(
                    review, kind, plan["evidence_by_path"]
                )
            else:
                row["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": _shared._unresolved_reason(kind),
                    "evidence": [],
                }
        for name in plan["remove_obligations"]:
            row["obligations"].pop(name, None)
        for name, declaration in declarations.items():
            if name in plan["preserve_obligations"]:
                continue
            kind = name.split("-", 1)[0]
            row["obligations"][name] = {
                "reason": _obligation_reason(review.profile, kind),
                "evidence": _role_evidence(review, kind, plan["evidence_by_path"]),
                "declaration": dict(declaration),
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)
    return result


__all__ = [
    "CLAIM_BOUNDARY",
    "REVIEW_KINDS",
    "SCRIPT_OBJECT_IDS",
    "apply_package_semantic_review_scripts",
    "review_document",
]
