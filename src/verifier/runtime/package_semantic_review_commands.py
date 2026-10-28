"""Current-source Tier-0 reviews for thirteen bounded command mechanisms.

Terminology: application programming interface (API); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard
(VSTD).

These reviews answer one repository-admission question for exact, path-owned
objects: which consequential namespace kinds apply to each command mechanism,
why each decided kind applies or is explicitly refuted, and which current
source bytes support each declaration.  A kind named in neither literal set is
canonical UNRESOLVED; tuple absence never becomes a refutation.  A review does
not execute a command, establish the truth of
its output, authenticate a selector, authorize publication, or establish any
Tier-1-plus result.

Application is pure, atomic, and fail closed.  Every owned byte is checked
against the caller's digest census before and after semantic preflight.
Compatible complete bindings are preserved; stale, partial, contradictory,
mislabeled, or unowned bindings abort the whole thirteen-object operation.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.package_original_kind_profiles import (
    ORIGINAL_NON_OBJECT_KINDS,
)
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


REVIEW_KINDS = _shared.REVIEW_KINDS

COMMAND_OBJECT_IDS = (
    "vstd-artifact-snapshot-transaction",
    "vstd-accessibility-artifact-reader",
    "vstd-graph-topology-reader",
    "vstd-current-object-reader",
    "vstd-experimental-workflow-reader",
    "vstd-security-artifact-reader",
    "vstd-certification-command",
    "vstd-clearance-publication-preparation",
    "vstd-demo-specimen-materializer",
    "vstd-core-obligation-union-policy",
    "vstd-security9-accounting-policy",
    "vstd-application-authority-protocol",
    "vstd-release-source-binding",
)

CLAIM_BOUNDARY = (
    "Current-source Tier-0 applicability and declaration review for thirteen "
    "exact command owners only. Mechanism execution, output truth, selector or "
    "human authority, application-wide polish, publication, release, deployment, "
    "and Tier-1-plus conformance remain separately unestablished."
)


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    profile: _shared._Profile
    refuted: tuple[str, ...] = ()


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


def _review(
    primary_kind: str,
    path: str,
    applicable: tuple[str, ...],
    profile: _shared._Profile,
    *,
    refuted: tuple[str, ...] = (),
) -> _Review:
    paths = (path,)
    return _Review(
        primary_kind=primary_kind,
        owned_paths=paths,
        applicable=applicable,
        role_paths={kind: paths for kind in applicable},
        profile=profile,
        refuted=refuted,
    )


def _reason(profile: _shared._Profile, kind: str, applies: bool) -> str:
    """Give every kind an explicit source-specific necessity or refutation."""
    if applies:
        necessity = {
            "LEDGER": (
                "Its unsealed caller dispatch can reach retained ordering or history "
                "behavior, so the ledger obligation remains live without asserting one occurred."
            ),
            "TRANSACTION": (
                "Its bounded local read/write or evaluation attempt has explicit "
                "preconditions, commit evidence, partial-failure state, and retry semantics."
            ),
            "ASSET": (
                "Its unsealed caller dispatch is not established to exclude resource, "
                "rights, custody, or backing behavior, so the asset obligation remains live."
            ),
            "MARKET": (
                "Its unsealed caller dispatch is not established to exclude participant, "
                "allocation, price, or settlement behavior, so the market obligation remains live."
            ),
            "MEASUREMENT": (
                "Its report distinguishes exact software-interface observations from "
                "unobserved source, mechanism, physical, or external state."
            ),
            "SENSOR": (
                "Its bounded software acquisition path has explicit source, range, "
                "latency, missingness, and fault behavior."
            ),
            "CONTROLLER": (
                "Its unsealed caller dispatch is not established to exclude feedback or "
                "command selection, so the controller obligation remains live."
            ),
            "ACTUATOR": (
                "It can execute a selected in-process mechanism or create a named local "
                "file, while downstream and external effects remain unestablished."
            ),
            "PROTOCOL": (
                "Its selected records, configured keys, ordered messages, states, and "
                "replay checks form a bounded participant protocol."
            ),
            "POLICY": (
                "Its rule selection, authority boundary, defaults, exceptions, and "
                "enforcement points determine the bounded result."
            ),
            "ROBOT": (
                "Its unsealed caller dispatch is not established to exclude a physical "
                "endpoint path; retaining the role does not assert actuation occurred."
            ),
            "FINBOT": (
                "Its unsealed caller dispatch is not established to exclude a financial "
                "endpoint path; retaining the role does not assert authority or effect."
            ),
        }[kind]
        return (
            profile.name
            + " applies as "
            + kind
            + ". "
            + necessity
            + " Reviewed boundary: "
            + profile.boundary
        )
    raise AssertionError("refuted kind " + kind + " needs an object-specific basis")


def _basis(review: _Review, kind: str) -> str:
    """Return a literal basis; absence from both sets remains unresolved."""
    if kind in review.applicable:
        return "APPLIES"
    if kind in review.refuted:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _decision_reason(object_id: str, review: _Review, kind: str) -> str:
    basis = _basis(review, kind)
    if basis == "UNRESOLVED":
        return _shared._unresolved_reason(kind)
    if basis == "DOES_NOT_APPLY":
        return (
            review.profile.name
            + " does not apply as "
            + kind
            + ". "
            + _DNE_BASES[object_id][kind]
            + " Reviewed boundary: "
            + review.profile.boundary
        )
    return _reason(review.profile, kind, True)


def _classification_document(
    object_id: str, review: _Review, kind: str
) -> dict[str, Any]:
    basis = _basis(review, kind)
    if basis == "UNRESOLVED":
        paths: tuple[str, ...] = ()
    elif basis == "APPLIES":
        paths = review.role_paths[kind]
    else:
        paths = review.owned_paths
    return {
        "status": basis,
        "reason": _decision_reason(object_id, review, kind),
        "evidence_paths": list(paths),
    }


def _explicit_decision(
    object_id: str,
    review: _Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
) -> dict[str, Any]:
    basis = _basis(review, kind)
    if basis == "APPLIES":
        paths = review.role_paths[kind]
    elif basis == "DOES_NOT_APPLY":
        paths = review.owned_paths
    else:
        raise AssertionError("explicit decision requested for unlisted " + kind)
    return {
        "status": basis,
        "reason": _decision_reason(object_id, review, kind),
        "evidence": [deepcopy(evidence_by_path[path]) for path in paths],
    }


def _obligation_reason(review: _Review, kind: str) -> str:
    return (
        _reason(review.profile, kind, True)
        + " This Tier-0 declaration names the reviewed boundary only; "
        "mechanism execution and Tier-1-plus fulfillment remain unestablished."
    )


_ARTIFACT_SNAPSHOT = _profile(
    name="The bounded artifact snapshot mechanism",
    scope="Capture exact ordinary local file or directory bytes, describe their finite inventory, and optionally materialize or exclusively write a caller-selected local result.",
    mechanism="Reject symlinks and reparse points, walk a finite sorted inventory, enforce byte and file caps, hash exact bytes, and use direct local reads or writes.",
    participants="The trusted caller, local filesystem, snapshot reader, inventory builder, and optional destination writer.",
    inputs="One caller-selected artifact path, finite ordinary source entries, optional destination path, and an optional canonical JSON record.",
    authority="The caller selects readable source and writable destination paths; the code provides no provenance, ownership, publication, locking, or external authority.",
    states="Unselected, reading, captured in memory, inventory returned, materializing, locally written, rejected, or interrupted.",
    ordering="Parent alias checks precede final-entry checks; sorted capture precedes inventory or materialization; each destination file is written in path order.",
    commands="Read ordinary source bytes, hash them, create destination directories, and write snapshot or canonical record bytes to selected local paths.",
    targets="The selected local source tree, in-memory Snapshot, and caller-selected local destination only.",
    effect_domains="LOCAL_FILESYSTEM_ONLY; no remote, physical, financial, publication, or deployment endpoint is represented.",
    effects="Read a finite local artifact and optionally create or replace individual destination files, or exclusively create one canonical output record.",
    commit="Capture commits only to an in-memory exact-byte Snapshot; materialization commits per file write and is not atomic across files, locked, fsynced, or crash durable.",
    retry="No transaction identifier or duplicate ledger exists; retry re-reads current source bytes and can repeat or partially overwrite materialization effects.",
    timing="Observations occur during sequential local reads and writes with no stable-snapshot lock, timestamp claim, deadline, or real-time guarantee.",
    limits="File count, traversal entries, individual bytes, total bytes, record bytes, ordinary-file status, and portable relative names are bounded.",
    observations="Exact bytes read at each local open, stat metadata used for admission, byte counts, portable paths, and SHA-256 commitments.",
    units="Exact bytes, files, traversal entries, portable paths, and SHA-256 digests.",
    failure="Missing, aliased, nonordinary, oversized, empty, changed, or unwritable paths raise; prior per-file writes are not rolled back.",
    recovery="Inspect source and destination state, remove or reconcile only with separate authority, then explicitly recapture or rematerialize.",
    boundary="Local exact-byte capture and per-file writing lack provenance authority, locking, crash durability, multi-file atomicity, and any external consequence claim.",
)


_ACCESSIBILITY_READER = _profile(
    name="The accessibility artifact reader",
    scope="Emit a getting-started guide or restate one selected stored artifact through a caller-supplied command namespace and path-coercion boundary.",
    mechanism="Read unsealed command attributes, coerce the supplied path, resolve a local target, decode selected JSON, project stored rows without reevaluating evidence, and map stored status to an exit code.",
    participants="The caller-supplied namespace and path-like object, local artifact reader, explanation projection, standard output, and consumer of the explanation.",
    inputs="A fixed built-in guide or caller-supplied command attributes, receipt/certificate path-like value, and stored fields.",
    authority="The caller selects the artifact; stored fields remain assertions of that artifact and neither the reader nor exit code grants provenance or conformance authority.",
    states="Guide selected, artifact resolved, decoded, recognized projection, generic projection, rejected, or explanation emitted.",
    ordering="Selection and bounded decode precede type-specific projection; stored verdict is preserved before human and JSON renderings are emitted.",
    commands="Read unsealed namespace attributes, coerce a path-like value, read and project stored fields, and emit to standard output; delegated caller hooks remain unsealed.",
    targets="The caller-supplied namespace and path-like object, selected local JSON artifact, and standard output.",
    effect_domains="LOCAL_READ_AND_STDOUT_WITH_UNSEALED_CALLER_DISPATCH; downstream physical, financial, publication, and authority effects remain unestablished.",
    effects="Invoke caller-controlled attribute and path coercion hooks, read a selected artifact, emit an explanation, and return a process exit status without asserting any delegated effect occurred.",
    commit="Commit is emission of a projection derived from the decoded document; it does not commit or upgrade any stored result.",
    retry="Repeated reading produces a new projection of current selected bytes; no cached success or duplicate identity is retained.",
    timing="The read has no freshness proof or stable-file lock; only values present when read are observed.",
    limits="Selected JSON shape and local availability bound the projection; no source provenance or complete artifact-family denominator is inferred.",
    observations="Stored status, obligation/check rows, blockers, reasons, claim boundaries, and artifact paths only.",
    units="Stored rows, status labels, paths, and exact decoded JSON values.",
    failure="Caller hooks, unavailable or malformed input, decoding, projection, and output may fail; absent fields remain absent or default to unestablished rather than being invented.",
    recovery="Correct or replace the selected artifact and rerun; execute the separately named checker when fresh evaluation is required.",
    boundary="Applicability retains every delegated obligation without claiming a hook or endpoint ran; a projection does not reevaluate evidence, prove provenance, establish identity or authority, or grant conformance.",
)


_GRAPH_READER = _profile(
    name="The graph-topology diagnostic reader",
    scope="Read one selected graph inspection envelope and contract, then report bounded structural, Boolean-consistency, and temporal-consistency diagnostics.",
    mechanism="Open ordinary files with finite byte reads, strict JSON decode, construct a ProvenanceHypergraph and GraphTopologyContract, and run the selected bounded analyzer.",
    participants="The caller, two local input files, graph/contract decoders, bounded topology analyzer, and report consumer.",
    inputs="One verifier-data-1 hypergraph envelope, one interpretation contract, and a finite maximum-assignment bound.",
    authority="The caller selects both graph and interpretation; neither bytes nor a consistent diagnostic authenticate causality, provenance, payloads, or conformance.",
    states="Inputs selected, decoded, graph constructed, analyzed as consistent/conflicted/unresolved, rejected, or report emitted.",
    ordering="Both documents are bounded and decoded before analysis; structural, Boolean, and temporal facets are then projected into one report.",
    commands="Read selected local files and execute the in-process topology diagnostic without mutating the graph.",
    targets="The selected graph projection, contract, bounded analyzer state, and standard output.",
    effect_domains="READ_ONLY_GRAPH_DIAGNOSTIC; no graph mutation, payload inspection, causal actuation, or conformance issuance occurs.",
    effects="Emit a topology diagnostic and corresponding exit status only.",
    commit="Commit is one emitted report over the selected decoded graph and contract; no source graph or enclosing receipt state is committed.",
    retry="Retry reopens current files and recomputes; no run identity, stable snapshot, or cached decision is retained.",
    timing="Local read time is not graph event time; temporal consistency is only under the supplied graph and interpretation.",
    limits="Each document is capped at 2 MiB and parser nesting and assignment exploration remain bounded or fail closed.",
    observations="Decoded nodes, edges, supplied interpretation, and analyzer facet statuses only.",
    units="Graph nodes, edges, assignments, temporal values supplied by the contract, bytes, and status labels.",
    failure="Malformed, nonordinary, oversized, recursively invalid, conflicted, or unresolved inputs remain rejected, conflicted, or unresolved.",
    recovery="Correct the exact graph or interpretation and rerun; separately validate enclosing receipt and payload bytes when those claims matter.",
    boundary="The result is a selected graph projection diagnostic, not receipt validation, payload integrity, physical causality, or application conformance.",
)


_CURRENT_OBJECT_READER = _profile(
    name="The current-object replay command",
    scope="List installed native current-object routes or replay one exact caller-selected certificate against independently selected request and policy bytes.",
    mechanism="Select installed code before certificate decode, bounded-read three local files, strict-decode request/policy, and invoke the registered native replay route.",
    participants="The caller, local certificate/request/policy files, installed route catalog, selected native checker, and report consumer.",
    inputs="Semantic version, objective, represented kind, exact certificate bytes, independently selected request and policy objects, and installed route code.",
    authority="The caller independently selects route, request, and policy; certificate contents cannot select code or confer application, owner, publication, or release authority.",
    states="Cataloged, route selected, inputs acquired, replay PASS/FAIL/UNKNOWN, unavailable, rejected, or result emitted.",
    ordering="Installed route selection precedes opening self-describing certificate bytes; independent request and policy are read before certificate replay.",
    commands="Read local inputs and execute one installed in-process replay checker; no certificate producer command is executed.",
    targets="Selected local records, installed native route, in-memory replay state, and standard output.",
    effect_domains="LOCAL_NATIVE_REPLAY_ONLY; host-process checker behavior is not sandboxed and no publication or external endpoint is authorized.",
    effects="Run the selected checker and emit its bounded computational result and claim boundary.",
    commit="Commit is return/emission of the replay result after exact selection checks; no object-profile or package-wide state is committed.",
    retry="Retry is a new read and checker execution; no general checker idempotency, stable-input lock, or duplicate guard is established.",
    timing="Reads and replay occur at command time without a freshness witness or general checker timeout guarantee.",
    limits="Certificate and selection-text bytes, installed route identity, represented-kind rule, and checker policy constrain the run.",
    observations="Selected record bytes, native checker return, replay status, computational status, and explicit failure category only.",
    units="Bytes, route identifiers, obligation/check rows, status labels, and exact digests declared by the selected route.",
    failure="Unavailable checker or capacity remains UNKNOWN; malformed, incompatible, or refuted input is rejected or FAIL without upgrading other claims.",
    recovery="Restore the exact checker or correct independent inputs and explicitly replay again; inspect external callback state if a checker was interrupted.",
    boundary="Selected native replay establishes only its bounded result; no whole tier, full package, source authority, publication, or release follows.",
)


_EXPERIMENTAL_READER = _profile(
    name="The experimental-workflow artifact reader",
    scope="Validate one non-normative workflow manifest and optional repository artifact bytes, or adapt one normalized GitHub snapshot into verdict-neutral events.",
    mechanism="Resolve selected local paths, decode finite structured inputs through the experimental profile, verify declared repository artifact bindings when a root is supplied, and project normalized events.",
    participants="The caller, selected manifest or snapshot, optional repository root, experimental profile validators/adapters, and report consumer.",
    inputs="One experimental manifest or normalized GitHub snapshot plus an optional independently selected repository root.",
    authority="The caller selects all local inputs; a structurally valid manifest or normalized event supplies no native verifier, publication, independence, or VSTD verdict authority.",
    states="Selected, decoded, repository artifacts verified/not checked/not applicable, normalized, adapted, rejected, or report emitted.",
    ordering="Manifest structure is checked before optional repository bindings; normalized snapshot decode precedes ordered event adaptation.",
    commands="Read selected local bytes, compare declared repository artifact identities, and compute a verdict-neutral projection; write nothing.",
    targets="Selected experimental records, optional repository artifact paths, in-memory projections, and standard output.",
    effect_domains="READ_ONLY_EXPERIMENTAL_PROJECTION; no workflow execution, remote GitHub access, publication, or verdict issuance occurs.",
    effects="Emit validation state or normalized events while explicitly granting zero VSTD verdicts.",
    commit="Commit is only emission of the selected structural projection; no repository, workflow, or verifier state is changed.",
    retry="Retry rereads current selected bytes; it retains no stable snapshot, remote event identity, or cached verification result.",
    timing="Local read time and normalized event timestamps are distinct; no remote freshness, arrival, or causal ordering is authenticated.",
    limits="Manifest/profile schema, declared digests, optional repository locator checks, normalized snapshot shape, and local availability bound the result.",
    observations="Declared workflow/profile fields, manifest digest, optional local artifact comparisons, and normalized event fields only.",
    units="Files, declared artifact locators, events, byte digests, and status labels.",
    failure="Malformed or mismatched input is rejected; omitted repository root leaves repository artifacts NOT_CHECKED rather than treating them as valid.",
    recovery="Supply the exact repository root or correct the selected normalized record and rerun; use a separately admitted native mechanism for a verdict.",
    boundary="Structural validity and selected byte comparisons do not establish the hypothesis, native verifier, independence, publication, or a VSTD verdict.",
)


_SECURITY_READER = _profile(
    name="The dangerous-pathway security replay command",
    scope="List the installed security dialect or recheck one retained pathway certificate/request pair or host-selected aggregate assessment.",
    mechanism="Bounded-read selected local records, invoke installed dangerous-pathway replay functions, preserve FAIL/UNKNOWN, and project security and publication fields.",
    participants="The caller, selected local records, installed dangerous-pathway checker, host policy represented by the inputs, and report consumer.",
    inputs="A command selection and exact certificate/request or assessment bytes under installed checker capacity.",
    authority="The host selects the records and applicable policy outside this command; a retained security record never grants publication or operational authority.",
    states="Cataloged, selected, acquired, security established/refuted/not established, checker unavailable, rejected, or report emitted.",
    ordering="Command and independent request selection precede replay; bounded acquisition precedes checker evaluation and fail-closed exit mapping.",
    commands="Read selected local inputs and execute one installed in-process security replay without changing the assessed system.",
    targets="Selected security records, installed replay mechanism, in-memory result, and standard output.",
    effect_domains="LOCAL_SECURITY_REPLAY_ONLY; no dangerous pathway is exercised, disabled, published, or authorized by this command.",
    effects="Emit the bounded security outcome, explicit claim boundary, and process exit status.",
    commit="Commit is only the returned replay result; it is not a security clearance, publication approval, or change to a dangerous pathway.",
    retry="A retry rereads current records and reexecutes the checker; no stable artifact snapshot or general idempotency is established.",
    timing="The command establishes no retained-record freshness beyond checks inside the selected mechanism and no general execution deadline.",
    limits="Certificate, request, and assessment byte bounds plus installed checker contracts bound the replay.",
    observations="Selected record bytes, checker outcome, blockers, security outcome, and publication-authority field only.",
    units="Bytes, pathway rows, aggregate rows, status labels, and mechanism-defined exact digests.",
    failure="Checker absence or resource exhaustion remains UNKNOWN; malformed or refuted contracts FAIL without conferring clearance.",
    recovery="Restore the exact checker or correct independent records and replay; separately evaluate current deployment state before action.",
    boundary="Local replay can establish only its selected security outcome; it grants no security clearance, publication authority, deployment fact, or general safety proof.",
)


_CERTIFICATION_COMMAND = _profile(
    name="The certification command dispatcher",
    scope="Catalog installed obligations or assess/recheck one selected grounded, domain, or mainstay certificate under independent request and policy inputs.",
    mechanism="Bounded strict JSON reads, externally selected policy/request construction, registered built-in mechanism execution, exact result aggregation, and exclusive optional certificate creation.",
    participants="The caller, local request/policy/evidence or certificate files, installed certification mechanisms, optional output writer, and result consumer.",
    inputs="A command mode, exact local records, independently selected request and policy, installed mechanisms, and optional new output path.",
    authority="The caller supplies selection and policy; certificate bytes cannot admit their own mechanism or grant owner, application, publication, human, legal, or release authority.",
    states="Cataloged, selected, evidence loaded, mechanism running, PASS/FAIL/UNKNOWN, certificate exclusively created, rejected, or emitted.",
    ordering="Independent request and policy decode precedes evidence/certificate evaluation; mechanism registration precedes execution; successful assessment precedes optional exclusive output write.",
    commands="Execute admitted in-process certification mechanisms and optionally create one new local certificate file.",
    targets="Selected local records, in-memory evidence/session state, registered mechanism code, standard output, and optional exclusive local certificate path.",
    effect_domains="TRUSTED_IN_PROCESS_CHECK_AND_OPTIONAL_LOCAL_CREATE; mechanism confinement and downstream use are not established.",
    effects="Run selected checks, aggregate bounded result rows, emit a status, and optionally create one certificate without overwriting an existing file.",
    commit="Commit is a returned assessment/replay result and, when requested, one exclusive local certificate write; execution and output are not atomic together or crash durable.",
    retry="Retry repeats reads and mechanism execution; exclusive output refuses duplicates but checker side effects and prior emission are not rolled back.",
    timing="Inputs and mechanisms are observed during the command with no stable-file lock, universal checker timeout, or external freshness proof.",
    limits="Document bytes, admitted evidence references, selected policy, installed mechanism support, and domain/mainstay contracts bound evaluation.",
    observations="Exact selected inputs, mechanism returns, obligation/check outcomes, blockers, certified depth, and output-write result only.",
    units="Documents, evidence references, obligation/check rows, profile depth, bytes, digests, and status labels.",
    failure="Malformed selection, unsupported mechanism, missing evidence, checker exception, unavailable capacity, or write refusal remains rejected, FAIL, or UNKNOWN; partial effects are not erased.",
    recovery="Inspect any optional output and mechanism-visible state, correct the independent inputs or installation, and explicitly start a fresh run.",
    boundary="A selected certificate result does not by itself establish full object-profile conformance, application authority, checker confinement, publication, or release.",
)


_CLEARANCE_PREPARATION = _profile(
    name="The clearance publication-preparation transaction",
    scope="Replay selected clearance, dependency, and facet records against an exact artifact snapshot and optionally create one local publication-preparation payload in mandatory dry-run mode.",
    mechanism="Read bounded local records, independently select expected policies, replay clearance and facet completeness, recapture the artifact around assembly, and exclusively write canonical output.",
    participants="The caller, local artifact and policy records, installed clearance/facet checkers, payload builder, optional output writer, and later independent host reviewer.",
    inputs="One artifact, clearance, dependency policy, facet inventory/specification/policy, optional gate policy, dry-run selection, and optional output path.",
    authority="The caller selects every consumer policy input; this module reads no credential, performs no transport, and grants no authentication, moderation, rights, provenance, or production authority.",
    states="Selected, clearance replayed, facet coverage unknown/refuted/passed, artifact recaptured, payload prepared, exclusively written, rejected, or unavailable.",
    ordering="Mode checks and independent policies precede replay; first snapshot precedes facet assessment and payload assembly; second snapshot precedes optional output creation.",
    commands="Read and recheck selected local inputs, construct a base64-bearing dry-run payload, and optionally create one new local output file.",
    targets="The selected local artifact/records, in-memory preparation payload, standard output, and optional exclusive local output path.",
    effect_domains="LOCAL_DRY_RUN_PREPARATION_ONLY; transport, credential use, moderation, public publication, deployment, and payment are excluded.",
    effects="Prepare or exclusively write one local payload and diagnostic result; send nothing to any publication endpoint.",
    commit="Commit is only successful in-memory payload assembly and optional exclusive local file creation; inputs and output are not locked, grouped atomically, or crash durable.",
    retry="Exclusive output detects an existing file, but rerun repeats all reads and checks; no publication identity or remote duplicate semantics exist.",
    timing="Two artifact captures narrow but do not eliminate concurrent change; no filesystem lock, freshness witness, deadline, or remote event time is established.",
    limits="Artifact snapshot bounds, record byte caps, exact policy selection, facet denominator, dry-run-only mode, and mutually exclusive command modes constrain preparation.",
    observations="Selected exact bytes, clearance replay result, facet assessment, two artifact inventories, assembled payload digest, and local output outcome.",
    units="Files, exact bytes, facet rows, inventory entries, base64 content, and SHA-256 digests.",
    failure="Missing denominator remains UNKNOWN, invalid clearance/mode FAILS, unavailable I/O remains UNKNOWN, and a partial local write is not remote publication.",
    recovery="Inspect the optional output and current artifact, supply independent missing policies, and prepare again; publication requires a separate authenticated host action.",
    boundary="This is local publication preparation only: it sends nothing and proves no authentication, moderation, rights, provenance, production publication, locking, or multi-file atomicity.",
)


_DEMO_MATERIALIZER = _profile(
    name="The demonstration specimen materializer",
    scope="Construct deterministic educational PASS/FAIL/UNKNOWN scenarios in memory and optionally materialize their specimen JSON and report files to a selected local directory.",
    mechanism="Build fixed specimen graphs and claim bindings, run installed example checks, project bounded DemoResult rows, and write text files through local safe-write checks.",
    participants="The caller, fixed demonstration scenario builders, installed in-process checkers, optional local output directory, and learner consuming the report.",
    inputs="One supported scenario selection, fixed demonstration constants, installed checker code, and optional output directory.",
    authority="The demo source selects illustrative claims and artifacts only; successful discrimination confers no authority over a user repository, application, release, physical system, or money.",
    states="Scenario selected, specimen built, checker evaluated, expected result compared, report assembled, files materialized, rejected, or emitted.",
    ordering="Fixed specimen construction precedes checker invocation; actual and expected outcomes are compared before optional deterministic file materialization.",
    commands="Execute built-in demonstration checks and optionally create local specimen and report files under the selected directory.",
    targets="In-memory demonstration artifacts/results, standard output, and optional local demo-output files only.",
    effect_domains="EDUCATIONAL_IN_PROCESS_CHECK_AND_LOCAL_FILES; no general target, external service, physical endpoint, or financial endpoint is represented.",
    effects="Produce illustrative checker outcomes and optionally write demonstration JSON/text artifacts.",
    commit="Commit is one returned demo report and per-file local materialization; multiple files are not a locked, atomic, or crash-durable transaction.",
    retry="Retry reruns fixed examples and can encounter or repeat local file effects; no general duplicate or rollback protocol is established.",
    timing="Fixed scenarios have no claim of current external state, stable repository snapshot, or real-time validity.",
    limits="Supported scenario names, fixed finite graphs, installed mechanism behavior, and selected local path bound the demonstration.",
    observations="Constructed specimen fields, actual checker results, expected result labels, comparison success, and local write outcome only.",
    units="Scenarios, artifacts, graph nodes, result rows, local files, and exact serialized bytes.",
    failure="An unexpected checker result or unsafe/unwritable output is explicit; prior individual file writes are not rolled back.",
    recovery="Inspect generated demo files, correct only the demonstration mechanism or destination, and rerun; verify real artifacts through their own routes.",
    boundary="Demonstration behavior is regression and teaching evidence for fixed specimens, never general proof of package, application, safety, publication, or release correctness.",
)


_OBLIGATION_UNION = _profile(
    name="The core-obligation candidate-union policy",
    scope="Validate and adapt exact finite candidate contributions against an independently selected family/member authority without promoting structural coverage to semantic completeness or release admission.",
    mechanism="Strictly validate bounded candidate schemas, exact source/dependency/digest bindings, expected family/member sets, conservative statuses, and specialized private candidate projections.",
    participants="The host selector, candidate authority record, finite contribution producers, structural union validator, and consumer of its report.",
    inputs="Independent expected authority/source coordinates, bounded authority and contribution objects or private candidate bytes, and exact dependency/mechanism digests.",
    authority="The host must select the family/member denominator and expected digests externally; candidate authors and structural matching cannot authenticate completeness or release authority.",
    states="Authority absent/mismatched/matched, contribution invalid/covered, dependency unknown, structural report produced, semantic completeness UNKNOWN, and release inadmissible.",
    ordering="External pins and authority structure are checked before candidate membership; every family/member/dependency row is validated before aggregate coverage fields are computed.",
    commands="Decode and inspect supplied in-memory candidate bytes and produce conservative candidate/union projections; execute no submitted code and write nothing.",
    targets="Supplied candidate records, independently selected finite denominator, in-memory report, and returned adapted structures.",
    effect_domains="PURE_STRUCTURAL_POLICY_EVALUATION; no filesystem mutation, network transport, mechanism execution, publication, or release occurs.",
    effects="Accept or refute structural bindings and return a report that keeps semantic completeness UNKNOWN and release_admissible false.",
    commit="Commit is only return of a deterministic structural report for the selected finite inputs; no candidate is adopted or released.",
    retry="Equal exact inputs produce an equal projection; a different host denominator or candidate byte set is a new evaluation, not a correction history.",
    timing="No live source acquisition or freshness check occurs; time-sensitive authority and source selection remain external.",
    limits="Finite schemas, text/record sizes, exact digests, candidate-only markers, known status vocabularies, and selected member sets bound evaluation.",
    observations="Submitted fields, exact digest equalities, set conservation, dependency bindings, structural issues, and bounded counts only.",
    units="Candidate families, members, requirements, evidence bindings, exact bytes, and SHA-256 digests.",
    failure="Malformed, substituted, unexpected, duplicated, or overclaiming rows produce issues or rejection; missing authority remains UNKNOWN rather than complete.",
    recovery="Supply a corrected current candidate and an independently authorized exact denominator, then rerun; semantic adoption requires a separate mechanism.",
    boundary="Structural union equality to a selected candidate denominator never establishes semantic completeness, source authority, human acceptance, inventory authority, release permission, or polished admission.",
)


_SECURITY9_ACCOUNTING = _profile(
    name="The Security-9 structural-accounting policy",
    scope="Check one host-pinned finite Security-9 selection against exact application requirement instances, families, threat models, roots, checkers, falsifiers, children, and interactions.",
    mechanism="Strict-decode selected records, bind source and mechanism digests, conserve all selected Tier-9 instance identities, and validate exact structural relationships and conservative census states.",
    participants="The host selector, application-requirements record, Security-9 selection, installed accounting mechanism, and assessment consumer.",
    inputs="Exact selection and requirements bytes, expected digests, consumer source coordinate, installed mechanism digest, and cancellation flag.",
    authority="The host pins inputs and installed source; selected rows do not authenticate exhaustive applicability, semantic completeness, public checkability, human acceptance, safety, or release authority.",
    states="Cancelled/unavailable, structurally rejected, structurally accounted, applicability/dependency/interaction unknown, or conservative UNKNOWN assessment returned.",
    ordering="Host pins and mechanism identity precede decode; requirement denominator precedes selected family/instance conservation; children/interactions precede aggregate blockers.",
    commands="Read installed specification/mechanism bytes and evaluate supplied records in process; execute no submitted checker and write nothing.",
    targets="The selected finite Security-9 structural records and returned in-memory assessment only.",
    effect_domains="PURE_STRUCTURAL_SECURITY_POLICY_CHECK; no target system, security control, publication, or release state is changed.",
    effects="Return PASS fields for bounded structural accounting where proven while retaining semantic and authority blockers as UNKNOWN and release false.",
    commit="Commit is only the deterministic assessment over exact pinned inputs; no security requirement is thereby implemented, accepted, or released.",
    retry="Equal current inputs and installed mechanism give equal accounting; a changed selection or requirement denominator is a new assessment.",
    timing="No live deployment observation or freshness acquisition occurs; selected record times, if any, do not prove current operational security.",
    limits="Record bytes, row counts, exact schema fields, Tier-9 identities, source/mechanism digests, and finite child/interaction sets bound evaluation.",
    observations="Supplied identities, declared threat-model/root/checker/falsifier bindings, census markers, structural conservation, and blockers only.",
    units="Families, instances, child requirements, interaction requirements, exact bytes, and SHA-256 digests.",
    failure="Substitution, malformed fields, conservation mismatch, or overclaim FAILS; cancellation and resource exhaustion remain UNKNOWN.",
    recovery="Correct the independently selected exact records or restore installed source and rerun; separately establish applicability, semantics, public checkability, acceptance, and release.",
    boundary="Finite Security-9 structural accounting does not authenticate exhaustive applicability, semantic completeness, operational safety, public checkability, human acceptance, or release authority.",
)


_APPLICATION_AUTHORITY = _profile(
    name="The configured-key application-authority protocol",
    scope="Replay one exact configured-key scope-admission or semantic-completeness receipt and bind a host-selected core application denominator without conflating signatures with human or legal authority.",
    mechanism="Strict-decode bounded policy/receipt records, pin installed source and revision digests, verify domain-separated Ed25519 envelopes under configured keys, enforce quorum/revocation/time rules, and compose conservative binding status.",
    participants="The trusted host selector, configured public keys and actor identifiers, requester, approval signers, status signer, exact receipt/policy records, installed verifier, and result consumer.",
    inputs="Host-authenticated profile/union/compiler/application selections plus exact policy and receipt bytes, independent digests, operation/revision/subject pins, evaluation time, and minimum status sequence.",
    authority="Configured keys authenticate only the exact current statements they sign; signatures and actor labels do not establish personhood, legal authority, denominator truth, human acceptance, polish, or release permission.",
    states="Selected, policy current/expired, signatures valid/invalid, approval current/revoked, quorum met/unmet, execution/evidence current/stale, replay reproduced/rejected/not established, and application binding UNKNOWN/FAIL.",
    ordering="Host pins and installed mechanism identity precede decoding; receipt body binds approvals; every approval and status envelope is authenticated before quorum/revocation/currentness determines replay state.",
    commands="Verify configured-key signatures and exact host-selected application bindings in process; send nothing, execute no candidate, and write nothing.",
    targets="Selected in-memory policy/receipt/application records, configured public-key verifier, and returned replay/assessment structures.",
    effect_domains="CRYPTOGRAPHIC_STATEMENT_REPLAY_ONLY; no human, legal, publication, release, physical, financial, or deployment effect is authorized.",
    effects="Authenticate or refute exact configured-key statements and return conservative scope/semantic binding statuses and blockers.",
    commit="Commit is only return of the replay or binding report; an authenticated statement is not application adoption, acceptance, polish, release, or an external action.",
    retry="Replay requires the same exact policy/receipt/revision/subject pins and evaluation inputs; status sequence, revocation, expiry, or installed source changes require fresh selection.",
    timing="Host-supplied evaluation time is checked against explicit policy, receipt, approval, and status windows plus minimum sequence and maximum status age.",
    limits="Record bytes, key/approval counts, exact Ed25519 backend version, supported operations, fixed schemas, digest pins, and finite application member sets bound replay.",
    observations="Exact configured-key signatures, declared actor/key identifiers, revisions, subject, quorum, revocation list, time windows, application bindings, and blockers only.",
    units="Configured keys, approvals, actor labels, status sequences, Unix-time integers, records, application members, and SHA-256 digests.",
    failure="Forgery, substitution, denial, revocation, stale or inconsistent binding FAILS; missing, cancelled, carried, incomplete, or unavailable evidence remains UNKNOWN.",
    recovery="Obtain a fresh independently selected policy/status/receipt and corrected exact application denominator, then replay under current installed source; acquire human/legal acceptance separately.",
    boundary="A cryptographically valid configured-key application statement is not proof of personhood, legal authority, denominator truth, human acceptance, polish, publication, or release permission.",
)


_RELEASE_SOURCE_BINDING = _profile(
    name="The release-source byte-binding policy",
    scope="Compare one externally selected subject, five-artifact release tuple, full selected source inventory, public/applicability inventories, console aliases, and harness records to supplied exact bytes.",
    mechanism="Strict-decode a finite selection, enforce portable NFC path uniqueness, hash bounded supplied bytes, parse only a literal project.scripts grammar, and report exact commitment equality.",
    participants="The independent selector, finite selection record, supplied file-byte map, installed source-binding checker, and report consumer.",
    inputs="One exact selection record, supplied bytes for every selected source/release/inventory/harness path, installed mechanism source, and optional cancellation flag.",
    authority="The selector and commitments are external inputs; equality to them does not establish selector authority, inventory completeness, loaded execution, human acceptance, release permission, or application-profile adoption.",
    states="Selected, paths normalized/unique, files matched/missing/mismatched, aliases assessed/unassessed, cancelled/exhausted, binding PASS/FAIL/UNKNOWN, and report returned.",
    ordering="Selection schema and path references precede byte lookup; all role/source/inventory/harness commitments are checked before aggregate binding status and bounded report size.",
    commands="Inspect supplied in-memory bytes and installed mechanism bytes, compute exact digests, and return a report; execute no package input and write nothing.",
    targets="The finite supplied byte map, selected commitment inventory, and returned in-memory source-binding report.",
    effect_domains="PURE_RELEASE_BYTE_COMPARISON; no build, import, install, execution, publication, deployment, or release action occurs.",
    effects="Return exact equality/missingness findings for selected commitments while keeping full-application and release claims unestablished.",
    commit="Commit is only a deterministic binding report for supplied bytes; it does not adopt an inventory, application profile, or release.",
    retry="Equal exact selection and file bytes give equal findings; changed source, inventory, harness, or external commitments form a new assessment.",
    timing="No current filesystem acquisition, loaded-runtime observation, or release freshness witness occurs; supplied bytes define the entire observation.",
    limits="Selection/file/report bytes, file/node/depth counts, fixed five release roles, exact digests, canonical relative paths, and supported scripts grammar are bounded.",
    observations="Supplied exact bytes, selected path/digest references, literal console aliases, harness records, and equality/missingness findings only.",
    units="Files, source/public/applicability rows, harness executions, exact bytes, paths, and SHA-256 digests.",
    failure="Missing input remains UNKNOWN, mismatch FAILS, unsupported script grammar or exhausted capacity remains explicit, and no absent inventory member can be inferred.",
    recovery="Supply a fresh independently authorized complete selection and exact bytes, then rerun; execute and admit the selected application through separate routes.",
    boundary="Equality to selected commitments proves no source/public inventory completeness, selector authority, native replay, loaded execution, human acceptance, polished admission, publication, or release permission.",
)


# Object-specific refutations for every DOES_NOT_APPLY cell.  Each sentence names the
# reviewed file and an observed fact of its executable code (no process, network,
# device, or file-write call; or the module's own stated role).  Identifier hits such
# as ledger, asset, or request are data names and are explained rather than accepted as
# the refuted role.  A refuted kind without a source-cited sentence fails at import.
_DNE_BASES: dict[str, dict[str, str]] = {
    "vstd-artifact-snapshot-transaction": {
        "LEDGER": "artifact_snapshot.py captures exact bytes in memory and writes only the caller-selected materialization; it keeps no authoritative history, balance, or sequence.",
        "ASSET": "artifact_snapshot.py captures bytes and an inventory and represents no quantity, right, custody, or issuance.",
        "MARKET": "artifact_snapshot.py captures local files and matches no orders, trades, or prices.",
        "CONTROLLER": "artifact_snapshot.py captures and writes bytes once per call and computes no feedback or command selection.",
        "PROTOCOL": "artifact_snapshot.py reads local files and writes selected local files; it exchanges no request or response with a participant.",
        "POLICY": "artifact_snapshot.py refuses symlinks, reparse points, and byte or count overruns as fixed structural guards; the caller selects only paths and no rule, precedence, or exception is configurable.",
        "ROBOT": "artifact_snapshot.py captures and writes local files and connects no agent, harness, or physical actuator.",
        "FINBOT": "artifact_snapshot.py captures and writes local files and connects no agent to a real financial endpoint.",
    },
    "vstd-accessibility-artifact-reader": {},
    "vstd-graph-topology-reader": {
        "LEDGER": "graph_topology_cli.py decodes one selected graph and writes nothing; it keeps no authoritative history or balance.",
        "TRANSACTION": "graph_topology_cli.py runs one read-only topology diagnostic with no commit, rollback, or coordinated effect.",
        "ASSET": "graph_topology_cli.py inspects graph nodes and edges and represents no quantity, right, custody, or issuance.",
        "MARKET": "graph_topology_cli.py inspects graph topology and matches no orders, trades, or prices.",
        "CONTROLLER": "graph_topology_cli.py reports Boolean and temporal consistency of a selected graph and computes no feedback or command selection.",
        "ACTUATOR": "graph_topology_cli.py writes no file and calls no process, network, device, or file-write API.",
        "PROTOCOL": "graph_topology_cli.py reads two selected local files and exchanges no request or response with a participant.",
        "ROBOT": "graph_topology_cli.py diagnoses a selected graph and connects no agent, harness, or physical actuator.",
        "FINBOT": "graph_topology_cli.py diagnoses a selected graph and connects no agent to a real financial endpoint.",
    },
    "vstd-current-object-reader": {
        "LEDGER": "current_object_cli.py reads three local inputs and emits one report; it writes no file and keeps no history or balance.",
        "TRANSACTION": "current_object_cli.py runs one read-only native replay with no commit, rollback, or coordinated effect.",
        "ASSET": "current_object_cli.py replays a certificate and represents no quantity, right, custody, or issuance.",
        "MARKET": "current_object_cli.py replays a certificate and matches no orders, trades, or prices.",
        "CONTROLLER": "current_object_cli.py replays a certificate and computes no feedback or command selection.",
        "ROBOT": "current_object_cli.py replays a certificate and connects no agent, harness, or physical actuator.",
        "FINBOT": "current_object_cli.py replays a certificate and connects no agent to a real financial endpoint.",
    },
    "vstd-experimental-workflow-reader": {
        "LEDGER": "experimental_workflow_cli.py validates selected local inputs and writes nothing; it keeps no history or balance.",
        "TRANSACTION": "experimental_workflow_cli.py performs a read-only projection with no commit or coordinated effect.",
        "ASSET": "experimental_workflow_cli.py validates a workflow manifest and represents no quantity, right, custody, or issuance.",
        "MARKET": "experimental_workflow_cli.py validates workflow records and matches no orders, trades, or prices.",
        "CONTROLLER": "experimental_workflow_cli.py projects normalized events and computes no feedback or command selection.",
        "ACTUATOR": "experimental_workflow_cli.py executes no workflow and calls no process, network, device, or file-write API.",
        "PROTOCOL": "experimental_workflow_cli.py reads a selected normalized snapshot and exchanges no request or response with a participant.",
        "ROBOT": "experimental_workflow_cli.py validates experimental records and connects no agent, harness, or physical actuator.",
        "FINBOT": "experimental_workflow_cli.py validates experimental records and connects no agent to a real financial endpoint.",
    },
    "vstd-security-artifact-reader": {
        "LEDGER": "security_cli.py performs bounded local replay and writes nothing; it keeps no authoritative history or balance.",
        "TRANSACTION": "security_cli.py runs one bounded local replay with no commit, rollback, or coordinated effect.",
        "ASSET": "security_cli.py replays security records and represents no quantity, right, custody, or issuance.",
        "MARKET": "security_cli.py replays security records and matches no orders, trades, or prices.",
        "CONTROLLER": "security_cli.py replays security records and computes no feedback or command selection.",
        "PROTOCOL": "security_cli.py reads selected local records and exchanges no request or response with a participant.",
        "ROBOT": "security_cli.py replays security records and connects no agent, harness, or physical actuator.",
        "FINBOT": "security_cli.py replays security records and connects no agent to a real financial endpoint.",
    },
    "vstd-certification-command": {
        "LEDGER": "certification_cli.py exclusively creates at most one certificate file per run and keeps no authoritative history or balance.",
        "ASSET": "certification_cli.py creates certificates and represents no quantity, right, custody, or issuance.",
        "MARKET": "certification_cli.py evaluates certification mechanisms and matches no orders, trades, or prices.",
        "CONTROLLER": "certification_cli.py evaluates certification mechanisms and computes no feedback or command selection.",
        "PROTOCOL": "certification_cli.py decodes its requests as local records in-process and exchanges no request or response across a process or network boundary.",
        "ROBOT": "certification_cli.py runs built-in certification mechanisms in-process and connects no agent, harness, or physical actuator.",
        "FINBOT": "certification_cli.py runs built-in certification mechanisms in-process and connects no agent to a real financial endpoint.",
    },
    "vstd-clearance-publication-preparation": {
        "LEDGER": "clearance_publish.py writes at most one exclusive payload and keeps no authoritative history or balance.",
        "ASSET": "clearance_publish.py builds a verification record that grants no right and holds no quantity, custody, issuance, or redemption field; publication stays NOT_ESTABLISHED.",
        "MARKET": "clearance_publish.py prepares a dry-run payload and matches no orders, trades, or prices.",
        "CONTROLLER": "clearance_publish.py replays clearance and facet records and computes no feedback or command selection.",
        "PROTOCOL": "clearance_publish.py sets transport_performed to False and opens no network or process channel.",
        "ROBOT": "clearance_publish.py prepares local publication payloads and connects no agent, harness, or physical actuator.",
        "FINBOT": "clearance_publish.py prepares local publication payloads and connects no agent to a real financial endpoint.",
    },
    "vstd-demo-specimen-materializer": {
        "LEDGER": "demo.py materializes illustrative specimen files and keeps no authoritative history or balance.",
        "ASSET": "demo.py builds illustrative specimens and represents no quantity, right, custody, or issuance.",
        "MARKET": "demo.py builds illustrative specimens and matches no orders, trades, or prices.",
        "CONTROLLER": "demo.py runs fixed scenarios and computes no feedback or command selection.",
        "PROTOCOL": "demo.py runs its fixed scenarios in one process and exchanges no request or response with a participant.",
        "ROBOT": "demo.py runs fixed in-process demonstrations and connects no agent, harness, or physical actuator.",
        "FINBOT": "demo.py runs fixed in-process demonstrations and connects no agent to a real financial endpoint.",
    },
    "vstd-core-obligation-union-policy": {
        "LEDGER": "core_obligation_union.py's adapt_release_evidence_ledger reads a supplied source-registration ledger with zero runtime credit and writes nothing.",
        "ASSET": "core_obligation_union.py's _issue helper appends structural issue records to a list; the module represents no quantity, right, custody, or issuance.",
        "MARKET": "core_obligation_union.py validates candidate unions and matches no orders, trades, or prices.",
        "MEASUREMENT": "core_obligation_union.py checks structural digests of supplied bytes and observes no phenomenon with uncertainty.",
        "SENSOR": "core_obligation_union.py reads only supplied bytes and acquires no device, file, or network reading.",
        "CONTROLLER": "core_obligation_union.py validates candidate unions and computes no feedback or command selection.",
        "ACTUATOR": "core_obligation_union.py executes no submitted code and calls no process, network, device, or file-write API.",
        "PROTOCOL": "core_obligation_union.py decodes supplied candidate bytes in one call and exchanges no request or response with a participant.",
        "ROBOT": "core_obligation_union.py's adapt_harness_candidate projects harness candidates as data and connects no agent or physical actuator.",
        "FINBOT": "core_obligation_union.py projects candidate families as data and connects no agent to a real financial endpoint.",
    },
    "vstd-security9-accounting-policy": {
        "LEDGER": "core_security9_accounting.py conserves selected identities in one in-process assessment and keeps no history or balance.",
        "ASSET": "core_security9_accounting.py counts selected Tier-9 identities and represents no quantity, right, custody, or issuance.",
        "MARKET": "core_security9_accounting.py checks structural accounting and matches no orders, trades, or prices.",
        "MEASUREMENT": "core_security9_accounting.py checks structural records and observes no phenomenon with uncertainty.",
        "SENSOR": "core_security9_accounting.py reads supplied records and installed specification bytes to pin digests, and acquires no device or network reading.",
        "CONTROLLER": "core_security9_accounting.py checks structural accounting and computes no feedback or command selection.",
        "ACTUATOR": "core_security9_accounting.py executes no submitted checker and calls no process, network, device, or file-write API.",
        "PROTOCOL": "core_security9_accounting.py evaluates supplied records in process and exchanges no request or response with a participant.",
        "ROBOT": "core_security9_accounting.py checks Security-9 accounting and connects no agent, harness, or physical actuator.",
        "FINBOT": "core_security9_accounting.py checks Security-9 accounting and connects no agent to a real financial endpoint.",
    },
    "vstd-application-authority-protocol": {
        "LEDGER": "core_application_authority.py replays one supplied receipt and writes nothing; its status sequence is a supplied minimum, not retained history.",
        "ASSET": "core_application_authority.py authenticates configured-key statements and represents no quantity, right, custody, or issuance.",
        "MEASUREMENT": "core_application_authority.py verifies signatures and checks host-supplied times and observes no physical phenomenon.",
        "MARKET": "core_application_authority.py verifies receipts and matches no orders, trades, or prices.",
        "SENSOR": "core_application_authority.py reads only installed module and specification bytes to pin digests and acquires no device, network, or phenomenon reading.",
        "CONTROLLER": "core_application_authority.py verifies statements and computes no feedback or command selection.",
        "ACTUATOR": "core_application_authority.py sends nothing and writes nothing; its only asyncio use is CancelledError, and it calls no process, network, device, or file-write API.",
        "ROBOT": "core_application_authority.py authenticates application statements and connects no agent, harness, or physical actuator.",
        "FINBOT": "core_application_authority.py authenticates application statements and connects no agent to a real financial endpoint.",
    },
    "vstd-release-source-binding": {
        "LEDGER": "release_source_binding.py compares supplied bytes to commitments and writes nothing; it keeps no history or balance.",
        "ASSET": "release_source_binding.py compares digests of supplied bytes and represents no quantity, right, custody, or issuance.",
        "MARKET": "release_source_binding.py compares supplied bytes and matches no orders, trades, or prices.",
        "MEASUREMENT": "release_source_binding.py's result is exact equality of digests, not an observation of a phenomenon with uncertainty.",
        "SENSOR": "release_source_binding.py reads only its own module bytes to pin a mechanism digest; the caller supplies every compared byte, so it acquires no device or network reading.",
        "CONTROLLER": "release_source_binding.py compares commitments and computes no feedback or command selection.",
        "ACTUATOR": "release_source_binding.py executes no package input and calls no process, network, device, or file-write API.",
        "PROTOCOL": "release_source_binding.py exchanges no request or response with a participant; the caller supplies the complete selection and bytes.",
        "ROBOT": "release_source_binding.py compares release commitments and connects no agent, harness, or physical actuator.",
        "FINBOT": "release_source_binding.py compares release commitments and connects no agent to a real financial endpoint.",
    },
}


_REVIEWS = {
    "vstd-artifact-snapshot-transaction": _review(
        "TRANSACTION",
        "src/verifier/runtime/artifact_snapshot.py",
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR"),
        _ARTIFACT_SNAPSHOT,
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
            "POLICY",
        ),
    ),
    "vstd-accessibility-artifact-reader": _review(
        "VERIFIER",
        "src/verifier/runtime/accessibility_cli.py",
        (
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
        ),
        _ACCESSIBILITY_READER,
    ),
    "vstd-graph-topology-reader": _review(
        "VERIFIER",
        "src/verifier/runtime/graph_topology_cli.py",
        ("MEASUREMENT", "SENSOR", "POLICY"),
        _GRAPH_READER,
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-current-object-reader": _review(
        "VERIFIER",
        "src/verifier/runtime/current_object_cli.py",
        ("MEASUREMENT", "SENSOR", "POLICY", "ACTUATOR"),
        _CURRENT_OBJECT_READER,
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-experimental-workflow-reader": _review(
        "VERIFIER",
        "src/verifier/runtime/experimental_workflow_cli.py",
        ("MEASUREMENT", "SENSOR", "POLICY"),
        _EXPERIMENTAL_READER,
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-security-artifact-reader": _review(
        "VERIFIER",
        "src/verifier/runtime/security_cli.py",
        ("MEASUREMENT", "SENSOR", "POLICY", "ACTUATOR"),
        _SECURITY_READER,
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-certification-command": _review(
        "VERIFIER",
        "src/verifier/runtime/certification_cli.py",
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "POLICY"),
        _CERTIFICATION_COMMAND,
        refuted=("LEDGER", "ASSET", "MARKET", "CONTROLLER", "PROTOCOL", "ROBOT", "FINBOT"),
    ),
    "vstd-clearance-publication-preparation": _review(
        "TRANSACTION",
        "src/verifier/runtime/clearance_publish.py",
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "POLICY"),
        _CLEARANCE_PREPARATION,
        refuted=("LEDGER", "ASSET", "MARKET", "CONTROLLER", "PROTOCOL", "ROBOT", "FINBOT"),
    ),
    "vstd-demo-specimen-materializer": _review(
        "VERIFIER",
        "src/verifier/runtime/demo.py",
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "POLICY"),
        _DEMO_MATERIALIZER,
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-core-obligation-union-policy": _review(
        "VERIFIER",
        "src/verifier/runtime/core_obligation_union.py",
        ("POLICY",),
        _OBLIGATION_UNION,
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-security9-accounting-policy": _review(
        "VERIFIER",
        "src/verifier/runtime/core_security9_accounting.py",
        ("POLICY",),
        _SECURITY9_ACCOUNTING,
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-application-authority-protocol": _review(
        "PROTOCOL",
        "src/verifier/runtime/core_application_authority.py",
        ("PROTOCOL", "POLICY"),
        _APPLICATION_AUTHORITY,
        refuted=(
            "LEDGER",
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
    "vstd-release-source-binding": _review(
        "VERIFIER",
        "src/verifier/runtime/release_source_binding.py",
        ("POLICY",),
        _RELEASE_SOURCE_BINDING,
        refuted=(
            "LEDGER",
            "MEASUREMENT",
            "SENSOR",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
}

# Unsealed caller hooks keep these consequence obligations live without making
# the reader itself a physical or financial agent.
OBLIGATION_RETENTION_APPLIES: dict[str, tuple[str, ...]] = {
    "vstd-accessibility-artifact-reader": ("FINBOT", "ROBOT"),
}


def obligation_retention_reason(object_id: str, kind: str) -> str:
    """Return one exact command-review demand-only reason."""

    if kind not in OBLIGATION_RETENTION_APPLIES.get(object_id, ()):
        raise ValueError("COMMAND_REVIEW_OBLIGATION_RETENTION_UNDECLARED")
    return _decision_reason(object_id, _REVIEWS[object_id], kind)


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


_SOURCE_REFERENCE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_\-]*\.(?:py|mjs)\b")


def _catalog_check() -> None:
    if tuple(_REVIEWS) != COMMAND_OBJECT_IDS:
        raise AssertionError("command review order differs from public object order")
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
                "command ownership overlaps: " + ", ".join(sorted(overlap))
            )
        owned_paths.update(review.owned_paths)
        if len(review.applicable) != len(set(review.applicable)):
            raise AssertionError(object_id + " repeats an applicable kind")
        if not set(review.applicable) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " has an unsupported review kind")
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if len(review.refuted) != len(set(review.refuted)):
            raise AssertionError(object_id + " repeats a refuted kind")
        if not set(review.refuted) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " has an unsupported refuted kind")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " has contradictory role bases")
        if any(
            not paths or not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence leaves owned source")
        bases = _DNE_BASES.get(object_id, {})
        if set(bases) != set(review.refuted):
            raise AssertionError(object_id + " refutation basis differs")
        basenames = {Path(path).name for path in review.owned_paths}
        for text in bases.values():
            # The sentence's subject is its own owned file; any other source it names is a
            # foreign referent that would let one object's refutation describe another.
            if not any(text.startswith(name) for name in basenames):
                raise AssertionError(object_id + " refutation does not cite its source")
            if not set(_SOURCE_REFERENCE.findall(text)) <= basenames:
                raise AssertionError(object_id + " refutation cites an unowned source")
        reasons = {
            kind: _decision_reason(object_id, review, kind) for kind in REVIEW_KINDS
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


def review_document() -> dict[str, Any]:
    """Return a defensive deterministic review of all thirteen exact owners."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: _classification_document(object_id, review, kind)
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


def apply_package_semantic_review_commands(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply all thirteen current-source reviews atomically to a deep copy."""
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

        classification = row.get("classification")
        obligations = row.get("obligations")
        specializations = row.get("specializations")
        if type(classification) is not dict or type(obligations) is not dict:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + object_id)
        # An extra classification key such as OBJECT is an unreviewed label, not a
        # kind decision, so it cannot ride along as a preserved answer.  The
        # original-kind questions are the one legitimate extra: their own catalogs
        # own them, and this review neither reads nor rewrites them.
        keys = set(classification)
        if not set(REVIEW_KINDS) <= keys <= set(REVIEW_KINDS) | set(
            ORIGINAL_NON_OBJECT_KINDS
        ):
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + object_id)
        if (
            type(specializations) is not list
            or any(
                type(kind) is not str or kind not in REVIEW_KINDS
                for kind in specializations
            )
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
        # Every retained obligation must be a registered contract row; a name with
        # an unregistered prefix such as OBJECT- is not exempt from this check.
        for name in obligations:
            if type(name) is not str or name not in known_obligations:
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
            basis = _basis(review, kind)
            decision = classification.get(kind)
            if basis == "UNRESOLVED":
                code = (
                    "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:"
                    + object_id
                    + ":"
                    + kind
                )
                is_unresolved = _shared._unresolved_decision(
                    decision, files, owned, kind=kind, code=code
                )
                if not is_unresolved:
                    raise ValueError(code)
                if decision is not None and decision["evidence"]:
                    unresolved_candidates[kind] = [
                        deepcopy(evidence_by_path[item["path"]])
                        for item in decision["evidence"]
                    ]
            elif _shared._preserve_explicit_decision(
                decision,
                _explicit_decision(object_id, review, kind, evidence_by_path),
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
                        _obligation_reason(review, kind),
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

    # Re-read every exact owner only after every semantic conflict has passed.
    # Concurrent source drift therefore cannot produce a partly current review.
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
                    "reason": _shared._unresolved_reason(kind),
                    "evidence": deepcopy(
                        plan["unresolved_candidates"].get(kind, [])
                    ),
                }
            else:
                row["classification"][kind] = _explicit_decision(
                    object_id, review, kind, plan["evidence_by_path"]
                )
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
    "COMMAND_OBJECT_IDS",
    "OBLIGATION_RETENTION_APPLIES",
    "REVIEW_KINDS",
    "apply_package_semantic_review_commands",
    "obligation_retention_reason",
    "review_document",
]
