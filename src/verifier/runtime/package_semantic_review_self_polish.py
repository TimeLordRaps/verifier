"""Current-source Tier-0 reviews for fourteen self-polish owners.

Terminology: abstract syntax tree (AST); command-line interface (CLI); directed
acyclic graph (DAG); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); Verifier Standard (VSTD).

The reviews in this module classify exact source-owned mechanisms, registries,
and reason ledgers.  Every added namespace kind receives an explicit necessary
or refuted decision and every applicable obligation receives a live declaration
whose evidence is restricted to the owning source paths.

This is repository-admission metadata, not execution evidence.  In particular,
case registries do not replay their specimens, prepared extensions remain
uninstalled, and no result here establishes a whole tier, an application,
release, deployment, host or physical truth, or ROBOT/FINBOT authority.
Application is pure, atomic, source-current, and fail closed.

A DOES_NOT_APPLY refutation is established only from the owned bytes read once
for the digest, and only while the channel census is clean and the flow is
closed.  Disclaimer text, labels, and absent evidence never decide it.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.package_semantic_review_polish import (
    _CALLBACK_KEYWORDS,
    _INVOKING_NAMES,
    _KNOWN_MODULES,
    _SAFE_BUILTINS,
    REFUTABLE_CHANNELS,
    _scan,
    refutation_reason,
)
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


REVIEW_KINDS = _shared.REVIEW_KINDS

SELF_POLISH_OBJECT_IDS = (
    "vstd-self-polish-dynamics-controller",
    "vstd-self-polish-estate-authority",
    "vstd-self-polish-estate-evidence",
    "vstd-self-polish-estate-native-sensor",
    "vstd-self-polish-facet-reason-ledger",
    "vstd-self-polish-native-adapters",
    "vstd-self-polish-native-case-registry",
    "vstd-self-polish-native-extension-registry",
    "vstd-self-polish-native-replay-controller",
    "vstd-self-polish-statics-controller",
    "vstd-self-polish-tier-controller",
    "vstd-tier-zero-orchestrator",
    "vstd-tier-zero-profile-policy",
    "vstd-tier-zero-reason-ledger",
)

CLAIM_BOUNDARY = (
    "Current-source Tier-0 applicability and declaration review for fourteen "
    "exact self-polish owners only. Mechanism execution, declaration truth, "
    "whole-tier or application conformance, external authority, host or "
    "physical truth, release, deployment, ROBOT, FINBOT, and Tier-1-plus "
    "fulfillment remain separately unestablished."
)


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    profile: _shared._Profile
    refuted: tuple[str, ...]
    anchors: Mapping[str, str]
    blocked: tuple[str, ...]


def _unresolved_reason(kind: str) -> str:
    return (
        "Migration retains this applicability question. Static ownership "
        "alone cannot refute a " + kind + " role."
    )


def _basis(review: _Review, kind: str) -> str:
    if kind in review.applicable:
        return "APPLIES"
    if kind in review.refuted:
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
    action: str,
    observations: str,
    limits: str,
    failure: str,
    boundary: str,
) -> _shared._Profile:
    """Expand concise audited facts into every live Tier-0 declaration field."""
    return _shared._Profile(
        name=name,
        scope=scope,
        mechanism=mechanism,
        participants=participants,
        inputs=inputs,
        authority=authority,
        states=states,
        ordering=ordering,
        commands=action,
        targets=scope,
        effect_domains=(
            "LOCAL_VERIFIER_ASSESSMENT_ONLY; no physical, financial, publication, "
            "release, or deployment endpoint is represented. " + boundary
        ),
        effects=action,
        commit=(
            "Commit is only return of the named bounded in-process record after "
            "its declared checks. It is not an atomic external commit, tier PASS, "
            "application qualification, release, or deployment."
        ),
        retry=(
            "Each call is a new evaluation of its selected inputs and current "
            "source. No retained result, duplicate identity, rollback, or general "
            "idempotency is inferred."
        ),
        timing=(
            "Observations occur during one ordered call; no stable global snapshot, "
            "external event time, real-time deadline, or eventual progress is proved."
        ),
        limits=limits,
        observations=observations,
        units=(
            "Exact bytes, SHA-256 digests, finite route/candidate/obligation counts, "
            "ordered records, and explicit PASS, FAIL, UNKNOWN, or lifecycle labels."
        ),
        failure=failure,
        recovery=(
            "Retain the failure or UNKNOWN boundary, correct the exact input or "
            "source condition, and explicitly start a fresh evaluation; never "
            "upgrade an earlier or partial result."
        ),
        boundary=boundary,
    )


_DYNAMICS = _profile(
    name="The source-native Dynamics controller",
    scope="Fresh cumulative replay of the installed Tier-1 and Tier-2 native route triads at one selected source coordinate.",
    mechanism="Build and replay fixed installed native manifests, aggregate direct and cumulative status, and bind necessity reasons to current receipts.",
    participants="The caller, Dynamics progression, installed native replay registry and mechanisms, selected source root, and returned assessment consumer.",
    inputs="A selected source root, source-coordinate digest, subject identity, prior-report digest, and cancellation flag.",
    authority="The caller selects the local coordinate and attempt; the installed registry selects routes. Neither grants arbitrary-application, release, physical, or financial authority.",
    states="Unattempted, attempted, executed, cancelled, PASS, FAIL, UNKNOWN, cumulative-depth, and reason-bound states.",
    ordering="Facets replay precedes Dynamics replay; cumulative failure or uncertainty cannot be erased by later aggregation; reasons bind the Dynamics receipt afterward.",
    action="Invoke selected installed replay mechanisms for both tiers and return their exact receipts, cumulative status, blockers, and reason records.",
    observations="Current mechanism digests, registry membership, replay receipts, native outcomes, blockers, selected depth, and cumulative status.",
    limits="Only the fixed installed Tier-1 and Tier-2 route union, bounded native specimens, exact digests, and explicit failure/uncertainty rules are admitted.",
    failure="Malformed selection or native contradiction fails; unavailable execution remains UNKNOWN unless failure was already observed; partial PASS is never promoted.",
    boundary="The fixed progression is not an application certificate DAG, historical resource attestation, whole-tier proof, host truth, or external effect authority.",
)

_ESTATE_AUTHORITY = _profile(
    name="The self-polish estate authority protocol",
    scope="Configured-key authority replay for one exact source-bound estate selection.",
    mechanism="Construct and validate a digest-complete subject, delegate to the configured-key application-scope authority checker, and preserve its bounded status.",
    participants="The caller, estate-authority adapter, configured-key authority mechanism, configured signers/quorum, and result consumer.",
    inputs="Exact source, census, estate, applicability, inventory, objective, crosswalk, and structural/route/shared identity digests plus the selected authority receipt.",
    authority="Only a qualifying configured-key receipt can establish authority over the exact estate selection; it cannot grant semantic, polish, release, or deployment authority.",
    states="Subject constructed, structurally rejected, authority PASS, authority FAIL, authority UNKNOWN, and exact replay-bound result.",
    ordering="All subject digests and operation identity are validated before configured-key replay; definite authority nonfulfillment remains explicit.",
    action="Replay the configured-key authority statement and return its bounded status without executing estate evidence or changing repository state.",
    observations="Validated subject fields, mechanism identity, configured-key receipt status, quorum/execution/currentness conditions, and result digest.",
    limits="One exact operation and digest-complete estate subject are accepted; caller applicability labels and broader authority are excluded.",
    failure="Malformed or mismatched subjects fail closed; missing current authority, quorum, execution, or evidence remains FAIL or UNKNOWN under the delegated contract.",
    boundary="Estate-selection authority is not semantic applicability, per-candidate evidence, repository closure, Tier-1 status, polish, release, or deployment authority.",
)

_ESTATE_EVIDENCE = _profile(
    name="The self-polish estate evidence verifier",
    scope="Exact estate-manifest validation and configured-key replay for authority and every selected candidate evidence statement.",
    mechanism="Re-observe current source bindings, validate complete canonical manifests and ledgers, crosswalk authority, and replay each selected configured-key evidence subject.",
    participants="The caller, selected source, estate and ledger validators, configured-key authority and candidate-evidence mechanisms, and result consumer.",
    inputs="One validated estate, exact applicability-ledger bytes, bounded evidence-manifest bytes, expected digests, and selected authority/evidence receipts.",
    authority="Configured keys can authenticate only their exact selected statements; labels, candidate truth, complete-estate closure, and application authority are not inferred.",
    states="Template UNKNOWN, validated, source-current, candidate PASS, candidate FAIL, candidate UNKNOWN, incomplete, rejected, and aggregate result states.",
    ordering="Estate and ledger validation precede manifest validation; estate authority is crosswalked before each exact candidate receipt is replayed and aggregated.",
    action="Read and validate selected bytes, invoke configured-key replay mechanisms, and return per-candidate and aggregate evidence records without mutating source.",
    observations="Current source digests, estate identities, manifest coverage, authority bindings, per-candidate receipt states, omissions, and aggregate blockers.",
    limits="Manifest and justification bytes, exact candidate denominator, schemas, digests, configured operations, and canonical field sets are bounded.",
    failure="Malformed, stale, missing, duplicate, contradictory, unauthorized, or incomplete evidence fails or remains UNKNOWN; caller PASS labels never substitute for replay.",
    boundary="The replay closes only the enumerated estate evidence at one coordinate, not broader repository completeness, whole Tier 1, external truth, release, or deployment.",
)

_ESTATE_NATIVE_SENSOR = _profile(
    name="The selected-root native estate sensor",
    scope="Direct current-source correspondence checks for each selected estate candidate under the installed native category rules.",
    mechanism="Resolve ordinary in-root source, package, module, function, registry, command, and schema targets; recapture the selected source once and derive status without a caller PASS field.",
    participants="The caller, selected repository root, estate candidate records, installed native category verifiers, and replay result consumer.",
    inputs="One validated estate, bounded native evidence artifact, exact expected digests, and a freshly prepared selected-root replay context.",
    authority="The selected source bytes and installed category rules authorize only observation; they provide no external signer, package owner, release, or deployment authority.",
    states="Context prepared, artifact validated, source matched, source differed, category unsupported, PASS, FAIL, and UNKNOWN.",
    ordering="The complete source context is captured before individual artifacts are validated and checked against their category-specific current-source target.",
    action="Read exact selected-root targets and derive one bounded native evidence outcome without writing source or invoking an external endpoint.",
    observations="Ordinary-file identity, source/package/module/function/registry/CLI/schema correspondence, exact digests, category status, missingness, and error codes.",
    limits="Only installed candidate categories, in-root ordinary paths, finite artifact bytes, exact schemas, and a single prepared context are accepted.",
    failure="Path escape, aliasing, malformed artifact, source mismatch, unsupported category, missing target, or context drift fails or remains UNKNOWN under explicit rules.",
    boundary="Current source correspondence is not external authority, complete package coverage, semantic correctness beyond the registered check, tier PASS, release, or deployment.",
)

_FACET_REASON_LEDGER = _profile(
    name="The installed Facet reason ledger",
    scope="The source-bound Tier-1 facet and domain-route reason denominator plus its replay assessment.",
    mechanism="Derive installed source bindings and denominators, construct necessary/not-necessary/unknown reason rows, and replay the exact ledger against current bytes.",
    participants="The installed registry and source providers, reason-ledger builder, assessment replayer, selected source files, and result consumer.",
    inputs="Current installed mechanism bytes, facet/domain route registries, source-coordinate bindings, role contracts, and exact ledger records.",
    authority="Installed definitions select the current reason denominator; they do not establish normative completeness, owner adoption, application authority, or route truth.",
    states="Reason inferred, necessary, not necessary, unknown, source-bound, stale, PASS coverage, FAIL conflict, and UNKNOWN support states.",
    ordering="Denominators and source bindings are fixed before reasons are derived; replay compares the complete ledger to current sources before reporting coverage.",
    action="Construct or replay the complete reason ledger and return exact source-bound coverage and assessment records without changing the installed registry.",
    observations="Facet and route membership, role contracts, source digests, choice rows, reason text, support projection, assessment status, and blockers.",
    limits="The installed Tier-1 facet and domain-route denominator, fixed choices, exact schemas, current bindings, and complete row coverage are required.",
    failure="Missing, blank, stale, malformed, contradictory, unsupported, or denominator-different reasons fail closed or retain UNKNOWN support.",
    boundary="Reason coverage does not establish route outcomes, normative completeness, whole-tier or application polish, release, or deployment readiness.",
)

_NATIVE_ADAPTERS = _profile(
    name="The native specimen adapter set",
    scope="Named, non-generic input transformations and selected native builder invocation for installed replay specimens.",
    mechanism="Strictly decode supported input shapes, construct bounded negative or unavailable variants, resolve one named adapter, and call the selected trusted builder.",
    participants="The replay controller, named adapter, trusted in-process native builder callback, exact specimen input, and returned certificate consumer.",
    inputs="A registered adapter name, bounded exact specimen bytes or values, a selected builder callable, and route-specific construction parameters.",
    authority="The installed adapter registry and trusted caller select the callback; no sandbox, external endpoint, owner, physical, financial, release, or deployment authority is supplied.",
    states="Adapter selected, input decoded, variant constructed, builder invoked, certificate returned, malformed, unsupported, or exceptional.",
    ordering="Adapter and input validation precede transformation; exactly one selected builder invocation follows; returned bytes remain subject to replay validation.",
    action="Transform one exact specimen and invoke one trusted in-process native builder, which can have undeclared host-process effects.",
    observations="Selected adapter identity, decoded fields, transformed evidence, builder return or exception, and canonical certificate bytes.",
    limits="Only explicitly named adapters, bounded payloads, registered shapes, and one selected in-process builder are admitted.",
    failure="Unknown adapter, malformed or oversized input, invalid transformation, callback exception, or malformed returned certificate is rejected; callback effects cannot be rolled back.",
    boundary="Trusted in-process invocation is not confinement, and produced specimen bytes prove no route, tier, package, release, deployment, physical, or financial property by themselves.",
)

_NATIVE_CASE_REGISTRY = _profile(
    name="The installed native case registry",
    scope="Source-owned positive, negative, and unavailable specimen inputs, adapter selections, and expected outcomes for installed native routes.",
    mechanism="Boundedly decode embedded canonical case payloads, check fixed entry counts and registry digests, and return immutable input records; no builder or rechecker is invoked.",
    participants="The installed generated registry modules, bounded payload decoder, replay controller that may later consume the records, and registry consumer.",
    inputs="Embedded compressed or encoded case payloads, fixed registry metadata, exact entry counts, route identities, adapter names, and expected triad outcomes.",
    authority="The installed source defines case-admission policy only; registration cannot authorize replay, qualify a route, or promote a tier.",
    states="Embedded, decoded, registry-bound, returned as policy data, malformed, oversized, count-different, or digest-different.",
    ordering="Capacity and encoding checks precede decode; exact registry identity and duplicate checks precede return of the case mapping.",
    action="Decode and return source-owned case data only; no builder or rechecker is invoked and no specimen replay occurs.",
    observations="Encoded/compressed/decompressed sizes, entry identity and count, registry digest, adapter selection, input payload, and expected outcome labels.",
    limits="Fixed per-module entry counts and digests, bounded encoded/compressed/decompressed bytes, unique keys, and explicit triad labels are required.",
    failure="Malformed encoding, decompression overflow, duplicate entries, count mismatch, digest mismatch, or invalid case shape is rejected before data is returned.",
    boundary="Decoding and registration perform no replay and establish no route, tier, package, release, deployment, host, physical, or financial conformance.",
)

_NATIVE_EXTENSIONS = _profile(
    name="The prepared native extension registry",
    scope="Current generated-module observation and prepared Tier-3-through-Tier-9 extension membership and input policy.",
    mechanism="Import generated source-owned case modules, bind their current bytes and route memberships, validate input payload limits, and describe prepared registry rows; these checks install nothing.",
    participants="The caller, prepared extension registry, generated case modules, installed route inventory, source-byte reader, and registry consumer.",
    inputs="Current generated module bytes, fixed tier membership, exact route identities, prepared case inputs, and bounded evidence payloads.",
    authority="The registry may describe only prepared inputs; it cannot install them, qualify their mechanisms, or grant tier, package, release, or deployment authority.",
    states="Generated source observed, membership matched, prepared, malformed, source-different, route-different, uninstalled, and unqualified.",
    ordering="Installed route membership and generated source bindings are checked before prepared inputs and the registry description are returned.",
    action="Read and validate current generated case-module records and return prepared metadata; execute no native replay and install nothing.",
    observations="Generated source digests, tier/route membership, input cardinality, bounded payload sizes, registry digest, and preparation status.",
    limits="Only fixed Tier-3-through-Tier-9 generated modules, exact installed memberships, bounded evidence bytes, and complete triads are admitted.",
    failure="Missing module, stale source binding, membership mismatch, malformed payload, incomplete triad, or capacity violation is rejected and remains uninstalled.",
    boundary="Prepared extensions remain uninstalled and unqualified; their registry establishes no installed route, tier, package, release, deployment, host, or physical result.",
)

_NATIVE_REPLAY = _profile(
    name="The installed and prepared native replay controller",
    scope="Source-bound resolution, builder/rechecker execution, triad observation, registry closure, and installed/prepared candidate aggregation.",
    mechanism="Resolve package-owned callables to exact selected bytes, build bounded certificates, replay expected positive/negative/unknown outcomes, and compose installed with prepared results without erasing installation state.",
    participants="The caller, selected source root, installed and prepared registries, trusted builder and checker callables, replay controller, and result consumer.",
    inputs="Exact source coordinate, tier selection, canonical manifests, route memberships, case inputs, expected outcomes, mechanism paths/symbols, and byte caps.",
    authority="Installed source selects installed routes and the caller selects execution; prepared records remain uninstalled and neither path grants application, release, physical, or financial authority.",
    states="Selected, source-bound, builder invoked, checker invoked, PASS, FAIL, UNKNOWN, installed, prepared-uninstalled, cumulative candidate, rejected, and unavailable.",
    ordering="Registry and source closure precede manifest construction; each positive, negative, and unknown case is built then rechecked; aggregation preserves failures, uncertainty, and installation boundaries.",
    action="Invoke trusted in-process native builders and recheckers, observe returned certificates, and compose exact installed/prepared replay receipts.",
    observations="Current source and mechanism digests, case membership, callback return/exception, native outcome, expected-outcome match, invalidators, closure, and aggregate status.",
    limits="Exact registry memberships, selected-root layouts, finite manifest/certificate bytes, fixed triads, source bindings, and explicit status joins constrain the replay; prepared extensions remain uninstalled.",
    failure="Malformed or stale source, missing mechanism, callback exception, wrong outcome, capacity violation, incomplete triad, or closure mismatch fails or remains UNKNOWN; callback effects are not rolled back.",
    boundary="Specimen discrimination is not whole-tier, package, application, release, deployment, host, physical, or financial qualification; prepared extensions remain uninstalled.",
)

_STATICS = _profile(
    name="The source-native Statics controller",
    scope="Fresh prerequisite execution, installed/repository byte comparison, complete Tier-3 native triads, and final source recapture.",
    mechanism="Run admission, Facets and Dynamics prerequisites, derive installed Statics registry closure, replay all Tier-3 native cases, compare package source bytes, and recapture the coordinate.",
    participants="The caller, selected repository, prerequisite assessors, native replay mechanisms, installed distribution, source recapture, and report consumer.",
    inputs="Selected source root, current source coordinate, installed registry and package bytes, prerequisite results, Tier-3 case inputs, and cancellation state.",
    authority="The caller authorizes a local attempt; installed source defines the route set. Byte equality and replay do not provide host attestation, application, release, or deployment authority.",
    states="Prerequisite attempted, native replay attempted/executed, source equal/different, cancelled, PASS, FAIL, UNKNOWN, and recapture-consistent/inconsistent.",
    ordering="Admission, Facets, and Dynamics precede Statics; package binding and complete Tier-3 triads precede final source recapture and cumulative result.",
    action="Invoke prerequisite and Tier-3 mechanisms, read installed and repository bytes, and return a cumulative report with exact receipts and blockers.",
    observations="Prerequisite statuses, route registry, selected and installed source digests, native triad outcomes, package-byte equality, recaptured coordinate, and blockers.",
    limits="Only the installed Tier-3 registry, exact package modules, finite reports and native artifacts, selected source coordinate, and fail-closed status join are admitted.",
    failure="Unavailable prerequisite or observation remains UNKNOWN; contradictions, wrong native outcomes, source mismatch, or changed recapture fail and cannot leave a partial PASS.",
    boundary="Source equality and specimen replay are not host attestation, physical truth, full package or application polish, release authority, or deployment evidence.",
)

_TIER_CONTROLLER = _profile(
    name="The numeric self-polish tier controller",
    scope="Numeric-tier orchestration over repository estate, evidence, native replay, authority conditions, dependency progression, and source recapture.",
    mechanism="Validate exact selected inputs, derive or replay bounded estate and native evidence, enforce tier dependencies and authority conditions, then recapture source before final status.",
    participants="The caller, selected repository and manifests, estate/evidence/authority adapters, installed native tier mechanisms, dependency assessors, and report consumer.",
    inputs="Tier selection, source root and coordinate, bounded evidence and authority artifacts with expected digests, retained prior reports, and optional dependency bundles.",
    authority="Only explicitly replayed authority applies to its selected operation; numeric orchestration cannot manufacture owner, application, release, deployment, physical, or financial authority.",
    states="Selected tier, prerequisite retained/replayed, candidate census, evidence replayed, dependency blocked, PASS, FAIL, UNKNOWN, source-changed, and unpolished.",
    ordering="Tier-specific prerequisites and denominators are validated before evidence replay; dependencies and authority are joined conservatively; post-replay source recapture precedes final status.",
    action="Invoke the selected bounded assessment and replay mechanisms, read current source and artifacts, and produce one exact tier report without publishing or deploying anything.",
    observations="Source/estate/manifest digests, prerequisite and native outcomes, authority condition, dependency state, denominator identities, blockers, and post-replay recapture.",
    limits="Finite input/report bytes, exact schemas and digests, installed route denominators, numeric tier rules, dependency relations, and conservative status joins apply.",
    failure="Malformed or stale input, unmet dependency, refuted evidence, authority mismatch, source drift, or mechanism contradiction fails; unavailable support stays UNKNOWN and cannot be waived.",
    boundary="A bounded numeric-tier result is not automatic whole-tier, full-application, release, deployment, host, physical, or financial authority.",
)

_TIER_ZERO = _profile(
    name="The Tier-Zero repository-admission orchestrator",
    scope="Current repository/manifest estate acquisition and independent Python/Node reconciliation for the installed Tier-Zero profile.",
    mechanism="Dispatch the retained or current admission version, read selected files, evaluate profile closures, launch bounded Node reconciliation, compare canonical receipts, and return conservative outcomes.",
    participants="The caller, selected repository and objects manifest, Python admission mechanisms, Node reconciler child process, installed profile/reason providers, and report consumer.",
    inputs="Selected source root, manifest and attachments, installed Tier-Zero profile, estate and reason artifacts, expected digests, interpreter selection, and version request.",
    authority="The caller authorizes local reads and a bounded Node child process; neither interpreter grants Tier-1-plus, application, owner, release, deployment, physical, or financial authority.",
    states="Version selected, source captured, manifest admitted/rejected, Node unavailable/executed, receipts agree/disagree, PASS, FAIL, UNKNOWN, and source-changed.",
    ordering="Version dispatch and source/manifest validation precede closure checks; Python and Node results are independently produced and reconciled before final admission status.",
    action="Read selected repository bytes, invoke bounded local admission mechanisms and Node reconciliation, and return one repository-admission report without modifying the repository.",
    observations="Current file digests, estate/manifest closure, obligation and reason denominators, Python and Node receipts, process exit/output, reconciliation equality, and blockers.",
    limits="Installed profile/schema versions, bounded files and process output, exact digests, complete denominators, in-root paths, and conservative status rules apply.",
    failure="Unavailable runtime or evidence remains UNKNOWN; malformed input, closure mismatch, interpreter disagreement, stale bytes, or source drift fails and cannot be promoted.",
    boundary="Tier Zero establishes repository admission only; subprocess reconciliation is not sandboxing, a controller feedback claim, Tier-1-plus conformance, release, or deployment.",
)

_TIER_ZERO_PROFILE = _profile(
    name="The installed Tier-Zero profile policy",
    scope="The immutable versioned repository-admission obligation denominator, reasons, closure dimensions, and finalization rule.",
    mechanism="Construct the fixed nine-obligation profile, validate internal field and coordinate uniqueness, and bind it with module and specification digests.",
    participants="The installed profile module, VSTD Tier-Zero specification, admission orchestrator that consumes the profile, and profile consumer.",
    inputs="Fixed obligation definitions, reasons, evidence requirements, satisfiers, unknown conditions, falsifiers, boundaries, closure dimensions, and installed counts.",
    authority="The installed VSTD profile selects this versioned admission policy only; its declaration does not decide a repository instance or grant higher authority.",
    states="Defined, internally validated, digest-bound, version-current, version-different, malformed, or consumed by an admission assessment.",
    ordering="All obligation rows and unique coordinates are validated before the profile and its mechanism/specification digest bindings are returned.",
    action="Return deterministic policy data and digests only; execute no repository check, subprocess, native replay, write, publication, release, or deployment.",
    observations="Fixed profile fields, obligation and closure counts, coordinate uniqueness, installed counts, profile digest, and specification/module digests.",
    limits="Exactly the installed profile version, nine obligations, declared closure dimensions, canonical JSON digest rules, and fixed count fields are represented.",
    failure="Internal missing/extra fields, duplicate coordinates, or changed source/specification bytes changes or rejects the profile identity rather than silently widening it.",
    boundary="The policy declaration alone establishes no repository result, mechanism truth, whole package polish, Tier-1-plus conformance, release, or deployment.",
)

_TIER_ZERO_REASONS = _profile(
    name="The source-derived Tier-Zero reason ledger",
    scope="Authoritative current route and kind-tier slot reason identities with repository-realization annotations for the installed denominator.",
    mechanism="Enumerate installed routes and 234 kind-tier slots, derive standard reasons and current mechanism bindings, preserve residuals and falsifiers, and issue a source-bound provider receipt.",
    participants="The installed VSTD inventory and route registry, selected source root, mechanism-binding resolver, reason-ledger provider, and receipt consumer.",
    inputs="The 408 installed routes, 234 installed slots, governing questions and rationales, current mechanism source bytes, semantic identities, and selected source root.",
    authority="The installed registry is authoritative only for the current denominator and reason identity; it does not establish normative closure, owner adoption, application, release, or deployment authority.",
    states="Route reason derived, slot reason derived, direct or conditional realization, semantic UNKNOWN, source-bound, denominator-complete, denominator-different, and receipt-issued.",
    ordering="Installed inventory and route/slot identities are enumerated before current mechanism bindings and annotations; exact 408/234 closure precedes the provider receipt.",
    action="Read current mechanism bytes and return a deterministic reason ledger and receipt; execute no route certificate and change no repository state.",
    observations="Route and slot identity, rationale, checking-mechanism path and digest, semantic digest, evidence requirements, preserved/unpreserved semantics, residuals, falsifiers, and counts.",
    limits="Exactly 408 installed routes and 234 installed slots, current in-root mechanism bindings, complete annotation fields, and source-derived identities are required.",
    failure="Missing or changed inventory, absent mechanism binding, incomplete annotation, count mismatch, or source unavailability prevents a complete provider receipt and never proves fulfillment.",
    boundary="Annotation binding proves neither an annotation's semantic claim nor any route, slot, repository, tier, application, release, or deployment fulfillment.",
)


_CASE_PATHS = (
    "src/verifier/runtime/self_polish_native_cases.py",
    "src/verifier/runtime/self_polish_native_sim_case_patch.py",
    "src/verifier/runtime/self_polish_native_tier3_cases.py",
    "src/verifier/runtime/self_polish_native_tier4_cases.py",
    "src/verifier/runtime/self_polish_native_tier5_cases.py",
    "src/verifier/runtime/self_polish_native_tier6_cases.py",
    "src/verifier/runtime/self_polish_native_tier7_cases.py",
    "src/verifier/runtime/self_polish_native_tier8_cases.py",
    "src/verifier/runtime/self_polish_native_tier9_cases.py",
)

_REPLAY_PATHS = (
    "src/verifier/runtime/self_polish_native_extension_replay.py",
    "src/verifier/runtime/self_polish_native_full_candidate.py",
    "src/verifier/runtime/self_polish_native_replay.py",
)


def _review(
    primary_kind: str,
    paths: tuple[str, ...],
    applicable: tuple[str, ...],
    profile: _shared._Profile,
    *,
    refuted: tuple[str, ...],
    anchors: Mapping[str, str] | None = None,
    blocked: tuple[str, ...] = (),
) -> _Review:
    return _Review(
        primary_kind=primary_kind,
        owned_paths=paths,
        applicable=applicable,
        role_paths={kind: paths for kind in applicable},
        profile=profile,
        refuted=refuted,
        anchors=dict(anchors or {}),
        blocked=blocked,
    )


_REVIEWS = {
    "vstd-self-polish-dynamics-controller": _review(
        "VERIFIER",
        ("src/verifier/runtime/self_polish_dynamics.py",),
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "POLICY", "CONTROLLER", "ACTUATOR", "PROTOCOL"),
        _DYNAMICS,
        refuted=(),
        anchors={
            "TRANSACTION": "self_polish_dynamics.py:170-174,205-225",
            "MEASUREMENT": "self_polish_dynamics.py:70-72,119-125,186-191",
            "POLICY": "self_polish_dynamics.py:70-72,90-93,171-174",
            "CONTROLLER": "self_polish_dynamics.py:176-196,213-225",
            "ACTUATOR": "self_polish_dynamics.py:75-85,180-188",
            "SENSOR": "self_polish_dynamics.py:75-85,176-225",
            "PROTOCOL": "self_polish_dynamics.py:75-85,176-225",
        },
    ),
    "vstd-self-polish-estate-authority": _review(
        "PROTOCOL",
        ("src/verifier/runtime/self_polish_estate_authority.py",),
        ("PROTOCOL", "POLICY"),
        _ESTATE_AUTHORITY,
        refuted=(),
        anchors={
            "PROTOCOL": "self_polish_estate_authority.py:117-128,131-170",
            "POLICY": "self_polish_estate_authority.py:117-128,155-183",
        },
    ),
    "vstd-self-polish-estate-evidence": _review(
        "VERIFIER",
        ("src/verifier/runtime/self_polish_estate_evidence.py",),
        ("MEASUREMENT", "SENSOR", "PROTOCOL", "POLICY"),
        _ESTATE_EVIDENCE,
        refuted=(),
        anchors={
            "MEASUREMENT": "self_polish_estate_evidence.py:686-781,1025-1055",
            "PROTOCOL": "self_polish_estate_evidence.py:504-624,627-672,897-1022",
            "POLICY": "self_polish_estate_evidence.py:700-760,1059-1127",
            "SENSOR": "self_polish_estate_evidence.py:897-915",
        },
    ),
    "vstd-self-polish-estate-native-sensor": _review(
        "SENSOR",
        ("src/verifier/runtime/self_polish_estate_native_evidence.py",),
        ("MEASUREMENT", "SENSOR", "POLICY"),
        _ESTATE_NATIVE_SENSOR,
        refuted=(),
        anchors={
            "MEASUREMENT": "self_polish_estate_native_evidence.py:327-345,406-458",
            "SENSOR": "self_polish_estate_native_evidence.py:367-398",
            "POLICY": "self_polish_estate_native_evidence.py:90-92,100-117,172-261,281-284",
        },
    ),
    "vstd-self-polish-facet-reason-ledger": _review(
        "LEDGER",
        ("src/verifier/runtime/self_polish_facet_reasons.py",),
        ("LEDGER", "MEASUREMENT", "SENSOR", "POLICY"),
        _FACET_REASON_LEDGER,
        refuted=(),
        anchors={
            "LEDGER": "self_polish_facet_reasons.py:922-941,1101-1135,1230-1269,1497-1553",
            "MEASUREMENT": "self_polish_facet_reasons.py:421-430,1437-1492",
            "POLICY": "self_polish_facet_reasons.py:1219-1269,1273-1337",
            "SENSOR": "self_polish_facet_reasons.py:421-430",
        },
    ),
    "vstd-self-polish-native-adapters": _review(
        "VERIFIER",
        ("src/verifier/runtime/self_polish_native_adapters.py",),
        ("ACTUATOR", "POLICY"),
        _NATIVE_ADAPTERS,
        refuted=(),
        anchors={
            "ACTUATOR": "self_polish_native_adapters.py:476-513",
            "POLICY": "self_polish_native_adapters.py:442,473,486-513",
        },
    ),
    "vstd-self-polish-native-case-registry": _review(
        "DATA",
        _CASE_PATHS,
        ("POLICY",),
        _NATIVE_CASE_REGISTRY,
        refuted=(),
        anchors={
            "POLICY": "self_polish_native_cases.py:2992-3042; self_polish_native_tier3_cases.py:1877-1913",
        },
    ),
    "vstd-self-polish-native-extension-registry": _review(
        "DATA",
        ("src/verifier/runtime/self_polish_native_extensions.py",),
        ("MEASUREMENT", "SENSOR", "POLICY"),
        _NATIVE_EXTENSIONS,
        refuted=(),
        anchors={
            "MEASUREMENT": "self_polish_native_extensions.py:60-94,158-211",
            "POLICY": "self_polish_native_extensions.py:97-155",
            "SENSOR": "self_polish_native_extensions.py:158-211",
        },
    ),
    "vstd-self-polish-native-replay-controller": _review(
        "VERIFIER",
        _REPLAY_PATHS,
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL", "POLICY"),
        _NATIVE_REPLAY,
        refuted=(),
        anchors={
            "TRANSACTION": "self_polish_native_replay.py:547-779; self_polish_native_full_candidate.py:130-137",
            "MEASUREMENT": "self_polish_native_replay.py:653-721",
            "SENSOR": "self_polish_native_replay.py:393-395,636-652,691-708,761-768",
            "ACTUATOR": "self_polish_native_replay.py:499-511,655-660; self_polish_native_extension_replay.py:197-210",
            "PROTOCOL": "self_polish_native_replay.py:447-538,580-591,722-723",
            "POLICY": "self_polish_native_replay.py:389-395,683-687,728-730",
        },
    ),
    "vstd-self-polish-statics-controller": _review(
        "VERIFIER",
        ("src/verifier/runtime/self_polish_statics.py",),
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY"),
        _STATICS,
        refuted=(),
        anchors={
            "TRANSACTION": "self_polish_statics.py:282-284,352-354,369-371,533-545",
            "MEASUREMENT": "self_polish_statics.py:303-324,349-351",
            "SENSOR": "self_polish_statics.py:253-266,374-378",
            "CONTROLLER": "self_polish_statics.py:413-464,487-490,504-509",
            "ACTUATOR": "self_polish_statics.py:310-324",
            "PROTOCOL": "self_polish_statics.py:416-424,465-474",
            "POLICY": "self_polish_statics.py:209-215,222-227,319-320,465-474",
        },
    ),
    "vstd-self-polish-tier-controller": _review(
        "VERIFIER",
        ("src/verifier/runtime/self_polish_tiers.py",),
        ("MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "POLICY", "PROTOCOL"),
        _TIER_CONTROLLER,
        refuted=(),
        anchors={
            "MEASUREMENT": "self_polish_tiers.py:2327-2392",
            "SENSOR": "self_polish_tiers.py:2327-2365",
            "CONTROLLER": "self_polish_tiers.py:3245-3277,3581-3633,3953-3960",
            "ACTUATOR": "self_polish_tiers.py:1113-1130,3888-3926",
            "POLICY": "self_polish_tiers.py:3150-3188,2883-2922,3872-3878,3961-3978",
            "PROTOCOL": "self_polish_tiers.py:1123-1147,1579-1601,2883-2889,2933-2944",
        },
    ),
    "vstd-tier-zero-orchestrator": _review(
        "VERIFIER",
        ("src/verifier/runtime/tier_zero.py",),
        ("MEASUREMENT", "SENSOR", "ACTUATOR", "POLICY", "PROTOCOL"),
        _TIER_ZERO,
        refuted=(),
        anchors={
            "MEASUREMENT": "tier_zero.py:196-261,442-502",
            "SENSOR": "tier_zero.py:273-299,352-353",
            "ACTUATOR": "tier_zero.py:274-325",
            "POLICY": "tier_zero.py:113-161,64-91,443-445,505-518",
            "PROTOCOL": "tier_zero.py:301-325",
        },
    ),
    "vstd-tier-zero-profile-policy": _review(
        "POLICY",
        ("src/verifier/runtime/tier_zero_profile.py",),
        ("POLICY",),
        _TIER_ZERO_PROFILE,
        refuted=("LEDGER", "TRANSACTION", "ROBOT", "FINBOT"),
        anchors={
            "POLICY": "tier_zero_profile.py:51-98,232-237",
        },
    ),
    "vstd-tier-zero-reason-ledger": _review(
        "LEDGER",
        ("src/verifier/runtime/tier_zero_reasons.py",),
        ("LEDGER", "MEASUREMENT", "SENSOR", "POLICY"),
        _TIER_ZERO_REASONS,
        refuted=(),
        anchors={
            "LEDGER": "tier_zero_reasons.py:185-226",
            "MEASUREMENT": "tier_zero_reasons.py:207-226",
            "POLICY": "tier_zero_reasons.py:67-69,139-140,219",
            "SENSOR": "tier_zero_reasons.py:26-38,185-217",
        },
    ),
}


_DECLARATION_BUILDERS = dict(_shared._DECLARATION_BUILDERS)


def _reason(profile: _shared._Profile, kind: str, applies: bool) -> str:
    """State an explicit necessity or source-bounded refutation for every kind."""
    if not applies:
        return refutation_reason(profile, kind)
    necessity = {
        "LEDGER": "Its authoritative ordered reason denominator, identity, correction, replay, and recovery semantics cannot be reduced to generic data.",
        "TRANSACTION": "Its selected execution attempt has explicit preconditions, named effects, commit evidence, partial failure, finality, and retry boundaries.",
        "MEASUREMENT": "Its report must distinguish exact current software observations from unobserved source, mechanism, host, physical, or external state.",
        "SENSOR": "Its bounded digital acquisition path has explicit source, range, sampling, latency, missingness, fault, and recovery semantics.",
        "CONTROLLER": "It selects commands from prerequisite and replay feedback, joins cumulative state, and gates later progression under explicit failure behavior.",
        "ACTUATOR": "It commands an in-process mechanism or child reconciliation attempt while keeping downstream and external effects unestablished.",
        "PROTOCOL": "Its exact subjects, participants, ordered messages or calls, compatibility bindings, replay rules, and failure states form a bounded exchange.",
        "POLICY": "Its denominator, selection rules, authority boundary, precedence, defaults, exceptions, and enforcement points decide the bounded result.",
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


def _applies_reason(review: _Review, kind: str) -> str:
    reason = _reason(review.profile, kind, True)
    if kind in review.blocked:
        return (
            reason
            + " The source audit did not establish this kind; it is retained only "
            "because the registry fixes it as this owner's primary kind, so it "
            "remains an open blocker."
        )
    return reason + " Audited source anchor: " + review.anchors[kind] + "."


def _classification_reason(review: _Review, kind: str) -> str:
    basis = _basis(review, kind)
    if basis == "APPLIES":
        return _applies_reason(review, kind)
    if basis == "DOES_NOT_APPLY":
        return _reason(review.profile, kind, False)
    return _unresolved_reason(kind)


def _evidence_paths(review: _Review, kind: str) -> tuple[str, ...]:
    basis = _basis(review, kind)
    if basis == "APPLIES":
        return review.role_paths[kind]
    if basis == "DOES_NOT_APPLY":
        return review.owned_paths
    return ()


def _obligation_reason(review: _Review, kind: str) -> str:
    return (
        _applies_reason(review, kind)
        + " This Tier-0 declaration names the reviewed boundary only; "
        "mechanism execution and Tier-1-plus fulfillment remain unestablished."
    )


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
    if tuple(_REVIEWS) != SELF_POLISH_OBJECT_IDS:
        raise AssertionError(
            "self-polish review order differs from public object order"
        )
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
                "self-polish ownership overlaps: " + ", ".join(sorted(overlap))
            )
        owned_paths.update(review.owned_paths)
        if len(review.applicable) != len(set(review.applicable)):
            raise AssertionError(object_id + " repeats an applicable kind")
        if not set(review.applicable) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " has an unsupported review kind")
        if len(review.refuted) != len(set(review.refuted)):
            raise AssertionError(object_id + " repeats a refuted kind")
        if not set(review.refuted) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " refutes an unsupported review kind")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " applies and refutes one kind")
        if not set(review.refuted) <= set(REFUTABLE_CHANNELS):
            raise AssertionError(
                object_id + " refutes a kind without an audited channel census"
            )
        if set(review.applicable) | set(review.refuted) == set(REVIEW_KINDS):
            raise AssertionError(object_id + " refutation table is complement-shaped")
        if not set(review.blocked) <= set(review.applicable) or not set(
            review.blocked
        ) <= {review.primary_kind}:
            raise AssertionError(
                object_id + " blocks a kind other than its primary kind"
            )
        if set(review.anchors) != set(review.applicable) - set(review.blocked) or any(
            not anchor.strip() for anchor in review.anchors.values()
        ):
            raise AssertionError(object_id + " APPLIES lacks an exact source anchor")
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if any(
            not paths or not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence leaves owned source")
        reasons = {kind: _classification_reason(review, kind) for kind in REVIEW_KINDS}
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
    """Return a defensive deterministic review of all fourteen exact owners."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: {
                    "status": _basis(review, kind),
                    "reason": _classification_reason(review, kind),
                    "evidence_paths": list(_evidence_paths(review, kind)),
                }
                for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(_declarations(review)),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for object_id, review in _REVIEWS.items()
    }


def _read_exact(root: Path, path: str) -> bytes:
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
        return resolved.read_bytes()
    except OSError as exc:
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE:" + path) from exc


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _owned_bytes(root: Path, paths: tuple[str, ...]) -> dict[str, bytes]:
    """Read each owned source exactly once; digests and scans share these bytes."""
    return {path: _read_exact(root, path) for path in paths}


def _source_evidence(
    raw: Mapping[str, bytes], paths: tuple[str, ...]
) -> list[dict[str, str]]:
    return [{"path": path, "sha256": _digest(raw[path])} for path in paths]


def _current_evidence(
    raw: Mapping[str, bytes],
    paths: tuple[str, ...],
    files: Mapping[str, str],
    *,
    object_id: str,
) -> list[dict[str, str]]:
    evidence = _source_evidence(raw, paths)
    for reference in evidence:
        path = reference["path"]
        if files.get(path) != reference["sha256"]:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:" + object_id + ":" + path
            )
    return evidence


# Path-taking calls that can open a device or file.  Each must receive a literal
# string, because a constructed or variable path is not classified by the census.
_PATH_TAKERS = frozenset({
    "FileIO", "Path", "PurePath", "fdopen", "open", "read_bytes", "read_text",
})
def _bindings(tree: ast.AST) -> dict[str, list[str]]:
    """Return every binding kind of each name in one file, in walk order.

    A callee is trusted only through its one binding: an unbound builtin, local
    definitions alone, or a single import.  Any other binding, such as an
    assignment from a parameter, lets the same spelling call an argument.
    """
    bound: dict[str, list[str]] = {}

    def add(name: str | None, kind: str) -> None:
        if name:
            bound.setdefault(name, []).append(kind)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                add(alias.asname or root, "import:" + root)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            for alias in node.names:
                add(alias.asname or alias.name, "from:" + root)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(node.name, "def")
        elif isinstance(node, ast.arg):
            add(node.arg, "arg")
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            add(node.id, "store")
        elif isinstance(node, ast.ExceptHandler):
            add(node.name, "store")
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            add(node.name, "store")
        elif isinstance(node, ast.MatchMapping):
            add(node.rest, "store")
    return bound


class _ClosureGuard(ast.NodeVisitor):
    """Reject owned flows that a DOES_NOT_APPLY refutation cannot bound.

    The shared census classifies channels by name and literal text.  It does not
    bound a parameter that reaches a non-local call, such as a callable given as
    ``re.sub`` replacement or ``sort`` key, nor a path that is constructed before
    a read.  This guard adds exactly those two closure rules.  A parameter is
    data-only only at a callee the shared scanner knows does not invoke it, and
    a callee name rebound in the file is never trusted.  It only narrows the
    refutation and never establishes one.
    """

    def __init__(self, bindings: Mapping[str, list[str]]) -> None:
        self.bindings = bindings
        self.frames: list[frozenset[str]] = []
        self.bound: dict[str, str] = {}
        self.findings: set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.bound[alias.asname or alias.name] = alias.name

    def _function(self, node: ast.AST) -> None:
        args = node.args  # type: ignore[attr-defined]
        names = [
            arg.arg
            for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]
            if arg is not None
        ]
        self.frames.append(frozenset(names))
        self.generic_visit(node)
        self.frames.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function
    visit_Lambda = _function

    def _is_param(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and any(
            node.id in frame for frame in self.frames
        )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        local = False
        name = ""
        if isinstance(func, ast.Name):
            if self._is_param(func):
                self.findings.add("CALLBACK:" + func.id)
            name = self.bound.get(func.id, func.id)
            if self._is_param(func):
                self.findings.add("CALLBACK:" + func.id)
            elif self._local_def(func.id):
                local = True
            elif self._kinds(func.id) and not self._single_binding(func.id):
                # A rebinding can make this spelling call an argument.
                self.findings.add("REBOUND_CALLEE:" + func.id)
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if not local:
            known = self._known_callee(func, name)
            flows = [(value, "") for value in node.args] + [
                (keyword.value, keyword.arg or "**") for keyword in node.keywords
            ]
            for value, keyword in flows:
                param = self._param_within(value)
                if param and (
                    not known or keyword in _CALLBACK_KEYWORDS or keyword == "**"
                ):
                    self.findings.add("FLOW_ARGUMENT:" + param)
        if name in _PATH_TAKERS:
            self._path_call(node, func, name)
        self.generic_visit(node)

    def _kinds(self, name: str) -> list[str]:
        return self.bindings.get(name, [])

    def _single_binding(self, name: str) -> bool:
        """Whether a name's only binding is one import or one from-import."""
        kinds = self._kinds(name)
        return len(kinds) == 1 and kinds[0].startswith(("import:", "from:"))

    def _import_root(self, name: str) -> str | None:
        """Return the top-level module a name is solely bound to by an import."""
        kinds = self._kinds(name)
        if len(kinds) == 1 and kinds[0].startswith("import:"):
            return kinds[0].removeprefix("import:")
        return None

    def _local_def(self, name: str) -> bool:
        kinds = self._kinds(name)
        return bool(kinds) and all(kind == "def" for kind in kinds)

    def _known_callee(self, func: ast.expr, name: str) -> bool:
        """Whether the shared scanner knows the callee does not call an argument."""
        if name in _INVOKING_NAMES:
            return False
        if isinstance(func, ast.Attribute):
            root = func.value
            while isinstance(root, ast.Attribute):
                root = root.value
            module = self._import_root(root.id) if isinstance(root, ast.Name) else None
            return module is not None and module in _KNOWN_MODULES
        if not isinstance(func, ast.Name):
            return False
        kinds = self._kinds(func.id)
        if not kinds:
            return func.id in _SAFE_BUILTINS
        if len(kinds) == 1 and kinds[0].startswith("from:"):
            return kinds[0].removeprefix("from:") in _KNOWN_MODULES
        return False

    def _param_within(self, value: ast.expr) -> str | None:
        """Return a parameter name occurring anywhere inside one argument."""
        for node in ast.walk(value):
            if isinstance(node, ast.Name) and self._is_param(node):
                return node.id
        return None

    def _path_call(self, node: ast.Call, func: ast.AST, name: str) -> None:
        if isinstance(func, ast.Attribute):
            receiver = func.value
            if isinstance(receiver, ast.Call):
                # A constructor's own literal is checked at its own call site.
                return
            if not (
                isinstance(receiver, ast.Name)
                and self._import_root(receiver.id) is not None
            ):
                self.findings.add("DYNAMIC_PATH:" + name)
                return
        if not node.args:
            if node.keywords:
                self.findings.add("DYNAMIC_PATH:" + name)
            return
        target = node.args[0]
        if not (
            isinstance(target, ast.Constant) and isinstance(target.value, (str, bytes))
        ):
            self.findings.add("DYNAMIC_PATH:" + name)


def _closure_findings(raw: bytes, path: str) -> set[str]:
    """Return every flow reason the closure guard refuses in one owned source."""
    try:
        tree = ast.parse(raw, filename=path)
    except (SyntaxError, ValueError) as exc:
        raise ValueError(
            "PACKAGE_SEMANTIC_REVIEW_CHANNEL_UNVERIFIABLE:" + path
        ) from exc
    guard = _ClosureGuard(_bindings(tree))
    guard.visit(tree)
    return guard.findings


def _surface_reasons(scan: Any, raw: bytes, path: str) -> set[str]:
    """Every reason one owned source fails to be a closed refutation surface."""
    reasons = set(scan.findings)
    reasons |= {"CHANNEL:" + channel for channel in scan.channels}
    reasons |= _closure_findings(raw, path)
    return reasons


def _reject_aliases(rows: Mapping[str, Any]) -> None:
    """Fail closed when one mutable container is reachable twice or is cyclic.

    Shared lists or dicts let a write for one object land in another object's
    row, so the whole input is checked before any row is read for update.
    """
    seen: set[int] = set()
    for object_id, row in rows.items():
        pending: list[Any] = [row]
        while pending:
            value = pending.pop()
            if type(value) is dict:
                children: list[Any] = list(value.values())
            elif type(value) is list:
                children = value
            else:
                continue
            if id(value) in seen:
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_ALIAS_CONFLICT:" + str(object_id)
                )
            seen.add(id(value))
            pending.extend(children)


def apply_package_semantic_review_self_polish(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply all fourteen current-source reviews atomically to a deep copy."""
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

    _reject_aliases(rows)
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
        raw = _owned_bytes(selected_root, review.owned_paths)
        current = _current_evidence(raw, review.owned_paths, files, object_id=object_id)
        evidence_by_path = {item["path"]: item for item in current}
        if review.refuted:
            scans = {path: _scan(path, raw[path]) for path in review.owned_paths}
            present = {channel for scan in scans.values() for channel in scan.channels}
            for kind in review.refuted:
                if any(channel in present for channel in REFUTABLE_CHANNELS[kind]):
                    raise ValueError(
                        "PACKAGE_SEMANTIC_REVIEW_REFUTATION_CHANNEL_PRESENT:"
                        + object_id
                        + ":"
                        + kind
                    )
            if any(
                _surface_reasons(scans[path], raw[path], path)
                for path in review.owned_paths
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_REFUTATION_SURFACE_OPEN:" + object_id
                )

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
            if _basis(review, kind) != "APPLIES" and (
                row["kind"] == kind or kind in specializations
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id + ":" + kind
                )

        known_obligations = {
            name for values in live_obligations.values() for name in values
        }
        for name in obligations:
            if type(name) is not str or (
                name.split("-", 1)[0] in REVIEW_KINDS and name not in known_obligations
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
            basis = _basis(review, kind)
            decision = classification.get(kind)
            if basis == "UNRESOLVED":
                code = "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
                if decision is not None and not (
                    type(decision) is dict and decision.get("status") == "UNRESOLVED"
                ):
                    raise ValueError(code)
                if (
                    _shared._unresolved_decision(
                        decision, files, owned, kind=kind, code=code
                    )
                    and decision is not None
                    and decision["evidence"]
                ):
                    unresolved_candidates[kind] = [
                        deepcopy(evidence_by_path[item["path"]])
                        for item in decision["evidence"]
                    ]
            else:
                paths = review.role_paths[kind] if basis == "APPLIES" else review.owned_paths
                expected_decision = {
                    "status": basis,
                    "reason": _classification_reason(review, kind),
                    "evidence": [deepcopy(evidence_by_path[path]) for path in paths],
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
                        binding, fields, files, owned, code=code
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

    # Every semantic conflict is settled before this closing byte census.  A
    # concurrent edit therefore aborts the entire fourteen-owner operation.
    for object_id, review in _REVIEWS.items():
        closing = _source_evidence(
            _owned_bytes(selected_root, review.owned_paths), review.owned_paths
        )
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
            basis = _basis(review, kind)
            if basis == "UNRESOLVED":
                row["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": _unresolved_reason(kind),
                    "evidence": deepcopy(plan["unresolved_candidates"].get(kind, [])),
                }
            else:
                paths = review.role_paths[kind] if basis == "APPLIES" else review.owned_paths
                row["classification"][kind] = {
                    "status": basis,
                    "reason": _classification_reason(review, kind),
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
    "REVIEW_KINDS",
    "SELF_POLISH_OBJECT_IDS",
    "apply_package_semantic_review_self_polish",
    "review_document",
]
