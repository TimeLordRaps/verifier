"""Current-source Tier-0 reviews for eight VERIFIER support mechanisms.

Terminology: abstract syntax tree (AST); command-line interface (CLI);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).

Each review is bound to an exact path-owned object and answers all twelve
consequential namespace questions.  An applicable role receives the complete
registered Tier-0 declaration shape and exact current owned-source evidence.
Every other role is canonical UNRESOLVED.  No DOES_NOT_APPLY cell is currently
audited: a refutation needs an explicit, object-specific, source-audited basis that
binds owned source, and a deliberate change to the catalog guard.  Absence
of a direct import or write call is never that basis.  These declarations do not
prove mechanism behavior, whole-application coverage, polished status, authority,
release, or deployment.

Application is pure and atomic.  The complete eight-object denominator, current
source digests, existing decisions, declarations, and ownership are validated
before a copied row is changed.  Each existing decision must equal its explicit
basis exactly; conflicting, partial, stale, forged, unbacked, missing, unowned,
or invented-name state aborts the operation without mutating the caller.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.namespace_contracts import namespace_registry


REVIEW_KINDS = _shared.REVIEW_KINDS
VERIFIER_OBJECT_IDS = (
    "vstd-verifier-native-execution-controller",
    "vstd-verifier-run-constraint-controller",
    "vstd-repository-admission-reconciler",
    "vstd-native-gate-suite",
    "vstd-source-provenance-observer",
    "vstd-core-self-polish-assessor",
    "vstd-added-kind-behavioral-verifier",
    "vstd-asset-tier0-execution-verifier",
)
CLAIM_BOUNDARY = (
    "Exact-source Tier-0 applicability and declaration review for these eight "
    "bounded objects only. It does not establish mechanism truth, full-application "
    "coverage or polish, Tier-1-plus conformance, external authority, physical or "
    "financial safety, publication, release, or deployment."
)


_NATIVE_EXECUTION = _shared._Profile(
    name="native VERIFIER execution controller",
    scope=(
        "Admit one fixed source-bound proof worker, apply a Windows Job committed-"
        "memory ceiling before resume, observe bounded work and output, and terminate "
        "the owned job on completion, timeout, exhaustion, or error."
    ),
    mechanism=(
        "Canonical JSON is sent to a fixed isolated CPython child created suspended; "
        "the parent assigns and verifies a kill-on-close Windows Job, resumes the "
        "primary thread, polls owned membership/output/time, and validates the reply."
    ),
    participants=(
        "The trusted parent evaluator, fixed source-loaded CPython worker, Windows "
        "Job Object kernel interface, retained child handles, and returned proof reply."
    ),
    inputs=(
        "An admitted soundness artifact and claims, fixed worker loader, checker/source "
        "digest, canonical request bytes, and positive memory, wall-time, work, item, "
        "process-count, and output ceilings."
    ),
    authority=(
        "Only the installed evaluator selects the fixed worker and exact limits. Caller "
        "commands or code are never admitted, and this grants no arbitrary execution, "
        "soundness, physical, financial, publication, or release authority."
    ),
    states=(
        "Unsupported, suspended, assigned, limits-verified, resumed, observing, "
        "completed, timed-out, output-exhausted, terminated, cleaned, PASS, FAIL, and "
        "UNKNOWN states remain distinct."
    ),
    ordering=(
        "Request validation and complete work reservation precede child creation; job "
        "assignment and exact limit verification precede resume; completion observation "
        "precedes reply acceptance; termination and handle cleanup are mandatory."
    ),
    commands=(
        "Create the fixed suspended child, assign it to the owned Job, resume exactly "
        "once, query membership/accounting, terminate the exact Job, and close retained "
        "handles."
    ),
    targets=(
        "One fixed local CPython worker, its three explicitly inherited standard-stream "
        "handles, its temporary directory, and one owned Windows Job Object."
    ),
    effect_domains=(
        "LOCAL_FIXED_PROCESS_LIFECYCLE_ONLY; process creation, resume, observation, and "
        "termination are real host effects, but submitted commands, network endpoints, "
        "physical actuators, and financial endpoints are excluded."
    ),
    effects=(
        "Create and run one fixed native proof worker, read its bounded outputs and Job "
        "accounting, terminate every observed owned member, and return a typed replay "
        "result."
    ),
    commit=(
        "Commit is only a validated PASS reply whose request, checker, toolchain, proof "
        "digest, work use, pre-resume limits, and observed empty-job cleanup all match."
    ),
    retry=(
        "No automatic proof retry occurs. Membership disagreement receives at most four "
        "bounded observations; any later invocation is a new process execution with a "
        "new observation boundary."
    ),
    timing=(
        "Wall time begins immediately before resume and is polled against a finite "
        "deadline; watchdog scheduling and termination are not hard real-time guarantees."
    ),
    limits=(
        "Windows CPython only; request and output bytes, committed Job memory, wall "
        "seconds, conservative native work, structure items, retained processes, "
        "membership attempts, and cleanup time are finite and fail closed."
    ),
    observations=(
        "The parent observes applied Job limits, current membership and retained-handle "
        "signals, lifetime counts, output size, completion/timeout, exit code, exact "
        "reply bytes, and proof/work fields."
    ),
    units=(
        "Committed bytes, output bytes, wall seconds, dimensionless process and proof "
        "counts, charged work units, and SHA-256 identities."
    ),
    failure=(
        "Unsupported platforms or unavailable enforcement remain UNKNOWN; malformed or "
        "contradictory proof replies FAIL; timeout, output exhaustion, incomplete cleanup, "
        "or changed source never becomes PASS."
    ),
    recovery=(
        "The parent terminates the exact owned Job, waits for retained handles, closes "
        "all handles, discards the uncertain reply, and requires a separate fresh run "
        "after the unavailable condition is corrected."
    ),
    boundary=(
        "This is one fixed Windows Job-bounded proof replay, not a general sandbox, "
        "arbitrary verifier executor, hard-real-time monitor, lifetime process-identity "
        "census, whole-application proof, ROBOT, or FINBOT."
    ),
)


_RUN_CONSTRAINTS = _shared._Profile(
    name="VERIFIER run-constraint controller",
    scope=(
        "Validate one selected VERIFIER-3.1 subject and replay one exact registered child "
        "certificate twice in-process while counting CPython trace events and canonical "
        "report bytes against caller-declared maxima."
    ),
    mechanism=(
        "The checker binds exact request, policy, object, child request/policy/certificate "
        "digests and source digest; installs a local trace hook, invokes the registered "
        "route twice, restores tracing, compares reports, and issues or rechecks a receipt."
    ),
    participants=(
        "The trusted caller, current process, VERIFIER-3.1 checker, registered child route, "
        "selected evidence store, trace hook, and returned certificate consumer."
    ),
    inputs=(
        "One canonical VERIFIER record, exact child request, policy and certificate, "
        "external trust roots and evidence reference, sorted declared constraints, and "
        "finite evidence, item, operation, replay-event, and certificate ceilings."
    ),
    authority=(
        "The selected policy and registered route authorize this replay, including the "
        "Job-bounded child-process launches a selected route performs. Caller declarations "
        "are retained but never promoted to checker observations; no sandbox, physical, "
        "financial, governance, or release authority is created."
    ),
    states=(
        "Selected, tracing, exhausted, child-unavailable, child-refused, displaced, "
        "nonreproducible, PASS, FAIL, UNKNOWN, certificate-built, and replay-reproduced "
        "states remain explicit."
    ),
    ordering=(
        "Policy and all digest bindings are validated before replay; nesting is refused; "
        "two sequential traced replays must produce identical canonical reports; observed "
        "constraints are then compared before certificate construction."
    ),
    commands=(
        "Install the counting trace hook, invoke the exact registered child replay twice, "
        "restore the previous hook, compare reports, and construct or recheck the bounded "
        "certificate."
    ),
    targets=(
        "The current Python process, thread-local recursion guard, current trace hook, "
        "one registered child route, one selected certificate, and in-memory evidence and "
        "certificate values."
    ),
    effect_domains=(
        "TRUSTED_REPLAY_WITH_ROUTE_CHILD_PROCESSES; the parent replays in process, and a "
        "selected child route may create Job-bounded CPython worker processes (observed for "
        "MODEL-3.2). Selected child code executes with host-process authority inside the "
        "parent or those workers; no sandbox, physical-resource enforcement, or general "
        "subprocess isolation is established."
    ),
    effects=(
        "Execute the selected child twice, temporarily replace the current trace hook, "
        "retain checker-produced event/report observations, and return canonical "
        "certificate bytes; a registered MODEL-3.2 child route creates Job-owned CPython "
        "worker processes during those replays."
    ),
    commit=(
        "Commit is a bounded certificate status for the exact run digest after both "
        "reports reproduce and every supported declared maximum is evaluated; full "
        "VERIFIER conformance and whole-application polish remain UNKNOWN."
    ),
    retry=(
        "Exactly two replays occur inside one assessment. A later build or recheck is a "
        "fresh execution; matching digests do not make selected child effects idempotent."
    ),
    timing=(
        "No wall-time or external scheduling observation is made. Trace-event exhaustion "
        "bounds only counted CPython events during each selected in-process replay."
    ),
    limits=(
        "One evidence bundle, at most thirty-two constraints and sixty-four declarations, "
        "bounded canonical bytes/items/operations/events, supported registered routes, and "
        "no nested VERIFIER-3.1/4.1 replay."
    ),
    observations=(
        "Checker-produced observations are traced Python event count, canonical report "
        "byte count/digest, replay count, child status, and relation to declared maxima; "
        "caller declarations remain unadmitted."
    ),
    units=(
        "Dimensionless CPython trace events, canonical report bytes, replay and constraint "
        "counts, finite integer maxima, and SHA-256 identities."
    ),
    failure=(
        "Malformed/substituted inputs, exceeded declared maxima, refusal, or differing "
        "reports FAIL; unsupported quantities, exhausted checker ceiling, displaced trace, "
        "or unavailable child remain UNKNOWN."
    ),
    recovery=(
        "Restore the previous trace hook unconditionally, correct the exact selected "
        "request/policy/certificate or ceiling, and start a new assessment; caller "
        "observations cannot fill a missing checker observation."
    ),
    boundary=(
        "The two replays occur in one Python process and establish neither a serialized "
        "participant protocol nor substrate identity, physical resources, isolation, "
        "general determinism, whole-VERIFIER statics, full-application polish, ROBOT, or "
        "FINBOT consequences."
    ),
)


_REPOSITORY_ADMISSION = _shared._Profile(
    name="repository-admission reconciler",
    scope=(
        "Admit one exact objects.vstd package graph by conjoining retained Tier-0 gates "
        "with extensible namespace classification, discovered-surface coverage, reasons, "
        "source freshness, and independent Python/Node declaration reconciliation."
    ),
    mechanism=(
        "The Python assessors read canonical manifest and source census data, derive "
        "requirements and consequences, launch fixed bounded Node reconcilers over "
        "canonical JSON, compare exact receipts, and recapture source and mechanism state."
    ),
    participants=(
        "The selected repository and manifest, Python admission assessors, fixed Node "
        "reconcilers, installed namespace registry and discovery adapters, selected "
        "package GRAPH/VERIFIER, and report consumer."
    ),
    inputs=(
        "Exact canonical manifest bytes, repository coordinate, discovered surface and "
        "file census, installed registry/contracts, classification decisions and reasons, "
        "representation updates, selected reconciliation scripts, and mechanism bindings."
    ),
    authority=(
        "The caller selects the repository and manifest; installed contracts define the "
        "checks. Repository-authored reasons are declarations, not authenticated semantic, "
        "safety, financial, publication, release, or deployment authority."
    ),
    states=(
        "Unselected, admitted-input, discovered, classified, reconciled, source-changed, "
        "PASS, FAIL, UNKNOWN, finalized, and unclosed-coordinate states are retained."
    ),
    ordering=(
        "Manifest and coordinate selection precede discovery/classification; Python and "
        "Node derive from the same selected census; retained and namespace checks are "
        "conjoined; final recapture precedes package PASS."
    ),
    commands=(
        "Read the selected repository and manifest, invoke the fixed Node reconciliation "
        "programs with bounded canonical input, run retained and namespace assessors, and "
        "produce one combined package-admission report. Discovery runs fixed Git status and "
        "ls-files queries with repository-configured fsmonitor execution disabled."
    ),
    targets=(
        "One selected local repository, objects.vstd, installed namespace/admission "
        "mechanisms, fixed Node interpreter and reconciliation scripts, and the in-memory "
        "report."
    ),
    effect_domains=(
        "READ_ONLY_REPOSITORY_OBSERVATION_AND_FIXED_CHILD_EXECUTION; the route reads source "
        "and launches fixed reconcilers and isolated Git queries. Candidate-configured "
        "fsmonitor execution is disabled. The route does not rewrite the manifest, publish, "
        "deploy, actuate hardware, or transfer money."
    ),
    effects=(
        "Read selected source/manifest/Git state, create fixed Node reconciliation child "
        "processes, and return a source-bound admission report without changing worktree bytes."
    ),
    commit=(
        "Commit is only a Tier-0 package-admission PASS when every retained and namespace "
        "coordinate passes on one unchanged graph, source census, coordinate, and mechanism."
    ),
    retry=(
        "A retry is a complete fresh admission and recapture. Prior reconciliation or PASS "
        "cannot be replayed across changed manifest, source, registry, coordinate, or "
        "mechanism bytes."
    ),
    timing=(
        "Git selection has a finite timeout and Node reconciliation is bounded to twenty "
        "seconds; no eventual assessment, release, or deployment progress is promised."
    ),
    limits=(
        "Canonical JSON, manifest and reconciliation input bytes, object/surface/source "
        "censuses, graph acyclicity, exact registry/requirement sets, process timeout, and "
        "closing recapture are bounded and fail closed."
    ),
    observations=(
        "Manifest/source digests, repository revision, discovered surfaces/gaps, effective "
        "kinds, obligation sets, graph/representation/consequence digests, per-coordinate "
        "findings, reconciler receipt, and closing census agreement."
    ),
    units=(
        "Exact bytes and SHA-256 identities, object/surface/file/obligation/finding counts, "
        "nine Tier-0 coordinates, and process seconds."
    ),
    failure=(
        "Contradiction or mismatched independent interpretation FAILS; missing tool/source/"
        "reason/evidence or an unexecuted prerequisite remains UNKNOWN; changed source or "
        "mechanism prevents final PASS."
    ),
    recovery=(
        "Repair the named source-bound finding or restore the fixed interpreter/input, "
        "then rerun the entire admission against a fresh unchanged census; never substitute "
        "a narrower receipt."
    ),
    boundary=(
        "Repository admission is declaration, graph, source, and independent-interpretation "
        "closure at Tier 0 only. Repository-configured Git hook execution is disabled; it does not "
        "establish semantic truth, Tier-1-plus, full-application polish, release, ROBOT, or "
        "FINBOT safety."
    ),
)


_NATIVE_GATE = _shared._Profile(
    name="native gate suite",
    scope=(
        "Select shipped scanners, retained-artifact checks, manifest-object obligations, "
        "PRDEL/attestation/pipeline checks, and externally selected native replays for one "
        "exact snapshot or manifest object."
    ),
    mechanism=(
        "Bounded filesystem and archive reads, Python AST inspection, pattern matching, "
        "exact Git/PRDEL and receipt checks, installed gate discovery, source recapture, "
        "and selected callback/certificate replay produce typed findings."
    ),
    participants=(
        "The caller, selected snapshot/repository/manifest object, shipped gate registry, "
        "installed checkers and routes, fixed Git children where required, and the report "
        "consumer."
    ),
    inputs=(
        "Exact target paths or snapshot bytes, bounded gate policy, selected manifest "
        "object/obligation, optional external request/policy/certificate evidence, source "
        "coordinate, and installed registry/mechanism bytes."
    ),
    authority=(
        "Only installed callbacks and exact externally selected native routes may run. "
        "Artifact metadata never authorizes execution, and local clearance grants no "
        "universal quality, safety, publication, release, or deployment authority."
    ),
    states=(
        "Selected, applicable, not-applicable, scanning, replaying, PASS, FAIL/REJECTED, "
        "UNKNOWN, UNSUPPORTED, SKIP, source-changed, and unclosed-prerequisite states."
    ),
    ordering=(
        "Policy and snapshot/object selection precede gate discovery; static checks and "
        "selected native replays run under their own bounds; result aggregation and final "
        "manifest/source recapture precede any PASS."
    ),
    commands=(
        "Read bounded files/archives, parse Python source, launch fixed Git queries where "
        "selected, invoke only installed gate or route callbacks, replay selected "
        "certificates, and emit exact findings."
    ),
    targets=(
        "One declared local artifact snapshot or repository manifest object, installed "
        "gate implementations and native route callbacks, fixed Git queries, and in-memory "
        "clearance/gate reports."
    ),
    effect_domains=(
        "LOCAL_READ_AND_INSTALLED_CHECKER_EXECUTION_ONLY; file/Git reads and installed "
        "callback execution occur, including selected MODEL-3.2 replays that create Job-owned "
        "CPython worker processes; artifact-authored commands, publication, deployment, "
        "physical actuation, and financial effects are excluded."
    ),
    effects=(
        "Read selected bytes, create fixed diagnostic Git processes where required, execute "
        "installed bounded checkers, and return source-bound gate findings without mutating "
        "the selected artifact."
    ),
    commit=(
        "Commit is only the aggregate status or one exact manifest-object gate result after "
        "required selected checks and closing recapture; a scanner PASS is not polished "
        "status or semantic fulfillment."
    ),
    retry=(
        "A rerun reacquires current bytes and can repeat installed checker effects. No "
        "unstated idempotency or automatic retry after an uncertain callback/Git boundary "
        "is assumed."
    ),
    timing=(
        "Individual fixed Git and selected checker routes carry their own finite limits; "
        "the suite provides no general callback preemption, real-time guarantee, or eventual "
        "closure."
    ),
    limits=(
        "File/archive/total bytes, path counts, AST traversal and static iteration bounds, "
        "policy terms/selections, supported contracts, evidence selections, and source "
        "recapture are finite and fail closed."
    ),
    observations=(
        "Selected byte digests, scan counts and violations, AST/pattern findings, Git/PRDEL "
        "and receipt results, applicability, checker statuses, execution observations, and "
        "closing source/manifest agreement."
    ),
    units=(
        "Exact bytes, files/archive members/AST nodes/findings/gates, source lines, bounded "
        "iteration counts, process results, and SHA-256 identities."
    ),
    failure=(
        "Detected contradictions FAIL; unsupported format, missing applicability/evidence, "
        "unavailable checker or incomplete scan remains UNKNOWN/UNSUPPORTED; source change "
        "invalidates acceptance."
    ),
    recovery=(
        "Inspect the exact named gate/object/obligation, restore selected current evidence "
        "or repair the contradiction, then rerun against freshly captured bytes; never "
        "replace package evidence with a passing specimen."
    ),
    boundary=(
        "This suite gives bounded local technical gate evidence only. It is not complete "
        "nine-tier or full-application polish, arbitrary command confinement, universal "
        "quality/safety, rights clearance, release authority, ROBOT, or FINBOT assurance."
    ),
)


_SOURCE_OBSERVER = _shared._Profile(
    name="source-provenance observer",
    scope=(
        "Capture bounded current Git/source estate facts, exact commit-to-commit PRDEL "
        "changes, authored explanation projections, and path-scoped Git history without "
        "importing candidate source. Only the mutable worktree-state capture disables "
        "repository-configured fsmonitor hooks."
    ),
    mechanism=(
        "Fixed bounded Git object/history queries, ordinary-file reads, strict JSON and "
        "Python AST/token parsing, digest-bound source snapshots, static estate enumeration, "
        "and in-memory projection/validation produce deterministic records or staged bytes."
    ),
    participants=(
        "The caller, selected local Git repository and revisions, fixed Git child processes, "
        "candidate source treated as data, authored definitions/requirements, and returned "
        "estate, PRDEL, projection, or provenance consumer."
    ),
    inputs=(
        "Selected repository root/revisions, tracked and bounded untracked bytes, exact "
        "definitions/requirements/PRDEL documents, source paths/regions, expected digests, "
        "and finite file/history/AST/graph limits."
    ),
    authority=(
        "The caller selects readable local source coordinates. Git metadata, authored prose, "
        "digests, and static declarations do not authenticate authorship, requirement "
        "authority, execution, publication, release, or downstream effects."
    ),
    states=(
        "Unavailable, captured, projected-staged, generated, validated, contradicted, "
        "UNKNOWN, PASS/FAIL report, and fresh-recapture states remain distinct."
    ),
    ordering=(
        "Resolve exact revisions and source census before reading blobs/history; bind every "
        "projection or explanation row to selected bytes/regions; finalize digests and "
        "limits only after complete bounded enumeration."
    ),
    commands=(
        "Launch fixed read-only Git queries, read selected ordinary files, parse candidate "
        "bytes as inert data, and return staged comment bytes or source-bound reports. Only "
        "the mutable worktree-state capture runs Git status and ls-files with repository-configured "
        "fsmonitor execution disabled."
    ),
    targets=(
        "One selected local Git repository, its exact objects/index/worktree metadata, "
        "bounded ordinary source files and authored input documents, fixed Git children, "
        "and in-memory outputs."
    ),
    effect_domains=(
        "READ_ONLY_SOURCE_ACQUISITION_WITH_FIXED_CHILD_EXECUTION; fixed Git child creation in the "
        "mutable worktree-state capture occurs with repository-configured fsmonitor disabled, and "
        "object-database children assert neither index refresh nor fsmonitor behavior. Source is not imported or rewritten, and nothing is "
        "committed, published, deployed, physically actuated, or financially transacted."
    ),
    effects=(
        "Read repository/source metadata and exact blobs, create fixed Git query processes, "
        "and return staged bytes or deterministic observation documents without changing the "
        "candidate worktree."
    ),
    commit=(
        "Commit is return of a complete digest-bound observation/projection/report for the "
        "selected coordinate; no repository write, historical authorship, runtime correctness, "
        "workspace clearance, or publication is committed."
    ),
    retry=(
        "Every retry reacquires current Git/source state. Retained output is historical and "
        "cannot establish current bytes after coordinate, index, status, definition, or "
        "requirement changes."
    ),
    timing=(
        "Git queries and provenance walks have finite timeouts/deadlines; timestamps and "
        "commit history are observations of selected records, not authenticated authorship "
        "or independently witnessed precommit time."
    ),
    limits=(
        "Git output/history, files and total bytes, AST/source nodes, definitions/regions/"
        "candidates, CLI routes, graph materialization, paths, and recursion are bounded and "
        "fail closed."
    ),
    observations=(
        "Repository coordinate/index/status, exact source/blob/mode digests, static symbols "
        "and changes, source-region predicates, authored definitions/comments, mechanically "
        "visible candidates, and explicit gaps."
    ),
    units=(
        "Exact bytes, files/commits/definitions/regions/candidates/nodes/lines, time seconds, "
        "Git modes, and SHA-256 identities."
    ),
    failure=(
        "Malformed/substituted input or supported contradiction FAILS; unavailable Git/source, "
        "ambiguous projection, or exhausted bound remains unavailable/UNKNOWN; missing data "
        "is never replaced with inferred provenance."
    ),
    recovery=(
        "Restore the exact selected source or bounded Git access, correct authored/selection "
        "ambiguity, and perform a fresh capture; staged output remains uncommitted until a "
        "separate authorized writer acts."
    ),
    boundary=(
        "Only the mutable worktree-state capture observes selected source with repository-configured "
        "fsmonitor execution disabled; the object-database paths assert neither index refresh nor "
        "fsmonitor behavior. They establish neither "
        "authorship, requirement authority, test execution, runtime correctness, complete "
        "objective or full-application polish, publication, ROBOT, nor FINBOT consequences."
    ),
)


_CORE_SELF_POLISH = _shared._Profile(
    name="core self-polish assessor",
    scope=(
        "Prepare and replay one externally digest-pinned CORE-SELF-POLISH-1 selection for "
        "the exact Verifier source state, structural application compiler, installed rules, "
        "and two selected Tier-1 certificates."
    ),
    mechanism=(
        "Capture Git/index/worktree and candidate-source census, bind installed mechanism "
        "sources and instructions, derive and reproduce structural compiler output, replay "
        "selected native objectives, recapture source, and issue/recheck a narrow receipt."
    ),
    participants=(
        "The caller/external selector, selected Verifier repository, fixed Git queries, "
        "core self-polish assessor, structural compiler, registered native object routes, "
        "selected certificates, and receipt consumer."
    ),
    inputs=(
        "Exact source manifest and digest, application/object selections, source scope and "
        "collection bytes, compiler policy/manifest, polish request/bundle/inventory, selected "
        "certificates, expected digests, and optional cancellation callback."
    ),
    authority=(
        "The caller must independently retain/select the preparation digest. The resulting "
        "receipt records selection authority, public checkability, human acceptance, release, "
        "and full-application status as unestablished."
    ),
    states=(
        "Prepared-without-credit, externally-selected, source-reproduced, compiler-reproduced, "
        "native-replayed, receipt-issued, PASS, FAIL, UNKNOWN, cancelled, invalidated, and "
        "replay-rejected states remain explicit."
    ),
    ordering=(
        "Source and mechanism capture precede preparation; external digest selection precedes "
        "assessment; source, compiler, object facets, typed facets, and native inventory replay "
        "must close in order; final recapture precedes receipt issue."
    ),
    commands=(
        "Run fixed Git source queries, invoke the installed structural compiler and registered "
        "native certificate replays, compare exact canonical outputs, and issue or reproduce "
        "the bounded CORE-SELF-POLISH receipt."
    ),
    targets=(
        "One selected Verifier source tree and worktree state, installed compiler/rule/route "
        "mechanisms, two selected Tier-1 objective certificates, and in-memory assessment and "
        "receipt values."
    ),
    effect_domains=(
        "LOCAL_FIXED_GIT_AND_INSTALLED_REPLAY_ONLY; the route reads source and executes installed "
        "compiler/checker code, but does not run arbitrary repository commands, publish, release, "
        "deploy, physically actuate, or transact money."
    ),
    effects=(
        "Read and recapture exact source state, create fixed Git children, execute installed "
        "compiler/native replay functions, and return a narrow source-bound receipt without "
        "changing repository bytes."
    ),
    commit=(
        "Commit is issuance of a CORE-SELF-POLISH receipt only after exact source/compiler/native "
        "reproduction. The receipt explicitly keeps full_application_status UNKNOWN and "
        "polished false."
    ),
    retry=(
        "Recheck reruns the complete current assessment and requires byte-identical assessment "
        "and receipt digests. Any source, instruction, selection, rule, route, or mechanism "
        "change invalidates the retained result."
    ),
    timing=(
        "Fixed Git queries have finite timeouts and cancellation is observed at explicit stages; "
        "installed in-process compiler/checker calls have no general preemption or real-time "
        "guarantee."
    ),
    limits=(
        "Source files/bytes, Git outputs, selection/inventory/request/bundle bytes, objects, "
        "requirements, objectives, registered routes, compiler pins, and exact digest/shape "
        "checks are finite and fail closed."
    ),
    observations=(
        "Git head/tree/index/status and source census, mechanism/source/instruction/rule digests, "
        "compiler and native replay status, installed counts, selected objective closure, "
        "recapture agreement, and receipt digest."
    ),
    units=(
        "Exact bytes, source files, installed definitions/memberships, objects/requirements/"
        "objectives/certificates, fixed replay counts, and SHA-256 identities."
    ),
    failure=(
        "Invalid or substituted selection/input FAILS; missing source/mechanism or cancellation "
        "remains UNKNOWN; resource exhaustion remains UNKNOWN; no partial replay or preparation "
        "alone issues a PASS receipt."
    ),
    recovery=(
        "Restore the exact externally selected source/mechanism/input set, prepare a new digest "
        "when anything changed, and rerun the full gate; never promote the narrow receipt to "
        "whole-application polish."
    ),
    boundary=(
        "PASS covers only the exact CORE-SELF-POLISH-1 structural selection and two native "
        "Tier-1 replays. Full-application completeness, polished issuance, authority, public "
        "checkability, acceptance, release, ROBOT, and FINBOT consequences remain unestablished."
    ),
)


_ADDED_KIND_BEHAVIORAL = _shared._Profile(
    name="added-kind retained-evidence VERIFIER",
    scope=(
        "Select one of nine exact source-registered MARKET, ROBOT, or FINBOT "
        "propositions and construct or independently recheck its bounded retained-byte "
        "certificate without executing the represented subject; for POLICY observations, "
        "launch one exact isolated local worker and retain its bounded response. The "
        "applicable ASSET boundary retains an obligation-bearing FINBOT consequence role "
        "without promoting a represented financial effect."
    ),
    mechanism=(
        "Exact policy, request, proposition, source, mechanism, and evidence digests "
        "are checked before strict canonical-JSON decoding; the selected finite domain "
        "evaluator and installed consequence-graph engine produce a typed result, and "
        "recheck rebuilds the complete self-digested certificate byte for byte. POLICY "
        "observation acquisition launches the installed worker as python -I -S -B, sends "
        "one nonce-bound request, and verifies its return status, schema, nonce, and source pins."
    ),
    participants=(
        "The caller selecting retained bytes, the installed route registry, one of the "
        "MARKET/ROBOT/FINBOT domain evaluators, the installed consequence engine where "
        "selected, the exact isolated POLICY observation worker where selected, and the "
        "certificate consumer. No represented market participant, physical actuator, or "
        "financial endpoint participates in checker execution; an actual financial AGENT "
        "and HARNESS binding are NOT_ESTABLISHED."
    ),
    inputs=(
        "An exact kind/check/subject/source selection, current proposition and mechanism "
        "digests, an immutable evidence-byte reference, sorted unique trust-root labels, "
        "a policy digest, retained asset and party identifiers where selected, and finite "
        "evidence-byte, record, and certificate ceilings."
    ),
    authority=(
        "Installed route and policy code select the proposition, checker, limits, and "
        "nonpromotion boundary and authorize only the named local worker launch. "
        "Caller-supplied trust-root labels and retained records grant no venue, physical, "
        "legal, publication, or release authority; actual financial authority is "
        "NOT_ESTABLISHED."
    ),
    states=(
        "Unselected, policy-admitted, request-admitted, evidence-unavailable, decoded, "
        "evaluated PASS/FAIL/UNKNOWN, certificate-built, replay-reproduced, stale, "
        "substituted, malformed, limit-exhausted, worker-unavailable, worker-timed-out, "
        "worker-failed, and worker-response-refused states remain distinct."
    ),
    ordering=(
        "Validate the current policy, mechanism, route, proposition, request, limits, and "
        "evidence reference before decoding retained bytes; for observation acquisition, "
        "construct the fixed nonce request before the isolated worker launch and accept "
        "output only after return-code, schema, nonce, and source-pin checks; evaluate only "
        "the selected route; bind the result and nonpromotion fields before the envelope "
        "digest; on recheck, validate the envelope and rebuild it exactly before returning."
    ),
    commands=(
        "Call installed route selection, strict decoding, digest, finite domain-evaluation, "
        "consequence-graph assessment, certificate construction, and certificate recheck "
        "functions, or launch only the exact installed POLICY observation worker as "
        "python -I -S -B; no subject-authored command is executed."
    ),
    targets=(
        "One caller-supplied immutable retained-evidence payload, one exact installed "
        "MARKET/ROBOT/FINBOT route and evaluator, current mechanism sources, the exact "
        "local POLICY observation worker when selected, and one in-memory certificate."
    ),
    effect_domains=(
        "BOUNDED_LOCAL_SOFTWARE_PROCESS_ACTUATION_AND_RETAINED_BYTE_VERIFICATION_ONLY; "
        "the checker may launch its exact isolated observation worker and otherwise parses, "
        "hashes, and replays supplied records, but performs no participant exchange, "
        "trading, settlement, physical actuation, real-money movement, or represented "
        "runtime correspondence."
    ),
    effects=(
        "Launch at most one selected local POLICY observation subprocess per acquisition, "
        "write its bounded nonce request to standard input, capture its return code and "
        "output, read current checker sources and caller-supplied bytes, compute digests, "
        "replay finite retained relationships, and return certificate bytes or a typed "
        "refusal without commanding the represented external system."
    ),
    commit=(
        "Commit is only a self-digested canonical certificate for the exact selected "
        "request, policy, mechanism, proposition, evidence payload, and bounded result. "
        "Every certificate retains object-profile and external-effect claims as "
        "NOT_ESTABLISHED."
    ),
    retry=(
        "A build or recheck is a fresh retained-byte evaluation, and each requested worker "
        "acquisition is a fresh bounded process launch rather than an automatic retry. "
        "Recheck must reproduce the entire certificate exactly; matching retained records "
        "do not make any represented market, physical, or financial action idempotent."
    ),
    timing=(
        "The local observation worker has an explicit caller-selected timeout (180 seconds "
        "by default); timeout is refusal evidence, not a scheduler or external progress "
        "guarantee. Other work is bounded by selected byte and record ceilings."
    ),
    limits=(
        "Canonical closed schemas, one exact registered route, one to sixteen sorted "
        "unique trust-root labels, at most 4 MiB of evidence, 4096 retained records per "
        "selected collection, at most 8 MiB per certificate, bounded identifiers, plain "
        "integer quantities, one exact isolated worker command per observation acquisition, "
        "one positive timeout, and exact SHA-256 commitments fail closed."
    ),
    observations=(
        "Current mechanism and proposition digests, exact policy/request/evidence "
        "bindings, selected route and source coordinate, finite retained lifecycle or "
        "consequence relationships, worker return status, response bytes, nonce, schema, "
        "and source pins where launched, typed PASS/FAIL/UNKNOWN reason, explicit "
        "NOT_ESTABLISHED fields, and reproduced certificate digest."
    ),
    units=(
        "Evidence and certificate bytes, retained record and trust-root counts, integer "
        "price/quantity/exposure/sequence units declared by the retained evidence, and "
        "SHA-256 identities; worker timeouts use integer seconds and process completion uses "
        "one integer return code."
    ),
    failure=(
        "Malformed, noncanonical, mutated, stale, foreign, digest-inconsistent, or "
        "contradictory evidence and certificates FAIL; absent or explicitly incomplete "
        "retained evidence and bounded-resource exhaustion remain UNKNOWN. Worker launch "
        "errors or timeouts are unavailable, nonzero status is failed, and malformed, "
        "nonce-mismatched, or source-drifted output is refused; none is promoted to runtime "
        "truth or external safety."
    ),
    recovery=(
        "Select the exact current route and policy, restore current source/proposition "
        "bindings and worker availability, supply a complete bounded canonical retained "
        "payload, and perform a fresh full acquisition, build, or recheck; never edit or "
        "trust a partial response or certificate. Real-world financial reconciliation "
        "and recovery remain NOT_ESTABLISHED."
    ),
    boundary=(
        "This is a first-party VERIFIER with bounded local software actuation for one exact "
        "isolated POLICY observation worker. Its retained records and certificate lifecycle "
        "carry the twelve review-kind roles so their obligations cannot be discarded. These "
        "are bounded checker and evidence roles, not promotion to represented subjects: an "
        "actual financial or physical AGENT, HARNESS binding, live market participant, venue, "
        "financial authority, exposure, real-world endpoint, physical reach, effect, safety, "
        "settlement, and reconciliation are NOT_ESTABLISHED. The checker commands no "
        "represented subject, performs no external participant exchange, physical actuation, "
        "settlement, or real-money movement, and does not establish runtime correspondence; "
        "asset backing and custody are NOT_ESTABLISHED. It does not establish full-application "
        "polish, publication, release, or deployment."
    ),
)


_ASSET_TIER0_EXECUTION = _shared._Profile(
    name="ASSET Tier-0 in-memory policy verifier",
    scope=(
        "Evaluate one fixed finite specimen for the twelve ASSET-0.1, ASSET-0.2, "
        "and ASSET-0.3 declaration fields, expose their exact source-owned field "
        "statuses, compare supplied route metadata with pinned correspondence, and "
        "accept an observation only when it strictly equals a fresh evaluation. The "
        "checker is not an ASSET subject or instance and owns no ASSET route."
    ),
    mechanism=(
        "Standard-library dataclasses and closed vocabularies enforce typed integer "
        "quantities, authority-grant lookup, idempotent operation identifiers, atomic "
        "batch staging, custody/control and encumbrance rules, reconciliation, strict "
        "same-type equality, canonical JSON SHA-256 digests, and a digest of this "
        "module's own current bytes."
    ),
    participants=(
        "The caller, installed in-process checker, its fixed in-memory claim and backing "
        "records, caller-supplied retained observation or route rows, and the report "
        "consumer. No real issuer, custodian, holder, settlement venue, or ASSET route "
        "owner participates."
    ),
    inputs=(
        "The installed field catalog and specimen constants; closed claim, instrument, "
        "backing, rights, grant, operation, account, and unit records; caller-supplied "
        "route-catalog rows; or one caller-supplied observation for strict comparison "
        "with a fresh report."
    ),
    authority=(
        "Only installed checker code selects the finite rules and expected outcomes. "
        "AuthorityGrant and custodian/controller identifiers are specimen data, not "
        "authenticated issuer, legal, custody, redemption, financial, route, release, "
        "or deployment authority; no real instrument is issued or redeemed."
    ),
    states=(
        "Typed-record admitted/refused, grant active/revoked/exhausted, operation new/"
        "duplicate/conflicting, batch staged/committed/refused, encumbrance active/"
        "released, reconciliation PASS/FAIL/UNKNOWN, in-model reproduced/unreproduced, "
        "route NOT_ESTABLISHED, and observation accepted/refused remain distinct."
    ),
    ordering=(
        "Validate identifiers, units, quantities, grants, control, available balance, "
        "and operation identity before staging mutation; commit a complete batch only "
        "after every staged operation succeeds; build route correspondence after all "
        "fixed rows run; strict fresh-report equality precedes observation acceptance."
    ),
    commands=(
        "Construct the fixed specimen, apply in-memory operations or batches, reconcile "
        "one supplied statement, enumerate field metadata, compare route rows, evaluate "
        "the fixed scenarios, or strictly compare a supplied report with fresh output."
    ),
    targets=(
        "One process-local ledger clone and its claim, grant, account, journal, backing, "
        "and encumbrance records; caller-supplied Python values; returned dictionaries; "
        "and this module's own source file for its source digest."
    ),
    effect_domains=(
        "PURE_IN_PROCESS_ASSET_RECORD_VERIFICATION_ONLY; the checker mutates only new or "
        "caller-owned in-memory specimen state and reads only its own source bytes. It "
        "spawns no process, opens no network connection, and reaches no real asset, "
        "custody, settlement, physical, or financial endpoint."
    ),
    effects=(
        "Allocate and mutate finite in-memory specimen records, read and hash the current "
        "checker source, and return field catalogs, exact diagnostics, reproduction "
        "metadata, or a typed refusal. No real instrument is issued or redeemed, no "
        "backing or custody moves, and no route result is changed."
    ),
    commit=(
        "Commit is only an in-memory operation or atomic batch accepted under the fixed "
        "specimen rules, or a report PASS meaning every fixed expected outcome reproduced. "
        "Fresh observation acceptance remains auxiliary and never establishes ASSET "
        "conformance, carried_by_route, or ASSET-1.1, ASSET-2.1, or ASSET-3.1 PASS."
    ),
    retry=(
        "A repeated operation identifier is idempotent only when its exact payload "
        "matches; conflicting reuse is refused. Every evaluate or observation check is "
        "a fresh in-process reproduction, and matching bytes do not make any represented "
        "real issuance, redemption, custody, or settlement idempotent."
    ),
    timing=(
        "No clock, scheduler, external-event time, deadline, or liveness is observed. "
        "Only deterministic call order in one Python process is represented."
    ),
    limits=(
        "The fixed specimen uses closed identifiers, rights, operation kinds and units, "
        "non-boolean integers from zero through 2**63-1, and a finite scenario catalog. "
        "Caller-supplied route sequences and observation structures have no explicit "
        "byte, row, or nesting ceiling before comparison, so resource exhaustion is not "
        "converted into PASS."
    ),
    observations=(
        "Exact operation outcomes, journal height, balances, issued/redeemed totals, "
        "recorded backing, state/source/specimen digests, field statuses and reasons, "
        "reconciliation diagnostics, route correspondence, and strict equality with "
        "fresh output; external truth is not observed."
    ),
    units=(
        "Exact dimensionless integer counts tagged as instrument units or backing atoms, "
        "journal and scenario counts, source/report bytes, and SHA-256 identities."
    ),
    failure=(
        "Malformed records and forbidden operations raise stable typed refusals; expected-"
        "outcome drift returns FAIL; malformed or incomplete reconciliation input remains "
        "UNKNOWN or exact diagnostics; route drift is reported; a stale, forged, reordered, "
        "aliased, or altered observation is refused and never promoted to route PASS."
    ),
    recovery=(
        "Correct the exact retained record, statement, route metadata, or installed source "
        "and perform a complete fresh evaluation. A refused batch leaves the original "
        "ledger unchanged; no catalog row, in-model reproduction, or prior report may be "
        "used as a substitute for the separately owned ASSET route."
    ),
    boundary=(
        "This is a pure in-memory VERIFIER with a POLICY decision surface over one finite "
        "ASSET-shaped specimen. It is not an ASSET subject or instance and not an "
        "ASSET-1.1, ASSET-2.1, or ASSET-3.1 route owner. It establishes no real issuer "
        "authority, signature validity, custody, holding completeness, redemption terms, "
        "supply conservation, backing, carried_by_route, route PASS, full-application "
        "polish, release, or deployment."
    ),
)


_REPOSITORY_PATHS = (
    "src/verifier/runtime/namespace_admission.py",
    "src/verifier/runtime/namespace_reconcile.mjs",
    "src/verifier/runtime/package_admission.py",
    "src/verifier/runtime/tier_zero_reconcile.mjs",
)
_GATE_PATHS = (
    "src/verifier/runtime/gate.py",
    "src/verifier/runtime/gates.py",
    "src/verifier/runtime/manifest_gate.py",
)
_SOURCE_PATHS = (
    "src/verifier/runtime/explanation_projection.py",
    "src/verifier/runtime/prdel.py",
    "src/verifier/runtime/self_polish_estate.py",
)
_ADDED_KIND_BEHAVIORAL_PATHS = (
    "src/verifier/domains/contracts/finbot_checks.py",
    "src/verifier/domains/contracts/market_checks.py",
    "src/verifier/domains/contracts/robot_checks.py",
    "src/verifier/runtime/added_kind_behavioral_routes.py",
)
_ASSET_TIER0_EXECUTION_PATHS = (
    "src/verifier/runtime/asset_execution.py",
)


@dataclass(frozen=True)
class _Refutation:
    """An audited DOES_NOT_APPLY basis over owned source only."""

    basis: str


# A refutation is accepted only when its object and kind appear here with a
# source-audited basis over the exact owned boundary.  Absence of
# a direct import, direct write call, or read-only Git verb is never a basis: the
# current review leaves unsupported roles UNRESOLVED rather than refuting them.
# This registry is therefore empty until a new basis is audited.
_AUDITED_REFUTATIONS: dict[str, dict[str, _Refutation]] = {}

# Source-bound UNRESOLVED reasons for previously overclassified cells. UNRESOLVED
# carries no evidence and never transfers a role from a reached downstream owner.
_SOURCE_BOUND_UNRESOLVED_REASONS = {
    ("vstd-source-provenance-observer", "TRANSACTION"): (
        "Transaction boundaries are not established. Only the mutable worktree-state capture runs "
        "Git with repository-configured fsmonitor disabled; the object-database helpers assert "
        "neither index refresh nor fsmonitor behavior and name no owned commit, rollback, or "
        "partial-failure unit. Applicability is UNRESOLVED, not refuted."
    ),
    ("vstd-repository-admission-reconciler", "TRANSACTION"): (
        "Transaction boundaries are not established. Discovery's fixed Git queries disable "
        "repository-configured fsmonitor execution and name no owned commit, rollback, or "
        "partial-failure unit. Applicability is UNRESOLVED, not refuted."
    ),
    ("vstd-verifier-run-constraint-controller", "ACTUATOR"): (
        "Actuator applicability is not established. Replaying a registered downstream worker "
        "does not transfer that worker's command-to-effect endpoint, feedback, or failure "
        "surface to this controller. Applicability is UNRESOLVED, not refuted."
    ),
    ("vstd-native-gate-suite", "ACTUATOR"): (
        "Actuator applicability is not established. Dispatching a registered downstream "
        "worker does not transfer that worker's command-to-effect endpoint, feedback, or "
        "failure surface to this gate suite. Applicability is UNRESOLVED, not refuted."
    ),
    ("vstd-repository-admission-reconciler", "ACTUATOR"): (
        "Actuator applicability is not established. Fixed reconciler and Git process launch "
        "does not expose an owned command-to-effect endpoint with effect feedback and a "
        "failure surface. Applicability is UNRESOLVED, not refuted."
    ),
    ("vstd-source-provenance-observer", "ACTUATOR"): (
        "Actuator applicability is not established. Fixed read-only Git process launch is "
        "not an owned command-to-effect endpoint. Only the mutable worktree-state capture "
        "disables repository-configured fsmonitor execution, and that configuration hardening "
        "is not an effect endpoint. Applicability is UNRESOLVED, not refuted."
    ),
}


def _role_paths(
    paths: tuple[str, ...],
    applicable: tuple[str, ...],
) -> dict[str, tuple[str, ...]]:
    """Bind each applicable role to owned source only."""
    return {kind: paths for kind in applicable}


_REVIEWS = {
    "vstd-verifier-native-execution-controller": _shared._review(
        "VERIFIER",
        ("src/verifier/domains/verifier_execution.py",),
        (
            "TRANSACTION",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "POLICY",
        ),
        _NATIVE_EXECUTION,
        actuator_basis=_shared._ActuatorBasis(
            endpoint_path="src/verifier/domains/verifier_execution.py",
            command_to_effect=(
                "The owned controller creates, resumes, and terminates one fixed Job-owned "
                "worker process."
            ),
            feedback=(
                "The owned controller observes Job membership, accounting, process state, "
                "bounded output, exit status, and cleanup."
            ),
            failure_surface=(
                "Timeout, output exhaustion, membership disagreement, incomplete cleanup, "
                "and malformed replies remain explicit non-PASS outcomes."
            ),
        ),
    ),
    "vstd-verifier-run-constraint-controller": _shared._review(
        "VERIFIER",
        ("src/verifier/domains/contracts/verifier_run_constraints.py",),
        (
            "TRANSACTION",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "POLICY",
        ),
        _RUN_CONSTRAINTS,
        _role_paths(
            ("src/verifier/domains/contracts/verifier_run_constraints.py",),
            (
                "TRANSACTION",
                "MEASUREMENT",
                "SENSOR",
                "CONTROLLER",
                "POLICY",
            ),
        ),
    ),
    "vstd-repository-admission-reconciler": _shared._review(
        "VERIFIER",
        _REPOSITORY_PATHS,
        ("MEASUREMENT", "SENSOR", "PROTOCOL", "POLICY"),
        _REPOSITORY_ADMISSION,
        _role_paths(
            _REPOSITORY_PATHS,
            ("MEASUREMENT", "SENSOR", "PROTOCOL", "POLICY"),
        ),
    ),
    "vstd-native-gate-suite": _shared._review(
        "VERIFIER",
        _GATE_PATHS,
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "PROTOCOL", "POLICY"),
        _NATIVE_GATE,
        _role_paths(
            _GATE_PATHS,
            ("TRANSACTION", "MEASUREMENT", "SENSOR", "PROTOCOL", "POLICY"),
        ),
    ),
    "vstd-source-provenance-observer": _shared._review(
        "SENSOR",
        _SOURCE_PATHS,
        ("MEASUREMENT", "SENSOR", "PROTOCOL"),
        _SOURCE_OBSERVER,
        _role_paths(
            _SOURCE_PATHS,
            ("MEASUREMENT", "SENSOR", "PROTOCOL"),
        ),
    ),
    "vstd-core-self-polish-assessor": _shared._review(
        "VERIFIER",
        ("src/verifier/runtime/polish_requirements.py",),
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL", "POLICY"),
        _CORE_SELF_POLISH,
        actuator_basis=_shared._ActuatorBasis(
            endpoint_path="src/verifier/runtime/polish_requirements.py",
            command_to_effect=(
                "The owned assessor invokes the selected installed compiler and native "
                "certificate mechanisms to produce a bounded assessment receipt."
            ),
            feedback=(
                "The owned assessor consumes compiler and replay status, source recapture, "
                "cancellation, and exact receipt-recheck observations."
            ),
            failure_surface=(
                "Invalid selection, missing mechanisms, cancellation, exhausted bounds, "
                "changed source, or replay disagreement remain explicit non-PASS outcomes."
            ),
        ),
    ),
    "vstd-added-kind-behavioral-verifier": _shared._review(
        "VERIFIER",
        _ADDED_KIND_BEHAVIORAL_PATHS,
        (
            "ACTUATOR",
            "ASSET",
            "CONTROLLER",
            "FINBOT",
            "LEDGER",
            "MARKET",
            "MEASUREMENT",
            "POLICY",
            "PROTOCOL",
            "ROBOT",
            "SENSOR",
            "TRANSACTION",
        ),
        _ADDED_KIND_BEHAVIORAL,
        {
            "ACTUATOR": ("src/verifier/runtime/added_kind_behavioral_routes.py",),
            "ASSET": _ADDED_KIND_BEHAVIORAL_PATHS,
            "CONTROLLER": ("src/verifier/runtime/added_kind_behavioral_routes.py",),
            "FINBOT": (
                "src/verifier/domains/contracts/finbot_checks.py",
                "src/verifier/runtime/added_kind_behavioral_routes.py",
            ),
            "LEDGER": _ADDED_KIND_BEHAVIORAL_PATHS,
            "MARKET": (
                "src/verifier/domains/contracts/market_checks.py",
                "src/verifier/runtime/added_kind_behavioral_routes.py",
            ),
            "MEASUREMENT": ("src/verifier/runtime/added_kind_behavioral_routes.py",),
            "POLICY": _ADDED_KIND_BEHAVIORAL_PATHS,
            "PROTOCOL": ("src/verifier/runtime/added_kind_behavioral_routes.py",),
            "ROBOT": (
                "src/verifier/domains/contracts/robot_checks.py",
                "src/verifier/runtime/added_kind_behavioral_routes.py",
            ),
            "SENSOR": ("src/verifier/runtime/added_kind_behavioral_routes.py",),
            "TRANSACTION": _ADDED_KIND_BEHAVIORAL_PATHS,
        },
        actuator_basis=_shared._ActuatorBasis(
            endpoint_path="src/verifier/runtime/added_kind_behavioral_routes.py",
            command_to_effect=(
                "The owned route launches the exact isolated POLICY observation worker "
                "as python -I -S -B and writes one nonce-bound request to its stdin."
            ),
            feedback=(
                "The route captures return status and output, then validates schema, nonce, "
                "observations, and installed source pins before accepting the response."
            ),
            failure_surface=(
                "Launch error, timeout, nonzero return, malformed output, nonce mismatch, "
                "and source drift are explicit typed refusals and never PASS."
            ),
        ),
    ),
    "vstd-asset-tier0-execution-verifier": _shared._review(
        "VERIFIER",
        _ASSET_TIER0_EXECUTION_PATHS,
        ("POLICY",),
        _ASSET_TIER0_EXECUTION,
    ),
}

# These rows verify retained ROBOT/FINBOT evidence; the checker is not thereby
# the represented robot or financial agent and no external endpoint is run.
OBLIGATION_RETENTION_APPLIES: dict[str, tuple[str, ...]] = {
    "vstd-added-kind-behavioral-verifier": ("FINBOT", "ROBOT"),
}


def obligation_retention_reason(object_id: str, kind: str) -> str:
    """Return one exact VERIFIER-review demand-only reason."""

    if kind not in OBLIGATION_RETENTION_APPLIES.get(object_id, ()):
        raise ValueError("VERIFIER_REVIEW_OBLIGATION_RETENTION_UNDECLARED")
    return _cell_reason(object_id, _REVIEWS[object_id], kind)


def _cell_paths(object_id: str, review: _shared._Review, kind: str) -> tuple[str, ...]:
    """Return the exact source basis of one cell; UNRESOLVED has none."""
    basis = _shared._basis(review, kind)
    if basis == "APPLIES":
        return tuple(review.role_paths[kind])
    if basis == "DOES_NOT_APPLY":
        return tuple(review.owned_paths)
    return ()


def _evidence_universe(object_id: str, review: _shared._Review) -> tuple[str, ...]:
    """Return every source path that any cell of this object binds, in stable order."""
    paths = list(review.owned_paths)
    for kind in REVIEW_KINDS:
        for path in _cell_paths(object_id, review, kind):
            if path not in paths:
                paths.append(path)
    return tuple(paths)


def _cell_reason(object_id: str, review: _shared._Review, kind: str) -> str:
    """Return the source-bound reason for one review cell."""
    basis = _shared._basis(review, kind)
    if basis == "UNRESOLVED":
        return _SOURCE_BOUND_UNRESOLVED_REASONS.get(
            (object_id, kind), _shared._unresolved_reason(kind)
        )
    return _shared._reason(review.profile, kind, basis == "APPLIES")


def _explicit_decision(
    object_id: str,
    review: _shared._Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
) -> dict[str, Any]:
    """Return the canonical row decision for one explicit APPLIES or DOES_NOT_APPLY cell."""
    basis = _shared._basis(review, kind)
    if basis == "UNRESOLVED":
        raise AssertionError("explicit decision requested for unlisted " + kind)
    return {
        "status": basis,
        "reason": _cell_reason(object_id, review, kind),
        "evidence": [
            deepcopy(evidence_by_path[path])
            for path in _cell_paths(object_id, review, kind)
        ],
    }


def _classification_document(object_id: str, review: _shared._Review, kind: str) -> dict[str, Any]:
    return {
        "status": _shared._basis(review, kind),
        "reason": _cell_reason(object_id, review, kind),
        "evidence_paths": list(_cell_paths(object_id, review, kind)),
    }


def _catalog_check() -> None:
    if tuple(_REVIEWS) != VERIFIER_OBJECT_IDS:
        raise AssertionError("VERIFIER review object order differs")
    for object_id, review in _REVIEWS.items():
        if (
            review.primary_kind in REVIEW_KINDS
            and review.primary_kind not in review.applicable
        ):
            raise AssertionError(object_id + " primary kind is not applicable")
        if len(review.applicable) != len(set(review.applicable)):
            raise AssertionError(object_id + " repeats an applicable kind")
        if len(review.refuted) != len(set(review.refuted)) or any(
            kind not in REVIEW_KINDS or kind in review.applicable
            for kind in review.refuted
        ):
            raise AssertionError(object_id + " refutation is not disjoint or registered")
        audits = _AUDITED_REFUTATIONS.get(object_id, {})
        if set(review.refuted) != set(audits):
            raise AssertionError(object_id + " declares an unaudited refutation")
        for kind in review.refuted:
            refutation = audits[kind]
            if (
                type(refutation) is not _Refutation
                or not refutation.basis.startswith("Audited against ")
            ):
                raise AssertionError(
                    object_id + ":" + kind + " refutation lacks owned-source basis"
                )
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        for kind, paths in review.role_paths.items():
            if not paths or not set(paths) <= set(review.owned_paths):
                raise AssertionError(object_id + " role evidence leaves owned source")
        actuator_basis = review.actuator_basis
        if "ACTUATOR" in review.applicable:
            if (
                type(actuator_basis) is not _shared._ActuatorBasis
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
        if any(
            not _cell_reason(object_id, review, kind).strip()
            for kind in REVIEW_KINDS
        ):
            raise AssertionError(object_id + " classification reason is blank")
        expected = {
            row["id"]: set(row["declaration_fields"])
            for kind in review.applicable
            for row in _shared._contract_rows(kind)
        }
        declarations = _shared._declarations(review)
        if set(declarations) != set(expected):
            raise AssertionError(object_id + " declaration denominator differs")
        for obligation_id, fields in declarations.items():
            if set(fields) != expected[obligation_id] or any(
                type(value) is not str or not value.strip() for value in fields.values()
            ):
                raise AssertionError(object_id + " declaration fields differ")


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return a defensive digest-free view of all eight exact reviews."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: _classification_document(object_id, review, kind)
                for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(_shared._declarations(review)),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for object_id, review in _REVIEWS.items()
    }


def _role_evidence(
    review: _shared._Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
) -> list[dict[str, str]]:
    """Return the exact current evidence for one applicable role, in role order."""
    return [deepcopy(evidence_by_path[path]) for path in review.role_paths[kind]]


def _preserve_classification(
    decision: Any,
    review: _shared._Review,
    kind: str,
    evidence_by_path: Mapping[str, dict[str, str]],
    files: Mapping[str, str],
    owned: set[str],
    *,
    object_id: str,
) -> bool:
    """Return True only for a complete decision equal to its explicit basis.

    Absence of a literal basis is never a refutation.  A kind with an APPLIES or
    audited DOES_NOT_APPLY basis must equal that basis exactly.  Any other kind may
    hold only a validated UNRESOLVED candidate; a complete APPLIES or DOES_NOT_APPLY
    decision there is rejected as unbacked, not erased.
    """
    code = "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
    if _shared._basis(review, kind) in {"APPLIES", "DOES_NOT_APPLY"}:
        return _shared._preserve_explicit_decision(
            decision,
            _explicit_decision(object_id, review, kind, evidence_by_path),
            files,
            owned,
            object_id=object_id,
            kind=kind,
        )
    if _shared._unresolved_decision(decision, files, owned, kind=kind, code=code):
        return type(decision) is dict and bool(decision["evidence"])
    if type(decision) is dict and decision.get("status") in {
        "APPLIES",
        "DOES_NOT_APPLY",
    }:
        raise ValueError(
            "PACKAGE_SEMANTIC_REVIEW_UNBACKED_DECISION:" + object_id + ":" + kind
        )
    raise ValueError(code)


def apply_package_semantic_review_verifier(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply the complete eight-object source-bound review atomically."""
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
            for row in _shared._contract_rows(kind)
        }
        for kind in REVIEW_KINDS
    }
    # OBJECT is the generic fallback, never a registered question, so it cannot
    # be a classification key.  Matches the original-kind review computation.
    registered_questions = set(namespace_registry()) - {"OBJECT"}
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
        universe = _evidence_universe(object_id, review)
        current = _shared._current_evidence(
            selected_root, universe, files, object_id=object_id
        )
        evidence_by_path = {item["path"]: item for item in current}

        classification = row.get("classification")
        obligations = row.get("obligations")
        specializations = row.get("specializations")
        if type(classification) is not dict or type(obligations) is not dict:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + object_id)
        # Roles accumulate only over this review's denominator.  A registered
        # kind outside it (for example OBJECT) cannot be minted as a role label.
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
        # Kinds outside the denominator belong to other partitions and are kept
        # verbatim, but every key must still be a registered question name.
        if any(
            type(kind) is not str or kind not in registered_questions
            for kind in classification
        ):
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_CLASSIFICATION_KIND_UNKNOWN:" + object_id
            )
        for kind in REVIEW_KINDS:
            if kind not in review.applicable and (
                row["kind"] == kind or kind in specializations
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id + ":" + kind
                )

        # Obligation names are exact registered ids.  Only registered obligations
        # of the denominator exist, so a foreign prefix, a case variant, or an
        # invented id under any registered kind must not survive unvalidated.
        known_obligations = {
            name for values in live_obligations.values() for name in values
        }
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
        for kind in REVIEW_KINDS:
            applies = _shared._basis(review, kind) == "APPLIES"
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
                        _shared._obligation_reason(review.profile, kind),
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
            "universe": universe,
            "opening_evidence": current,
            "evidence_by_path": evidence_by_path,
            "preserve_decisions": preserve_decisions,
            "preserve_obligations": preserve_obligations,
            "remove_obligations": remove_obligations,
        }

    # A concurrent writer cannot leave only a prefix of this owned review current.
    for object_id, review in _REVIEWS.items():
        closing = _shared._source_evidence(selected_root, plans[object_id]["universe"])
        if closing != plans[object_id]["opening_evidence"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)

    result = deepcopy(rows)
    for object_id, review in _REVIEWS.items():
        row = result[object_id]
        plan = plans[object_id]
        declarations = _shared._declarations(review)
        for kind in REVIEW_KINDS:
            if kind in plan["preserve_decisions"]:
                continue
            if _shared._basis(review, kind) in {"APPLIES", "DOES_NOT_APPLY"}:
                row["classification"][kind] = _explicit_decision(
                    object_id, review, kind, plan["evidence_by_path"]
                )
            else:
                row["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": _cell_reason(object_id, review, kind),
                    "evidence": [],
                }
        for name in plan["remove_obligations"]:
            row["obligations"].pop(name, None)
        for name, declaration in declarations.items():
            if name in plan["preserve_obligations"]:
                continue
            kind = name.split("-", 1)[0]
            row["obligations"][name] = {
                "reason": _shared._obligation_reason(review.profile, kind),
                "evidence": _role_evidence(review, kind, plan["evidence_by_path"]),
                "declaration": dict(declaration),
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)
    return result


__all__ = [
    "CLAIM_BOUNDARY",
    "OBLIGATION_RETENTION_APPLIES",
    "REVIEW_KINDS",
    "VERIFIER_OBJECT_IDS",
    "apply_package_semantic_review_verifier",
    "obligation_retention_reason",
    "review_document",
]
