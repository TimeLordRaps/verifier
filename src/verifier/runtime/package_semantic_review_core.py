"""Current-source Tier-0 semantic review for the retained VERIFIER core.

Terminology: application programming interface (API); abstract syntax tree
(AST); directed acyclic graph (DAG); JavaScript Object Notation (JSON); Secure
Hash Algorithm 256-bit (SHA-256).

``verifier-core-self`` retains nineteen source files after specialized path
owners have been split from the historical catch-all object.  This module
reviews those exact bytes against the twelve added consequence kinds. Every role
applies: seven are direct retained verifier mechanisms, while five remain required
because the witness runner launches caller-selected subject code without a closed
physical or financial effect boundary. Applicability keeps those obligations in
scope; it does not claim that their higher-tier mechanisms pass.

The review is declarative.  It does not execute a verifier, prove the
declarations, establish higher-tier polish, or authorize physical, financial,
publication, release, or deployment effects.  Application validates every
source and existing binding before mutating a deep copy, then recaptures the
complete source denominator so concurrent drift cannot produce a partial
review.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime import package_semantic_review_operations as _shared


CORE_OBJECT_ID = "verifier-core-self"
CORE_PATHS = (
    "src/verifier/domains/verifier.py",
    "src/verifier/domains/verifier_bootstrap.py",
    "src/verifier/domains/contracts/verifier_coverage_closure.py",
    "src/verifier/domains/contracts/verifier_composed_security.py",
    "src/verifier/domains/contracts/verifier_replacement.py",
    "src/verifier/runtime/package_review_stage_gaps.py",
    "src/verifier/runtime/package_verifier_graph.py",
    "src/verifier/runtime/tier_zero_reasoning/__init__.py",
    "src/verifier/runtime/tier_zero_reasoning/binding_registry.py",
    "src/verifier/runtime/tier_zero_reasoning/cli.py",
    "src/verifier/runtime/tier_zero_reasoning/conditional_dispatch.py",
    "src/verifier/runtime/tier_zero_reasoning/effect_reach_prototype.py",
    "src/verifier/runtime/tier_zero_reasoning/integration.py",
    "src/verifier/runtime/tier_zero_reasoning/project_effect_first.py",
    "src/verifier/runtime/tier_zero_reasoning/reasons_check.py",
    "src/verifier/runtime/tier_zero_reasoning/reasons_dsl.py",
    "src/verifier/runtime/tier_zero_reasoning/redundancy_obligations.py",
    "src/verifier/runtime/tier_zero_reasoning/replace_codec_probe.py",
    "src/verifier/runtime/tier_zero_reasoning/witness_runner.py",
)
_COVERAGE_PATHS = (
    "src/verifier/domains/contracts/verifier_coverage_closure.py",
)
_PROTOCOL_PATHS = (
    "src/verifier/domains/verifier_bootstrap.py",
    "src/verifier/domains/contracts/verifier_composed_security.py",
    "src/verifier/domains/contracts/verifier_replacement.py",
)

REVIEW_KINDS = _shared.REVIEW_KINDS
APPLICABLE_KINDS = (
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
REFUTED_KINDS: tuple[str, ...] = ()
_WITNESS_EFFECT_PATHS = (
    "src/verifier/runtime/tier_zero_reasoning/conditional_dispatch.py",
    "src/verifier/runtime/tier_zero_reasoning/integration.py",
    "src/verifier/runtime/tier_zero_reasoning/witness_runner.py",
)
_LEDGER_PATHS = (
    "src/verifier/runtime/package_review_stage_gaps.py",
    "src/verifier/runtime/tier_zero_reasoning/integration.py",
    "src/verifier/runtime/tier_zero_reasoning/reasons_check.py",
)
ROLE_PATHS = {
    "LEDGER": _LEDGER_PATHS,
    "TRANSACTION": _COVERAGE_PATHS,
    "ASSET": CORE_PATHS,
    "MARKET": _WITNESS_EFFECT_PATHS,
    "MEASUREMENT": CORE_PATHS,
    "SENSOR": CORE_PATHS,
    "CONTROLLER": _COVERAGE_PATHS,
    "ACTUATOR": _COVERAGE_PATHS,
    "PROTOCOL": _PROTOCOL_PATHS,
    "POLICY": CORE_PATHS,
    "ROBOT": _WITNESS_EFFECT_PATHS,
    "FINBOT": _WITNESS_EFFECT_PATHS,
}

CLAIM_BOUNDARY = (
    "Exact-current-source Tier-0 applicability and declaration review for the "
    "nineteen retained verifier-core-self files only. It does not establish mechanism "
    "execution or truth, whole-package completeness, Tier-1-plus conformance, "
    "general verifier soundness, physical or financial safety, publication, "
    "release, or deployment."
)


_BASE_PROFILE = _shared._Profile(
    name="retained VERIFIER core",
    scope=(
        "Validate finite selected VERIFIER artifacts, policies, requests, retained "
        "evidence, native replay outcomes, canonical certificates, and selected "
        "test or observer witnesses within the nineteen exact retained source files."
    ),
    mechanism=(
        "Strict bounded record validation, digest and signature binding, finite proof "
        "or route replay, explicit PASS/FAIL/UNKNOWN aggregation, and canonical "
        "certificate reconstruction, plus explicit child-process witness execution."
    ),
    participants=(
        "The local caller, selected VERIFIER subject, exact retained evidence and "
        "policies, installed verification routes, admitted trust roots, the selected "
        "witness subject, and the consumer of the returned decision."
    ),
    inputs=(
        "Canonical bounded requests, policies, subject identities, retained evidence "
        "and certificates, exact digests, finite limits, route selections, and "
        "explicit trust roots."
    ),
    authority=(
        "Only the caller-selected policy, installed route registry, and admitted trust "
        "roots authorize the named local verification step. No human, legal, physical, "
        "financial, publication, release, or deployment authority is created."
    ),
    states=(
        "Unselected, admitted, evaluating, replaying, PASS, FAIL, UNKNOWN, unavailable, "
        "refused, exhausted, changed-source, and reproduced states remain distinct."
    ),
    ordering=(
        "Validate selection, policy, digests, limits, and evidence before native replay; "
        "aggregate explicit outcomes before certificate construction; recheck canonical "
        "bytes and source bindings before accepting a retained result."
    ),
    commands=(
        "Invoke installed finite verification or replay routes and, when explicitly "
        "selected, launch the named test or observer subject in a child process."
    ),
    targets=(
        "Exact requests, policies, retained source-bound artifacts, installed replay "
        "routes, and caller-selected witness subjects executed in a child process."
    ),
    effect_domains=(
        "LOCAL_VERIFICATION_AND_SELECTED_CHILD_EXECUTION; the verifier bounds its own "
        "inputs and receipts, but does not establish that a selected witness subject "
        "cannot reach physical, financial, network, process, or filesystem effects."
    ),
    effects=(
        "Read and validate selected values, execute an admitted local route or selected "
        "witness child, and return a typed decision, receipt, or canonical certificate."
    ),
    commit=(
        "Commit is only a canonical result for the exact selected subject, request, "
        "policy, evidence, mechanism, source, and finite limits; excluded propositions "
        "remain NOT_ESTABLISHED."
    ),
    retry=(
        "A repeated call is a fresh evaluation of current bytes. Exact identities can "
        "detect substitution or duplicate selection but do not imply external "
        "idempotency."
    ),
    timing=(
        "Only source order, retained-event order, bounded operation counts, and explicit "
        "local completion are represented; no hard-real-time or eventual-progress "
        "guarantee is inferred."
    ),
    limits=(
        "Finite canonical bytes, items, operations, members, cases, evidence, registered "
        "routes, timeouts, selected algorithms, and source digests fail closed; the "
        "child subject's downstream effect envelope is not proven closed."
    ),
    observations=(
        "Selected identities and digests, parsed fields, proof and route outcomes, "
        "member and boundary counts, signature results, child return codes, coverage, "
        "audit events, explicit gaps, and typed PASS/FAIL/UNKNOWN status."
    ),
    units=(
        "Exact bytes, dimensionless item/operation/member counts, finite Boolean "
        "assignments, route outcomes, and SHA-256 identities."
    ),
    failure=(
        "Malformed, contradictory, substituted, over-limit, or reproduced-negative "
        "evidence or child execution fails; missing, unsupported, unobservable, cancelled, "
        "timed-out, or unavailable evidence remains UNKNOWN and is never promoted to PASS."
    ),
    recovery=(
        "Preserve the prior decision, correct or reselect the exact bounded input, "
        "policy, source, trust root, or route, and perform a separate fresh evaluation."
    ),
    boundary=(
        "The retained sources implement bounded VERIFIER checks and selected child "
        "witness execution. They do not establish universal soundness, external truth, "
        "whole-package polish, physical or financial safety, or downstream effect absence."
    ),
)


# Declaration vocabulary is role-specific even though every role belongs to the
# same retained object.  This prevents, for example, protocol declarations from
# borrowing the coverage-closure path or controller declarations from borrowing
# the signed-association paths.
_ROLE_PROFILES = {
    "LEDGER": replace(
        _BASE_PROFILE,
        name="verifier obligation and witness ledger",
        scope=(
            "Retain ordered review gaps, authored reason decisions, witness outcomes, "
            "source coordinates, and typed status transitions for one exact run."
        ),
        states=(
            "Prepared, running, HOLDS, REFUTED, UNKNOWN, failed, timed-out, stale-source, "
            "and reconciled entries remain distinct and append as new observations."
        ),
        ordering=(
            "Bind source and reason identities before execution, retain each child result "
            "before aggregation, and reconcile only against the same current coordinate."
        ),
        effects=(
            "Append exact gap, decision, witness, and execution observations to the local "
            "run record; no financial balance or external settlement is represented."
        ),
        commit=(
            "Commit is one digest-bound local decision or witness receipt at its source "
            "coordinate; existing history is not rewritten into a stronger status."
        ),
        units="Ordered discrete entries, byte counts, exit codes, status counts, and SHA-256 identities.",
        recovery=(
            "Preserve prior entries, repair the named source, reason, observer, or runner, "
            "then append a separately identified fresh execution and reconciliation."
        ),
        boundary=(
            "This is an evidence and obligation ledger, not a monetary ledger; its entries "
            "bind local observations but do not make their claims independently true."
        ),
    ),
    "TRANSACTION": replace(
        _BASE_PROFILE,
        name="VERIFIER finite coverage-closure transaction",
        scope=(
            "Build or recheck one canonical VERIFIER-4.1 certificate for an exact "
            "selected finite claim class, DAG bundle, boundary-case set, and policy."
        ),
        mechanism=(
            "verifier_coverage_closure.py validates the complete selection, replays "
            "members and declared counterexample boundaries, aggregates outcomes, and "
            "constructs one digest-bound certificate."
        ),
        effects=(
            "Perform the admitted finite replays and either commit one canonical "
            "certificate result or return/refuse without asserting broader closure."
        ),
        commit=(
            "Commit is the canonical VERIFIER-4.1 certificate for the exact request and "
            "policy after finite member and boundary aggregation; missing evidence "
            "remains UNKNOWN and a contradiction remains FAIL."
        ),
        retry=(
            "Request, policy, evidence, and certificate digests identify duplicate "
            "selection; every build or recheck still performs a fresh bounded replay."
        ),
        observations=(
            "Enumerated members, boundary cases, DAG assessment, direct and qualified "
            "statuses, replay outcomes, explicit unknowns, and final certificate bytes."
        ),
        boundary=(
            "The transaction ends at one local canonical coverage certificate; it does "
            "not commit whole-VERIFIER correctness, class adequacy, release, or any "
            "external effect."
        ),
    ),
    "ASSET": replace(
        _BASE_PROFILE,
        name="retained verifier evidence-asset surface",
        scope=(
            "Identify and retain exact source, policy, certificate, reason, and witness "
            "artifacts as digest-bound digital assets of one verification run."
        ),
        inputs=(
            "Exact artifact bytes, object and reason identifiers, source coordinates, "
            "digests, policies, receipts, and caller-selected retention paths."
        ),
        authority=(
            "The caller may select and retain local verification artifacts only; no legal "
            "title, transferable property right, issuance, redemption, or financial claim is created."
        ),
        targets=(
            "Digest-bound local source, reason, certificate, report, and witness artifacts "
            "at caller-selected paths under the current repository or output boundary."
        ),
        units="Exact bytes, artifact counts, record counts, and SHA-256 identities; no monetary quantity is represented.",
        effects=(
            "Create or retain a new local evidence artifact or receipt under explicit "
            "caller selection; source artifacts are never silently overwritten as proof."
        ),
        recovery=(
            "Preserve the prior digest, recapture or regenerate the exact artifact under a "
            "new identity, and reconcile references without claiming legal redemption."
        ),
        boundary=(
            "Asset applicability is limited to controlled digital evidence artifacts; it "
            "does not establish ownership, custody law, market value, backing, or redemption."
        ),
    ),
    "MARKET": replace(
        _BASE_PROFILE,
        name="unconfined market-capable witness boundary",
        scope=(
            "Execute a caller-selected witness subject that may implement orders, matching, "
            "allocation, pricing, or settlement; retain those obligations because reach is not excluded."
        ),
        participants=(
            "The selecting caller, witness runner, child process, selected subject, and any "
            "participants or services that subject reaches; their authority is not inferred."
        ),
        authority=(
            "The verifier authorizes only local witness execution. It grants no trading, "
            "matching, allocation, pricing, settlement, account, or participant authority."
        ),
        states=(
            "Selected, launched, running, observed, HOLDS, REFUTED, UNKNOWN, timed-out, and "
            "failed are verifier states; subject market states remain independently unestablished."
        ),
        commands=(
            "Launch only the named witness subject and record its outcome; no native order, "
            "match, allocation, cancellation, price, or settlement command is supplied."
        ),
        targets="The selected child subject and any market-like endpoints it can reach; reach is not a grant of authority.",
        effects=(
            "The child may produce market-like effects that the verifier does not prove "
            "confined; the retained verifier effect is execution plus bounded observation."
        ),
        commit="Only the witness receipt commits; no order, match, price, allocation, or settlement finality is claimed.",
        units="Child exit codes, event and coverage counts, exact bytes and digests; no price, currency, lot, or quantity unit is assumed.",
        failure=(
            "Unobserved, unauthorized, unavailable, timed-out, or nonzero child behavior is "
            "FAIL or UNKNOWN and never becomes evidence of market safety or settlement."
        ),
        recovery="Stop at the bounded child result, preserve evidence, repair the selected witness, and rerun without retrying market effects.",
        boundary=(
            "MARKET is retained because selected child reach is not closed. The verifier "
            "does not itself establish a market mechanism or authorize real trading."
        ),
    ),
    "MEASUREMENT": replace(
        _BASE_PROFILE,
        name="retained VERIFIER digital measurement surface",
        mechanism=(
            "The retained core source set parses exact bounded inputs and derives "
            "digital counts, digests, signature results, route outcomes, gaps, and typed "
            "status without treating supplied labels as observations."
        ),
        observations=(
            "The measured phenomena are exact bytes and digests, finite formula or DAG "
            "structure, assignments, members, boundaries, replay and signature outcomes, "
            "and explicit missing or contradictory evidence."
        ),
        units=(
            "Bytes, dimensionless variables/assignments/items/operations/members/cases, "
            "ordered status records, and SHA-256 identities; no physical unit is inferred."
        ),
        timing=(
            "Each observation belongs to the current local invocation and retained "
            "ordering; the files do not infer physical event time or future freshness."
        ),
        boundary=(
            "Measurements are bounded digital checker observations from the exact retained "
            "sources, not external factual truth, physical telemetry, or universal "
            "verifier correctness."
        ),
    ),
    "SENSOR": replace(
        _BASE_PROFILE,
        name="retained VERIFIER evidence sensor",
        mechanism=(
            "The retained core source set acquires caller-selected canonical records and "
            "retained bytes through strict parsers, digest/signature checks, and installed "
            "finite replay routes, exposing faults rather than filling missing evidence."
        ),
        observations=(
            "Acquired observations are the accepted fields, exact byte identities, "
            "finite replay outputs, signature results, source/mechanism pins, and explicit "
            "FAIL or UNKNOWN causes."
        ),
        targets=(
            "The deployment surface is the local process and the exact selected retained "
            "records and installed routes; there is no physical sensor deployment."
        ),
        limits=(
            "Acquisition accepts only canonical bounded records, exact digests, admitted "
            "keys and routes, finite counts and bytes, and the algorithms encoded by the "
            "retained core source set."
        ),
        failure=(
            "Malformed, substituted, contradictory, duplicated, or invalid evidence is "
            "detected as failure; absent, unsupported, cancelled, exhausted, or unavailable "
            "acquisition remains UNKNOWN."
        ),
        boundary=(
            "This is digital evidence acquisition, not metrological calibration, physical "
            "sensing, complete environment observation, or proof that unobserved effects "
            "did not occur."
        ),
    ),
    "CONTROLLER": replace(
        _BASE_PROFILE,
        name="VERIFIER finite coverage-closure controller",
        scope=(
            "Drive one bounded VERIFIER-4.1 evaluation toward the declared objective: "
            "every enumerated member and selected counterexample boundary must reach its "
            "required native replay state."
        ),
        observations=(
            "Feedback consists of DAG assessment state, each member's direct and "
            "qualified status, each boundary replay outcome, budget use, and explicit "
            "failure or unknown sets."
        ),
        commands=(
            "Select and invoke only registered member and boundary replay routes, update "
            "the bounded aggregate state, and emit the resulting local decision."
        ),
        authority=(
            "The exact VERIFIER-4.1 request and policy authorize only their finite local "
            "member and boundary replays; they grant no arbitrary process, physical, "
            "financial, release, or deployment authority."
        ),
        limits=(
            "Finite members, nodes, boundary cases, artifact files, operations, items, "
            "evidence bytes, installed routes, and a nonreentrant local evaluation bound "
            "the control loop."
        ),
        failure=(
            "Contradictory feedback produces FAIL; missing or unavailable feedback, "
            "budget exhaustion, unregistered routes, or absent cases produce UNKNOWN "
            "rather than an optimistic closure decision."
        ),
        recovery=(
            "Leave the prior result intact, restore a complete exact selection or "
            "available route, and start a fresh nonnested coverage evaluation."
        ),
        boundary=(
            "This controller governs a bounded in-process verification lifecycle, not a "
            "physical plant, general scheduler, whole-package polish loop, or downstream "
            "safety controller."
        ),
    ),
    "ACTUATOR": replace(
        _BASE_PROFILE,
        name="VERIFIER coverage native-replay actuator",
        commands=(
            "Dispatch only the exact installed DAG assessment and registered current-object "
            "boundary replay selected by verifier_coverage_closure.py."
        ),
        targets=(
            "Selected in-memory retained artifacts and installed verification route "
            "functions named by the bounded coverage request; no arbitrary command, "
            "physical endpoint, or financial endpoint."
        ),
        effect_domains=(
            "TRUSTED_LOCAL_VERIFICATION_REPLAY_ONLY; selected Python verification code "
            "executes in process and returns typed decisions, with no represented physical "
            "or real-money effect domain."
        ),
        observations=(
            "Response feedback is each registered route's reproduced computational status "
            "or explicit unavailable/refused/unknown outcome plus aggregate budget state."
        ),
        limits=(
            "Only installed selected routes, finite members and boundary cases, bounded "
            "bytes/items/operations, and a nonnested coverage evaluation are admitted."
        ),
        failure=(
            "Unregistered, unavailable, refused, mismatched, over-limit, or nonreproducing "
            "replay is retained as FAIL or UNKNOWN and cannot be converted to an effect."
        ),
        ordering=(
            "Validate all request, policy, digest, and route bindings before dispatch; "
            "collect each bounded response before committing the aggregate certificate."
        ),
        recovery=(
            "Do not retry implicitly; repair the exact route or retained evidence and "
            "perform a separate fresh coverage evaluation."
        ),
        boundary=(
            "Actuation ends at calls to registered local verification routes and their "
            "typed responses; it is not process confinement, physical actuation, money "
            "movement, publication, or deployment."
        ),
    ),
    "PROTOCOL": replace(
        _BASE_PROFILE,
        name="retained VERIFIER signed-evidence protocol",
        scope=(
            "Exchange exact bootstrap, composed-security, and replacement selections, "
            "signed admissions/attestations, retained evidence, and canonical results "
            "across explicit participant roles."
        ),
        participants=(
            "The selecting caller, finite bootstrap oracle or installed child checkers, "
            "admitted signing authorities and observers, selected VERIFIER subject, "
            "and the certificate consumer."
        ),
        states=(
            "Selected, admitted, signed, verified, replaying, reproduced, unavailable, "
            "revoked, incomplete, PASS, FAIL, and UNKNOWN protocol states remain distinct."
        ),
        ordering=(
            "Bind the exact selection and policy before evidence exchange; verify purpose, "
            "identity, signatures, revocation and observer records before result acceptance; "
            "reconstruct the canonical certificate on recheck."
        ),
        retry=(
            "Digests and signed operation/selection identities detect substitution and "
            "replay; a later invocation is a fresh protocol run and never silently "
            "upgrades an unavailable or negative carried result."
        ),
        mechanism=(
            "verifier_bootstrap.py, verifier_composed_security.py, and "
            "verifier_replacement.py validate canonical message fields, exact scope, "
            "signatures, retained payloads, ordered lifecycle evidence, and replay parity."
        ),
        timing=(
            "Protocol order and selected epochs are checked where represented, but no "
            "network delivery, hard deadline, or eventual participant progress is promised."
        ),
        failure=(
            "Wrong purpose, identity, ordering, signature, revocation, selection, or "
            "canonical bytes fails; a missing checker, key, observer, or retained payload "
            "remains UNKNOWN."
        ),
        recovery=(
            "Preserve the carried result, obtain the exact missing independently admitted "
            "record or checker, and execute a fresh complete protocol replay."
        ),
        boundary=(
            "The protocol binds finite local verifier evidence and authority statements; "
            "it does not establish organizational independence, network reliability, "
            "universal soundness, or external effect authority."
        ),
    ),
    "POLICY": replace(
        _BASE_PROFILE,
        name="retained VERIFIER admission policy",
        scope=(
            "Define which verifier kinds, finite proposition classes, evidence shapes, "
            "trust roots, routes, bounds, signatures, lifecycle records, and excluded "
            "claims may participate in these retained mechanisms."
        ),
        inputs=(
            "Exact artifact and subject identities, claim classes, requests, policies, "
            "limits, trust roots, signed records, retained evidence, route registrations, "
            "and source/mechanism digests."
        ),
        ordering=(
            "Hard schema, identity, scope, digest, bound, and route requirements precede "
            "evidence evaluation; refutations outrank unavailable evidence; exclusions "
            "remain NOT_ESTABLISHED even after a local PASS."
        ),
        authority=(
            "Authority is restricted to caller selection plus explicit policy trust roots "
            "and purpose-specific signed admissions. Self-assertion and bare digests do "
            "not create bootstrap, observer, physical, financial, or release authority."
        ),
        states=(
            "Inactive until an exact policy and request are admitted; then selected, "
            "evaluating, PASS, FAIL, UNKNOWN, unavailable, revoked, or reproduced."
        ),
        limits=(
            "Unsupported classes, self-reference, unregistered routes, excess bytes or "
            "counts, wrong trust roots, incomplete evidence, and excluded claims cannot "
            "bypass the five mechanisms' explicit finite boundaries."
        ),
        mechanism=(
            "Feature-near validators in the retained core source set enforce exact schemas, identities, "
            "bounds, route selection, authority purpose, and fail/unknown precedence "
            "before a result can commit."
        ),
        observations=(
            "Decision evidence includes the exact admitted inputs, policy/mechanism/source "
            "digests, signature and route outcomes, finite counts, explicit missingness, "
            "and excluded propositions."
        ),
        failure=(
            "Invalid or contradictory selection is rejected; missing independent authority, "
            "evidence, route, source, or checker remains UNKNOWN. No permissive default or "
            "unstated exception is admitted."
        ),
        boundary=(
            "This policy governs only the retained local VERIFIER mechanisms and "
            "their exact finite claims; it is not legal policy, package release authority, "
            "physical safety policy, or financial governance."
        ),
    ),
    "ROBOT": replace(
        _BASE_PROFILE,
        name="unconfined robot-capable witness boundary",
        scope=(
            "Execute a caller-selected witness subject that may connect agents, harnesses, "
            "controllers, actuators, or physical endpoints; retain obligations because reach is not excluded."
        ),
        participants="The selecting caller, witness runner, child subject, and any controller or actuator that subject reaches.",
        authority=(
            "The verifier authorizes only local witness execution. It grants no robot, "
            "controller, actuator, device, facility, or physical intervention authority."
        ),
        commands=(
            "Launch only the named witness subject and record its outcome; no native robot, "
            "controller, actuator, motion, or physical-intervention command is supplied."
        ),
        targets="The selected child subject and any device or actuator endpoints it can reach; physical reach is not proven confined.",
        effect_domains=(
            "SELECTED_CHILD_WITH_UNCLOSED_PHYSICAL_REACH; local execution is observed, but "
            "device, actuator, facility, and environmental effects are not independently excluded."
        ),
        effects=(
            "The child may produce robot or physical effects outside the verifier's observed "
            "receipt; applicability preserves those obligations without asserting occurrence."
        ),
        limits=(
            "Child timeout, exact subject identity, source digest, return code, coverage, and "
            "observer events bound the receipt; they do not prove physical confinement or a safe envelope."
        ),
        observations=(
            "Child return code, named-subject coverage, declared observable audit events, "
            "stdout/stderr digests, and explicit missing or blind event classes."
        ),
        units="Exit codes, event and coverage counts, bytes, and digests; no physical frame or engineering unit is inferred.",
        failure=(
            "Missing coverage, observer blind spots, timeout, unavailable subject, or nonzero "
            "execution stays UNKNOWN or FAIL; no physical safe state is inferred."
        ),
        recovery="Preserve the receipt, stop at the child boundary, repair the witness or confinement evidence, and run a fresh observation.",
        boundary=(
            "ROBOT is retained because child reach is not closed. The verifier does not "
            "establish physical command authority, confinement, hazard control, or safe state."
        ),
    ),
    "FINBOT": replace(
        _BASE_PROFILE,
        name="unconfined financial-agent witness boundary",
        scope=(
            "Execute a caller-selected witness subject that may combine automated decisions "
            "with assets, accounts, markets, or financial effects; retain obligations because reach is not excluded."
        ),
        participants="The selecting caller, witness runner, child subject, and any parties, accounts, venues, or services it reaches.",
        authority=(
            "The verifier authorizes only local witness execution. It grants no account, "
            "asset, trading, payment, transfer, settlement, advisory, or fiduciary authority."
        ),
        commands=(
            "Launch only the named witness subject and record its outcome; no native order, "
            "payment, transfer, allocation, account, or settlement command is supplied."
        ),
        targets="The selected child subject and any financial parties, accounts, assets, venues, or endpoints it can reach.",
        effect_domains=(
            "SELECTED_CHILD_WITH_UNCLOSED_FINANCIAL_REACH; local execution is observed, but "
            "real-money, account, asset, market, payment, and settlement effects are not excluded."
        ),
        effects=(
            "The child may produce financial-agent effects outside the verifier's receipt; "
            "applicability retains the obligations without asserting that an effect occurred."
        ),
        limits=(
            "Child timeout, exact subject identity, source digest, return code, coverage, and "
            "observer events bound the receipt; no exposure, position, loss, or transaction limit is enforced."
        ),
        observations=(
            "Child return code, named-subject coverage, declared observable audit events, "
            "stdout/stderr digests, and explicit missing or blind event classes."
        ),
        units="Exit codes, event and coverage counts, bytes, and digests; no currency, price, quantity, or exposure unit is inferred.",
        failure=(
            "Missing coverage, observer blind spots, timeout, unavailable subject, or nonzero "
            "execution stays UNKNOWN or FAIL; no financial safety or limit compliance is inferred."
        ),
        recovery="Preserve the receipt, stop at the child boundary, repair the witness or effect controls, and run a fresh observation.",
        boundary=(
            "FINBOT is retained because child reach is not closed. The verifier does not "
            "establish financial authority, exposure control, intervention, or reconciliation."
        ),
    ),
}


_REASONS = {
    "LEDGER": (
        "verifier-core-self applies as LEDGER because the retained reasoning and integration "
        "sources preserve ordered gap, reason, witness, source-coordinate, and typed outcome "
        "records whose reconciliation and correction semantics must remain explicit."
    ),
    "TRANSACTION": (
        "verifier-core-self applies as TRANSACTION because "
        "verifier_coverage_closure.py coordinates selected member and boundary replays "
        "into one canonical certificate commit with explicit FAIL/UNKNOWN partial-failure "
        "and fresh-replay behavior; a generic VERIFIER label would hide that finality boundary."
    ),
    "ASSET": (
        "verifier-core-self applies as ASSET because it identifies and retains source, reason, "
        "certificate, report, and witness artifacts as digest-bound digital assets with explicit "
        "selection, retention, reconciliation, and non-property boundaries."
    ),
    "MARKET": (
        "verifier-core-self applies as MARKET because witness_runner.py launches caller-selected "
        "subject code whose market effects are not proven unreachable; applicability retains the "
        "obligations without claiming a native market or real trading authority."
    ),
    "MEASUREMENT": (
        "verifier-core-self applies as MEASUREMENT because the retained core sources derive "
        "bounded digital observations such as digests, counts, assignments, signatures, "
        "route outcomes, and explicit missingness from exact selected inputs."
    ),
    "SENSOR": (
        "verifier-core-self applies as SENSOR because the retained core sources acquire and "
        "validate exact evidence through parsers, digest/signature checks, and finite replay "
        "interfaces with explicit range, drift, and fault boundaries."
    ),
    "CONTROLLER": (
        "verifier-core-self applies as CONTROLLER because verifier_coverage_closure.py "
        "uses member and boundary feedback to govern a bounded nonnested evaluation and "
        "select PASS, FAIL, or UNKNOWN under explicit operating limits."
    ),
    "ACTUATOR": (
        "verifier-core-self applies as ACTUATOR because verifier_coverage_closure.py "
        "dispatches exact installed DAG and boundary replay routes and observes their "
        "typed local effects before committing the aggregate result."
    ),
    "PROTOCOL": (
        "verifier-core-self applies as PROTOCOL because verifier_bootstrap.py, "
        "verifier_composed_security.py, and verifier_replacement.py define ordered, "
        "purpose-bound exchanges among selectors, checkers, signers, observers, and "
        "certificate consumers with replay and failure rules."
    ),
    "POLICY": (
        "verifier-core-self applies as POLICY because the retained core sources enforce "
        "feature-near rules for admitted claim classes, identities, trust roots, routes, "
        "bounds, evidence, exclusions, precedence, and unavailable behavior."
    ),
    "ROBOT": (
        "verifier-core-self applies as ROBOT because witness_runner.py launches caller-selected "
        "subject code whose device or physical effects are not proven unreachable; applicability "
        "retains the obligations without asserting actuation or physical authority."
    ),
    "FINBOT": (
        "verifier-core-self applies as FINBOT because witness_runner.py launches caller-selected "
        "subject code whose automated financial effects are not proven unreachable; applicability "
        "retains the obligations without asserting financial authority or occurrence."
    ),
}


def _evidence_paths(kind: str) -> tuple[str, ...]:
    basis = _basis(kind)
    if basis == "APPLIES":
        return ROLE_PATHS[kind]
    if basis == "DOES_NOT_APPLY":
        return CORE_PATHS
    return ()


def _basis(kind: str) -> str:
    """Return the explicit retained-core basis for one registered kind."""
    if kind in APPLICABLE_KINDS:
        return "APPLIES"
    if kind in REFUTED_KINDS:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _decision_reason(kind: str) -> str:
    if _basis(kind) == "UNRESOLVED":
        return _shared._unresolved_reason(kind)
    return _REASONS[kind]


def _explicit_decision(
    kind: str, evidence_by_path: Mapping[str, dict[str, str]]
) -> dict[str, Any]:
    basis = _basis(kind)
    if basis == "APPLIES":
        paths = ROLE_PATHS[kind]
    elif basis == "DOES_NOT_APPLY":
        paths = CORE_PATHS
    else:
        raise AssertionError("explicit decision requested for unlisted " + kind)
    return {
        "status": basis,
        "reason": _decision_reason(kind),
        "evidence": [deepcopy(evidence_by_path[path]) for path in paths],
    }


def _obligation_reason(kind: str) -> str:
    return (
        _REASONS[kind]
        + " This Tier-0 declaration names the exact reviewed source boundary "
        "only; mechanism execution, declaration truth, and Tier-1-plus "
        "fulfillment remain unestablished."
    )


def _declarations() -> dict[str, dict[str, str]]:
    """Build the exact live contract fields from role-specific vocabulary."""
    result: dict[str, dict[str, str]] = {}
    for kind in APPLICABLE_KINDS:
        try:
            selected = _shared._DECLARATION_BUILDERS[kind](_ROLE_PROFILES[kind])
        except KeyError as exc:
            raise AssertionError("missing declaration builder for " + kind) from exc
        overlap = set(result).intersection(selected)
        if overlap:
            raise AssertionError(
                "duplicate retained-core declaration ids: "
                + ", ".join(sorted(overlap))
            )
        result.update(selected)
    return result


def _catalog_check() -> None:
    if len(CORE_PATHS) != len(set(CORE_PATHS)) or len(CORE_PATHS) != 19:
        raise AssertionError("retained-core source denominator differs")
    explicit = set(APPLICABLE_KINDS) | set(REFUTED_KINDS)
    if explicit != set(_REASONS):
        raise AssertionError("retained-core classification matrix differs")
    if set(APPLICABLE_KINDS) & set(REFUTED_KINDS):
        raise AssertionError("retained-core role bases overlap")
    if not explicit <= set(REVIEW_KINDS):
        raise AssertionError("retained-core explicit role denominator differs")
    if set(APPLICABLE_KINDS) != set(ROLE_PATHS) != set(_ROLE_PROFILES):
        raise AssertionError("retained-core applicable-role denominator differs")
    if any(
        not paths or not set(paths) <= set(CORE_PATHS)
        for paths in ROLE_PATHS.values()
    ):
        raise AssertionError("retained-core role evidence leaves owned source")
    if any(not reason.strip() for reason in _REASONS.values()):
        raise AssertionError("retained-core reason is empty")

    expected = {
        row["id"]: set(row["declaration_fields"])
        for kind in APPLICABLE_KINDS
        for row in _shared._contract_rows(kind)
    }
    declarations = _declarations()
    if len(declarations) != 36 or set(declarations) != set(expected):
        raise AssertionError("retained-core declaration denominator differs")
    for obligation_id, fields in declarations.items():
        if set(fields) != expected[obligation_id] or any(
            type(value) is not str or not value.strip() or len(value) > 8192
            for value in fields.values()
        ):
            raise AssertionError(
                "retained-core declaration fields differ: " + obligation_id
            )


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return a defensive digest-free view of the complete retained-core review."""
    return {
        CORE_OBJECT_ID: {
            "primary_kind": "VERIFIER",
            "owned_paths": list(CORE_PATHS),
            "classification": {
                kind: {
                    "status": _basis(kind),
                    "reason": _decision_reason(kind),
                    "evidence_paths": list(_evidence_paths(kind)),
                }
                for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(_declarations()),
            "claim_boundary": CLAIM_BOUNDARY,
        }
    }


def review_counts() -> dict[str, int]:
    """Return exact denominators for integration diagnostics."""
    declarations = _declarations()
    return {
        "objects": 1,
        "paths": len(CORE_PATHS),
        "decisions": len(REVIEW_KINDS),
        "applies": len(APPLICABLE_KINDS),
        "does_not_apply": len(REFUTED_KINDS),
        "unresolved": len(REVIEW_KINDS)
        - len(APPLICABLE_KINDS)
        - len(REFUTED_KINDS),
        "declarations": len(declarations),
        "declaration_fields": sum(len(fields) for fields in declarations.values()),
    }


def _exact_evidence_paths(binding: Mapping[str, Any], paths: tuple[str, ...]) -> bool:
    evidence = binding.get("evidence")
    return type(evidence) is list and tuple(
        reference.get("path") if type(reference) is dict else None
        for reference in evidence
    ) == paths


def _reject_mutable_aliases(rows: Mapping[str, Any]) -> None:
    """Reject shared or cyclic JSON containers before planning any update.

    Manifest rows are value graphs, not Python object graphs.  A list or mapping
    reachable from two coordinates would let one object's review appear at a
    foreign referent after ``deepcopy`` preserves the alias.  A cycle is likewise
    not representable in ``objects.vstd``.  The first owner is retained in the
    diagnostic so a later foreign alias cannot hide the affected object.
    """
    seen: dict[int, str] = {}
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
            marker = id(value)
            if marker in seen:
                first_owner = seen[marker]
                affected = (
                    CORE_OBJECT_ID
                    if CORE_OBJECT_ID in {first_owner, str(object_id)}
                    else first_owner
                )
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_ALIAS_CONFLICT:" + affected
                )
            seen[marker] = str(object_id)
            pending.extend(children)


_PATH_TAKERS = frozenset(
    {"FileIO", "Path", "PurePath", "fdopen", "open", "read_bytes", "read_text"}
)
_SAFE_FLOW_CALLEES = frozenset(
    {"callable", "id", "isinstance", "issubclass", "len", "type"}
)
_EFFECT_MODULES = frozenset(
    {
        "aiohttp",
        "ctypes",
        "ftplib",
        "http",
        "httpx",
        "multiprocessing",
        "poplib",
        "requests",
        "shutil",
        "smtplib",
        "socket",
        "ssl",
        "subprocess",
        "urllib",
    }
)
_OS_EFFECT_NAMES = frozenset(
    {
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "fork",
        "forkpty",
        "popen",
        "posix_spawn",
        "posix_spawnp",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "startfile",
        "system",
    }
)


def _dotted_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


class _RefutationFlowGuard(ast.NodeVisitor):
    """Find callback and constructed-path flows a lexical channel scan misses.

    The transitive surface screen below already follows project imports and
    rejects dynamic loading, reflection, process/network channels and writes.
    This supplemental guard rejects caller-controlled callables passed through
    container/library APIs and non-literal paths.  It can only withhold a
    DOES_NOT_APPLY decision; it never infers an applicable role.
    """

    def __init__(self, local_defs: frozenset[str]) -> None:
        self.local_defs = local_defs
        self.frames: list[frozenset[str]] = []
        self.modules: set[str] = set()
        self.aliases: dict[str, str] = {}
        self.findings: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.modules.add(local)
            self.aliases[local] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = (
                    node.module + "." + alias.name
                )

    def _function(self, node: ast.AST) -> None:
        arguments = node.args  # type: ignore[attr-defined]
        names = {
            arg.arg
            for arg in (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            )
        }
        if arguments.vararg:
            names.add(arguments.vararg.arg)
        if arguments.kwarg:
            names.add(arguments.kwarg.arg)
        self.frames.append(frozenset(names))
        self.generic_visit(node)
        self.frames.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function
    visit_Lambda = _function

    def _is_parameter(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and any(
            node.id in frame for frame in self.frames
        )

    def _origin(self, node: ast.AST) -> str | None:
        dotted = _dotted_name(node)
        if dotted is None:
            return None
        head, separator, tail = dotted.partition(".")
        origin = self.aliases.get(head, head)
        return origin + (separator + tail if separator else "")

    def _effect_referent(self, node: ast.AST) -> str | None:
        origin = self._origin(node)
        if origin is None:
            return None
        head, _, tail = origin.partition(".")
        if head in _EFFECT_MODULES:
            return origin
        if head == "os" and tail.rsplit(".", 1)[-1] in _OS_EFFECT_NAMES:
            return origin
        return None

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        local = False
        name = ""
        if isinstance(func, ast.Name):
            if self._is_parameter(func):
                self.findings.add("CALLBACK:" + func.id)
            name = self.aliases.get(func.id, func.id).rsplit(".", 1)[-1]
            local = (
                func.id in self.local_defs or func.id in _SAFE_FLOW_CALLEES
            ) and not self._is_parameter(func)
        elif isinstance(func, ast.Attribute):
            name = func.attr

        values = [*node.args, *(keyword.value for keyword in node.keywords)]
        if not local:
            for value in values:
                target = value.value if isinstance(value, ast.Starred) else value
                if self._is_parameter(target):
                    self.findings.add("FLOW_ARGUMENT:" + target.id)
                effect = self._effect_referent(target)
                if effect is not None:
                    self.findings.add("EFFECT_CALLBACK:" + effect)

        if name in _PATH_TAKERS:
            self._path_call(node, func, name)
        self.generic_visit(node)

    def _path_call(self, node: ast.Call, func: ast.AST, name: str) -> None:
        if isinstance(func, ast.Attribute):
            receiver = func.value
            if isinstance(receiver, ast.Call):
                return
            if not (isinstance(receiver, ast.Name) and receiver.id in self.modules):
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


def _refutation_flow_findings(raw: bytes, path: str) -> tuple[str, ...]:
    """Return source-bound flow reasons that keep a refutation open."""
    try:
        tree = ast.parse(raw, filename=path)
    except (SyntaxError, ValueError):
        return ("PYTHON_SYNTAX_ERROR:" + path,)
    local_defs = frozenset(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    guard = _RefutationFlowGuard(local_defs)
    guard.visit(tree)
    return tuple(sorted(guard.findings))


def _refutation_surface(
    root: str | Path,
    paths: tuple[str, ...] = CORE_PATHS,
) -> dict[str, Any]:
    """Return the conservative transitive surface that may support a future DNE.

    This audit follows project imports through exact current bytes.  OPEN is a
    one-way result: it withholds a refutation but does not prove that any role
    applies.  The current core has no DNE decisions; its five unresolved kinds
    therefore remain unresolved regardless of disclaimer or absence text.
    """
    from verifier.runtime.package_semantic_review_records import (
        closed_surface_screen,
        screen_blocks,
    )

    selected_root = Path(root).resolve(strict=True)
    screen = closed_surface_screen(selected_root, paths)
    blockers = set(screen.blockers)
    flows: set[tuple[str, str]] = set()
    closure: list[dict[str, str]] = []
    for path, digest in screen.closure:
        candidate = selected_root.joinpath(*path.split("/"))
        try:
            resolved = candidate.resolve(strict=True)
            if (
                candidate.is_symlink()
                or not resolved.is_relative_to(selected_root)
                or not resolved.is_file()
            ):
                raise OSError
            raw = resolved.read_bytes()
        except OSError:
            blockers.add("SOURCE_UNAVAILABLE:" + path)
            continue
        current = "sha256:" + sha256(raw).hexdigest()
        if current != digest:
            blockers.add("SOURCE_CHANGED:" + path)
            continue
        closure.append({"path": path, "sha256": digest})
        if path.endswith(".py"):
            flows.update(
                (path, finding)
                for finding in _refutation_flow_findings(raw, path)
            )
    status = (
        "CLOSED"
        if screen.status == "CLOSED"
        and not screen.write_sites
        and not blockers
        and not flows
        else "OPEN"
    )
    blocked_kinds = tuple(
        kind
        for kind in REVIEW_KINDS
        if status == "OPEN" or screen_blocks(screen, kind)
    )
    return {
        "status": status,
        "closure": closure,
        "open_sites": list(screen.open_sites),
        "write_sites": list(screen.write_sites),
        "flow_findings": [list(item) for item in sorted(flows)],
        "blockers": sorted(blockers),
        "blocked_kinds": list(blocked_kinds),
    }


def apply_package_semantic_review_core(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply the one-object retained-core review atomically to a deep copy."""
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

    _reject_mutable_aliases(rows)

    row = rows.get(CORE_OBJECT_ID)
    if type(row) is not dict:
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_OBJECT_MISSING:" + CORE_OBJECT_ID)
    if row.get("object_id") != CORE_OBJECT_ID or row.get("kind") != "VERIFIER":
        raise ValueError(
            "PACKAGE_SEMANTIC_REVIEW_PRIMARY_KIND_DIFFERS:" + CORE_OBJECT_ID
        )
    owned = _shared._owned_file_paths(row)
    if owned != set(CORE_PATHS):
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_OWNERSHIP_DIFFERS:" + CORE_OBJECT_ID)
    current = _shared._current_evidence(
        selected_root,
        CORE_PATHS,
        files,
        object_id=CORE_OBJECT_ID,
    )
    evidence_by_path = {item["path"]: item for item in current}

    # A catalog author may never add a DOES_NOT_APPLY cell on prose alone.  The
    # expensive transitive screen is skipped while the catalog contains no DNE,
    # which is the current exact state (seven APPLIES, five UNRESOLVED).
    if REFUTED_KINDS:
        surface = _refutation_surface(selected_root)
        for kind in REFUTED_KINDS:
            if kind in surface["blocked_kinds"]:
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_REFUTATION_SURFACE_OPEN:"
                    + CORE_OBJECT_ID
                    + ":"
                    + kind
                )

    classification = row.get("classification")
    obligations = row.get("obligations")
    specializations = row.get("specializations")
    if type(classification) is not dict or type(obligations) is not dict:
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + CORE_OBJECT_ID)
    if (
        type(specializations) is not list
        or any(type(kind) is not str for kind in specializations)
        or len(specializations) != len(set(specializations))
    ):
        raise ValueError(
            "PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID:" + CORE_OBJECT_ID
        )
    # The twelve consequence kinds are OBJECT refinements and may therefore
    # label any primary kind.  A retained label is valid only when this exact
    # complete retained-core review establishes that the role applies; a refuted label must
    # fail rather than survive as an obligation escape hatch.
    for kind in REVIEW_KINDS:
        if kind not in APPLICABLE_KINDS and kind in specializations:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:"
                + CORE_OBJECT_ID
                + ":"
                + kind
            )

    live_obligations = {
        kind: {
            item["id"]: tuple(item["declaration_fields"])
            for item in _shared._contract_rows(kind)
        }
        for kind in REVIEW_KINDS
    }
    known_obligations = {
        obligation_id
        for selected in live_obligations.values()
        for obligation_id in selected
    }
    for obligation_id in obligations:
        if type(obligation_id) is not str or obligation_id not in known_obligations:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN:"
                + CORE_OBJECT_ID
                + ":"
                + str(obligation_id)
            )

    preserve_decisions: set[str] = set()
    preserve_obligations: set[str] = set()
    remove_obligations: set[str] = set()
    unresolved_candidates: dict[str, list[dict[str, str]]] = {}
    for kind in REVIEW_KINDS:
        basis = _basis(kind)
        decision = classification.get(kind)
        if basis == "UNRESOLVED":
            code = (
                "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:"
                + CORE_OBJECT_ID
                + ":"
                + kind
            )
            # Only a bounded UNRESOLVED candidate may be filled; any complete
            # APPLIES/DOES_NOT_APPLY text for an unlisted kind is a conflict.
            if not _shared._unresolved_decision(
                decision,
                files,
                owned,
                kind=kind,
                code=code,
            ):
                raise ValueError(code)
            if type(decision) is dict and decision["evidence"]:
                unresolved_candidates[kind] = [
                    deepcopy(evidence_by_path[reference["path"]])
                    for reference in decision["evidence"]
                ]
        elif _shared._preserve_explicit_decision(
            decision,
            _explicit_decision(kind, evidence_by_path),
            files,
            owned,
            object_id=CORE_OBJECT_ID,
            kind=kind,
        ):
            preserve_decisions.add(kind)

        for obligation_id, fields in live_obligations[kind].items():
            binding = obligations.get(obligation_id)
            if basis == "APPLIES":
                expected_evidence = [
                    deepcopy(evidence_by_path[path]) for path in ROLE_PATHS[kind]
                ]
                if _shared._preserve_explicit_obligation(
                    binding,
                    fields,
                    _obligation_reason(kind),
                    expected_evidence,
                    files,
                    owned,
                    object_id=CORE_OBJECT_ID,
                    obligation_id=obligation_id,
                ):
                    preserve_obligations.add(obligation_id)
            elif binding is not None:
                prefix = (
                    "PACKAGE_SEMANTIC_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                    if basis == "DOES_NOT_APPLY"
                    else "PACKAGE_SEMANTIC_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
                )
                code = prefix + CORE_OBJECT_ID + ":" + obligation_id
                if not _shared._blank_obligation(
                    binding,
                    fields,
                    files,
                    owned,
                    code=code,
                ):
                    raise ValueError(code)
                remove_obligations.add(obligation_id)

    # Re-read after every semantic conflict has passed. A concurrent source
    # writer cannot leave only a prefix of the complete retained-core review current.
    closing = _shared._source_evidence(selected_root, CORE_PATHS)
    if closing != current:
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + CORE_OBJECT_ID)

    result = deepcopy(rows)
    selected = result[CORE_OBJECT_ID]
    for kind in REVIEW_KINDS:
        if kind in preserve_decisions:
            continue
        if _basis(kind) == "UNRESOLVED":
            selected["classification"][kind] = {
                "status": "UNRESOLVED",
                "reason": _decision_reason(kind),
                "evidence": deepcopy(unresolved_candidates.get(kind, [])),
            }
        else:
            selected["classification"][kind] = _explicit_decision(
                kind, evidence_by_path
            )
    for obligation_id in remove_obligations:
        selected["obligations"].pop(obligation_id, None)
    for obligation_id, declaration in _declarations().items():
        if obligation_id in preserve_obligations:
            continue
        kind = obligation_id.split("-", 1)[0]
        selected["obligations"][obligation_id] = {
            "reason": _obligation_reason(kind),
            "evidence": [
                deepcopy(evidence_by_path[path]) for path in ROLE_PATHS[kind]
            ],
            "declaration": dict(declaration),
        }
    for kind in REVIEW_KINDS:
        if (
            kind in APPLICABLE_KINDS
            and kind != selected["kind"]
            and kind not in selected["specializations"]
        ):
            selected["specializations"].append(kind)
    return result


__all__ = [
    "APPLICABLE_KINDS",
    "CLAIM_BOUNDARY",
    "CORE_OBJECT_ID",
    "CORE_PATHS",
    "REFUTED_KINDS",
    "REVIEW_KINDS",
    "ROLE_PATHS",
    "apply_package_semantic_review_core",
    "review_counts",
    "review_document",
]
