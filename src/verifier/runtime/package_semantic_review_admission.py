"""Exact-source Tier-0 reviews for repository-admission support objects.

Terminology: application programming interface (API); abstract syntax tree
(AST); command-line interface (CLI); Hypertext Markup Language (HTML);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).

These thirteen objects implement the package marker, namespace discovery and
rule machinery, manifest admission, semantic-review policy, graph contracts,
instance and kind evidence, owner decisions, native-operation metadata, and
object-context closure.  This module answers only the added-kind admission
question for their exact current sources.  A kind is decided only when the
catalog names an explicit basis: applicable roles become APPLIES, explicit
refutations become DOES_NOT_APPLY, and every unlisted role stays canonical
UNRESOLVED.  Absence from an applicability tuple is never a refutation.  The
review does not turn structural data
into behavior truth, make a candidate normative, establish Tier-1-plus
conformance, or confer human, legal, physical, financial, release, or
deployment authority.

Application is pure, atomic, and fail closed.  The complete sixty-one-path
denominator is digest-checked before and after semantic preflight.  Existing
answers are preserved only when they are complete, compatible, and current;
stale, partial, conflicting, mislabeled, or unowned evidence aborts without
changing the caller's rows.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
import ast
import re
from typing import Any, Callable, Iterator, Mapping

from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.package_original_kind_profiles import (
    ORIGINAL_NON_OBJECT_KINDS,
)


REVIEW_KINDS = _shared.REVIEW_KINDS
ADMISSION_OBJECT_IDS = (
    "vstd-runtime-package-marker",
    "vstd-namespace-rule-engine",
    "vstd-namespace-source-census",
    "vstd-manifest-admission",
    "vstd-package-semantic-review-policy",
    "vstd-package-semantic-ownership-policy",
    "vstd-package-graph-contract",
    "vstd-package-instance-evidence",
    "vstd-package-kind-requirements",
    "vstd-package-obligation-candidate",
    "vstd-package-owner-decision",
    "vstd-native-operation-metadata",
    "vstd-object-context-closure",
)

CLAIM_BOUNDARY = (
    "Exact-current-source Tier-0 applicability and declaration review for "
    "these thirteen repository-admission support objects only. It establishes "
    "neither behavior truth nor whole-package completeness, Tier-1-plus "
    "conformance, external or human authority, legal effect, physical or "
    "financial safety, publication, release, or deployment. A parser child is "
    "a bounded observed process exchange, not a sandbox or reachability proof."
)


_RUNTIME_MARKER_PATHS = ("src/verifier/runtime/__init__.py",)
_NAMESPACE_RULE_PATHS = (
    "src/verifier/runtime/namespace_classification.py",
    "src/verifier/runtime/namespace_consequences.mjs",
    "src/verifier/runtime/namespace_consequences.py",
    "src/verifier/runtime/namespace_contracts.py",
    "src/verifier/runtime/namespace_dominance.py",
    "src/verifier/runtime/namespace_refutation.py",
)
_NAMESPACE_CENSUS_PATHS = (
    "src/verifier/runtime/namespace_discovery.py",
    "src/verifier/runtime/namespace_exports.py",
    "src/verifier/runtime/namespace_html.py",
    "src/verifier/runtime/namespace_metadata.py",
    "src/verifier/runtime/namespace_source_imports.py",
    "src/verifier/runtime/namespace_svg.py",
    "src/verifier/runtime/source_declaration_inputs.py",
)
# The declaration-input fingerprint measures one supplied Python file and decides no admission, so
# the census POLICY role stays on the files that select, bind and classify census members.
_NAMESPACE_CENSUS_POLICY_PATHS = tuple(
    path for path in _NAMESPACE_CENSUS_PATHS
    if path != "src/verifier/runtime/source_declaration_inputs.py"
)
# Files whose own bodies read repository members at a parent interface: discovery
# digests each census member, and source_imports reads a local target it binds.
_NAMESPACE_ACQUISITION_PATHS = (
    "src/verifier/runtime/namespace_discovery.py",
    "src/verifier/runtime/namespace_source_imports.py",
)
_MANIFEST_PATHS = (
    "src/verifier/runtime/namespace_manifest.py",
    "src/verifier/runtime/package_manifest.py",
    "src/verifier/runtime/tier_zero_manifest.py",
)
_SEMANTIC_REVIEW_PATHS = (
    "src/verifier/runtime/package_api_surface_admission.py",
    "src/verifier/runtime/package_namespace_review.py",
    "src/verifier/runtime/package_original_kind_catalog.py",
    "src/verifier/runtime/package_original_kind_catalog_domains.py",
    "src/verifier/runtime/package_original_kind_catalog_experiments_hardware.py",
    "src/verifier/runtime/package_original_kind_catalog_python_apps_public_cli.py",
    "src/verifier/runtime/package_original_kind_catalog_repository_assets.py",
    "src/verifier/runtime/package_original_kind_catalog_retained.py",
    "src/verifier/runtime/package_original_kind_catalog_runtime.py",
    "src/verifier/runtime/package_original_kind_catalog_scripts_examples.py",
    "src/verifier/runtime/package_original_kind_catalog_tests_normative.py",
    "src/verifier/runtime/package_original_kind_profiles.py",
    "src/verifier/runtime/package_original_kind_review.py",
    "src/verifier/runtime/package_original_review_computation.py",
    "src/verifier/runtime/package_original_review_people.py",
    "src/verifier/runtime/package_original_review_systems.py",
    "src/verifier/runtime/package_semantic_review_admission.py",
    "src/verifier/runtime/package_semantic_review_commands.py",
    "src/verifier/runtime/package_semantic_review_core.py",
    "src/verifier/runtime/package_semantic_review_hardware_cli.py",
    "src/verifier/runtime/package_semantic_review_operations.py",
    "src/verifier/runtime/package_semantic_review_package_object.py",
    "src/verifier/runtime/package_semantic_review_partitions.py",
    "src/verifier/runtime/package_semantic_review_polish.py",
    "src/verifier/runtime/package_semantic_review_records.py",
    "src/verifier/runtime/package_semantic_review_scripts.py",
    "src/verifier/runtime/package_semantic_review_self_polish.py",
    "src/verifier/runtime/package_semantic_review_subjects.py",
    "src/verifier/runtime/package_semantic_review_verifier.py",
)
_SEMANTIC_OWNERSHIP_PATHS = (
    "src/verifier/runtime/package_semantic_ownership.py",
    "src/verifier/runtime/package_semantic_ownership_current_untracked.py",
    "src/verifier/runtime/package_semantic_ownership_domains.py",
    "src/verifier/runtime/package_semantic_ownership_domains_agency_collective.py",
    "src/verifier/runtime/package_semantic_ownership_domains_context.py",
    "src/verifier/runtime/package_semantic_ownership_domains_sim_model.py",
    "src/verifier/runtime/package_semantic_ownership_domains_systems.py",
    "src/verifier/runtime/package_semantic_ownership_experiments.py",
    "src/verifier/runtime/package_semantic_ownership_hardware_interop.py",
    "src/verifier/runtime/package_semantic_ownership_model.py",
    "src/verifier/runtime/package_semantic_ownership_normative_assets.py",
    "src/verifier/runtime/package_semantic_ownership_python_apps.py",
    "src/verifier/runtime/package_semantic_ownership_public_cli.py",
    "src/verifier/runtime/package_semantic_ownership_repository_assets.py",
    "src/verifier/runtime/package_semantic_ownership_scripts_examples.py",
    "src/verifier/runtime/package_semantic_ownership_tests_fixtures.py",
)
_GRAPH_CONTRACT_PATHS = (
    "src/verifier/runtime/package_contract_coverage.py",
    "src/verifier/runtime/package_contract_profiles.py",
    "src/verifier/runtime/package_graph_representation.py",
)
_INSTANCE_EVIDENCE_PATHS = ("src/verifier/runtime/package_instance_evidence.py",)
_KIND_REQUIREMENT_PATHS = ("src/verifier/runtime/package_kind_requirements.py",)
_OBLIGATION_CANDIDATE_PATHS = ("src/verifier/runtime/package_obligation_candidate.py",)
_OWNER_DECISION_PATHS = ("src/verifier/runtime/package_owner_decision.py",)
_NATIVE_OPERATION_PATHS = (
    "src/verifier/runtime/native_operation_contracts.py",
    "src/verifier/runtime/native_operation_cli.py",
)
_NATIVE_OPERATION_OBSERVATION_PATHS = (
    "src/verifier/runtime/native_operation_contracts.py",
)
_CONTEXT_CLOSURE_PATHS = ("src/verifier/runtime/object_context_closure.py",)


def _profile(
    *,
    name: str,
    scope: str,
    mechanism: str,
    inputs: str,
    observations: str,
    commands: str,
    states: str,
    limits: str,
    boundary: str,
    participants: str = (
        "The caller, the current repository source coordinate, and the returned "
        "typed value or diagnostic."
    ),
    effects: str | None = None,
    ordering: str | None = None,
    timing: str | None = None,
    units: str | None = None,
    failure: str | None = None,
    recovery: str | None = None,
) -> _shared._Profile:
    """Build a conservative profile without claiming the reviewed mechanism ran."""
    return _shared._Profile(
        name=name,
        scope=scope,
        mechanism=mechanism,
        participants=participants,
        inputs=inputs,
        authority=(
            "The caller selects the repository coordinate and supplied inputs. "
            "The mechanism grants no human, legal, physical, financial, publication, "
            "release, deployment, or higher-tier authority."
        ),
        states=states,
        ordering=(
            ordering
            or "Validate the exact inputs and source bindings before deriving a result; "
            "retain unresolved or unavailable states instead of treating them as empty "
            "success; emit a result only after all local checks complete."
        ),
        commands=commands,
        targets=(
            "Only the explicitly supplied records and exact repository members named "
            "by this object's owned paths or their digest-bound subject coordinate."
        ),
        effect_domains=(
            "BOUNDED_LOCAL_REPOSITORY_ADMISSION_ONLY; no represented physical "
            "actuator, real-money endpoint, public release, or deployment target."
        ),
        effects=(
            effects
            or "Return a bounded structural decision, observation, declaration, or "
            "diagnostic for the exact supplied inputs; downstream truth and effects "
            "remain separately unestablished."
        ),
        commit=(
            "Commit means only that the typed returned value is complete for the exact "
            "accepted inputs and named local boundary. It is not behavioral truth, "
            "normative adoption, package polish, release, or deployment."
        ),
        retry=(
            "No hidden retry is assumed. A later call is a fresh evaluation; matching "
            "digests permit comparison but do not prove external idempotence."
        ),
        timing=(
            timing
            or "Source and record ordering are represented, but no wall-clock freshness, "
            "hard-real-time deadline, or external event time is inferred."
        ),
        limits=limits,
        observations=observations,
        units=(
            units
            or "Exact path identities, canonical record counts and bytes, bounded item "
            "counts, source positions where present, and SHA-256 digests."
        ),
        failure=(
            failure
            or "Missing, malformed, stale, contradictory, unsupported, or over-limit "
            "input fails closed as an explicit refusal, failure, or unknown state; it "
            "never becomes an empty successful denominator."
        ),
        recovery=(
            recovery
            or "Correct or reselect the exact input and source coordinate, preserve the "
            "prior diagnostic, and perform a separate fresh evaluation."
        ),
        boundary=boundary,
    )


_RUNTIME_MARKER = _profile(
    name="runtime package marker",
    scope="Identify the verifier.runtime Python package without defining a route.",
    mechanism="A static package initializer containing no admission mechanism.",
    inputs="The exact initializer bytes only.",
    observations="No phenomenon is sampled and no repository claim is derived.",
    commands="No command, filesystem mutation, process launch, or endpoint call.",
    states="Importable package marker or unavailable source; no operational lifecycle.",
    limits="One current ordinary initializer file and no represented dynamic surface.",
    boundary=(
        "One static Python package marker, not a policy, measurement, sensor, "
        "transaction, actuator, protocol, ROBOT, or FINBOT mechanism."
    ),
)

_NAMESPACE_RULE_ENGINE = _profile(
    name="namespace rule engine",
    scope=(
        "Validate namespace kinds, inheritance, dominance, consequences, Tier-0 "
        "contracts, and classification decisions over supplied structural records."
    ),
    mechanism=(
        "Deterministic Python and JavaScript rule evaluation against finite built-in "
        "registries and caller-supplied canonical values."
    ),
    inputs="Declared kinds, evidence-bound decisions, contract rows, and object records.",
    observations=(
        "Rule matches, inherited consequences, contract requirements, dominance, "
        "refutations, and unresolved classifications derived from supplied values."
    ),
    commands="Return rules, classifications, and diagnostics; issue no external command.",
    states="Declared, inferred, refuted, unresolved, invalid, and accepted rule states.",
    limits="Finite registered kinds, finite input values, and deterministic local rules.",
    boundary=(
        "Structural namespace policy evaluation only; it does not observe subject "
        "behavior, adopt an owner decision, or prove a mechanism or external effect."
    ),
)

_NAMESPACE_SOURCE_CENSUS = _profile(
    name="namespace source census",
    scope=(
        "Acquire a digest-bound repository census and derive bounded Python, HTML, "
        "SVG, metadata, export, and import surfaces with explicit gaps."
    ),
    mechanism=(
        "Read exact ordinary source members, apply language-specific parsers and "
        "static resolvers, and let the discovery orchestrator perform its registered "
        "bounded parser exchange where required."
    ),
    participants=(
        "The discovery caller, exact repository members, local static parsers, and any "
        "registered parser child selected by namespace_discovery.py."
    ),
    inputs=(
        "An anchored repository root, exact source census and digests, bounded source "
        "bytes, parser-mechanism bindings, and supported suffixes."
    ),
    observations=(
        "Source members, definitions, exports, references, fragments, import bindings, "
        "kind hints, dynamic gaps, parser identities, and digest disagreements."
    ),
    commands=(
        "Read exact source members and, only through the discovery orchestrator, start "
        "and exchange bounded records with a registered parser child."
    ),
    states=(
        "Captured, parsed, bound, unsupported, dynamic, unresolved, stale, failed, and "
        "complete-census states remain distinct."
    ),
    limits=(
        "Only census-named ordinary in-root files, registered formats, bounded bytes "
        "and records, exact digests, and finite parser replies are accepted."
    ),
    effects=(
        "Perform bounded local file reads and the discovery orchestrator's parser-child "
        "lifecycle, then return a structural census; source execution and reachability "
        "are not established."
    ),
    boundary=(
        "Static and parser-mediated source acquisition only. Parser subprocesses are "
        "not a sandbox, code-reachability proof, behavior proof, or complete dynamic "
        "interface census."
    ),
)

_MANIFEST_ADMISSION = _profile(
    name="manifest admission mechanism",
    scope=(
        "Parse and validate namespace, package, and Tier-0 manifest structure, bounds, "
        "identities, classifications, declarations, and digest bindings."
    ),
    mechanism=(
        "Strict bounded JSON/schema-shaped validation plus canonical structural and "
        "digest comparisons over caller-supplied manifest bytes and records."
    ),
    inputs="Exact manifest bytes or values, registered kinds, source digests, and limits.",
    observations=(
        "Namespace and Tier-0 validators observe declared object, surface, evidence, "
        "classification, obligation, and digest fields; package_manifest supplies "
        "policy rules but is not a separate acquisition source."
    ),
    commands="Return a validated manifest value or exact refusal; perform no subject action.",
    states="Absent, malformed, unsupported, incomplete, contradictory, admitted, or refused.",
    limits="Finite canonical manifests, registered fields and kinds, and exact digest syntax.",
    boundary=(
        "Manifest structure and admission policy only; schema-valid text does not prove "
        "mechanism behavior, full route coverage, authority, or higher-tier conformance."
    ),
)

_SEMANTIC_REVIEW_POLICY = _profile(
    name="package semantic-review policy",
    scope=(
        "Inspect exact owner rows, twelve added-kind decisions, Tier-0 declaration "
        "shapes, and current evidence for bounded audited object families."
    ),
    mechanism=(
        "Deterministic review catalogs plus fail-closed validators compare supplied "
        "rows and source digests with registered contracts before returning copied rows."
    ),
    inputs=(
        "Exact source-bound ownership rows, the current digest census, registered "
        "Tier-0 contracts, and pre-existing decisions or declarations."
    ),
    observations=(
        "Decision status, reason, evidence path/digest, declaration completeness, label "
        "compatibility, ownership, source drift, and unresolved review state."
    ),
    commands="Construct and return reviewed copies; never mutate the caller's rows.",
    states="Unresolved, applies, does-not-apply, preserved, conflicting, stale, and complete.",
    limits=(
        "Only each catalog's finite exact owner denominator and live registered Tier-0 "
        "declaration fields; no unreviewed source or invented obligation is admitted."
    ),
    boundary=(
        "Source-bound review policy and observations about supplied records only; prose "
        "declarations are not execution evidence or proof of their asserted mechanism."
    ),
)

_SEMANTIC_OWNERSHIP_POLICY = _profile(
    name="package semantic-ownership policy",
    scope=(
        "Define the finite path-to-object partition, primary kinds, specializations, "
        "and bounded object reasons used by repository admission."
    ),
    mechanism="A deterministic immutable catalog of exact path-owned semantic objects.",
    inputs="Repository-relative paths and the catalog's explicit object specifications.",
    observations="Duplicate paths, invalid kinds, missing reasons, and partition membership.",
    commands="Return ownership specifications and diagnostics; issue no subject command.",
    states="Owned, duplicate, invalid, missing, reserved, or outside the selected partition.",
    limits="Finite explicit repository-relative paths and registered namespace kinds.",
    boundary=(
        "Ownership and labeling policy only; path ownership does not prove applicability, "
        "source behavior, semantic completeness, or conformance."
    ),
)

_PACKAGE_GRAPH_CONTRACT = _profile(
    name="package graph contract",
    scope=(
        "Derive and check finite package-object graph representation and declared "
        "contract coverage over exact admitted objects, routes, and interfaces."
    ),
    mechanism=(
        "Pure graph and set comparisons bind supplied object nodes, edges, routes, "
        "interfaces, obligations, and coverage gaps into deterministic records."
    ),
    inputs="Admitted object rows, declared edges, route/interface records, and contracts.",
    observations="Represented nodes, edges, declared coverage, duplicates, and structural gaps.",
    commands="Return graph and coverage records; execute no represented route or interface.",
    states="Represented, covered, duplicate, dangling, uncovered, invalid, or unresolved.",
    limits="Finite supplied graph rows and exact identifiers; no dynamic behavior inference.",
    boundary=(
        "Structural graph and coverage policy only; represented or covered does not mean "
        "reachable, executed, correct, safe, polished, released, or deployed."
    ),
)

_PACKAGE_INSTANCE_EVIDENCE = _profile(
    name="package instance-evidence selector",
    scope=(
        "Select an installed native route for an exact package-instance certificate, "
        "execute its bounded registered replay, and retain typed evidence."
    ),
    mechanism=(
        "Reject caller commands and module names, bind the exact installed route and "
        "certificate inputs, perform its finite native replay, and validate the result."
    ),
    inputs=(
        "Exact package/object/kind coordinate, registered route, bounded certificate "
        "and policy values, source digests, evidence roots, and replay limits."
    ),
    observations=(
        "Route selection, certificate bindings, replay status, returned evidence, "
        "declared limits, failures, and digest agreement."
    ),
    commands="Invoke only the exact installed native replay route and return its typed result.",
    states="Unselected, selected, running, pass, fail, unknown, refused, or stale.",
    limits="Installed routes only, canonical bounded values, finite evidence, and exact digests.",
    effects=(
        "Execute one installed bounded replay in its declared local mechanism boundary; "
        "actual subject execution, external effects, and domain completeness are not inferred."
    ),
    boundary=(
        "One registered evidence replay, not arbitrary code execution, a general sandbox, "
        "actual subject execution, complete package proof, ROBOT, or FINBOT authority."
    ),
)

_PACKAGE_KIND_REQUIREMENTS = _profile(
    name="package kind-requirement derivation",
    scope=(
        "Carry admitted and discovered namespace kinds into exact package obligation and "
        "native-route requirements without casting evidence into a different subject."
    ),
    mechanism=(
        "Compose classification, consequence, contract, discovery, harness-applicability, "
        "and installed-route mechanisms over one exact declaration and source census."
    ),
    inputs=(
        "Exact package declaration, source census, kind decisions, consequences, route "
        "catalog, evidence records, and requested polish tier."
    ),
    observations=(
        "Effective kinds and their bases, source/export digests, required obligations, "
        "route applicability, unavailable discovery, and unresolved refinements."
    ),
    commands=(
        "Acquire the bounded source census and invoke only registered requirement or "
        "evidence routes selected by the exact effective-kind result."
    ),
    states="Declared, discovered, effective, required, unavailable, unresolved, or refused.",
    limits="Registered kinds/routes, finite admitted declarations and censuses, and exact digests.",
    effects=(
        "Perform bounded local discovery and selected installed requirement checks, then "
        "return requirement records; no downstream subject effect is authorized."
    ),
    boundary=(
        "Requirement derivation and registered local checks only; an added obligation is "
        "not a passing obligation, and unavailable discovery is not evidence of absence."
    ),
)

_OBLIGATION_CANDIDATE = _profile(
    name="package obligation-candidate binder",
    scope=(
        "Bind candidate obligation cards to exact installed routes and structural object "
        "coordinates while preserving their non-normative candidate status."
    ),
    mechanism=(
        "Strict bounded candidate parsing, identifier and route lookup, duplicate checks, "
        "canonical digests, and fail-closed structural comparison."
    ),
    inputs="Candidate cards, object coordinates, installed route metadata, and exact digests.",
    observations="Candidate fields, route matches, duplicates, omissions, and digest bindings.",
    commands="Return bound candidate records or diagnostics; execute no candidate route.",
    states="Proposed, bound, duplicate, missing-route, malformed, refused, or unresolved.",
    limits="Finite candidate cards, installed route identifiers, canonical values, and exact digests.",
    boundary=(
        "Candidate structural evidence only; validity does not make a proposal normative "
        "or establish any obligation instance as passing, failing, or complete."
    ),
)

_OWNER_DECISION = _profile(
    name="package owner-decision admission",
    scope=(
        "Authenticate one finite owner statement against separately selected and "
        "digest-pinned policy bytes and an exact candidate decision denominator."
    ),
    mechanism=(
        "Read bounded ordinary files, verify exact canonical digests and configured-key "
        "Ed25519 evidence, and return a typed admission record."
    ),
    participants=(
        "The selecting caller, configured public-key policy, signed owner-decision "
        "envelope, exact candidate ledger, and local admission verifier."
    ),
    inputs=(
        "Selected policy and envelope files/digests, configured key identity, source "
        "coordinate digest, candidate selection digest, and exact decision subjects."
    ),
    observations=(
        "File/digest identity, policy revision and activation bounds, signature result, "
        "decision subjects, adopted identifiers, and admission status."
    ),
    commands="Read selected local files and verify evidence; issue no signing or external command.",
    states="Not-selected, admitted, failed, unknown, stale, malformed, or unauthorized-by-policy.",
    limits="Finite ordinary files, configured admitted keys, exact decision set, and bounded bytes.",
    boundary=(
        "Configured-key evidence for one selected finite statement only; it does not "
        "create a key, choose policy, prove personhood, infer legal authority, or make "
        "candidate semantics normative."
    ),
)

_NATIVE_OPERATION_METADATA = _profile(
    name="native-operation metadata catalog",
    scope=(
        "Inspect installed native replay callables and export bounded read-only operation "
        "descriptors, lookup results, schemas, and command-line JSON metadata."
    ),
    mechanism=(
        "Static module/callable inspection, exact descriptor validation and digesting, "
        "registered lookup, and read-only JSON serialization."
    ),
    inputs="Installed modules and callables, operation identifiers, descriptors, and CLI queries.",
    observations=(
        "The contracts module observes callable signatures, metadata fields, schemas, "
        "lookup identity, module/source bindings, and descriptor digests."
    ),
    commands="Return or print metadata only; never invoke the described replay operation.",
    states="Available, historical, missing, malformed, refused, unavailable, or exported.",
    limits="Installed metadata only, finite descriptors, supported signatures, and bounded JSON.",
    boundary=(
        "Read-only metadata and policy surface; availability does not establish replay, "
        "execution, effects, cancellation, authority, or a complete obligation census."
    ),
)

_OBJECT_CONTEXT_CLOSURE = _profile(
    name="object-context closure composer",
    scope=(
        "Compose selected exact object, context, security, certificate-DAG, and application "
        "requirement evidence through existing narrow recheckers."
    ),
    mechanism=(
        "Bounded canonical parsing, digest and identifier checks, selected local rechecker "
        "composition, and fail-closed status aggregation."
    ),
    inputs="Selected object/context/security records, trust roots, certificates, policies, and digests.",
    observations="Binding digests, rechecker status, missing evidence, contradictions, and closure gaps.",
    commands="Invoke only selected narrow local recheckers and return the composed closure record.",
    states="Selected, pass, fail, unknown, incomplete, contradictory, stale, or refused.",
    limits="Finite selected records and registered local recheckers; no open-world completeness inference.",
    boundary=(
        "Composition of existing bounded evidence only; it does not establish authority, "
        "permissions, actual history, release, or complete object/security conformance."
    ),
)


# Object-specific refutations for every DOES_NOT_APPLY cell.  Each sentence names
# a reviewed file and an observed fact of its executable code: no process, network,
# device, or file-write call, or the module's own stated role.  Identifier hits
# such as ledger, token, or request are data names and are explained, not accepted
# as the refuted role.  A refuted kind without a source-cited sentence fails at import.
_DNE_BASES: dict[str, dict[str, str]] = {
    "vstd-runtime-package-marker": {
        "LEDGER": "__init__.py declares only an empty __all__ list, so it holds no history, balance, or sequence state.",
        "TRANSACTION": "__init__.py has no executable operation that changes state, so it defines no commit, rollback, or partial-failure boundary.",
        "ASSET": "__init__.py contains no quantity, right, custody, or issuance representation.",
        "MARKET": "__init__.py contains no order, quote, match, or settlement code.",
        "MEASUREMENT": "__init__.py observes no phenomenon; its only executable statement binds __all__.",
        "SENSOR": "__init__.py performs no acquisition, device read, or sampling.",
        "CONTROLLER": "__init__.py computes no feedback and selects no command.",
        "ACTUATOR": "__init__.py issues no command and crosses no submission boundary.",
        "PROTOCOL": "__init__.py exchanges no request or response with any participant.",
        "POLICY": "__init__.py defines no rule, precedence, exception, or enforcement decision.",
        "ROBOT": "__init__.py connects no agent, harness, controller, or physical actuator path.",
        "FINBOT": "__init__.py connects no agent to a financial decision or real financial endpoint.",
    },
    "vstd-namespace-rule-engine": {
        "LEDGER": "namespace_classification.py calls its output an evidence ledger, but the rule-engine files write no file and keep no authoritative history, balance, or sequence.",
        "ASSET": "namespace_classification.py evaluates declared kinds over supplied records and represents no quantity, right, custody, or issuance.",
        "MARKET": "namespace_dominance.py orders dominator nodes only; the rule engine matches no orders, trades, or prices.",
        "MEASUREMENT": "namespace_classification.py evaluates supplied declarations and observes no phenomenon with uncertainty.",
        "SENSOR": "namespace_consequences.py acquires no device, file, or network reading; it evaluates values its caller supplies.",
        "CONTROLLER": "namespace_consequences.py names controllers only as declared graph relations and applies no feedback to select a command.",
        "ACTUATOR": "namespace_consequences.py issues no command, and the rule-engine files call no process, network, device, or file-write API.",
        "PROTOCOL": "namespace_contracts.py exchanges no ordered messages across a process or network boundary; each function returns a value to its caller.",
        "ROBOT": "namespace_consequences.py may compile one source-reviewed structural agent/controller/actuator declaration, but it runs no agent or harness and issues no command to a physical actuator.",
        "FINBOT": "namespace_consequences.py computes declared financial reachability and connects no agent to a real financial endpoint.",
    },
    "vstd-namespace-source-census": {
        "LEDGER": "namespace_discovery.py reads source members and returns discovery records; none of the seven census files writes a file or keeps authoritative history.",
        "ASSET": "namespace_discovery.py lists source members and their bindings and represents no right, quantity, custody, or issuance; its token hits are lexical.",
        "MARKET": "namespace_exports.py records source export bindings and matches no orders, trades, or prices.",
        "CONTROLLER": "namespace_source_imports.py derives source bindings and records no feedback or command selection for any target.",
        "ROBOT": "namespace_discovery.py reads and parses source text in-process and connects no agent, harness, or physical actuator.",
        "FINBOT": "namespace_metadata.py parses dependency declarations and represents no agent or real financial decision or endpoint.",
    },
    "vstd-manifest-admission": {
        "LEDGER": "namespace_manifest.py states that declaring LEDGER does not invent or alter a legacy primitive; its validators hold no history and write no file.",
        "PROTOCOL": "tier_zero_manifest.py decodes and checks one supplied document per call; it exchanges no request or response across a process boundary.",
        "ASSET": "namespace_manifest.py checks declared fields and represents no quantity, right, custody, or issuance; its token hits are lexical.",
        "MARKET": "package_manifest.py validates manifest bridges and matches no orders, trades, or prices.",
        "CONTROLLER": "namespace_manifest.py checks declared structure and computes no feedback or command selection.",
        "ACTUATOR": "tier_zero_manifest.py issues no command, and the manifest files call no process, network, device, or file-write API.",
        "ROBOT": "namespace_manifest.py checks declared consequence edges but connects no agent, harness, or physical actuator.",
        "FINBOT": "namespace_manifest.py checks declared decision edges but connects no agent to a real financial endpoint.",
    },
    "vstd-package-semantic-review-policy": {
        "LEDGER": "package_namespace_review.py defines _LEDGER_* catalogs for other objects; the 29 review files write no file and keep no authoritative history or balance.",
        "ASSET": "package_original_review_computation.py names _TOKEN_ASSET catalogs of reviewed objects and represents no right, quantity, custody, or issuance.",
        "MARKET": "package_semantic_review_operations.py orders review rows only; the 29 review files match no orders, trades, or prices.",
        "CONTROLLER": "package_semantic_review_polish.py names controller profiles of reviewed objects and its executable code computes no feedback or command selection.",
        "ACTUATOR": "package_namespace_review.py describes other objects' actuator surfaces as prose; its executable code issues no command and calls no process, network, device, or file-write API.",
        "PROTOCOL": "package_semantic_review_polish.py has no serialized participant exchange; its executable code calls no process, network, or socket API.",
        "ROBOT": "package_original_review_computation.py classifies agent surfaces of other objects as data and connects no agent, harness, or physical actuator.",
        "FINBOT": "package_original_review_people.py classifies financial surfaces of other objects as data and connects no agent to a real financial endpoint.",
    },
    "vstd-package-semantic-ownership-policy": {
        "LEDGER": "package_semantic_ownership.py assigns audited source-ownership splits; it keeps no history, balance, or sequence and writes no file.",
        "TRANSACTION": "package_semantic_ownership.py defines no coordinated effect or commit unit; it assigns immutable path ownership only.",
        "ASSET": "package_semantic_ownership_repository_assets.py assigns ownership of 234 non-code repository asset paths, not a right, quantity, custody, or issuance.",
        "MARKET": "package_semantic_ownership_domains.py assigns source ownership for domain paths only and matches no orders, trades, or prices.",
        "MEASUREMENT": "package_semantic_ownership_model.py holds immutable ownership records and normalization and observes no phenomenon.",
        "SENSOR": "package_semantic_ownership_hardware_interop.py assigns path-level semantic ownership only and acquires no device, file, or network reading.",
        "CONTROLLER": "package_semantic_ownership_python_apps.py assigns ownership of Python application paths and computes no feedback or command selection.",
        "ACTUATOR": "package_semantic_ownership_scripts_examples.py assigns ownership of script and example paths; its executable code calls no process, network, device, or file-write API.",
        "PROTOCOL": "package_semantic_ownership_public_cli.py assigns the one public dispatcher path and exchanges no messages with any participant.",
        "ROBOT": "package_semantic_ownership_experiments.py assigns ownership of experiment paths and connects no agent, harness, or physical actuator.",
        "FINBOT": "package_semantic_ownership_normative_assets.py assigns ownership of normative contract assets and connects no agent to a financial decision or endpoint.",
    },
    "vstd-package-graph-contract": {
        "LEDGER": "package_contract_coverage.py aggregates the current invocation's results, keeps no history, balance, or sequence, and writes no file.",
        "ASSET": "package_graph_representation.py derives declared nodes and edges, not a quantity, right, custody, or issuance.",
        "MARKET": "package_contract_profiles.py defines installed package-variant closure profiles and matches no orders, trades, or prices.",
        "MEASUREMENT": "package_contract_coverage.py compares declared clauses with results and observes no phenomenon with uncertainty.",
        "SENSOR": "package_graph_representation.py acquires no device, file, or network reading.",
        "CONTROLLER": "package_contract_coverage.py computes no feedback and selects no command for a target.",
        "ACTUATOR": "package_contract_coverage.py executes no route or subject and its executable code calls no process, network, device, or file-write API.",
        "PROTOCOL": "package_contract_coverage.py rebuilds clauses in-process and exchanges no messages with a participant.",
        "ROBOT": "package_graph_representation.py joins declared objects and connects no agent, harness, or physical actuator.",
        "FINBOT": "package_graph_representation.py joins declared objects and connects no agent to a real financial endpoint.",
    },
    "vstd-package-instance-evidence": {
        "LEDGER": "package_instance_evidence.py validates recorded execution rows and writes no file, so it keeps no authoritative history, balance, or sequence.",
        "TRANSACTION": "package_instance_evidence.py reads digest-bound evidence and returns one checker result but owns no coordinated effect-and-commit unit, transaction resource, atomic commit, compensation protocol, or durable finality.",
        "ASSET": "package_instance_evidence.py checks certificates and consequence bindings and represents no right, quantity, custody, or issuance.",
        "MARKET": "package_instance_evidence.py orders certificate rows with _ordered_records and matches no orders, trades, or prices.",
        "CONTROLLER": "package_instance_evidence.py validates declared controller edges without computing feedback or selecting a command.",
        "ACTUATOR": "package_instance_evidence.py invokes one registered checker as an internal dispatcher but owns no command-to-effect endpoint, submission boundary, or represented actuator target.",
        "ROBOT": "package_instance_evidence.py labels ROBOT consequences as REAL_PHYSICAL for validation only and connects no agent, harness, or physical actuator.",
        "FINBOT": "package_instance_evidence.py labels FINBOT consequences as REAL_FINANCIAL for validation only and connects no agent to a real financial endpoint.",
    },
    "vstd-package-kind-requirements": {
        "LEDGER": "package_kind_requirements.py derives requirement rows from supplied classifications and keeps no history, balance, or sequence.",
        "ASSET": "package_kind_requirements.py derives requirement rows for kinds and represents no quantity, right, custody, or issuance.",
        "MARKET": "package_kind_requirements.py derives requirement rows and matches no orders, trades, or prices.",
        "CONTROLLER": "package_kind_requirements.py derives requirement rows and computes no feedback or command selection.",
        "ROBOT": "package_kind_requirements.py consults a harness applicability assessment for a selected repository and acts as no agent or actuator.",
        "FINBOT": "package_kind_requirements.py derives financial requirement rows without acting as an agent or reaching a real financial endpoint.",
    },
    "vstd-package-obligation-candidate": {
        "LEDGER": "package_obligation_candidate.py reads its reason-ledger input as bounded bytes and writes no file, so it keeps no authoritative ledger state.",
        "ASSET": "package_obligation_candidate.py binds candidate cards to routes and represents no quantity, right, custody, or issuance.",
        "MARKET": "package_obligation_candidate.py binds candidate cards and matches no orders, trades, or prices.",
        "CONTROLLER": "package_obligation_candidate.py validates candidate cards and computes no feedback or command selection.",
        "ACTUATOR": "package_obligation_candidate.py executes no candidate route, and its executable code calls no process, network, device, or file-write API.",
        "PROTOCOL": "package_obligation_candidate.py parses supplied candidate bytes in one call and exchanges no messages with a participant.",
        "ROBOT": "package_obligation_candidate.py binds candidate cards to installed routes and connects no agent, harness, or physical actuator.",
        "FINBOT": "package_obligation_candidate.py binds candidate cards to installed routes and connects no agent to a real financial endpoint.",
    },
    "vstd-package-owner-decision": {
        "LEDGER": "package_owner_decision.py reads a supplied candidate_ledger document and writes nothing, so it keeps no authoritative history or balance.",
        "ASSET": "package_owner_decision.py authenticates one signed owner statement; that statement is not a transferable right, quantity, custody, or backing claim, and the module grants no legal authority.",
        "MARKET": "package_owner_decision.py authenticates one owner statement and matches no orders, trades, or prices.",
        "CONTROLLER": "package_owner_decision.py authenticates one owner statement and computes no feedback or command selection.",
        "ACTUATOR": "package_owner_decision.py issues no command; its executable code calls only Ed25519 verification and no process, network, device, or file-write API.",
        "ROBOT": "package_owner_decision.py authenticates an owner statement and connects no agent, harness, or physical actuator.",
        "FINBOT": "package_owner_decision.py authenticates an owner statement and connects no agent to a real financial decision or endpoint.",
    },
    "vstd-native-operation-metadata": {
        "LEDGER": "native_operation_contracts.py exports read-only descriptors, writes no file, and keeps no authoritative history, balance, or sequence.",
        "ASSET": "native_operation_contracts.py exports operation metadata and represents no quantity, right, custody, or issuance.",
        "MARKET": "native_operation_contracts.py exports operation metadata and matches no orders, trades, or prices.",
        "CONTROLLER": "native_operation_contracts.py inspects callable signatures and computes no feedback or command selection.",
        "ACTUATOR": "native_operation_contracts.py never invokes the described replay operation and calls no process, network, device, or file-write API.",
        "PROTOCOL": "native_operation_cli.py serializes local descriptors for a caller and exchanges no request or response with a participant.",
        "ROBOT": "native_operation_contracts.py exports metadata for native replay callables and connects no agent, harness, or physical actuator.",
        "FINBOT": "native_operation_contracts.py exports metadata for native replay callables and connects no agent to a real financial endpoint.",
    },
    "vstd-object-context-closure": {
        "LEDGER": "object_context_closure.py composes supplied records, reports actual_revision_history as NOT_ESTABLISHED, and writes no file.",
        "ASSET": "object_context_closure.py composes evidence records and represents no quantity, right, custody, or issuance.",
        "MARKET": "object_context_closure.py composes evidence records and matches no orders, trades, or prices.",
        "CONTROLLER": "object_context_closure.py composes recheck results and computes no feedback or command selection.",
        "ROBOT": "object_context_closure.py composes object and security evidence and connects no agent, harness, or physical actuator.",
        "FINBOT": "object_context_closure.py composes object and security evidence and connects no agent to a real financial endpoint.",
    },
}


_REVIEWS = {
    "vstd-runtime-package-marker": _shared._review(
        "VERIFIER",
        _RUNTIME_MARKER_PATHS,
        (),
        _RUNTIME_MARKER,
        refuted=(
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
    ),
    "vstd-namespace-rule-engine": _shared._review(
        "POLICY",
        _NAMESPACE_RULE_PATHS,
        ("POLICY",),
        _NAMESPACE_RULE_ENGINE,
        {"POLICY": _NAMESPACE_RULE_PATHS},
        refuted=(
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "LEDGER",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-namespace-source-census": _shared._review(
        "SENSOR",
        _NAMESPACE_CENSUS_PATHS,
        ("MEASUREMENT", "SENSOR", "POLICY"),
        _NAMESPACE_SOURCE_CENSUS,
        {
            "MEASUREMENT": _NAMESPACE_ACQUISITION_PATHS,
            "SENSOR": _NAMESPACE_ACQUISITION_PATHS,
            "POLICY": _NAMESPACE_CENSUS_POLICY_PATHS,
        },
        refuted=("LEDGER", "ASSET", "MARKET", "CONTROLLER", "ROBOT", "FINBOT"),
    ),
    "vstd-manifest-admission": _shared._review(
        "VERIFIER",
        _MANIFEST_PATHS,
        ("POLICY",),
        _MANIFEST_ADMISSION,
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-package-semantic-review-policy": _shared._review(
        "VERIFIER",
        _SEMANTIC_REVIEW_PATHS,
        ("POLICY",),
        _SEMANTIC_REVIEW_POLICY,
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-package-semantic-ownership-policy": _shared._review(
        "POLICY",
        _SEMANTIC_OWNERSHIP_PATHS,
        ("POLICY",),
        _SEMANTIC_OWNERSHIP_POLICY,
        refuted=(
            "LEDGER",
            "TRANSACTION",
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
    "vstd-package-graph-contract": _shared._review(
        "VERIFIER",
        _GRAPH_CONTRACT_PATHS,
        ("POLICY",),
        _PACKAGE_GRAPH_CONTRACT,
        {"POLICY": _GRAPH_CONTRACT_PATHS},
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
    "vstd-package-instance-evidence": _shared._review(
        "VERIFIER",
        _INSTANCE_EVIDENCE_PATHS,
        ("MEASUREMENT", "POLICY", "SENSOR"),
        _PACKAGE_INSTANCE_EVIDENCE,
        refuted=(
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-package-kind-requirements": _shared._review(
        "VERIFIER",
        _KIND_REQUIREMENT_PATHS,
        ("POLICY",),
        _PACKAGE_KIND_REQUIREMENTS,
        refuted=("LEDGER", "ASSET", "MARKET", "CONTROLLER", "ROBOT", "FINBOT"),
    ),
    "vstd-package-obligation-candidate": _shared._review(
        "VERIFIER",
        _OBLIGATION_CANDIDATE_PATHS,
        ("POLICY",),
        _OBLIGATION_CANDIDATE,
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-package-owner-decision": _shared._review(
        "PROTOCOL",
        _OWNER_DECISION_PATHS,
        ("PROTOCOL", "POLICY"),
        _OWNER_DECISION,
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-native-operation-metadata": _shared._review(
        "VERIFIER",
        _NATIVE_OPERATION_PATHS,
        ("POLICY",),
        _NATIVE_OPERATION_METADATA,
        {"POLICY": _NATIVE_OPERATION_OBSERVATION_PATHS},
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        ),
    ),
    "vstd-object-context-closure": _shared._review(
        "VERIFIER",
        _CONTEXT_CLOSURE_PATHS,
        ("POLICY",),
        _OBJECT_CONTEXT_CLOSURE,
        refuted=(
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ROBOT",
            "FINBOT",
        ),
    ),
}


def _reason(object_id: str, review: _shared._Review, kind: str) -> str:
    """Return a source-specific necessity or refutation for one added kind."""
    applies = kind in review.applicable
    if not applies:
        return (
            review.profile.name
            + " does not apply as "
            + kind
            + ". "
            + _DNE_BASES[object_id][kind]
            + " Reviewed boundary: "
            + review.profile.boundary
        )
    reason = _shared._reason(review.profile, kind, applies)
    basis = {
        "TRANSACTION": review.profile.effects,
        "MEASUREMENT": review.profile.observations,
        "SENSOR": review.profile.mechanism,
        "ACTUATOR": review.profile.commands,
        "PROTOCOL": review.profile.participants,
        "POLICY": review.profile.scope,
    }[kind]
    return reason + " Exact source-specific basis: " + basis


def _basis(review: _shared._Review, kind: str) -> str:
    """Return a literal catalog basis; an omitted kind remains unresolved."""
    return _shared._basis(review, kind)


def _decision_reason(
    object_id: str, review: _shared._Review, kind: str
) -> str:
    if _basis(review, kind) == "UNRESOLVED":
        return _shared._unresolved_reason(kind)
    return _reason(object_id, review, kind)


def _classification_document(
    object_id: str, review: _shared._Review, kind: str
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
    review: _shared._Review,
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


def _obligation_reason(
    object_id: str, review: _shared._Review, kind: str
) -> str:
    return (
        _reason(object_id, review, kind)
        + " This Tier-0 declaration names the exact reviewed boundary only; "
        "mechanism execution and Tier-1-plus fulfillment remain unestablished."
    )


def _catalog_check() -> None:
    if tuple(_REVIEWS) != ADMISSION_OBJECT_IDS:
        raise AssertionError("admission review object order differs")
    if sum(len(review.owned_paths) for review in _REVIEWS.values()) != 72:
        raise AssertionError("admission review path denominator differs")
    if len({path for review in _REVIEWS.values() for path in review.owned_paths}) != 72:
        raise AssertionError("admission review paths overlap")
    for object_id, review in _REVIEWS.items():
        if (
            review.primary_kind in REVIEW_KINDS
            and review.primary_kind not in review.applicable
        ):
            raise AssertionError(object_id + " primary kind is not applicable")
        if len(review.applicable) != len(set(review.applicable)):
            raise AssertionError(object_id + " repeats an applicable kind")
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if any(
            not paths or not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence leaves owned source")
        if len(review.refuted) != len(set(review.refuted)):
            raise AssertionError(object_id + " repeats a refuted kind")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " has contradictory role bases")
        bases = _DNE_BASES.get(object_id, {})
        if set(bases) != set(review.refuted):
            raise AssertionError(object_id + " refutation basis differs")
        basenames = {Path(path).name for path in review.owned_paths}
        for text in bases.values():
            # Every cited source must be this object's own file; a sentence that
            # names a neighbour's file (or no file) is a referent mistake.
            cited = set(re.findall(r"[A-Za-z_]\w*\.(?:py|mjs)\b", text))
            if not cited or not cited <= basenames:
                raise AssertionError(object_id + " refutation cites no or a foreign source")
        if not set(review.refuted) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " has an unsupported refuted kind")
        reasons = {
            kind: _decision_reason(object_id, review, kind) for kind in REVIEW_KINDS
        }
        if set(reasons) != set(REVIEW_KINDS) or any(
            not reason.strip() for reason in reasons.values()
        ):
            raise AssertionError(object_id + " classification matrix is incomplete")
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


# Mechanical DOES_NOT_APPLY gate.  A catalog refutation is kept only when the
# object's exact closure is fully visible and free of the refuted role's channels.
# The closure is the object's owned files plus every admission-owned module they
# import, transitively.  Every file must parse, every import must be either a
# standard-library module on the allowlist below or an admission-owned file, and
# no dynamic dispatch, unresolved callee, or role-specific channel may appear in
# executable code (strings and comments are data and never count).  Semantic-only
# roles also require an observed declaration-only closure.  A refutation that
# fails the gate is downgraded to canonical UNRESOLVED.  The gate never creates
# APPLIES and never upgrades an UNRESOLVED cell.  Limit: an attribute-held callable
# is judged by its attribute name, not by what it binds to.
_PACKAGE_ROOT = Path(__file__).resolve().parents[3]
_AMBIENT_PATH = "src/verifier/__init__.py"
_ALLOWED_IMPORT_ROOTS = frozenset(
    {
        "__future__", "abc", "ast", "base64", "collections", "copy", "dataclasses",
        "decimal", "enum", "fractions", "functools", "hashlib", "hmac", "importlib",
        "itertools", "json", "math", "numbers", "operator", "pathlib", "re", "stat",
        "string", "struct", "textwrap", "typing", "unicodedata", "warnings",
    }
)
_DYN_ROOTS = frozenset({"builtins", "importlib"})
_DYN_BUILTINS = frozenset(
    {
        "__import__", "eval", "exec", "compile", "getattr", "setattr", "delattr",
        "globals", "locals", "vars", "breakpoint", "help", "exit", "quit", "license",
        "copyright", "credits",
    }
)
_STDIO_BUILTINS = frozenset({"input", "print"})
_KNOWN_BUILTINS = frozenset(
    name for name in _shared.STATIC_BUILTIN_NAMES if not name.startswith("_")
) - _DYN_BUILTINS - _STDIO_BUILTINS - {"open"}
_PURE_CALLS = frozenset(
    {
        "all", "any", "bool", "bytes", "dict", "enumerate", "float", "frozenset",
        "int", "len", "list", "max", "min", "range", "reversed", "set", "sorted",
        "str", "sum", "tuple", "zip",
    }
)
_READ_ATTRS = frozenset(
    {
        "cwd", "exists", "expanduser", "file_digest", "glob", "group", "home",
        "is_dir", "is_file", "is_symlink", "iterdir", "load", "lstat", "owner",
        "read", "read_bytes", "read_text", "readline", "readlines", "readlink",
        "recv", "recvfrom", "resolve", "rglob", "samefile", "scandir", "stat",
    }
)
_WRITE_ATTRS = frozenset(
    {
        "chmod", "chown", "commit", "copyfile", "copytree", "dump", "execute",
        "executemany", "executescript", "hardlink_to", "makedirs", "mkdir", "move",
        "rename", "rmdir", "rmtree", "rollback", "symlink_to", "touch", "truncate",
        "unlink", "write", "write_bytes", "write_text", "writelines",
    }
)
_PROC_ATTRS = frozenset(
    {
        "Popen", "accept", "bind", "call", "check_call", "check_output",
        "communicate", "connect", "create_subprocess_exec", "create_subprocess_shell",
        "exec", "execv", "execve", "fork", "kill", "listen", "popen", "post", "put",
        "request", "run", "send", "sendall", "sendto", "spawn", "start", "system",
        "terminate", "urlopen",
    }
)
_STDIO_ATTRS = frozenset({"stderr", "stdin", "stdout", "warn"})
_DYN_ATTRS = frozenset(
    {
        "__base__", "__bases__", "__builtins__", "__call__", "__class__", "__closure__",
        "__code__", "__defaults__", "__delattr__", "__dict__", "__get__", "__getattr__",
        "__getattribute__", "__globals__", "__import__", "__loader__", "__mro__",
        "__new__", "__reduce__", "__reduce_ex__", "__set__", "__setattr__",
        "__spec__", "__subclasses__", "cr_frame", "f_back", "f_globals", "f_locals",
        "gi_frame", "import_module", "reload", "tb_frame",
    }
)
_STATE_ATTRS = frozenset(
    {
        "add", "append", "clear", "discard", "extend", "insert", "pop", "popitem",
        "remove", "setdefault", "update", "__delitem__", "__setitem__",
    }
)
# Method names too generic to judge as values (dataclass fields, str, dict) are excluded.
_AMBIGUOUS_ATTRS = frozenset(
    {
        "call", "commit", "dump", "exec", "exists", "group", "home", "cwd", "load",
        "move", "owner", "post", "put", "read", "readline", "readlines", "rename",
        "request", "rollback", "run", "send", "start", "stat", "update", "write",
        "writelines",
    }
)
_REF_METHODS = (_READ_ATTRS | _WRITE_ATTRS | _PROC_ATTRS) - _AMBIGUOUS_ATTRS
_FULL_NAME_CHANNELS = {
    "hashlib.file_digest": frozenset({"READ"}),
    "json.dump": frozenset({"WRITE"}),
    "json.load": frozenset({"READ"}),
    "warnings.warn": frozenset({"STDIO"}),
}
_ROLE_CHANNELS = {
    "ACTUATOR": frozenset({"WRITE", "PROC", "DYN"}),
    "FINBOT": frozenset({"WRITE", "PROC", "STDIO", "DYN"}),
    "LEDGER": frozenset({"WRITE", "STATE", "DYN"}),
    "MEASUREMENT": frozenset({"READ", "DYN"}),
    "POLICY": frozenset({"BRANCH", "DYN"}),
    "PROTOCOL": frozenset({"PROC", "STDIO", "DYN"}),
    "ROBOT": frozenset({"WRITE", "PROC", "STDIO", "DYN"}),
    "SENSOR": frozenset({"READ", "DYN"}),
    "TRANSACTION": frozenset({"WRITE", "STATE", "PROC", "DYN"}),
}
_DECLARATION_ONLY_ROLES = frozenset({"ASSET", "CONTROLLER", "MARKET"})


@dataclass(frozen=True)
class _SourceFacts:
    edges: frozenset[str]
    channels: frozenset[str]
    open_edge: bool
    declarative: bool
    executes_at_import: bool
    references_package: bool


@dataclass(frozen=True)
class _Closure:
    open_edge: bool
    channels: frozenset[str]
    declarative: bool


_OPEN_FACTS = _SourceFacts(
    edges=frozenset(),
    channels=frozenset(),
    open_edge=True,
    declarative=False,
    executes_at_import=True,
    references_package=False,
)


def _module_file(module: str, denominator: frozenset[str]) -> str | None:
    """Return the admission-owned file a verifier module names, if any."""
    parts = module.split(".")
    if parts[0] != "verifier" or len(parts) < 2:
        return None
    base = "src/" + "/".join(parts)
    for candidate in (base + ".py", base + "/__init__.py"):
        if candidate in denominator:
            return candidate
    return None


def _import_edges(module: str, denominator: frozenset[str]) -> tuple[set[str], bool]:
    """Return owned edges for one dotted import, or True when it leaves the owned set."""
    parts = module.split(".")
    if parts[0] in _ALLOWED_IMPORT_ROOTS:
        return set(), False
    if parts[0] != "verifier" or len(parts) < 2:
        return set(), True
    edges: set[str] = set()
    for depth in range(2, len(parts)):
        package = "src/" + "/".join(parts[:depth]) + "/__init__.py"
        if package not in denominator:
            return set(), True
        edges.add(package)
    target = _module_file(module, denominator)
    if target is None:
        return set(), True
    edges.add(target)
    return edges, False


def _dotted_base(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _root_name(node: ast.expr) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _qualify(dotted: str, aliases: Mapping[str, str]) -> str:
    head, sep, rest = dotted.partition(".")
    return aliases.get(head, head) + sep + rest


def _open_mode_channels(call: ast.Call, *, index: int) -> set[str]:
    mode: ast.expr | None = call.args[index] if len(call.args) > index else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if mode is None:
        return {"READ"}
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return {"WRITE"} if any(char in mode.value for char in "wax+") else {"READ"}
    return {"READ", "WRITE"}


def _attribute_channels(attr: str, call: ast.Call | None) -> set[str]:
    """Channels named by an attribute, judged by name because receivers are untyped."""
    if attr in _DYN_ATTRS:
        return {"DYN"}
    found: set[str] = set()
    if attr in _READ_ATTRS:
        found.add("READ")
    if attr in _WRITE_ATTRS:
        found.add("WRITE")
    if attr in _PROC_ATTRS:
        found.add("PROC")
    if attr in _STDIO_ATTRS:
        found.add("STDIO")
    if call is not None and attr == "open":
        found |= _open_mode_channels(call, index=0)
    if call is not None and attr == "replace" and len(call.args) == 1 and not call.keywords:
        found.add("WRITE")  # Path.replace(target); str.replace takes two arguments.
    return found


def _dotted_channels(qualified: str) -> set[str]:
    """Channels of a module-level name after alias resolution."""
    if qualified.split(".")[0] in _DYN_ROOTS:
        return {"DYN"}
    return set(_FULL_NAME_CHANNELS.get(qualified, frozenset()))


def _call_channels(
    call: ast.Call,
    *,
    aliases: Mapping[str, str],
    modules: frozenset[str],
    module_names: frozenset[str],
    known: frozenset[str],
) -> set[str]:
    func = call.func
    if isinstance(func, ast.Name):
        name = func.id
        if name in aliases:
            return _dotted_channels(aliases[name])
        if name == "open":
            return _open_mode_channels(call, index=1)
        if name in _STDIO_BUILTINS:
            return {"STDIO"}
        if name in _DYN_BUILTINS or name not in known:
            return {"DYN"}  # Unresolved callee: a parameter, local, or callback.
        return set()
    if not isinstance(func, ast.Attribute):
        return {"DYN"}  # Subscript, call result, or lambda used as a callee.
    base = _dotted_base(func.value)
    if base is not None and base.split(".")[0] in modules:
        return _dotted_channels(_qualify(base, aliases) + "." + func.attr)
    found = _attribute_channels(func.attr, call)
    if func.attr in _STATE_ATTRS and _root_name(func.value) in module_names:
        found.add("STATE")
    return found


def _pure_value(node: ast.AST) -> bool:
    for item in ast.walk(node):
        if isinstance(item, ast.Call):
            if not (isinstance(item.func, ast.Name) and item.func.id in _PURE_CALLS):
                return False
        elif not isinstance(
            item,
            (
                ast.Constant, ast.Name, ast.Attribute, ast.Subscript, ast.Tuple,
                ast.List, ast.Set, ast.Dict, ast.Starred, ast.UnaryOp, ast.BinOp,
                ast.BoolOp, ast.Load, ast.Store, ast.operator, ast.unaryop,
                ast.boolop, ast.expr_context, ast.keyword,
            ),
        ):
            return False
    return True


def _executes(stmt: ast.stmt) -> bool:
    """Return True when importing the module runs this top-level statement's code."""
    if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass)):
        return False
    if isinstance(stmt, ast.Expr):
        return not (
            isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)
        )
    if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
        return stmt.value is not None and not _pure_value(stmt.value)
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        defaults = stmt.args.defaults + [d for d in stmt.args.kw_defaults if d is not None]
        return bool(stmt.decorator_list) or not all(_pure_value(d) for d in defaults)
    if isinstance(stmt, ast.ClassDef):
        return (
            bool(stmt.decorator_list)
            or not all(_pure_value(base) for base in stmt.bases)
            or any(_executes(item) for item in stmt.body)
        )
    if isinstance(stmt, ast.If) and isinstance(stmt.test, ast.Name):
        if stmt.test.id == "TYPE_CHECKING":
            return False  # Never executed at runtime.
    return True


def _scan_source(path: str, raw: bytes | None, denominator: frozenset[str]) -> _SourceFacts:
    if raw is None or not path.endswith(".py"):
        return _OPEN_FACTS
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=path)
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return _OPEN_FACTS

    aliases: dict[str, str] = {}
    modules: set[str] = set()
    edges: set[str] = set()
    open_edge = False
    local_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".")[0]
                aliases[item.asname or root] = item.name if item.asname else root
                modules.add(item.asname or root)
                found, opened = _import_edges(item.name, denominator)
                edges |= found
                open_edge = open_edge or opened
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module is None:
                open_edge = True
                continue
            found, opened = _import_edges(node.module, denominator)
            edges |= found
            open_edge = open_edge or opened
            for item in node.names:
                if item.name == "*":
                    open_edge = True
                    continue
                aliases[item.asname or item.name] = node.module + "." + item.name
                submodule = _module_file(node.module + "." + item.name, denominator)
                if submodule is not None:
                    edges.add(submodule)
                elif (_module_file(node.module, denominator) or "").endswith("__init__.py"):
                    open_edge = True  # A package attribute other than an owned submodule.
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local_names.add(node.name)

    module_names: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_names.add(stmt.name)
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            module_names.update(_bound_names(stmt))
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                module_names.update(item.id for item in ast.walk(target) if isinstance(item, ast.Name))
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            module_names.add(stmt.target.id)
    # Only definitions, imports, and builtins are callable by name here.  A module
    # name bound by assignment may hold a bound method or builtin, so calling it is
    # an opaque callee rather than a known function.
    known = frozenset(local_names | _KNOWN_BUILTINS | set(aliases))
    module_names_frozen = frozenset(module_names)
    modules_frozen = frozenset(modules)
    call_funcs = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}

    channels: set[str] = set()
    references_package = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.IfExp, ast.Match, ast.Assert, ast.Raise)):
            channels.add("BRANCH")
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            channels.add("STATE")
        elif isinstance(node, ast.Call):
            channels |= _call_channels(
                node,
                aliases=aliases,
                modules=modules_frozen,
                module_names=module_names_frozen,
                known=known,
            )
        elif isinstance(node, ast.Attribute):
            # Method tables judge call sites only; a bare attribute such as a
            # dataclass field named commit is data.  Module-qualified references
            # resolve through the full-name table and reflection attributes stay DYN.
            base = _dotted_base(node.value)
            if base is not None and base.split(".")[0] in modules:
                channels |= _dotted_channels(_qualify(base, aliases) + "." + node.attr)
            elif node.attr in _DYN_ATTRS:
                channels.add("DYN")
            elif node.attr in _REF_METHODS:
                # A bound method passed or stored as a value, e.g. map(p.unlink, xs).
                channels |= _attribute_channels(node.attr, None)
        elif isinstance(node, ast.Name):
            if node.id == "verifier":
                references_package = True
            if isinstance(node.ctx, ast.Load) and id(node) not in call_funcs:
                # A builtin referenced as a value, e.g. _OPEN = open, can be called later.
                if node.id in _DYN_BUILTINS and node.id not in aliases:
                    channels.add("DYN")
                elif node.id == "open" and node.id not in aliases:
                    channels |= {"READ", "WRITE"}
                elif node.id in _STDIO_BUILTINS and node.id not in aliases:
                    channels.add("STDIO")
            if node.id in aliases:
                channels |= _dotted_channels(aliases[node.id])
        elif isinstance(node, ast.withitem):
            if isinstance(node.context_expr, ast.Name) and node.context_expr.id not in known:
                channels.add("DYN")  # Implicit __enter__ of an unresolved object.
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name) and decorator.id not in known:
                    channels.add("DYN")
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            for target in targets:
                for item in ast.walk(target):
                    if isinstance(item, (ast.Attribute, ast.Subscript)) and _root_name(item) in module_names_frozen:
                        channels.add("STATE")

    # A module-level import runs at import time even though _executes treats it as
    # inert; one that leaves the owned set is therefore an executed open boundary.
    top_level_open = any(
        _import_edges(item.name, denominator)[1]
        for stmt in tree.body
        if isinstance(stmt, ast.Import)
        for item in stmt.names
    ) or any(
        _import_edges(stmt.module, denominator)[1]
        for stmt in tree.body
        if isinstance(stmt, ast.ImportFrom) and stmt.module and not stmt.level
    )
    executes = top_level_open or any(_executes(stmt) for stmt in tree.body)
    declarative = not executes and not any(
        isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))
        for item in ast.walk(tree)
    )
    return _SourceFacts(
        edges=frozenset(edges),
        channels=frozenset(channels),
        open_edge=open_edge,
        declarative=declarative,
        executes_at_import=executes,
        references_package=references_package,
    )


def _bound_names(stmt: ast.Import | ast.ImportFrom) -> set[str]:
    """Return the top-level names one import statement binds."""
    if isinstance(stmt, ast.Import):
        return {item.asname or item.name.split(".")[0] for item in stmt.names}
    return {item.asname or item.name for item in stmt.names}


def _closure(review: _shared._Review, facts: Mapping[str, _SourceFacts], ambient: _SourceFacts) -> _Closure:
    seen: set[str] = set()
    pending = list(review.owned_paths)
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        pending.extend(facts[path].edges - seen)
    members = [facts[path] for path in seen]
    channels = set().union(*(member.channels for member in members))
    # Importing any verifier module executes the package initializer; its
    # lazy-export hook is reachable only from code that accesses the package name.
    open_edge = ambient.executes_at_import or any(member.open_edge for member in members)
    if any(member.references_package for member in members) and "DYN" in ambient.channels:
        channels.add("DYN")
    return _Closure(
        open_edge=open_edge,
        channels=frozenset(channels),
        declarative=all(member.declarative for member in members),
    )


def _survives(kind: str, closure: _Closure) -> bool:
    if closure.open_edge:
        return False
    if kind in _DECLARATION_ONLY_ROLES:
        return closure.declarative and not closure.channels
    return not (closure.channels & _ROLE_CHANNELS[kind])


def _read_source(root: Path, path: str) -> bytes | None:
    """Read one in-root ordinary file, or None when it is absent or escapes root."""
    candidate = root.joinpath(*path.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        if candidate.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
            return None
        return resolved.read_bytes()
    except OSError:
        return None


def _read_sources(root: Path) -> dict[str, bytes | None]:
    paths = {path for review in _REVIEWS.values() for path in review.owned_paths}
    return {path: _read_source(root, path) for path in sorted(paths | {_AMBIENT_PATH})}


def _bytes_digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


# Positive APPLIES guard.  A SENSOR, MEASUREMENT, PROTOCOL, or ACTUATOR claim is
# kept only when one of its cited files itself contains a call or reference of the
# matching class: a read (SENSOR, MEASUREMENT), a process or remote exchange
# (PROTOCOL), or a write or process command (ACTUATOR).  Unlike the DNE closure gate,
# this is not closure-wide: a sibling's effect cannot establish a cited file's role.
# Names are read from the AST, so strings, comments, and docstrings never count.
# Presence never creates APPLIES; absence withdraws an unsupported claim to canonical
# UNRESOLVED.  POLICY has no channel test here because a rule decision is a BRANCH
# shared by almost every module; its evidence is audited in the catalog instead.
_POSITIVE_ROLE_CHANNELS = {
    "SENSOR": frozenset({"READ"}),
    "MEASUREMENT": frozenset({"READ"}),
    "PROTOCOL": frozenset({"PROC"}),
    "ACTUATOR": frozenset({"WRITE", "PROC"}),
}
# Owner-decision PROTOCOL is the object's primary kind, assigned by the upstream
# ownership catalog.  Withdrawing it would make every apply raise LABEL_CONFLICT, so
# it is kept and reported as a residual until that catalog changes.
_PRIMARY_LABEL_RESIDUALS = frozenset({("vstd-package-owner-decision", "PROTOCOL")})


def _positive_channels(path: str, raw: bytes | None) -> frozenset[str]:
    """Return the channels named by one file's own executable body."""
    if raw is None or not path.endswith(".py"):
        return frozenset()
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=path)
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return frozenset()
    calls = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                found |= _attribute_channels(node.func.attr, node)
            elif isinstance(node.func, ast.Name) and node.func.id == "open":
                found |= _open_mode_channels(node, index=1)
        elif isinstance(node, ast.Attribute) and id(node) not in calls:
            found |= _attribute_channels(node.attr, None)
    return frozenset(found)


def _positively_supported(
    kind: str, paths: tuple[str, ...], positives: Mapping[str, frozenset[str]]
) -> bool:
    required = _POSITIVE_ROLE_CHANNELS.get(kind)
    return required is None or any(positives[path] & required for path in paths)


# One polish command runs this review many times over the same bytes: the migration
# stage is rerun once per stale specialization label it has to hide
# (``package_review_stage_gaps.run_stage``), and refresh asks for the review document
# again.  Inside ``analysis_scope`` each file is analysed once per exact path, bytes and
# denominator; a changed byte is a different key, so a stale verdict can never be
# returned.  Sources are still read fresh on every call.  Outside a scope nothing is kept.
_SCOPE_DEPTH = 0
_SCOPED_ANALYSES: dict[tuple[Any, ...], Any] = {}


@contextmanager
def analysis_scope() -> Iterator[None]:
    """Analyse each distinct reviewed source once for the enclosed command."""
    global _SCOPE_DEPTH
    _SCOPE_DEPTH += 1
    try:
        yield
    finally:
        _SCOPE_DEPTH -= 1
        if _SCOPE_DEPTH == 0:
            _SCOPED_ANALYSES.clear()


def _analysed(analyse: Callable[..., Any], *key: Any) -> Any:
    """Return ``analyse(*key)``, computed once per exact key inside ``analysis_scope``."""
    if not _SCOPE_DEPTH:
        return analyse(*key)
    memo = (analyse, *key)
    if memo not in _SCOPED_ANALYSES:
        _SCOPED_ANALYSES[memo] = analyse(*key)
    return _SCOPED_ANALYSES[memo]


def _verified_reviews(sources: Mapping[str, bytes | None]) -> dict[str, _shared._Review]:
    """Return each review with only the refutations and APPLIES cells the source supports."""
    denominator = frozenset(path for review in _REVIEWS.values() for path in review.owned_paths)
    facts = {
        path: _analysed(_scan_source, path, sources.get(path), denominator)
        for path in denominator
    }
    ambient = _analysed(_scan_source, _AMBIENT_PATH, sources.get(_AMBIENT_PATH), denominator)
    positives = {
        path: _analysed(_positive_channels, path, sources.get(path)) for path in denominator
    }
    verified: dict[str, _shared._Review] = {}
    for object_id, review in _REVIEWS.items():
        closure = _closure(review, facts, ambient)
        applicable = tuple(
            kind
            for kind in review.applicable
            if (object_id, kind) in _PRIMARY_LABEL_RESIDUALS
            or _positively_supported(kind, review.role_paths[kind], positives)
        )
        verified[object_id] = replace(
            review,
            applicable=applicable,
            role_paths={kind: review.role_paths[kind] for kind in applicable},
            refuted=tuple(kind for kind in review.refuted if _survives(kind, closure)),
        )
    return verified


def review_document(root: str | Path | None = None) -> dict[str, Any]:
    """Return a defensive digest-free view of all thirteen exact reviews.

    Refutations are verified against the current source under ``root`` (this
    repository by default); unreadable source downgrades every refutation it touches.
    """
    selected = _PACKAGE_ROOT if root is None else Path(root).resolve(strict=True)
    verified = _verified_reviews(_read_sources(selected))
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
        for object_id, review in verified.items()
    }


def apply_package_semantic_review_admission(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply the complete thirteen-object exact-source review atomically."""
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

    # Analysis reads the same bytes whose digests are compared below, so a verdict
    # is bound to the exact source that produced it.
    sources = _read_sources(selected_root)
    verified = _verified_reviews(sources)
    live_obligations = {
        kind: {
            row["id"]: tuple(row["declaration_fields"])
            for row in _shared._contract_rows(kind)
        }
        for kind in REVIEW_KINDS
    }
    known_obligations = {
        name for obligations in live_obligations.values() for name in obligations
    }
    plans: dict[str, dict[str, Any]] = {}
    for object_id, review in verified.items():
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
        current = _shared._current_evidence(
            selected_root, review.owned_paths, files, object_id=object_id
        )
        for reference in current:
            raw = sources.get(reference["path"])
            if raw is None or _bytes_digest(raw) != reference["sha256"]:
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:"
                    + object_id
                    + ":"
                    + reference["path"]
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
                        _obligation_reason(object_id, review, kind),
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

    # Re-read the full sixty-one-path denominator after semantic preflight.
    # A concurrent writer therefore cannot leave a partly current review.
    for object_id, review in verified.items():
        closing = _shared._source_evidence(selected_root, review.owned_paths)
        if closing != plans[object_id]["opening_evidence"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)
    # The gate also read the admission ambient initializer and the same bytes; a
    # change to any of them after analysis invalidates the verdicts.
    closing_sources = _read_sources(selected_root)
    for path in sorted(sources):
        if closing_sources[path] != sources[path]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + path)

    result = deepcopy(rows)
    for object_id, review in verified.items():
        row = result[object_id]
        plan = plans[object_id]
        declarations = _shared._declarations(review)
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
                "reason": _obligation_reason(object_id, review, kind),
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
    "ADMISSION_OBJECT_IDS",
    "CLAIM_BOUNDARY",
    "REVIEW_KINDS",
    "apply_package_semantic_review_admission",
    "review_document",
]
