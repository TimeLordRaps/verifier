"""Audited domain and domain-contract source-ownership partition.

Terminology: abstract syntax tree (AST); Secure Hash Algorithm 256-bit (SHA-256).

Terminology: directed acyclic graph (DAG).

The declarations cover exactly the residual 39 source paths from the package
ownership audit.  They assign source ownership and accumulated consequence
roles only; they do not establish obligation fulfillment, mechanism truth,
physical effect, financial effect, release authority, or deployment.
"""

from __future__ import annotations

import ast
import hashlib

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


# Domain infrastructure is separated from individual contracts.  Dispatching
# a checker, reading a carrier, and declaring an obligation denominator have
# different consequences even when all three support the same package graph.
DOMAIN_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-domains-package-marker",
        "ARCH",
        ("src/verifier/domains/__init__.py",),
        "Domain package identity and import boundary.",
        "The package marker needs a precise inert owner rather than inheriting the behavior of every domain implementation.",
        "A package marker establishes no domain implementation, execution, or conformance.",
    ),
    ownership_spec(
        "vstd-domain-carrier-protocols",
        "PROTOCOL",
        ("src/verifier/domains/carriers.py",),
        "Bounded HAR and safetensors carrier parsing and measurement-bearing round trips.",
        "Carrier admission and round trips have explicit protocol, measurement, and policy semantics distinct from domain evaluation.",
        "Supplied limited-format carriers establish neither authenticity, execution, nor full domain conformance.",
        "MEASUREMENT",
        "POLICY",
    ),
    ownership_spec(
        "vstd-domain-specification-catalog",
        "POLICY",
        ("src/verifier/domains/catalog.py",),
        "Installed domain specification and dependency catalog.",
        "The catalog observes the selected installed standard and applies finite inclusion and dependency policy.",
        "Completeness is bounded to the selected installed specification and does not establish execution.",
        "MEASUREMENT",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-domain-certificate-engine",
        "VERIFIER",
        ("src/verifier/domains/certification.py",),
        "Installed domain-evaluator dispatch and bounded source-bound certificate production.",
        "Dispatching evaluators acquires evidence and crosses controlled effect and transaction boundaries under explicit policy.",
        "Evaluators are trusted in-process mechanisms; no sandbox, subject-code execution, or external authority is established.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-domain-checking-primitives",
        "VERIFIER",
        ("src/verifier/domains/common.py",),
        "Finite parsing, budget, and certificate-checking primitives.",
        "Shared checking primitives need a precise verification-policy owner without inheriting callers' domain claims.",
        "Helper correctness does not establish the claims made by its callers.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-domain-contracts-package-marker",
        "ARCH",
        ("src/verifier/domains/contracts/__init__.py",),
        "Domain-contract package identity and import boundary.",
        "The package marker needs a precise inert owner separate from the contracts it exposes.",
        "A package marker performs no contract check.",
    ),
    ownership_spec(
        "vstd-object-obligation-inventory",
        "POLICY",
        ("src/verifier/domains/inventory.py",),
        "Retained 26-ObjectKind by nine-tier native obligation inventory and registration denominator.",
        "Selecting the native obligation denominator is an explicit normative policy decision rather than generic package data; distinguishing it from the twelve accumulating extensible roles prevents the retained catalog from being mistaken for complete 38-kind discharge.",
        "The declared native denominator does not discharge extensible-role obligations or establish applicability completeness or fulfillment.",
    ),
    ownership_spec(
        "vstd-mainstay-certificate-engine",
        "VERIFIER",
        ("src/verifier/domains/mainstay_certification.py",),
        "Bounded source-bound mainstay certificate production and replay.",
        "Certificate replay observes retained carrier evidence and applies explicit mainstay policy.",
        "Retained carrier checks are not native full-domain conformance or authentication.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-mainstay-evaluator",
        "VERIFIER",
        ("src/verifier/domains/mainstays.py",),
        "Bounded fixed mainstay carrier evaluation.",
        "Mainstay evaluation observes selected carrier values under an explicit acceptance policy.",
        "A fixed pure evaluator does not establish imported execution or external authority.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-retained-model-training-arithmetic",
        "VERIFIER",
        ("src/verifier/domains/numerical.py",),
        "Retained binary64 dense-model and training-optimizer arithmetic recomputation.",
        "The source recomputes selected numeric observations under explicit tolerance and acceptance policy.",
        "Finite retained values are not accelerator arithmetic, MODEL execution, or TRAIN execution.",
        "MEASUREMENT",
        "POLICY",
    ),
    ownership_spec(
        "vstd-tier3-statics-evaluator",
        "VERIFIER",
        ("src/verifier/domains/statics.py",),
        "Source-bound retained Tier-3 statics evaluation.",
        "The evaluator observes and recomputes finite retained witnesses under explicit policy.",
        "Witness consistency and recomputation do not establish independent external observation.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),

    # Each contract below owns one bounded proposition family.  Generic OBJECT
    # or VERIFIER ownership must not erase controller, protocol, measurement,
    # asset, transaction, or policy consequences introduced by that family.
    ownership_spec(
        "vstd-hardware-ownership-eligibility",
        "VERIFIER",
        ("src/verifier/domains/contracts/accountability.py",),
        "Declared hardware ownership eligibility and asset-policy verification.",
        "Hardware eligibility reasons about an asset relationship and therefore requires ASSET and POLICY consequences.",
        "It does not establish title, custody, physical control, human authenticity, or containment.",
        "ASSET",
        "POLICY",
    ),
    ownership_spec(
        "vstd-application-requirements-compiler",
        "VERIFIER",
        ("src/verifier/domains/contracts/application_requirements.py",),
        "Installed-source application requirement compilation.",
        "The compiler acquires selected sources and derives finite requirements under explicit policy.",
        "The result covers selected structural propositions only, not source authority or the full application.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-certificate-dependency-controller",
        "CONTROLLER",
        ("src/verifier/domains/contracts/certificate_dag.py",),
        "Fail-closed certificate dependency-DAG scheduling and callback observation.",
        "The source schedules and submits dependency callbacks, observes results, and controls a failure-sensitive transaction.",
        "Callbacks are cooperative registered mechanisms, not a sandbox or whole-application controller.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "The exact certificate_dag.py source parses and validates a bounded selected dependency graph, replays registered native certificates, and emits a finite assessment, so this CONTROLLER also has a VERIFIER checking role.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-consent-certificate-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/consent_checks.py",),
        "Source-bound signed consent-certificate protocol verification.",
        "Consent certificates carry message order, timing, observation, and decision policy that must remain explicit.",
        "Configured authority and timing do not prove voluntary consent, legal authority, or enforcement.",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-current-object-replay-router",
        "CONTROLLER",
        ("src/verifier/domains/contracts/current_object_routes.py",),
        "Bounded current-object replay-route selection and invocation.",
        "The source selects, submits, and observes registered replay callbacks under transactional policy.",
        "Routes are trusted installed callbacks; there is no sandbox or proof of general route completeness.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-dangerous-pathway-assessor",
        "VERIFIER",
        ("src/verifier/domains/contracts/dangerous_pathway_security.py",),
        "Source-bound dangerous-pathway assessment over finite retained records.",
        "The assessment observes selected security records and applies explicit danger policy.",
        "It does not select the complete threat catalog, classify the host, establish authority, or execute commands.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-facet-obligation-compiler",
        "VERIFIER",
        ("src/verifier/domains/contracts/facet_coverage.py",),
        "Native-source and specification facet-obligation compilation.",
        "The compiler observes selected sources and derives facet obligations under explicit policy.",
        "The selected catalog does not prove applicability completeness or safety.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-independence-certificate-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/independence_checks.py",),
        "Bounded source-bound independence-certificate verification.",
        "The verifier observes documentary separation evidence under explicit independence policy.",
        "Documentary separation does not prove real actor, causal, or statistical independence.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-independence-projection-policy",
        "POLICY",
        ("src/verifier/domains/contracts/independence_projection.py",),
        "Selected registration-source independence projection.",
        "The projection observes selected source declarations and applies a finite narrowing policy.",
        "The projection is one-way and establishes no semantic equivalence, evidence, or authority.",
        "MEASUREMENT",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-native-child-link-assessor",
        "VERIFIER",
        ("src/verifier/domains/contracts/native_child_links.py",),
        "Source-bound selected native-child identity and link assessment.",
        "The assessor observes declared child links and applies explicit link policy.",
        "It does not replay children or establish their closure, payload, or profile truth.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-object-address-closure-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/object_address_closure.py",),
        "Source-bound reachable object-address closure verification.",
        "Address closure observes selected retained records and applies explicit reachability policy.",
        "Selected retained records do not establish typed composition or payload truth.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-object-facet-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/object_facets.py",),
        "Generic selected-object facet and address verification.",
        "Facet checking observes declarations and applies finite generic object policy.",
        "Generic representation does not satisfy specialized consequence obligations or the full tier.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-object-governance-protocol",
        "PROTOCOL",
        ("src/verifier/domains/contracts/object_governance.py",),
        "Signed governance participant, timing, and status protocol.",
        "Governance records cross a message boundary and require explicit observation and decision policy.",
        "Configured keys are not real authority, legal status, or enforcement.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "The exact object_governance.py source builds and independently rechecks bounded governance certificates, including participant, timing, quorum, and status decisions, so this PROTOCOL also has a VERIFIER checking role.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-grounding-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/object_grounding.py",),
        "Finite source-bound SIM grounding verification.",
        "Grounding checks observe selected declarations and apply explicit simulation policy.",
        "Declared grounding and confinement are not physical containment or complete independence.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-object-lineage-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/object_lineage.py",),
        "Source-bound declared object-lineage verification.",
        "The verifier observes a supplied lineage and applies finite relationship policy without owning that history.",
        "It owns no authoritative history and proves no actual authorship, time, or payload truth; therefore it is not a LEDGER.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-object-statics-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/object_statics.py",),
        "Canonical source-bound collection statics verification.",
        "The verifier observes selected collection records and applies finite structural policy.",
        "Collection shape does not establish composition or payload truth.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-privacy-certificate-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/privacy_checks.py",),
        "Source-bound disclosure and privacy-certificate verification.",
        "The verifier observes selected disclosure records and applies explicit privacy policy.",
        "A complete selected record is not privacy-law compliance, external authority, or enforcement.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-retained-selection-policy",
        "POLICY",
        ("src/verifier/domains/contracts/retained_selection.py",),
        "Registered retained-policy, digest, and limit selection.",
        "The source chooses one bounded evaluation configuration without performing the selected evaluation.",
        "Selection infrastructure does not perform or validate the selected native evaluation.",
    ),
    ownership_spec(
        "vstd-reviewed-conflict-refusal-policy",
        "POLICY",
        ("src/verifier/domains/contracts/reviewed_conflict_lane_refusals.py",),
        "Reviewed closed refusal table for known contract conflicts.",
        "The finite reviewed refusal rows are explicit policy and must not be treated as a generic fallback.",
        "Exact reviewed rows do not provide a general fallback or complete conflict policy.",
    ),
    ownership_spec(
        "vstd-reviewed-singleton-projection-policy",
        "POLICY",
        (
            "src/verifier/domains/contracts/reviewed_singleton_projections.py",
            "src/verifier/domains/contracts/reviewed_singleton_projections_batch04_06.py",
        ),
        "Pinned-module reviewed singleton projection tables.",
        "The projection observes exact installed sources and applies reviewed one-way mapping policy.",
        "The mapping is one-way and establishes no semantic equivalence or underlying evidence truth.",
        "MEASUREMENT",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-selected-native-context-assessor",
        "VERIFIER",
        ("src/verifier/domains/contracts/selected_native_contexts.py",),
        "Current-source selected native-context identity assessment.",
        "The assessor observes selected source identities and applies explicit context policy.",
        "It does not replay the native mechanism or establish global DAG closure.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-retained-execution-measurement",
        "MEASUREMENT",
        ("src/verifier/domains/contracts/spacetime_execution.py",),
        "Retained execution cost, ordering, and cancellation observation.",
        "The source computes execution measurements and applies finite interpretation policy.",
        "Supplied evidence does not establish live enforcement, asymptotics, or actual TIME.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-sim-host-time-mapping-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/spacetime_mapping.py",),
        "Bounded partial SIM-time to host-time mapping verification.",
        "The verifier evaluates declared time measurements under explicit mapping policy.",
        "It establishes no clock authentication, synchronization, interpolation, or execution.",
        "MEASUREMENT",
        "POLICY",
    ),
    ownership_spec(
        "vstd-spacetime-capability-measurement",
        "MEASUREMENT",
        ("src/verifier/domains/contracts/spacetime_profiles.py",),
        "Rational TIME and SPACE capability profile validation and computation.",
        "The source computes declared spacetime quantities under explicit interpretation policy.",
        "Declared coordinates are not a physical clock or universal resource metric.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "The exact spacetime_profiles.py assess_profile procedure checks independently selected digests, canonical profile structure, and bounded TIME or SPACE axioms and returns PASS, FAIL, REFUSAL, or UNKNOWN, so this MEASUREMENT also has a VERIFIER checking role.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-subject-security-chain-verifier",
        "PROTOCOL",
        ("src/verifier/domains/contracts/subject_security.py",),
        "Source-bound anchored receipt-chain inclusion protocol.",
        "The source observes and checks supplied chain messages under explicit security policy without owning their history.",
        "It owns no authoritative history and proves no issuer identity, actual execution, or enforcement; therefore it is not a LEDGER.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "The exact subject_security.py source builds and independently rechecks bounded selected receipt-chain certificates and reproduces their result, so this PROTOCOL also has a VERIFIER checking role.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-typed-facet-verifier",
        "VERIFIER",
        ("src/verifier/domains/contracts/typed_facets.py",),
        "Source-bound typed-facet certificate verification.",
        "The verifier observes selected certificate structure and applies explicit typed-facet policy.",
        "Declared structure does not establish real authority or specialized obligation fulfillment.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-typed-facet-projection-policy",
        "POLICY",
        ("src/verifier/domains/contracts/typed_facets_projection.py",),
        "Pinned registration and route-source typed-facet projection.",
        "The projection observes exact installed sources and applies a finite one-way mapping policy.",
        "The mapping is one-way and does not establish semantic equivalence or evidence truth.",
        "MEASUREMENT",
        "SENSOR",
    ),
)


# Fields whose absent, None, and empty-list values are one semantic state.
# CPython releases differ on which of these are materialized: ast.dump in 3.13+
# omits empty ``Call.args``/``Call.keywords`` that 3.12 prints, and 3.12+ adds
# ``type_params=[]`` to definitions that 3.11 lacks.  Neither difference is
# code, and no node type in the owned source distinguishes the three states.
# ``Constant.value`` is exempt because None is a real constant there.
# ``type_comment`` is populated only with type_comments=True and is not executable.
_IGNORED_AST_FIELDS = frozenset({"type_comment"})


def _canonical_value(value: object) -> str:
    if isinstance(value, ast.AST):
        return _canonical_node(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical_value(item) for item in value) + "]"
    if value is None:
        return "None"
    return f"{type(value).__name__}:{value!r}"


def _canonical_node(node: ast.AST) -> str:
    parts = []
    for name in sorted(node._fields):
        if name in _IGNORED_AST_FIELDS:
            continue
        value = getattr(node, name, None)
        exempt = isinstance(node, ast.Constant) and name == "value"
        if not exempt and (value is None or (isinstance(value, list) and not value)):
            continue
        parts.append(f"{name}={_canonical_value(value)}")
    return f"{type(node).__name__}({','.join(parts)})"


def canonical_executable_ast(tree: ast.Module) -> str:
    """Canonical text of the executable syntax, excluding a leading module docstring.

    Node types and fields are emitted in sorted field-name order with explicit
    field names, so the form is deterministic across interpreter releases and
    does not depend on ``ast.dump`` formatting.  Positions and comments are not
    part of the tree and are therefore not part of the form.
    """
    body = tree.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return "Module(body=[" + ",".join(_canonical_value(item) for item in body) + "])"


def canonical_executable_ast_sha256(source: str) -> str:
    """SHA-256 of the canonical executable form of ``source``."""
    tree = ast.parse(source)
    return hashlib.sha256(canonical_executable_ast(tree).encode("utf-8")).hexdigest()


__all__ = [
    "DOMAIN_OWNERSHIP_SPECS",
    "SemanticOwnershipSpec",
    "canonical_executable_ast",
    "canonical_executable_ast_sha256",
]
