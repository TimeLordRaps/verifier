"""Audited ownership of installed normative contract assets.

The Verifier Standard (VSTD) ships specification text, strict schemas, and
selected installed and documentation profiles as source-owned package members.
These declarations cover the exact residual ordinary-file denominator under
``standard``, ``schemas``, and both source and documentation ``profiles``
directories after the existing semantic catalog is subtracted.

The assets state architecture, policy, protocol, data, or verifier contracts;
they do not execute a mechanism, observe a subject, establish conformance, or
grant release authority.  Grouping follows the proposition family carried by
the bytes, not merely the filename or file extension.
"""

from __future__ import annotations

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


def _standard(*names: str) -> tuple[str, ...]:
    return tuple(f"src/verifier/standard/{name}" for name in names)


def _schemas(*names: str) -> tuple[str, ...]:
    return tuple(f"src/verifier/schemas/{name}" for name in names)


def _profiles(*names: str) -> tuple[str, ...]:
    return tuple(f"src/verifier/profiles/{name}" for name in names)


# The sole authored reasons.vstd conservatively selects APPLIES for every open
# kind on the cumulative agency crosswalk.  These are obligation-retention
# decisions, not claims that the static crosswalk instantiates those subjects or
# reaches their effects.  POLICY and PROTOCOL are already declared labels;
# OBJECT is intentionally absent.
AGENCY_CROSSWALK_APPLIES = (
    "ACTOR",
    "ACTUATOR",
    "AGENT",
    "ARCH",
    "ASSET",
    "BENCH",
    "BOT",
    "COLLECTIVE",
    "CONTROLLER",
    "DATA",
    "ENV",
    "EVENT",
    "FINBOT",
    "GRAPH",
    "HARDWARE",
    "HARNESS",
    "HUMAN",
    "HYPER",
    "IDENTITY",
    "LEDGER",
    "MARKET",
    "MEASUREMENT",
    "MODEL",
    "OWNER",
    "RECEIPT",
    "ROBOT",
    "ROLE",
    "SENSOR",
    "SIM",
    "SPACE",
    "TIME",
    "TOKEN",
    "TRAIN",
    "TRANSACTION",
    "VERIFIER",
)

# Root-role decisions are restricted by the ownership contract to namespace
# roots.  The ten OBJECT refinements are bound separately by the semantic
# review's source-audited applicability table.
AGENCY_CROSSWALK_ROOT_APPLIES = (
    "ACTOR",
    "AGENT",
    "ARCH",
    "BENCH",
    "BOT",
    "COLLECTIVE",
    "DATA",
    "ENV",
    "EVENT",
    "GRAPH",
    "HARDWARE",
    "HARNESS",
    "HUMAN",
    "HYPER",
    "IDENTITY",
    "MODEL",
    "OWNER",
    "RECEIPT",
    "ROLE",
    "SIM",
    "SPACE",
    "TIME",
    "TOKEN",
    "TRAIN",
    "VERIFIER",
)

AGENCY_CROSSWALK_ADDITIVE_APPLIES = tuple(
    kind for kind in AGENCY_CROSSWALK_APPLIES if kind not in AGENCY_CROSSWALK_ROOT_APPLIES
)


def _agency_crosswalk_decisions():
    return tuple(
        root_role_decision(
            kind,
            "APPLIES",
            "The sole authored reasons.vstd conservatively selects APPLIES for "
            + kind
            + " on this exact agency crosswalk so its obligations remain required; "
            "this decision establishes neither subject instantiation nor external effect.",
        )
        for kind in AGENCY_CROSSWALK_ROOT_APPLIES
    )


def _documentation_profiles(*names: str) -> tuple[str, ...]:
    return tuple(f"docs/profiles/{name}" for name in names)


NORMATIVE_ASSET_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    # Governing architecture, admission, polish, release, and runner contracts
    # are separated because each selects a different authority and wire scope.
    ownership_spec(
        "vstd-profile-architecture-assets",
        "POLICY",
        _standard(
            "GRAPH-1.md",
            "GRAPH-2.md",
            "GRAPH-3.md",
            "GRAPH-4.md",
            "GRAPH-5.md",
            "GRAPH_GROUNDING.md",
            "GROUNDED_CERTIFICATION.md",
            "LADDER.md",
            "META_TIERS.md",
            "VSTD-1.md",
            "VSTD-2.md",
            "VSTD-3.md",
            "VSTD-4.md",
            "VSTD-5.md",
            "WIRE_IDENTIFIERS.md",
        )
        + _schemas(
            "verifier-graph-assurance-1.schema.json",
            "verifier-grounded-certification-1.schema.json",
            "verifier-grounded-policy-1.schema.json",
            "verifier-grounded-request-1.schema.json",
        ),
        "Numbered-profile, Graph-axis, closure-coordinate, assurance-event, and wire-dispatch policy architecture.",
        "The two-axis profile system and its serialized identifiers need one explicit architecture with normative rule and participant boundaries.",
        "These static texts and schemas describe the standard's layout and wire shape, not a computational-model ARCH; they execute no profile, replay no assurance event, and establish no conformance or adoption.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-domain-certification-assets",
        "PROTOCOL",
        _standard("DOMAIN_GROUNDING.md", "DOMAIN_OBLIGATIONS.md")
        + _schemas(
            "verifier-domain-certification-1.schema.json",
            "verifier-domain-evidence-1.schema.json",
            "verifier-domain-policy-1.schema.json",
            "verifier-domain-request-1.schema.json",
        ),
        "Domain request, policy, evidence, certification, grounding, and obligation interchange contract.",
        "The four participant records and their grounding rules must remain a coherent protocol rather than unrelated generic data files.",
        "Structural and normative assets do not invoke a domain evaluator, authenticate intent, or qualify a certificate.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-repository-admission-assets",
        "POLICY",
        _standard(
            "CURRENT_APPLICATION_REQUIREMENTS.md",
            "CURRENT_NATIVE_OPERATION_CONTRACTS.md",
            "CURRENT_REVIEWED_CONFLICT_LANE_REFUSALS.md",
            "CURRENT_REVIEWED_SINGLETON_PROJECTIONS.md",
            "CURRENT_REVIEWED_SINGLETON_PROJECTIONS_BATCH04_06.md",
            "CURRENT_SELECTED_NATIVE_CONTEXTS.md",
            "EXTENSIBLE_NAMESPACE.md",
            "FACET_OBLIGATION_DERIVATION.md",
            "NAMESPACE_OBJECTS.md",
            "NATIVE_CHILD_LINKS.md",
            "OBJECT_CONTEXT_CLOSURE.md",
            "PACKAGE_OWNER_DECISIONS.md",
            "SEMANTIC_CONTRACT_SELECTION.md",
            "TIER_ZERO.md",
        )
        + _schemas(
            "verifier-manifest-object-gate-1.schema.json",
            "verifier-namespace-manifest-3.schema.json",
            "verifier-objects-manifest-1.schema.json",
            "verifier-objects-manifest-2.schema.json",
            "verifier-objects-manifest-3.schema.json",
            "verifier-objects-manifest-4.schema.json",
            "verifier-objects-manifest-5.schema.json",
            "verifier-objects-manifest-6.schema.json",
            "verifier-package-contract-coverage-1.schema.json",
            "verifier-package-contract-coverage-2.schema.json",
            "verifier-package-obligation-candidate-selection-1.schema.json",
        ),
        "Repository-admission namespace, manifest evolution, classification, projection, ownership, and object-gate policy.",
        "Admission needs explicit kind, source, migration, precedence, refusal, and manifest-wire rules so generic OBJECT labeling cannot erase consequences.",
        "The assets prescribe and encode admission inputs; they do not census a repository, reconcile a manifest, execute an obligation, or establish polish.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-package-polish-assets",
        "POLICY",
        _standard(
            "PACKAGE_POLISH.md",
            "POLISHED_ARTIFACTS.md",
            "POLISH_INVENTORY.md",
            "POLISH_INVENTORY_AUTHORITY.md",
            "POLISH_INVOCATION_LEDGER.md",
            "POLISH_PUBLIC_AUTHORITY.md",
            "POLISH_REQUIREMENTS.md",
        )
        + _schemas(
            "verifier-gate-publication-1.schema.json",
            "verifier-manifest-package-polish-1.schema.json",
            "verifier-manifest-package-polish-2.schema.json",
            "verifier-manifest-package-polish-capacity-2.schema.json",
            "verifier-manifest-package-polish-publication-rejected-1.schema.json",
            "verifier-polish-manifest-refresh-blocked-1.schema.json",
            "verifier-polish-preparation-bundle-1.schema.json",
            "verifier-polish-workflow-policy-1.schema.json",
            "verifier-quality-profile-1.schema.json",
        ),
        "Package-polish inventory, applicability, authority, preparation, finding, and retained-report contract.",
        "Polish decisions depend on selected inventory, reason, evidence, authority, and preparation precedence rather than the presence of a report-shaped document.",
        "Static requirements and schemas do not run a gate, authenticate an invocation, make preparation atomic, or establish any polish tier.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-package-self-polish-assets",
        "VERIFIER",
        _standard(
            "CURRENT_TEN_TIER_PROGRESSION.md",
            "PACKAGE_SELF_POLISH.md",
            "SELF_POLISH_ESTATE.md",
            "SELF_POLISH_EVIDENCE.md",
            "SELF_POLISH_FACET_REASONS.md",
            "SELF_POLISH_STATICS.md",
            "SELF_POLISH_TIERS.md",
        )
        + _schemas(
            "verifier-package-graph-self-polish-assessment-1.schema.json",
            "verifier-package-graph-self-polish-recheck-1.schema.json",
            "verifier-self-derivation-mechanism-1.schema.json",
            "verifier-self-polish-native-replay-manifest-2.schema.json",
            "verifier-self-polish-native-replay-receipt-2.schema.json",
        ),
        "Package-Graph self-assessment, replay, estate, reasons, statics, and cumulative-tier verifier contract.",
        "Self-polish needs an exact denominator, source binding, distinct native replay, and retained uncertainty rules instead of self-asserted success.",
        "These verifier descriptions and wire schemas run nothing and supply no independence, application authority, tier PASS, release, or deployment evidence.",
        "POLICY",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-core-application-release-assets",
        "POLICY",
        _standard(
            "APPLICATION_RELEASE_CONSUMER.md",
            "CORE_APPLICATION_AUTHORITY.md",
            "CORE_FULL_GATE_REPLAY.md",
            "CORE_NINE_TIER_RELEASE.md",
            "CORE_OBLIGATION_UNION.md",
            "CORE_SECURITY9_ACCOUNTING.md",
            "CORE_SECURITY9_REQUIREMENTS.md",
            "CORE_V2_RELEASE_SCOPE.md",
        ),
        "Private core-application denominator, obligation union, full-gate replay, Security-9 accounting, and release-selection contract.",
        "Application authority and release selection must remain distinct from candidate bytes, individual gate results, and union membership.",
        "These candidate rules select no application, authenticate no owner, execute no gate, and confer no release or publication authority.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-language-runner-isolation-assets",
        "PROTOCOL",
        _standard("LANGUAGE_RUNNERS.md", "SIM_ISOLATION.md"),
        "Language-runner extension, debugger hook, optional sandbox, and bounded SIM-isolation interface contract.",
        "Cross-language invocation and isolation require explicit request, response, compatibility, failure, and confinement boundaries.",
        "Documentation does not install a runner or OpenShell, execute a subject, provide a sandbox, or prove isolation.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-corrigibility-control-assets",
        "POLICY",
        _standard("CORRIGIBILITY_RESEARCH.md", "TRAIN_CONTROL.md"),
        "Corrigibility research boundary and selected finite TRAIN mediation contract.",
        "The research proposal and bounded action policy must preserve their distinct authority, stop, replay, and unresolved-safety assumptions.",
        "Static policy is neither corrigibility evidence nor execution mediation and does not establish MODEL, AGENT, BOT, ROBOT, or SIM safety.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-prdel-language-assets",
        "PROTOCOL",
        _standard(
            "PRDEL_NATIVE_V2.md",
            "PRDEL_NATIVE_V2_CLI.md",
            "PRDEL_NATIVE_V2_COORDINATES.md",
            "PRDEL_SHARDS.md",
        )
        + _schemas(
            "verifier-prdel-1.schema.json",
            "verifier-prdel-2.schema.json",
            "verifier-prdel-cli-1.schema.json",
            "verifier-prdel-cli-2.schema.json",
            "verifier-prdel-compilation-1.schema.json",
            "verifier-prdel-compilation-shards-1.schema.json",
            "verifier-prdel-compilation-shards-2.schema.json",
            "verifier-prdel-replay-plan-1.schema.json",
            "verifier-prdel-shard-description-1.schema.json",
            "verifier-prdel-v2-document-shard-1.schema.json",
            "verifier-prdel-v2-release-subject-2.schema.json",
            "verifier-prdel-v2-shard-manifest-1.schema.json",
        )
        + _profiles(
            "prdel-manifest-2-selection.json",
            "prdel-native-v2-cli-selection-1.json",
            "prdel-native-v2-cli-selection-2.json",
            "prdel-native-v2-selection-1.json",
            "prdel-native-v2-selection-2.json",
        ),
        "Pull Request Domain Explanation Language document, compilation, shard, replay, command, and source-selection wire contract.",
        "Compilation and replay involve ordered compatible records and externally selected coordinates that cannot be collapsed into generic documentation data.",
        "Schema-valid or profile-selected PRDEL bytes do not inspect source, execute replay, clear a gate, qualify a release, or authorize publication.",
        "POLICY",
    ),

    # Each additive mechanism family keeps its prose, strict record schema, and
    # selected profile together.  The owner represents the declared contract;
    # the boundary denies execution or conformance from those bytes alone.
    ownership_spec(
        "vstd-artifact-control-assets",
        "PROTOCOL",
        _standard("ARTIFACT_CONTROL.md"),
        "Exact-byte freeze, readable seal, thaw, lineage, and recovery protocol specification.",
        "Freeze, seal, encryption, thaw, lineage, and preservation are distinct ordered states with different failure and authority semantics.",
        "The specification performs no filesystem mutation, preservation, signing, encryption, or recovery and proves no privileged-write exclusion.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-bounded-completeness-assets",
        "VERIFIER",
        _standard("BOUNDED_COMPLETENESS.md")
        + _schemas("verifier-bounded-completeness-1.schema.json")
        + _profiles("bounded-completeness-mechanism-1.json"),
        "Finite externally grounded denominator and decisive-disposition completeness verifier contract.",
        "Completeness is meaningful only relative to exact denominator bytes, supported observations, replay, and bounded disposition policy.",
        "Static mechanism and record assets do not inspect a denominator, replay an observation, or establish completeness outside or inside any actual scope.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-certificate-dependency-assets",
        "POLICY",
        _standard("CERTIFICATE_DAG.md"),
        "Exact certificate dependency-Graph closure, correlation, replay, and clearance policy.",
        "Certificate prerequisites and cross-profile edges need explicit acyclic ordering, selected-child identity, and failure precedence.",
        "The text schedules or replays no certificate and supplies no dependency, closure, or clearance evidence.",
        "PROTOCOL",
    ),
    # Cross-role agency routes are a distinct proposition family: one table
    # joins AGENT, BOT, ROBOT, and FINBOT child certificates by exact operands.
    # Single-role BOT and AGENT policy owners disclaim ROBOT consequence, so
    # the crosswalk cannot be absorbed by either without contradicting them.
    ownership_spec(
        "vstd-agency-surface-crosswalk-assets",
        "POLICY",
        _standard("AGENCY_SURFACE.md"),
        "Cumulative BOT, ROBOT, and FINBOT agency-surface route table, applicability condition, and retained-child join policy.",
        "Valid AGENT, BOT, ROBOT, and FINBOT certificates can name different operands, traces, or boundaries; roles accumulate by selected effect, and an OBJECT label or unknown applicability cannot exempt a conditional route.",
        "The conservative root applicability decisions retain every open obligation but do not promote the static crosswalk into the represented subjects. The crosswalk supplies no new evidence source; actual identity, causality, operational boundaries, physical safety, legal authority, real-money effects, and subject instantiation remain NOT_ESTABLISHED.",
        "PROTOCOL",
        root_role_decisions=_agency_crosswalk_decisions(),
    ),
    ownership_spec(
        "vstd-consent-protocol-assets",
        "PROTOCOL",
        _standard(
            "CONSENT_PUBLIC_ADMISSION.md",
            "CONSENT_STAGES.md",
            "CURRENT_CONSENT_CHECKS.md",
        ),
        "Public-key holder admission, distinct consent-stage predicates, and current consent-certificate protocol.",
        "Holder selection, signatures, purpose, timing, withdrawal, replay, and stage distinction are participant protocol and policy concerns.",
        "The specifications authenticate no real holder, determine no voluntariness or legal authority, and execute no consent check.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-dangerous-pathway-assets",
        "VERIFIER",
        _standard("DANGEROUS_PATHWAY_SECURITY.md")
        + _schemas(
            "claim-garden-dangerous-pathway-assessment-1.schema.json",
            "claim-garden-dangerous-pathway-assessment-2.schema.json",
            "verifier-dangerous-pathway-certificate-1.schema.json",
            "verifier-dangerous-pathway-request-1.schema.json",
        ),
        "Dangerous-pathway request, certificate, multi-decision assessment, and Claim Garden interchange contract.",
        "Pathway scope, evidence, separate decisions, aggregation, and consumer transport need an exact verifier and protocol boundary.",
        "The text and schemas identify no complete danger catalog, inspect no subject, execute no assessment, and establish no safety or publication authority.",
        "POLICY",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-deriver-self-status-assets",
        "VERIFIER",
        _standard("DERIVER_SELF_STATUS.md")
        + _schemas("verifier-deriver-self-status-1.schema.json")
        + _profiles("deriver-self-status-checker-1.json"),
        "Actual-deriver declaration, executable identity, recorded invocation, fresh replay, and transcript comparison contract.",
        "A self-status claim requires exact executable and runtime coordinates plus independent fresh-directory replay rather than producer assertion.",
        "Static rules and wire records do not launch the deriver, reproduce a transcript, establish independence, or validate any generated claim.",
        "POLICY",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-finite-authority-assets",
        "POLICY",
        _standard("FINITE_AUTHORITY_COMPOSITION.md")
        + _schemas("verifier-authority-model-1.schema.json"),
        "Finite declared authority-state, transition, correspondence, exception, and composition contract.",
        "Authority claims require explicit actors, transitions, observations, precedence, and correspondence rather than graph shape alone.",
        "A schema-valid authority model does not authenticate an actor, observe access, enforce a permission, or prove runtime correspondence.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-finite-record-issuance-assets",
        "PROTOCOL",
        _standard("FINITE_RECORD_ISSUANCE.md")
        + _schemas("verifier-push-request-1.schema.json"),
        "Acyclic finite-record authorization, exact commit, cancellation, selection, and host-neutral push-request contract.",
        "Issuance crosses an authority and transport boundary with ordering, retry, cancellation, and finality questions.",
        "The static contract transmits, commits, or publishes nothing and grants no account, repository, release, or full-application authority.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-typed-formation-assets",
        "PROTOCOL",
        _standard("FORMATION_RECEIPT.md", "TYPED_FORMATION.md")
        + _schemas("verifier-typed-formation-1.schema.json")
        + _profiles("typed-formation-1.json"),
        "Typed formation grammar, subject, path, proof, resource, receipt, storage, and inspection contract.",
        "Formation records carry ordered endpoint, quotation, composition, observation, and retained-resource semantics across producer and checker.",
        "Grammar, profile, and schema bytes neither form a subject nor retrieve, execute, preserve, qualify, or authorize an artifact.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-global-cycle-assets",
        "VERIFIER",
        _standard("GLOBAL_CYCLE_ASSESSMENT.md")
        + _schemas(
            "graph-topology.schema.json",
            "verifier-global-cycle-assessment-1.schema.json",
        ),
        "Selected topology, relation, cycle, closure, and finite global-Graph assessment contract.",
        "Cycle conclusions depend on exact graph and relation inputs, source binding, closure facets, and failure precedence.",
        "Schemas and text inspect no graph and establish no topology completeness, runtime causality, or global closure.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-proposition-transfer-assets",
        "VERIFIER",
        _standard("PROPOSITION_TRANSFER.md")
        + _schemas("verifier-proposition-transfer-1.schema.json")
        + _profiles("proposition-transfer-rule-1.json"),
        "Finite proposition membership, context, premise, compiled-rule, transfer, refusal, and receipt contract.",
        "A proposition may transfer only under exact rule, input, context, and evidence bindings with explicit refusal semantics.",
        "Static rules and records perform no transport, evaluation, or enforcement and establish no premise or conclusion as true.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-public-checkability-assets",
        "PROTOCOL",
        _standard("PUBLIC_CHECKABILITY.md"),
        "Authenticated finite public-witness disclosure, selection, replay, and resource-outcome protocol.",
        "Public checking needs exact witness availability, authentication, selection, ordering, and failure semantics separate from confidential evidence.",
        "The specification discloses or authenticates no witness, performs no replay, and grants no public acceptance or publication authority.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-relation-boundary-assets",
        "VERIFIER",
        _standard("RELATION_BOUNDARY.md")
        + _schemas("verifier-relation-boundary-1.schema.json")
        + _profiles("relation-boundary-mechanism-1.json"),
        "Finite relation-frame, facet-map, topology, qualification, and boundary-check contract.",
        "Relation claims need explicit accepted frames, maps, qualification rules, and bounded failure outcomes rather than resemblance.",
        "Static mechanism assets compare no relation and prove no semantic equivalence, causal relation, or completeness.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-runtime-authority-correspondence-assets",
        "VERIFIER",
        _standard("RUNTIME_AUTHORITY_CORRESPONDENCE.md")
        + _profiles("runtime-authority-correspondence-profile-1.json"),
        "Declared authority model, bound execution trace, fresh replay, event mapping, and correspondence verifier contract.",
        "Runtime correspondence requires exact retained bytes, ordered participant events, reconstruction, and explicit completeness limits.",
        "The text and selected profile launch no process, retain no event ledger, and establish no runtime authority or enforcement.",
        "POLICY",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-selected-secret-gate-assets",
        "POLICY",
        _standard("SELECTED_SECRET_GATE.md"),
        "Externally selected secret-presence gate, refusal, and disclosure policy.",
        "Secret checks need exact selected scope, authority, non-disclosure, and unavailable-input behavior rather than accidental environment access.",
        "The specification reads no secret, authenticates no selector, and supplies no security or release clearance.",
    ),
    ownership_spec(
        "vstd-source-grounding-assets",
        "VERIFIER",
        _standard("SOURCE_GROUNDING.md")
        + _schemas("verifier-source-grounding-1.schema.json")
        + _profiles("source-grounding-mechanism-1.json"),
        "Canonical source-frame, pointer, equality, qualification, and source-grounding verifier contract.",
        "Grounding requires exact source bytes, interpretation, context, and supported mechanism selection instead of an unqualified digest.",
        "Static assets read no source and establish no authorship, freshness, semantic truth, or source-grounded result.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-spacetime-context-assets",
        "POLICY",
        _standard("SPACETIME_CONTEXT_EXTENSION.md"),
        "TIME, SPACE, SIM-host mapping, capability, execution-observation, and contextual-namespace contract.",
        "Units, mappings, retained observations, costs, and qualification assumptions must be explicit before spacetime claims compose.",
        "The specification measures no clock, memory, computation, physical space, or simulation state and establishes no mapping accuracy.",
    ),
    ownership_spec(
        "vstd-zero-identity-token-assets",
        "PROTOCOL",
        _standard("IDENTITY_OCCUPANCY.md", "ZIZK_TOKENS.md")
        + _schemas(
            "verifier-aging-token-1.schema.json",
            "verifier-birth-token-1.schema.json",
            "verifier-lifetime-token-1.schema.json",
        ),
        "Adjacent identity occupancy and birth, aging, lifetime-capability, revocation, and prohibited-inference token protocol.",
        "Token lifecycle messages require exact epoch, scope, expiry, revocation, replay, and identity-adjacency rules.",
        "Schemas and prose mint, verify, revoke, or transmit no token and establish no civil identity, personhood, tenure, capability, or zero-knowledge proof.",
        "POLICY",
    ),

    # These schema-only families are wire or inert-data contracts.  They stay
    # separate from runtime producers and consumers so shape cannot masquerade
    # as storage, transport, verification, or receipt truth.
    ownership_spec(
        "vstd-artifact-network-wire-assets",
        "PROTOCOL",
        _schemas("verifier-artifact-network-1.schema.json"),
        "Verification-artifact network record and relationship interchange grammar.",
        "Artifact publishers and consumers need explicit record identity, relationship, compatibility, and replay shape.",
        "Schema validity establishes no artifact correctness, publisher identity, network publication, availability, or authority.",
    ),
    ownership_spec(
        "vstd-component-index-data-assets",
        "DATA",
        _schemas("verifier-component-index-1.schema.json"),
        "Content-addressed stored-component index data grammar.",
        "Index identity, order, paths, and digest references need one inert data contract separate from storage behavior.",
        "The schema stores, discovers, retrieves, qualifies, or executes no component.",
    ),
    ownership_spec(
        "vstd-explanation-definition-data-assets",
        "DATA",
        _schemas("verifier-explanation-definitions-1.schema.json"),
        "Canonical authored explanation, invariant, and requirement-definition data grammar.",
        "Authored intent needs a distinct retained representation from checked source facts and later commit bindings.",
        "Schema-valid definitions prove no intent, invariant, requirement authority, execution, coverage, or completeness.",
    ),
    ownership_spec(
        "vstd-native-replay-metadata-assets",
        "DATA",
        _schemas(
            "native-replay-operation-descriptor-1.schema.json",
            "native-replay-operation-lookup-1.schema.json",
        ),
        "Finite native-operation descriptor and lookup-result metadata grammar.",
        "Operation identity, support, and lookup output need inert metadata separate from native requests, policy, evidence, and results.",
        "Metadata description and lookup PASS do not execute or qualify native replay.",
    ),
    ownership_spec(
        "vstd-silo-protocol-assets",
        "PROTOCOL",
        _schemas(
            "verifier-silo-assessment-1.schema.json",
            "verifier-silo-assessment-receipt-1.schema.json",
            "verifier-silo-composition-1.schema.json",
            "verifier-silo-composition-assessment-1.schema.json",
            "verifier-silo-composition-assessment-receipt-1.schema.json",
            "verifier-silo-formation-receipt-1.schema.json",
            "verifier-silo-transfer-1.schema.json",
        ),
        "Silo formation, transfer, composition, assessment, and receipt interchange grammar.",
        "Selected snapshot transport and composition require explicit members, ordering, bindings, result axes, and receipt replay boundaries.",
        "Schema validity performs no transfer or composition and establishes no artifact correctness, publisher identity, storage, or trust.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-simulation-risk-receipt-assets",
        "PROTOCOL",
        _schemas(
            "verifier-risk-profile-2.schema.json",
            "verifier-simulation-receipt-1.schema.json",
        ),
        "Experimental simulation and multi-facet risk declaration and receipt grammar.",
        "Simulation inputs, outputs, risk facets, claim limits, and receipt identity require retained typed records rather than prose inference.",
        "Schema-valid receipts establish no simulation execution, physical fidelity, MODEL safety, risk completeness, or real-world authority.",
        root_role_decisions=(
            root_role_decision(
                "RECEIPT",
                "DOES_NOT_APPLY",
                "These files define simulation-risk and receipt wire grammars; schema documents are not receipt instances with bound subject and hardware operands.",
            ),
        ),
    ),

    # Documentation profiles are non-normative selected policies or exchange
    # contracts.  They are source-owned but confer neither numbered-profile
    # conformance nor external adoption.
    ownership_spec(
        "vstd-competition-evaluation-profile-assets",
        "POLICY",
        _documentation_profiles("competition-evaluation.md"),
        "Non-normative scored-evaluation surface, evidence-chain, hidden-test horizon, timing, and bounded-claim profile.",
        "Competition and scientific evaluation claims need exact task, data, model, environment, scorer, time, evidence, and organizer-authority boundaries.",
        "The profile runs no evaluation and establishes no score correctness, benchmark quality, ranking, prize eligibility, organizer acceptance, adoption, or endorsement.",
    ),
    ownership_spec(
        "vstd-experimental-workflow-profile-assets",
        "PROTOCOL",
        _documentation_profiles(
            "experimental-workflow.md",
            "experimental-workflow.schema.json",
        ),
        "Non-normative experiment question, hypothesis, budget, action, observation, intervention, horizon, and workflow-event interchange profile.",
        "Workflow systems need a strict verdict-neutral exchange that preserves native results, mapping status, amendments, challenges, and unresolved horizons.",
        "Profile or schema validity executes no experiment, verifies no evidence, maps no native result to VSTD, and does not turn a workflow, merge, or publication into PASS.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-three-hardware-integration-profile-assets",
        "POLICY",
        _documentation_profiles(
            "vstd-3/artifact-tracing.md",
            "vstd-3/compatibility.md",
            "vstd-3/references.md",
            "vstd-3/threat-model.md",
            "vstd-3/vendor-integration.md",
        ),
        "VSTD-3 hardware-accountability threat model, compatibility, vendor-integration, artifact-tracing, and source-reference profile guidance.",
        "Device evidence and integration guidance need explicit adversaries, trust boundaries, formats, carrier effects, vendor capabilities, and unsupported cases.",
        "These non-executable documents observe or attest no device, embed no marker, qualify no vendor adapter, and establish no physical security, mediation, or endorsement.",
        "PROTOCOL",
    ),

    # Current-object documents are retained as separate policy owners.  Each
    # family selects different propositions and exclusions even though all are
    # static normative inputs to their independently implemented checkers.
    ownership_spec(
        "vstd-current-actor-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_ACTOR_CLOSURE.md",
            "CURRENT_ACTOR_DECISION_RECORD.md",
            "CURRENT_ACTOR_REPLAY.md",
        ),
        "Current ACTOR decision-record, accountability replay, and finite closure policy.",
        "ACTOR chronology, decisions, replay, and closure need explicit retained selection and outcome rules.",
        "The texts retain no real actor history, execute no replay, and establish no identity, accountability, or closure.",
    ),
    ownership_spec(
        "vstd-current-agent-policy-assets",
        "POLICY",
        _standard("CURRENT_AGENT_CEILING_FIXITY.md", "CURRENT_AGENT_CHECKS.md"),
        "Current AGENT retained trajectory, harness, environment, model, and fixed-observation-ceiling policy.",
        "An open-ended AGENT claim needs an explicit observation ceiling and selected retained checks rather than implied boundedness.",
        "Static policy observes or confines no AGENT and establishes no HARNESS, MODEL, ENV, safety, or corrigibility result.",
    ),
    ownership_spec(
        "vstd-current-arch-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_ARCH_RESOLUTION.md",
            "CURRENT_ARCH_SCHEDULE.md",
            "CURRENT_ARCH_SHAPES.md",
        ),
        "Current ARCH operator resolution, tensor-shape consistency, and retained schedule policy.",
        "Architecture claims require selected operators, arities, shapes, dependencies, and order with explicit precedence.",
        "The documents instantiate or execute no computational architecture and establish no model behavior.",
    ),
    ownership_spec(
        "vstd-current-bench-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_BENCH_ATTEMPTS.md",
            "CURRENT_BENCH_CHECK_PROJECTIONS.md",
            "CURRENT_BENCH_CHECKS.md",
        ),
        "Current BENCH problems, oracles, attempts, budgets, coverage, and reviewed projection policy.",
        "Benchmark meaning depends on exact problem, oracle, attempt, selection, budget, and coverage rules.",
        "The texts run no benchmark and establish no oracle correctness, representative coverage, performance, or best-of-N validity.",
    ),
    ownership_spec(
        "vstd-current-bot-policy-assets",
        "POLICY",
        _standard("CURRENT_BOT_CHECKS.md", "CURRENT_BOT_INHERITED_CEILING.md"),
        "Current simulated BOT environment, agent, action, trajectory, and inherited-observation-ceiling policy.",
        "A BOT inherits bounded SIM and AGENT surfaces whose ceilings and selected evidence must remain explicit.",
        "The policy instantiates no BOT or SIM and has no ROBOT, physical-actuation, deployment, or real-world consequence claim.",
    ),
    ownership_spec(
        "vstd-current-collective-protocol-assets",
        "PROTOCOL",
        _standard(
            "CURRENT_COLLECTIVE_CONSTRAINTS.md",
            "CURRENT_COLLECTIVE_DECISION_CLOSURE.md",
            "CURRENT_COLLECTIVE_LIFECYCLE.md",
        )
        + _schemas("collective_closure_evidence.json"),
        "Current COLLECTIVE membership lifecycle, constraints, point-decision closure, and retained-evidence protocol.",
        "Membership changes and decisions require participant roles, ordering, replay, closure, and failure rules.",
        "The assets coordinate no participants, retain no authoritative history, and establish no decision legitimacy or collective closure.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-current-data-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_DATA_CHECK_PROJECTIONS.md",
            "CURRENT_DATA_CHECKS.md",
            "CURRENT_DATA_DISTRIBUTION.md",
        ),
        "Current DATA integrity, lineage, labeling, distribution, entropy, and reviewed projection policy.",
        "Dataset claims need exact selected bytes, lineage, labels, distribution measures, projection direction, and tolerance rules.",
        "The documents contain no dataset observation and establish no provenance, representativeness, privacy, or model fitness.",
    ),
    ownership_spec(
        "vstd-current-env-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_ENV_CHECK_PROJECTIONS.md",
            "CURRENT_ENV_CHECKS.md",
            "CURRENT_ENV_CONFIGURATION_SURFACE.md",
            "CURRENT_ENV_EXECUTABLE.md",
            "CURRENT_ENV_PIN_CLOSURE.md",
        ),
        "Current ENV executable, inventory, configuration-domain, reproduction, resource, pin-closure, and projection policy.",
        "Environment claims require explicit executable and configuration coordinates, resolver closure, resources, and selected replay semantics.",
        "The texts launch or isolate no environment and establish no dependency availability, reproducibility, sandboxing, or execution result.",
    ),
    ownership_spec(
        "vstd-current-event-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_EVENT_CLOSURE.md",
            "CURRENT_EVENT_DISPATCH.md",
            "CURRENT_EVENT_PREREQUISITES.md",
        ),
        "Current EVENT prerequisite, payload, dispatch, acknowledgment, sequence, and selected-head closure policy.",
        "Event validity depends on explicit prerequisites, message identity, order, dispatch, acknowledgment, and closure boundaries.",
        "The documents emit, receive, retain, or replay no event and establish no delivery, processing, or log closure.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-current-graph-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_GRAPH_CLOSURE.md",
            "CURRENT_GRAPH_LINEAGE.md",
            "CURRENT_GRAPH_ORDER.md",
            "CURRENT_GRAPH_STATICS.md",
        ),
        "Current GRAPH edge statics, least topological order, reachability closure, and operand-lineage policy.",
        "Graph results need exact node, edge, order, endpoint-content, lineage, and closure inputs with bounded precedence.",
        "The texts inspect no graph and establish no source completeness, runtime causality, lineage truth, or closure.",
    ),
    ownership_spec(
        "vstd-current-hardware-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_HARDWARE_CAPACITY.md",
            "CURRENT_HARDWARE_INVENTORY.md",
            "CURRENT_HARDWARE_INVENTORY_CLOSURE.md",
            "CURRENT_HARDWARE_MEASUREMENTS.md",
            "CURRENT_HARDWARE_SUBSTRATE_OBSERVATIONS.md",
            "CURRENT_HARDWARE_TOPOLOGY.md",
        ),
        "Current HARDWARE inventory, topology, capacity, measurement, substrate-observation, and closure policy.",
        "Physical-substrate claims require explicit units, reservations, topology, provenance, freshness, qualification, and inventory closure.",
        "The specifications sense, attest, reserve, control, own, or physically verify no hardware and establish no custody or backing.",
    ),
    ownership_spec(
        "vstd-current-harness-policy-assets",
        "POLICY",
        _standard("CURRENT_HARNESS_CHECKS.md", "CURRENT_HARNESS_GAP_BOUNDARY.md"),
        "Current HARNESS binding, action-space, intervention, observation, and unresolved-gap boundary policy.",
        "A HARNESS bounds an AGENT only through explicit selected interfaces, controls, observations, and known gaps.",
        "Static policy wraps or confines no AGENT, MODEL, BOT, or process and establishes no operational safety boundary.",
    ),
    ownership_spec(
        "vstd-current-human-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_HUMAN_NO_COMPOSITION.md",
            "CURRENT_HUMAN_POPULATION_DECLARATION.md",
            "CURRENT_HUMAN_TEMPLATE_IRREVERSIBILITY.md",
        ),
        "Current HUMAN non-composition, population-declaration, and template-irreversibility policy.",
        "Human representation needs explicit limits against composition, inference, reversibility, and population overclaim.",
        "The texts identify, authenticate, model, count, compose, or make decisions about no real person or population.",
    ),
    ownership_spec(
        "vstd-current-hyper-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_HYPER_CLOSURE.md",
            "CURRENT_HYPER_COMPOSED_CEILING.md",
            "CURRENT_HYPER_UNKNOWN_ABSORPTION.md",
        ),
        "Current HYPER composition ceiling, UNKNOWN absorption, and retained closure policy.",
        "Higher-order composition must preserve negative and unknown child states and a fixed grounded observation ceiling.",
        "The documents compose or evaluate no objects and establish no HYPER closure or stronger child result.",
    ),
    ownership_spec(
        "vstd-current-identity-protocol-assets",
        "PROTOCOL",
        _standard(
            "CURRENT_IDENTITY_LIFECYCLE.md",
            "CURRENT_IDENTITY_PRESENTATION.md",
            "CURRENT_IDENTITY_SCOPE.md",
        )
        + _schemas(
            "identity_lifecycle_evidence.json",
            "identity_presentation_evidence.json",
        ),
        "Current IDENTITY scope, presentation, lifecycle, witness, time-coverage, and retained-evidence protocol.",
        "Identity evidence crosses holder, witness, verifier, timing, purpose, replay, and lifecycle boundaries that require explicit states.",
        "The assets authenticate no person or key holder and establish no civil identity, authority, occupancy, or uninterrupted lifecycle.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-current-model-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_MODEL_ARTIFACT_BYTES.md",
            "CURRENT_MODEL_CHECKS.md",
            "CURRENT_MODEL_DATA_CITATION.md",
            "CURRENT_MODEL_DATA_LINEAGE.md",
            "CURRENT_MODEL_HARDWARE_OBSERVATION.md",
            "CURRENT_MODEL_QUANTIZATION.md",
            "CURRENT_MODEL_TRAIN_CITATION.md",
        ),
        "Current MODEL artifact, architecture, quantization, DATA, TRAIN, hardware-observation, and citation policy.",
        "MODEL identity and reproducibility require exact artifact bytes and explicit architecture, quantization, training, data, and hardware relationships.",
        "The documents load, run, train, inspect, or qualify no MODEL and establish no correctness, safety, provenance, or hardware correspondence.",
    ),
    ownership_spec(
        "vstd-current-object-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_OBJECT_ADDRESS_CLOSURE.md",
            "CURRENT_OBJECT_FACETS.md",
            "CURRENT_OBJECT_GOVERNANCE.md",
            "CURRENT_OBJECT_GROUNDING.md",
            "CURRENT_OBJECT_LINEAGE.md",
            "CURRENT_OBJECT_STATICS.md",
        ),
        "Current generic OBJECT facet, address, statics, grounding, lineage, and governance policy.",
        "Generic object checks need exact selected kinds, addresses, records, lineage, grounding, and governance without suppressing specialized obligations.",
        "The texts evaluate no object and generic structure cannot satisfy or remove any consequential kind's obligations.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-current-owner-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_OWNER_FORKS.md",
            "CURRENT_OWNER_HARDWARE_ELIGIBILITY.md",
            "CURRENT_OWNER_REPLAY.md",
        ),
        "Current OWNER hardware-eligibility, fork, and replay policy.",
        "Ownership claims need explicit selected subject, eligibility, authority, fork, history, and replay semantics.",
        "The documents establish no real identity, title, custody, legal ownership, hardware possession, or enforcement.",
    ),
    ownership_spec(
        "vstd-current-receipt-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_RECEIPT_AUTHENTICITY.md",
            "CURRENT_RECEIPT_CHAIN.md",
            "CURRENT_RECEIPT_PREREQUISITE_CLOSURE.md",
            "CURRENT_RECEIPT_STATICS.md",
            "CURRENT_RECEIPT_VALIDATION_REPLAY.md",
        ),
        "Current RECEIPT statics, authenticity, chain, prerequisite closure, and validation-replay policy.",
        "Receipt reliance requires exact wire identity, issuer/key scope, chain order, prerequisites, retained validation, and replay rules.",
        "The texts parse, authenticate, retain, or replay no receipt and establish no issuer identity, execution, or prerequisite truth.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-current-role-protocol-assets",
        "PROTOCOL",
        _standard(
            "CURRENT_ROLE_CONSTRAINTS.md",
            "CURRENT_ROLE_DECISION_CLOSURE.md",
            "CURRENT_ROLE_LIFECYCLE.md",
        )
        + _schemas("role_closure_evidence.json"),
        "Current ROLE membership lifecycle, constraints, decision closure, and retained-evidence protocol.",
        "Role admission, departure, authority, constraints, decisions, order, replay, and closure require explicit participant states.",
        "The assets assign or enforce no role and establish no actor identity, authority, decision legitimacy, or lifecycle closure.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-current-sim-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_SIM_CHECKER.md",
            "CURRENT_SIM_DYNAMICS.md",
            "CURRENT_SIM_EXTERNAL_LAW.md",
            "CURRENT_SIM_INTERNAL_STATE.md",
            "CURRENT_SIM_PERSPECTIVE.md",
            "CURRENT_SIM_RESOURCE.md",
            "CURRENT_SIM_RESOURCE_FRESH.md",
            "CURRENT_SIM_RESPONSE.md",
            "CURRENT_SIM_SHARD_COVERAGE.md",
            "CURRENT_SIM_SHARD_RELATIONS.md",
            "CURRENT_SIM_SHARD_SIGNATURES.md",
            "CURRENT_SIM_SURFACE_PARTITION.md",
        ),
        "Current SIM checker, state, dynamics, law, perspective, response, resource, shard, signature, relation, and surface-partition policy.",
        "Simulation claims require explicit modeled law, state, update, perspective, response, resource, shard, and provenance boundaries.",
        "The documents execute or isolate no SIM and establish no physical fidelity, prediction reliability, fresh resource observation, or real-world control.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-current-space-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_SPACE_CLOSURE.md",
            "CURRENT_SPACE_LAYOUT.md",
            "CURRENT_SPACE_MIGRATION.md",
        ),
        "Current SPACE layout, migration, address, extent, and closure policy.",
        "Space claims need explicit units, layout, mapping, movement, retained endpoints, and closure boundaries.",
        "The texts allocate, inspect, migrate, or control no memory, storage, physical space, or address space.",
    ),
    ownership_spec(
        "vstd-current-time-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_TIME_CLOSURE.md",
            "CURRENT_TIME_ORDER.md",
            "CURRENT_TIME_STRICT.md",
        ),
        "Current TIME strict-order, selected event-order, interval, and closure policy.",
        "Time claims require explicit units, clock source, ordering, uncertainty, interval, and closure semantics.",
        "The texts observe no clock or event and establish no synchronization, causality, freshness, or physical time accuracy.",
    ),
    ownership_spec(
        "vstd-current-token-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_TOKEN_CHECK_PROJECTIONS.md",
            "CURRENT_TOKEN_CHECKS.md",
            "CURRENT_TOKEN_FACET_MAPPING.md",
        ),
        "Current TOKEN facet, issuance, scope, lifecycle, contradiction, and reviewed-projection policy.",
        "Token checks need exact selected grammar, issuer and scope claims, lifecycle, projection direction, and negative precedence.",
        "The documents issue, verify, revoke, transfer, or authorize no token and establish no identity or capability.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-current-train-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_TRAIN_ACCUMULATION.md",
            "CURRENT_TRAIN_CHECKS.md",
            "CURRENT_TRAIN_DATA_BRIDGE.md",
        ),
        "Current TRAIN configuration, step, optimizer, accumulation, checkpoint, and DATA-bridge policy.",
        "Training claims require exact data, model, optimizer, step order, accumulation, checkpoint, and bridge citations.",
        "The texts execute or control no training and establish no optimization, reproducibility, MODEL correctness, DATA rights, or safety.",
    ),
    ownership_spec(
        "vstd-current-verifier-policy-assets",
        "POLICY",
        _standard(
            "CURRENT_VERIFIER_COMPOSED_SECURITY.md",
            "CURRENT_VERIFIER_COVERAGE_CLOSURE.md",
            "CURRENT_VERIFIER_REPLACEMENT.md",
            "CURRENT_VERIFIER_RUN_CONSTRAINTS.md",
        ),
        "Current VERIFIER coverage, run-constraint, replacement, composed-security, recursion, and selected-source policy.",
        "Verifier claims require exact mechanism, obligation, selector, constraints, coverage, replacement, recursion, and composed-security boundaries.",
        "The documents execute no verifier and establish no coverage, constraint enforcement, replacement equivalence, composed security, or self-conformance.",
    ),
    ownership_spec(
        "vstd-current-independence-privacy-assets",
        "POLICY",
        _standard(
            "CURRENT_INDEPENDENCE_CHECKS.md",
            "CURRENT_INDEPENDENCE_PROJECTIONS.md",
            "CURRENT_PRIVACY_CHECKS.md",
        ),
        "Current independence, disclosure, privacy-certificate, and reviewed one-way projection policy.",
        "Independence and privacy claims need exact actors, causes, observations, disclosures, authorities, projections, and failure precedence.",
        "The specifications observe no real actor or disclosure and establish no causal, statistical, organizational, or legal independence or privacy.",
    ),
    ownership_spec(
        "vstd-current-permission-slot-assets",
        "PROTOCOL",
        _standard("CURRENT_PERMISSION_SLOT.md"),
        "Current permission-slot grant, registration, cancellation, drain, successor, and event-order protocol.",
        "Permission lifecycle and callback-entry races require explicit states, order, replay, recovery, and authority boundaries.",
        "The text grants or enforces no permission, invokes no callback, and establishes no downstream effect or operational confinement.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-current-subject-security-assets",
        "PROTOCOL",
        _standard("CURRENT_SUBJECT_SECURITY.md"),
        "Current subject receipt-chain, anchor, inclusion, order, and security-check protocol.",
        "Subject security records cross issuer, anchor, checker, ordering, and replay boundaries that need explicit failure semantics.",
        "The specification authenticates no issuer or subject, retains no authoritative history, and establishes no execution or security.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-current-typed-facet-assets",
        "POLICY",
        _standard("CURRENT_TYPED_FACETS.md", "CURRENT_TYPED_FACET_PROJECTIONS.md"),
        "Current typed-facet certificate, selected-kind, address, and reviewed one-way projection policy.",
        "Typed facets need exact kind, address, certificate, source, and projection direction so generic structure cannot erase specialization.",
        "The texts evaluate no facet and establish no certificate authority, semantic equivalence, specialized obligation, or evidence truth.",
    ),
)


__all__ = ["NORMATIVE_ASSET_OWNERSHIP_SPECS", "SemanticOwnershipSpec"]
