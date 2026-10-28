"""Audited ownership for Verifier's non-domain Python application surfaces.

Terminology: application programming interface (API); command-line interface
(CLI); directed acyclic graph (DAG); Verifier Standard (VSTD).

These declarations partition exactly 42 source paths across the package API,
consent, corrigibility, data, environments, experimental workflow, identity,
layer-4, and schema-marker surfaces.  They assign source ownership only; they
do not establish admission, conformance, mechanism truth, sandboxing, physical
or financial effects, release authority, or deployment.
"""

from __future__ import annotations

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


ONTOLOGY_EXCLUDED_ORIGINAL_KINDS = (
    "ACTOR",
    "BENCH",
    "COLLECTIVE",
    "DATA",
    "ENV",
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
    "TOKEN",
    "TRAIN",
    "VERIFIER",
)


def ontology_role_refutation_reason(kind: str) -> str:
    """Bind one ontology exclusion to the exhaustive owned-source table."""

    if kind not in ONTOLOGY_EXCLUDED_ORIGINAL_KINDS:
        raise ValueError("ONTOLOGY_ROLE_REFUTATION_KIND_INVALID:" + kind)
    return (
        "Owned source ontology.py's exhaustive literal ORIGINAL_KIND_ROLE_BOUNDARY "
        "entry '(\""
        + kind
        + "\", \"DOES_NOT_APPLY\"),' explicitly classifies "
        + kind
        + " outside this exact row's represented and accumulated roles. The "
        "one-file owner must also remain byte-bound and CLOSED under the effect "
        "audit; operand names and consequence-boundary terms acquire no role. "
        "This refutes only this row-kind pair and establishes no higher-tier "
        "conformance or exemption for an applicable role."
    )


# Public package routing and consent mechanisms are separate owners: exports
# are architecture, process dispatch is a protocol, and a consent decision is
# never permission to alter the underlying computational verdict.
PYTHON_APPS_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-python-public-api",
        "ARCH",
        ("src/verifier/__init__.py",),
        "Lazy top-level public export architecture and compatibility policy.",
        "The installed symbol map and version/status projection determine the public package architecture under explicit routing policy.",
        "Lazy export reachability does not execute an exported mechanism, establish conformance, or confer release or deployment authority.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-module-cli-entrypoint",
        "PROTOCOL",
        ("src/verifier/__main__.py",),
        "Python module-entry protocol delegating process arguments, streams, and exit status to the public CLI.",
        "Module execution crosses a process-facing command boundary and delegates observation, decision, and effect handling to one selected CLI entrypoint.",
        "Delegation to the installed CLI is not a sandbox and establishes neither command correctness nor the truth of any reported measurement or verdict.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-consent-package-api",
        "ARCH",
        ("src/verifier/consent/__init__.py",),
        "Consent namespace export architecture.",
        "The consent package's public names need an exact source owner distinct from the mechanisms they expose.",
        "Import and export representation alone performs no consent evaluation, authentication, enforcement, or computational-verdict change.",
    ),
    # Negative prose ("does not establish ... voluntary human consent") is a
    # disclaimer, not a living-person refutation, and this row's closure is not
    # CLOSED.  No root decision is declared, so the human root stays unresolved.
    ownership_spec(
        "vstd-consent-stage-verifier",
        "VERIFIER",
        ("src/verifier/consent/stages.py",),
        "Bounded staged-consent predicates, authenticated receipt composition, and retained reproduction.",
        "Consent-stage decisions consume selected records and mechanism bytes under explicit policy and protocol rules that generic verification would hide.",
        "The checks do not establish all required holders, authenticate clocks, prove voluntary human consent, or change the underlying computational verdict.",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
    ),

    # Corrigibility sources mix inert records, bounded assessors, in-process
    # callback execution, and declared containment.  Their roles accumulate,
    # but terminology about an AGENT, BOT, MODEL, or TRAIN is not execution.
    ownership_spec(
        "vstd-corrigibility-package-api",
        "ARCH",
        ("src/verifier/corrigibility/__init__.py",),
        "Corrigibility namespace export architecture.",
        "The namespace aggregates distinct records and mechanisms and therefore needs a public-surface owner separate from their behavioral owners.",
        "Export reachability establishes no model, agent, bot, training, containment, or shutdown behavior.",
    ),
    ownership_spec(
        "vstd-benchmark-suite-verifier",
        "VERIFIER",
        ("src/verifier/corrigibility/benchmark.py",),
        "Refutable benchmark specifications, score provenance, and non-gaming checks over supplied records.",
        "Benchmark acceptance derives bounded measurements under explicit scoring and integrity policy.",
        "Supplied benchmark records and arithmetic do not execute a workload, authenticate provenance, or establish real capability or safety.",
        "MEASUREMENT",
        "POLICY",
    ),
    ownership_spec(
        "vstd-corrigibility-containment-contracts",
        "HARNESS",
        ("src/verifier/corrigibility/contracts.py",),
        "Executable corrigibility contract and invariant harness over supplied state.",
        "Containment and shutdown invariants define a bounded protocol and decision policy distinct from an executing sandbox.",
        "Contract evaluation does not confine a process, deliver a signal, control hardware, or establish corrigibility of a running system.",
        "POLICY",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-training-data-contamination-assessor",
        "VERIFIER",
        ("src/verifier/corrigibility/data.py",),
        "Training and evaluation dataset provenance, integrity, and contamination assessor.",
        "Contamination conclusions derive measurements from supplied manifests under explicit split and overlap policy.",
        "The assessor does not acquire dataset bytes, authenticate lineage, execute training, or prove absence of unrepresented contamination.",
        "MEASUREMENT",
        "POLICY",
    ),
    ownership_spec(
        "vstd-corrigibility-environment-profile",
        "ENV",
        ("src/verifier/corrigibility/environment.py",),
        "Declared hardware and software substrate profile with isolation and execution-bound checks.",
        "Environment declarations carry measurable resource and isolation claims governed by explicit acceptance policy.",
        "Supplied profile records do not inspect a live host, create isolation, enforce limits, or attest execution occurrence.",
        "MEASUREMENT",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "HARDWARE",
                "APPLIES",
                "Owned source environment.py declares 'Hardware capability profile and accelerator device identity.' for its HardwareSubstrate, so the declared substrate profile embodies a HARDWARE device-inventory role with capacity and accelerator envelopes; declared capability is not an inspected live device.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-corrigibility-provenance-ledger",
        "LEDGER",
        ("src/verifier/corrigibility/graph.py",),
        "In-memory computational provenance DAG with lineage and causal-consistency rules.",
        "Ordered node and edge additions rely on correction, duplication, and acyclicity policy and therefore require explicit ledger and transaction roles.",
        "The in-memory DAG is not durable or externally witnessed authoritative history and does not prove runtime causality or provenance truth.",
        "POLICY",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-training-checkpoint-ledger",
        "LEDGER",
        ("src/verifier/corrigibility/hyperparameters.py",),
        "Hyperparameter, training-step, and checkpoint-lineage records with ordered consistency checks.",
        "Checkpoint lineage retains measured training metadata through policy-governed state transitions and additions.",
        "Caller-supplied records are not durable authoritative history, checkpoint-byte acquisition, or evidence that training or numerical updates occurred.",
        "MEASUREMENT",
        "POLICY",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-model-reproducibility-profile",
        "DATA",
        ("src/verifier/corrigibility/model.py",),
        "Declarative model reproducibility and risk-profile records with bounded arithmetic checks.",
        "The source represents and measures declared MODEL facets under explicit completeness and acceptance policy.",
        "Retained data and arithmetic do not load, train, infer with, evaluate, or establish the behavior of a MODEL artifact.",
        "MEASUREMENT",
        "POLICY",
    ),
    ownership_spec(
        "vstd-agent-bot-ontology-architecture",
        "ARCH",
        ("src/verifier/corrigibility/ontology.py",),
        "Computational SPACE, TIME, EVENT, AGENT, and BOT ontology record architecture.",
        "Ontology composition applies explicit classification policy to inert structural records and must not inherit behavioral roles from the names it represents.",
        "The records execute no AGENT or BOT, create no confinement, and establish no ROBOT, FINBOT, physical, or financial consequence.",
        "POLICY",
        root_role_decisions=(
            *(
                root_role_decision(
                    kind,
                    "DOES_NOT_APPLY",
                    ontology_role_refutation_reason(kind),
                )
                for kind in ONTOLOGY_EXCLUDED_ORIGINAL_KINDS
            ),
            root_role_decision(
                "SIM",
                "APPLIES",
                "Owned source ontology.py states 'Formalizes the situated intelligence definition: BOT = AGENT + SIM.', so the accumulated BOT formula makes SIM a constituent role of this row; the record defines that composition, executes no simulation, and carries no physical or financial consequence.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-operator-stop-authentication",
        "PROTOCOL",
        ("src/verifier/corrigibility/operator_stop.py",),
        "Configured-key authentication protocol for one bounded operator-stop request.",
        "Request signatures, replay fields, time windows, and selected policy form a protocol boundary separate from process control.",
        "Authentication identifies no human and does not stop a process or descendant, deliver a signal, or establish operator authority beyond configured host input.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-capability-reward-lock",
        "HARNESS",
        ("src/verifier/corrigibility/reward_lock.py",),
        "Composite reward-lock and computation-proof thaw harness over supplied records.",
        "Lock and thaw evaluation derives bounded measurements under explicit composition and acceptance policy.",
        "Hash and predicate evaluation does not execute training, constrain a live model, hold a real secret, or actuate an external system.",
        "MEASUREMENT",
        "POLICY",
    ),
    ownership_spec(
        "vstd-corrigibility-risk-assessor",
        "VERIFIER",
        ("src/verifier/corrigibility/risk_profile.py",),
        "Aggregate corrigibility risk-profile assessor over selected supplied records.",
        "Cross-surface risk conclusions combine finite measurements under explicit aggregation and fail-closed policy.",
        "Aggregation does not independently acquire evidence, run a model or agent, test a sandbox, or establish whole-system corrigibility.",
        "MEASUREMENT",
        "POLICY",
    ),
    ownership_spec(
        "vstd-sim-trace-assessor",
        "VERIFIER",
        ("src/verifier/corrigibility/simulation.py",),
        "Tiered simulation trace, invariant, abstraction, agent-parity, and sharding assessor.",
        "The assessor invokes selected transition and predicate callbacks, observes state, and applies bounded control and transaction policy across a trace.",
        "Callbacks run in-process without sandboxing; trace checks are not physics validation, a running BOT, ROBOT or FINBOT, or evidence of physical or financial effects.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-tesla-cage-contract",
        "HARNESS",
        ("src/verifier/corrigibility/tesla_cage.py",),
        "Tesla-cage containment declarations, attestations, and invariant checks.",
        "Containment representations carry measurable claims governed by explicit fail-closed policy and need a HARNESS owner rather than a generic object.",
        "The source implements no preemption, process actuation, controller, sandbox launch, ROBOT, or physical containment mechanism.",
        "MEASUREMENT",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "HARDWARE",
                "APPLIES",
                "Owned source tesla_cage.py declares 'Unauthenticated declaration of mechanical relay properties; not proof.' for its device records, so the containment declarations embody declared device inventory and break-response envelopes; these are unauthenticated declarations and establish no physical device.",
            ),
        ),
    ),
    # A type-distinction sentence ("MODEL means an optimized artifact") names a
    # kind; it is not a refutation of that kind for this row.  Closure is not
    # CLOSED, so no root decision is declared and MODEL stays unresolved.
    ownership_spec(
        "vstd-training-control-profile",
        "POLICY",
        ("src/verifier/corrigibility/train_profile.py",),
        "Finite TRAIN control-plan analysis policy.",
        "Protected facets, effect names, relations, and dependency checks are normative selection rules for one explicit application profile.",
        "Plan analysis performs no optimization, model mutation, checkpoint write, authority grant, or whole-system corrigibility assessment.",
    ),

    # GRAPH data records, decisions, and publication have different consequence
    # surfaces.  In particular, recorded artifacts can be ASSET claims without
    # proving custody or backing, and local receipt writes are not a ledger.
    ownership_spec(
        "vstd-data-package-api",
        "ARCH",
        ("src/verifier/data/__init__.py",),
        "GRAPH data namespace export architecture.",
        "The data package aggregates record, policy, assurance, and receipt surfaces that require a distinct public namespace owner.",
        "Export reachability performs no graph assessment, evidence acquisition, receipt publication, or mechanism execution.",
    ),
    ownership_spec(
        "vstd-graph-level-verifier",
        "VERIFIER",
        ("src/verifier/data/graph_level.py",),
        "Evidence-bound graph-level encoding, independent decision checks, and registered-mechanism evaluation.",
        "Graph-level establishment observes selected evidence and invokes registered mechanisms through a bounded policy-governed transaction.",
        "The candidate level depends on caller-supplied ratings and selected mechanisms; it is not a sandbox, universal graph proof, or automatic object conformance.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "GRAPH",
                "APPLIES",
                "Owned source graph_level.py defines 'graph_level(C) = max { N : CNF_N(C) is satisfiable }' over a collection C with membership, provenance-closure, and edge-evidence conditions, so the collection is the represented subject and GRAPH accumulates; the candidate level uses caller-supplied ratings and is not conformance.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-provenance-hypergraph-ledger",
        "LEDGER",
        ("src/verifier/data/models.py",),
        "Artifact, rights, conflict, and transformation-hypergraph records with in-memory mutation rules.",
        "Artifact claims and ordered graph mutations require explicit ASSET, measurement, policy, and transaction consequences.",
        "Recorded claims do not establish actual backing, custody, rights, source truth, durable history, runtime causality, or financial value.",
        "ASSET",
        "MEASUREMENT",
        "POLICY",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-data-receipt-lifecycle",
        "RECEIPT",
        ("src/verifier/data/receipt.py",),
        "GRAPH receipt construction, local artifact publication, validation, and reproduction lifecycle.",
        "The receipt binds a data subject and hardware context while observing and mutating a selected local output directory under explicit policy.",
        "Publication is a non-atomic local multi-file write without external witness or durable truth; it proves neither source claims nor financial or physical effects.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
        operands=(
            ("hardware", ("vstd-hardware",)),
            ("subject", ("vstd-data",)),
        ),
    ),

    # Environment records and projections remain separate from assessments and
    # the deliberately synthetic in-process specimen harness.
    ownership_spec(
        "vstd-environments-package-api",
        "ARCH",
        ("src/verifier/environments/__init__.py",),
        "Experimental environment namespace export architecture.",
        "The namespace exposes contracts, projections, and assessments with materially different consequences and needs an exact public owner.",
        "Direct imports are experimental; exports do not execute submitted environment implementations or establish support or conformance.",
    ),
    ownership_spec(
        "vstd-environment-record-contracts",
        "ENV",
        ("src/verifier/environments/contracts.py",),
        "Bounded environment definition, instance, mechanism, component, connection, and run records.",
        "Environment records declare capability and boundary policy that must remain distinct from runtime enforcement.",
        "Canonical records do not execute an environment, enforce isolation, authenticate occurrence, or satisfy a numbered profile.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-environment-assessor",
        "VERIFIER",
        ("src/verifier/environments/assessment.py",),
        "Declared-environment assessment and selected registered-mechanism evaluation.",
        "Explicit evaluation observes evidence and invokes existing verification mechanisms in a bounded policy-governed transaction.",
        "Inspection never executes the environment itself; evaluation establishes neither runtime occurrence, enforcement, actor independence, nor numbered-profile conformance.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-environment-integration-projection",
        "ARCH",
        ("src/verifier/environments/integration.py",),
        "Nonexecuting environment catalog, geometry, relation, workload, and package projections.",
        "Cross-package environment representations apply explicit projection and binding policy and need an architecture owner.",
        "Projection and packaging of supplied records confer no verdict, execution permission, runtime occurrence, or enforcement.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-environment-specimen-checker",
        "VERIFIER",
        ("src/verifier/environments/specimen_checks.py",),
        "Independent bounded checker for exact synthetic environment fixture bytes.",
        "Fixture evaluation observes selected bytes and applies explicit comparison and decision policy.",
        "The checker imports no producer and executes no submitted implementation; fixtures prove neither model performance, physical simulation validity, nor independent actors.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-environment-synthetic-specimens",
        "HARNESS",
        ("src/verifier/environments/specimens.py",),
        "Synthetic in-process environment, scripted reference model, packaging, and evaluation harness.",
        "The specimen changes finite in-memory state, retains selected bytes, and invokes registered checks through explicit control and transaction policy.",
        "It is synthetic and unsandboxed, not learned-model inference, a capability benchmark, an independent witness, a BOT, ROBOT, FINBOT, or physical or financial system.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "ENV",
                "APPLIES",
                "Owned source specimens.py declares 'Runnable, synthetic environment specimens for Verifier Standard (VSTD).', so the row represents an execution environment with in-process software, configuration, and reproduction boundary; it is synthetic and unsandboxed and establishes no physical or financial environment.",
            ),
        ),
    ),

    # Experimental workflow and identity sources describe and inspect bounded
    # records.  Platform vocabulary and token chains do not create live remote
    # observation, real identity, authority, or durable authoritative history.
    ownership_spec(
        "vstd-experimental-workflow-package-api",
        "ARCH",
        ("src/verifier/experimental_workflow/__init__.py",),
        "Experimental workflow namespace export architecture.",
        "The non-normative workflow profile, schema, and adapter need one exact public-surface owner separate from their implementations.",
        "Exports remain non-normative and verdict-neutral and execute no workflow or platform operation.",
    ),
    ownership_spec(
        "vstd-github-snapshot-event-adapter",
        "VERIFIER",
        ("src/verifier/experimental_workflow/github.py",),
        "Deterministic supplied GitHub-snapshot to workflow-event adapter.",
        "Snapshot normalization applies an exact field and event-classification policy that warrants bounded verification ownership.",
        "The adapter performs no GitHub API call or live observation and does not authenticate, upgrade, or execute the supplied platform events.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-experimental-workflow-profile",
        "VERIFIER",
        (
            "src/verifier/experimental_workflow/profile.py",
            "src/verifier/experimental_workflow/schema.py",
        ),
        "Non-normative workflow manifest schema, validation, digesting, and selected repository-artifact observation.",
        "Profile validation and artifact comparison derive bounded measurements from supplied records and selected local bytes under explicit policy.",
        "The profile does not execute domain verifiers, derive VSTD verdicts, run workflow actions, or treat repository state as verification.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-identity-package-api",
        "ARCH",
        ("src/verifier/identity/__init__.py",),
        "Zero-identity token and offline-evaluation namespace architecture.",
        "The identity namespace exports records, policy, evaluation, and audit surfaces and needs an exact public owner.",
        "Export reachability establishes no actor identity, authentication, authority, liveness, or network observation.",
    ),
    ownership_spec(
        "vstd-identity-token-records",
        "TOKEN",
        ("src/verifier/identity/tokens.py",),
        "Birth, aging, and lifetime token records with canonical commitment and accumulator chaining.",
        "Token messages and ordered accumulator transitions carry explicit protocol, policy, and retained-history semantics.",
        "Local hash chains are not externally witnessed authoritative history and do not prove a human, legal identity, key ownership, liveness, or authority.",
        "LEDGER",
        "POLICY",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-identity-policy-evaluator",
        "VERIFIER",
        (
            "src/verifier/identity/evaluator.py",
            "src/verifier/identity/invariants.py",
        ),
        "Offline identity-token evaluator with normative verdict and prohibited-inference policy.",
        "The evaluator observes supplied token fields and derives bounded property measurements under explicit fail-closed identity policy.",
        "Offline evaluation discovers no actor, authenticates no person or clock, grants no authority, and performs no network or physical observation.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-identity-adversarial-audit",
        "HARNESS",
        ("src/verifier/identity/audit.py",),
        "In-process adversarial identity-slippage fixture harness.",
        "The fixed attack battery measures evaluator behavior under explicit loophole-detection policy.",
        "Passing synthetic cases is not adversarial completeness, independent evidence, sandboxing, live identity verification, or authority.",
        "MEASUREMENT",
        "POLICY",
    ),

    # Layer-4 public architecture, refutation policy, and structural closure are
    # distinct from the other layer-4 ledgers and assessments not in this slice.
    ownership_spec(
        "vstd-layer4-package-api",
        "ARCH",
        ("src/verifier/layer4/__init__.py",),
        "Layer-4 refutability namespace export architecture.",
        "The namespace aggregates refutation, closure, availability, challenge, and precommitment surfaces under one exact public owner.",
        "Exports outside the trusted decision kernel establish no refutability verdict, evidence validity, challenge outcome, or conformance.",
    ),
    ownership_spec(
        "vstd-refutation-surface-policy",
        "POLICY",
        ("src/verifier/layer4/surface.py",),
        "Explicit admissible-refutation and excluded-claim surface policy.",
        "Challenge predicates, coordinates, falsifiers, and permanent physical-world exclusions are normative rules rather than generic records.",
        "A declared surface does not supply evidence, resolve a challenge, prove physical-world completeness, or establish portable-certificate validity.",
    ),
    ownership_spec(
        "vstd-refutability-closure-verifier",
        "VERIFIER",
        ("src/verifier/layer4/closure.py",),
        "Structural refutability-closure and minimum-depth verifier.",
        "Closure applies explicit policy to caller-supplied input, transformation, and composition mappings.",
        "Accepted structure leaves certificate references unresolved and conformance NOT_ESTABLISHED; it is not a VSTD-5 entry gate.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-schema-package-marker",
        "DATA",
        ("src/verifier/schemas/__init__.py",),
        "Inert package marker for bundled public schema copies.",
        "The schema package marker needs exact ownership without inheriting validator or policy behavior from neighboring schema artifacts.",
        "The marker contains no schema parser, validation, byte-identity check, admission decision, or conformance mechanism.",
    ),
)


__all__ = [
    "ONTOLOGY_EXCLUDED_ORIGINAL_KINDS",
    "PYTHON_APPS_OWNERSHIP_SPECS",
    "SemanticOwnershipSpec",
    "ontology_role_refutation_reason",
]
