"""Audited semantic ownership for static repository assets.

This partition owns exactly 234 non-code paths that were previously hidden by
the package catchall: retained ``.vstd`` evidence inputs, documentation,
repository policy, GitHub workflow declarations, receipt schemas, and generated
distribution metadata.  Verifier Standard (VSTD) artifact records and workflow
declarations are represented according to their stored contract, not as proof
that a mechanism ran or that a platform honored a declaration.

Claim boundary: static bytes do not establish current evidence, mechanism
execution, conformance, release, deployment, publication authority, financial
effect, physical effect, or BOT, ROBOT, or FINBOT behavior.  Generated metadata
does not establish an installed or published distribution.
"""

from __future__ import annotations

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


CATCHALL_BOUNDARY_EXCLUSIONS = (
    "docs/assets/orientation-previews.js",
    "docs/assets/site.css",
    "docs/assets/vstd-overview.png",
    "docs/assets/vstd-overview.svg",
    "docs/guides.html",
    "docs/index.html",
    "docs/profiles/competition-evaluation.md",
    "docs/profiles/experimental-workflow.md",
    "docs/profiles/experimental-workflow.schema.json",
    "docs/profiles/vstd-3/artifact-tracing.md",
    "docs/profiles/vstd-3/compatibility.md",
    "docs/profiles/vstd-3/references.md",
    "docs/profiles/vstd-3/threat-model.md",
    "docs/profiles/vstd-3/vendor-integration.md",
    "docs/reference.html",
    "pyproject.toml",
)
"""Code, generated-site, binary and build surfaces reserved to other audits."""


_BOUNDED_COHORT = ".vstd/instance-evidence/bounded-structural-20261013"
_CURRENT_COHORT = ".vstd/instance-evidence/current-representations-20261013"

# These stems are explicit because future evidence files must not become owned
# merely by appearing in a directory.  The two retained cohorts use different
# filename separators while carrying the same selected typed-facet subjects.
_TYPED_FACET_STEMS = (
    "verifier-core-self-VERIFIER-1.1",
    "vstd-actor-ACTOR-1.1",
    "vstd-agent-AGENT-1.1",
    "vstd-architecture-ARCH-1.1",
    "vstd-benchmark-BENCH-1.1",
    "vstd-bot-BOT-1.1",
    "vstd-collective-COLLECTIVE-1.1",
    "vstd-data-DATA-1.1",
    "vstd-environment-ENV-1.1",
    "vstd-event-EVENT-1.1",
    "vstd-hardware-HARDWARE-1.1",
    "vstd-harness-HARNESS-1.1",
    "vstd-human-HUMAN-1.1",
    "vstd-hypergraph-HYPER-1.1",
    "vstd-identity-IDENTITY-1.1",
    "vstd-invocation-ledger-OBJECT-1.2",
    "vstd-manifest-write-OBJECT-1.2",
    "vstd-model-MODEL-1.1",
    "vstd-owner-OWNER-1.1",
    "vstd-package-graph-GRAPH-1.1",
    "vstd-package-object-OBJECT-1.2",
    "vstd-receipt-RECEIPT-1.1",
    "vstd-role-ROLE-1.1",
    "vstd-simulation-SIM-1.1",
    "vstd-space-SPACE-1.1",
    "vstd-time-TIME-1.1",
    "vstd-token-TOKEN-1.1",
    "vstd-training-TRAIN-1.1",
)
_OBJECT_FACET_STEMS = (
    "vstd-invocation-ledger-OBJECT-1.1",
    "vstd-manifest-write-OBJECT-1.1",
    "vstd-package-object-OBJECT-1.1",
)


def _facet_paths(stems: tuple[str, ...], artifact: str) -> tuple[str, ...]:
    """Return the fixed two-cohort paths for one retained artifact contract."""
    return tuple(
        [f"{_BOUNDED_COHORT}/{stem}.{artifact}.json" for stem in stems]
        + [f"{_CURRENT_COHORT}/{stem}-{artifact}.json" for stem in stems]
    )


_ACCELERATOR_PROFILE_SCHEMA_ORIGINAL_KINDS = (
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
_ACCELERATOR_PROFILE_SCHEMA_ROOT_DECISIONS = tuple(
    root_role_decision(
        kind,
        "APPLIES",
        "The static accelerator-profile schema is a normative contract consumed by "
        "the verifier namespace graph, whose current consumer closure is not established "
        "to exclude "
        + kind
        + " behavior; effect-first admission therefore retains the obligation without "
        "asserting execution, authority, identity, hardware truth, physical or financial "
        "effect, publication, or release.",
    )
    for kind in _ACCELERATOR_PROFILE_SCHEMA_ORIGINAL_KINDS
)


REPOSITORY_ASSET_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    # Stored evidence is split by wire contract.  Policies, requests, and
    # certificates are inputs or records; no row claims a fresh execution.
    ownership_spec(
        "vstd-retained-facet-policy-inputs",
        "POLICY",
        (
            f"{_BOUNDED_COHORT}/generic-policy.json",
            f"{_BOUNDED_COHORT}/typed-policy.json",
            f"{_CURRENT_COHORT}/policy-0.json",
            f"{_CURRENT_COHORT}/policy-1.json",
        ),
        "Retained object-facet and typed-facet mechanism-policy inputs for two dated instance-evidence cohorts.",
        "The selected mechanism digest, trust roots and certificate limit are decision rules and therefore require explicit POLICY ownership.",
        "Retained policy bytes do not show that a mechanism ran, that a trust root was authoritative, or that any object or package conformed.",
    ),
    ownership_spec(
        "vstd-retained-graph-statics-policy-input",
        "POLICY",
        (f"{_CURRENT_COHORT}/graph-statics-policy.json",),
        "Retained graph-statics mechanism-policy input for the dated current-representations cohort.",
        "Graph-static certificate limits and selected mechanism identity are decision rules distinct from request and certificate records.",
        "The stored policy is not graph execution, current graph evidence, conformance, release, or publication authority.",
    ),
    ownership_spec(
        "vstd-retained-object-facet-requests",
        "PROTOCOL",
        _facet_paths(_OBJECT_FACET_STEMS, "request"),
        "Retained generic object-facet request messages for the selected package, invocation-ledger and manifest-write subjects.",
        "The canonical requests bind selected coordinates, digests and limits as protocol inputs without being mechanisms themselves.",
        "A stored request proves neither dispatch nor execution and supplies no current evidence, verdict, conformance or effect.",
    ),
    ownership_spec(
        "vstd-retained-typed-facet-requests",
        "PROTOCOL",
        _facet_paths(_TYPED_FACET_STEMS, "request"),
        "Retained typed-facet request messages for the exact dated subject and coordinate denominator.",
        "The request records bind selected subject, object, collection, policy and resource-limit fields under one typed request contract.",
        "A retained request does not establish dispatch, mechanism execution, fresh observation, conformance, release or any real-world effect.",
    ),
    ownership_spec(
        "vstd-retained-graph-statics-request",
        "PROTOCOL",
        (f"{_CURRENT_COHORT}/graph-statics-request.json",),
        "Retained graph-statics request message binding the selected package-graph digests and limits.",
        "Graph selection and request fields have an explicit portable message contract separate from a policy or result.",
        "The stored request is not execution, an observation of the current graph, a verdict or a package-conformance claim.",
    ),
    ownership_spec(
        "vstd-retained-object-facet-certificates",
        "DATA",
        _facet_paths(_OBJECT_FACET_STEMS, "certificate"),
        "Retained generic object-facet certificate records for two dated instance-evidence cohorts.",
        "The records bind requests, policy and mechanism digests, evidence references and bounded results as portable certificate artifacts.",
        "Stored certificate bytes are historical inputs, not fresh replay, current evidence, independent verification, conformance or authority.",
        root_role_decisions=(
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "The retained files are certificate result records, so RECEIPT obligations remain necessary even though the aggregate owner spans multiple subjects and has no exact execution-hardware operand.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-retained-typed-facet-certificates",
        "DATA",
        _facet_paths(_TYPED_FACET_STEMS, "certificate"),
        "Retained typed-facet certificate records for the exact dated subject and coordinate denominator.",
        "Each artifact binds its typed request and selected policy and mechanism under the shared certificate-record contract.",
        "Retention does not authenticate the original run, make evidence current, establish subject truth or confer package conformance, release or publication authority.",
        root_role_decisions=(
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "The retained files are typed certificate results, so RECEIPT obligations remain necessary even though the aggregate owner spans many subjects and coordinates without one hardware operand.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-retained-graph-statics-certificate",
        "DATA",
        (f"{_CURRENT_COHORT}/graph-statics-certificate.json",),
        "Retained graph-statics certificate record for the dated package-graph request.",
        "The stored result, request and digest bindings form a portable certificate artifact distinct from the checker that can replay it.",
        "The historical certificate is not a fresh graph recapture or replay and does not establish current package conformance or promotion authority.",
        root_role_decisions=(
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "The file is an actual retained graph-statics certificate, so RECEIPT obligations apply even though current bytes do not bind an exact execution-hardware object.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-root-uv-dependency-resolution",
        "DATA",
        ("uv.lock",),
        "Retained root uv dependency-resolution record with exact package versions, artifacts, hashes, markers, and resolver revision.",
        (
            "The structured uv record controls locked dependency selection and exchange when "
            "a compatible tool consumes it, so its selection POLICY and file PROTOCOL must not "
            "be hidden inside the generic package object."
        ),
        (
            "Retained lock bytes do not prove installed dependencies, artifact availability, "
            "artifact integrity, runtime execution, reproducibility, or compliance with "
            "Verifier's zero-required-runtime-dependency boundary."
        ),
        "POLICY",
        "PROTOCOL",
    ),

    # Documentation rows are grouped by the contract readers rely on.  Guides
    # and profiles remain declarative bytes even when they describe commands.
    ownership_spec(
        "vstd-documentation-claim-boundary-policy",
        "POLICY",
        (
            "docs/ACCOUNTABILITY_RELEASE_SCOPE.md",
            "docs/API_STABILITY.md",
            "docs/CLAIMS_AND_LIMITS.md",
            "docs/CURRENT_CERTIFICATE_EMISSION.md",
            "docs/MAINSTAY_COVERAGE.md",
            "docs/RELEASE_FEATURE_GROUNDING.md",
            "docs/TEST_SKIP_RUBRIC.md",
            "docs/V2_CANDIDATE.md",
        ),
        "Public claim, compatibility, evidence, skip, candidate and release-description boundaries.",
        "Readers and repository gates rely on these explicit rules to prevent stronger conclusions than the selected evidence supports.",
        "Documentation policy does not itself run a gate, replay evidence, qualify a release, authorize publication or establish conformance.",
    ),
    ownership_spec(
        "vstd-documentation-reader-reference",
        "DATA",
        (
            "docs/ACRONYMS.md",
            "docs/CONCEPTS_AND_PRECEDENTS.md",
            "docs/ECOSYSTEM.md",
            "docs/USE_CASES.md",
        ),
        "Reader-facing terminology, precedent, ecosystem and use-case reference material.",
        "These nonexecuting references preserve vocabulary and scope distinctions needed to interpret the implemented surfaces.",
        "Reference prose is not a normative mechanism, adoption evidence, endorsement, execution record or universal applicability claim.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-documentation-core-architecture",
        "ARCH",
        (
            "docs/ARCHITECTURE.md",
            "docs/GROUNDED_CERTIFICATION.md",
            "docs/MATHEMATICAL_FOUNDATIONS.md",
            "docs/VERIFICATION_DRIVEN_DEVELOPMENT.md",
            "docs/VERIFIER_ADMISSION.md",
        ),
        "Conformance, grounding, mathematical and verification-development architecture documentation.",
        "The documents map component boundaries, claim dependencies and bounded admission semantics without replacing authoritative specifications or implementations.",
        "Architecture prose neither executes a verifier nor proves soundness, completeness, admission, conformance or release readiness.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-documentation-artifact-interoperability-architecture",
        "ARCH",
        (
            "docs/ARTIFACT_AWARENESS.md",
            "docs/ARTIFACT_NETWORK.md",
            "docs/COMPONENT_HUB.md",
            "docs/COMPONENT_PACKAGES.md",
            "docs/PLATFORM_INTEROPERABILITY.md",
            "docs/REALMS_AND_TIME_CAPSULES.md",
        ),
        "Artifact-awareness, network, stored-component, platform and temporal-realm architecture documentation.",
        "These files define how experimental representations relate and which claims do not transfer across their boundaries.",
        "Described stores, networks, components and realms are not deployed services, current observations, executable packages, endorsement or conformance evidence.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-documentation-control-domain-candidates",
        "POLICY",
        (
            "docs/CONSENT_LEVEL7.md",
            "docs/CONTROL_LEVELS.md",
            "docs/CORRIGIBILITY_CONTROL.md",
            "docs/GOVERNANCE_LEVEL8.md",
            "docs/PRIVACY_LEVEL6_REVIEW.md",
        ),
        "Candidate privacy, consent, governance and cooperative-control obligation boundaries.",
        "The documents record proposed decision conditions and prohibited inferences for distinct control domains.",
        "Candidate prose and bounded helpers do not establish effective enforcement, model corrigibility, actor authority, physical confinement or complete tier conformance.",
    ),
    ownership_spec(
        "vstd-documentation-environment-graph-architecture",
        "ARCH",
        (
            "docs/ENVIRONMENT_CONTRACT.md",
            "docs/ENVIRONMENTS.md",
            "docs/GRAPH_TOPOLOGY.md",
        ),
        "Environment contract, direct namespace and bounded graph-topology architecture documentation.",
        "The files distinguish declared computational environments and graph interpretations from their runtime or causal realization.",
        "Documentation does not host an environment, run a workload, observe a physical system or prove a declared graph is causally complete.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-documentation-local-tool-protocols",
        "PROTOCOL",
        (
            "docs/FIRST_RECEIPT.md",
            "docs/GATE_AUTOMATION.md",
            "docs/tutorials/SEAL_AN_ARTIFACT.md",
            "docs/tutorials/YOUR_FIRST_VERIFIABLE_SOFTWARE.md",
        ),
        "Local receipt, gate, artifact-seal and polish tutorial procedures with explicit result boundaries.",
        "The guides specify ordered participant actions and expected messages for selected local tool surfaces.",
        "Instructions and examples do not prove that commands ran, that output is current, that privileged writes are prevented or that any package conforms.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-documentation-remote-submission-protocols",
        "PROTOCOL",
        (
            "docs/CLAIMGARDEN_SIM_ARTIFACT.md",
            "docs/GATED_PUBLISH.md",
            "docs/tutorials/PUBLISH_A_CLAIM.md",
            "docs/tutorials/PUBLISH_A_SILO.md",
        ),
        "Claim, simulation-artifact and silo submission procedures and response-state boundaries.",
        "The guides describe ordered local checks, remote messages, indeterminate outcomes and review states that must not collapse into publication.",
        "Static instructions perform no upload, authenticate no live service, grant no publication authority and establish no stored, reviewed or published state.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-documentation-user-navigation",
        "DATA",
        (
            "docs/INSTALLATION.md",
            "docs/NEWCOMER_GUIDE.md",
            "docs/PYTHON_API_GUIDE.md",
            "docs/QUICKSTART.md",
            "docs/REPOSITORY_WALKTHROUGH.md",
        ),
        "Installation, newcomer, application programming interface, quickstart and repository navigation guides.",
        "These files orient a reader to selected supported surfaces and their limits without becoming implementations of those surfaces.",
        "Examples and instructions do not establish installation, execution, compatibility, test results, conformance or production suitability.",
    ),
    ownership_spec(
        "vstd-documentation-hosting-protocol",
        "PROTOCOL",
        ("docs/DOCUMENTATION_HOSTING.md",),
        "Documentation build, promotion, hosting-coordinate and historical live-observation protocol description.",
        "The document distinguishes source, deployment and observed serving coordinates under an explicit promotion sequence.",
        "The stored description is not a current network observation, account configuration, deployment receipt or publication authority.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-documentation-adjacent-standards-crosswalks",
        "ARCH",
        (
            "docs/standards/ADJACENT_STANDARDS_MATRIX.md",
            "docs/standards/SCITT_SEMANTIC_BOUNDARY.md",
            "docs/standards/VSTD_SCITT_CROSSWALK.md",
        ),
        "Experimental adjacent-standard and Supply Chain Integrity, Transparency, and Trust interoperability crosswalks.",
        "The crosswalks preserve which external mechanism may support which bounded proposition and where inference must stop.",
        "Static mappings do not implement an external standard, prove interoperability, claim standards-body review or transfer external trust into VSTD conformance.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-documentation-derived-metadata",
        "DATA",
        (
            "docs/API_MEMBER_SUMMARIES.json",
            "docs/PR_SOURCE_FEATURES.json",
            "docs/platform-component-contracts.json",
        ),
        "Generated application programming interface member summaries, pull-request source features and static platform-component contract data.",
        "These machine-readable rows support documentation rendering and source coverage while remaining distinct from the generating and checking mechanisms.",
        "Generated metadata does not prove source freshness, runtime reachability, mechanism execution, component qualification, release or publication.",
    ),

    # Root assets preserve repository policy, legal and reader-facing state.
    ownership_spec(
        "vstd-repository-file-and-package-policy",
        "POLICY",
        (".gitattributes", ".gitignore", "MANIFEST.in"),
        "Repository text-normalization, ignored-path and source-distribution inclusion declarations.",
        "Git and package builders rely on these declarative rules to select and normalize repository artifacts.",
        "The files do not prove a tool applied them, that an archive contains the declared set or that any built distribution was released.",
    ),
    ownership_spec(
        "vstd-repository-citation-metadata",
        "DATA",
        (".zenodo.json", "CITATION.cff"),
        "Repository citation and prospective archival-deposit metadata.",
        "The files retain how a selected source coordinate asks to be cited and described by compatible services.",
        "Metadata presence does not establish a deposit, publication, persistent identifier, authorship verification, endorsement or release authority.",
    ),
    ownership_spec(
        "vstd-repository-legal-notices",
        "POLICY",
        ("LICENSE", "NOTICE"),
        "Distributed license terms and repository copyright notice.",
        "Recipients need the exact legal and attribution text kept separate from technical conformance claims.",
        "Static legal text is not legal advice, identity verification, acceptance evidence, artifact provenance or technical correctness.",
    ),
    ownership_spec(
        "vstd-repository-agent-operating-policy",
        "POLICY",
        ("AGENTS.md", "CLAUDE.md", "HUMANS.md"),
        "Automated-agent and human operating guidance for repository work.",
        "The guides declare authority, evidence, terminology and execution disciplines expected of contributors.",
        "Written guidance does not prove an actor read or obeyed it, grant missing permission, validate work or authorize release or publication.",
    ),
    ownership_spec(
        "vstd-repository-community-governance-policy",
        "POLICY",
        (
            "CODE_OF_CONDUCT.md",
            "CONTRIBUTING.md",
            "GOVERNANCE.md",
            "SECURITY.md",
        ),
        "Community conduct, contribution, governance and vulnerability-reporting policy.",
        "The files define participation and escalation boundaries distinct from computational-verification results.",
        "Policy prose does not authenticate participants, enforce behavior, resolve reports, approve contributions or confer merge, release or publication authority.",
    ),
    ownership_spec(
        "vstd-repository-source-admission-designs",
        "ARCH",
        (
            "ADMITTED_ROOT_BINDING_DESIGN.md",
            "EXACT_MATERIALIZED_MEMBER_ADAPTER_DESIGN.md",
            "EXACT_SOURCE_SCOPE_READER_DESIGN.md",
            "WINDOWS_ANCHORED_MEMBER_OPENER_DESIGN.md",
        ),
        "Test-first designs for admitted roots, exact selected members and anchored source acquisition.",
        "The design set records the shared selected-source threat boundary and intended adapter seams before implementation evidence is considered.",
        "Design documents are not implementations, passing tests, secure host primitives, admitted source receipts or conformance evidence.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-repository-overview",
        "DATA",
        ("README.md",),
        "Repository orientation, capability summary and bounded public entry points.",
        "The overview directs readers to authoritative specifications, supported commands and explicit limitations.",
        "Overview prose does not establish implementation reachability, successful examples, adoption, release state, deployment or conformance.",
    ),
    ownership_spec(
        "vstd-repository-release-procedure-policy",
        "POLICY",
        ("RELEASING.md", "TIME.md"),
        "Maintainer release procedure and live repository-contradiction annunciator policy.",
        "Release promotion and contradiction handling require explicit sequencing, authority and fail-closed conditions.",
        "A clear annunciator or documented procedure is not a release receipt, acceptance, current hosted result, tag or publication authority.",
    ),
    ownership_spec(
        "vstd-repository-history-and-roadmap",
        "DATA",
        ("CHANGELOG.md", "ROADMAP.md"),
        "Declared change history and public technical roadmap.",
        "Readers need past release descriptions and planned work distinguished from current implemented and validated state.",
        "History and plans do not establish current source behavior, completion, release qualification, deployment or future delivery.",
    ),

    # Hosted workflow files are protocols and policies, not run receipts.  They
    # intentionally receive no actuator or transaction role from static text.
    ownership_spec(
        "vstd-github-contribution-form-policy",
        "POLICY",
        (
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/ISSUE_TEMPLATE/counterexample.yml",
            ".github/ISSUE_TEMPLATE/implementation-report.yml",
            ".github/ISSUE_TEMPLATE/specification-ambiguity.yml",
            ".github/PULL_REQUEST_TEMPLATE.md",
        ),
        "Issue and pull-request intake forms for counterexamples, implementation reports and specification ambiguity.",
        "The templates require selected coordinates and evidence fields so reports remain reviewable and bounded.",
        "A static template neither validates submitted content nor proves review, acceptance, authorization, integration or closure.",
    ),
    ownership_spec(
        "vstd-github-external-link-policy",
        "POLICY",
        (".github/external-links-allowlist.txt",),
        "Explicit external-link exceptions for the repository presentation gate.",
        "The allowlist is a narrow decision input whose scope must not be inferred from general documentation links.",
        "Listing a locator does not fetch it, establish availability, approve its content, authenticate its operator or waive other presentation checks.",
    ),
    ownership_spec(
        "vstd-github-verification-workflow-protocols",
        "PROTOCOL",
        (".github/workflows/ci.yml", ".github/workflows/external-links.yml"),
        "Hosted continuous-integration and external-link workflow declarations.",
        "The declarations define triggers, jobs, permissions and ordered platform messages for verification-oriented automation.",
        "Static workflow text is not a current run, executed command, check result, trusted platform receipt, release qualification or conformance evidence.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-github-source-description-workflow-protocol",
        "PROTOCOL",
        (".github/workflows/pr-description.yml",),
        "Hosted pull-request source-description coverage workflow declaration.",
        "The workflow describes how changed source and pull-request prose are compared under bounded platform permissions.",
        "The declaration is not an executed comparison, current source observation, passing check, approval or merge authority.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-github-promotion-policy-protocols",
        "PROTOCOL",
        (
            ".github/workflows/pr-policy-notification.yml",
            ".github/workflows/pr-policy.yml",
        ),
        "Hosted notification and default-branch promotion-policy workflow declarations.",
        "The files describe participant events, permission separation and fail-closed pull-request and merge-group decisions.",
        "Static workflow bytes are not a dispatched event, trusted run, human acceptance, queue state, approval, merge authority or integration proof.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-github-documentation-deployment-protocol",
        "PROTOCOL",
        (".github/workflows/pages.yml",),
        "Hosted documentation build, promotion, deployment and observation workflow declaration.",
        "The declaration sequences source qualification, site construction, deployment and bounded live observation under platform policy.",
        "The static declaration does not build or deploy a site, observe a current endpoint, prove successful publication or grant deployment authority.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-github-release-workflow-protocol",
        "PROTOCOL",
        (".github/workflows/release.yml",),
        "Hosted artifact build, comparison, verification and release workflow declaration.",
        "The declaration defines ordered release checks and platform interactions whose actual results require separate run evidence and authority.",
        "The static declaration is not an executed build, artifact receipt, passing release gate, tag, upload, publication or release authorization.",
        "POLICY",
    ),

    # Receipt schemas define wire shapes only; they neither parse nor validate a
    # supplied record.  Hardware profile structure is kept separate from receipt
    # envelopes to avoid treating a declared accelerator as observed hardware.
    ownership_spec(
        "vstd-receipt-wire-schema-catalog",
        "PROTOCOL",
        (
            "receipts/schema/vstd1_generic_run_receipt.json",
            "receipts/schema/vstd1_receipt.json",
            "receipts/schema/vstd2_receipt.json",
            "receipts/schema/vstd3_receipt.json",
            "receipts/schema/vstd4_certificate.json",
            "receipts/schema/vstd4_receipt.json",
            "receipts/schema/vstd5_receipt.json",
            "receipts/schema/vstd_graph_receipt.json",
        ),
        "Published JavaScript Object Notation schemas for numbered, graph and generic-run receipt records.",
        "The schemas declare portable field, type and identifier contracts independently of the readers that enforce them.",
        "Schema bytes do not parse an instance, prove a receipt valid, authenticate a signer, execute a mechanism or establish conformance.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-accelerator-profile-wire-schema",
        "PROTOCOL",
        ("receipts/schema/vstd3_accelerator_profile.json",),
        "Published JavaScript Object Notation schema for a declared VSTD-3 accelerator profile.",
        "The schema fixes the portable representation of selected accelerator-profile fields separately from receipt envelopes and hardware adapters.",
        "A structural schema does not detect hardware, measure a device, attest identity, prove custody or backing, or establish VSTD-3 conformance.",
        "POLICY",
        root_role_decisions=_ACCELERATOR_PROFILE_SCHEMA_ROOT_DECISIONS,
    ),
    ownership_spec(
        "vstd-generated-distribution-metadata",
        "DATA",
        (
            "src/verifier_standard.egg-info/PKG-INFO",
            "src/verifier_standard.egg-info/SOURCES.txt",
            "src/verifier_standard.egg-info/dependency_links.txt",
            "src/verifier_standard.egg-info/entry_points.txt",
            "src/verifier_standard.egg-info/requires.txt",
            "src/verifier_standard.egg-info/top_level.txt",
        ),
        "Generated Python distribution description, source inventory, dependency, entry-point and top-level package metadata.",
        "Build and installation tools may consume these generated records, so they require an exact static owner separate from source configuration.",
        "Generated metadata does not prove freshness, archive contents, installation, import resolution, artifact identity, release or publication.",
    ),
)


__all__ = [
    "CATCHALL_BOUNDARY_EXCLUSIONS",
    "REPOSITORY_ASSET_OWNERSHIP_SPECS",
    "SemanticOwnershipSpec",
]
