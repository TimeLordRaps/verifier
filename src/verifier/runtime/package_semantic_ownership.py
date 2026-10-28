"""Audited minimum semantic ownership splits for Verifier's package graph.

Terminology: application programming interface (API).

Terminology: Advanced Micro Devices (AMD); abstract syntax tree (AST); central
processing unit (CPU); directed acyclic graph (DAG); hash-based message
authentication code (HMAC); identifier (ID); JavaScript Object Notation (JSON);
JSON Lines (JSONL); NVIDIA Management Library (NVML); Software Bill of Materials
(SBOM); Supply Chain
Integrity, Transparency, and Trust (SCITT); system management interface (SMI);
Verifier Standard (VSTD); YAML Ain't Markup Language (YAML).

The package manifest migration historically assigned broad directory catch-alls.
Those rows hide materially different protocols, ledgers, controls, sensors and
policies behind one generic OBJECT.  This catalog names the smallest current
path partitions established by the package audit.  It is deliberately data-only:
using a row still requires repository-specific declarations and mechanisms.

Claim boundary: this is not a complete partition of ``src/verifier`` and it does
not establish namespace admission or polish conformance.  Ownership is currently
path-granular.  Co-resident mechanisms such as Claim Garden registration, upload,
finalization and claim publication therefore remain one compound instance until
surface-granular ownership exists.  Roles accumulate; no row asserts physical
confinement, ROBOT/FINBOT status, real-money effects, or publication authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Mapping

from verifier.runtime.package_semantic_ownership_model import (
    RootRoleDecision,
    SemanticOwnershipSpec,
    ownership_spec as _spec,
)
from verifier.runtime.package_semantic_ownership_domains import (
    DOMAIN_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_experiments import (
    EXPERIMENT_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_hardware_interop import (
    HARDWARE_INTEROP_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_python_apps import (
    PYTHON_APPS_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_public_cli import (
    PUBLIC_CLI_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_repository_assets import (
    REPOSITORY_ASSET_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_scripts_examples import (
    SCRIPT_EXAMPLE_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_tests_fixtures import (
    TEST_FIXTURE_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_normative_assets import (
    NORMATIVE_ASSET_OWNERSHIP_SPECS,
)
from verifier.runtime import package_api_surface_admission as _api_surface_admission
from verifier.runtime import package_semantic_ownership_current_untracked as _current_untracked
from verifier.runtime import package_semantic_ownership_domains_agency_collective as _agency_collective
from verifier.runtime import package_semantic_ownership_domains_context as _domain_context
from verifier.runtime import package_semantic_ownership_domains_sim_model as _sim_model
from verifier.runtime import package_semantic_ownership_domains_systems as _domain_systems
from verifier.runtime import package_protocol_dependency_relation as protocol_relation
from verifier.runtime import tier_zero_manifest as _tier_zero_manifest


SCHEMA_VERSION = "verifier-package-semantic-ownership-2"
CLAIM_BOUNDARY = (
    "Audited minimum path-level ownership splits only; not a complete package "
    "partition, namespace admission result, polish result, physical-confinement "
    "claim, financial-effect claim, or publication authority. Co-resident "
    "surfaces remain one compound instance until surface ownership is supported."
)

# Exact IDs and kinds from the declarative graph that compiles to objects.vstd.
# Operand resolution is about graph identity, not whether the target's source
# ownership row has already passed this separate aggregate audit.
_INSTALLED_OBJECT_KINDS = {
    row["object_id"]: row["object_kind"]
    for row in _tier_zero_manifest.installed_object_declarations()
}


@dataclass(frozen=True, slots=True)
class AggregateBatchStatus:
    """One standalone audit's explicit central-admission partition.

    A blocked object remains visible here and absent from the admitted catalog.
    ``blocked`` never means DOES_NOT_APPLY; it means that the source owner or a
    required relation remains UNKNOWN at this aggregate coordinate.
    """

    name: str
    candidate_object_ids: tuple[str, ...]
    accepted_object_ids: tuple[str, ...]
    blocked_object_ids: tuple[str, ...]
    state: str
    reason: str

    @property
    def counts(self) -> tuple[int, int, int]:
        """Return candidate, accepted and blocked cardinalities."""
        return (
            len(self.candidate_object_ids),
            len(self.accepted_object_ids),
            len(self.blocked_object_ids),
        )


@dataclass(frozen=True, slots=True)
class AggregateFinding:
    """A deterministic fail-closed aggregate or API-overlay finding."""

    code: str
    object_id: str
    reason: str
    operand_role: str | None = None
    target_id: str | None = None
    required_kinds: tuple[str, ...] = ()


def _aggregate_finding_key(item: AggregateFinding) -> tuple:
    return (
        item.code,
        item.object_id,
        item.operand_role or "",
        item.target_id or "",
        item.required_kinds,
        item.reason,
    )


_AGGREGATE_FINDING_KEY = _aggregate_finding_key


# Repository-admission support is split from the broad runtime VERIFIER owner.
# Each row is the exact path denominator audited together; declaration truth and
# later-tier execution remain separate from assigning these source bytes.
_RUNTIME_ADMISSION_SPECS = (
    _spec(
        "vstd-runtime-package-marker",
        "VERIFIER",
        ("src/verifier/runtime/__init__.py",),
        "Inert runtime package and public-module marker.",
        "The package marker needs an exact owner so it cannot inherit behavioral consequence roles from a broad runtime catch-all.",
        "It declares a Python package only and performs no checking, acquisition, effect, policy decision, physical action or financial action.",
    ),
    _spec(
        "vstd-namespace-rule-engine",
        "POLICY",
        (
            "src/verifier/runtime/namespace_classification.py",
            "src/verifier/runtime/namespace_consequences.mjs",
            "src/verifier/runtime/namespace_consequences.py",
            "src/verifier/runtime/namespace_contracts.py",
            "src/verifier/runtime/namespace_dominance.py",
            "src/verifier/runtime/namespace_refutation.py",
        ),
        "Installed kind contracts, classification rules, consequence closure and mandatory-path dominance policy.",
        "Repository admission depends on explicit rule scope, precedence, revisions and fail-closed behavior rather than filename inference.",
        "These sources compute declared rules only; they do not prove subject behavior, discovery completeness, effect containment or higher-tier conformance.",
    ),
    _spec(
        "vstd-namespace-source-census",
        "SENSOR",
        (
            "src/verifier/runtime/namespace_discovery.py",
            "src/verifier/runtime/namespace_exports.py",
            "src/verifier/runtime/namespace_html.py",
            "src/verifier/runtime/namespace_metadata.py",
            "src/verifier/runtime/namespace_source_imports.py",
            "src/verifier/runtime/namespace_svg.py",
            "src/verifier/runtime/source_declaration_inputs.py",
        ),
        "Current repository-byte and exposed-surface census with isolated supported-language parser dispatch.",
        "Direct source acquisition, derived measurements and parser exchanges need explicit observation, policy, protocol and failure semantics.",
        "Coverage is limited to supported static grammars and selected paths; parser processes are not subject sandboxes and prove neither runtime reachability nor complete semantics.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
    ),
    _spec(
        "vstd-manifest-admission",
        "VERIFIER",
        (
            "src/verifier/runtime/namespace_manifest.py",
            "src/verifier/runtime/package_manifest.py",
            "src/verifier/runtime/tier_zero_manifest.py",
        ),
        "Strict manifest readers, typed composition validators and retained/additive package-graph bridge.",
        "Admission reads selected declaration bytes and applies finite structural policy, so source and decision boundaries must remain explicit.",
        "Structural declaration admission establishes neither implementation truth nor any numbered tier beyond the bounded repository-admission question.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-package-semantic-review-policy",
        "VERIFIER",
        (
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
            "src/verifier/runtime/package_api_surface_admission.py",
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
        ),
        "Atomic current-source Tier-0 applicability and declaration review family.",
        "Hard-coded repository review policy acquires and recaptures every selected source denominator before filling classifications and declarations.",
        "These reviews complete declared reasons only; they do not execute mechanisms, establish Tier-1-plus truth, confer external authority, release or deploy.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-package-semantic-ownership-policy",
        "POLICY",
        (
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
        ),
        "Explicit path-disjoint package source partition and object-kind assignment policy.",
        "Every specialized child needs one inspectable source owner and boundary instead of accidental broad catch-all ownership.",
        "Catalog validity is not repository admission, semantic review, mechanism execution, release or deployment.",
    ),
    _spec(
        "vstd-package-graph-contract",
        "VERIFIER",
        (
            "src/verifier/runtime/package_contract_coverage.py",
            "src/verifier/runtime/package_contract_profiles.py",
            "src/verifier/runtime/package_graph_representation.py",
        ),
        "Finite declared dependency-edge projection and exact package contract-denominator checks.",
        "Graph membership and registered route coverage are policy-selected structural questions distinct from generic VERIFIER behavior.",
        "Declared graph and route accounting do not establish dynamic causality, runtime effects or normative completeness.",
        "POLICY",
    ),
    _spec(
        protocol_relation.OBJECT_ID,
        protocol_relation.PRIMARY_KIND,
        protocol_relation.OWNED_PATHS,
        protocol_relation.REPRESENTATION_ROLE,
        protocol_relation.NECESSITY_REASON,
        protocol_relation.CONSEQUENCE_BOUNDARY,
        operands=protocol_relation.validate_operands(protocol_relation.OPERANDS),
    ),
    _spec(
        "vstd-package-instance-evidence",
        "VERIFIER",
        ("src/verifier/runtime/package_instance_evidence.py",),
        "Selected file snapshots and policy-bound native instance rechecker execution.",
        "Running a registered checker over acquired bytes has explicit authority, effect, observation and failure consequences.",
        "The selected instance proposition and trusted checker execution are not sandboxing, whole-package proof, physical control or financial authority.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-package-kind-requirements",
        "VERIFIER",
        ("src/verifier/runtime/package_kind_requirements.py",),
        "Source discovery, isolated-parser exchange, consequence closure and obligation-selection assessment.",
        "Selecting required kinds from current source crosses observation and parser boundaries and applies consequential policy.",
        "Derived requirements do not convert records, establish final domain applicability, prove confinement or discharge selected obligations.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
    ),
    _spec(
        "vstd-package-obligation-candidate",
        "VERIFIER",
        ("src/verifier/runtime/package_obligation_candidate.py",),
        "Candidate-card, manifest and reason-ledger acquisition under finite selection rules.",
        "Candidate selection consumes current repository evidence and policy and therefore needs explicit observation and decision boundaries.",
        "A validated candidate remains an inferred proposal; owner adoption, normative closure and mechanism truth remain unestablished.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-package-owner-decision",
        "PROTOCOL",
        ("src/verifier/runtime/package_owner_decision.py",),
        "Configured-key owner-decision acquisition and authentication against selected policy and time windows.",
        "A signed participant statement has message authority, replay, compatibility and policy semantics distinct from generic package data.",
        "The configured-key statement establishes neither human or legal authority, semantic truth nor release authority.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-native-operation-metadata",
        "VERIFIER",
        (
            "src/verifier/runtime/native_operation_cli.py",
            "src/verifier/runtime/native_operation_contracts.py",
        ),
        "Installed native-route source, signature, schema and selection metadata introspection.",
        "Native operation admission requires explicit metadata-source and selection-policy boundaries.",
        "Metadata availability establishes neither route execution, effects nor a complete obligation census.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-object-context-closure",
        "VERIFIER",
        ("src/verifier/runtime/object_context_closure.py",),
        "Source-bound composition of selected object, context and security rechecks.",
        "Closure consumes current source evidence, invokes selected in-process recheckers, and applies finite composition policy that must be reviewable explicitly.",
        "Selected composition establishes no authority, permissions, release, retained history or complete security claim.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
)


_RUNTIME_COMMAND_SPECS = (
    _spec(
        "vstd-artifact-snapshot-transaction",
        "TRANSACTION",
        ("src/verifier/runtime/artifact_snapshot.py",),
        "Bounded source acquisition and exclusive local artifact file or directory materialization.",
        "Snapshot publication changes caller-selected filesystem state and therefore needs explicit observation, effect, commit and retry semantics.",
        "The local snapshot establishes no provenance authority, lock, crash durability, atomic multi-file commit, physical effect or financial effect.",
        "ACTUATOR",
        "MEASUREMENT",
        "SENSOR",
    ),
    _spec(
        "vstd-accessibility-artifact-reader",
        "VERIFIER",
        ("src/verifier/runtime/accessibility_cli.py",),
        "Caller-selected accessibility projection through an unsealed command-argument and path-coercion boundary.",
        "The public handler reads attributes from a caller-supplied namespace and coerces its path without a runtime type seal, so every delegated consequence role remains explicit while artifact interpretation stays bounded.",
        "Applicability retains delegated obligations without asserting any effect occurred; an explanation is not artifact validity, evidence authentication, identity, authority, physical or financial effect, publication, release, or higher-tier proof.",
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
    _spec(
        "vstd-graph-topology-reader",
        "VERIFIER",
        ("src/verifier/runtime/graph_topology_cli.py",),
        "Secure local graph-record acquisition and topology-contract projection.",
        "Topology checks depend on exact selected records and declared structural policy rather than generic VERIFIER ownership.",
        "The projection establishes neither an enclosing receipt's validity nor runtime causality or external authority.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-current-object-reader",
        "VERIFIER",
        ("src/verifier/runtime/current_object_cli.py",),
        "Selected request, policy and certificate acquisition for one installed bounded object replay.",
        "Replay selection, current input acquisition and installed in-process checker invocation require explicit observation, effect and fail-closed policy semantics.",
        "The route performs no network publication and establishes no broader object, application or release conformance.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-experimental-workflow-reader",
        "VERIFIER",
        ("src/verifier/runtime/experimental_workflow_cli.py",),
        "Selected snapshot acquisition under an explicitly non-normative experimental workflow profile.",
        "Snapshot interpretation depends on current bytes and declared policy that must not be confused with live provider state.",
        "It makes no live GitHub request and establishes no normative clearance, external authority, effect or release decision.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-security-artifact-reader",
        "VERIFIER",
        ("src/verifier/runtime/security_cli.py",),
        "Bounded local security-artifact acquisition and fixed dangerous-pathway replay selection.",
        "Selected in-process security-rechecker invocation needs exact input provenance plus explicit effect and decision scope.",
        "A fixed replay is not a general security, confinement, application-safety or release proof.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-certification-command",
        "VERIFIER",
        ("src/verifier/runtime/certification_cli.py",),
        "Selected input acquisition, built-in certification execution and exclusive local output creation.",
        "Checker invocation and output publication have authority, observation, effect and failure boundaries beyond passive verification metadata.",
        "The command invokes no external domain mechanism and establishes no application-wide certification, sandboxing or endpoint authority.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    ),
    _spec(
        "vstd-clearance-publication-preparation",
        "TRANSACTION",
        ("src/verifier/runtime/clearance_publish.py",),
        "Selected clearance and policy checks followed by local publication-preparation record creation.",
        "Preparing a durable local effect requires explicit input, authority, commit, observation and policy treatment.",
        "The path performs no transport, credential read, external approval or production publication and grants no release authority.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-demo-specimen-materializer",
        "VERIFIER",
        ("src/verifier/runtime/demo.py",),
        "Adversarial scenario checks with optional collision-checked specimen materialization.",
        "Optional local writes and selected scenario policy have explicit observation, effect and transaction boundaries.",
        "Demonstration specimens are examples, not general correctness, clearance, deployment, physical-effect or financial-effect proof.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    ),
    _spec(
        "vstd-core-obligation-union-policy",
        "VERIFIER",
        ("src/verifier/runtime/core_obligation_union.py",),
        "Finite core-contribution union validation and structural adaptation policy.",
        "Combining obligation contributions needs explicit denominator, duplicate and compatibility rules.",
        "A clean structural union is not semantic completeness, external authority, execution evidence or release admission.",
        "POLICY",
    ),
    _spec(
        "vstd-security9-accounting-policy",
        "VERIFIER",
        ("src/verifier/runtime/core_security9_accounting.py",),
        "Finite Security-9 accounting denominator and source-binding policy.",
        "Security accounting requires explicit selected membership and source rules rather than an implicit checklist.",
        "Selection accounting authenticates neither semantic completeness nor mechanism truth or release qualification.",
        "POLICY",
    ),
    _spec(
        "vstd-application-authority-protocol",
        "PROTOCOL",
        ("src/verifier/runtime/core_application_authority.py",),
        "Configured-key scope and completeness statement replay under explicit status, time and revocation policy.",
        "Authenticated application statements require participant, ordering, replay, compatibility and policy semantics.",
        "Cryptographic replay is not human or legal authority, application acceptance, polish conformance or release permission.",
        "POLICY",
    ),
    _spec(
        "vstd-release-source-binding",
        "VERIFIER",
        ("src/verifier/runtime/release_source_binding.py",),
        "Exact supplied-byte commitments for source, archive, distribution, SBOM and public-surface roles.",
        "Release inputs require explicit role selection and equality policy before they can be compared.",
        "Equality to selected commitments establishes neither inventory authority, native replay, signing, upload nor release permission.",
        "POLICY",
    ),
)


_RUNTIME_POLISH_SPECS = (
    _spec(
        "vstd-tier-progression-controller",
        "VERIFIER",
        (
            "src/verifier/runtime/core_tier_progression.py",
            "src/verifier/runtime/tier_progression.py",
        ),
        "Finite nine- and ten-tier native DAG assessment and cumulative progression control.",
        "Observed prerequisite outcomes command whether later selected tiers may advance, requiring explicit feedback, effect and policy semantics.",
        "This is a finite selected-rank overlay, not whole-tier or application completeness, release authority, physical control or financial authority.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
    ),
    _spec(
        "vstd-application-release-controller",
        "VERIFIER",
        (
            "src/verifier/runtime/application_release.py",
            "src/verifier/runtime/core_application_release.py",
        ),
        "Release-consumer acquisition and finite native instance and gate replay orchestration.",
        "Release-facing progression acts on observed verification results and therefore needs explicit controller, effect and policy boundaries.",
        "A bounded result never authorizes release or deployment and does not establish a complete application denominator.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    ),
    _spec(
        "vstd-package-polish-controller",
        "VERIFIER",
        (
            "src/verifier/runtime/package_polish.py",
            "src/verifier/runtime/package_polish_schema_validation.py",
            "src/verifier/runtime/package_source_contracts.py",
        ),
        "Root GRAPH selection, source observation, worker/native checking, cumulative gating and final recapture orchestration.",
        "Package polish commands selected mechanisms and gates later states from acquired results across a process protocol.",
        "Missing instance or applicability evidence remains UNKNOWN; this source alone establishes no polished status, release or deployment authority.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    _spec(
        "vstd-package-self-polish-controller",
        "VERIFIER",
        ("src/verifier/runtime/package_self_polish.py",),
        "Recursive package self-assessment over source census, native execution, authority paths and gate outcomes.",
        "Self-assessment coordinates multiple observed and effectful mechanisms through bounded request-response records whose ordering and progression policy must remain explicit.",
        "A source-bound assessment is not external adoption, complete application proof, release or deployment authority.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
    ),
    _spec(
        "vstd-package-self-polish-rechecker",
        "VERIFIER",
        ("src/verifier/runtime/package_self_polish_recheck.py",),
        "Independent reconstruction and replay of retained package-report invariants and native results.",
        "Rechecking a report invokes selected mechanisms and observes their correspondence under a bounded replay protocol.",
        "Report-integrity reproduction is not package truth, application closure, release qualification or deployment authority.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
    ),
    _spec(
        "vstd-polish-assessment-engine",
        "VERIFIER",
        ("src/verifier/runtime/polish.py",),
        "Bounded polish catalog, object-composition assessment, registered objective replay and exact retained-result recheck engine.",
        "Assessment invokes selected registered mechanisms and derives source-bound observations under explicit admission, resource and acceptance policy, so its effects and failure semantics cannot remain hidden in a generic runtime owner.",
        "The engine returns bounded non-promoting records only; polished remains false, and it establishes neither inventory completeness, external authority, release, deployment, physical control nor financial effect.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
    ),
    _spec(
        "vstd-polish-command-controller",
        "CONTROLLER",
        ("src/verifier/runtime/polish_cli.py",),
        "Polish command parser, selected-file acquisition, subcommand dispatch and bounded result-rendering controller.",
        "Command routing sequences selected assessment, recheck, authority, report and preparation mechanisms from acquired inputs, requiring explicit feedback, effect, observation, policy and transaction boundaries.",
        "Dispatch and rendering do not establish mechanism truth, atomic preparation, sandboxing, polish promotion, release, deployment, physical control or financial authority.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    ),
    _spec(
        "vstd-polish-capacity-policy",
        "POLICY",
        ("src/verifier/runtime/polish_capacity.py",),
        "Bounded polish transport and work-budget admission policy.",
        "Resource ceilings and rejection behavior must be explicit before any selected mechanism runs.",
        "Capacity admission discharges no numbered obligation and establishes no polish or release status.",
    ),
    _spec(
        "vstd-polish-findings-projection",
        "VERIFIER",
        ("src/verifier/runtime/polish_findings.py",),
        "Deterministic diagnostic-report projection and retained-finding comparison over supplied bytes.",
        "Supplied reports and comparison rules are measurement and policy inputs rather than an active source-acquisition mechanism.",
        "The projection performs no check replay, evidence authentication, run chronology reconstruction, fix or downstream execution.",
        "MEASUREMENT",
        "POLICY",
    ),
    _spec(
        "vstd-polish-inventory-policy",
        "VERIFIER",
        ("src/verifier/runtime/polish_inventory.py",),
        "Exact finite inventory applicability and coverage policy.",
        "A selected polish plan needs explicit membership, applicability and coverage rules.",
        "Finite plan closure is not normative exhaustiveness, native mechanism truth, application polish or release authority.",
        "POLICY",
    ),
    _spec(
        "vstd-polish-inventory-authority",
        "PROTOCOL",
        ("src/verifier/runtime/polish_inventory_authority.py",),
        "Configured-key admission of one exact selected inventory under explicit participant and policy replay.",
        "Inventory authority statements require authenticated participant, ordering, replay and policy semantics.",
        "Key-holder authentication is not normative completeness, independent semantic truth, application polish or release authority.",
        "POLICY",
    ),
    _spec(
        "vstd-polish-public-authority",
        "PROTOCOL",
        ("src/verifier/runtime/polish_public_authority.py",),
        "Public-key decision and status protocol for one bounded issuance subject.",
        "A public authority exchange needs explicit participants, message authority, replay, status and decision policy.",
        "It establishes no legal or human authority, completeness, native truth, consent or atomic invocation consumption.",
        "POLICY",
    ),
    _spec(
        "vstd-prdel-coverage-policy",
        "VERIFIER",
        ("src/verifier/runtime/prdel_coverage.py",),
        "Explanation, evidence-coverage and preventative-obligation policy checks.",
        "PRDEL coverage needs explicit denominator and rule correspondence rather than prose presence alone.",
        "Carried test receipts are not authenticated execution, predicate truth, application closure or promotion clearance.",
        "POLICY",
    ),
    _spec(
        "vstd-prdel-impact-graph",
        "VERIFIER",
        ("src/verifier/runtime/prdel_graph.py",),
        "Deterministic bounded AST relationship and impact projection over supplied snapshots.",
        "Static relationship traversal depends on explicit selection, bounds and impact policy.",
        "Static relations do not establish dynamic dispatch, runtime effects, complete applicability or promotion clearance.",
        "POLICY",
    ),
    _spec(
        "vstd-prdel-source-compiler",
        "VERIFIER",
        ("src/verifier/runtime/prdel_rules.py",),
        "Committed Git source acquisition and authored explanation-association compilation.",
        "Source compilation crosses a bounded Git process protocol and applies fail-closed authoring policy.",
        "Compilation does not invent motivation, prove predicates, authenticate execution or authorize publication or promotion.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
    ),
    _spec(
        "vstd-prdel-shard-protocol",
        "PROTOCOL",
        (
            "src/verifier/runtime/prdel_shard_index.py",
            "src/verifier/runtime/prdel_shards.py",
        ),
        "PRDEL partition, reconstruction and index protocol with optional independent source recompilation.",
        "Complete sharding needs ordering, linkage, compatibility and replay rules; source replay additionally acquires and executes a bounded compiler path.",
        "Transport and linkage integrity establish neither explanation truth, authenticated execution nor promotion clearance.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-prdel-v2-shard-protocol",
        "PROTOCOL",
        ("src/verifier/runtime/prdel_v2_shards.py",),
        "Bounded complete-document PRDEL partition and reconstruction protocol.",
        "Document shards require explicit participant, ordering, completeness, replay and compatibility rules.",
        "Transport integrity carries no independent verdict, source replay, execution evidence or promotion authority.",
        "POLICY",
    ),
    _spec(
        "vstd-public-checkability-protocol",
        "PROTOCOL",
        ("src/verifier/runtime/public_checkability.py",),
        "Disclosure request, consent and grant replay, node modes and finite public-evidence policy.",
        "Public checkability is a participant and authorization protocol whose ordering and scope must be explicit.",
        "It performs no publication and establishes neither public availability, confidential-proof support, claim correctness nor overall safety.",
        "POLICY",
    ),
)


_RUNTIME_SELF_POLISH_SPECS = (
    _spec(
        "vstd-self-polish-dynamics-controller",
        "VERIFIER",
        ("src/verifier/runtime/self_polish_dynamics.py",),
        "Fresh cumulative Tier-1 and Tier-2 triad replay, including process-backed fresh SIM variants.",
        "Progression acquires current source and replay outcomes, commands selected rechecks, and gates later states through bounded manifest and receipt exchanges.",
        "The fixed installed route union is not arbitrary-application completeness, a historical resource claim, physical control or financial authority.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    _spec(
        "vstd-self-polish-estate-authority",
        "PROTOCOL",
        ("src/verifier/runtime/self_polish_estate_authority.py",),
        "Configured-key replay of one exact self-polish estate-selection authority statement.",
        "Estate selection authority requires participant, message, replay, compatibility and policy semantics.",
        "Estate-scope key authority is not semantic applicability, evidence closure, polish conformance or release authority.",
        "POLICY",
    ),
    _spec(
        "vstd-self-polish-estate-evidence",
        "VERIFIER",
        ("src/verifier/runtime/self_polish_estate_evidence.py",),
        "Current source re-observation combined with optional signed estate and candidate authority protocols.",
        "Estate closure depends on exact current observations and authenticated bounded participant statements.",
        "It closes only the enumerated estate at one coordinate and proves neither broader repository completeness nor Tier-1 status.",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
    ),
    _spec(
        "vstd-self-polish-estate-native-sensor",
        "SENSOR",
        ("src/verifier/runtime/self_polish_estate_native_evidence.py",),
        "Exact selected-root candidate re-observation under installed category rules.",
        "Direct source correspondence is an observation mechanism with explicit sampling, missingness and policy scope.",
        "Source correspondence is not external authority, package completeness or semantic correctness beyond the registered check.",
        "MEASUREMENT",
        "POLICY",
    ),
    _spec(
        "vstd-self-polish-facet-reason-ledger",
        "LEDGER",
        ("src/verifier/runtime/self_polish_facet_reasons.py",),
        "Authoritative installed reason mapping with source-bound route and facet denominators.",
        "Reason identity and retained denominator changes require explicit history, observation and selection policy.",
        "Reason coverage establishes neither route outcomes, normative completeness, polish conformance nor release readiness.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-self-polish-native-adapters",
        "VERIFIER",
        ("src/verifier/runtime/self_polish_native_adapters.py",),
        "Named adapter policy that transforms cases and invokes selected builder callables.",
        "Trusted builder invocation is an in-process command-to-effect boundary selected by explicit adapter policy; the adapter does not establish a coordinated commit or retry transaction.",
        "The invocation is not a sandbox, and produced specimen bytes prove no wider property or tier conformance.",
        "ACTUATOR",
        "POLICY",
    ),
    _spec(
        "vstd-self-polish-native-case-registry",
        "DATA",
        (
            "src/verifier/runtime/self_polish_native_cases.py",
            "src/verifier/runtime/self_polish_native_sim_case_patch.py",
            "src/verifier/runtime/self_polish_native_tier3_cases.py",
            "src/verifier/runtime/self_polish_native_tier4_cases.py",
            "src/verifier/runtime/self_polish_native_tier5_cases.py",
            "src/verifier/runtime/self_polish_native_tier6_cases.py",
            "src/verifier/runtime/self_polish_native_tier7_cases.py",
            "src/verifier/runtime/self_polish_native_tier8_cases.py",
            "src/verifier/runtime/self_polish_native_tier9_cases.py",
        ),
        "Installed source-owned native case inputs, adapter selections and expected triad outcomes.",
        "Case admission and expected-result selection are policy data that must remain distinct from replay execution.",
        "Decoding and registration perform no replay and establish no route, tier, package, release or deployment conformance.",
        "POLICY",
    ),
    _spec(
        "vstd-self-polish-native-extension-registry",
        "DATA",
        ("src/verifier/runtime/self_polish_native_extensions.py",),
        "Exact generated-module observation and prepared extension membership and input policy.",
        "Prepared extensions depend on current generated bytes and explicit admission rules.",
        "Prepared inputs remain uninstalled and unqualified and establish no installed route or tier result.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
    _spec(
        "vstd-self-polish-native-replay-controller",
        "VERIFIER",
        (
            "src/verifier/runtime/self_polish_native_extension_replay.py",
            "src/verifier/runtime/self_polish_native_full_candidate.py",
            "src/verifier/runtime/self_polish_native_replay.py",
        ),
        "Source-bound mechanism resolution, builder and rechecker execution, triad observation and installed or prepared progression aggregation.",
        "Native replay invokes selected effectful mechanisms and aggregates their fixed request-response outcomes without establishing feedback-directed command control.",
        "Specimen discrimination is not whole-tier, package, release or deployment qualification and provides no physical or financial authority.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    _spec(
        "vstd-self-polish-statics-controller",
        "VERIFIER",
        ("src/verifier/runtime/self_polish_statics.py",),
        "Installed and repository byte comparison, fresh prerequisite execution, Tier-3 specimen triads and final source recapture.",
        "Static-layer progression commands mechanisms and gates results on current observations across bounded process exchanges.",
        "Source equality is not host attestation, physical truth, full package polish, release authority or deployment evidence.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    _spec(
        "vstd-self-polish-tier-controller",
        "VERIFIER",
        ("src/verifier/runtime/self_polish_tiers.py",),
        "Numeric-tier orchestration over estate evidence, native replay, authority conditions, dependency progression and source recapture.",
        "Tier outcomes depend on observed prerequisites and policy-directed mechanism execution and therefore require explicit control semantics.",
        "A bounded numeric-tier result is not automatic full-application, release or deployment authority.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
    ),
    _spec(
        "vstd-tier-zero-orchestrator",
        "VERIFIER",
        ("src/verifier/runtime/tier_zero.py",),
        "Repository and manifest estate acquisition plus independent Node reconciliation process orchestration.",
        "Repository admission observes current source and commands a bounded reconciliation exchange under fail-closed policy.",
        "Tier Zero establishes repository admission only; subprocess reconciliation is not sandboxing or Tier-1-plus conformance.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
    ),
    _spec(
        "vstd-tier-zero-profile-policy",
        "POLICY",
        ("src/verifier/runtime/tier_zero_profile.py",),
        "Immutable installed Tier-Zero denominator, obligation reasons and finalization rule.",
        "Repository admission needs one explicit versioned profile and fail-closed completion policy.",
        "The profile declaration alone establishes no repository result, mechanism truth or higher-tier conformance.",
    ),
    _spec(
        "vstd-tier-zero-reason-ledger",
        "LEDGER",
        ("src/verifier/runtime/tier_zero_reasons.py",),
        "Source-bound authoritative route and slot reason identities with realization annotations.",
        "Retained reason identities and denominator correspondence require explicit history, observation and policy rules.",
        "Annotation binding proves neither the annotation's semantic claim nor repository or higher-tier fulfillment.",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    ),
)


# The public VSTD 3 command facade is split by mechanism so registry projection,
# live discovery, virtual probing, and stored-receipt assessment do not inherit
# one another's consequences merely because they share a command family.  The
# dispatch facade itself does accumulate consequences of handlers it actually
# invokes: live acquisition, emitted observations, and bounded local commits.
_RUNTIME_HARDWARE_CLI_SPECS = (
    _spec(
        "vstd-hardware-cli-protocol",
        "PROTOCOL",
        (
            "src/verifier/runtime/hardware_cli.py",
            "src/verifier/runtime/hardware_cli_support.py",
        ),
        "Stable VSTD 3 parser, key-decoding, dispatch, output-framing and exit-status protocol.",
        "Command selection and framing cross a caller/tool boundary; dispatch reaches live acquisition, emitted observation, and local-write handlers, so sensor, measurement, transaction, policy, protocol and bounded software-effect semantics are necessary.",
        "The facade reaches host queries and bounded local writes but establishes no caller identity, authorization, sandbox, hardware fact beyond the reported observation, physical actuation, financial effect, publication or release authority.",
        "ACTUATOR",
        "ASSET",
        "CONTROLLER",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "MEASUREMENT",
        "POLICY",
        "ROBOT",
        "SENSOR",
        "TRANSACTION",
    ),
    _spec(
        "vstd-accelerator-profile-reader",
        "VERIFIER",
        ("src/verifier/runtime/hardware_registry_cli.py",),
        "Caller-selected accelerator-profile projection through a public registry dispatch boundary.",
        "The handler invokes list, get, and returned-object methods on a caller-supplied registry without a runtime type seal, so all delegated consequence roles stay explicit while selection and output policy remain bounded.",
        "Applicability retains delegated obligations without asserting any such effect occurred; PASS output establishes no device fact, caller identity, external authority, physical actuation, financial effect, publication or release.",
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
    _spec(
        "vstd-accelerator-discovery-command",
        "SENSOR",
        ("src/verifier/runtime/hardware_discovery_cli.py",),
        "Selected vendor or fixture adapter acquisition with optional local normalized-result publication.",
        "Adapter selection actively acquires device-shaped observations and may overwrite a named local output, so acquisition, policy, effect and failure boundaries are necessary.",
        "Vendor or fixture output establishes no device identity, physical attestation, calibration completeness, ownership or custody; retaining ROBOT and FINBOT keeps delegated effect obligations live but establishes neither physical actuation nor financial authority, and the optional write is neither atomic, exclusive nor durability-guaranteed.",
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
        "TRANSACTION",
    ),
    _spec(
        "vstd-virtual-firmware-probe-harness",
        "HARNESS",
        ("src/verifier/runtime/hardware_probe_cli.py",),
        "Deterministic in-process virtual accelerator lifecycle, receipt publication and validation harness.",
        "The probe runs a fixed open-loop emulator lifecycle, records a firmware-counter AccountingQuantity, and emits a local receipt, requiring explicit sequencing, effect, measurement, protocol, policy and transaction boundaries without implying a feedback CONTROLLER.",
        "This is a test-only virtual probe, not commodity or physical attestation, confinement, a ROBOT path, FINBOT authority, durable history or complete mediation beyond the reference emulator interface.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "TRANSACTION",
    ),
    _spec(
        "vstd-hardware-receipt-assessor",
        "VERIFIER",
        ("src/verifier/runtime/hardware_receipt_cli.py",),
        "Stored hardware-receipt validation, conformance, continuity, fleet, evidence and claim assessment commands.",
        "Acquiring a selected receipt and applying finite validation policy produces bounded observations that must remain separate from original execution truth and physical replay.",
        "Assessment proves no distinct actor, external authority, physical-world completeness, asset custody, publication, release, sandboxing or real-money effect.",
        "MEASUREMENT",
        "POLICY",
    ),
)


# The added-kind route family is one retained-evidence VERIFIER. Its twelve
# review-kind specializations keep every checker, retained-record, worker, and
# consequence obligation visible; they do not promote the represented
# MARKET/ROBOT/FINBOT subjects or their external effects.
_ADDED_KIND_BEHAVIORAL_SPECS = (
    _spec(
        "vstd-added-kind-behavioral-verifier",
        "VERIFIER",
        (
            "src/verifier/domains/contracts/finbot_checks.py",
            "src/verifier/domains/contracts/market_checks.py",
            "src/verifier/domains/contracts/robot_checks.py",
            "src/verifier/runtime/added_kind_behavioral_routes.py",
        ),
        "Source-bound MARKET, ROBOT and FINBOT retained-evidence certificate construction, independent replay, and isolated local POLICY-observation worker actuation.",
        "These four sources share exact conditional route policy, strict retained-byte decoding, consequence-graph replay, finite limits and certificate nonpromotion. All twelve review-kind roles remain explicit on the same inspectable VERIFIER owner so no worker, retained-record, certificate-lifecycle, market, robot, financial, or other consequence obligation is silently discarded.",
        "Operates on caller-supplied retained bytes and local values and may launch one exact isolated local software worker. The specializations establish obligations only, not represented external subjects: actual agency, harness binding, participant access, venue, financial authority, exposure, real-world endpoints, physical reach, reconciliation, safety and effects remain unestablished. This checker submits no live order or settlement, actuates no hardware, reaches no physical endpoint, moves no money, and establishes no runtime correspondence or legal authority.",
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
)


# The ASSET Tier-0 mechanism is one pure in-memory VERIFIER, distinct from the
# ASSET-1.1/2.1/3.1 routes that token_asset_execution checks against retained TOKEN
# subjects.  Its POLICY role comes only from check_observations, which accepts or
# refuses caller-supplied observations against a fresh evaluation.  It is not an
# ASSET subject, spawns no worker and carries no route.
_ASSET_TIER0_SPECS = (
    _spec(
        "vstd-asset-tier0-execution-verifier",
        "VERIFIER",
        ("src/verifier/runtime/asset_execution.py",),
        "Pure in-memory ASSET Tier-0 declaration specimen with typed quantities, an authority-gated idempotent supply journal, custody and encumbrance records, and exact reconciliation diagnostics.",
        "Its finite field statuses, route-correspondence rule and observation-acceptance decision are source-specific checks over caller-supplied retained records; generic package ownership cannot state that catalog presence or in-model reproduction is not a route PASS.",
        "Operates only on its in-memory specimen and caller-supplied retained observations. It is not an ASSET subject or instance and is not the ASSET-1.1, ASSET-2.1 or ASSET-3.1 route owner; it issues or redeems no real instrument, moves no backing or custody, spawns no worker, and establishes no issuer authority, signature validity, real custody, holding completeness, redemption terms, supply conservation, backing, carried_by_route or route PASS.",
        "POLICY",
    ),
)


# The two in-memory POLICY and TRANSACTION mechanisms below were audited as standalone rows in
# ``package_semantic_ownership_current_untracked`` (roles and boundaries are carried over from
# that audit).  They are admitted here as exact path owners only, with no retained-root decision:
# each remaining kind question stays UNRESOLVED until a source-cited decision is reviewed.
_ENFORCEMENT_COORDINATOR_SPECS = (
    _spec(
        "vstd-policy-enforcement-engine",
        "POLICY",
        (
            "src/verifier/runtime/policy_enforcement_execution.py",
            "src/verifier/runtime/policy_enforcement_routes.py",
            "src/verifier/runtime/policy_enforcement_worker.py",
        ),
        "Source-bound in-memory POLICY enforcement engine, its route cases and the isolated worker oracle that judges the engine's observations.",
        "enforce() decides each request under verified authority, exceptions, revisions, decision evidence and consequence roles and appends one hash-chained receipt per call, so the admission decision is POLICY. The route module starts the isolated worker and exchanges a nonce with source pins, and the worker runs the cases and judges them against an independent oracle, so the parent and worker exchange is PROTOCOL.",
        "Decides caller-supplied requests in process and observes only calls made through enforce. It does not execute downstream effects, prove key custody or signer identity, establish publication or currentness of revisions, or establish the truth of the facts behind decision evidence. FINANCIAL and PHYSICAL roles are enforced as gates only, so no ACTUATOR, ROBOT or FINBOT role is accumulated. The worker is an isolated interpreter, not a filesystem, network or host sandbox, its fixture keys are not trust roots, and a route PASS is local field evidence, never route conformance.",
        "PROTOCOL",
    ),
    _spec(
        "vstd-transaction-execution-coordinator",
        "TRANSACTION",
        ("src/verifier/runtime/transaction_execution.py",),
        "Deterministic in-memory two-resource transaction coordinator with a hash-chained journal.",
        "Prepare, commit, abort, compensate and reconcile are state transitions over an append-only journal with retry and compensation rules, which is TRANSACTION. The closed phase and replay state machine is PROTOCOL, and the keyed authorization over canonical request bodies with precondition gating is POLICY.",
        "Mutates only in-memory LocalResource dictionaries. Precondition snapshot binding, keyed authorization, replay and bounded retry are established inside this model only. Durability, concurrent writers, external settlement, external atomicity, real authorizer identity and any finality beyond the local final record are NOT_ESTABLISHED, and the coordinator performs no external actuation.",
        "POLICY",
        "PROTOCOL",
    ),
)


def _extend_exact_owner_paths(
    specs: tuple[SemanticOwnershipSpec, ...],
    object_id: str,
    additions: tuple[str, ...],
) -> tuple[SemanticOwnershipSpec, ...]:
    """Add audited paths to exactly one existing owner or refuse import."""
    matches = [item for item in specs if item.object_id == object_id]
    if len(matches) != 1:
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_SELF_HOST_OWNER_INVALID")
    return tuple(
        replace(
            item,
            owned_paths=tuple(sorted(set(item.owned_paths) | set(additions))),
        )
        if item.object_id == object_id
        else item
        for item in specs
    )


_AGGREGATE_TEST_PATHS = (
    "tests/test_package_api_surface_admission.py",
    "tests/test_package_semantic_ownership_aggregate.py",
    "tests/test_package_semantic_ownership_current_untracked.py",
    "tests/test_package_semantic_ownership_domains_agency_collective.py",
    "tests/test_package_semantic_ownership_domains_context.py",
    "tests/test_package_semantic_ownership_domains_sim_model.py",
    "tests/test_package_semantic_ownership_domains_systems.py",
)
# The systems audit has an explicit row-level partition: four TRAIN rows remain
# blocked on sixteen typed operands; the other forty-three rows satisfy the
# installed layout.  No other standalone batch currently exposes a ready row
# partition, so none is silently cherry-picked from those batches.
_SYSTEMS_BLOCKED_IDS = frozenset(
    blocker.object_id for blocker in _domain_systems.INTEGRATION_BLOCKERS
)
_SYSTEMS_ACCEPTED_SPECS = tuple(
    spec
    for spec in _domain_systems.DOMAIN_SYSTEMS_OWNERSHIP_SPECS
    if spec.object_id not in _SYSTEMS_BLOCKED_IDS
)
_AGENCY_ACCEPTED_SPECS = (
    _agency_collective.SEMANTIC_OWNERSHIP_SPECS
    if _agency_collective.aggregation_ready()
    and not _agency_collective.unresolved_records()
    else ()
)

_CURRENT_UNKNOWN = tuple(
    record
    for spec in _current_untracked.CURRENT_UNTRACKED_OWNERSHIP_SPECS
    for record in _current_untracked.applicability_records(spec)
    if record.status == "UNKNOWN"
)

# Keep the original typed records, not lossy booleans.  Consumers can inspect
# the exact source-owned reason; absence from RootRoleDecision never becomes a
# DOES_NOT_APPLY decision during aggregation.
AGGREGATE_UNRESOLVED_SIDECARS: tuple[tuple[str, tuple[Any, ...]], ...] = (
    ("context", _domain_context.unknown_decisions()),
    ("agency_collective", _agency_collective.unresolved_records()),
    ("systems", _domain_systems.UNRESOLVED_RECORDS),
    ("current_untracked", _CURRENT_UNKNOWN),
)
AGGREGATE_BLOCKER_SIDECARS: tuple[tuple[str, tuple[Any, ...]], ...] = (
    ("context", _domain_context.aggregation_blockers()),
    ("agency_collective", _agency_collective.integration_blockers()),
    ("sim_model", _sim_model.INTEGRATION_BLOCKERS),
    ("systems", _domain_systems.INTEGRATION_BLOCKERS),
    ("current_untracked", _current_untracked.INTEGRATION_BLOCKERS),
)


def _batch_status(
    name: str,
    specs: Iterable[SemanticOwnershipSpec],
    accepted_ids: Iterable[str],
    reason: str,
) -> AggregateBatchStatus:
    candidates = tuple(sorted(item.object_id for item in specs))
    accepted = tuple(sorted(set(accepted_ids)))
    if not set(accepted) <= set(candidates):
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_BATCH_PARTITION_INVALID")
    blocked = tuple(sorted(set(candidates) - set(accepted)))
    state = "ACCEPTED" if not blocked else ("PARTIAL" if accepted else "BLOCKED")
    return AggregateBatchStatus(name, candidates, accepted, blocked, state, reason)


AGGREGATE_BATCH_STATUSES: tuple[AggregateBatchStatus, ...] = (
    _batch_status(
        "context",
        _domain_context.DOMAIN_CONTEXT_OWNERSHIP_SPECS,
        (),
        "Two source roles, the GRAPH layout, and the OWNER ASSET obligations remain explicitly unresolved.",
    ),
    _batch_status(
        "agency_collective",
        _agency_collective.SEMANTIC_OWNERSHIP_SPECS,
        (item.object_id for item in _AGENCY_ACCEPTED_SPECS),
        "All eleven typed slots bind exact retained registry objects, and every added-kind obligation is either source-established or conservatively retained by the sole reasons.vstd.",
    ),
    _batch_status(
        "sim_model",
        _sim_model.SIM_MODEL_OWNERSHIP_SPECS,
        (),
        "Every SIM or MODEL row has unbound typed operands; target IDs are never invented.",
    ),
    _batch_status(
        "systems",
        _domain_systems.DOMAIN_SYSTEMS_OWNERSHIP_SPECS,
        (item.object_id for item in _SYSTEMS_ACCEPTED_SPECS),
        "Forty-three rows satisfy the installed layout; four TRAIN rows retain sixteen typed blockers.",
    ),
    _batch_status(
        "current_untracked",
        _current_untracked.CURRENT_UNTRACKED_OWNERSHIP_SPECS,
        (),
        "This batch remains held for exact current-source pin review; its 338 UNKNOWN applicability records are preserved.",
    ),
)


# The inventory is intentionally explicit.  Globs would make ownership change
# when unrelated files appear and would make duplicate-path review ambiguous.
SEMANTIC_OWNERSHIP_SPECS = tuple(
    sorted(
        (
            *_RUNTIME_ADMISSION_SPECS,
            *_RUNTIME_COMMAND_SPECS,
            *_RUNTIME_POLISH_SPECS,
            *_RUNTIME_SELF_POLISH_SPECS,
            *_RUNTIME_HARDWARE_CLI_SPECS,
            *_ADDED_KIND_BEHAVIORAL_SPECS,
            *_ASSET_TIER0_SPECS,
            *_ENFORCEMENT_COORDINATOR_SPECS,
            *DOMAIN_OWNERSHIP_SPECS,
            *EXPERIMENT_OWNERSHIP_SPECS,
            *HARDWARE_INTEROP_OWNERSHIP_SPECS,
            *PYTHON_APPS_OWNERSHIP_SPECS,
            *PUBLIC_CLI_OWNERSHIP_SPECS,
            *REPOSITORY_ASSET_OWNERSHIP_SPECS,
            *SCRIPT_EXAMPLE_OWNERSHIP_SPECS,
            *TEST_FIXTURE_OWNERSHIP_SPECS,
            *NORMATIVE_ASSET_OWNERSHIP_SPECS,
            _spec(
                "vstd-amd-live-sensor",
                "SENSOR",
                ("src/verifier/hardware/adapters/amd.py",),
                "Live AMD SMI/ROCm host discovery and normalization of observed accelerator state.",
                "Live vendor acquisition has calibration, freshness and failure questions that generic package ownership cannot express.",
                "Reads live host state but commands no device; identity, calibration and physical completeness remain unestablished.",
                "MEASUREMENT",
            ),
            _spec(
                "vstd-anchor-history-ledger",
                "LEDGER",
                ("src/verifier/hardware/anchors.py",),
                "In-memory and append-only JSONL continuity-anchor history with duplicate and fork rejection.",
                "Anchor ordering, authority and recovery semantics are authoritative-history concerns rather than generic object structure. Creating an anchor mutates memory and may append a JSONL record, with a material memory-before-file partial-failure boundary and duplicate retry rules.",
                "Local HMAC and file history establish neither external anchoring authority nor physical or financial effects.",
                "TRANSACTION",
            ),
            _spec(
                "vstd-artifact-control-lifecycle",
                "TRANSACTION",
                (
                    "src/verifier/artifact_control/__init__.py",
                    "src/verifier/artifact_control/artifact-control-1.schema.json",
                    "src/verifier/schemas/artifact-control-1.schema.json",
                ),
                "Local artifact freeze, seal and thaw lifecycle plus its duplicated wire schema.",
                "Lifecycle state changes have precondition, authority, ordering, duplicate and partial-failure questions that generic artifact ownership would hide.",
                "The local lifecycle does not establish artifact correctness, source freshness, external authority, durable anchoring, crash durability, physical effect or financial effect.",
                "PROTOCOL",
            ),
            _spec(
                "vstd-artifact-network-history",
                "LEDGER",
                (
                    "examples/artifact-network/build_specimen.py",
                    "src/verifier/interoperability/network.py",
                    "src/verifier/runtime/network_cli.py",
                ),
                "Content-addressed silo, publisher-head, key-continuity and directory history with transfer protocols.",
                "Persistent signed heads and continuity records need explicit history and replay semantics across network exchange. The source implements explicit authority-model and silo-composition admission rules over allowable actions, local additions, and closure evidence.",
                "Artifact transfer and local materialization are external effects; retained bytes prove neither correctness nor execution permission.",
                "POLICY",
                "PROTOCOL",
                "TRANSACTION",
            ),
            _spec(
                "vstd-network-fixture-corpus",
                "LEDGER",
                (
                    "scripts/build_artifact_network_fixture.py",
                    "scripts/build_artifact_network_negative_corpus.py",
                    "scripts/build_formation_corpus.py",
                    "scripts/build_formation_receipt_corpus.py",
                    "scripts/build_proposition_transfer_fixture.py",
                    "scripts/build_silo_composition_fixture.py",
                ),
                "Canonical signed-head, silo-history, transfer, composition, formation, receipt and rejection fixture generation.",
                "The generated history and exchange corpus needs explicit ordering, duplicate, correction, replay and publication semantics instead of generic script ownership.",
                "These are synthetic reference fixtures with fixed keys; writes are not atomic or durable and outputs establish no identity, authority, deployment, asset backing, market operation or financial effect.",
                "PROTOCOL",
                "TRANSACTION",
            ),
            _spec(
                "vstd-assurance-event-ledger",
                "LEDGER",
                ("src/verifier/data/assurance.py",),
                "Append-only assurance events, conflicts, applicability decisions and challenge projections.",
                "Assurance conclusions depend on authoritative event ordering and retained conflicts that generic DATA ownership would conceal. Its record methods mutate the retained prefix, and grouped guilt recording explicitly stages related evidence to avoid partial ledger commit while detecting exporter-induced graph mutation before the group append.",
                "This records assurance state only; it is not an asset ledger and creates no monetary claim or backing.",
                "TRANSACTION",
            ),
            _spec(
                "vstd-challenge-record-ledger",
                "LEDGER",
                ("src/verifier/layer4/challenge.py",),
                "Append-only challenge, adjudication and claim-status record history.",
                "Final adjudication and retained challenges require explicit duplicate, correction and replay treatment. Admissibility, exact exclusions, terminal outcome interpretation, and most-degraded status projection are explicit local decision rules. Filing and final adjudication are validated local state mutations with duplicate, abort, commit, finality, and retry semantics.",
                "Challenge records establish no financial balance, asset custody or external enforcement by themselves.",
                "POLICY",
                "TRANSACTION",
            ),
            _spec(
                "vstd-claim-garden-lifecycle",
                "PROTOCOL",
                ("src/verifier/interoperability/claim_garden.py",),
                "Compound Claim Garden publisher registration, object upload, push finalization and claim-publication transport.",
                "Authenticated multi-step remote exchanges have ordering, retry, partial-failure and finality semantics absent from generic ownership.",
                "Path-level ownership cannot split the co-resident phases. Submission ends in bounded remote states and does not establish publication, moderation, real-money transfer or FINBOT responsibility.",
                "TRANSACTION",
            ),
            _spec(
                "vstd-consent-policy",
                "POLICY",
                ("src/verifier/consent/engine.py", "src/verifier/consent/public.py"),
                "Trusted-caller consent policy evaluation with separate shared-key and public-key authority variants.",
                "Consent scope, precedence, revocation and authority must remain distinct from a submitted artifact's own declarations.",
                "Cryptographic statements do not prove voluntary human consent, legal authority or enforcement outside the named evaluators.",
            ),
            _spec(
                "vstd-component-package-storage",
                "DATA",
                (
                    "src/verifier/interoperability/storage.py",
                    "src/verifier/schemas/verifier-component-package-1.schema.json",
                    "src/verifier/schemas/verifier-component-package-2.schema.json",
                ),
                "Exclusive-create local component-package persistence and the admitted package record schemas.",
                "Publishing selected package bytes changes local storage and therefore needs explicit authorization, duplicate, partial-write and retry treatment.",
                "Local persistence proves neither publisher or license authority nor package execution, crash durability, external witnessing, custody, physical effect or financial effect.",
                "TRANSACTION",
            ),
            _spec(
                "vstd-core-mechanism-executor",
                "VERIFIER",
                (
                    "src/verifier/core/certification_mechanisms.py",
                    "src/verifier/core/depth.py",
                    "src/verifier/core/evidence.py",
                    "src/verifier/core/grounded_certification.py",
                    "src/verifier/core/profile_obligations.py",
                    "src/verifier/core/translation.py",
                    "src/verifier/core/witness.py",
                ),
                "Core VERIFIER policy selection and execution of caller-registered in-process checking mechanisms.",
                "Admitted mechanism callbacks have authority, selection, limits and failure behavior that cannot remain implicit in generic VERIFIER ownership; callback replay does not itself establish an owned command-to-effect endpoint.",
                "Trusted in-process callback execution is not a sandbox. A returned result proves neither absence of side effects nor external correctness; physical or financial endpoints separately accumulate ROBOT or FINBOT and every other applicable role.",
                "POLICY",
                "TRANSACTION",
            ),
            _spec(
                "vstd-core-pure-verifier",
                "VERIFIER",
                (
                    "src/verifier/core/certificate.py",
                    "src/verifier/core/checker.py",
                    "src/verifier/core/contextual_namespace.py",
                    "src/verifier/core/geometry.py",
                    "src/verifier/core/geometry_io.py",
                    "src/verifier/core/grounding.py",
                    "src/verifier/core/kernel.py",
                    "src/verifier/core/namespace.py",
                    "src/verifier/core/platform_comparison.py",
                    "src/verifier/core/refutation.py",
                    "src/verifier/core/reproducibility.py",
                    "src/verifier/core/signature_keys.py",
                ),
                "Pure core VERIFIER records, canonicalization, geometry, comparison, grounding and refutation helpers.",
                "These exact modules must be separated from core process launch, callback execution, provenance acquisition and receipt publication before the added consequence roles can be honestly refuted.",
                "The sources construct and check supplied local values only. They acquire no phenomenon, invoke no caller mechanism, publish no files, implement no participant exchange, and expose no physical or real-money endpoint.",
            ),
            _spec(
                "vstd-core-provenance-sensor",
                "SENSOR",
                ("src/verifier/core/provenance.py",),
                "Host, repository and selected-file provenance acquisition with a bounded Git request/response boundary.",
                "Direct environment and Git acquisition has source, units, timing, missingness, drift, protocol and fault questions that static provenance declarations cannot answer.",
                "Observes host- and repository-visible software state only. Fixed read-only Git queries and the returned in-memory record create no coordinated durable effect or replay unit, so TRANSACTION does not apply. Git output and local clocks are trusted inputs, not hostile-host attestation, physical calibration, confinement or historical execution proof.",
                "MEASUREMENT",
                "PROTOCOL",
            ),
            _spec(
                "vstd-core-receipt-transaction",
                "TRANSACTION",
                ("src/verifier/core/receipt.py",),
                "Local multi-file receipt and payload publication to a caller-selected directory.",
                "Directory creation and sequential exclusive writes have authorization, commit, partial-failure, duplicate and recovery semantics that generic VERIFIER ownership would hide.",
                "The publication is not atomic across files, crash-durable, externally witnessed or proof that the represented verification occurred; it has no physical or real-money endpoint.",
            ),
            _spec(
                "vstd-core-self-polish-assessor",
                "VERIFIER",
                ("src/verifier/runtime/polish_requirements.py",),
                "Source-bound core self-polish assessment that prepares compiler and native-replay inputs and issues one bounded gate result.",
                "Acquisition, selected checker execution, retained observations and gate policy are consequential mechanisms that cannot remain hidden in a broad VERIFIER catch-all.",
                "The assessment is not a sandbox, external witness, whole-package polish result, publication authorization, physical endpoint or real-money decision.",
                "ACTUATOR",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-controlled-emission-controller",
                "CONTROLLER",
                ("src/verifier/corrigibility/controlled_operation.py",),
                "Cooperative stop-latched admission controller around consequential local callbacks.",
                "Callback admission, concurrent stop, duplicate invocation and completion states require explicit control and transaction boundaries.",
                "Callback submission is not proof of downstream effect. Only cooperating in-process calls are controlled; actual physical or financial endpoints accumulate ROBOT or FINBOT and their other applicable roles.",
                "POLICY",
                "TRANSACTION",
            ),
            _spec(
                "vstd-dataset-provenance-policy",
                "POLICY",
                (
                    "src/verifier/data/policy.py",
                    "src/verifier/runtime/provenance_policy_execution.py",
                    "src/verifier/runtime/provenance_policy_worker.py",
                ),
                "Formal SAT-backed policy decisions over dataset and computational provenance graphs.",
                "Provenance acceptance needs explicit rule grounding and decision correspondence rather than an undifferentiated DATA label.",
                "A checked decision is not proof that every producer or consumer enforced the selected policy.",
            ),
            _spec(
                "vstd-deriver-process-exchange",
                "PROTOCOL",
                ("src/verifier/interoperability/deriver_self_status.py",),
                "Bounded DERIVER child-process request, timeout, termination, output capture and deterministic response replay.",
                "A process exchange has participant, envelope, observation, deadline, failure and replay semantics that generic interoperability ownership would conceal.",
                "Process control and captured output do not establish sandboxing, child purity, descendant confinement, semantic correctness, physical effect or financial effect.",
                "ACTUATOR",
                "CONTROLLER",
                "MEASUREMENT",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-digest-validation-policy",
                "POLICY",
                (
                    "examples/selected_validation/demo.py",
                    "src/verifier/interoperability/validation_loop.py",
                ),
                "Host-selected bounded validation-loop targets, authorization and ordered execution control.",
                "A loop's target set, bounds and allowed execution mechanism are policy choices with control and message-order consequences.",
                "Digest equality and exhausted declared targets do not establish semantic correctness, geometry closure or sandboxing.",
                "CONTROLLER",
                "PROTOCOL",
            ),
            _spec(
                "vstd-firmware-emulator-accounting",
                "LEDGER",
                ("src/verifier/hardware/emulator.py",),
                "Virtual accelerator command, simulated effect and append-only firmware-accounting state machine.",
                "The emulator combines authoritative accounting with command-to-effect control, so generic HARDWARE ownership loses necessary ledger and actuation questions. Caller, emulator, anchor provider, and verifier participate in an ordered boot/challenge/attestation/execution/accounting state machine. Its commands mutate multi-part in-memory state and sometimes an anchor provider, requiring explicit precondition, commit, partial-failure, retry, and replay boundaries.",
                "Software simulation only: no physical actuator, live sensor, tamper-resistance, ROBOT, confinement or real-money claim is made.",
                "ACTUATOR",
                "CONTROLLER",
                "PROTOCOL",
                "TRANSACTION",
            ),
            _spec(
                "vstd-finite-record-issuance",
                "TRANSACTION",
                ("src/verifier/runtime/finite_record_issuance.py",),
                "Exact finite OBJECT record precommit, one local atomic issuance commit, signed postcommit finalization and independent replay.",
                "Issuance changes the selected invocation ledger and crosses staged request, assessment, commit, signed-status and replay states whose authority, ordering, partial failure and recovery cannot remain generic VERIFIER behavior.",
                "The route issues only the named finite OBJECT record and keeps full-application polish UNKNOWN. It performs no transport, publication, human acceptance, physical actuation or real-money decision.",
                "LEDGER",
                "POLICY",
                "PROTOCOL",
            ),
            _spec(
                "vstd-gate-pipeline-controller",
                "CONTROLLER",
                (
                    "src/verifier/runtime/gate_pipeline.py",
                    "src/verifier/runtime/prdel_evidence.py",
                    "src/verifier/runtime/quality_checks.py",
                    "src/verifier/runtime/secret_gate.py",
                    "src/verifier/runtime/self_polish_evidence.py",
                ),
                "Manifest-directed dependency pipeline that launches bounded commands and retains an aggregate receipt.",
                "Command ordering, deadlines, abort behavior and receipt finality are control and transaction concerns, not generic functions.",
                "Process-command submission is not proof of downstream effect or a sandbox; actual physical or financial endpoints accumulate ROBOT or FINBOT and their other applicable roles.",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-gated-publication",
                "PROTOCOL",
                ("src/verifier/interoperability/gated_publish.py",),
                "Gate-bound preparation, account preflight and one-shot remote submission for private human review.",
                "Credentialed submission, quota accounting, deduplication and remote final states require explicit protocol and transaction treatment.",
                "Preparation sends nothing; submission retains remote state but does not establish public release, review outcome, payment, or financial authority.",
                "TRANSACTION",
            ),
            _spec(
                "vstd-governance-policy",
                "POLICY",
                ("src/verifier/governance/__init__.py",),
                "Governance rule, principal, signature and status-root evaluation under trusted caller selection.",
                "Rule precedence, authority roles, effective intervals and enforcement decisions must be reviewable as a policy mechanism.",
                "Configured signatures establish bounded statements, not personhood, legal authority or enforcement outside the evaluator.",
            ),
            _spec(
                "vstd-hardware-receipt-publication",
                "RECEIPT",
                ("src/verifier/hardware/receipt.py",),
                "Local hardware-receipt serialization and caller-selected file publication.",
                "A receipt write has authority, target, replacement, partial-failure and replay questions distinct from the receipt's represented hardware claim.",
                "The truncating local write is not atomic, exclusive, fsync-durable, externally witnessed, retained history, physical observation, custody proof or financial finality.",
                "TRANSACTION",
                operands=(
                    ("hardware", ("vstd-hardware",)),
                    ("subject", ("vstd-hardware",)),
                ),
            ),
            _spec(
                "vstd-hardware-resource-accounting",
                "MEASUREMENT",
                ("src/verifier/hardware/fleet.py",),
                "Pure aggregation of caller-supplied hardware-resource records into fleet capacity and policy checks.",
                "Quantities, units, asset identity and admission rules must be explicit even when computation is performed only over supplied records.",
                "This module acquires no live phenomenon and establishes no calibration, freshness, ledger history, issuance, custody, encumbrance, physical actuation or actual asset backing.",
                "ASSET",
                "POLICY",
            ),
            _spec(
                "vstd-javascript-parser-protocol",
                "PROTOCOL",
                (
                    "src/verifier/runtime/namespace_javascript.py",
                    "src/verifier/runtime/namespace_javascript_worker.py",
                ),
                "Parent-launched isolated-worker JavaScript syntax-census request and response protocol.",
                "The parent submits a fixed child-process command, while parser byte pins, source identity and response ordering must agree across that process boundary.",
                "The fixed parser-child launch is not an owned command-to-effect endpoint. Static parsing never imports or executes subject code and does not prove subject reachability or downstream effects.",
            ),
            _spec(
                "vstd-invocation-ledger",
                "LEDGER",
                (
                    "src/verifier/runtime/local_ledger_control_checks.py",
                    "src/verifier/runtime/local_ledger_controls.py",
                    "src/verifier/runtime/local_ledger_execution.py",
                    "src/verifier/runtime/local_ledger_worker.py",
                    "src/verifier/runtime/polish_invocation_ledger.py",
                ),
                "Host-selected local invocation-consumption ledger, bounded SQLite control experiments and fixed parent/worker execution adapter.",
                "The same source owns authoritative local consumption history, transaction guards, admission policy and a versioned parent/worker JSON exchange, so those consequential roles must accumulate on one exact owner.",
                "One host-provisioned nonmonetary local SQLite ledger and fresh temporary worker experiments only; no actor authentication, external authority, delivery proof, automatic retry, liveness guarantee, distributed or financial accounting, public history, or global finality.",
                "POLICY",
                "PROTOCOL",
                "TRANSACTION",
            ),
            _spec(
                "vstd-logit-constraint-controller",
                "CONTROLLER",
                (
                    "src/verifier/constraints/__init__.py",
                    "src/verifier/constraints/kernel.py",
                    "src/verifier/constraints/llguidance_backend.py",
                    "src/verifier/constraints/postvalidate.py",
                    "src/verifier/constraints/torch_mask.py",
                ),
                "In-process logit-mask constraint loop with backend exchange, selected policy, observations and postvalidation.",
                "Constraint application changes admitted token choices and uses feedback across a backend boundary, so control, observation, actuation and protocol roles must remain visible.",
                "The loop does not prove model truth, safety, sandboxing, complete policy enforcement, physical actuation, ROBOT status or real-money authority.",
                "ACTUATOR",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-native-gate-suite",
                "VERIFIER",
                (
                    "src/verifier/runtime/gate.py",
                    "src/verifier/runtime/gates.py",
                    "src/verifier/runtime/manifest_gate.py",
                ),
                "Native source, boundary, receipt and manifest-gate assessment and dispatch suite.",
                "Gate dispatch invokes selected checks, acquires current source and process results, and applies admission policy; those observation and decision roles cannot remain implicit in generic VERIFIER ownership. Dispatch does not transfer a downstream worker's ACTUATOR role.",
                "A bounded gate result is not sandboxing, external attestation, whole-package conformance, publication authorization, physical control or financial authority.",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-nvidia-live-sensor",
                "SENSOR",
                ("src/verifier/hardware/adapters/nvidia.py",),
                "Live NVML/nvidia-smi host discovery and normalization of observed accelerator state.",
                "Live vendor acquisition has calibration, freshness and failure questions that generic package ownership cannot express.",
                "Reads live host state but commands no device; identity, calibration and physical completeness remain unestablished.",
                "MEASUREMENT",
            ),
            _spec(
                "vstd-openshell-environment",
                "ENV",
                (
                    "extensions/openshell/pyproject.toml",
                    "extensions/openshell/src/vstd_openshell/__init__.py",
                    "extensions/openshell/src/vstd_openshell/environment.py",
                    "extensions/openshell/src/vstd_openshell/live.py",
                ),
                "Optional OpenShell execution environment, gateway lifecycle, policy probes, exact-byte staging and ENV projection.",
                "An explicitly selected sandbox backend is an ENV whose remote command, observation, policy and cleanup boundaries must not remain hidden inside generic package ownership.",
                "Optional path only: the basic runner does not require OpenShell. Named probes and a successful subject process do not establish complete containment, corrigibility, availability, physical effects, financial effects or whole-object conformance.",
                "ACTUATOR",
                "CONTROLLER",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-package-worker-exchange",
                "PROTOCOL",
                (
                    "src/verifier/runtime/package_execution.py",
                    "src/verifier/runtime/package_checker_worker.py",
                    "src/verifier/runtime/package_execution_observation.py",
                    "src/verifier/runtime/worker_protocol_execution.py",
                    "src/verifier/runtime/worker_protocol_worker.py",
                    "src/verifier/runtime/token_asset_execution.py",
                    "src/verifier/runtime/token_asset_worker.py",
                    "src/verifier/runtime/emulator_control_execution.py",
                    "src/verifier/runtime/emulator_control_worker.py",
                ),
                "Fixed parent/child package-mechanism selection, request, response and retained boundary observation.",
                "A subprocess exchange needs participant, envelope, source-pin, failure and replay semantics independent of the selected checker.",
                "Parent-interface acquisition observes return code and bounded stream bytes, counts, digests and completeness; it does not observe child internals, descendants, external effects or confinement.",
                "ACTUATOR",
                "MEASUREMENT",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-sim-resource-measurement",
                "MEASUREMENT",
                (
                    "src/verifier/runtime/resource_measurement_execution.py",
                    "src/verifier/runtime/resource_measurement_worker.py",
                ),
                "Source-bound fresh acquisition and independent checks for selected SIM transition CPU-time and traced-allocation observations.",
                "The shipped route directly acquires bounded software resource observations and exercises missingness and instrument-fault behavior, which generic VERIFIER ownership cannot express.",
                "Observations are CPython thread CPU nanoseconds and tracemalloc peak bytes for fixed selected SIM transitions only; no physical calibration, device accounting, whole-SIM fidelity, actuation, availability or confinement claim is made.",
                "SENSOR",
            ),
            _spec(
                "vstd-self-polish-case-materializer",
                "TRANSACTION",
                (
                    "scripts/build_self_polish_native_cases.py",
                    "scripts/build_self_polish_sim_case_patch.py",
                    "scripts/render_self_polish_native_case_module.py",
                ),
                "Trusted maintainer import, digest/capacity policy check and generated native-case module publication.",
                "Dynamically invoking the selected builder and writing generated Python changes local state and therefore needs explicit authority, effect, policy and failure treatment.",
                "This route is not a sandbox; target writes are direct and non-atomic with no exclusive lock, durability, rollback, installation, semantic-correctness or tier-PASS guarantee.",
                "ACTUATOR",
                "POLICY",
            ),
            _spec(
                "vstd-self-polish-full-candidate-capture",
                "CONTROLLER",
                ("scripts/build_self_polish_native_full_candidate.py",),
                "Current Git/source capture and orchestration of installed and prepared native replays into one 408-route candidate artifact.",
                "The script selects, launches, observes and aggregates multiple verification routes, requiring explicit controller, effect, observation, protocol, policy and transaction boundaries.",
                "This is local source/process observation and trusted replay, not a sandbox, containment proof, installed Tier 3-9 status, whole-tier or package conformance, release authority, physical effect or financial effect.",
                "ACTUATOR",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-self-polish-native-case-corpus",
                "POLICY",
                (
                    "scripts/build_self_polish_native_tier3_cases.py",
                    "scripts/build_self_polish_native_tier4_cases.py",
                    "scripts/build_self_polish_native_tier5_cases.py",
                    "scripts/build_self_polish_native_tier6_cases.py",
                    "scripts/build_self_polish_native_tier7_cases.py",
                    "scripts/build_self_polish_native_tier8_cases.py",
                    "scripts/build_self_polish_native_tier9_cases.py",
                    "scripts/fixtures/self_polish_native_tier4_seed.json",
                ),
                "Route-bound request, policy, evidence and negative/unknown specimen generation for self-polish Tiers 3 through 9.",
                "The corpus fixes admission policy, while the Tier-3 builder also acquires the current Python-reported machine identity for MODEL-3.2 and therefore has bounded observation responsibilities.",
                "These are synthetic specimens plus one uncalibrated machine string, not hardware attestation, physical telemetry, execution provenance, whole-tier conformance, installation or release evidence.",
                "MEASUREMENT",
                "SENSOR",
            ),
            _spec(
                "vstd-software-diode-effect",
                "ACTUATOR",
                ("src/verifier/hardware/diode_emulator.py",),
                "Software BytesIO one-way transmission rehearsal with counters and sink observations.",
                "The emulated transmission changes a software sink and reports observed transfer state across a participant boundary, requiring explicit effect and observation semantics.",
                "This is not a physical diode, hardware isolation, hostile-process confinement, ROBOT endpoint, durable record or real-money transfer.",
                "MEASUREMENT",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-permission-slot-controller",
                "CONTROLLER",
                ("src/verifier/runtime/permission_slot.py",),
                "Revocable permission lifecycle and bounded append-only event trace admitting one registered invocation and one separately admitted successor.",
                "Grant verification, registration, cancellation, drain and callback-entry races require one explicit control lifecycle and authoritative local event sequence.",
                "Callback admission and submission are not proof of downstream effect. The trace is local in-memory history with an optional exact external anchor, not effect replay, durable global history or financial accounting; actual physical or financial endpoints accumulate ROBOT or FINBOT and their other applicable roles.",
                "LEDGER",
                "POLICY",
                "PROTOCOL",
                "TRANSACTION",
            ),
            _spec(
                "vstd-polish-workflow-transaction",
                "TRANSACTION",
                (
                    "src/verifier/runtime/polish_prepare.py",
                    "src/verifier/runtime/polish_workflow.py",
                    "src/verifier/runtime/polish_workflow_cli.py",
                    "src/verifier/runtime/polish_workflow_replay.py",
                ),
                "Policy-selected multi-stage preparation, hash-chained append-only local journal, retained recovery and compare-before-apply workflow.",
                "Multi-file apply, abort and recovery behavior plus its authoritative local chronology cannot be represented honestly as a generic package helper.",
                "The unwitnessed local journal is not external authoritative execution or financial accounting. The workflow is preparation-only, is not atomic across files, and establishes no polish tier, publication or exclusive filesystem ownership.",
                "CONTROLLER",
                "LEDGER",
                "POLICY",
                "PROTOCOL",
            ),
            _spec(
                "vstd-privacy-emission-policy",
                "POLICY",
                (
                    "src/verifier/controlled_emission.py",
                    "src/verifier/privacy/__init__.py",
                    "src/verifier/privacy/adapters.py",
                    "src/verifier/privacy/composition.py",
                    "src/verifier/privacy/current_certificate_emission.py",
                    "src/verifier/privacy/engine.py",
                    "src/verifier/privacy/independence.py",
                    "src/verifier/privacy/models.py",
                ),
                "Controlled privacy-emission policy and in-memory differential-privacy budget accounting.",
                "Emission rules and mutable privacy-budget consumption require explicit precedence, authorization, accounting, duplicate and correction semantics.",
                "The accounting is in-memory, non-durable and non-concurrent; these paths execute no caller callback or external transmission and prove no downstream recipient behavior.",
                "LEDGER",
                "TRANSACTION",
            ),
            _spec(
                "vstd-repository-admission-reconciler",
                "VERIFIER",
                (
                    "src/verifier/runtime/namespace_admission.py",
                    "src/verifier/runtime/namespace_reconcile.mjs",
                    "src/verifier/runtime/package_admission.py",
                    "src/verifier/runtime/tier_zero_reconcile.mjs",
                ),
                "Cross-language repository-admission template, source census, manifest reconciliation and Tier-0 package assessment.",
                "Admission launches the selected reconciler, observes current source and applies fail-closed namespace policy, so its process, observation and decision boundaries must be explicit. Fixed process launch is not an owned command-to-effect endpoint.",
                "Repository admission establishes only the bounded selected manifest and source coordinate; it is not later-tier conformance, sandboxing, release, publication, physical control or financial authority.",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-precommitment-ledger",
                "LEDGER",
                ("src/verifier/layer4/precommit.py",),
                "Append-only precommitment selections, degrees of freedom and violation audit history.",
                "A declared evaluation envelope needs authoritative ordering and retained deviations to prevent post-result rewriting. Recording an envelope is a fork-checked local map assignment with exact duplicate idempotency, fork abort, local finality, and a separate-anchor boundary.",
                "Precommitment history is not an asset, market or real-money ledger.",
                "TRANSACTION",
            ),
            _spec(
                "vstd-retention-policy",
                "POLICY",
                ("src/verifier/layer4/availability.py",),
                "Artifact retrieval and retention-policy rules used to derive bounded availability states.",
                "A content address alone cannot establish retrievability; retention duration, locator and portability rules need explicit policy ownership. The source evaluates exact supplied retrieval bytes, content identity, locator, observation coordinates, missingness, and derived availability levels; it does not acquire them.",
                "A declared retention promise is not current availability or durable third-party custody without observation.",
                "MEASUREMENT",
            ),
            _spec(
                "vstd-scitt-evidence-protocol",
                "PROTOCOL",
                (
                    "src/verifier/interoperability/scitt/__init__.py",
                    "src/verifier/interoperability/scitt/adapter.py",
                    "src/verifier/interoperability/scitt/derived_subjects.py",
                    "src/verifier/interoperability/scitt/evidence_profiles.py",
                ),
                "Deterministic SCITT evidence-profile, derived-subject and adapter mapping over supplied records.",
                "Participant record shape and profile selection are protocol and policy questions even when no transport is performed.",
                "These paths perform no signing, transport, registration, ledger append, live acquisition, transaction commit, physical effect or financial effect.",
                "POLICY",
            ),
            _spec(
                "vstd-selected-source-admission",
                "POLICY",
                (
                    "scripts/admitted_root_binding.py",
                    "scripts/exact_materialized_member.py",
                    "scripts/exact_source_scope.py",
                    "scripts/windows_anchored_member.py",
                ),
                "Externally authorized source-member admission, anchored acquisition, cancellation and single-use commit tools.",
                "Selected source admission observes exact identity and bytes, applies caller-provided policy and commits one bounded handle, so control, observation, protocol and transaction roles are necessary.",
                "Admission covers only the supplied manifest, handle and selected members; it does not establish repository completeness, authorship, semantic correctness, release admissibility, durable replay, sandboxing, physical effect or financial effect.",
                "CONTROLLER",
                "MEASUREMENT",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-sim-artifact-publication",
                "PROTOCOL",
                ("src/verifier/interoperability/artifact_publish.py",),
                "Exact-byte SIM artifact upload and stored-response verification against Claim Garden.",
                "A SIM upload crosses a remote boundary with authentication, retry and finality questions distinct from simulation validity.",
                "Remote storage does not establish scientific validity, public release, physical effects, payment or publication authority.",
                "TRANSACTION",
            ),
            _spec(
                "vstd-systems-parser-protocol",
                "PROTOCOL",
                (
                    "src/verifier/runtime/namespace_rust_expansions.py",
                    "src/verifier/runtime/namespace_systems.py",
                    "src/verifier/runtime/namespace_systems_worker.py",
                ),
                "Parent-launched isolated-worker Rust and Bash syntax-census request and response protocol.",
                "The parent submits a fixed child-process command, while grammar byte pins, language selection, source identity and response ordering must agree across that process boundary.",
                "The fixed parser-child launch is not an owned command-to-effect endpoint. Static parsing expands no macros, sources no shell and proves neither subject reachability nor downstream effects.",
            ),
            _spec(
                "vstd-train-control-session",
                "CONTROLLER",
                ("src/verifier/corrigibility/train_control.py",),
                "Authenticated TRAIN action mediation, stop policy and bounded session event control.",
                "Training changes require explicit authority, timing, replay and intervention behavior rather than generic TRAIN ownership. Its lock-protected hash-linked EVENT chain is the locally authoritative bounded history used for capacity, admission and denial replay, so the LEDGER role remains explicit even though the history is not durable.",
                "Action or callback submission is not proof of downstream effect. The local EVENT ledger has no restart durability or reconciliation path and can omit an outcome when plan context cannot be resolved. Trusted-host mediation is not a sandbox; actual physical or financial endpoints accumulate ROBOT or FINBOT and their other applicable roles.",
                "LEDGER",
                "POLICY",
                "TRANSACTION",
            ),
            _spec(
                "vstd-tier1-evidence-ledger",
                "LEDGER",
                ("scripts/build_self_polish_tier1_ledger.py",),
                "Authoritative candidate mapping, bounded Git and pytest observations, replay-receipt consumption and Tier-1 ledger artifact generation.",
                "Candidate history, selected checker execution, observations and aggregation policy require explicit ledger, control, effect, protocol and transaction semantics.",
                "This local candidate subledger hard-codes the legacy 26-kind and 45-membership denominator; it establishes neither current 38-kind completeness, whole-tier closure, release readiness, sandboxing, physical effect nor financial authority.",
                "ACTUATOR",
                "CONTROLLER",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-source-provenance-observer",
                "SENSOR",
                (
                    "src/verifier/runtime/explanation_projection.py",
                    "src/verifier/runtime/prdel.py",
                    "src/verifier/runtime/self_polish_estate.py",
                ),
                "Read-only Git and source-state acquisition with bounded derived explanation, PRDEL and estate projections.",
                "Direct current-source acquisition and Git request/response have identity, timing, missingness, protocol and failure questions absent from static metadata.",
                "The observer stages derived bytes, and does not write subject source, establish hostile-host attestation, execute a checker, publish externally, control a physical endpoint or make a real-money decision. Only the mutable worktree-state capture in self_polish_estate.py runs Git with repository-configured fsmonitor disabled; the read-only object-database helpers in explanation_projection.py and prdel.py assert neither index refresh nor fsmonitor behavior.",
                "MEASUREMENT",
                "PROTOCOL",
                "TRANSACTION",
            ),
            _spec(
                "vstd-verifier-native-execution-controller",
                "VERIFIER",
                ("src/verifier/domains/verifier_execution.py",),
                "Bounded native child-process launch, Windows Job control, resource observation and limit evaluation.",
                "Launching and terminating a process from observed resource feedback is an effectful verification controller, not a passive VERIFIER declaration.",
                "The fixed parent-child exchange and host counters are not a sandbox, hostile-host attestation, semantic correctness proof, physical controller, ROBOT endpoint or financial authority.",
                "ACTUATOR",
                "CONTROLLER",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-verifier-run-constraint-controller",
                "VERIFIER",
                ("src/verifier/domains/contracts/verifier_run_constraints.py",),
                "In-process traced-replay execution, observation and resource-allowance termination for selected VERIFIER constraints.",
                "Invoking native replay callbacks and stopping on selected trace allowances creates control, observation and policy responsibilities beyond static constraint data. Replay does not transfer a downstream worker's ACTUATOR role.",
                "The trusted in-process call has no participant or process protocol boundary and is not a sandbox, physical controller, ROBOT endpoint or real-money decision.",
                "CONTROLLER",
                "MEASUREMENT",
                "POLICY",
                "SENSOR",
                "TRANSACTION",
            ),
            _spec(
                "vstd-workflow-parser-protocol",
                "PROTOCOL",
                (
                    "src/verifier/runtime/namespace_workflow_worker.py",
                    "src/verifier/runtime/namespace_workflows.py",
                ),
                "Parent-launched isolated-worker YAML workflow census, reference resolution and command declaration protocol.",
                "The parent submits a fixed child-process command, while parser byte pins, selected references, duplicate-key handling and response binding cross that process boundary.",
                "The fixed parser-child launch is not an owned command-to-effect endpoint. Discovery parses declarations only; it downloads no action and executes no workflow command.",
            ),
        ),
        key=lambda item: item.object_id,
    )
)


# ``SEMANTIC_OWNERSHIP_SPECS`` remains the exact normative partition catalog:
# ``package_semantic_review_partitions`` proves that its independently owned
# partitions form precisely that denominator.  Aggregate-only self-hosting
# paths and ready standalone rows are admitted into this explicit view instead
# of silently changing that independently checked contract.  Blocked rows never
# enter either view.
_AGGREGATE_SELF_HOSTED_SPECS = _extend_exact_owner_paths(
    SEMANTIC_OWNERSHIP_SPECS,
    "vstd-test-namespace-admission-regressions",
    _AGGREGATE_TEST_PATHS,
)
AGGREGATED_SEMANTIC_OWNERSHIP_SPECS = tuple(
    sorted(
        (*_AGGREGATE_SELF_HOSTED_SPECS, *_AGENCY_ACCEPTED_SPECS, *_SYSTEMS_ACCEPTED_SPECS),
        key=lambda item: item.object_id,
    )
)


# This mirrors the installed typed-composition contract.  It is deliberately
# central here because source-ownership aggregation must resolve exact target
# IDs and kinds, while ``validate_object_layout`` only checks slot shape.
_AGGREGATE_OPERAND_KINDS: dict[str, dict[str, tuple[str, ...]]] = {
    "ACTOR": {"representation": ("HUMAN", "AGENT", "BOT"), "root_human": ("HUMAN",)},
    "COLLECTIVE": {"roles": ("ROLE",)},
    "IDENTITY": {"actor": ("ACTOR",), "role": ("ROLE",)},
    "OWNER": {"actor": ("ACTOR",), "object": ("OBJECT",)},
    "RECEIPT": {"subject": ("OBJECT",), "hardware": ("HARDWARE",)},
    "EVENT": {"time": ("TIME",), "space": ("SPACE",), "meaning": ("OBJECT",)},
    "BENCH": {"verifier": ("VERIFIER",), "data": ("DATA",)},
    "TRAIN": {"data": ("DATA",), "events": ("EVENT",), "bench": ("BENCH",), "arch": ("ARCH",)},
    "MODEL": {
        "train": ("TRAIN",),
        "data": ("DATA",),
        "events": ("EVENT",),
        "bench": ("BENCH",),
        "arch": ("ARCH",),
        "env": ("ENV",),
        "hardware": ("HARDWARE",),
    },
    "AGENT": {"model": ("MODEL",), "harness": ("HARNESS",), "env": ("ENV",)},
    "SIM": {"data": ("DATA",), "verifier": ("VERIFIER",), "objects": ("OBJECT",), "env": ("ENV",)},
    "BOT": {"agent": ("AGENT",), "sim": ("SIM",), "env": ("ENV",)},
    "GRAPH": {"members": ("OBJECT",)},
}
_INVENTED_TARGET_TOKENS = ("unresolved", "placeholder", "invented")


def _aggregate_cycle_members(graph: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    state: dict[str, int] = {}
    stack: list[str] = []
    members: set[str] = set()

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for target in graph.get(node, ()):
            if target not in graph:
                continue
            if state.get(target, 0) == 0:
                visit(target)
            elif state.get(target) == 1:
                members.update(stack[stack.index(target):])
        stack.pop()
        state[node] = 2

    for node in sorted(graph):
        if state.get(node, 0) == 0:
            visit(node)
    return tuple(sorted(members))


def aggregate_operand_findings(
    specs: Iterable[SemanticOwnershipSpec] = AGGREGATED_SEMANTIC_OWNERSHIP_SPECS,
) -> tuple[AggregateFinding, ...]:
    """Resolve aggregate operand IDs, kinds and cycles without inventing facts.

    Missing required operands are typed UNKNOWN blockers.  They are never
    converted into applicability refutations or DOES_NOT_APPLY decisions.
    Targets resolve through either an audited semantic owner row or the exact
    installed graph declaration that compiles to ``objects.vstd``.  ``OBJECT``
    in an allowed-kind position means any exact known graph object, not a
    generic OBJECT fallback row.
    """
    selected = tuple(specs)
    findings: list[AggregateFinding] = []
    owners: dict[str, list[SemanticOwnershipSpec]] = {}
    for item in selected:
        owners.setdefault(item.object_id, []).append(item)
    for object_id, rows in sorted(owners.items()):
        if len(rows) > 1:
            findings.append(AggregateFinding(
                "OPERAND_TARGET_OWNER_DUPLICATED",
                object_id,
                "An exact operand target ID resolves to more than one audited owner row.",
                target_id=object_id,
            ))
    by_id = {object_id: rows[0] for object_id, rows in owners.items()}

    for item in selected:
        role_rows: dict[str, list[tuple[str, ...]]] = {}
        for role, targets in item.operands:
            role_rows.setdefault(role, []).append(targets)
        for role, rows in sorted(role_rows.items()):
            if len(rows) > 1:
                findings.append(AggregateFinding(
                    "OPERAND_ROLE_DUPLICATED",
                    item.object_id,
                    "An operand role occurs more than once; the required relation is ambiguous.",
                    operand_role=role,
                ))

        layout = _AGGREGATE_OPERAND_KINDS.get(item.primary_kind, {})
        if item.primary_kind == "HYPER":
            if not role_rows:
                findings.append(AggregateFinding(
                    "OPERAND_UNBOUND",
                    item.object_id,
                    "No exact relation is bound; applicability remains UNKNOWN, never DOES_NOT_APPLY.",
                ))
        else:
            for role in sorted(set(role_rows) - set(layout)):
                findings.append(AggregateFinding(
                    "OPERAND_ROLE_UNKNOWN",
                    item.object_id,
                    "The operand role is absent from the installed typed-composition contract.",
                    operand_role=role,
                ))
            for role, required in sorted(layout.items()):
                rows = role_rows.get(role, [])
                targets = rows[0] if len(rows) == 1 else ()
                if not targets:
                    findings.append(AggregateFinding(
                        "OPERAND_UNBOUND",
                        item.object_id,
                        "No exact source-audited target is bound; applicability remains UNKNOWN, never DOES_NOT_APPLY.",
                        operand_role=role,
                        required_kinds=required,
                    ))

        for role, rows in sorted(role_rows.items()):
            required = layout.get(role, ())
            for targets in rows:
                if len(targets) != len(set(targets)):
                    findings.append(AggregateFinding(
                        "OPERAND_TARGET_DUPLICATED",
                        item.object_id,
                        "One operand role repeats a target ID; multiplicity cannot be inferred from duplication.",
                        operand_role=role,
                    ))
                for target_id in targets:
                    if any(token in target_id.lower() for token in _INVENTED_TARGET_TOKENS):
                        findings.append(AggregateFinding(
                            "OPERAND_TARGET_INVENTED",
                            item.object_id,
                            "A placeholder-shaped identifier is not an audited graph object.",
                            operand_role=role,
                            target_id=target_id,
                            required_kinds=required,
                        ))
                        continue
                    target_rows = owners.get(target_id, [])
                    installed_kind = _INSTALLED_OBJECT_KINDS.get(target_id)
                    if not target_rows and installed_kind is None:
                        findings.append(AggregateFinding(
                            "OPERAND_TARGET_MISSING",
                            item.object_id,
                            "The exact target ID has neither an audited semantic owner row nor an installed registry declaration.",
                            operand_role=role,
                            target_id=target_id,
                            required_kinds=required,
                        ))
                        continue
                    if len(target_rows) > 1:
                        continue
                    target_kind = (
                        target_rows[0].primary_kind if target_rows else installed_kind
                    )
                    if (
                        installed_kind is not None
                        and target_rows
                        and target_rows[0].primary_kind != installed_kind
                    ):
                        findings.append(AggregateFinding(
                            "OPERAND_TARGET_REGISTRY_KIND_DIFFERS",
                            item.object_id,
                            f"The semantic owner kind is {target_rows[0].primary_kind}; the installed registry kind is {installed_kind}.",
                            operand_role=role,
                            target_id=target_id,
                            required_kinds=required,
                        ))
                        continue
                    if required and "OBJECT" not in required and target_kind not in required:
                        findings.append(AggregateFinding(
                            "OPERAND_TARGET_KIND_DIFFERS",
                            item.object_id,
                            f"The exact target kind is {target_kind}; the slot requires {', '.join(required)}.",
                            operand_role=role,
                            target_id=target_id,
                            required_kinds=required,
                        ))

    graph = {
        item.object_id: tuple(
            target
            for _role, targets in item.operands
            for target in targets
            if target in by_id
        )
        for item in selected
        if len(owners[item.object_id]) == 1
    }
    for object_id in _aggregate_cycle_members(graph):
        findings.append(AggregateFinding(
            "OPERAND_CYCLE",
            object_id,
            "The aggregate operand graph contains a directed cycle.",
        ))
    return tuple(sorted(set(findings), key=_AGGREGATE_FINDING_KEY))


def api_surface_overlay_findings(
    specs: Iterable[SemanticOwnershipSpec] = AGGREGATED_SEMANTIC_OWNERSHIP_SPECS,
    *,
    admitted: Iterable[Any] | None = None,
) -> tuple[AggregateFinding, ...]:
    """Cross-check API admissions against ownership without concatenating rows."""
    selected = tuple(specs)
    api_rows = tuple(_api_surface_admission.ADMITTED if admitted is None else admitted)
    by_id: dict[str, list[SemanticOwnershipSpec]] = {}
    by_path: dict[str, list[str]] = {}
    for item in selected:
        by_id.setdefault(item.object_id, []).append(item)
        for path in item.owned_paths:
            by_path.setdefault(path, []).append(item.object_id)
    findings: list[AggregateFinding] = []
    for owner in api_rows:
        rows = by_id.get(owner.owner_id, [])
        if not rows:
            findings.append(AggregateFinding(
                "API_OWNER_MISSING",
                owner.owner_id,
                "The admitted API owner ID is absent from semantic ownership.",
            ))
            continue
        if len(rows) > 1:
            findings.append(AggregateFinding(
                "API_OWNER_DUPLICATED",
                owner.owner_id,
                "The admitted API owner ID resolves to multiple semantic rows.",
            ))
            continue
        row = rows[0]
        if row.primary_kind != owner.primary_kind:
            findings.append(AggregateFinding(
                "API_OWNER_KIND_DIFFERS",
                owner.owner_id,
                f"API admission names {owner.primary_kind}; semantic ownership names {row.primary_kind}.",
            ))
        if row.owned_paths != owner.owned_paths:
            findings.append(AggregateFinding(
                "API_OWNER_PATHS_DIFFER",
                owner.owner_id,
                "API admission and semantic ownership do not name the same exact path denominator.",
            ))
        for path in owner.owned_paths:
            path_owners = tuple(sorted(by_path.get(path, ())))
            if path_owners != (owner.owner_id,):
                findings.append(AggregateFinding(
                    "API_PATH_OWNER_DIFFERS",
                    owner.owner_id,
                    f"The API path resolves to semantic owners {path_owners or ('none',)}.",
                    target_id=path,
                ))
    return tuple(sorted(set(findings), key=_AGGREGATE_FINDING_KEY))


def _portable(path: str) -> PurePosixPath:
    if type(path) is not str or not path or "\\" in path:
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_PATH_NOT_PORTABLE")
    portable = PurePosixPath(path)
    if (
        portable.is_absolute()
        or portable.as_posix() != path
        or not portable.parts
        or any(part in {"", ".", ".."} for part in portable.parts)
        or re.match(r"^[A-Za-z]:", portable.parts[0])
    ):
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_PATH_NOT_PORTABLE")
    return portable


def validate_catalog(
    source_root: str | Path,
    specs: Iterable[SemanticOwnershipSpec] = SEMANTIC_OWNERSHIP_SPECS,
    *,
    registry: Mapping[str, Any] | None = None,
) -> tuple[SemanticOwnershipSpec, ...]:
    """Validate IDs, registered roles and an exact current path partition."""
    from verifier.runtime.namespace_contracts import (
        ancestors,
        compatible_specialization,
        namespace_registry,
    )
    from verifier.core.namespace import NamespaceObject, validate_object_layout

    root = Path(source_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_ROOT_NOT_DIRECTORY")
    selected = tuple(specs)
    if not selected:
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_EMPTY")
    if any(type(item) is not SemanticOwnershipSpec for item in selected):
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_SPEC_INVALID")
    ids = [item.object_id for item in selected]
    if len(ids) != len(set(ids)):
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_ID_DUPLICATED")
    installed = namespace_registry() if registry is None else registry
    owners: dict[str, str] = {}
    for item in selected:
        if re.fullmatch(r"[a-z][a-z0-9-]{2,95}", item.object_id) is None:
            raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_ID_INVALID")
        if item.primary_kind not in installed or any(
            kind not in installed for kind in item.specializations
        ):
            raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_KIND_UNREGISTERED")
        if item.primary_kind in item.specializations or item.specializations != tuple(
            sorted(set(item.specializations))
        ):
            raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_SPECIALIZATIONS_INVALID")
        for kind in item.specializations:
            if installed[kind].extends is None:
                raise ValueError(
                    "PACKAGE_SEMANTIC_OWNERSHIP_SPECIALIZATION_NOT_REFINEMENT"
                )
            if not compatible_specialization(installed, item.primary_kind, kind):
                raise ValueError(
                    "PACKAGE_SEMANTIC_OWNERSHIP_SPECIALIZATION_BASE_DIFFERS"
                )
        decisions = item.root_role_decisions
        if (
            type(decisions) is not tuple
            or any(type(decision) is not RootRoleDecision for decision in decisions)
            or tuple(sorted(decisions, key=lambda decision: decision.kind)) != decisions
            or len({decision.kind for decision in decisions}) != len(decisions)
        ):
            raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_ROOT_ROLES_INVALID")
        for decision in decisions:
            if (
                decision.kind not in installed
                or installed[decision.kind].extends is not None
                or decision.kind == item.primary_kind
                or decision.status not in {"APPLIES", "DOES_NOT_APPLY"}
                or type(decision.reason) is not str
                or not decision.reason.strip()
            ):
                raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_ROOT_ROLE_INVALID")
        if item.operands != tuple(sorted(item.operands)) or len(
            {role for role, _targets in item.operands}
        ) != len(item.operands):
            raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_OPERANDS_INVALID")
        for role, targets in item.operands:
            if (
                re.fullmatch(r"[a-z][a-z0-9_]{0,63}", role) is None
                or not targets
                or targets != tuple(sorted(set(targets)))
                or any(
                    re.fullmatch(r"[a-z][a-z0-9-]{2,95}", target) is None
                    for target in targets
                )
            ):
                raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_OPERANDS_INVALID")
        base_kind = ancestors(installed, item.primary_kind)[-1]
        try:
            layout = NamespaceObject.create(
                item.object_id,
                base_kind,
                {"representation_role": item.representation_role},
                {role: list(targets) for role, targets in item.operands},
            )
            validate_object_layout(layout)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_SEMANTIC_OWNERSHIP_TYPED_LAYOUT_INVALID: "
                + item.object_id
            ) from exc
        if not item.owned_paths or item.owned_paths != tuple(
            sorted(set(item.owned_paths))
        ):
            raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_PATHS_INVALID")
        for value in (
            item.representation_role,
            item.necessity_reason,
            item.consequence_boundary,
        ):
            if type(value) is not str or not value.strip():
                raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_REASON_REQUIRED")
        for value in item.owned_paths:
            portable = _portable(value)
            previous = owners.setdefault(value, item.object_id)
            if previous != item.object_id:
                raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_PATH_DUPLICATED")
            candidate = root.joinpath(*portable.parts)
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_PATH_MISSING") from exc
            if not resolved.is_relative_to(root) or not resolved.is_file():
                raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_PATH_INVALID")
    return tuple(sorted(selected, key=lambda item: item.object_id))


def catalog_document(
    source_root: str | Path,
    specs: Iterable[SemanticOwnershipSpec] = SEMANTIC_OWNERSHIP_SPECS,
) -> dict[str, Any]:
    """Return one canonical deterministic view after current-path validation."""
    rows = [asdict(item) for item in validate_catalog(source_root, specs)]
    payload = {
        "schema_version": SCHEMA_VERSION,
        "claim_boundary": CLAIM_BOUNDARY,
        "objects": rows,
    }
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return {**payload, "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}


# Pure census completeness.  Inputs are a caller-supplied candidate census and
# semantic specs; no filesystem, Git or process state is read.  Generic OBJECT
# rows are fallback claims: they are reported, never counted as ownership.
MANIFEST_PATH = "objects.vstd"
GENERIC_FALLBACK_KIND = "OBJECT"
FAILURE_UNOWNED = "UNOWNED_CENSUS_PATH"
FAILURE_GENERIC_FALLBACK_ONLY = "GENERIC_OBJECT_FALLBACK_ONLY"
FAILURE_DUPLICATE_OWNER = "DUPLICATE_OWNER"
FAILURE_MISSING_OWNED_PATH = "OWNED_PATH_NOT_IN_CENSUS"
FAILURE_MANIFEST_SELF_OWNED = "MANIFEST_SELF_OWNERSHIP"
_BROAD_PATTERN_CHARACTERS = frozenset("*?[]{}")


@dataclass(frozen=True, slots=True)
class CompletenessFailure:
    """One exact reason a census path lacks a single specific semantic owner."""

    kind: str
    path: str
    owners: tuple[str, ...]
    fallback_owners: tuple[str, ...]
    reason: str
    next_action: str

    def render(self) -> str:
        owners = ", ".join(self.owners) or "none"
        fallback = ", ".join(self.fallback_owners) or "none"
        return (
            f"{self.kind} {self.path} | owners: {owners} | generic fallback: "
            f"{fallback} | reason: {self.reason} | next: {self.next_action}"
        )


def _completeness_path(value: object, *, field: str) -> str:
    """Admit one exact portable repository-relative file path or refuse it."""
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"PACKAGE_SEMANTIC_OWNERSHIP_{field}_PATH_MALFORMED")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"PACKAGE_SEMANTIC_OWNERSHIP_{field}_PATH_MALFORMED")
    if _BROAD_PATTERN_CHARACTERS.intersection(value):
        raise ValueError(f"PACKAGE_SEMANTIC_OWNERSHIP_{field}_PATTERN_REFUSED")
    _portable(value)
    return value


def _census_paths(census_paths: object) -> tuple[str, ...]:
    if isinstance(census_paths, (str, bytes, bytearray, Mapping)) or not isinstance(
        census_paths, Iterable
    ):
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_CENSUS_INVALID")
    paths = tuple(_completeness_path(item, field="CENSUS") for item in census_paths)
    if len(set(paths)) != len(paths):
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_CENSUS_DUPLICATED")
    return paths


def _completeness_specs(
    specs: Iterable[SemanticOwnershipSpec],
) -> tuple[SemanticOwnershipSpec, ...]:
    selected = tuple(specs)
    if any(type(item) is not SemanticOwnershipSpec for item in selected):
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_SPEC_INVALID")
    ids = [item.object_id for item in selected]
    if len(ids) != len(set(ids)):
        raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_ID_DUPLICATED")
    for item in selected:
        if type(item.primary_kind) is not str or not item.primary_kind.strip():
            raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_KIND_INVALID")
        owned = item.owned_paths
        if type(owned) is not tuple:
            raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_OWNED_PATHS_INVALID")
        for path in owned:
            _completeness_path(path, field="OWNED")
        if owned != tuple(sorted(set(owned))):
            raise ValueError("PACKAGE_SEMANTIC_OWNERSHIP_OWNED_PATHS_INVALID")
    return selected


def completeness_failures(
    census_paths: Iterable[str],
    specs: Iterable[SemanticOwnershipSpec] = SEMANTIC_OWNERSHIP_SPECS,
    *,
    manifest_path: str | None = None,
) -> tuple[CompletenessFailure, ...]:
    """Return every census path lacking exactly one specific semantic owner.

    ``census_paths`` must already be the exact candidate census (tracked and
    nonignored files; ignored files never enter it).  The only exclusion is the
    caller-named ``manifest_path``; no pattern, suffix or lookalike is excluded.
    Malformed, broad, traversing or duplicated inputs raise ``ValueError``.
    Ownership gaps are returned as typed failures sorted by path then kind.
    """
    census = _census_paths(census_paths)
    selected = _completeness_specs(specs)
    manifest = (
        None if manifest_path is None else _completeness_path(manifest_path, field="MANIFEST")
    )
    specific: dict[str, list[str]] = {}
    fallback: dict[str, list[str]] = {}
    for item in selected:
        bucket = fallback if item.primary_kind == GENERIC_FALLBACK_KIND else specific
        for path in item.owned_paths:
            bucket.setdefault(path, []).append(item.object_id)

    def owners_of(path: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return tuple(sorted(specific.get(path, ()))), tuple(sorted(fallback.get(path, ())))

    present = set(census)
    evaluated = present if manifest is None else present - {manifest}
    failures: list[CompletenessFailure] = []
    for path in sorted(set(specific) | set(fallback)):
        owners, generic = owners_of(path)
        if path == manifest:
            failures.append(CompletenessFailure(
                FAILURE_MANIFEST_SELF_OWNED, path, owners, generic,
                "the root manifest cannot own itself",
                "remove the manifest row; the manifest gate binds objects.vstd separately",
            ))
        elif path not in present:
            failures.append(CompletenessFailure(
                FAILURE_MISSING_OWNED_PATH, path, owners, generic,
                "owned path is absent from the supplied candidate census",
                "remove the row or restore this exact path to the census source before re-auditing",
            ))
    for path in sorted(evaluated):
        owners, generic = owners_of(path)
        if len(owners) > 1 or (owners and generic):
            failures.append(CompletenessFailure(
                FAILURE_DUPLICATE_OWNER, path, owners, generic,
                "more than one owner claims this path, or a generic fallback overlaps a specific owner",
                "assign the path to exactly one specific semantic object and drop generic fallback claims",
            ))
        elif owners:
            continue
        elif generic:
            failures.append(CompletenessFailure(
                FAILURE_GENERIC_FALLBACK_ONLY, path, (), generic,
                "only generic OBJECT fallback claims this path; fallback is not semantic ownership",
                "assign a specific primary kind with an exact audited necessity reason and boundary",
            ))
        else:
            failures.append(CompletenessFailure(
                FAILURE_UNOWNED, path, (), (),
                "candidate census path has no specific semantic owner",
                "add one audited SemanticOwnershipSpec with a specific kind and this exact path",
            ))
    return tuple(sorted(failures, key=lambda item: (item.path, item.kind)))


__all__ = [
    "AGGREGATED_SEMANTIC_OWNERSHIP_SPECS",
    "AGGREGATE_BATCH_STATUSES",
    "AGGREGATE_BLOCKER_SIDECARS",
    "AGGREGATE_UNRESOLVED_SIDECARS",
    "AggregateBatchStatus",
    "AggregateFinding",
    "CLAIM_BOUNDARY",
    "CompletenessFailure",
    "FAILURE_DUPLICATE_OWNER",
    "FAILURE_GENERIC_FALLBACK_ONLY",
    "FAILURE_MANIFEST_SELF_OWNED",
    "FAILURE_MISSING_OWNED_PATH",
    "FAILURE_UNOWNED",
    "MANIFEST_PATH",
    "SCHEMA_VERSION",
    "SEMANTIC_OWNERSHIP_SPECS",
    "SemanticOwnershipSpec",
    "aggregate_operand_findings",
    "api_surface_overlay_findings",
    "catalog_document",
    "completeness_failures",
    "validate_catalog",
]
