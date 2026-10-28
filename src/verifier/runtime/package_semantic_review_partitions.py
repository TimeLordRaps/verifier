"""Source-bound Tier-0 reviews for audited executable ownership partitions.

The ownership partitions answer which object owns each source path.  This
module answers the separate Tier-0 semantic-review question for those exact
bytes: which of the twelve added consequence kinds apply, which are refuted by
a literal per-object basis, which remain UNRESOLVED, why, and which declaration
fields are required for every applicable kind.

The review is declarative and fail closed.  It does not execute a mechanism or
establish that a declaration is true.  A kind is APPLIES only when an explicit
primary or specialization label says so, DOES_NOT_APPLY only when the literal
refutation catalog names that exact object and kind, and UNRESOLVED otherwise.
Omission is never a refutation.  Applying the review validates the complete
source denominator before and after semantic preflight, preserves only exact
current bindings, and mutates only a deep copy after every object has passed.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime import package_original_kind_catalog_runtime as _original_kind
from verifier.runtime import package_semantic_ownership as _ownership
from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.package_semantic_ownership_domains import (
    DOMAIN_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_experiments import (
    EXPERIMENT_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_hardware_interop import (
    HARDWARE_INTEROP_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_model import SemanticOwnershipSpec
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
from verifier.runtime.package_semantic_ownership_normative_assets import (
    AGENCY_CROSSWALK_ADDITIVE_APPLIES,
    NORMATIVE_ASSET_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_tests_fixtures import (
    TEST_FIXTURE_OWNERSHIP_SPECS,
)


REVIEW_KINDS = _shared.REVIEW_KINDS
# The denominator text is repeated in every reason and declaration of an object, so a long
# inline path list is multiplied by hundreds of fields in objects.vstd.  Above this length the
# text carries the path count and the sha256 of the path list; every path and file digest stays
# bound by each cell's evidence.  Lowered from 2,048 so the regenerated receipt fits the 32 MiB
# invariant (about 980 KB saved on the 2026-10-16 regeneration, which was 274 KB over).
MAX_INLINE_SOURCE_DENOMINATOR_CHARS = 512
PARTITION_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    *HARDWARE_INTEROP_OWNERSHIP_SPECS,
    *PYTHON_APPS_OWNERSHIP_SPECS,
    *DOMAIN_OWNERSHIP_SPECS,
    *EXPERIMENT_OWNERSHIP_SPECS,
    *PUBLIC_CLI_OWNERSHIP_SPECS,
    *REPOSITORY_ASSET_OWNERSHIP_SPECS,
    *SCRIPT_EXAMPLE_OWNERSHIP_SPECS,
    *NORMATIVE_ASSET_OWNERSHIP_SPECS,
    *TEST_FIXTURE_OWNERSHIP_SPECS,
)
PARTITION_OBJECT_IDS = tuple(spec.object_id for spec in PARTITION_SPECS)
# Central rows defined inside the aggregate ownership module.  Their identities
# come from the literal original-kind audit inventory, not from a complement of
# the imported partitions, so a row dropped from or added to either side fails.
_LOCAL_OBJECT_IDS = frozenset(
    row.object_id for row in _original_kind.RUNTIME_ORIGINAL_KIND_AUDITS
)
_LOCAL_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = tuple(
    spec
    for spec in _ownership.SEMANTIC_OWNERSHIP_SPECS
    if spec.object_id in _LOCAL_OBJECT_IDS
)

# Additional applicability must be exceptional and source-audited.  The domain
# grounding specimen declares AGENT/BOT and TRANSACTION on the same owner.  The
# consequence graph therefore requires the additive FINBOT role even though
# its retained fixtures establish no real-money authority or effect.
SOURCE_AUDITED_APPLICABILITY_BASIS: tuple[tuple[str, str, str], ...] = (
    (
        "vstd-domain-grounding-specimen",
        "FINBOT",
        "vstd-domain-grounding-specimen applies as FINBOT because its exact owned "
        "source combines declared AGENT and BOT decision roles with the owner's "
        "TRANSACTION specialization. This preserves the typed financial-decision "
        "boundary without claiming real-money authority, exposure, settlement, or effect.",
    ),
    *tuple(
        (
            "vstd-agency-surface-crosswalk-assets",
            kind,
            "vstd-agency-surface-crosswalk-assets: the sole authored reasons.vstd "
            "conservatively selects APPLIES for "
            + kind
            + " on the exact agency crosswalk, so its obligations remain required. "
            "This source-audited applicability decision establishes neither subject "
            "instantiation nor external effect.",
        )
        for kind in AGENCY_CROSSWALK_ADDITIVE_APPLIES
    ),
)

# These exact cells cannot be refuted because the owned sources invoke or
# forward caller-controlled callables without an enforceable purity/effect
# contract. Their intended lookup, digest, or cancellation purpose does not
# prove that an arbitrary supplied implementation is effect-free.
UNCHECKED_EXTERNAL_CALLABLE_BASIS: tuple[tuple[str, str, str], ...] = (
    (
        "vstd-provider-control-plane-evidence-protocol",
        "ACTUATOR",
        "src/verifier/hardware/provider_evidence.py directly invokes the supplied "
        "key_resolver without a purity or effect contract.",
    ),
    (
        "vstd-hardware-attestation-verifier",
        "ACTUATOR",
        "src/verifier/hardware/attestation.py directly invokes the supplied "
        "key_resolver without a purity or effect contract.",
    ),
    (
        "vstd-hardware-accounting-continuity-ledger",
        "ACTUATOR",
        "src/verifier/hardware/continuity.py directly invokes the supplied "
        "key_resolver for event and anchor verification without a purity or effect contract.",
    ),
    (
        "vstd-hardware-provenance-graph-attachment",
        "ACTUATOR",
        "src/verifier/hardware/provenance.py forwards the supplied key_resolver into "
        "receipt and provider verification without a purity or effect contract.",
    ),
    (
        "vstd-hardware-receipt-validator",
        "ACTUATOR",
        "src/verifier/hardware/validation.py forwards the supplied key_resolver into "
        "attestation, provider, and continuity verification without a purity or effect contract.",
    ),
    (
        "vstd-retained-selection-policy",
        "ACTUATOR",
        "src/verifier/domains/contracts/retained_selection.py invokes the supplied "
        "current_digest callable without a purity or effect contract.",
    ),
    (
        "vstd-retained-execution-measurement",
        "ACTUATOR",
        "src/verifier/domains/contracts/spacetime_execution.py repeatedly invokes the "
        "supplied cancelled callback without a purity or effect contract.",
    ),
    (
        "vstd-sim-host-time-mapping-verifier",
        "ACTUATOR",
        "src/verifier/domains/contracts/spacetime_mapping.py repeatedly invokes the "
        "supplied cancelled callback without a purity or effect contract.",
    ),
)

# This public namespace is only import/export syntax in its owned bytes, but the
# routes it exposes include the mutable VirtualVSTDAccelerator and callback-
# invoking artifact-trace operation. ACTUATOR cannot be refuted from the
# absence of a direct call in the two __init__.py files.
EXPOSED_EFFECT_ROUTE_BASIS: tuple[tuple[str, str, str], ...] = (
    (
        "vstd-hardware-public-api",
        "ACTUATOR",
        "src/verifier/hardware/__init__.py exports VirtualVSTDAccelerator and "
        "issue_artifact_trace, while src/verifier/hardware/adapters/__init__.py "
        "exports adapter classes; their reachable methods can mutate virtual state, "
        "invoke caller-supplied callbacks, or query host mechanisms, so re-export-only "
        "owned syntax does not establish an effect-free public route.",
    ),
)

# The source audits above establish why these nine ACTUATOR cells cannot be
# refuted; they do not establish that an effect occurred. The sole authored
# reasons.vstd therefore makes the conservative Tier-0 decision: retain each
# obligation as APPLIES while making no mechanism, effect, authority, or
# checker-success claim.
OBLIGATION_RETENTION_APPLICABILITY_BASIS: tuple[tuple[str, str, str], ...] = tuple(
    (
        object_id,
        kind,
        object_id
        + " applies as "
        + kind
        + " because the sole authored reasons.vstd conservatively retains the "
        "obligation: "
        + source_reason
        + " This APPLIES decision asserts neither that an external effect occurred "
        "nor that a mechanism, authority, physical consequence, checker PASS, or "
        "Tier-1-plus fulfillment was established.",
    )
    for object_id, kind, source_reason in (
        *UNCHECKED_EXTERNAL_CALLABLE_BASIS,
        *EXPOSED_EFFECT_ROUTE_BASIS,
    )
)

# Source-audited literal assignments for the exact current partition objects.
# Each tuple names every kind explicitly refuted for that one object.  This is
# intentionally verbose data: runtime code never obtains a refutation by taking
# the complement of an applicable label.  A future object or kind absent here
# remains UNRESOLVED until a new current-source audit adds a literal assignment.
REFUTED_KINDS_BY_OBJECT: tuple[tuple[str, tuple[str, ...]], ...] = (
    ('vstd-hardware-public-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-generic-accelerator-evidence-sensor', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-provider-control-plane-evidence-protocol', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-hardware-evidence-records', ('TRANSACTION', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-hardware-attestation-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-hardware-claim-conformance-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-hardware-accounting-continuity-ledger', ('TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-hardware-provenance-graph-attachment', ('LEDGER', 'MARKET', 'SENSOR', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-accelerator-profile-registry', ()),
    ('vstd-temporal-comb-measurement', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-artifact-trace-protocol', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-hardware-receipt-validator', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-interoperability-public-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-interoperability-component-catalog', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-component-index-storage', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-interoperability-validation-planning-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-selected-digest-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-authority-composition-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-silo-composition-qualification', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-typed-formation-wire-protocol', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-typed-formation-certificate-producer', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-typed-formation-checker', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-typed-formation-receipt', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-source-grounding-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-relation-boundary-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-bounded-completeness-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-proposition-transfer-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-geometry-consistency-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-graph-topology-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-global-cycle-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-runtime-authority-correspondence', ('ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-untraversability-verifier', ('LEDGER', 'ASSET', 'MARKET', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-python-public-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-module-cli-entrypoint', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-consent-package-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-consent-stage-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-corrigibility-package-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-benchmark-suite-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-corrigibility-containment-contracts', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-training-data-contamination-assessor', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-corrigibility-environment-profile', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-corrigibility-provenance-ledger', ('ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-training-checkpoint-ledger', ('ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-model-reproducibility-profile', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-agent-bot-ontology-architecture', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-operator-stop-authentication', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-capability-reward-lock', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-corrigibility-risk-assessor', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-sim-trace-assessor', ('LEDGER', 'ASSET', 'MARKET', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-tesla-cage-contract', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-training-control-profile', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-data-package-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-graph-level-verifier', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-provenance-hypergraph-ledger', ('MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-data-receipt-lifecycle', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-environments-package-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-environment-record-contracts', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-environment-assessor', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-environment-integration-projection', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-environment-specimen-checker', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-environment-synthetic-specimens', ('LEDGER', 'ASSET', 'MARKET', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-experimental-workflow-package-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-github-snapshot-event-adapter', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-experimental-workflow-profile', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-identity-package-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-identity-token-records', ('TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-identity-policy-evaluator', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-identity-adversarial-audit', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-layer4-package-api', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-refutation-surface-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-refutability-closure-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-schema-package-marker', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-domains-package-marker', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-domain-carrier-protocols', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-domain-specification-catalog', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-domain-certificate-engine', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-domain-checking-primitives', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-domain-contracts-package-marker', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-object-obligation-inventory', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-mainstay-certificate-engine', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-mainstay-evaluator', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-retained-model-training-arithmetic', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-tier3-statics-evaluator', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-hardware-ownership-eligibility', ('LEDGER', 'TRANSACTION', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-application-requirements-compiler', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-certificate-dependency-controller', ('LEDGER', 'ASSET', 'MARKET', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-consent-certificate-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-object-replay-router', ('LEDGER', 'ASSET', 'MARKET', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-dangerous-pathway-assessor', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-facet-obligation-compiler', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-independence-certificate-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-independence-projection-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-native-child-link-assessor', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-object-address-closure-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-object-facet-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-object-governance-protocol', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-sim-grounding-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-object-lineage-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-object-statics-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-privacy-certificate-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-retained-selection-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-reviewed-conflict-refusal-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-reviewed-singleton-projection-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-selected-native-context-assessor', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-retained-execution-measurement', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-sim-host-time-mapping-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-spacetime-capability-measurement', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-subject-security-chain-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-typed-facet-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-typed-facet-projection-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-artifact-first-mechanism-study', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-experiment-catalog-records', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-github-verdict-neutrality-study-record', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-architecture-documents', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-artifact-audit', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-baseline-encoding-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-benchmark-controller', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-canonical-artifact-io', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-environment-declarations', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-freeze-ledger', ('ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-independent-record-validator', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-instance-corpus', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-metric-contract', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-model-endpoint-harness', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-model-prompt-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-native-verifier-adapters', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-noise-measurement', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-package-marker', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-provenance-record-binding', ('TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-public-result-records', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-regression-harness', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-reserve-verifiers', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-result-classification-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-result-validator', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-route-compiler', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-sat-backend', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-study-governance', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-trial-harness', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-vendored-license-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-vgsat-verifier-contract-protocol', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-public-cli-dispatch', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-retained-facet-policy-inputs', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-retained-graph-statics-policy-input', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-retained-object-facet-requests', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-retained-typed-facet-requests', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-retained-graph-statics-request', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-retained-object-facet-certificates', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-retained-typed-facet-certificates', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-retained-graph-statics-certificate', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-root-uv-dependency-resolution', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-claim-boundary-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-reader-reference', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-core-architecture', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-artifact-interoperability-architecture', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-control-domain-candidates', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-environment-graph-architecture', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-local-tool-protocols', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-remote-submission-protocols', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-user-navigation', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-hosting-protocol', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-adjacent-standards-crosswalks', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-derived-metadata', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-repository-file-and-package-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-repository-citation-metadata', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-repository-legal-notices', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-repository-agent-operating-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-repository-community-governance-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-repository-source-admission-designs', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-repository-overview', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-repository-release-procedure-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-repository-history-and-roadmap', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-github-contribution-form-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-github-external-link-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-github-verification-workflow-protocols', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-github-source-description-workflow-protocol', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-github-promotion-policy-protocols', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-github-documentation-deployment-protocol', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-github-release-workflow-protocol', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-receipt-wire-schema-catalog', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-accelerator-profile-wire-schema', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-generated-distribution-metadata', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-artifact-network-fixture-ledger', ('ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-documentation-site-assembly', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-domain-grounding-specimen', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT')),
    ('vstd-example-catalog-guide', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-example-dataset-gate-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-example-gate-pipeline', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-experiment-index-materialization', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-first-software-workflow-declarations', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-flagship-adversarial-receipts', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-generic-run-specimen', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-geometry-constraint-verifier-specimen', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-graph-topology-specimen', ('LEDGER', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-grounded-certification-specimen', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-interoperability-composition-harness', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-interoperability-planning-harness', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-local-preflight-controller', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-logits-constraint-harness', ('LEDGER', 'ASSET', 'MARKET', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-mainstay-admission-specimen', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-monograph-build-transaction', ('LEDGER', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-package-manifest-migration-controller', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-platform-evidence-recording', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-prdel-self-polish-declarations', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-prdel-source-selection-checks', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-public-reference-generation', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-public-source-policy-gates', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-publication-state-observers', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-pull-request-promotion-policy', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-release-admission-utilities', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-release-artifact-controller', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-risc0-proof-boundary', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-risc0-proof-environment', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-risc0-proof-host-controller', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-risc0-proof-program', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-risc0-recorded-proof', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-comparison-catalog-entry', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-distribution-fetch-controller', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-distribution-staging', ('LEDGER', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-local-log-specimen', ('ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-native-comparison-plan', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-native-execution-harness', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-native-package-marker', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-recorded-comparison-verifier', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-requirement-consistency-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-scitt-source-freeze-transaction', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-selected-validation-guide', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-selected-validation-subjects', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-stored-component-export', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'ROBOT', 'FINBOT')),
    ('vstd-verification-geometry-residual', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-verifier-bootstrap-admission-specimen', ('LEDGER', 'ASSET', 'MARKET', 'CONTROLLER', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-workflow-verdict-neutrality-specimen', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-zero-identity-fixture-corpus', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-zero-identity-policy', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-zero-identity-reference-verifier', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-zero-identity-status-model', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-zizk-reference-guide', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-profile-architecture-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-domain-certification-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-repository-admission-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-package-polish-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-package-self-polish-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-core-application-release-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-language-runner-isolation-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-corrigibility-control-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-prdel-language-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-artifact-control-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-bounded-completeness-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-certificate-dependency-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-consent-protocol-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-dangerous-pathway-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-deriver-self-status-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-finite-authority-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-finite-record-issuance-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-typed-formation-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-global-cycle-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-proposition-transfer-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-public-checkability-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-relation-boundary-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-runtime-authority-correspondence-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-selected-secret-gate-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-source-grounding-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-spacetime-context-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-zero-identity-token-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-artifact-network-wire-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-component-index-data-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-explanation-definition-data-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-native-replay-metadata-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-silo-protocol-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-simulation-risk-receipt-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'POLICY', 'ROBOT', 'FINBOT')),
    ('vstd-competition-evaluation-profile-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-experimental-workflow-profile-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-three-hardware-integration-profile-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-actor-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-agent-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-arch-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-bench-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-bot-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-collective-protocol-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-data-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-env-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-event-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-graph-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-hardware-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-harness-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-human-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-hyper-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-identity-protocol-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-model-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-object-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-owner-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-receipt-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-role-protocol-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-sim-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-space-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-time-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-token-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-train-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-verifier-policy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-independence-privacy-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-current-permission-slot-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-subject-security-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-current-typed-facet-assets', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'PROTOCOL', 'ROBOT', 'FINBOT')),
    ('vstd-test-fixture-harness', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-formation-fixture-corpus', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-test-spacetime-extension-schema', ('LEDGER', 'TRANSACTION', 'ASSET', 'MARKET', 'MEASUREMENT', 'SENSOR', 'CONTROLLER', 'ACTUATOR', 'ROBOT', 'FINBOT')),
    ('vstd-test-namespace-admission-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-polish-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-current-object-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-simulation-model-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-hardware-environment-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-artifact-evidence-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-governance-authority-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-release-publication-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-prdel-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-security-privacy-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-graph-composition-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-runtime-execution-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
    ('vstd-test-packaging-compatibility-regressions', ('LEDGER', 'ASSET', 'MARKET', 'ROBOT', 'FINBOT')),
)
# Partition objects admitted into the exact union but not yet covered by a literal
# refutation audit.  Every kind they do not explicitly apply to stays UNRESOLVED;
# absence from REFUTED_KINDS_BY_OBJECT is never a refutation.  Each object must be
# listed in exactly one of the two catalogs, so a new object cannot be forgotten.
PENDING_REFUTATION_AUDIT_OBJECT_IDS: tuple[str, ...] = (
    "vstd-agency-surface-crosswalk-assets",
)

CLAIM_BOUNDARY = (
    "Exact-current-source Tier-0 applicability and declaration review for the "
    "audited executable ownership partitions only. It does not establish "
    "mechanism execution or semantic truth, Tier-1-plus conformance, physical "
    "confinement, real-money authority or effects, publication, release, or deployment."
)


def _source_denominator(spec: SemanticOwnershipSpec) -> str:
    """Keep declarations readable and bounded while evidence retains every path."""
    joined = ", ".join(spec.owned_paths)
    if len(joined) <= MAX_INLINE_SOURCE_DENOMINATOR_CHARS:
        return joined
    digest = hashlib.sha256("\n".join(spec.owned_paths).encode("utf-8")).hexdigest()
    return (
        str(len(spec.owned_paths))
        + " exact paths bound by sha256:"
        + digest
        + "; the complete current path/digest denominator is carried by evidence"
    )


def _operands_text(spec: SemanticOwnershipSpec) -> str:
    return ", ".join(
        name + "=" + ",".join(targets) for name, targets in spec.operands
    ) or "none"


_AGENCY_CROSSWALK_OBJECT_ID = "vstd-agency-surface-crosswalk-assets"


def _declaration_basis_digest(spec: SemanticOwnershipSpec) -> str:
    """Bind the complete declaration basis for compact repeated field text."""
    payload = "\0".join(
        (
            spec.object_id,
            spec.representation_role,
            spec.necessity_reason,
            spec.consequence_boundary,
            "\n".join(spec.owned_paths),
            "\n".join(
                name + "=" + ",".join(targets) for name, targets in spec.operands
            ),
        )
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _declaration_basis(spec: SemanticOwnershipSpec) -> str:
    """Return an exact compact pointer to the complete declaration basis.

    The object row retains the full source role, necessity, consequence boundary,
    operands, and owned paths once. Repeating that prose in every declaration
    field made the expanded semantic graph exceed its bounded transport. The
    digest binds every one of those fields without dropping an answer.
    """
    return (
        spec.object_id
        + " declaration basis "
        + _declaration_basis_digest(spec)
        + " binds exact source "
        + _source_denominator(spec)
        + "; source role, necessity, consequence boundary, operands, and path set "
        "are hash-bound; declaration text alone establishes no execution truth."
    )


def _basis(spec: SemanticOwnershipSpec) -> str:
    """Return the readable source and semantic basis for classification reasons."""
    return (
        spec.object_id
        + " owns "
        + spec.representation_role
        + " Exact current source-byte denominator: "
        + _source_denominator(spec)
        + ". Fixed operands: "
        + _operands_text(spec)
        + ". Necessity: "
        + spec.necessity_reason
        + " Consequence boundary: "
        + spec.consequence_boundary
    )


def _profile(spec: SemanticOwnershipSpec) -> _shared._Profile:
    """Build readable contract vocabulary without asserting source behavior."""
    if spec.object_id == _AGENCY_CROSSWALK_OBJECT_ID:
        # This one crosswalk deliberately retains all twelve review roles.  Keep
        # each required declaration explicit but avoid repeating its long source
        # rationale 145 times in the expanded semantic manifest.
        return _shared._Profile(
            name="vstd-agency-surface-crosswalk-assets",
            scope="Exact AGENCY_SURFACE.md crosswalk; every selected obligation applies.",
            mechanism="Static route table and retained-child join; no execution.",
            participants="Only source-named roles; external identity is not established.",
            inputs="Exact owned source bytes and source-named operands only.",
            authority="No human, legal, physical, financial, or release authority.",
            states="Only source-recorded states; unobserved states remain UNKNOWN.",
            ordering="Only source-recorded route and child-certificate ordering.",
            commands="No command or downstream effect is established by this review.",
            targets="Only source-named values, records, and conditional endpoints.",
            effect_domains="No physical or real-money effect domain is established.",
            effects="Applicability retains obligations; it proves no effect occurred.",
            commit="No external commit or publication boundary is established.",
            retry="No retry, replay, or idempotency guarantee is inferred.",
            timing="No liveness, latency, or physical-clock guarantee is inferred.",
            limits="Only limits written in the exact owned source apply.",
            observations="Source records are not promoted to external-world truth.",
            units="Only source-named units; no conversion is inferred.",
            failure="Invalid, partial, stale, or contradictory input remains UNKNOWN.",
            recovery="Only a fresh bounded review; no rollback or repair is invented.",
            boundary=(
                "Identity, authority, physical safety, real-money effects, and subject "
                "instantiation remain NOT_ESTABLISHED."
            ),
        )
    name = spec.object_id + " (" + spec.representation_role + ")"
    sources = _source_denominator(spec)
    return _shared._Profile(
        name=name,
        scope=(
            name
            + " is reviewed only as the path-owned source role declared by the "
            "audited partition. Its exact source denominator is "
            + sources
            + "."
        ),
        mechanism=(
            name
            + " is represented by current bytes at "
            + sources
            + "; the review binds those bytes but does not execute or validate them."
        ),
        participants=(
            name
            + " represents the direct caller, the path owner, and only participants "
            "explicitly named by those sources; no external identity is inferred."
        ),
        inputs=(
            name
            + " accepts only its exact current source bytes and the bounded values "
            "those sources explicitly admit; undeclared external state is not input."
        ),
        authority=(
            name
            + " has only caller invocation and source-declared authority. Ownership "
            "review grants no human, legal, physical, financial, or release authority."
        ),
        states=(
            name
            + " includes only states explicitly represented by the owned sources; "
            "unobserved runtime or external states remain UNKNOWN."
        ),
        ordering=(
            name
            + " uses only order explicitly represented by its source-defined calls, "
            "records, or dependencies; no global temporal order is inferred."
        ),
        commands=(
            name
            + " can submit only calls, callbacks, decisions, or records implemented "
            "by its owned sources; downstream effects require separate evidence."
        ),
        targets=(
            name
            + " is limited to in-process values and any files, processes, or endpoints "
            "explicitly selected by its owned sources."
        ),
        effect_domains=(
            name
            + " is bounded to declared software effects. No physical or real-money "
            "effect domain is inferred from source ownership."
        ),
        effects=(
            name
            + " may have only effects explicitly implemented by the exact owned bytes; "
            "this Tier-0 review performs none of those effects."
        ),
        commit=(
            name
            + " commits only at a source-defined successful return or publication "
            "boundary; ambiguous completion remains UNKNOWN."
        ),
        retry=(
            name
            + " has no inferred retry or idempotency guarantee. A repeat is a fresh "
            "source-bound invocation unless the owned source says otherwise."
        ),
        timing=(
            name
            + " has only timestamps, ordering, or timeouts explicitly represented by "
            "the owned source; no liveness or physical-clock guarantee is inferred."
        ),
        limits=(
            name
            + " is bounded by limits explicit in its exact source and declared role. "
            "Missing limits are not invented by this review."
        ),
        observations=(
            name
            + " exposes only source-defined return values, records, or diagnostics; "
            "they are not promoted to semantic or external-world truth."
        ),
        units=(
            name
            + " retains the bytes, counts, identifiers, times, quantities, and units "
            "explicitly named by its source; no unit conversion is inferred."
        ),
        failure=(
            name
            + " treats invalid, unavailable, contradictory, partial, or stale inputs "
            "as refusal or UNKNOWN rather than silently inferring success."
        ),
        recovery=(
            name
            + " recovers only through a fresh bounded invocation or an explicit "
            "source-defined recovery path; no rollback or repair is invented."
        ),
        boundary=spec.consequence_boundary,
    )


def _asset(profile: _shared._Profile) -> dict[str, dict[str, str]]:
    """Declare resource claims without turning them into title or backing."""
    return {
        "ASSET-0.1-identity-and-quantity": {
            "identity": profile.targets,
            "rights": profile.authority,
            "units": profile.units,
            "precision": profile.limits,
        },
        "ASSET-0.2-issuance-and-redemption": {
            "issuance_authority": profile.authority,
            "supply_changes": profile.effects,
            "redemption": profile.recovery,
            "backing_claims": profile.boundary,
        },
        "ASSET-0.3-custody-and-encumbrance": {
            "custody": profile.states,
            "control": profile.commands,
            "encumbrances": profile.failure,
            "reconciliation": profile.observations,
        },
    }


def _finbot(profile: _shared._Profile) -> dict[str, dict[str, str]]:
    """Declare the typed financial-decision boundary without inventing authority."""
    return {
        "FINBOT-0.1-agent-and-financial-authority": {
            "agent": profile.participants,
            "harness": profile.mechanism,
            "decision_scope": profile.scope,
            "financial_authority": profile.authority,
        },
        "FINBOT-0.2-financial-exposure-and-dependencies": {
            "assets_and_parties": profile.targets,
            "financial_dependencies": profile.inputs,
            "real_world_paths": profile.boundary,
            "exposure_limits": profile.limits,
        },
        "FINBOT-0.3-decisions-effects-and-recovery": {
            "decision_effect_evidence": profile.observations,
            "limit_enforcement": profile.limits,
            "intervention": profile.commands,
            "reconciliation_and_recovery": profile.recovery,
        },
    }


_DECLARATION_BUILDERS = dict(_shared._DECLARATION_BUILDERS)
_DECLARATION_BUILDERS["ASSET"] = _asset
_DECLARATION_BUILDERS["FINBOT"] = _finbot


def _applicable(spec: SemanticOwnershipSpec) -> tuple[str, ...]:
    declared = {spec.primary_kind, *spec.specializations}
    declared.update(
        decision.kind
        for decision in spec.root_role_decisions
        if decision.status == "APPLIES"
    )
    declared.update(
        kind
        for object_id, kind, _reason in (
            *SOURCE_AUDITED_APPLICABILITY_BASIS,
            *OBLIGATION_RETENTION_APPLICABILITY_BASIS,
        )
        if object_id == spec.object_id
    )
    return tuple(kind for kind in REVIEW_KINDS if kind in declared)


_SPECS = {spec.object_id: spec for spec in PARTITION_SPECS}
_ADDITIONAL_APPLICABILITY: dict[tuple[str, str], str] = {}
for _object_id, _kind, _applicability_reason in (
    *SOURCE_AUDITED_APPLICABILITY_BASIS,
    *OBLIGATION_RETENTION_APPLICABILITY_BASIS,
):
    if _object_id not in _SPECS or _kind not in REVIEW_KINDS:
        raise AssertionError(
            "source-audited applicability target differs: "
            + _object_id
            + " "
            + _kind
        )
    if _kind in {
        _SPECS[_object_id].primary_kind,
        *_SPECS[_object_id].specializations,
    }:
        raise AssertionError(
            "source-audited applicability duplicates a declared label: "
            + _object_id
            + " "
            + _kind
        )
    if (
        (_object_id, _kind) in _ADDITIONAL_APPLICABILITY
        or not _applicability_reason.strip()
        or _object_id not in _applicability_reason
        or _kind not in _applicability_reason
    ):
        raise AssertionError(
            "source-audited applicability basis differs: "
            + _object_id
            + " "
            + _kind
        )
    _ADDITIONAL_APPLICABILITY[(_object_id, _kind)] = _applicability_reason

_DECLARED_DELEGATED_APPLICABILITY = {
    ("vstd-accelerator-profile-registry", kind): (
        "vstd-accelerator-profile-registry applies as "
        + kind
        + " because its exact owned source accepts caller-supplied profile objects "
        "and performs overridable self.register and cls(...) dispatch; that unsealed "
        "runtime boundary is not established to exclude "
        + kind
        + " behavior. This retains the obligation without asserting occurrence, "
        "authority, physical or financial effect, publication, or release."
    )
    for kind in REVIEW_KINDS
}

_UNCHECKED_EXTERNAL_CALLABLES: dict[tuple[str, str], str] = {}
for _object_id, _kind, _callable_reason in UNCHECKED_EXTERNAL_CALLABLE_BASIS:
    if (
        _object_id not in _SPECS
        or _kind not in REVIEW_KINDS
        or (_object_id, _kind) in _UNCHECKED_EXTERNAL_CALLABLES
        or not _callable_reason.strip()
    ):
        raise AssertionError(
            "unchecked external callable basis differs: "
            + _object_id
            + " "
            + _kind
        )
    _UNCHECKED_EXTERNAL_CALLABLES[(_object_id, _kind)] = _callable_reason

_EXPOSED_EFFECT_ROUTES: dict[tuple[str, str], str] = {}
for _object_id, _kind, _route_reason in EXPOSED_EFFECT_ROUTE_BASIS:
    if (
        _object_id not in _SPECS
        or _kind not in REVIEW_KINDS
        or (_object_id, _kind) in _EXPOSED_EFFECT_ROUTES
        or not _route_reason.strip()
    ):
        raise AssertionError(
            "exposed effect route basis differs: " + _object_id + " " + _kind
        )
    _EXPOSED_EFFECT_ROUTES[(_object_id, _kind)] = _route_reason


def _protected_from_refutation(object_id: str, kind: str) -> bool:
    return (object_id, kind) in _UNCHECKED_EXTERNAL_CALLABLES or (
        object_id,
        kind,
    ) in _EXPOSED_EFFECT_ROUTES

# These clauses state the defining mechanism or effect whose absence was
# checked for each literally assigned cell.  They are not used to select a
# status; selection comes only from REFUTED_KINDS_BY_OBJECT above.
_KIND_SPECIFIC_ABSENCE = {
    "LEDGER": (
        "the owned bytes implement no relied-on authoritative ordered record with "
        "posting, reconciliation, correction-history, or duplicate-application semantics"
    ),
    "TRANSACTION": (
        "the owned bytes implement no consequential state transition with a defined "
        "precondition, authority, atomicity or partial-failure boundary, retry or "
        "compensation rule, and finality point"
    ),
    "ASSET": (
        "the owned bytes represent no resource or claim requiring quantity and units, "
        "issuance or redemption, custody, encumbrance, or actual-backing semantics"
    ),
    "MARKET": (
        "the owned bytes implement no participant order lifecycle, matching or allocation "
        "rule, access control, manipulation control, or settlement dependency"
    ),
    "MEASUREMENT": (
        "the owned bytes acquire or compute no phenomenon-bound quantity requiring units, "
        "timestamps, uncertainty, calibration, or missing-observation semantics"
    ),
    "SENSOR": (
        "the owned bytes implement no observation boundary that acquires a runtime, "
        "environmental, or external phenomenon for downstream use"
    ),
    "CONTROLLER": (
        "the owned bytes implement no feedback, scheduling, or decision mechanism that "
        "controls an actuator under an operating envelope, timing rule, interlock, or "
        "safe-failure rule"
    ),
    "ACTUATOR": (
        "the owned bytes submit no command, callback, write, process, network request, or "
        "other bounded effect outside pure representation or computation"
    ),
    "PROTOCOL": (
        "the owned bytes define no participant or message state machine requiring ordering, "
        "replay resistance, failure assumptions, safety, or liveness"
    ),
    "POLICY": (
        "the owned bytes define no normative rule precedence, decision authority, exception, "
        "or enforcement point"
    ),
    "ROBOT": (
        "the owned bytes instantiate no AGENT in a HARNESS whose CONTROLLER commands "
        "real-world ACTUATORs, including through a simulation-to-real boundary"
    ),
    "FINBOT": (
        "the owned bytes instantiate no agent authorized to make or execute consequential "
        "real-money decisions; financial-like records and fixtures confer no such authority"
    ),
}


def _refutation_reason(spec: SemanticOwnershipSpec, kind: str) -> str:
    """Bind one literal refutation to its exact audited source and semantics."""
    try:
        absence = _KIND_SPECIFIC_ABSENCE[kind]
    except KeyError as exc:
        raise AssertionError("missing kind-specific refutation clause: " + kind) from exc
    return (
        spec.object_id
        + " is explicitly DOES_NOT_APPLY for "
        + kind
        + " after a current-source audit. Exact owned source denominator: "
        + _source_denominator(spec)
        + ". Representation boundary: "
        + spec.representation_role
        + " Necessity boundary: "
        + spec.necessity_reason
        + " Consequence boundary: "
        + spec.consequence_boundary
        + " Kind-specific defining-mechanism refutation: "
        + absence
        + ". Fixed operands: "
        + _operands_text(spec)
        + "."
    )


def _expand_literal_refutations(
    assignments: tuple[tuple[str, tuple[str, ...]], ...],
) -> tuple[tuple[str, str, str], ...]:
    """Expand only authored object/kind names; never derive an applicability complement."""
    result: list[tuple[str, str, str]] = []
    seen_objects: set[str] = set()
    for assignment in assignments:
        if (
            type(assignment) is not tuple
            or len(assignment) != 2
            or type(assignment[0]) is not str
            or type(assignment[1]) is not tuple
        ):
            raise AssertionError(
                "refutation assignment must be an (object_id, kinds) tuple"
            )
        object_id, kinds = assignment
        if object_id not in _SPECS:
            raise AssertionError(
                "refutation object is not a partition object: " + object_id
            )
        if object_id in seen_objects:
            raise AssertionError("duplicate refutation object: " + object_id)
        seen_objects.add(object_id)
        if any(type(kind) is not str for kind in kinds) or len(kinds) != len(set(kinds)):
            raise AssertionError("invalid refutation kinds for: " + object_id)
        spec = _SPECS[object_id]
        for kind in kinds:
            if kind not in REVIEW_KINDS:
                raise AssertionError("refutation kind is not a review kind: " + kind)
            if _protected_from_refutation(object_id, kind):
                raise AssertionError(
                    "explicit non-refutation source basis cannot be refuted: "
                    + object_id
                    + " "
                    + kind
                )
            if kind in _applicable(spec):
                raise AssertionError(
                    "refutation overlaps an applicable label: " + object_id + " " + kind
                )
            result.append((object_id, kind, _refutation_reason(spec, kind)))
    return tuple(result)


REFUTATION_BASIS = _expand_literal_refutations(REFUTED_KINDS_BY_OBJECT)
_REVIEWS = {
    spec.object_id: _shared._review(
        spec.primary_kind,
        spec.owned_paths,
        _applicable(spec),
        _profile(spec),
    )
    for spec in PARTITION_SPECS
}


def _validated_refutations(
    entries: tuple[tuple[str, str, str], ...],
) -> dict[tuple[str, str], str]:
    """Check literal refutations without deriving any refutation from labels."""
    result: dict[tuple[str, str], str] = {}
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 3 or any(
            type(item) is not str for item in entry
        ):
            raise AssertionError(
                "refutation entry must be an (object_id, kind, reason) triple"
            )
        object_id, kind, reason = entry
        if object_id not in _SPECS:
            raise AssertionError(
                "refutation object is not a partition object: " + object_id
            )
        if kind not in REVIEW_KINDS:
            raise AssertionError("refutation kind is not a review kind: " + kind)
        if _protected_from_refutation(object_id, kind):
            raise AssertionError(
                "explicit non-refutation source basis cannot be refuted: "
                + object_id
                + " "
                + kind
            )
        if kind in _REVIEWS[object_id].applicable:
            raise AssertionError(
                "refutation overlaps an applicable label: " + object_id + " " + kind
            )
        if (object_id, kind) in result:
            raise AssertionError("duplicate refutation: " + object_id + " " + kind)
        if reason != _refutation_reason(_SPECS[object_id], kind):
            raise AssertionError(
                "refutation reason is not the exact source-audited reason: "
                + object_id
                + " "
                + kind
            )
        result[(object_id, kind)] = reason
    return result


_REFUTATIONS = _validated_refutations(REFUTATION_BASIS)


def _status(
    spec: SemanticOwnershipSpec,
    review: _shared._Review,
    kind: str,
) -> str:
    """Return only an explicit label or a literal refutation; omission stays UNRESOLVED."""
    if kind in review.applicable:
        return "APPLIES"
    if (spec.object_id, kind) in _REFUTATIONS:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _unresolved_text(object_id: str, kind: str) -> str:
    external_callable = _UNCHECKED_EXTERNAL_CALLABLES.get((object_id, kind))
    if external_callable is not None:
        return (
            object_id
            + " leaves "
            + kind
            + " UNRESOLVED: "
            + external_callable
            + " Intended lookup, digest, or cancellation use does not establish "
            "that a caller-controlled implementation is effect-free."
        )
    exposed_route = _EXPOSED_EFFECT_ROUTES.get((object_id, kind))
    if exposed_route is not None:
        return (
            object_id
            + " leaves "
            + kind
            + " UNRESOLVED: "
            + exposed_route
            + " Direct-call absence in the export owner cannot substitute for a "
            "graph-level decision about consequences reachable through that public route."
        )
    return (
        object_id
        + " leaves "
        + kind
        + " UNRESOLVED: no literal per-object refutation basis is authored, and "
        "omission from the applicable labels is not a refutation."
    )


def _reason(
    spec: SemanticOwnershipSpec,
    review: _shared._Review,
    kind: str,
) -> str:
    status = _status(spec, review, kind)
    if status == "APPLIES":
        if (spec.object_id, kind) in _DECLARED_DELEGATED_APPLICABILITY:
            decision = _DECLARED_DELEGATED_APPLICABILITY[(spec.object_id, kind)]
        elif (spec.object_id, kind) in _ADDITIONAL_APPLICABILITY:
            decision = _ADDITIONAL_APPLICABILITY[(spec.object_id, kind)]
        elif kind == "ASSET":
            decision = (
                review.profile.name
                + " applies as ASSET. Its represented resource identity, quantity, "
                "rights, custody, backing, and reconciliation boundaries would be hidden "
                "by a generic object label."
            )
        else:
            decision = _shared._reason(review.profile, kind, True)
    elif status == "DOES_NOT_APPLY":
        # The literal refutation already states the owner, denominator, role,
        # necessity, consequence boundary and fixed operands of the audited basis;
        # appending the basis again would only duplicate that text in every cell.
        return _REFUTATIONS[(spec.object_id, kind)]
    else:
        decision = _unresolved_text(spec.object_id, kind)
    return decision + " Audited semantic basis: " + _basis(spec)


# These applicability cells retain declaration obligations at open or static
# boundaries.  Their exact reasons expressly withhold subject instantiation,
# external mechanism, or real physical/financial effect, so they cannot serve
# as structural role evidence in the consequence graph.
_OBLIGATION_RETENTION_CELLS = {
    (object_id, kind)
    for object_id, kind, _reason_text in OBLIGATION_RETENTION_APPLICABILITY_BASIS
}
_OBLIGATION_RETENTION_CELLS.update(
    ("vstd-accelerator-profile-registry", kind) for kind in REVIEW_KINDS
)
_OBLIGATION_RETENTION_CELLS.update(
    ("vstd-agency-surface-crosswalk-assets", kind)
    for kind in AGENCY_CROSSWALK_ADDITIVE_APPLIES
)
_OBLIGATION_RETENTION_CELLS.add(("vstd-domain-grounding-specimen", "FINBOT"))
OBLIGATION_RETENTION_APPLIES: dict[str, tuple[str, ...]] = {
    object_id: tuple(
        kind
        for kind in REVIEW_KINDS
        if (object_id, kind) in _OBLIGATION_RETENTION_CELLS
    )
    for object_id in sorted({object_id for object_id, _kind in _OBLIGATION_RETENTION_CELLS})
}


def obligation_retention_reason(object_id: str, kind: str) -> str:
    """Return one exact partition-review demand-only reason."""

    if kind not in OBLIGATION_RETENTION_APPLIES.get(object_id, ()):
        raise ValueError("PARTITION_REVIEW_OBLIGATION_RETENTION_UNDECLARED")
    return _reason(_SPECS[object_id], _REVIEWS[object_id], kind)


def _cell(
    spec: SemanticOwnershipSpec,
    review: _shared._Review,
    kind: str,
) -> tuple[str, str, tuple[str, ...]]:
    """Return the only admissible status, reason, and evidence paths for one cell."""
    status = _status(spec, review, kind)
    paths = () if status == "UNRESOLVED" else review.owned_paths
    return status, _reason(spec, review, kind), paths


def _declarations(
    spec: SemanticOwnershipSpec,
    review: _shared._Review,
) -> dict[str, dict[str, str]]:
    """Fill every live field and bind its prose to this exact source owner."""
    result: dict[str, dict[str, str]] = {}
    basis = _declaration_basis(spec)
    for kind in review.applicable:
        try:
            selected = _DECLARATION_BUILDERS[kind](review.profile)
        except KeyError as exc:
            raise AssertionError("missing declaration builder for " + kind) from exc
        overlap = set(result).intersection(selected)
        if overlap:
            raise AssertionError(
                "duplicate declaration ids: " + ", ".join(sorted(overlap))
            )
        result.update(
            {
                obligation_id: {
                    field: basis + " Field declaration: " + value
                    for field, value in fields.items()
                }
                for obligation_id, fields in selected.items()
            }
        )
    return result


def _union_failure(
    partition: tuple[SemanticOwnershipSpec, ...],
    local: tuple[SemanticOwnershipSpec, ...],
    central: tuple[SemanticOwnershipSpec, ...],
) -> str | None:
    """Return the first way partition and local rows fail to tile the central catalog."""
    members = (*partition, *local)
    ids = [spec.object_id for spec in members]
    if len(ids) != len(set(ids)):
        return "object identifier is duplicated across partition and local catalogs"
    by_id = {spec.object_id: spec for spec in central}
    if len(by_id) != len(central):
        return "central ownership catalog repeats an object identifier"
    if set(ids) != set(by_id):
        return "partition and local catalogs omit or add central ownership objects"
    if any(by_id[spec.object_id] != spec for spec in members):
        return "partition or local object differs from its central ownership spec"
    paths = [path for spec in members for path in spec.owned_paths]
    if len(paths) != len(set(paths)):
        return "source path is owned by more than one object"
    return None


def _refutation_coverage_failure(
    object_ids: list[str],
    refuted: list[str],
    pending: list[str],
) -> str | None:
    """Return the first way literal refutations and pending objects fail to cover objects."""
    if len(set(refuted)) != len(refuted) or len(set(pending)) != len(pending):
        return "duplicate object identifier in refutation or pending catalog"
    if set(refuted) & set(pending):
        return "object is both literally refuted and pending"
    if set(refuted) | set(pending) != set(object_ids):
        return "partition object lacks an explicit refutation or pending status"
    return None


def _catalog_check() -> None:
    if len(PARTITION_SPECS) != 319 or len(_SPECS) != 319:
        raise AssertionError("partition review object denominator differs")
    if len(_LOCAL_OBJECT_IDS) != 122 or len(_LOCAL_OWNERSHIP_SPECS) != 122:
        raise AssertionError("local ownership denominator differs from central catalog")
    failure = _union_failure(
        PARTITION_SPECS, _LOCAL_OWNERSHIP_SPECS, _ownership.SEMANTIC_OWNERSHIP_SPECS
    )
    if failure is not None:
        raise AssertionError("partition union differs from central catalog: " + failure)
    failure = _refutation_coverage_failure(
        list(PARTITION_OBJECT_IDS),
        [object_id for object_id, _kinds in REFUTED_KINDS_BY_OBJECT],
        list(PENDING_REFUTATION_AUDIT_OBJECT_IDS),
    )
    if failure is not None:
        raise AssertionError("partition refutation coverage differs: " + failure)
    if len(_REFUTATIONS) != 2_965:
        raise AssertionError("partition refutation denominator differs")
    if any(
        cell in _REFUTATIONS
        or _status(_SPECS[cell[0]], _REVIEWS[cell[0]], cell[1]) != "APPLIES"
        for cell in (*_UNCHECKED_EXTERNAL_CALLABLES, *_EXPOSED_EFFECT_ROUTES)
    ):
        raise AssertionError("non-refutable effect boundary was not obligation-retained")
    paths = [path for spec in PARTITION_SPECS for path in spec.owned_paths]
    if len(paths) != 1_551 or len(paths) != len(set(paths)):
        raise AssertionError(
            "partition review path denominator differs: "
            f"total={len(paths)} unique={len(set(paths))}"
        )
    for object_id, review in _REVIEWS.items():
        spec = _SPECS[object_id]
        if review.applicable != _applicable(spec):
            raise AssertionError(object_id + " applicable-kind denominator differs")
        statuses = {kind: _status(spec, review, kind) for kind in REVIEW_KINDS}
        if {
            kind for kind, status in statuses.items() if status == "APPLIES"
        } != set(review.applicable):
            raise AssertionError(object_id + " explicit applicability differs")
        if (
            review.primary_kind in REVIEW_KINDS
            and all(review.primary_kind != kind for kind in review.applicable)
        ):
            raise AssertionError(object_id + " primary kind is not applicable")
        if set(review.role_paths) != set(review.applicable) or any(
            paths != review.owned_paths for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence denominator differs")
        reasons = {
            kind: _reason(spec, review, kind) for kind in REVIEW_KINDS
        }
        if any(not reason.strip() for reason in reasons.values()):
            raise AssertionError(object_id + " classification matrix is incomplete")
        expected = {
            row["id"]: set(row["declaration_fields"])
            for kind in review.applicable
            for row in _shared._contract_rows(kind)
        }
        declarations = _declarations(spec, review)
        if set(declarations) != set(expected):
            raise AssertionError(object_id + " declaration denominator differs")
        compact_basis = _declaration_basis(spec)
        for obligation_id, fields in declarations.items():
            if set(fields) != expected[obligation_id] or any(
                type(value) is not str
                or not value.strip()
                or object_id not in value
                or _source_denominator(spec) not in value
                or compact_basis not in value
                or _declaration_basis_digest(spec) not in value
                or len(value) > 8192
                for value in fields.values()
            ):
                raise AssertionError(object_id + " declaration fields differ")


_catalog_check()


def _document(object_id: str, review: _shared._Review) -> dict[str, Any]:
    spec = _SPECS[object_id]
    classification: dict[str, dict[str, Any]] = {}
    for kind in REVIEW_KINDS:
        status, reason, paths = _cell(spec, review, kind)
        classification[kind] = {
            "status": status,
            "reason": reason,
            "evidence_paths": list(paths),
        }
    return {
        "primary_kind": review.primary_kind,
        "owned_paths": list(review.owned_paths),
        "classification": classification,
        "declarations": deepcopy(_declarations(spec, review)),
        "claim_boundary": CLAIM_BOUNDARY,
    }


def review_document() -> dict[str, Any]:
    """Return a defensive digest-free view of all 319 exact reviews."""
    return {
        object_id: _document(object_id, review)
        for object_id, review in _REVIEWS.items()
    }


def review_counts() -> dict[str, int]:
    """Return exact review-denominator counts for integration and diagnostics."""
    statuses = [
        _status(_SPECS[object_id], review, kind)
        for object_id, review in _REVIEWS.items()
        for kind in REVIEW_KINDS
    ]
    declarations = [
        fields
        for object_id, review in _REVIEWS.items()
        for fields in _declarations(_SPECS[object_id], review).values()
    ]
    return {
        "objects": len(_REVIEWS),
        "paths": sum(len(review.owned_paths) for review in _REVIEWS.values()),
        "decisions": len(statuses),
        "applies": statuses.count("APPLIES"),
        "refuted": statuses.count("DOES_NOT_APPLY"),
        "unresolved": statuses.count("UNRESOLVED"),
        "declarations": len(declarations),
        "declaration_fields": sum(len(fields) for fields in declarations),
    }


def unresolved_inventory() -> dict[str, tuple[str, ...]]:
    """Return the exact per-object kinds that remain UNRESOLVED."""
    return {
        object_id: tuple(
            kind
            for kind in REVIEW_KINDS
            if _status(_SPECS[object_id], review, kind) == "UNRESOLVED"
        )
        for object_id, review in _REVIEWS.items()
    }


# Kept as a local seam so changed-source behavior can be tested without editing
# the shared review contract or any repository source file.
_source_evidence = _shared._source_evidence


def _row_operands(row: Mapping[str, Any], *, object_id: str) -> tuple[
    tuple[str, tuple[str, ...]], ...
]:
    """Normalize one candidate's fixed operands without accepting ambiguity."""
    operands = row.get("operands")
    if type(operands) is not dict:
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_OPERANDS_INVALID:" + object_id)
    normalized = []
    for name, targets in operands.items():
        if (
            type(name) is not str
            or not name
            or type(targets) not in {list, tuple}
            or any(type(target) is not str or not target for target in targets)
            or len(targets) != len(set(targets))
        ):
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_OPERANDS_INVALID:" + object_id)
        normalized.append((name, tuple(sorted(targets))))
    return tuple(sorted(normalized))


_UNAPPLIED_DECLARATION_CODES = {
    "DOES_NOT_APPLY": "PACKAGE_SEMANTIC_REVIEW_REFUTED_DECLARATION_CONFLICT:",
    "UNRESOLVED": "PACKAGE_SEMANTIC_REVIEW_UNRESOLVED_DECLARATION_CONFLICT:",
}


def _preserve_decision(
    decision: Any,
    status: str,
    reason: str,
    evidence: list[dict[str, str]],
    *,
    object_id: str,
    kind: str,
) -> bool:
    """Preserve only an exact complete decision; same-status prose is not authority."""
    code = "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
    if decision is None:
        return False
    if (
        type(decision) is not dict
        or set(decision) != {"status", "reason", "evidence"}
        or type(decision["reason"]) is not str
        or type(decision["evidence"]) is not list
    ):
        raise ValueError(code)
    if decision["status"] == "UNRESOLVED":
        # UNRESOLVED carries no authority, so the canonical cell replaces it.
        return False
    if decision["status"] == "DOES_NOT_APPLY" and status == "UNRESOLVED":
        raise ValueError(
            "PACKAGE_SEMANTIC_REVIEW_REFUTATION_UNSUPPORTED:" + object_id + ":" + kind
        )
    if (
        decision["status"] != status
        or decision["reason"] != reason
        or decision["evidence"] != evidence
    ):
        raise ValueError(code)
    return True


def _blank_binding(binding: Any, fields: tuple[str, ...], *, code: str) -> bool:
    """Return True only for an empty placeholder; malformed bindings fail closed."""
    if binding is None:
        return True
    if (
        type(binding) is not dict
        or set(binding) != {"reason", "evidence", "declaration"}
        or type(binding["reason"]) is not str
        or type(binding["evidence"]) is not list
        or type(binding["declaration"]) is not dict
    ):
        raise ValueError(code)
    declaration = binding["declaration"]
    return (
        binding["reason"] == ""
        and binding["evidence"] == []
        and set(declaration) == set(fields)
        and all(value == "" for value in declaration.values())
    )


def _preserve_declaration(
    binding: Any,
    fields: tuple[str, ...],
    evidence: list[dict[str, str]],
    *,
    object_id: str,
    obligation_id: str,
) -> bool:
    """Preserve a complete declaration only with the exact full owned evidence."""
    code = (
        "PACKAGE_SEMANTIC_REVIEW_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id
    )
    if _blank_binding(binding, fields, code=code):
        return False
    declaration = binding["declaration"]
    if (
        not binding["reason"].strip()
        or set(declaration) != set(fields)
        or any(
            type(value) is not str or not value.strip()
            for value in declaration.values()
        )
        or binding["evidence"] != evidence
    ):
        raise ValueError(code)
    return True


def apply_package_semantic_review_partitions(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply all 319 reviews atomically to a deep copy of candidate rows.

    Only explicit labels and literal refutations are written as APPLIES or
    DOES_NOT_APPLY.  Every other cell is canonical UNRESOLVED with no evidence.
    """
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
    known_obligations = {
        name for obligations in live_obligations.values() for name in obligations
    }
    plans: dict[str, dict[str, Any]] = {}
    for object_id, review in _REVIEWS.items():
        spec = _SPECS[object_id]
        row = rows.get(object_id)
        if type(row) is not dict:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_OBJECT_MISSING:" + object_id)
        if row.get("object_id") != object_id or row.get("kind") != review.primary_kind:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_PRIMARY_KIND_DIFFERS:" + object_id
            )
        if _row_operands(row, object_id=object_id) != spec.operands:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_OPERANDS_DIFFER:" + object_id)
        owned = _shared._owned_file_paths(row)
        if owned != set(review.owned_paths):
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_OWNERSHIP_DIFFERS:" + object_id)
        current = _shared._current_evidence(
            selected_root,
            review.owned_paths,
            files,
            object_id=object_id,
        )
        evidence_by_path = {item["path"]: item for item in current}

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
            if _status(spec, review, kind) != "APPLIES" and (
                row["kind"] == kind or kind in specializations
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:"
                    + object_id
                    + ":"
                    + kind
                )
        for name in obligations:
            if (
                type(name) is not str
                or name.split("-", 1)[0] in REVIEW_KINDS
                and name not in known_obligations
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
        for kind in REVIEW_KINDS:
            status, reason, paths = _cell(spec, review, kind)
            if _preserve_decision(
                classification.get(kind),
                status,
                reason,
                [evidence_by_path[path] for path in paths],
                object_id=object_id,
                kind=kind,
            ):
                preserve_decisions.add(kind)
            for obligation_id, fields in live_obligations[kind].items():
                binding = obligations.get(obligation_id)
                if status == "APPLIES":
                    if _preserve_declaration(
                        binding,
                        fields,
                        current,
                        object_id=object_id,
                        obligation_id=obligation_id,
                    ):
                        preserve_obligations.add(obligation_id)
                elif binding is not None:
                    code = (
                        _UNAPPLIED_DECLARATION_CODES[status]
                        + object_id
                        + ":"
                        + obligation_id
                    )
                    if not _blank_binding(binding, fields, code=code):
                        raise ValueError(code)
                    remove_obligations.add(obligation_id)

        plans[object_id] = {
            "opening_evidence": current,
            "evidence_by_path": evidence_by_path,
            "preserve_decisions": preserve_decisions,
            "preserve_obligations": preserve_obligations,
            "remove_obligations": remove_obligations,
        }

    # Re-read only after all semantic conflicts have passed. No copied row is
    # changed when a source disappears or changes during the full preflight.
    for object_id, review in _REVIEWS.items():
        closing = _source_evidence(selected_root, review.owned_paths)
        if closing != plans[object_id]["opening_evidence"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)

    result = deepcopy(rows)
    for object_id, review in _REVIEWS.items():
        row = result[object_id]
        spec = _SPECS[object_id]
        plan = plans[object_id]
        for kind in REVIEW_KINDS:
            if kind in plan["preserve_decisions"]:
                continue
            status, reason, paths = _cell(spec, review, kind)
            row["classification"][kind] = {
                "status": status,
                "reason": reason,
                "evidence": [
                    deepcopy(plan["evidence_by_path"][path]) for path in paths
                ],
            }
        for name in plan["remove_obligations"]:
            row["obligations"].pop(name, None)
        for name, declaration in _declarations(spec, review).items():
            if name in plan["preserve_obligations"]:
                continue
            kind = name.split("-", 1)[0]
            row["obligations"][name] = {
                "reason": (
                    _reason(spec, review, kind)
                    + " This Tier-0 declaration names the reviewed exact-source "
                    "boundary only; mechanism execution, semantic truth, and "
                    "Tier-1-plus fulfillment remain unestablished."
                ),
                "evidence": [
                    deepcopy(plan["evidence_by_path"][path])
                    for path in review.owned_paths
                ],
                "declaration": dict(declaration),
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)
    return result


__all__ = [
    "CLAIM_BOUNDARY",
    "EXPOSED_EFFECT_ROUTE_BASIS",
    "OBLIGATION_RETENTION_APPLIES",
    "OBLIGATION_RETENTION_APPLICABILITY_BASIS",
    "PARTITION_OBJECT_IDS",
    "PARTITION_SPECS",
    "REFUTATION_BASIS",
    "REFUTED_KINDS_BY_OBJECT",
    "REVIEW_KINDS",
    "SOURCE_AUDITED_APPLICABILITY_BASIS",
    "UNCHECKED_EXTERNAL_CALLABLE_BASIS",
    "apply_package_semantic_review_partitions",
    "obligation_retention_reason",
    "review_counts",
    "review_document",
    "unresolved_inventory",
]
